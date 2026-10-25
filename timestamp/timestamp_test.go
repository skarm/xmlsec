package timestamp_test

import (
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"io"
	"math"
	"math/big"
	"runtime"
	"testing"
	"time"

	"github.com/skarm/xmlsec/cms"
	"github.com/skarm/xmlsec/internal/der"
	"github.com/skarm/xmlsec/internal/testutil/testcert"
	"github.com/skarm/xmlsec/pki"
	"github.com/skarm/xmlsec/timestamp"
)

func TestParsedTokenIndependentFixtures(t *testing.T) {
	for _, name := range []string{"ts-rsa-256", "ts-rsa-384", "ts-rsa-512", "ts-ecdsa-256", "ts-ecdsa-384", "ts-ecdsa-512"} {
		t.Run(name, func(t *testing.T) { testParsedTokenIndependentFixture(t, name) })
	}
}

func testParsedTokenIndependentFixture(t *testing.T, name string) {
	t.Helper()

	fixture := testcert.LoadFixture(t, "../testdata/evidence", name)

	response, err := timestamp.ParseResponse(t.Context(), fixture.Read(t, name+"/response.der"))
	if err != nil {
		t.Fatal(err)
	}

	request, err := timestamp.ParseRequest(fixture.Read(t, name+"/request.der"))
	if err != nil {
		t.Fatal(err)
	}

	v, err := timestamp.NewVerifier(timestamp.Config{PKI: pki.Config{Roots: [][]byte{fixture.Read(t, name+"/root.der")}, Revocation: pki.RequireCRL}, AllowedPolicies: []asn1.ObjectIdentifier{policy()}, ClockSkew: time.Minute})
	if err != nil {
		t.Fatal(err)
	}

	raw := response.TokenDER()
	want := bytes.Clone(raw)
	source := &body{Reader: bytes.NewReader(raw)}

	token, err := timestamp.ParseTokenReader(t.Context(), source)
	if err != nil || source.closed {
		t.Fatal(err, source.closed)
	}

	raw[0] ^= 1

	if !bytes.Equal(token.DER(), want) || token.Size() != len(want) {
		t.Fatal("parsed token borrows caller bytes")
	}

	result, err := v.Verify(t.Context(), token, timestamp.Expectation{Imprint: request.Imprint(), Nonce: request.Nonce(), Policy: request.Policy()}, fixture.At, pki.Evidence{CRLs: [][]byte{fixture.Read(t, name+"/crl.der")}})
	if err != nil || result.Token() != token || result.Trust().RevocationStatus() != pki.Valid {
		t.Fatal(result, err)
	}

	var output bytes.Buffer
	if n, err := result.Token().WriterTo(t.Context()).WriteTo(&output); err != nil || n != int64(len(want)) || !bytes.Equal(output.Bytes(), want) {
		t.Fatal("token DER replay", n, err)
	}

	certificates := token.Certificates()
	if len(certificates) > 0 {
		certificates[0][0] ^= 1
	}

	if !bytes.Equal(result.TokenDER(), want) {
		t.Fatal("token mutated through getter")
	}
}

func TestTimestampTokenWorkingStorage(t *testing.T) {
	c := testcert.New(t)
	v := verifier(t, c)

	q, err := timestamp.CreateRequest(t.Context(), []byte("payload"), timestamp.RequestOptions{Policy: policy()})
	if err != nil {
		t.Fatal(err)
	}

	response, err := timestamp.IssueResponse(t.Context(), q.DER(), c.TSAKey, c.TSA.Raw, timestamp.IssueOptions{Policy: policy(), SerialNumber: big.NewInt(1), GenTime: testcert.Now()})
	if err != nil {
		t.Fatal(err)
	}

	r, err := timestamp.ParseResponse(t.Context(), response)
	if err != nil {
		t.Fatal(err)
	}

	container, err := cms.Parse(t.Context(), r.TokenDER(), cms.Limits{})
	if err != nil {
		t.Fatal(err)
	}

	info, err := der.Read(container.UnverifiedContent(), 1<<20)
	if err != nil {
		t.Fatal(err)
	}

	fields, err := der.Sequence(info, 5, 10)
	if err != nil {
		t.Fatal(err)
	}

	parts := make([][]byte, 0, len(fields)+1)
	for _, field := range fields {
		parts = append(parts, field.FullBytes)
	}

	padding := bytes.Repeat([]byte{7}, 512<<10)
	parts = append(parts, der.Ctx(1, der.Seq(der.OID(asn1.ObjectIdentifier{1, 2, 3, 4, 5}), der.Octets(padding))))

	raw, err := cms.Sign(t.Context(), der.Seq(parts...), []cms.Signer{{Key: c.TSAKey, CertificateDER: c.TSA.Raw}}, cms.SignOptions{ContentType: timestamp.TSTInfoOID()})
	if err != nil {
		t.Fatal(err)
	}

	response = der.Seq(der.Seq(der.Int(0)), raw)
	ev := pki.Evidence{CRLs: [][]byte{testcert.CRL(t, c)}}
	want := timestamp.Expectation{Imprint: q.Imprint(), Nonce: q.Nonce(), Policy: q.Policy()}

	token, err := timestamp.ParseToken(t.Context(), raw)
	if err != nil {
		t.Fatal(err)
	}

	measure := func(run func() error) uint64 {
		t.Helper()

		allocated := ^uint64(0)

		for range 3 {
			var before, after runtime.MemStats
			runtime.ReadMemStats(&before)

			if err := run(); err != nil {
				t.Fatal(err)
			}

			runtime.ReadMemStats(&after)
			allocated = min(allocated, after.TotalAlloc-before.TotalAlloc)
		}

		return allocated
	}
	allocated := measure(func() error { _, err := v.Verify(t.Context(), token, want, testcert.Now(), ev); return err })
	t.Logf("parsed token verification: %d DER bytes, %d allocated bytes", len(raw), allocated)

	if allocated > 256<<10 {
		t.Fatalf("parsed token was copied or reparsed: %d allocated", allocated)
	}

	allocated = measure(func() error { _, err := timestamp.ParseToken(t.Context(), raw); return err })
	t.Logf("token parsing: %d allocated bytes", allocated)

	if allocated > 2*uint64(len(raw))+(128<<10) {
		t.Fatalf("token parsing retained excess content copies: %d allocated", allocated)
	}

	allocated = measure(func() error {
		_, err := v.VerifyResponseReader(t.Context(), bytes.NewReader(response), q, testcert.Now(), ev)
		return err
	})
	t.Logf("response verification: %d response bytes, %d allocated bytes", len(response), allocated)

	if allocated > 3*uint64(len(response))+(256<<10) {
		t.Fatalf("response verification reparsed/copied tokens: %d allocated", allocated)
	}

	allocated = measure(func() error { _, err := token.WriterTo(t.Context()).WriteTo(io.Discard); return err })
	if allocated > 64<<10 {
		t.Fatalf("token writer copied DER: %d allocated", allocated)
	}

	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	if result, err := v.Verify(ctx, token, want, testcert.Now(), ev); result != nil || !errors.Is(err, context.Canceled) {
		t.Fatal(result, err)
	}

	if n, err := token.WriterTo(ctx).WriteTo(io.Discard); n != 0 || !errors.Is(err, context.Canceled) {
		t.Fatal(n, err)
	}

	small, err := timestamp.NewVerifier(timestamp.Config{PKI: pki.Config{Roots: [][]byte{c.Root.Raw}, Revocation: pki.RequireCRL}, AllowedPolicies: []asn1.ObjectIdentifier{policy()}, MaxBytes: len(raw) - 1})
	if err != nil {
		t.Fatal(err)
	}

	if result, err := small.Verify(t.Context(), token, want, testcert.Now(), ev); result != nil || !errors.Is(err, timestamp.ErrPolicy) {
		t.Fatal("parsed token escaped byte budget", result, err)
	}
}

func TestResponseWriterCompatibilityAndErrors(t *testing.T) {
	c := testcert.New(t)
	v := verifier(t, c)

	evidence := pki.Evidence{CRLs: [][]byte{testcert.CRL(t, c)}}
	for _, h := range []crypto.Hash{crypto.SHA256, crypto.SHA384, crypto.SHA512} {
		q, err := timestamp.CreateRequest(t.Context(), []byte("payload"), timestamp.RequestOptions{Hash: h, Policy: policy()})
		if err != nil {
			t.Fatal(err)
		}

		options := timestamp.IssueOptions{Policy: policy(), SerialNumber: big.NewInt(1), GenTime: testcert.Now(), Hash: h}

		var output bytes.Buffer

		n, err := timestamp.WriteResponse(t.Context(), &output, q.DER(), c.TSAKey, c.TSA.Raw, options)
		if err != nil || n != int64(output.Len()) {
			t.Fatal("response size", n, err)
		}

		result, err := v.VerifyResponseReader(t.Context(), bytes.NewReader(output.Bytes()), q, testcert.Now(), evidence)
		if err != nil || result.Info().Imprint().Hash != h {
			t.Fatal("writer response failed verification", err)
		}

		failure := errors.New("destination failed")

		output.Reset()

		dst := responseWriteFunc(func(p []byte) (int, error) {
			used := min(len(p), 128-output.Len())

			_, _ = output.Write(p[:used])
			if used < len(p) {
				return used, failure
			}

			return used, nil
		})
		if n, err := timestamp.WriteResponse(t.Context(), dst, q.DER(), c.TSAKey, c.TSA.Raw, options); n != 128 || !errors.Is(err, failure) {
			t.Fatal("response partial output", n, err)
		}

		ctx, cancel := context.WithCancel(t.Context())

		output.Reset()

		dst = func(p []byte) (int, error) { n, err := output.Write(p); cancel(); return n, err }
		if n, err := timestamp.WriteResponse(ctx, dst, q.DER(), c.TSAKey, c.TSA.Raw, options); !errors.Is(err, context.Canceled) || n > 32<<10 {
			t.Fatal("response cancellation", n, err)
		}

		cancel()
		output.Reset()

		if n, err := timestamp.WriteResponse(t.Context(), &output, q.DER(), c.LeafKey, c.Leaf.Raw, options); n != 0 || output.Len() != 0 || !errors.Is(err, timestamp.ErrTrust) {
			t.Fatal("invalid issuer wrote response", n, err)
		}
	}
}

func TestRoundTripAndBindings(t *testing.T) {
	c := testcert.New(t)
	v := verifier(t, c)
	ev := pki.Evidence{CRLs: [][]byte{testcert.CRL(t, c)}}
	a := 1500 * time.Microsecond

	for _, h := range []crypto.Hash{crypto.SHA256, crypto.SHA384, crypto.SHA512} {
		for _, omit := range []bool{false, true} {
			suffix := " cert"
			if omit {
				suffix = " no cert"
			}

			t.Run(h.String()+suffix, func(t *testing.T) { testRoundTripAndBindingsCase(t, &h, &omit, &c, &a, &v, &ev) })
		}
	}
}

func testRoundTripAndBindingsCase(t *testing.T, h *crypto.Hash, omit *bool, c *testcert.Chain, a *time.Duration, v **timestamp.Verifier, ev *pki.Evidence) {
	q, e := timestamp.CreateRequest(t.Context(), []byte("data"), timestamp.RequestOptions{Hash: *h, Policy: policy(), OmitCertificates: *omit})
	if e != nil {
		t.Fatal(e)
	}

	raw, e := timestamp.IssueResponse(context.Background(), q.DER(), c.TSAKey, c.TSA.Raw, timestamp.IssueOptions{Policy: policy(), SerialNumber: big.NewInt(10), GenTime: testcert.Now().Add(-time.Second + 123456000*time.Nanosecond), Accuracy: a, Ordering: true, Hash: *h, ExtraCertificates: [][]byte{c.Root.Raw}})
	if e != nil {
		t.Fatal(e)
	}

	r, e := (*v).VerifyResponse(context.Background(), raw, q, testcert.Now(), *ev)
	if e != nil || r == nil {
		t.Fatal(e)
	}

	if r.Info().Nonce().Cmp(q.Nonce()) != 0 || r.Trust().RevocationStatus() != pki.Valid {
		t.Fatal("nonce/trust")
	}

	d, ok := r.Info().Accuracy()
	if !ok || d != (*a) {
		t.Fatal("accuracy")
	}

	r.TokenDER()[0] ^= 1
	if _, e = timestamp.InspectToken(t.Context(), r.TokenDER()); e != nil {
		t.Fatal("mutable")
	}

	wrong, e := timestamp.CreateRequest(t.Context(), []byte("other"), timestamp.RequestOptions{Policy: policy()})
	if e != nil {
		t.Fatal(e)
	}

	if r, e := (*v).VerifyResponse(context.Background(), raw, wrong, testcert.Now(), *ev); r != nil || !errors.Is(e, timestamp.ErrBinding) {
		t.Fatal("wrong request", e)
	}

	for _, tc := range []struct {
		name string
		at   time.Time
		e    pki.Evidence
		want error
	}{{"missing revocation", testcert.Now(), pki.Evidence{}, timestamp.ErrTrust}, {"revoked TSA", testcert.Now(), pki.Evidence{CRLs: [][]byte{testcert.CRL(t, *c, c.TSA)}}, pki.ErrRevoked}, {"future token", testcert.Now().Add(-2 * time.Second), *ev, timestamp.ErrPolicy}} {
		t.Run(tc.name, func(t *testing.T) {
			r, e := (*v).VerifyResponse(context.Background(), raw, q, tc.at, tc.e)
			if r != nil || !errors.Is(e, tc.want) {
				t.Fatal(e)
			}
		})
	}
}

func TestTSAUsageAndPolicy(t *testing.T) {
	c := testcert.New(t)
	if _, e := timestamp.NewVerifier(timestamp.Config{PKI: pki.Config{Roots: [][]byte{c.Root.Raw}}, AllowedPolicies: []asn1.ObjectIdentifier{policy()}}); !errors.Is(e, timestamp.ErrPolicy) {
		t.Fatal("implicit unchecked revocation", e)
	}

	q, e := timestamp.CreateRequest(t.Context(), nil, timestamp.RequestOptions{Policy: policy()})
	if e != nil {
		t.Fatal(e)
	}

	o := timestamp.IssueOptions{Policy: policy(), SerialNumber: big.NewInt(1), GenTime: testcert.Now()}
	if _, e := timestamp.IssueResponse(context.Background(), q.DER(), c.LeafKey, c.Leaf.Raw, o); !errors.Is(e, timestamp.ErrTrust) {
		t.Fatal("wrong EKU", e)
	}

	weak := *c.TSA
	weak.Raw = nil
	weak.SerialNumber = big.NewInt(11)
	weak.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping}
	weak.ExtraExtensions = nil
	weak.Extensions = nil

	crt := testcert.Issue(t, &weak, c.Root, &c.TSAKey.PublicKey, c.RootKey)
	if _, e := timestamp.IssueResponse(context.Background(), q.DER(), c.TSAKey, crt.Raw, o); !errors.Is(e, timestamp.ErrTrust) {
		t.Fatal("noncritical EKU", e)
	}

	o.Policy = asn1.ObjectIdentifier{1, 2, 3}
	if _, e := timestamp.IssueResponse(context.Background(), q.DER(), c.TSAKey, c.TSA.Raw, o); !errors.Is(e, timestamp.ErrBinding) {
		t.Fatal("wrong policy", e)
	}
}

func TestMalformedAndCancellation(t *testing.T) {
	policyTooLarge := make(asn1.ObjectIdentifier, 1<<16)

	policyTooLarge[0], policyTooLarge[1] = 1, 2
	if request, err := timestamp.CreateImprintRequest(timestamp.Imprint{Hash: crypto.SHA256, Digest: make([]byte, 32)}, timestamp.RequestOptions{Policy: policyTooLarge, OmitNonce: true}); request != nil || !errors.Is(err, timestamp.ErrPolicy) {
		t.Fatal("generated request escaped byte budget", request, err)
	}

	for _, b := range [][]byte{nil, {0x30, 0}, {0x30, 3, 2, 1, 7}, {0x30, 5, 0x30, 3, 2, 1, 0}, {0x30, 5, 0x30, 3, 2, 1, 2}} {
		if _, e := timestamp.ParseResponse(t.Context(), b); e == nil {
			t.Fatal("accepted malformed/failure", b)
		}
	}

	q, e := timestamp.CreateRequest(t.Context(), nil, timestamp.RequestOptions{})
	if e != nil || q.Nonce() == nil {
		t.Fatal(e)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	v := verifier(t, testcert.New(t))
	if _, e = v.VerifyToken(ctx, nil, timestamp.Expectation{Imprint: q.Imprint()}, testcert.Now(), pki.Evidence{}); !errors.Is(e, context.Canceled) {
		t.Fatal(e)
	}
}

func TestFetchBoundsAndCloses(t *testing.T) {
	c := testcert.New(t)

	v, e := timestamp.NewVerifier(timestamp.Config{PKI: pki.Config{Roots: [][]byte{c.Root.Raw}, Revocation: pki.RequireCRL}, AllowedPolicies: []asn1.ObjectIdentifier{policy()}, MaxBytes: 1024})
	if e != nil {
		t.Fatal(e)
	}

	q, e := timestamp.CreateRequest(t.Context(), nil, timestamp.RequestOptions{})
	if e != nil {
		t.Fatal(e)
	}

	b := &body{Reader: bytes.NewReader([]byte{0x30, 0x82, 0x08, 0x00})}
	if r, e := v.Fetch(context.Background(), transport{b: b}, q, testcert.Now(), pki.Evidence{}); r != nil || !errors.Is(e, timestamp.ErrPolicy) || !b.closed {
		t.Fatal(e)
	}

	b = &body{Reader: bytes.NewReader(nil), closeErr: io.ErrClosedPipe}
	if r, e := v.Fetch(context.Background(), transport{b: b}, q, testcert.Now(), pki.Evidence{}); r != nil || !errors.Is(e, io.ErrClosedPipe) || !b.closed {
		t.Fatal(e)
	}

	if r, e := v.Fetch(context.Background(), transport{}, q, testcert.Now(), pki.Evidence{}); r != nil || !errors.Is(e, timestamp.ErrFormat) {
		t.Fatal("typed nil body", e)
	}
}

func TestFetchRejectsInvalidStateBeforeTransport(t *testing.T) {
	c := testcert.New(t)
	v := verifier(t, c)

	q, err := timestamp.CreateRequest(t.Context(), nil, timestamp.RequestOptions{Policy: policy()})
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name string
		v    *timestamp.Verifier
		q    *timestamp.Request
		at   time.Time
	}{
		{"zero verifier", new(timestamp.Verifier), q, testcert.Now()},
		{"zero request", v, new(timestamp.Request), testcert.Now()},
		{"zero validation time", v, q, time.Time{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			tr := timestamp.TransportFunc(func(context.Context, []byte) (io.ReadCloser, error) {
				calls++
				return io.NopCloser(bytes.NewReader(nil)), nil
			})

			result, err := tc.v.Fetch(context.Background(), tr, tc.q, tc.at, pki.Evidence{})
			if calls != 0 || result != nil || !errors.Is(err, timestamp.ErrPolicy) {
				t.Fatalf("transport calls=%d result=%v error=%v", calls, result != nil, err)
			}
		})
	}
}

func TestFetchPreservesTransportAndCloseErrors(t *testing.T) {
	c := testcert.New(t)
	v := verifier(t, c)

	q, err := timestamp.CreateRequest(t.Context(), nil, timestamp.RequestOptions{})
	if err != nil {
		t.Fatal(err)
	}

	transportErr, closeErr := errors.New("transport failed"), errors.New("close failed")
	response := &body{Reader: bytes.NewReader(nil), closeErr: closeErr}

	result, err := v.Fetch(t.Context(), transport{b: response, err: transportErr}, q, testcert.Now(), pki.Evidence{})
	if result != nil || !response.closed || !errors.Is(err, transportErr) || !errors.Is(err, closeErr) {
		t.Fatal(result, err, response.closed)
	}
}

func TestFetchClosesWithoutReadingAfterCancellation(t *testing.T) {
	c := testcert.New(t)
	v := verifier(t, c)

	q, err := timestamp.CreateRequest(t.Context(), nil, timestamp.RequestOptions{})
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	response := &body{Reader: panicReader{}}
	tr := timestamp.TransportFunc(func(context.Context, []byte) (io.ReadCloser, error) { cancel(); return response, nil })

	result, err := v.Fetch(ctx, tr, q, testcert.Now(), pki.Evidence{})
	if result != nil || !response.closed || !errors.Is(err, context.Canceled) {
		t.Fatal(result, err, response.closed)
	}
}

func TestFetchPreservesReadAndCloseErrors(t *testing.T) {
	c := testcert.New(t)
	v := verifier(t, c)

	q, err := timestamp.CreateRequest(t.Context(), nil, timestamp.RequestOptions{})
	if err != nil {
		t.Fatal(err)
	}

	readErr, closeErr := errors.New("read failed"), errors.New("close failed")
	response := &body{Reader: failingReader{err: readErr}, closeErr: closeErr}

	result, err := v.Fetch(t.Context(), transport{b: response}, q, testcert.Now(), pki.Evidence{})
	if result != nil || !response.closed || !errors.Is(err, readErr) || !errors.Is(err, closeErr) {
		t.Fatal(result, err, response.closed)
	}
}

func TestMaxAgeDoesNotOverflowWithClockSkew(t *testing.T) {
	c := testcert.New(t)
	ctx := context.Background()

	q, err := timestamp.CreateRequest(t.Context(), []byte("age boundary"), timestamp.RequestOptions{Policy: policy()})
	if err != nil {
		t.Fatal(err)
	}

	raw, err := timestamp.IssueResponse(ctx, q.DER(), c.TSAKey, c.TSA.Raw, timestamp.IssueOptions{Policy: policy(), SerialNumber: big.NewInt(20), GenTime: testcert.Now().Add(-30 * time.Second)})
	if err != nil {
		t.Fatal(err)
	}

	for _, maxAge := range []time.Duration{time.Minute, math.MaxInt64 - time.Minute, math.MaxInt64} {
		v, err := timestamp.NewVerifier(timestamp.Config{
			PKI:             pki.Config{Roots: [][]byte{c.Root.Raw}, Revocation: pki.RequireCRL},
			AllowedPolicies: []asn1.ObjectIdentifier{policy()},
			ClockSkew:       time.Minute,
			MaxAge:          maxAge,
		})
		if err != nil {
			t.Fatal(err)
		}

		if r, err := v.VerifyResponse(ctx, raw, q, testcert.Now(), pki.Evidence{CRLs: [][]byte{testcert.CRL(t, c)}}); err != nil || r == nil {
			t.Fatalf("valid recent timestamp rejected with MaxAge=%v: %v", maxAge, err)
		}
	}
}

func FuzzRequest(f *testing.F) {
	q, e := timestamp.CreateRequest(f.Context(), nil, timestamp.RequestOptions{})
	if e != nil {
		f.Fatal(e)
	}

	f.Add(q.DER())
	f.Add([]byte{0x30, 0})
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 1<<16 {
			t.Skip()
		}

		_, _ = timestamp.ParseRequest(b)
	})
}

func FuzzResponse(f *testing.F) {
	fixture := testcert.LoadFixture(f, "../testdata/evidence", "ts-ecdsa-256")
	raw := fixture.Read(f, "ts-ecdsa-256/response.der")

	q, e := timestamp.ParseRequest(fixture.Read(f, "ts-ecdsa-256/request.der"))
	if e != nil {
		f.Fatal(e)
	}

	v, e := timestamp.NewVerifier(timestamp.Config{PKI: pki.Config{Roots: [][]byte{fixture.Read(f, "ts-ecdsa-256/root.der")}, Revocation: pki.RequireCRL}, AllowedPolicies: []asn1.ObjectIdentifier{policy()}, ClockSkew: time.Minute})
	if e != nil {
		f.Fatal(e)
	}

	evidence := pki.Evidence{CRLs: [][]byte{fixture.Read(f, "ts-ecdsa-256/crl.der")}}
	if result, e := v.VerifyResponse(context.Background(), raw, q, fixture.At, evidence); e != nil || result == nil {
		f.Fatalf("invalid positive timestamp fixture: %v", e)
	}

	f.Add(raw)
	f.Add([]byte{0x30, 0})
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 1<<20 {
			t.Skip()
		}

		if _, e := timestamp.ParseResponse(t.Context(), b); e != nil {
			return
		}

		result, e := v.VerifyResponse(context.Background(), b, q, fixture.At, evidence)
		if e != nil && result != nil || e == nil && (result == nil || result.Trust() == nil || result.Trust().RevocationStatus() != pki.Valid) {
			t.Fatal("inconsistent timestamp verification result")
		}
	})
}

func BenchmarkVerifyResponse(b *testing.B) {
	c := testcert.New(b)
	v := verifier(b, c)

	q, err := timestamp.CreateRequest(b.Context(), []byte("data"), timestamp.RequestOptions{Policy: policy()})
	if err != nil {
		b.Fatal(err)
	}

	raw, err := timestamp.IssueResponse(context.Background(), q.DER(), c.TSAKey, c.TSA.Raw, timestamp.IssueOptions{Policy: policy(), SerialNumber: big.NewInt(10), GenTime: testcert.Now().Add(-time.Second)})
	if err != nil {
		b.Fatal(err)
	}

	e := pki.Evidence{CRLs: [][]byte{testcert.CRL(b, c)}}
	b.ReportAllocs()

	for b.Loop() {
		if _, err := v.VerifyResponse(context.Background(), raw, q, testcert.Now(), e); err != nil {
			b.Fatal(err)
		}
	}
}

type responseWriteFunc func([]byte) (int, error)

func (f responseWriteFunc) Write(p []byte) (int, error) { return f(p) }

func policy() asn1.ObjectIdentifier { return asn1.ObjectIdentifier{1, 2, 3, 4, 1} }

func verifier(t testing.TB, c testcert.Chain) *timestamp.Verifier {
	t.Helper()

	v, e := timestamp.NewVerifier(timestamp.Config{PKI: pki.Config{Roots: [][]byte{c.Root.Raw}, Revocation: pki.RequireCRL}, AllowedPolicies: []asn1.ObjectIdentifier{policy()}, Certificates: [][]byte{c.TSA.Raw}})
	if e != nil {
		t.Fatal(e)
	}

	return v
}

type body struct {
	io.Reader
	closed   bool
	closeErr error
}

func (b *body) Close() error { b.closed = true; return b.closeErr }

type transport struct {
	b   *body
	err error
}

func (t transport) RoundTrip(context.Context, []byte) (io.ReadCloser, error) { return t.b, t.err }

type panicReader struct{}

func (panicReader) Read([]byte) (int, error) { panic("read after cancellation") }

type failingReader struct{ err error }

func (r failingReader) Read([]byte) (int, error) { return 0, r.err }
