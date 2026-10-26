package timestamp_test

import (
	"bytes"
	"context"
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"io"
	"math"
	"math/big"
	"net"
	"net/url"
	"runtime"
	"slices"
	"strconv"
	"testing"
	"time"

	"github.com/skarm/xmlsec/cms"
	"github.com/skarm/xmlsec/evidence"
	"github.com/skarm/xmlsec/internal/der"
	"github.com/skarm/xmlsec/internal/signature"
	"github.com/skarm/xmlsec/internal/testutil/testcert"
	"github.com/skarm/xmlsec/pki"
	"github.com/skarm/xmlsec/timestamp"
)

type responseWriteFunc func([]byte) (int, error)

func (f responseWriteFunc) Write(p []byte) (int, error) { return f(p) }

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

func policy() asn1.ObjectIdentifier { return asn1.ObjectIdentifier{1, 2, 3, 4, 1} }

func verifier(t testing.TB, c testcert.Chain) *timestamp.Verifier {
	t.Helper()

	v, e := timestamp.NewVerifier(timestamp.Config{PKI: pki.Config{Roots: [][]byte{c.Root.Raw}, Revocation: pki.RequireCRL}, AllowedPolicies: []asn1.ObjectIdentifier{policy()}, Certificates: [][]byte{c.TSA.Raw}})
	if e != nil {
		t.Fatal(e)
	}

	return v
}

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

	// Independent OpenSSL token bytes can be authenticated after the TSA path
	// expires, but that cryptographic fact must not become a trusted Result.
	later := fixture.At.AddDate(100, 0, 0)
	expectation := timestamp.Expectation{Imprint: request.Imprint(), Nonce: request.Nonce(), Policy: request.Policy()}
	assertion, err := v.Authenticate(t.Context(), token, expectation, later)
	if err != nil || !assertion.Valid() || assertion.TokenSHA256() != sha256.Sum256(want) || assertion.SignatureHash() == 0 || assertion.SignatureAlgorithmOID() == "" || !bytes.Equal(assertion.CertificateDER(), result.TSACertificateDER()) {
		t.Fatal("cryptographic token authentication", err)
	}
	if trusted, err := v.Verify(t.Context(), token, expectation, later, pki.Evidence{}); trusted != nil || err == nil {
		t.Fatal("authentication bypassed expired TSA trust", err)
	}
	assertion.CertificateDER()[0] ^= 1
	if !bytes.Equal(assertion.CertificateDER(), result.TSACertificateDER()) {
		t.Fatal("mutable authenticated certificate")
	}
	expectation.Imprint.Digest[0] ^= 1
	if assertion, err := v.Authenticate(t.Context(), token, expectation, later); assertion != nil || !errors.Is(err, timestamp.ErrBinding) {
		t.Fatal("unbound token authentication", err)
	}
	var zero timestamp.AuthenticatedToken
	if zero.Valid() || zero.Token() != nil || zero.CertificateDER() != nil || zero.SignatureHash() != 0 || zero.TokenSHA256() != ([32]byte{}) {
		t.Fatal("zero authenticated assertion")
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

func TestTimestampIssuanceRejectsBeforeOutput(t *testing.T) {
	c := testcert.New(t)
	request, err := timestamp.CreateRequest(t.Context(), []byte("bounded issuance"), timestamp.RequestOptions{Policy: policy()})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		change func(*timestamp.IssueOptions)
		want   error
	}{
		{"missing serial", func(o *timestamp.IssueOptions) { o.SerialNumber = nil }, timestamp.ErrPolicy},
		{"zero serial", func(o *timestamp.IssueOptions) { o.SerialNumber = big.NewInt(0) }, timestamp.ErrPolicy},
		{"negative serial", func(o *timestamp.IssueOptions) { o.SerialNumber = big.NewInt(-1) }, timestamp.ErrPolicy},
		{"serial over 160 bits", func(o *timestamp.IssueOptions) { o.SerialNumber = new(big.Int).Lsh(big.NewInt(1), 160) }, timestamp.ErrPolicy},
		{"invalid policy OID", func(o *timestamp.IssueOptions) { o.Policy = asn1.ObjectIdentifier{3, 1} }, timestamp.ErrPolicy},
		{"different policy", func(o *timestamp.IssueOptions) { o.Policy = asn1.ObjectIdentifier{1, 2, 3, 99} }, timestamp.ErrBinding},
		{"negative accuracy", func(o *timestamp.IssueOptions) { d := -time.Microsecond; o.Accuracy = &d }, timestamp.ErrPolicy},
		{"submicrosecond accuracy", func(o *timestamp.IssueOptions) { d := time.Nanosecond; o.Accuracy = &d }, timestamp.ErrPolicy},
	} {
		t.Run(tc.name, func(t *testing.T) {
			options := timestamp.IssueOptions{Policy: policy(), SerialNumber: big.NewInt(1), GenTime: testcert.Now()}
			tc.change(&options)
			var output bytes.Buffer
			if n, err := timestamp.WriteResponse(t.Context(), &output, request.DER(), c.TSAKey, c.TSA.Raw, options); n != 0 || output.Len() != 0 || !errors.Is(err, tc.want) {
				t.Fatal("invalid issuance emitted output or lost cause", n, output.Len(), err)
			}
		})
	}
	serial := new(big.Int).Lsh(big.NewInt(1), 159)
	accuracy := time.Microsecond
	raw, err := timestamp.IssueResponse(t.Context(), request.DER(), c.TSAKey, c.TSA.Raw, timestamp.IssueOptions{Policy: policy(), SerialNumber: serial, GenTime: testcert.Now(), Accuracy: &accuracy})
	if err != nil {
		t.Fatal("160-bit serial rejected", err)
	}
	result, err := verifier(t, c).VerifyResponse(t.Context(), raw, request, testcert.Now(), pki.Evidence{CRLs: [][]byte{testcert.CRL(t, c)}})
	if err != nil || result == nil || result.Info().SerialNumber().Cmp(serial) != 0 {
		t.Fatal("boundary issuance failed verification", err)
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

	raw, e := timestamp.IssueResponse(t.Context(), q.DER(), c.TSAKey, c.TSA.Raw, timestamp.IssueOptions{Policy: policy(), SerialNumber: big.NewInt(10), GenTime: testcert.Now().Add(-time.Second + 123456000*time.Nanosecond), Accuracy: a, Ordering: true, Hash: *h, ExtraCertificates: [][]byte{c.Root.Raw}})
	if e != nil {
		t.Fatal(e)
	}

	r, e := (*v).VerifyResponse(t.Context(), raw, q, testcert.Now(), *ev)
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

	if r, e := (*v).VerifyResponse(t.Context(), raw, wrong, testcert.Now(), *ev); r != nil || !errors.Is(e, timestamp.ErrBinding) {
		t.Fatal("wrong request", e)
	}

	for _, tc := range []struct {
		name string
		at   time.Time
		e    pki.Evidence
		want error
	}{{"missing revocation", testcert.Now(), pki.Evidence{}, timestamp.ErrTrust}, {"revoked TSA", testcert.Now(), pki.Evidence{CRLs: [][]byte{testcert.CRL(t, *c, c.TSA)}}, pki.ErrRevoked}, {"future token", testcert.Now().Add(-2 * time.Second), *ev, timestamp.ErrPolicy}} {
		t.Run(tc.name, func(t *testing.T) {
			r, e := (*v).VerifyResponse(t.Context(), raw, q, tc.at, tc.e)
			if r != nil || !errors.Is(e, tc.want) {
				t.Fatal(e)
			}
		})
	}
}

func TestRequestSchemaNonceAndInputBounds(t *testing.T) {
	imprint, err := timestamp.ImprintFor(t.Context(), []byte("request format boundaries"), crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	algorithm := der.Seq(der.OID(signature.SHA256()), []byte{5, 0})
	encodedImprint := der.Seq(algorithm, der.Octets(imprint.Digest))
	maximumNonce := new(big.Int).Lsh(big.NewInt(1), 255)
	nonce, err := asn1.Marshal(maximumNonce)
	if err != nil {
		t.Fatal(err)
	}
	tooLarge, err := asn1.Marshal(new(big.Int).Lsh(big.NewInt(1), 256))
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		raw  []byte
		want error
	}{
		{"minimal request", der.Seq(der.Int(1), encodedImprint), nil},
		{"maximum 256 bit nonce", der.Seq(der.Int(1), encodedImprint, der.OID(policy()), nonce, []byte{1, 1, 255}), nil},
		{"wrong version", der.Seq(der.Int(2), encodedImprint), timestamp.ErrFormat},
		{"missing imprint", der.Seq(der.Int(1)), timestamp.ErrFormat},
		{"malformed imprint", der.Seq(der.Int(1), der.Int(1)), timestamp.ErrFormat},
		{"short digest", der.Seq(der.Int(1), der.Seq(algorithm, der.Octets(imprint.Digest[:31]))), timestamp.ErrFormat},
		{"unsupported digest OID", der.Seq(der.Int(1), der.Seq(der.Seq(der.OID(asn1.ObjectIdentifier{1, 2, 3, 99})), der.Octets(imprint.Digest))), timestamp.ErrPolicy},
		{"zero nonce", der.Seq(der.Int(1), encodedImprint, der.Int(0)), timestamp.ErrFormat},
		{"negative nonce", der.Seq(der.Int(1), encodedImprint, der.Int(-1)), timestamp.ErrFormat},
		{"257 bit nonce", der.Seq(der.Int(1), encodedImprint, tooLarge), timestamp.ErrFormat},
		{"policy follows nonce", der.Seq(der.Int(1), encodedImprint, nonce, der.OID(policy())), timestamp.ErrFormat},
		{"duplicate nonce", der.Seq(der.Int(1), encodedImprint, nonce, nonce), timestamp.ErrFormat},
		{"unsupported extensions", der.Seq(der.Int(1), encodedImprint, der.Ctx(0, der.Seq())), timestamp.ErrFormat},
		{"encoded request exceeds 64 KiB", bytes.Repeat([]byte{0}, (1<<16)+1), timestamp.ErrPolicy},
	} {
		t.Run(tc.name, func(t *testing.T) {
			input := bytes.Clone(tc.raw)
			parsed, err := timestamp.ParseRequest(input)
			if tc.want != nil {
				if parsed != nil || !errors.Is(err, tc.want) {
					t.Fatal("invalid request or nonce budget accepted", parsed != nil, err)
				}
				return
			}
			if parsed == nil || err != nil || !bytes.Equal(parsed.Imprint().Digest, imprint.Digest) {
				t.Fatal("valid request boundary rejected", err)
			}
			clear(input)
			if !bytes.Equal(parsed.DER(), tc.raw) {
				t.Fatal("request retained caller storage")
			}
			if parsed.CertificatesRequested() {
				value := parsed.Nonce()
				if value == nil || value.Cmp(maximumNonce) != 0 || !parsed.Policy().Equal(policy()) {
					t.Fatal("maximum nonce or optional fields changed")
				}
				value.SetInt64(0)
				if parsed.Nonce().Cmp(maximumNonce) != 0 {
					t.Fatal("nonce accessor exposes mutable request state")
				}
			} else if parsed.Nonce() != nil || len(parsed.Policy()) != 0 {
				t.Fatal("minimal request acquired optional fields")
			}
		})
	}
	for _, options := range []timestamp.RequestOptions{
		{Nonce: make([]byte, 16)},
		{Nonce: bytes.Repeat([]byte{1}, 15)},
		{Nonce: bytes.Repeat([]byte{1}, 33)},
		{Nonce: bytes.Repeat([]byte{1}, 16), OmitNonce: true},
		{Policy: asn1.ObjectIdentifier{1}},
	} {
		if request, err := timestamp.CreateImprintRequest(imprint, options); request != nil || !errors.Is(err, timestamp.ErrPolicy) {
			t.Fatal("invalid local request options accepted", request != nil, err)
		}
	}
}

func TestResponseCertificateRequestBinding(t *testing.T) {
	chain := testcert.New(t)
	verifier, err := timestamp.NewVerifier(timestamp.Config{PKI: pki.Config{Roots: [][]byte{chain.Root.Raw}, Revocation: pki.RequireCRL}, Certificates: [][]byte{chain.TSA.Raw}, AllowedPolicies: []asn1.ObjectIdentifier{policy()}})
	if err != nil {
		t.Fatal(err)
	}
	requests := make([]*timestamp.Request, 2)
	for index := range requests {
		requests[index], err = timestamp.CreateRequest(t.Context(), []byte("same imprint and nonce"), timestamp.RequestOptions{Policy: policy(), Nonce: bytes.Repeat([]byte{0x5a}, 16), OmitCertificates: index == 1})
		if err != nil {
			t.Fatal(err)
		}
	}
	proof := pki.Evidence{CRLs: [][]byte{testcert.CRL(t, chain)}}
	for responseIndex, source := range requests {
		raw, err := timestamp.IssueResponse(t.Context(), source.DER(), chain.TSAKey, chain.TSA.Raw, timestamp.IssueOptions{Policy: policy(), SerialNumber: big.NewInt(31), GenTime: testcert.Now()})
		if err != nil {
			t.Fatal(err)
		}
		parsed, err := timestamp.ParseResponse(t.Context(), raw)
		if err != nil {
			t.Fatal(err)
		}
		want := timestamp.Expectation{Imprint: source.Imprint(), Nonce: source.Nonce(), Policy: source.Policy()}
		if result, err := verifier.VerifyToken(t.Context(), parsed.TokenDER(), want, testcert.Now(), proof); result == nil || err != nil {
			t.Fatal("control token must have valid cryptography, bindings and TSA trust", err)
		}
		for requestIndex, expected := range requests {
			result, err := verifier.VerifyResponse(t.Context(), raw, expected, testcert.Now(), proof)
			if requestIndex == responseIndex {
				if result == nil || err != nil {
					t.Fatal("matching certReq rejected", requestIndex, err)
				}
			} else if result != nil || !errors.Is(err, timestamp.ErrBinding) {
				t.Fatal("same nonce/imprint hid incorrect certificate response policy", requestIndex, responseIndex, err)
			}
		}
	}
}

func TestTimestampAccuracyAndClockBoundaries(t *testing.T) {
	chain := testcert.New(t)
	now := testcert.Now()
	zero, exact, excessive := time.Duration(0), time.Millisecond, time.Millisecond+time.Microsecond
	request, err := timestamp.CreateRequest(t.Context(), []byte("bounded timestamp"), timestamp.RequestOptions{Policy: policy()})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name     string
		gen      time.Time
		accuracy *time.Duration
		require  bool
		maximum  time.Duration
		pass     bool
	}{
		{"required accuracy missing", now, nil, true, 0, false},
		{"accuracy limit does not imply presence", now, nil, false, exact, true},
		{"explicit zero accuracy", now, &zero, true, exact, true},
		{"exact accuracy limit", now, &exact, true, exact, true},
		{"accuracy above limit", now, &excessive, true, exact, false},
		{"future clock boundary", now.Add(30 * time.Second), &exact, true, exact, true},
		{"future clock boundary exceeded", now.Add(30*time.Second + time.Microsecond), &exact, true, exact, false},
		{"oldest accepted token", now.Add(-90 * time.Second), &exact, true, exact, true},
		{"token older by one microsecond", now.Add(-90*time.Second - time.Microsecond), &exact, true, exact, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw, err := timestamp.IssueResponse(t.Context(), request.DER(), chain.TSAKey, chain.TSA.Raw, timestamp.IssueOptions{Policy: policy(), SerialNumber: big.NewInt(32), GenTime: tc.gen, Accuracy: tc.accuracy})
			if err != nil {
				t.Fatal("valid issued control rejected", err)
			}
			verifier, err := timestamp.NewVerifier(timestamp.Config{PKI: pki.Config{Roots: [][]byte{chain.Root.Raw}, Revocation: pki.RequireCRL}, AllowedPolicies: []asn1.ObjectIdentifier{policy()}, RequireAccuracy: tc.require, MaxAccuracy: tc.maximum, MaxAge: time.Minute, ClockSkew: 30 * time.Second})
			if err != nil {
				t.Fatal(err)
			}
			result, err := verifier.VerifyResponse(t.Context(), raw, request, now, pki.Evidence{CRLs: [][]byte{testcert.CRL(t, chain)}})
			if !tc.pass {
				if result != nil || !errors.Is(err, timestamp.ErrPolicy) {
					t.Fatal("time or accuracy policy bypassed", result != nil, err)
				}
				return
			}
			if result == nil || err != nil || !result.Info().GenTime().Equal(tc.gen) {
				t.Fatal("valid boundary timestamp lost its original generation time", err)
			}
			accuracy, present := result.Info().Accuracy()
			if present != (tc.accuracy != nil) || tc.accuracy != nil && accuracy != *tc.accuracy {
				t.Fatal("accuracy presence or precision changed", accuracy, present)
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
	if _, e := timestamp.IssueResponse(t.Context(), q.DER(), c.LeafKey, c.Leaf.Raw, o); !errors.Is(e, timestamp.ErrTrust) {
		t.Fatal("wrong EKU", e)
	}

	weak := *c.TSA
	weak.Raw = nil
	weak.SerialNumber = big.NewInt(11)
	weak.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping}
	weak.ExtraExtensions = nil
	weak.Extensions = nil

	crt := testcert.Issue(t, &weak, c.Root, &c.TSAKey.PublicKey, c.RootKey)
	if _, e := timestamp.IssueResponse(t.Context(), q.DER(), c.TSAKey, crt.Raw, o); !errors.Is(e, timestamp.ErrTrust) {
		t.Fatal("noncritical EKU", e)
	}

	o.Policy = asn1.ObjectIdentifier{1, 2, 3}
	if _, e := timestamp.IssueResponse(t.Context(), q.DER(), c.TSAKey, c.TSA.Raw, o); !errors.Is(e, timestamp.ErrBinding) {
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

	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	v := verifier(t, testcert.New(t))
	if _, e = v.VerifyToken(ctx, nil, timestamp.Expectation{Imprint: q.Imprint()}, testcert.Now(), pki.Evidence{}); !errors.Is(e, context.Canceled) {
		t.Fatal(e)
	}
}

func TestResponseStatusSchemaAndDiagnostics(t *testing.T) {
	t.Parallel()
	text := der.Seq(der.Wrap(0, asn1.TagUTF8String, false, []byte("untrusted TSA explanation")))
	bits := func(positions ...int) []byte {
		t.Helper()
		var value asn1.BitString
		for _, p := range positions {
			value.BitLength = max(value.BitLength, p+1)
		}
		value.Bytes = make([]byte, (value.BitLength+7)/8)
		for _, p := range positions {
			value.Bytes[p/8] |= 1 << (7 - p%8)
		}
		raw, err := asn1.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	for _, status := range []int{2, 3, 4, 5} {
		raw := der.Seq(der.Seq(der.Int(status), text, bits(0, 2, 5, 14, 15, 16, 17, 25)))
		response, err := timestamp.ParseResponse(t.Context(), raw)
		var detail *timestamp.ResponseError
		if response == nil || response.Status() != status || len(response.TokenDER()) != 0 || !errors.As(err, &detail) || detail.Status != status || !slices.Equal(detail.Text, []string{"untrusted TSA explanation"}) || !slices.Equal(detail.FailureBits, []int{0, 2, 5, 14, 15, 16, 17, 25}) {
			t.Fatalf("status %d: %+v, %v", status, response, err)
		}
		response.DER()[0] ^= 1
		if !bytes.Equal(response.DER(), raw) {
			t.Fatal("response getter exposed owned encoding")
		}
	}
	for _, tc := range []struct {
		name string
		raw  []byte
	}{
		{"negative status", der.Seq(der.Seq(der.Int(-1)))},
		{"unknown status", der.Seq(der.Seq(der.Int(6)))},
		{"wrong status type", der.Seq(der.Seq(der.Octets([]byte{2})))},
		{"empty status text", der.Seq(der.Seq(der.Int(2), der.Seq()))},
		{"wrong status text type", der.Seq(der.Seq(der.Int(2), der.Seq(der.Octets([]byte("text")))))},
		{"oversized status text", der.Seq(der.Seq(der.Int(2), der.Seq(der.Wrap(0, asn1.TagUTF8String, false, bytes.Repeat([]byte{'x'}, 4097)))))},
		{"unknown failure bit", der.Seq(der.Seq(der.Int(2), bits(1)))},
		{"failure bit past bound", der.Seq(der.Seq(der.Int(2), bits(26)))},
		{"trailing status field", der.Seq(der.Seq(der.Int(2), bits(0), der.Int(1)))},
		{"granted without token", der.Seq(der.Seq(der.Int(0)))},
		{"modified grant without token", der.Seq(der.Seq(der.Int(1)))},
		{"granted with failure", der.Seq(der.Seq(der.Int(0), bits(0)), der.Seq())},
		{"rejected with token", der.Seq(der.Seq(der.Int(2)), der.Seq())},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if response, err := timestamp.ParseResponse(t.Context(), tc.raw); response != nil || !errors.Is(err, timestamp.ErrFormat) {
				t.Fatalf("malformed status: %v, %v", response, err)
			}
		})
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
	if r, e := v.Fetch(t.Context(), transport{b: b}, q, testcert.Now(), pki.Evidence{}); r != nil || !errors.Is(e, timestamp.ErrPolicy) || !b.closed {
		t.Fatal(e)
	}

	b = &body{Reader: bytes.NewReader(nil), closeErr: io.ErrClosedPipe}
	if r, e := v.Fetch(t.Context(), transport{b: b}, q, testcert.Now(), pki.Evidence{}); r != nil || !errors.Is(e, io.ErrClosedPipe) || !b.closed {
		t.Fatal(e)
	}

	if r, e := v.Fetch(t.Context(), transport{}, q, testcert.Now(), pki.Evidence{}); r != nil || !errors.Is(e, timestamp.ErrFormat) {
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

			result, err := tc.v.Fetch(t.Context(), tr, tc.q, tc.at, pki.Evidence{})
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
	ctx := t.Context()

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

func TestVerifiedTimestampAssertion(t *testing.T) {
	for _, empty := range []*timestamp.VerifiedAssertion{nil, new(timestamp.VerifiedAssertion)} {
		if empty.Valid() || empty.TokenSHA256() != "" || empty.TSACertificateSHA256() != "" || empty.Trust() != nil || !empty.GenTime().IsZero() || !empty.ValidationTime().IsZero() || empty.Policy() != nil || len(empty.Imprint().Digest) != 0 {
			t.Fatal("caller-created timestamp fact was authenticated")
		}
	}
	chain := testcert.New(t)
	request, err := timestamp.CreateRequest(t.Context(), []byte("assertion binding"), timestamp.RequestOptions{Policy: policy()})
	if err != nil {
		t.Fatal(err)
	}
	generation := testcert.Now().Add(-time.Second)
	accuracy := 1500 * time.Millisecond
	raw, err := timestamp.IssueResponse(t.Context(), request.DER(), chain.TSAKey, chain.TSA.Raw, timestamp.IssueOptions{Policy: policy(), SerialNumber: big.NewInt(18), GenTime: generation, Accuracy: &accuracy, Ordering: true})
	if err != nil {
		t.Fatal(err)
	}
	checker := verifier(t, chain)
	result, err := checker.VerifyResponse(t.Context(), raw, request, testcert.Now(), pki.Evidence{CRLs: [][]byte{testcert.CRL(t, chain)}})
	if err != nil {
		t.Fatal(err)
	}
	records := result.Evidence()
	if len(records) != 1 || records[0].AuthenticationStatus() != pki.Valid {
		t.Fatal("timestamp lost authenticated chain evidence", len(records))
	}
	records[0] = nil
	if result.Evidence()[0] == nil {
		t.Fatal("mutable timestamp evidence slice")
	}
	fact := result.Assertion()
	if value, present := fact.Accuracy(); !present || value != accuracy || !fact.Ordering() {
		t.Fatal("timestamp accuracy/ordering lost from authenticated assertion")
	}
	token := sha256.Sum256(result.TokenDER())
	tsa := sha256.Sum256(chain.TSA.Raw)
	if !fact.Valid() || fact.TokenSHA256() != hex.EncodeToString(token[:]) || fact.TSACertificateSHA256() != hex.EncodeToString(tsa[:]) || fact.GenTime() != generation || fact.ValidationTime() != testcert.Now() || fact.Trust() != result.Trust() || !fact.Policy().Equal(policy()) || !bytes.Equal(fact.Imprint().Digest, request.Imprint().Digest) {
		t.Fatal("authenticated timestamp fact bindings")
	}
	imprint := fact.Imprint()
	imprint.Digest[0] ^= 1
	oid := fact.Policy()
	oid[0] ^= 1
	if !bytes.Equal(fact.Imprint().Digest, request.Imprint().Digest) || !fact.Policy().Equal(policy()) {
		t.Fatal("mutable timestamp assertion getter")
	}
	changed, err := timestamp.CreateRequest(t.Context(), []byte("other bytes"), timestamp.RequestOptions{Policy: policy()})
	if err != nil {
		t.Fatal(err)
	}
	if rejected, err := checker.VerifyResponse(t.Context(), raw, changed, testcert.Now(), pki.Evidence{CRLs: [][]byte{testcert.CRL(t, chain)}}); rejected != nil || !errors.Is(err, timestamp.ErrBinding) {
		t.Fatal("bad imprint minted assertion", err)
	}
	var absent *timestamp.Result
	if absent.Assertion() != nil || absent.Evidence() != nil {
		t.Fatal("nil result yielded an assertion")
	}
}

func TestTimestampSemanticDirectoryName(t *testing.T) {
	chain := testcert.New(t)
	request, err := timestamp.CreateRequest(t.Context(), []byte("TSA name binding"), timestamp.RequestOptions{Policy: policy()})
	if err != nil {
		t.Fatal(err)
	}
	response, err := timestamp.IssueResponse(t.Context(), request.DER(), chain.TSAKey, chain.TSA.Raw, timestamp.IssueOptions{Policy: policy(), SerialNumber: big.NewInt(39), GenTime: testcert.Now(), OmitTSAName: true})
	if err != nil {
		t.Fatal(err)
	}
	parsedResponse, err := timestamp.ParseResponse(t.Context(), response)
	if err != nil {
		t.Fatal(err)
	}
	container, err := cms.Parse(t.Context(), parsedResponse.TokenDER(), cms.Limits{})
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
	for _, wrong := range []bool{false, true} {
		t.Run(strconv.FormatBool(wrong), func(t *testing.T) {
			value := " TEST  TSA "
			if wrong {
				value = "unrelated"
			}
			name, _ := asn1.Marshal(pkix.RDNSequence{{{Type: asn1.ObjectIdentifier{2, 5, 4, 3}, Value: asn1.RawValue{Tag: asn1.TagUTF8String, Bytes: []byte(value)}}}})
			parts := make([][]byte, 0, len(fields)+1)
			for _, field := range fields {
				parts = append(parts, field.FullBytes)
			}
			parts = append(parts, der.Ctx(0, der.Ctx(4, name)))
			token, err := cms.Sign(t.Context(), der.Seq(parts...), []cms.Signer{{Key: chain.TSAKey, CertificateDER: chain.TSA.Raw}}, cms.SignOptions{ContentType: timestamp.TSTInfoOID()})
			if err != nil {
				t.Fatal(err)
			}
			result, err := verifier(t, chain).VerifyToken(t.Context(), token, timestamp.Expectation{Imprint: request.Imprint(), Nonce: request.Nonce(), Policy: request.Policy()}, testcert.Now(), pki.Evidence{CRLs: [][]byte{testcert.CRL(t, chain)}})
			if wrong {
				if result != nil || !errors.Is(err, timestamp.ErrTrust) {
					t.Fatal("unrelated TSA name accepted", err)
				}
			} else if result == nil || err != nil || !result.Assertion().Valid() {
				t.Fatal("equivalent TSA name rejected", err)
			}
		})
	}
}

func TestTimestampTSAAlternativeNameBindings(t *testing.T) {
	chain := testcert.New(t)
	template := *chain.TSA
	template.DNSNames = []string{"tsa.example.test"}
	template.EmailAddresses = []string{"tsa@example.test"}
	template.URIs = []*url.URL{{Scheme: "https", Host: "tsa.example.test", Path: "/stamp"}}
	template.IPAddresses = []net.IP{{192, 0, 2, 1}, {0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}}
	for _, extension := range chain.TSA.Extensions {
		if extension.Id.Equal(asn1.ObjectIdentifier{2, 5, 29, 37}) {
			template.ExtraExtensions = append(template.ExtraExtensions, extension)
		}
	}
	chain.TSA = testcert.Issue(t, &template, chain.Root, chain.TSAKey.Public(), chain.RootKey)
	request, err := timestamp.CreateRequest(t.Context(), []byte("named TSA"), timestamp.RequestOptions{Policy: policy()})
	if err != nil {
		t.Fatal(err)
	}
	response, err := timestamp.IssueResponse(t.Context(), request.DER(), chain.TSAKey, chain.TSA.Raw, timestamp.IssueOptions{Policy: policy(), SerialNumber: big.NewInt(39), GenTime: testcert.Now(), OmitTSAName: true})
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := timestamp.ParseResponse(t.Context(), response)
	if err != nil {
		t.Fatal(err)
	}
	container, err := cms.Parse(t.Context(), parsed.TokenDER(), cms.Limits{})
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
	v := verifier(t, chain)
	evidence := pki.Evidence{CRLs: [][]byte{testcert.CRL(t, chain)}}
	for _, tc := range []struct {
		name string
		tag  int
		body []byte
		want error
	}{
		{"email", 1, []byte("tsa@example.test"), nil},
		{"wrong email", 1, []byte("other@example.test"), timestamp.ErrTrust},
		{"DNS", 2, []byte("tsa.example.test"), nil},
		{"wrong DNS", 2, []byte("other.example.test"), timestamp.ErrTrust},
		{"URI", 6, []byte("https://tsa.example.test/stamp"), nil},
		{"wrong URI path", 6, []byte("https://tsa.example.test/other"), timestamp.ErrTrust},
		{"IPv4", 7, []byte{192, 0, 2, 1}, nil},
		{"IPv6", 7, []byte{0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}, nil},
		{"wrong IP", 7, []byte{192, 0, 2, 2}, timestamp.ErrTrust},
		{"invalid IP size", 7, []byte{192, 0, 2}, timestamp.ErrFormat},
		{"unsupported name kind", 8, []byte{42, 3}, timestamp.ErrFormat},
	} {
		t.Run(tc.name, func(t *testing.T) {
			parts := make([][]byte, 0, len(fields)+1)
			for _, field := range fields {
				parts = append(parts, field.FullBytes)
			}
			parts = append(parts, der.Ctx(0, der.Wrap(2, tc.tag, false, tc.body)))
			token, err := cms.Sign(t.Context(), der.Seq(parts...), []cms.Signer{{Key: chain.TSAKey, CertificateDER: chain.TSA.Raw}}, cms.SignOptions{ContentType: timestamp.TSTInfoOID()})
			if err != nil {
				t.Fatal(err)
			}
			result, err := v.VerifyToken(t.Context(), token, timestamp.Expectation{Imprint: request.Imprint(), Nonce: request.Nonce(), Policy: request.Policy()}, testcert.Now(), evidence)
			if tc.want != nil {
				if result != nil || !errors.Is(err, tc.want) {
					t.Fatalf("TSA binding returned %v, %v; want %v", result != nil, err, tc.want)
				}
			} else if result == nil || err != nil || !result.Assertion().Valid() {
				t.Fatal("matching TSA alternative name rejected", err)
			}
		})
	}
}

func TestTimestampExactSourceBindings(t *testing.T) {
	chain := testcert.New(t)
	request, err := timestamp.CreateRequest(t.Context(), []byte("observed timestamp"), timestamp.RequestOptions{Policy: policy()})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := timestamp.IssueResponse(t.Context(), request.DER(), chain.TSAKey, chain.TSA.Raw, timestamp.IssueOptions{Policy: policy(), SerialNumber: big.NewInt(41), GenTime: testcert.Now()})
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := timestamp.ParseResponse(t.Context(), raw)
	if err != nil {
		t.Fatal(err)
	}
	responseSource, err := evidence.NewObservation(t.Context(), evidence.Timestamp, raw, evidence.Provenance{URI: "https://example.test/tsa", RetrievedAt: testcert.Now().Add(24 * time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	tokenSource, err := evidence.NewObservation(t.Context(), evidence.Timestamp, parsed.TokenDER(), evidence.Provenance{})
	if err != nil {
		t.Fatal(err)
	}
	crl := testcert.CRL(t, chain)
	crlSource, err := evidence.NewObservation(t.Context(), evidence.CRL, crl, evidence.Provenance{})
	if err != nil {
		t.Fatal(err)
	}
	input := pki.Evidence{CRLs: [][]byte{crl}, Sources: []*evidence.Observation{responseSource, tokenSource, crlSource}}
	result, err := verifier(t, chain).VerifyResponseReader(t.Context(), bytes.NewReader(raw), request, testcert.Now(), input)
	if err != nil || result == nil {
		t.Fatal(err)
	}
	sources := result.Assertion().Sources()
	if len(sources) != 2 || sources[0] != responseSource || sources[1] != tokenSource || result.Assertion().GenTime() != testcert.Now() || result.Assertion().ValidationTime() != testcert.Now() || len(result.Evidence()[0].Sources()) != 1 {
		t.Fatal("source binding confused acquisition and trusted time")
	}
	sources[0] = nil
	if result.Assertion().Sources()[0] == nil {
		t.Fatal("mutable assertion provenance")
	}
	want := timestamp.Expectation{Imprint: request.Imprint(), Nonce: request.Nonce(), Policy: request.Policy()}
	input.Sources = []*evidence.Observation{tokenSource, crlSource}
	if verified, err := verifier(t, chain).VerifyToken(t.Context(), parsed.TokenDER(), want, testcert.Now(), input); err != nil || verified == nil || len(verified.Assertion().Sources()) != 1 {
		t.Fatal("exact token observation rejected", err)
	}
	wrongSource, err := evidence.NewObservation(t.Context(), evidence.Timestamp, []byte("different"), evidence.Provenance{})
	if err != nil {
		t.Fatal(err)
	}
	for _, source := range []*evidence.Observation{nil, {}, wrongSource, responseSource} {
		input.Sources = []*evidence.Observation{source}
		if verified, err := verifier(t, chain).VerifyToken(t.Context(), parsed.TokenDER(), want, testcert.Now(), input); verified != nil || !errors.Is(err, timestamp.ErrBinding) {
			t.Fatal("unmatched/invalid source returned assertion", err)
		}
	}
	bounded, err := timestamp.NewVerifier(timestamp.Config{PKI: pki.Config{Roots: [][]byte{chain.Root.Raw}, Revocation: pki.RequireCRL}, AllowedPolicies: []asn1.ObjectIdentifier{policy()}, Certificates: [][]byte{chain.TSA.Raw}, MaxBytes: len(raw)})
	if err != nil {
		t.Fatal(err)
	}
	input.Sources = []*evidence.Observation{responseSource, tokenSource}
	if verified, err := bounded.VerifyResponse(t.Context(), raw, request, testcert.Now(), input); verified != nil || !errors.Is(err, timestamp.ErrPolicy) {
		t.Fatal("aggregate source byte bound ignored", err)
	}
}

func TestTimestampRejectsUnevaluatedESSPathRestrictions(t *testing.T) {
	chain := testcert.New(t)
	request, err := timestamp.CreateRequest(t.Context(), []byte("restricted TSA path"), timestamp.RequestOptions{Policy: policy()})
	if err != nil {
		t.Fatal(err)
	}
	response, err := timestamp.IssueResponse(t.Context(), request.DER(), chain.TSAKey, chain.TSA.Raw, timestamp.IssueOptions{Policy: policy(), SerialNumber: big.NewInt(42), GenTime: testcert.Now()})
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := timestamp.ParseResponse(t.Context(), response)
	if err != nil {
		t.Fatal(err)
	}
	token := timestampDuplicateESSID(t, parsed.TokenDER(), chain.TSAKey)
	cryptoOnly, err := cms.Parse(t.Context(), token, cms.Limits{})
	if err != nil {
		t.Fatal(err)
	}
	if result, err := cryptoOnly.Verify(t.Context(), [][]byte{chain.TSA.Raw}, cms.VerifyOptions{ExpectedContentType: timestamp.TSTInfoOID(), RequireCertificateBinding: true}); err != nil || result == nil {
		t.Fatal("re-signed first-certificate binding invalid", err)
	}
	want := timestamp.Expectation{Imprint: request.Imprint(), Nonce: request.Nonce(), Policy: request.Policy()}
	if result, err := verifier(t, chain).VerifyToken(t.Context(), token, want, testcert.Now(), pki.Evidence{CRLs: [][]byte{testcert.CRL(t, chain)}}); result != nil || !errors.Is(err, cms.ErrUnsupported) {
		t.Fatal("unsupported ESS path restriction returned trusted assertion", err)
	}
}

func timestampDuplicateESSID(t *testing.T, raw []byte, key crypto.Signer, variant ...string) []byte {
	t.Helper()
	outer, _ := der.Read(raw, len(raw))
	ci, _ := der.Sequence(outer, 2, 2)
	content, _ := der.Explicit(ci[1], 0)
	sd, _ := der.Sequence(content, 4, 6)
	signers, _ := der.SetFields(sd[len(sd)-1], 0, asn1.TagSet, 1)
	signer, _ := der.Sequence(signers[0], 6, 6)
	attributes, _ := der.Children(signer[3])
	attrs := make([][]byte, 0, len(attributes))
	for _, value := range attributes {
		attribute, _ := der.Sequence(value, 2, 2)
		var oid asn1.ObjectIdentifier
		if der.Decode(attribute[0], &oid) != nil {
			t.Fatal("attribute OID")
		}
		if oid.Equal(asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 2, 47}) {
			values, _ := der.SetFields(attribute[1], 0, asn1.TagSet, 1)
			top, _ := der.Sequence(values[0], 1, 2)
			ids, _ := der.Sequence(top[0], 1, 1)
			if len(variant) == 0 {
				attrs = append(attrs, der.Seq(attribute[0].FullBytes, der.Set(der.Seq(der.Seq(ids[0].FullBytes, ids[0].FullBytes)))))
			} else {
				id, _ := der.Sequence(ids[0], 2, 2)
				issuer, _ := der.Sequence(id[1], 2, 2)
				names, _ := der.Sequence(issuer[0], 1, 1)
				extra := der.Wrap(2, 6, false, []byte("https://unrelated.test/"))
				if variant[0] == "directoryName" {
					extra = names[0].FullBytes
				}
				changed := der.Seq(id[0].FullBytes, der.Seq(der.Seq(names[0].FullBytes, extra), issuer[1].FullBytes))
				attrs = append(attrs, der.Seq(attribute[0].FullBytes, der.Set(der.Seq(der.Seq(changed)))))
			}
		} else {
			attrs = append(attrs, value.FullBytes)
		}
	}
	set := der.Set(attrs...)
	signedAttrs, _ := der.Read(set, len(set))
	parts := make([][]byte, len(signer))
	for i := range signer {
		parts[i] = signer[i].FullBytes
	}
	parts[3] = der.Wrap(2, 0, true, signedAttrs.Bytes)
	algorithm, err := signature.Algorithm(signer[4])
	if err != nil {
		t.Fatal(err)
	}
	signed, err := signature.Sign(t.Context(), key, algorithm, set)
	if err != nil {
		t.Fatal(err)
	}
	parts[5] = der.Octets(signed)
	sdParts := make([][]byte, len(sd))
	for i := range sd {
		sdParts[i] = sd[i].FullBytes
	}
	sdParts[len(sdParts)-1] = der.Set(der.Seq(parts...))
	return der.Seq(ci[0].FullBytes, der.Ctx(0, der.Seq(sdParts...)))
}

func TestTimestampRejectsExplicitDefaultFields(t *testing.T) {
	c := testcert.New(t)
	request, err := timestamp.CreateRequest(t.Context(), []byte("DER defaults"), timestamp.RequestOptions{Policy: policy(), OmitNonce: true, OmitCertificates: true})
	if err != nil {
		t.Fatal(err)
	}
	value, _ := der.Read(request.DER(), 1<<16)
	fields, _ := der.Sequence(value, 2, 4)
	parts := make([][]byte, len(fields), len(fields)+1)
	for i := range fields {
		parts[i] = fields[i].FullBytes
	}
	parts = append(parts, []byte{1, 1, 0})
	if changed, err := timestamp.ParseRequest(der.Seq(parts...)); changed != nil || !errors.Is(err, timestamp.ErrFormat) {
		t.Fatal("certReq DEFAULT FALSE accepted", err)
	}
	raw, err := timestamp.IssueResponse(t.Context(), request.DER(), c.TSAKey, c.TSA.Raw, timestamp.IssueOptions{Policy: policy(), SerialNumber: big.NewInt(44), GenTime: testcert.Now(), OmitTSAName: true})
	if err != nil {
		t.Fatal(err)
	}
	response, err := timestamp.ParseResponse(t.Context(), raw)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := cms.Parse(t.Context(), response.TokenDER(), cms.Limits{})
	if err != nil {
		t.Fatal(err)
	}
	info, _ := der.Read(signed.UnverifiedContent(), 1<<20)
	required, _ := der.Sequence(info, 5, 5)
	for _, name := range []string{"ordering", "extension critical"} {
		t.Run(name, func(t *testing.T) {
			fields := make([][]byte, len(required))
			for i := range required {
				fields[i] = required[i].FullBytes
			}
			if name == "ordering" {
				fields = append(fields, []byte{1, 1, 0})
			} else {
				fields = append(fields, der.Ctx(1, der.Seq(der.OID(asn1.ObjectIdentifier{1, 2, 3, 4, 5}), []byte{1, 1, 0}, der.Octets([]byte{5, 0}))))
			}
			token, err := cms.Sign(t.Context(), der.Seq(fields...), []cms.Signer{{Key: c.TSAKey, CertificateDER: c.TSA.Raw}}, cms.SignOptions{ContentType: timestamp.TSTInfoOID()})
			if err != nil {
				t.Fatal(err)
			}
			if parsed, err := timestamp.ParseToken(t.Context(), token); parsed != nil || !errors.Is(err, timestamp.ErrFormat) {
				t.Fatal("re-signed explicit FALSE DEFAULT accepted", err)
			}
		})
	}
}

func TestTimestampRejectsAdditionalESSIssuerNames(t *testing.T) {
	c := testcert.New(t)
	request, err := timestamp.CreateRequest(t.Context(), []byte("ESS issuer only"), timestamp.RequestOptions{Policy: policy()})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := timestamp.IssueResponse(t.Context(), request.DER(), c.TSAKey, c.TSA.Raw, timestamp.IssueOptions{Policy: policy(), SerialNumber: big.NewInt(45), GenTime: testcert.Now()})
	if err != nil {
		t.Fatal(err)
	}
	response, err := timestamp.ParseResponse(t.Context(), raw)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"URI", "directoryName"} {
		t.Run(name, func(t *testing.T) {
			token := timestampDuplicateESSID(t, response.TokenDER(), c.TSAKey, name)
			want := timestamp.Expectation{Imprint: request.Imprint(), Nonce: request.Nonce(), Policy: request.Policy()}
			result, err := verifier(t, c).VerifyToken(t.Context(), token, want, testcert.Now(), pki.Evidence{CRLs: [][]byte{testcert.CRL(t, c)}})
			if result != nil || !errors.Is(err, cms.ErrCertificate) {
				t.Fatal("additional ESS issuer names returned a timestamp assertion", err)
			}
		})
	}
}

func TestTimestampRejectsSchemaInvalidCertificate(t *testing.T) {
	c := testcert.New(t)
	value, _ := der.Read(c.TSA.Raw, len(c.TSA.Raw))
	outer, _ := der.Sequence(value, 3, 3)
	fields, _ := der.Sequence(outer[0], 7, 10)
	extensions, _ := der.Explicit(fields[len(fields)-1], 3)
	values, _ := der.Sequence(extensions, 1, 32)
	encoded := make([][]byte, len(values))
	changed := false
	for i, extension := range values {
		f, _ := der.Sequence(extension, 2, 3)
		encoded[i] = extension.FullBytes
		if len(f) == 2 && !changed {
			encoded[i] = der.Seq(f[0].FullBytes, []byte{1, 1, 0}, f[1].FullBytes)
			changed = true
		}
	}
	if !changed {
		t.Fatal("no omitted critical FALSE")
	}
	parts := make([][]byte, len(fields))
	for i := range fields {
		parts[i] = fields[i].FullBytes
	}
	parts[len(parts)-1] = der.Ctx(3, der.Seq(encoded...))
	tbs := der.Seq(parts...)
	algorithm, _ := signature.Algorithm(outer[1])
	signed, err := signature.Sign(t.Context(), c.RootKey, algorithm, tbs)
	if err != nil {
		t.Fatal(err)
	}
	bits, _ := asn1.Marshal(asn1.BitString{Bytes: signed, BitLength: len(signed) * 8})
	certificate := der.Seq(tbs, outer[1].FullBytes, bits)
	request, err := timestamp.CreateRequest(t.Context(), nil, timestamp.RequestOptions{Policy: policy()})
	if err != nil {
		t.Fatal(err)
	}
	if raw, err := timestamp.IssueResponse(t.Context(), request.DER(), c.TSAKey, certificate, timestamp.IssueOptions{Policy: policy(), SerialNumber: big.NewInt(46), GenTime: testcert.Now()}); raw != nil || !errors.Is(err, timestamp.ErrTrust) {
		t.Fatal("schema-invalid TSA certificate accepted", err)
	}
	if v, err := timestamp.NewVerifier(timestamp.Config{PKI: pki.Config{Roots: [][]byte{c.Root.Raw}, Revocation: pki.RequireCRL}, AllowedPolicies: []asn1.ObjectIdentifier{policy()}, Certificates: [][]byte{certificate}}); v != nil || !errors.Is(err, timestamp.ErrPolicy) {
		t.Fatal("schema-invalid lookup certificate accepted", err)
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
	if result, e := v.VerifyResponse(f.Context(), raw, q, fixture.At, evidence); e != nil || result == nil {
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

		result, e := v.VerifyResponse(t.Context(), b, q, fixture.At, evidence)
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

	raw, err := timestamp.IssueResponse(b.Context(), q.DER(), c.TSAKey, c.TSA.Raw, timestamp.IssueOptions{Policy: policy(), SerialNumber: big.NewInt(10), GenTime: testcert.Now().Add(-time.Second)})
	if err != nil {
		b.Fatal(err)
	}

	e := pki.Evidence{CRLs: [][]byte{testcert.CRL(b, c)}}
	b.ReportAllocs()

	for b.Loop() {
		if _, err := v.VerifyResponse(b.Context(), raw, q, testcert.Now(), e); err != nil {
			b.Fatal(err)
		}
	}
}
