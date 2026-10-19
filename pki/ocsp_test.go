package pki_test

import (
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"io"
	"math/big"
	"runtime"
	"testing"
	"time"

	"github.com/skarm/xmlsec/internal/testutil/testcert"
	"github.com/skarm/xmlsec/pki"
)

func TestOCSPRoundTripAndFailures(t *testing.T) {
	c := testcert.New(t)
	n := bytes.Repeat([]byte{42}, 32)

	req, e := pki.CreateOCSPRequest(c.Leaf.Raw, c.Root.Raw, crypto.SHA256, n)
	if e != nil {
		t.Fatal(e)
	}

	r, e := pki.ParseOCSPRequest(req)
	if e != nil || !bytes.Equal(r.Nonce(), n) || r.Hash() != crypto.SHA256 {
		t.Fatal(e)
	}

	r.Nonce()[0] ^= 1
	if !bytes.Equal(r.Nonce(), n) {
		t.Fatal("mutable")
	}

	good, e := pki.CreateOCSPResponse(context.Background(), req, c.Leaf.Raw, c.Root.Raw, c.Root.Raw, c.RootKey, ocspTemplate())
	if e != nil {
		t.Fatal(e)
	}

	for _, tc := range []struct {
		name            string
		at              time.Time
		nonce, response []byte
		want            error
	}{{"good", testcert.Now(), n, good, nil}, {"no nonce expectation", testcert.Now(), nil, good, nil}, {"wrong nonce", testcert.Now(), []byte("other"), good, pki.ErrEvidence}, {"future", testcert.Now().Add(-time.Minute), n, good, pki.ErrUnavailable}, {"stale", testcert.Now().Add(2 * time.Minute), n, good, pki.ErrUnavailable}, {"truncated", testcert.Now(), n, good[:len(good)-1], pki.ErrEvidence}, {"trailing", testcert.Now(), n, append(bytes.Clone(good), 0), pki.ErrEvidence}} {
		t.Run(tc.name, func(t *testing.T) { testOCSPRoundTripAndFailuresCase(t, &tc, &c) })
	}

	v, e := pki.NewVerifier(pki.Config{Roots: [][]byte{c.Root.Raw}, Revocation: pki.RequireOCSP})
	if e != nil {
		t.Fatal(e)
	}

	if r, rep, e := v.Verify(context.Background(), c.Leaf.Raw, testcert.Now(), pki.Evidence{OCSPResponses: [][]byte{good}}); e != nil || r == nil || rep.Revocation != pki.Valid {
		t.Fatalf("%v %+v", e, rep)
	}

	if r, _, e := v.Verify(context.Background(), c.Leaf.Raw, testcert.Now(), pki.Evidence{}); r != nil || !errors.Is(e, pki.ErrUnavailable) {
		t.Fatal("missing evidence", e)
	}

	for _, status := range []pki.OCSPStatus{pki.OCSPUnknown, pki.OCSPRevoked} {
		tmpl := ocspTemplate()
		tmpl.Status = status
		tmpl.RevokedAt = testcert.Now().Add(-time.Minute)
		tmpl.RevocationReason = 1

		raw, e := pki.CreateOCSPResponse(context.Background(), req, c.Leaf.Raw, c.Root.Raw, c.Root.Raw, c.RootKey, tmpl)
		if e != nil {
			t.Fatal(e)
		}

		r, rep, e := pki.VerifyOCSP(context.Background(), raw, c.Leaf.Raw, c.Root.Raw, testcert.Now(), pki.OCSPOptions{})
		if r != nil || e == nil || rep.Signature != pki.Valid || rep.Status != status {
			t.Fatalf("%v %+v", e, rep)
		}

		if status == pki.OCSPRevoked {
			if r, _, e := v.Verify(context.Background(), c.Leaf.Raw, testcert.Now(), pki.Evidence{OCSPResponses: [][]byte{good, raw}}); r != nil || !errors.Is(e, pki.ErrRevoked) {
				t.Fatal("revocation hidden by GOOD", e)
			}
		}
	}
}

func testOCSPRoundTripAndFailuresCase(t *testing.T, tc *struct {
	name     string
	at       time.Time
	nonce    []byte
	response []byte
	want     error
}, c *testcert.Chain,
) {
	r, rep, e := pki.VerifyOCSP(context.Background(), tc.response, c.Leaf.Raw, c.Root.Raw, tc.at, pki.OCSPOptions{ExpectedNonce: tc.nonce})
	if tc.want == nil {
		if e != nil || r == nil || rep.Status != pki.OCSPGood || rep.Signature != pki.Valid {
			t.Fatalf("%v %+v", e, rep)
		}

		r.DER()[0] ^= 1
		if _, _, e = pki.VerifyOCSP(context.Background(), r.DER(), c.Leaf.Raw, c.Root.Raw, tc.at, pki.OCSPOptions{}); e != nil {
			t.Fatal("mutable result", e)
		}
	} else if r != nil || !errors.Is(e, tc.want) {
		t.Fatalf("want %v got %v %+v", tc.want, e, rep)
	}
}

func TestOCSPDelegation(t *testing.T) {
	c := testcert.New(t)

	req, e := pki.CreateOCSPRequest(c.Leaf.Raw, c.Root.Raw, crypto.SHA1, nil)
	if e != nil {
		t.Fatal(e)
	}

	for _, tc := range []struct {
		name              string
		eku, nocheck, crl bool
		want              error
	}{{"authorized", true, true, false, nil}, {"missing EKU", false, true, false, pki.ErrEvidence}, {"no responder revocation", true, false, false, pki.ErrUnavailable}, {"responder CRL", true, false, true, nil}} {
		t.Run(tc.name, func(t *testing.T) {
			key := testcert.Key(t)

			ct := &x509.Certificate{SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: "responder"}, NotBefore: testcert.Now().Add(-time.Hour), NotAfter: testcert.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature}
			if tc.eku {
				ct.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageOCSPSigning}
			}

			if tc.nocheck {
				ct.ExtraExtensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1, 5}, Value: []byte{5, 0}}}
			}

			cert := testcert.Issue(t, ct, c.Root, &key.PublicKey, c.RootKey)

			raw, e := pki.CreateOCSPResponse(context.Background(), req, c.Leaf.Raw, c.Root.Raw, cert.Raw, key, ocspTemplate())
			if e != nil {
				t.Fatal(e)
			}

			o := pki.OCSPOptions{}
			if tc.crl {
				o.ResponderCRLs = [][]byte{testcert.CRL(t, c)}
			}

			r, rep, e := pki.VerifyOCSP(context.Background(), raw, c.Leaf.Raw, c.Root.Raw, testcert.Now(), o)
			if tc.want == nil {
				if e != nil || r == nil || !rep.Delegated {
					t.Fatal(e)
				}
			} else if r != nil || !errors.Is(e, tc.want) {
				t.Fatal(e)
			}
		})
	}
}

func TestOCSPNonceSizeAndCancellation(t *testing.T) {
	c := testcert.New(t)
	for _, n := range []int{0, 1, 16, 31, 32, 128, 129} {
		b, e := pki.CreateOCSPRequest(c.Leaf.Raw, c.Root.Raw, crypto.SHA256, make([]byte, n))
		if n > 0 && n < 32 || n > 128 {
			if b != nil || !errors.Is(e, pki.ErrPolicy) {
				t.Fatalf("requester nonce length %d: output=%v, error=%v", n, b != nil, e)
			}

			continue
		}

		if e != nil {
			t.Fatal(e)
		}

		if _, e = pki.ParseOCSPRequest(b); e != nil {
			t.Fatal(e)
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if _, _, e := pki.VerifyOCSP(ctx, nil, nil, nil, testcert.Now(), pki.OCSPOptions{}); !errors.Is(e, context.Canceled) {
		t.Fatal(e)
	}
}

func TestOCSPRejectsOversizedInputBeforeAllocation(t *testing.T) {
	c := testcert.New(t)
	input := make([]byte, 8<<20)

	for _, tc := range []struct {
		name string
		run  func() error
	}{
		{"request", func() error {
			result, err := pki.ParseOCSPRequest(input)
			if result != nil {
				t.Fatal("oversized request returned a result")
			}

			return err
		}},
		{"response", func() error {
			result, report, err := pki.VerifyOCSP(context.Background(), input, c.Leaf.Raw, c.Root.Raw, testcert.Now(), pki.OCSPOptions{MaxBytes: 1 << 16})
			if result != nil || report.Signature != pki.NotChecked {
				t.Fatal("oversized response was processed")
			}

			return err
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var before, after runtime.MemStats
			runtime.ReadMemStats(&before)

			err := tc.run()

			runtime.ReadMemStats(&after)

			if !errors.Is(err, pki.ErrEvidence) {
				t.Fatalf("want ErrEvidence, got %v", err)
			}

			if allocated := after.TotalAlloc - before.TotalAlloc; allocated > 1<<16 {
				t.Fatalf("oversized input allocated %d bytes before rejection", allocated)
			}
		})
	}

	runtime.KeepAlive(input)
}

func TestOCSPWorkingStorage(t *testing.T) {
	c := testcert.New(t)
	key := testcert.Key(t)
	certificate := testcert.Issue(t, &x509.Certificate{SerialNumber: big.NewInt(10), Subject: pkix.Name{CommonName: "large responder"}, NotBefore: c.Root.NotBefore, NotAfter: c.Root.NotAfter, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageOCSPSigning}, ExtraExtensions: []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1, 5}, Value: []byte{5, 0}}, {Id: asn1.ObjectIdentifier{1, 2, 3, 4}, Value: bytes.Repeat([]byte{7}, 512<<10)}}}, c.Root, key.Public(), c.RootKey)

	request, err := pki.CreateOCSPRequest(c.Leaf.Raw, c.Root.Raw, crypto.SHA256, nil)
	if err != nil {
		t.Fatal(err)
	}

	write := func(ctx context.Context, dst io.Writer) (int64, error) {
		return pki.WriteOCSPResponse(ctx, dst, request, c.Leaf.Raw, c.Root.Raw, certificate.Raw, key, ocspTemplate())
	}
	allocated := ocspAllocated(t, func() error { _, err := write(t.Context(), io.Discard); return err })
	t.Logf("OCSP writer: %d certificate bytes, %d allocated", len(certificate.Raw), allocated)

	if allocated > uint64(len(certificate.Raw))+(128<<10) {
		t.Fatal("OCSP writer copied nested certificate encodings", allocated)
	}

	allocated = ocspAllocated(t, func() error {
		_, err := pki.CreateOCSPResponse(t.Context(), request, c.Leaf.Raw, c.Root.Raw, certificate.Raw, key, ocspTemplate())
		return err
	})
	if allocated > uint64(2*len(certificate.Raw))+(128<<10) {
		t.Fatal("OCSP byte output grew intermediate buffers", allocated)
	}

	var wire bytes.Buffer
	if n, err := write(t.Context(), &wire); err != nil || n != int64(wire.Len()) {
		t.Fatal(n, err)
	}

	var result *pki.OCSPResult

	allocated = ocspAllocated(t, func() error {
		var err error

		result, _, err = pki.VerifyOCSP(t.Context(), wire.Bytes(), c.Leaf.Raw, c.Root.Raw, testcert.Now(), pki.OCSPOptions{})

		return err
	})
	t.Logf("OCSP verification: %d response bytes, %d allocated", wire.Len(), allocated)

	if allocated > uint64(wire.Len())+(128<<10) {
		t.Fatal("OCSP verification copied BasicOCSPResponse or embedded DER", allocated)
	}

	verifier, err := pki.NewVerifier(pki.Config{Roots: [][]byte{c.Root.Raw}, Revocation: pki.RequireOCSP})
	if err != nil {
		t.Fatal(err)
	}

	allocated = ocspAllocated(t, func() error {
		_, _, err := verifier.Verify(t.Context(), c.Leaf.Raw, testcert.Now(), pki.Evidence{OCSPResponses: [][]byte{wire.Bytes()}})
		return err
	})
	t.Logf("OCSP chain evidence: %d allocated", allocated)

	if allocated > 128<<10 {
		t.Fatal("chain verification copied temporary OCSP evidence", allocated)
	}

	clear(wire.Bytes())

	if !bytes.Equal(result.ResponderDER(), certificate.Raw) {
		t.Fatal("responder aliases input")
	}

	if _, _, err := pki.VerifyOCSP(t.Context(), result.DER(), c.Leaf.Raw, c.Root.Raw, testcert.Now(), pki.OCSPOptions{}); err != nil {
		t.Fatal("response aliases input", err)
	}

	failure := errors.New("write failed")
	remaining := 128

	if n, err := write(t.Context(), ocspWriteFunc(func(p []byte) (int, error) {
		n := min(len(p), remaining)

		remaining -= n
		if n < len(p) {
			return n, failure
		}

		return n, nil
	})); n != 128 || !errors.Is(err, failure) {
		t.Fatal("partial write", n, err)
	}

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	if n, err := write(ctx, ocspWriteFunc(func(p []byte) (int, error) { cancel(); return len(p), nil })); n > 32<<10 || !errors.Is(err, context.Canceled) {
		t.Fatal("writer cancellation", n, err)
	}
}

func ocspAllocated(t *testing.T, run func() error) uint64 {
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

func FuzzOCSPRequest(f *testing.F) {
	f.Add([]byte{0x30, 0})
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 1<<16 {
			t.Skip()
		}

		_, _ = pki.ParseOCSPRequest(b)
	})
}

func FuzzOCSPResponse(f *testing.F) {
	fixture := testcert.LoadFixture(f, "../testdata/evidence", "ocsp-rsa-sha256-HASH-GOOD")
	raw := fixture.Read(f, "ocsp-rsa-sha256-HASH-GOOD/response.der")
	leaf := fixture.Read(f, "ocsp-rsa-sha256-HASH-GOOD/leaf.der")
	issuer := fixture.Read(f, "ocsp-rsa-sha256-HASH-GOOD/issuer.der")
	options := pki.OCSPOptions{ExpectedNonce: fixture.Nonce}

	result, report, e := pki.VerifyOCSP(context.Background(), raw, leaf, issuer, fixture.At, options)
	if e != nil || result == nil || report.Signature != pki.Valid || report.Status != pki.OCSPGood {
		f.Fatalf("invalid positive OCSP fixture: %v %+v", e, report)
	}

	f.Add(raw)
	f.Add([]byte{0x30, 0})
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 1<<20 {
			t.Skip()
		}

		result, report, e := pki.VerifyOCSP(context.Background(), b, leaf, issuer, fixture.At, options)
		if e != nil && result != nil || e == nil && (result == nil || report.Signature != pki.Valid || report.Status != pki.OCSPGood) {
			t.Fatal("inconsistent OCSP verification result")
		}
	})
}

type ocspWriteFunc func([]byte) (int, error)

func (f ocspWriteFunc) Write(p []byte) (int, error) { return f(p) }

func ocspTemplate() pki.OCSPResponseTemplate {
	return pki.OCSPResponseTemplate{Status: pki.OCSPGood, ProducedAt: testcert.Now(), ThisUpdate: testcert.Now().Add(-time.Minute), NextUpdate: testcert.Now().Add(time.Minute)}
}
