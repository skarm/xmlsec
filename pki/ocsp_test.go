package pki_test

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
	"math/big"
	"runtime"
	"strconv"
	"testing"
	"time"

	"github.com/skarm/xmlsec/evidence"
	"github.com/skarm/xmlsec/internal/der"
	"github.com/skarm/xmlsec/internal/signature"
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

	good, e := pki.CreateOCSPResponse(t.Context(), req, c.Leaf.Raw, c.Root.Raw, c.Root.Raw, c.RootKey, ocspTemplate())
	if e != nil {
		t.Fatal(e)
	}

	for _, tc := range []struct {
		name     string
		at       time.Time
		nonce    []byte
		response []byte
		want     error
	}{{"good", testcert.Now(), n, good, nil}, {"no nonce expectation", testcert.Now(), nil, good, nil}, {"wrong nonce", testcert.Now(), []byte("other"), good, pki.ErrEvidence}, {"future", testcert.Now().Add(-time.Minute), n, good, pki.ErrUnavailable}, {"stale", testcert.Now().Add(2 * time.Minute), n, good, pki.ErrUnavailable}, {"truncated", testcert.Now(), n, good[:len(good)-1], pki.ErrEvidence}, {"trailing", testcert.Now(), n, append(bytes.Clone(good), 0), pki.ErrEvidence}} {
		t.Run(tc.name, func(t *testing.T) { testOCSPRoundTripAndFailuresCase(t, &tc, &c) })
	}

	v, e := pki.NewVerifier(pki.Config{Roots: [][]byte{c.Root.Raw}, Revocation: pki.RequireOCSP})
	if e != nil {
		t.Fatal(e)
	}

	if r, rep, e := v.Verify(t.Context(), c.Leaf.Raw, testcert.Now(), pki.Evidence{OCSPResponses: [][]byte{good}}); e != nil || r == nil || rep.Revocation != pki.Valid {
		t.Fatalf("%v %+v", e, rep)
	}

	if r, _, e := v.Verify(t.Context(), c.Leaf.Raw, testcert.Now(), pki.Evidence{}); r != nil || !errors.Is(e, pki.ErrUnavailable) {
		t.Fatal("missing evidence", e)
	}

	for _, status := range []pki.OCSPStatus{pki.OCSPUnknown, pki.OCSPRevoked} {
		tmpl := ocspTemplate()
		tmpl.Status = status
		tmpl.RevokedAt = testcert.Now().Add(-time.Minute)
		tmpl.RevocationReason = 1

		raw, e := pki.CreateOCSPResponse(t.Context(), req, c.Leaf.Raw, c.Root.Raw, c.Root.Raw, c.RootKey, tmpl)
		if e != nil {
			t.Fatal(e)
		}

		r, rep, e := pki.VerifyOCSP(t.Context(), raw, c.Leaf.Raw, c.Root.Raw, testcert.Now(), pki.OCSPOptions{})
		if r != nil || e == nil || rep.Signature != pki.Valid || rep.Status != status {
			t.Fatalf("%v %+v", e, rep)
		}

		if status == pki.OCSPRevoked {
			if r, _, e := v.Verify(t.Context(), c.Leaf.Raw, testcert.Now(), pki.Evidence{OCSPResponses: [][]byte{good, raw}}); r != nil || !errors.Is(e, pki.ErrRevoked) {
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
	r, rep, e := pki.VerifyOCSP(t.Context(), tc.response, c.Leaf.Raw, c.Root.Raw, tc.at, pki.OCSPOptions{ExpectedNonce: tc.nonce})
	if tc.want == nil {
		if e != nil || r == nil || rep.Status != pki.OCSPGood || rep.Signature != pki.Valid {
			t.Fatalf("%v %+v", e, rep)
		}

		r.DER()[0] ^= 1
		if _, _, e = pki.VerifyOCSP(t.Context(), r.DER(), c.Leaf.Raw, c.Root.Raw, tc.at, pki.OCSPOptions{}); e != nil {
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
		name    string
		eku     bool
		nocheck bool
		crl     bool
		want    error
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

			raw, e := pki.CreateOCSPResponse(t.Context(), req, c.Leaf.Raw, c.Root.Raw, cert.Raw, key, ocspTemplate())
			if e != nil {
				t.Fatal(e)
			}

			o := pki.OCSPOptions{}
			if tc.crl {
				o.ResponderCRLs = [][]byte{testcert.CRL(t, c)}
			}

			r, rep, e := pki.VerifyOCSP(t.Context(), raw, c.Leaf.Raw, c.Root.Raw, testcert.Now(), o)
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

	ctx, cancel := context.WithCancel(t.Context())
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
			result, report, err := pki.VerifyOCSP(t.Context(), input, c.Leaf.Raw, c.Root.Raw, testcert.Now(), pki.OCSPOptions{MaxBytes: 1 << 16})
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

	var chainResult *pki.Result
	allocated = ocspAllocated(t, func() error {
		var err error
		chainResult, _, err = verifier.Verify(t.Context(), c.Leaf.Raw, testcert.Now(), pki.Evidence{OCSPResponses: [][]byte{wire.Bytes()}})
		return err
	})
	t.Logf("OCSP chain evidence: %d allocated", allocated)

	// Result.Evidence now retains one immutable snapshot of the original source.
	// Repeated certificate targets must share it rather than copying nested DER.
	if allocated > uint64(wire.Len())+(128<<10) {
		t.Fatal("chain verification copied OCSP source more than once", allocated)
	}
	original := bytes.Clone(wire.Bytes())
	if len(chainResult.Evidence()) != 1 {
		t.Fatal("missing authenticated chain OCSP evidence")
	}

	clear(wire.Bytes())
	if !bytes.Equal(chainResult.Evidence()[0].DER(), original) {
		t.Fatal("chain OCSP evidence borrows caller wire")
	}

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

	result, report, e := pki.VerifyOCSP(f.Context(), raw, leaf, issuer, fixture.At, options)
	if e != nil || result == nil || report.Signature != pki.Valid || report.Status != pki.OCSPGood {
		f.Fatalf("invalid positive OCSP fixture: %v %+v", e, report)
	}

	f.Add(raw)
	f.Add([]byte{0x30, 0})
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 1<<20 {
			t.Skip()
		}

		result, report, e := pki.VerifyOCSP(t.Context(), b, leaf, issuer, fixture.At, options)
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

func TestOCSPResponderNameCandidateMustBeAuthorized(t *testing.T) {
	chain := testcert.New(t)
	key := testcert.Key(t)
	template := &x509.Certificate{SerialNumber: big.NewInt(14), Subject: chain.Root.Subject, NotBefore: testcert.Now().Add(-time.Hour), NotAfter: testcert.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageOCSPSigning}, ExtraExtensions: []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1, 5}, Value: []byte{5, 0}}}}
	responder := testcert.Issue(t, template, chain.Root, key.Public(), chain.RootKey)
	request, err := pki.CreateOCSPRequest(chain.Leaf.Raw, chain.Root.Raw, crypto.SHA256, nil)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := pki.CreateOCSPResponse(t.Context(), request, chain.Leaf.Raw, chain.Root.Raw, responder.Raw, key, ocspTemplate())
	if err != nil {
		t.Fatal(err)
	}
	result, report, err := pki.VerifyOCSP(t.Context(), raw, chain.Leaf.Raw, chain.Root.Raw, testcert.Now(), pki.OCSPOptions{})
	if err != nil || result == nil || !report.Delegated || !bytes.Equal(result.ResponderDER(), responder.Raw) {
		t.Fatal("non-signing same-name issuer poisoned responder selection", err)
	}
}

func TestOCSPLocalAuthorityIsIssuerScoped(t *testing.T) {
	chain, other := testcert.New(t), testcert.New(t)
	request, err := pki.CreateOCSPRequest(chain.Leaf.Raw, chain.Root.Raw, crypto.SHA256, nil)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := pki.CreateOCSPResponse(t.Context(), request, chain.Leaf.Raw, chain.Root.Raw, other.Leaf.Raw, other.LeafKey, ocspTemplate())
	if err != nil {
		t.Fatal(err)
	}
	if result, _, err := pki.VerifyOCSP(t.Context(), raw, chain.Leaf.Raw, chain.Root.Raw, testcert.Now(), pki.OCSPOptions{}); result != nil || !errors.Is(err, pki.ErrEvidence) {
		t.Fatal("embedded external responder acquired trust", err)
	}
	authority := pki.OCSPAuthority{ResponderCertificateDER: other.Leaf.Raw, IssuerCertificateDER: chain.Root.Raw}
	options := pki.OCSPOptions{Authorities: []pki.OCSPAuthority{authority}}
	result, report, err := pki.VerifyOCSP(t.Context(), raw, chain.Leaf.Raw, chain.Root.Raw, testcert.Now(), options)
	if err != nil || result == nil || report.Delegated || report.Authorization != pki.OCSPAuthorityLocal || !bytes.Equal(result.ResponderDER(), other.Leaf.Raw) {
		t.Fatal("explicit local authority", err)
	}
	options.Authorities[0].IssuerCertificateDER = other.Root.Raw
	if result, _, err := pki.VerifyOCSP(t.Context(), raw, chain.Leaf.Raw, chain.Root.Raw, testcert.Now(), options); result != nil || !errors.Is(err, pki.ErrEvidence) {
		t.Fatal("local authority crossed issuer scope", err)
	}
	options.Authorities = []pki.OCSPAuthority{authority, authority}
	if result, _, err := pki.VerifyOCSP(t.Context(), raw, chain.Leaf.Raw, chain.Root.Raw, testcert.Now(), options); result != nil || !errors.Is(err, pki.ErrPolicy) {
		t.Fatal("duplicate local authority accepted", err)
	}
	verifier, err := pki.NewVerifier(pki.Config{Roots: [][]byte{chain.Root.Raw}, Revocation: pki.RequireOCSP, OCSPAuthorities: []pki.OCSPAuthority{authority}})
	if err != nil {
		t.Fatal(err)
	}
	if trusted, _, err := verifier.Verify(t.Context(), chain.Leaf.Raw, testcert.Now(), pki.Evidence{OCSPResponses: [][]byte{raw}}); err != nil || trusted == nil || len(trusted.Evidence()) != 1 {
		t.Fatal("configured local authority not wired to chain verification", err)
	}
}

func TestOCSPAuthenticatedEvidence(t *testing.T) {
	chain := testcert.New(t)
	request, err := pki.CreateOCSPRequest(chain.Leaf.Raw, chain.Root.Raw, crypto.SHA256, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, status := range []pki.OCSPStatus{pki.OCSPGood, pki.OCSPRevoked, pki.OCSPUnknown} {
		t.Run(string(status), func(t *testing.T) {
			template := ocspTemplate()
			template.Status = status
			template.RevokedAt = testcert.Now().Add(-time.Minute)
			raw, err := pki.CreateOCSPResponse(t.Context(), request, chain.Leaf.Raw, chain.Root.Raw, chain.Root.Raw, chain.RootKey, template)
			if err != nil {
				t.Fatal(err)
			}
			original := bytes.Clone(raw)
			result, report, err := pki.VerifyOCSP(t.Context(), raw, chain.Leaf.Raw, chain.Root.Raw, testcert.Now(), pki.OCSPOptions{})
			if status == pki.OCSPGood {
				if result == nil || err != nil {
					t.Fatal(err)
				}
			} else if result != nil || err == nil {
				t.Fatal("non-GOOD assertion returned success", err)
			}
			records := report.Evidence()
			if len(records) != 1 {
				t.Fatal("authenticated assertion missing", len(records))
			}
			record := records[0]
			source := sha256.Sum256(original)
			target := sha256.Sum256(chain.Leaf.Raw)
			issuer := sha256.Sum256(chain.Root.RawSubjectPublicKeyInfo)
			if record.Kind() != pki.EvidenceOCSP || record.AuthenticationStatus() != pki.Valid || record.FingerprintSHA256() != hex.EncodeToString(source[:]) || record.TargetCertificateSHA256() != hex.EncodeToString(target[:]) || record.IssuerSPKISHA256() != hex.EncodeToString(issuer[:]) || record.AssertedStatus() != string(status) || record.ValidationTime() != testcert.Now() || record.IssuerScopeBinding() == "" {
				t.Fatal("OCSP evidence lost authenticated source/target/issuer binding")
			}
			clear(raw)
			records[0] = nil
			if !bytes.Equal(record.DER(), original) || report.Evidence()[0] == nil {
				t.Fatal("OCSP evidence borrowed caller state")
			}
			if status == pki.OCSPGood && len(result.Evidence()) != 1 {
				t.Fatal("successful result lost source assertion")
			}
		})
	}
}

// Re-sign each intervention so semantic failures cannot be explained by a bad signature.
func rewriteOCSPData(t *testing.T, raw []byte, key crypto.Signer, change func([]asn1.RawValue) [][]byte) []byte {
	t.Helper()
	root, err := der.Read(raw, len(raw))
	if err != nil {
		t.Fatal(err)
	}
	outer, err := der.Sequence(root, 2, 2)
	if err != nil {
		t.Fatal(err)
	}
	explicit, err := der.Explicit(outer[1], 0)
	if err != nil {
		t.Fatal(err)
	}
	response, err := der.Sequence(explicit, 2, 2)
	if err != nil {
		t.Fatal(err)
	}
	var octets []byte
	if der.Decode(response[1], &octets) != nil {
		t.Fatal("response octets")
	}
	basic, err := der.Read(octets, len(octets))
	if err != nil {
		t.Fatal(err)
	}
	fields, err := der.Sequence(basic, 3, 4)
	if err != nil {
		t.Fatal(err)
	}
	tbs, err := der.Sequence(fields[0], 3, 4)
	if err != nil {
		t.Fatal(err)
	}
	changed := der.Seq(change(tbs)...)
	algorithm, err := signature.Algorithm(fields[1])
	if err != nil {
		t.Fatal(err)
	}
	sig, err := signature.Sign(t.Context(), key, algorithm, changed)
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ := asn1.Marshal(asn1.BitString{Bytes: sig, BitLength: len(sig) * 8})
	parts := [][]byte{changed, fields[1].FullBytes, encoded}
	if len(fields) == 4 {
		parts = append(parts, fields[3].FullBytes)
	}
	return der.Seq(outer[0].FullBytes, der.Ctx(0, der.Seq(response[0].FullBytes, der.Octets(der.Seq(parts...)))))
}

func ocspFieldBytes(fields []asn1.RawValue) [][]byte {
	out := make([][]byte, len(fields))
	for i := range fields {
		out[i] = fields[i].FullBytes
	}
	return out
}

func TestOCSPMultipleEntrySelection(t *testing.T) {
	chain := testcert.New(t)
	request, err := pki.CreateOCSPRequest(chain.Leaf.Raw, chain.Root.Raw, crypto.SHA256, nil)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := pki.CreateOCSPResponse(t.Context(), request, chain.Leaf.Raw, chain.Root.Raw, chain.Root.Raw, chain.RootKey, ocspTemplate())
	if err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"unrelated before", "unrelated after", "only unrelated", "duplicate matching", "conflicting matching", "too many entries"} {
		t.Run(kind, func(t *testing.T) {
			variant := rewriteOCSPData(t, raw, chain.RootKey, func(fields []asn1.RawValue) [][]byte {
				entries, err := der.Sequence(fields[2], 1, 1)
				if err != nil {
					t.Fatal(err)
				}
				single, err := der.Sequence(entries[0], 3, 5)
				if err != nil {
					t.Fatal(err)
				}
				id, err := der.Sequence(single[0], 4, 4)
				if err != nil {
					t.Fatal(err)
				}
				alternateID := ocspFieldBytes(id)
				alternateID[3] = der.Int(999)
				alternate := ocspFieldBytes(single)
				alternate[0] = der.Seq(alternateID...)
				wanted := entries[0].FullBytes
				other := der.Seq(alternate...)
				var all [][]byte
				switch kind {
				case "unrelated before":
					all = [][]byte{other, wanted}
				case "unrelated after":
					all = [][]byte{wanted, other}
				case "only unrelated":
					all = [][]byte{other}
				case "duplicate matching":
					all = [][]byte{wanted, wanted}
				case "conflicting matching":
					conflict := ocspFieldBytes(single)
					when, _ := asn1.MarshalWithParams(testcert.Now().Add(-time.Hour), "generalized")
					conflict[1] = der.Wrap(2, 1, true, when)
					all = [][]byte{wanted, der.Seq(conflict...)}
				case "too many entries":
					all = make([][]byte, 0, 65)
					for range 65 {
						all = append(all, other)
					}
				}
				parts := ocspFieldBytes(fields)
				parts[2] = der.Seq(all...)
				return parts
			})
			result, report, err := pki.VerifyOCSP(t.Context(), variant, chain.Leaf.Raw, chain.Root.Raw, testcert.Now(), pki.OCSPOptions{})
			good := kind == "unrelated before" || kind == "unrelated after"
			if good {
				if err != nil || result == nil || report.Status != pki.OCSPGood || len(result.Evidence()) != 1 {
					t.Fatal("permitted extra response poisoned exact CertID", err)
				}
			} else if result != nil || !errors.Is(err, pki.ErrEvidence) {
				t.Fatal("ambiguous/unmatched response accepted", err)
			}
		})
	}
}

func TestOCSPResponseExtensionRules(t *testing.T) {
	chain := testcert.New(t)
	request, err := pki.CreateOCSPRequest(chain.Leaf.Raw, chain.Root.Raw, crypto.SHA256, nil)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := pki.CreateOCSPResponse(t.Context(), request, chain.Leaf.Raw, chain.Root.Raw, chain.Root.Raw, chain.RootKey, ocspTemplate())
	if err != nil {
		t.Fatal(err)
	}
	nonceOID := asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1, 2}
	unknownOID := asn1.ObjectIdentifier{1, 2, 3, 4, 999}
	for _, kind := range []string{"unknown noncritical", "unknown critical", "explicit default false", "duplicate extension", "nonce empty", "nonce129", "bad nonce encoding"} {
		t.Run(kind, func(t *testing.T) {
			extension := der.Seq(der.OID(unknownOID), der.Octets([]byte{1, 2, 3}))
			switch kind {
			case "explicit default false":
				extension = der.Seq(der.OID(unknownOID), []byte{1, 1, 0}, der.Octets([]byte{1, 2, 3}))
			case "unknown critical":
				critical, _ := asn1.Marshal(true)
				extension = der.Seq(der.OID(unknownOID), critical, der.Octets([]byte{1, 2, 3}))
			case "nonce empty":
				extension = der.Seq(der.OID(nonceOID), der.Octets(der.Octets(nil)))
			case "nonce129":
				extension = der.Seq(der.OID(nonceOID), der.Octets(der.Octets(make([]byte, 129))))
			case "bad nonce encoding":
				extension = der.Seq(der.OID(nonceOID), der.Octets(make([]byte, 32)))
			}
			extensions := der.Seq(extension)
			if kind == "duplicate extension" {
				extensions = der.Seq(extension, extension)
			}
			variant := rewriteOCSPData(t, raw, chain.RootKey, func(fields []asn1.RawValue) [][]byte { return append(ocspFieldBytes(fields), der.Ctx(1, extensions)) })
			result, _, err := pki.VerifyOCSP(t.Context(), variant, chain.Leaf.Raw, chain.Root.Raw, testcert.Now(), pki.OCSPOptions{})
			if kind == "unknown noncritical" {
				if err != nil || result == nil {
					t.Fatal("unknown noncritical extension not ignored", err)
				}
			} else if result != nil || err == nil {
				t.Fatal("invalid/critical/duplicate extension accepted", kind, err)
			}
		})
	}
}

func TestOCSPAuthorizationDependenciesAndSources(t *testing.T) {
	chain := testcert.New(t)
	key := testcert.Key(t)
	responder := testcert.Issue(t, &x509.Certificate{SerialNumber: big.NewInt(18), Subject: pkix.Name{CommonName: "revocation-checked responder"}, NotBefore: chain.Root.NotBefore, NotAfter: chain.Root.NotAfter, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageOCSPSigning}}, chain.Root, key.Public(), chain.RootKey)
	request, err := pki.CreateOCSPRequest(chain.Leaf.Raw, chain.Root.Raw, crypto.SHA256, nil)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := pki.CreateOCSPResponse(t.Context(), request, chain.Leaf.Raw, chain.Root.Raw, responder.Raw, key, ocspTemplate())
	if err != nil {
		t.Fatal(err)
	}
	crl := testcert.CRL(t, chain)
	source, err := evidence.NewObservation(t.Context(), evidence.OCSP, raw, evidence.Provenance{URI: "https://example.test/status", RetrievedAt: testcert.Now().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	crlSource, err := evidence.NewObservation(t.Context(), evidence.CRL, crl, evidence.Provenance{})
	if err != nil {
		t.Fatal(err)
	}
	options := pki.OCSPOptions{ResponderCRLs: [][]byte{crl}, Sources: []*evidence.Observation{source, crlSource}}
	result, _, err := pki.VerifyOCSP(t.Context(), raw, chain.Leaf.Raw, chain.Root.Raw, testcert.Now(), options)
	if err != nil || result == nil {
		t.Fatal(err)
	}
	records := result.Evidence()
	if len(records) != 2 {
		t.Fatal("authorization CRL missing", len(records))
	}
	var ocsp, dependency *pki.VerifiedEvidence
	for _, record := range records {
		if record.Kind() == pki.EvidenceOCSP {
			ocsp = record
		} else {
			dependency = record
		}
	}
	if ocsp == nil || dependency == nil || len(ocsp.Dependencies()) != 1 || ocsp.Dependencies()[0] != dependency.FingerprintSHA256() || dependency.TargetCertificateSHA256() != hexDigest(responder.Raw) {
		t.Fatal("OCSP authorization dependency lost responder binding")
	}
	if len(ocsp.Sources()) != 1 || ocsp.Sources()[0] != source || len(dependency.Sources()) != 1 || dependency.Sources()[0] != crlSource || !bytes.Equal(ocsp.DER(), raw) {
		t.Fatal("matched provenance was not retained")
	}
	ocsp.Sources()[0] = nil
	ocsp.Dependencies()[0] = "changed"
	if ocsp.Sources()[0] == nil || ocsp.Dependencies()[0] != dependency.FingerprintSHA256() {
		t.Fatal("mutable source/dependency accessors")
	}
	options.ResponderCRLs = [][]byte{testcert.CRL(t, chain, responder)}
	options.Sources = nil
	if result, _, err := pki.VerifyOCSP(t.Context(), raw, chain.Leaf.Raw, chain.Root.Raw, testcert.Now(), options); result != nil || !errors.Is(err, pki.ErrRevoked) {
		t.Fatal("revoked responder authorized response", err)
	}
	for _, invalid := range []*evidence.Observation{nil, {}, crlSource} {
		options = pki.OCSPOptions{Sources: []*evidence.Observation{invalid}}
		if result, report, err := pki.VerifyOCSP(t.Context(), raw, chain.Leaf.Raw, chain.Root.Raw, testcert.Now(), options); result != nil || !errors.Is(err, pki.ErrEvidence) || report.Signature != pki.NotChecked {
			t.Fatal("invalid/unmatched provenance accepted", err)
		}
	}
}

func hexDigest(raw []byte) string { sum := sha256.Sum256(raw); return hex.EncodeToString(sum[:]) }

func TestOCSPFractionalEncoderTimes(t *testing.T) {
	chain := testcert.New(t)
	request, err := pki.CreateOCSPRequest(chain.Leaf.Raw, chain.Root.Raw, crypto.SHA256, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"produced", "this", "next", "revoked"} {
		t.Run(name, func(t *testing.T) {
			template := ocspTemplate()
			switch name {
			case "produced":
				template.ProducedAt = template.ProducedAt.Add(time.Nanosecond)
			case "this":
				template.ThisUpdate = template.ThisUpdate.Add(time.Nanosecond)
			case "next":
				template.NextUpdate = template.NextUpdate.Add(time.Nanosecond)
			case "revoked":
				template.Status = pki.OCSPRevoked
				template.RevokedAt = testcert.Now().Add(-time.Minute + time.Nanosecond)
			}
			if raw, err := pki.CreateOCSPResponse(t.Context(), request, chain.Leaf.Raw, chain.Root.Raw, chain.Root.Raw, chain.RootKey, template); raw != nil || !errors.Is(err, pki.ErrPolicy) {
				t.Fatal("fractional encoder time silently changed", err)
			}
		})
	}
}

func TestOCSPNamesAndExactIssuerHash(t *testing.T) {
	chain := testcert.New(t)
	alternative, _ := asn1.Marshal(pkix.RDNSequence{{{Type: asn1.ObjectIdentifier{2, 5, 4, 3}, Value: asn1.RawValue{Tag: asn1.TagUTF8String, Bytes: []byte("  ITERATION  6 TEST ROOT  ")}}}})
	parent := *chain.Root
	parent.RawSubject = alternative
	child := testcert.Issue(t, &x509.Certificate{SerialNumber: big.NewInt(37), Subject: pkix.Name{CommonName: "semantic issuer"}, NotBefore: chain.Root.NotBefore, NotAfter: chain.Root.NotAfter, KeyUsage: x509.KeyUsageDigitalSignature}, &parent, chain.LeafKey.Public(), chain.RootKey)
	if bytes.Equal(child.RawIssuer, chain.Root.RawSubject) {
		t.Fatal("ineffective issuer intervention")
	}
	request, err := pki.CreateOCSPRequest(child.Raw, chain.Root.Raw, crypto.SHA256, nil)
	if err != nil {
		t.Fatal("equivalent issuer rejected", err)
	}
	parsed, _ := der.Read(request, len(request))
	outer, _ := der.Sequence(parsed, 1, 1)
	tbs, _ := der.Sequence(outer[0], 1, 1)
	requests, _ := der.Sequence(tbs[0], 1, 1)
	entry, _ := der.Sequence(requests[0], 1, 1)
	id, _ := der.Sequence(entry[0], 4, 4)
	var hash []byte
	if der.Decode(id[1], &hash) != nil {
		t.Fatal("issuerNameHash")
	}
	sum := sha256.Sum256(child.RawIssuer)
	if !bytes.Equal(hash, sum[:]) {
		t.Fatal("CertID hashed normalized or issuer subject bytes")
	}
	raw, err := pki.CreateOCSPResponse(t.Context(), request, child.Raw, chain.Root.Raw, chain.Root.Raw, chain.RootKey, ocspTemplate())
	if err != nil {
		t.Fatal(err)
	}
	for _, wrong := range []bool{false, true} {
		t.Run(strconv.FormatBool(wrong), func(t *testing.T) {
			name := alternative
			if wrong {
				name, _ = asn1.Marshal(pkix.RDNSequence{{{Type: asn1.ObjectIdentifier{2, 5, 4, 3}, Value: "unrelated"}}})
			}
			wire := rewriteOCSPData(t, raw, chain.RootKey, func(fields []asn1.RawValue) [][]byte {
				parts := ocspFieldBytes(fields)
				parts[0] = der.Ctx(1, name)
				return parts
			})
			result, _, err := pki.VerifyOCSP(t.Context(), wire, child.Raw, chain.Root.Raw, testcert.Now(), pki.OCSPOptions{})
			if wrong {
				if result != nil || !errors.Is(err, pki.ErrEvidence) {
					t.Fatal("different responder name matched", err)
				}
			} else if result == nil || err != nil {
				t.Fatal("equivalent responder name rejected", err)
			}
		})
	}
}

func TestOCSPRequestRejectsExplicitDefaultFalse(t *testing.T) {
	c := testcert.New(t)
	request, err := pki.CreateOCSPRequest(c.Leaf.Raw, c.Root.Raw, crypto.SHA256, nil)
	if err != nil {
		t.Fatal(err)
	}
	value, _ := der.Read(request, len(request))
	outer, _ := der.Sequence(value, 1, 1)
	fields, _ := der.Sequence(outer[0], 1, 1)
	extension := der.Seq(der.OID(asn1.ObjectIdentifier{1, 2, 3, 4, 5}), []byte{1, 1, 0}, der.Octets([]byte{5, 0}))
	changed := der.Seq(der.Seq(fields[0].FullBytes, der.Ctx(2, der.Seq(extension))))
	if parsed, err := pki.ParseOCSPRequest(changed); parsed != nil || !errors.Is(err, pki.ErrEvidence) {
		t.Fatal("DEFAULT FALSE encoded in request", err)
	}
}
