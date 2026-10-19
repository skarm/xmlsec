package pki_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/skarm/xmlsec/internal/der"
	"github.com/skarm/xmlsec/internal/signature"
	"github.com/skarm/xmlsec/internal/testutil/testcert"
	"github.com/skarm/xmlsec/pki"
)

func TestOCSPNextUpdateIsExclusive(t *testing.T) {
	c := testcert.New(t)

	q, err := pki.CreateOCSPRequest(c.Leaf.Raw, c.Root.Raw, 0, nil)
	if err != nil {
		t.Fatal(err)
	}

	tmpl := ocspTemplate()

	raw, err := pki.CreateOCSPResponse(context.Background(), q, c.Leaf.Raw, c.Root.Raw, c.Root.Raw, c.RootKey, tmpl)
	if err != nil {
		t.Fatal(err)
	}

	for _, skew := range []time.Duration{0, time.Second} {
		for _, delta := range []time.Duration{-time.Nanosecond, 0, time.Nanosecond} {
			at := tmpl.NextUpdate.Add(skew + delta)

			result, report, err := pki.VerifyOCSP(context.Background(), raw, c.Leaf.Raw, c.Root.Raw, at, pki.OCSPOptions{ClockSkew: skew})
			if report.Signature != pki.Valid {
				t.Fatal("control must have an authenticated signature", report, err)
			}

			if delta < 0 {
				if err != nil || result == nil {
					t.Fatalf("fresh response rejected: %v", err)
				}
			} else if result != nil || !errors.Is(err, pki.ErrUnavailable) {
				t.Fatalf("expired response accepted at nextUpdate+%v: result=%v, error=%v", skew+delta, result != nil, err)
			}
		}
	}
}

func TestCRLRequiresExplicitSigningKeyUsage(t *testing.T) {
	c := makeChain(t)
	for _, usage := range []x509.KeyUsage{0, x509.KeyUsageCertSign, x509.KeyUsageCertSign | x509.KeyUsageCRLSign} {
		template := *c.root
		template.KeyUsage = usage
		template.Subject = pkix.Name{CommonName: "CRL intermediate"}
		template.RawSubject = nil
		template.SubjectKeyId = []byte{4, 5, 6}
		template.SerialNumber = big.NewInt(3)

		issuerDER, err := x509.CreateCertificate(rand.Reader, &template, c.root, c.rootKey.Public(), c.rootKey)
		if err != nil {
			t.Fatal(err)
		}

		issuer, err := x509.ParseCertificate(issuerDER)
		if err != nil {
			t.Fatal(err)
		}
		// Create authentic evidence with the same key even when its certificate
		// does not authorize CRL signing. The standard generator checks the Go
		// template's KeyUsage, so change only this private issuance copy.
		issuanceCopy := *issuer
		issuanceCopy.KeyUsage |= x509.KeyUsageCRLSign

		crlDER, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
			Number: big.NewInt(1), ThisUpdate: verificationTime().Add(-time.Minute), NextUpdate: verificationTime().Add(time.Minute),
		}, &issuanceCopy, c.rootKey)
		if err != nil {
			t.Fatal(err)
		}

		leaf := *c.leaf
		leaf.AuthorityKeyId = nil

		leafDER, err := x509.CreateCertificate(rand.Reader, &leaf, issuer, c.leafKey.Public(), c.rootKey)
		if err != nil {
			t.Fatal(err)
		}

		verifier, err := pki.NewVerifier(pki.Config{Roots: [][]byte{c.root.Raw}, Intermediates: [][]byte{issuerDER}, Revocation: pki.RequireCRL, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning}})
		if err != nil {
			t.Fatal(err)
		}

		result, _, err := verifier.Verify(t.Context(), leafDER, verificationTime(), pki.Evidence{CRLs: [][]byte{crlDER, makeCRL(t, c, false, nil)}})
		if usage&x509.KeyUsageCRLSign != 0 {
			if err != nil || result == nil {
				t.Fatalf("authorized CRL rejected: %v", err)
			}
		} else if result != nil || !errors.Is(err, pki.ErrUnavailable) {
			t.Fatalf("CRL issuer KeyUsage=%v accepted: %v", usage, err)
		}
	}
}

func TestOCSPResponseStatusEnumeration(t *testing.T) {
	c := testcert.New(t)

	for _, status := range []int{-1, 1, 2, 3, 4, 5, 6, 7, 99} {
		encoded, err := asn1.Marshal(asn1.Enumerated(status))
		if err != nil {
			t.Fatal(err)
		}

		want := pki.ErrUnavailable
		if status < 0 || status == 4 || status > 6 {
			want = pki.ErrEvidence
		}

		result, report, err := pki.VerifyOCSP(context.Background(), der.Seq(encoded), c.Leaf.Raw, c.Root.Raw, testcert.Now(), pki.OCSPOptions{})
		if result != nil || !errors.Is(err, want) || report.Signature != pki.NotChecked {
			t.Fatalf("status %d: result=%v, report=%v, error=%v; want %v", status, result != nil, report, err, want)
		}
	}
}

func TestOCSPResponderAcceptsLegacyNonceLengths(t *testing.T) {
	c := testcert.New(t)

	request, err := pki.CreateOCSPRequest(c.Leaf.Raw, c.Root.Raw, 0, nil)
	if err != nil {
		t.Fatal(err)
	}

	v, err := der.Read(request, len(request))
	if err != nil {
		t.Fatal(err)
	}

	f, err := der.Sequence(v, 1, 1)
	if err != nil {
		t.Fatal(err)
	}

	tbs, err := der.Sequence(f[0], 1, 1)
	if err != nil {
		t.Fatal(err)
	}

	for _, n := range []int{0, 1, 15, 16, 31, 32, 33, 128, 129} {
		nonce := bytes.Repeat([]byte{42}, n)
		ext := der.Seq(der.Seq(der.OID(asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1, 2}), der.Octets(der.Octets(nonce))))
		raw := der.Seq(der.Seq(tbs[0].FullBytes, der.Ctx(2, ext)))

		parsed, err := pki.ParseOCSPRequest(raw)
		if n == 0 || n > 128 {
			if parsed != nil || !errors.Is(err, pki.ErrEvidence) {
				t.Fatalf("invalid nonce length %d accepted: %v", n, err)
			}

			continue
		}

		if err != nil || !bytes.Equal(parsed.Nonce(), nonce) {
			t.Fatalf("valid inbound nonce length %d rejected: %v", n, err)
		}

		response, err := pki.CreateOCSPResponse(context.Background(), raw, c.Leaf.Raw, c.Root.Raw, c.Root.Raw, c.RootKey, ocspTemplate())
		if err != nil {
			t.Fatal(err)
		}

		if result, _, err := pki.VerifyOCSP(context.Background(), response, c.Leaf.Raw, c.Root.Raw, testcert.Now(), pki.OCSPOptions{ExpectedNonce: nonce}); err != nil || result == nil {
			t.Fatalf("legacy nonce length %d failed response binding: %v", n, err)
		}
	}
}

func TestCRLNumberConflictsAreOrderIndependent(t *testing.T) {
	c := testcert.New(t)
	makeList := func(number int64, age time.Duration, revoked bool) []byte {
		template := &x509.RevocationList{Number: big.NewInt(number), ThisUpdate: testcert.Now().Add(-age), NextUpdate: testcert.Now().Add(time.Hour)}
		if revoked {
			template.RevokedCertificateEntries = []x509.RevocationListEntry{{SerialNumber: c.Leaf.SerialNumber, RevocationTime: testcert.Now().Add(-time.Hour)}}
		}

		raw, err := x509.CreateRevocationList(rand.Reader, template, c.Root, c.RootKey)
		if err != nil {
			t.Fatal(err)
		}

		return raw
	}

	v, err := pki.NewVerifier(pki.Config{Roots: [][]byte{c.Root.Raw}, Revocation: pki.RequireCRL})
	if err != nil {
		t.Fatal(err)
	}

	latest := makeList(3, time.Minute, false)
	older := makeList(2, 2*time.Minute, false)
	conflicting := makeList(2, 2*time.Minute, true)
	reusedNumber := makeList(3, 2*time.Minute, true)

	rollbackNumber := makeList(4, 2*time.Minute, true)
	for _, crls := range [][][]byte{
		{latest, older, conflicting},
		{conflicting, latest, older},
		{older, conflicting, latest},
		{latest, reusedNumber},
		{reusedNumber, latest},
		{latest, rollbackNumber},
		{rollbackNumber, latest},
	} {
		result, report, err := v.Verify(context.Background(), c.Leaf.Raw, testcert.Now(), pki.Evidence{CRLs: crls})
		if result != nil || !errors.Is(err, pki.ErrEvidence) || report.Revocation != pki.Indeterminate {
			t.Fatalf("conflicting authenticated evidence: result=%v report=%v error=%v", result != nil, report, err)
		}
	}
	// Duplicate evidence is harmless, and coherent older evidence is allowed.
	if result, _, err := v.Verify(context.Background(), c.Leaf.Raw, testcert.Now(), pki.Evidence{CRLs: [][]byte{older, latest, latest}}); result == nil || err != nil {
		t.Fatal(err)
	}
}

func TestCRLRejectsCriticalProfileExtensions(t *testing.T) {
	c := testcert.New(t)

	v, err := pki.NewVerifier(pki.Config{Roots: [][]byte{c.Root.Raw}, Revocation: pki.RequireCRL})
	if err != nil {
		t.Fatal(err)
	}

	for _, kind := range []string{"number", "authorityKeyIdentifier", "reasonCode"} {
		entry := kind == "reasonCode"

		template := &x509.RevocationList{Number: big.NewInt(1), ThisUpdate: testcert.Now().Add(-time.Minute), NextUpdate: testcert.Now().Add(time.Hour)}
		if entry {
			template.RevokedCertificateEntries = []x509.RevocationListEntry{{SerialNumber: big.NewInt(999), RevocationTime: testcert.Now().Add(-time.Hour), ReasonCode: 1}}
		} else {
			template.ExtraExtensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, 20}, Critical: true, Value: der.Int(1)}}
			if kind == "authorityKeyIdentifier" {
				template.ExtraExtensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, 35}, Critical: true, Value: der.Seq(der.Wrap(2, 0, false, c.Root.SubjectKeyId))}}
			}
		}

		raw, err := x509.CreateRevocationList(rand.Reader, template, c.Root, c.RootKey)
		if err != nil {
			t.Fatal(err)
		}

		if entry {
			raw = criticalCRLReason(t, raw, c)
		}

		result, _, err := v.Verify(context.Background(), c.Leaf.Raw, testcert.Now(), pki.Evidence{CRLs: [][]byte{raw}})
		if result != nil || !errors.Is(err, pki.ErrEvidence) {
			t.Fatalf("critical %s accepted: result=%v error=%v", kind, result != nil, err)
		}
	}
}

func criticalCRLReason(t *testing.T, raw []byte, c testcert.Chain) []byte {
	t.Helper()

	v, err := der.Read(raw, len(raw))
	if err != nil {
		t.Fatal(err)
	}

	f, err := der.Sequence(v, 3, 3)
	if err != nil {
		t.Fatal(err)
	}

	tbs, err := der.Sequence(f[0], 7, 7)
	if err != nil {
		t.Fatal(err)
	}

	entries, err := der.Sequence(tbs[5], 1, 1)
	if err != nil {
		t.Fatal(err)
	}

	one, err := der.Sequence(entries[0], 3, 3)
	if err != nil {
		t.Fatal(err)
	}

	reason, _ := asn1.Marshal(asn1.Enumerated(1))
	critical, _ := asn1.Marshal(true)
	ext := der.Seq(der.Seq(der.OID(asn1.ObjectIdentifier{2, 5, 29, 21}), critical, der.Octets(reason)))

	parts := make([][]byte, len(tbs))
	for i := range tbs {
		parts[i] = tbs[i].FullBytes
	}

	parts[5] = der.Seq(der.Seq(one[0].FullBytes, one[1].FullBytes, ext))
	data := der.Seq(parts...)

	algorithm, err := signature.Algorithm(f[1])
	if err != nil {
		t.Fatal(err)
	}

	sig, err := signature.Sign(context.Background(), c.RootKey, algorithm, data)
	if err != nil {
		t.Fatal(err)
	}

	bits, _ := asn1.Marshal(asn1.BitString{Bytes: sig, BitLength: len(sig) * 8})

	return der.Seq(data, f[1].FullBytes, bits)
}

func TestOCSPRequiresPKIXTimeEncoding(t *testing.T) {
	c := testcert.New(t)

	q, err := pki.CreateOCSPRequest(c.Leaf.Raw, c.Root.Raw, 0, nil)
	if err != nil {
		t.Fatal(err)
	}

	raw, err := pki.CreateOCSPResponse(context.Background(), q, c.Leaf.Raw, c.Root.Raw, c.Root.Raw, c.RootKey, pki.OCSPResponseTemplate{Status: pki.OCSPGood, ProducedAt: testcert.Now(), ThisUpdate: testcert.Now().Add(-time.Minute), NextUpdate: testcert.Now().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}

	for field := range 4 {
		if field == 3 {
			raw, err = pki.CreateOCSPResponse(context.Background(), q, c.Leaf.Raw, c.Root.Raw, c.Root.Raw, c.RootKey, pki.OCSPResponseTemplate{Status: pki.OCSPRevoked, ProducedAt: testcert.Now(), ThisUpdate: testcert.Now().Add(-time.Minute), NextUpdate: testcert.Now().Add(time.Hour), RevokedAt: testcert.Now().Add(-2 * time.Minute)})
			if err != nil {
				t.Fatal(err)
			}

			if result, report, err := pki.VerifyOCSP(context.Background(), raw, c.Leaf.Raw, c.Root.Raw, testcert.Now(), pki.OCSPOptions{}); result != nil || !errors.Is(err, pki.ErrRevoked) || report.Signature != pki.Valid {
				t.Fatal("invalid authenticated revoked control", err)
			}
		}

		for _, text := range []string{"202610081200Z", "20261008120000.1Z", "20261008140000+0200"} {
			modified := replaceOCSPTime(t, raw, c, field, text)

			result, _, err := pki.VerifyOCSP(context.Background(), modified, c.Leaf.Raw, c.Root.Raw, testcert.Now(), pki.OCSPOptions{})
			if result != nil || !errors.Is(err, pki.ErrEvidence) {
				t.Fatalf("field=%d time=%q result=%v error=%v", field, text, result != nil, err)
			}
		}
	}
}

// Rewrite authenticated OCSP data and re-sign it: failure cannot be attributed
// to a broken signature or stale evidence.
func replaceOCSPTime(t *testing.T, raw []byte, c testcert.Chain, field int, text string) []byte {
	t.Helper()

	v, err := der.Read(raw, len(raw))
	if err != nil {
		t.Fatal(err)
	}

	f, err := der.Sequence(v, 2, 2)
	if err != nil {
		t.Fatal(err)
	}

	x, err := der.Explicit(f[1], 0)
	if err != nil {
		t.Fatal(err)
	}

	r, err := der.Sequence(x, 2, 2)
	if err != nil {
		t.Fatal(err)
	}

	var body []byte
	if err := der.Decode(r[1], &body); err != nil {
		t.Fatal(err)
	}

	v, err = der.Read(body, len(body))
	if err != nil {
		t.Fatal(err)
	}

	basic, err := der.Sequence(v, 3, 4)
	if err != nil {
		t.Fatal(err)
	}

	tbs, err := der.Sequence(basic[0], 3, 4)
	if err != nil {
		t.Fatal(err)
	}

	parts := make([][]byte, len(tbs))
	for i := range tbs {
		parts[i] = tbs[i].FullBytes
	}

	encoded := der.Wrap(0, asn1.TagGeneralizedTime, false, []byte(text))
	if field == 0 {
		parts[1] = encoded
	} else {
		entries, err := der.Sequence(tbs[2], 1, 1)
		if err != nil {
			t.Fatal(err)
		}

		single, err := der.Sequence(entries[0], 3, 5)
		if err != nil {
			t.Fatal(err)
		}

		one := make([][]byte, len(single))
		for i := range single {
			one[i] = single[i].FullBytes
		}

		switch field {
		case 1:
			one[2] = encoded
		case 2:
			one[3] = der.Ctx(0, encoded)
		default:
			revoked, err := der.Children(single[1])
			if err != nil || len(revoked) != 1 {
				t.Fatal("invalid revoked test response", err)
			}

			one[1] = der.Wrap(2, 1, true, encoded)
		}

		parts[2] = der.Seq(der.Seq(one...))
	}

	data := der.Seq(parts...)

	algorithm, err := signature.Algorithm(basic[1])
	if err != nil {
		t.Fatal(err)
	}

	sig, err := signature.Sign(context.Background(), c.RootKey, algorithm, data)
	if err != nil {
		t.Fatal(err)
	}

	bits, _ := asn1.Marshal(asn1.BitString{Bytes: sig, BitLength: len(sig) * 8})

	return der.Seq(f[0].FullBytes, der.Ctx(0, der.Seq(r[0].FullBytes, der.Octets(der.Seq(data, basic[1].FullBytes, bits)))))
}

func TestPKIZeroVerifierRejectsBeforePathBuilding(t *testing.T) {
	c := testcert.New(t)

	result, report, err := new(pki.Verifier).Verify(context.Background(), c.Leaf.Raw, testcert.Now(), pki.Evidence{})
	if result != nil || !errors.Is(err, pki.ErrPolicy) || report.Chain != pki.NotChecked {
		t.Fatalf("result=%v report=%v error=%v", result, report, err)
	}
}
