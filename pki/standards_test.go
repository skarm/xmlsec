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

	"github.com/skarm/xmlsec/evidence"
	"github.com/skarm/xmlsec/internal/der"
	"github.com/skarm/xmlsec/internal/signature"
	"github.com/skarm/xmlsec/internal/testutil/testcert"
	"github.com/skarm/xmlsec/keys"
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

		if !entry {
			raw = p6ReplaceCRLExtension(t, raw, chainData{root: c.Root, rootKey: c.RootKey}, template.ExtraExtensions[0])
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

func TestCRLV1Compatibility(t *testing.T) {
	c := makeChain(t)
	original := makeCRL(t, c, false, nil)
	value, err := der.Read(original, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	fields, err := der.Sequence(value, 3, 3)
	if err != nil {
		t.Fatal(err)
	}
	tbs, err := der.Sequence(fields[0], 5, 7)
	if err != nil {
		t.Fatal(err)
	}
	var parts [][]byte
	for index, field := range tbs {
		if index == 0 || field.Class == 2 && field.Tag == 0 {
			continue
		}
		parts = append(parts, field.FullBytes)
	}
	raw := der.Seq(parts...)
	algorithm, err := signature.Algorithm(fields[1])
	if err != nil {
		t.Fatal(err)
	}
	signed, err := signature.Sign(t.Context(), c.rootKey, algorithm, raw)
	if err != nil {
		t.Fatal(err)
	}
	bits, _ := asn1.Marshal(asn1.BitString{Bytes: signed, BitLength: len(signed) * 8})
	evidence := der.Seq(raw, fields[1].FullBytes, bits)
	verifier, err := pki.NewVerifier(pki.Config{Roots: [][]byte{c.root.Raw}, Revocation: pki.RequireCRL})
	if err != nil {
		t.Fatal(err)
	}
	if result, report, err := verifier.Verify(t.Context(), c.leaf.Raw, verificationTime(), pki.Evidence{CRLs: [][]byte{evidence}}); err != nil || result == nil || report.Revocation != pki.Valid {
		t.Fatal("result", result != nil, report, err)
	}
}

func TestOCSPUnknownNoncriticalRequestExtensions(t *testing.T) {
	c := testcert.New(t)
	request, err := pki.CreateOCSPRequest(c.Leaf.Raw, c.Root.Raw, 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	value, err := der.Read(request, 1<<16)
	if err != nil {
		t.Fatal(err)
	}
	outer, err := der.Sequence(value, 1, 1)
	if err != nil {
		t.Fatal(err)
	}
	fields, err := der.Sequence(outer[0], 1, 1)
	if err != nil {
		t.Fatal(err)
	}
	for _, critical := range []bool{false, true} {
		name := "noncritical"
		if critical {
			name = "critical"
		}
		t.Run(name, func(t *testing.T) {
			items := [][]byte{der.OID(asn1.ObjectIdentifier{1, 2, 3, 4, 5})}
			if critical {
				items = append(items, []byte{1, 1, 255})
			}
			items = append(items, der.Octets([]byte{5, 0}))
			changed := der.Seq(der.Seq(fields[0].FullBytes, der.Ctx(2, der.Seq(der.Seq(items...)))))
			result, err := pki.ParseOCSPRequest(changed)
			if critical {
				if result != nil || !errors.Is(err, pki.ErrUnsupported) {
					t.Fatal(result, err)
				}
			} else if err != nil || result == nil {
				t.Fatal(result, err)
			}
		})
	}
}

func p6CRL(t *testing.T, c chainData, number int64, this, next time.Time, base int64, scope []byte, entries []x509.RevocationListEntry) []byte {
	t.Helper()
	template := &x509.RevocationList{Number: big.NewInt(number), ThisUpdate: this, NextUpdate: next, RevokedCertificateEntries: entries}
	if base >= 0 {
		template.ExtraExtensions = append(template.ExtraExtensions, pkix.Extension{Id: asn1.ObjectIdentifier{2, 5, 29, 27}, Critical: true, Value: der.Int(int(base))})
	}
	if scope != nil {
		template.ExtraExtensions = append(template.ExtraExtensions, pkix.Extension{Id: asn1.ObjectIdentifier{2, 5, 29, 28}, Critical: true, Value: scope})
	}
	return makeCRL(t, c, false, template)
}

func TestCRLDeltaComposition(t *testing.T) {
	c := makeChain(t)
	at := verificationTime()
	revoked := func(reason int) []x509.RevocationListEntry {
		return []x509.RevocationListEntry{{SerialNumber: c.leaf.SerialNumber, RevocationTime: at.Add(-time.Minute), ReasonCode: reason}}
	}
	base := p6CRL(t, c, 1, at.Add(-2*time.Minute), at.Add(time.Hour), -1, nil, revoked(6))
	release := p6CRL(t, c, 3, at.Add(-time.Minute), at.Add(time.Hour), 1, nil, revoked(8))
	intermediate := p6CRL(t, c, 2, at.Add(-90*time.Second), at.Add(time.Hour), -1, nil, revoked(6))
	expired := p6CRL(t, c, 1, at.Add(-2*time.Minute), at.Add(-time.Second), -1, nil, revoked(6))
	good := p6CRL(t, c, 1, at.Add(-2*time.Minute), at.Add(time.Hour), -1, nil, nil)
	bad := p6CRL(t, c, 3, at.Add(-time.Minute), at.Add(time.Hour), 1, nil, revoked(1))
	currentGood := p6CRL(t, c, 3, at.Add(-time.Minute), at.Add(time.Hour), -1, nil, nil)
	currentBad := p6CRL(t, c, 3, at.Add(-time.Minute), at.Add(time.Hour), -1, nil, revoked(1))
	olderSameTime := p6CRL(t, c, 2, at.Add(-time.Minute), at.Add(time.Hour), -1, nil, revoked(6))
	for _, test := range []struct {
		name    string
		lists   [][]byte
		disable bool
		want    error
	}{
		{"hold released", [][]byte{base, release}, false, nil},
		{"permuted", [][]byte{release, base}, false, nil},
		{"base range", [][]byte{intermediate, release}, false, nil},
		{"expired base renewed", [][]byte{expired, release}, false, nil},
		{"new revocation", [][]byte{good, bad}, false, pki.ErrRevoked},
		{"unpaired delta", [][]byte{release}, false, pki.ErrUnavailable},
		{"disabled delta", [][]byte{base, release}, true, pki.ErrRevoked},
		{"complete delta equivalent", [][]byte{base, release, currentGood}, false, nil},
		{"same number different kinds consistent", [][]byte{good, bad, currentBad}, false, pki.ErrRevoked},
		{"same number different kinds conflict", [][]byte{good, bad, currentGood}, false, pki.ErrEvidence},
		{"same second complete sequence", [][]byte{olderSameTime, currentGood}, false, nil},
		{"same second complete sequence permuted", [][]byte{currentGood, olderSameTime}, false, nil},
	} {
		t.Run(test.name, func(t *testing.T) {
			verifier, err := pki.NewVerifier(pki.Config{Roots: [][]byte{c.root.Raw}, Revocation: pki.RequireCRL, CRL: pki.CRLOptions{DisableDeltaCRLs: test.disable}})
			if err != nil {
				t.Fatal(err)
			}
			result, report, err := verifier.Verify(t.Context(), c.leaf.Raw, at, pki.Evidence{CRLs: test.lists})
			if test.want != nil {
				if result != nil || !errors.Is(err, test.want) {
					t.Fatal("result", result != nil, report, err)
				}
				return
			}
			if err != nil || result == nil || report.Revocation != pki.Valid {
				t.Fatal("result", result != nil, report, err)
			}
			if len(result.Evidence()) < 1 {
				t.Fatal("missing authenticated source evidence")
			}
			for _, fact := range result.Evidence() {
				if fact.AuthenticationStatus() != pki.Valid || fact.TargetCertificateSHA256() == "" || fact.ValidationTime() != at {
					t.Fatal("unbound assertion")
				}
				owned := fact.DER()
				owned[0] ^= 1
				if bytes.Equal(owned, fact.DER()) {
					t.Fatal("mutable evidence")
				}
			}
		})
	}
}

func p6PointName(uri string) []byte {
	return der.Ctx(0, der.Wrap(2, 0, true, der.Wrap(2, 6, false, []byte(uri))))
}

func p6Reasons(mask uint16) []byte {
	bits := asn1.BitString{}
	for index := 1; index <= 8; index++ {
		if mask&(1<<(index-1)) != 0 {
			bits.BitLength = index + 1
		}
	}
	bits.Bytes = make([]byte, (bits.BitLength+7)/8)
	for index := 1; index <= 8; index++ {
		if mask&(1<<(index-1)) != 0 {
			bits.Bytes[index/8] |= 1 << (7 - index%8)
		}
	}
	encoded, _ := asn1.Marshal(bits)
	var value asn1.RawValue
	_, _ = asn1.Unmarshal(encoded, &value)
	return value.Bytes
}

func p6LeafExtensions(t *testing.T, c chainData, extra []pkix.Extension) *x509.Certificate {
	t.Helper()
	template := *c.leaf
	template.ExtraExtensions = extra
	encoded, err := x509.CreateCertificate(rand.Reader, &template, c.root, c.leafKey.Public(), c.rootKey)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := keys.ParseCertificate(encoded, keys.Limits{})
	if err != nil {
		t.Fatal(err)
	}
	return leaf
}

func TestCRLScopedReasonCoverage(t *testing.T) {
	c := makeChain(t)
	at := verificationTime()
	point := func(uri string, mask uint16) []byte {
		fields := [][]byte{p6PointName(uri)}
		if mask != 255 {
			fields = append(fields, der.Wrap(2, 1, false, p6Reasons(mask)))
		}
		return der.Seq(fields...)
	}
	leaf := p6LeafExtensions(t, c, []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, 31}, Value: der.Seq(point("urn:part-a", 15), point("urn:part-b", 240))}})
	scope := func(uri string, mask uint16, flags ...int) []byte {
		fields := [][]byte{p6PointName(uri)}
		for _, flag := range flags {
			fields = append(fields, der.Wrap(2, flag, false, []byte{255}))
		}
		if mask != 255 {
			fields = append(fields, der.Wrap(2, 3, false, p6Reasons(mask)))
		}
		return der.Seq(fields...)
	}
	a := p6CRL(t, c, 1, at.Add(-time.Minute), at.Add(time.Hour), -1, scope("urn:part-a", 15), nil)
	b := p6CRL(t, c, 1, at.Add(-time.Minute), at.Add(time.Hour), -1, scope("urn:part-b", 240), nil)
	for _, test := range []struct {
		name  string
		lists [][]byte
		want  error
	}{
		{"missing reasons", [][]byte{a}, pki.ErrUnavailable},
		{"all reasons", [][]byte{a, b}, nil},
		{"permuted same numbers different scopes", [][]byte{b, a}, nil},
		{"wrong distribution point", [][]byte{p6CRL(t, c, 2, at.Add(-time.Minute), at.Add(time.Hour), -1, scope("urn:other", 255), nil)}, pki.ErrUnavailable},
		{"CA only", [][]byte{p6CRL(t, c, 2, at.Add(-time.Minute), at.Add(time.Hour), -1, scope("urn:part-a", 255, 2), nil)}, pki.ErrUnavailable},
		{"attribute only", [][]byte{p6CRL(t, c, 2, at.Add(-time.Minute), at.Add(time.Hour), -1, scope("urn:part-a", 255, 5), nil)}, pki.ErrUnavailable},
		{"empty IDP", [][]byte{p6CRL(t, c, 2, at.Add(-time.Minute), at.Add(time.Hour), -1, der.Seq(), nil)}, pki.ErrEvidence},
		{"conflicting IDP types", [][]byte{p6CRL(t, c, 2, at.Add(-time.Minute), at.Add(time.Hour), -1, scope("urn:part-a", 255, 1, 2), nil)}, pki.ErrEvidence},
	} {
		t.Run(test.name, func(t *testing.T) {
			verifier, err := pki.NewVerifier(pki.Config{Roots: [][]byte{c.root.Raw}, Revocation: pki.RequireCRL})
			if err != nil {
				t.Fatal(err)
			}
			result, report, err := verifier.Verify(t.Context(), leaf.Raw, at, pki.Evidence{CRLs: test.lists})
			if test.want != nil {
				if result != nil || !errors.Is(err, test.want) {
					t.Fatal("result", result != nil, report, err)
				}
			} else if err != nil || result == nil {
				t.Fatal("result", result != nil, report, err)
			}
		})
	}
}

func TestCRLIndirectIssuerAndEntryBinding(t *testing.T) {
	c := makeChain(t)
	at := verificationTime()
	signerTemplate := &x509.Certificate{SerialNumber: big.NewInt(10), Subject: pkix.Name{CommonName: "delegated CRL issuer"}, NotBefore: at.Add(-time.Hour), NotAfter: at.Add(time.Hour), KeyUsage: x509.KeyUsageCRLSign, SubjectKeyId: []byte{9, 8, 7}, BasicConstraintsValid: true}
	signerDER, err := x509.CreateCertificate(rand.Reader, signerTemplate, c.root, c.leafKey.Public(), c.rootKey)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := x509.ParseCertificate(signerDER)
	if err != nil {
		t.Fatal(err)
	}
	point := der.Seq(p6PointName("urn:delegated-crl"), der.Wrap(2, 2, true, der.Ctx(4, signer.RawSubject)))
	leaf := p6LeafExtensions(t, c, []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, 31}, Value: der.Seq(point)}})
	scope := der.Seq(p6PointName("urn:delegated-crl"), der.Wrap(2, 4, false, []byte{255}))
	delegated := chainData{root: signer, rootKey: c.leafKey, leaf: leaf}
	issuer := pkix.Extension{Id: asn1.ObjectIdentifier{2, 5, 29, 29}, Critical: true, Value: der.Seq(der.Ctx(4, c.root.RawSubject))}
	entry := x509.RevocationListEntry{SerialNumber: leaf.SerialNumber, RevocationTime: at.Add(-time.Minute), ReasonCode: 1, ExtraExtensions: []pkix.Extension{issuer}}
	good := p6CRL(t, delegated, 1, at.Add(-time.Minute), at.Add(time.Hour), -1, scope, nil)
	revoked := p6CRL(t, delegated, 1, at.Add(-time.Minute), at.Add(time.Hour), -1, scope, []x509.RevocationListEntry{entry})
	inherited := entry
	inherited.SerialNumber = big.NewInt(999)
	next := entry
	next.ExtraExtensions = nil
	inheritance := p6CRL(t, delegated, 1, at.Add(-time.Minute), at.Add(time.Hour), -1, scope, []x509.RevocationListEntry{inherited, next})
	differentIssuer := entry
	differentIssuer.ExtraExtensions = nil
	disjoint := p6CRL(t, delegated, 1, at.Add(-time.Minute), at.Add(time.Hour), -1, scope, []x509.RevocationListEntry{differentIssuer, entry})
	noncritical := entry
	noncritical.ExtraExtensions = append([]pkix.Extension(nil), entry.ExtraExtensions...)
	noncritical.ExtraExtensions[0].Critical = false
	invalidCritical := p6CRL(t, delegated, 1, at.Add(-time.Minute), at.Add(time.Hour), -1, scope, []x509.RevocationListEntry{noncritical})
	for _, test := range []struct {
		name       string
		raw        []byte
		candidates bool
		want       error
	}{
		{"non CA signer authorized", good, true, nil},
		{"exact issuer serial revoked", revoked, true, pki.ErrRevoked},
		{"inherited certificate issuer", inheritance, true, pki.ErrRevoked},
		{"equal serial different issuers legal", disjoint, true, pki.ErrRevoked},
		{"missing signer certificate", good, false, pki.ErrUnavailable},
		{"certificateIssuer must be critical", invalidCritical, true, pki.ErrEvidence},
	} {
		t.Run(test.name, func(t *testing.T) {
			verifier, err := pki.NewVerifier(pki.Config{Roots: [][]byte{c.root.Raw}, Revocation: pki.RequireCRL})
			if err != nil {
				t.Fatal(err)
			}
			evidence := pki.Evidence{CRLs: [][]byte{test.raw}}
			if test.candidates {
				evidence.Intermediates = [][]byte{signer.Raw}
			}
			result, report, err := verifier.Verify(t.Context(), leaf.Raw, at, evidence)
			if test.want != nil {
				if result != nil || !errors.Is(err, test.want) {
					t.Fatal("result", result != nil, report, err)
				}
			} else if err != nil || result == nil {
				t.Fatal("result", result != nil, report, err)
			}
		})
	}
	t.Run("indirect delta release preserves issuer aliases", func(t *testing.T) {
		held := entry
		held.ReasonCode = 6
		base := p6CRL(t, delegated, 1, at.Add(-2*time.Minute), at.Add(time.Hour), -1, scope, []x509.RevocationListEntry{held})
		released := entry
		released.ReasonCode = 8
		alias, _ := asn1.Marshal(pkix.Name{CommonName: "another alias"}.ToRDNSequence())
		released.ExtraExtensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, 29}, Critical: true, Value: der.Seq(der.Ctx(4, alias), der.Ctx(4, c.root.RawSubject))}}
		delta := p6CRL(t, delegated, 2, at.Add(-time.Minute), at.Add(time.Hour), 1, scope, []x509.RevocationListEntry{released})
		verifier, err := pki.NewVerifier(pki.Config{Roots: [][]byte{c.root.Raw}, Intermediates: [][]byte{signer.Raw}, Revocation: pki.RequireCRL})
		if err != nil {
			t.Fatal(err)
		}
		result, _, err := verifier.Verify(t.Context(), leaf.Raw, at, pki.Evidence{CRLs: [][]byte{delta, base}})
		if err != nil || result == nil {
			t.Fatal(result != nil, err)
		}
		found := false
		for _, fact := range result.Evidence() {
			if fact.AssertedStatus() == "remove-from-crl" {
				reason, present := fact.RevocationReason()
				if !present || reason != 8 || len(fact.Dependencies()) != 1 || fact.RevokedAt().IsZero() {
					t.Fatal("lost authenticated delta metadata")
				}
				found = true
			}
		}
		if !found {
			t.Fatal("no remove-from-crl fact")
		}
	})
	t.Run("replacing intermediates removes CRL delegate", func(t *testing.T) {
		verifier, err := pki.NewVerifier(pki.Config{Roots: [][]byte{c.root.Raw}, Intermediates: [][]byte{signer.Raw}, Revocation: pki.RequireCRL})
		if err != nil {
			t.Fatal(err)
		}
		if result, _, err := verifier.Verify(t.Context(), leaf.Raw, at, pki.Evidence{CRLs: [][]byte{good}}); err != nil || result == nil {
			t.Fatal(result, err)
		}
		replaced, err := verifier.WithIntermediateCertificates(nil)
		if err != nil {
			t.Fatal(err)
		}
		if result, _, err := replaced.Verify(t.Context(), leaf.Raw, at, pki.Evidence{CRLs: [][]byte{good}}); result != nil || !errors.Is(err, pki.ErrUnavailable) {
			t.Fatal(result, err)
		}
	})
}

func TestCRLAuthenticatedMetadataBinding(t *testing.T) {
	c := makeChain(t)
	at := verificationTime()
	base := p6CRL(t, c, 1, at.Add(-2*time.Minute), at.Add(-time.Second), -1, nil, nil)
	number := der.Int(999)
	var serial asn1.RawValue
	_, _ = asn1.Unmarshal(number, &serial)
	authority := der.Seq(der.Wrap(2, 0, false, c.root.SubjectKeyId), der.Wrap(2, 1, true, der.Ctx(4, c.root.RawIssuer)), der.Wrap(2, 2, false, serial.Bytes))
	badDelta := makeCRL(t, c, false, &x509.RevocationList{Number: big.NewInt(2), ThisUpdate: at.Add(-time.Minute), NextUpdate: at.Add(time.Hour), ExtraExtensions: []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, 27}, Critical: true, Value: der.Int(1)}, {Id: asn1.ObjectIdentifier{2, 5, 29, 35}, Value: authority}}})
	badDelta = p6ReplaceCRLExtension(t, badDelta, c, pkix.Extension{Id: asn1.ObjectIdentifier{2, 5, 29, 35}, Value: authority})
	advertised := der.Seq(der.Seq(p6PointName("urn:delta-source")))
	invalidAdvertised := der.Seq(der.Seq(p6PointName("urn:delta-source"), der.Wrap(2, 1, false, p6Reasons(255))))
	complete := func(fresh []byte) []byte {
		return makeCRL(t, c, false, &x509.RevocationList{Number: big.NewInt(1), ThisUpdate: at.Add(-2 * time.Minute), NextUpdate: at.Add(time.Hour), ExtraExtensions: []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, 46}, Value: fresh}}})
	}
	delta := p6CRL(t, c, 2, at.Add(-time.Minute), at.Add(time.Hour), 1, nil, nil)
	badAlt := makeCRL(t, c, false, &x509.RevocationList{Number: big.NewInt(1), ThisUpdate: at.Add(-time.Minute), NextUpdate: at.Add(time.Hour), ExtraExtensions: []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, 18}, Value: der.Wrap(0, asn1.TagSet, true, der.Ctx(4, c.root.RawSubject))}}})

	for _, test := range []struct {
		name    string
		lists   [][]byte
		disable bool
		want    error
	}{
		{"GeneralNames must be SEQUENCE", [][]byte{badAlt}, false, pki.ErrEvidence},
		{"authority issuer serial mismatch", [][]byte{base, badDelta}, false, pki.ErrUnavailable},
		{"freshest missing", [][]byte{complete(advertised)}, false, pki.ErrUnavailable},
		{"freshest fulfilled offline", [][]byte{complete(advertised), delta}, false, nil},
		{"freshest explicitly disabled", [][]byte{complete(advertised)}, true, nil},
		{"freshest reasons must be absent", [][]byte{complete(invalidAdvertised), delta}, false, pki.ErrEvidence},
	} {
		t.Run(test.name, func(t *testing.T) {
			verifier, err := pki.NewVerifier(pki.Config{Roots: [][]byte{c.root.Raw}, Revocation: pki.RequireCRL, CRL: pki.CRLOptions{DisableDeltaCRLs: test.disable}})
			if err != nil {
				t.Fatal(err)
			}
			result, report, err := verifier.Verify(t.Context(), c.leaf.Raw, at, pki.Evidence{CRLs: test.lists})
			if test.want != nil {
				if result != nil || !errors.Is(err, test.want) {
					t.Fatal("result", result != nil, report, err)
				}
			} else if err != nil || result == nil {
				t.Fatal("result", result != nil, report, err)
			}
		})
	}
}

func p6ReplaceCRLExtension(t *testing.T, raw []byte, c chainData, replacement pkix.Extension) []byte {
	t.Helper()
	value, err := der.Read(raw, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	fields, err := der.Sequence(value, 3, 3)
	if err != nil {
		t.Fatal(err)
	}
	tbs, err := der.Sequence(fields[0], 5, 7)
	if err != nil {
		t.Fatal(err)
	}
	ext, err := der.Explicit(tbs[len(tbs)-1], 0)
	if err != nil {
		t.Fatal(err)
	}
	old, err := der.Sequence(ext, 1, 32)
	if err != nil {
		t.Fatal(err)
	}
	var extensions [][]byte
	for _, item := range old {
		var parsed pkix.Extension
		if der.Decode(item, &parsed) != nil {
			t.Fatal("extension shape")
		}
		if !parsed.Id.Equal(replacement.Id) {
			extensions = append(extensions, item.FullBytes)
		}
	}
	encoded, err := asn1.Marshal(replacement)
	if err != nil {
		t.Fatal(err)
	}
	extensions = append(extensions, encoded)
	tbs[len(tbs)-1].FullBytes = der.Ctx(0, der.Seq(extensions...))
	parts := make([][]byte, 0, len(tbs))
	for _, part := range tbs {
		parts = append(parts, part.FullBytes)
	}
	data := der.Seq(parts...)
	algorithm, err := signature.Algorithm(fields[1])
	if err != nil {
		t.Fatal(err)
	}
	signed, err := signature.Sign(t.Context(), c.rootKey, algorithm, data)
	if err != nil {
		t.Fatal(err)
	}
	bits, _ := asn1.Marshal(asn1.BitString{Bytes: signed, BitLength: len(signed) * 8})
	return der.Seq(data, fields[1].FullBytes, bits)
}

func TestVerifiedCRLEvidenceSources(t *testing.T) {
	c := makeChain(t)
	at := verificationTime()
	raw := makeCRL(t, c, false, nil)
	original := bytes.Clone(raw)
	source, err := evidence.NewObservation(t.Context(), evidence.CRL, raw, evidence.Provenance{URI: "https://example.test/status.crl", RetrievedAt: at.AddDate(-20, 0, 0), Redirects: []string{"https://example.test/current.crl"}})
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := pki.NewVerifier(pki.Config{Roots: [][]byte{c.root.Raw}, Revocation: pki.RequireCRL})
	if err != nil {
		t.Fatal(err)
	}
	result, _, err := verifier.Verify(t.Context(), c.leaf.Raw, at, pki.Evidence{CRLs: [][]byte{raw}, Sources: []*evidence.Observation{source}})
	if err != nil || result == nil {
		t.Fatal(result != nil, err)
	}
	clear(raw)
	facts := result.Evidence()
	if len(facts) != 1 {
		t.Fatal(len(facts))
	}
	fact := facts[0]
	facts[0] = nil
	if fact.AuthenticationStatus() != pki.Valid || fact.ValidationTime() != at || fact.FingerprintSHA256() != source.FingerprintSHA256() || !bytes.Equal(fact.DER(), original) {
		t.Fatal("source binding or authentication differs")
	}
	if len(result.Evidence()) != 1 || result.Evidence()[0] == nil || len(fact.Sources()) != 1 {
		t.Fatal("mutable evidence slice")
	}
	sources := fact.Sources()
	sources[0] = nil
	if fact.Sources()[0].Provenance().RetrievedAt != at.AddDate(-20, 0, 0) {
		t.Fatal("untrusted retrieval time changed authentication")
	}
	owned := fact.DER()
	clear(owned)
	if !bytes.Equal(fact.DER(), original) {
		t.Fatal("mutable original bytes")
	}
	var zero pki.VerifiedEvidence
	if zero.AuthenticationStatus() != pki.NotChecked {
		t.Fatal("zero observation authenticated")
	}
	for _, test := range []struct {
		name string
		kind evidence.Kind
		raw  []byte
	}{
		{"wrong kind", evidence.OCSP, original},
		{"wrong digest", evidence.CRL, []byte{0}},
	} {
		t.Run(test.name, func(t *testing.T) {
			unbound, err := evidence.NewObservation(t.Context(), test.kind, test.raw, evidence.Provenance{})
			if err != nil {
				t.Fatal(err)
			}
			result, _, err := verifier.Verify(t.Context(), c.leaf.Raw, at, pki.Evidence{CRLs: [][]byte{original}, Sources: []*evidence.Observation{unbound}})
			if result != nil || !errors.Is(err, pki.ErrEvidence) {
				t.Fatal(result != nil, err)
			}
		})
	}
	expired := makeCRL(t, c, false, &x509.RevocationList{Number: big.NewInt(1), ThisUpdate: at.Add(-2 * time.Hour), NextUpdate: at.Add(-time.Hour)})
	result, report, err := verifier.Verify(t.Context(), c.leaf.Raw, at, pki.Evidence{CRLs: [][]byte{expired}})
	if result != nil || !errors.Is(err, pki.ErrUnavailable) || len(report.Evidence()) != 1 || report.Evidence()[0].AuthenticationStatus() != pki.Valid {
		t.Fatal("stale authenticated assertion became trust", result != nil, err, len(report.Evidence()))
	}
}

func TestPKIXSemanticNamesPreserveOriginalDER(t *testing.T) {
	c := makeChain(t)
	at := verificationTime()
	for _, test := range []struct {
		name, text string
		tag        int
		valid      bool
	}{
		{"case and encoding", "TEST ROOT", asn1.TagUTF8String, true},
		{"insignificant spaces", "  test    root  ", asn1.TagPrintableString, true},
		{"different name", "other root", asn1.TagUTF8String, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			encodedName := der.Seq(der.Wrap(0, asn1.TagSet, true, der.Seq(der.OID(asn1.ObjectIdentifier{2, 5, 4, 3}), der.Wrap(0, test.tag, false, []byte(test.text)))))
			issuerView := *c.root
			issuerView.RawSubject = encodedName
			template := *c.leaf
			raw, err := x509.CreateCertificate(rand.Reader, &template, &issuerView, c.leafKey.Public(), c.rootKey)
			if err != nil {
				t.Fatal(err)
			}
			leaf, err := x509.ParseCertificate(raw)
			if err != nil {
				t.Fatal(err)
			}
			verifier, err := pki.NewVerifier(pki.Config{Roots: [][]byte{c.root.Raw}, Revocation: pki.RequireCRL})
			if err != nil {
				t.Fatal(err)
			}
			result, _, err := verifier.Verify(t.Context(), leaf.Raw, at, pki.Evidence{CRLs: [][]byte{makeCRL(t, c, false, nil)}})
			if !test.valid {
				if result != nil || !errors.Is(err, pki.ErrCertificate) {
					t.Fatal(result != nil, err)
				}
				return
			}
			if err != nil || result == nil {
				t.Fatal(result != nil, err)
			}
			chain := result.ChainDER()
			if len(chain) != 2 || !bytes.Equal(chain[0], leaf.Raw) || !bytes.Equal(chain[1], c.root.Raw) {
				t.Fatal("synthetic name metadata escaped into result")
			}
			restored, err := x509.ParseCertificate(chain[0])
			if err != nil || !bytes.Equal(restored.RawIssuer, encodedName) {
				t.Fatal("CertID source name was rewritten", err)
			}
		})
	}
}

func p6TransformCRL(t *testing.T, raw []byte, c chainData, edit func([]asn1.RawValue) [][]byte) []byte {
	t.Helper()
	value, err := der.Read(raw, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	fields, err := der.Sequence(value, 3, 3)
	if err != nil {
		t.Fatal(err)
	}
	body, err := der.Sequence(fields[0], 3, 7)
	if err != nil {
		t.Fatal(err)
	}
	data := der.Seq(edit(body)...)
	algorithm, err := signature.Algorithm(fields[1])
	if err != nil {
		t.Fatal(err)
	}
	signed, err := signature.Sign(t.Context(), c.rootKey, algorithm, data)
	if err != nil {
		t.Fatal(err)
	}
	bits, _ := asn1.Marshal(asn1.BitString{Bytes: signed, BitLength: len(signed) * 8})
	return der.Seq(data, fields[1].FullBytes, bits)
}

func TestCRLTimeAndPolicyBoundaries(t *testing.T) {
	c := makeChain(t)
	at := verificationTime()
	raw := makeCRL(t, c, false, nil)
	noNext := p6TransformCRL(t, raw, c, func(fields []asn1.RawValue) [][]byte {
		var parts [][]byte
		for index, field := range fields {
			if index != 4 {
				parts = append(parts, field.FullBytes)
			}
		}
		return parts
	})
	for _, test := range []struct {
		name   string
		raw    []byte
		at     time.Time
		maxAge time.Duration
		want   error
	}{
		{"fresh before nextUpdate", raw, at.Add(time.Minute - time.Nanosecond), 0, nil},
		{"nextUpdate exclusive", raw, at.Add(time.Minute), 0, pki.ErrUnavailable},
		{"thisUpdate future", raw, at.Add(-time.Minute - time.Nanosecond), 0, pki.ErrUnavailable},
		{"missing nextUpdate bounded", noNext, at, 2 * time.Minute, nil},
		{"missing nextUpdate expires", noNext, at, 30 * time.Second, pki.ErrUnavailable},
		{"explicit nextUpdate not extended", raw, at.Add(time.Minute), 30 * 24 * time.Hour, pki.ErrUnavailable},
		{"explicit nextUpdate not shortened", raw, at, time.Second, nil},
	} {
		t.Run(test.name, func(t *testing.T) {
			verifier, err := pki.NewVerifier(pki.Config{Roots: [][]byte{c.root.Raw}, Revocation: pki.RequireCRL, CRL: pki.CRLOptions{MaxAge: test.maxAge}})
			if err != nil {
				t.Fatal(err)
			}
			result, _, err := verifier.Verify(t.Context(), c.leaf.Raw, test.at, pki.Evidence{CRLs: [][]byte{test.raw}})
			if test.want != nil {
				if result != nil || !errors.Is(err, test.want) {
					t.Fatal(result != nil, err)
				}
			} else if err != nil || result == nil {
				t.Fatal(result != nil, err)
			}
		})
	}
	for _, duration := range []time.Duration{-1, 31 * 24 * time.Hour} {
		if verifier, err := pki.NewVerifier(pki.Config{Roots: [][]byte{c.root.Raw}, CRL: pki.CRLOptions{MaxAge: duration}}); verifier != nil || !errors.Is(err, pki.ErrPolicy) {
			t.Fatal(verifier != nil, err)
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	verifier, err := pki.NewVerifier(pki.Config{Roots: [][]byte{c.root.Raw}, Revocation: pki.RequireCRL})
	if err != nil {
		t.Fatal(err)
	}
	if result, _, err := verifier.Verify(ctx, c.leaf.Raw, at, pki.Evidence{CRLs: [][]byte{raw}}); result != nil || !errors.Is(err, context.Canceled) {
		t.Fatal(result != nil, err)
	}
}

func TestCRLRelativeDistributionPoints(t *testing.T) {
	c := makeChain(t)
	at := verificationTime()
	relative := func(value string) []byte {
		return der.Ctx(0, der.Wrap(2, 1, true, der.Seq(der.OID(asn1.ObjectIdentifier{2, 5, 4, 3}), der.Wrap(0, asn1.TagUTF8String, false, []byte(value)))))
	}
	leaf := p6LeafExtensions(t, c, []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, 31}, Value: der.Seq(der.Seq(relative("partition")))}})
	for _, test := range []struct {
		name, value string
		want        error
	}{{"matching relative name", "PARTITION", nil}, {"different relative name", "other", pki.ErrUnavailable}} {
		t.Run(test.name, func(t *testing.T) {
			source := p6CRL(t, c, 1, at.Add(-time.Minute), at.Add(time.Hour), -1, der.Seq(relative(test.value)), nil)
			verifier, err := pki.NewVerifier(pki.Config{Roots: [][]byte{c.root.Raw}, Revocation: pki.RequireCRL})
			if err != nil {
				t.Fatal(err)
			}
			result, _, err := verifier.Verify(t.Context(), leaf.Raw, at, pki.Evidence{CRLs: [][]byte{source}})
			if test.want != nil {
				if result != nil || !errors.Is(err, test.want) {
					t.Fatal(result != nil, err)
				}
			} else if result == nil || err != nil {
				t.Fatal(result != nil, err)
			}
		})
	}
}

func TestCRLRequiresSameTargetTrustAnchor(t *testing.T) {
	c, other := makeChain(t), makeChain(t)
	at := verificationTime()
	otherRoot := *other.root
	otherRoot.Subject = pkix.Name{CommonName: "other trust anchor"}
	otherRoot.RawSubject = nil
	raw, err := x509.CreateCertificate(rand.Reader, &otherRoot, &otherRoot, other.rootKey.Public(), other.rootKey)
	if err != nil {
		t.Fatal(err)
	}
	other.root, err = x509.ParseCertificate(raw)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(10), Subject: pkix.Name{CommonName: "foreign delegate"}, NotBefore: at.Add(-time.Hour), NotAfter: at.Add(time.Hour), KeyUsage: x509.KeyUsageCRLSign, SubjectKeyId: []byte{9, 8, 7}}
	raw, err = x509.CreateCertificate(rand.Reader, template, other.root, c.leafKey.Public(), other.rootKey)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := x509.ParseCertificate(raw)
	if err != nil {
		t.Fatal(err)
	}
	point := der.Seq(p6PointName("urn:foreign"), der.Wrap(2, 2, true, der.Ctx(4, signer.RawSubject)))
	leaf := p6LeafExtensions(t, c, []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, 31}, Value: der.Seq(point)}})
	scope := der.Seq(p6PointName("urn:foreign"), der.Wrap(2, 4, false, []byte{255}))
	source := p6CRL(t, chainData{root: signer, rootKey: c.leafKey}, 1, at.Add(-time.Minute), at.Add(time.Hour), -1, scope, nil)
	verifier, err := pki.NewVerifier(pki.Config{Roots: [][]byte{c.root.Raw, other.root.Raw}, Intermediates: [][]byte{signer.Raw}, Revocation: pki.RequireCRL})
	if err != nil {
		t.Fatal(err)
	}
	if result, _, err := verifier.Verify(t.Context(), leaf.Raw, at, pki.Evidence{CRLs: [][]byte{source}}); result != nil || !errors.Is(err, pki.ErrUnavailable) {
		t.Fatal("unrelated trusted root authenticated a CRL for this target", result != nil, err)
	}
}

func TestCRLDistributionPointNamePreparation(t *testing.T) {
	c := makeChain(t)
	at := verificationTime()
	for _, test := range []struct {
		name, a, b string
		tag        int
		match      bool
	}{
		{"URI scheme and host", "HTTPS://EXAMPLE.test/status", "https://example.test/status", 6, true},
		{"URI default port", "https://example.test:443/status", "https://example.test/status", 6, true},
		{"URI unreserved and dots", "https://example.test/a/../%73tatus", "https://example.test/status", 6, true},
		{"URI path case", "https://example.test/Status", "https://example.test/status", 6, false},
		{"URI reserved slash", "https://example.test/a%2fb", "https://example.test/a/b", 6, false},
		{"URI empty query", "https://example.test/status?", "https://example.test/status", 6, false},
		{"LDAP default port and path", "ldap://EXAMPLE.test:389", "ldap://example.test/", 6, true},
		{"FTP default port", "ftp://EXAMPLE.test:21/a", "ftp://example.test/a", 6, true},
		{"HTTP double slash significant", "http://example.test//a", "http://example.test/a", 6, false},
		{"mail host case", "local@EXAMPLE.test", "local@example.test", 1, true},
		{"mail local case", "Local@example.test", "local@example.test", 1, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			point := func(v string) []byte {
				return der.Ctx(0, der.Wrap(2, 0, true, der.Wrap(2, test.tag, false, []byte(v))))
			}
			leaf := p6LeafExtensions(t, c, []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, 31}, Value: der.Seq(der.Seq(point(test.a)))}})
			raw := p6CRL(t, c, 1, at.Add(-time.Minute), at.Add(time.Hour), -1, der.Seq(point(test.b)), nil)
			verifier, err := pki.NewVerifier(pki.Config{Roots: [][]byte{c.root.Raw}, Revocation: pki.RequireCRL})
			if err != nil {
				t.Fatal(err)
			}
			result, _, err := verifier.Verify(t.Context(), leaf.Raw, at, pki.Evidence{CRLs: [][]byte{raw}})
			if test.match {
				if err != nil || result == nil {
					t.Fatal(result != nil, err)
				}
			} else if result != nil || !errors.Is(err, pki.ErrUnavailable) {
				t.Fatal(result != nil, err)
			}
		})
	}
}

func TestCRLStrictExtensionDefaults(t *testing.T) {
	c := makeChain(t)
	for _, entry := range []bool{false, true} {
		t.Run(map[bool]string{false: "list", true: "entry"}[entry], func(t *testing.T) {
			raw := makeCRL(t, c, entry, nil)
			changed := p6TransformCRL(t, raw, c, func(fields []asn1.RawValue) [][]byte {
				parts := make([][]byte, len(fields))
				for index, field := range fields {
					parts[index] = field.FullBytes
				}
				addFalse := func(value asn1.RawValue) []byte {
					extensions, err := der.Sequence(value, 1, 32)
					if err != nil {
						t.Fatal(err)
					}
					encoded := make([][]byte, len(extensions))
					altered := false
					for index, extension := range extensions {
						elements, err := der.Sequence(extension, 2, 3)
						if err != nil {
							t.Fatal(err)
						}
						encoded[index] = extension.FullBytes
						if len(elements) == 2 && !altered {
							encoded[index] = der.Seq(elements[0].FullBytes, []byte{1, 1, 0}, elements[1].FullBytes)
							altered = true
						}
					}
					if !altered {
						t.Fatal("fixture lacks noncritical extension")
					}
					return der.Seq(encoded...)
				}
				if !entry {
					value, err := der.Explicit(fields[len(fields)-1], 0)
					if err != nil {
						t.Fatal(err)
					}
					parts[len(parts)-1] = der.Ctx(0, addFalse(value))
				} else {
					entries, err := der.Sequence(fields[5], 1, 100)
					if err != nil {
						t.Fatal(err)
					}
					elements, err := der.Sequence(entries[0], 2, 3)
					if err != nil {
						t.Fatal(err)
					}
					reason := der.Seq(der.OID(asn1.ObjectIdentifier{2, 5, 29, 21}), []byte{1, 1, 0}, der.Octets([]byte{10, 1, 1}))
					parts[5] = der.Seq(der.Seq(elements[0].FullBytes, elements[1].FullBytes, der.Seq(reason)))
				}
				return parts
			})
			verifier, err := pki.NewVerifier(pki.Config{Roots: [][]byte{c.root.Raw}, Revocation: pki.RequireCRL})
			if err != nil {
				t.Fatal(err)
			}
			if result, _, err := verifier.Verify(t.Context(), c.leaf.Raw, verificationTime(), pki.Evidence{CRLs: [][]byte{changed}}); result != nil || !errors.Is(err, pki.ErrEvidence) {
				t.Fatal(result != nil, err)
			}
			if parsed, err := keys.ParseCRL(changed, keys.Limits{}); parsed != nil || !errors.Is(err, keys.ErrFormat) {
				t.Fatal(parsed != nil, err)
			}
		})
	}
}

func TestCertificateStrictDefaults(t *testing.T) {
	c := makeChain(t)
	for _, kind := range []string{"explicit v1 version", "explicit extension false"} {
		t.Run(kind, func(t *testing.T) {
			value, err := der.Read(c.leaf.Raw, 1<<20)
			if err != nil {
				t.Fatal(err)
			}
			outer, err := der.Sequence(value, 3, 3)
			if err != nil {
				t.Fatal(err)
			}
			fields, err := der.Sequence(outer[0], 6, 10)
			if err != nil {
				t.Fatal(err)
			}
			parts := make([][]byte, 0, len(fields))
			for index, field := range fields {
				if kind == "explicit v1 version" {
					if index == 0 {
						parts = append(parts, der.Ctx(0, []byte{2, 1, 0}))
						continue
					}
					if field.Class == 2 {
						continue
					}
				} else if field.Class == 2 && field.Tag == 3 {
					value, err := der.Explicit(field, 3)
					if err != nil {
						t.Fatal(err)
					}
					entries, err := der.Sequence(value, 1, 256)
					if err != nil {
						t.Fatal(err)
					}
					encoded := make([][]byte, len(entries))
					changed := false
					for position, entry := range entries {
						fields, err := der.Sequence(entry, 2, 3)
						if err != nil {
							t.Fatal(err)
						}
						encoded[position] = entry.FullBytes
						if len(fields) == 2 && !changed {
							encoded[position] = der.Seq(fields[0].FullBytes, []byte{1, 1, 0}, fields[1].FullBytes)
							changed = true
						}
					}
					if !changed {
						t.Fatal("fixture lacks noncritical extension")
					}
					parts = append(parts, der.Ctx(3, der.Seq(encoded...)))
					continue
				}
				parts = append(parts, field.FullBytes)
			}
			body := der.Seq(parts...)
			algorithm, err := signature.Algorithm(outer[1])
			if err != nil {
				t.Fatal(err)
			}
			signed, err := signature.Sign(t.Context(), c.rootKey, algorithm, body)
			if err != nil {
				t.Fatal(err)
			}
			bits, _ := asn1.Marshal(asn1.BitString{Bytes: signed, BitLength: len(signed) * 8})
			raw := der.Seq(body, outer[1].FullBytes, bits)
			if certificate, err := keys.ParseCertificate(raw, keys.Limits{}); certificate != nil || !errors.Is(err, keys.ErrFormat) {
				t.Fatal(certificate != nil, err)
			}
			if request, err := pki.CreateOCSPRequest(raw, c.root.Raw, 0, nil); request != nil || !errors.Is(err, pki.ErrCertificate) {
				t.Fatal(request != nil, err)
			}
		})
	}
}

func TestCertificateMixedRelativeDistributionPoints(t *testing.T) {
	c := makeChain(t)
	const uri = "https://example.test/original.crl"
	relative := der.Ctx(0, der.Wrap(2, 1, true, der.Seq(der.OID(asn1.ObjectIdentifier{2, 5, 4, 3}), der.Wrap(0, asn1.TagUTF8String, false, []byte("partition")))))
	template := *c.leaf
	template.ExtraExtensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, 31}, Value: der.Seq(der.Seq(relative), der.Seq(p6PointName(uri)), der.Seq(p6PointName("urn:xmlsec:private-relative-dp-view")))}}
	raw, err := x509.CreateCertificate(rand.Reader, &template, c.root, c.leafKey.Public(), c.rootKey)
	if err != nil {
		t.Fatal(err)
	}
	original := bytes.Clone(raw)
	parsed, err := keys.ParseCertificate(raw, keys.Limits{})
	if err != nil {
		t.Fatal(err)
	}
	if len(parsed.CRLDistributionPoints) != 2 || parsed.CRLDistributionPoints[0] != uri || parsed.CRLDistributionPoints[1] != "urn:xmlsec:private-relative-dp-view" {
		t.Fatal(parsed.CRLDistributionPoints)
	}
	if !bytes.Equal(parsed.Raw, raw) || !bytes.Equal(parsed.Extensions[len(parsed.Extensions)-1].Value, template.ExtraExtensions[0].Value) {
		t.Fatal("original encoding was lost")
	}
	if parsed.CheckSignatureFrom(c.root) != nil {
		t.Fatal("original signed TBS was replaced")
	}
	clear(raw)
	if !bytes.Equal(parsed.Raw, original) {
		t.Fatal("returned certificate aliases caller input")
	}
}

func TestCRLIssuerAlternativeNameFallback(t *testing.T) {
	c := makeChain(t)
	at := verificationTime()
	const uri = "https://example.test/issuer"
	leaf := p6LeafExtensions(t, c, []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, 18}, Value: der.Seq(der.Wrap(2, 6, false, []byte(uri)))}})
	raw := p6CRL(t, c, 1, at.Add(-time.Minute), at.Add(time.Hour), -1, der.Seq(p6PointName(uri)), nil)
	verifier, err := pki.NewVerifier(pki.Config{Roots: [][]byte{c.root.Raw}, Revocation: pki.RequireCRL})
	if err != nil {
		t.Fatal(err)
	}
	if result, _, err := verifier.Verify(t.Context(), leaf.Raw, at, pki.Evidence{CRLs: [][]byte{raw}}); result == nil || err != nil {
		t.Fatal(result != nil, err)
	}
}

func TestCRLRevocationMetadata(t *testing.T) {
	c := makeChain(t)
	at := verificationTime()
	invalidity := at.Add(-2 * time.Hour)
	value, _ := asn1.MarshalWithParams(invalidity, "generalized")
	source := p6CRL(t, c, 1, at.Add(-time.Minute), at.Add(time.Hour), -1, nil, []x509.RevocationListEntry{{SerialNumber: c.leaf.SerialNumber, RevocationTime: at.Add(-time.Hour), ReasonCode: 1, ExtraExtensions: []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, 24}, Value: value}}}})
	verifier, err := pki.NewVerifier(pki.Config{Roots: [][]byte{c.root.Raw}, Revocation: pki.RequireCRL})
	if err != nil {
		t.Fatal(err)
	}
	result, report, err := verifier.Verify(t.Context(), c.leaf.Raw, at, pki.Evidence{CRLs: [][]byte{source}})
	if result != nil || !errors.Is(err, pki.ErrRevoked) {
		t.Fatal(result != nil, err)
	}
	facts := report.Evidence()
	if len(facts) != 1 {
		t.Fatal(len(facts))
	}
	fact := facts[0]
	reason, present := fact.RevocationReason()
	if fact.AuthenticationStatus() != pki.Valid || fact.AssertedStatus() != "revoked" || !fact.RevokedAt().Equal(at.Add(-time.Hour)) || !fact.InvalidityDate().Equal(invalidity) || !present || reason != 1 || fact.SignatureAlgorithmOID() == "" || fact.CoveredReasons() != 0 {
		t.Fatal("lost signed revocation facts")
	}
	if !bytes.Equal(fact.DER(), source) {
		t.Fatal("evidence source changed")
	}
}

func TestCRLUnknownExtensionCriticality(t *testing.T) {
	c := makeChain(t)
	at := verificationTime()
	for _, entry := range []bool{false, true} {
		for _, critical := range []bool{false, true} {
			name := "list"
			if entry {
				name = "entry"
			}
			if critical {
				name += " critical"
			} else {
				name += " noncritical"
			}
			t.Run(name, func(t *testing.T) {
				extension := pkix.Extension{Id: asn1.ObjectIdentifier{1, 2, 3, 4, 5}, Critical: critical, Value: []byte{5, 0}}
				template := &x509.RevocationList{Number: big.NewInt(1), ThisUpdate: at.Add(-time.Minute), NextUpdate: at.Add(time.Hour)}
				if entry {
					template.RevokedCertificateEntries = []x509.RevocationListEntry{{SerialNumber: big.NewInt(999), RevocationTime: at.Add(-time.Hour), ExtraExtensions: []pkix.Extension{extension}}}
				} else {
					template.ExtraExtensions = []pkix.Extension{extension}
				}
				source := makeCRL(t, c, false, template)
				verifier, err := pki.NewVerifier(pki.Config{Roots: [][]byte{c.root.Raw}, Revocation: pki.RequireCRL})
				if err != nil {
					t.Fatal(err)
				}
				result, _, err := verifier.Verify(t.Context(), c.leaf.Raw, at, pki.Evidence{CRLs: [][]byte{source}})
				if critical {
					if result != nil || !errors.Is(err, pki.ErrUnsupported) {
						t.Fatal(result != nil, err)
					}
				} else if result == nil || err != nil {
					t.Fatal(result != nil, err)
				}
			})
		}
	}
}

func TestCRLRejectsInvalidURIs(t *testing.T) {
	c := makeChain(t)
	at := verificationTime()
	for _, uri := range []string{"urn:", "http://", "https:opaque", "https://example.test/back\\slash", "https://example.test/<invalid>", "https://example.test/%GG", "https://example.test/a[b]", "https://example.test/a#b#c"} {
		t.Run(uri, func(t *testing.T) {
			leaf := p6LeafExtensions(t, c, []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, 31}, Value: der.Seq(der.Seq(p6PointName(uri)))}})
			source := p6CRL(t, c, 1, at.Add(-time.Minute), at.Add(time.Hour), -1, der.Seq(p6PointName(uri)), nil)
			verifier, err := pki.NewVerifier(pki.Config{Roots: [][]byte{c.root.Raw}, Revocation: pki.RequireCRL})
			if err != nil {
				t.Fatal(err)
			}
			if result, _, err := verifier.Verify(t.Context(), leaf.Raw, at, pki.Evidence{CRLs: [][]byte{source}}); result != nil || !errors.Is(err, pki.ErrEvidence) {
				t.Fatal(result != nil, err)
			}
		})
	}
}
