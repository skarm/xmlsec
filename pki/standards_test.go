package pki_test

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"math/big"
	"strconv"
	"testing"
	"time"

	"github.com/skarm/xmlsec/evidence"
	"github.com/skarm/xmlsec/internal/der"
	"github.com/skarm/xmlsec/internal/historical"
	"github.com/skarm/xmlsec/internal/historicalproof"
	"github.com/skarm/xmlsec/internal/signature"
	"github.com/skarm/xmlsec/internal/testutil/testcert"
	"github.com/skarm/xmlsec/keys"
	"github.com/skarm/xmlsec/pki"
	"github.com/skarm/xmlsec/timestamp"
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

func p7Proofs(t *testing.T, now time.Time, objects [][]byte, roles []string, at time.Time) *historicalproof.Set {
	t.Helper()
	source := sha256.Sum256([]byte("published historical building-block vector"))
	facts := make([]historicalproof.Fact, 0, len(objects))
	for index, object := range objects {
		facts = append(facts, historicalproof.Fact{Digest: sha256.Sum256(object), Source: source, At: at, Kind: historicalproof.Kind(roles[index])})
	}
	set, err := historicalproof.New(t.Context(), now, facts)
	if err != nil {
		t.Fatal(err)
	}
	return set
}

func TestHistoricalExpiredTargetAuthentication(t *testing.T) {
	c := makeChain(t)
	now := verificationTime().Add(3 * time.Hour)
	raw := makeCRL(t, c, false, nil)
	current, err := pki.NewVerifier(pki.Config{Roots: [][]byte{c.root.Raw}, Revocation: pki.RequireCRL})
	if err != nil {
		t.Fatal(err)
	}
	if result, _, err := current.Verify(t.Context(), c.leaf.Raw, now, pki.Evidence{CRLs: [][]byte{raw}}); result != nil || !errors.Is(err, pki.ErrCertificate) {
		t.Fatal(result != nil, err)
	}
	session, err := current.NewHistoricalSession(t.Context(), pki.HistoricalOptions{}, now, pki.Evidence{CRLs: [][]byte{raw}})
	if err != nil {
		t.Fatal(err)
	}
	paths, err := session.Paths(t.Context(), c.leaf.Raw)
	if err != nil || len(paths) != 1 {
		t.Fatal(len(paths), err)
	}
	checked, err := session.CheckPath(t.Context(), paths[0])
	if err != nil || checked == nil || checked.Model() != pki.ShellModel || !checked.ReferenceTime().Equal(c.leaf.NotBefore) {
		t.Fatal(checked != nil, err)
	}
	claims, err := session.AuthenticateEvidence(t.Context(), paths[0])
	if err != nil || len(claims) != 1 {
		t.Fatal(len(claims), err)
	}
	claim := claims[0]
	if claim.AuthenticationStatus() != pki.Valid || !bytes.Equal(claim.DER(), raw) || !claim.ValidationTime().Equal(verificationTime().Add(-time.Minute)) || claim.SignerAuthority() != "issuer" {
		t.Fatal("unbound historical assertion")
	}
	chain := claim.SignerChainDER()
	if len(chain) != 1 || !bytes.Equal(chain[0], c.root.Raw) {
		t.Fatal("wrong signer path")
	}
	clear(chain[0])
	if !bytes.Equal(claim.SignerChainDER()[0], c.root.Raw) {
		t.Fatal("mutable signer path")
	}
	clear(raw)
	if len(claim.DER()) == 0 || bytes.Equal(claim.DER(), raw) {
		t.Fatal("session retained mutable evidence")
	}
	foreign, err := current.NewHistoricalSession(t.Context(), pki.HistoricalOptions{}, now, pki.Evidence{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := foreign.CheckPath(t.Context(), paths[0]); !errors.Is(err, pki.ErrPolicy) {
		t.Fatal("foreign path accepted", err)
	}
}

func TestHistoricalCertificateTimeSliding(t *testing.T) {
	c := makeChain(t)
	now := verificationTime().Add(3 * time.Hour)
	raw := makeCRL(t, c, false, nil)
	input := pki.Evidence{CRLs: [][]byte{raw}}
	options := pki.HistoricalOptions{}
	config := pki.HistoricalConfig{PKI: pki.Config{Roots: [][]byte{c.root.Raw}, Revocation: pki.RequireCRL}, HistoricalOptions: options}
	for _, test := range []struct {
		name    string
		objects [][]byte
		roles   []string
		proofAt time.Time
		pass    bool
	}{
		{"old authenticated data", [][]byte{c.leaf.Raw, raw}, []string{"certificate", "crl"}, verificationTime(), true},
		{"proof at control inclusive", [][]byte{c.leaf.Raw, raw}, []string{"certificate", "crl"}, now, true},
		{"missing certificate proof", [][]byte{raw}, []string{"crl"}, verificationTime(), false},
		{"missing CRL proof", [][]byte{c.leaf.Raw}, []string{"certificate"}, verificationTime(), false},
		{"wrong CRL role", [][]byte{c.leaf.Raw, raw}, []string{"certificate", "data"}, verificationTime(), false},
	} {
		t.Run(test.name, func(t *testing.T) {
			session, err := pki.NewHistoricalSession(t.Context(), config, now, input)
			if err != nil {
				t.Fatal(err)
			}
			proofs := p7Proofs(t, now, test.objects, test.roles, test.proofAt)
			result, report, err := session.ValidatePast(t.Context(), c.leaf.Raw, proofs)
			if !test.pass {
				if result != nil || !errors.Is(err, pki.ErrUnavailable) || report.SubIndication() != "NO_POE" {
					t.Fatal(result != nil, report.SubIndication(), err)
				}
				return
			}
			bound := verificationTime().Add(-time.Minute)
			if err != nil || result == nil || !result.ValidationTime().Equal(bound) {
				t.Fatal(result != nil, err)
			}
			steps := report.Transitions()
			if len(steps) != 1 || steps[0].Reason != "freshness" || !steps[0].Before.Equal(now) || !steps[0].After.Equal(bound) {
				t.Fatal(steps)
			}
			steps[0].Reason = "forged"
			if report.Transitions()[0].Reason != "freshness" {
				t.Fatal("mutable transitions")
			}
			if len(result.Evidence()) != 1 || !bytes.Equal(result.Path().ChainDER()[0], c.leaf.Raw) {
				t.Fatal("lost process source/path")
			}
		})
	}
	session, err := pki.NewHistoricalSession(t.Context(), config, now, input)
	if err != nil {
		t.Fatal(err)
	}
	if result, _, err := session.ValidatePast(t.Context(), c.leaf.Raw, &historicalproof.Set{}); result != nil || !errors.Is(err, pki.ErrPolicy) {
		t.Fatal(result != nil, err)
	}
	different := p7Proofs(t, now.Add(time.Second), [][]byte{c.leaf.Raw, raw}, []string{"certificate", "crl"}, verificationTime())
	if result, _, err := session.ValidatePast(t.Context(), c.leaf.Raw, different); result != nil || !errors.Is(err, pki.ErrPolicy) {
		t.Fatal("cross-operation proof", result != nil, err)
	}
}

func TestHistoricalRevocationAndFreshnessBoundaries(t *testing.T) {
	c := makeChain(t)
	now := verificationTime()
	config := pki.Config{Roots: [][]byte{c.root.Raw}, Revocation: pki.RequireCRL}
	for _, test := range []struct {
		name      string
		issued    time.Time
		next      time.Time
		model     pki.ValidityModel
		reason    int
		freshness *time.Duration
		want      time.Time
		pass      bool
	}{
		{"issued strictly before", now.Add(-time.Minute), now.Add(time.Minute), pki.ShellModel, -1, nil, now, true},
		{"issued exactly at control", now, now.Add(time.Minute), pki.ShellModel, -1, nil, time.Time{}, false},
		{"missing next update", now.Add(-time.Minute), time.Time{}, pki.ShellModel, -1, nil, now.Add(-time.Minute), true},
		{"shell revocation", now.Add(-time.Minute), now.Add(time.Minute), pki.ShellModel, 3, nil, now.Add(-2 * time.Minute), true},
		{"chain noncompromise", now.Add(-time.Minute), now.Add(time.Minute), pki.ChainModel, 3, nil, now, true},
		{"chain key compromise", now.Add(-time.Minute), now.Add(time.Minute), pki.ChainModel, 1, nil, now.Add(-2 * time.Minute), true},
		{"chain unknown reason", now.Add(-time.Minute), now.Add(time.Minute), pki.ChainModel, 0, nil, now.Add(-2 * time.Minute), true},
	} {
		t.Run(test.name, func(t *testing.T) {
			var entries []x509.RevocationListEntry
			if test.reason >= 0 {
				entries = []x509.RevocationListEntry{{SerialNumber: c.leaf.SerialNumber, RevocationTime: now.Add(-2 * time.Minute), ReasonCode: test.reason}}
			}
			next := test.next
			if next.IsZero() {
				next = now.Add(time.Minute)
			}
			raw := p6CRL(t, c, 1, test.issued, next, -1, nil, entries)
			if test.next.IsZero() {
				raw = p6TransformCRL(t, raw, c, func(fields []asn1.RawValue) [][]byte {
					parts := make([][]byte, 0, len(fields))
					for index, field := range fields {
						if index != 4 {
							parts = append(parts, field.FullBytes)
						}
					}
					return parts
				})
			}
			session, err := pki.NewHistoricalSession(t.Context(), pki.HistoricalConfig{PKI: config, Model: test.model, RevocationFreshness: test.freshness}, now, pki.Evidence{CRLs: [][]byte{raw}})
			if err != nil {
				t.Fatal(err)
			}
			proofs := p7Proofs(t, now, [][]byte{c.leaf.Raw, raw}, []string{"certificate", "crl"}, now)
			result, _, err := session.ValidatePast(t.Context(), c.leaf.Raw, proofs)
			if test.pass {
				if err != nil || result == nil || !result.ValidationTime().Equal(test.want) {
					t.Fatal(result != nil, err)
				}
			} else if result != nil || !errors.Is(err, pki.ErrUnavailable) {
				t.Fatal(result != nil, err)
			}
		})
	}
}

func TestHistoricalCurrentPolicy(t *testing.T) {
	c := makeChain(t)
	now := verificationTime()
	raw := makeCRL(t, c, false, nil)
	zero, minute, two := time.Duration(0), time.Minute, 2*time.Minute
	digest := sha256.Sum256(c.root.Raw)
	root := hex.EncodeToString(digest[:])
	for _, tc := range []struct {
		name    string
		options pki.HistoricalOptions
		sub     string
	}{
		{"implicit interval", pki.HistoricalOptions{}, ""},
		{"explicit zero", pki.HistoricalOptions{RevocationFreshness: &zero}, "TRY_LATER"},
		{"strict freshness equality", pki.HistoricalOptions{RevocationFreshness: &minute}, "TRY_LATER"},
		{"configured fresh", pki.HistoricalOptions{RevocationFreshness: &two}, ""},
		{"anchor sunset at now", pki.HistoricalOptions{TrustAnchorSunsets: map[string]time.Time{root: now}}, "NO_CERTIFICATE_CHAIN_FOUND_NO_POE"},
		{"anchor future sunset", pki.HistoricalOptions{TrustAnchorSunsets: map[string]time.Time{root: now.Add(time.Second)}}, ""},
		{"signature cutoff at now", pki.HistoricalOptions{CryptoConstraints: []pki.CryptoConstraint{{SignatureAlgorithm: x509.ECDSAWithSHA256, ReliableUntil: now}}}, "CRYPTO_CONSTRAINTS_FAILURE_NO_POE"},
		{"digest cutoff", pki.HistoricalOptions{CryptoConstraints: []pki.CryptoConstraint{{Hash: crypto.SHA256, ReliableUntil: now.Add(-time.Second)}}}, "CRYPTO_CONSTRAINTS_FAILURE_NO_POE"},
		{"weak key cutoff", pki.HistoricalOptions{CryptoConstraints: []pki.CryptoConstraint{{PublicKeyAlgorithm: x509.ECDSA, MinimumKeyBits: 384, ReliableUntil: now}}}, "CRYPTO_CONSTRAINTS_FAILURE_NO_POE"},
		{"sufficient key size", pki.HistoricalOptions{CryptoConstraints: []pki.CryptoConstraint{{PublicKeyAlgorithm: x509.ECDSA, MinimumKeyBits: 256, ReliableUntil: now}}}, ""},
		{"other digest unaffected", pki.HistoricalOptions{CryptoConstraints: []pki.CryptoConstraint{{Hash: crypto.SHA512, ReliableUntil: now}}}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			session, err := pki.NewHistoricalSession(t.Context(), pki.HistoricalConfig{PKI: pki.Config{Roots: [][]byte{c.root.Raw}, Revocation: pki.RequireCRL}, HistoricalOptions: tc.options}, now, pki.Evidence{CRLs: [][]byte{raw}})
			if err != nil {
				t.Fatal(err)
			}
			current, _, err := session.VerifyCurrent(t.Context(), c.leaf.Raw)
			if err != nil || current == nil {
				t.Fatal("current verifier changed", err)
			}
			sub, err := session.CheckCurrentPolicy(t.Context(), current)
			if sub != tc.sub || (err == nil) != (tc.sub == "") {
				t.Fatal(sub, err)
			}
			if _, err := session.CheckCurrentPolicy(t.Context(), nil); !errors.Is(err, pki.ErrPolicy) {
				t.Fatal("zero current result accepted", err)
			}
		})
	}
}

func TestHistoricalCryptoAndSunsetProofs(t *testing.T) {
	c := makeChain(t)
	now := verificationTime()
	raw := makeCRL(t, c, false, nil)
	cutoff := now.Add(-30 * time.Second)
	hash := sha256.Sum256(c.root.Raw)
	root := hex.EncodeToString(hash[:])
	for _, tc := range []struct {
		name          string
		options       pki.HistoricalOptions
		proofAt, want time.Time
		pass          bool
	}{
		{"algorithm protected before cutoff", pki.HistoricalOptions{CryptoConstraints: []pki.CryptoConstraint{{Hash: crypto.SHA256, ReliableUntil: cutoff}}}, now.Add(-45 * time.Second), cutoff, true},
		{"proof exactly at cutoff", pki.HistoricalOptions{CryptoConstraints: []pki.CryptoConstraint{{Hash: crypto.SHA256, ReliableUntil: cutoff}}}, cutoff, time.Time{}, false},
		{"current observation cannot rescue old algorithm", pki.HistoricalOptions{CryptoConstraints: []pki.CryptoConstraint{{Hash: crypto.SHA256, ReliableUntil: cutoff}}}, now, time.Time{}, false},
		{"anchor cutoff initial bound", pki.HistoricalOptions{TrustAnchorSunsets: map[string]time.Time{root: cutoff}}, now.Add(-45 * time.Second), cutoff, true},
		{"certificate exists only after sunset", pki.HistoricalOptions{TrustAnchorSunsets: map[string]time.Time{root: cutoff}}, now, time.Time{}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			session, err := pki.NewHistoricalSession(t.Context(), pki.HistoricalConfig{PKI: pki.Config{Roots: [][]byte{c.root.Raw}, Revocation: pki.RequireCRL}, HistoricalOptions: tc.options}, now, pki.Evidence{CRLs: [][]byte{raw}})
			if err != nil {
				t.Fatal(err)
			}
			result, report, err := session.ValidatePast(t.Context(), c.leaf.Raw, p7Proofs(t, now, [][]byte{c.leaf.Raw, raw}, []string{"certificate", "crl"}, tc.proofAt))
			if tc.pass {
				if err != nil || result == nil || !result.ValidationTime().Equal(tc.want) || len(report.Transitions()) != 1 {
					t.Fatal(result != nil, report.Transitions(), err)
				}
			} else if result != nil || !errors.Is(err, pki.ErrUnavailable) {
				t.Fatal(result != nil, err)
			}
		})
	}
}

func p7Response(t *testing.T, c chainData, template pki.OCSPResponseTemplate) []byte {
	t.Helper()
	request, err := pki.CreateOCSPRequest(c.leaf.Raw, c.root.Raw, crypto.SHA256, nil)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := pki.CreateOCSPResponse(t.Context(), request, c.leaf.Raw, c.root.Raw, c.root.Raw, c.rootKey, template)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestHistoricalOCSPAndConflictingSources(t *testing.T) {
	c := makeChain(t)
	now := verificationTime()
	two := 2 * time.Minute
	old := p7Response(t, c, pki.OCSPResponseTemplate{Status: pki.OCSPGood, ProducedAt: now, ThisUpdate: now.Add(-10 * time.Minute), NextUpdate: now.Add(time.Minute)})
	latest := p7Response(t, c, pki.OCSPResponseTemplate{Status: pki.OCSPGood, ProducedAt: now, ThisUpdate: now.Add(-time.Minute), NextUpdate: now.Add(time.Minute)})
	revoked := p7Response(t, c, pki.OCSPResponseTemplate{Status: pki.OCSPRevoked, ProducedAt: now, ThisUpdate: now.Add(-30 * time.Second), NextUpdate: now.Add(time.Minute), RevokedAt: now.Add(-5 * time.Minute), RevocationReason: 1})
	unknown := p7Response(t, c, pki.OCSPResponseTemplate{Status: pki.OCSPUnknown, ProducedAt: now, ThisUpdate: now.Add(-30 * time.Second), NextUpdate: now.Add(time.Minute)})
	goodCRL := makeCRL(t, c, false, nil)
	for _, tc := range []struct {
		name            string
		mode            pki.RevocationMode
		responses, crls [][]byte
		want            time.Time
		pass            bool
	}{
		{"thisUpdate controls freshness", pki.RequireOCSP, [][]byte{old}, nil, now.Add(-10 * time.Minute), true},
		{"latest status replaces stale good", pki.RequireOCSP, [][]byte{old, latest}, nil, now, true},
		{"latest revocation beats earlier good", pki.RequireOCSP, [][]byte{latest, revoked}, nil, now.Add(-5 * time.Minute), true},
		{"latest unknown is not old good", pki.RequireOCSP, [][]byte{latest, unknown}, nil, time.Time{}, false},
		{"OCSP revocation not hidden by CRL", pki.RequireCRL, [][]byte{revoked}, [][]byte{goodCRL}, now.Add(-5 * time.Minute), true},
		{"configured CRL family still required", pki.RequireCRL, [][]byte{latest}, nil, time.Time{}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			input := pki.Evidence{CRLs: tc.crls, OCSPResponses: tc.responses}
			session, err := pki.NewHistoricalSession(t.Context(), pki.HistoricalConfig{PKI: pki.Config{Roots: [][]byte{c.root.Raw}, Revocation: tc.mode}, RevocationFreshness: &two}, now, input)
			if err != nil {
				t.Fatal(err)
			}
			objects := make([][]byte, 1, 1+len(tc.responses)+len(tc.crls))
			objects[0] = c.leaf.Raw
			roles := make([]string, 1, 1+len(tc.responses)+len(tc.crls))
			roles[0] = "certificate"
			for _, raw := range tc.responses {
				objects = append(objects, raw)
				roles = append(roles, "ocsp")
			}
			for _, raw := range tc.crls {
				objects = append(objects, raw)
				roles = append(roles, "crl")
			}
			result, _, err := session.ValidatePast(t.Context(), c.leaf.Raw, p7Proofs(t, now, objects, roles, now))
			if tc.pass {
				if err != nil || result == nil || !result.ValidationTime().Equal(tc.want) {
					t.Fatal(result != nil, err)
				}
			} else if result != nil || !errors.Is(err, pki.ErrUnavailable) {
				t.Fatal(result != nil, err)
			}
		})
	}
}

func p7SingleExtension(t *testing.T, raw []byte, c chainData, extension pkix.Extension) []byte {
	t.Helper()
	encoded, err := asn1.Marshal(extension)
	if err != nil {
		t.Fatal(err)
	}
	return rewriteOCSPData(t, raw, c.rootKey, func(fields []asn1.RawValue) [][]byte {
		responses, err := der.Sequence(fields[2], 1, 64)
		if err != nil {
			t.Fatal(err)
		}
		single, err := der.Sequence(responses[0], 3, 5)
		if err != nil {
			t.Fatal(err)
		}
		responses[0].FullBytes = der.Seq(append(ocspFieldBytes(single), der.Ctx(1, der.Seq(encoded)))...)
		fields[2].FullBytes = der.Seq(ocspFieldBytes(responses)...)
		return ocspFieldBytes(fields)
	})
}

func TestHistoricalExpiredRetention(t *testing.T) {
	c := makeChain(t)
	now := verificationTime().Add(3 * time.Hour)
	issued := now.Add(-time.Minute)
	base := p6CRL(t, c, 1, issued, now.Add(time.Hour), -1, nil, nil)
	response := p7Response(t, c, pki.OCSPResponseTemplate{Status: pki.OCSPGood, ProducedAt: now, ThisUpdate: issued, NextUpdate: now.Add(time.Hour)})
	for _, kind := range []string{"crl", "ocsp"} {
		for _, tc := range []struct {
			name                    string
			from                    time.Time
			present, critical, pass bool
		}{
			{"no retention", time.Time{}, false, false, false},
			{"inclusive expiry cutoff", c.leaf.NotAfter, true, false, true},
			{"earlier cutoff", c.leaf.NotAfter.Add(-time.Second), true, false, true},
			{"cutoff excludes target", c.leaf.NotAfter.Add(time.Second), true, false, false},
			{"critical extension rejected", c.leaf.NotAfter, true, true, false},
		} {
			t.Run(kind+"/"+tc.name, func(t *testing.T) {
				input := pki.Evidence{}
				mode := pki.RequireCRL
				raw := base
				extension := pkix.Extension{Id: asn1.ObjectIdentifier{2, 5, 29, 60}, Critical: tc.critical, Value: der.Wrap(0, asn1.TagGeneralizedTime, false, []byte(tc.from.UTC().Format("20060102150405Z")))}
				if kind == "ocsp" {
					mode = pki.RequireOCSP
					raw = response
					extension.Id = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1, 6}
				}
				if tc.present {
					if kind == "crl" {
						raw = p6ReplaceCRLExtension(t, raw, c, extension)
					} else {
						raw = p7SingleExtension(t, raw, c, extension)
					}
				}
				if kind == "crl" {
					input.CRLs = [][]byte{raw}
				} else {
					input.OCSPResponses = [][]byte{raw}
				}
				session, err := pki.NewHistoricalSession(t.Context(), pki.HistoricalConfig{PKI: pki.Config{Roots: [][]byte{c.root.Raw}, Revocation: mode}}, now, input)
				if err != nil {
					t.Fatal(err)
				}
				result, _, err := session.ValidatePast(t.Context(), c.leaf.Raw, p7Proofs(t, now, [][]byte{c.leaf.Raw, raw}, []string{"certificate", kind}, now))
				if tc.pass {
					if err != nil || result == nil || !result.ValidationTime().Equal(now) {
						t.Fatal(result != nil, err)
					}
				} else if result != nil || err == nil {
					t.Fatal("unsupported retention accepted", result != nil, err)
				}
			})
		}
	}
}

func TestHistoricalModelAndPathAlternatives(t *testing.T) {
	c := makeChain(t)
	now := verificationTime()
	caKey := testcert.Key(t)
	template := &x509.Certificate{SerialNumber: big.NewInt(17), Subject: pkix.Name{CommonName: "historical intermediate"}, NotBefore: now.Add(-10 * time.Hour), NotAfter: now.Add(-2 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign, SubjectKeyId: []byte{8, 8, 8}}
	ca := testcert.Issue(t, template, c.root, caKey.Public(), c.rootKey)
	leafTemplate := &x509.Certificate{SerialNumber: big.NewInt(18), Subject: c.leaf.Subject, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature}
	for _, tc := range []struct {
		name       string
		model      pki.ValidityModel
		generation time.Time
		pass       bool
	}{
		{"shell disjoint intervals", pki.ShellModel, time.Time{}, false},
		{"chain fallback notBefore outside issuer", pki.ChainModel, time.Time{}, false},
		{"chain explicit generation", pki.ChainModel, now.Add(-3 * time.Hour), true},
		{"generation exactly issuer expiry", pki.ChainModel, ca.NotAfter, true},
		{"generation after issuer expiry", pki.ChainModel, ca.NotAfter.Add(time.Second), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			local := *leafTemplate
			if !tc.generation.IsZero() {
				local.ExtraExtensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 3, 36, 8, 3, 1}, Value: der.Wrap(0, asn1.TagGeneralizedTime, false, []byte(tc.generation.UTC().Format("20060102150405Z")))}}
			}
			leaf := testcert.Issue(t, &local, ca, c.leafKey.Public(), caKey)
			session, err := pki.NewHistoricalSession(t.Context(), pki.HistoricalConfig{PKI: pki.Config{Roots: [][]byte{c.root.Raw}}, Model: tc.model}, now, pki.Evidence{Intermediates: [][]byte{ca.Raw}})
			if err != nil {
				t.Fatal(err)
			}
			paths, err := session.Paths(t.Context(), leaf.Raw)
			if err != nil || len(paths) != 1 {
				t.Fatal(len(paths), err)
			}
			assessment, err := session.CheckPath(t.Context(), paths[0])
			if tc.pass {
				if err != nil || assessment == nil || !assessment.ReferenceTime().Equal(leaf.NotBefore) {
					t.Fatal(err)
				}
			} else if assessment != nil || !errors.Is(err, pki.ErrCertificate) {
				t.Fatal(assessment != nil, err)
			}
		})
	}
	// Two exact issuer certificates with the same issuer subject/AKI are two prospective
	// paths. The invalid path must not mask the independently valid alternative.
	badTemplate := *c.root
	badTemplate.SerialNumber = big.NewInt(91)
	badKey := testcert.Key(t)
	badTemplate.PublicKey = badKey.Public()
	bad := testcert.Issue(t, &badTemplate, &badTemplate, badKey.Public(), badKey)
	validTemplate := *c.root
	validTemplate.ExtraExtensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 2, 3, 4, 6}, Value: make([]byte, 64)}}
	validRoot := testcert.Issue(t, &validTemplate, &validTemplate, c.rootKey.Public(), c.rootKey)
	originalCRL := makeCRL(t, c, false, nil)

	for _, pathLimit := range []int{1, 2} {
		t.Run("path limit "+big.NewInt(int64(pathLimit)).String(), func(t *testing.T) {
			session, err := pki.NewHistoricalSession(t.Context(), pki.HistoricalConfig{PKI: pki.Config{Roots: [][]byte{bad.Raw, validRoot.Raw}, Revocation: pki.RequireCRL}, MaxPaths: pathLimit}, now, pki.Evidence{CRLs: [][]byte{originalCRL}})
			if err != nil {
				t.Fatal(err)
			}
			paths, err := session.Paths(t.Context(), c.leaf.Raw)
			if pathLimit == 1 {
				if paths != nil || !errors.Is(err, pki.ErrLimit) {
					t.Fatal(len(paths), err)
				}
				return
			}
			if err != nil || len(paths) != 2 {
				t.Fatal(len(paths), err)
			}
			valid := 0
			for _, path := range paths {
				if _, err := session.CheckPath(t.Context(), path); err == nil {
					valid++
				}
			}
			if valid != 1 {
				t.Fatal("bad issuer constraints ignored", valid)
			}
			if !bytes.Equal(paths[0].ChainDER()[1], bad.Raw) {
				t.Fatal("fixture must enumerate rejected path first")
			}
			result, _, err := session.ValidatePast(t.Context(), c.leaf.Raw, p7Proofs(t, now, [][]byte{c.leaf.Raw, originalCRL}, []string{"certificate", "crl"}, now))
			if err != nil || result == nil || !bytes.Equal(result.Path().ChainDER()[1], validRoot.Raw) {
				t.Fatal("failed first path masked valid alternate", result != nil, err)
			}
		})
	}
}

func TestHistoricalDelegatedSourcePaths(t *testing.T) {
	c := makeChain(t)
	now := verificationTime().Add(3 * time.Hour)
	request, err := pki.CreateOCSPRequest(c.leaf.Raw, c.root.Raw, crypto.SHA256, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name                                 string
		noCheck, crl, certificateProof, pass bool
	}{
		{"delegated nocheck", true, false, true, true},
		{"delegated CRL dependency", false, true, true, true},
		{"missing responder status", false, false, true, false},
		{"nocheck does not waive responder PoE", true, false, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			key := testcert.Key(t)
			template := &x509.Certificate{SerialNumber: big.NewInt(44), Subject: pkix.Name{CommonName: "historical responder"}, NotBefore: c.leaf.NotBefore, NotAfter: c.leaf.NotAfter, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageOCSPSigning}}
			if tc.noCheck {
				template.ExtraExtensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1, 5}, Value: []byte{5, 0}}}
			}
			responder := testcert.Issue(t, template, c.root, key.Public(), c.rootKey)
			response, err := pki.CreateOCSPResponse(t.Context(), request, c.leaf.Raw, c.root.Raw, responder.Raw, key, pki.OCSPResponseTemplate{Status: pki.OCSPGood, ProducedAt: verificationTime(), ThisUpdate: verificationTime().Add(-time.Minute), NextUpdate: verificationTime().Add(time.Minute)})
			if err != nil {
				t.Fatal(err)
			}
			input := pki.Evidence{OCSPResponses: [][]byte{response}}
			objects, roles := [][]byte{c.leaf.Raw, response}, []string{"certificate", "ocsp"}
			if tc.certificateProof {
				objects = append(objects, responder.Raw)
				roles = append(roles, "certificate")
			}
			if tc.crl {
				raw := makeCRL(t, c, false, nil)
				input.CRLs = [][]byte{raw}
				objects = append(objects, raw)
				roles = append(roles, "crl")
			}
			session, err := pki.NewHistoricalSession(t.Context(), pki.HistoricalConfig{PKI: pki.Config{Roots: [][]byte{c.root.Raw}, Revocation: pki.RequireOCSP}}, now, input)
			if err != nil {
				t.Fatal(err)
			}
			paths, err := session.Paths(t.Context(), c.leaf.Raw)
			if err != nil || len(paths) != 1 {
				t.Fatal(len(paths), err)
			}
			facts, err := session.AuthenticateEvidence(t.Context(), paths[0])
			if err != nil || len(facts) < 1 {
				t.Fatal(len(facts), err)
			}
			var selected *pki.VerifiedEvidence
			for _, fact := range facts {
				if fact.Kind() == pki.EvidenceOCSP {
					selected = fact
				}
			}
			if selected == nil || selected.SignerAuthority() != "delegated" || len(selected.SignerChainDER()) != 2 || !bytes.Equal(selected.SignerChainDER()[0], responder.Raw) {
				t.Fatal("wrong historical signer path")
			}
			result, report, err := session.ValidatePast(t.Context(), c.leaf.Raw, p7Proofs(t, now, objects, roles, verificationTime()))
			if tc.pass {
				if err != nil || result == nil || !result.ValidationTime().Equal(verificationTime().Add(-time.Minute)) {
					t.Fatal(result != nil, report.Transitions(), err)
				}
			} else if result != nil || !errors.Is(err, pki.ErrUnavailable) {
				t.Fatal(result != nil, err)
			}
		})
	}
}

func TestHistoricalDeltaAndReasonCoverage(t *testing.T) {
	c := makeChain(t)
	now := verificationTime()
	held := []x509.RevocationListEntry{{SerialNumber: c.leaf.SerialNumber, RevocationTime: now.Add(-20 * time.Minute), ReasonCode: 6}}
	base := p6CRL(t, c, 1, now.Add(-10*time.Minute), now.Add(-time.Minute), -1, nil, held)
	release := p6CRL(t, c, 2, now.Add(-time.Minute), now.Add(time.Hour), 1, nil, []x509.RevocationListEntry{{SerialNumber: c.leaf.SerialNumber, RevocationTime: now.Add(-30 * time.Second), ReasonCode: 8}})
	left := p6CRL(t, c, 1, now.Add(-time.Minute), now.Add(time.Hour), -1, der.Seq(der.Wrap(2, 3, false, []byte{3, 0x78})), nil)
	// Reason masks cover bits1..8. The pair partitions the whole RFC5280 set.
	right := p6CRL(t, c, 1, now.Add(-time.Minute), now.Add(time.Hour), -1, der.Seq(der.Wrap(2, 3, false, []byte{7, 0x07, 0x80})), nil)
	for _, tc := range []struct {
		name                string
		raws                [][]byte
		omitBaseProof, pass bool
		want                time.Time
	}{
		{"held base", [][]byte{base}, false, true, now.Add(-20 * time.Minute)},
		{"fresh delta supersedes expired base", [][]byte{base, release}, false, true, now},
		{"delta without base", [][]byte{release}, false, false, time.Time{}},
		{"delta missing base PoE", [][]byte{base, release}, true, false, time.Time{}},
		{"partial reason scope", [][]byte{left}, false, false, time.Time{}},
		{"complete reason union", [][]byte{left, right}, false, true, now},
	} {
		t.Run(tc.name, func(t *testing.T) {
			session, err := pki.NewHistoricalSession(t.Context(), pki.HistoricalConfig{PKI: pki.Config{Roots: [][]byte{c.root.Raw}, Revocation: pki.RequireCRL}}, now, pki.Evidence{CRLs: tc.raws})
			if err != nil {
				t.Fatal(err)
			}
			objects, roles := [][]byte{c.leaf.Raw}, []string{"certificate"}
			for _, raw := range tc.raws {
				if tc.omitBaseProof && bytes.Equal(raw, base) {
					continue
				}
				objects = append(objects, raw)
				roles = append(roles, "crl")
			}
			result, _, err := session.ValidatePast(t.Context(), c.leaf.Raw, p7Proofs(t, now, objects, roles, now))
			if tc.pass {
				if err != nil || result == nil || !result.ValidationTime().Equal(tc.want) {
					t.Fatal(result != nil, err)
				}
				if len(tc.raws) == 2 && bytes.Equal(tc.raws[1], release) {
					found := false
					for _, fact := range result.Evidence() {
						if bytes.Equal(fact.DER(), release) {
							found = len(fact.Dependencies()) == 1 && fact.CoveredReasons() == 255
						}
					}
					if !found {
						t.Fatal("lost effective delta dependencies")
					}
				}
			} else if result != nil || !errors.Is(err, pki.ErrUnavailable) {
				t.Fatal(result != nil, err)
			}
		})
	}
}

func TestHistoricalSessionBoundsAndSnapshots(t *testing.T) {
	c := makeChain(t)
	now := verificationTime()
	raw := makeCRL(t, c, false, nil)
	base := pki.Config{Roots: [][]byte{c.root.Raw}, Revocation: pki.RequireCRL}
	rootDigest := sha256.Sum256(c.root.Raw)
	root := hex.EncodeToString(rootDigest[:])
	freshness := 2 * time.Minute
	options := pki.HistoricalOptions{RevocationFreshness: &freshness, TrustAnchorSunsets: map[string]time.Time{root: now.Add(time.Hour)}, CryptoConstraints: []pki.CryptoConstraint{{Hash: crypto.SHA256, ReliableUntil: now.Add(time.Hour)}}}
	ownedRaw := bytes.Clone(raw)
	session, err := pki.NewHistoricalSession(t.Context(), pki.HistoricalConfig{PKI: base, HistoricalOptions: options}, now, pki.Evidence{CRLs: [][]byte{ownedRaw}})
	if err != nil {
		t.Fatal(err)
	}
	clear(ownedRaw)
	freshness = 0
	options.TrustAnchorSunsets[root] = now.Add(-time.Hour)
	options.CryptoConstraints[0].ReliableUntil = now.Add(-time.Hour)
	current, _, err := session.VerifyCurrent(t.Context(), c.leaf.Raw)
	if err != nil || current == nil {
		t.Fatal(err)
	}
	if sub, err := session.CheckCurrentPolicy(t.Context(), current); err != nil || sub != "" {
		t.Fatal("mutable historical options", sub, err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := session.Paths(ctx, c.leaf.Raw); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	paths, err := session.Paths(t.Context(), c.leaf.Raw)
	if err != nil || len(paths) != 1 {
		t.Fatal(len(paths), err)
	}
	if _, err := session.CheckPath(ctx, paths[0]); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if _, err := session.AuthenticateEvidence(ctx, paths[0]); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if _, _, err := session.ValidatePast(ctx, c.leaf.Raw, nil); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if _, _, err := session.VerifyCurrent(ctx, c.leaf.Raw); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if _, err := session.CheckCurrentPolicy(ctx, current); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	var zero pki.HistoricalSession
	if _, err := zero.Paths(t.Context(), c.leaf.Raw); !errors.Is(err, pki.ErrPolicy) {
		t.Fatal("zero session accepted", err)
	}
	if _, err := session.CheckPath(t.Context(), &pki.HistoricalPath{}); !errors.Is(err, pki.ErrPolicy) {
		t.Fatal("zero path accepted", err)
	}
	other := makeChain(t)
	otherTemplate := *other.root
	otherTemplate.Subject = pkix.Name{CommonName: "another historical authority"}
	otherTemplate.RawSubject = nil
	otherTemplate.RawIssuer = nil
	otherRoot := testcert.Issue(t, &otherTemplate, &otherTemplate, other.rootKey.Public(), other.rootKey)
	foreignLeaf := testcert.Issue(t, c.leaf, otherRoot, other.leafKey.Public(), other.rootKey)
	empty, err := pki.NewHistoricalSession(t.Context(), pki.HistoricalConfig{PKI: base}, now, pki.Evidence{})
	if err != nil {
		t.Fatal(err)
	}
	if result, report, err := empty.ValidatePast(t.Context(), foreignLeaf.Raw, p7Proofs(t, now, nil, nil, now)); result != nil || !errors.Is(err, pki.ErrUnavailable) || report.SubIndication() != "NO_CERTIFICATE_CHAIN_FOUND" {
		t.Fatal(result != nil, report.SubIndication(), err)
	}
	for _, tc := range []struct {
		name    string
		options pki.HistoricalOptions
	}{
		{"unknown model", pki.HistoricalOptions{Model: "ignored"}},
		{"negative path count", pki.HistoricalOptions{MaxPaths: -1}},
		{"excessive path count", pki.HistoricalOptions{MaxPaths: 257}},
		{"unknown sunset anchor", pki.HistoricalOptions{TrustAnchorSunsets: map[string]time.Time{"unknown": now}}},
		{"multiple crypto selectors", pki.HistoricalOptions{CryptoConstraints: []pki.CryptoConstraint{{Hash: crypto.SHA256, SignatureAlgorithm: x509.ECDSAWithSHA256, ReliableUntil: now}}}},
		{"unknown crypto selector", pki.HistoricalOptions{CryptoConstraints: []pki.CryptoConstraint{{SignatureAlgorithm: x509.SignatureAlgorithm(999), ReliableUntil: now}}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if result, err := pki.NewHistoricalSession(t.Context(), pki.HistoricalConfig{PKI: base, HistoricalOptions: tc.options}, now, pki.Evidence{}); result != nil || !errors.Is(err, pki.ErrPolicy) {
				t.Fatal(result != nil, err)
			}
		})
	}
	raw = makeCRL(t, c, false, &x509.RevocationList{Number: big.NewInt(4), ThisUpdate: now.Add(-time.Minute), NextUpdate: now.Add(time.Hour), ExtraExtensions: []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 2, 3, 4, 5}, Value: make([]byte, 1024)}}})
	tooSmall := base
	tooSmall.MaxEvidenceBytes = len(raw) - 1
	if result, err := pki.NewHistoricalSession(t.Context(), pki.HistoricalConfig{PKI: tooSmall}, now, pki.Evidence{CRLs: [][]byte{raw}}); result != nil || !errors.Is(err, pki.ErrLimit) {
		t.Fatal(result != nil, err)
	}
	fitting := base
	fitting.MaxEvidenceBytes = len(raw)
	if result, err := pki.NewHistoricalSession(t.Context(), pki.HistoricalConfig{PKI: fitting}, now, pki.Evidence{CRLs: [][]byte{raw}}); result == nil || err != nil {
		t.Fatal(result != nil, err)
	}
}

func TestHistoricalIssuerToTargetOrder(t *testing.T) {
	c := makeChain(t)
	at := verificationTime()
	now := at.Add(3 * time.Hour)
	caKey := testcert.Key(t)
	template := &x509.Certificate{SerialNumber: big.NewInt(100), Subject: pkix.Name{CommonName: "historical time-order intermediate"}, NotBefore: at.Add(-8 * time.Hour), NotAfter: at.Add(8 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign, SubjectKeyId: []byte{4, 5, 6}}
	ca := testcert.Issue(t, template, c.root, caKey.Public(), c.rootKey)
	leaf := testcert.Issue(t, c.leaf, ca, c.leafKey.Public(), caKey)
	caList := p6CRL(t, c, 1, at.Add(time.Hour), at.Add(2*time.Hour), -1, nil, nil)
	leafList := p6CRL(t, chainData{root: ca, rootKey: caKey}, 1, at.Add(-10*time.Minute), at.Add(-5*time.Minute), -1, nil, nil)
	source := sha256.Sum256([]byte("issuer to target chronological vector"))
	facts := []historicalproof.Fact{{Digest: sha256.Sum256(ca.Raw), Source: source, At: at.Add(-30 * time.Minute), Kind: "certificate"}, {Digest: sha256.Sum256(leaf.Raw), Source: source, At: at.Add(-30 * time.Minute), Kind: "certificate"}, {Digest: sha256.Sum256(caList), Source: source, At: at.Add(time.Hour), Kind: "crl"}, {Digest: sha256.Sum256(leafList), Source: source, At: at.Add(-10 * time.Minute), Kind: "crl"}}
	proofs, err := historicalproof.New(t.Context(), now, facts)
	if err != nil {
		t.Fatal(err)
	}
	for _, reverse := range []bool{false, true} {
		t.Run(strconv.FormatBool(reverse), func(t *testing.T) {
			lists := [][]byte{caList, leafList}
			if reverse {
				lists[0], lists[1] = lists[1], lists[0]
			}
			session, err := pki.NewHistoricalSession(t.Context(), pki.HistoricalConfig{PKI: pki.Config{Roots: [][]byte{c.root.Raw}, Revocation: pki.RequireCRL}}, now, pki.Evidence{Intermediates: [][]byte{ca.Raw}, CRLs: lists})
			if err != nil {
				t.Fatal(err)
			}
			result, report, err := session.ValidatePast(t.Context(), leaf.Raw, proofs)
			if err != nil || result == nil || !result.ValidationTime().Equal(at.Add(-10*time.Minute)) {
				t.Fatal(result != nil, err)
			}
			transitions := report.Transitions()
			caDigest := sha256.Sum256(ca.Raw)
			leafDigest := sha256.Sum256(leaf.Raw)
			if len(transitions) != 2 || transitions[0].CertificateSHA256 != hex.EncodeToString(caDigest[:]) || !transitions[0].After.Equal(at.Add(time.Hour)) || transitions[1].CertificateSHA256 != hex.EncodeToString(leafDigest[:]) || !transitions[1].Before.Equal(at.Add(time.Hour)) {
				t.Fatal("wrong processing order", transitions)
			}
		})
	}
}

func TestHistoricalGenerationEncodings(t *testing.T) {
	c := makeChain(t)
	now := verificationTime()
	caKey := testcert.Key(t)
	caTemplate := &x509.Certificate{SerialNumber: big.NewInt(55), Subject: pkix.Name{CommonName: "generation encoding intermediate"}, NotBefore: now.Add(-8 * time.Hour), NotAfter: now.Add(8 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, SubjectKeyId: []byte{6, 7, 8}}
	ca := testcert.Issue(t, caTemplate, c.root, caKey.Public(), c.rootKey)
	for _, tc := range []struct {
		name     string
		value    []byte
		critical bool
	}{
		{"wrong ASN1 type", der.Octets([]byte("20261008110000Z")), false},
		{"offset encoding", der.Wrap(0, asn1.TagGeneralizedTime, false, []byte("20261008110000+0000")), false},
		{"fractional encoding", der.Wrap(0, asn1.TagGeneralizedTime, false, []byte("20261008110000.5Z")), false},
		{"unsupported critical semantics", der.Wrap(0, asn1.TagGeneralizedTime, false, []byte("20261008110000Z")), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			local := *c.leaf
			local.ExtraExtensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 3, 36, 8, 3, 1}, Value: tc.value, Critical: tc.critical}}
			leaf := testcert.Issue(t, &local, ca, c.leafKey.Public(), caKey)
			session, err := pki.NewHistoricalSession(t.Context(), pki.HistoricalConfig{PKI: pki.Config{Roots: [][]byte{c.root.Raw}}, HistoricalOptions: pki.HistoricalOptions{Model: pki.ChainModel}}, now, pki.Evidence{Intermediates: [][]byte{ca.Raw}})
			if err != nil {
				t.Fatal(err)
			}
			paths, err := session.Paths(t.Context(), leaf.Raw)
			if err != nil || len(paths) != 1 {
				t.Fatal(len(paths), err)
			}
			if result, err := session.CheckPath(t.Context(), paths[0]); result != nil || !errors.Is(err, pki.ErrCertificate) {
				t.Fatal("invalid generation metadata accepted", result != nil, err)
			}
		})
	}
}

func TestHistoricalAuthenticationBindings(t *testing.T) {
	c := makeChain(t)
	other := makeChain(t)
	now := verificationTime()
	foreignList := makeCRL(t, other, false, nil)
	ownList := makeCRL(t, c, false, nil)
	for _, tc := range []struct {
		name   string
		source []byte
		pass   bool
	}{
		{"matching source anchor", ownList, true},
		{"other explicitly trusted source anchor", foreignList, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			session, err := pki.NewHistoricalSession(t.Context(), pki.HistoricalConfig{PKI: pki.Config{Roots: [][]byte{c.root.Raw, other.root.Raw}, Revocation: pki.RequireCRL}}, now, pki.Evidence{CRLs: [][]byte{tc.source}})
			if err != nil {
				t.Fatal(err)
			}
			paths, err := session.Paths(t.Context(), c.leaf.Raw)
			if err != nil {
				t.Fatal(err)
			}
			var path *pki.HistoricalPath
			for _, candidate := range paths {
				chain := candidate.ChainDER()
				if bytes.Equal(chain[len(chain)-1], c.root.Raw) {
					path = candidate
				}
			}
			if path == nil {
				t.Fatal("missing selected target path")
			}
			claims, err := session.AuthenticateEvidence(t.Context(), path)
			if err != nil || (len(claims) == 1) != tc.pass {
				t.Fatal("wrong source anchor binding", len(claims), err)
			}
		})
	}
	template := *c.leaf
	template.SerialNumber = big.NewInt(777)
	unrelated := testcert.Issue(t, &template, c.root, c.leafKey.Public(), c.rootKey)
	foreign := p7Response(t, chainData{root: c.root, rootKey: c.rootKey, leaf: unrelated}, pki.OCSPResponseTemplate{Status: pki.OCSPGood, ProducedAt: now, ThisUpdate: now.Add(-time.Minute), NextUpdate: now.Add(time.Minute)})
	correct := p7Response(t, c, pki.OCSPResponseTemplate{Status: pki.OCSPGood, ProducedAt: now, ThisUpdate: now.Add(-time.Minute), NextUpdate: now.Add(time.Minute)})
	duplicate := rewriteOCSPData(t, correct, c.rootKey, func(fields []asn1.RawValue) [][]byte {
		entries, err := der.Sequence(fields[2], 1, 64)
		if err != nil {
			t.Fatal(err)
		}
		fields[2].FullBytes = der.Seq(entries[0].FullBytes, entries[0].FullBytes)
		return ocspFieldBytes(fields)
	})
	for _, tc := range []struct {
		name      string
		responses [][]byte
		pass      bool
		want      error
	}{
		{"foreign status is not target status", [][]byte{foreign}, false, nil},
		{"foreign response does not mask matching source", [][]byte{foreign, correct}, true, nil},
		{"ambiguous matching response rejected", [][]byte{duplicate}, false, pki.ErrEvidence},
		{"good response does not hide duplicate match", [][]byte{correct, duplicate}, false, pki.ErrEvidence},
	} {
		t.Run(tc.name, func(t *testing.T) {
			session, err := pki.NewHistoricalSession(t.Context(), pki.HistoricalConfig{PKI: pki.Config{Roots: [][]byte{c.root.Raw}, Revocation: pki.RequireOCSP}}, now, pki.Evidence{OCSPResponses: tc.responses})
			if err != nil {
				t.Fatal(err)
			}
			paths, err := session.Paths(t.Context(), c.leaf.Raw)
			if err != nil || len(paths) != 1 {
				t.Fatal(len(paths), err)
			}
			claims, err := session.AuthenticateEvidence(t.Context(), paths[0])
			if tc.want != nil {
				if len(claims) != 0 || !errors.Is(err, tc.want) {
					t.Fatal(len(claims), err)
				}
				return
			}
			if err != nil || (len(claims) == 1) != tc.pass {
				t.Fatal(len(claims), err)
			}
		})
	}
}

func TestHistoricalSourceIssuanceBounds(t *testing.T) {
	c := makeChain(t)
	at := verificationTime()
	now := at.Add(28 * time.Hour)
	for _, tc := range []struct {
		name   string
		issued time.Time
		pass   bool
	}{
		{"CRL signer lifetime inclusive", c.root.NotAfter, true},
		{"CRL issued after signer expiry", c.root.NotAfter.Add(time.Second), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw := p6CRL(t, c, 1, tc.issued, tc.issued.Add(time.Hour), -1, nil, nil)
			session, err := pki.NewHistoricalSession(t.Context(), pki.HistoricalConfig{PKI: pki.Config{Roots: [][]byte{c.root.Raw}, Revocation: pki.RequireCRL}}, now, pki.Evidence{CRLs: [][]byte{raw}})
			if err != nil {
				t.Fatal(err)
			}
			paths, err := session.Paths(t.Context(), c.leaf.Raw)
			if err != nil || len(paths) != 1 {
				t.Fatal(len(paths), err)
			}
			facts, err := session.AuthenticateEvidence(t.Context(), paths[0])
			if err != nil || (len(facts) == 1) != tc.pass {
				t.Fatal(len(facts), err)
			}
		})
	}
	request, err := pki.CreateOCSPRequest(c.leaf.Raw, c.root.Raw, crypto.SHA256, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, valid := range []bool{false, true} {
		t.Run("OCSP signer issuance lifetime "+strconv.FormatBool(valid), func(t *testing.T) {
			key := testcert.Key(t)
			end := at.Add(-time.Minute)
			if valid {
				end = at.Add(time.Minute)
			}
			template := &x509.Certificate{SerialNumber: big.NewInt(222), Subject: pkix.Name{CommonName: "issued status signer"}, NotBefore: at.Add(-time.Hour), NotAfter: end, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageOCSPSigning}, ExtraExtensions: []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1, 5}, Value: []byte{5, 0}}}}
			responder := testcert.Issue(t, template, c.root, key.Public(), c.rootKey)
			raw, err := pki.CreateOCSPResponse(t.Context(), request, c.leaf.Raw, c.root.Raw, responder.Raw, key, pki.OCSPResponseTemplate{Status: pki.OCSPGood, ProducedAt: at, ThisUpdate: at.Add(-time.Minute), NextUpdate: at.Add(time.Minute)})
			if err != nil {
				t.Fatal(err)
			}
			session, err := pki.NewHistoricalSession(t.Context(), pki.HistoricalConfig{PKI: pki.Config{Roots: [][]byte{c.root.Raw}, Revocation: pki.RequireOCSP}}, now, pki.Evidence{OCSPResponses: [][]byte{raw}})
			if err != nil {
				t.Fatal(err)
			}
			paths, err := session.Paths(t.Context(), c.leaf.Raw)
			if err != nil || len(paths) != 1 {
				t.Fatal(len(paths), err)
			}
			facts, err := session.AuthenticateEvidence(t.Context(), paths[0])
			if err != nil || (len(facts) == 1) != valid {
				t.Fatal(len(facts), err)
			}
		})
	}
}

func TestHistoricalEmbeddedCertificates(t *testing.T) {
	c := makeChain(t)
	now := verificationTime()
	responderTemplate := *c.leaf
	responderTemplate.SerialNumber = big.NewInt(78)
	responderTemplate.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageOCSPSigning}
	responder := testcert.Issue(t, &responderTemplate, c.root, c.leafKey.Public(), c.rootKey)
	request, err := pki.CreateOCSPRequest(c.leaf.Raw, c.root.Raw, crypto.SHA256, nil)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := pki.CreateOCSPResponse(t.Context(), request, c.leaf.Raw, c.root.Raw, responder.Raw, c.leafKey, pki.OCSPResponseTemplate{Status: pki.OCSPGood, ProducedAt: now, ThisUpdate: now.Add(-time.Minute), NextUpdate: now.Add(time.Minute)})
	if err != nil {
		t.Fatal(err)
	}
	certificates, err := pki.InspectOCSPCertificates(t.Context(), raw)
	if err != nil || len(certificates) != 1 || !bytes.Equal(certificates[0], responder.Raw) {
		t.Fatal(len(certificates), err)
	}
	clear(certificates[0])
	next, err := pki.InspectOCSPCertificates(t.Context(), raw)
	if err != nil || !bytes.Equal(next[0], responder.Raw) {
		t.Fatal("inspection retained caller storage", err)
	}
	// The parser reports actual byte containment only. It must not pretend that
	// syntactic inspection verified an envelope signature or conferred trust.
	broken := rewriteOCSPData(t, raw, c.leafKey, ocspFieldBytes)
	value, err := der.Read(broken, len(broken))
	if err != nil {
		t.Fatal(err)
	}
	outer, err := der.Sequence(value, 2, 2)
	if err != nil {
		t.Fatal(err)
	}
	response, err := der.Explicit(outer[1], 0)
	if err != nil {
		t.Fatal(err)
	}
	responseFields, err := der.Sequence(response, 2, 2)
	if err != nil {
		t.Fatal(err)
	}
	basic, err := der.Read(responseFields[1].Bytes, len(broken))
	if err != nil {
		t.Fatal(err)
	}
	fields, err := der.Sequence(basic, 3, 4)
	if err != nil {
		t.Fatal(err)
	}
	signatureBits := bytes.Clone(fields[2].FullBytes)
	signatureBits[len(signatureBits)-1] ^= 1
	fields[2].FullBytes = signatureBits
	broken = der.Seq(outer[0].FullBytes, der.Ctx(0, der.Seq(responseFields[0].FullBytes, der.Octets(der.Seq(ocspFieldBytes(fields)...)))))
	if certificates, err := pki.InspectOCSPCertificates(t.Context(), broken); err != nil || len(certificates) != 1 || !bytes.Equal(certificates[0], responder.Raw) {
		t.Fatal("inspection confused containment and authentication", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if result, err := pki.InspectOCSPCertificates(ctx, raw); result != nil || !errors.Is(err, context.Canceled) {
		t.Fatal(result != nil, err)
	}
	if result, err := pki.InspectOCSPCertificates(nil, raw); result != nil || !errors.Is(err, pki.ErrPolicy) {
		t.Fatal(result != nil, err)
	}
	if result, err := pki.InspectOCSPCertificates(t.Context(), raw[:len(raw)-1]); result != nil || !errors.Is(err, pki.ErrEvidence) {
		t.Fatal(result != nil, err)
	}
}

func TestHistoricalConstraintIndications(t *testing.T) {
	c := makeChain(t)
	now := verificationTime()
	raw := makeCRL(t, c, false, nil)
	for _, tc := range []struct {
		name  string
		usage x509.ExtKeyUsage
		pass  bool
	}{
		{"configured signer usage", x509.ExtKeyUsageCodeSigning, true},
		{"wrong configured usage", x509.ExtKeyUsageServerAuth, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			session, err := pki.NewHistoricalSession(t.Context(), pki.HistoricalConfig{PKI: pki.Config{Roots: [][]byte{c.root.Raw}, KeyUsages: []x509.ExtKeyUsage{tc.usage}, Revocation: pki.RequireCRL}}, now, pki.Evidence{CRLs: [][]byte{raw}})
			if err != nil {
				t.Fatal(err)
			}
			result, report, err := session.ValidatePast(t.Context(), c.leaf.Raw, p7Proofs(t, now, [][]byte{c.leaf.Raw, raw}, []string{"certificate", "crl"}, now))
			if tc.pass {
				if err != nil || result == nil || report.SubIndication() != "" {
					t.Fatal(result != nil, report.SubIndication(), err)
				}
			} else if result != nil || !errors.Is(err, pki.ErrCertificate) || report.SubIndication() != "CHAIN_CONSTRAINTS_FAILURE" {
				t.Fatal(result != nil, report.SubIndication(), err)
			}
		})
	}
}

func TestHistoricalMixedCryptoCutoffs(t *testing.T) {
	c := makeChain(t)
	now := verificationTime()
	raw := makeCRL(t, c, false, &x509.RevocationList{Number: big.NewInt(1), ThisUpdate: now.Add(-time.Minute), NextUpdate: now.Add(time.Hour), SignatureAlgorithm: x509.ECDSAWithSHA384})
	sourceCutoff := now.Add(-20 * time.Second)
	certificateCutoff := now.Add(-10 * time.Second)
	for _, tc := range []struct {
		name    string
		proofAt time.Time
		pass    bool
	}{
		{"both signed materials protected", now.Add(-45 * time.Second), true},
		{"source proof exactly at earliest cutoff", sourceCutoff, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			session, err := pki.NewHistoricalSession(t.Context(), pki.HistoricalConfig{PKI: pki.Config{Roots: [][]byte{c.root.Raw}, Revocation: pki.RequireCRL}, HistoricalOptions: pki.HistoricalOptions{CryptoConstraints: []pki.CryptoConstraint{{Hash: crypto.SHA256, ReliableUntil: certificateCutoff}, {Hash: crypto.SHA384, ReliableUntil: sourceCutoff}}}}, now, pki.Evidence{CRLs: [][]byte{raw}})
			if err != nil {
				t.Fatal(err)
			}
			result, _, err := session.ValidatePast(t.Context(), c.leaf.Raw, p7Proofs(t, now, [][]byte{c.leaf.Raw, raw}, []string{"certificate", "crl"}, tc.proofAt))
			if tc.pass {
				if err != nil || result == nil || !result.ValidationTime().Equal(sourceCutoff) {
					t.Fatal(result != nil, err)
				}
			} else if result != nil || !errors.Is(err, pki.ErrUnavailable) {
				t.Fatal(result != nil, err)
			}
		})
	}
}

func TestHistoricalFreshnessDependenciesAreTargetBound(t *testing.T) {
	c := makeChain(t)
	now := verificationTime()
	proofTime := now.Add(-time.Hour)
	caKey := testcert.Key(t)
	caTemplate := &x509.Certificate{SerialNumber: big.NewInt(300), Subject: pkix.Name{CommonName: "mixed composite intermediate"}, NotBefore: now.Add(-8 * time.Hour), NotAfter: now.Add(8 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign, SubjectKeyId: []byte{3, 0, 0}}
	ca := testcert.Issue(t, caTemplate, c.root, caKey.Public(), c.rootKey)
	local := *c.leaf
	local.NotBefore = now.Add(-6 * time.Hour)
	local.NotAfter = now.Add(6 * time.Hour)
	point := der.Seq(der.Wrap(2, 2, true, der.Ctx(4, c.root.RawSubject)))
	local.ExtraExtensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, 31}, Value: der.Seq(point)}}
	leaf := testcert.Issue(t, &local, ca, c.leafKey.Public(), caKey)
	scope := der.Seq(der.Wrap(2, 4, false, []byte{255}))
	base := p6CRL(t, c, 1, now.Add(-2*time.Hour), now.Add(10*time.Minute), -1, scope, nil)
	delta := p6CRL(t, c, 2, proofTime, now.Add(-30*time.Minute), 1, scope, nil)
	signerEvidence := pki.Evidence{Intermediates: [][]byte{ca.Raw}, CRLs: [][]byte{base, delta}}
	verifier, err := pki.NewVerifier(pki.Config{Roots: [][]byte{c.root.Raw}, Revocation: pki.RequireCRL})
	if err != nil {
		t.Fatal(err)
	}
	// This is a core-phase fixture after format cryptographic validation. Its
	// timestamp actually hashes the exact bundle whose children receive PoE.
	signatureValue := []byte("already verified core-phase signature value")
	protected := [][]byte{signatureValue, leaf.Raw, ca.Raw, c.root.Raw, base}
	roles := []string{"signature", "certificate", "certificate", "certificate", "crl"}
	objects := make([]historical.Object, 0, len(protected)+1)
	children := make([][32]byte, 0, len(protected))
	for index, raw := range protected {
		objects = append(objects, historical.Object{Bytes: raw, Kind: historicalproof.Kind(roles[index])})
		children = append(children, sha256.Sum256(raw))
	}
	bundle := bytes.Join(protected, nil)
	objects = append(objects, historical.Object{Bytes: bundle, Kind: "data", Contains: children})
	tsaChain := testcert.New(t)
	policy := asn1.ObjectIdentifier{1, 2, 3, 5, 8}
	tsa, err := timestamp.NewVerifier(timestamp.Config{PKI: pki.Config{Roots: [][]byte{tsaChain.Root.Raw}, Revocation: pki.RequireCRL}, Certificates: [][]byte{tsaChain.TSA.Raw}, AllowedPolicies: []asn1.ObjectIdentifier{policy}})
	if err != nil {
		t.Fatal(err)
	}
	request, err := timestamp.CreateRequest(t.Context(), bundle, timestamp.RequestOptions{Hash: crypto.SHA256, Policy: policy})
	if err != nil {
		t.Fatal(err)
	}
	response, err := timestamp.IssueResponse(t.Context(), request.DER(), tsaChain.TSAKey, tsaChain.TSA.Raw, timestamp.IssueOptions{Policy: policy, SerialNumber: big.NewInt(77), GenTime: proofTime})
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := timestamp.ParseResponse(t.Context(), response)
	if err != nil {
		t.Fatal(err)
	}
	token, err := timestamp.ParseToken(t.Context(), envelope.TokenDER())
	if err != nil {
		t.Fatal(err)
	}
	zero := time.Duration(0)
	input := historical.Input{Signature: sha256.Sum256(signatureValue), Certificate: leaf.Raw, SignatureMethod: x509.ECDSAWithSHA256, Hashes: []crypto.Hash{crypto.SHA256}, Objects: objects, Timestamps: []historical.Candidate{{Token: token, Imprint: request.Imprint(), Covered: [][32]byte{sha256.Sum256(bundle)}, Archive: true}}}
	config := historical.Config{Signer: verifier, TSA: tsa, MissingAccuracy: &zero, RequireAllTimestamps: true}
	for _, archive := range []bool{false, true} {
		t.Run(strconv.FormatBool(archive), func(t *testing.T) {
			selected := input
			if !archive {
				selected.Timestamps = nil
			}
			report, err := historical.Validate(t.Context(), config, selected, now, signerEvidence, pki.Evidence{CRLs: [][]byte{testcert.CRL(t, tsaChain)}})
			if !archive {
				if err == nil || report.Indication == historical.Passed || report.SubIndication != "TRY_LATER" {
					t.Fatal("missing historical proof accepted", report.SubIndication, err)
				}
				return
			}
			if err != nil || report.Indication != historical.Passed || !report.Validation.Equal(proofTime) {
				t.Fatal("another target's delta dependency suppressed signer head", report.Indication, report.SubIndication, err)
			}
			leafHash := sha256.Sum256(leaf.Raw)
			caHash := sha256.Sum256(ca.Raw)
			leafHead, caComposite := false, false
			for _, fact := range report.Past.Evidence() {
				if fact.TargetCertificateSHA256() == hex.EncodeToString(leafHash[:]) && bytes.Equal(fact.DER(), base) && len(fact.Dependencies()) == 0 {
					leafHead = true
				}
				if fact.TargetCertificateSHA256() == hex.EncodeToString(caHash[:]) && bytes.Equal(fact.DER(), delta) && len(fact.Dependencies()) == 1 {
					caComposite = true
				}
			}
			if !leafHead || !caComposite {
				t.Fatal("fixture did not select distinct target composite roles", leafHead, caComposite)
			}
		})
	}
}
