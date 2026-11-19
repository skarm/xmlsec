package pki //nolint:testpackage // Checks the CRL parser's signed metadata before verifier policy is applied.

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/skarm/xmlsec/internal/der"
	"github.com/skarm/xmlsec/internal/testutil/testcert"
)

func TestSimultaneousCRLViewsAcceptEquivalentIssuerNames(t *testing.T) {
	t.Parallel()

	name := func(commonName string) crlGeneralName {
		t.Helper()

		raw, err := asn1.Marshal(pkix.Name{CommonName: commonName}.ToRDNSequence())
		if err != nil {
			t.Fatal(err)
		}

		out, err := crlDirectoryName(t.Context(), raw)
		if err != nil {
			t.Fatal(err)
		}

		return out
	}

	issuer := name("Project CA")
	target := &x509.Certificate{RawIssuer: issuer.value, SerialNumber: big.NewInt(17)}
	now := testcert.Now()
	full := &parsedCRL{number: big.NewInt(2), entries: []crlEntry{{
		serial: target.SerialNumber, revoked: now, reason: 1,
		issuers: []crlGeneralName{issuer, name("Optional directory name A")},
	}}}
	delta := &parsedCRL{number: big.NewInt(2), entries: []crlEntry{{
		serial: target.SerialNumber, revoked: now, reason: 1,
		issuers: []crlGeneralName{issuer, name("Optional directory name B")},
	}}}
	views := []completeCRLView{
		{base: &authenticatedCRL{list: full}},
		{base: &authenticatedCRL{list: &parsedCRL{number: big.NewInt(1)}}, delta: &authenticatedCRL{list: delta}},
	}

	if err := checkEquivalentCRLViews(t.Context(), views, target); err != nil {
		t.Fatalf("same revocation information with different optional names: %v", err)
	}

	delta.entries[0].revoked = now.Add(time.Minute)
	if err := checkEquivalentCRLViews(t.Context(), views, target); !errors.Is(err, ErrEvidence) {
		t.Fatalf("different revocation information: %v, want ErrEvidence", err)
	}
}

func TestParseCRLRetainsEd25519SignatureAndMetadata(t *testing.T) {
	t.Parallel()

	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{3}, ed25519.SeedSize))
	now := testcert.Now()
	certificate := &x509.Certificate{
		SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: "Ed25519 CRL issuer"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), BasicConstraintsValid: true,
		IsCA: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	issuer := testcert.Issue(t, certificate, certificate, key.Public(), key)
	const serial = 17
	revokedAt := now.Add(-time.Minute)
	raw, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number: big.NewInt(9), ThisUpdate: now, NextUpdate: now.Add(time.Hour),
		RevokedCertificateEntries: []x509.RevocationListEntry{{SerialNumber: big.NewInt(serial), RevocationTime: revokedAt, ReasonCode: 1}},
	}, issuer, key)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := parseCRL(t.Context(), raw)
	if err != nil {
		t.Fatalf("parse Ed25519 CRL: %v", err)
	}
	if !bytes.Equal(parsed.raw, raw) || !bytes.Equal(parsed.issuer, issuer.RawSubject) || !bytes.Equal(parsed.authorityKeyID, issuer.SubjectKeyId) ||
		parsed.number.Cmp(big.NewInt(9)) != 0 || parsed.signatureAlgorithm != x509.PureEd25519 || !parsed.this.Equal(now) || !parsed.next.Equal(now.Add(time.Hour)) {
		t.Fatalf("parsed CRL lost signed issuer, number, algorithm, or update times")
	}
	if len(parsed.entries) != 1 || parsed.entries[0].serial.Cmp(big.NewInt(serial)) != 0 || !parsed.entries[0].revoked.Equal(revokedAt) || parsed.entries[0].reason != 1 {
		t.Fatalf("parsed entries = %+v, want serial %d revoked at %s with reason 1", parsed.entries, serial, revokedAt)
	}
	for _, tc := range []struct {
		name string
		key  crypto.PublicKey
		want error
	}{
		{"issuer_key", key.Public(), nil},
		{"different_ed25519_key", ed25519.NewKeyFromSeed(bytes.Repeat([]byte{5}, ed25519.SeedSize)).Public(), ErrEvidence},
		{"different_key_family", testcert.Key(t).Public(), ErrEvidence},
		{"empty_key", nil, ErrPolicy},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if err := parsed.verifySignature(tc.key); !errors.Is(err, tc.want) {
				t.Errorf("verifySignature(%T) = %v, want %v", tc.key, err, tc.want)
			}
		})
	}
}

func TestParseExpiredCRLRetentionChecksIssuanceBoundary(t *testing.T) {
	t.Parallel()

	issued := testcert.Now()
	for _, tc := range []struct {
		name     string
		date     time.Time
		critical bool
		want     error
	}{
		{"earlier_than_issuance", issued.Add(-time.Hour), false, nil},
		{"equal_to_issuance", issued, false, nil},
		{"later_than_issuance", issued.Add(time.Second), false, ErrEvidence},
		{"must_be_noncritical", issued, true, ErrEvidence},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			raw, err := asn1.MarshalWithParams(tc.date, "generalized")
			if err != nil {
				t.Fatal(err)
			}
			got, err := parseExpiredCRLRetention(pkix.Extension{Critical: tc.critical, Value: raw}, issued)
			want := tc.date
			if tc.want != nil {
				want = time.Time{}
			}
			if !errors.Is(err, tc.want) || !got.Equal(want) {
				t.Errorf("parseExpiredCRLRetention = (%s, %v), want (%s, %v)", got, err, want, tc.want)
			}
		})
	}
}

func TestParseCRLRejectsInconsistentDeltaNumber(t *testing.T) {
	t.Parallel()

	chain := testcert.New(t)
	now := testcert.Now()
	for _, tc := range []struct {
		name string
		base int
		want error
	}{
		{"newer_than_base", 6, nil},
		{"equal_to_base", 7, ErrEvidence},
		{"older_than_base", 8, ErrEvidence},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			raw, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
				Number: big.NewInt(7), ThisUpdate: now, NextUpdate: now.Add(time.Hour),
				ExtraExtensions: []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, 27}, Critical: true, Value: der.Int(tc.base)}},
			}, chain.Root, chain.RootKey)
			if err != nil {
				t.Fatal(err)
			}
			got, err := parseCRL(t.Context(), raw)
			if !errors.Is(err, tc.want) || (got == nil) != (tc.want != nil) {
				t.Fatalf("parseCRL: result present = %t, error = %v, want %v", got != nil, err, tc.want)
			}
			if got != nil && (got.base == nil || got.base.Int64() != int64(tc.base) || got.number == nil || got.number.Int64() != 7) {
				t.Errorf("parsed CRL number = %v, base = %v, want 7, %d", got.number, got.base, tc.base)
			}
		})
	}
}

func TestCRLMailboxDomainComparison(t *testing.T) {
	t.Parallel()

	const address = `"team\"@Lab"@example.test`
	if !equalCRLMailbox(address, `"team\"@Lab"@EXAMPLE.TEST`) {
		t.Fatal("mailbox comparison did not fold the domain")
	}
	if equalCRLMailbox(address, `"team\"@lab"@example.test`) {
		t.Fatal("mailbox comparison folded the quoted local part")
	}
}

func TestRelativeCRLNamePreservesOpaqueRDN(t *testing.T) {
	t.Parallel()

	commonName := asn1.ObjectIdentifier{2, 5, 4, 3}
	rdn := func(tag int, value string) []byte {
		return der.Set(der.Seq(der.OID(commonName), der.Wrap(0, tag, false, []byte(value))))
	}
	issuer := rdn(asn1.TagT61String, "legacy issuer")
	partition := rdn(asn1.TagUTF8String, "partition")
	resolved, err := crlPointNames(t.Context(), crlDistributionPoint{relative: partition}, der.Seq(issuer))
	if err != nil || len(resolved) != 1 {
		t.Fatalf("relative CRL name = %d names, %v, want one resolved name", len(resolved), err)
	}

	for _, tc := range []struct {
		value []byte
		match bool
	}{
		{partition, true},
		{rdn(asn1.TagUTF8String, "other partition"), false},
	} {
		fullName, err := crlDirectoryName(t.Context(), der.Seq(issuer, tc.value))
		if err != nil {
			t.Fatal(err)
		}
		if got := equalCRLGeneralName(resolved[0], fullName); got != tc.match {
			t.Errorf("relative name equals complete name %x = %t, want %t", fullName.value, got, tc.match)
		}
	}
}
