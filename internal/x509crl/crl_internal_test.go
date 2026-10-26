package x509crl

import (
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"testing"
	"time"

	"github.com/skarm/xmlsec/internal/der"
	"github.com/skarm/xmlsec/internal/signature"
)

func TestPKIXTimeFormsAndCenturyBoundary(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		tag   int
		input string
		year  int
		valid bool
	}{
		{asn1.TagUTCTime, "491231235959Z", 2049, true},
		{asn1.TagUTCTime, "500101000000Z", 1950, true},
		{asn1.TagUTCTime, "680229123456Z", 1968, true},
		{asn1.TagUTCTime, "690101000000Z", 1969, true},
		{asn1.TagUTCTime, "000229000000Z", 2000, true},
		{asn1.TagGeneralizedTime, "00010101000000Z", 1, true},
		{asn1.TagGeneralizedTime, "20500101000000Z", 2050, true},
		{asn1.TagGeneralizedTime, "99991231235959Z", 9999, true},
		{asn1.TagGeneralizedTime, "00000101000000Z", 0, false},
		{asn1.TagGeneralizedTime, "20230229000000Z", 0, false},
		{asn1.TagGeneralizedTime, "20000101000000.1Z", 0, false},
		{asn1.TagUTCTime, "5001010000Z", 0, false},
		{asn1.TagUTCTime, "500101000000+0000", 0, false},
		{asn1.TagUTCTime, "500101000060Z", 0, false},
		{asn1.TagUTF8String, "500101000000Z", 0, false},
	} {
		got, err := parseTime(asn1.RawValue{Tag: tc.tag, Bytes: []byte(tc.input), FullBytes: der.Wrap(0, tc.tag, false, []byte(tc.input))})
		if (err == nil) != tc.valid || tc.valid && (got.Year() != tc.year || got.Location() != time.UTC) {
			t.Fatalf("%d/%s: %v, %v", tc.tag, tc.input, got, err)
		}
	}
}

func TestV1SignatureAlgorithmIdentifiers(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		oid  asn1.ObjectIdentifier
		want x509.SignatureAlgorithm
	}{
		{asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}, x509.SHA256WithRSA},
		{asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 12}, x509.SHA384WithRSA},
		{asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 13}, x509.SHA512WithRSA},
		{asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 5}, x509.SHA1WithRSA},
		{asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 4}, x509.MD5WithRSA},
		{asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}, x509.ECDSAWithSHA256},
		{asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 3}, x509.ECDSAWithSHA384},
		{asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 4}, x509.ECDSAWithSHA512},
		{asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 1}, x509.ECDSAWithSHA1},
		{asn1.ObjectIdentifier{1, 2, 840, 10040, 4, 3}, x509.DSAWithSHA1},
		{asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 2}, x509.DSAWithSHA256},
		{asn1.ObjectIdentifier{1, 3, 101, 112}, x509.PureEd25519},
		{asn1.ObjectIdentifier{1, 2, 3, 4}, x509.UnknownSignatureAlgorithm},
	} {
		t.Run(tc.want.String(), func(t *testing.T) {
			t.Parallel()
			algorithm := pkix.AlgorithmIdentifier{Algorithm: tc.oid}
			if got := signatureAlgorithm(algorithm); got != tc.want {
				t.Fatalf("OID %s: %v; want %v", tc.oid, got, tc.want)
			}
			algorithm.Parameters = asn1.RawValue{Tag: asn1.TagNull, FullBytes: []byte{5, 0}}
			want := x509.UnknownSignatureAlgorithm
			if tc.want == x509.SHA256WithRSA || tc.want == x509.SHA384WithRSA || tc.want == x509.SHA512WithRSA || tc.want == x509.SHA1WithRSA || tc.want == x509.MD5WithRSA {
				want = tc.want
			}
			if got := signatureAlgorithm(algorithm); got != want {
				t.Fatalf("OID %s with NULL: %v; want %v", tc.oid, got, want)
			}
			algorithm.Parameters = asn1.RawValue{FullBytes: der.Int(1)}
			if got := signatureAlgorithm(algorithm); got != x509.UnknownSignatureAlgorithm {
				t.Fatal("invalid parameters accepted", got)
			}
		})
	}
	for i, hash := range []crypto.Hash{crypto.SHA256, crypto.SHA384, crypto.SHA512} {
		digest, err := signature.DigestAlgorithm(hash)
		if err != nil {
			t.Fatal(err)
		}
		d := signature.EncAlgorithm(digest)
		algorithm := pkix.AlgorithmIdentifier{Algorithm: signature.PSS(), Parameters: asn1.RawValue{FullBytes: der.Seq(der.Ctx(0, d), der.Ctx(1, der.Seq(der.OID(signature.MGF1()), d)), der.Ctx(2, der.Int(hash.Size())))}}
		want := []x509.SignatureAlgorithm{x509.SHA256WithRSAPSS, x509.SHA384WithRSAPSS, x509.SHA512WithRSAPSS}[i]
		if got := signatureAlgorithm(algorithm); got != want {
			t.Fatalf("PSS %v: %v; want %v", hash, got, want)
		}
		algorithm.Parameters = asn1.RawValue{}
		if got := signatureAlgorithm(algorithm); got != x509.UnknownSignatureAlgorithm {
			t.Fatal("PSS without explicit parameters accepted", got)
		}
	}
}

func TestCertificateListSchemaAndEntryLimitPrecedence(t *testing.T) {
	t.Parallel()
	algorithm := der.Seq(der.OID(asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}))
	issuer, err := asn1.Marshal(pkix.Name{CommonName: "test issuer"}.ToRDNSequence())
	if err != nil {
		t.Fatal(err)
	}
	stamp := der.Wrap(0, asn1.TagUTCTime, false, []byte("260101000000Z"))
	entry := der.Seq(der.Int(42), stamp)
	// A structural decoder does not authenticate the signature. A fixed,
	// nonempty byte-aligned BIT STRING isolates schema checks from crypto.
	bits := der.Wrap(0, asn1.TagBitString, false, []byte{0, 1})
	build := func(fields ...[]byte) []byte { return der.Seq(der.Seq(fields...), algorithm, bits) }
	valid := build(algorithm, issuer, stamp, der.Seq(entry))
	limits := Limits{Bytes: 4096, Depth: 33, Nodes: 1000, Entries: 2}
	view, err := Parse(valid, limits)
	if err != nil || view == nil || view.Version != 0 || len(view.CRL.RevokedCertificateEntries) != 1 || view.CRL.RevokedCertificateEntries[0].SerialNumber.Int64() != 42 {
		t.Fatalf("valid v1 list: %+v, %v", view, err)
	}
	for _, tc := range []struct {
		name string
		raw  []byte
	}{
		{"explicit v1 version", build(der.Int(0), algorithm, issuer, stamp)},
		{"unsupported version", build(der.Int(2), algorithm, issuer, stamp)},
		{"mismatching signature algorithm", build(der.Seq(der.OID(asn1.ObjectIdentifier{1, 3, 101, 112})), issuer, stamp)},
		{"empty issuer", build(algorithm, der.Seq(), stamp)},
		{"missing thisUpdate", build(algorithm, issuer)},
		{"invalid nextUpdate", build(algorithm, issuer, stamp, der.Wrap(0, asn1.TagUTCTime, false, []byte("260230000000Z")))},
		{"empty revoked sequence", build(algorithm, issuer, stamp, der.Seq())},
		{"wrong serial type", build(algorithm, issuer, stamp, der.Seq(der.Seq(der.Octets([]byte{42}), stamp)))},
		{"entry missing time", build(algorithm, issuer, stamp, der.Seq(der.Seq(der.Int(42))))},
		{"v1 entry extensions", build(algorithm, issuer, stamp, der.Seq(der.Seq(der.Int(42), stamp, der.Seq())))},
		{"trailing field", build(algorithm, issuer, stamp, der.Int(7))},
		{"empty signature", der.Seq(der.Seq(algorithm, issuer, stamp), algorithm, der.Wrap(0, asn1.TagBitString, false, []byte{0}))},
		{"unaligned signature", der.Seq(der.Seq(algorithm, issuer, stamp), algorithm, der.Wrap(0, asn1.TagBitString, false, []byte{1, 2}))},
	} {
		caseLimits := limits
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got, err := Parse(tc.raw, caseLimits); got != nil || err == nil || errors.Is(err, ErrLimit) {
				t.Fatalf("malformed list: %+v, %v; want syntax error without result", got, err)
			}
		})
	}
	malformed := der.Seq(der.Int(42), der.Octets([]byte("not a time")))
	raw := build(algorithm, issuer, stamp, der.Seq(malformed, entry))
	limits.Entries = 1
	if got, err := Parse(raw, limits); got != nil || !errors.Is(err, ErrLimit) {
		t.Fatal("entry budget must precede schema validation", got, err)
	}
	limits.Entries = 2
	if got, err := Parse(raw, limits); got != nil || !errors.Is(err, der.ErrInvalidDER) || errors.Is(err, ErrLimit) {
		t.Fatal("schema error hidden with sufficient entry budget", got, err)
	}
}

func TestExtensionSchemaDefaultAndUniqueness(t *testing.T) {
	t.Parallel()
	oid := der.OID(asn1.ObjectIdentifier{2, 5, 29, 21})
	value := der.Octets([]byte{10, 1, 1})
	extension := der.Seq(oid, value)
	critical := []byte{1, 1, 255}
	for _, tc := range []struct {
		name  string
		raw   []byte
		valid bool
	}{
		{"omitted critical flag", der.Seq(extension), true},
		{"explicit true critical flag", der.Seq(der.Seq(oid, critical, value)), true},
		{"different OIDs", der.Seq(extension, der.Seq(der.OID(asn1.ObjectIdentifier{2, 5, 29, 20}), value)), true},
		{"empty extensions", der.Seq(), false},
		{"duplicate OID", der.Seq(extension, extension), false},
		{"explicit default false", der.Seq(der.Seq(oid, []byte{1, 1, 0}, value)), false},
		{"wrong critical type", der.Seq(der.Seq(oid, der.Int(1), value)), false},
		{"wrong OID type", der.Seq(der.Seq(der.Int(1), value)), false},
		{"wrong value type", der.Seq(der.Seq(oid, der.Int(1))), false},
		{"missing value", der.Seq(der.Seq(oid)), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			raw, err := der.Read(tc.raw, 4096)
			if err != nil {
				t.Fatal("fixture must be structurally valid DER", err)
			}
			err = validateExtensions(raw)
			if tc.valid && err != nil || !tc.valid && !errors.Is(err, der.ErrInvalidDER) {
				t.Fatalf("extension schema: %v; valid=%v", err, tc.valid)
			}
		})
	}
}
