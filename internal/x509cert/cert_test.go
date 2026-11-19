package x509cert_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"slices"
	"testing"

	"github.com/skarm/xmlsec/internal/der"
	"github.com/skarm/xmlsec/internal/testutil/testcert"
	"github.com/skarm/xmlsec/internal/x509cert"
)

func TestParseCRLDistributionPointsWithReasonAndIssuer(t *testing.T) {
	t.Parallel()

	const wantURI = "https://example.test/root.crl"
	chain := testcert.New(t)
	uri := der.Wrap(asn1.ClassContextSpecific, 6, false, []byte(wantURI))
	// A two-bit ReasonFlags value with only keyCompromise (bit 1) set.
	reason := der.Wrap(asn1.ClassContextSpecific, 1, false, []byte{6, 0x40})
	fullName := der.Seq(der.Ctx(0, der.Ctx(0, uri)), reason)
	issuerOnly := der.Seq(der.Ctx(2, der.Ctx(4, chain.Root.RawSubject)))
	points := der.Seq(relativeCRLPoint(), fullName, issuerOnly)
	encoded := issueWithCRLPoints(t, chain, points)

	parsed, err := x509cert.ParseDefault(encoded)
	if err != nil {
		t.Fatalf("ParseDefault() error = %v", err)
	}
	if !slices.Equal(parsed.CRLDistributionPoints, []string{wantURI}) {
		t.Errorf("CRLDistributionPoints = %q, want [%q]", parsed.CRLDistributionPoints, wantURI)
	}
	for _, ext := range parsed.Extensions {
		if ext.Id.Equal(asn1.ObjectIdentifier{2, 5, 29, 31}) {
			if !bytes.Equal(ext.Value, points) {
				t.Errorf("CRL distribution point extension = %x, want %x", ext.Value, points)
			}
			return
		}
	}
	t.Error("parsed certificate lost its CRL distribution point extension")
}

func TestParseFullNameCRLDistributionPointURIs(t *testing.T) {
	t.Parallel()

	const uri = "https://example.test/root.crl"
	chain := testcert.New(t)
	uriName := der.Wrap(asn1.ClassContextSpecific, 6, false, []byte(uri))
	dnsName := der.Wrap(asn1.ClassContextSpecific, 2, false, []byte("example.test"))
	point := func(names ...[]byte) []byte {
		return der.Seq(der.Ctx(0, der.Ctx(0, names...)))
	}
	// GeneralNames and DistributionPoints allow multiple entries. When a
	// valid input exceeds the supplemental parser's fixed point count, the
	// successful standard-library view is still available.
	const beyondSupplementalPointLimit = 257
	singleNamePoint := point(uriName)
	manyPoints := der.Wrap(asn1.ClassUniversal, asn1.TagSequence, true, bytes.Repeat(singleNamePoint, beyondSupplementalPointLimit))
	for _, tc := range []struct {
		name  string
		point []byte
		count int
	}{
		{"uri_first", der.Seq(point(uriName, dnsName)), 1},
		{"dns_first", der.Seq(point(dnsName, uriName)), 1},
		{"standard_library_view_above_supplemental_limit", manyPoints, beyondSupplementalPointLimit},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			encoded := issueWithCRLPoints(t, chain, tc.point)
			certificate, err := x509cert.ParseDefault(encoded)
			if err != nil {
				t.Fatalf("parse fullName distribution points: %v", err)
			}
			if len(certificate.CRLDistributionPoints) != tc.count {
				t.Fatalf("found %d distribution point URIs, want %d", len(certificate.CRLDistributionPoints), tc.count)
			}
			for _, got := range certificate.CRLDistributionPoints {
				if got != uri {
					t.Errorf("distribution point URI %q, want %q", got, uri)
				}
			}
			if err := certificate.CheckSignatureFrom(chain.Root); err != nil {
				t.Fatalf("original certificate signature: %v", err)
			}
		})
	}
}

func TestParseRejectsIncompleteCRLDistributionPoints(t *testing.T) {
	t.Parallel()

	chain := testcert.New(t)
	// Use a relative first point to exercise the package's distribution point parser.
	relative := relativeCRLPoint()
	for _, tc := range []struct {
		name  string
		point []byte
	}{
		{name: "empty_point", point: der.Seq()},
		{name: "empty_full_name", point: der.Seq(der.Ctx(0, der.Ctx(0)))},
		{name: "empty_relative_name", point: der.Seq(der.Ctx(0, der.Ctx(1)))},
		{name: "reason_without_name_or_issuer", point: der.Seq(der.Wrap(asn1.ClassContextSpecific, 1, false, []byte{6, 0x40}))},
		{name: "empty_issuer", point: der.Seq(der.Ctx(2))},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			encoded := issueWithCRLPoints(t, chain, der.Seq(relative, tc.point))
			got, err := x509cert.ParseDefault(encoded)
			if got != nil || !errors.Is(err, der.ErrInvalidDER) {
				t.Fatalf("ParseDefault() = (%v, %v), want (nil, %v)", got, err, der.ErrInvalidDER)
			}
		})
	}
}

func relativeCRLPoint() []byte {
	cn := der.Seq(der.OID(asn1.ObjectIdentifier{2, 5, 4, 3}), der.Wrap(asn1.ClassUniversal, asn1.TagUTF8String, false, []byte("relative CRL")))
	return der.Seq(der.Ctx(0, der.Ctx(1, cn)))
}

func issueWithCRLPoints(t *testing.T, chain testcert.Chain, points []byte) []byte {
	t.Helper()

	template := *chain.Leaf
	template.ExtraExtensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, 31}, Value: points}}
	encoded, err := x509.CreateCertificate(rand.Reader, &template, chain.Root, chain.LeafKey.Public(), chain.RootKey)
	if err != nil {
		t.Fatalf("create certificate with CRL distribution points: %v", err)
	}
	return encoded
}

func TestParsePreservesOriginalSignedCertificate(t *testing.T) {
	t.Parallel()

	chain := testcert.New(t)
	relative := der.Seq(relativeCRLPoint())
	encoded := issueWithCRLPoints(t, chain, relative)
	before := bytes.Clone(encoded)
	parsed, err := x509cert.ParseDefault(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(encoded, before) || !bytes.Equal(parsed.Raw, encoded) || !bytes.Equal(parsed.RawIssuer, chain.Leaf.RawIssuer) || len(parsed.CRLDistributionPoints) != 0 {
		t.Fatal("private parsing view changed original DER or invented a URI")
	}
	if err := parsed.CheckSignatureFrom(chain.Root); err != nil {
		t.Fatal("original signed TBS was not restored", err)
	}
	var found bool
	for _, extension := range parsed.Extensions {
		if extension.Id.Equal(asn1.ObjectIdentifier{2, 5, 29, 31}) {
			found = bytes.Equal(extension.Value, relative)
		}
	}
	if !found {
		t.Fatal("original relative distribution point was replaced")
	}
}

func TestParseBoundsAndNoAuthentication(t *testing.T) {
	t.Parallel()

	chain := testcert.New(t)
	raw := chain.Leaf.Raw
	for _, tc := range []struct {
		name   string
		limits x509cert.Limits
	}{
		{"bytes", x509cert.Limits{Bytes: len(raw) - 1, Depth: 33, Nodes: 100000}},
		{"depth", x509cert.Limits{Bytes: len(raw), Depth: 1, Nodes: 100000}},
		{"nodes", x509cert.Limits{Bytes: len(raw), Depth: 33, Nodes: 1}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if got, err := x509cert.Parse(raw, tc.limits); got != nil || !errors.Is(err, der.ErrLimit) {
				t.Fatal(got, err)
			}
		})
	}
	exact, err := x509cert.ParseWithMaxBytes(raw, len(raw))
	if err != nil || !bytes.Equal(exact.RawTBSCertificate, chain.Leaf.RawTBSCertificate) {
		t.Fatal("exact byte bound", err)
	}
	for _, invalid := range [][]byte{nil, {0x30, 0}, append(bytes.Clone(raw), 0)} {
		if got, err := x509cert.ParseDefault(invalid); got != nil || err == nil {
			t.Fatal("malformed certificate accepted", got, err)
		}
	}
	changed := bytes.Clone(raw)
	changed[len(changed)-1] ^= 1
	parsed, err := x509cert.ParseDefault(changed)
	if err != nil {
		t.Fatal("a parser must not claim signature authentication", err)
	}
	if err := parsed.CheckSignatureFrom(chain.Root); err == nil {
		t.Fatal("corrupted signature passed independent signature check")
	}
}

func BenchmarkParseCertificate(b *testing.B) {
	chain := testcert.New(b)
	for _, size := range []int{0, 64 << 10} {
		raw := chain.Leaf.Raw
		name := "ordinary"
		if size != 0 {
			template := *chain.Leaf
			template.ExtraExtensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 2, 3, 4}, Value: der.Octets(bytes.Repeat([]byte("x"), size))}}
			var err error
			raw, err = x509.CreateCertificate(rand.Reader, &template, chain.Root, chain.LeafKey.Public(), chain.RootKey)
			if err != nil {
				b.Fatal(err)
			}
			name = "large-extension"
		}
		b.Run(name, func(b *testing.B) {
			b.ReportAllocs()
			b.SetBytes(int64(len(raw)))
			for b.Loop() {
				if _, err := x509cert.ParseDefault(raw); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func TestParseRejectsTrailingPublicKeyInfoFields(t *testing.T) {
	t.Parallel()

	chain := testcert.New(t)
	for _, relative := range []bool{false, true} {
		raw := chain.Leaf.Raw
		if relative {
			raw = issueWithCRLPoints(t, chain, der.Seq(relativeCRLPoint()))
		}
		outer := publicStructureFields(t, raw)
		body := publicStructureFields(t, outer[0])
		spki := publicStructureFields(t, body[6])
		algorithm := publicStructureFields(t, spki[0])
		for name, malformed := range map[string][]byte{
			"outer":     der.Seq(append(spki, der.Int(0))...),
			"algorithm": der.Seq(der.Seq(append(algorithm, der.Int(0))...), spki[1]),
		} {
			changed := append([][]byte(nil), body...)
			changed[6] = malformed
			tbs := der.Seq(changed...)
			digest := sha256.Sum256(tbs)
			signed, err := ecdsa.SignASN1(rand.Reader, chain.RootKey, digest[:])
			if err != nil {
				t.Fatal(err)
			}
			if err := chain.Root.CheckSignature(x509.ECDSAWithSHA256, tbs, signed); err != nil {
				t.Fatalf("malformed-schema fixture must retain a valid issuer signature: %v", err)
			}
			bits, err := asn1.Marshal(asn1.BitString{Bytes: signed, BitLength: len(signed) * 8})
			if err != nil {
				t.Fatal(err)
			}
			encoded := der.Seq(tbs, outer[1], bits)
			if parsed, err := x509cert.ParseDefault(encoded); parsed != nil || !errors.Is(err, der.ErrInvalidDER) {
				t.Errorf("%s relative=%t accepted trailing SPKI fields: certificate=%t err=%v", name, relative, parsed != nil, err)
			}
		}
	}
}

func publicStructureFields(t *testing.T, raw []byte) [][]byte {
	t.Helper()
	value, err := der.Read(raw, len(raw))
	if err != nil {
		t.Fatal(err)
	}
	fields, err := der.Sequence(value, 1, 10)
	if err != nil {
		t.Fatal(err)
	}
	parts := make([][]byte, len(fields))
	for index, field := range fields {
		parts[index] = field.FullBytes
	}
	return parts
}
