package x509cert //nolint:testpackage // Validates the private GeneralName schema preflight with checked DER fixtures.

import (
	"bytes"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"slices"
	"testing"

	"github.com/skarm/xmlsec/internal/der"
	"github.com/skarm/xmlsec/internal/testutil/testcert"
)

func parseNameFixture(t *testing.T, encoded []byte) asn1.RawValue {
	t.Helper()
	value, err := der.Read(encoded, 1<<20)
	if err != nil {
		t.Fatal("invalid DER fixture", err)
	}
	return value
}

func TestGeneralNameChoices(t *testing.T) {
	t.Parallel()

	oid := asn1.ObjectIdentifier{1, 2, 3, 4}
	oidContent := parseNameFixture(t, der.OID(oid)).Bytes
	dn, err := asn1.Marshal(pkix.RDNSequence{{{Type: asn1.ObjectIdentifier{2, 5, 4, 3}, Value: "issuer"}}})
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name    string
		encoded []byte
	}{
		{"otherName", der.Ctx(0, bytes.Join([][]byte{der.OID(oid), der.Ctx(0, der.Octets([]byte("value")))}, nil))},
		{"mail", der.Wrap(2, 1, false, []byte("user@example.test"))},
		{"DNS", der.Wrap(2, 2, false, []byte("example.test"))},
		{"directoryName", der.Ctx(4, dn)},
		{"URI", der.Wrap(2, 6, false, []byte("https://example.test/crl"))},
		{"IPv4", der.Wrap(2, 7, false, []byte{192, 0, 2, 1})},
		{"IPv6", der.Wrap(2, 7, false, make([]byte, 16))},
		{"registered ID", der.Wrap(2, 8, false, oidContent)},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			if err := generalName(parseNameFixture(t, test.encoded)); err != nil {
				t.Fatal("valid GeneralName rejected", err)
			}
		})
	}
}

func TestGeneralNameRejectsInvalidSchema(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name    string
		encoded []byte
	}{
		{"wrong class", der.Octets([]byte("x"))},
		{"unknown choice", der.Wrap(2, 9, false, []byte("x"))},
		{"empty otherName", der.Ctx(0, nil)},
		{"incomplete otherName", der.Ctx(0, der.OID(asn1.ObjectIdentifier{1, 2, 3}))},
		{"otherName missing OID", der.Ctx(0, bytes.Join([][]byte{der.Octets([]byte("x")), der.Ctx(0, der.Octets(nil))}, nil))},
		{"otherName wrong explicit tag", der.Ctx(0, bytes.Join([][]byte{der.OID(asn1.ObjectIdentifier{1, 2, 3}), der.Ctx(1, der.Octets(nil))}, nil))},
		{"directory name primitive", der.Wrap(2, 4, false, []byte{0x30, 0})},
		{"directory name wrong structure", der.Ctx(4, der.Octets(nil))},
		{"primitive x400", der.Wrap(2, 3, false, nil)},
		{"primitive edi", der.Wrap(2, 5, false, nil)},
		{"short IPv4", der.Wrap(2, 7, false, []byte{192, 0, 2})},
		{"long IPv4", der.Wrap(2, 7, false, make([]byte, 5))},
		{"long IPv6", der.Wrap(2, 7, false, make([]byte, 17))},
		{"constructed IP", der.Ctx(7, der.Octets([]byte{192, 0, 2, 1}))},
		{"empty registered ID", der.Wrap(2, 8, false, nil)},
		{"unterminated registered ID", der.Wrap(2, 8, false, []byte{0x80})},
		{"constructed registered ID", der.Ctx(8, der.OID(asn1.ObjectIdentifier{1, 2, 3}))},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			if err := generalName(parseNameFixture(t, test.encoded)); !errors.Is(err, der.ErrInvalidDER) {
				t.Fatalf("invalid GeneralName accepted: %v", err)
			}
		})
	}
	for _, tag := range []int{1, 2, 6} {
		for _, invalid := range [][]byte{nil, []byte("control\n"), []byte("non-ascii-é"), {0x7f}} {
			if err := generalName(parseNameFixture(t, der.Wrap(2, tag, false, invalid))); !errors.Is(err, der.ErrInvalidDER) {
				t.Fatalf("ASCII choice %d accepted %q: %v", tag, invalid, err)
			}
		}
		if err := generalName(parseNameFixture(t, der.Ctx(tag, der.Octets([]byte("value"))))); !errors.Is(err, der.ErrInvalidDER) {
			t.Fatalf("constructed ASCII choice %d accepted: %v", tag, err)
		}
	}
}

func TestGeneralNamesBounds(t *testing.T) {
	t.Parallel()

	name := der.Wrap(2, 2, false, []byte("example.test"))
	for _, count := range []int{0, 1, 256, 257} {
		value := parseNameFixture(t, der.Ctx(0, bytes.Repeat(name, count)))
		err := generalNames(value)
		if count == 1 || count == 256 {
			if err != nil {
				t.Fatalf("%d names rejected: %v", count, err)
			}
		} else if !errors.Is(err, der.ErrInvalidDER) {
			t.Fatalf("%d names accepted: %v", count, err)
		}
		if count == 257 && !errors.Is(err, der.ErrLimit) {
			t.Fatal("lost child-count limit", err)
		}
	}
	if err := generalNames(parseNameFixture(t, der.Wrap(2, 0, false, name))); !errors.Is(err, der.ErrInvalidDER) {
		t.Fatal("primitive GeneralNames accepted", err)
	}
}

func TestRelativeCRLPointRetainsIssuerAndFullURIs(t *testing.T) {
	t.Parallel()

	chain := testcert.New(t)
	cn := der.Seq(der.OID(asn1.ObjectIdentifier{2, 5, 4, 3}), der.Wrap(0, asn1.TagUTF8String, false, []byte("relative")))
	issuer := der.Ctx(4, chain.Root.RawSubject)
	relativePoint := der.Seq(der.Ctx(0, der.Ctx(1, cn)), der.Ctx(2, issuer))
	fullPoint := der.Seq(der.Ctx(0, der.Ctx(0, bytes.Join([][]byte{
		der.Wrap(2, 2, false, []byte("ignored.example.test")),
		der.Wrap(2, 6, false, []byte("https://example.test/first.crl")),
		der.Wrap(2, 6, false, []byte("https://example.test/second.crl")),
	}, nil))))
	points := der.Seq(relativePoint, fullPoint)
	template := *chain.Leaf
	template.ExtraExtensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, 31}, Value: points}}
	raw, err := x509.CreateCertificate(rand.Reader, &template, chain.Root, chain.LeafKey.Public(), chain.RootKey)
	if err != nil {
		t.Fatal(err)
	}
	before := bytes.Clone(raw)
	cert, err := ParseDefault(raw)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(raw, before) || !bytes.Equal(cert.Raw, raw) || !slices.Equal(cert.CRLDistributionPoints, []string{"https://example.test/first.crl", "https://example.test/second.crl"}) {
		t.Fatal("private parse view changed input or leaked/invented distribution URI", cert.CRLDistributionPoints)
	}
	if err := cert.CheckSignatureFrom(chain.Root); err != nil {
		t.Fatal("original signed bytes were not restored", err)
	}
	for _, extension := range cert.Extensions {
		if extension.Id.Equal(asn1.ObjectIdentifier{2, 5, 29, 31}) {
			if !bytes.Equal(extension.Value, points) {
				t.Fatal("original distribution-point extension changed")
			}
			return
		}
	}
	t.Fatal("distribution-point extension lost")
}
