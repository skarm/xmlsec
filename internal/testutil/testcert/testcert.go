package testcert

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"testing"
	"time"

	"github.com/skarm/xmlsec/internal/der"
	"github.com/skarm/xmlsec/internal/signature"
)

// Chain contains disposable test identities and their private keys.
type Chain struct {
	Root         *x509.Certificate
	Leaf         *x509.Certificate
	TSA          *x509.Certificate
	Responder    *x509.Certificate
	RootKey      *ecdsa.PrivateKey
	LeafKey      *ecdsa.PrivateKey
	TSAKey       *ecdsa.PrivateKey
	ResponderKey *ecdsa.PrivateKey
}

// New creates an ephemeral test chain and its signing keys.
func New(t testing.TB) Chain {
	t.Helper()
	c := Chain{RootKey: Key(t), LeafKey: Key(t), TSAKey: Key(t), ResponderKey: Key(t)}
	root := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "iteration 6 test root"}, NotBefore: Now().Add(-365 * 24 * time.Hour), NotAfter: Now().Add(365 * 24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign, SubjectKeyId: []byte{1, 2, 3, 4}}
	c.Root = Issue(t, root, root, &c.RootKey.PublicKey, c.RootKey)
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "test signer"}, NotBefore: Now().Add(-24 * time.Hour), NotAfter: Now().Add(24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning}, SubjectKeyId: []byte{5, 6, 7, 8}}
	c.Leaf = Issue(t, leaf, c.Root, &c.LeafKey.PublicKey, c.RootKey)
	eku, _ := asn1.Marshal([]asn1.ObjectIdentifier{{1, 3, 6, 1, 5, 5, 7, 3, 8}})
	tsa := &x509.Certificate{SerialNumber: big.NewInt(3), Subject: pkix.Name{CommonName: "test TSA"}, NotBefore: Now().Add(-24 * time.Hour), NotAfter: Now().Add(24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtraExtensions: []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, 37}, Critical: true, Value: eku}}}
	c.TSA = Issue(t, tsa, c.Root, &c.TSAKey.PublicKey, c.RootKey)
	responder := &x509.Certificate{SerialNumber: big.NewInt(4), Subject: pkix.Name{CommonName: "test responder"}, NotBefore: Now().Add(-24 * time.Hour), NotAfter: Now().Add(24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageOCSPSigning}, ExtraExtensions: []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1, 5}, Value: []byte{5, 0}}}}
	c.Responder = Issue(t, responder, c.Root, &c.ResponderKey.PublicKey, c.RootKey)

	return c
}

// Now returns the fixed verification time used by ephemeral test fixtures.
func Now() time.Time { return time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC) }

// Key generates a disposable P-256 private key for a test.
func Key(t testing.TB) *ecdsa.PrivateKey {
	t.Helper()

	k, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}

	return k
}

// Issue issues and parses a disposable test certificate.
func Issue(t testing.TB, template, parent *x509.Certificate, public crypto.PublicKey, key crypto.Signer) *x509.Certificate {
	t.Helper()

	b, e := x509.CreateCertificate(rand.Reader, template, parent, public, key)
	if e != nil {
		t.Fatal(e)
	}

	c, e := x509.ParseCertificate(b)
	if e != nil {
		t.Fatal(e)
	}

	return c
}

// CRL issues a complete test CRL containing the explicitly revoked certificates.
func CRL(t testing.TB, c Chain, revoked ...*x509.Certificate) []byte {
	t.Helper()

	template := &x509.RevocationList{Number: big.NewInt(1), ThisUpdate: Now().Add(-time.Minute), NextUpdate: Now().Add(time.Hour)}
	for _, cert := range revoked {
		template.RevokedCertificateEntries = append(template.RevokedCertificateEntries, x509.RevocationListEntry{SerialNumber: cert.SerialNumber, RevocationTime: Now().Add(-time.Hour)})
	}

	b, e := x509.CreateRevocationList(rand.Reader, template, c.Root, c.RootKey)
	if e != nil {
		t.Fatal(e)
	}

	return b
}

// CRLV1 issues an original signed v1 complete CRL, omitting v2 extensions.
func CRLV1(t testing.TB, c Chain, revoked ...*x509.Certificate) []byte {
	t.Helper()
	original := CRL(t, c, revoked...)

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

	signed, err := signature.Sign(t.Context(), c.RootKey, algorithm, raw)
	if err != nil {
		t.Fatal(err)
	}

	bits, _ := asn1.Marshal(asn1.BitString{Bytes: signed, BitLength: len(signed) * 8})

	return der.Seq(raw, fields[1].FullBytes, bits)
}

// CertificateEncoding is a signed encoding control; Valid refers only to its
// RFC5280/DER syntax, not application trust or certificate policy.
type CertificateEncoding struct {
	Name  string
	DER   []byte
	Valid bool
}

// CertificateEncodings supplies canonical controls and exactly three schema
// variants for the same leaf public key: a valid relative distribution point,
// an explicitly encoded DEFAULT version0, and explicit extension criticalFALSE.
// Fixtures are built/re-signed with standard crypto; no production decoder is
// used to decide whether their original bytes are valid.
func CertificateEncodings(t testing.TB, c Chain) []CertificateEncoding {
	t.Helper()

	value, err := der.Read(c.Leaf.Raw, len(c.Leaf.Raw))
	if err != nil {
		t.Fatal(err)
	}

	outer, err := der.Sequence(value, 3, 3)
	if err != nil {
		t.Fatal(err)
	}

	body, err := der.Sequence(outer[0], 6, 10)
	if err != nil {
		t.Fatal(err)
	}

	resign := func(parts [][]byte) []byte {
		t.Helper()

		tbs := der.Seq(parts...)

		algorithm, err := signature.Algorithm(outer[1])
		if err != nil {
			t.Fatal(err)
		}

		signed, err := signature.Sign(t.Context(), c.RootKey, algorithm, tbs)
		if err != nil {
			t.Fatal(err)
		}

		bits, err := asn1.Marshal(asn1.BitString{Bytes: signed, BitLength: len(signed) * 8})
		if err != nil {
			t.Fatal(err)
		}

		return der.Seq(tbs, outer[1].FullBytes, bits)
	}

	var v1 [][]byte

	for _, field := range body {
		if field.Class == 2 && (field.Tag == 0 || field.Tag == 3) {
			continue
		}

		v1 = append(v1, field.FullBytes)
	}

	canonicalV1 := resign(v1)
	explicitV1 := resign(append([][]byte{der.Ctx(0, der.Int(0))}, v1...))
	criticalParts := certificateCriticalFalse(t, body)

	template := *c.Leaf
	attribute := der.Seq(der.OID(asn1.ObjectIdentifier{2, 5, 4, 3}), der.Wrap(0, asn1.TagUTF8String, false, []byte("relative partition")))
	point := der.Seq(der.Ctx(0, der.Wrap(2, 1, true, attribute)))
	template.ExtraExtensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, 31}, Value: der.Seq(point)}}

	relative, err := x509.CreateCertificate(rand.Reader, &template, c.Root, &c.LeafKey.PublicKey, c.RootKey)
	if err != nil {
		t.Fatal(err)
	}

	return []CertificateEncoding{
		{Name: "canonical v3", DER: c.Leaf.Raw, Valid: true},
		{Name: "canonical v1", DER: canonicalV1, Valid: true},
		{Name: "relative distribution point", DER: relative, Valid: true},
		{Name: "explicit default version0", DER: explicitV1},
		{Name: "explicit critical false", DER: resign(criticalParts)},
	}
}

// certificateCriticalFalse changes only one omitted DEFAULT in signed fixture
// metadata; the caller re-signs the result without consulting a production parser.
func certificateCriticalFalse(t testing.TB, body []asn1.RawValue) [][]byte {
	t.Helper()

	criticalParts := make([][]byte, len(body))
	changed := false

	for i, field := range body {
		criticalParts[i] = field.FullBytes
		if field.Class != 2 || field.Tag != 3 {
			continue
		}

		v, err := der.Explicit(field, 3)
		if err != nil {
			t.Fatal(err)
		}

		extensions, err := der.Sequence(v, 1, 256)
		if err != nil {
			t.Fatal(err)
		}

		parts := make([][]byte, len(extensions))
		for at, extension := range extensions {
			fields, err := der.Sequence(extension, 2, 3)
			if err != nil {
				t.Fatal(err)
			}

			parts[at] = extension.FullBytes
			if len(fields) == 2 && !changed {
				parts[at] = der.Seq(fields[0].FullBytes, []byte{1, 1, 0}, fields[1].FullBytes)
				changed = true
			}
		}

		criticalParts[i] = der.Ctx(3, der.Seq(parts...))
	}

	if !changed {
		t.Fatal("fixture needs a noncritical extension")
	}

	return criticalParts
}
