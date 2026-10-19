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
)

// Chain contains disposable test identities and their private keys.
type Chain struct {
	Root, Leaf, TSA, Responder             *x509.Certificate
	RootKey, LeafKey, TSAKey, ResponderKey *ecdsa.PrivateKey
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
