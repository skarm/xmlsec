package democert

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"math/big"
	"time"
)

// Chain contains disposable certificates, private keys and a complete CRL for examples.
type Chain struct {
	Root      *x509.Certificate
	Signer    *x509.Certificate
	TSA       *x509.Certificate
	Peer      *x509.Certificate
	RootKey   *ecdsa.PrivateKey
	SignerKey *ecdsa.PrivateKey
	TSAKey    *ecdsa.PrivateKey
	PeerKey   *ecdsa.PrivateKey
	CRL       []byte
}

// New generates a disposable ECDSA trust chain valid at the explicit example time.
func New(at time.Time) (Chain, error) {
	var c Chain
	if at.IsZero() {
		return c, errors.New("explicit demonstration time required")
	}

	keys := []**ecdsa.PrivateKey{&c.RootKey, &c.SignerKey, &c.TSAKey, &c.PeerKey}
	for _, target := range keys {
		k, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if e != nil {
			return c, e
		}

		*target = k
	}

	issue := func(t, p *x509.Certificate, key, issuer *ecdsa.PrivateKey) (*x509.Certificate, error) {
		b, e := x509.CreateCertificate(rand.Reader, t, p, &key.PublicKey, issuer)
		if e != nil {
			return nil, e
		}

		return x509.ParseCertificate(b)
	}
	rt := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "ephemeral example root"}, NotBefore: at.Add(-24 * time.Hour), NotAfter: at.Add(365 * 24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign, SubjectKeyId: []byte{1, 2, 3, 4}}

	var e error

	c.Root, e = issue(rt, rt, c.RootKey, c.RootKey)
	if e != nil {
		return c, e
	}

	leaf := func(serial int64, cn string) *x509.Certificate {
		return &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: cn}, NotBefore: at.Add(-time.Hour), NotAfter: at.Add(24 * time.Hour), BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature}
	}
	st := leaf(2, "example document signer")
	st.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning}

	c.Signer, e = issue(st, c.Root, c.SignerKey, c.RootKey)
	if e != nil {
		return c, e
	}

	tt := leaf(3, "example TSA")

	eku, e := asn1.Marshal([]asn1.ObjectIdentifier{{1, 3, 6, 1, 5, 5, 7, 3, 8}})
	if e != nil {
		return c, e
	}

	tt.ExtraExtensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, 37}, Critical: true, Value: eku}}

	c.TSA, e = issue(tt, c.Root, c.TSAKey, c.RootKey)
	if e != nil {
		return c, e
	}

	pt := leaf(4, "example SAML IdP")

	c.Peer, e = issue(pt, c.Root, c.PeerKey, c.RootKey)
	if e != nil {
		return c, e
	}

	c.CRL, e = x509.CreateRevocationList(rand.Reader, &x509.RevocationList{Number: big.NewInt(1), ThisUpdate: at.Add(-time.Minute), NextUpdate: at.Add(time.Hour)}, c.Root, c.RootKey)

	return c, e
}
