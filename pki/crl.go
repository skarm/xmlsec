package pki

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"

	"github.com/skarm/xmlsec/internal/ecdsakey"
)

func safeMarshalPublic(public crypto.PublicKey) ([]byte, error) {
	switch k := public.(type) {
	case *rsa.PublicKey:
		if k == nil || k.N == nil || k.N.Sign() <= 0 || k.E < 3 {
			return nil, ErrCertificate
		}
	case *ecdsa.PublicKey:
		if _, err := ecdsakey.PublicBytes(k); err != nil {
			return nil, ErrCertificate
		}
	case ed25519.PublicKey:
		if len(k) != ed25519.PublicKeySize {
			return nil, ErrCertificate
		}
	default:
		return nil, ErrCertificate
	}

	return x509.MarshalPKIXPublicKey(public)
}
