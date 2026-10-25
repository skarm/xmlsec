package pki

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"fmt"

	"github.com/skarm/xmlsec/internal/ecdsakey"
)

// This package currently uses a fixed modern offline validation profile. It does
// not inherit GODEBUG exceptions allowing SHA-1 or small RSA keys.
func allowedPublicKey(key crypto.PublicKey) error {
	switch k := key.(type) {
	case *rsa.PublicKey:
		if k == nil || k.N == nil || k.N.BitLen() < 2048 || k.N.BitLen() > 16384 || k.E < 3 || k.E%2 == 0 {
			return fmt.Errorf("%w: RSA key strength", ErrPolicy)
		}
	case *ecdsa.PublicKey:
		if k == nil || (k.Curve != elliptic.P256() && k.Curve != elliptic.P384() && k.Curve != elliptic.P521()) {
			return fmt.Errorf("%w: ECDSA key", ErrPolicy)
		}

		if _, err := ecdsakey.PublicBytes(k); err != nil {
			return fmt.Errorf("%w: ECDSA key", ErrPolicy)
		}
	case ed25519.PublicKey:
		if len(k) != ed25519.PublicKeySize {
			return fmt.Errorf("%w: Ed25519 key", ErrPolicy)
		}
	default:
		return fmt.Errorf("%w: public key algorithm", ErrPolicy)
	}

	return nil
}

func allowedSignature(a x509.SignatureAlgorithm) bool {
	switch a {
	case x509.SHA256WithRSA, x509.SHA384WithRSA, x509.SHA512WithRSA,
		x509.SHA256WithRSAPSS, x509.SHA384WithRSAPSS, x509.SHA512WithRSAPSS,
		x509.ECDSAWithSHA256, x509.ECDSAWithSHA384, x509.ECDSAWithSHA512, x509.PureEd25519:
		return true
	}

	return false
}
