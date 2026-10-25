package historical

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"time"

	"github.com/skarm/xmlsec/pki"
)

func hashReliable(hash crypto.Hash, at time.Time, rules []pki.CryptoConstraint) bool {
	for _, rule := range rules {
		if rule.Hash == hash && !at.Before(rule.ReliableUntil) {
			return false
		}
	}

	return true
}

func signatureReliable(algorithm x509.SignatureAlgorithm, hash crypto.Hash, certificate *x509.Certificate, at time.Time, rules []pki.CryptoConstraint) bool {
	for _, rule := range rules {
		applies := rule.SignatureAlgorithm != 0 && rule.SignatureAlgorithm == algorithm || rule.Hash != 0 && rule.Hash == hash
		if rule.PublicKeyAlgorithm != 0 && certificate != nil && certificate.PublicKeyAlgorithm == rule.PublicKeyAlgorithm {
			bits := keyBits(certificate.PublicKey)
			applies = bits > 0 && bits < rule.MinimumKeyBits
		}

		if applies && !at.Before(rule.ReliableUntil) {
			return false
		}
	}

	return true
}

func keyBits(key crypto.PublicKey) int {
	switch key := key.(type) {
	case *rsa.PublicKey:
		if key != nil && key.N != nil {
			return key.N.BitLen()
		}
	case *ecdsa.PublicKey:
		if key != nil && key.Curve != nil {
			return key.Curve.Params().BitSize
		}
	case ed25519.PublicKey:
		return len(key) * 8
	}

	return 0
}

// CMS normalizes rsaEncryption using the authenticated digest before returning
// the OID. RSA-PSS parameters were already checked by CMS's fixed profile.
func cmsAlgorithm(oid string, hash crypto.Hash) x509.SignatureAlgorithm {
	switch oid {
	case "1.2.840.113549.1.1.11":
		return x509.SHA256WithRSA
	case "1.2.840.113549.1.1.12":
		return x509.SHA384WithRSA
	case "1.2.840.113549.1.1.13":
		return x509.SHA512WithRSA
	case "1.2.840.10045.4.3.2":
		return x509.ECDSAWithSHA256
	case "1.2.840.10045.4.3.3":
		return x509.ECDSAWithSHA384
	case "1.2.840.10045.4.3.4":
		return x509.ECDSAWithSHA512
	case "1.2.840.113549.1.1.10":
		switch hash {
		case crypto.SHA256:
			return x509.SHA256WithRSAPSS
		case crypto.SHA384:
			return x509.SHA384WithRSAPSS
		case crypto.SHA512:
			return x509.SHA512WithRSAPSS
		}
	case "1.3.101.112":
		return x509.PureEd25519
	}

	return x509.UnknownSignatureAlgorithm
}
