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

// CMS signature OIDs map authenticated algorithm identifiers to the PKIX family;
// digest selection and RSA-PSS parameter validation happen before this dispatch.
const (
	oidECDSAWithSHA256 = "1.2.840.10045.4.3.2"
	oidECDSAWithSHA384 = "1.2.840.10045.4.3.3"
	oidECDSAWithSHA512 = "1.2.840.10045.4.3.4"
	oidEd25519         = "1.3.101.112"
	oidRSAPSS          = "1.2.840.113549.1.1.10"
	oidSHA256WithRSA   = "1.2.840.113549.1.1.11"
	oidSHA384WithRSA   = "1.2.840.113549.1.1.12"
	oidSHA512WithRSA   = "1.2.840.113549.1.1.13"
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
	const bitsPerOctet = 8

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
		return len(key) * bitsPerOctet
	}

	return 0
}

// CMS normalizes rsaEncryption using the authenticated digest before returning
// the OID. RSA-PSS parameters were already checked by CMS's fixed profile.
func cmsAlgorithm(oid string, hash crypto.Hash) x509.SignatureAlgorithm {
	switch oid {
	case oidSHA256WithRSA:
		return x509.SHA256WithRSA
	case oidSHA384WithRSA:
		return x509.SHA384WithRSA
	case oidSHA512WithRSA:
		return x509.SHA512WithRSA
	case oidECDSAWithSHA256:
		return x509.ECDSAWithSHA256
	case oidECDSAWithSHA384:
		return x509.ECDSAWithSHA384
	case oidECDSAWithSHA512:
		return x509.ECDSAWithSHA512
	case oidRSAPSS:
		switch hash {
		case crypto.SHA256:
			return x509.SHA256WithRSAPSS
		case crypto.SHA384:
			return x509.SHA384WithRSAPSS
		case crypto.SHA512:
			return x509.SHA512WithRSAPSS
		}
	case oidEd25519:
		return x509.PureEd25519
	}

	return x509.UnknownSignatureAlgorithm
}
