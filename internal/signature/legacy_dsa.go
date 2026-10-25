package signature

import (
	"crypto"
	// #nosec G406 -- Explicit bounded legacy compatibility only.
	"crypto/dsa" //nolint:staticcheck // XMLDSig 1.1 requires legacy DSA verification; generation is disabled.
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
)

// LegacyDSAKey validates the 1024/160 public-key profile required for
// XMLDSig 1.1 DSA-SHA1 verification. It does not authorize signature use.
// Sizes are checked before primality tests and exponentiation bound work.
func LegacyDSAKey(k *dsa.PublicKey) error {
	if k == nil || k.P == nil || k.Q == nil || k.G == nil || k.Y == nil {
		return Err
	}

	if k.P.Sign() <= 0 || k.Q.Sign() <= 0 || k.P.BitLen() != 1024 || k.Q.BitLen() != 160 {
		return Err
	}

	one := big.NewInt(1)
	if k.G.Cmp(one) <= 0 || k.G.Cmp(k.P) >= 0 || k.Y.Cmp(one) <= 0 || k.Y.Cmp(k.P) >= 0 {
		return Err
	}

	if !k.P.ProbablyPrime(32) || !k.Q.ProbablyPrime(32) {
		return Err
	}

	if new(big.Int).Mod(new(big.Int).Sub(k.P, one), k.Q).Sign() != 0 ||
		new(big.Int).Exp(k.G, k.Q, k.P).Cmp(one) != 0 ||
		new(big.Int).Exp(k.Y, k.Q, k.P).Cmp(one) != 0 {
		return Err
	}

	return nil
}

// MarshalPublicKey returns SubjectPublicKeyInfo DER, including the bounded
// legacy DSA form that crypto/x509 can parse but does not marshal. Other key
// types retain crypto/x509's validation and encoding.
func MarshalPublicKey(key crypto.PublicKey) ([]byte, error) {
	k, ok := key.(*dsa.PublicKey)
	if !ok {
		return x509.MarshalPKIXPublicKey(key)
	}

	if err := LegacyDSAKey(k); err != nil {
		return nil, err
	}

	parameters, err := asn1.Marshal(struct {
		P *big.Int
		Q *big.Int
		G *big.Int
	}{P: k.P, Q: k.Q, G: k.G})
	if err != nil {
		return nil, err
	}

	value, err := asn1.Marshal(k.Y)
	if err != nil {
		return nil, err
	}
	// RFC 3279 section 2.3.2: Dss-Parms and DER INTEGER y in the BIT STRING.
	return asn1.Marshal(struct {
		Algorithm pkix.AlgorithmIdentifier
		Key       asn1.BitString
	}{
		Algorithm: pkix.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{1, 2, 840, 10040, 4, 1}, Parameters: asn1.RawValue{FullBytes: parameters}},
		Key:       asn1.BitString{Bytes: value, BitLength: len(value) * 8},
	})
}
