package keys

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"

	"github.com/skarm/xmlsec/internal/der"
)

// crypto/x509 intentionally accepts some malformed legacy key representations.
// Check complete structures, including fields that x509 ignores. The key is
// owned by this parse, so RSA marshaling cannot mutate a caller's key.
func validatePrivateStructure(raw []byte, key crypto.Signer, limits Limits) error {
	v, err := readDER(raw, limits.MaxKeyBytes, limits)
	if err != nil {
		return err
	}

	f, err := der.Sequence(v, 2, 10)
	if err != nil {
		return ErrFormat
	}

	var outerCurve asn1.ObjectIdentifier

	if der.Is(f[1], 0, asn1.TagSequence, true) {
		f, err = privateKeyInfoFields(v)
		if err != nil {
			return err
		}

		if _, ok := key.(*ecdsa.PrivateKey); ok {
			algorithm, err := der.Sequence(f[1], 2, 2)
			if err != nil || der.Decode(algorithm[1], &outerCurve) != nil {
				return ErrFormat
			}
		}

		raw = f[2].Bytes

		v, err = readDER(raw, limits.MaxKeyBytes, limits)
		if err != nil {
			return ErrFormat
		}
	}

	switch key := key.(type) {
	case *rsa.PrivateKey:
		// Re-encoding checks two-prime/multi-prime versions, required components
		// and the additional CRT values ignored by crypto/x509.
		canonical := x509.MarshalPKCS1PrivateKey(key)
		defer clear(canonical)

		if !bytes.Equal(raw, canonical) {
			return ErrFormat
		}
	case *ecdsa.PrivateKey:
		return validateECStructure(v, key, outerCurve)
	}

	return nil
}

func privateKeyInfoFields(v asn1.RawValue) ([]asn1.RawValue, error) {
	f, err := der.Sequence(v, 3, 4)
	if err != nil || !der.Is(f[2], 0, asn1.TagOctetString, false) {
		return nil, ErrFormat
	}

	var version int
	if der.Decode(f[0], &version) != nil || version != 0 {
		return nil, ErrFormat
	}

	algo, err := der.Sequence(f[1], 1, 2)
	if err != nil || !der.Is(algo[0], 0, asn1.TagOID, false) {
		return nil, ErrFormat
	}

	if len(f) == 4 {
		if err := validatePrivateAttributes(f[3]); err != nil {
			return nil, err
		}
	}

	return f, nil
}

func validatePrivateAttributes(v asn1.RawValue) error {
	attrs, err := der.SetFields(v, 2, 0, 16)
	if err != nil {
		return ErrFormat
	}

	for _, attr := range attrs {
		fields, err := der.Sequence(attr, 2, 2)
		if err != nil || !der.Is(fields[0], 0, asn1.TagOID, false) {
			return ErrFormat
		}

		values, err := der.SetFields(fields[1], 0, asn1.TagSet, 16)
		if err != nil || len(values) == 0 {
			return ErrFormat
		}
	}

	return nil
}

func validateECStructure(v asn1.RawValue, key *ecdsa.PrivateKey, outerCurve asn1.ObjectIdentifier) error {
	f, err := der.Sequence(v, 2, 4)
	if err != nil || !der.Is(f[1], 0, asn1.TagOctetString, false) || len(f[1].Bytes) != (key.Params().N.BitLen()+7)/8 {
		return ErrFormat
	}

	var version int
	if der.Decode(f[0], &version) != nil || version != 1 {
		return ErrFormat
	}

	encoded, err := x509.MarshalPKIXPublicKey(key.Public())
	if err != nil {
		return ErrFormat
	}

	var spki struct {
		Algorithm pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}
	if der.Unmarshal(encoded, &spki) != nil {
		return ErrFormat
	}

	var expectedCurve asn1.ObjectIdentifier
	if der.Decode(spki.Algorithm.Parameters, &expectedCurve) != nil || len(outerCurve) > 0 && !outerCurve.Equal(expectedCurve) {
		return ErrFormat
	}

	i := 2
	if i < len(f) && der.Is(f[i], 2, 0, true) {
		value, err := der.Explicit(f[i], 0)

		var curve asn1.ObjectIdentifier
		if err != nil || der.Decode(value, &curve) != nil || !curve.Equal(expectedCurve) {
			return ErrFormat
		}

		i++
	} else if len(outerCurve) == 0 {
		return ErrFormat
	}

	if i < len(f) && der.Is(f[i], 2, 1, true) {
		value, err := der.Explicit(f[i], 1)

		var public asn1.BitString
		if err != nil || der.Decode(value, &public) != nil || public.BitLength != spki.PublicKey.BitLength || !bytes.Equal(public.Bytes, spki.PublicKey.Bytes) {
			return ErrFormat
		}

		i++
	}

	if i != len(f) {
		return ErrFormat
	}

	return nil
}
