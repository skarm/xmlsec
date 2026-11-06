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

const (
	// Count caps for optional PKCS#8 attributes and each attribute's SET OF values.
	maximumPrivateKeyAttributeValues = 16
	maximumPrivateKeyAttributes      = 16
)

// PrivateKeyInfo has three required fields and an optional attributes field.
const (
	privateKeyInfoMinimumFields = 3
	privateKeyInfoMaximumFields = 4
)

// crypto/x509 intentionally accepts some malformed legacy key representations.
// Check complete structures, including fields that x509 ignores. The key is
// owned by this parse, so RSA marshaling cannot mutate a caller's key.
func validatePrivateStructure(raw []byte, key crypto.Signer, limits Limits) error {
	// Every supported outer key schema has at least two fields; PKCS#1 with
	// OtherPrimeInfos is the largest. EC algorithm parameters carry the curve OID.
	const (
		minimumPrivateKeyStructureFields = 2
		maximumPrivateKeyStructureFields = 10
		ecAlgorithmIdentifierFields      = 2
	)

	v, err := readDER(raw, limits.MaxKeyBytes, limits)
	if err != nil {
		return err
	}

	f, err := der.Sequence(v, minimumPrivateKeyStructureFields, maximumPrivateKeyStructureFields)
	if err != nil {
		return ErrFormat
	}

	var outerCurve asn1.ObjectIdentifier

	if der.Is(f[1], asn1.ClassUniversal, asn1.TagSequence, true) {
		f, err = privateKeyInfoFields(v)
		if err != nil {
			return err
		}

		if _, ok := key.(*ecdsa.PrivateKey); ok {
			algorithm, err := der.Sequence(f[1], ecAlgorithmIdentifierFields, ecAlgorithmIdentifierFields)
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
	const privateKeyInfoVersion = 0 // original PKCS#8 PrivateKeyInfo encoded version

	f, err := der.Sequence(v, privateKeyInfoMinimumFields, privateKeyInfoMaximumFields)
	if err != nil || !der.Is(f[2], asn1.ClassUniversal, asn1.TagOctetString, false) {
		return nil, ErrFormat
	}

	var version int
	if der.Decode(f[0], &version) != nil || version != privateKeyInfoVersion {
		return nil, ErrFormat
	}

	algo, err := der.Sequence(f[1], algorithmIdentifierMinimumFields, algorithmIdentifierMaximumFields)
	if err != nil || !der.Is(algo[0], asn1.ClassUniversal, asn1.TagOID, false) {
		return nil, ErrFormat
	}

	if len(f) == privateKeyInfoMaximumFields {
		if err := validatePrivateAttributes(f[3]); err != nil {
			return nil, err
		}
	}

	return f, nil
}

func validatePrivateAttributes(v asn1.RawValue) error {
	const attributeFields = 2 // type OID and SET OF attribute values

	attrs, err := der.SetFields(v, asn1.ClassContextSpecific, 0, maximumPrivateKeyAttributes)
	if err != nil {
		return ErrFormat
	}

	for _, attr := range attrs {
		fields, err := der.Sequence(attr, attributeFields, attributeFields)
		if err != nil || !der.Is(fields[0], asn1.ClassUniversal, asn1.TagOID, false) {
			return ErrFormat
		}

		values, err := der.SetFields(fields[1], asn1.ClassUniversal, asn1.TagSet, maximumPrivateKeyAttributeValues)
		if err != nil || len(values) == 0 {
			return ErrFormat
		}
	}

	return nil
}

func validateECStructure(v asn1.RawValue, key *ecdsa.PrivateKey, outerCurve asn1.ObjectIdentifier) error {
	// ECPrivateKey has two required fields and two optional tagged fields.
	const maximumECPrivateFields = 4

	f, err := der.Sequence(v, 2, maximumECPrivateFields)
	if err != nil || !der.Is(f[1], asn1.ClassUniversal, asn1.TagOctetString, false) || len(f[1].Bytes) != (key.Params().N.BitLen()+bitsPerOctet-1)/bitsPerOctet {
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
	if i < len(f) && der.Is(f[i], asn1.ClassContextSpecific, 0, true) {
		value, err := der.Explicit(f[i], 0)

		var curve asn1.ObjectIdentifier
		if err != nil || der.Decode(value, &curve) != nil || !curve.Equal(expectedCurve) {
			return ErrFormat
		}

		i++
	} else if len(outerCurve) == 0 {
		return ErrFormat
	}

	if i < len(f) && der.Is(f[i], asn1.ClassContextSpecific, 1, true) {
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
