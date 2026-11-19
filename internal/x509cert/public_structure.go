package x509cert

import (
	"crypto"
	"crypto/x509"
	"encoding/asn1"

	"github.com/skarm/xmlsec/internal/der"
)

// ParsePublicKey parses one complete DER SubjectPublicKeyInfo with the caller's
// byte budget and shared depth/value caps. It makes no trust or strength decision.
func ParsePublicKey(raw []byte, maximum int) (crypto.PublicKey, error) {
	limits := Limits{Bytes: maximum, Depth: defaultASN1Depth, Nodes: defaultASN1Nodes}

	value, err := der.ReadLimits(raw, limits.Bytes, limits.Depth, limits.Nodes)
	if err != nil {
		return nil, err
	}

	key, err := x509.ParsePKIXPublicKey(raw)
	if err != nil {
		return nil, err
	}

	if err := ValidatePublicKeyInfo(value, key, limits); err != nil {
		return nil, err
	}

	return key, nil
}

// ValidatePublicKeyInfo checks a validated DER SubjectPublicKeyInfo against its
// parsed key. It rejects fields that crypto/x509 can ignore when decoding an
// ASN.1 struct. The caller must first validate value with the DER scanner.
func ValidatePublicKeyInfo(value asn1.RawValue, key crypto.PublicKey, limits Limits) error {
	var spkiFields, algorithmFields [2]asn1.RawValue

	fields, err := checkedSequence(value, len(spkiFields), spkiFields[:])
	if err != nil {
		return der.ErrInvalidDER
	}

	algorithm, err := checkedSequence(fields[0], 1, algorithmFields[:])
	if err != nil {
		return der.ErrInvalidDER
	}

	// ReadLimits has already checked BIT STRING padding. Its first content
	// byte is the unused-bit count, which must be zero for supported keys.
	bits := fields[1]
	if !der.Is(bits, asn1.ClassUniversal, asn1.TagBitString, false) || key != nil && bits.Bytes[0] != 0 {
		return der.ErrInvalidDER
	}

	var oid asn1.ObjectIdentifier
	if err := der.Decode(algorithm[0], &oid); err != nil {
		return der.ErrInvalidDER
	}

	switch {
	case oid.Equal(asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}):
		value, err := der.ReadLimits(bits.Bytes[1:], limits.Bytes, limits.Depth, limits.Nodes)
		if err != nil {
			return err
		}

		if _, err := der.Sequence(value, 2, 2); err != nil {
			return der.ErrInvalidDER
		}
	case oid.Equal(asn1.ObjectIdentifier{1, 2, 840, 10040, 4, 1}):
		if len(algorithm) != 2 {
			return der.ErrInvalidDER
		}
		// Dss-Parms contains exactly p, q and g; subjectPublicKey contains y.
		if _, err := der.Sequence(algorithm[1], 3, 3); err != nil {
			return der.ErrInvalidDER
		}

		value, err := der.ReadLimits(bits.Bytes[1:], limits.Bytes, limits.Depth, limits.Nodes)
		if err != nil {
			return err
		}

		if !der.Is(value, asn1.ClassUniversal, asn1.TagInteger, false) {
			return der.ErrInvalidDER
		}
	}

	return nil
}

func validateCertificatePublicKey(body []asn1.RawValue, certificate *x509.Certificate, limits Limits) error {
	offset := 0
	if body[0].Class == asn1.ClassContextSpecific {
		offset++
	}

	return ValidatePublicKeyInfo(body[offset+5], certificate.PublicKey, limits)
}
