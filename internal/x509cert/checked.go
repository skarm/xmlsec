package x509cert

import (
	"encoding/asn1"

	"github.com/skarm/xmlsec/internal/der"
)

// checkedValue only exposes borrowed views of input that der.ReadLimits has
// already validated completely. It does not replace DER syntax, integer, OID,
// string, SET-order or resource validation. Avoiding reflective re-decoding here
// keeps the additional certificate-schema preflight independent of blob size.
func checkedValue(input []byte) (asn1.RawValue, []byte) {
	return der.ValidatedValue(input)
}

func checkedSequence(value asn1.RawValue, minimum int, fields []asn1.RawValue) ([]asn1.RawValue, error) {
	return der.ValidatedSequence(value, minimum, fields)
}

func checkedExplicit(value asn1.RawValue, tag int) (asn1.RawValue, error) {
	if !der.Is(value, 2, tag, true) || len(value.Bytes) == 0 {
		return asn1.RawValue{}, der.ErrInvalidDER
	}

	child, rest := checkedValue(value.Bytes)
	if len(rest) != 0 {
		return asn1.RawValue{}, der.ErrInvalidDER
	}

	return child, nil
}
