package x509cert

import (
	"encoding/asn1"
	"errors"

	"github.com/skarm/xmlsec/internal/der"
)

// checkedValue only exposes borrowed views of input that der.ReadLimits has
// already validated completely. It does not replace DER syntax, integer, OID,
// string, SET-order or resource validation. Avoiding reflective re-decoding here
// keeps the additional certificate-schema preflight independent of blob size.
func checkedValue(input []byte) (asn1.RawValue, []byte) {
	value := asn1.RawValue{Class: int(input[0] >> 6), Tag: int(input[0] & 31), IsCompound: input[0]&32 != 0}
	at := 1

	if value.Tag == 31 {
		value.Tag = 0

		for {
			octet := input[at]
			at++

			value.Tag = value.Tag<<7 | int(octet&127)
			if octet&128 == 0 {
				break
			}
		}
	}

	length := int(input[at])
	at++

	if length >= 128 {
		count := length & 127

		length = 0
		for range count {
			length = length<<8 | int(input[at])
			at++
		}
	}

	value.Bytes, value.FullBytes = input[at:at+length], input[:at+length]

	return value, input[at+length:]
}

func checkedSequence(value asn1.RawValue, minimum int, fields []asn1.RawValue) ([]asn1.RawValue, error) {
	if !der.Is(value, 0, asn1.TagSequence, true) {
		return nil, der.ErrInvalidDER
	}

	count := 0
	for content := value.Bytes; len(content) > 0; count++ {
		if count == len(fields) {
			return nil, errors.Join(der.ErrInvalidDER, der.ErrLimit)
		}

		fields[count], content = checkedValue(content)
	}

	if count < minimum {
		return nil, der.ErrInvalidDER
	}

	return fields[:count], nil
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
