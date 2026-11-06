package der

import (
	"encoding/asn1"
	"errors"
	"iter"
)

// ValidatedValue borrows the first value of input, which MUST already have
// passed Read/ReadLimits and remain unchanged. It only splits validated DER;
// it performs no syntax, content, depth or node-budget validation of its own.
// Keeping this separate from Read avoids reflective decoding during schema
// checks without bypassing the complete initial validation.
func ValidatedValue(input []byte) (asn1.RawValue, []byte) {
	value := asn1.RawValue{Class: int(input[0] >> identifierClassShift), Tag: int(input[0] & highTagNumber), IsCompound: input[0]&constructedBit != 0}
	at := 1

	if value.Tag == highTagNumber {
		value.Tag = 0

		for {
			octet := input[at]
			at++
			value.Tag = value.Tag<<base128Bits | int(octet&base128PayloadMask)

			if octet&base128Continuation == 0 {
				break
			}
		}
	}

	length := int(input[at])
	at++

	if length >= longLengthFlag {
		count := length & longLengthCountMask
		length = 0

		for range count {
			length = length<<octetBits | int(input[at])
			at++
		}
	}

	value.Bytes, value.FullBytes = input[at:at+length], input[:at+length]

	return value, input[at+length:]
}

// ValidatedChildren iterates over a constructed value from Read/ReadLimits
// without retaining a child slice. The validated bytes must remain unchanged.
func ValidatedChildren(value asn1.RawValue) iter.Seq[asn1.RawValue] {
	return func(yield func(asn1.RawValue) bool) {
		for content := value.Bytes; len(content) > 0; {
			var child asn1.RawValue

			child, content = ValidatedValue(content)
			if !yield(child) {
				return
			}
		}
	}
}

// ValidatedSequence fills caller-owned field storage from a SEQUENCE that has
// already passed Read/ReadLimits. The storage length bounds its component count.
func ValidatedSequence(value asn1.RawValue, minimum int, fields []asn1.RawValue) ([]asn1.RawValue, error) {
	if !Is(value, asn1.ClassUniversal, asn1.TagSequence, true) {
		return nil, ErrInvalidDER
	}

	count := 0

	for content := value.Bytes; len(content) > 0; count++ {
		if count == len(fields) {
			return nil, errors.Join(ErrInvalidDER, ErrLimit)
		}

		fields[count], content = ValidatedValue(content)
	}

	if count < minimum {
		return nil, ErrInvalidDER
	}

	return fields[:count], nil
}
