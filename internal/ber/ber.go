// Package ber scans bounded BER without interpreting or repairing opaque fields.
// Schema-specific callers select which wrappers can be normalized to DER.
package ber

import (
	"bytes"
	"context"
	"encoding/asn1"
	"errors"
	"math"
)

// BER identifier and length octets. These are wire-format values; callers
// supply independent work and content budgets through Limits.
const (
	constructedBit      = 0x20
	highTagNumber       = 0x1f
	base128Continuation = 0x80
	base128PayloadMask  = 0x7f
	base128Radix        = 128
	maximumTagOctets    = 5
	indefiniteLength    = 0x80
	longLengthCountMask = 0x7f
	maximumLengthOctets = 8
	lengthOctetRadix    = 256
	minimumHeaderBytes  = 2
	endOfContentsBytes  = 2
	constructedOctetTag = constructedBit | asn1.TagOctetString
)

// ErrSyntax reports malformed BER, including misplaced or missing EOC.
var ErrSyntax = errors.New("invalid BER")

// ErrLimit reports an exceeded byte, depth, node or flattened-content budget.
var ErrLimit = errors.New("BER limit exceeded")

// Limits bounds a complete structural scan, with the root at depth one.
type Limits struct {
	// MaxBytes bounds the complete input encoding in bytes and must be positive.
	MaxBytes int
	// MaxDepth bounds ASN.1 nesting with the root at depth one.
	MaxDepth int
	// MaxNodes bounds the total number of scanned ASN.1 values.
	MaxNodes int
}

// Value preserves the original tag, complete encoding, body and child order.
type Value struct {
	// Tag retains the original single-octet ASN.1 tag.
	Tag byte
	// Full borrows the complete original encoding, including an indefinite value's
	// end marker.
	Full []byte
	// Body borrows the value's content octets, excluding its outer end marker.
	Body []byte
	// Children preserves the scanned children of a constructed value in source
	// order.
	Children []Value
}

// Read scans exactly one value. Returned slices borrow input; no content is
// authenticated or canonically re-encoded. Input must remain unchanged in use.
func Read(ctx context.Context, input []byte, limits Limits) (Value, error) {
	if ctx == nil || len(input) == 0 || limits.MaxBytes < 1 || limits.MaxDepth < 1 || limits.MaxNodes < 1 {
		return Value{}, ErrSyntax
	}

	if len(input) > limits.MaxBytes {
		return Value{}, ErrLimit
	}

	scanner := berScanner{ctx: ctx, remaining: limits.MaxNodes, maxDepth: limits.MaxDepth}

	value, consumed, err := scanner.value(input, 1)
	if err != nil {
		return Value{}, err
	}

	if consumed != len(input) {
		return Value{}, ErrSyntax
	}

	return value, nil
}

type berScanner struct {
	ctx       context.Context
	remaining int
	maxDepth  int
}

func (s *berScanner) value(b []byte, depth int) (Value, int, error) {
	if err := s.ctx.Err(); err != nil {
		return Value{}, 0, err
	}

	if depth > s.maxDepth || s.remaining == 0 {
		return Value{}, 0, ErrLimit
	}

	s.remaining--

	header, length, indefinite, err := berHeader(b)
	if err != nil {
		return Value{}, 0, err
	}

	v := Value{Tag: b[0]}
	if indefinite && v.Tag&constructedBit == 0 {
		return v, 0, ErrSyntax
	}

	end := header + length
	if indefinite {
		end = len(b)
	}

	at := header
	if v.Tag&constructedBit == 0 {
		at = end
	}

	for at < end {
		if indefinite && end-at >= endOfContentsBytes && b[at] == 0 && b[at+1] == 0 {
			v.Body, v.Full = b[header:at], b[:at+endOfContentsBytes]
			return v, at + endOfContentsBytes, nil
		}

		child, used, err := s.value(b[at:end], depth+1)
		if err != nil {
			return v, 0, err
		}

		v.Children = append(v.Children, child)
		at += used
	}

	if indefinite {
		return v, 0, ErrSyntax
	}

	v.Body, v.Full = b[header:end], b[:end]

	return v, end, nil
}

// AppendOctets flattens only primitive or recursively constructed OCTET STRINGs.
// dst may contain a partial result on error; maximum bounds its total length.
func AppendOctets(ctx context.Context, value Value, dst *bytes.Buffer, maximum int) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	switch value.Tag {
	case asn1.TagOctetString:
		if len(value.Body) > maximum-dst.Len() {
			return ErrLimit
		}

		dst.Write(value.Body)
	case constructedOctetTag:
		for _, child := range value.Children {
			if err := AppendOctets(ctx, child, dst, maximum); err != nil {
				return err
			}
		}
	default:
		return ErrSyntax
	}

	return nil
}

// OctetLength validates primitive or constructed OCTET STRINGs and measures
// their flattened length without allocating content storage.
func OctetLength(ctx context.Context, value Value, maximum int) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}

	switch value.Tag {
	case asn1.TagOctetString:
		if len(value.Body) > maximum {
			return 0, ErrLimit
		}

		return len(value.Body), nil
	case constructedOctetTag:
		total := 0
		for _, child := range value.Children {
			size, err := OctetLength(ctx, child, maximum-total)
			if err != nil {
				return 0, err
			}

			total += size
		}

		return total, nil
	default:
		return 0, ErrSyntax
	}
}

// BER permits nonminimal length octets; only the selected wrapper headers are
// normalized. Opaque fields reach the strict DER parser with their original bytes.
func berHeader(b []byte) (header, length int, indefinite bool, err error) {
	// Universal tag zero is reserved for the primitive 00 00 terminator,
	// consumed only by an indefinite parent's loop. It has no constructed form.
	if len(b) < minimumHeaderBytes || b[0] == 0 || b[0] == constructedBit {
		return 0, 0, false, ErrSyntax
	}

	at := 1

	if b[0]&highTagNumber == highTagNumber {
		tag := 0

		for {
			if at >= len(b) || at > maximumTagOctets || at == 1 && b[at]&base128PayloadMask == 0 {
				return 0, 0, false, ErrSyntax
			}

			if tag > (math.MaxInt32-int(b[at]&base128PayloadMask))/base128Radix {
				return 0, 0, false, ErrSyntax
			}

			tag = tag*base128Radix + int(b[at]&base128PayloadMask)

			at++
			if b[at-1]&base128Continuation == 0 {
				break
			}
		}

		if tag < highTagNumber {
			return 0, 0, false, ErrSyntax
		}
	}

	if at >= len(b) {
		return 0, 0, false, ErrSyntax
	}

	length = int(b[at])

	at++
	if length == indefiniteLength {
		return at, 0, true, nil
	}

	if length > indefiniteLength {
		count := length & longLengthCountMask
		if count > maximumLengthOctets || count > len(b)-at {
			return 0, 0, false, ErrSyntax
		}

		length = 0
		for _, c := range b[at : at+count] {
			if length > len(b)/lengthOctetRadix {
				return 0, 0, false, ErrSyntax
			}

			length = length*lengthOctetRadix + int(c)
		}

		at += count
	}

	if length > len(b)-at {
		return 0, 0, false, ErrSyntax
	}

	return at, length, false, nil
}
