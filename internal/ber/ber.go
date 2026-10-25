// Package ber scans bounded BER without interpreting or repairing opaque fields.
// Schema-specific callers select which wrappers can be normalized to DER.
package ber

import (
	"bytes"
	"context"
	"errors"
)

// ErrSyntax reports malformed BER, including misplaced or missing EOC.
var ErrSyntax = errors.New("invalid BER")

// ErrLimit reports an exceeded byte, depth, node or flattened-content budget.
var ErrLimit = errors.New("BER limit exceeded")

// Limits bounds a complete structural scan, with the root at depth one.
type Limits struct{ MaxBytes, MaxDepth, MaxNodes int }

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

// Value preserves the original tag, complete encoding, body and child order.
type Value struct {
	Tag        byte
	Full, Body []byte
	Children   []Value
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
	if indefinite && v.Tag&0x20 == 0 {
		return v, 0, ErrSyntax
	}

	end := header + length
	if indefinite {
		end = len(b)
	}

	at := header
	if v.Tag&0x20 == 0 {
		at = end
	}

	for at < end {
		if indefinite && end-at >= 2 && b[at] == 0 && b[at+1] == 0 {
			v.Body, v.Full = b[header:at], b[:at+2]
			return v, at + 2, nil
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

// BER permits nonminimal length octets; only the selected wrapper headers are
// normalized. Opaque fields reach the strict DER parser with their original bytes.
func berHeader(b []byte) (header, length int, indefinite bool, err error) {
	if len(b) < 2 || b[0] == 0 {
		return 0, 0, false, ErrSyntax
	}

	at := 1

	if b[0]&31 == 31 {
		tag := 0

		for {
			if at >= len(b) || at > 5 || at == 1 && b[at]&127 == 0 {
				return 0, 0, false, ErrSyntax
			}

			if tag > (0x7fffffff-int(b[at]&127))/128 {
				return 0, 0, false, ErrSyntax
			}

			tag = tag*128 + int(b[at]&127)

			at++
			if b[at-1]&128 == 0 {
				break
			}
		}

		if tag < 31 {
			return 0, 0, false, ErrSyntax
		}
	}

	if at >= len(b) {
		return 0, 0, false, ErrSyntax
	}

	length = int(b[at])

	at++
	if length == 128 {
		return at, 0, true, nil
	}

	if length > 128 {
		count := length & 127
		if count > 8 || count > len(b)-at {
			return 0, 0, false, ErrSyntax
		}

		length = 0
		for _, c := range b[at : at+count] {
			if length > len(b)/256 {
				return 0, 0, false, ErrSyntax
			}

			length = length*256 + int(c)
		}

		at += count
	}

	if length > len(b)-at {
		return 0, 0, false, ErrSyntax
	}

	return at, length, false, nil
}

// AppendOctets flattens only primitive or recursively constructed OCTET STRINGs.
// dst may contain a partial result on error; maximum bounds its total length.
func AppendOctets(ctx context.Context, value Value, dst *bytes.Buffer, maximum int) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	switch value.Tag {
	case 4:
		if len(value.Body) > maximum-dst.Len() {
			return ErrLimit
		}

		dst.Write(value.Body)
	case 0x24:
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
