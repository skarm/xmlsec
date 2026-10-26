// Derived from lestrrat-go/helium at 7362c0a70122a757780f4d0b545a9b370dead6ab.
// Copyright (c) 2015 lestrrat. MIT License; see licenses/MIT-helium.txt at the repository root.

package xdm

import (
	"math"
	"math/big"
)

// NewRangeSequence creates a lazy integer range sequence from start to end (inclusive).
// If start > end, returns nil (empty sequence per XPath spec).
//
// A Sequence's length is an int. A range with more items than math.MaxInt
// (possible where int is 32 bits, or for a range spanning nearly all of int64)
// reports math.MaxInt as its length, so every length limit still rejects it.
func NewRangeSequence(start, end int64) Sequence {
	if start > end {
		return nil
	}

	return &rangeSequence{start: start, n: rangeLen(start, end)}
}

// SingleNode creates a Sequence containing a single NodeItem.
func SingleNode(n Node) Sequence {
	return ItemSlice{NodeItem{Node: n}}
}

// SingleAtomic creates a Sequence containing a single AtomicValue.
func SingleAtomic(v AtomicValue) Sequence {
	return ItemSlice{v}
}

// SingleBoolean creates a caller-owned sequence containing one xs:boolean.
func SingleBoolean(b bool) Sequence {
	return SingleAtomic(AtomicValue{TypeName: TypeBoolean, Value: b})
}

// SingleInteger creates a Sequence containing a single xs:integer from int64.
func SingleInteger(n int64) Sequence {
	return ItemSlice{AtomicValue{TypeName: TypeInteger, Value: n}}
}

// SingleIntegerBig creates a Sequence containing a single xs:integer from *big.Int.
func SingleIntegerBig(n *big.Int) Sequence {
	return ItemSlice{AtomicValue{TypeName: TypeInteger, Value: n}}
}

// SingleDecimal creates a Sequence containing a single xs:decimal from *big.Rat.
func SingleDecimal(r *big.Rat) Sequence {
	return ItemSlice{AtomicValue{TypeName: TypeDecimal, Value: r}}
}

// SingleDouble creates a Sequence containing a single xs:double.
func SingleDouble(f float64) Sequence {
	return ItemSlice{AtomicValue{TypeName: TypeDouble, Value: NewDouble(f)}}
}

// SingleFloat creates a Sequence containing a single xs:float.
func SingleFloat(f float64) Sequence {
	return ItemSlice{AtomicValue{TypeName: TypeFloat, Value: NewFloat(f)}}
}

// SingleString creates a Sequence containing a single xs:string.
func SingleString(s string) Sequence {
	return ItemSlice{AtomicValue{TypeName: TypeString, Value: s}}
}

// EmptySequence returns an empty Sequence.
func EmptySequence() Sequence {
	return nil
}

// NodesFrom extracts all Node values from a sequence.
// Returns (nodes, true) if all items are NodeItems, or (nil, false) if any are not.
func NodesFrom(seq Sequence) ([]Node, bool) {
	if SequenceLen(seq) == 0 {
		return nil, true
	}

	nodes, ok := AppendSequenceNodes(make([]Node, 0, seq.Len()), seq)
	if !ok {
		return nil, false
	}

	return nodes, true
}

// AppendSequenceNodes appends the node of every item of seq to dst. It
// reports false, with dst holding the nodes before it, when an item is not a
// NodeItem.
func AppendSequenceNodes(dst []Node, seq Sequence) ([]Node, bool) {
	if SequenceLen(seq) == 0 {
		return dst, true
	}
	// Range over a slice directly: the Items iterator allocates a closure.
	if items, ok := seq.(ItemSlice); ok {
		for _, item := range items {
			ni, ok := item.(NodeItem)
			if !ok || ni.ResultTreeFragment {
				return dst, false
			}

			dst = append(dst, ni.Node)
		}

		return dst, true
	}

	for item := range SequenceItems(seq) {
		ni, ok := item.(NodeItem)
		if !ok || ni.ResultTreeFragment {
			return dst, false
		}

		dst = append(dst, ni.Node)
	}

	return dst, true
}

// rangeLen returns the number of integers in start..end (start <= end),
// saturated at math.MaxInt. The span is computed in uint64, where end-start
// cannot overflow.
func rangeLen(start, end int64) int {
	span := uint64(end) - uint64(start) // #nosec G115 -- Unsigned subtraction intentionally preserves the full signed-range span before saturation.
	if span >= math.MaxInt {
		return math.MaxInt
	}

	return int(span) + 1
}
