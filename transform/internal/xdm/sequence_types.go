// Derived from lestrrat-go/helium at 7362c0a70122a757780f4d0b545a9b370dead6ab.
// Copyright (c) 2015 lestrrat. MIT License; see licenses/MIT-helium.txt at the repository root.

package xdm

import "iter"

// Sequence is an ordered collection of XDM items, backed by a slice or a lazy range.
type Sequence interface {
	Len() int
	Get(i int) Item
	Items() iter.Seq[Item]
	Materialize() []Item
}

// ItemSlice is a Sequence backed by a plain slice of Item values.
type ItemSlice []Item

func (s ItemSlice) Len() int { return len(s) }

func (s ItemSlice) Get(i int) Item { return s[i] }

func (s ItemSlice) Materialize() []Item { return s }

func (s ItemSlice) Items() iter.Seq[Item] {
	return func(yield func(Item) bool) {
		for _, item := range s {
			if !yield(item) {
				return
			}
		}
	}
}

// SequenceLen returns zero for an empty sequence.
func SequenceLen(s Sequence) int {
	if s == nil {
		return 0
	}

	return s.Len()
}

// SequenceItems iterates an empty sequence safely.
func SequenceItems(s Sequence) iter.Seq[Item] {
	if s == nil {
		return func(func(Item) bool) {}
	}

	return s.Items()
}

// Materialize returns the sequence's slice representation, preserving nil.
func Materialize(s Sequence) []Item {
	if s == nil {
		return nil
	}

	return s.Materialize()
}

// rangeSequence computes integer items on demand without allocating the full range.
type rangeSequence struct {
	start int64
	n     int
}

func (r *rangeSequence) Len() int { return r.n }

func (r *rangeSequence) Get(i int) Item {
	return AtomicValue{TypeName: TypeInteger, Value: r.start + int64(i)}
}

func (r *rangeSequence) Items() iter.Seq[Item] {
	return func(yield func(Item) bool) {
		for i := range r.n {
			if !yield(r.Get(i)) {
				return
			}
		}
	}
}

func (r *rangeSequence) Materialize() []Item {
	result := make([]Item, r.n)
	for i := range r.n {
		result[i] = r.Get(i)
	}

	return result
}
