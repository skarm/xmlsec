package transform

import (
	"fmt"
	"math/big"
	"time"

	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/transform/internal/xdm"
	"github.com/skarm/xmlsec/transform/internal/xpath"
)

// Name is the library's shared expanded XML name. Space is the namespace URI.
type Name = document.Name

// Bindings maps expanded names to typed sequences for XPath variables and XSLT
// parameters.
type Bindings map[Name]Sequence

// ValueKind describes an XDM item.
type ValueKind uint8

const (
	// InvalidValue is the zero Value.
	InvalidValue ValueKind = iota
	// AtomicValue is a typed scalar, including strings, numbers, dates and QNames.
	AtomicValue
	// NodeValue is an immutable XML node handle.
	NodeValue
	// MapValue contains atomic keys and sequence values.
	MapValue
	// ArrayValue contains ordered sequence members.
	ArrayValue
	// FunctionValue may be bound to a variable and invoked from XPath.
	FunctionValue
)

// Value retains one immutable XDM item. Its zero value denotes an absent item.
type Value struct{ item xdm.Item }

// String creates an xs:string item sharing the immutable value storage.
// Pass strings.Clone(value) to detach a caller-created substring from its source.
func String(value string) Value {
	return Value{item: xdm.AtomicValue{TypeName: xdm.TypeString, Value: value}}
}

// Boolean creates an xs:boolean item.
func Boolean(value bool) Value {
	return Value{item: xdm.AtomicValue{TypeName: xdm.TypeBoolean, Value: value}}
}

// Integer creates an xs:integer item.
func Integer(value int64) Value { return Value{item: xdm.SingleInteger(value).Get(0)} }

// BigInteger copies an arbitrary-precision integer. Nil creates an absent item.
func BigInteger(value *big.Int) Value {
	if value == nil {
		return Value{}
	}

	return Value{item: xdm.SingleIntegerBig(new(big.Int).Set(value)).Get(0)}
}

// Decimal creates an exact xs:decimal from a decimal lexical form.
func Decimal(value string) (Value, error) {
	a, err := xpath.CastAtomic(xdm.AtomicValue{TypeName: xdm.TypeString, Value: value}, xdm.TypeDecimal)
	if err != nil {
		return Value{}, wrap("decimal", err)
	}

	return Value{item: a}, nil
}

// Double creates an xs:double item.
func Double(value float64) Value {
	return Value{item: xdm.AtomicValue{TypeName: xdm.TypeDouble, Value: value}}
}

// DateTime creates an xs:dateTime with an explicit timezone.
func DateTime(value time.Time) Value {
	return Value{item: xdm.AtomicValue{TypeName: xdm.TypeDateTime, Value: value}}
}

// Array creates an array with immutable sequence members.
func Array(members ...Sequence) Value {
	raw := make([]xdm.Sequence, len(members))
	for i, member := range members {
		raw[i] = member.items
	}

	return Value{item: xdm.NewArray(raw)}
}

// Map creates an XDM map, rejecting non-atomic or duplicate keys.
func Map(entries ...MapEntry) (Value, error) {
	builder := xdm.NewMapBuilder(xdm.MergeReject, len(entries))
	for _, entry := range entries {
		key, ok := entry.Key.item.(xdm.AtomicValue)
		if !ok {
			return Value{}, wrap("map", ErrInput)
		}

		if err := builder.Add(key, entry.Value.items); err != nil {
			return Value{}, wrap("map", err)
		}
	}

	return Value{item: builder.Build()}, nil
}

// Kind reports the item's kind.
func (v Value) Kind() ValueKind {
	switch v.item.(type) {
	case xdm.AtomicValue:
		return AtomicValue
	case xdm.NodeItem:
		return NodeValue
	case xdm.MapItem:
		return MapValue
	case xdm.ArrayItem:
		return ArrayValue
	case xdm.FunctionItem:
		return FunctionValue
	default:
		return InvalidValue
	}
}

// Type returns the expanded XML Schema type of an atomic value.
func (v Value) Type() Name {
	a, ok := v.item.(xdm.AtomicValue)
	if !ok {
		return Name{}
	}

	local := a.TypeName
	if name, ok := stringsCutXS(local); ok {
		return Name{Space: xpath.NSXS, Local: name}
	}

	return Name{Local: local}
}

func stringsCutXS(s string) (string, bool) {
	if len(s) > 3 && s[:3] == "xs:" {
		return s[3:], true
	}

	return s, false
}

// Text returns the canonical lexical form of an atomic item or a node's string value.
func (v Value) Text() (string, error) {
	a, err := xpath.AtomizeItem(v.item)
	if err != nil {
		return "", wrap("atomize", err)
	}

	return lexical(a)
}

func lexical(value xdm.AtomicValue) (string, error) {
	converted, err := xpath.CastAtomic(value, xdm.TypeString)
	if err != nil {
		return "", wrap("lexical value", err)
	}

	return converted.StringVal(), nil
}

// Boolean returns an xs:boolean; it never silently converts another type.
func (v Value) Boolean() (bool, error) {
	a, ok := v.item.(xdm.AtomicValue)
	if !ok || a.TypeName != xdm.TypeBoolean {
		return false, wrap("boolean", ErrInput)
	}

	return a.BooleanVal(), nil
}

// Integer returns a copy of an arbitrary-precision integer.
func (v Value) Integer() (*big.Int, error) {
	a, ok := v.item.(xdm.AtomicValue)
	if !ok || !xdm.BuiltinIsSubtypeOf(a.TypeName, xdm.TypeInteger) {
		return nil, wrap("integer", ErrInput)
	}

	return new(big.Int).Set(a.BigInt()), nil
}

// Decimal returns a copy of an exact decimal (or integer).
func (v Value) Decimal() (*big.Rat, error) {
	a, ok := v.item.(xdm.AtomicValue)
	if !ok || !xdm.BuiltinIsSubtypeOf(a.TypeName, xdm.TypeDecimal) {
		return nil, wrap("decimal", ErrInput)
	}

	return new(big.Rat).Set(a.BigRat()), nil
}

// Float64 returns the IEEE 754 value of a numeric item. Integer and decimal
// conversion can lose precision; use Integer or Decimal to preserve it.
func (v Value) Float64() (float64, error) {
	a, ok := v.item.(xdm.AtomicValue)
	if !ok || !a.IsNumeric() {
		return 0, wrap("number", ErrInput)
	}

	return a.ToFloat64(), nil
}

// Node returns an immutable node handle when this item is a node.
func (v Value) Node() (Node, bool) {
	n, ok := v.item.(xdm.NodeItem)
	return Node{native: n.Node}, ok
}

// Lookup retrieves a map entry using an atomic key.
func (v Value) Lookup(key Value) (Sequence, bool) {
	m, ok := v.item.(xdm.MapItem)

	a, atomic := key.item.(xdm.AtomicValue)
	if !ok || !atomic {
		return Sequence{}, false
	}

	seq, found := m.GetView(a)

	return Sequence{items: seq}, found
}

// Member retrieves an array member using a zero-based Go index.
func (v Value) Member(index int) (Sequence, error) {
	a, ok := v.item.(xdm.ArrayItem)
	if !ok || index < 0 {
		return Sequence{}, wrap("array member", ErrInput)
	}

	seq, err := a.GetView(index + 1)

	return Sequence{items: seq}, wrap("array member", err)
}

// Size reports a map's entry count or an array's member count.
func (v Value) Size() (int, error) {
	switch item := v.item.(type) {
	case xdm.MapItem:
		return item.Size(), nil
	case xdm.ArrayItem:
		return item.Size(), nil
	default:
		return 0, wrap("size", ErrInput)
	}
}

// Double returns the floating-point value of an xs:float or xs:double.
func (v Value) Double() (float64, error) {
	a, ok := v.item.(xdm.AtomicValue)
	if !ok || a.TypeName != xdm.TypeDouble && a.TypeName != xdm.TypeFloat {
		return 0, wrap("double", ErrInput)
	}

	return a.DoubleVal(), nil
}

// DateTime returns an xs:dateTime value with its recorded timezone.
func (v Value) DateTime() (time.Time, error) {
	a, ok := v.item.(xdm.AtomicValue)
	if !ok || !xdm.BuiltinIsSubtypeOf(a.TypeName, xdm.TypeDateTime) {
		return time.Time{}, wrap("dateTime", ErrInput)
	}

	return a.TimeVal(), nil
}

// Keys returns a map's atomic keys in implementation-defined order.
func (v Value) Keys() ([]Value, error) {
	m, ok := v.item.(xdm.MapItem)
	if !ok {
		return nil, wrap("map keys", ErrInput)
	}

	keys := m.Keys()

	values := make([]Value, len(keys))
	for i, key := range keys {
		values[i] = Value{item: key}
	}

	return values, nil
}

// Sequence retains an immutable XDM sequence. Its zero value is empty.
type Sequence struct{ items xdm.Sequence }

// Values constructs an owned sequence, omitting absent items.
func Values(values ...Value) Sequence {
	items := make(xdm.ItemSlice, 0, len(values))
	for _, value := range values {
		if value.item != nil {
			items = append(items, value.item)
		}
	}

	return Sequence{items: items}
}

// Len returns the number of items.
func (s Sequence) Len() int {
	if s.items == nil {
		return 0
	}

	return s.items.Len()
}

// At returns an item at a zero-based Go index.
func (s Sequence) At(index int) (Value, bool) {
	if index < 0 || index >= s.Len() {
		return Value{}, false
	}

	return Value{item: s.items.Get(index)}, true
}

// Single returns the only item or an error when cardinality is not one.
func (s Sequence) Single() (Value, error) {
	if s.Len() != 1 {
		return Value{}, wrap("single item", fmt.Errorf("%w: got %d items", ErrInput, s.Len()))
	}

	v, _ := s.At(0)

	return v, nil
}

// Text returns the lexical form of a singleton atomic item or node.
func (s Sequence) Text() (string, error) {
	v, err := s.Single()
	if err != nil {
		return "", err
	}

	return v.Text()
}

// EffectiveBoolean computes XPath's effective boolean value, preserving type errors.
func (s Sequence) EffectiveBoolean() (bool, error) {
	value, err := xpath.EBV(s.items)
	return value, wrap("effective boolean", err)
}

// MapEntry associates one atomic XDM key with an immutable sequence value.
type MapEntry struct {
	// Key is the atomic XDM key. Non-atomic values are rejected by Map.
	Key Value
	// Value is the sequence associated with Key, including an empty sequence.
	Value Sequence
}

func expandedName(q document.Name) string {
	if q.Space == "" {
		return q.Local
	}

	return xdm.ClarkName(q.Space, q.Local)
}

func ownSequence(items xdm.Sequence) Sequence { return Sequence{items: xdm.CloneSequence(items)} }
