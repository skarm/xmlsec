// Derived from lestrrat-go/helium at 7362c0a70122a757780f4d0b545a9b370dead6ab.
// Copyright (c) 2015 lestrrat. MIT License; see licenses/MIT-helium.txt at the repository root.

package xdm

import (
	"context"
	"encoding/hex"
	"fmt"
	"math"
	"math/big"
	"strconv"
	"strings"
	"time"

	"github.com/skarm/xmlsec/internal/lexicon"
)

// Type family constants used for aggregate, comparison, and collation grouping.
const (
	FamilyNumeric    = "numeric"
	FamilyDurationYM = "duration:YM"
	FamilyDurationDT = "duration:DT"
)

// Atomic type name constants matching XSD types.
const (
	TypeString            = "xs:string"
	TypeInteger           = "xs:integer"
	TypeDecimal           = "xs:decimal"
	TypeDouble            = "xs:double"
	TypeFloat             = "xs:float"
	TypeBoolean           = "xs:boolean"
	TypeDate              = "xs:date"
	TypeDateTime          = "xs:dateTime"
	TypeTime              = "xs:time"
	TypeDuration          = "xs:duration"
	TypeDayTimeDuration   = "xs:dayTimeDuration"
	TypeYearMonthDuration = "xs:yearMonthDuration"
	TypeAnyURI            = "xs:anyURI"
	TypeQName             = "xs:QName"
	TypeBase64Binary      = "xs:base64Binary"
	TypeHexBinary         = "xs:hexBinary"
	TypeUntypedAtomic     = "xs:untypedAtomic"
	TypeAnyAtomicType     = "xs:anyAtomicType"

	// TypeLong and the following are derived integer types.
	TypeLong               = "xs:long"
	TypeInt                = "xs:int"
	TypeShort              = "xs:short"
	TypeByte               = "xs:byte"
	TypeUnsignedLong       = "xs:unsignedLong"
	TypeUnsignedInt        = "xs:unsignedInt"
	TypeUnsignedShort      = "xs:unsignedShort"
	TypeUnsignedByte       = "xs:unsignedByte"
	TypeNonNegativeInteger = "xs:nonNegativeInteger"
	TypeNonPositiveInteger = "xs:nonPositiveInteger"
	TypePositiveInteger    = "xs:positiveInteger"
	TypeNegativeInteger    = "xs:negativeInteger"

	// TypeNormalizedString and the following are derived string types.
	TypeNormalizedString = "xs:normalizedString"
	TypeToken            = "xs:token"
	TypeLanguage         = "xs:language"
	TypeName             = "xs:Name"
	TypeNCName           = "xs:NCName"
	TypeNMTOKEN          = "xs:NMTOKEN"  // #nosec G101 -- XML Schema type name, not a credential.
	TypeNMTOKENS         = "xs:NMTOKENS" // #nosec G101 -- XML Schema type name, not a credential.
	TypeENTITY           = "xs:ENTITY"
	TypeID               = "xs:ID"
	TypeIDREF            = "xs:IDREF"
	TypeIDREFS           = "xs:IDREFS"
	TypeENTITIES         = "xs:ENTITIES"

	// TypeGDay and the following are Gregorian date part types.
	TypeGDay       = "xs:gDay"
	TypeGMonth     = "xs:gMonth"
	TypeGMonthDay  = "xs:gMonthDay"
	TypeGYear      = "xs:gYear"
	TypeGYearMonth = "xs:gYearMonth"

	// TypeDateTimeStamp and the following are other derived types.
	TypeDateTimeStamp = "xs:dateTimeStamp"
	TypeError         = "xs:error"
	TypeNumeric       = "xs:numeric"

	// TypeAnyType and the following are non-atomic / structural types.
	TypeAnyType       = "xs:anyType"
	TypeAnySimpleType = "xs:anySimpleType"
	TypeUntyped       = "xs:untyped"
	TypeNOTATION      = "xs:NOTATION"
)

// noTimezoneName is reserved for XSD values without an explicit timezone.
// Zone identity is carried in time.Time; each value owns its location.
const noTimezoneName = "xmlsec:no-timezone"

// Item represents an atomic value, node, function, map or array in the shared XDM
// value model. The selected language profile controls which item kinds expressions can
// use.
type Item interface {
	// itemTag restricts XDM items to implementations declared in this package.
	itemTag()
}

// CloneItem copies mutable atomic payloads and item metadata while retaining XDM
// identity. It clones pointer-backed numeric values, byte slices, duration rationals
// and mutable node/function metadata slices.
//
// Immutable maps and arrays share their entries; node storage and function closures
// remain shared. This avoids recursively copying nested immutable structures. Callers
// must keep shared nodes, metadata records and captured closure state valid for
// readers.
func CloneItem(item Item) Item {
	switch v := item.(type) {
	case AtomicValue:
		// Only re-box when the payload actually carries shared mutable state.
		// Returning the original boxed Item for immutable payloads (int64,
		// string, bool, float64, time.Time, QNameValue, by-value Duration
		// without rationals, …) avoids an interface re-allocation per item on
		// the hot clone path.
		if cloned, copied := deepCloneAtomicValue(v); copied {
			return cloned
		}

		return item
	case NodeItem:
		if v.UnionMemberTypes == nil && v.ListItemLeaves == nil {
			return item
		}

		v.UnionMemberTypes = append([]string(nil), v.UnionMemberTypes...)
		v.ListItemLeaves = append([]*NodeItemUnionMember(nil), v.ListItemLeaves...)
		// ActiveUnionMember / ListItemLeaves entries point at immutable
		// NodeItemUnionMember values (never mutated after construction), so the
		// pointers are safely shared across clones.
		return v
	case FunctionItem:
		if v.ParamTypes == nil && v.ReturnType == nil {
			return item
		}

		v.ParamTypes = CloneSequenceTypes(v.ParamTypes)
		v.ReturnType = CloneSequenceTypePtr(v.ReturnType)

		return v
	default:
		return item
	}
}

// NodeItem pairs a shared node identity with optional internal atomization metadata.
// Metadata can describe typed values when supplied by a host; it does not enable
// schema-aware processing in the public profiles.
type NodeItem struct {
	// Node is the underlying node whose identity is retained by this item.
	Node Node
	// ActiveUnionMember retains the resolved atomic or list leaf for a union-typed node.
	// Nil means no active member was supplied or resolved. Atomization uses this metadata
	// without repeating member selection.
	ActiveUnionMember *NodeItemUnionMember
	TypeAnnotation    string   // optional xs:... type annotation (schema-aware)
	AtomizedType      string   // optional built-in base type used for typed atomization
	ListItemType      string   // non-empty when the type is a list; the item type name
	ListItemAtomized  string   // built-in base of the list item type (e.g. xs:QName for a QName-derived item)
	UnionMemberTypes  []string // member type names for union types (for atomization)
	// ListItemLeaves aligns resolved union-member leaves with whitespace-separated list
	// tokens. A nil entry falls back to static list-item metadata. Entries are immutable
	// after construction and can be shared by clones.
	ListItemLeaves []*NodeItemUnionMember
	// ResultTreeFragment marks an XSLT 1.0 temporary tree (not a node-set).
	ResultTreeFragment bool
	// QNameNoDefaultNS suppresses default-namespace resolution when atomizing an
	// unprefixed QName or NOTATION value. It is an internal host option and is false by
	// default.
	QNameNoDefaultNS bool
}

func (NodeItem) itemTag() {}

// NodeItemUnionMember retains the resolved atomic or list-member metadata needed for
// typed atomization. Records are immutable after construction and can be shared by
// NodeItem clones.
type NodeItemUnionMember struct {
	TypeName     string // member type annotation name
	Atomized     string // built-in base of an atomic member (for typing)
	ListItem     string // non-empty if the member is a list: its item type name
	ListItemAtom string // built-in base of the list item (e.g. xs:QName)
	// ListItemLeaves aligns active union leaves with tokens when this member is a list
	// whose item type is a union. Nil entries have no resolved leaf and use the atomizer's
	// fallback path.
	ListItemLeaves []*NodeItemUnionMember
}

// AtomicValue pairs a type name with its Go representation and optional built-in base
// type. Callers must supply a representation compatible with the selected type and
// keep shared payloads immutable.
type AtomicValue struct {
	TypeName string // e.g. "xs:string", "xs:integer"
	Value    any    // string, bool, integer, rational, FloatValue, bytes, time, QName or Duration payload
	BaseType string // built-in base type when TypeName is a user-defined schema type
}

// CloneMapKey copies mutable atomic key payloads before map insertion so later caller
// mutations cannot change the stored key. Immutable payloads are shared. Copying cost
// depends on the size of pointer-backed numeric or byte values.
func CloneMapKey(key AtomicValue) AtomicValue {
	if cloned, copied := deepCloneAtomicValue(key); copied {
		return cloned
	}

	return key
}

// StringVal returns the backing string value. Panics if not a string-backed type.
func (a AtomicValue) StringVal() string {
	return a.Value.(string) //nolint:forcetypeassert // The type-specific accessor requires the matching XDM value representation.
}

// IntegerVal returns an int64-backed value or delegates to big.Int.Int64. It does not
// check overflow; use Int64Val when range validation is required. Other backing types
// panic.
func (a AtomicValue) IntegerVal() int64 {
	if v, ok := a.Value.(int64); ok {
		return v
	}

	return a.Value.(*big.Int).Int64() //nolint:forcetypeassert // The type-specific accessor requires the matching XDM value representation.
}

// Int64Val returns the int64 value if it fits, or (0, false) otherwise.
func (a AtomicValue) Int64Val() (int64, bool) {
	switch v := a.Value.(type) {
	case int64:
		return v, true
	case *big.Int:
		if v.IsInt64() {
			return v.Int64(), true
		}

		return 0, false
	}

	return 0, false
}

// BigInt returns a borrowed big.Int, promotes an int64 or parses a decimal string.
// Unsupported or invalid input returns a new zero integer. Callers must not mutate
// borrowed value storage.
func (a AtomicValue) BigInt() *big.Int {
	switch v := a.Value.(type) {
	case *big.Int:
		return v
	case int64:
		return big.NewInt(v)
	case string:
		n, ok := new(big.Int).SetString(v, 10)
		if ok {
			return n
		}
	}

	return new(big.Int)
}

// BigRat returns a borrowed big.Rat or parses a rational string. Unsupported or
// invalid input returns a new zero rational. Callers must not mutate borrowed value
// storage.
func (a AtomicValue) BigRat() *big.Rat {
	if r, ok := a.Value.(*big.Rat); ok {
		return r
	}

	if s, ok := a.Value.(string); ok {
		r, ok := new(big.Rat).SetString(s)
		if ok {
			return r
		}
	}
	// Last resort: return zero
	return new(big.Rat)
}

// DoubleVal returns the backing float64 value. The backing value is normally a
// *FloatValue, but a schema-derived or directly constructed double/float can
// carry a plain float64/float32; route through ToFloat64 so no caller panics.
func (a AtomicValue) DoubleVal() float64 {
	return a.ToFloat64()
}

// FloatVal returns the backing value as a *FloatValue. A schema-derived or
// directly constructed double/float can carry a plain float64/float32; wrap it
// at the precision implied by the type so callers never panic on a non-pointer
// backing value.
func (a AtomicValue) FloatVal() *FloatValue {
	// A schema-derived xs:float can be backed by a *FloatValue at double
	// precision (e.g. NewDouble(16777217)). Honor the effective numeric type so
	// such values are narrowed to single precision, and never returned as-is.
	singlePrec := a.effectiveNumericType() == TypeFloat
	if fv, ok := a.Value.(*FloatValue); ok {
		if singlePrec {
			return NewFloat(fv.Float64())
		}

		return fv
	}

	f := a.ToFloat64()
	if singlePrec {
		return NewFloat(f)
	}

	return NewDouble(f)
}

// BooleanVal returns the backing bool value.
func (a AtomicValue) BooleanVal() bool {
	return a.Value.(bool) //nolint:forcetypeassert // The type-specific accessor requires the matching XDM value representation.
}

// TimeVal returns the backing time.Time value.
func (a AtomicValue) TimeVal() time.Time {
	return a.Value.(time.Time) //nolint:forcetypeassert // The type-specific accessor requires the matching XDM value representation.
}

// DurationVal returns the backing Duration value.
func (a AtomicValue) DurationVal() Duration {
	return a.Value.(Duration) //nolint:forcetypeassert // The type-specific accessor requires the matching XDM value representation.
}

// BytesVal returns the borrowed byte-slice payload and panics for other backing types.
// Callers must not mutate shared XDM value storage.
func (a AtomicValue) BytesVal() []byte {
	return a.Value.([]byte) //nolint:forcetypeassert // The type-specific accessor requires the matching XDM value representation.
}

// QNameVal returns the backing QNameValue.
func (a AtomicValue) QNameVal() QNameValue {
	return a.Value.(QNameValue) //nolint:forcetypeassert // The type-specific accessor requires the matching XDM value representation.
}

// IsNaN returns true if the atomic value is NaN (xs:double or xs:float).
func (a AtomicValue) IsNaN() bool {
	if a.TypeName != TypeDouble && a.TypeName != TypeFloat {
		return false
	}

	fv, ok := a.Value.(*FloatValue)

	return ok && fv.IsNaN()
}

// IsNumeric returns true if the type is xs:integer (or derived), xs:decimal, xs:double, or xs:float.
// Also returns true for user-defined types whose underlying value is numeric.
func (a AtomicValue) IsNumeric() bool {
	if IsIntegerDerived(a.TypeName) {
		return true
	}

	switch a.TypeName {
	case TypeDecimal, TypeDouble, TypeFloat:
		return true
	}
	// User-defined schema types: check the underlying Go value.
	switch a.Value.(type) {
	case int64, *big.Int, *big.Rat, float64, float32, *FloatValue:
		return true
	}

	return false
}

// ToFloat64 converts any numeric atomic value to float64.
func (a AtomicValue) ToFloat64() float64 {
	et := a.effectiveNumericType()
	if IsIntegerDerived(et) {
		switch v := a.Value.(type) {
		case int64:
			return float64(v)
		case *big.Int:
			f, _ := new(big.Float).SetInt(v).Float64()
			return f
		}

		return 0
	}

	switch et {
	case TypeDouble, TypeFloat:
		// xs:double/xs:float atomics are normally backed by *FloatValue, but a
		// schema-derived double/float (or a value constructed directly) can carry
		// a plain float64/float32 backing value. Accept all forms so callers on
		// the map-key path never panic.
		var f float64

		switch v := a.Value.(type) {
		case *FloatValue:
			f = v.Float64()
		case float64:
			f = v
		case float32:
			f = float64(v)
		default:
			return 0
		}

		if et == TypeFloat {
			// An effective xs:float (including a schema-derived float backed by a
			// double-precision *FloatValue or a plain float64) must be narrowed to
			// single precision so ToFloat64/DoubleVal stay consistent with FloatVal.
			return float64(float32(f))
		}

		return f
	case TypeDecimal:
		r, ok := a.Value.(*big.Rat)
		if !ok {
			return 0
		}

		f, _ := r.Float64()

		return f
	}

	return 0
}

// String returns a human-readable representation.
func (a AtomicValue) String() string {
	return fmt.Sprintf("%s(%v)", a.TypeName, a.Value)
}

func (AtomicValue) itemTag() {}

// effectiveNumericType resolves the built-in numeric type that governs a value's
// conversion: the TypeName itself when it is a recognized numeric built-in, else
// the BaseType of a schema-derived value (custom TypeName whose BaseType names a
// built-in numeric ancestor). This mirrors PromoteSchemaType's BaseType fallback
// so schema-derived float/double/decimal/integer values convert correctly.
func (a AtomicValue) effectiveNumericType() string {
	if IsIntegerDerived(a.TypeName) {
		return a.TypeName
	}

	switch a.TypeName {
	case TypeDecimal, TypeDouble, TypeFloat:
		return a.TypeName
	}

	if a.BaseType != "" && IsKnownXSDType(a.BaseType) {
		return a.BaseType
	}

	return a.TypeName
}

// QNameValue holds the components of an xs:QName value.
type QNameValue struct {
	// Prefix retains the lexical prefix for diagnostics and serialization.
	Prefix string
	// Local is the local name of the QName value.
	Local string
	// URI is the expanded namespace URI, or empty for no namespace.
	URI string
}

// Duration is the value of an xs:duration, xs:yearMonthDuration, or
// xs:dayTimeDuration. Months is an int: where int is 32 bits, a month total
// above 2^31-1 is a duration overflow (FODT0002) wherever one is computed.
type Duration struct {
	Months  int      // total months (years*12 + months)
	Seconds float64  // total seconds (days*86400 + hours*3600 + minutes*60 + seconds)
	FracSec *big.Rat // exact fractional seconds component (the part after decimal in 'S'), nil if integer
	SecRat  *big.Rat // exact total dayTime seconds magnitude (>=0); authoritative when non-nil, sign carried by Negative
	// Negative carries the sign of the duration's component magnitudes.
	Negative bool
}

// clone returns a deep copy of the Duration, duplicating its *big.Rat fields so
// a mutation of the original cannot reach the copy. Used by value-semantics deep
// cloning of atomic values stored in maps/arrays.
func (d Duration) clone() Duration {
	if d.FracSec != nil {
		d.FracSec = new(big.Rat).Set(d.FracSec)
	}

	if d.SecRat != nil {
		d.SecRat = new(big.Rat).Set(d.SecRat)
	}

	return d
}

// FunctionItem represents a callable function value (inline, named ref, partial application).
type FunctionItem struct {
	// Arity is the fixed number of arguments accepted by this function item.
	Arity     int
	Name      string // empty for anonymous
	Namespace string // namespace URI (empty for anonymous or default)
	// Invoke executes the captured function with the caller's context and argument
	// sequences.
	Invoke          func(ctx context.Context, args []Sequence) (Sequence, error)
	ParamTypes      []SequenceType // parameter type annotations (nil if untyped)
	RepeatParamType bool           // the sole parameter annotation applies to every argument
	ReturnType      *SequenceType  // return type annotation (nil if untyped)
}

func (FunctionItem) itemTag() {}

// FunctionParameterType reads fixed or compact repeated parameter metadata.
func FunctionParameterType(params []SequenceType, repeated bool, index int) (SequenceType, bool) {
	if index < 0 {
		return SequenceType{}, false
	}

	if repeated && len(params) == 1 {
		return params[0], true
	}

	if index < len(params) {
		return params[index], true
	}

	return SequenceType{}, false
}

// MapItem is an immutable key-value map. Put returns a new map (copy-on-write).
type MapItem struct {
	// entries retains map iteration order and borrowed immutable entry values.
	entries []EntryView
	index   map[MapKey]int // index into entries
}

// SingleEntryMap creates a MapItem with exactly one entry without cloning the value.
// Used by map:entry where the value is already owned by the caller.
func SingleEntryMap(key AtomicValue, value Sequence) MapItem {
	return MapItem{
		entries: []EntryView{{key: CloneMapKey(key), Value: value}},
	}
}

// NewMap creates a MapItem from a slice of MapEntry.
func NewMap(entries []MapEntry) MapItem {
	// Fast path for single-entry maps (e.g., map:entry results):
	// skip the index map allocation entirely.
	if len(entries) == 1 {
		return MapItem{
			entries: []EntryView{{key: CloneMapKey(entries[0].Key), Value: CloneSequence(entries[0].Value)}},
		}
	}

	m := MapItem{
		entries: make([]EntryView, len(entries)),
		index:   make(map[MapKey]int, len(entries)),
	}
	for i, e := range entries {
		m.entries[i] = EntryView{key: CloneMapKey(e.Key), Value: CloneSequence(e.Value)}
		m.index[NormalizeMapKey(e.Key)] = i
	}

	return m
}

// MergeMaps merges multiple maps according to the given policy.
func MergeMaps(maps []MapItem, policy MergePolicy) (MapItem, error) {
	var allEntries []EntryView

	seen := map[MapKey]int{}

	for _, m := range maps {
		for _, e := range m.entries {
			nk := NormalizeMapKey(e.key)
			if idx, ok := seen[nk]; ok {
				switch policy {
				case MergeUseFirst:
					continue
				case MergeUseLast:
					allEntries[idx] = EntryView{key: CloneMapKey(e.key), Value: CloneSequence(e.Value)}
					continue
				case MergeReject:
					return MapItem{}, &Error{
						Code:    "FOJS0003",
						Message: fmt.Sprintf("duplicate key in map merge: %v", e.key.Value),
					}
				case MergeCombine:
					// Combine: concatenate values
					allEntries[idx] = EntryView{
						key:   allEntries[idx].key,
						Value: ItemSlice(append(Materialize(CloneSequence(allEntries[idx].Value)), Materialize(e.Value)...)),
					}

					continue
				}
			}

			seen[nk] = len(allEntries)
			allEntries = append(allEntries, EntryView{key: CloneMapKey(e.key), Value: CloneSequence(e.Value)})
		}
	}

	newIndex := make(map[MapKey]int, len(allEntries))
	for i, e := range allEntries {
		newIndex[NormalizeMapKey(e.key)] = i
	}

	return MapItem{entries: allEntries, index: newIndex}, nil
}

// Get returns the value associated with key, or (nil, false) if not found.
func (m MapItem) Get(key AtomicValue) (Sequence, bool) {
	if m.index == nil {
		// Single-entry fast path: compare directly
		if len(m.entries) == 1 && NormalizeMapKey(m.entries[0].key) == NormalizeMapKey(key) {
			return CloneSequence(m.entries[0].Value), true
		}

		return nil, false
	}

	idx, ok := m.index[NormalizeMapKey(key)]
	if !ok {
		return nil, false
	}

	return CloneSequence(m.entries[idx].Value), true
}

// GetView returns the value associated with key without cloning it, or
// (nil, false) if not found. The returned Sequence is the one stored in the
// map (possibly a borrowed lazy sequence); callers must not mutate it and must
// clone before exposing it outward. This lets bounded walkers check the stored
// value's length before deciding whether to clone/materialize it.
func (m MapItem) GetView(key AtomicValue) (Sequence, bool) {
	if m.index == nil {
		if len(m.entries) == 1 && NormalizeMapKey(m.entries[0].key) == NormalizeMapKey(key) {
			return m.entries[0].Value, true
		}

		return nil, false
	}

	idx, ok := m.index[NormalizeMapKey(key)]
	if !ok {
		return nil, false
	}

	return m.entries[idx].Value, true
}

// Put returns a new map with the given key-value pair added or replaced.
func (m MapItem) Put(key AtomicValue, value Sequence) MapItem {
	nk := NormalizeMapKey(key)
	newEntries := make([]EntryView, len(m.entries))
	copy(newEntries, m.entries)
	newIndex := make(map[MapKey]int, len(m.entries)+1)
	// Rebuild index from entries when it was nil (single-entry maps)
	for i, e := range newEntries {
		newIndex[NormalizeMapKey(e.key)] = i
	}

	if idx, ok := newIndex[nk]; ok {
		newEntries[idx] = EntryView{key: CloneMapKey(key), Value: CloneSequence(value)}
	} else {
		newEntries = append(newEntries, EntryView{key: CloneMapKey(key), Value: CloneSequence(value)})
		newIndex[nk] = len(newEntries) - 1
	}

	return MapItem{entries: newEntries, index: newIndex}
}

// Contains returns true if the map contains the given key.
func (m MapItem) Contains(key AtomicValue) bool {
	if m.index == nil {
		return len(m.entries) == 1 && NormalizeMapKey(m.entries[0].key) == NormalizeMapKey(key)
	}

	_, ok := m.index[NormalizeMapKey(key)]

	return ok
}

// Keys returns all keys in insertion order. Keys are cloned so a caller cannot
// mutate a pointer-backed key and change the stored map key.
func (m MapItem) Keys() []AtomicValue {
	keys := make([]AtomicValue, len(m.entries))
	for i, e := range m.entries {
		keys[i] = CloneMapKey(e.key)
	}

	return keys
}

// KeysView returns the map's keys in insertion order without cloning. The returned
// AtomicValues are the map's own stored keys; callers must not mutate them.
// Used by trusted internal paths that only read keys.
func (m MapItem) KeysView() []AtomicValue {
	keys := make([]AtomicValue, len(m.entries))
	for i, e := range m.entries {
		keys[i] = e.key
	}

	return keys
}

// Size returns the number of entries.
func (m MapItem) Size() int {
	return len(m.entries)
}

// ForEach calls fn for each entry in insertion order. Stops on first error.
// The key and value passed to fn are clones of the map's stored entry, so a
// caller that mutates a pointer-backed atomic through fn cannot change the
// supposedly-immutable map. Trusted internal callers that need to avoid the
// clone (e.g. bounded/lazy iteration) use ForEachView instead.
func (m MapItem) ForEach(fn func(AtomicValue, Sequence) error) error {
	for _, e := range m.entries {
		if err := fn(CloneMapKey(e.key), CloneSequence(e.Value)); err != nil {
			return err
		}
	}

	return nil
}

// ForEachView calls fn for each entry in insertion order WITHOUT cloning the key or
// value. The key and value passed to fn are the map's own backing storage;
// callers must not mutate either and must clone before exposing them outward.
// Used by trusted internal/lazy/bounded paths that preserve laziness and bounds.
func (m MapItem) ForEachView(fn func(AtomicValue, Sequence) error) error {
	for _, e := range m.entries {
		if err := fn(e.key, e.Value); err != nil {
			return err
		}
	}

	return nil
}

// EntriesView returns the map's entries in insertion order without cloning. The
// returned slice and its value sequences are the map's own backing storage;
// callers must not mutate either. Used by bounded walkers that iterate value
// sequences in place, allocating no []Sequence copy.
func (m MapItem) EntriesView() []EntryView {
	return m.entries
}

// Remove returns a new map with the given key removed.
func (m MapItem) Remove(key AtomicValue) MapItem {
	nk := NormalizeMapKey(key)
	if m.index == nil {
		if len(m.entries) == 1 && NormalizeMapKey(m.entries[0].key) == nk {
			return MapItem{}
		}

		return m
	}

	idx, ok := m.index[nk]
	if !ok {
		return m
	}

	newEntries := make([]EntryView, 0, len(m.entries)-1)

	newIndex := make(map[MapKey]int, len(m.index)-1)
	for i, e := range m.entries {
		if i == idx {
			continue
		}

		newIndex[NormalizeMapKey(e.key)] = len(newEntries)
		newEntries = append(newEntries, e)
	}

	return MapItem{entries: newEntries, index: newIndex}
}

func (MapItem) itemTag() {}

// MapEntry is a public key-value pair for constructing maps.
type MapEntry struct {
	// Key is the atomic key used for map lookup and duplicate detection.
	Key AtomicValue
	// Value is the sequence associated with Key.
	Value Sequence
}

// EntryView exposes an immutable map entry while retaining its private key
// representation. Value is borrowed and must not be mutated.
type EntryView struct {
	// key retains the immutable atomic key used for comparison and lookup.
	key AtomicValue
	// Value is the borrowed sequence associated with this entry's key.
	Value Sequence
}

// MapKey is the normalized key used for O(1) lookup in the index map.
// time.Time is normalized to UTC RFC3339Nano string, []byte to hex string.
type MapKey struct {
	// typeName selects the normalized equality domain for value.
	typeName string
	value    any // only types with Go map equality: string, int64, float64, bool
}

// NormalizeMapKey converts an atomic value to the internal comparable map-key form,
// including numeric and string-family equivalence.
func NormalizeMapKey(key AtomicValue) MapKey {
	// Per XPath 3.1 spec, map keys use value-based equality (eq operator semantics).
	// Numerics that compare equal are the same key: xs:integer(1), xs:double(1.0e0),
	// xs:float(1.0), and xs:decimal(1.0) all refer to the same map entry.
	// xs:string and xs:untypedAtomic are compared as strings.
	// xs:anyURI promotes to xs:string for comparison.
	tn := key.TypeName

	// Normalize string-like types: xs:untypedAtomic and xs:anyURI promote to
	// xs:string, as do types derived from xs:string (e.g. xs:NCName, xs:token),
	// so they share a key with an equal xs:string value. Schema-derived atomics
	// can carry a custom TypeName whose BaseType is the string-like ancestor, so
	// consult BaseType as well to fold those against an equal xs:string key.
	if isStringMapKey(key) {
		return MapKey{typeName: TypeString, value: key.Value}
	}

	// Normalize all numeric types to a common representation using exact
	// rational arithmetic so that precision is not lost across types.
	if key.IsNumeric() {
		return normalizeNumericMapKey(key)
	}

	// Normalize duration types: xs:duration, xs:yearMonthDuration, xs:dayTimeDuration
	// that have equal values should be the same key. Schema-derived durations carry
	// a custom TypeName whose BaseType is a built-in duration ancestor, so consult
	// BaseType as well to fold those against an equal built-in duration key.
	tn = mapKeyTypeName(tn, key.BaseType)

	switch v := key.Value.(type) {
	case time.Time:
		// Per XPath 3.1, dateTimes with and without timezone are not equal
		// (they are incomparable), so they must be different map keys.
		if HasTimezone(v) {
			return MapKey{typeName: tn, value: v.UTC().Format(time.RFC3339Nano)}
		}

		return MapKey{typeName: tn, value: "notz:" + v.Format("2006-01-02T15:04:05.999999999")}
	case []byte:
		return MapKey{typeName: tn, value: hex.EncodeToString(v)}
	case QNameValue:
		// QName equality is based on URI and local name, not prefix
		return MapKey{typeName: tn, value: v.URI + "\x00" + v.Local}
	case Duration:
		// Duration holds a *big.Rat (FracSec) whose pointer breaks Go map
		// equality, and Seconds (a float64) can carry an exact fractional part
		// that int64() would truncate. Canonicalize to value content using the
		// exact-rational helper: signed total months and signed EXACT total
		// seconds (whole seconds plus the rational fraction). DurationToRat
		// folds the sign into each rational, and big.Rat normalizes -0 to 0,
		// so -PT0S and PT0S produce the same key.
		months := DurationToRat(v, true)
		secs := DurationToRat(v, false)
		canon := months.RatString() + "|" + secs.RatString()
		// The Go value is unambiguously a duration, so fold every duration-derived
		// key (built-in or schema-derived through any number of levels) to
		// TypeDuration. This catches schema types whose BaseType is itself another
		// custom duration type and never resolves to a built-in duration above.
		return MapKey{typeName: TypeDuration, value: canon}
	default:
		return MapKey{typeName: tn, value: key.Value}
	}
}

func normalizeNumericMapKey(key AtomicValue) MapKey {
	// Fast path: integer keys stored as int64 — use directly as map key
	// to avoid big.Rat/RatString overhead. This is safe because int64
	// has Go map equality and any numeric type that equals this integer
	// will also be detected as an exact integer below.
	if v, ok := key.Value.(int64); ok {
		return MapKey{typeName: FamilyNumeric, value: v}
	}
	// Exact numeric types must normalize with exact arithmetic, never float64:
	// ToFloat64 overflows values > MaxFloat64 to +Inf, collapsing distinct keys.
	// Also consult BaseType so a user-defined schema type derived from
	// xs:integer/xs:decimal is normalized exactly, and never via float64.
	if IsIntegerDerived(key.TypeName) || IsIntegerDerived(key.BaseType) {
		bi := key.BigInt()
		if bi.IsInt64() {
			return MapKey{typeName: FamilyNumeric, value: bi.Int64()}
		}

		return MapKey{typeName: FamilyNumeric, value: new(big.Rat).SetInt(bi).RatString()}
	}

	if key.TypeName == TypeDecimal || key.BaseType == TypeDecimal {
		r := key.BigRat()
		if r.IsInt() && r.Num().IsInt64() {
			return MapKey{typeName: FamilyNumeric, value: r.Num().Int64()}
		}

		return MapKey{typeName: FamilyNumeric, value: new(big.Rat).Set(r).RatString()}
	}
	// Remaining numerics are xs:float / xs:double (and user-defined types whose
	// effective base is a float/double). ToFloat64 keys off TypeName only, so a
	// schema-derived double/float (custom TypeName, BaseType=xs:double/xs:float)
	// would collapse to 0. Promote to the built-in base type first so ToFloat64
	// reads the underlying FloatValue exactly.
	f := PromoteSchemaType(key).ToFloat64()
	// xs:float keys are compared in single precision: a plain float64/float32
	// backing (schema-derived or directly constructed) may not yet be rounded,
	// so collapse to single precision before keying. Otherwise 16777217 and
	// 16777216 — equal as xs:float — would land in distinct slots.
	if key.effectiveNumericType() == TypeFloat {
		f = float64(float32(f))
	}

	if math.IsNaN(f) {
		return MapKey{typeName: FamilyNumeric, value: "NaN"}
	}

	if math.IsInf(f, 1) {
		return MapKey{typeName: FamilyNumeric, value: "+Inf"}
	}

	if math.IsInf(f, -1) {
		return MapKey{typeName: FamilyNumeric, value: "-Inf"}
	}
	// Remaining numerics are xs:float / xs:double (and user-defined types whose
	// underlying value is a float). Build an exact rational and use the int64
	// fast path ONLY when the value is an exact integer that fits in int64.
	// A naive "f <= math.MaxInt64" guard is unsafe: math.MaxInt64 (2^63-1)
	// rounds UP to 2^63 as a float64, so xs:double(2^63) would pass the check
	// and int64(f) would overflow-wrap to -2^63, colliding with xs:integer(-2^63).
	// Routing through the rational avoids that: r.Num().IsInt64() is exact.
	r := new(big.Rat).SetFloat64(f)
	if r == nil {
		// SetFloat64 returns nil for NaN/Inf; those are handled above, but
		// guard defensively so a stray non-finite value still produces a key.
		return MapKey{typeName: FamilyNumeric, value: strconv.FormatFloat(f, 'g', -1, 64)}
	}

	if r.IsInt() && r.Num().IsInt64() {
		return MapKey{typeName: FamilyNumeric, value: r.Num().Int64()}
	}

	return MapKey{typeName: FamilyNumeric, value: r.RatString()}
}

func isStringMapKey(key AtomicValue) bool {
	return key.TypeName == TypeUntypedAtomic || key.TypeName == TypeAnyURI || IsStringDerived(key.TypeName) || key.BaseType == TypeAnyURI || IsStringDerived(key.BaseType)
}

func mapKeyTypeName(typeName, baseType string) string {
	if typeName == TypeDuration || typeName == TypeYearMonthDuration || typeName == TypeDayTimeDuration || baseType == TypeDuration || baseType == TypeYearMonthDuration || baseType == TypeDayTimeDuration {
		return TypeDuration
	}

	return typeName
}

// MergePolicy controls how duplicate keys are handled in MergeMaps.
type MergePolicy int

const (
	MergeUseFirst MergePolicy = iota
	MergeUseLast
	MergeReject
	MergeCombine
)

// MapBuilder accumulates entries and applies a duplicate-key policy before
// transferring storage to Build. Added values are borrowed without cloning and must
// remain immutable. The builder must not be used concurrently or reused after Build.
type MapBuilder struct {
	// entries accumulates entries in insertion order before ownership transfers to Build.
	entries []EntryView
	// index maps normalized keys to entry positions for duplicate detection.
	index map[MapKey]int
	// policy selects how Add handles duplicate keys.
	policy MergePolicy
	// combined retains mutable sequence buffers while combining duplicate values.
	combined map[int]ItemSlice
}

// NewMapBuilder creates a builder for accumulating map entries.
// sizeHint is used to pre-allocate internal storage.
func NewMapBuilder(policy MergePolicy, sizeHint int) *MapBuilder {
	return &MapBuilder{
		entries: make([]EntryView, 0, sizeHint),
		index:   make(map[MapKey]int, sizeHint),
		policy:  policy,
	}
}

// Add inserts a cloned atomic key and a borrowed value sequence, applying the
// duplicate-key policy. The caller must not mutate the sequence or its shared payloads
// after insertion.
func (b *MapBuilder) Add(key AtomicValue, value Sequence) error {
	nk := NormalizeMapKey(key)
	if idx, ok := b.index[nk]; ok {
		switch b.policy {
		case MergeUseFirst:
			return nil
		case MergeUseLast:
			b.entries[idx] = EntryView{key: CloneMapKey(key), Value: value}
			return nil
		case MergeReject:
			return &Error{
				Code:    "FOJS0003",
				Message: fmt.Sprintf("duplicate key in map merge: %v", key.Value),
			}
		case MergeCombine:
			b.combineValue(idx, value)

			return nil
		}
	}

	b.index[nk] = len(b.entries)
	b.entries = append(b.entries, EntryView{key: CloneMapKey(key), Value: value})

	return nil
}

// Size returns the number of distinct keys accumulated so far.
func (b *MapBuilder) Size() int { return len(b.entries) }

// Build returns the accumulated MapItem. The builder should not be used
// after calling Build.
func (b *MapBuilder) Build() MapItem {
	return MapItem{entries: b.entries, index: b.index}
}

func (b *MapBuilder) combineValue(idx int, value Sequence) {
	items, owned := b.combined[idx]
	if !owned {
		existing := b.entries[idx].Value

		items = make(ItemSlice, 0, SequenceLen(existing)+SequenceLen(value))
		for item := range SequenceItems(existing) {
			items = append(items, item)
		}

		if b.combined == nil {
			b.combined = make(map[int]ItemSlice)
		}
	}

	for item := range SequenceItems(value) {
		items = append(items, item)
	}

	b.combined[idx] = items
	b.entries[idx].Value = items
}

// ArrayItem is an immutable indexed sequence of members. Uses 1-based indexing.
type ArrayItem struct {
	// members retains immutable member sequences in one-based array order.
	members []Sequence
}

// NewArray creates an ArrayItem from a slice of Sequence members.
func NewArray(members []Sequence) ArrayItem {
	return ArrayItem{members: CloneSequences(members)}
}

// NewArrayFromImmutableMembers takes ownership of an outer member slice whose
// sequences and items are already immutable. It performs no cloning. Callers
// must not modify the slice or its members after handing them over. Trusted
// internal producers can use it to reorder existing ArrayItem members.
func NewArrayFromImmutableMembers(members []Sequence) ArrayItem {
	return ArrayItem{members: members}
}

// Get returns the member at the given 1-based index.
func (a ArrayItem) Get(index int) (Sequence, error) {
	if index < 1 || index > len(a.members) {
		return nil, &Error{
			Code:    lexicon.ErrFOAY0001,
			Message: fmt.Sprintf("array index %d out of bounds (size %d)", index, len(a.members)),
		}
	}

	return CloneSequence(a.members[index-1]), nil
}

// Size returns the number of members.
func (a ArrayItem) Size() int {
	return len(a.members)
}

// Put returns a new array with the member at the given 1-based index replaced.
func (a ArrayItem) Put(index int, value Sequence) (ArrayItem, error) {
	if index < 1 || index > len(a.members) {
		return ArrayItem{}, &Error{
			Code:    lexicon.ErrFOAY0001,
			Message: fmt.Sprintf("array index %d out of bounds (size %d)", index, len(a.members)),
		}
	}

	newMembers := make([]Sequence, len(a.members))
	copy(newMembers, a.members)
	newMembers[index-1] = CloneSequence(value)

	return ArrayItem{members: newMembers}, nil
}

// Append returns a new array with the value appended.
func (a ArrayItem) Append(value Sequence) ArrayItem {
	newMembers := make([]Sequence, len(a.members)+1)
	copy(newMembers, a.members)
	newMembers[len(a.members)] = CloneSequence(value)

	return ArrayItem{members: newMembers}
}

// Members returns all members (defensively cloned).
func (a ArrayItem) Members() []Sequence {
	return CloneSequences(a.members)
}

// MembersView returns the underlying members slice without cloning.
// Callers must not mutate the returned slices.
func (a ArrayItem) MembersView() []Sequence {
	return a.members
}

// GetView returns the member at the given 1-based index without cloning.
// Callers must not mutate the returned sequence.
func (a ArrayItem) GetView(index int) (Sequence, error) {
	if index < 1 || index > len(a.members) {
		return nil, &Error{
			Code:    lexicon.ErrFOAY0001,
			Message: fmt.Sprintf("array index %d out of bounds (size %d)", index, len(a.members)),
		}
	}

	return a.members[index-1], nil
}

// SubArray returns a new array from start to end (1-based, inclusive).
func (a ArrayItem) SubArray(start, length int) (ArrayItem, error) {
	size := len(a.members)
	// Bounds are checked without forming start+length, which can overflow for
	// huge positions and bypass the guard, leading to a make([]Sequence, length)
	// panic. With start>=1 established first, size-start+1 cannot overflow.
	if start < 1 || start > size+1 || length < 0 || length > size-start+1 {
		code := lexicon.ErrFOAY0001
		if start >= 1 && start <= size+1 && length < 0 {
			code = "FOAY0002"
		}

		return ArrayItem{}, &Error{
			Code:    code,
			Message: fmt.Sprintf("array subarray(%d, %d) out of bounds (size %d)", start, length, size),
		}
	}

	newMembers := make([]Sequence, length)
	copy(newMembers, a.members[start-1:start-1+length])

	return ArrayItem{members: newMembers}, nil
}

// Flatten returns all members concatenated into a single sequence.
// Nested arrays are recursively flattened per XPath 3.1 spec.
//
// Leaf items are deep-cloned via deepCloneItem so that pointer-backed atomics
// (*big.Int, *big.Rat, *FloatValue, []byte) held in the array's internal
// storage are not exposed to the caller; mutating the returned sequence must
// not mutate the original array. Nested arrays/maps are flattened recursively
// (their own leaves are cloned at that level) and any non-flattened maps are
// kept shared by value — they are immutable and were detached at ingress — to
// avoid O(N^2) deep recursion and stay within the resource bounds.
func (a ArrayItem) Flatten() Sequence {
	var result ItemSlice
	// Keep one cursor per nesting level and append every leaf once. Building
	// a separate flattened slice at each level copies a skewed array O(n²).
	type cursor struct {
		members []Sequence
		item    int
	}

	stack := []cursor{{members: a.members}}
	for len(stack) > 0 {
		top := &stack[len(stack)-1]
		if len(top.members) == 0 {
			stack = stack[:len(stack)-1]
			continue
		}

		member := top.members[0]
		if top.item >= SequenceLen(member) {
			top.members, top.item = top.members[1:], 0
			continue
		}

		item := member.Get(top.item)
		top.item++

		if nested, ok := item.(ArrayItem); ok {
			stack = append(stack, cursor{members: nested.members})
		} else {
			result = append(result, CloneItem(item))
		}
	}

	return result
}

func (ArrayItem) itemTag() {}

// CloneSequence returns a deep copy of the Sequence. Bounded call sites charge
// its length against OpLimit before materializing it. It then deep-copies each item
// so that pointer-backed atomic values (*big.Int, *big.Rat, *FloatValue,
// []byte) and nested maps/arrays are not shared with the source. This preserves
// XPath 3.1 value semantics: mutating a value after it was inserted into a
// map/array must not change the stored map/array.
func CloneSequence(seq Sequence) Sequence {
	if seq == nil {
		return nil
	}

	// Integer ranges are immutable descriptors; copying them must not turn a
	// bounded lazy sequence into two complete item slices.
	if _, ok := seq.(*rangeSequence); ok {
		return seq
	}

	if seq.Len() == 0 {
		return ItemSlice(nil)
	}

	cloned := make([]Item, seq.Len())

	i := 0
	for item := range seq.Items() {
		cloned[i] = CloneItem(item)
		i++
	}

	return ItemSlice(cloned)
}

// CloneSequenceTypePtr deep-copies a *SequenceType, preserving nil.
func CloneSequenceTypePtr(st *SequenceType) *SequenceType {
	if st == nil {
		return nil
	}

	cloned := CloneSequenceType(*st)

	return &cloned
}

// CloneSequenceTypes deep-copies a slice of SequenceType, preserving nil.
func CloneSequenceTypes(sts []SequenceType) []SequenceType {
	if sts == nil {
		return nil
	}

	cloned := make([]SequenceType, len(sts))
	for i := range sts {
		cloned[i] = CloneSequenceType(sts[i])
	}

	return cloned
}

// CloneSequenceType deep-copies a SequenceType's mutable metadata. Three item
// tests carry mutable backing reachable from a SequenceType: FunctionTest
// (ParamTypes slice + ReturnType, each itself a SequenceType), MapTest
// (ValType) and ArrayTest (MemberType). Those nested SequenceTypes can in turn
// hold a FunctionTest, so cloning recurses through all three. Every other
// NodeTest is an immutable value with no shared mutable backing, so it is kept
// as-is.
func CloneSequenceType(st SequenceType) SequenceType {
	switch t := st.ItemTest.(type) {
	case FunctionTest:
		t.ParamTypes = CloneSequenceTypes(t.ParamTypes)
		t.ReturnType = CloneSequenceType(t.ReturnType)
		st.ItemTest = t
	case MapTest:
		t.ValType = CloneSequenceType(t.ValType)
		st.ItemTest = t
	case ArrayTest:
		t.MemberType = CloneSequenceType(t.MemberType)
		st.ItemTest = t
	}

	return st
}

// CloneSequences copies the outer slice and clones each member sequence while
// preserving shared immutable item identities.
func CloneSequences(seqs []Sequence) []Sequence {
	if seqs == nil {
		return nil
	}

	cloned := make([]Sequence, len(seqs))
	for i, seq := range seqs {
		cloned[i] = CloneSequence(seq)
	}

	return cloned
}

// QAnnotation returns the Q{ns}local annotation format for a namespace URI and local name.
func QAnnotation(ns, local string) string {
	return "Q{" + ns + "}" + local
}

// IsSubtypeOf reports ancestry in the fixed XSD type hierarchy.
func IsSubtypeOf(actualType, targetType string) bool {
	return actualType == targetType || computeIsSubtypeOf(actualType, targetType)
}

// IsAtomicSubtypeOf reports whether the atomic value's type is targetType or a
// subtype of it, honoring both the built-in XSD hierarchy and the value's
// built-in BaseType (set when TypeName is a user-defined schema type derived by
// restriction). Unlike PromoteSchemaType it never falls back to the Go value's
// kind, so a sibling type (e.g. xs:dateTime relative to xs:date) is correctly
// rejected, and never reinterpreted from its time.Time payload.
func IsAtomicSubtypeOf(av AtomicValue, targetType string) bool {
	if IsSubtypeOf(av.TypeName, targetType) {
		return true
	}

	if av.BaseType != "" && IsKnownXSDType(av.BaseType) && IsSubtypeOf(av.BaseType, targetType) {
		return true
	}

	return false
}

// BuiltinIsSubtypeOf reports whether actualType is the same as or a subtype of
// targetType using only the built-in XSD type hierarchy (no schema lookup).
// This is exported for use by schema-aware backends (e.g. xslt) that need to
// check the final leg of a type ancestry chain against a built-in base type.
func BuiltinIsSubtypeOf(actualType, targetType string) bool {
	return IsSubtypeOf(actualType, targetType)
}

// DecimalToString returns the canonical XSD decimal string for a *big.Rat.
func DecimalToString(r *big.Rat) string {
	if r.IsInt() {
		return r.Num().String()
	}
	// Use enough precision for exact representation, then trim trailing zeros
	n, exact := r.FloatPrec()
	if !exact {
		// Not exactly representable in decimal; use high precision
		s := r.FloatString(20)

		s = strings.TrimRight(s, "0")
		if strings.HasSuffix(s, ".") {
			s += "0"
		}

		return s
	}

	s := r.FloatString(n)

	s = strings.TrimRight(s, "0")
	if strings.HasSuffix(s, ".") {
		s += "0"
	}

	return s
}

// NoTimezone constructs the location for a timezone-less XSD date/time.
func NoTimezone() *time.Location { return time.FixedZone(noTimezoneName, 0) }

// HasTimezone reports whether a value carries an explicit timezone.
func HasTimezone(t time.Time) bool { return t.Location().String() != noTimezoneName }

// IsKnownXSDType returns true if name is a recognized XSD type in the
// XPath type hierarchy (the xsdTypeParent lookup or a base type).
func IsKnownXSDType(name string) bool {
	if _, ok := lookupXSDTypeParent(name); ok {
		return true
	}

	switch name {
	case TypeAnyAtomicType, TypeNumeric,
		TypeAnyType, TypeAnySimpleType, TypeUntyped,
		TypeNOTATION, TypeError,
		TypeNMTOKENS, TypeENTITIES, TypeIDREFS:
		return true
	}

	return false
}

// SchemaAnnotationParts splits a custom annotation into local name and namespace.
// Built-in xs: and xsd: names return ok=false; URI-qualified names retain their URI.
func SchemaAnnotationParts(name string) (local, ns string, ok bool) {
	if strings.HasPrefix(name, "Q{") {
		end := strings.IndexByte(name, '}')
		if end <= 1 || end == len(name)-1 {
			return "", "", false
		}

		return name[end+1:], name[2:end], true
	}

	if strings.HasPrefix(name, "xs:") || strings.HasPrefix(name, "xsd:") {
		return "", "", false
	}

	if _, local, ok := strings.Cut(name, ":"); ok {
		return local, "", true
	}

	if name == "" {
		return "", "", false
	}

	return name, "", true
}

func computeIsSubtypeOf(actualType, targetType string) bool {
	// xs:numeric is a union of xs:integer, xs:decimal, xs:float, xs:double
	if targetType == TypeNumeric {
		return IsSubtypeOf(actualType, TypeDecimal) ||
			actualType == TypeFloat || actualType == TypeDouble
	}
	// Walk up the type hierarchy
	cur := actualType
	for {
		parent, ok := lookupXSDTypeParent(cur)
		if !ok {
			return false
		}

		if parent == targetType {
			return true
		}

		cur = parent
	}
}

// deepCloneAtomicValue copies an AtomicValue when its Go payload is pointer- or
// slice-backed, duplicating that payload so a later mutation of the original
// cannot reach the stored copy. It returns (copy, true) only when a duplication
// was needed; for immutable value payloads it returns (zero, false) so the
// caller can keep the original (already-boxed) Item and skip a re-allocation.
func deepCloneAtomicValue(a AtomicValue) (AtomicValue, bool) {
	switch v := a.Value.(type) {
	case *big.Int:
		a.Value = new(big.Int).Set(v)
	case *big.Rat:
		a.Value = new(big.Rat).Set(v)
	case *FloatValue:
		a.Value = v.clone()
	case []byte:
		a.Value = append([]byte(nil), v...)
	case Duration:
		a.Value = v.clone()
	case *Duration:
		d := v.clone()
		a.Value = &d
	default:
		return AtomicValue{}, false
	}

	return a, true
}

// lookupXSDTypeParent maps each derived XSD type to its parent (base) type.
func lookupXSDTypeParent(key string) (string, bool) {
	switch key {
	case TypeByte:
		return TypeShort, true
	case TypeShort:
		return TypeInt, true
	case TypeInt:
		return TypeLong, true
	case TypeLong, TypeNonNegativeInteger, TypeNonPositiveInteger:
		return TypeInteger, true
	case TypeUnsignedByte:
		return TypeUnsignedShort, true
	case TypeUnsignedShort:
		return TypeUnsignedInt, true
	case TypeUnsignedInt:
		return TypeUnsignedLong, true
	case TypeUnsignedLong, TypePositiveInteger:
		return TypeNonNegativeInteger, true
	case TypeNegativeInteger:
		return TypeNonPositiveInteger, true
	case TypeInteger:
		return TypeDecimal, true
	case TypeDecimal, TypeFloat, TypeDouble, TypeDuration, TypeDateTime, TypeDate, TypeTime, TypeString, TypeBoolean, TypeAnyURI, TypeQName, TypeBase64Binary, TypeHexBinary, TypeUntypedAtomic, TypeGDay, TypeGMonth, TypeGMonthDay, TypeGYear, TypeGYearMonth:
		return TypeAnyAtomicType, true
	case TypeDayTimeDuration, TypeYearMonthDuration:
		return TypeDuration, true
	case TypeDateTimeStamp:
		return TypeDateTime, true
	case TypeNormalizedString:
		return TypeString, true
	case TypeToken:
		return TypeNormalizedString, true
	case TypeLanguage, TypeNMTOKEN, TypeName:
		return TypeToken, true
	case TypeNCName:
		return TypeName, true
	case TypeID, TypeIDREF, TypeENTITY:
		return TypeNCName, true
	case TypeUntyped, TypeAnySimpleType:
		return TypeAnyType, true
	case TypeAnyAtomicType:
		return TypeAnySimpleType, true
	}

	var zero string

	return zero, false
}

func xsdTypeParent(key string) string { value, _ := lookupXSDTypeParent(key); return value }
