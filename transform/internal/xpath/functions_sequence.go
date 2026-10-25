// Derived from lestrrat-go/helium at 7362c0a70122a757780f4d0b545a9b370dead6ab.
// Copyright (c) 2015 lestrrat. MIT License; see licenses/MIT-helium.txt at the repository root.

package xpath

import (
	"context"
	"fmt"
	"math"
	"math/big"
	"sort"
	"time"

	"github.com/skarm/xmlsec/internal/lexicon"
	"github.com/skarm/xmlsec/transform/internal/xdm"
)

func lookupFunctionsSequence(name string) (*builtinFunc, bool) {
	switch name {
	case "empty":
		return &builtinFunc{name: name, min: 1, max: 1, fn: fnEmpty}, true
	case "exists":
		return &builtinFunc{name: name, min: 1, max: 1, fn: fnExists}, true
	case fnNameHead:
		return &builtinFunc{name: name, min: 1, max: 1, fn: fnHead}, true
	case nameTail:
		return &builtinFunc{name: name, min: 1, max: 1, fn: fnTail}, true
	case "insert-before":
		return &builtinFunc{name: name, min: 3, max: 3, fn: fnInsertBefore}, true
	case nameRemove:
		return &builtinFunc{name: name, min: 2, max: 2, fn: fnRemove}, true
	case nameReverse:
		return &builtinFunc{name: name, min: 1, max: 1, fn: fnReverse}, true
	case "subsequence":
		return &builtinFunc{name: name, min: 2, max: 3, fn: fnSubsequence}, true
	case "unordered":
		return &builtinFunc{name: name, min: 1, max: 1, fn: fnUnordered}, true
	case "zero-or-one":
		return &builtinFunc{name: name, min: 1, max: 1, fn: fnZeroOrOne}, true
	case "one-or-more":
		return &builtinFunc{name: name, min: 1, max: 1, fn: fnOneOrMore}, true
	case "exactly-one":
		return &builtinFunc{name: name, min: 1, max: 1, fn: fnExactlyOne}, true
	case "deep-equal":
		return &builtinFunc{name: name, min: 2, max: 3, fn: fnDeepEqual}, true
	case "index-of":
		return &builtinFunc{name: name, min: 2, max: 3, fn: fnIndexOf}, true
	case lexicon.FnLast:
		return &builtinFunc{name: name, min: 0, max: 0, fn: fnLast}, true
	case lexicon.FnPosition:
		return &builtinFunc{name: name, min: 0, max: 0, fn: fnPosition}, true
	case nameSort:
		return &builtinFunc{name: name, min: 1, max: 3, fn: fnSort}, true
	case "flatten":
		return &builtinFunc{name: name, min: 1, max: 1, fn: fnFlatten, extension: true}, true
	}

	return nil, false
}

func fnEmpty(_ context.Context, args []xdm.Sequence) (xdm.Sequence, error) {
	return xdm.SingleBoolean(xdm.SequenceLen(args[0]) == 0), nil
}

func fnExists(_ context.Context, args []xdm.Sequence) (xdm.Sequence, error) {
	return xdm.SingleBoolean(xdm.SequenceLen(args[0]) > 0), nil
}

func fnHead(_ context.Context, args []xdm.Sequence) (xdm.Sequence, error) {
	if xdm.SequenceLen(args[0]) == 0 {
		return nil, nil
	}

	return xdm.ItemSlice{args[0].Get(0)}, nil
}

func fnTail(_ context.Context, args []xdm.Sequence) (xdm.Sequence, error) {
	if xdm.SequenceLen(args[0]) <= 1 {
		return nil, nil
	}

	return xdm.ItemSlice(xdm.Materialize(args[0])[1:]), nil
}

func fnInsertBefore(ctx context.Context, args []xdm.Sequence) (xdm.Sequence, error) {
	target := args[0]
	// $position is xs:integer: reject empty/multi-item/non-integer (XPTY0004).
	posVal, err := coerceArgToInteger(ctx, args[1])
	if err != nil {
		return nil, err
	}

	inserts := args[2]
	tItems := xdm.Materialize(target)

	// Clamp on the int64 value so an oversized position cannot wrap when
	// converted to int (e.g. on 32-bit platforms): a position past the end
	// must insert at the end, a position before the start at position 1.
	var pos int

	switch {
	case posVal < 1:
		pos = 1
	case posVal > int64(len(tItems)+1):
		pos = len(tItems) + 1
	default:
		pos = int(posVal)
	}

	iItems := xdm.Materialize(inserts)
	result := make(xdm.ItemSlice, 0, len(tItems)+len(iItems))
	result = append(result, tItems[:pos-1]...)
	result = append(result, iItems...)
	result = append(result, tItems[pos-1:]...)

	return result, nil
}

func fnRemove(ctx context.Context, args []xdm.Sequence) (xdm.Sequence, error) {
	target := args[0]

	posVal, err := coerceArgToInteger(ctx, args[1])
	if err != nil {
		return nil, err
	}

	tItems := xdm.Materialize(target)
	// Range-check on int64 before converting so an out-of-int position cannot
	// wrap into a valid index (e.g. on 32-bit platforms).
	if posVal < 1 || posVal > int64(len(tItems)) {
		return target, nil
	}

	pos := int(posVal)

	result := make(xdm.ItemSlice, 0, len(tItems)-1)
	result = append(result, tItems[:pos-1]...)
	result = append(result, tItems[pos:]...)

	return result, nil
}

func fnReverse(_ context.Context, args []xdm.Sequence) (xdm.Sequence, error) {
	seq := args[0]
	items := xdm.Materialize(seq)

	result := make(xdm.ItemSlice, len(items))
	for i, item := range items {
		result[len(items)-1-i] = item
	}

	return result, nil
}

func fnSubsequence(ctx context.Context, args []xdm.Sequence) (xdm.Sequence, error) {
	compat := getFnContext(ctx).xpath10CompatMode()

	start, err := roundSubsequenceArgument(args[1], compat, "starting position")
	if err != nil {
		return nil, err
	}

	length, bounded, err := subsequenceLength(args, compat)
	if err != nil {
		return nil, err
	}

	// Validate both arguments before applying the NaN rules.
	if math.IsNaN(start) || (bounded && math.IsNaN(length)) {
		return nil, nil
	}

	end := start + length
	// -INF + INF = NaN yields the empty sequence.
	if bounded && math.IsNaN(end) {
		return nil, nil
	}

	return collectSubsequence(args[0], start, end, bounded), nil
}

func roundSubsequenceArgument(arg xdm.Sequence, compat bool, role string) (float64, error) {
	if compat {
		// XPath 1.0 uses fn:number: first item, with empty/non-numeric as NaN.
		value, err := xpath10CompatNumberItem(arg)
		if err != nil {
			return 0, err
		}

		return roundHalfUpFloat(value.ToFloat64(), 0), nil
	}

	switch xdm.SequenceLen(arg) {
	case 0:
		return 0, subsequenceArgumentError(role, "is required")
	case 1:
		// Continue with the single atomic value.
	default:
		return 0, subsequenceArgumentError(role, "must be a single value")
	}

	value, err := AtomizeItem(arg.Get(0))
	if err != nil {
		return 0, err
	}

	if value.TypeName == xdm.TypeUntypedAtomic {
		value, err = CastAtomic(value, xdm.TypeDouble)
		if err != nil {
			return 0, subsequenceArgumentError(role, "must be numeric")
		}
	}

	if !xdm.IsSubtypeOf(value.TypeName, xdm.TypeNumeric) {
		return 0, subsequenceArgumentError(role, "must be numeric")
	}

	return roundHalfUpFloat(value.ToFloat64(), 0), nil
}

func subsequenceArgumentError(role, problem string) error {
	return &xdm.Error{Code: lexicon.ErrXPTY0004, Message: "subsequence: " + role + " " + problem}
}

func subsequenceLength(args []xdm.Sequence, compat bool) (float64, bool, error) {
	if len(args) <= 2 {
		return 0, false, nil
	}

	length, err := roundSubsequenceArgument(args[2], compat, "length")

	return length, true, err
}

func collectSubsequence(seq xdm.Sequence, start, end float64, bounded bool) xdm.Sequence {
	var result xdm.ItemSlice

	i := 0
	for item := range xdm.SequenceItems(seq) {
		position := float64(i + 1)
		if position < start {
			i++
			continue
		}

		if bounded && position >= end {
			break
		}

		result = append(result, item)
		i++
	}

	return result
}

func fnUnordered(_ context.Context, args []xdm.Sequence) (xdm.Sequence, error) {
	return args[0], nil
}

func fnZeroOrOne(_ context.Context, args []xdm.Sequence) (xdm.Sequence, error) {
	if xdm.SequenceLen(args[0]) > 1 {
		return nil, &xdm.Error{Code: "FORG0003", Message: fmt.Sprintf("zero-or-one() called with sequence of length %d", xdm.SequenceLen(args[0]))}
	}

	return args[0], nil
}

func fnOneOrMore(_ context.Context, args []xdm.Sequence) (xdm.Sequence, error) {
	if xdm.SequenceLen(args[0]) == 0 {
		return nil, &xdm.Error{Code: "FORG0004", Message: "one-or-more() called with empty sequence"}
	}

	return args[0], nil
}

func fnExactlyOne(_ context.Context, args []xdm.Sequence) (xdm.Sequence, error) {
	if xdm.SequenceLen(args[0]) != 1 {
		return nil, &xdm.Error{Code: "FORG0005", Message: fmt.Sprintf("exactly-one() called with sequence of length %d", xdm.SequenceLen(args[0]))}
	}

	return args[0], nil
}

type deepEqualOptions struct {
	coll       *collationImpl
	implicitTZ *time.Location
}

func (opts deepEqualOptions) stringsEqual(a, b string) bool {
	if opts.coll != nil {
		return opts.coll.compare(a, b) == 0
	}

	return a == b
}

func fnDeepEqual(ctx context.Context, args []xdm.Sequence) (xdm.Sequence, error) {
	coll, err := getCollation(ctx, args, 2)
	if err != nil {
		return nil, err
	}

	opts := deepEqualOptions{coll: coll}
	if ec := getFnContext(ctx); ec != nil {
		opts.implicitTZ = ec.getImplicitTimezone()
	}

	eq, err := deepEqualSequence(args[0], args[1], opts)
	if err != nil {
		return nil, err
	}

	return xdm.SingleBoolean(eq), nil
}

// deepEqualMapMatcher tracks the right-hand entries already matched by value.
type deepEqualMapMatcher struct {
	a, b xdm.MapItem
	opts deepEqualOptions
	keys []xdm.AtomicValue
	used []bool
}

func (m *deepEqualMapMatcher) match(key xdm.AtomicValue) (bool, error) {
	// Exact lookup precedes cross-type key matching and its value comparisons.
	if value, ok := m.b.Get(key); ok {
		aValue, _ := m.a.Get(key)

		equal, err := deepEqualSequence(aValue, value, m.opts)
		if err != nil {
			return false, err
		}

		if equal {
			m.markKeyUsed(key)
			return true, nil
		}
	}

	return m.matchByValue(key)
}

func (m *deepEqualMapMatcher) markKeyUsed(key xdm.AtomicValue) {
	for i, candidate := range m.keys {
		if !m.used[i] && sameMapKey(key, candidate) {
			m.used[i] = true
			return
		}
	}
}

func (m *deepEqualMapMatcher) matchByValue(key xdm.AtomicValue) (bool, error) {
	aValue, _ := m.a.Get(key)
	for i, candidate := range m.keys {
		if m.used[i] || !sameMapKey(key, candidate) {
			continue
		}

		bValue, _ := m.b.Get(candidate)

		equal, err := deepEqualSequence(aValue, bValue, m.opts)
		if err != nil {
			return false, err
		}

		if equal {
			m.used[i] = true
			return true, nil
		}
	}

	return false, nil
}

func deepEqualSequence(a, b xdm.Sequence, opts deepEqualOptions) (bool, error) {
	if xdm.SequenceLen(a) != xdm.SequenceLen(b) {
		return false, nil
	}

	for i := range xdm.SequenceLen(a) {
		eq, err := deepEqualItem(a.Get(i), b.Get(i), opts)
		if err != nil {
			return false, err
		}

		if !eq {
			return false, nil
		}
	}

	return true, nil
}

func deepEqualItem(a, b xdm.Item, opts deepEqualOptions) (bool, error) {
	switch av := a.(type) {
	case xdm.AtomicValue:
		bv, ok := b.(xdm.AtomicValue)
		if !ok {
			return false, nil
		}

		return deepEqualAtomic(av, bv, opts)
	case xdm.NodeItem:
		bv, ok := b.(xdm.NodeItem)
		if !ok {
			return false, nil
		}

		return deepEqualNode(av.Node, bv.Node, opts), nil
	case xdm.MapItem:
		bv, ok := b.(xdm.MapItem)
		if !ok {
			return false, nil
		}

		return deepEqualMap(av, bv, opts)
	case xdm.ArrayItem:
		bv, ok := b.(xdm.ArrayItem)
		if !ok {
			return false, nil
		}

		return deepEqualArray(av, bv, opts)
	case xdm.FunctionItem:
		if _, ok := b.(xdm.FunctionItem); ok {
			return false, &xdm.Error{Code: "FOTY0015", Message: "deep-equal: cannot compare function items"}
		}

		return false, nil
	default:
		return false, nil
	}
}

func deepEqualAtomic(a, b xdm.AtomicValue, opts deepEqualOptions) (bool, error) {
	// NaN equals NaN for deep-equal purposes
	if a.TypeName == xdm.TypeDouble || a.TypeName == xdm.TypeFloat {
		af := a.ToFloat64()
		if b.TypeName == xdm.TypeDouble || b.TypeName == xdm.TypeFloat {
			bf := b.ToFloat64()
			if af != af && bf != bf { // both NaN
				return true, nil
			}
		}
	}

	aStr := xdm.IsStringDerived(a.TypeName) || a.TypeName == xdm.TypeAnyURI

	bStr := xdm.IsStringDerived(b.TypeName) || b.TypeName == xdm.TypeAnyURI
	if opts.coll != nil && aStr && bStr {
		return opts.coll.compare(stringFromAtomic(a), stringFromAtomic(b)) == 0, nil
	}

	eq, err := ValueCompareWithImplicitTimezone(TokenEq, a, b, opts.implicitTZ)
	if err != nil {
		// Incomparable types are not deep-equal
		return false, nil //nolint:nilerr // incomparable types yield false per fn:deep-equal spec
	}

	return eq, nil
}

func deepEqualNode(a, b xdm.Node, opts deepEqualOptions) bool {
	if a.Type() != b.Type() {
		return false
	}

	switch a.Type() {
	case xdm.DocumentNode:
		return deepEqualChildren(a, b, opts)
	case xdm.ElementNode:
		return deepEqualElementNodes(a, b, opts)
	case xdm.AttributeNode:
		aa, aOK := a.(*xdm.Attribute)
		ba, bOK := b.(*xdm.Attribute)

		return aOK && bOK && deepEqualAttribute(aa, ba, opts)
	case xdm.NamespaceNode, xdm.ProcessingInstructionNode:
		return a.Name() == b.Name() && xdm.CharacterData(a) == xdm.CharacterData(b)
	case xdm.TextNode, xdm.CDATASectionNode:
		return opts.stringsEqual(xdm.CharacterData(a), xdm.CharacterData(b))
	case xdm.CommentNode:
		return xdm.CharacterData(a) == xdm.CharacterData(b)
	default:
		return false
	}
}

func deepEqualElementNodes(a, b xdm.Node, opts deepEqualOptions) bool {
	ae, aOK := a.(*xdm.Element)

	be, bOK := b.(*xdm.Element)
	if !aOK || !bOK {
		return false
	}

	// Expanded names and order-independent attributes precede child comparison.
	if ae.LocalName() != be.LocalName() || ae.URI() != be.URI() {
		return false
	}

	if !deepEqualAttributes(ae.Attributes(), be.Attributes(), opts) {
		return false
	}

	return deepEqualChildren(a, b, opts)
}

func deepEqualAttributes(a, b []*xdm.Attribute, opts deepEqualOptions) bool {
	if len(a) != len(b) {
		return false
	}

	for _, attr := range a {
		match := findExpandedAttribute(b, attr.LocalName(), attr.URI())
		if match == nil || !opts.stringsEqual(attr.Value(), match.Value()) {
			return false
		}
	}

	return true
}

func findExpandedAttribute(attrs []*xdm.Attribute, localName, uri string) *xdm.Attribute {
	for _, attr := range attrs {
		if attr.LocalName() == localName && attr.URI() == uri {
			return attr
		}
	}

	return nil
}

func deepEqualAttribute(a, b *xdm.Attribute, opts deepEqualOptions) bool {
	return a.LocalName() == b.LocalName() && a.URI() == b.URI() && opts.stringsEqual(a.Value(), b.Value())
}

func deepEqualChildren(a, b xdm.Node, opts deepEqualOptions) bool {
	ac := a.FirstChild()

	bc := b.FirstChild()
	for ac != nil && bc != nil {
		if !deepEqualNode(ac, bc, opts) {
			return false
		}

		ac = ac.NextSibling()
		bc = bc.NextSibling()
	}

	return ac == nil && bc == nil
}

func deepEqualMap(a, b xdm.MapItem, opts deepEqualOptions) (bool, error) {
	if a.Size() != b.Size() {
		return false, nil
	}

	keys := b.KeysView()

	matcher := deepEqualMapMatcher{a: a, b: b, opts: opts, keys: keys, used: make([]bool, len(keys))}
	for _, key := range a.KeysView() {
		found, err := matcher.match(key)
		if err != nil {
			return false, err
		}

		if !found {
			return false, nil
		}
	}

	return true, nil
}

func sameMapKey(a, b xdm.AtomicValue) bool {
	return xdm.NormalizeMapKey(a) == xdm.NormalizeMapKey(b)
}

func deepEqualArray(a, b xdm.ArrayItem, opts deepEqualOptions) (bool, error) {
	am0, bm0 := a.MembersView(), b.MembersView()
	if len(am0) != len(bm0) {
		return false, nil
	}

	for i := range am0 {
		am, bm := am0[i], bm0[i]

		eq, err := deepEqualSequence(am, bm, opts)
		if err != nil {
			return false, err
		}

		if !eq {
			return false, nil
		}
	}

	return true, nil
}

func fnIndexOf(ctx context.Context, args []xdm.Sequence) (xdm.Sequence, error) {
	// $search is declared xs:anyAtomicType (exactly one item): an empty or
	// multi-item search value is a type error, not a search for the first item.
	searchAtoms, err := AtomizeSequence(args[1])
	if err != nil {
		return nil, err
	}

	if len(searchAtoms) != 1 {
		return nil, &xdm.Error{Code: lexicon.ErrXPTY0004, Message: "index-of: search value must be exactly one atomic item"}
	}

	search := searchAtoms[0]
	// Explicit 3rd arg with empty sequence is a type error (xs:string, not xs:string?)
	if len(args) > 2 && xdm.SequenceLen(args[2]) == 0 {
		return nil, &xdm.Error{Code: lexicon.ErrXPTY0004, Message: "collation argument must not be empty"}
	}
	// Resolve collation: explicit 3rd arg, or default collation
	coll, err := getCollation(ctx, args, 2)
	if err != nil {
		return nil, err
	}
	// codepointCollation is the default — treat as nil for fast path
	if coll.isCodepoint() {
		coll = nil
	}
	// Per spec: untypedAtomic values are cast to xs:string for comparison
	if search.TypeName == xdm.TypeUntypedAtomic {
		search = xdm.AtomicValue{TypeName: xdm.TypeString, Value: search.StringVal()}
	}

	// Atomize sequence to handle arrays (XPath 3.1: atomizing flattens arrays)
	atoms, err := AtomizeSequence(args[0])
	if err != nil {
		return nil, err
	}

	var result xdm.ItemSlice

	for i, a := range atoms {
		if a.TypeName == xdm.TypeUntypedAtomic {
			a = xdm.AtomicValue{TypeName: xdm.TypeString, Value: a.StringVal()}
		}

		var eq bool
		if coll != nil && xdm.IsStringDerived(a.TypeName) && xdm.IsStringDerived(search.TypeName) {
			eq = coll.compare(a.StringVal(), search.StringVal()) == 0
		} else {
			matched, cmpErr := compareAtomic(TokenEq, a, search)
			if cmpErr != nil {
				continue // incomparable types are silently skipped
			}

			eq = matched
		}

		if eq {
			result = append(result, xdm.AtomicValue{TypeName: xdm.TypeInteger, Value: big.NewInt(int64(i + 1))})
		}
	}

	return result, nil
}

func fnLast(ctx context.Context, _ []xdm.Sequence) (xdm.Sequence, error) {
	fc := getFnContext(ctx)
	if fc == nil || (fc.node == nil && fc.contextItem == nil) {
		return nil, &xdm.Error{Code: lexicon.ErrXPDY0002, Message: "last() requires a focus (context item)"}
	}

	return xdm.SingleInteger(int64(fc.size)), nil
}

func fnPosition(ctx context.Context, _ []xdm.Sequence) (xdm.Sequence, error) {
	fc := getFnContext(ctx)
	if fc == nil || (fc.node == nil && fc.contextItem == nil) {
		return nil, &xdm.Error{Code: lexicon.ErrXPDY0002, Message: "position() requires a focus (context item)"}
	}

	return xdm.SingleInteger(int64(fc.position)), nil
}

// fnSort implements fn:sort($input [, $collation [, $key]])
func fnSort(ctx context.Context, args []xdm.Sequence) (xdm.Sequence, error) {
	input := args[0]

	coll, err := sortCollation(ctx, args)
	if err != nil {
		return nil, err
	}

	keyFn, err := sortKeyFunction(args)
	if err != nil {
		return nil, err
	}

	pairs, err := sequenceSortPairs(ctx, input, keyFn)
	if err != nil {
		return nil, err
	}

	var sortErr error

	sort.SliceStable(pairs, func(i, j int) bool {
		if sortErr != nil {
			return false
		}

		var less bool

		less, sortErr = sequenceSortKeyLess(ctx, pairs[i].key, pairs[j].key, coll)

		return less
	})

	if sortErr != nil {
		return nil, sortErr
	}

	result := make(xdm.ItemSlice, len(pairs))
	for i, pair := range pairs {
		result[i] = pair.item
	}

	return result, nil
}

func sortCollation(ctx context.Context, args []xdm.Sequence) (*collationImpl, error) {
	return getCollation(ctx, args, 1)
}

func sortKeyFunction(args []xdm.Sequence) (*xdm.FunctionItem, error) {
	if len(args) < 3 || xdm.SequenceLen(args[2]) == 0 {
		return nil, nil
	}

	keyFn, err := extractFunctionItem(args[2])
	if err != nil {
		return nil, err
	}

	return &keyFn, nil
}

type sequenceSortPair struct {
	item xdm.Item
	key  xdm.Sequence
}

func sequenceSortPairs(ctx context.Context, input xdm.Sequence, keyFn *xdm.FunctionItem) ([]sequenceSortPair, error) {
	items := xdm.Materialize(input)

	pairs := make([]sequenceSortPair, len(items))
	for i, item := range items {
		key, err := sequenceSortKey(ctx, item, keyFn)
		if err != nil {
			return nil, err
		}

		pairs[i] = sequenceSortPair{item: item, key: key}
	}

	return pairs, nil
}

func sequenceSortKey(ctx context.Context, item xdm.Item, keyFn *xdm.FunctionItem) (xdm.Sequence, error) {
	var value xdm.Sequence = xdm.ItemSlice{item}

	if keyFn != nil {
		var err error

		value, err = keyFn.Invoke(ctx, []xdm.Sequence{value})
		if err != nil {
			return nil, err
		}
	}

	return atomizedSortKey(value)
}

func atomizedSortKey(value xdm.Sequence) (xdm.Sequence, error) {
	// Both default and application keys are atomized, including for a singleton
	// input whose key is never visited by the sorting comparator.
	atoms, err := AtomizeSequence(value)
	if err != nil {
		return nil, err
	}

	key := make(xdm.ItemSlice, len(atoms))
	for i, atom := range atoms {
		key[i] = atom
	}

	return key, nil
}

func sequenceSortKeyLess(ctx context.Context, a, b xdm.Sequence, coll *collationImpl) (bool, error) {
	var implicitTZ *time.Location
	if fc := getFnContext(ctx); fc != nil {
		implicitTZ = fc.implicitTimezone
	}

	for i := range min(xdm.SequenceLen(a), xdm.SequenceLen(b)) {
		av, aErr := AtomizeItem(a.Get(i))

		bv, bErr := AtomizeItem(b.Get(i))

		if aErr != nil {
			return false, aErr
		}

		if bErr != nil {
			return false, bErr
		}

		if av.IsNumeric() && bv.IsNumeric() {
			aNaN, bNaN := math.IsNaN(av.ToFloat64()), math.IsNaN(bv.ToFloat64())
			if aNaN && bNaN {
				continue
			}

			if aNaN || bNaN {
				return aNaN, nil
			}
		}

		order, err := valueCompareThreeWayWithImplicitTimezone(av, bv, coll, implicitTZ)
		if err != nil {
			return false, err
		}

		if order != 0 {
			return order < 0, nil
		}
	}

	// Equal common prefixes sort by key length.
	return xdm.SequenceLen(a) < xdm.SequenceLen(b), nil
}

func fnFlatten(_ context.Context, args []xdm.Sequence) (xdm.Sequence, error) {
	var result xdm.ItemSlice
	flattenItems(args[0], &result)

	return result, nil
}

func flattenItems(seq xdm.Sequence, result *xdm.ItemSlice) {
	for item := range xdm.SequenceItems(seq) {
		if arr, ok := item.(xdm.ArrayItem); ok {
			for _, m := range arr.MembersView() {
				flattenItems(m, result)
			}
		} else {
			*result = append(*result, item)
		}
	}
}
