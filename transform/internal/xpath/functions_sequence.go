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

func fnTail(ctx context.Context, args []xdm.Sequence) (xdm.Sequence, error) {
	if xdm.SequenceLen(args[0]) <= 1 {
		return nil, nil
	}

	result, err := appendIndexedSequence(ctx, getFnContext(ctx), nil, args[0], 1, args[0].Len())
	if err != nil {
		return nil, err
	}

	return result, nil
}

func fnInsertBefore(ctx context.Context, args []xdm.Sequence) (xdm.Sequence, error) {
	posVal, err := coerceArgToInteger(ctx, args[1])
	if err != nil {
		return nil, err
	}

	target, inserts := args[0], args[2]
	n := xdm.SequenceLen(target)
	ec := getFnContext(ctx)

	if n > fnMaxNodes(ec) || xdm.SequenceLen(inserts) > fnMaxNodes(ec)-n {
		return nil, ErrNodeSetLimit
	}

	// Clamp before converting to int, without overflowing n+1 at MaxInt.
	pos := 0
	if posVal > int64(n) {
		pos = n
	} else if posVal > 1 {
		pos = int(posVal) - 1
	}

	result, err := appendIndexedSequence(ctx, ec, nil, target, 0, pos)
	if err != nil {
		return nil, err
	}

	result, err = appendIndexedSequence(ctx, ec, result, inserts, 0, xdm.SequenceLen(inserts))
	if err != nil {
		return nil, err
	}

	result, err = appendIndexedSequence(ctx, ec, result, target, pos, n)
	if err != nil {
		return nil, err
	}

	return result, nil
}

func fnRemove(ctx context.Context, args []xdm.Sequence) (xdm.Sequence, error) {
	posVal, err := coerceArgToInteger(ctx, args[1])
	if err != nil {
		return nil, err
	}

	target := args[0]
	n := xdm.SequenceLen(target)

	if posVal < 1 || posVal > int64(n) {
		return target, nil
	}

	ec := getFnContext(ctx)

	if n-1 > fnMaxNodes(ec) {
		return nil, ErrNodeSetLimit
	}

	pos := int(posVal) - 1

	result, err := appendIndexedSequence(ctx, ec, nil, target, 0, pos)
	if err != nil {
		return nil, err
	}

	result, err = appendIndexedSequence(ctx, ec, result, target, pos+1, n)
	if err != nil {
		return nil, err
	}

	return result, nil
}

func fnReverse(ctx context.Context, args []xdm.Sequence) (xdm.Sequence, error) {
	seq := args[0]
	n := xdm.SequenceLen(seq)
	ec := getFnContext(ctx)

	if n > fnMaxNodes(ec) {
		return nil, ErrNodeSetLimit
	}

	var result xdm.ItemSlice

	for i := n - 1; i >= 0; i-- {
		if err := fnCountOp(ctx, ec); err != nil {
			return nil, err
		}

		result = append(result, seq.Get(i))
	}

	return result, nil
}

// appendIndexedSequence visits only the selected items, checking work and size
// before accessing or appending each item. It never materializes its input.
func appendIndexedSequence(ctx context.Context, ec *evalContext, result xdm.ItemSlice, seq xdm.Sequence, first, last int) (xdm.ItemSlice, error) {
	if last-first > fnMaxNodes(ec)-len(result) {
		return nil, ErrNodeSetLimit
	}

	for i := first; i < last; i++ {
		if err := fnCountOp(ctx, ec); err != nil {
			return nil, err
		}

		result = append(result, seq.Get(i))
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

	return collectSubsequence(ctx, args[0], start, end, bounded)
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

// collectSubsequence uses the indexed Sequence contract to avoid visiting the
// skipped prefix of a lazy range. Searching with the original position
// comparison preserves float64 rounding even when a sequence length exceeds
// the integers exactly representable by a double.
func collectSubsequence(ctx context.Context, seq xdm.Sequence, start, end float64, bounded bool) (xdm.Sequence, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	n := xdm.SequenceLen(seq)
	first := sort.Search(n, func(i int) bool { return float64(i+1) >= start })
	last := n

	if bounded {
		last = sort.Search(n, func(i int) bool { return float64(i+1) >= end })
	}

	result, err := appendIndexedSequence(ctx, getFnContext(ctx), nil, seq, first, last)
	if err != nil {
		return nil, err
	}

	return result, nil
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
	ctx        context.Context
	ec         *evalContext
	depth      int
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

	opts := deepEqualOptions{coll: coll, ctx: ctx, ec: getFnContext(ctx)}
	if ec := getFnContext(ctx); ec != nil {
		opts.implicitTZ = ec.getImplicitTimezone()
	}

	eq, err := deepEqualSequence(args[0], args[1], opts)
	if err != nil {
		return nil, err
	}

	return xdm.SingleBoolean(eq), nil
}

func (opts deepEqualOptions) descend() (deepEqualOptions, error) {
	opts.depth++
	if opts.depth > DepthLimit(opts.ctx, 128) {
		return opts, ErrRecursionLimit
	}

	return opts, fnCountOp(opts.ctx, opts.ec)
}

func deepEqualSequence(a, b xdm.Sequence, opts deepEqualOptions) (bool, error) {
	if xdm.SequenceLen(a) != xdm.SequenceLen(b) {
		return false, nil
	}

	for i := range xdm.SequenceLen(a) {
		if err := fnCountOp(opts.ctx, opts.ec); err != nil {
			return false, err
		}

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
	if _, function := a.(xdm.FunctionItem); function {
		return false, &xdm.Error{Code: "FOTY0015", Message: "deep-equal: cannot compare function items"}
	}

	if _, function := b.(xdm.FunctionItem); function {
		return false, &xdm.Error{Code: "FOTY0015", Message: "deep-equal: cannot compare function items"}
	}

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

		return deepEqualNode(av.Node, bv.Node, opts)
	case xdm.MapItem:
		bv, ok := b.(xdm.MapItem)
		if !ok {
			return false, nil
		}

		nested, err := opts.descend()
		if err != nil {
			return false, err
		}

		return deepEqualMap(av, bv, nested)
	case xdm.ArrayItem:
		bv, ok := b.(xdm.ArrayItem)
		if !ok {
			return false, nil
		}

		nested, err := opts.descend()
		if err != nil {
			return false, err
		}

		return deepEqualArray(av, bv, nested)
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

func deepEqualNode(a, b xdm.Node, opts deepEqualOptions) (bool, error) {
	if deepEqualNodeKind(a) != deepEqualNodeKind(b) {
		return false, nil
	}

	var err error

	opts, err = opts.descend()
	if err != nil {
		return false, err
	}

	switch a.Type() {
	case xdm.DocumentNode:
		return deepEqualChildren(a, b, opts)
	case xdm.ElementNode:
		return deepEqualElementNodes(a, b, opts)
	case xdm.AttributeNode:
		aa, aOK := a.(*xdm.Attribute)
		ba, bOK := b.(*xdm.Attribute)

		return aOK && bOK && deepEqualAttribute(aa, ba, opts), nil
	case xdm.NamespaceNode, xdm.ProcessingInstructionNode:
		return a.Name() == b.Name() && xdm.CharacterData(a) == xdm.CharacterData(b), nil
	case xdm.TextNode, xdm.CDATASectionNode:
		return opts.stringsEqual(xdm.CharacterData(a), xdm.CharacterData(b)), nil
	case xdm.CommentNode:
		return xdm.CharacterData(a) == xdm.CharacterData(b), nil
	default:
		return false, nil
	}
}

func deepEqualNodeKind(node xdm.Node) xdm.ElementType {
	if node.Type() == xdm.CDATASectionNode {
		return xdm.TextNode
	}

	return node.Type()
}

func deepEqualElementNodes(a, b xdm.Node, opts deepEqualOptions) (bool, error) {
	ae, aOK := a.(*xdm.Element)
	be, bOK := b.(*xdm.Element)

	if !aOK || !bOK || ae.LocalName() != be.LocalName() || ae.URI() != be.URI() {
		return false, nil
	}

	equal, err := deepEqualAttributes(ae, be, opts)
	if err != nil || !equal {
		return false, err
	}

	return deepEqualChildren(a, b, opts)
}

func deepEqualAttributes(a, b *xdm.Element, opts deepEqualOptions) (bool, error) {
	if a.AttributeCount() != b.AttributeCount() {
		return false, nil
	}
	// Walk stored expanded names and normalized values directly: Attributes
	// would allocate both complete view slices, and Attribute.Value would
	// rescan the owner's raw attributes for each ordinary value.
	type name struct{ local, uri string }

	byName := make(map[name]string)

	var walkErr error

	b.ForEachAttributeValue(func(local, uri, value string) bool {
		if walkErr = fnCountOp(opts.ctx, opts.ec); walkErr != nil {
			return false
		}

		key := name{local, uri}
		if _, exists := byName[key]; !exists {
			byName[key] = value
		}

		return true
	})

	if walkErr != nil {
		return false, walkErr
	}

	equal := true

	a.ForEachAttributeValue(func(local, uri, value string) bool {
		if walkErr = fnCountOp(opts.ctx, opts.ec); walkErr != nil {
			return false
		}

		match, found := byName[name{local, uri}]
		equal = found && opts.stringsEqual(value, match)

		return equal
	})

	return equal, walkErr
}

func deepEqualAttribute(a, b *xdm.Attribute, opts deepEqualOptions) bool {
	return a.LocalName() == b.LocalName() && a.URI() == b.URI() && opts.stringsEqual(a.Value(), b.Value())
}

func deepEqualChildren(a, b xdm.Node, opts deepEqualOptions) (bool, error) {
	ac, err := nextDeepEqualChild(a.FirstChild(), opts)
	if err != nil {
		return false, err
	}

	bc, err := nextDeepEqualChild(b.FirstChild(), opts)
	if err != nil {
		return false, err
	}

	for ac != nil && bc != nil {
		equal, err := deepEqualNode(ac, bc, opts)
		if err != nil || !equal {
			return false, err
		}

		ac, err = nextDeepEqualChild(ac.NextSibling(), opts)
		if err != nil {
			return false, err
		}

		bc, err = nextDeepEqualChild(bc.NextSibling(), opts)
		if err != nil {
			return false, err
		}
	}

	return ac == nil && bc == nil, nil
}

func nextDeepEqualChild(node xdm.Node, opts deepEqualOptions) (xdm.Node, error) {
	for node != nil {
		if err := fnCountOp(opts.ctx, opts.ec); err != nil {
			return nil, err
		}

		switch node.Type() {
		case xdm.ElementNode, xdm.TextNode, xdm.CDATASectionNode:
			return node, nil
		}

		node = node.NextSibling()
	}

	return nil, nil
}

func deepEqualMap(a, b xdm.MapItem, opts deepEqualOptions) (bool, error) {
	if a.Size() != b.Size() {
		return false, nil
	}
	// KeysView copies the key list; charge that work before allocating it.
	if err := fnCountOps(opts.ctx, opts.ec, a.Size()); err != nil {
		return false, err
	}

	for _, key := range a.KeysView() {
		if err := fnCountOp(opts.ctx, opts.ec); err != nil {
			return false, err
		}

		bv, found := b.GetView(key)
		if !found {
			return false, nil
		}

		av, _ := a.GetView(key)

		equal, err := deepEqualSequence(av, bv, opts)
		if err != nil || !equal {
			return false, err
		}
	}

	return true, nil
}

func deepEqualArray(a, b xdm.ArrayItem, opts deepEqualOptions) (bool, error) {
	am0, bm0 := a.MembersView(), b.MembersView()
	if len(am0) != len(bm0) {
		return false, nil
	}

	for i := range am0 {
		if err := fnCountOp(opts.ctx, opts.ec); err != nil {
			return false, err
		}

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
	searchAtoms, err := FnAtomize(ctx, args[1])
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
	atoms, err := FnAtomize(ctx, args[0])
	if err != nil {
		return nil, err
	}

	var result xdm.ItemSlice

	for i, a := range atoms {
		if err := fnCountOp(ctx, getFnContext(ctx)); err != nil {
			return nil, err
		}

		if a.TypeName == xdm.TypeUntypedAtomic {
			a = xdm.AtomicValue{TypeName: xdm.TypeString, Value: a.StringVal()}
		}

		eq, cmpErr := compareAtomicInContext(TokenEq, a, search, coll, getFnContext(ctx))
		if cmpErr != nil {
			continue // incomparable types are silently skipped
		}

		if eq {
			result = append(result, xdm.AtomicValue{TypeName: xdm.TypeInteger, Value: big.NewInt(int64(i + 1))})
		}
	}

	return result, nil
}

func fnLast(ctx context.Context, _ []xdm.Sequence) (xdm.Sequence, error) {
	fc := getFnContext(ctx)
	if fc == nil || (fc.node == nil && fc.contextItem == nil) || fc.size <= 0 {
		return nil, &xdm.Error{Code: lexicon.ErrXPDY0002, Message: "last() requires a context size"}
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

	if err := stableSortWithError(pairs, func(i, j int) (bool, error) {
		return sequenceSortKeyLess(ctx, pairs[i].key, pairs[j].key, coll)
	}); err != nil {
		return nil, err
	}

	if err := fnCountOps(ctx, getFnContext(ctx), len(pairs)); err != nil {
		return nil, err
	}

	result := make(xdm.ItemSlice, len(pairs))

	for i, pair := range pairs {
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		result[i] = pair.item
	}

	return result, nil
}

// stableSortWithError keeps the standard stable algorithm but stops immediately
// when its comparator fails. Only this invocation's private sentinel is caught;
// panics from the comparator or the sort itself propagate unchanged.
func stableSortWithError(items any, less func(int, int) (bool, error)) (err error) {
	var failure sequenceSortFailure

	defer func() {
		if stopped := recover(); stopped != nil {
			if stopped == &failure {
				err = failure.err
				return
			}

			panic(stopped)
		}
	}()

	sort.SliceStable(items, func(i, j int) bool {
		value, compareErr := less(i, j)
		if compareErr != nil {
			failure.err = compareErr
			panic(&failure)
		}

		return value
	})

	return nil
}

type sequenceSortFailure struct{ err error }

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
	n := xdm.SequenceLen(input)
	ec := getFnContext(ctx)

	if n > fnMaxNodes(ec) {
		return nil, ErrNodeSetLimit
	}

	var pairs []sequenceSortPair

	for i := range n {
		if err := fnCountOp(ctx, ec); err != nil {
			return nil, err
		}

		item := input.Get(i)

		key, err := sequenceSortKey(ctx, item, keyFn)
		if err != nil {
			return nil, err
		}

		pairs = append(pairs, sequenceSortPair{item: item, key: key})
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

	return atomizedSortKey(ctx, value)
}

func atomizedSortKey(ctx context.Context, value xdm.Sequence) (xdm.Sequence, error) {
	// Both default and application keys are atomized, including for a singleton
	// input whose key is never visited by the sorting comparator.
	atoms, err := FnAtomize(ctx, value)
	if err != nil {
		return nil, err
	}

	if err := fnCountOps(ctx, getFnContext(ctx), len(atoms)); err != nil {
		return nil, err
	}

	key := make(xdm.ItemSlice, len(atoms))
	for i, atom := range atoms {
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		key[i] = atom
	}

	return key, nil
}

func sequenceSortKeyLess(ctx context.Context, a, b xdm.Sequence, coll *collationImpl) (bool, error) {
	if err := fnCountOp(ctx, getFnContext(ctx)); err != nil {
		return false, err
	}

	var implicitTZ *time.Location
	if fc := getFnContext(ctx); fc != nil {
		implicitTZ = fc.implicitTimezone
	}

	for i := range min(xdm.SequenceLen(a), xdm.SequenceLen(b)) {
		if err := fnCountOp(ctx, getFnContext(ctx)); err != nil {
			return false, err
		}

		av, aErr := AtomizeItem(a.Get(i))
		if aErr != nil {
			return false, aErr
		}

		bv, bErr := AtomizeItem(b.Get(i))
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
