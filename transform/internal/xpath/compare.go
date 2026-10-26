// Derived from lestrrat-go/helium at 7362c0a70122a757780f4d0b545a9b370dead6ab.
// Copyright (c) 2015 lestrrat. MIT License; see licenses/MIT-helium.txt at the repository root.

package xpath

import (
	"bytes"
	"context"
	"fmt"
	"math"
	"math/big"
	"slices"
	"strings"
	"time"

	"github.com/skarm/xmlsec/internal/lexicon"
	"github.com/skarm/xmlsec/transform/internal/xdm"
)

// GeneralCompare performs a general comparison between two sequences.
// Atomizes both sides and returns true if any pair of atomic values
// satisfies the operator.
func GeneralCompare(op TokenType, left, right xdm.Sequence) (bool, error) {
	return generalCompareWithCollation(context.Background(), op, left, right, nil, nil)
}

// ValueCompare performs a value comparison between two atomic values.
func ValueCompare(op TokenType, a, b xdm.AtomicValue) (bool, error) {
	return ValueCompareWithImplicitTimezone(op, a, b, nil)
}

// ValueCompareWithImplicitTimezone compares two atomic values after XPath
// value-comparison promotion, using implicitTZ for values without a timezone.
func ValueCompareWithImplicitTimezone(op TokenType, a, b xdm.AtomicValue, implicitTZ *time.Location) (bool, error) {
	pa, pb := promoteForValueComparison(a, b)
	return compareAtomicWithImplicitTimezone(op, pa, pb, implicitTZ)
}

// AtomicEquals tests two atomic values for equality using XPath value
// comparison (eq) semantics, including untypedAtomic promotion.
// Returns false when the types are not comparable (instead of an error),
// making it suitable for key() lookup where type mismatches mean "no match".
func AtomicEquals(a, b xdm.AtomicValue) bool {
	result, err := ValueCompare(TokenEq, a, b)
	if err != nil {
		return false
	}

	return result
}

// TimeToReferenceDateTime converts an xs:time to an xs:dateTime using the
// XPath reference date 1972-12-31, preserving the timezone offset.
// This is the canonical conversion for comparing xs:time values per F&O §10.4.4.
func TimeToReferenceDateTime(t time.Time) time.Time {
	return timeToReferenceDateTime(t)
}

// ApplyImplicitTZ applies the implicit timezone to a time that has
// no explicit timezone. Times with explicit timezones are returned as-is.
func ApplyImplicitTZ(t time.Time, implicitTZ *time.Location) time.Time {
	return applyImplicitTZ(t, implicitTZ)
}

// generalCompareWithCollation is the collation-aware implementation of
// general comparison.  When coll is nil, codepoint collation is used.
//
// The existential left x right scan is O(N*M), so it charges one op (and honors
// context cancellation) per candidate pair via fnCountOp. A comparison over two
// large sequences therefore respects OpLimit / context cancellation instead of
// running to completion unbounded and uncancellable.
func generalCompareWithCollation(ctx context.Context, op TokenType, left, right xdm.Sequence, coll *collationImpl, ec *evalContext) (bool, error) {
	leftIter := newAtomicSequenceIter(left)
	rightAtoms := newCachedAtomicSequence(right)

	for {
		la, ok, err := leftIter.Next()
		if err != nil {
			return false, err
		}

		if !ok {
			return false, nil
		}

		for i := 0; ; i++ {
			if err := fnCountOp(ctx, ec); err != nil {
				return false, err
			}

			ra, ok, err := rightAtoms.At(i)
			if err != nil {
				return false, err
			}

			if !ok {
				break
			}

			pa, pb, err := promoteForGeneralComparison(ctx, la, ra, ec)
			if err != nil {
				return false, err
			}

			match, err := compareAtomicInContext(op, pa, pb, coll, ec)
			if err != nil {
				return false, err
			}

			if match {
				return true, nil
			}
		}
	}
}

// promoteForGeneralComparison applies type promotion rules for general comparison (= != < > <= >=).
// Per XPath 3.1 Section 3.7.1 — untypedAtomic is cast to the type of the other operand.
func promoteForGeneralComparison(ctx context.Context, a, b xdm.AtomicValue, ec *evalContext) (xdm.AtomicValue, xdm.AtomicValue, error) {
	// untypedAtomic vs untypedAtomic → compare as string
	if a.TypeName == xdm.TypeUntypedAtomic && b.TypeName == xdm.TypeUntypedAtomic {
		return xdm.AtomicValue{TypeName: xdm.TypeString, Value: stringFromAtomic(a)},
			xdm.AtomicValue{TypeName: xdm.TypeString, Value: stringFromAtomic(b)}, nil
	}
	// untypedAtomic vs typed → cast untypedAtomic to the other's type
	if a.TypeName == xdm.TypeUntypedAtomic {
		castA, err := castUntypedToType(ctx, a, b.TypeName, ec)
		if err != nil {
			return xdm.AtomicValue{}, xdm.AtomicValue{}, err
		}

		return castA, b, nil
	}

	if b.TypeName == xdm.TypeUntypedAtomic {
		castB, err := castUntypedToType(ctx, b, a.TypeName, ec)
		if err != nil {
			return xdm.AtomicValue{}, xdm.AtomicValue{}, err
		}

		return a, castB, nil
	}

	return a, b, nil
}

// castUntypedToType casts an untypedAtomic value to the given target type.
// For general comparison, cast failures are errors (not silently ignored).
func castUntypedToType(ctx context.Context, untyped xdm.AtomicValue, targetType string, ec *evalContext) (xdm.AtomicValue, error) {
	// QName requires namespace context for prefix resolution
	if targetType == xdm.TypeQName {
		return castToQName(untyped, ec)
	}
	// For numeric types, cast to double per spec
	if xdm.IsIntegerDerived(targetType) || targetType == xdm.TypeDecimal || targetType == xdm.TypeFloat {
		targetType = xdm.TypeDouble
	}
	// String-derived types: cast to string for comparison
	if xdm.IsStringDerived(targetType) {
		targetType = xdm.TypeString
	}

	if ec != nil && ec.schemaDeclarations != nil {
		return schemaAwareCast(ctx, ec, untyped, targetType)
	}

	return CastFromStringContext(ctx, stringFromAtomic(untyped), targetType)
}

// Binary ordering operators were introduced by F&O 3.1; earlier editions
// define binary equality alone. Keep this check at the language evaluation
// boundary because exported atomic helpers use the current operator library.
func validateComparisonEdition(op TokenType, a, b xdm.AtomicValue, ec *evalContext) error {
	if ec == nil || ec.version == 0 || ec.version >= 31 {
		return nil
	}

	op = normalizeCompareOp(op)
	if op == TokenEq || op == TokenNe {
		return nil
	}

	for _, value := range []xdm.AtomicValue{a, b} {
		value = promoteSchemaForCompare(value)
		if value.TypeName == xdm.TypeHexBinary || value.TypeName == xdm.TypeBase64Binary {
			return &xdm.Error{Code: lexicon.ErrXPTY0004, Message: "binary ordering requires XPath 3.1"}
		}
	}

	return nil
}

func compareAtomicInContext(op TokenType, a, b xdm.AtomicValue, coll *collationImpl, ec *evalContext) (bool, error) {
	if err := validateComparisonEdition(op, a, b, ec); err != nil {
		return false, err
	}

	var implicitTZ *time.Location
	if ec != nil {
		implicitTZ = ec.getImplicitTimezone()
	}

	return compareAtomicCollation(op, a, b, implicitTZ, coll)
}

// compareAtomicCollation compares two atomic values using the given collation
// for string comparisons.  When coll is nil, codepoint collation is used.
func compareAtomicCollation(op TokenType, a, b xdm.AtomicValue, implicitTZ *time.Location, coll *collationImpl) (bool, error) {
	if coll == nil {
		return compareAtomicWithImplicitTimezone(op, a, b, implicitTZ)
	}
	// Normalize the operator
	op = normalizeCompareOp(op)

	// String comparison with collation
	aStr := xdm.IsStringDerived(a.TypeName) || a.TypeName == xdm.TypeAnyURI

	bStr := xdm.IsStringDerived(b.TypeName) || b.TypeName == xdm.TypeAnyURI
	if aStr && bStr {
		sa := stringFromAtomic(a)
		sb := stringFromAtomic(b)
		cmp := coll.compare(sa, sb)

		return applyCompare(op, cmp), nil
	}

	// For non-string types, collation doesn't apply — delegate to the
	// standard comparison which handles numerics, dates, etc.
	return compareAtomicWithImplicitTimezone(op, a, b, implicitTZ)
}

// promoteForValueComparison applies type promotion rules for value comparison (eq/ne/lt/gt/le/ge).
// Per XPath 3.1 Section 3.7.2: xs:untypedAtomic is always cast to xs:string.
// This differs from general comparison where untypedAtomic is cast to the other operand's type.
func promoteForValueComparison(a, b xdm.AtomicValue) (xdm.AtomicValue, xdm.AtomicValue) {
	if a.TypeName == xdm.TypeUntypedAtomic {
		a = xdm.AtomicValue{TypeName: xdm.TypeString, Value: stringFromAtomic(a)}
	}

	if b.TypeName == xdm.TypeUntypedAtomic {
		b = xdm.AtomicValue{TypeName: xdm.TypeString, Value: stringFromAtomic(b)}
	}

	return a, b
}

// evalGeneralComparison implements general comparison (= != < <= > >=).
// Per XPath 3.1 Section 3.7.1: atomize both operands, then existentially
// quantify — true if ANY pair satisfies the value comparison.
func evalGeneralComparison(evalFn exprEvaluator, ctx context.Context, ec *evalContext, e BinaryExpr) (xdm.Sequence, error) {
	// The X = (M to N) range fast-path assumes ordinary comparison semantics; in
	// XPath 1.0 compatibility mode the operands are converted (boolean/numeric/
	// string rules), so route through the general path instead.
	if !ec.xpath10CompatMode() {
		if result, ok, err := evalGeneralComparisonAgainstRange(evalFn, ctx, ec, e); ok {
			if err != nil {
				return nil, err
			}

			return xdm.SingleBoolean(result), nil
		}
	}

	left, err := evalFn(ctx, ec, e.Left)
	if err != nil {
		return nil, err
	}

	right, err := evalFn(ctx, ec, e.Right)
	if err != nil {
		return nil, err
	}

	coll := ec.resolveDefaultCollation()
	if ec.xpath10CompatMode() {
		result, err := generalCompareXPath10Compat(ctx, e.Op, left, right, coll, ec)
		if err != nil {
			return nil, err
		}

		return xdm.SingleBoolean(result), nil
	}

	result, err := generalCompareWithCollation(ctx, e.Op, left, right, coll, ec)
	if err != nil {
		return nil, err
	}

	return xdm.SingleBoolean(result), nil
}

func evalGeneralComparisonAgainstRange(evalFn exprEvaluator, ctx context.Context, ec *evalContext, e BinaryExpr) (bool, bool, error) {
	if re, ok := e.Right.(RangeExpr); ok {
		return compareSingletonAgainstRange(evalFn, ctx, ec, e.Op, e.Left, re, false)
	}

	if re, ok := e.Left.(RangeExpr); ok {
		return compareSingletonAgainstRange(evalFn, ctx, ec, e.Op, e.Right, re, true)
	}

	return false, false, nil
}

func compareSingletonAgainstRange(evalFn exprEvaluator, ctx context.Context, ec *evalContext, op TokenType, singletonExpr Expr, rangeExpr RangeExpr, rangeOnLeft bool) (bool, bool, error) {
	singletonSeq, err := evalFn(ctx, ec, singletonExpr)
	if err != nil {
		return false, true, err
	}

	if xdm.SequenceLen(singletonSeq) == 0 {
		return false, true, nil
	}
	// Atomize with an early stop (cap 2): the range fast-path only applies when
	// the non-range side is a singleton, so a multi-item or unbounded-lazy operand
	// (e.g. another large range) must be detected WITHOUT materializing/draining
	// the whole sequence. When more than one atom is produced, fall back to the
	// general O(N*M) path, which honors OpLimit / context cancellation.
	singletonAtoms, err := atomizeSingletonOperand(singletonSeq)
	if err != nil {
		return false, true, err
	}

	if len(singletonAtoms) != 1 {
		return false, false, nil
	}

	// An untyped singleton in a general comparison promotes to double, not
	// integer. Leave it to the ordinary path, avoiding an unbounded integer
	// parse merely to decide whether this optimization applies.
	if !xdm.IsIntegerDerived(singletonAtoms[0].TypeName) {
		return false, false, nil
	}

	singletonInt, err := coerceToInteger(ctx, singletonAtoms[0])
	if err != nil {
		return false, false, nil //nolint:nilerr // non-integer subscript means no match
	}

	start, end, empty, err := evalRangeBounds(evalFn, ctx, ec, rangeExpr)
	if err != nil {
		return false, true, err
	}

	if empty {
		return false, true, nil
	}

	sv, sok := singletonInt.Int64Val()
	if sok && start.IsInt64() && end.IsInt64() {
		return compareRangeBoundsInt64(op, sv, start.Int64(), end.Int64(), rangeOnLeft), true, nil
	}

	return compareRangeBounds(op, singletonInt.BigInt(), start, end, rangeOnLeft), true, nil
}

func evalRangeBounds(evalFn exprEvaluator, ctx context.Context, ec *evalContext, e RangeExpr) (*big.Int, *big.Int, bool, error) {
	startSeq, err := evalFn(ctx, ec, e.Start)
	if err != nil {
		return nil, nil, false, err
	}

	endSeq, err := evalFn(ctx, ec, e.End)
	if err != nil {
		return nil, nil, false, err
	}

	if xdm.SequenceLen(startSeq) == 0 || xdm.SequenceLen(endSeq) == 0 {
		return nil, nil, true, nil
	}

	startAtoms, err := AtomizeSequence(startSeq)
	if err != nil {
		return nil, nil, false, err
	}

	endAtoms, err := AtomizeSequence(endSeq)
	if err != nil {
		return nil, nil, false, err
	}

	if len(startAtoms) != 1 || len(endAtoms) != 1 {
		return nil, nil, false, &xdm.Error{Code: lexicon.ErrXPTY0004, Message: "range bounds must be singletons"}
	}

	startInt, err := coerceToInteger(ctx, startAtoms[0])
	if err != nil {
		return nil, nil, false, err
	}

	endInt, err := coerceToInteger(ctx, endAtoms[0])
	if err != nil {
		return nil, nil, false, err
	}

	start := startInt.BigInt()

	end := endInt.BigInt()
	if start.Cmp(end) > 0 {
		return nil, nil, true, nil
	}

	return start, end, false, nil
}

func compareRangeBoundsInt64(op TokenType, singleton, start, end int64, rangeOnLeft bool) bool {
	switch op {
	case TokenEquals:
		return singleton >= start && singleton <= end
	case TokenNotEquals:
		return start != end || singleton != start
	case TokenLess:
		if rangeOnLeft {
			return start < singleton
		}

		return singleton < end
	case TokenLessEq:
		if rangeOnLeft {
			return start <= singleton
		}

		return singleton <= end
	case TokenGreater:
		if rangeOnLeft {
			return end > singleton
		}

		return singleton > start
	case TokenGreaterEq:
		if rangeOnLeft {
			return end >= singleton
		}

		return singleton >= start
	default:
		return false
	}
}

func compareRangeBounds(op TokenType, singleton, start, end *big.Int, rangeOnLeft bool) bool {
	switch op {
	case TokenEquals:
		return singleton.Cmp(start) >= 0 && singleton.Cmp(end) <= 0
	case TokenNotEquals:
		return start.Cmp(end) != 0 || singleton.Cmp(start) != 0
	case TokenLess:
		if rangeOnLeft {
			return start.Cmp(singleton) < 0
		}

		return singleton.Cmp(end) < 0
	case TokenLessEq:
		if rangeOnLeft {
			return start.Cmp(singleton) <= 0
		}

		return singleton.Cmp(end) <= 0
	case TokenGreater:
		if rangeOnLeft {
			return end.Cmp(singleton) > 0
		}

		return singleton.Cmp(start) > 0
	case TokenGreaterEq:
		if rangeOnLeft {
			return end.Cmp(singleton) >= 0
		}

		return singleton.Cmp(start) >= 0
	default:
		return false
	}
}

// evalValueComparison implements value comparison (eq ne lt le gt ge).
// Per XPath 3.1 Section 3.7.2: both operands must be single atomic values.
func evalValueComparison(evalFn exprEvaluator, ctx context.Context, ec *evalContext, e BinaryExpr) (xdm.Sequence, error) {
	left, err := evalFn(ctx, ec, e.Left)
	if err != nil {
		return nil, err
	}

	right, err := evalFn(ctx, ec, e.Right)
	if err != nil {
		return nil, err
	}
	// Atomize operands (handles arrays, nodes, etc.). A value comparison only
	// needs to distinguish empty / one / more-than-one item, so atomize with an
	// early stop: a multi-item (or unbounded lazy) operand is rejected with
	// XPTY0004 below without materializing the whole sequence.
	leftAtoms, err := atomizeSingletonOperand(left)
	if err != nil {
		return nil, err
	}

	rightAtoms, err := atomizeSingletonOperand(right)
	if err != nil {
		return nil, err
	}
	// Empty sequence yields empty sequence
	if len(leftAtoms) == 0 || len(rightAtoms) == 0 {
		return nil, nil
	}

	if len(leftAtoms) > 1 || len(rightAtoms) > 1 {
		return nil, &xdm.Error{Code: lexicon.ErrXPTY0004, Message: "value comparison requires singletons"}
	}

	la := leftAtoms[0]
	ra := rightAtoms[0]
	pa, pb := promoteForValueComparison(la, ra)
	coll := ec.resolveDefaultCollation()

	result, err := compareAtomicInContext(e.Op, pa, pb, coll, ec)
	if err != nil {
		return nil, err
	}

	return xdm.SingleBoolean(result), nil
}

// atomizeSingletonOperand atomizes seq for a value comparison, stopping as soon
// as a second atomic value is produced. Value comparison only needs to tell
// empty / one / more-than-one apart, so a multi-item (or unbounded lazy) operand
// can be detected without materializing the whole sequence. It returns at most
// two atoms; a genuine atomization error (e.g. FOTY0013 for a map/function item
// encountered before the cap) still propagates.
func atomizeSingletonOperand(seq xdm.Sequence) ([]xdm.AtomicValue, error) {
	// Fast path: a single ALREADY-ATOMIC item atomizes to itself, with no streaming
	// machinery — preserving perf on hot numeric paths (arithmetic, range). Arrays
	// (flattened) and schema list/union-typed nodes (expanded) fall through to
	// atomizeStream so their multi-atom typed value is seen.
	if xdm.SequenceLen(seq) == 1 {
		if av, ok := seq.Get(0).(xdm.AtomicValue); ok {
			return []xdm.AtomicValue{av}, nil
		}
	}

	atoms := make([]xdm.AtomicValue, 0, 2)

	err := atomizeStream(seq, func(av xdm.AtomicValue) (bool, error) {
		atoms = append(atoms, av)
		return len(atoms) < 2, nil
	})
	if err != nil {
		return nil, err
	}

	return atoms, nil
}

func evalNodeComparison(evalFn exprEvaluator, ctx context.Context, ec *evalContext, e BinaryExpr) (xdm.Sequence, error) {
	left, err := evalFn(ctx, ec, e.Left)
	if err != nil {
		return nil, err
	}

	right, err := evalFn(ctx, ec, e.Right)
	if err != nil {
		return nil, err
	}
	// Empty sequence yields empty sequence
	if xdm.SequenceLen(left) == 0 || xdm.SequenceLen(right) == 0 {
		return nil, nil
	}

	if left.Len() > 1 || right.Len() > 1 {
		return nil, &xdm.Error{Code: lexicon.ErrXPTY0004, Message: "node comparison requires singletons"}
	}

	ln, ok := left.Get(0).(xdm.NodeItem)
	if !ok {
		return nil, &xdm.Error{Code: lexicon.ErrXPTY0004, Message: "node comparison requires node operands"}
	}

	rn, ok := right.Get(0).(xdm.NodeItem)
	if !ok {
		return nil, &xdm.Error{Code: lexicon.ErrXPTY0004, Message: "node comparison requires node operands"}
	}

	switch e.Op {
	case TokenIs:
		return xdm.SingleBoolean(xdm.SameNode(ln.Node, rn.Node)), nil
	case TokenNodePre:
		ec.docOrder.BuildFrom(ln.Node)
		ec.docOrder.BuildFrom(rn.Node)

		return xdm.SingleBoolean(ec.docOrder.Compare(ln.Node, rn.Node) < 0), nil
	case TokenNodeFol:
		ec.docOrder.BuildFrom(ln.Node)
		ec.docOrder.BuildFrom(rn.Node)

		return xdm.SingleBoolean(ec.docOrder.Compare(ln.Node, rn.Node) > 0), nil
	}

	return nil, fmt.Errorf("%w: %s", ErrUnsupportedBinaryOp, e.Op)
}

type atomicSeqFrame struct {
	seq   xdm.Sequence
	index int
}

type atomicSequenceIter struct {
	stack []atomicSeqFrame
}

func newAtomicSequenceIter(seq xdm.Sequence) *atomicSequenceIter {
	return &atomicSequenceIter{
		stack: []atomicSeqFrame{{seq: seq}},
	}
}

func (it *atomicSequenceIter) Next() (xdm.AtomicValue, bool, error) {
	for len(it.stack) > 0 {
		top := &it.stack[len(it.stack)-1]
		if top.index >= xdm.SequenceLen(top.seq) {
			it.stack = it.stack[:len(it.stack)-1]
			continue
		}

		item := top.seq.Get(top.index)
		top.index++

		expanded, err := it.expandItem(item)
		if err != nil {
			return xdm.AtomicValue{}, false, err
		}

		if expanded {
			continue
		}

		atom, err := AtomizeItem(item)
		if err != nil {
			return xdm.AtomicValue{}, false, err
		}

		return atom, true, nil
	}

	return xdm.AtomicValue{}, false, nil
}

// expandItem pushes arrays and typed multi-atom node values onto the iterator.
func (it *atomicSequenceIter) expandItem(item xdm.Item) (bool, error) {
	switch value := item.(type) {
	case xdm.ArrayItem:
		for _, member := range slices.Backward(value.MembersView()) {
			it.stack = append(it.stack, atomicSeqFrame{seq: member})
		}

		return true, nil
	case xdm.NodeItem:
		return it.expandNode(value)
	default:
		return false, nil
	}
}

func (it *atomicSequenceIter) expandNode(node xdm.NodeItem) (bool, error) {
	if listItem := nodeListItemType(node); listItem != "" {
		items, err := atomizeListNodeSequence(node, listItem)
		if err != nil {
			return false, err
		}

		it.stack = append(it.stack, atomicSeqFrame{seq: items})

		return true, nil
	}

	if node.ActiveUnionMember == nil {
		return false, nil
	}

	atoms, handled := atomizeUnionItems(node)
	if !handled {
		return false, nil
	}

	items := make(xdm.ItemSlice, len(atoms))
	for i, atom := range atoms {
		items[i] = atom
	}

	it.stack = append(it.stack, atomicSeqFrame{seq: items})

	return true, nil
}

func atomizeListNodeSequence(node xdm.NodeItem, listItem string) (xdm.Sequence, error) {
	tokens := xsdListFields(xdm.StringValue(node.Node))
	items := make(xdm.ItemSlice, len(tokens))
	// A typed list is converted in full before its first atom is yielded.
	for i, token := range tokens {
		atom, err := atomizeListTokenAt(i, token, listItem, node)
		if err != nil {
			return nil, err
		}

		items[i] = atom
	}

	return items, nil
}

type cachedAtomicSequence struct {
	iter      *atomicSequenceIter
	cache     []xdm.AtomicValue
	exhausted bool
}

func newCachedAtomicSequence(seq xdm.Sequence) *cachedAtomicSequence {
	return &cachedAtomicSequence{iter: newAtomicSequenceIter(seq)}
}

func (s *cachedAtomicSequence) At(idx int) (xdm.AtomicValue, bool, error) {
	for len(s.cache) <= idx && !s.exhausted {
		atom, ok, err := s.iter.Next()
		if err != nil {
			return xdm.AtomicValue{}, false, err
		}

		if !ok {
			s.exhausted = true
			break
		}

		s.cache = append(s.cache, atom)
	}

	if idx < len(s.cache) {
		return s.cache[idx], true, nil
	}

	return xdm.AtomicValue{}, false, nil
}

// valueCompareThreeWayWithImplicitTimezone compares atomics using the selected
// collation and invocation timezone.
func valueCompareThreeWayWithImplicitTimezone(a, b xdm.AtomicValue, coll *collationImpl, implicitTZ *time.Location) (int, error) {
	pa, pb := promoteForValueComparison(a, b)

	// If both are strings and a collation is provided, use it
	aStr := xdm.IsStringDerived(pa.TypeName) || pa.TypeName == xdm.TypeAnyURI

	bStr := xdm.IsStringDerived(pb.TypeName) || pb.TypeName == xdm.TypeAnyURI
	if aStr && bStr && coll != nil {
		sa := stringFromAtomic(pa)
		sb := stringFromAtomic(pb)

		return coll.compare(sa, sb), nil
	}

	// Fall back to standard comparison
	less, err := compareAtomicWithImplicitTimezone(TokenLt, pa, pb, implicitTZ)
	if err != nil {
		return 0, err
	}

	if less {
		return -1, nil
	}

	greater, err := compareAtomicWithImplicitTimezone(TokenGt, pa, pb, implicitTZ)
	if err != nil {
		return 0, err
	}

	if greater {
		return 1, nil
	}

	return 0, nil
}

func comparisonFamily(typeName string) string {
	if xdm.IsIntegerDerived(typeName) {
		return xdm.FamilyNumeric
	}

	switch typeName {
	case xdm.TypeDecimal, xdm.TypeDouble, xdm.TypeFloat:
		return xdm.FamilyNumeric
	case xdm.TypeString, xdm.TypeAnyURI:
		return lexicon.TypeString
	case xdm.TypeBoolean:
		return lexicon.TypeBoolean
	case xdm.TypeDate:
		return lexicon.TypeDate
	case xdm.TypeDateTime:
		return lexicon.TypeDateTime
	case xdm.TypeTime:
		return lexicon.TypeTime
	case xdm.TypeDuration:
		return lexicon.TypeDuration
	case xdm.TypeYearMonthDuration:
		return "duration:YM"
	case xdm.TypeDayTimeDuration:
		return "duration:DT"
	case xdm.TypeBase64Binary:
		return lexicon.TypeBase64Binary
	case xdm.TypeHexBinary:
		return lexicon.TypeHexBinary
	case xdm.TypeQName:
		return lexicon.TypeQName
	case xdm.TypeGDay:
		return lexicon.TypeGDay
	case xdm.TypeGMonth:
		return lexicon.TypeGMonth
	case xdm.TypeGMonthDay:
		return lexicon.TypeGMonthDay
	case xdm.TypeGYear:
		return lexicon.TypeGYear
	case xdm.TypeGYearMonth:
		return lexicon.TypeGYearMonth
	}

	return ""
}

func stringFromAtomic(a xdm.AtomicValue) string {
	if s, ok := a.Value.(string); ok {
		return s
	}

	s, _ := atomicToString(a)

	return s
}

// coerceTimePair safely extracts time.Time from two AtomicValues,
// handling the case where the value is stored as a string by re-parsing.
func coerceTimePair(a, b xdm.AtomicValue) (time.Time, time.Time, error) {
	ta, err := coerceToTime(a)
	if err != nil {
		return time.Time{}, time.Time{}, err
	}

	tb, err := coerceToTime(b)
	if err != nil {
		return time.Time{}, time.Time{}, err
	}

	return ta, tb, nil
}

func coerceToTime(v xdm.AtomicValue) (time.Time, error) {
	if t, ok := v.Value.(time.Time); ok {
		return t, nil
	}
	// Value stored as string — re-parse
	if s, ok := v.Value.(string); ok {
		switch v.TypeName {
		case xdm.TypeDate:
			return parseXSDDate(s)
		case xdm.TypeDateTime, xdm.TypeDateTimeStamp:
			return parseXSDDateTime(s)
		case xdm.TypeTime:
			return parseXSDTime(s)
		}
	}

	return time.Time{}, fmt.Errorf("cannot coerce %T to time.Time for %s", v.Value, v.TypeName)
}

func compareAtomicWithImplicitTimezone(op TokenType, a, b xdm.AtomicValue, implicitTZ *time.Location) (bool, error) {
	op = normalizeCompareOp(op)
	a = promoteSchemaForCompare(a)
	b = promoteSchemaForCompare(b)
	a = normalizeDateTimeStamp(a)
	b = normalizeDateTimeStamp(b)

	// String-like comparison precedes boolean, numeric and typed comparisons.
	aString := xdm.IsStringDerived(a.TypeName) || a.TypeName == xdm.TypeAnyURI

	bString := xdm.IsStringDerived(b.TypeName) || b.TypeName == xdm.TypeAnyURI
	if aString && bString {
		return applyCompare(op, strings.Compare(stringFromAtomic(a), stringFromAtomic(b))), nil
	}

	if a.TypeName == xdm.TypeBoolean && b.TypeName == xdm.TypeBoolean {
		return compareBooleans(op, a.Value.(bool), b.Value.(bool)), nil //nolint:forcetypeassert
	}

	if a.IsNumeric() && b.IsNumeric() {
		return compareNumeric(op, a, b)
	}

	if a.TypeName == b.TypeName {
		if result, handled, err := compareSameTypeAtomics(op, a, b, implicitTZ); handled {
			return result, err
		}
	}

	familyA, familyB := comparisonFamily(a.TypeName), comparisonFamily(b.TypeName)
	if strings.HasPrefix(familyA, lexicon.TypeDuration) && strings.HasPrefix(familyB, lexicon.TypeDuration) {
		return compareDurationValues(op, a, b)
	}

	if result, handled, err := compareUserAtomicValues(op, a, b, implicitTZ); handled {
		return result, err
	}

	return false, &xdm.Error{
		Code:    lexicon.ErrXPTY0004,
		Message: fmt.Sprintf("cannot compare %s with %s", a.TypeName, b.TypeName),
	}
}

func compareSameTypeAtomics(op TokenType, a, b xdm.AtomicValue, implicitTZ *time.Location) (bool, bool, error) {
	var result bool

	var err error

	switch a.TypeName {
	case xdm.TypeDate, xdm.TypeDateTime, xdm.TypeTime:
		result, err = compareTemporalValues(op, a, b, implicitTZ)
	case xdm.TypeYearMonthDuration, xdm.TypeDayTimeDuration, xdm.TypeDuration:
		result, err = compareDurationValues(op, a, b)
	case xdm.TypeBase64Binary, xdm.TypeHexBinary:
		result = compareBinary(op, a.Value.([]byte), b.Value.([]byte)) //nolint:forcetypeassert
	case xdm.TypeQName:
		result, err = compareQName(op, a.Value.(xdm.QNameValue), b.Value.(xdm.QNameValue)) //nolint:forcetypeassert
	case xdm.TypeGDay, xdm.TypeGMonth, xdm.TypeGMonthDay, xdm.TypeGYear, xdm.TypeGYearMonth:
		result, err = compareGregorianValues(op, a, b, implicitTZ)
	default:
		return false, false, nil
	}

	return result, true, err
}

func compareTemporalValues(op TokenType, a, b xdm.AtomicValue, implicitTZ *time.Location) (bool, error) {
	left, right, err := coerceTimePair(a, b)
	if err != nil {
		return false, err
	}

	switch a.TypeName {
	case xdm.TypeDate:
		return compareDate(op, left, right, implicitTZ), nil
	case xdm.TypeDateTime:
		return compareTime(op, applyImplicitTZ(left, implicitTZ), applyImplicitTZ(right, implicitTZ)), nil
	default:
		return compareTimeOfDay(op, left, right, implicitTZ), nil
	}
}

func compareDurationValues(op TokenType, a, b xdm.AtomicValue) (bool, error) {
	if a.TypeName == xdm.TypeDuration || b.TypeName == xdm.TypeDuration {
		if op != TokenEq && op != TokenNe {
			return false, &xdm.Error{Code: lexicon.ErrXPTY0004, Message: textXsDurationValuesAreNotOrderable}
		}
	} else if a.TypeName != b.TypeName && op != TokenEq && op != TokenNe {
		return false, &xdm.Error{Code: lexicon.ErrXPTY0004, Message: "cannot order xs:yearMonthDuration and xs:dayTimeDuration"}
	}

	return compareDuration(op, a.DurationVal(), b.DurationVal())
}

func compareGregorianValues(op TokenType, a, b xdm.AtomicValue, implicitTZ *time.Location) (bool, error) {
	if op != TokenEq && op != TokenNe {
		return false, &xdm.Error{Code: lexicon.ErrXPTY0004, Message: fmt.Sprintf("%s values are not orderable", a.TypeName)}
	}

	left, leftOK := parseGTypeToTime(a.TypeName, stringFromAtomic(a))

	right, rightOK := parseGTypeToTime(b.TypeName, stringFromAtomic(b))
	if !leftOK || !rightOK {
		// Invalid partial-date lexicals retain the normalized-string fallback.
		leftText := normalizeGTZ(stringFromAtomic(a))
		rightText := normalizeGTZ(stringFromAtomic(b))

		return applyCompare(op, strings.Compare(leftText, rightText)), nil
	}

	return compareTime(op, applyImplicitTZ(left, implicitTZ), applyImplicitTZ(right, implicitTZ)), nil
}

func compareUserAtomicValues(op TokenType, a, b xdm.AtomicValue, implicitTZ *time.Location) (bool, bool, error) {
	if xdm.IsKnownXSDType(a.TypeName) && xdm.IsKnownXSDType(b.TypeName) {
		return false, false, nil
	}

	if left, ok := a.Value.(time.Time); ok {
		if right, ok := b.Value.(time.Time); ok {
			return compareDate(op, left, right, implicitTZ), true, nil
		}
	}

	if _, ok := a.Value.(xdm.Duration); ok {
		if _, ok := b.Value.(xdm.Duration); ok {
			result, err := compareDuration(op, a.DurationVal(), b.DurationVal())
			return result, true, err
		}
	}

	return false, false, nil
}

// promoteSchemaForCompare promotes a user-defined schema type to its built-in
// base type for comparison purposes.
func promoteSchemaForCompare(a xdm.AtomicValue) xdm.AtomicValue {
	return xdm.PromoteSchemaType(a)
}

// normalizeDateTimeStamp rewrites an xs:dateTimeStamp value to xs:dateTime for
// comparison. xs:dateTimeStamp (XSD 1.1) is a built-in subtype of xs:dateTime
// with identical value-space ordering, so comparing it as xs:dateTime is correct
// for both same-type and mixed dateTime/dateTimeStamp comparisons.
func normalizeDateTimeStamp(a xdm.AtomicValue) xdm.AtomicValue {
	if a.TypeName == xdm.TypeDateTimeStamp {
		a.TypeName = xdm.TypeDateTime
	}

	return a
}

// compareDate compares xs:date values by their UTC instants.
// Applies implicit timezone for values without explicit timezone.
func compareDate(op TokenType, a, b time.Time, implicitTZ *time.Location) bool {
	return compareTime(op, applyImplicitTZ(a, implicitTZ), applyImplicitTZ(b, implicitTZ))
}

// compareTimeOfDay compares xs:time values per XPath F&O 3.0 §10.4.4:
// https://www.w3.org/TR/xpath-functions-30/#func-time-equal
// Times are converted to xs:dateTime using the reference date 1972-12-31,
// then compared as UTC instants. This correctly handles date-wrap from timezone offsets.
// When a time has no explicit timezone (Location == time.UTC), the implicit
// timezone is applied per spec.
func compareTimeOfDay(op TokenType, a, b time.Time, implicitTZ *time.Location) bool {
	ra := timeToReferenceDateTime(applyImplicitTZ(a, implicitTZ))
	rb := timeToReferenceDateTime(applyImplicitTZ(b, implicitTZ))

	return compareTime(op, ra, rb)
}

// timeToReferenceDateTime converts an xs:time to an xs:dateTime using the
// XPath reference date 1972-12-31, preserving the timezone offset.
func timeToReferenceDateTime(t time.Time) time.Time {
	_, offset := t.Zone()
	loc := time.FixedZone("", offset)

	return time.Date(1972, 12, 31, t.Hour(), t.Minute(), t.Second(), t.Nanosecond(), loc)
}

// applyImplicitTZ applies the system's implicit timezone to a time that has
// no explicit timezone (Location == time.UTC). Times with explicit timezones
// (Location is a FixedZone) are returned as-is.
func applyImplicitTZ(t time.Time, implicitTZ *time.Location) time.Time {
	if xdm.HasTimezone(t) {
		return t // has explicit timezone
	}

	loc := implicitTZ
	if loc == nil {
		loc = time.Local
	}

	return time.Date(t.Year(), t.Month(), t.Day(), t.Hour(), t.Minute(), t.Second(), t.Nanosecond(), loc)
}

// normalizeGTZ normalizes timezone suffixes in g* type string values
// so that -00:00, +00:00, and Z are all treated as equivalent.
func normalizeGTZ(s string) string {
	if strings.HasSuffix(s, "+00:00") || strings.HasSuffix(s, "-00:00") {
		return s[:len(s)-6] + "Z"
	}

	return s
}

// parseGTypeToTime converts a g* type string value into a time.Time using
// reference dates from the XSD specification for comparison purposes.
// Reference dates: gDay → 1972-12-DD, gMonth → 1972-MM-01,
// gMonthDay → 1972-MM-DD, gYear → YYYY-01-01, gYearMonth → YYYY-MM-01.
func parseGTypeToTime(typeName, s string) (time.Time, bool) {
	loc, rest := parseGTimezone(s)

	switch typeName {
	case xdm.TypeGDay:
		// Format: ---DD
		if len(rest) < 5 {
			return time.Time{}, false
		}

		day := parseInt(rest[3:5])

		return time.Date(1972, 12, day, 0, 0, 0, 0, loc), true
	case xdm.TypeGMonth:
		// Format: --MM
		if len(rest) < 4 {
			return time.Time{}, false
		}

		month := parseInt(rest[2:4])

		return time.Date(1972, time.Month(month), 1, 0, 0, 0, 0, loc), true
	case xdm.TypeGMonthDay:
		// Format: --MM-DD
		if len(rest) < 7 {
			return time.Time{}, false
		}

		month := parseInt(rest[2:4])
		day := parseInt(rest[5:7])

		return time.Date(1972, time.Month(month), day, 0, 0, 0, 0, loc), true
	case xdm.TypeGYear:
		// Format: [-]YYYY
		year, endIdx := parseGYear(rest)
		_ = endIdx

		return time.Date(year, 1, 1, 0, 0, 0, 0, loc), true
	case xdm.TypeGYearMonth:
		// Format: [-]YYYY-MM
		year, endIdx := parseGYear(rest)
		if endIdx+3 > len(rest) {
			return time.Time{}, false
		}

		month := parseInt(rest[endIdx+1 : endIdx+3])

		return time.Date(year, time.Month(month), 1, 0, 0, 0, 0, loc), true
	}

	return time.Time{}, false
}

// parseGTimezone extracts the timezone from a g* string value, returning the
// location and the string with timezone removed.
func parseGTimezone(s string) (*time.Location, string) {
	if strings.HasSuffix(s, "Z") {
		return time.UTC, s[:len(s)-1]
	}

	if len(s) >= 6 {
		tz := s[len(s)-6:]
		if (tz[0] == '+' || tz[0] == '-') && tz[3] == ':' {
			hours := parseInt(tz[1:3])
			mins := parseInt(tz[4:6])

			offset := hours*3600 + mins*60
			if tz[0] == '-' {
				offset = -offset
			}

			return time.FixedZone("", offset), s[:len(s)-6]
		}
	}
	// No timezone — use noTZLocation sentinel
	return xdm.NoTimezone(), s
}

// parseInt parses a string of digits as an int (no error handling — input is pre-validated by regex).
func parseInt(s string) int {
	n := 0
	for _, c := range s {
		n = n*10 + int(c-'0')
	}

	return n
}

// parseGYear parses the year from a g* value string, returning the year and
// the index after the year digits.
func parseGYear(s string) (int, int) {
	neg := false
	start := 0

	if len(s) > 0 && s[0] == '-' {
		neg = true
		start = 1
	}

	end := start
	for end < len(s) && s[end] >= '0' && s[end] <= '9' {
		end++
	}

	year := parseInt(s[start:end])
	if neg {
		year = -year
	}

	return year, end
}

func compareTime(op TokenType, a, b time.Time) bool {
	switch op {
	case TokenEq:
		return a.Equal(b)
	case TokenNe:
		return !a.Equal(b)
	case TokenLt:
		return a.Before(b)
	case TokenLe:
		return a.Before(b) || a.Equal(b)
	case TokenGt:
		return a.After(b)
	case TokenGe:
		return a.After(b) || a.Equal(b)
	}

	return false
}

func compareDuration(op TokenType, a, b xdm.Duration) (bool, error) {
	// Compare via exact signed rationals — months and seconds each as their own
	// exact value space — so consecutive huge whole seconds and near-1 fractional
	// seconds stay distinct (no float64 epsilon collapse). durationToRat folds the
	// Negative sign into each rational.
	aMonthsRat := xdm.DurationToRat(a, true)
	aSecsRat := xdm.DurationToRat(a, false)
	bMonthsRat := xdm.DurationToRat(b, true)
	bSecsRat := xdm.DurationToRat(b, false)

	eq := aMonthsRat.Cmp(bMonthsRat) == 0 && aSecsRat.Cmp(bSecsRat) == 0

	switch op {
	case TokenEq:
		return eq, nil
	case TokenNe:
		return !eq, nil
	case TokenLt, TokenLe, TokenGt, TokenGe:
		// Ordering is only defined for yearMonthDuration and dayTimeDuration (not mixed)
		if aMonthsRat.Sign() != 0 && aSecsRat.Sign() != 0 {
			return false, &xdm.Error{Code: lexicon.ErrXPTY0004, Message: textXsDurationValuesAreNotOrderable}
		}

		if bMonthsRat.Sign() != 0 && bSecsRat.Sign() != 0 {
			return false, &xdm.Error{Code: lexicon.ErrXPTY0004, Message: textXsDurationValuesAreNotOrderable}
		}
		// Compare months-only or seconds-only
		if aMonthsRat.Sign() != 0 || bMonthsRat.Sign() != 0 {
			return applyCompare(op, aMonthsRat.Cmp(bMonthsRat)), nil
		}

		return applyCompare(op, aSecsRat.Cmp(bSecsRat)), nil
	}

	return false, nil
}

func compareBinary(op TokenType, a, b []byte) bool {
	cmp := bytes.Compare(a, b)
	return applyCompare(op, cmp)
}

func compareQName(op TokenType, a, b xdm.QNameValue) (bool, error) {
	switch op {
	case TokenEq:
		return a.URI == b.URI && a.Local == b.Local, nil
	case TokenNe:
		return a.URI != b.URI || a.Local != b.Local, nil
	default:
		return false, &xdm.Error{Code: lexicon.ErrXPTY0004, Message: "QName values only support eq/ne"}
	}
}

func normalizeCompareOp(op TokenType) TokenType {
	switch op {
	case TokenEquals:
		return TokenEq
	case TokenNotEquals:
		return TokenNe
	case TokenLess:
		return TokenLt
	case TokenLessEq:
		return TokenLe
	case TokenGreater:
		return TokenGt
	case TokenGreaterEq:
		return TokenGe
	}

	return op
}

func applyCompare(op TokenType, cmp int) bool {
	switch op {
	case TokenEq:
		return cmp == 0
	case TokenNe:
		return cmp != 0
	case TokenLt:
		return cmp < 0
	case TokenLe:
		return cmp <= 0
	case TokenGt:
		return cmp > 0
	case TokenGe:
		return cmp >= 0
	}

	return false
}

// compareNumeric performs type-preserving numeric comparison.
// Both integer → big.Int.Cmp; either decimal → big.Rat.Cmp; otherwise → float64.
func compareNumeric(op TokenType, a, b xdm.AtomicValue) (bool, error) {
	// Both integer → int64 fast path, fall back to big.Int
	if xdm.IsIntegerDerived(a.TypeName) && xdm.IsIntegerDerived(b.TypeName) {
		av, aok := a.Int64Val()

		bv, bok := b.Int64Val()
		if aok && bok {
			var cmp int

			switch {
			case av < bv:
				cmp = -1
			case av > bv:
				cmp = 1
			}

			return applyCompare(op, cmp), nil
		}

		cmp := a.BigInt().Cmp(b.BigInt())

		return applyCompare(op, cmp), nil
	}
	// Either decimal (and other is integer or decimal) → big.Rat comparison
	aDecOrInt := a.TypeName == xdm.TypeDecimal || xdm.IsIntegerDerived(a.TypeName)

	bDecOrInt := b.TypeName == xdm.TypeDecimal || xdm.IsIntegerDerived(b.TypeName)
	if aDecOrInt && bDecOrInt {
		ar := toRatForCompare(a)
		br := toRatForCompare(b)
		cmp := ar.Cmp(br)

		return applyCompare(op, cmp), nil
	}
	// When one operand is xs:float and the other is decimal/integer,
	// promote to xs:float (float32) per XPath type promotion rules.
	// This avoids float32→float64 precision artifacts (e.g., float32(1.2) != float64(1.2)).
	aIsFloat := a.TypeName == xdm.TypeFloat

	bIsFloat := b.TypeName == xdm.TypeFloat
	if (aIsFloat || bIsFloat) && a.TypeName != xdm.TypeDouble && b.TypeName != xdm.TypeDouble {
		return compareFloats(op, float64(numericToFloat32(a)), float64(numericToFloat32(b))), nil
	}
	// Otherwise → float64 (handles double, float, NaN, ±Inf)
	return compareFloats(op, a.ToFloat64(), b.ToFloat64()), nil
}

func toRatForCompare(a xdm.AtomicValue) *big.Rat {
	if xdm.IsIntegerDerived(a.TypeName) {
		if v, ok := a.Value.(int64); ok {
			return new(big.Rat).SetInt64(v)
		}

		return new(big.Rat).SetInt(a.BigInt())
	}

	return a.BigRat()
}

func compareFloats(op TokenType, a, b float64) bool {
	switch op {
	case TokenEq:
		return a == b
	case TokenNe:
		// NaN != NaN is true per IEEE 754
		if math.IsNaN(a) || math.IsNaN(b) {
			return true
		}

		return a != b
	case TokenLt:
		return a < b
	case TokenLe:
		return a <= b
	case TokenGt:
		return a > b
	case TokenGe:
		return a >= b
	}

	return false
}

func compareBooleans(op TokenType, a, b bool) bool {
	ai, bi := 0, 0
	if a {
		ai = 1
	}

	if b {
		bi = 1
	}

	switch op {
	case TokenEq:
		return ai == bi
	case TokenNe:
		return ai != bi
	case TokenLt:
		return ai < bi
	case TokenLe:
		return ai <= bi
	case TokenGt:
		return ai > bi
	case TokenGe:
		return ai >= bi
	}

	return false
}
