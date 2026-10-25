// Derived from lestrrat-go/helium at 7362c0a70122a757780f4d0b545a9b370dead6ab.
// Copyright (c) 2015 lestrrat. MIT License; see licenses/MIT-helium.txt at the repository root.

package xpath

import (
	"context"
	"fmt"
	"math/big"

	"github.com/skarm/xmlsec/transform/internal/xdm"
	"github.com/skarm/xmlsec/transform/internal/xdm/lexicon"
)

func evalBinaryExpr(evalFn exprEvaluator, ctx context.Context, ec *evalContext, e BinaryExpr) (xdm.Sequence, error) {
	switch e.Op {
	case TokenOr:
		return evalLogicOr(evalFn, ctx, ec, e)
	case TokenAnd:
		return evalLogicAnd(evalFn, ctx, ec, e)
	case TokenEquals, TokenNotEquals, TokenLess, TokenLessEq, TokenGreater, TokenGreaterEq:
		return evalGeneralComparison(evalFn, ctx, ec, e)
	case TokenEq, TokenNe, TokenLt, TokenLe, TokenGt, TokenGe:
		return evalValueComparison(evalFn, ctx, ec, e)
	case TokenIs, TokenNodePre, TokenNodeFol:
		return evalNodeComparison(evalFn, ctx, ec, e)
	case TokenPlus, TokenMinus, TokenStar, TokenDiv, TokenIdiv, TokenMod:
		return evalArithmetic(evalFn, ctx, ec, e)
	}

	return nil, fmt.Errorf("%w: %s", ErrUnsupportedBinaryOp, e.Op)
}

func evalLogicOr(evalFn exprEvaluator, ctx context.Context, ec *evalContext, e BinaryExpr) (xdm.Sequence, error) {
	left, err := evalFn(ctx, ec, e.Left)
	if err != nil {
		return nil, err
	}

	lb, err := EBV(left)
	if err != nil {
		return nil, err
	}

	if lb {
		return xdm.SingleBoolean(true), nil
	}

	right, err := evalFn(ctx, ec, e.Right)
	if err != nil {
		return nil, err
	}

	rb, err := EBV(right)
	if err != nil {
		return nil, err
	}

	return xdm.SingleBoolean(rb), nil
}

func evalLogicAnd(evalFn exprEvaluator, ctx context.Context, ec *evalContext, e BinaryExpr) (xdm.Sequence, error) {
	left, err := evalFn(ctx, ec, e.Left)
	if err != nil {
		return nil, err
	}

	lb, err := EBV(left)
	if err != nil {
		return nil, err
	}

	if !lb {
		return xdm.SingleBoolean(false), nil
	}

	right, err := evalFn(ctx, ec, e.Right)
	if err != nil {
		return nil, err
	}

	rb, err := EBV(right)
	if err != nil {
		return nil, err
	}

	return xdm.SingleBoolean(rb), nil
}

func evalConcatExpr(evalFn exprEvaluator, ctx context.Context, ec *evalContext, e ConcatExpr) (xdm.Sequence, error) {
	left, err := evalFn(ctx, ec, e.Left)
	if err != nil {
		return nil, err
	}

	right, err := evalFn(ctx, ec, e.Right)
	if err != nil {
		return nil, err
	}

	ls, err := concatToString(ctx, ec, left, 0)
	if err != nil {
		return nil, err
	}

	rs, err := concatToString(ctx, ec, right, 1)
	if err != nil {
		return nil, err
	}

	if err := ChargeString(ctx, len(ls), len(rs)); err != nil {
		return nil, err
	}

	return xdm.SingleString(ls + rs), nil
}

// The || operator uses fn:concat's xs:anyAtomicType? conversion, including
// bounded atomization, cardinality and FOTY0013 for non-atomizable items.
func concatToString(ctx context.Context, ec *evalContext, seq xdm.Sequence, index int) (string, error) {
	coerced, err := coerceFuncallArg(ctx, seq, stAtomic(xdm.TypeAnyAtomicType, xdm.OccurrenceZeroOrOne), nameConcat, index, ec)
	if err != nil {
		return "", err
	}

	return seqToStringErr(withFnContext(ctx, ec), coerced)
}

// appendBounded appends src to dst, enforcing the configured sequence/node-set
// size limit. Returns ErrNodeSetLimit once the accumulated length would exceed
// maxNodes. Used by accumulation sites (simple-map, FLWOR return, lookup) that
// concatenate per-item sub-sequences and could otherwise materialize unbounded
// output regardless of maxNodes.
func appendBounded(dst xdm.ItemSlice, src []xdm.Item, maxNodes int) (xdm.ItemSlice, error) {
	if maxNodes > 0 && len(dst)+len(src) > maxNodes {
		return nil, ErrNodeSetLimit
	}

	return append(dst, src...), nil
}

// appendBoundedSeq appends the items of src to dst one at a time, enforcing the
// configured sequence/node-set size limit before each append. Unlike
// appendBounded (which takes an already-materialized []Item), it iterates src
// lazily via seqItems so a callback returning an unbounded lazy Sequence is
// rejected with ErrNodeSetLimit as soon as the accumulated length would exceed
// maxNodes — without ever materializing the whole source sequence.
//
// It also charges one op (and honors cancellation) per appended item via
// fnCountOp, so draining a large lazy source respects OpLimit / context
// cancellation, and never runs to completion unbounded.
func appendBoundedSeq(ctx context.Context, ec *evalContext, dst xdm.ItemSlice, src xdm.Sequence, maxNodes int) (xdm.ItemSlice, error) {
	for item := range xdm.SequenceItems(src) {
		if err := fnCountOp(ctx, ec); err != nil {
			return nil, err
		}

		if maxNodes > 0 && len(dst)+1 > maxNodes {
			return nil, ErrNodeSetLimit
		}

		dst = append(dst, item)
	}

	return dst, nil
}

// appendBoundedClonedSeq behaves like appendBoundedSeq but appends a defensive
// deep clone of each item, and never the item itself. It is used by lookup /
// map:get paths that drain a BORROWED (no-clone) stored map value via get0:
// draining lazily charges op (and honors cancellation) and enforces maxNodes
// BEFORE each item is appended, so a borrowed lazy value whose Materialize is
// unbounded/panics trips the bound first; cloning each appended item then keeps
// value semantics so mutating the exposed result cannot reach the source map.
func appendBoundedClonedSeq(ctx context.Context, ec *evalContext, dst xdm.ItemSlice, src xdm.Sequence, maxNodes int) (xdm.ItemSlice, error) {
	for item := range xdm.SequenceItems(src) {
		if err := fnCountOp(ctx, ec); err != nil {
			return nil, err
		}

		if maxNodes > 0 && len(dst)+1 > maxNodes {
			return nil, ErrNodeSetLimit
		}

		dst = append(dst, xdm.CloneItem(item))
	}

	return dst, nil
}

func evalSimpleMapExpr(evalFn exprEvaluator, ctx context.Context, ec *evalContext, e SimpleMapExpr) (xdm.Sequence, error) {
	left, err := evalFn(ctx, ec, e.Left)
	if err != nil {
		return nil, err
	}

	var result xdm.ItemSlice

	size := xdm.SequenceLen(left)
	i := 0

	for item := range xdm.SequenceItems(left) {
		var frame evalContextFrame
		if ni, ok := item.(xdm.NodeItem); ok {
			frame = ec.pushNodeContext(ni.Node, i+1, size)
		} else {
			frame = ec.pushContextItem(item, i+1, size)
		}

		r, err := evalFn(ctx, ec, e.Right)
		ec.restoreContext(frame)

		if err != nil {
			return nil, err
		}
		// Accumulate the right-hand sequence lazily so the aggregate maxNodes /
		// OpLimit / cancellation bound is enforced item-by-item BEFORE the whole
		// sub-sequence is materialized — a per-item right expression producing a
		// large lazy Sequence is rejected without first allocating it in full.
		result, err = appendBoundedSeq(ctx, ec, result, r, ec.maxNodes)
		if err != nil {
			return nil, err
		}

		i++
	}

	return result, nil
}

// simpleMapNodes evaluates E1 ! E2 for the E1 that evaluates to the node
// items of nodes, as evalSimpleMapExpr does: each node in turn is the
// context node.
func simpleMapNodes(evalFn exprEvaluator, ctx context.Context, ec *evalContext, e SimpleMapExpr, nodes []xdm.Node) (xdm.Sequence, error) {
	var result xdm.ItemSlice

	for i, n := range nodes {
		frame := ec.pushNodeContext(n, i+1, len(nodes))
		r, err := evalFn(ctx, ec, e.Right)
		ec.restoreContext(frame)

		if err != nil {
			return nil, err
		}

		result, err = appendBoundedSeq(ctx, ec, result, r, ec.maxNodes)
		if err != nil {
			return nil, err
		}
	}

	return result, nil
}

func evalRangeExpr(evalFn exprEvaluator, ctx context.Context, ec *evalContext, e RangeExpr) (xdm.Sequence, error) {
	startSeq, err := evalFn(ctx, ec, e.Start)
	if err != nil {
		return nil, err
	}

	endSeq, err := evalFn(ctx, ec, e.End)
	if err != nil {
		return nil, err
	}
	// Atomize through the stream so a schema-typed list/union node expands; the
	// at-most-one cardinality is checked on the atomized result.
	sAtoms, err := atomizeSingletonOperand(startSeq)
	if err != nil {
		return nil, err
	}

	eAtoms, err := atomizeSingletonOperand(endSeq)
	if err != nil {
		return nil, err
	}

	if len(sAtoms) == 0 || len(eAtoms) == 0 {
		return nil, nil
	}
	// XPath 1.0 compatibility mode: a range bound keeps only its first atom rather
	// than raising a cardinality error.
	if ec.xpath10CompatMode() {
		sAtoms = sAtoms[:1]
		eAtoms = eAtoms[:1]
	}

	if len(sAtoms) > 1 || len(eAtoms) > 1 {
		return nil, &xdm.Error{Code: lexicon.ErrXPTY0004, Message: "to operator operands must each be xs:integer? (at most one item)"}
	}

	sa := sAtoms[0]
	ea := eAtoms[0]
	// Per spec, operands are converted using function coercion rules for xs:integer?.
	// This allows untypedAtomic → integer, but rejects double/float/decimal → integer.
	saInt, err := coerceToInteger(ctx, sa)
	if err != nil {
		return nil, err
	}

	eaInt, err := coerceToInteger(ctx, ea)
	if err != nil {
		return nil, err
	}
	// Fast path: both bounds fit in int64
	sv, sok := saInt.Int64Val()

	ev, eok := eaInt.Int64Val()
	if sok && eok {
		if sv > ev {
			return nil, nil
		}
		// Compute the span with big.Int: ev-sv+1 can overflow int64 even when
		// both bounds fit (e.g. minInt64 .. maxInt64), which would wrap the
		// count and bypass the limit check or build a negative-length range.
		span := new(big.Int).Sub(big.NewInt(ev), big.NewInt(sv))
		span.Add(span, big.NewInt(1))

		if !span.IsInt64() || span.Int64() > int64(ec.maxNodes) {
			return nil, ErrNodeSetLimit
		}

		return xdm.NewRangeSequence(sv, ev), nil
	}

	start := saInt.BigInt()

	end := eaInt.BigInt()
	if start.Cmp(end) > 0 {
		return nil, nil
	}

	count := new(big.Int).Sub(end, start)
	count.Add(count, big.NewInt(1))

	if !count.IsInt64() || count.Int64() > int64(ec.maxNodes) {
		return nil, ErrNodeSetLimit
	}
	// Fallback for big integer ranges (rare)
	n := count.Int64()
	result := make(xdm.ItemSlice, 0, n)

	cur := new(big.Int).Set(start)
	for cur.Cmp(end) <= 0 {
		result = append(result, xdm.AtomicValue{TypeName: xdm.TypeInteger, Value: new(big.Int).Set(cur)})
		cur.Add(cur, big.NewInt(1))
	}

	return result, nil
}

func evalUnionExpr(evalFn exprEvaluator, ctx context.Context, ec *evalContext, e UnionExpr) (xdm.Sequence, error) {
	left, err := evalFn(ctx, ec, e.Left)
	if err != nil {
		return nil, err
	}

	right, err := evalFn(ctx, ec, e.Right)
	if err != nil {
		return nil, err
	}
	// Gather both operands into one buffer, left then right, so the union
	// can return it as is when it is already in document order.
	nodes, ok := xdm.AppendSequenceNodes(make([]xdm.Node, 0, xdm.SequenceLen(left)+xdm.SequenceLen(right)), left)
	if !ok {
		return nil, languageError(ErrUnionNotNodeSet, errCodeXPTY0004, ec.version)
	}

	split := len(nodes)

	nodes, ok = xdm.AppendSequenceNodes(nodes, right)
	if !ok {
		return nil, languageError(ErrUnionNotNodeSet, errCodeXPTY0004, ec.version)
	}

	merged, err := xdm.UnionNodeSets(nodes, split, ec.docOrder, ec.maxNodes)
	if err != nil {
		return nil, err
	}

	result := make(xdm.ItemSlice, len(merged))
	for i, n := range merged {
		result[i] = nodeItemFor(ctx, ec, n)
	}

	return result, nil
}

func evalIntersectExceptExpr(evalFn exprEvaluator, ctx context.Context, ec *evalContext, e IntersectExceptExpr) (xdm.Sequence, error) {
	left, err := evalFn(ctx, ec, e.Left)
	if err != nil {
		return nil, err
	}

	right, err := evalFn(ctx, ec, e.Right)
	if err != nil {
		return nil, err
	}

	leftNodes, ok1 := xdm.NodesFrom(left)

	rightNodes, ok2 := xdm.NodesFrom(right)
	if !ok1 || !ok2 {
		return nil, languageError(ErrUnionNotNodeSet, errCodeXPTY0004, ec.version)
	}

	result, err := intersectExceptNodes(ec, e.Op, leftNodes, rightNodes)
	if err != nil {
		return nil, err
	}

	return nodeItemsFor(ctx, ec, result), nil
}

// intersectExceptNodes returns the nodes of leftNodes that are (op is
// TokenIntersect) or are not (TokenExcept) in rightNodes, in document order
// and free of duplicates.
func intersectExceptNodes(ec *evalContext, op TokenType, leftNodes, rightNodes []xdm.Node) ([]xdm.Node, error) {
	rightSet := make(map[nodeIdentityKey]struct{}, len(rightNodes))
	for _, n := range rightNodes {
		rightSet[makeNodeIdentityKey(n)] = struct{}{}
	}

	seen := make(map[nodeIdentityKey]struct{}, len(leftNodes))

	result := make([]xdm.Node, 0, len(leftNodes))
	for _, n := range leftNodes {
		key := makeNodeIdentityKey(n)
		if _, dup := seen[key]; dup {
			continue
		}

		seen[key] = struct{}{}

		_, inRight := rightSet[key]
		if op == TokenIntersect && inRight {
			result = append(result, n)
		} else if op == TokenExcept && !inRight {
			result = append(result, n)
		}
	}
	// XPath requires intersect/except results in document order
	return xdm.DeduplicateNodes(result, ec.docOrder, ec.maxNodes)
}

func evalFilterExpr(evalFn exprEvaluator, ctx context.Context, ec *evalContext, e FilterExpr) (xdm.Sequence, error) {
	base, err := evalFn(ctx, ec, e.Expr)
	if err != nil {
		return nil, err
	}

	if ec.version == 10 {
		if err := xpath10NodeSet(base); err != nil {
			return nil, err
		}
	}

	// Try node-set path (optimized for node predicates)
	if nodes, ok := xdm.NodesFrom(base); ok {
		for _, pred := range e.Predicates {
			nodes, err = applyPredicate(evalFn, ctx, ec, nodes, pred)
			if err != nil {
				return nil, err
			}
		}

		result := make(xdm.ItemSlice, len(nodes))
		for i, n := range nodes {
			result[i] = nodeItemFor(ctx, ec, n)
		}

		return result, nil
	}

	// General sequence filtering (XPath 3.1)
	seq := base
	for _, pred := range e.Predicates {
		seq, err = applySequencePredicate(evalFn, ctx, ec, seq, pred)
		if err != nil {
			return nil, err
		}
	}

	return seq, nil
}

// applySequencePredicate filters a sequence by a predicate expression.
// Each item becomes the context item; numeric predicates select by position.
func applySequencePredicate(evalFn exprEvaluator, ctx context.Context, ec *evalContext, seq xdm.Sequence, pred Expr) (xdm.Sequence, error) {
	size := xdm.SequenceLen(seq)
	result := make(xdm.ItemSlice, 0, size)
	i := 0

	for item := range xdm.SequenceItems(seq) {
		var frame evalContextFrame
		if ni, ok := item.(xdm.NodeItem); ok {
			frame = ec.pushNodeContext(ni.Node, i+1, size)
		} else {
			frame = ec.pushContextItem(item, i+1, size)
		}

		r, err := evalFn(ctx, ec, pred)
		ec.restoreContext(frame)

		if err != nil {
			return nil, err
		}
		// Numeric predicate: position match
		if xdm.SequenceLen(r) == 1 {
			if a, ok := r.Get(0).(xdm.AtomicValue); ok && a.IsNumeric() {
				f := a.ToFloat64()
				if f == float64(i+1) {
					result = append(result, item)
				}

				i++

				continue
			}
		}
		// Boolean predicate
		b, err := EBV(r)
		if err != nil {
			return nil, err
		}

		if b {
			result = append(result, item)
		}

		i++
	}

	return result, nil
}

func evalPathExpr(evalFn exprEvaluator, ctx context.Context, ec *evalContext, e PathExpr) (xdm.Sequence, error) {
	base, err := evalFn(ctx, ec, e.Filter)
	if err != nil {
		return nil, err
	}

	if e.Path == nil {
		return base, nil
	}

	baseNodes, ok := xdm.NodesFrom(base)
	if !ok {
		return nil, ErrPathNotNodeSet
	}

	result := make([]xdm.Node, 0, len(baseNodes))
	for _, n := range baseNodes {
		frame := ec.pushNodeContext(n, 1, 1)
		subResult, err := evalLocationPath(evalFn, ctx, ec, e.Path)
		ec.restoreContext(frame)

		if err != nil {
			return nil, err
		}

		subNodes, _ := xdm.NodesFrom(subResult)
		result = append(result, subNodes...)
	}
	// Per XPath 3.1 §3.3.5: E1/E2 returns nodes in document order.
	// However, when the filter is an ordering function (reverse, sort),
	// preserve the explicit ordering and only deduplicate.
	var deduped []xdm.Node
	if filterPreservesOrder(ctx, ec, e.Filter) {
		deduped, err = xdm.DeduplicateNodesPreserveOrder(result, ec.maxNodes)
	} else {
		deduped, err = xdm.DeduplicateNodes(result, ec.docOrder, ec.maxNodes)
	}

	if err != nil {
		return nil, err
	}

	seq := make(xdm.ItemSlice, len(deduped))
	for i, n := range deduped {
		seq[i] = nodeItemFor(ctx, ec, n)
	}

	return seq, nil
}

func evalVMPathExpr(evalFn exprEvaluator, ctx context.Context, ec *evalContext, e vmPathExpr) (xdm.Sequence, error) {
	base, err := evalFn(ctx, ec, e.Filter)
	if err != nil {
		return nil, err
	}

	if e.Path == nil {
		return base, nil
	}

	baseNodes, ok := xdm.NodesFrom(base)
	if !ok {
		return nil, ErrPathNotNodeSet
	}

	nodes, err := vmPathStepNodes(evalFn, ctx, ec, e, baseNodes)
	if err != nil {
		return nil, err
	}

	return nodeItemsFor(ctx, ec, nodes), nil
}

// vmPathStepNodes evaluates the location path e.Path from every node of
// baseNodes and returns the results merged in document order, or in the
// order of baseNodes when e.OrderFilter is fn:reverse or fn:sort.
func vmPathStepNodes(evalFn exprEvaluator, ctx context.Context, ec *evalContext, e vmPathExpr, baseNodes []xdm.Node) ([]xdm.Node, error) {
	result := make([]xdm.Node, 0, len(baseNodes))
	for _, n := range baseNodes {
		frame := ec.pushNodeContext(n, 1, 1)
		subNodes, err := evalVMLocationPathNodes(evalFn, ctx, ec, *e.Path)
		ec.restoreContext(frame)

		if err != nil {
			return nil, err
		}

		result = append(result, subNodes...)
	}

	if filterPreservesOrder(ctx, ec, e.OrderFilter) {
		return xdm.DeduplicateNodesPreserveOrder(result, ec.maxNodes)
	}

	return xdm.DeduplicateNodes(result, ec.docOrder, ec.maxNodes)
}

// filterPreservesOrder returns true if the filter expression is a call to the
// built-in fn:reverse or fn:sort, which explicitly control sequence order. In
// these cases, a subsequent path step (/@attr) should preserve the caller's
// ordering, re-sorting into no document order.
//
// The decision is made against the runtime function resolver so that a rebound
// "fn" prefix or a user function overriding the built-in is not mistaken for
// the order-controlling built-in. (Do not use the lexical streamability helper
// StreamFnLocalName here — that is a static spelling check, not a binding.)
func filterPreservesOrder(ctx context.Context, ec *evalContext, e Expr) bool {
	fc, ok := e.(FunctionCall)
	if !ok {
		return false
	}

	r, err := resolveFunctionInfo(ctx, ec, fc.Prefix, fc.Name, len(fc.Args))
	if err != nil {
		return false
	}

	if !r.isBuiltin || r.uri != NSFn {
		return false
	}

	return r.name == nameReverse || r.name == nameSort
}

// evalPathStepExpr evaluates E1/E2 where E2 is a non-axis expression.
// Per XPath 3.1 §3.3.1.1: E1 must produce a node sequence (XPTY0019); E2 is
// evaluated for each node with that node as context. If all results are nodes,
// they are sorted in document order and deduplicated; if all are non-nodes,
// they keep their order. Any mix of nodes and non-nodes, within one result of
// E2 or across the results for different context nodes, raises XPTY0018. An
// empty result counts as either kind.
func evalPathStepExpr(evalFn exprEvaluator, ctx context.Context, ec *evalContext, e PathStepExpr) (xdm.Sequence, error) {
	base, err := evalFn(ctx, ec, e.Left)
	if err != nil {
		return nil, err
	}

	baseNodes, ok := xdm.NodesFrom(base)
	if !ok {
		return nil, ErrPathNotNodeSet
	}

	return pathStepFromNodes(evalFn, ctx, ec, e, baseNodes)
}

// pathStepFromNodes evaluates E1/E2 for a non-axis E2 and the E1 whose
// nodes are baseNodes.
func pathStepFromNodes(evalFn exprEvaluator, ctx context.Context, ec *evalContext, e PathStepExpr, baseNodes []xdm.Node) (xdm.Sequence, error) {
	allNodes := make([]xdm.Node, 0, len(baseNodes))
	allItems := make(xdm.ItemSlice, 0, len(baseNodes))
	hasNodes := false
	hasNonNodes := false

	for i, n := range baseNodes {
		frame := ec.pushNodeContext(n, i+1, len(baseNodes))
		r, err := evalFn(ctx, ec, e.Right)
		ec.restoreContext(frame)

		if err != nil {
			return nil, err
		}

		if xdm.SequenceLen(r) == 0 {
			continue
		}

		rNodes, nok := xdm.NodesFrom(r)
		if nok && !hasNonNodes {
			hasNodes = true

			allNodes = append(allNodes, rNodes...)

			continue
		}
		// r is all nodes after earlier non-nodes, or it holds a non-node after
		// earlier nodes or next to a node of its own.
		if nok || hasNodes || sequenceHasNode(r) {
			return nil, &xdm.Error{Code: errCodeXPTY0018, Message: errMsgPathMixedResult}
		}

		hasNonNodes = true
		// Accumulate through the bounded helper so maxNodes / OpLimit /
		// cancellation are enforced on the atomic branch just as they are on
		// the node branch below; otherwise a per-node right expression such as
		// (1 to 10000000) could grow allItems past ec.maxNodes unbounded.
		allItems, err = appendBoundedSeq(ctx, ec, allItems, r, ec.maxNodes)
		if err != nil {
			return nil, err
		}
	}

	if hasNodes {
		var err error
		if filterPreservesOrder(ctx, ec, e.Left) {
			allNodes, err = xdm.DeduplicateNodesPreserveOrder(allNodes, ec.maxNodes)
		} else {
			allNodes, err = xdm.DeduplicateNodes(allNodes, ec.docOrder, ec.maxNodes)
		}

		if err != nil {
			return nil, err
		}

		return nodeItemsFor(ctx, ec, allNodes), nil
	}

	return allItems, nil
}

func sequenceHasNode(seq xdm.Sequence) bool {
	for item := range xdm.SequenceItems(seq) {
		if _, ok := item.(xdm.NodeItem); ok {
			return true
		}
	}

	return false
}
