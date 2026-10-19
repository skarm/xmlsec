// Derived from lestrrat-go/helium at 7362c0a70122a757780f4d0b545a9b370dead6ab.
// Copyright (c) 2015 lestrrat. MIT License; see licenses/MIT-helium.txt at the repository root.

package xpath

import (
	"context"
	"slices"

	"github.com/skarm/xmlsec/transform/internal/xdm"
)

// Fuse descendant-or-self::node() plus a child/attribute step into a
// preorder walk, producing document order without a whole-document order index.
// Predicates still see each parent's candidate list, so position() and last()
// retain their step-by-step meaning.
//
// Nested contexts are deduplicated, but their subtree sizes are still charged.
// For predicates that can fail or charge operations, a counting pass establishes
// node limits and document registration before any predicate runs. Quiet
// predicates permit a single pass. Unsupported context orders use separate steps.

// fusesDescendantStep reports whether steps[i] is descendant-or-self::node()
// without predicates and steps[i+1] is a child or attribute step.
func fusesDescendantStep(steps []vmLocationStep, i int) bool {
	if i+1 >= len(steps) {
		return false
	}

	step := steps[i]
	if step.Axis != AxisDescendantOrSelf || len(step.Predicates) != 0 {
		return false
	}

	tt, ok := step.NodeTest.(xdm.TypeTest)
	if !ok || tt.Kind != xdm.NodeKindNode {
		return false
	}

	switch steps[i+1].Axis {
	case AxisChild, AxisAttribute:
		return true
	}

	return false
}

// fusesDescendantContexts reports whether the fused walk can run from the
// context list nodes, which is sorted in document order and duplicate-free.
// Every node must pass xdm.OrderedFrom. With more than one node, none may
// be an attribute or namespace node (whose position sits between an element
// and its children), and a node inside the subtree of an earlier one must be
// a kind the walk of that subtree visits (xdm.IsXDMChild).
func fusesDescendantContexts(nodes []xdm.Node) bool {
	if len(nodes) == 0 {
		return false
	}

	if len(nodes) == 1 {
		return xdm.OrderedFrom(nodes[0])
	}

	for _, n := range nodes {
		switch n.Type() {
		case xdm.AttributeNode, xdm.NamespaceNode:
			return false
		}

		if !xdm.OrderedFrom(n) {
			return false
		}
	}

	for i := 0; i < len(nodes); {
		nested := nodes[i+1 : i+1+nestedContextRun(nodes, i)]
		for _, n := range nested {
			if !xdm.IsXDMChild(n) {
				return false
			}
		}

		i += 1 + len(nested)
	}

	return true
}

// nestedContextRun returns how many of the nodes that follow contexts[i] lie
// inside its subtree. contexts is sorted in document order, so they are the
// ones right after it.
func nestedContextRun(contexts []xdm.Node, i int) int {
	top := contexts[i]
	prevParent := top.Parent()
	prevNested := false
	run := 0

	for _, n := range contexts[i+1:] {
		parent := n.Parent()
		nested := prevNested
		// A sibling of the previous node lies inside top exactly when the
		// previous node does: top is not one of them, so it is an ancestor
		// of one exactly when it is an ancestor of their parent.
		if parent == nil || parent != prevParent {
			nested = hasAncestor(n, top)
		}

		if !nested {
			break
		}

		run++
		prevParent = parent
		prevNested = true
	}

	return run
}

func hasAncestor(n, a xdm.Node) bool {
	for p := n.Parent(); p != nil; p = p.Parent() {
		if p == a {
			return true
		}
	}

	return false
}

// evalVMDescendantStep evaluates descendant-or-self::node()/step from the
// context list contexts, where step is a child or attribute step. contexts
// must pass fusesDescendantContexts.
func evalVMDescendantStep(evalFn exprEvaluator, ctx context.Context, ec *evalContext, contexts []xdm.Node, step vmLocationStep) ([]xdm.Node, error) {
	switch {
	case len(step.Predicates) == 0:
		return descendantStepNoPredicates(ctx, ec, contexts, step)
	case quietPredicates(ec, step.Predicates):
		return descendantStepQuietPredicates(evalFn, ctx, ec, contexts, step)
	default:
		return descendantStepWithPredicates(evalFn, ctx, ec, contexts, step)
	}
}

// quietPredicates reports whether preds only select nodes: each is a
// position ([N]), an attribute test ([@a]) or an attribute comparison with a
// string ([@a = 's']) that never falls back to evaluating the comparison,
// which it does only for an attribute with a type annotation. Such predicates
// charge no operations and fail only when ctx is cancelled.
func quietPredicates(ec *evalContext, preds []Expr) bool {
	for _, pred := range preds {
		switch pred.(type) {
		case vmPositionPredicateExpr, vmAttributeExistsPredicateExpr:
		case vmAttributeEqualsStringPredicateExpr:
			if ec.typeAnnotations != nil {
				return false
			}
		default:
			return false
		}
	}

	return true
}

// descendantStepNoPredicates walks the subtree of every outermost context
// node once, collecting the step's matches in document order.
func descendantStepNoPredicates(ctx context.Context, ec *evalContext, contexts []xdm.Node, step vmLocationStep) ([]xdm.Node, error) {
	var out []xdm.Node

	total := 0
	// candidates counts what the second step enumerates. On the child axis
	// it is every subtree node but the context nodes.
	candidates := 0

	var sizes nestedSubtrees

	for i := 0; i < len(contexts); {
		c := contexts[i]
		sizes.reset(contexts[i+1 : i+1+nestedContextRun(contexts, i)])

		var (
			visited, traversed int
			err                error
		)

		out, visited, traversed, err = appendDescendantMatches(ctx, ec, out, c, step, &sizes)
		if err != nil {
			return nil, err
		}

		if err := chargeDescendantOrSelf(ctx, ec, visited, sizes.sizes); err != nil {
			return nil, err
		}

		total += visited
		candidates += traversed
		i += 1 + len(sizes.sizes)
	}

	if err := finishDescendantOrSelfStep(ec, contexts[0], total); err != nil {
		return nil, err
	}

	if err := ec.countOps(ctx, candidates); err != nil {
		return nil, err
	}

	return clampDescendantResult(ec, out)
}

// appendDescendantMatches walks the subtree of c, appending the matches of
// step to out and measuring the nested context subtrees in sizes. It returns
// the number of subtree nodes and the number of candidates the step
// enumerates from them.
func appendDescendantMatches(ctx context.Context, ec *evalContext, out []xdm.Node, c xdm.Node, step vmLocationStep, sizes *nestedSubtrees) ([]xdm.Node, int, int, error) {
	stack, err := startDescendantWalk(ctx, ec, c)
	if err != nil {
		return nil, 0, 0, err
	}

	visited := 1
	candidates := 0

	if step.Axis == AxisAttribute {
		var traversed int

		out, traversed, err = appendAxisNodeMatches(ctx, out, ec, c, AxisAttribute, step.NodeTest)
		if err != nil {
			return nil, 0, 0, err
		}

		candidates += traversed
	}

	for len(stack) > 0 {
		if err := ctx.Err(); err != nil {
			return nil, 0, 0, err
		}

		if len(sizes.pending) > 0 {
			sizes.close(len(stack), visited)
		}

		last := len(stack) - 1
		cur := stack[last]
		stack = stack[:last]

		visited++
		if visited > ec.maxNodes {
			return nil, 0, 0, xdm.ErrNodeSetLimit
		}

		if sizes.next < len(sizes.nested) {
			sizes.open(cur, len(stack), visited)
		}

		if step.Axis == AxisChild {
			candidates++

			if matchNodeTest(step.NodeTest, cur, AxisChild, ec) {
				out = append(out, cur)
			}
		} else {
			var traversed int

			out, traversed, err = appendAxisNodeMatches(ctx, out, ec, cur, AxisAttribute, step.NodeTest)
			if err != nil {
				return nil, 0, 0, err
			}

			candidates += traversed
		}

		stack, err = xdm.PushXDMChildren(ctx, stack, cur)
		if err != nil {
			return nil, 0, 0, err
		}
	}

	if len(sizes.pending) > 0 {
		sizes.close(0, visited)
	}

	return out, visited, candidates, nil
}

// descendantStepWithPredicates counts the subtree of every context node and
// charges the descendant-or-self step, then walks the outermost subtrees
// again, applying the second step and its predicates to every subtree node
// in document order.
func descendantStepWithPredicates(evalFn exprEvaluator, ctx context.Context, ec *evalContext, contexts []xdm.Node, step vmLocationStep) ([]xdm.Node, error) {
	total := 0

	var (
		tops  []xdm.Node
		sizes nestedSubtrees
	)

	for i := 0; i < len(contexts); {
		c := contexts[i]
		sizes.reset(contexts[i+1 : i+1+nestedContextRun(contexts, i)])

		visited, err := countDescendantOrSelf(ctx, ec, c, &sizes)
		if err != nil {
			return nil, err
		}

		if err := chargeDescendantOrSelf(ctx, ec, visited, sizes.sizes); err != nil {
			return nil, err
		}

		total += visited

		tops = append(tops, c)
		i += 1 + len(sizes.sizes)
	}

	if err := finishDescendantOrSelfStep(ec, contexts[0], total); err != nil {
		return nil, err
	}

	w := descendantWalker{step: step}
	for _, c := range tops {
		if _, err := w.walk(evalFn, ctx, ec, c); err != nil {
			return nil, err
		}
	}

	return clampDescendantResult(ec, w.out)
}

// descendantStepQuietPredicates walks the subtree of every outermost context
// node once, counting it as countDescendantOrSelf does and applying the
// second step and its predicates, which must pass quietPredicates, to every
// subtree node in document order. It charges what
// descendantStepWithPredicates charges, in the same order: the predicates
// charge nothing, so the second step's charges can wait until the walk ends.
func descendantStepQuietPredicates(evalFn exprEvaluator, ctx context.Context, ec *evalContext, contexts []xdm.Node, step vmLocationStep) ([]xdm.Node, error) {
	total := 0
	w := descendantWalker{step: step, counting: true}

	for i := 0; i < len(contexts); {
		c := contexts[i]
		w.sizes.reset(contexts[i+1 : i+1+nestedContextRun(contexts, i)])
		// The checks startDescendantWalk makes before the walk.
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		if ec.maxNodes < 1 {
			return nil, xdm.ErrNodeSetLimit
		}

		visited, err := w.walk(evalFn, ctx, ec, c)
		if err != nil {
			return nil, err
		}

		if err := chargeDescendantOrSelf(ctx, ec, visited, w.sizes.sizes); err != nil {
			return nil, err
		}

		total += visited
		i += 1 + len(w.sizes.sizes)
	}

	if err := finishDescendantOrSelfStep(ec, contexts[0], total); err != nil {
		return nil, err
	}

	if err := ec.countOps(ctx, w.candidates); err != nil {
		return nil, err
	}

	return clampDescendantResult(ec, w.out)
}

// descendantEntry is a node waiting on the pre-order walk stack. selected
// records whether the child step of its parent kept it.
type descendantEntry struct {
	node     xdm.Node
	selected bool
}

// descendantWalker applies the second step and its predicates to every node
// of a subtree, in pre-order. It emits each child the step selects when the
// walk pops it, and the attributes the step selects when the walk reaches
// their element.
//
// Without counting, it charges the candidates of each node before applying
// the predicates, as the step-by-step evaluation does. With counting (quiet
// predicates), it also counts the subtree, fails where countDescendantOrSelf
// fails, measures the nested context subtrees in sizes, and adds the
// candidates to candidates for the caller to charge.
//
// The evaluator is a parameter of walk rather than a field: a field would let
// the method value the VM passes as evalFn escape to the heap on every
// evaluation.
type descendantWalker struct {
	step       vmLocationStep
	counting   bool
	out        []xdm.Node
	matched    []xdm.Node
	stack      []descendantEntry
	sizes      nestedSubtrees
	candidates int
}

// walk walks the subtree of c. When counting, it returns the number of
// subtree nodes.
func (w *descendantWalker) walk(evalFn exprEvaluator, ctx context.Context, ec *evalContext, c xdm.Node) (int, error) {
	step := w.step
	w.stack = append(w.stack[:0], descendantEntry{node: c})
	visited := 0

	for len(w.stack) > 0 {
		if err := walkCounting(ctx, w, visited); err != nil {
			return 0, err
		}

		last := len(w.stack) - 1
		cur := w.stack[last]

		w.stack = w.stack[:last]
		if w.counting {
			visited++
			if visited > ec.maxNodes {
				return 0, xdm.ErrNodeSetLimit
			}

			if w.sizes.next < len(w.sizes.nested) {
				w.sizes.open(cur.node, len(w.stack), visited)
			}
		}

		if cur.selected {
			w.out = append(w.out, cur.node)
		}

		start := len(w.stack)

		var (
			traversed int
			err       error
		)
		if returned1, matchedBranch := walkAxis(ctx, &step, w, &traversed, &err, ec, &cur); matchedBranch {
			return 0, returned1
		}

		if w.counting {
			w.candidates += traversed
		} else if err := ec.countOps(ctx, traversed); err != nil {
			return 0, err
		}

		selected := w.matched
		for _, pred := range step.Predicates {
			selected, err = applyVMPredicate(evalFn, ctx, ec, selected, pred)
			if err != nil {
				return 0, err
			}
		}

		if step.Axis == AxisChild {
			markSelectedEntries(w.stack[start:], selected)
		} else {
			w.out = append(w.out, selected...)
		}

		slices.Reverse(w.stack[start:])
	}

	if len(w.sizes.pending) > 0 {
		w.sizes.close(0, visited)
	}

	return visited, nil
}

// pushMatchingChildEntries pushes the XDM children of n onto stack in
// document order and appends the ones that match test to matched,
// enumerating them as the child step does (appendAxisNodeMatches). It returns
// the grown stack and matched slices and the number of children enumerated.
func pushMatchingChildEntries(ctx context.Context, ec *evalContext, stack []descendantEntry, matched []xdm.Node, n xdm.Node, test xdm.NodeTest) ([]descendantEntry, []xdm.Node, int, error) {
	if _, ok := n.(*xdm.Attribute); ok {
		return stack, matched, 0, nil
	}

	traversed := 0

	for child := range xdm.Children(n) {
		if err := ctx.Err(); err != nil {
			return nil, nil, 0, err
		}

		if !xdm.IsXDMChild(child) {
			continue
		}

		traversed++

		stack = append(stack, descendantEntry{node: child})
		if matchNodeTest(test, child, AxisChild, ec) {
			matched = append(matched, child)
		}
	}

	return stack, matched, traversed, nil
}

// pushChildEntries pushes the XDM children of n onto stack in document
// order.
func pushChildEntries(ctx context.Context, stack []descendantEntry, n xdm.Node) ([]descendantEntry, error) {
	if _, ok := n.(*xdm.Attribute); ok {
		return stack, nil
	}

	for child := range xdm.Children(n) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		if xdm.IsXDMChild(child) {
			stack = append(stack, descendantEntry{node: child})
		}
	}

	return stack, nil
}

// markSelectedEntries flags the entries whose node is in selected. Both lists
// are in document order and selected is a subsequence of the entries.
func markSelectedEntries(entries []descendantEntry, selected []xdm.Node) {
	k := 0
	for i := range entries {
		if k == len(selected) {
			return
		}

		if entries[i].node == selected[k] {
			entries[i].selected = true
			k++
		}
	}
}

func walkCounting(ctx context.Context, w *descendantWalker, visited int) error {
	if w.counting {
		if err := ctx.Err(); err != nil {
			return err
		}

		if len(w.sizes.pending) > 0 {
			w.sizes.close(len(w.stack), visited)
		}
	}

	return nil
}

func walkAxis(ctx context.Context, step *vmLocationStep, w *descendantWalker, traversed *int, err *error, ec *evalContext, cur *descendantEntry) (returned1 error, matchedBranch bool) {
	if step.Axis == AxisChild {
		w.stack, w.matched, (*traversed), (*err) = pushMatchingChildEntries(ctx, ec, w.stack, w.matched[:0], cur.node, step.NodeTest)
		if (*err) != nil {
			return (*err), true
		}
	} else {
		w.matched, (*traversed), (*err) = appendAxisNodeMatches(ctx, w.matched[:0], ec, cur.node, AxisAttribute, step.NodeTest)
		if (*err) != nil {
			return (*err), true
		}

		w.stack, (*err) = pushChildEntries(ctx, w.stack, cur.node)
		if (*err) != nil {
			return (*err), true
		}
	}

	return
}

// startDescendantWalk begins the descendant-or-self walk from c the way
// xdm.TraverseAxis does: it checks ctx, counts c against the node-set
// limit, and returns the stack of c's XDM children. An attribute has none.
func startDescendantWalk(ctx context.Context, ec *evalContext, c xdm.Node) ([]xdm.Node, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	if ec.maxNodes < 1 {
		return nil, xdm.ErrNodeSetLimit
	}

	if _, ok := c.(*xdm.Attribute); ok {
		return nil, nil
	}

	return xdm.PushXDMChildren(ctx, nil, c)
}

// countDescendantOrSelf returns the size of the descendant-or-self axis of c,
// failing where xdm.TraverseAxis fails on that axis, and measures the
// nested context subtrees in sizes.
func countDescendantOrSelf(ctx context.Context, ec *evalContext, c xdm.Node, sizes *nestedSubtrees) (int, error) {
	stack, err := startDescendantWalk(ctx, ec, c)
	if err != nil {
		return 0, err
	}

	visited := 1

	for len(stack) > 0 {
		if err := ctx.Err(); err != nil {
			return 0, err
		}

		if len(sizes.pending) > 0 {
			sizes.close(len(stack), visited)
		}

		last := len(stack) - 1
		cur := stack[last]
		stack = stack[:last]

		visited++
		if visited > ec.maxNodes {
			return 0, xdm.ErrNodeSetLimit
		}

		if sizes.next < len(sizes.nested) {
			sizes.open(cur, len(stack), visited)
		}

		stack, err = xdm.PushXDMChildren(ctx, stack, cur)
		if err != nil {
			return 0, err
		}
	}

	if len(sizes.pending) > 0 {
		sizes.close(0, visited)
	}

	return visited, nil
}

// chargeDescendantOrSelf charges the descendant-or-self traversal of an
// outermost context node, whose subtree has visited nodes, and then of the
// context nodes nested in it, whose subtrees have nested nodes each, as the
// step-by-step evaluation charges them one after the other.
func chargeDescendantOrSelf(ctx context.Context, ec *evalContext, visited int, nested []int) error {
	if err := ec.countOps(ctx, visited); err != nil {
		return err
	}

	for _, size := range nested {
		if err := ec.countOps(ctx, size); err != nil {
			return err
		}
	}

	return nil
}

// pendingSubtree is a nested context node whose subtree the walk is in.
type pendingSubtree struct {
	index    int // index in nestedSubtrees.nested
	stackLen int // stack length right after the node was popped
	start    int // visit count including the node
}

// nestedSubtrees measures the subtrees of the context nodes that lie inside
// the subtree a walk visits. The walks call open only while a nested node is
// still ahead (next < len(nested)) and close only while a subtree is pending,
// so a walk without nested context nodes pays two comparisons per node. The walk pops nodes in pre-order from a stack
// that holds the pending XDM children; when it pops a nested context node,
// the node's descendants are exactly the nodes it pops while the stack is
// longer than it was right after that pop.
type nestedSubtrees struct {
	nested []xdm.Node
	// sizes[i] is the size of the subtree of nested[i].
	sizes []int
	// next is the index of the next nested context node the walk reaches.
	next int
	// pending holds the nested context nodes whose subtrees the walk is in,
	// innermost last.
	pending []pendingSubtree
}

// reset starts measuring the nested context nodes nested, which are sorted
// in document order, reusing the buffers of the previous measure.
func (s *nestedSubtrees) reset(nested []xdm.Node) {
	s.nested = nested
	s.next = 0

	s.pending = s.pending[:0]
	if len(nested) == 0 {
		s.sizes = s.sizes[:0]
		return
	}

	s.sizes = slices.Grow(s.sizes[:0], len(nested))[:len(nested)]
	clear(s.sizes)
}

// open records that the walk popped n, leaving stackLen entries on the
// stack, as its visited-th node.
func (s *nestedSubtrees) open(n xdm.Node, stackLen, visited int) {
	if s.next == len(s.nested) || n != s.nested[s.next] {
		return
	}

	s.pending = append(s.pending, pendingSubtree{index: s.next, stackLen: stackLen, start: visited})
	s.next++
}

// close ends the subtrees the walk has left: those whose node was popped
// with at least stackLen entries left on the stack. visited is the number
// of nodes the walk has popped so far.
func (s *nestedSubtrees) close(stackLen, visited int) {
	for len(s.pending) > 0 {
		last := len(s.pending) - 1

		p := s.pending[last]
		if stackLen > p.stackLen {
			return
		}

		s.sizes[p.index] = visited - p.start + 1
		s.pending = s.pending[:last]
	}
}

// finishDescendantOrSelfStep ends the descendant-or-self::node() step whose
// result has total nodes the way xdm.OrderStepResult ends it: a result of
// more than maxNodes nodes fails, and a result of more than one node
// registers the document of c in the order cache.
func finishDescendantOrSelfStep(ec *evalContext, c xdm.Node, total int) error {
	if total > ec.maxNodes {
		return xdm.ErrNodeSetLimit
	}

	if total > 1 {
		ec.docOrder.ReserveDocument(c)
	}

	return nil
}

// clampDescendantResult ends the second step the way xdm.OrderStepResult
// ends a step whose result is already in document order: a result of more
// than maxNodes nodes fails, and the capacity of a longer-than-one result is
// clamped.
func clampDescendantResult(ec *evalContext, out []xdm.Node) ([]xdm.Node, error) {
	if len(out) <= 1 {
		return out, nil
	}

	if len(out) > ec.maxNodes {
		return nil, xdm.ErrNodeSetLimit
	}

	return out[:len(out):len(out)], nil
}
