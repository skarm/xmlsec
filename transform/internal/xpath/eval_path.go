// Derived from lestrrat-go/helium at 7362c0a70122a757780f4d0b545a9b370dead6ab.
// Copyright (c) 2015 lestrrat. MIT License; see licenses/MIT-helium.txt at the repository root.

package xpath

import (
	"context"
	"fmt"
	"math"
	"math/big"
	"strings"

	"github.com/skarm/xmlsec/internal/lexicon"
	"github.com/skarm/xmlsec/transform/internal/xdm"
)

func evalLiteral(e LiteralExpr) (xdm.Sequence, error) {
	switch v := e.Value.(type) {
	case string:
		return xdm.SingleString(v), nil
	case *big.Int:
		return xdm.SingleIntegerBig(v), nil
	case *big.Rat:
		return xdm.SingleDecimal(v), nil
	case float64:
		return xdm.SingleDouble(v), nil
	}

	return nil, fmt.Errorf("%w: literal %T", ErrUnsupportedExpr, e.Value)
}

func evalVariable(ctx context.Context, ec *evalContext, e VariableExpr) (xdm.Sequence, error) {
	if ec.vars != nil {
		if value, ok := ec.vars.Lookup(VariableKey(e.Name, ec.namespaces)); ok {
			return enrichNodeItems(ctx, ec, value), nil
		}

		if value, ok := ec.vars.Lookup(e.Name); ok {
			return enrichNodeItems(ctx, ec, value), nil
		}
	}
	// Fallback to lazy variable resolver (e.g. for XSLT global variables)
	if ec.variableResolver != nil {
		v, ok, err := ec.variableResolver.ResolveVariable(ctx, VariableKey(e.Name, ec.namespaces))
		if err != nil {
			return nil, err
		}

		if ok {
			return enrichNodeItems(ctx, ec, v), nil
		}
	}

	return nil, UndefinedVariableError(e.Name, ec.version)
}

// enrichNodeItems ensures NodeItems in a sequence have their TypeAnnotation
// and related fields set from the evalContext's type annotations map. This is
// needed because variables may store NodeItems created before type annotations
// were available (e.g., validated after construction).
func enrichNodeItems(ctx context.Context, ec *evalContext, seq xdm.Sequence) xdm.Sequence {
	if ec == nil || ec.typeAnnotations == nil {
		return seq
	}

	needsEnrich := false

	for item := range xdm.SequenceItems(seq) {
		if ni, ok := item.(xdm.NodeItem); ok && ni.TypeAnnotation == "" {
			if _, hasAnn := ec.typeAnnotations[ni.Node]; hasAnn {
				needsEnrich = true
				break
			}
		}
	}

	if !needsEnrich {
		return seq
	}

	result := make(xdm.ItemSlice, xdm.SequenceLen(seq))
	i := 0

	for item := range xdm.SequenceItems(seq) {
		if ni, ok := item.(xdm.NodeItem); ok && ni.TypeAnnotation == "" {
			enriched := nodeItemFor(ctx, ec, ni.Node)
			result[i] = enriched
		} else {
			result[i] = item
		}

		i++
	}

	return result
}

func evalSequenceExpr(evalFn exprEvaluator, ctx context.Context, ec *evalContext, e SequenceExpr) (xdm.Sequence, error) {
	if len(e.Items) == 0 {
		return nil, nil
	}

	var result xdm.ItemSlice

	for _, item := range e.Items {
		seq, err := evalFn(ctx, ec, item)
		if err != nil {
			return nil, err
		}
		// Concatenate through appendBoundedSeq so maxNodes / OpLimit /
		// cancellation fire across the aggregate. Each operand is itself capped,
		// but the concatenation is not, so a sequence of K capped range operands
		// (1 to N, 1 to N, ...) would otherwise materialize K*N items past the
		// configured limit.
		result, err = appendBoundedSeq(ctx, ec, result, seq, ec.maxNodes)
		if err != nil {
			return nil, err
		}
	}

	return result, nil
}

func evalLocationPath(evalFn exprEvaluator, ctx context.Context, ec *evalContext, lp *LocationPath) (xdm.Sequence, error) {
	var nodes []xdm.Node

	if lp.Absolute {
		if xdm.IsNilNode(ec.node) {
			return nil, &xdm.Error{Code: lexicon.ErrXPDY0002, Message: errMsgContextItemAbsent}
		}

		root := xdm.DocumentRoot(ec.node)
		// XPDY0050: the root of the context node's tree must be a document node.
		if root.Type() != xdm.DocumentNode {
			return nil, &xdm.Error{Code: errCodeXPDY0050, Message: textRootOfTheTreeContainingTheContextNode}
		}

		nodes = []xdm.Node{root}
	} else {
		if xdm.IsNilNode(ec.node) {
			return nil, &xdm.Error{Code: lexicon.ErrXPDY0002, Message: errMsgContextItemAbsent}
		}

		nodes = []xdm.Node{ec.node}
	}

	// The path starts from one node and every step returns its result sorted
	// and duplicate-free, so each step's context list meets the precondition
	// of xdm.OrderStepResult, which ends every step.
	var err error

	for _, step := range lp.Steps {
		if len(step.Predicates) > 0 {
			nodes, err = evalStepWithPredicates(evalFn, ctx, ec, nodes, step)
		} else {
			nodes, err = evalStepNoPredicates(ctx, ec, nodes, step)
		}

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

func evalVMLocationPath(evalFn exprEvaluator, ctx context.Context, ec *evalContext, lp vmLocationPathExpr) (xdm.Sequence, error) {
	nodes, err := evalVMLocationPathNodes(evalFn, ctx, ec, lp)
	if err != nil {
		return nil, err
	}

	return nodeItemsFor(ctx, ec, nodes), nil
}

func nodeItemsFor(ctx context.Context, ec *evalContext, nodes []xdm.Node) xdm.ItemSlice {
	result := make(xdm.ItemSlice, len(nodes))
	for i, n := range nodes {
		result[i] = nodeItemFor(ctx, ec, n)
	}

	return result
}

// evalVMLocationPathNodes evaluates lp and returns its nodes, in document
// order and free of duplicates, without wrapping them in items.
func evalVMLocationPathNodes(evalFn exprEvaluator, ctx context.Context, ec *evalContext, lp vmLocationPathExpr) ([]xdm.Node, error) {
	start, err := locationPathStart(ec, lp)
	if err != nil {
		return nil, err
	}

	return evalVMSteps(evalFn, ctx, ec, []xdm.Node{start}, lp.Steps)
}

// locationPathStart returns the node the location path lp starts from: the
// root of the context node's tree for an absolute path, which must be a
// document node, and the context node otherwise.
func locationPathStart(ec *evalContext, lp vmLocationPathExpr) (xdm.Node, error) {
	if xdm.IsNilNode(ec.node) {
		if ec.contextItem != nil {
			return nil, &xdm.Error{Code: errCodeXPTY0020, Message: "a path requires a node context item"}
		}

		return nil, &xdm.Error{Code: lexicon.ErrXPDY0002, Message: errMsgContextItemAbsent}
	}

	if !lp.Absolute {
		return ec.node, nil
	}

	root := xdm.DocumentRoot(ec.node)
	// XPDY0050: the root of the context node's tree must be a document node.
	if root.Type() != xdm.DocumentNode {
		return nil, &xdm.Error{Code: errCodeXPDY0050, Message: textRootOfTheTreeContainingTheContextNode}
	}

	return root, nil
}

// evalVMSteps evaluates steps from the context list nodes, which must be
// sorted in document order and free of duplicates, and returns the result of
// the last step.
func evalVMSteps(evalFn exprEvaluator, ctx context.Context, ec *evalContext, nodes []xdm.Node, steps []vmLocationStep) ([]xdm.Node, error) {
	// The path starts from one node and every step returns its result sorted
	// and duplicate-free, so each step's context list meets the precondition
	// of xdm.OrderStepResult, which ends every step.
	var err error

	for i := 0; i < len(steps); i++ {
		step := steps[i]
		switch {
		case fusesDescendantStep(steps, i) && fusesDescendantContexts(nodes):
			i++
			nodes, err = evalVMDescendantStep(evalFn, ctx, ec, nodes, steps[i])
		case len(step.Predicates) > 0:
			nodes, err = evalVMStepWithPredicates(evalFn, ctx, ec, nodes, step)
		default:
			nodes, err = evalVMStepNoPredicates(ctx, ec, nodes, step)
		}

		if err != nil {
			return nil, err
		}
	}

	return nodes, nil
}

func nodeItemFor(ctx context.Context, ec *evalContext, n xdm.Node) xdm.NodeItem {
	ni := xdm.NodeItem{Node: n}
	if ec == nil || ec.typeAnnotations == nil {
		return ni
	}

	ni.TypeAnnotation = ec.typeAnnotations[n]
	ni.AtomizedType = atomizedTypeForAnnotation(ni.TypeAnnotation, ec.schemaDeclarations)

	ni.QNameNoDefaultNS = ec.qnameValueNoDefaultNS
	if ec.schemaDeclarations != nil && ni.TypeAnnotation != "" {
		if itemType, ok := ec.schemaDeclarations.ListItemType(ni.TypeAnnotation); ok {
			ni.ListItemType = itemType
			ni.ListItemAtomized = atomizedTypeForAnnotation(itemType, ec.schemaDeclarations)
			// When the list ITEM type is a UNION, the static ListItemAtomized base is
			// one member only; resolve EACH token's active union member so the list
			// atomizes per-token consistently with $value.
			if members := ec.schemaDeclarations.UnionMemberTypes(itemType); len(members) > 0 {
				tokens := xsdListFields(xdm.StringValue(n))

				leaves := make([]*xdm.NodeItemUnionMember, len(tokens))
				for i, tok := range tokens {
					leaves[i] = resolveActiveUnionLeafForValue(ctx, ec, n, itemType, ni.QNameNoDefaultNS, tok)
				}

				ni.ListItemLeaves = leaves
			}
		}

		if members := ec.schemaDeclarations.UnionMemberTypes(ni.TypeAnnotation); len(members) > 0 {
			ni.UnionMemberTypes = members
			if leaf := resolveActiveUnionLeaf(ctx, ec, n, ni.TypeAnnotation, ni.QNameNoDefaultNS); leaf != nil {
				ni.ActiveUnionMember = leaf
			}
		}
	}

	return ni
}

// resolveActiveUnionLeaf resolves a union node's value-dependent ACTIVE LEAF member:
// the first DIRECT member (declaration order) the value fully validates against;
// when that member is ITSELF a union it descends recursively to find the nested
// leaf, mirroring fixedUnionActiveMember so data() and $value agree for arbitrarily
// nested unions. Full validation = the lexical/value cast (and, for a list member,
// every token plus the list structure) AND the member's own facets/assertions via
// SchemaDeclarations.ValidateCastWithNS (a no-op for built-ins, where the cast check
// already covers validity). Returns nil when no member validates.
func resolveActiveUnionLeaf(ctx context.Context, ec *evalContext, n xdm.Node, unionType string, qnameNoDefault bool) *xdm.NodeItemUnionMember {
	return resolveActiveUnionLeafForValue(ctx, ec, n, unionType, qnameNoDefault, xdm.StringValue(n))
}

// resolveActiveUnionLeafForValue resolves the active leaf member of unionType for an
// EXPLICIT value, in place of the node's whole string value, used to resolve EACH
// token of an xs:list whose item type is a union — so a list-of-union node atomizes
// each token through its own active member (matching $value), not one static base.
// QName/NOTATION members still resolve their prefix against the node n's namespaces.
func resolveActiveUnionLeafForValue(ctx context.Context, ec *evalContext, n xdm.Node, unionType string, qnameNoDefault bool, val string) *xdm.NodeItemUnionMember {
	nsMap := inScopeNSMap(n)
	// visited tracks union type NAMES currently being descended, so any finite
	// acyclic nesting (however deep) is fully walked while a cyclic union graph
	// still terminates — mirroring the validation side's visited-set guards rather
	// than capping at an arbitrary depth.
	visited := map[string]struct{}{unionType: {}}

	return resolveActiveUnionLeafRec(ctx, ec, n, unionType, qnameNoDefault, val, nsMap, visited)
}

func resolveActiveUnionLeafRec(ctx context.Context, ec *evalContext, n xdm.Node, unionType string, qnameNoDefault bool, val string, nsMap map[string]string, visited map[string]struct{}) *xdm.NodeItemUnionMember {
	for _, m := range ec.schemaDeclarations.UnionMemberTypes(unionType) {
		// A member that is itself a union: full-validate the value against it, then
		// descend to its nested active leaf (matches fixedUnionActiveMember). A member
		// already on the descent path is a cycle — skip it (the cyclic graph is
		// invalid, but node atomization must still terminate).
		if nested := ec.schemaDeclarations.UnionMemberTypes(m); len(nested) > 0 {
			if _, seen := visited[m]; seen {
				continue
			}

			if err := ec.schemaDeclarations.ValidateCastWithNS(ctx, val, m, nsMap); err != nil {
				continue
			}

			visited[m] = struct{}{}
			leaf := resolveActiveUnionLeafRec(ctx, ec, n, m, qnameNoDefault, val, nsMap, visited)
			delete(visited, m)

			if leaf != nil {
				return leaf
			}

			continue
		}

		meta := unionMemberMeta(ec.schemaDeclarations, m)
		if !unionMemberCastOK(val, meta, n, qnameNoDefault) {
			continue
		}

		if err := ec.schemaDeclarations.ValidateCastWithNS(ctx, val, m, nsMap); err != nil {
			continue
		}
		// When this active member is a LIST whose item type is itself a UNION, resolve
		// EACH list token's active leaf so the member atomizes per-token (matching
		// $value), not through one static ListItemAtom base.
		if meta.ListItem != "" {
			if itemMembers := ec.schemaDeclarations.UnionMemberTypes(meta.ListItem); len(itemMembers) > 0 {
				tokens := xsdListFields(val)

				leaves := make([]*xdm.NodeItemUnionMember, len(tokens))
				for i, tok := range tokens {
					leaves[i] = resolveActiveUnionLeafForValue(ctx, ec, n, meta.ListItem, qnameNoDefault, tok)
				}

				meta.ListItemLeaves = leaves
			}
		}

		leaf := meta

		return &leaf
	}

	return nil
}

// unionMemberMeta builds the per-member atomization metadata (built-in base, and
// list-item info when the member is a list) for a union member type name.
func unionMemberMeta(decls SchemaDeclarations, member string) xdm.NodeItemUnionMember {
	meta := xdm.NodeItemUnionMember{
		TypeName: member,
		Atomized: atomizedTypeForAnnotation(member, decls),
	}
	if li, ok := decls.ListItemType(member); ok {
		meta.ListItem = li
		meta.ListItemAtom = atomizedTypeForAnnotation(li, decls)
	}

	return meta
}

// unionMemberCastOK reports whether val is lexically/value-valid for a NON-UNION
// union member (a list member requires every whitespace token to atomize, an atomic
// member to cast / a QName/NOTATION member to resolve as a single token). It does
// NOT check user facets — resolveActiveUnionLeafRec layers ValidateCastWithNS on top
// — but it is what enforces BUILT-IN member validity (ValidateCast is a no-op for
// built-ins).
func unionMemberCastOK(val string, m xdm.NodeItemUnionMember, node xdm.Node, qnameNoDefault bool) bool {
	if m.ListItem != "" {
		// An EMPTY list value (zero tokens) is a valid list lexically — the validator
		// accepts it unless a facet (e.g. minLength) disallows it, which the
		// ValidateCastWithNS layer enforces. Do NOT reject it here, else active-member
		// selection for node atomization would disagree with validation/$value (a
		// union(IntList, xs:string) with value "" must resolve to the empty list).
		lni := xdm.NodeItem{Node: node, ListItemAtomized: m.ListItemAtom, QNameNoDefaultNS: qnameNoDefault}
		for _, tok := range xsdListFields(val) {
			if _, err := atomizeListToken(tok, m.ListItem, lni); err != nil {
				return false
			}
		}

		return true
	}

	if m.Atomized == xdm.TypeQName || m.Atomized == xdm.TypeNOTATION ||
		m.TypeName == xdm.TypeQName || m.TypeName == xdm.TypeNOTATION {
		if len(xsdListFields(val)) != 1 {
			return false
		}

		_, err := resolveQNameFromNode(val, node, qnameNoDefault)

		return err == nil
	}

	t := m.Atomized
	if t == "" {
		t = m.TypeName
	}

	_, err := CastFromString(val, t)

	return err == nil
}

// inScopeNSMap returns the in-scope namespace bindings (prefix → URI) for a node,
// used to resolve QName prefixes when validating a union member value-dependently.
func inScopeNSMap(n xdm.Node) map[string]string {
	scope := n
	if _, ok := scope.(*xdm.Element); !ok {
		if p := n.Parent(); p != nil {
			scope = p
		}
	}

	e, ok := scope.(*xdm.Element)
	if !ok {
		return nil
	}

	out := make(map[string]string)
	for prefix, ns := range xdm.InScopeNamespaces(e, false) {
		out[prefix] = ns.URI()
	}

	return out
}

func evalStepWithPredicates(evalFn exprEvaluator, ctx context.Context, ec *evalContext, nodes []xdm.Node, step Step) ([]xdm.Node, error) {
	allFiltered := make([]xdm.Node, 0, len(nodes))
	for _, n := range nodes {
		matched, traversed, err := appendAxisNodeMatches(ctx, nil, ec, n, step.Axis, step.NodeTest)
		if err != nil {
			return nil, err
		}

		if err := ec.countOps(ctx, traversed); err != nil {
			return nil, err
		}

		for _, pred := range step.Predicates {
			matched, err = applyPredicate(evalFn, ctx, ec, matched, pred)
			if err != nil {
				return nil, err
			}
		}

		allFiltered = append(allFiltered, matched...)
	}

	return xdm.OrderStepResult(allFiltered, nodes, step.Axis, ec.docOrder, ec.maxNodes)
}

func evalStepNoPredicates(ctx context.Context, ec *evalContext, nodes []xdm.Node, step Step) ([]xdm.Node, error) {
	return evalAxisStep(ctx, ec, nodes, step.Axis, step.NodeTest)
}

func evalAxisStep(ctx context.Context, ec *evalContext, nodes []xdm.Node, axis AxisType, nodeTest xdm.NodeTest) ([]xdm.Node, error) {
	next := make([]xdm.Node, 0, len(nodes))
	for _, n := range nodes {
		var (
			traversed int
			err       error
		)

		next, traversed, err = appendAxisNodeMatches(ctx, next, ec, n, axis, nodeTest)
		if err != nil {
			return nil, err
		}

		if err := ec.countOps(ctx, traversed); err != nil {
			return nil, err
		}
	}

	return xdm.OrderStepResult(next, nodes, axis, ec.docOrder, ec.maxNodes)
}

func evalVMStepWithPredicates(evalFn exprEvaluator, ctx context.Context, ec *evalContext, nodes []xdm.Node, step vmLocationStep) ([]xdm.Node, error) {
	allFiltered := make([]xdm.Node, 0, len(nodes))
	for _, n := range nodes {
		matched, traversed, err := appendAxisNodeMatches(ctx, nil, ec, n, step.Axis, step.NodeTest)
		if err != nil {
			return nil, err
		}

		if err := ec.countOps(ctx, traversed); err != nil {
			return nil, err
		}

		for _, pred := range step.Predicates {
			matched, err = applyVMPredicate(evalFn, ctx, ec, matched, pred)
			if err != nil {
				return nil, err
			}
		}

		allFiltered = append(allFiltered, matched...)
	}

	return xdm.OrderStepResult(allFiltered, nodes, step.Axis, ec.docOrder, ec.maxNodes)
}

func applyVMPredicate(evalFn exprEvaluator, ctx context.Context, ec *evalContext, nodes []xdm.Node, pred Expr) ([]xdm.Node, error) {
	switch p := pred.(type) {
	case vmPositionPredicateExpr:
		return applyVMPositionPredicate(nodes, p), nil
	case vmAttributeExistsPredicateExpr:
		return applyVMAttributeExistsPredicate(ctx, ec, nodes, p)
	case vmAttributeEqualsStringPredicateExpr:
		return applyVMAttributeEqualsStringPredicate(evalFn, ctx, ec, nodes, p)
	default:
		return applyPredicate(evalFn, ctx, ec, nodes, pred)
	}
}

func applyVMPositionPredicate(nodes []xdm.Node, pred vmPositionPredicateExpr) []xdm.Node {
	if pred.Position <= 0 || pred.Position > len(nodes) {
		return nil
	}

	return nodes[pred.Position-1 : pred.Position]
}

func applyVMAttributeExistsPredicate(ctx context.Context, ec *evalContext, nodes []xdm.Node, pred vmAttributeExistsPredicateExpr) ([]xdm.Node, error) {
	result := make([]xdm.Node, 0, len(nodes))
	for _, n := range nodes {
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		found, err := nodeHasMatchingAttribute(ctx, ec, n, pred.NodeTest)
		if err != nil {
			return nil, err
		}

		if found {
			result = append(result, n)
		}
	}

	return result, nil
}

func applyVMAttributeEqualsStringPredicate(evalFn exprEvaluator, ctx context.Context, ec *evalContext, nodes []xdm.Node, pred vmAttributeEqualsStringPredicateExpr) ([]xdm.Node, error) {
	size := len(nodes)
	result := make([]xdm.Node, 0, size)

	for i, n := range nodes {
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		match, ok, err := vmAttributeEqualsStringPredicateMatches(ctx, ec, n, pred)
		if err != nil {
			return nil, err
		}

		if !ok {
			frame := ec.pushNodeContext(n, i+1, size)
			r, err := evalFn(ctx, ec, pred.Fallback)
			ec.restoreContext(frame)

			if err != nil {
				return nil, err
			}

			predMatch, err := predicateTrue(r, i+1)
			if err != nil {
				return nil, err
			}

			match = predMatch
		}

		if match {
			result = append(result, n)
		}
	}

	return result, nil
}

func vmAttributeEqualsStringPredicateMatches(ctx context.Context, ec *evalContext, node xdm.Node, pred vmAttributeEqualsStringPredicateExpr) (bool, bool, error) {
	elem, ok := node.(*xdm.Element)
	if !ok {
		return false, true, nil
	}

	mustFallback := false
	matched := false

	var cancelErr error

	elem.ForEachAttribute(func(attr *xdm.Attribute) bool {
		if err := ctx.Err(); err != nil {
			cancelErr = err
			return false
		}

		if !matchNodeTest(pred.NodeTest, attr, AxisAttribute, ec) {
			return true
		}

		if nodeTypeAnnotation(attr, ec) != "" {
			mustFallback = true
			return false
		}

		if attr.Value() == pred.Value {
			matched = true
			return false
		}

		return true
	})

	if cancelErr != nil {
		return false, false, cancelErr
	}

	if mustFallback {
		return false, false, nil
	}

	return matched, true, nil
}

func nodeHasMatchingAttribute(ctx context.Context, ec *evalContext, node xdm.Node, test xdm.NodeTest) (bool, error) {
	elem, ok := node.(*xdm.Element)
	if !ok {
		return false, nil
	}

	found := false

	var cancelErr error

	elem.ForEachAttribute(func(attr *xdm.Attribute) bool {
		if err := ctx.Err(); err != nil {
			cancelErr = err
			return false
		}

		if !matchNodeTest(test, attr, AxisAttribute, ec) {
			return true
		}

		found = true

		return false
	})

	if cancelErr != nil {
		return false, cancelErr
	}

	return found, nil
}

func evalVMStepNoPredicates(ctx context.Context, ec *evalContext, nodes []xdm.Node, step vmLocationStep) ([]xdm.Node, error) {
	return evalAxisStep(ctx, ec, nodes, step.Axis, step.NodeTest)
}

func appendAxisNodeMatches(ctx context.Context, dst []xdm.Node, ec *evalContext, node xdm.Node, axis AxisType, nodeTest xdm.NodeTest) ([]xdm.Node, int, error) {
	switch axis {
	case AxisChild:
		return appendChildNodeMatches(ctx, dst, ec, node, nodeTest)
	case AxisAttribute:
		return appendAttributeNodeMatches(ctx, dst, ec, node, nodeTest)
	case AxisSelf:
		if matchNodeTest(nodeTest, node, axis, ec) {
			dst = append(dst, node)
		}

		return dst, 1, nil
	case AxisParent:
		parent := node.Parent()
		if parent == nil {
			return dst, 0, nil
		}

		if matchNodeTest(nodeTest, parent, axis, ec) {
			dst = append(dst, parent)
		}

		return dst, 1, nil
	default:
		candidates, err := xdm.TraverseAxis(ctx, axis, node, ec.maxNodes)
		if err != nil {
			return nil, 0, err
		}

		for _, candidate := range candidates {
			if matchNodeTest(nodeTest, candidate, axis, ec) {
				dst = append(dst, candidate)
			}
		}

		return dst, len(candidates), nil
	}
}

func appendChildNodeMatches(ctx context.Context, dst []xdm.Node, ec *evalContext, node xdm.Node, nodeTest xdm.NodeTest) ([]xdm.Node, int, error) {
	if _, ok := node.(*xdm.Attribute); ok {
		return dst, 0, nil
	}

	traversed := 0

	for child := range xdm.Children(node) {
		if err := ctx.Err(); err != nil {
			return nil, 0, err
		}

		if !xdm.IsXDMChild(child) {
			continue
		}

		traversed++

		if matchNodeTest(nodeTest, child, AxisChild, ec) {
			dst = append(dst, child)
		}
	}

	return dst, traversed, nil
}

func appendAttributeNodeMatches(ctx context.Context, dst []xdm.Node, ec *evalContext, node xdm.Node, nodeTest xdm.NodeTest) ([]xdm.Node, int, error) {
	elem, ok := node.(*xdm.Element)
	if !ok {
		return dst, 0, nil
	}

	if err := ctx.Err(); err != nil {
		return nil, 0, err
	}

	traversed := 0

	var iterErr error

	elem.ForEachAttribute(func(attr *xdm.Attribute) bool {
		if err := ctx.Err(); err != nil {
			iterErr = err
			return false
		}

		traversed++

		if matchNodeTest(nodeTest, attr, AxisAttribute, ec) {
			dst = append(dst, attr)
		}

		return true
	})

	if iterErr != nil {
		return nil, 0, iterErr
	}

	return dst, traversed, nil
}

func matchNodeTest(nt xdm.NodeTest, n xdm.Node, axis AxisType, ec *evalContext) bool {
	switch test := nt.(type) {
	case xdm.NameTest:
		return matchNameTest(test, n, axis, ec)
	case xdm.TypeTest:
		return matchTypeTest(test, n)
	case xdm.PITest:
		if n.Type() != xdm.ProcessingInstructionNode {
			return false
		}

		if test.Target == "" && !test.HasTarget {
			return true
		}

		return n.Name() == test.Target
	case xdm.ElementTest:
		return matchElementTest(test, n, ec)
	case xdm.AttributeTest:
		return matchAttributeTest(test, n, ec)
	case xdm.DocumentTest:
		return matchDocumentTest(test, n, ec)
	case xdm.SchemaElementTest:
		return matchSchemaElementTest(test, n, ec)
	case xdm.SchemaAttributeTest:
		return matchSchemaAttributeTest(test, n, ec)
	case xdm.NamespaceNodeTest:
		return n.Type() == xdm.NamespaceNode
	case xdm.AnyItemTest:
		return true
	}

	return false
}

func matchElementTest(test xdm.ElementTest, n xdm.Node, ec *evalContext) bool {
	if n.Type() != xdm.ElementNode {
		return false
	}

	if test.Name != "" && test.Name != "*" {
		if !matchElementOrAttributeName(test.Name, n, ec, false) {
			return false
		}
	}

	if test.TypeName != "" {
		ann := nodeAnnotationOr(n, ec, xdm.TypeUntyped)
		target := resolveTestTypeName(test.TypeName, ec)

		if !matchAnnotationSubtype(ann, target, ec) {
			return false
		}
		// element(name, type) without ? does not match a nilled element;
		// element(name, type?) with ? matches even when nilled. A nilled
		// element has no typed value, so it cannot satisfy a specific type.
		if !test.Nillable && ec != nil && ec.nilledElements != nil {
			if _, nilled := ec.nilledElements[n]; nilled {
				return false
			}
		}
	}

	return true
}

func matchAttributeTest(test xdm.AttributeTest, n xdm.Node, ec *evalContext) bool {
	if _, ok := n.(*xdm.Attribute); !ok {
		return false
	}

	if test.Name != "" && test.Name != "*" {
		if !matchElementOrAttributeName(test.Name, n, ec, true) {
			return false
		}
	}

	if test.TypeName != "" {
		ann := nodeAnnotationOr(n, ec, xdm.TypeUntypedAtomic)
		target := resolveTestTypeName(test.TypeName, ec)

		if !matchAnnotationSubtype(ann, target, ec) {
			return false
		}
	}

	return true
}

func matchDocumentTest(test xdm.DocumentTest, n xdm.Node, ec *evalContext) bool {
	if n.Type() != xdm.DocumentNode {
		return false
	}

	if test.Inner != nil {
		// document-node(E) matches when the document has exactly one element
		// child, no text node children, and that element matches E.
		var (
			elemCount    int
			matchedInner bool
		)

		for c := range xdm.Children(n) {
			switch c.Type() {
			case xdm.ElementNode:
				elemCount++
				if elemCount > 1 {
					return false
				}

				if matchNodeTest(test.Inner, c, AxisChild, ec) {
					matchedInner = true
				}
			case xdm.TextNode:
				return false
			}
		}

		return elemCount == 1 && matchedInner
	}

	return true
}

func matchSchemaElementTest(test xdm.SchemaElementTest, n xdm.Node, ec *evalContext) bool {
	if n.Type() != xdm.ElementNode {
		return false
	}

	if ec == nil || ec.schemaDeclarations == nil {
		// Without schema, match by name only.
		if test.Name == "" || test.Name == "*" {
			return true
		}

		_, local := splitQName(test.Name)

		return xdm.LocalNameOf(n) == local
	}

	local, ns := resolveSchemaTestName(test.Name, ec, false)

	nameMatch := xdm.LocalNameOf(n) == local && xdm.NodeNamespaceURI(n) == ns
	if !nameMatch {
		// The node's name is not the head's own name, so it matches only
		// when the node's element is a member of the substitution group
		// headed by (local, ns). Substitution-group membership already
		// requires each member's declared type to derive from the head's
		// type, so a validated (non-untyped) member satisfies the kind
		// test; a type-derivation check alone would wrongly admit any
		// element whose type happens to derive from the head's type
		// without being substitutable for it.
		if !ec.schemaDeclarations.IsSubstitutionGroupMember(xdm.LocalNameOf(n), xdm.NodeNamespaceURI(n), local, ns) {
			return false
		}

		ann := nodeTypeAnnotation(n, ec)
		if ann == "" || ann == xdm.TypeUntyped {
			return false
		}

		return true
	}

	typeName, found := ec.schemaDeclarations.LookupSchemaElement(local, ns)
	if !found {
		return false
	}

	ann := nodeTypeAnnotation(n, ec)
	if ann == "" {
		ann = xdm.TypeUntyped
	}

	if xdm.IsSubtypeOf(ann, typeName) {
		return true
	}

	return ec.schemaDeclarations.IsSubtypeOf(ann, typeName)
}

func matchSchemaAttributeTest(test xdm.SchemaAttributeTest, n xdm.Node, ec *evalContext) bool {
	attr, ok := n.(*xdm.Attribute)
	if !ok {
		return false
	}

	if ec == nil || ec.schemaDeclarations == nil {
		if test.Name == "" || test.Name == "*" {
			return true
		}

		_, local := splitQName(test.Name)

		return attr.LocalName() == local
	}

	local, ns := resolveSchemaTestName(test.Name, ec, true)
	if attr.LocalName() != local || attr.URI() != ns {
		return false
	}

	typeName, found := ec.schemaDeclarations.LookupSchemaAttribute(local, ns)
	if !found {
		return false
	}

	ann := nodeTypeAnnotation(n, ec)
	if ann == "" {
		ann = xdm.TypeUntypedAtomic
	}
	// Untyped attributes have not been validated — they do NOT match schema-attribute().
	if ann == xdm.TypeUntypedAtomic {
		return false
	}

	if xdm.IsSubtypeOf(ann, typeName) {
		return true
	}

	return ec.schemaDeclarations.IsSubtypeOf(ann, typeName)
}

func nodeAnnotationOr(n xdm.Node, ec *evalContext, fallback string) string {
	ann := nodeTypeAnnotation(n, ec)
	if ann == "" {
		return fallback
	}

	return ann
}

func matchAnnotationSubtype(annotation, target string, ec *evalContext) bool {
	if xdm.IsSubtypeOf(annotation, target) {
		return true
	}

	return ec != nil && ec.schemaDeclarations != nil && ec.schemaDeclarations.IsSubtypeOf(annotation, target)
}

// matchElementOrAttributeName matches an element/attribute name from an
// ElementTest or AttributeTest against a node. Handles URIQualifiedNames
// (Q{uri}local), prefixed names (prefix:local), and plain local names.
// isAttr selects the namespace rule for an unprefixed name: attributes match
// only no-namespace nodes, elements match the default element namespace.
func matchElementOrAttributeName(name string, n xdm.Node, ec *evalContext, isAttr bool) bool {
	if strings.HasPrefix(name, "Q{") {
		if idx := strings.Index(name, "}"); idx >= 0 {
			uri := name[2:idx]
			local := name[idx+1:]

			return xdm.LocalNameOf(n) == local && xdm.NodeNamespaceURI(n) == uri
		}
	}

	prefix, local := splitQName(name)
	if xdm.LocalNameOf(n) != local {
		return false
	}

	if prefix != "" {
		return matchPrefix(prefix, n, ec)
	}
	// Unprefixed name: same namespace rule as a NameTest (XPath 3.1 §3.3.2.1).
	if isAttr {
		return xdm.NodeNamespaceURI(n) == ""
	}

	defaultNS := ""
	if ec != nil && ec.namespaces != nil {
		defaultNS = ec.namespaces[""]
	}

	return xdm.NodeNamespaceURI(n) == defaultNS
}

func matchNameTest(test xdm.NameTest, n xdm.Node, axis AxisType, ec *evalContext) bool {
	switch axis {
	case AxisAttribute:
		if _, ok := n.(*xdm.Attribute); !ok {
			return false
		}
	case AxisNamespace:
		if n.Type() != xdm.NamespaceNode {
			return false
		}
		// Namespace nodes have simple NCName prefixes, not QNames.
		// A name test with a prefix (e.g. namespace::b:a) cannot
		// match any namespace node.
		if test.Prefix != "" {
			return false
		}

		if test.Local == "*" {
			return true
		}

		return n.Name() == test.Local
	default:
		if n.Type() != xdm.ElementNode {
			return false
		}
	}

	if test.Local == "*" {
		if test.URI != "" {
			return xdm.NodeNamespaceURI(n) == test.URI
		}

		if test.Prefix == "" {
			return true
		}

		return matchPrefix(test.Prefix, n, ec)
	}

	if xdm.LocalNameOf(n) != test.Local {
		return false
	}

	if test.URI != "" {
		return xdm.NodeNamespaceURI(n) == test.URI
	}

	if test.Prefix == "*" {
		// *:local matches any namespace
		return true
	}

	if test.Prefix != "" {
		return matchPrefix(test.Prefix, n, ec)
	}
	// Check for default element namespace (xpath-default-namespace).
	// Only applies to element axis, not attributes.
	// Per XPath 3.1 §3.3.2.1: when default element namespace is absent,
	// unprefixed names match only no-namespace elements.
	if axis == AxisAttribute {
		// Per XPath 3.1 §3.3.2.1: an unprefixed attribute name test
		// matches only attributes with no namespace URI.
		return xdm.NodeNamespaceURI(n) == ""
	}
	// Per XPath 3.1 §3.3.2.1: when no default element namespace is bound,
	// an unprefixed name test matches only no-namespace elements.
	defaultNS := ""
	if ec.namespaces != nil {
		defaultNS = ec.namespaces[""]
	}

	return xdm.NodeNamespaceURI(n) == defaultNS
}

func matchPrefix(prefix string, n xdm.Node, ec *evalContext) bool {
	if ec.namespaces != nil {
		if uri, ok := ec.namespaces[prefix]; ok {
			return xdm.NodeNamespaceURI(n) == uri
		}
	}
	// The xml prefix is always bound per the XML Namespaces spec.
	if prefix == lexicon.PrefixXML {
		return xdm.NodeNamespaceURI(n) == lexicon.NamespaceXML
	}
	// Check built-in XPath prefixes (fn, xs, math, map, array, err).
	if uri, ok := PredeclaredNamespace(prefix); ok {
		return xdm.NodeNamespaceURI(n) == uri
	}
	// Per XPath spec, prefix resolution must come from the static/evaluation
	// namespace bindings, not the document's lexical prefixes. If the prefix
	// is not declared in the namespace context, it cannot match.
	return false
}

func matchTypeTest(test xdm.TypeTest, n xdm.Node) bool {
	switch test.Kind {
	case xdm.NodeKindNode:
		return true
	case xdm.NodeKindText:
		return n.Type() == xdm.TextNode || n.Type() == xdm.CDATASectionNode
	case xdm.NodeKindComment:
		return n.Type() == xdm.CommentNode
	case xdm.NodeKindProcessingInstruction:
		return n.Type() == xdm.ProcessingInstructionNode
	}

	return false
}

func applyPredicate(evalFn exprEvaluator, ctx context.Context, ec *evalContext, nodes []xdm.Node, pred Expr) ([]xdm.Node, error) {
	if err := ec.countOps(ctx, len(nodes)); err != nil {
		return nil, err
	}

	size := len(nodes)

	var result []xdm.Node

	for i, n := range nodes {
		frame := ec.pushNodeContext(n, i+1, size)
		r, err := evalFn(ctx, ec, pred)
		ec.restoreContext(frame)

		if err != nil {
			return nil, err
		}

		match, err := predicateTrue(r, i+1)
		if err != nil {
			return nil, err
		}

		if match {
			result = append(result, n)
		}
	}

	return result, nil
}

// nodeTypeAnnotation returns the type annotation for a node from the
// evalContext's type annotation map.
func nodeTypeAnnotation(n xdm.Node, ec *evalContext) string {
	if ec == nil || ec.typeAnnotations == nil {
		return ""
	}

	return ec.typeAnnotations[n]
}

// resolveSchemaTestName resolves a name from a SchemaElementTest or
// SchemaAttributeTest. Handles Q{uri}local (EQName) and prefix:local forms.
// A prefixed name resolves via resolveSchemaTestPrefix (in-scope bindings, then
// predeclared XPath prefixes, then xml), mirroring the xslt pattern resolver.
// isAttr selects the namespace rule for an unprefixed name (same rule as
// matchElementOrAttributeName / a NameTest, XPath 3.1 §3.3.2.1): a bare
// schema-attribute() name is always in no namespace — the default element
// namespace governs element names, not attribute names — while a bare
// schema-element() name takes the default element namespace.
func resolveSchemaTestName(name string, ec *evalContext, isAttr bool) (local, ns string) {
	if strings.HasPrefix(name, "Q{") {
		if idx := strings.Index(name, "}"); idx >= 0 {
			return name[idx+1:], name[2:idx]
		}
	}

	prefix, loc := splitQName(name)
	if prefix != "" {
		return loc, resolveSchemaTestPrefix(prefix, ec)
	}

	if !isAttr && ec != nil && ec.namespaces != nil {
		return loc, ec.namespaces[""]
	}

	return loc, ""
}

// resolveSchemaTestPrefix resolves a non-empty namespace prefix used inside a
// schema-element()/schema-attribute() test. It mirrors the xslt pattern prefix
// resolver: the explicit in-scope namespace bindings take precedence, then the
// XPath 3.0 predeclared prefixes (fn, math, map, array, err, xs), then the
// universally bound xml prefix. An unbound prefix resolves to no namespace.
func resolveSchemaTestPrefix(prefix string, ec *evalContext) string {
	if ec != nil && ec.namespaces != nil {
		if uri, ok := ec.namespaces[prefix]; ok {
			return uri
		}
	}

	if uri, ok := PredeclaredNamespace(prefix); ok {
		return uri
	}

	if prefix == lexicon.PrefixXML {
		return lexicon.NamespaceXML
	}

	return ""
}

// resolveTestTypeName uses the same expanded-name rules as atomic types,
// including declaration-bound EQNames in exported function signatures.
func resolveTestTypeName(raw string, ec *evalContext) string {
	return resolveAtomicTypeName(AtomicTypeName{Name: raw}, ec)
}

// predicateTrue evaluates a predicate result per XPath spec:
// numeric → compare to position, otherwise → EBV.
func predicateTrue(r xdm.Sequence, position int) (bool, error) {
	if xdm.SequenceLen(r) == 1 {
		if av, ok := r.Get(0).(xdm.AtomicValue); ok && av.IsNumeric() {
			return compareNumeric(TokenEq, xdm.PromoteSchemaType(av), xdm.AtomicValue{
				TypeName: xdm.TypeInteger, Value: int64(position),
			})
		}
	}

	return EBV(r)
}

func vmPredicatePosition(expr Expr) (int, bool) {
	switch e := expr.(type) {
	case LiteralExpr:
		return vmPositionFromLiteral(e)
	case *LiteralExpr:
		if e == nil {
			return 0, false
		}

		return vmPositionFromLiteral(*e)
	case BinaryExpr:
		return vmPredicatePositionFromBinary(e)
	case *BinaryExpr:
		if e == nil {
			return 0, false
		}

		return vmPredicatePositionFromBinary(*e)
	default:
		return 0, false
	}
}

func vmPredicatePositionFromBinary(expr BinaryExpr) (int, bool) {
	if expr.Op != TokenEquals && expr.Op != TokenEq {
		return 0, false
	}

	if positionCall(expr.Left) {
		return vmPositionFromExpr(expr.Right)
	}

	if positionCall(expr.Right) {
		return vmPositionFromExpr(expr.Left)
	}

	return 0, false
}

func vmPositionFromExpr(expr Expr) (int, bool) {
	switch e := expr.(type) {
	case LiteralExpr:
		return vmPositionFromLiteral(e)
	case *LiteralExpr:
		if e == nil {
			return 0, false
		}

		return vmPositionFromLiteral(*e)
	default:
		return 0, false
	}
}

func vmPositionFromLiteral(expr LiteralExpr) (int, bool) {
	switch v := expr.Value.(type) {
	case *big.Int:
		if !v.IsInt64() {
			return 0, false
		}

		n := v.Int64()
		if n <= 0 || n > math.MaxInt {
			return 0, false
		}

		return int(n), true
	case float64:
		if v <= 0 || v != math.Trunc(v) || v > math.MaxInt {
			return 0, false
		}

		return int(v), true
	default:
		return 0, false
	}
}

func positionCall(expr Expr) bool {
	switch e := expr.(type) {
	case FunctionCall:
		local, isFn := lexicalFnLocalName(e.Name, e.Prefix)
		return len(e.Args) == 0 && isFn && local == lexicon.FnPosition
	case *FunctionCall:
		if e == nil {
			return false
		}

		local, isFn := lexicalFnLocalName(e.Name, e.Prefix)

		return len(e.Args) == 0 && isFn && local == lexicon.FnPosition
	default:
		return false
	}
}

func vmPredicateAttributeExists(expr Expr) (xdm.NodeTest, bool) {
	return vmSingleRelativeAttributePath(expr)
}

func vmPredicateAttributeEqualsString(expr Expr) (xdm.NodeTest, string, bool) {
	switch e := expr.(type) {
	case BinaryExpr:
		return vmPredicateAttributeEqualsStringBinary(e)
	case *BinaryExpr:
		if e == nil {
			return nil, "", false
		}

		return vmPredicateAttributeEqualsStringBinary(*e)
	default:
		return nil, "", false
	}
}

func vmPredicateAttributeEqualsStringBinary(expr BinaryExpr) (xdm.NodeTest, string, bool) {
	if expr.Op != TokenEquals && expr.Op != TokenEq {
		return nil, "", false
	}

	if test, ok := vmSingleRelativeAttributePath(expr.Left); ok {
		if value, ok := vmStringLiteralValue(expr.Right); ok {
			return test, value, true
		}
	}

	if test, ok := vmSingleRelativeAttributePath(expr.Right); ok {
		if value, ok := vmStringLiteralValue(expr.Left); ok {
			return test, value, true
		}
	}

	return nil, "", false
}

func vmSingleRelativeAttributePath(expr Expr) (xdm.NodeTest, bool) {
	switch e := expr.(type) {
	case LocationPath:
		return vmAttributeNodeTestFromLocationPath(e.Absolute, e.Steps)
	case *LocationPath:
		if e == nil {
			return nil, false
		}

		return vmAttributeNodeTestFromLocationPath(e.Absolute, e.Steps)
	case vmLocationPathExpr:
		return vmAttributeNodeTestFromVMLocationPath(e.Absolute, e.Steps)
	case *vmLocationPathExpr:
		if e == nil {
			return nil, false
		}

		return vmAttributeNodeTestFromVMLocationPath(e.Absolute, e.Steps)
	default:
		return nil, false
	}
}

func vmAttributeNodeTestFromLocationPath(absolute bool, steps []Step) (xdm.NodeTest, bool) {
	if absolute || len(steps) != 1 {
		return nil, false
	}

	step := steps[0]
	if step.Axis != AxisAttribute || len(step.Predicates) != 0 {
		return nil, false
	}

	return step.NodeTest, true
}

func vmAttributeNodeTestFromVMLocationPath(absolute bool, steps []vmLocationStep) (xdm.NodeTest, bool) {
	if absolute || len(steps) != 1 {
		return nil, false
	}

	step := steps[0]
	if step.Axis != AxisAttribute || len(step.Predicates) != 0 {
		return nil, false
	}

	return step.NodeTest, true
}

func vmStringLiteralValue(expr Expr) (string, bool) {
	switch e := expr.(type) {
	case LiteralExpr:
		value, ok := e.Value.(string)
		return value, ok
	case *LiteralExpr:
		if e == nil {
			return "", false
		}

		value, ok := e.Value.(string)

		return value, ok
	default:
		return "", false
	}
}
