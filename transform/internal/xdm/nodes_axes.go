// Derived from lestrrat-go/helium at 7362c0a70122a757780f4d0b545a9b370dead6ab.
// Copyright (c) 2015 lestrrat. MIT License; see licenses/MIT-helium.txt at the repository root.

package xdm

import (
	"context"
	"slices"

	"github.com/skarm/xmlsec/internal/lexicon"
	"github.com/skarm/xmlsec/internal/nilcheck"
)

// maxInt is the largest value an int can hold, used to saturate the node-set
// limit when offsetting it past the nodes already in the destination slice
// would overflow.
const maxInt = int(^uint(0) >> 1)

// AxisType identifies one of the 13 XPath axes.
type AxisType int

// AxisChild and the other AxisType constants identify the thirteen XPath axes.
const (
	AxisChild AxisType = iota
	AxisDescendant
	AxisParent
	AxisAncestor
	AxisFollowingSibling
	AxisPrecedingSibling
	AxisFollowing
	AxisPreceding
	AxisAttribute
	AxisNamespace
	AxisSelf
	AxisDescendantOrSelf
	AxisAncestorOrSelf
)

// AxisFromName maps an axis name string to its AxisType.
// Returns the axis and true if recognized, or AxisChild and false otherwise.
func AxisFromName(name string) (AxisType, bool) {
	for axis := AxisChild; axis <= AxisAncestorOrSelf; axis++ {
		if axis.String() == name {
			return axis, true
		}
	}

	return AxisChild, false
}

func (a AxisType) String() string {
	if s, ok := lookupaxisNames(a); ok {
		return s
	}

	return "unknown-axis"
}

func lookupaxisNames(key AxisType) (string, bool) {
	switch key {
	case AxisChild:
		return "child", true
	case AxisDescendant:
		return "descendant", true
	case AxisParent:
		return "parent", true
	case AxisAncestor:
		return "ancestor", true
	case AxisFollowingSibling:
		return "following-sibling", true
	case AxisPrecedingSibling:
		return "preceding-sibling", true
	case AxisFollowing:
		return "following", true
	case AxisPreceding:
		return "preceding", true
	case AxisAttribute:
		return "attribute", true
	case AxisNamespace:
		return "namespace", true
	case AxisSelf:
		return "self", true
	case AxisDescendantOrSelf:
		return "descendant-or-self", true
	case AxisAncestorOrSelf:
		return "ancestor-or-self", true
	}

	var zero string

	return zero, false
}

// IsNilNode reports whether n is nil or a nil pointer wrapped in a non-nil
// interface.
func IsNilNode(n Node) bool {
	if n == nil {
		return true
	}

	// Built-in node implementations use pointer identity.
	switch node := n.(type) {
	case *Document:
		return node == nil
	case *Element:
		return node == nil
	case *Text:
		return node == nil
	case *CDATASection:
		return node == nil
	case *Comment:
		return node == nil
	case *ProcessingInstruction:
		return node == nil
	case *Attribute:
		return node == nil
	case *NamespaceNodeWrapper:
		return node == nil
	case *nodeView:
		return node == nil
	}

	// Embedding Node can also produce wrapper types in other internal packages.
	return nilcheck.IsNil(n)
}

// TraverseAxis returns the nodes along the given axis from the context node,
// in the order defined by the XPath spec. maxNodes limits the result size
// for unbounded axes; use DefaultMaxNodeSetLength if unsure. ctx is checked
// inside the unbounded descendant/following/preceding walks so a cancelled
// context aborts the traversal promptly, leaving the rest of the subtree unwalked.
func TraverseAxis(ctx context.Context, axis AxisType, node Node, maxNodes int) ([]Node, error) {
	if IsNilNode(node) {
		return nil, nil
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	switch axis {
	case AxisDescendant, AxisDescendantOrSelf:
		return AppendAxis(ctx, nil, axis, node, maxNodes)
	case AxisFollowing:
		return axisFollowing(ctx, node, maxNodes)
	case AxisPreceding:
		return axisPreceding(ctx, node, maxNodes)
	}

	return TraverseAxisSimple(ctx, axis, node)
}

func axisFollowing(ctx context.Context, node Node, maxNodes int) ([]Node, error) {
	// Per XPath data model: attribute and namespace nodes are ordered after
	// their parent element and before the parent's children.  Therefore the
	// following axis from an attribute/namespace node includes the parent's
	// descendants, then the parent's following siblings (+ their descendants),
	// and so on up the ancestor chain.
	switch node.(type) {
	case *Attribute, *NamespaceNodeWrapper:
		return axisFollowingEntries(ctx, node, maxNodes)
	}

	var result []Node

	for s := node.NextSibling(); s != nil; s = s.NextSibling() {
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		if !IsXDMChild(s) {
			continue
		}

		if err := appendAxisNode(&result, s, maxNodes); err != nil {
			return nil, err
		}

		if err := collectDescendants(ctx, s, &result, maxNodes); err != nil {
			return nil, err
		}
	}

	for p := node.Parent(); p != nil; p = p.Parent() {
		for s := p.NextSibling(); s != nil; s = s.NextSibling() {
			if err := ctx.Err(); err != nil {
				return nil, err
			}

			if !IsXDMChild(s) {
				continue
			}

			if err := appendAxisNode(&result, s, maxNodes); err != nil {
				return nil, err
			}

			if err := collectDescendants(ctx, s, &result, maxNodes); err != nil {
				return nil, err
			}
		}
	}

	return result, nil
}

func axisPreceding(ctx context.Context, node Node, maxNodes int) ([]Node, error) {
	// Per XPath data model: attribute and namespace nodes are ordered after
	// their parent element and before the parent's children.  Therefore the
	// preceding axis from an attribute/namespace node contains the same nodes
	// as the preceding axis from the parent element (the parent's preceding
	// siblings + their descendants, and up the ancestor chain).  The parent
	// element itself is excluded because it is an ancestor.
	switch node.(type) {
	case *Attribute, *NamespaceNodeWrapper:
		return axisPrecedingEntries(ctx, node, maxNodes)
	}

	var result []Node

	for s := node.PrevSibling(); s != nil; s = s.PrevSibling() {
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		if !IsXDMChild(s) {
			continue
		}

		if err := collectDescendantsReverse(ctx, s, &result, maxNodes); err != nil {
			return nil, err
		}

		if err := appendAxisNode(&result, s, maxNodes); err != nil {
			return nil, err
		}
	}

	for p := node.Parent(); p != nil; p = p.Parent() {
		for s := p.PrevSibling(); s != nil; s = s.PrevSibling() {
			if err := ctx.Err(); err != nil {
				return nil, err
			}

			if !IsXDMChild(s) {
				continue
			}

			if err := collectDescendantsReverse(ctx, s, &result, maxNodes); err != nil {
				return nil, err
			}

			if err := appendAxisNode(&result, s, maxNodes); err != nil {
				return nil, err
			}
		}
	}

	return result, nil
}

func collectDescendantsReverse(ctx context.Context, node Node, result *[]Node, maxNodes int) error {
	type frame struct {
		node     Node
		expanded bool
	}

	var stack []frame

	for c := range Children(node) {
		if err := ctx.Err(); err != nil {
			return err
		}

		if IsXDMChild(c) {
			stack = append(stack, frame{node: c})
		}
	}

	for len(stack) > 0 {
		if err := ctx.Err(); err != nil {
			return err
		}

		last := len(stack) - 1
		cur := stack[last]
		stack = stack[:last]

		if cur.expanded {
			if err := appendAxisNode(result, cur.node, maxNodes); err != nil {
				return err
			}

			continue
		}

		stack = append(stack, frame{node: cur.node, expanded: true})
		for child := range Children(cur.node) {
			if err := ctx.Err(); err != nil {
				return err
			}

			if IsXDMChild(child) {
				stack = append(stack, frame{node: child})
			}
		}
	}

	return nil
}

func axisFollowingEntries(ctx context.Context, node Node, maxNodes int) ([]Node, error) {
	parent := node.Parent()
	if IsNilNode(parent) {
		return nil, nil
	}

	var result []Node
	// Parent's descendants come first (they follow attrs in document order).
	if err := collectDescendants(ctx, parent, &result, maxNodes); err != nil {
		return nil, err
	}
	// Then the parent's following siblings + their descendants, and up
	// through ancestors — same as the normal following axis from the parent.
	for p := parent; p != nil; p = p.Parent() {
		for s := p.NextSibling(); s != nil; s = s.NextSibling() {
			if err := ctx.Err(); err != nil {
				return nil, err
			}

			if !IsXDMChild(s) {
				continue
			}

			if err := appendAxisNode(&result, s, maxNodes); err != nil {
				return nil, err
			}

			if err := collectDescendants(ctx, s, &result, maxNodes); err != nil {
				return nil, err
			}
		}
	}

	return result, nil
}

func axisPrecedingEntries(ctx context.Context, node Node, maxNodes int) ([]Node, error) {
	parent := node.Parent()
	if IsNilNode(parent) {
		return nil, nil
	}

	var result []Node

	for s := parent.PrevSibling(); s != nil; s = s.PrevSibling() {
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		if !IsXDMChild(s) {
			continue
		}

		if err := collectDescendantsReverse(ctx, s, &result, maxNodes); err != nil {
			return nil, err
		}

		if err := appendAxisNode(&result, s, maxNodes); err != nil {
			return nil, err
		}
	}

	for p := parent.Parent(); p != nil; p = p.Parent() {
		for s := p.PrevSibling(); s != nil; s = s.PrevSibling() {
			if err := ctx.Err(); err != nil {
				return nil, err
			}

			if !IsXDMChild(s) {
				continue
			}

			if err := collectDescendantsReverse(ctx, s, &result, maxNodes); err != nil {
				return nil, err
			}

			if err := appendAxisNode(&result, s, maxNodes); err != nil {
				return nil, err
			}
		}
	}

	return result, nil
}

// AppendAxis appends the nodes along axis from node to dst, in the order
// defined by the XPath spec, and returns the grown slice. It lets a caller
// accumulate several traversals in one buffer instead of allocating a fresh
// slice per traversal.
//
// maxNodes limits how many nodes THIS traversal may append; nodes already in
// dst do not count against it, so the limit means the same thing it does in
// TraverseAxis. ctx is checked inside the unbounded descendant walks so a
// cancelled context aborts the traversal promptly. On error dst is discarded
// and the returned slice is nil, as in TraverseAxis.
func AppendAxis(ctx context.Context, dst []Node, axis AxisType, node Node, maxNodes int) ([]Node, error) {
	if IsNilNode(node) {
		return dst, nil
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	switch axis {
	case AxisDescendant, AxisDescendantOrSelf:
		limit := maxNodes
		if n := len(dst); n > 0 {
			limit = maxNodes + n
			if limit < n { // overflow: maxNodes was near maxInt
				limit = maxInt
			}
		}

		if axis == AxisDescendantOrSelf {
			if err := appendAxisNode(&dst, node, limit); err != nil {
				return nil, err
			}
		}

		if err := collectDescendants(ctx, node, &dst, limit); err != nil {
			return nil, err
		}

		return dst, nil
	}

	nodes, err := TraverseAxis(ctx, axis, node, maxNodes)
	if err != nil {
		return nil, err
	}

	return append(dst, nodes...), nil
}

// TraverseAxisSimple handles axes whose result size is bounded by the tree
// shape (children, attributes, siblings, ancestors, namespaces).  Although
// these axes never hit the node-set limit, their enumeration loops still
// consult ctx so a cancelled context aborts a wide traversal promptly rather
// than materializing the whole node-set.
func TraverseAxisSimple(ctx context.Context, axis AxisType, node Node) ([]Node, error) {
	if IsNilNode(node) {
		return nil, nil
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	switch axis {
	case AxisChild:
		return axisChild(ctx, node)
	case AxisParent:
		return axisParent(node), nil
	case AxisAncestor:
		return axisAncestor(ctx, node)
	case AxisAncestorOrSelf:
		return axisAncestorOrSelf(ctx, node)
	case AxisFollowingSibling:
		return axisFollowingSibling(ctx, node)
	case AxisPrecedingSibling:
		return axisPrecedingSibling(ctx, node)
	case AxisSelf:
		return []Node{node}, nil
	case AxisAttribute:
		return axisAttribute(ctx, node)
	case AxisNamespace:
		return axisNamespace(ctx, node)
	}

	return nil, nil
}

func axisChild(ctx context.Context, node Node) ([]Node, error) {
	// In XPath, attributes have no children
	if _, ok := node.(*Attribute); ok {
		return nil, nil
	}

	var result []Node

	for c := range Children(node) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		if IsXDMChild(c) {
			result = append(result, c)
		}
	}

	return result, nil
}

func axisParent(node Node) []Node {
	if p := node.Parent(); p != nil {
		return []Node{p}
	}

	return nil
}

func axisAncestor(ctx context.Context, node Node) ([]Node, error) {
	var result []Node

	for p := node.Parent(); p != nil; p = p.Parent() {
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		result = append(result, p)
	}

	return result, nil
}

func axisAncestorOrSelf(ctx context.Context, node Node) ([]Node, error) {
	if IsNilNode(node) {
		return nil, nil
	}

	result := []Node{node}
	for p := node.Parent(); p != nil; p = p.Parent() {
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		result = append(result, p)
	}

	return result, nil
}

func axisFollowingSibling(ctx context.Context, node Node) ([]Node, error) {
	// Per XPath spec: if the context node is an attribute or namespace node,
	// the following-sibling axis is empty.
	switch node.(type) {
	case *Attribute, *NamespaceNodeWrapper:
		return nil, nil
	}

	var result []Node

	for s := node.NextSibling(); s != nil; s = s.NextSibling() {
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		if IsXDMChild(s) {
			result = append(result, s)
		}
	}

	return result, nil
}

func axisPrecedingSibling(ctx context.Context, node Node) ([]Node, error) {
	// Per XPath spec: if the context node is an attribute or namespace node,
	// the preceding-sibling axis is empty.
	switch node.(type) {
	case *Attribute, *NamespaceNodeWrapper:
		return nil, nil
	}

	var result []Node

	for s := node.PrevSibling(); s != nil; s = s.PrevSibling() {
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		if IsXDMChild(s) {
			result = append(result, s)
		}
	}

	return result, nil
}

func axisAttribute(ctx context.Context, node Node) ([]Node, error) {
	elem, ok := node.(*Element)
	if !ok {
		return nil, nil
	}
	// Keep the zero-attribute case allocation-free; the small append growth
	// cost for the common 1-3 attribute case is an acceptable tradeoff here.
	var (
		result []Node
		ctxErr error
	)

	elem.ForEachAttribute(func(attr *Attribute) bool {
		if err := ctx.Err(); err != nil {
			ctxErr = err
			return false
		}

		result = append(result, attr)

		return true
	})

	if ctxErr != nil {
		return nil, ctxErr
	}

	return result, nil
}

func axisNamespace(ctx context.Context, node Node) ([]Node, error) {
	elem, ok := node.(*Element)
	if !ok {
		return nil, nil
	}

	var ancestors []Node

	for cur := Node(elem); cur != nil; cur = cur.Parent() {
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		ancestors = append(ancestors, cur)
	}

	inScope, err := NamespacePrefixesInScope(ctx, ancestors)
	if err != nil {
		return nil, err
	}

	return CollectNamespaceNodes(ctx, ancestors, inScope, elem)
}

// IsXDMChild returns true if the node is a valid child in the XPath Data
// Model.  DTD, entity declarations, notation nodes, and other non-XDM
// node types that may appear in the DOM tree are excluded.
func IsXDMChild(n Node) bool {
	switch n.Type() {
	case ElementNode,
		TextNode,
		CDATASectionNode,
		CommentNode,
		ProcessingInstructionNode:
		return true
	}

	return false
}

// PushXDMChildren appends the XDM children of n to stack in reverse document
// order, so the first child is the next one popped. It enumerates the owned
// children (Children) and checks ctx before each one; on error it
// returns a nil stack. n must not be an attribute: the XDM gives attributes
// no children, and the caller handles that case.
func PushXDMChildren(ctx context.Context, stack []Node, n Node) ([]Node, error) {
	start := len(stack)

	for c := range Children(n) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		if IsXDMChild(c) {
			stack = append(stack, c)
		}
	}

	slices.Reverse(stack[start:])

	return stack, nil
}

// NamespacePrefixesInScope returns a map of prefix → active (non-empty URI)
// by walking ancestors from outermost to innermost so inner declarations win.
// It checks ctx for cancellation in both its outer and inner loops so a long
// namespace::* traversal can be aborted promptly.
func NamespacePrefixesInScope(ctx context.Context, ancestors []Node) (map[string]bool, error) {
	inScope := map[string]bool{}

	for _, v := range slices.Backward(ancestors) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		ns, ok := v.(NamespaceContainer)
		if !ok {
			continue
		}

		for _, n := range ns.Namespaces() {
			if err := ctx.Err(); err != nil {
				return nil, err
			}

			inScope[n.Prefix()] = n.URI() != ""
		}
	}

	return inScope, nil
}

// CollectNamespaceNodes builds the namespace node list for an element, adding
// the xml prefix first and then ancestor-declared prefixes in document order.
// For each prefix, the innermost (closest ancestor) declaration provides the
// URI, but the output order follows document order (outermost first).
// It checks ctx for cancellation in both passes (outer and inner loops) so a
// long namespace::* traversal can be aborted promptly.
func CollectNamespaceNodes(ctx context.Context, ancestors []Node, inScope map[string]bool, elem *Element) ([]Node, error) {
	// First pass: find the correct namespace for each prefix (innermost wins).
	// ancestors[0] is the element itself (innermost), ancestors[len-1] outermost.
	winner := map[string]*Namespace{}

	if err := collectNamespaceNodesAncestors(ctx, ancestors, winner, inScope); err != nil {
		return nil, err
	}

	var result []Node

	xmlNS := NewNamespace("xml", lexicon.NamespaceXML)
	result = append(result, NewNamespaceNodeWrapper(xmlNS, elem))

	// Second pass: output in document order (outermost to innermost), but
	// use the innermost URI for each prefix.
	emitted := map[string]struct{}{"xml": {}}

	for _, v := range slices.Backward(ancestors) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		ns, ok := v.(NamespaceContainer)
		if !ok {
			continue
		}

		for _, n := range ns.Namespaces() {
			if err := ctx.Err(); err != nil {
				return nil, err
			}

			prefix := n.Prefix()
			if _, done := emitted[prefix]; done {
				continue
			}

			w := winner[prefix]
			if w == nil {
				continue
			}

			emitted[prefix] = struct{}{}

			result = append(result, NewNamespaceNodeWrapper(w, elem))
		}
	}

	return result, nil
}

func collectNamespaceNodesAncestors(ctx context.Context, ancestors []Node, winner map[string]*Namespace, inScope map[string]bool) error {
	for _, anc := range ancestors {
		if err := ctx.Err(); err != nil {
			return err
		}

		ns, ok := anc.(NamespaceContainer)
		if !ok {
			continue
		}

		for _, n := range ns.Namespaces() {
			if err := ctx.Err(); err != nil {
				return err
			}

			prefix := n.Prefix()
			if _, found := winner[prefix]; found {
				continue // innermost already recorded
			}

			if !inScope[prefix] || n.URI() == "" {
				continue
			}

			winner[prefix] = n
		}
	}

	return nil
}

func appendAxisNode(result *[]Node, node Node, maxNodes int) error {
	*result = append(*result, node)
	if len(*result) > maxNodes {
		return ErrNodeSetLimit
	}

	return nil
}

// collectDescendants appends descendants in document order and enforces limits.
func collectDescendants(ctx context.Context, node Node, result *[]Node, maxNodes int) error {
	// In XPath, attributes have no children
	if _, ok := node.(*Attribute); ok {
		return nil
	}

	stack, err := PushXDMChildren(ctx, nil, node)
	if err != nil {
		return err
	}

	for len(stack) > 0 {
		if err := ctx.Err(); err != nil {
			return err
		}

		last := len(stack) - 1
		cur := stack[last]
		stack = stack[:last]

		if err := appendAxisNode(result, cur, maxNodes); err != nil {
			return err
		}

		stack, err = PushXDMChildren(ctx, stack, cur)
		if err != nil {
			return err
		}
	}

	return nil
}
