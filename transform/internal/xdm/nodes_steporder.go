// Derived from lestrrat-go/helium at 7362c0a70122a757780f4d0b545a9b370dead6ab.
// Copyright (c) 2015 lestrrat. MIT License; see licenses/MIT-helium.txt at the repository root.

package xdm

import (
	"slices"
)

// maxSameDepth bounds the parent-chain walk sameDepth performs on the first
// input node. Deeper inputs take the DeduplicateNodes path.
const maxSameDepth = 64

// OrderStepResult sorts and deduplicates one location step in document order.
// inputs must be sorted and duplicate-free; out concatenates their axis results
// after predicate filtering. A single context or disjoint same-depth contexts
// can establish order without indexing the whole document. Reverse axes are
// reversed; adjacent parent duplicates are compacted. Other cases use
// DeduplicateNodes.
//
// All output nodes must belong to one tree. Fast paths enforce maxNodes, clamp
// slice capacity and reserve document registration at the same point as
// DeduplicateNodes, preserving later cross-document ordering.
func OrderStepResult(out, inputs []Node, axis AxisType, cache *DocOrderCache, maxNodes int) ([]Node, error) {
	if len(out) <= 1 {
		return out, nil
	}

	if len(inputs) <= 1 && allOrderedContexts(inputs) {
		if isReverseAxis(axis) {
			slices.Reverse(out)
		}

		cache.ReserveDocument(out[0])

		return clampStepResult(out, maxNodes)
	}

	switch axis {
	case AxisChild, AxisAttribute, AxisSelf, AxisNamespace, AxisParent:
		if !allOrderedContexts(inputs) || !sameDepth(inputs) {
			break
		}

		if axis == AxisParent {
			out = slices.Compact(out)
		}

		cache.ReserveDocument(out[0])

		return clampStepResult(out, maxNodes)
	}

	return DeduplicateNodes(out, cache, maxNodes)
}

// clampStepResult applies the node-set limit and returns out with its
// capacity clamped, so the result never shares spare capacity with the
// caller's buffer.
func clampStepResult(out []Node, maxNodes int) ([]Node, error) {
	if len(out) > maxNodes {
		return nil, ErrNodeSetLimit
	}

	return out[:len(out):len(out)], nil
}

func isReverseAxis(axis AxisType) bool {
	switch axis {
	case AxisAncestor, AxisAncestorOrSelf, AxisPreceding, AxisPrecedingSibling:
		return true
	}

	return false
}

func sameDepth(nodes []Node) bool {
	depth := 0
	for p := nodes[0].Parent(); p != nil; p = p.Parent() {
		depth++
		if depth > maxSameDepth {
			return false
		}
	}

	prevParent := nodes[0].Parent()
	for _, n := range nodes[1:] {
		parent := n.Parent()
		if parent == prevParent {
			continue
		}

		prevParent = parent

		p := n
		for range depth {
			p = p.Parent()
			if p == nil {
				return false
			}
		}

		if p.Parent() != nil {
			return false
		}
	}

	return true
}

// OrderedFrom reports whether axis traversal from n preserves document order.
func OrderedFrom(n Node) bool {
	return allOrderedContexts([]Node{n})
}

// allOrderedContexts reports whether every node of nodes is a kind whose axis
// traversal yields document order (see OrderStepResult).
func allOrderedContexts(nodes []Node) bool {
	for _, n := range nodes {
		switch n.Type() {
		case DocumentNode, AttributeNode, NamespaceNode:
			continue
		}

		if !IsXDMChild(n) {
			return false
		}
	}

	return true
}
