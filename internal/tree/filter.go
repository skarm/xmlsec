package tree

import (
	"context"
	"fmt"
)

// FilterNodeSet is an internal, immutable membership filter. Iteration order is
// irrelevant: ordering is established only when a node-set is consumed.
// keep must be pure; partial selections are evaluated twice to size the result.
func FilterNodeSet(ctx context.Context, set NodeSet, keep func(NodeRef) bool) (NodeSet, error) {
	if ctx == nil || !set.Valid() || keep == nil {
		return NodeSet{}, fmt.Errorf("%w: invalid node-set filter", ErrMalformed)
	}

	if err := ctx.Err(); err != nil {
		return NodeSet{}, err
	}

	count, i := 0, 0
	for n := range set.members {
		if i&255 == 0 {
			if err := ctx.Err(); err != nil {
				return NodeSet{}, err
			}
		}

		i++

		if keep(n) {
			count++
		}
	}

	if count == len(set.members) {
		return set, ctx.Err()
	}

	out := NodeSet{doc: set.doc, members: make(map[NodeRef]struct{}, count)}
	if count != 0 {
		i = 0
		for n := range set.members {
			if i&255 == 0 {
				if err := ctx.Err(); err != nil {
					return NodeSet{}, err
				}
			}

			i++

			if keep(n) {
				out.members[n] = struct{}{}
			}
		}
	}

	return out, ctx.Err()
}

// NodeWithin includes attributes/namespaces belonging to the excluded subtree.
// Handles from distinct document snapshots never match.
func NodeWithin(n NodeRef, ancestor Element) bool {
	if !n.Valid() || !ancestor.Valid() || n.doc != ancestor.doc || n.kind == DocumentNode {
		return false
	}

	for p := n.node; p != nil; p = p.Parent {
		if p == ancestor.node {
			return true
		}
	}

	return false
}

// IsNodeSetSubset checks membership without ordering or copying either set.
func IsNodeSetSubset(ctx context.Context, subset, superset NodeSet) (bool, error) {
	if ctx == nil || !subset.Valid() || !superset.Valid() || subset.doc != superset.doc {
		return false, ErrMalformed
	}

	if err := ctx.Err(); err != nil {
		return false, err
	}

	index := 0
	for node := range subset.members {
		if index&255 == 0 {
			if err := ctx.Err(); err != nil {
				return false, err
			}
		}

		index++

		if !superset.Contains(node) {
			return false, nil
		}
	}

	return true, ctx.Err()
}
