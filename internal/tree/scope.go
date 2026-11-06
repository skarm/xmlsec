package tree

import (
	"context"
	"slices"
)

// ScopeDocument creates an immutable subtree view while retaining its original
// ancestors for canonicalization. It neither copies nor changes source nodes.
// Selection is restricted to that subtree. Signature verifiers use ContextElement
// for full-source reference/ID validation and pin the exact protocol root.
func ScopeDocument(source *Document, element Element) (*Document, error) {
	if source == nil || element.doc != source || !element.Valid() {
		return nil, ErrMalformed
	}

	origin := source
	if source.contextual {
		origin = source.contextSource
	}

	return &Document{root: element.node, children: []*Node{element.node}, limits: source.limits, inputBytes: source.inputBytes, unparsedEntities: source.unparsedEntities, dtdInfo: source.dtdInfo, nodeBases: source.nodeBases, dtdTypes: source.dtdTypes, contextual: true, contextSource: origin, contextAnchor: element.node}, nil
}

// ContextElement maps a scoped element to its complete source snapshot for
// signature reference resolution, including duplicate IDs in the outer envelope.
// Mapping the context does not broaden signature coverage.
func ContextElement(e Element) Element {
	if e.doc == nil || !e.doc.contextual {
		return e
	}

	return Wrap(e.doc.contextSource, e.node)
}

func serializationChildren(d *Document) ([]*Node, error) {
	if !d.contextual {
		return d.children, nil
	}

	for parent := d.root.Parent; parent != nil; parent = parent.Parent {
		for _, a := range parent.Attrs {
			if a.Name.Space == XMLNamespace {
				return nil, ErrUnsupported
			}
		}
	}
	// Materialize namespace bindings for an independently serialized subtree.
	// XML attributes cannot be moved onto a schema-constrained protocol root.
	return []*Node{ExtractSubtree(d.root)}, nil
}

func reparseContextual(ctx context.Context, draft *Document, limits Limits) (*Document, error) {
	root := *draft.root
	root.Parent = nil
	branch := &root

	var path []int

	anchor := draft.contextAnchor

	for source := draft.root.Parent; source != nil; source = source.Parent {
		parent := *source
		parent.Attrs = slices.Clone(source.Attrs)
		parent.NS = slices.Clone(source.NS)
		parent.Children = slices.Clone(source.Children)
		index, found := 0, false

		for i, child := range source.Children {
			if child == anchor {
				parent.Children[i] = branch
				found = true

				break
			}

			if child.Kind == ElementNode {
				index++
			}
		}

		if !found {
			return nil, ErrMalformed
		}

		path = append(path, index)
		parent.Parent = nil
		branch.Parent = &parent
		branch = &parent
		anchor = source
	}

	d, err := Reparse(ctx, FromNodes([]*Node{branch}, limits), limits)
	if err != nil {
		return nil, err
	}

	e := d.Root()
	for _, p := range slices.Backward(path) {
		cs := e.Children()
		if p >= len(cs) {
			return nil, ErrMalformed
		}

		e = cs[p]
	}

	return ScopeDocument(d, e)
}
