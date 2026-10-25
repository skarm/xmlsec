package xdm

import (
	"context"

	"github.com/skarm/xmlsec/internal/tree"
)

// PublishNode anchors a privately constructed detached node in its owner
// snapshot before that snapshot becomes immutable. Sequence items are never
// merged, copied or reordered, including adjacent text nodes.
func PublishNode(n Node) {
	if n == nil || n.OwnerDocument() == nil {
		return
	}

	d := n.OwnerDocument()
	if d.readOnly.Load() {
		return
	}

	root := n
	for parent := root.Parent(); parent != nil; parent = root.Parent() {
		if parent.Type() == DocumentNode {
			return
		}

		root = parent
	}

	if root.Type() == DocumentNode || root.Type() == AttributeNode || root.Type() == NamespaceNode {
		return
	}

	v := root.view()
	v.slot = len(d.raw.Children)
	d.raw.Children = append(d.raw.Children, v.raw)
	d.sync()
}

// ElementDocument copies one element into an independent document, including
// namespace bindings inherited from ancestors outside the selected subtree.
func ElementDocument(ctx context.Context, element *Element) (*Document, error) {
	draft := tree.FromNodes([]*tree.Node{tree.ExtractSubtree(element.raw)}, tree.DefaultLimits())

	cloned, err := tree.Clone(ctx, draft)
	if err != nil {
		return nil, err
	}

	doc, err := WrapDocument(ctx, cloned)
	if err != nil {
		return nil, err
	}

	doc.SetURL(element.OwnerDocument().URL())

	return doc, nil
}

// NodeView returns a language-engine view of the very same project node.
func (d *Document) NodeView(n tree.NodeRef) Node {
	source, raw := tree.UnwrapNode(n)
	if source != d.native || !n.Valid() {
		return nil
	}

	switch n.Kind() {
	case tree.DocumentNode:
		return d
	case tree.AttributeNode:
		e, ok := d.nodes[raw].(*Element)
		if !ok {
			return nil
		}

		name := n.Name()

		return e.GetAttributeNodeNS(name.Local, name.Space)
	case tree.NamespaceNode:
		return NewNamespaceNodeWrapper(NewNamespace(n.Name().Local, n.Value()), d.nodes[raw])
	default:
		return d.nodes[raw]
	}
}

// Reference returns the original immutable handle, including owner-bound
// attribute and namespace identity. No document is copied or reparsed.
func (nv *nodeView) Reference() tree.NodeRef {
	n := nv.self
	if n == nil || n.OwnerDocument() == nil {
		return tree.NodeRef{}
	}

	d := n.OwnerDocument()

	raw := n.view().raw
	switch n.Type() {
	case DocumentNode:
		return d.native.Node()
	case AttributeNode:
		a, ok := n.(*Attribute)
		if !ok {
			return tree.NodeRef{}
		}

		e := tree.Wrap(d.native, raw)
		for _, v := range e.AttributeNodes() {
			name := v.Name()
			if name.Local == a.LocalName() && name.Space == a.URI() {
				return v
			}
		}
	case NamespaceNode:
		owner := n.Parent()
		if owner == nil {
			return tree.NodeRef{}
		}

		for _, v := range tree.Wrap(d.native, owner.view().raw).NamespaceNodes() {
			if v.Name().Local == n.Name() {
				return v
			}
		}
	default:
		return tree.WrapNode(d.native, raw)
	}

	return tree.NodeRef{}
}
