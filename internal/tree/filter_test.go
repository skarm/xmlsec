package tree_test

import (
	"context"
	"errors"
	"slices"
	"testing"

	treepkg "github.com/skarm/xmlsec/internal/tree"
)

func TestFilterNodeSetKeepsSnapshotsIndependent(t *testing.T) {
	ctx := t.Context()

	d, err := treepkg.Parse(ctx, []byte(`<r><a x="1">text</a><!--c--><b/></r>`), treepkg.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}

	original, err := d.AllNodes(ctx)
	if err != nil {
		t.Fatal(err)
	}

	count := original.Len()
	for _, keep := range []func(treepkg.NodeRef) bool{func(treepkg.NodeRef) bool { return true }, func(treepkg.NodeRef) bool { return false }, func(n treepkg.NodeRef) bool { return n.Kind() == treepkg.ElementNode }} {
		selected, err := treepkg.FilterNodeSet(ctx, original, keep)
		if err != nil {
			t.Fatal(err)
		}

		for _, n := range original.Nodes() {
			if selected.Contains(n) != keep(n) {
				t.Fatal("incorrect filtered membership", n.Kind())
			}
		}
		// Immutable public set operations must work even when a no-op filter shares
		// membership with its input.
		changed, err := selected.With(d.Root().Node())
		if err != nil || !changed.Contains(d.Root().Node()) {
			t.Fatal(changed, err)
		}

		removed, err := selected.Without(d.Root().Node())
		if err != nil || removed.Contains(d.Root().Node()) {
			t.Fatal(removed, err)
		}

		if original.Len() != count || !original.Contains(d.Root().Node()) {
			t.Fatal("input selection mutated")
		}
	}

	canceled, cancel := context.WithCancel(ctx)
	cancel()

	if _, err := treepkg.FilterNodeSet(canceled, original, func(treepkg.NodeRef) bool { return true }); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

func TestSingleAxisReferencesMatchEnumeration(t *testing.T) {
	t.Parallel()
	doc, err := treepkg.Parse(t.Context(), []byte(`<r xmlns="urn:default" xmlns:p="urn:outer" b="2" a="1"><c xmlns="" xmlns:p="urn:inner" p:a="3"/></r>`), treepkg.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	root := treepkg.Root(doc)
	for _, raw := range []*treepkg.Node{root, root.Children[0]} {
		element := treepkg.Wrap(doc, raw)
		attributes := element.AttributeNodes()
		for i := range raw.Attrs {
			got := treepkg.WrapAttribute(doc, raw, i)
			if !slices.Contains(attributes, got) || got.Name() != raw.Attrs[i].Name || got.Value() != raw.Attrs[i].Value {
				t.Fatal("single attribute changed identity or content", i, got)
			}
		}
		for _, index := range []int{-1, len(raw.Attrs)} {
			if treepkg.WrapAttribute(doc, raw, index).Valid() {
				t.Fatal("invalid attribute index accepted", index)
			}
		}
		namespaces := element.NamespaceNodes()
		for _, want := range namespaces {
			if got := treepkg.WrapNamespace(doc, raw, want.Name().Local); got != want || got.Value() != want.Value() {
				t.Fatal("single namespace changed owner, binding or identity", got, want)
			}
		}
		if treepkg.WrapNamespace(doc, raw, "missing").Valid() {
			t.Fatal("unbound prefix acquired a reference")
		}
	}
	if treepkg.WrapNamespace(doc, root.Children[0], "").Valid() {
		t.Fatal("default namespace undeclaration acquired a reference")
	}
	if treepkg.WrapAttribute(nil, root, 0).Valid() || treepkg.WrapAttribute(doc, nil, 0).Valid() || treepkg.WrapNamespace(nil, root, "xml").Valid() || treepkg.WrapNamespace(doc, nil, "xml").Valid() {
		t.Fatal("nil storage acquired an axis reference")
	}
}

func TestExpandedCapacityHintPreservesLimitsAndMembership(t *testing.T) {
	t.Parallel()
	root := &treepkg.Node{
		Kind:  treepkg.ElementNode,
		Name:  treepkg.Name{Local: "r"},
		NS:    []treepkg.Namespace{{Prefix: "p", URI: "urn:outer"}, {Prefix: "empty", URI: ""}},
		Attrs: []treepkg.Attribute{{Name: treepkg.Name{Local: "a"}, Value: "1"}},
	}
	child := &treepkg.Node{
		Kind:   treepkg.ElementNode,
		Name:   treepkg.Name{Local: "c"},
		Parent: root,
		NS:     []treepkg.Namespace{{Prefix: "p", URI: "urn:inner"}, {Prefix: "", URI: ""}},
		Attrs:  []treepkg.Attribute{{Name: treepkg.Name{Local: "b"}, Value: "2"}},
	}
	child.Children = []*treepkg.Node{{Kind: treepkg.TextNode, Data: "text", Parent: child}}
	root.Children = []*treepkg.Node{child}
	for _, duplicate := range []bool{false, true} {
		if duplicate {
			// Drafts may borrow an existing node twice. Capacity estimation must
			// not replace add's unique-membership budget with a visit count.
			root.Children = append(root.Children, child)
		}
		for _, maximum := range []int{9, 10} {
			limits := treepkg.DefaultLimits()
			limits.MaxNodeSetNodes = maximum
			doc := treepkg.FromNodes([]*treepkg.Node{root}, limits)
			set, err := doc.AllNodes(t.Context())
			if maximum == 9 {
				if set.Valid() || !errors.Is(err, treepkg.ErrLimit) {
					t.Fatal("expanded limit changed", set.Len(), err)
				}
			} else if err != nil || set.Len() != 10 {
				t.Fatal("expanded selection changed", set.Len(), err)
			}
			subtree, err := doc.Root().Subtree(t.Context())
			if err != nil || subtree.Len() != 9 {
				t.Fatal("subtree counted a document or empty namespace", subtree.Len(), err)
			}
		}
	}

	// Internal drafts can carry unvalidated policy; preserve an error rather
	// than passing a negative capacity hint to make.
	invalid := treepkg.DefaultLimits()
	invalid.MaxNodeSetNodes = -1
	leaf := treepkg.FromNodes([]*treepkg.Node{{Kind: treepkg.ElementNode, Name: treepkg.Name{Local: "leaf"}}}, invalid)
	if set, err := leaf.AllNodes(t.Context()); set.Valid() || !errors.Is(err, treepkg.ErrLimit) {
		t.Fatal("negative draft policy did not fail safely", err)
	}
	if set, err := leaf.Root().Subtree(t.Context()); set.Valid() || !errors.Is(err, treepkg.ErrLimit) {
		t.Fatal("negative subtree policy did not fail safely", err)
	}
}
