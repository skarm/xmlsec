package tree_test

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/skarm/xmlsec/internal/tree"
)

func TestFilterNodeSetKeepsSnapshotsIndependent(t *testing.T) {
	ctx := t.Context()

	d, err := tree.Parse(ctx, []byte(`<r><a x="1">text</a><!--c--><b/></r>`), tree.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}

	original, err := d.AllNodes(ctx)
	if err != nil {
		t.Fatal(err)
	}

	count := original.Len()
	for _, keep := range []func(tree.NodeRef) bool{func(tree.NodeRef) bool { return true }, func(tree.NodeRef) bool { return false }, func(n tree.NodeRef) bool { return n.Kind() == tree.ElementNode }} {
		selected, err := tree.FilterNodeSet(ctx, original, keep)
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
		if err != nil {
			t.Fatal(err)
		}

		if !changed.Contains(d.Root().Node()) {
			t.Fatal("added root is missing")
		}

		removed, err := selected.Without(d.Root().Node())
		if err != nil {
			t.Fatal(err)
		}

		if removed.Contains(d.Root().Node()) {
			t.Fatal("removed root remains selected")
		}

		if original.Len() != count || !original.Contains(d.Root().Node()) {
			t.Fatal("input selection mutated")
		}
	}

	canceled, cancel := context.WithCancel(ctx)
	cancel()

	if _, err := tree.FilterNodeSet(canceled, original, func(tree.NodeRef) bool { return true }); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

func TestNodeWithinUsesTheOwningElementAndSnapshot(t *testing.T) {
	t.Parallel()

	const input = `<r xmlns:p="urn:p"><a id="a"><b>inside</b></a><c id="c"/></r>`
	doc, err := tree.Parse(t.Context(), []byte(input), tree.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	root := doc.Root()
	a, c := root.Children()[0], root.Children()[1]
	b := a.Children()[0]
	_, bNode := tree.Unwrap(b)
	_, cNode := tree.Unwrap(c)
	scope, err := tree.ScopeDocument(doc, a)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name     string
		node     tree.NodeRef
		ancestor tree.Element
		want     bool
	}{
		{name: "element_itself", node: a.Node(), ancestor: a, want: true},
		{name: "descendant_text", node: b.Node().Children()[0], ancestor: a, want: true},
		{name: "attribute_of_ancestor", node: a.AttributeNodes()[0], ancestor: a, want: true},
		{name: "inherited_binding_owned_by_descendant", node: tree.WrapNamespace(doc, bNode, "p"), ancestor: a, want: true},
		{name: "same_binding_owned_by_sibling", node: tree.WrapNamespace(doc, cNode, "p"), ancestor: a},
		{name: "parent_element", node: root.Node(), ancestor: a},
		{name: "document_node", node: doc.Node(), ancestor: a},
		{name: "same_element_from_another_snapshot", node: a.Node(), ancestor: scope.Root()},
		{name: "invalid_ancestor", node: a.Node()},
		{name: "invalid_node", ancestor: a},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if got := tree.NodeWithin(tc.node, tc.ancestor); got != tc.want {
				t.Errorf("NodeWithin(%s %q, %q) = %t, want %t", tc.node.Kind(), tc.node.Name().Local, tc.ancestor.Name().Local, got, tc.want)
			}
		})
	}
}

func TestIsNodeSetSubsetComparesIndividualNodes(t *testing.T) {
	t.Parallel()

	doc, err := tree.Parse(t.Context(), []byte(`<r xmlns:p="urn:p" id="one"><p:c/></r>`), tree.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	clone, err := tree.Clone(t.Context(), doc)
	if err != nil {
		t.Fatal(err)
	}

	newSet := func(t *testing.T, d *tree.Document, refs ...tree.NodeRef) tree.NodeSet {
		t.Helper()
		set, err := tree.NewNodeSet(d, refs...)
		if err != nil {
			t.Fatal(err)
		}
		return set
	}
	root := doc.Root().Node()
	attr := doc.Root().AttributeNodes()[0]
	empty := newSet(t, doc)
	elements := newSet(t, doc, root)
	axes := newSet(t, doc, attr)
	both := newSet(t, doc, root, attr)
	other := newSet(t, clone, clone.Root().Node())
	canceled, cancel := context.WithCancel(t.Context())
	cancel()

	for _, tc := range []struct {
		name     string
		ctx      context.Context
		sub, sup tree.NodeSet
		want     bool
		wantErr  error
	}{
		{name: "empty_is_subset", ctx: t.Context(), sub: empty, sup: elements, want: true},
		{name: "equal_sets", ctx: t.Context(), sub: both, sup: both, want: true},
		{name: "proper_subset", ctx: t.Context(), sub: axes, sup: both, want: true},
		{name: "owner_does_not_include_its_axis", ctx: t.Context(), sub: axes, sup: elements},
		{name: "empty_superset", ctx: t.Context(), sub: elements, sup: empty},
		{name: "foreign_snapshot", ctx: t.Context(), sub: elements, sup: other, wantErr: tree.ErrMalformed},
		{name: "invalid_subset", ctx: t.Context(), sup: both, wantErr: tree.ErrMalformed},
		{name: "invalid_superset", ctx: t.Context(), sub: both, wantErr: tree.ErrMalformed},
		{name: "nil_context", sub: both, sup: both, wantErr: tree.ErrMalformed},
		{name: "canceled", ctx: canceled, sub: both, sup: both, wantErr: context.Canceled},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, err := tree.IsNodeSetSubset(tc.ctx, tc.sub, tc.sup)
			if got != tc.want || !errors.Is(err, tc.wantErr) {
				t.Errorf("IsNodeSetSubset = (%t, %v), want (%t, %v)", got, err, tc.want, tc.wantErr)
			}
		})
	}
}

func TestSingleAxisReferencesMatchEnumeration(t *testing.T) {
	t.Parallel()
	doc, err := tree.Parse(t.Context(), []byte(`<r xmlns="urn:default" xmlns:p="urn:outer" b="2" a="1"><c xmlns="" xmlns:p="urn:inner" p:a="3"/></r>`), tree.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	root := tree.Root(doc)
	for _, raw := range []*tree.Node{root, root.Children[0]} {
		element := tree.Wrap(doc, raw)
		attributes := element.AttributeNodes()
		for i := range raw.Attrs {
			got := tree.WrapAttribute(doc, raw, i)
			if !slices.Contains(attributes, got) || got.Name() != raw.Attrs[i].Name || got.Value() != raw.Attrs[i].Value {
				t.Fatal("single attribute changed identity or content", i, got)
			}
		}
		for _, index := range []int{-1, len(raw.Attrs)} {
			if tree.WrapAttribute(doc, raw, index).Valid() {
				t.Fatal("invalid attribute index accepted", index)
			}
		}
		namespaces := element.NamespaceNodes()
		for _, want := range namespaces {
			if got := tree.WrapNamespace(doc, raw, want.Name().Local); got != want || got.Value() != want.Value() {
				t.Fatal("single namespace changed owner, binding or identity", got, want)
			}
		}
		if tree.WrapNamespace(doc, raw, "missing").Valid() {
			t.Fatal("unbound prefix acquired a reference")
		}
	}
	if tree.WrapNamespace(doc, root.Children[0], "").Valid() {
		t.Fatal("default namespace undeclaration acquired a reference")
	}
	if tree.WrapAttribute(nil, root, 0).Valid() || tree.WrapAttribute(doc, nil, 0).Valid() || tree.WrapNamespace(nil, root, "xml").Valid() || tree.WrapNamespace(doc, nil, "xml").Valid() {
		t.Fatal("nil storage acquired an axis reference")
	}
}

func TestExpandedCapacityHintPreservesLimitsAndMembership(t *testing.T) {
	t.Parallel()
	root := &tree.Node{
		Kind:  tree.ElementNode,
		Name:  tree.Name{Local: "r"},
		NS:    []tree.Namespace{{Prefix: "p", URI: "urn:outer"}, {Prefix: "empty", URI: ""}},
		Attrs: []tree.Attribute{{Name: tree.Name{Local: "a"}, Value: "1"}},
	}
	child := &tree.Node{
		Kind:   tree.ElementNode,
		Name:   tree.Name{Local: "c"},
		Parent: root,
		NS:     []tree.Namespace{{Prefix: "p", URI: "urn:inner"}, {Prefix: "", URI: ""}},
		Attrs:  []tree.Attribute{{Name: tree.Name{Local: "b"}, Value: "2"}},
	}
	child.Children = []*tree.Node{{Kind: tree.TextNode, Data: "text", Parent: child}}
	root.Children = []*tree.Node{child}
	for _, duplicate := range []bool{false, true} {
		if duplicate {
			// Drafts may borrow an existing node twice. Capacity estimation must
			// not replace add's unique-membership budget with a visit count.
			root.Children = append(root.Children, child)
		}
		for _, maximum := range []int{9, 10} {
			limits := tree.DefaultLimits()
			limits.MaxNodeSetNodes = maximum
			doc := tree.FromNodes([]*tree.Node{root}, limits)
			set, err := doc.AllNodes(t.Context())
			if maximum == 9 {
				requireNodeSetLimit(t, set, err)
			} else {
				if err != nil {
					t.Fatal(err)
				}

				if set.Len() != 10 {
					t.Fatal("expanded selection changed", set.Len())
				}
			}

			subtree, err := doc.Root().Subtree(t.Context())
			if err != nil {
				t.Fatal(err)
			}

			if subtree.Len() != 9 {
				t.Fatal("subtree counted a document or empty namespace", subtree.Len())
			}
		}
	}

	// Internal drafts can carry unvalidated policy; preserve an error rather
	// than passing a negative capacity hint to make.
	invalid := tree.DefaultLimits()
	invalid.MaxNodeSetNodes = -1
	leaf := tree.FromNodes([]*tree.Node{{Kind: tree.ElementNode, Name: tree.Name{Local: "leaf"}}}, invalid)
	set, err := leaf.AllNodes(t.Context())
	requireNodeSetLimit(t, set, err)

	subtree, err := leaf.Root().Subtree(t.Context())
	requireNodeSetLimit(t, subtree, err)
}

func requireNodeSetLimit(t *testing.T, set tree.NodeSet, err error) {
	t.Helper()

	if !errors.Is(err, tree.ErrLimit) {
		t.Fatalf("expected node-set limit error, got %v", err)
	}

	if set.Valid() {
		t.Fatal("limit failure returned a valid node set")
	}
}

func BenchmarkFilterNodeSet(b *testing.B) {
	d, err := tree.Parse(b.Context(), []byte(`<r><drop>`+strings.Repeat(`<item a="1">text</item>`, 100)+`</drop><keep>`+strings.Repeat(`<item a="1">text</item>`, 100)+`</keep></r>`), tree.DefaultLimits())
	if err != nil {
		b.Fatal(err)
	}

	set, err := d.AllNodes(b.Context())
	if err != nil {
		b.Fatal(err)
	}

	drop := d.Root().Children()[0]

	for name, keep := range map[string]func(tree.NodeRef) bool{
		"All":      func(tree.NodeRef) bool { return true },
		"None":     func(tree.NodeRef) bool { return false },
		"Elements": func(n tree.NodeRef) bool { return n.Kind() == tree.ElementNode },
		"Subtree":  func(n tree.NodeRef) bool { return !tree.NodeWithin(n, drop) },
	} {
		b.Run(name, func(b *testing.B) {
			b.ReportAllocs()

			for b.Loop() {
				if _, err := tree.FilterNodeSet(b.Context(), set, keep); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
