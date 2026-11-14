package tree_test

import (
	"testing"

	"github.com/skarm/xmlsec/internal/tree"
)

func TestNodeRefNamesValuesAndOwners(t *testing.T) {
	t.Parallel()
	doc, err := tree.Parse(t.Context(), []byte(`<p:r xmlns:p="urn:p" p:key="007">a<!--note--><?task ready?><p:c>b</p:c></p:r>`), tree.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	root := tree.Root(doc)
	rootRef := tree.WrapNode(doc, root)
	refs := rootRef.Children()
	if len(refs) != 4 {
		t.Fatalf("fixture has %d child nodes, want 4", len(refs))
	}
	for _, tc := range []struct {
		label       string
		node, owner tree.NodeRef
		kind        tree.Kind
		name        tree.Name
		prefix      string
		value       string
	}{
		{"document", doc.Node(), tree.NodeRef{}, tree.DocumentNode, tree.Name{}, "", "ab"},
		{"root", rootRef, doc.Node(), tree.ElementNode, tree.Name{Space: "urn:p", Local: "r"}, "p", "ab"},
		{"attribute", tree.WrapAttribute(doc, root, 0), rootRef, tree.AttributeNode, tree.Name{Space: "urn:p", Local: "key"}, "p", "007"},
		{"namespace", tree.WrapNamespace(doc, root, "p"), rootRef, tree.NamespaceNode, tree.Name{Local: "p"}, "", "urn:p"},
		{"text", refs[0], rootRef, tree.TextNode, tree.Name{}, "", "a"},
		{"comment", refs[1], rootRef, tree.CommentNode, tree.Name{}, "", "note"},
		{"processing_instruction", refs[2], rootRef, tree.PINode, tree.Name{Local: "task"}, "", "ready"},
	} {
		t.Run(tc.label, func(t *testing.T) {
			t.Parallel()
			n := tc.node
			if n.Document() != doc || n.Kind() != tc.kind || n.Name() != tc.name || n.Prefix() != tc.prefix || n.Value() != tc.value || n.Parent() != tc.owner {
				t.Fatalf("kind=%v, name=%+v, prefix=%q, value=%q, correct parent=%t; want %v, %+v, %q, %q and the fixture parent",
					n.Kind(), n.Name(), n.Prefix(), n.Value(), n.Parent() == tc.owner, tc.kind, tc.name, tc.prefix, tc.value)
			}
			if element, ok := n.Element(); ok != (tc.kind == tree.ElementNode) || ok && !element.Node().Same(n) {
				t.Fatalf("Element() = %v, %t for kind %v", element, ok, tc.kind)
			}
			if tc.kind == tree.AttributeNode || tc.kind == tree.NamespaceNode {
				d, owner := tree.UnwrapNode(n)
				if d != doc || owner != root || len(n.Children()) != 0 {
					t.Fatalf("unwrap = %p, %p and %d child nodes; want fixture owner and no children", d, owner, len(n.Children()))
				}
			}
		})
	}
	for _, invalid := range []tree.NodeRef{tree.WrapAttribute(doc, root, -1), tree.WrapAttribute(doc, root, 1), tree.WrapNamespace(doc, root, "absent")} {
		if invalid.Valid() || invalid.Kind() != tree.InvalidNode || invalid.Prefix() != "" || invalid.Value() != "" || invalid.Parent().Valid() {
			t.Error("unbound reference did not behave like the zero value")
		}
	}
}
