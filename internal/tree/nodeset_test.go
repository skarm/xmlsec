package tree_test

import (
	"context"
	"errors"
	"slices"
	"strconv"
	"strings"
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

func TestNodeSetOperationsPreserveSnapshotAndDocumentOrder(t *testing.T) {
	t.Parallel()
	limits := tree.DefaultLimits()
	limits.MaxNodeSetNodes = 3
	const input = `<r><a/><b/><c/><d/></r>`
	doc, err := tree.Parse(t.Context(), []byte(input), limits)
	if err != nil {
		t.Fatal(err)
	}
	foreign, err := tree.Parse(t.Context(), []byte(input), limits)
	if err != nil {
		t.Fatal(err)
	}
	children := doc.Root().Node().Children()
	if len(children) != 4 {
		t.Fatalf("fixture has %d child nodes, want 4", len(children))
	}
	a, b, c, d := children[0], children[1], children[2], children[3]
	left, err := tree.NewNodeSet(doc, c, a, c)
	if err != nil {
		t.Fatal(err)
	}
	right, err := tree.NewNodeSet(doc, b, c)
	if err != nil {
		t.Fatal(err)
	}
	overLimit, err := tree.NewNodeSet(doc, b, d)
	if err != nil {
		t.Fatal(err)
	}
	wrongSnapshot, err := tree.NewNodeSet(foreign, foreign.Root().Node())
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name  string
		apply func() (tree.NodeSet, error)
		want  []tree.NodeRef
		err   error
	}{
		{"union", func() (tree.NodeSet, error) { return left.Union(right) }, []tree.NodeRef{a, b, c}, nil},
		{"intersection", func() (tree.NodeSet, error) { return left.Intersect(right) }, []tree.NodeRef{c}, nil},
		{"difference", func() (tree.NodeSet, error) { return left.Difference(right) }, []tree.NodeRef{a}, nil},
		{"valid_empty_difference", func() (tree.NodeSet, error) { return left.Difference(left) }, nil, nil},
		{"add_duplicate_at_limit", func() (tree.NodeSet, error) { return left.With(b, c, b) }, []tree.NodeRef{a, b, c}, nil},
		{"remove_present_and_absent", func() (tree.NodeSet, error) { return left.Without(c, b) }, []tree.NodeRef{a}, nil},
		{"union_limit", func() (tree.NodeSet, error) { return left.Union(overLimit) }, nil, tree.ErrLimit},
		{"foreign_snapshot", func() (tree.NodeSet, error) { return left.Intersect(wrongSnapshot) }, nil, tree.ErrMalformed},
		{"uninitialized_set", func() (tree.NodeSet, error) { return left.Difference(tree.NodeSet{}) }, nil, tree.ErrMalformed},
		{"foreign_node_removal", func() (tree.NodeSet, error) { return left.Without(foreign.Root().Node()) }, nil, tree.ErrMalformed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := tc.apply()
			if tc.err != nil {
				if got.Valid() || !errors.Is(err, tc.err) {
					t.Fatalf("result valid=%t, error=%v; want invalid result and %v", got.Valid(), err, tc.err)
				}
				return
			}
			if err != nil || !got.Valid() || got.Document() != doc || !slices.Equal(got.Nodes(), tc.want) {
				t.Fatalf("result=%v, error=%v; want nodes %v from the original snapshot", got.Nodes(), err, tc.want)
			}
			ordered := got.Nodes()
			if len(ordered) > 0 {
				ordered[0] = tree.NodeRef{}
				if !slices.Equal(got.Nodes(), tc.want) {
					t.Error("changing the returned slice changed the set")
				}
			}
			if !slices.Equal(left.Nodes(), []tree.NodeRef{a, c}) || !slices.Equal(right.Nodes(), []tree.NodeRef{b, c}) {
				t.Error("an input set changed")
			}
		})
	}
}

func TestNodeSetNodesOrdersSelectedAxesOfUnselectedElements(t *testing.T) {
	t.Parallel()

	const input = `<r xmlns:z="urn:z" xmlns:a="urn:a"><item z:b="3" b="2" a:c="4" a="1"><leaf/></item></r>`
	doc, err := tree.Parse(t.Context(), []byte(input), tree.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	item := tree.Root(doc).Children[0]
	nsA := tree.WrapNamespace(doc, item, "a")
	nsZ := tree.WrapNamespace(doc, item, "z")
	attrZ := tree.WrapAttribute(doc, item, 0)
	attrB := tree.WrapAttribute(doc, item, 1)
	attrC := tree.WrapAttribute(doc, item, 2)
	attrA := tree.WrapAttribute(doc, item, 3)
	leaf := tree.WrapNode(doc, item.Children[0])
	set, err := tree.NewNodeSet(doc, leaf, attrZ, attrB, nsZ, attrC, nsA, attrA)
	if err != nil {
		t.Fatal(err)
	}

	want := []tree.NodeRef{nsA, nsZ, attrA, attrB, attrC, attrZ, leaf}
	got := set.Nodes()
	if len(got) != len(want) {
		t.Fatalf("Nodes returned %d entries, want %d", len(got), len(want))
	}
	for i, node := range got {
		if !node.Same(want[i]) {
			t.Errorf("Nodes entry %d = (%s, %+v), want (%s, %+v)", i, node.Kind(), node.Name(), want[i].Kind(), want[i].Name())
		}
	}
}

func TestNewNodeSetRejectsInvalidSelection(t *testing.T) {
	t.Parallel()

	limits := tree.DefaultLimits()
	limits.MaxNodeSetNodes = 1
	doc, err := tree.Parse(t.Context(), []byte("<r><a/></r>"), limits)
	if err != nil {
		t.Fatal(err)
	}
	scope, err := tree.ScopeDocument(doc, doc.Root())
	if err != nil {
		t.Fatal(err)
	}
	root := doc.Root().Node()
	for _, tc := range []struct {
		name    string
		doc     *tree.Document
		nodes   []tree.NodeRef
		wantErr error
	}{
		{name: "nil_document", wantErr: tree.ErrMalformed},
		{name: "document_without_root", doc: &tree.Document{}, wantErr: tree.ErrMalformed},
		{name: "uninitialized_node", doc: doc, nodes: []tree.NodeRef{root, {}}, wantErr: tree.ErrMalformed},
		{name: "node_from_another_snapshot", doc: doc, nodes: []tree.NodeRef{root, scope.Root().Node()}, wantErr: tree.ErrMalformed},
		{name: "selection_over_budget", doc: doc, nodes: []tree.NodeRef{root, root.Children()[0]}, wantErr: tree.ErrLimit},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			set, err := tree.NewNodeSet(tc.doc, tc.nodes...)
			if !errors.Is(err, tc.wantErr) || set.Valid() || set.Nodes() != nil {
				t.Errorf("NewNodeSet returned valid=%t, nodes=%v, error=%v, want invalid set and %v", set.Valid(), set.Nodes(), err, tc.wantErr)
			}
		})
	}
}

func TestSubtreeCountsInheritedBindingsAndAttributesInBudget(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name    string
		budget  int
		wantErr error
	}{
		{name: "exact_budget", budget: 8},
		{name: "descendant_namespace_exceeds_budget", budget: 7, wantErr: tree.ErrLimit},
		{name: "attribute_exceeds_budget", budget: 3, wantErr: tree.ErrLimit},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			limits := tree.DefaultLimits()
			limits.MaxNodeSetNodes = tc.budget
			const input = `<r xmlns="urn:default" xmlns:p="urn:p"><item xmlns="" a="1" b="2"><p:leaf/></item><sibling/></r>`
			doc, err := tree.Parse(t.Context(), []byte(input), limits)
			if err != nil {
				t.Fatal(err)
			}
			item := doc.Root().Children()[0]
			set, err := item.Subtree(t.Context())
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) || set.Valid() {
					t.Errorf("Subtree with budget %d returned valid=%t, error=%v, want invalid set and %v", tc.budget, set.Valid(), err, tc.wantErr)
				}
				return
			}
			if err != nil || !set.Valid() || set.Document() != doc {
				t.Fatalf("Subtree returned valid=%t, error=%v, want a selection from the source document", set.Valid(), err)
			}

			_, raw := tree.Unwrap(item)
			leaf := raw.Children[0]
			want := []tree.NodeRef{
				item.Node(), tree.WrapNamespace(doc, raw, "p"), tree.WrapNamespace(doc, raw, "xml"),
				tree.WrapAttribute(doc, raw, 0), tree.WrapAttribute(doc, raw, 1),
				tree.WrapNode(doc, leaf), tree.WrapNamespace(doc, leaf, "p"), tree.WrapNamespace(doc, leaf, "xml"),
			}
			if set.Len() != len(want) || !slices.Equal(set.Nodes(), want) {
				t.Fatalf("Subtree returned %v, want %v", set.Nodes(), want)
			}
		})
	}
}

func TestAllNodesReturnsNoSelectionWhenCanceled(t *testing.T) {
	t.Parallel()

	doc, err := tree.Parse(t.Context(), []byte("<r><a/></r>"), tree.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	set, err := doc.AllNodes(ctx)
	if !errors.Is(err, context.Canceled) || set.Valid() {
		t.Errorf("AllNodes returned valid=%t, error=%v, want invalid set and context.Canceled", set.Valid(), err)
	}
}

func BenchmarkAllNodes(b *testing.B) {
	for _, size := range []int{0, 1, 16, 1024, 8192} {
		for _, namespaces := range []int{1, 8} {
			b.Run(strconv.Itoa(size)+"/"+strconv.Itoa(namespaces), func(b *testing.B) {
				var input strings.Builder
				input.WriteString(`<r`)
				for i := range namespaces {
					input.WriteString(` xmlns:p` + strconv.Itoa(i) + `="urn:p` + strconv.Itoa(i) + `"`)
				}
				input.WriteString(`>`)
				input.WriteString(strings.Repeat(`<item a="1">text</item>`, size))
				input.WriteString(`</r>`)
				doc, err := tree.Parse(b.Context(), []byte(input.String()), tree.DefaultLimits())
				if err != nil {
					b.Fatal(err)
				}
				want := 1 + 1 + namespaces + 1 + size*(1+namespaces+1+1+1)
				b.ReportAllocs()
				for b.Loop() {
					set, err := doc.AllNodes(b.Context())
					if err != nil || set.Len() != want {
						b.Fatal("expanded node count", set.Len(), want, err)
					}
				}
			})
		}
	}
}

// Exercise the ordered node enumeration used by XPath signature transforms.
// Parsing and expanded selection construction are outside the timed loop.
func BenchmarkNodeSetNodes(b *testing.B) {
	for _, size := range []int{16, 1024, 8192} {
		b.Run(strconv.Itoa(size), func(b *testing.B) {
			doc, err := tree.Parse(b.Context(), []byte(`<r xmlns:p="urn:p">`+strings.Repeat(`<item b="2" a="1">text</item>`, size)+`</r>`), tree.DefaultLimits())
			if err != nil {
				b.Fatal(err)
			}
			all, err := doc.AllNodes(b.Context())
			if err != nil {
				b.Fatal(err)
			}
			empty, err := tree.NewNodeSet(doc)
			if err != nil {
				b.Fatal(err)
			}
			for name, set := range map[string]tree.NodeSet{"All": all, "Empty": empty} {
				b.Run(name, func(b *testing.B) {
					b.ReportAllocs()
					for b.Loop() {
						if got := set.Nodes(); len(got) != set.Len() {
							b.Fatal("wrong node count")
						}
					}
				})
			}
		})
	}
}
