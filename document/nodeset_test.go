package document_test

import (
	"context"
	"errors"
	"slices"
	"sync"
	"testing"

	"github.com/skarm/xmlsec/document"
)

func TestXPathNodeModel(t *testing.T) {
	d := mustDoc(t, `<?p before?><r xmlns="urn:r" xmlns:p="urn:p" b="2" p:a="1">one<![CDATA[two]]>&amp;<c xmlns="">three</c><!--comment--><?p data?></r>`)
	root := d.Root()

	doc := d.Node()
	if doc.Kind() != document.DocumentNode || doc.Parent().Valid() || doc.Name() != (document.Name{}) || doc.Value() != "onetwo&three" {
		t.Fatal("document node")
	}

	if !root.Node().Parent().Same(doc) || !root.Node().Same(doc.Children()[1]) {
		t.Fatal("element parent")
	}

	if !root.Node().Valid() || root.Node().Name() != root.Name() || root.Node().Value() != root.Text() {
		t.Fatal("element projection")
	}

	e, ok := root.Node().Element()
	if !ok || !e.Same(root) {
		t.Fatal("element conversion")
	}

	children := root.Node().Children()

	wantKinds := []document.NodeKind{document.TextNode, document.ElementNode, document.CommentNode, document.ProcessingInstructionNode}
	for i, child := range children {
		if child.Kind() != wantKinds[i] || !child.Parent().Same(root.Node()) {
			t.Fatal("child axis", i)
		}
	}

	if len(children) != 4 || children[0].Value() != "onetwo&" {
		t.Fatal("adjacent text / CDATA were not coalesced", children)
	}

	if children[2].Value() != "comment" || children[3].Name().Local != "p" || children[3].Value() != "data" {
		t.Fatal("comment/PI")
	}

	if _, ok := children[0].Element(); ok {
		t.Fatal("text is not an element")
	}

	for _, n := range []document.Node{children[0], children[2], children[3]} {
		if len(n.Children()) != 0 {
			t.Fatal("leaf children")
		}
	}

	checkXPathNodeAxes(t, d, root, children)

	if !doc.Children()[0].Parent().Same(doc) {
		t.Fatal("top PI parent")
	}
}

func checkXPathNodeAxes(t *testing.T, d *document.Document, root document.Element, children []document.Node) {
	t.Helper()

	attrs := root.AttributeNodes()
	if len(attrs) != 2 || attrs[0].Name().Local != "b" || attrs[0].Prefix() != "" || attrs[1].Prefix() != "p" {
		t.Fatal("attribute order")
	}

	for _, a := range attrs {
		if !a.Parent().Same(root.Node()) || len(a.Children()) != 0 || a.Kind() != document.AttributeNode {
			t.Fatal("attribute ownership")
		}
	}

	axes := root.NamespaceNodes()
	if len(axes) != 3 || axes[0].Name().Local != "" || axes[0].Value() != "urn:r" || axes[1].Name().Local != "p" || axes[2].Name().Local != "xml" {
		t.Fatal("namespace axis")
	}

	childNS := root.Children()[0].NamespaceNodes()
	if len(childNS) != 2 || childNS[0].Value() != "urn:p" {
		t.Fatal("empty default must be absent")
	}

	if childNS[0].Same(axes[1]) || !childNS[0].Parent().Same(children[1]) {
		t.Fatal("inherited namespace identity")
	}

	if axes[1].Prefix() != "" || axes[1].Name().Space != "" {
		t.Fatal("namespace name must not be xmlns QName")
	}

	if root.Node().Document() != d || axes[0].Document() != d {
		t.Fatal("snapshot")
	}
}

func TestNodeSetSemantics(t *testing.T) {
	d := mustDoc(t, `<r xmlns:p="urn:p" z="2" a="1">t<c p:x="v"/></r>`)
	root := d.Root()

	one, err := document.NewNodeSet(d, root.Node(), root.Node())
	if err != nil {
		t.Fatal(err)
	}

	if one.Len() != 1 || !one.Contains(root.Node()) || one.Contains(root.AttributeNodes()[0]) || one.Contains(root.Children()[0].Node()) {
		t.Fatal("selection is not an individual-node set")
	}

	all, err := d.AllNodes(t.Context())
	if err != nil {
		t.Fatal(err)
	}

	sub, err := root.Subtree(t.Context())
	if err != nil {
		t.Fatal(err)
	}

	if sub.Len() != all.Len()-1 || sub.Contains(d.Node()) || !all.Contains(d.Node()) {
		t.Fatal("document vs subtree")
	}

	if !all.Document().Root().Same(root) || !all.Valid() {
		t.Fatal("validity")
	}

	n := one.Nodes()
	n[0] = document.Node{}

	if !one.Contains(root.Node()) {
		t.Fatal("Nodes aliases selection")
	}

	checkNodeSetAlgebra(t, root, one, sub)

	empty, err := document.NewNodeSet(d)
	if err != nil || !empty.Valid() || empty.Len() != 0 {
		t.Fatal("valid empty set")
	}

	got := all.Nodes()
	if got[0].Kind() != document.DocumentNode || got[1].Kind() != document.ElementNode || got[2].Kind() != document.NamespaceNode || got[3].Kind() != document.NamespaceNode || got[4].Kind() != document.AttributeNode || got[4].Name().Local != "a" {
		t.Fatal("document/axis order", got)
	}
}

func checkNodeSetAlgebra(t *testing.T, root document.Element, one, sub document.NodeSet) {
	t.Helper()

	more, err := one.With(root.AttributeNodes()[0])
	if err != nil || more.Len() != 2 || one.Len() != 1 {
		t.Fatal("With mutated original", err)
	}

	less, err := more.Without(root.Node())
	if err != nil || less.Len() != 1 || less.Contains(root.Node()) || more.Len() != 2 {
		t.Fatal("Without", err)
	}

	intersection, err := sub.Intersect(one)
	if err != nil || intersection.Len() != 1 {
		t.Fatal("intersection", err)
	}

	difference, err := sub.Difference(one)
	if err != nil || difference.Len() != sub.Len()-1 {
		t.Fatal("difference", err)
	}

	union, err := difference.Union(one)
	if err != nil || !slices.Equal(union.Nodes(), sub.Nodes()) {
		t.Fatal("union", err)
	}
}

func TestInvalidNodeSetHandles(t *testing.T) {
	var (
		node    document.Node
		element document.Element
		set     document.NodeSet
		dnil    *document.Document
	)

	if node.Valid() || node.Same(node) || node.Kind() != document.InvalidNode || node.Kind().String() != "invalid" || node.Name() != (document.Name{}) || node.Prefix() != "" || node.Value() != "" || node.Parent().Valid() || node.Document() != nil || len(node.Children()) != 0 {
		t.Fatal("zero Node")
	}

	if element.Node().Valid() || len(element.AttributeNodes()) != 0 || len(element.NamespaceNodes()) != 0 || dnil.Node().Valid() {
		t.Fatal("zero projections")
	}

	if set.Valid() || set.Contains(node) || set.Nodes() != nil {
		t.Fatal("zero set")
	}

	d := mustDoc(t, `<r/>`)
	other := mustDoc(t, `<r/>`)
	good, _ := d.Root().Subtree(t.Context())
	foreign, _ := other.Root().Subtree(t.Context())

	tests := []struct {
		name string
		fn   func() error
	}{
		{"nil document", func() error { _, e := document.NewNodeSet(nil); return e }},
		{"zero handle", func() error { _, e := document.NewNodeSet(d, node); return e }},
		{"foreign handle", func() error { _, e := document.NewNodeSet(d, other.Root().Node()); return e }},
		{"with zero", func() error { _, e := set.With(node); return e }},
		{"without zero", func() error { _, e := set.Without(node); return e }},
		{"with foreign", func() error { _, e := good.With(other.Node()); return e }},
		{"without foreign", func() error { _, e := good.Without(other.Node()); return e }},
		{"foreign union", func() error { _, e := good.Union(foreign); return e }},
		{"foreign intersection", func() error { _, e := good.Intersect(foreign); return e }},
		{"foreign difference", func() error { _, e := good.Difference(foreign); return e }},
		{"invalid subtree", func() error { _, e := element.Subtree(t.Context()); return e }},
		{"nil all", func() error { _, e := dnil.AllNodes(t.Context()); return e }},
		{"nil context", func() error { _, e := d.AllNodes(nil); return e }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.fn(); !errors.Is(err, document.ErrMalformed) {
				t.Fatal(err)
			}
		})
	}

	if good.Contains(other.Root().Node()) {
		t.Fatal("foreign membership")
	}
}

func TestNodeSetLimits(t *testing.T) {
	limits := document.DefaultLimits()
	limits.MaxNodeSetNodes = 2

	d, err := document.Parse(context.Background(), []byte(`<r><c/></r>`), limits)
	if err != nil {
		t.Fatal(err)
	}

	root, _ := document.NewNodeSet(d, d.Root().Node(), d.Node())
	child, _ := document.NewNodeSet(d, d.Root().Children()[0].Node())

	for _, fn := range []func() error{
		func() error { _, e := d.AllNodes(t.Context()); return e },
		func() error { _, e := d.Root().Subtree(t.Context()); return e },
		func() error { _, e := root.Union(child); return e },
		func() error { _, e := root.With(child.Nodes()[0]); return e },
	} {
		if err := fn(); !errors.Is(err, document.ErrLimit) {
			t.Fatal(err)
		}
	}

	if root.Len() != 2 {
		t.Fatal("failed operation mutated set")
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if _, err := d.AllNodes(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}

	limits = document.DefaultLimits()

	limits.MaxInScopeNamespaces = 2
	if _, err := document.Parse(context.Background(), []byte(`<r xmlns:p="urn:p"><c xmlns:q="urn:q"/></r>`), limits); !errors.Is(err, document.ErrLimit) {
		t.Fatal(err)
	}

	if _, err := document.Parse(context.Background(), []byte(`<r xmlns:p="urn:p"><c xmlns:p="urn:q"/></r>`), limits); err != nil {
		t.Fatal("rebindings do not add prefixes", err)
	}

	limits.MaxInScopeNamespaces = -1
	if _, err := document.Parse(context.Background(), []byte(`<r/>`), limits); !errors.Is(err, document.ErrLimit) {
		t.Fatal(err)
	}
}

func TestNodeSetConcurrentReaders(t *testing.T) {
	d := mustDoc(t, `<r xmlns:p="urn:p"><p:c a="1">text</p:c></r>`)
	all, _ := d.AllNodes(t.Context())
	child, _ := d.Root().Children()[0].Subtree(t.Context())

	var wg sync.WaitGroup
	for range 12 {
		wg.Go(func() {
			for range 20 {
				if _, err := all.Difference(child); err != nil {
					t.Error(err)
				}

				for _, node := range all.Nodes() {
					_ = node.Value()
					_ = node.Parent()
					_ = node.Children()
				}
			}
		})
	}

	wg.Wait()
}

func TestNamespaceScopeRestoresSiblings(t *testing.T) {
	d, err := document.Parse(t.Context(), []byte(`<r xmlns="urn:root" xmlns:p="urn:outer"><a xmlns="" xmlns:p="urn:inner"><p:x/></a><p:b/><c/></r>`), document.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}

	kids := d.Root().Children()

	expected := []document.Name{{Local: "a"}, {Space: "urn:outer", Local: "b"}, {Space: "urn:root", Local: "c"}}
	for i, child := range kids {
		if child.Name() != expected[i] {
			t.Fatalf("child %d: %v", i, child.Name())
		}

		ns, err := child.Subtree(t.Context())
		if err != nil {
			t.Fatal(err)
		}

		prefix := "urn:outer"
		if i == 0 {
			prefix = "urn:inner"
		}

		found := false

		for _, node := range ns.Nodes() {
			if node.Kind() == document.NamespaceNode && node.Parent().Same(child.Node()) && node.Name().Local == "p" {
				if node.Value() != prefix {
					t.Fatalf("child %d: namespace %q", i, node.Value())
				}

				found = true
			}
		}

		if !found {
			t.Fatal("namespace omitted")
		}
	}

	all, err := d.AllNodes(t.Context())
	if err != nil {
		t.Fatal(err)
	}

	for _, child := range kids {
		for _, ns := range child.NamespaceNodes() {
			if !all.Contains(ns) {
				t.Fatal("lost sibling binding")
			}
		}
	}
}
