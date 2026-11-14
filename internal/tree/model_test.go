package tree_test

import (
	"strings"
	"testing"

	"github.com/skarm/xmlsec/internal/tree"
)

func TestSetDraftChildrenRefreshesRoot(t *testing.T) {
	t.Parallel()
	old := &tree.Node{Kind: tree.ElementNode, Name: tree.Name{Local: "old"}}
	draft := tree.FromNodes([]*tree.Node{old}, tree.DefaultLimits())
	note := &tree.Node{Kind: tree.CommentNode, Data: "note"}
	root := &tree.Node{Kind: tree.ElementNode, Name: tree.Name{Local: "new"}}
	tree.SetDraftChildren(draft, []*tree.Node{note, root})
	if tree.Root(draft) != root || tree.Policy(draft) != tree.DefaultLimits() {
		t.Fatalf("root=%p, limits=%+v; want root=%p and original limits", tree.Root(draft), tree.Policy(draft), root)
	}
	got := tree.Children(draft)
	if len(got) != 2 || got[0] != note || got[1] != root {
		t.Fatalf("draft children=%v; want the comment and the new root in order", got)
	}
	tree.SetDraftChildren(draft, []*tree.Node{note})
	if tree.Root(draft) != nil || draft.Root().Valid() {
		t.Fatal("removed element still appears as the draft root")
	}
}

func TestAppendTextDataKeepsPublishedStringAndHandlesReplacement(t *testing.T) {
	t.Parallel()
	node := &tree.Node{Kind: tree.TextNode, Data: "pré"}
	tree.AppendTextData(node, "fix")
	first := node.Data
	tree.AppendTextData(node, "e")
	if first != "préfix" || node.Data != "préfixe" {
		t.Fatalf("prior=%q, current=%q; want préfix and préfixe", first, node.Data)
	}
	node.Data = "autre"
	tree.AppendTextData(node, " texte")
	if got := tree.StringValue(node); got != "autre texte" {
		t.Fatalf("text after replacing the draft value=%q; want autre texte", got)
	}
}

func BenchmarkClone(b *testing.B) {
	d, err := tree.Parse(b.Context(), []byte(`<r>`+strings.Repeat(`<item a="1">text</item>`, 100)+`</r>`), tree.DefaultLimits())
	if err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()

	for b.Loop() {
		if _, err := tree.Clone(b.Context(), d); err != nil {
			b.Fatal(err)
		}
	}
}

func TestDraftMetadataCloneIsolation(t *testing.T) {
	root := &tree.Node{Kind: tree.ElementNode, Name: tree.Name{Local: "r"}, Attrs: []tree.Attribute{
		{Name: tree.Name{Local: "id"}, Value: "a"},
		{Name: tree.Name{Local: "ref"}, Value: "a"},
		{Name: tree.Name{Local: "refs"}, Value: "a b"},
	}}
	source := tree.FromNodes([]*tree.Node{root}, tree.DefaultLimits())
	const base = "https://example.test/source.xml"
	tree.SetNodeBase(source, root, base)
	kinds := []tree.DTDAttributeType{tree.DTDID, tree.DTDIDRef, tree.DTDIDRefs}
	for i, attribute := range root.Attrs {
		tree.SetAttributeDTDType(source, root, attribute.Name, kinds[i])
	}

	copied, err := tree.Clone(t.Context(), source)
	if err != nil {
		t.Fatal(err)
	}
	clonedRoot := tree.Root(copied)
	if clonedRoot == root || tree.NodeBase(copied, clonedRoot) != base || tree.NodeBase(copied, root) != "" {
		t.Fatal("clone did not retain metadata on its own node")
	}
	for i, attribute := range clonedRoot.Attrs {
		if tree.AttributeDTDType(copied, clonedRoot, attribute.Name) != kinds[i] {
			t.Fatal("clone lost DTD classification", attribute.Name)
		}
		tree.SetAttributeDTDType(copied, clonedRoot, attribute.Name, tree.DTDNoType)
		if tree.AttributeDTDType(copied, clonedRoot, attribute.Name) != tree.DTDNoType || tree.AttributeDTDType(source, root, attribute.Name) != kinds[i] {
			t.Fatal("removing cloned DTD classification changed the source", attribute.Name)
		}
	}
	tree.SetNodeBase(copied, clonedRoot, "https://example.test/changed.xml")
	if tree.NodeBase(copied, clonedRoot) != "https://example.test/changed.xml" || tree.NodeBase(source, root) != base {
		t.Fatal("changing cloned retrieval metadata changed the source")
	}
	tree.SetNodeBase(copied, clonedRoot, "")
	if tree.NodeBase(copied, clonedRoot) != "" || tree.NodeBase(source, root) != base {
		t.Fatal("removing cloned retrieval metadata changed the source")
	}
}
