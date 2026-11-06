package tree_test

import (
	"slices"
	"testing"

	"github.com/skarm/xmlsec/internal/tree"
)

func TestParserOwnsReusedAttributeTokens(t *testing.T) {
	t.Parallel()
	doc, err := tree.Parse(t.Context(), []byte(`<r xmlns:p="urn:outer" marker="root"><p:a p:first="1" b="2" c="3"/><n only="4"/><plain/><p:b xmlns:p="urn:inner" p:second="5" other="6"/><tail marker="last"/></r>`), tree.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	root := tree.Root(doc)
	want := [][]tree.Attribute{
		{{Name: tree.Name{Local: "marker"}, Value: "root"}},
		{{Name: tree.Name{Space: "urn:outer", Local: "first"}, Prefix: "p", Value: "1"}, {Name: tree.Name{Local: "b"}, Value: "2"}, {Name: tree.Name{Local: "c"}, Value: "3"}},
		{{Name: tree.Name{Local: "only"}, Value: "4"}},
		{},
		{{Name: tree.Name{Space: "urn:inner", Local: "second"}, Prefix: "p", Value: "5"}, {Name: tree.Name{Local: "other"}, Value: "6"}},
		{{Name: tree.Name{Local: "marker"}, Value: "last"}},
	}
	nodes := append([]*tree.Node{root}, root.Children...)
	if len(nodes) != len(want) {
		t.Fatal("self-closing elements changed", len(nodes))
	}
	for i, node := range nodes {
		if !slices.Equal(node.Attrs, want[i]) {
			t.Fatalf("node %d attributes overwritten: got %+v; want %+v", i, node.Attrs, want[i])
		}
	}
	if root.Children[0].Name.Space != "urn:outer" || root.Children[3].Name.Space != "urn:inner" || root.NS[0].URI != "urn:outer" {
		t.Fatal("namespace token storage escaped into another element")
	}
}

func TestParserOwnsReusedContentTokens(t *testing.T) {
	t.Parallel()
	doc, err := tree.Parse(t.Context(), []byte(`<r>first<!--one--><?p x?><a>inner</a>last<![CDATA[ tail]]><!--two--><?q y?></r>`), tree.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	want := []struct {
		kind tree.Kind
		name string
		data string
	}{
		{tree.TextNode, "", "first"},
		{tree.CommentNode, "", "one"},
		{tree.PINode, "p", "x"},
		{tree.ElementNode, "a", ""},
		{tree.TextNode, "", "last tail"},
		{tree.CommentNode, "", "two"},
		{tree.PINode, "q", "y"},
	}
	nodes := tree.Root(doc).Children
	if len(nodes) != len(want) {
		t.Fatal("token kinds or text coalescing changed", len(nodes))
	}
	for i, node := range nodes {
		if node.Kind != want[i].kind || node.Name.Local != want[i].name || node.Data != want[i].data {
			t.Fatalf("node %d changed after token reuse: %+v", i, node)
		}
	}
	if got := nodes[3].Children; len(got) != 1 || got[0].Data != "inner" {
		t.Fatal("child text changed after the next character token")
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

func TestCopyUnparsedEntitiesDraft(t *testing.T) {
	const base = "https://example.test/source.xml"
	source, err := (tree.ParseOptions{Limits: tree.DefaultLimits(), AllowDTD: true, BaseURI: base}).ParseText(t.Context(),
		`<!DOCTYPE r [<!NOTATION bin SYSTEM "urn:bin"><!ENTITY image SYSTEM "image.bin" NDATA bin>]><r/>`)
	if err != nil {
		t.Fatal(err)
	}
	root := &tree.Node{Kind: tree.ElementNode, Name: tree.Name{Local: "target"}}
	destination := tree.FromNodes([]*tree.Node{root}, tree.DefaultLimits())
	if _, found := tree.LookupUnparsedEntity(destination, "image"); found {
		t.Fatal("empty draft has an unparsed entity")
	}
	tree.CopyUnparsedEntities(destination, source)
	entity, found := tree.LookupUnparsedEntity(destination, "image")
	if !found || entity.SystemID != "image.bin" || entity.BaseURI != base || tree.Root(destination) != root {
		t.Fatal("copy lost declaration metadata or replaced the target tree", entity, found)
	}
	if _, found := tree.LookupUnparsedEntity(destination, "missing"); found {
		t.Fatal("lookup invented an unparsed entity")
	}
	empty := tree.FromNodes(nil, tree.DefaultLimits())
	tree.CopyUnparsedEntities(destination, empty)
	if _, found := tree.LookupUnparsedEntity(destination, "image"); found {
		t.Fatal("replacement retained old declaration metadata")
	}
	if original, found := tree.LookupUnparsedEntity(source, "image"); !found || original != entity {
		t.Fatal("replacing destination metadata changed the source", original, found)
	}
}
