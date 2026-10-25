package tree_test

import (
	"testing"

	"github.com/skarm/xmlsec/internal/tree"
)

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
