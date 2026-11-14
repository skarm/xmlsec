package tree_test

import (
	"testing"

	"github.com/skarm/xmlsec/internal/tree"
)

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
