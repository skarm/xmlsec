package tree_test

import (
	"bytes"
	"testing"

	"github.com/skarm/xmlsec/internal/tree"
)

func TestImportSubtreeKeepsNamespaceContextAndSnapshots(t *testing.T) {
	for _, sourceXML := range []string{
		`<parent><item plain="v"><child/></item></parent>`,
		`<parent xmlns="urn:source" xmlns:p="urn:payload"><p:item xml:id="item" xml:lang="ru" xml:space="preserve" xml:base="relative/"><child xmlns="" p:a="v"/></p:item></parent>`,
		`<parent xmlns="urn:source" xmlns:p="urn:qname"><item type="p:kind"><child xmlns=""><p:leaf/></child></item></parent>`,
	} {
		t.Run(sourceXML, func(t *testing.T) { checkImportedNamespaceContext(t, sourceXML) })
	}
}

func checkImportedNamespaceContext(t *testing.T, sourceXML string) {
	t.Helper()

	limits := tree.DefaultLimits()

	source, err := tree.Parse(t.Context(), []byte(sourceXML), limits)
	if err != nil {
		t.Fatal(err)
	}

	host, err := tree.Parse(t.Context(), []byte(`<?before?><host xmlns="urn:host" xmlns:p="urn:conflict"><before/><slot/><after/></host><!--after-->`), limits)
	if err != nil {
		t.Fatal(err)
	}

	originalSource, originalHost := treeXML(t, source), treeXML(t, host)
	selected := tree.Root(source).Children[0]

	imported := tree.ImportSubtree(selected)
	if imported == selected || imported.Parent != nil || selected.Parent != tree.Root(source) {
		t.Fatal("import changed source ownership")
	}

	draft, err := tree.ReplaceDraft(t.Context(), host, tree.Root(host).Children[1], imported)
	if err != nil {
		t.Fatal(err)
	}

	result, err := tree.Reparse(t.Context(), draft, limits)
	if err != nil {
		t.Fatal(err)
	}

	got := tree.Root(result).Children[1]

	var before, after bytes.Buffer
	if err := tree.Canonical(t.Context(), &before, source, selected, nil, tree.CanonicalOptions{}); err != nil {
		t.Fatal(err)
	}

	if err := tree.Canonical(t.Context(), &after, result, got, nil, tree.CanonicalOptions{}); err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(before.Bytes(), after.Bytes()) {
		t.Fatalf("imported expanded names/attributes/content changed: %q != %q", after.Bytes(), before.Bytes())
	}

	for _, binding := range tree.Wrap(source, selected).NamespaceNodes() {
		actual, ok := tree.Wrap(result, got).Namespace(binding.Name().Local)
		if !ok || actual != binding.Value() {
			t.Fatalf("source QName context changed for %s: %q != %q", binding.Name().Local, actual, binding.Value())
		}
	}

	if treeXML(t, source) != originalSource || treeXML(t, host) != originalHost {
		t.Fatal("import or reparse modified an input snapshot")
	}
}
