package tree_test

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	treepkg "github.com/skarm/xmlsec/internal/tree"
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

	limits := treepkg.DefaultLimits()

	source, err := treepkg.Parse(t.Context(), []byte(sourceXML), limits)
	if err != nil {
		t.Fatal(err)
	}

	host, err := treepkg.Parse(t.Context(), []byte(`<?before?><host xmlns="urn:host" xmlns:p="urn:conflict"><before/><slot/><after/></host><!--after-->`), limits)
	if err != nil {
		t.Fatal(err)
	}

	originalSource, originalHost := treeXML(t, source), treeXML(t, host)
	selected := treepkg.Root(source).Children[0]

	imported := treepkg.ImportSubtree(selected)
	if imported == selected || imported.Parent != nil || selected.Parent != treepkg.Root(source) {
		t.Fatal("import changed source ownership")
	}

	draft, err := treepkg.ReplaceDraft(t.Context(), host, treepkg.Root(host).Children[1], imported)
	if err != nil {
		t.Fatal(err)
	}

	result, err := treepkg.Reparse(t.Context(), draft, limits)
	if err != nil {
		t.Fatal(err)
	}

	got := treepkg.Root(result).Children[1]

	var before, after bytes.Buffer
	if err := treepkg.Canonical(t.Context(), &before, source, selected, nil, treepkg.CanonicalOptions{}); err != nil {
		t.Fatal(err)
	}

	if err := treepkg.Canonical(t.Context(), &after, result, got, nil, treepkg.CanonicalOptions{}); err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(before.Bytes(), after.Bytes()) {
		t.Fatalf("imported expanded names/attributes/content changed: %q != %q", after.Bytes(), before.Bytes())
	}

	for _, binding := range treepkg.Wrap(source, selected).NamespaceNodes() {
		actual, ok := treepkg.Wrap(result, got).Namespace(binding.Name().Local)
		if !ok || actual != binding.Value() {
			t.Fatalf("source QName context changed for %s: %q != %q", binding.Name().Local, actual, binding.Value())
		}
	}

	if treeXML(t, source) != originalSource || treeXML(t, host) != originalHost {
		t.Fatal("import or reparse modified an input snapshot")
	}
}

func treeXML(t testing.TB, doc *treepkg.Document) string {
	t.Helper()

	raw, err := doc.XML(t.Context())
	if err != nil {
		t.Fatal(err)
	}

	return string(raw)
}

func TestFragmentUsesSemanticLimits(t *testing.T) {
	limits := treepkg.DefaultLimits()
	limits.MaxBytes = 1
	limits.MaxNodes = 1
	limits.MaxDepth = 1

	d, err := treepkg.ParseFragment(context.Background(), []byte("a"), limits)
	if err != nil || len(treepkg.Children(d)) != 1 || treepkg.Children(d)[0].Data != "a" {
		t.Fatal(d, err)
	}

	if _, err := treepkg.ParseFragment(context.Background(), []byte("ab"), limits); !errors.Is(err, treepkg.ErrLimit) {
		t.Fatal("fragment bytes were not bounded", err)
	}

	limits = treepkg.DefaultLimits()
	limits.MaxDepth = 512
	limits.MaxNodes = 512

	data := []byte(strings.Repeat("<n>", 512) + strings.Repeat("</n>", 512))
	if _, err := treepkg.ParseFragment(context.Background(), data, limits); err != nil {
		t.Fatal("synthetic root consumed a depth/node slot", err)
	}

	for _, xml := range []string{`<!DOCTYPE r [<!ENTITY x "x">]><r>&x;</r>`, `<p:r/>`, `<r a="1" a="2"/>`} {
		if _, err := treepkg.ParseFragment(context.Background(), []byte(xml), treepkg.DefaultLimits()); err == nil {
			t.Error("invalid fragment accepted", xml)
		}
	}
}
