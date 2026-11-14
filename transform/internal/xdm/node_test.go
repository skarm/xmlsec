package xdm_test

import (
	"context"
	"errors"
	"testing"

	"github.com/skarm/xmlsec/transform/internal/xdm"
)

func TestNodeNamesRespectLanguageBoundariesAndLexicalNamespaceDeclarations(t *testing.T) {
	t.Parallel()

	d := parseNodeDocument(t, `<r xml:lang="EN-us" xmlns:p="urn:old"><child xmlns:p="urn:new" xmlns:q="urn:q"><leaf/></child><override xml:lang="fr"><leaf/></override><empty xml:lang=""><leaf/></empty></r>`)
	r := d.DocumentElement()
	child := r.FirstChild().(*xdm.Element)
	leaf := child.FirstChild()
	for _, tc := range []struct {
		node           xdm.Node
		lang           string
		matched, found bool
	}{
		{leaf, "en", true, true},
		{leaf, "en-us", true, true},
		{leaf, "e", false, true},
		{leaf, "en-usa", false, true},
		{child.NextSibling().FirstChild(), "en", false, true},
		{child.NextSibling().FirstChild(), "fr", true, true},
		{r.LastChild().FirstChild(), "en", false, true},
		{r.LastChild().FirstChild(), "", true, true},
		{d, "en", false, false},
		{nil, "en", false, false},
	} {
		if matched, found := xdm.XMLLangMatches(tc.node, tc.lang); matched != tc.matched || found != tc.found {
			t.Fatal("xml:lang inheritance or sublanguage boundary changed", tc.lang, matched, found)
		}
	}
	if uri, ok := xdm.LookupNSPrefixURI(leaf, "p"); !ok || uri != "urn:new" {
		t.Fatal("nearest lexical declaration did not win", uri, ok)
	}
	if _, ok := xdm.LookupNSPrefixURI(leaf, "xml"); ok {
		t.Fatal("lexical-only namespace lookup synthesized xml")
	}
	if ns := xdm.LookupNSByPrefix(leaf, "xml"); ns == nil || ns.URI() != "http://www.w3.org/XML/1998/namespace" {
		t.Fatal("implicit xml binding lost")
	}
	if ns, ok := xdm.LookupNSURI(leaf, "urn:q"); !ok || ns.Prefix() != "q" {
		t.Fatal("namespace URI ancestor lookup failed", ns, ok)
	}
	if ns := xdm.LookupNSByHref(leaf, "urn:old"); ns == nil || ns.Prefix() != "p" {
		t.Fatal("lexical declaration search lost an ancestor declaration")
	}
	if ns, ok := xdm.LookupNSURI(nil, "absent"); ok || ns != nil {
		t.Fatal("nil namespace search produced binding")
	}
	bindings := xdm.InScopeNamespaces(child, true)
	if len(bindings) != 2 || bindings["p"].URI() != "urn:new" || bindings["q"].URI() != "urn:q" {
		t.Fatal("in-scope declaration override changed", bindings)
	}
	for _, index := range []int{-1, len(child.Namespaces())} {
		if ns, ok := xdm.NamespaceDeclarationAt(child, index); ok || ns != nil {
			t.Fatal("out-of-range namespace declaration accepted", index)
		}
	}
	for _, tc := range []struct {
		input, prefix, local string
		colon, valid         bool
	}{
		{" \t p:имя\r\n", "p", "имя", true, true},
		{"名", "", "名", false, true},
		{":name", "", "name", true, true},
		{"p:", "p", "", true, false},
		{"a:b:c", "a", "b:c", true, false},
		{"a b", "", "a b", false, false},
		{"\u00a0name", "", "\u00a0name", false, false},
	} {
		prefix, local, colon, valid := xdm.SplitLexicalQName(tc.input)
		if prefix != tc.prefix || local != tc.local || colon != tc.colon || valid != tc.valid {
			t.Fatal("QName splitting lost XML whitespace or caller-visible colon information", tc.input, prefix, local, colon, valid)
		}
	}
}

func TestNodePublicationAndReferenceRoundTripPreserveIdentity(t *testing.T) {
	t.Parallel()

	d := xdm.NewDefaultDocument()
	first, second, unanchored := d.CreateText("one"), d.CreateText("two"), d.CreateText("unanchored")
	xdm.PublishNode(nil)
	xdm.PublishNode(first)
	xdm.PublishNode(first)
	xdm.PublishNode(second)
	assertNodeChildren(t, d, first, second)
	if xdm.StringValue(d) != "onetwo" {
		t.Fatal("publication merged or changed adjacent sequence text")
	}
	d.Freeze()
	xdm.PublishNode(unanchored)
	if unanchored.Parent() != nil {
		t.Fatal("publication changed a frozen snapshot")
	}
	doc := parseNodeDocument(t, `<r xmlns:p="urn:p" p:a="v"><child/></r>`)
	other := parseNodeDocument(t, `<other/>`)
	r := doc.DocumentElement()
	ns := xdm.NewNamespaceNodeWrapper(xdm.NewNamespace("p", "urn:p"), r)
	for _, n := range []xdm.Node{doc, r, r.FirstChild(), r.GetAttributeNodeNS("a", "urn:p"), ns} {
		ref := n.Reference()
		view := doc.NodeView(ref)
		if !ref.Valid() || ref.Document() != doc.Snapshot() || !xdm.SameNode(view, n) || other.NodeView(ref) != nil {
			t.Fatal("reference round trip lost identity or admitted a foreign tree", n.Type())
		}
	}
	if xdm.NewNamespaceNodeWrapper(xdm.NewNamespace("p", "urn:p"), nil).Reference().Valid() {
		t.Fatal("detached namespace acquired a storage reference")
	}
	shared, err := xdm.FromDocument(t.Context(), doc.Snapshot())
	requireNodeSuccess(t, err)
	again, err := xdm.FromDocument(t.Context(), doc.Snapshot())
	requireNodeSuccess(t, err)
	if shared != again || shared.Snapshot() != doc.Snapshot() {
		t.Fatal("shared view import changed document identity")
	}
	if err := shared.DocumentElement().AppendText("changed"); err == nil {
		t.Fatal("shared snapshot view remained mutable")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if got, err := xdm.FromDocument(ctx, doc.Snapshot()); got != nil || !errors.Is(err, context.Canceled) {
		t.Fatal("cached view bypassed cancellation", got, err)
	}
}
