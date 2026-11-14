package xdm_test

import (
	"context"
	"errors"
	"slices"
	"testing"

	"github.com/skarm/xmlsec/internal/tree"
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

func TestNodeWalkStopsAtVisitorErrorAndPreservesStringValueRules(t *testing.T) {
	t.Parallel()

	d := parseNodeDocument(t, `<r>one<!--ignored--><child>two</child><?probe ignored?>three</r>`)
	r := d.DocumentElement()
	child := r.FirstChild().NextSibling().NextSibling()
	failure := errors.New("visitor stopped")
	var visited []xdm.Node
	err := xdm.Walk(d, xdm.NodeWalkerFunc(func(n xdm.Node) error {
		visited = append(visited, n)
		if n == child {
			return failure
		}
		return nil
	}))
	if !errors.Is(err, failure) || !slices.Equal(visited, []xdm.Node{d, r, r.FirstChild(), r.FirstChild().NextSibling(), child}) {
		t.Fatal("walk did not stop at first visitor failure", visited, err)
	}
	if xdm.StringValue(r) != "onetwothree" || xdm.StringValue(d) != "onetwothree" || xdm.CharacterData(nil) != "" {
		t.Fatal("element/document string value included comments or PIs")
	}
	if err := xdm.Walk(nil, xdm.NodeWalkerFunc(func(xdm.Node) error { t.Fatal("nil walk invoked visitor"); return nil })); err != nil {
		t.Fatal(err)
	}
	count := 0
	for range xdm.Children(r) {
		count++
		break
	}
	if count != 1 {
		t.Fatal("iterator ignored early stop")
	}
}

//nolint:tparallel // These rejection cases intentionally mutate and inspect the same draft graph in sequence.
func TestNodeDraftRejectsCyclesAndInvalidChildrenWithoutDetaching(t *testing.T) {
	t.Parallel()

	d := xdm.NewDefaultDocument()
	r, a := newDraftElement(t, d, "r"), newDraftElement(t, d, "a")
	requireNodeSuccess(t, d.AddChild(r), r.AddChild(a))
	text := d.CreateText("text")
	attribute, err := d.CreateAttribute("id", "value", nil)
	requireNodeSuccess(t, err)
	// Each rejected operation must leave the same draft intact for the next case.
	for _, tc := range []struct {
		name string
		call func() error
	}{
		{"self cycle", func() error { return r.AddChild(r) }},
		{"ancestor cycle", func() error { return a.AddChild(r) }},
		{"nil child", func() error { return r.AddChild(nil) }},
		{"text parent", func() error { return text.AddChild(a) }},
		{"attribute on document", func() error { return d.AddChild(attribute) }},
		{"ancestor sibling", func() error { return a.AddSibling(r) }},
		{"self sibling", func() error { return a.AddSibling(a) }},
		{"attribute sibling", func() error { return a.AddSibling(attribute) }},
		{"document sibling", func() error { return a.AddSibling(d) }},
		{"detached sibling", func() error { return text.AddSibling(a) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.call(); err == nil {
				t.Fatal("invalid mutation accepted")
			}
			assertNodeChildren(t, d, r)
			assertNodeChildren(t, r, a)
			if text.Parent() != nil || attribute.Parent() != nil {
				t.Fatal("invalid mutation attached a detached node")
			}
		})
	}
	for _, name := range []string{"", "a b", ":name", "p:", "a:b:c"} {
		if got, err := d.CreateElement(name); !errors.Is(err, tree.ErrMalformed) || got != nil {
			t.Fatalf("invalid QName %q accepted: %v,%v", name, got, err)
		}
	}
	if got, err := d.CreateNamespace("bad:prefix", "urn:x"); !errors.Is(err, tree.ErrMalformed) || got != nil {
		t.Fatal("invalid namespace prefix accepted", got, err)
	}
}

func TestNodeDraftLexicalQNamesRejectBeforeAttributeMutation(t *testing.T) {
	t.Parallel()

	d := xdm.NewDefaultDocument()
	r := newDraftElement(t, d, "root")
	requireNodeSuccess(t, d.AddChild(r), r.SetAttribute("code", "original"), r.DeclareNamespace("p", "urn:p"))
	for _, name := range []string{"", ":code", "p:", "a:b:c", "a b", "bad<name", "\xff"} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			d := xdm.NewDefaultDocument()
			r := newDraftElement(t, d, "root")
			requireNodeSuccess(t, d.AddChild(r), r.SetAttribute("code", "original"))
			original := r.GetAttributeNodeNS("code", "")
			if attr, err := d.CreateAttribute(name, "changed", nil); !errors.Is(err, tree.ErrMalformed) || attr != nil {
				t.Errorf("invalid lexical attribute name accepted: %q: %v,%v", name, attr, err)
			}
			if err := r.SetAttribute(name, "changed"); !errors.Is(err, tree.ErrMalformed) {
				t.Errorf("invalid attribute assignment accepted: %q: %v", name, err)
			}
			if r.AttributeCount() != 1 || r.GetAttributeNodeNS("code", "") != original || original.Value() != "original" {
				t.Fatal("invalid assignment altered existing attribute identity/value or inserted an attribute")
			}
			assertNodeChildren(t, d, r)
		})
	}
	for _, name := range []string{"bare", "p:local", "имя", "p:имя", "前:名"} {
		e, err := d.CreateElement(name)
		requireNodeSuccess(t, err)
		if e.Name() != name || e.Parent() != nil {
			t.Fatal("valid QName element changed", name)
		}
		attr, err := d.CreateAttribute(name, "value", nil)
		requireNodeSuccess(t, err)
		if attr.Name() != name || attr.Parent() != nil || attr.Value() != "value" {
			t.Fatal("valid QName attribute changed", name)
		}
		requireNodeSuccess(t, r.SetAttribute(name, "value"))
		if value, found := r.GetAttribute(name); !found || value != "value" {
			t.Fatal("valid QName assignment rejected", name, value, found)
		}
	}
	if value, found := r.GetAttributeNS("local", "urn:p"); !found || value != "value" {
		t.Fatal("QName validation changed namespace resolution", value, found)
	}
}

func TestNodeDraftMovesAdoptsAndReindexesSubtrees(t *testing.T) {
	t.Parallel()

	first, second := xdm.NewDefaultDocument(), xdm.NewDefaultDocument()
	r, a, b := newDraftElement(t, first, "r"), newDraftElement(t, first, "a"), newDraftElement(t, first, "b")
	nested := newDraftElement(t, first, "nested")
	requireNodeSuccess(t, first.AddChild(r), r.AddChild(a), r.AddChild(b), a.AddChild(nested), a.SetAttribute("code", "v"))
	attribute := a.GetAttributeNodeNS("code", "")
	attribute.SetIDType(xdm.IDAttribute)
	target := newDraftElement(t, second, "target")
	requireNodeSuccess(t, second.AddChild(target), target.AddChild(a))
	assertNodeChildren(t, r, b)
	assertNodeChildren(t, target, a)
	if a.OwnerDocument() != second || nested.OwnerDocument() != second || attribute.OwnerDocument() != second || second.GetElementByID("v") != a {
		t.Fatal("adoption lost subtree/attribute ownership or typed ID")
	}
	if a.GetAttributeNodeNS("code", "") != attribute || attribute.Parent() != a {
		t.Fatal("adoption replaced attribute identity")
	}
	requireNodeSuccess(t, target.AddChild(b), a.AddSibling(b))
	assertNodeChildren(t, r)
	assertNodeChildren(t, target, a, b)
	xdm.UnlinkNode(a)
	assertNodeChildren(t, target, b)
	if a.Parent() != nil || a.NextSibling() != nil || a.PrevSibling() != nil || nested.Parent() != a {
		t.Fatal("unlink damaged detached subtree")
	}
	xdm.UnlinkNode(a)
	requireNodeSuccess(t, b.AddSibling(a))
	assertNodeChildren(t, target, b, a)
}

func TestNodeDraftReplacementValidatesAllInputsBeforeMoving(t *testing.T) {
	t.Parallel()

	d := xdm.NewDefaultDocument()
	r, a, b, c := newDraftElement(t, d, "r"), newDraftElement(t, d, "a"), newDraftElement(t, d, "b"), newDraftElement(t, d, "c")
	donor, x := newDraftElement(t, d, "donor"), newDraftElement(t, d, "x")
	requireNodeSuccess(t, d.AddChild(r), r.AddChild(a), r.AddChild(b), r.AddChild(c), donor.AddChild(x))
	attribute, err := d.CreateAttribute("id", "v", nil)
	requireNodeSuccess(t, err)
	for _, replacement := range [][]xdm.Node{nil, {x, nil}, {x, x}, {x, r}, {attribute}, {d}} {
		if err := b.Replace(replacement...); err == nil {
			t.Fatal("invalid replacement accepted")
		}
		assertNodeChildren(t, r, a, b, c)
		assertNodeChildren(t, donor, x)
	}
	requireNodeSuccess(t, b.Replace(x, b))
	assertNodeChildren(t, r, a, x, b, c)
	assertNodeChildren(t, donor)
	requireNodeSuccess(t, b.Replace(a))
	assertNodeChildren(t, r, x, a, c)
	if b.Parent() != nil || b.NextSibling() != nil || b.PrevSibling() != nil {
		t.Fatal("replaced node remained linked")
	}
	if err := b.Replace(c); err == nil {
		t.Fatal("detached replacement target accepted")
	}
}

func TestNodeDraftTextCoalescingAndEditableIteration(t *testing.T) {
	t.Parallel()

	d := xdm.NewDefaultDocument()
	r := newDraftElement(t, d, "r")
	requireNodeSuccess(t, d.AddChild(r), r.AppendText("A"))
	text := r.FirstChild()
	requireNodeSuccess(t, r.AddChild(d.CreateText("B")), text.(xdm.MutableNode).AddSibling(d.CreateText("C")))
	if r.FirstChild() != text || r.LastChild() != text || xdm.StringValue(r) != "ABC" {
		t.Fatal("adjacent text failed to coalesce")
	}
	cd := d.CreateCDATASection("D")
	requireNodeSuccess(t, r.AddChild(cd), cd.AppendText("E"), r.AppendText("F"))
	if xdm.StringValue(r) != "ABCDEF" || cd.Type() != xdm.CDATASectionNode {
		t.Fatal("CDATA identity or concatenated text changed")
	}
	for _, name := range []string{"a", "b", "c"} {
		requireNodeSuccess(t, r.AddChild(newDraftElement(t, d, name)))
	}
	var visited []string
	for child := range xdm.ChildElements(r) {
		visited = append(visited, child.Name())
		xdm.UnlinkNode(child)
	}
	if !slices.Equal(visited, []string{"a", "b", "c"}) {
		t.Fatal("editing while iterating skipped children", visited)
	}
	if got := slices.Collect(xdm.ChildElements(r)); len(got) != 0 {
		t.Fatal("elements remained after unlink", got)
	}
	xdm.FilterChildren(r, func(n xdm.Node) bool { return n == cd })
	assertNodeChildren(t, r, cd)
	if text.Parent() != nil || xdm.StringValue(r) != "DE" {
		t.Fatal("filter retained stale parent or text")
	}
	if got := slices.Collect(xdm.Children(nil)); len(got) != 0 {
		t.Fatal("nil children iterator yielded nodes")
	}
}

func TestNodeDraftFrozenMutationsAndCopyOnAttach(t *testing.T) {
	t.Parallel()

	source := xdm.NewDefaultDocument()
	r, child := newDraftElement(t, source, "r"), newDraftElement(t, source, "child")
	requireNodeSuccess(t, source.AddChild(r), r.AddChild(child), child.SetAttribute("a", "source"), child.DeclareNamespace("p", "urn:source"))
	candidate := xdm.NewDefaultDocument().CreateText("bad")
	source.Freeze()
	for _, operation := range []struct {
		name string
		call func() error
	}{
		{"add child", func() error { return r.AddChild(candidate) }},
		{"add sibling", func() error { return child.AddSibling(candidate) }},
		{"replace", func() error { return child.Replace(child) }},
		{"append text", func() error { return child.AppendText("bad") }},
		{"set attribute", func() error { return child.SetAttribute("a", "changed") }},
		{"declare namespace", func() error { return child.DeclareNamespace("p", "urn:p") }},
	} {
		if err := operation.call(); err == nil {
			t.Fatalf("frozen mutation %q accepted", operation.name)
		}
	}
	assertNodeChildren(t, r, child)
	if value, found := child.GetAttribute("a"); !found || value != "source" {
		t.Fatalf("rejected frozen mutation changed attribute: %q, %v", value, found)
	}
	if namespace := xdm.LookupNSByPrefix(child, "p"); candidate.Parent() != nil || xdm.StringValue(child) != "" || namespace == nil || namespace.URI() != "urn:source" {
		t.Fatal("rejected frozen mutation changed text, namespace or candidate ownership")
	}
	destination := xdm.NewDefaultDocument()
	target := newDraftElement(t, destination, "target")
	requireNodeSuccess(t, destination.AddChild(target), target.AddChild(child))
	copied := target.FirstChild().(*xdm.Element)
	if copied == child || copied.OwnerDocument() != destination || child.Parent() != r {
		t.Fatal("attaching frozen source moved it instead of copying")
	}
	requireNodeSuccess(t, copied.SetAttribute("a", "changed"))
	if value, _ := child.GetAttribute("a"); value != "source" {
		t.Fatal("copy shares source attribute storage")
	}
	for _, operation := range []struct {
		name string
		call func()
	}{
		{"unlink", func() { xdm.UnlinkNode(child) }},
		{"filter children", func() { xdm.FilterChildren(r, func(xdm.Node) bool { return false }) }},
		{"set namespace", func() { child.SetNamespace(nil) }},
		{"remove namespace", func() { child.RemoveNamespaceByPrefix("p") }},
		{"remove attribute", func() { child.RemoveAttribute("a") }},
	} {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("frozen mutation %q did not panic", operation.name)
				}
			}()
			operation.call()
		}()
	}
	assertNodeChildren(t, r, child)
	if value, found := child.GetAttribute("a"); !found || value != "source" {
		t.Fatalf("panicking frozen mutation changed source attribute: %q, %v", value, found)
	}
	if namespace := xdm.LookupNSByPrefix(child, "p"); namespace == nil || namespace.URI() != "urn:source" {
		t.Fatal("panicking frozen mutation changed source namespace")
	}
}

func newDraftElement(t *testing.T, d *xdm.Document, name string) *xdm.Element {
	t.Helper()
	e, err := d.CreateElement(name)
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func requireNodeSuccess(t *testing.T, errs ...error) {
	t.Helper()
	for index, err := range errs {
		if err != nil {
			t.Fatalf("node operation %d failed: %v", index+1, err)
		}
	}
}

func assertNodeChildren(t *testing.T, parent xdm.Node, want ...xdm.Node) {
	t.Helper()
	got := slices.Collect(xdm.Children(parent))
	if !slices.Equal(got, want) {
		t.Fatalf("children of %s=%v; want %v", parent.Name(), got, want)
	}
	for i, child := range got {
		var prev, next xdm.Node
		if i > 0 {
			prev = got[i-1]
		}
		if i+1 < len(got) {
			next = got[i+1]
		}
		if child.Parent() != parent || child.PrevSibling() != prev || child.NextSibling() != next {
			t.Fatalf("child %d has stale parent/sibling links", i)
		}
	}
}
