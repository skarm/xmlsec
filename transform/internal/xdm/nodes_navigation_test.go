package xdm_test

import (
	"context"
	"errors"
	"maps"
	"slices"
	"testing"

	"github.com/skarm/xmlsec/transform/internal/xdm"
)

func parseNodeDocument(t *testing.T, source string) *xdm.Document {
	t.Helper()
	d, err := (xdm.ParseOptions{}).Parse(t.Context(), []byte(source))
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func assertAxisNodes(t *testing.T, axis xdm.AxisType, from xdm.Node, want ...xdm.Node) {
	t.Helper()
	got, err := xdm.TraverseAxis(t.Context(), axis, from, 100)
	if err != nil || !slices.Equal(got, want) {
		t.Fatalf("%s from %T: %v,%v; want %v", axis, from, got, err, want)
	}
}

func TestNodeAxesPreserveForwardAndReverseOrder(t *testing.T) {
	t.Parallel()

	d := parseNodeDocument(t, `<r><a><x/><y/></a>text<!--comment--><b flag="v"><z/></b><?probe data?><c/></r>`)
	r := d.DocumentElement()
	a := r.FirstChild()
	x := a.FirstChild()
	y := a.LastChild()
	text := a.NextSibling()
	comment := text.NextSibling()
	b := comment.NextSibling()
	z := b.FirstChild()
	pi := b.NextSibling()
	c := r.LastChild()
	d.Freeze() // The parallel axis cases only read this shared snapshot.
	for _, tc := range []struct {
		axis xdm.AxisType
		from xdm.Node
		want []xdm.Node
	}{
		{xdm.AxisChild, r, []xdm.Node{a, text, comment, b, pi, c}},
		{xdm.AxisDescendant, r, []xdm.Node{a, x, y, text, comment, b, z, pi, c}},
		{xdm.AxisDescendantOrSelf, b, []xdm.Node{b, z}},
		{xdm.AxisParent, b, []xdm.Node{r}},
		{xdm.AxisAncestor, z, []xdm.Node{b, r, d}},
		{xdm.AxisAncestorOrSelf, z, []xdm.Node{z, b, r, d}},
		{xdm.AxisFollowingSibling, a, []xdm.Node{text, comment, b, pi, c}},
		{xdm.AxisPrecedingSibling, b, []xdm.Node{comment, text, a}},
		{xdm.AxisFollowing, b, []xdm.Node{pi, c}},
		{xdm.AxisFollowing, x, []xdm.Node{y, text, comment, b, z, pi, c}},
		{xdm.AxisPreceding, b, []xdm.Node{comment, text, y, x, a}},
		{xdm.AxisPreceding, z, []xdm.Node{comment, text, y, x, a}},
		{xdm.AxisSelf, b, []xdm.Node{b}},
		{xdm.AxisAttribute, b, []xdm.Node{b.(*xdm.Element).GetAttributeNodeNS("flag", "")}},
		{xdm.AxisParent, d, nil},
		{xdm.AxisAttribute, text, nil},
		{xdm.AxisNamespace, text, nil},
		{xdm.AxisType(99), r, nil},
	} {
		t.Run(tc.axis.String()+"/"+tc.from.Name(), func(t *testing.T) {
			t.Parallel()
			assertAxisNodes(t, tc.axis, tc.from, tc.want...)
		})
	}
}

func TestNodeAxesAttributesAndNamespacesHaveNoSiblingOrChildAxes(t *testing.T) {
	t.Parallel()

	d := parseNodeDocument(t, `<r><before><leaf/></before><item xmlns:p="urn:p" a="v"><child/></item><after/></r>`)
	r := d.DocumentElement()
	before := r.FirstChild()
	item := before.NextSibling().(*xdm.Element)
	after := item.NextSibling()
	child := item.FirstChild()
	attribute := item.GetAttributeNodeNS("a", "")
	namespace := xdm.NewNamespaceNodeWrapper(xdm.NewNamespace("p", "urn:p"), item)
	for _, from := range []xdm.Node{attribute, namespace} {
		for _, axis := range []xdm.AxisType{xdm.AxisChild, xdm.AxisDescendant, xdm.AxisFollowingSibling, xdm.AxisPrecedingSibling} {
			assertAxisNodes(t, axis, from)
		}
		assertAxisNodes(t, xdm.AxisParent, from, item)
		assertAxisNodes(t, xdm.AxisAncestor, from, item, r, d)
		assertAxisNodes(t, xdm.AxisFollowing, from, child, after)
		assertAxisNodes(t, xdm.AxisPreceding, from, before.FirstChild(), before)
		assertAxisNodes(t, xdm.AxisDescendantOrSelf, from, from)
	}
	for _, from := range []xdm.Node{nil, (*xdm.Element)(nil), (*xdm.Attribute)(nil)} {
		assertAxisNodes(t, xdm.AxisDescendant, from)
		prefix := []xdm.Node{r}
		got, err := xdm.AppendAxis(t.Context(), prefix, xdm.AxisDescendant, from, 0)
		if err != nil || !slices.Equal(got, prefix) {
			t.Fatal("nil context node changed destination", got, err)
		}
	}
	detached := xdm.NewNamespaceNodeWrapper(xdm.NewNamespace("p", "urn:p"), nil)
	assertAxisNodes(t, xdm.AxisFollowing, detached)
	assertAxisNodes(t, xdm.AxisPreceding, detached)
}

func TestNodeAxesNamespaceShadowingUndeclarationAndIdentity(t *testing.T) {
	t.Parallel()

	d := parseNodeDocument(t, `<r xmlns="urn:default" xmlns:p="urn:old" xmlns:q="urn:kept"><child xmlns="" xmlns:p="urn:new"><leaf/></child></r>`)
	r := d.DocumentElement()
	child := r.FirstChild().(*xdm.Element)
	first, err := xdm.TraverseAxis(t.Context(), xdm.AxisNamespace, child, 100)
	requireNodeSuccess(t, err)
	second, err := xdm.TraverseAxis(t.Context(), xdm.AxisNamespace, child, 100)
	requireNodeSuccess(t, err)
	bindings := map[string]string{}
	for _, n := range first {
		if n.Parent() != child || n.OwnerDocument() != d {
			t.Fatal("namespace axis lost logical ownership")
		}
		if _, duplicate := bindings[n.Name()]; duplicate {
			t.Fatal("namespace prefix emitted twice", n.Name())
		}
		bindings[n.Name()] = xdm.StringValue(n)
		found := false
		for _, other := range second {
			if xdm.SameNode(n, other) {
				found = true
			}
		}
		if !found {
			t.Fatal("repeated namespace traversal lost XDM identity", n.Name())
		}
	}
	if !maps.Equal(bindings, map[string]string{"xml": "http://www.w3.org/XML/1998/namespace", "p": "urn:new", "q": "urn:kept"}) {
		t.Fatal("namespace shadowing/default undeclaration lost", bindings)
	}
	a := xdm.NewNamespaceNodeWrapper(xdm.NewNamespace("p", "urn:new"), child)
	equivalent := xdm.NewNamespaceNodeWrapper(xdm.NewNamespace("p", "urn:new"), child)
	b := xdm.NewNamespaceNodeWrapper(xdm.NewNamespace("p", "urn:old"), r)
	x := xdm.NewNamespaceNodeWrapper(xdm.NewNamespace("p", "urn:new"), nil)
	y := xdm.NewNamespaceNodeWrapper(xdm.NewNamespace("p", "urn:new"), nil)
	if !xdm.SameNode(a, equivalent) || xdm.SameNode(a, b) || xdm.SameNode(x, y) || !xdm.SameNode(x, x) || xdm.SameNode(a, nil) {
		t.Fatal("namespace identity collapsed distinct owners or detached roots")
	}
}

type cancelAfterErrChecks struct {
	context.Context
	cancel    context.CancelFunc
	checks    int
	remaining int
}

func (c *cancelAfterErrChecks) Err() error {
	c.checks++
	c.remaining--
	if c.remaining == 0 {
		c.cancel()
	}
	return c.Context.Err()
}

func TestNodeAxesLimitsAppendBudgetAndCancellation(t *testing.T) {
	t.Parallel()

	d := parseNodeDocument(t, `<r><a><x/><y/></a><b/><c/></r>`)
	r := d.DocumentElement()
	a := r.FirstChild()
	x := a.FirstChild()
	y := a.LastChild()
	b := a.NextSibling()
	c := r.LastChild()
	for _, tc := range []struct {
		axis xdm.AxisType
		from xdm.Node
		want []xdm.Node
	}{
		{xdm.AxisDescendant, r, []xdm.Node{a, x, y, b, c}},
		{xdm.AxisDescendantOrSelf, a, []xdm.Node{a, x, y}},
		{xdm.AxisFollowing, x, []xdm.Node{y, b, c}},
		{xdm.AxisPreceding, c, []xdm.Node{b, y, x, a}},
	} {
		got, err := xdm.TraverseAxis(t.Context(), tc.axis, tc.from, len(tc.want))
		if err != nil || !slices.Equal(got, tc.want) {
			t.Fatal("exact axis limit rejected", tc.axis, got, err)
		}
		if got, err := xdm.TraverseAxis(t.Context(), tc.axis, tc.from, len(tc.want)-1); got != nil || !errors.Is(err, xdm.ErrNodeSetLimit) {
			t.Fatal("axis limit exceeded without atomic error", tc.axis, got, err)
		}
		ctx, cancel := context.WithCancel(t.Context())
		mid := &cancelAfterErrChecks{Context: ctx, cancel: cancel, remaining: 3}
		got, err = xdm.TraverseAxis(mid, tc.axis, tc.from, 100)
		cancel()
		if got != nil || !errors.Is(err, context.Canceled) || mid.checks < 3 {
			t.Fatal("mid-traversal cancellation published a partial result", tc.axis, got, err, mid.checks)
		}
	}
	for _, limit := range []int{2, int(^uint(0) >> 1)} {
		got, err := xdm.AppendAxis(t.Context(), []xdm.Node{r, b}, xdm.AxisDescendant, a, limit)
		if err != nil || !slices.Equal(got, []xdm.Node{r, b, x, y}) {
			t.Fatal("existing destination consumed traversal budget or addition overflowed", got, err)
		}
	}
	if got, err := xdm.AppendAxis(t.Context(), []xdm.Node{r}, xdm.AxisDescendant, a, 1); got != nil || !errors.Is(err, xdm.ErrNodeSetLimit) {
		t.Fatal("append returned a partial traversal", got, err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	for _, axis := range []xdm.AxisType{xdm.AxisChild, xdm.AxisNamespace, xdm.AxisSelf, xdm.AxisDescendant, xdm.AxisFollowing, xdm.AxisPreceding} {
		if got, err := xdm.TraverseAxis(ctx, axis, r, 100); got != nil || !errors.Is(err, context.Canceled) {
			t.Fatal("cancelled traversal accepted", axis, got, err)
		}
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

func TestNodeIDSearchReportsDuplicatesAndHonorsOnlyDeclaredHeuristics(t *testing.T) {
	t.Parallel()

	d := parseNodeDocument(t, `<r Id="duplicate" ID="duplicate" id="alternate" xmlns:p="urn:p"><a xml:id=" duplicate "/><b ID="duplicate"/><c p:Id="hidden" AssertionID="hidden" iD="hidden"/><typed token="typed"/><refs token="not-id"/></r>`)
	r := d.DocumentElement()
	a := r.FirstChild().(*xdm.Element)
	b := a.NextSibling().(*xdm.Element)
	c := b.NextSibling().(*xdm.Element)
	typed := c.NextSibling().(*xdm.Element)
	refs := typed.NextSibling().(*xdm.Element)
	typed.GetAttributeNodeNS("token", "").SetIDType(xdm.IDAttribute)
	refs.GetAttributeNodeNS("token", "").SetIDType(xdm.IDRefsAttribute)
	want := map[string][]*xdm.Element{"duplicate": {r, a, b}, "alternate": {r}, "typed": {typed}}
	index, err := xdm.BuildIDIndex(t.Context(), r)
	requireNodeSuccess(t, err)
	if len(index) != len(want) {
		t.Fatal("ID index broadened the fixed name/type rule", index)
	}
	for id, elements := range want {
		if !slices.Equal(index[id], elements) || !slices.Equal(xdm.FindElementsByID(r, id), elements) {
			t.Fatal("ID search hid duplicates, a second ID, or document order", id, index[id])
		}
	}
	for _, id := range []string{"hidden", "not-id", "absent"} {
		if got := xdm.FindElementsByID(r, id); len(got) != 0 {
			t.Fatal("non-ID convention was guessed", id, got)
		}
	}
	if got := xdm.FindElementsByID(a, "duplicate"); !slices.Equal(got, []*xdm.Element{a}) {
		t.Fatal("subtree search escaped its root", got)
	}
	for _, root := range []xdm.Node{nil, (*xdm.Element)(nil), r.GetAttributeNodeNS("Id", "")} {
		index, err := xdm.BuildIDIndex(nil, root)
		if err != nil || len(index) != 0 || len(xdm.FindElementsByID(root, "duplicate")) != 0 {
			t.Fatal("empty root produced an ID", index, err)
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	mid := &cancelAfterErrChecks{Context: ctx, cancel: cancel, remaining: 3}
	index, err = xdm.BuildIDIndex(mid, r)
	cancel()
	if index != nil || !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled ID walk returned a partial index", index, err)
	}
}

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
