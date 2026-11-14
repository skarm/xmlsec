package xdm_test

import (
	"context"
	"errors"
	"maps"
	"slices"
	"testing"

	"github.com/skarm/xmlsec/transform/internal/xdm"
)

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
