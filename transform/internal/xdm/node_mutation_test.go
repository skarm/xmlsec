package xdm_test

import (
	"errors"
	"slices"
	"testing"

	"github.com/skarm/xmlsec/internal/tree"
	"github.com/skarm/xmlsec/transform/internal/xdm"
)

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
