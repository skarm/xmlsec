package xdm_test

import (
	"context"
	"errors"
	"slices"
	"testing"

	"github.com/skarm/xmlsec/transform/internal/xdm"
)

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
