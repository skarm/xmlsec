package xdm_test

import (
	"errors"
	"slices"
	"testing"

	"github.com/skarm/xmlsec/transform/internal/xdm"
)

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
