package main

import (
	"testing"

	"github.com/skarm/xmlsec/document"
)

func TestRun(t *testing.T) {
	if err := run(); err != nil {
		t.Fatal(err)
	}
}

func TestSubtreeWithoutComments(t *testing.T) {
	const input = `<Envelope><Payload code="42">one<!--remove--><Child>two<!--also remove--></Child></Payload><Sibling/></Envelope>`
	doc, err := document.Parse(t.Context(), []byte(input), document.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	payload, sibling := doc.Root().Children()[0], doc.Root().Children()[1]
	content := payload.Node().Children()
	childContent := content[2].Children()
	nodes, err := subtreeWithoutComments(t.Context(), payload)
	if err != nil {
		t.Fatalf("select subtree: %v", err)
	}
	for _, tc := range []struct {
		name string
		node document.Node
		want bool
	}{
		{name: "payload", node: payload.Node(), want: true},
		{name: "attribute", node: payload.AttributeNodes()[0], want: true},
		{name: "text", node: content[0], want: true},
		{name: "direct_comment", node: content[1]},
		{name: "child", node: content[2], want: true},
		{name: "nested_text", node: childContent[0], want: true},
		{name: "nested_comment", node: childContent[1]},
		{name: "parent", node: doc.Root().Node()},
		{name: "sibling", node: sibling.Node()},
	} {
		if got := nodes.Contains(tc.node); got != tc.want {
			t.Errorf("subtree contains %s = %t, want %t", tc.name, got, tc.want)
		}
	}
}
