package xdm_test

import (
	"testing"

	"github.com/skarm/xmlsec/transform/internal/xdm"
)

func TestNilNodeTypes(t *testing.T) {
	t.Parallel()

	for _, node := range []xdm.Node{
		nil,
		(*xdm.Document)(nil),
		(*xdm.Element)(nil),
		(*xdm.Text)(nil),
		(*xdm.CDATASection)(nil),
		(*xdm.Comment)(nil),
		(*xdm.ProcessingInstruction)(nil),
		(*xdm.Attribute)(nil),
		(*xdm.NamespaceNodeWrapper)(nil),
		(*embeddedNode)(nil),
	} {
		if !xdm.IsNilNode(node) {
			t.Fatalf("nil node %T was accepted", node)
		}

		if result, ok := xdm.AsNode[xdm.Node](node); ok || result != nil {
			t.Fatalf("nil node assertion %T returned %v, %t", node, result, ok)
		}

		if result, ok := xdm.AsNode[*xdm.CDATASection](node); ok || result != nil {
			t.Fatalf("nil CDATA assertion %T returned %v, %t", node, result, ok)
		}
	}
}

func TestNonNilNodeTypes(t *testing.T) {
	t.Parallel()

	doc, err := (xdm.ParseOptions{}).Parse(t.Context(), []byte(`<r a="v">text<!--c--><?p data?></r>`))
	if err != nil {
		t.Fatal(err)
	}

	element := doc.DocumentElement()
	nodes := []xdm.Node{doc, element, element.GetAttributeNodeNS("a", ""), doc.CreateCDATASection("data"), xdm.NewNamespaceNodeWrapper(xdm.NewNamespace("p", "urn:p"), element)}

	nodes = append(nodes, embeddedNode{Node: element}, &embeddedNode{Node: element})
	for node := range xdm.Children(element) {
		nodes = append(nodes, node)
	}

	for _, node := range nodes {
		if xdm.IsNilNode(node) {
			t.Fatalf("non-nil node %T was rejected", node)
		}

		if result, ok := xdm.AsNode[xdm.Node](node); !ok || result != node {
			t.Fatalf("node assertion %T lost identity", node)
		}
	}
}

type embeddedNode struct{ xdm.Node }
