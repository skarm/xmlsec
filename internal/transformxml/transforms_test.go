package transformxml_test

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/skarm/xmlsec/c14n"
	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/internal/transformxml"
	"github.com/skarm/xmlsec/internal/tree"
	"github.com/skarm/xmlsec/reference"
)

func TestXPathParametersAndHereIdentity(t *testing.T) {
	input := []byte(`<ds:Transform xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:p="urn:items" Algorithm="http://www.w3.org/2002/06/xmldsig-filter2"><xf:XPath xmlns:xf="http://www.w3.org/2002/06/xmldsig-filter2" Filter="intersect">//p:<!-- split -->item</xf:XPath></ds:Transform>`)
	doc, err := document.Parse(t.Context(), input, document.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}

	parsed, err := transformxml.Parse(t.Context(), doc, tree.Root(doc))
	if err != nil || parsed.Algorithm != reference.XPathFilter2 || len(parsed.XPath) != 1 {
		t.Fatalf("XPath program: %+v, %v", parsed, err)
	}

	x := parsed.XPath[0]
	if x.Expression != "//p:item" || x.Filter != "intersect" || x.Namespaces["p"] != "urn:items" || x.Namespaces["xml"] != document.XMLNamespace || !x.Here.Same(doc.Root().Children()[0]) {
		t.Fatalf("expression context/identity lost: %+v", x)
	}

	draft := &tree.Node{Kind: tree.ElementNode, Name: document.Name{Space: transformxml.Namespace, Local: "Transform"}, Prefix: "ds", NS: []tree.Namespace{{Prefix: "ds", URI: transformxml.Namespace}}, Attrs: []tree.Attribute{{Name: document.Name{Local: "Algorithm"}, Value: reference.XPathFilter2}}}
	program := reference.Transform{Algorithm: reference.XPathFilter2, XPath: []reference.XPathExpression{{Expression: "//p:item", Filter: "intersect", Namespaces: map[string]string{"p": "urn:items"}}}}
	if err := transformxml.AppendParameters(t.Context(), draft, program); err != nil {
		t.Fatal(err)
	}

	if len(program.XPath[0].Namespaces) != 1 || len(draft.Children) != 1 || draft.Children[0].Parent != draft {
		t.Fatal("parameter append changed caller bindings or lost parent ownership")
	}

	if len(draft.Children[0].NS) != 2 || draft.Children[0].NS[0].Prefix != "p" || draft.Children[0].NS[1].Prefix != "xf" {
		t.Fatal("parameter namespace declarations are not deterministic")
	}

	destination := tree.FromNodes([]*tree.Node{draft}, tree.DefaultLimits())
	roundTrip, err := transformxml.Parse(t.Context(), destination, draft)
	if err != nil || roundTrip.XPath[0].Expression != x.Expression || roundTrip.XPath[0].Filter != x.Filter || roundTrip.XPath[0].Namespaces["p"] != x.Namespaces["p"] {
		t.Fatalf("round trip: %+v, %v", roundTrip, err)
	}
}

func TestCanonicalParametersAndInvalidStructure(t *testing.T) {
	const namespace = `xmlns:ds="http://www.w3.org/2000/09/xmldsig#"`
	for _, tc := range []struct {
		name string
		xml  string
		want error
	}{
		{"exclusive prefixes", `<ds:Transform ` + namespace + ` Algorithm="` + c14n.Exclusive + `"><ec:InclusiveNamespaces xmlns:ec="` + c14n.Exclusive + `" PrefixList="p #default"/></ds:Transform>`, nil},
		{"parameters on inclusive algorithm", `<ds:Transform ` + namespace + ` Algorithm="` + c14n.Canonical10 + `"><x/></ds:Transform>`, reference.ErrInput},
		{"nested prefix element", `<ds:Transform ` + namespace + ` Algorithm="` + c14n.Exclusive + `"><ec:InclusiveNamespaces xmlns:ec="` + c14n.Exclusive + `" PrefixList="p"><x/></ec:InclusiveNamespaces></ds:Transform>`, reference.ErrInput},
		{"invalid inclusive prefix", `<ds:Transform ` + namespace + ` Algorithm="` + c14n.Exclusive + `"><ec:InclusiveNamespaces xmlns:ec="` + c14n.Exclusive + `" PrefixList="xmlns"/></ds:Transform>`, reference.ErrInput},
		{"unexpected attribute", `<ds:Transform ` + namespace + ` Algorithm="` + reference.Base64 + `" extra="x"/>`, reference.ErrInput},
		{"processing instruction", `<ds:Transform ` + namespace + ` Algorithm="` + reference.Base64 + `"><?test x?></ds:Transform>`, reference.ErrInput},
		{"unexpected text", `<ds:Transform ` + namespace + ` Algorithm="` + reference.Base64 + `">x</ds:Transform>`, reference.ErrInput},
		{"wrong XPath namespace", `<ds:Transform ` + namespace + ` Algorithm="` + reference.XPath + `"><XPath>true()</XPath></ds:Transform>`, reference.ErrInput},
		{"missing algorithm", `<ds:Transform ` + namespace + `/>`, reference.ErrInput},
	} {
		t.Run(tc.name, func(t *testing.T) {
			doc, err := document.Parse(t.Context(), []byte(tc.xml), document.DefaultLimits())
			if err != nil {
				t.Fatal(err)
			}

			got, err := transformxml.Parse(t.Context(), doc, tree.Root(doc))
			if !errors.Is(err, tc.want) {
				t.Fatalf("Parse = %+v, %v; want %v", got, err, tc.want)
			}

			if tc.want == nil && (got.Algorithm != c14n.Exclusive || len(got.InclusivePrefixes) != 2 || got.InclusivePrefixes[0] != "p" || got.InclusivePrefixes[1] != "#default") {
				t.Fatal("inclusive prefix order/spelling lost:", got)
			}
		})
	}

	if _, err := transformxml.Parse(nil, nil, nil); !errors.Is(err, reference.ErrInput) {
		t.Fatal("nil context/node:", err)
	}

	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := transformxml.Parse(ctx, nil, &tree.Node{}); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled parse:", err)
	}
}

func TestStylesheetNamespaceContext(t *testing.T) {
	input := []byte(`<ds:Transform xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:p="urn:items" Algorithm="http://www.w3.org/TR/1999/REC-xslt-19991116"><xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="1.0"><xsl:template match="p:item"/></xsl:stylesheet></ds:Transform>`)
	doc, err := document.Parse(t.Context(), input, document.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}

	before, err := doc.XML(t.Context())
	if err != nil {
		t.Fatal(err)
	}

	program, err := transformxml.Parse(t.Context(), doc, tree.Root(doc))
	if err != nil {
		t.Fatal(err)
	}

	standalone, err := document.Parse(t.Context(), program.Stylesheet, document.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}

	if uri, ok := standalone.Root().Namespace("p"); !ok || uri != "urn:items" {
		t.Fatal("standalone stylesheet lost inherited namespaces")
	}

	after, err := doc.XML(t.Context())
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("extracting a stylesheet changed the original snapshot:", err)
	}
}
