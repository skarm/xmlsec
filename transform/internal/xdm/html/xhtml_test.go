package html_test

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/skarm/xmlsec/internal/lexicon"
	"github.com/skarm/xmlsec/internal/tree"
	"github.com/skarm/xmlsec/transform/internal/xdm"
	"github.com/skarm/xmlsec/transform/internal/xdm/html"
)

func TestXHTMLNameAwareMarkupRules(t *testing.T) {
	t.Parallel()

	// Serialization 3.1 sections 6 and 6.1 distinguish XHTML's XML names,
	// HTML5 null-namespace names, and foreign namespaces.
	for _, test := range []struct {
		uri, local       string
		html5            bool
		empty            tree.EmptyElementMode
		inline, preserve bool
	}{
		{lexicon.NamespaceXHTML, "br", false, tree.EmptyElementSpaced, true, true},
		{lexicon.NamespaceXHTML, "BR", true, tree.EmptyElementExpanded, true, true},
		{lexicon.NamespaceXHTML, "div", true, tree.EmptyElementExpanded, false, false},
		{lexicon.NamespaceXHTML, "pre", true, tree.EmptyElementExpanded, false, true},
		{lexicon.NamespaceXHTML, "script", true, tree.EmptyElementExpanded, true, true},
		{lexicon.NamespaceXHTML, "basefont", true, tree.EmptyElementExpanded, true, true},
		{"", "br", true, tree.EmptyElementSpaced, true, true},
		{"", "br", false, tree.EmptyElementExpanded, false, false},
		{"urn:foreign", "br", true, tree.EmptyElementExpanded, false, false},
	} {
		var options tree.XMLWriteOptions
		html.ConfigureXHTML(&options, test.html5, true, 31)
		name := tree.Name{Space: test.uri, Local: test.local}
		if options.EmptyElement(name) != test.empty || options.InlineElement(name) != test.inline || options.PreserveContent(name) != test.preserve {
			t.Fatalf("XHTML rules for %+v html5=%v differ", name, test.html5)
		}
	}
	for _, test := range []struct {
		element, attribute tree.Name
		handled            bool
	}{
		{tree.Name{Space: lexicon.NamespaceXHTML, Local: "a"}, tree.Name{Local: "href"}, true},
		{tree.Name{Space: lexicon.NamespaceXHTML, Local: "a"}, tree.Name{Space: "urn:qualified", Local: "href"}, false},
		{tree.Name{Space: "urn:foreign", Local: "a"}, tree.Name{Local: "href"}, false},
		{tree.Name{Space: lexicon.NamespaceXHTML, Local: "a"}, tree.Name{Local: "title"}, false},
	} {
		var options tree.XMLWriteOptions
		html.ConfigureXHTML(&options, true, true, 31)
		var output bytes.Buffer
		handled, err := options.AttributeWriter(t.Context(), &output, test.element, tree.Attribute{Name: test.attribute, Value: "/cafe\u0301?x=1&y=\"v\""})
		want := ""
		if test.handled {
			want = `/caf%C3%A9?x=1&amp;y=&quot;v&quot;`
		}
		if err != nil || handled != test.handled || output.String() != want {
			t.Fatalf("XHTML attribute handling = %v, %q, %v; want %v, %q", handled, output.String(), err, test.handled, want)
		}
	}
	var options tree.XMLWriteOptions
	html.ConfigureXHTML(&options, true, false, 31)
	if options.AttributeWriter != nil {
		t.Fatal("disabled URI escaping installed an attribute handler")
	}
	for _, test := range []struct{ htmlVersion, version, want string }{{"", "", "5"}, {"", "4.01", "4.01"}, {"5", "4.01", "5"}} {
		if got := html.RequestedVersion(test.htmlVersion, test.version); got != test.want {
			t.Fatal("version precedence", got, test.want)
		}
	}
	for _, version := range []string{"4", "4.01", "5", "5.0"} {
		if !html.SupportedVersion(version) {
			t.Fatal("supported version rejected", version)
		}
	}
	for _, version := range []string{"3.2", "NaN", "+Inf", "not a number"} {
		if html.SupportedVersion(version) {
			t.Fatal("unsupported version accepted", version)
		}
	}
	if html.LowerASCII("PİÉ") != "pİÉ" || html.EqualFoldASCII("ſcript", "script") || !html.EqualFoldASCII("ScRiPt", "sCrIpT") {
		t.Fatal("HTML ASCII case matching used Unicode aliases")
	}
}

func TestPrepareXHTMLReplacesOnlyRecognizedMetadata(t *testing.T) {
	t.Parallel()

	for _, html5 := range []bool{false, true} {
		input := `<h:html xmlns:h="http://www.w3.org/1999/xhtml" xmlns:s="http://www.w3.org/2000/svg" xmlns:f="urn:foreign" h:custom="kept"><h:head><h:meta http-equiv=" Content-Type " content="old"/><h:meta name="viewport" content="kept"/><f:meta http-equiv="Content-Type" content="foreign"/><!--kept--></h:head><h:body><s:svg><s:circle/></s:svg><f:head/></h:body></h:html>`
		doc, err := (xdm.ParseOptions{}).Parse(t.Context(), []byte(input))
		if err != nil {
			t.Fatal(err)
		}
		if err := html.PrepareXHTML(t.Context(), doc, html5, "application/xhtml+xml; charset=UTF-8"); err != nil {
			t.Fatal(err)
		}
		root := doc.DocumentElement()
		if root.Prefix() != "" || root.URI() != lexicon.NamespaceXHTML {
			t.Fatal("XHTML element namespace was not normalized", root.Name(), root.URI())
		}
		if value, present := root.GetAttribute("h:custom"); !present || value != "kept" {
			t.Fatal("qualified attribute was renamed or lost")
		}
		var head, svg, foreign *xdm.Element
		if err := xdm.Walk(doc, xdm.NodeWalkerFunc(func(node xdm.Node) error {
			if e, ok := node.(*xdm.Element); ok {
				switch {
				case e.URI() == lexicon.NamespaceXHTML && e.LocalName() == "head":
					head = e
				case e.URI() == lexicon.NamespaceSVG && e.LocalName() == "svg":
					svg = e
				case e.URI() == "urn:foreign" && e.LocalName() == "head":
					foreign = e
				}
			}
			return nil
		})); err != nil {
			t.Fatal(err)
		}
		if head == nil || svg == nil || foreign == nil {
			t.Fatal("normalization removed elements")
		}
		var children []xdm.Node
		for child := range xdm.Children(head) {
			children = append(children, child)
		}
		if len(children) != 4 {
			t.Fatal("metadata replacement lost or duplicated children", len(children))
		}
		meta, ok := children[0].(*xdm.Element)
		if !ok {
			t.Fatal("metadata is not the first child element")
		}
		if value, present := meta.GetAttribute("content"); !present || value != "application/xhtml+xml; charset=UTF-8" || meta.URI() != lexicon.NamespaceXHTML {
			t.Fatal("wrong replacement metadata", value, meta.URI())
		}
		if value, _ := children[1].(*xdm.Element).GetAttribute("name"); value != "viewport" {
			t.Fatal("ordinary metadata was replaced")
		}
		if value, _ := children[2].(*xdm.Element).GetAttribute("content"); value != "foreign" || children[2].(*xdm.Element).URI() != "urn:foreign" {
			t.Fatal("foreign metadata was replaced")
		}
		if foreign.FirstChild() != nil {
			t.Fatal("foreign head received XHTML metadata")
		}
		if html5 && svg.Prefix() != "" || !html5 && svg.Prefix() != "s" {
			t.Fatal("SVG prefix normalization used the wrong HTML version", svg.Name())
		}
		var serialized bytes.Buffer
		if err := (xdm.XMLSerialization{OmitDeclaration: true, Reconcile: true}).WriteTo(&serialized, doc); err != nil {
			t.Fatal("prepared namespaces are not serializable", err)
		}
		if _, err := (xdm.ParseOptions{}).Parse(t.Context(), serialized.Bytes()); err != nil {
			t.Fatal("prepared tree serialized invalid namespace bindings", serialized.String(), err)
		}
	}
	doc, err := (xdm.ParseOptions{}).Parse(t.Context(), []byte(`<html xmlns="http://www.w3.org/1999/xhtml"><p/></html>`))
	if err != nil {
		t.Fatal(err)
	}
	if err := html.PrepareXHTML(t.Context(), doc, false, ""); err != nil || doc.DocumentElement().Prefix() != "" {
		t.Fatal("existing default namespace changed", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := html.PrepareXHTML(ctx, doc, true, "text/html"); !errors.Is(err, context.Canceled) {
		t.Fatal("canceled metadata preparation succeeded", err)
	}
}
