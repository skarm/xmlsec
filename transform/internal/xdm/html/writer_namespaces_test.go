package html_test

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/skarm/xmlsec/internal/lexicon"
	"github.com/skarm/xmlsec/transform/internal/xdm"
	"github.com/skarm/xmlsec/transform/internal/xdm/html"
)

func TestHTMLMarkupNamesMustFitOutputRepertoire(t *testing.T) {
	t.Parallel()

	for _, attribute := range []bool{false, true} {
		doc := xdm.NewDefaultDocument()
		name := "é"
		if attribute {
			name = "p"
		}
		root, err := doc.CreateElement(name)
		if err != nil {
			t.Fatal(err)
		}
		if err := doc.AddChild(root); err != nil {
			t.Fatal(err)
		}
		if attribute {
			if err := root.SetAttribute("é", "value"); err != nil {
				t.Fatal(err)
			}
		}
		var output bytes.Buffer
		err = html.NewWriter().DefaultDTD(false).Format(false).Repertoire(func(r rune) bool { return r < 128 }).WriteTo(&output, doc)
		var detail *xdm.Error
		if !errors.As(err, &detail) || detail.Code != "SERE0008" {
			t.Fatal("unrepresentable markup name was emitted", attribute, output.String(), err)
		}
	}
}

func TestHTMLProcessingInstructionsUseContextDelimiters(t *testing.T) {
	t.Parallel()

	for _, test := range []struct{ input, want string }{
		{`<div><!--comment--><?work value?><?empty?></div>`, `<div><!--comment--><?work value><?empty></div>`},
		{`<p:div xmlns:p="urn:p"><!--comment--><?work value?><?empty?></p:div>`, `<p:div xmlns:p="urn:p"><!--comment--><?work value?><?empty?></p:div>`},
	} {
		doc, err := (xdm.ParseOptions{}).Parse(t.Context(), []byte(test.input))
		if err != nil {
			t.Fatal(err)
		}
		var output bytes.Buffer
		if err := html.NewWriter().DefaultDTD(false).Format(false).PreserveCase(true).WriteTo(&output, doc); err != nil || output.String() != test.want {
			t.Fatal("PI delimiters did not follow HTML/XML island context", output.String(), test.want, err)
		}
	}
}

type cancelOnOutput struct {
	bytes.Buffer
	cancel context.CancelFunc
	calls  int
}

func (w *cancelOnOutput) WriteString(s string) (int, error) { return w.Write([]byte(s)) }

func (w *cancelOnOutput) Write(p []byte) (int, error) {
	w.calls++
	if w.calls == 1 {
		w.cancel()
	}
	return w.Buffer.Write(p)
}

func TestHTMLCancellationDuringURIExpansion(t *testing.T) {
	t.Parallel()

	doc, err := (xdm.ParseOptions{}).Parse(t.Context(), []byte(`<a href="/`+strings.Repeat("é", 4096)+`">link</a>`))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	out := &cancelOnOutput{cancel: cancel}
	err = html.NewWriter().DefaultDTD(false).Format(false).WriteSequence(ctx, out, func(yield func(xdm.XMLItem, error) bool) { yield(xdm.XMLItem{Node: doc}, nil) })
	if !errors.Is(err, context.Canceled) || out.calls == 0 || strings.Contains(out.String(), "</a>") {
		t.Fatal("URI serialization ignored cancellation after output began", out.calls, out.Len(), err)
	}
}

func TestHTMLForeignNamespaceElementsKeepAttributeBindings(t *testing.T) {
	t.Parallel()

	input := `<h:html xmlns:h="http://www.w3.org/1999/xhtml" xml:lang="en"><h:body><s:svg xmlns:s="http://www.w3.org/2000/svg"><s:circle s:fill="red"/></s:svg><m:math xmlns:m="http://www.w3.org/1998/Math/MathML"><m:mi>x</m:mi></m:math></h:body></h:html>`
	doc, err := (xdm.ParseOptions{}).Parse(t.Context(), []byte(input))
	if err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	if err := html.NewWriter().DefaultDTD(false).Format(false).PreserveCase(true).ForeignNamespaces(true).WriteTo(&output, doc); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(output.String(), "<h:") || strings.Contains(output.String(), "<s:") || strings.Contains(output.String(), "<m:") {
		t.Fatal("HTML5 foreign element prefixes retained", output.String())
	}
	parsed, err := (xdm.ParseOptions{}).Parse(t.Context(), output.Bytes())
	if err != nil {
		t.Fatal("namespace output is not XML-well-formed", output.String(), err)
	}
	var svg, circle, math, mi *xdm.Element
	if err := xdm.Walk(parsed, xdm.NodeWalkerFunc(func(node xdm.Node) error {
		if e, ok := node.(*xdm.Element); ok {
			switch e.LocalName() {
			case "svg":
				svg = e
			case "circle":
				circle = e
			case "math":
				math = e
			case "mi":
				mi = e
			}
		}
		return nil
	})); err != nil {
		t.Fatal(err)
	}
	if svg == nil || circle == nil || math == nil || mi == nil || svg.URI() != lexicon.NamespaceSVG || circle.URI() != lexicon.NamespaceSVG || math.URI() != lexicon.NamespaceMathML || mi.URI() != lexicon.NamespaceMathML {
		t.Fatal("foreign namespace boundaries lost", output.String())
	}
	if value, present := circle.GetAttributeNS("fill", lexicon.NamespaceSVG); !present || value != "red" {
		t.Fatal("qualified attribute namespace lost", output.String())
	}
	if doc.DocumentElement().Prefix() != "h" {
		t.Fatal("HTML writer renamed source nodes")
	}
}

func TestHTMLBooleanAttributesAreElementAndNamespaceAware(t *testing.T) {
	t.Parallel()

	for _, test := range []struct{ input, want string }{
		{`<input disabled="DISABLED" checked="yes"/>`, `<input disabled checked="yes">`},
		{`<option selected="SELECTED"/>`, `<option selected></option>`},
		{`<button checked="checked"/>`, `<button checked="checked"></button>`},
		{`<input xmlns:p="urn:p" p:disabled="disabled"/>`, `<input xmlns:p="urn:p" p:disabled="disabled">`},
		{`<input xmlns="urn:foreign" disabled="disabled"/>`, `<input xmlns="urn:foreign" disabled="disabled"></input>`},
	} {
		doc, err := (xdm.ParseOptions{}).Parse(t.Context(), []byte(test.input))
		if err != nil {
			t.Fatal(err)
		}
		var output bytes.Buffer
		if err := html.NewWriter().DefaultDTD(false).Format(false).PreserveCase(true).WriteTo(&output, doc); err != nil || output.String() != test.want {
			t.Fatalf("HTML boolean output = %q, %v; want %q", output.String(), err, test.want)
		}
	}
}

func TestHTMLURIAttributesFollowSerializationVersion(t *testing.T) {
	t.Parallel()

	for _, edition := range []int{20, 30, 31} {
		doc, err := (xdm.ParseOptions{}).Parse(t.Context(), []byte(`<input formaction="/café"/>`))
		if err != nil {
			t.Fatal(err)
		}
		var output bytes.Buffer
		if err := html.NewWriter().DefaultDTD(false).Format(false).SerializationVersion(edition).WriteTo(&output, doc); err != nil {
			t.Fatal(err)
		}
		want := `<input formaction="/caf%C3%A9">`
		if edition == 20 {
			want = `<input formaction="/caf&eacute;">`
		}
		if output.String() != want {
			t.Fatal("URI table used wrong serialization edition", edition, output.String(), want)
		}
	}
}

func TestHTMLXMLIslandCDATAAndRepertoire(t *testing.T) {
	t.Parallel()

	doc := xdm.NewDefaultDocument()
	root, err := doc.CreateElementNS("pre", xdm.NewNamespace("p", "urn:foreign"))
	if err != nil {
		t.Fatal(err)
	}
	if err := root.DeclareNamespace("p", "urn:foreign"); err != nil {
		t.Fatal(err)
	}
	if err := doc.AddChild(root); err != nil {
		t.Fatal(err)
	}
	if err := root.AddChild(doc.CreateText("a]]>b")); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	writer := html.NewWriter().DefaultDTD(false).Format(false).PreserveCase(true).CDATAElements(map[string]struct{}{"{urn:foreign}pre": {}})
	if err := writer.WriteTo(&output, doc); err != nil || output.String() != `<p:pre xmlns:p="urn:foreign"><![CDATA[a]]]]><![CDATA[>b]]></p:pre>` {
		t.Fatal("XML island CDATA was not safely split", output.String(), err)
	}
	text := xdm.NewDefaultDocument().CreateText("é中")
	output.Reset()
	if err := html.NewWriter().Format(false).Repertoire(func(r rune) bool { return r < 128 }).WriteTo(&output, text); err != nil || output.String() != `&#xE9;&#x4E2D;` {
		t.Fatal("unrepresentable HTML text was not referenced", output.String(), err)
	}
}
