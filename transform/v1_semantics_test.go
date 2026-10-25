package transform_test

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/skarm/xmlsec/c14n"
	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/reference"
	"github.com/skarm/xmlsec/transform"
)

const ds = "http://www.w3.org/2000/09/xmldsig#"

func TestProgramFingerprints(t *testing.T) {
	a := xp(`not(ancestor-or-self::p:hidden)`)
	a.XPath[0].Namespaces = map[string]string{"p": namespaceP}
	b := reference.CloneTransforms([]reference.Transform{a})[0]
	b.XPath[0].Namespaces["xml"] = document.XMLNamespace

	ha, e := transform.Fingerprint(a)
	if e != nil {
		t.Fatal(e)
	}

	hb, e := transform.Fingerprint(b)
	if e != nil || ha != hb {
		t.Fatal(ha, hb, e)
	}

	b.XPath[0].Namespaces["p"] = "urn:changed"

	hb, _ = transform.Fingerprint(b)
	if ha == hb {
		t.Fatal("namespace ignored")
	}

	b = a
	b.XPath = append([]reference.XPathExpression(nil), a.XPath...)
	b.XPath[0].Here = doc(t, `<x/>`).Root()

	hb, _ = transform.Fingerprint(b)
	if ha != hb {
		t.Fatal("runtime handles should not enter config fingerprint")
	}

	for _, a := range []reference.Transform{{Algorithm: "unknown"}, xp(""), style(`<xsl:template match="/"/>`)} {
		_, _ = transform.Fingerprint(a)
	}
}

func TestXPathAndFilter2(t *testing.T) {
	ctx := context.Background()

	for _, tt := range []struct {
		name  string
		input string
		tr    reference.Transform
		want  string
	}{
		{"boolean", "<root><keep a=\"x\">yes</keep><hidden>no</hidden></root>", xp(`not(ancestor-or-self::hidden)`), `<root><keep a="x">yes</keep></root>`},
		{"context-size-is-one", "<r><a/><b/></r>", xp(`position() = 1 and last() = 1`), `<r><a></a><b></b></r>`},
		{"namespace-prefix", `<r xmlns:p="urn:p"><p:keep/><p:hidden/></r>`, reference.Transform{Algorithm: reference.XPath, XPath: []reference.XPathExpression{{Expression: `not(ancestor-or-self::p:hidden)`, Namespaces: map[string]string{"p": namespaceP}}}}, `<r xmlns:p="urn:p"><p:keep></p:keep></r>`},
		{"filter-order", "<r><signed><skip><keep>yes</keep>no</skip><a/></signed><unsigned/></r>", f2(reference.XPathExpression{Expression: `//signed`, Filter: "intersect"}, reference.XPathExpression{Expression: `//skip`, Filter: "subtract"}, reference.XPathExpression{Expression: `//keep`, Filter: nameUnion}), `<signed><keep>yes</keep><a></a></signed>`},
		{"union-only-is-noop", "<r><a/></r>", f2(reference.XPathExpression{Expression: `//a`, Filter: nameUnion}), `<r><a></a></r>`},
		{"empty", `<r/>`, xp(falseExpression), ``},
	} {
		t.Run(tt.name, func(t *testing.T) {
			d := doc(t, tt.input)

			p := proc(t, tt.tr)
			if e := p.Validate(ctx, tt.tr); e != nil {
				t.Fatal(e)
			}

			out, e := p.Apply(ctx, tt.tr, nodes(t, d), reference.ExtensionContext{})
			if e != nil {
				t.Fatal(e)
			}

			if got := canon(t, out); got != tt.want {
				t.Fatalf("got %q want %q", got, tt.want)
			}
		})
	}
}

func TestNamespaceAttributeAndInputIntersection(t *testing.T) {
	ctx := context.Background()
	d := doc(t, `<r xmlns:p="urn:p" a="1"><child><!--not-selected--></child></r>`)

	var selected []document.Node

	for _, n := range d.Root().NamespaceNodes() {
		if n.Name().Local == "p" {
			selected = append(selected, n)
		}
	}

	selected = append(selected, d.Root().AttributeNodes()[0])

	set, e := document.NewNodeSet(d, selected...)
	if e != nil {
		t.Fatal(e)
	}

	in, _ := reference.Nodes(set)

	for _, tr := range []reference.Transform{xp(`parent::r`), f2(reference.XPathExpression{Expression: `/`, Filter: nameUnion})} {
		p := proc(t, tr)

		out, e := p.Apply(ctx, tr, in, reference.ExtensionContext{})
		if e != nil {
			t.Fatal(e)
		}

		n, _ := out.Nodes()
		if n.Len() != 2 || !n.Contains(selected[0]) || !n.Contains(selected[1]) {
			t.Fatal("namespace/attribute identity lost")
		}
	}
}

func TestHereAndID(t *testing.T) {
	ctx := context.Background()
	d := doc(t, `<r><a ID="A"/><b xml:id="B"/><ds:Signature xmlns:ds="`+ds+`"><ds:XPath>here</ds:XPath></ds:Signature></r>`)
	tr := f2(reference.XPathExpression{Expression: `here()/ancestor::ds:Signature[1]`, Filter: "subtract", Namespaces: map[string]string{"ds": ds}, Here: d.Root().Children()[2].Children()[0]})
	p := proc(t, tr)

	out, e := p.Apply(ctx, tr, nodes(t, d), reference.ExtensionContext{})
	if e != nil {
		t.Fatal(e)
	}

	if got := canon(t, out); got != `<r><a ID="A"></a><b xml:id="B"></b></r>` {
		t.Fatal(got)
	}

	tr.XPath[0].Here = doc(t, `<other/>`).Root()
	if _, e = p.Apply(ctx, tr, nodes(t, d), reference.ExtensionContext{}); e == nil {
		t.Fatal("foreign here accepted")
	}

	for _, tt := range []struct {
		id   string
		want string
	}{{"A", `<a ID="A"></a>`}, {"B", ``}} {
		tr := f2(reference.XPathExpression{Expression: `id('` + tt.id + `')`, Filter: "intersect"})
		p := proc(t, tr)

		out, e := p.Apply(ctx, tr, nodes(t, d), reference.ExtensionContext{IDRules: []reference.IDAttributeRule{{Attribute: document.Name{Local: "ID"}}}})
		if e != nil {
			t.Fatal(e)
		}

		if got := canon(t, out); got != tt.want {
			t.Fatalf("id %s: %s", tt.id, got)
		}
	}
}

func TestProgramPreflight(t *testing.T) {
	for _, code := range []string{`false() and $unbound`, `false() and bogus()`, `false() and p:thing`, `1 + (`} {
		t.Run(code, func(t *testing.T) {
			tr := xp(code)
			if _, e := transform.NewEngine(transform.Config{AllowedPrograms: []reference.Transform{tr}}); e == nil {
				t.Fatal("invalid static expression approved")
			}
		})
	}

	tr := xp(trueExpression)

	p := proc(t, tr)
	if e := p.Validate(context.Background(), xp(falseExpression)); !errors.Is(e, reference.ErrPolicy) {
		t.Fatal(e)
	}

	tr.XPath[0].Expression = falseExpression

	if e := p.Validate(context.Background(), xp(trueExpression)); e != nil {
		t.Fatal("config mutated", e)
	}
}

func TestXSLTAndLimits(t *testing.T) {
	ctx := context.Background()
	tr := style(`<xsl:output method="xml" omit-xml-declaration="yes"/><xsl:template match="/"><out><xsl:value-of select="/r/value"/></out></xsl:template>`)

	p := proc(t, tr)
	if e := p.Validate(ctx, tr); e != nil {
		t.Fatal(e)
	}

	out, e := p.Apply(ctx, tr, reference.Octets([]byte(`<r><value>yes</value></r>`)), reference.ExtensionContext{})
	if e != nil {
		t.Fatal(e)
	}

	b, _ := out.Bytes()
	if !bytes.Equal(bytes.TrimSpace(b), []byte("<out>yes</out>")) {
		t.Fatalf("%q", b)
	}

	for _, tt := range []struct {
		name string
		body string
	}{
		{"file", `<xsl:template match="/"><xsl:copy-of select="document('file:///etc/passwd')"/></xsl:template>`},
		{"network", `<xsl:template match="/"><xsl:copy-of select="document('https://example.invalid/resource')"/></xsl:template>`},
		{nameInclude, `<xsl:include href="file:///etc/passwd"/>`},
		{"recursion", `<xsl:template match="/"><xsl:call-template name="loop"/></xsl:template><xsl:template name="loop"><xsl:call-template name="loop"/></xsl:template>`},
	} {
		t.Run(tt.name, func(t *testing.T) {
			tr := style(tt.body)

			p, err := transform.NewEngine(transform.Config{AllowedPrograms: []reference.Transform{tr}})
			if err != nil {
				return
			}

			if _, e := p.Apply(ctx, tr, reference.Octets([]byte(`<r/>`)), reference.ExtensionContext{}); e == nil {
				t.Fatal("hostile transform accepted")
			}
		})
	}

	small, e := transform.NewEngine(transform.Config{AllowedPrograms: []reference.Transform{tr}, Limits: transform.Limits{MaxOutputBytes: 2}})
	if e != nil {
		t.Fatal(e)
	}

	if _, e = small.Apply(ctx, tr, reference.Octets([]byte(`<r><value>yes</value></r>`)), reference.ExtensionContext{}); e == nil {
		t.Fatal("output budget ignored")
	}

	if _, e = p.Apply(ctx, tr, reference.Octets([]byte(`<!DOCTYPE r [<!ENTITY x "y">]><r>&x;</r>`)), reference.ExtensionContext{}); e == nil {
		t.Fatal("DTD accepted")
	}
}

func TestConcurrentAndCancelled(t *testing.T) {
	tr := xp(trueExpression)
	p := proc(t, tr)
	in := nodes(t, doc(t, `<r a="1"/>`))

	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			if _, e := p.Apply(context.Background(), tr, in, reference.ExtensionContext{}); e != nil {
				t.Error(e)
			}
		})
	}

	wg.Wait()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if _, e := p.Apply(ctx, tr, in, reference.ExtensionContext{}); !errors.Is(e, context.Canceled) {
		t.Fatal(e)
	}
}

func proc(t testing.TB, ts ...reference.Transform) *transform.Engine {
	t.Helper()

	p, e := transform.NewEngine(transform.Config{AllowedPrograms: ts})
	if e != nil {
		t.Fatal(e)
	}

	return p
}

func doc(t testing.TB, s string) *document.Document {
	t.Helper()

	d, e := document.Parse(t.Context(), []byte(s), document.DefaultLimits())
	if e != nil {
		t.Fatal(e)
	}

	return d
}

func nodes(t testing.TB, d *document.Document) reference.Data {
	t.Helper()

	n, e := d.AllNodes(t.Context())
	if e != nil {
		t.Fatal(e)
	}

	out, e := reference.Nodes(n)
	if e != nil {
		t.Fatal(e)
	}

	return out
}

func canon(t testing.TB, d reference.Data) string {
	t.Helper()

	n, ok := d.Nodes()
	if !ok {
		b, _ := d.Bytes()
		return string(b)
	}

	var b bytes.Buffer
	if e := c14n.WriteNodeSet(context.Background(), &b, n, c14n.Options{Algorithm: c14n.Canonical10WithComments}); e != nil {
		t.Fatal(e)
	}

	return b.String()
}

func f2(es ...reference.XPathExpression) reference.Transform {
	return reference.Transform{Algorithm: reference.XPathFilter2, XPath: es}
}

func style(body string) reference.Transform {
	return reference.Transform{Algorithm: reference.XSLT, Stylesheet: []byte(`<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="1.0">` + body + `</xsl:stylesheet>`)}
}
