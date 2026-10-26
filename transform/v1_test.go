package transform_test

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/reference"
	"github.com/skarm/xmlsec/transform"
)

func TestUnifiedEngineModernAndV1(t *testing.T) {
	ctx := t.Context()
	tr := xp(`not(ancestor-or-self::volatile)`)
	e := newProcessor(t, tr)
	d := parse(t, `<r><fixed>0.1</fixed><volatile>ignored</volatile></r>`)

	legacy, err := e.Apply(ctx, tr, input(t, d), reference.ExtensionContext{})
	if err != nil || canon(t, legacy) != `<r><fixed>0.1</fixed></r>` {
		t.Fatal(legacy, err)
	}

	modern, err := e.Import(ctx, d)
	if err != nil {
		t.Fatal(err)
	}

	q := query(t, e, `xs:decimal(/r/fixed)+0.2`, transform.XPath31)

	result, err := q.Evaluate(ctx, modern, transform.XPathContext{})
	if err != nil || text(t, result) != name03 {
		t.Fatal(result, err)
	}

	out, err := stylesheet(t, e, sheet(version30, `<xsl:template match="/"><xsl:value-of select="xs:decimal(/r/fixed)+0.2"/></xsl:template>`)).Transform(ctx, modern, transform.XSLTContext{})
	if err != nil || string(out.Primary) != name03 {
		t.Fatal(out, err)
	}

	if err := e.Validate(ctx, xp(trueExpression)); !errors.Is(err, reference.ErrPolicy) {
		t.Fatal("modern compilation must not approve XMLDSig programs", err)
	}

	if err := engine(t, transform.Config{}).Validate(ctx, tr); !errors.Is(err, reference.ErrPolicy) {
		t.Fatal("XMLDSig v1 must remain opt-in", err)
	}
}

func TestXPathImmutableFocus(t *testing.T) {
	d := parse(t, `<?p before?><r xmlns:p="urn:p" xml:lang="ru-RU"><p:a ID="a">1<!--c--><?q x?></p:a><p:a ID="b">2</p:a></r><?p after?>`)

	for _, query := range []string{trueExpression, `position() = 1 and last() = 1`, `lang('ru') or not(ancestor-or-self::*)`, `count(//p:a)=2 and //p:a[2]/preceding-sibling::p:a[1]/@ID='a'`, `count(//p:a[1]/following-sibling::p:a)=1`, `count(//p:a[2]/ancestor::*)=1`, `count(/processing-instruction('p'))=2`, `count(//p:a[1]/namespace::p)=1`} {
		tr := xp(query)
		tr.XPath[0].Namespaces = map[string]string{"p": namespaceP}
		p := newProcessor(t, tr)
		out := apply(t, p, tr, input(t, d), reference.ExtensionContext{})

		before, _ := input(t, d).Nodes()
		if out.Len() != before.Len() || out.Document() != d {
			t.Fatalf("%s: lost nodes %d/%d", query, out.Len(), before.Len())
		}

		for _, n := range before.Nodes() {
			if !out.Contains(n) {
				t.Fatal("replaced original handle")
			}
		}
	}

	tr := xp(`not(ancestor-or-self::p:a[@ID='b'])`)
	tr.XPath[0].Namespaces = map[string]string{"p": namespaceP}

	out := apply(t, newProcessor(t, tr), tr, input(t, d), reference.ExtensionContext{})
	for _, n := range out.Nodes() {
		for a := n; a.Valid(); a = a.Parent() {
			if e, ok := a.Element(); ok {
				if id, _ := e.Attribute(document.Name{Local: "ID"}); id == "b" {
					t.Fatal("excluded subtree retained")
				}
			}
		}
	}
}

func TestLanguageComparisonUsesSharedStringBudget(t *testing.T) {
	// xml:lang is an attribute, not an element string-value. It must still be
	// charged before case folding during each context-node evaluation.
	d := parse(t, `<r xml:lang="EN-`+strings.Repeat("X", 4096)+`"><a/></r>`)
	tr := xp(`lang('en')`)

	p, err := transform.NewEngine(transform.Config{AllowedPrograms: []reference.Transform{tr}, Limits: transform.Limits{MaxOutputBytes: 1024}})
	if err != nil {
		t.Fatal(err)
	}

	out, err := p.Apply(t.Context(), tr, input(t, d), reference.ExtensionContext{})
	if _, ok := out.Nodes(); ok || !errors.Is(err, reference.ErrLimit) {
		t.Fatalf("unbudgeted language comparison: error=%v", err)
	}
}

func TestIDAndHere(t *testing.T) {
	d := parse(t, `<r><a ID="a"/><expr>not used</expr><a xml:id="guessed"/></r>`)
	kids := d.Root().Children()
	tr := xp(`count(id('a missing a'))=1 and id('guessed') = false() and count(here()/ancestor::r)=1`)
	tr.XPath[0].Here = kids[1]
	ec := reference.ExtensionContext{IDRules: []reference.IDAttributeRule{{Attribute: document.Name{Local: "ID"}}}}
	p := newProcessor(t, tr)
	out := apply(t, p, tr, input(t, d), ec)

	before, _ := input(t, d).Nodes()
	if out.Len() != before.Len() {
		t.Fatal("id/here focus")
	}

	tr.XPath[0].Here = parse(t, `<other/>`).Root()
	if _, e := p.Apply(t.Context(), tr, input(t, d), ec); !errors.Is(e, reference.ErrInput) {
		t.Fatal("foreign here", e)
	}

	tr.XPath[0].Here = document.Element{}
	if _, e := p.Apply(t.Context(), tr, input(t, d), ec); !errors.Is(e, reference.ErrInput) {
		t.Fatal("missing here", e)
	}

	tr = xp(`count(id('a'))=1`)
	p = newProcessor(t, tr)

	out = apply(t, p, tr, input(t, d), reference.ExtensionContext{})
	if out.Len() != 0 {
		t.Fatal("ID guessing")
	}

	dup := parse(t, `<r><a ID="a"/><b ID="a"/></r>`)
	if _, e := p.Apply(t.Context(), tr, input(t, dup), ec); !errors.Is(e, reference.ErrInput) {
		t.Fatal("duplicate ID", e)
	}
}

func TestFilter2ExpansionAndOrder(t *testing.T) {
	d := parse(t, `<r xmlns:p="urn:p"><a ID="a">one<b>two</b></a><c>three</c></r>`)
	tr := reference.Transform{Algorithm: reference.XPathFilter2, XPath: []reference.XPathExpression{filter("intersect", "/r/a"), filter("subtract", "/r/a/b"), filter(nameUnion, "/r/c")}}
	out := apply(t, newProcessor(t, tr), tr, input(t, d), reference.ExtensionContext{})
	a := d.Root().Children()[0]
	b := a.Children()[0]
	c := d.Root().Children()[1]
	an, _ := a.Subtree(t.Context())
	bn, _ := b.Subtree(t.Context())
	cn, _ := c.Subtree(t.Context())

	for _, n := range an.Nodes() {
		if out.Contains(n) == bn.Contains(n) {
			t.Fatal("subtree expansion/subtract", n.Kind())
		}
	}

	for _, n := range cn.Nodes() {
		if !out.Contains(n) {
			t.Fatal(nameUnion)
		}
	}
	// Union re-adds only nodes still present in the original sparse input.
	sparse, _ := document.NewNodeSet(d, a.Node())
	in, _ := reference.Nodes(sparse)

	out = apply(t, newProcessor(t, tr), tr, in, reference.ExtensionContext{})
	if out.Len() != 1 || !out.Contains(a.Node()) {
		t.Fatal("union expanded input")
	}

	ns := reference.Transform{Algorithm: reference.XPathFilter2, XPath: []reference.XPathExpression{filter("intersect", "/r/a/namespace::p")}}

	out = apply(t, newProcessor(t, ns), ns, input(t, d), reference.ExtensionContext{})
	if out.Len() != 1 || out.Nodes()[0].Kind() != document.NamespaceNode || !out.Nodes()[0].Parent().Same(a.Node()) {
		t.Fatal("namespace owner identity")
	}

	nonset := reference.Transform{Algorithm: reference.XPathFilter2, XPath: []reference.XPathExpression{filter("intersect", trueExpression)}}
	if _, e := newProcessor(t, nonset).Apply(t.Context(), nonset, input(t, d), reference.ExtensionContext{}); !errors.Is(e, reference.ErrInput) {
		t.Fatal("non-node-set", e)
	}
}

func filter(op, s string) reference.XPathExpression {
	return reference.XPathExpression{Filter: op, Expression: s}
}

func TestApprovalAndLimits(t *testing.T) {
	for _, q := range []string{`true() or unknown()`, `false() and p:x`, `true() or $external`, `document('file:///etc/passwd')`, `1 +`, `here(1)`} {
		_, e := transform.NewEngine(transform.Config{AllowedPrograms: []reference.Transform{xp(q)}})
		if e == nil {
			t.Fatal("unvalidated expression", q)
		}
	}

	tr := xp(trueExpression)
	p := newProcessor(t, tr)

	changed := xp(` true()`)
	if e := p.Validate(t.Context(), changed); !errors.Is(e, reference.ErrPolicy) {
		t.Fatal("exact program", e)
	}

	var zero transform.Engine
	if e := zero.Validate(t.Context(), tr); !errors.Is(e, reference.ErrPolicy) {
		t.Fatal(e)
	}

	if e := p.Validate(nil, tr); !errors.Is(e, reference.ErrInput) {
		t.Fatal(e)
	}

	d := parse(t, `<r><a/><b/><c/><d/></r>`)
	in := input(t, d)

	for _, c := range []transform.Config{{Limits: transform.Limits{MaxOperations: 1}}, {Limits: transform.Limits{MaxNodes: 3}}, {Limits: transform.Limits{MaxInputBytes: 10}}} {
		c.AllowedPrograms = []reference.Transform{tr}

		p, e := transform.NewEngine(c)
		if e != nil {
			t.Fatal(e)
		}

		out, e := p.Apply(t.Context(), tr, in, reference.ExtensionContext{})
		if !errors.Is(e, reference.ErrLimit) || out.Kind() != reference.Invalid {
			t.Fatal("bounded execution", c, out.Kind(), e)
		}
	}

	value := xp(`string(.) != 'x'`)

	p, e := transform.NewEngine(transform.Config{AllowedPrograms: []reference.Transform{value}, Limits: transform.Limits{MaxOutputBytes: 32}})
	if e != nil {
		t.Fatal(e)
	}

	_, e = p.Apply(t.Context(), value, input(t, parse(t, "<r>"+strings.Repeat("a", 1000)+"</r>")), reference.ExtensionContext{})
	if !errors.Is(e, reference.ErrLimit) {
		t.Fatal("string budget", e)
	}

	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	if _, e := newProcessor(t, tr).Apply(ctx, tr, in, reference.ExtensionContext{}); !errors.Is(e, context.Canceled) {
		t.Fatal(e)
	}

	if _, e := newProcessor(t, tr).Apply(t.Context(), tr, reference.Octets([]byte(`<r/>`)), reference.ExtensionContext{}); !errors.Is(e, reference.ErrInput) {
		t.Fatal(e)
	}
}

func TestApprovedProgramNumericCompilationBudget(t *testing.T) {
	source := strings.Repeat("9", 160) + ` > 0`
	for _, program := range []reference.Transform{
		{Algorithm: reference.XPath, XPath: []reference.XPathExpression{{Expression: source}}},
		{Algorithm: reference.XSLT, Stylesheet: []byte(`<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="1.0"><xsl:template match="/"><xsl:value-of select="` + source + `"/></xsl:template></xsl:stylesheet>`)},
	} {
		t.Run(program.Algorithm, func(t *testing.T) {
			_, err := transform.NewEngine(transform.Config{Limits: transform.Limits{MaxOutputBytes: 64}, AllowedPrograms: []reference.Transform{program}})
			if !errors.Is(err, transform.ErrLimit) {
				t.Fatalf("compilation budget: %v", err)
			}
		})
	}
}

func TestConcurrentImmutableApproval(t *testing.T) {
	tr := xp(`count(//p:a)=1`)
	tr.XPath[0].Namespaces = map[string]string{"p": namespaceP}
	p := newProcessor(t, tr)
	owned := reference.CloneTransforms([]reference.Transform{tr})[0]
	tr.XPath[0].Namespaces["p"] = "changed"
	d := parse(t, `<r xmlns:p="urn:p"><p:a/></r>`)
	in := input(t, d)

	var wg sync.WaitGroup
	for range 24 {
		wg.Go(func() {
			out, e := p.Apply(t.Context(), owned, in, reference.ExtensionContext{})
			if e != nil || out.Size() != in.Size() {
				t.Errorf("concurrent apply: %v", e)
			}
		})
	}

	wg.Wait()
}

func TestIDTokenPreallocationBound(t *testing.T) {
	tr := xp(`count(id(.))=0`)
	p := newProcessor(t, tr)
	d := parse(t, "<r>"+strings.Repeat("a ", 70000)+"</r>")

	out, e := p.Apply(t.Context(), tr, input(t, d), reference.ExtensionContext{})
	if !errors.Is(e, reference.ErrLimit) || out.Kind() != reference.Invalid {
		t.Fatal("unbounded ID tokens", e)
	}
}

func FuzzApprovedXPath(f *testing.F) {
	for _, s := range []string{`<r/>`, `<r xmlns:p="urn:p"><p:a>1</p:a><!--x--></r>`, `<r xml:lang="en"><a ID="a"/></r>`} {
		f.Add(s)
	}

	tr := xp(`not(ancestor-or-self::p:hidden) and position()=last()`)
	tr.XPath[0].Namespaces = map[string]string{"p": namespaceP}
	p := newProcessor(f, tr)
	f.Fuzz(func(t *testing.T, s string) {
		if len(s) > 64<<10 {
			return
		}

		d, e := document.Parse(t.Context(), []byte(s), document.DefaultLimits())
		if e != nil {
			return
		}

		in := input(t, d)

		out, e := p.Apply(t.Context(), tr, in, reference.ExtensionContext{})
		if e != nil {
			return
		}

		ns, ok := out.Nodes()
		original, _ := in.Nodes()

		if !ok || ns.Document() != d {
			t.Fatal("snapshot")
		}

		for _, n := range ns.Nodes() {
			if !original.Contains(n) {
				t.Fatal("foreign node")
			}
		}
	})
}

func FuzzXPathCompilation(f *testing.F) {
	for _, query := range []string{trueExpression, `not(ancestor-or-self::p:hidden)`, `false() and unknown()`, `/r/a[2]/preceding::*[1]`, `string(0 div 0)`, `$external`, `(((((`} {
		f.Add(query)
	}

	d := parse(f, `<r xmlns:p="urn:p"><a>1</a><p:hidden>2</p:hidden></r>`)
	in := input(f, d)
	f.Fuzz(func(t *testing.T, query string) {
		if len(query) > 16<<10 {
			return
		}

		tr := xp(query)
		tr.XPath[0].Namespaces = map[string]string{"p": namespaceP}

		p, e := transform.NewEngine(transform.Config{AllowedPrograms: []reference.Transform{tr}, Limits: transform.Limits{MaxOperations: 2000, MaxOutputBytes: 4096}})
		if e != nil {
			return
		}

		out, e := p.Apply(t.Context(), tr, in, reference.ExtensionContext{})
		if e != nil {
			if out.Kind() != reference.Invalid {
				t.Fatal("partial result")
			}

			return
		}

		ns, ok := out.Nodes()
		original, _ := in.Nodes()

		if !ok || ns.Document() != d {
			t.Fatal("snapshot")
		}

		for _, n := range ns.Nodes() {
			if !original.Contains(n) {
				t.Fatal("foreign node")
			}
		}
	})
}

func BenchmarkXPath(b *testing.B) {
	d := parse(b, `<r>`+strings.Repeat(`<item a="1">text</item>`, 100)+`</r>`)
	tr := xp(`not(ancestor-or-self::excluded)`)
	p := newProcessor(b, tr)
	in := input(b, d)
	b.ReportAllocs()

	for b.Loop() {
		if _, err := p.Apply(b.Context(), tr, in, reference.ExtensionContext{}); err != nil {
			b.Fatal(err)
		}
	}
}

func xp(s string) reference.Transform {
	return reference.Transform{Algorithm: reference.XPath, XPath: []reference.XPathExpression{{Expression: s}}}
}

func parse(t testing.TB, s string) *document.Document {
	t.Helper()

	d, e := document.Parse(t.Context(), []byte(s), document.DefaultLimits())
	if e != nil {
		t.Fatal(e)
	}

	return d
}

func input(t testing.TB, d *document.Document) reference.Data {
	t.Helper()

	n, e := d.AllNodes(t.Context())
	if e != nil {
		t.Fatal(e)
	}

	in, e := reference.Nodes(n)
	if e != nil {
		t.Fatal(e)
	}

	return in
}

func newProcessor(t testing.TB, ts ...reference.Transform) *transform.Engine {
	t.Helper()

	p, e := transform.NewEngine(transform.Config{AllowedPrograms: ts})
	if e != nil {
		t.Fatal(e)
	}

	return p
}

func apply(t testing.TB, p *transform.Engine, tr reference.Transform, in reference.Data, ec reference.ExtensionContext) document.NodeSet {
	t.Helper()

	out, e := p.Apply(t.Context(), tr, in, ec)
	if e != nil {
		t.Fatal(e)
	}

	ns, ok := out.Nodes()
	if !ok {
		t.Fatal("output kind")
	}

	return ns
}
