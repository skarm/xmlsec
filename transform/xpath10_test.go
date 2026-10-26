package transform_test

import (
	"context"
	"errors"
	"math"
	"testing"

	"github.com/skarm/xmlsec/transform"
)

// TestXPath10CoreConformance runs the XPath 1.0 core cases against the shared VM.
func TestXPath10CoreConformance(t *testing.T) {
	ctx := t.Context()
	e := engine(t, transform.Config{})

	d, err := e.Parse(ctx, []byte(`<?q before?><r xmlns:p="urn:p" xml:lang="en-US"><a ID="a" n="2">2<b>3</b><!--comment--><?q data?></a><a ID="b" n="4">4</a><p:x>5</p:x></r><?q after?>`))
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		query string
		want  any
	}{
		{`count(/r/child::*)`, 3.0},
		{`count(/r/descendant::*)`, 4.0},
		{`count(/r/a[1]/descendant-or-self::*)`, 2.0},
		{`count(/r/a[1]/b/ancestor-or-self::*)`, 3.0},
		{`name(/r/a[1]/b/ancestor::*[1])`, "a"},
		{`name((/r/a[1]/b/ancestor::*)[1])`, "r"},
		{`name(/r/a[1]/parent::*)`, "r"},
		{`name(/r/a[2]/preceding-sibling::*[1])`, "a"},
		{`name(/r/a[1]/following-sibling::*[1])`, "a"},
		{`name(/r/a[1]/following::*[1])`, "a"},
		{`name(/r/a[2]/preceding::*[1])`, "b"},
		{`name(/r/a[1]/@ID/following::*[1])`, "b"},
		{`count(/r/a[1]/attribute::*)`, 2.0},
		{`count(/r/a[1]/namespace::*)`, 2.0},
		{`string(/r/a[1]/namespace::p)`, namespaceP},
		{`count(/r/a[1]/self::a)`, 1.0},
		{`count(//a | /r/a[1])`, 2.0},
		{`count(/processing-instruction('q'))`, 2.0},
		{`count(/processing-instruction(''))`, 0.0},
		{`count(/processing-instruction())`, 2.0},
		{`string(/r/a[1])`, "23"},
		{`string(/)`, "2345"},
		{`string(//comment())`, "comment"},
		{`name(/r/p:x)`, "p:x"},
		{`local-name(/r/p:x)`, "x"},
		{`namespace-uri(/r/p:x)`, namespaceP},
		{`count(/r/x)`, 0.0},
		{`/r/a/@n = 2`, true},
		{`/r/a/@n != 2`, true},
		{`/r/a = false()`, false},
		{`/r/missing = false()`, true},
		{`boolean(0 div 0)`, false},
		{`string(1 div 0)`, nameInfinity},
		{`string(-1 div 0)`, "-Infinity"},
		{`string(0 div 0)`, valueNaN},
		{`string(2147483647)`, "2147483647"},
		{`string(0.0000001)`, "0.0000001"},
		{`string(round(-0.5))`, "0"},
		{`number(' +1')`, math.NaN()},
		{nameNumber1e2, math.NaN()},
		{`number('Inf')`, math.NaN()},
		{`number('\u00a01')`, math.NaN()},
		{`number(' -.5 ')`, -0.5},
		{`sum(/r/a/@n)`, 6.0},
		{`5 mod 2`, 1.0},
		{`floor(-1.1)`, -2.0},
		{`ceiling(-1.1)`, -1.0},
		{`concat('a','б','c')`, "aбc"},
		{`starts-with('abc','ab')`, true},
		{`contains('abc','b')`, true},
		{`substring-before('abc','b')`, "a"},
		{`substring-after('abc','b')`, "c"},
		{`substring('12345',1.5,2.6)`, "234"},
		{`substring('12345',0,3)`, "12"},
		{`substring('12345',0 div 0,3)`, ""},
		{`string-length('a😀б')`, 3.0},
		{`normalize-space(' a  b ')`, "a b"},
		{"normalize-space(' a\u00a0 b ')", "a\u00a0 b"},
		{`translate('abcab','aba','XY')`, "XYcXY"},
		{`string(/r/a[1]/b/missing)`, ""},
		{`count(/r/a[1]/namespace::p:*)`, 0.0},
		{`lang('en')`, false},
		{`count(/r/*[lang('en')])`, 3.0},
		{`not(false())`, true},
		{`round(1.5)`, 2.0},
		{`round(4503599627370497)`, 4503599627370497.0},
		{`round(0.49999999999999994)`, 0.0},
		{`substring('12345',0.49999999999999994,2.5)`, "12"},
	}
	for _, tt := range tests {
		t.Run(tt.query, func(t *testing.T) { testXPath10CoreConformanceCase(t, &e, &ctx, &tt, &d) })
	}
}

func testXPath10CoreConformanceCase(t *testing.T, e **transform.Engine, ctx *context.Context, tt *struct {
	query string
	want  any
}, d **transform.Document,
) {
	q, err := (*e).CompileXPath(*ctx, tt.query, transform.XPathOptions{Version: transform.XPath10, Namespaces: map[string]string{"p": namespaceP}})
	if err != nil {
		t.Fatal(err)
	}

	seq, err := q.Evaluate(*ctx, *d, transform.XPathContext{})
	if err != nil {
		t.Fatal(err)
	}

	v, ok := seq.At(0)
	if !ok {
		t.Fatal("empty result")
	}

	switch want := tt.want.(type) {
	case string:
		got, err := v.Text()
		if err != nil || got != want {
			t.Fatalf("got %q want %q: %v", got, want, err)
		}
	case bool:
		got, err := v.Boolean()
		if err != nil || got != want {
			t.Fatalf("got %v want %v: %v", got, want, err)
		}
	case float64:
		got, err := v.Float64()
		if err != nil || v.Type().Local != nameDouble || got != want && !(math.IsNaN(got) && math.IsNaN(want)) {
			t.Fatalf("got %v (%v) want %v: %v", got, v.Type(), want, err)
		}
	}
}

func TestXPath10LanguageBoundaries(t *testing.T) {
	e := engine(t, transform.Config{})
	for _, source := range []string{`1e2`, `+1`, `1 eq 1`, `1 idiv 2`, `(1,2)`, `()`, `1 to 3`, `if (true()) then 1 else 2`, `for $x in /r return $x`, `/element()`, `/processing-instruction(q)`, `/r/element()`, `/*:r`, `1 union /r`, `'a''b'`, `(:c:) 1`, `1 +2`, `xs:string(1)`, `fn:string(1)`, `matches('a','a')`, `count('a')`} {
		t.Run(source, func(t *testing.T) {
			q, err := e.CompileXPath(t.Context(), source, transform.XPathOptions{Version: transform.XPath10})
			if err == nil {
				_, err = q.Evaluate(t.Context(), nil, transform.XPathContext{})
			}

			if err == nil {
				t.Error("XPath 2+ construct accepted in 1.0")
			}
		})
	}
}

func TestXPath10LanguageInheritance(t *testing.T) {
	ctx := t.Context()
	e := engine(t, transform.Config{})

	d, err := e.Parse(ctx, []byte(`<?p before?><r xml:lang="EN-us" xmlns:p="urn:p"><a v="x">text<!--c--><?p in?></a><b xml:lang=""><c/></b><d xml:lang="fr-CA"><e/></d></r><?p after?>`))
	if err != nil {
		t.Fatal(err)
	}

	for _, source := range []string{
		`not(lang('en'))`,
		`count(/processing-instruction()[lang('en')]) = 0`,
		`count(/r[lang('eN') and lang('EN-US') and not(lang('en-u'))]) = 1`,
		`count(/r/a/@v[lang('en')]) = 1`,
		`count(/r/a/namespace::*[lang('en')]) = 2`,
		`count(/r/a/text()[lang('en')]) = 1`,
		`count(/r/a/comment()[lang('en')]) = 1`,
		`count(/r/a/processing-instruction()[lang('en')]) = 1`,
		`count(/r/b/descendant-or-self::*[lang('en')]) = 0`,
		`count(/r/b/descendant-or-self::*[lang('')]) = 2`,
		`count(/r/d/descendant-or-self::*[lang('fr') and not(lang('en'))]) = 2`,
	} {
		q := query(t, e, source, transform.XPath10)

		v, err := q.Evaluate(ctx, d, transform.XPathContext{})
		if err != nil || text(t, v) != nameTrue {
			t.Fatalf("%s: %v", source, err)
		}
	}
}

func TestXPath10DynamicFocusAndValueKinds(t *testing.T) {
	e := engine(t, transform.Config{})
	ctx := t.Context()

	d, err := e.Parse(ctx, []byte(`<r/>`))
	if err != nil {
		t.Fatal(err)
	}

	q := query(t, e, `concat(position(),':',last(),':',string($n))`, transform.XPath10)

	seq, err := q.Evaluate(ctx, d, transform.XPathContext{Position: 3, Size: 5, Variables: transform.Bindings{{Local: "n"}: transform.Values(transform.Integer(7))}})
	if err != nil || text(t, seq) != "3:5:7" {
		t.Fatal(seq, err)
	}

	focusQuery := query(t, e, `position()`, transform.XPath10)
	for _, focus := range []transform.XPathContext{{Position: -1}, {Size: -1}, {Position: 2, Size: 1}, {ContextItem: transform.String("atomic")}} {
		if _, err := focusQuery.Evaluate(ctx, d, focus); err == nil {
			t.Error("invalid XPath 1.0 focus accepted", focus)
		}
	}

	q = query(t, e, `$n`, transform.XPath10)

	seq, err = q.Evaluate(ctx, d, transform.XPathContext{Variables: transform.Bindings{{Local: "n"}: transform.Values(transform.Integer(7))}})
	if err != nil {
		t.Fatal(err)
	}

	v, ok := seq.At(0)
	if !ok || v.Type().Local != nameDouble {
		t.Fatal("numeric binding was not a double", v.Type())
	}
}

func TestXPath10IDWhitespaceAndIntermediateLimit(t *testing.T) {
	ctx := t.Context()
	e := engine(t, transform.Config{})

	d, err := e.Parse(ctx, []byte(`<r><n xml:id="a"/><n xml:id="b"/></r>`))
	if err != nil {
		t.Fatal(err)
	}

	q := query(t, e, `count(id($ids))`, transform.XPath10)

	for _, tc := range []struct {
		ids  string
		want string
	}{{"a\u00a0b", "0"}, {" \ta\r\n b ", "2"}} {
		ids, want := tc.ids, tc.want

		out, err := q.Evaluate(ctx, d, transform.XPathContext{Variables: transform.Bindings{{Local: "ids"}: transform.Values(transform.String(ids))}})
		if err != nil || text(t, out) != want {
			t.Fatalf("IDs %q: got %s, want %s: %v", ids, text(t, out), want, err)
		}
	}

	e = engine(t, transform.Config{Limits: transform.Limits{MaxNodes: 3}})

	d, err = e.Parse(ctx, []byte(`<r/>`))
	if err != nil {
		t.Fatal(err)
	}

	q = query(t, e, `count(id($ids))`, transform.XPath10)

	_, err = q.Evaluate(ctx, d, transform.XPathContext{Variables: transform.Bindings{{Local: "ids"}: transform.Values(transform.String("a b c d"))}})
	if !errors.Is(err, transform.ErrLimit) {
		t.Fatal("unbounded intermediate ID list", err)
	}
}
