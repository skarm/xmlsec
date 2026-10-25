package transform_test

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/big"
	"strings"
	"sync"
	"testing"
	"unicode/utf16"

	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/transform"
)

func TestLimitsCancellationAndResources(t *testing.T) {
	ctx := context.Background()

	e := engine(t, transform.Config{Limits: transform.Limits{MaxOutputBytes: 64, MaxOperations: 100, MaxNodes: 50}})
	for _, source := range []string{`sum(1 to 10000)`, `fold-left(1 to 20,'x',function($a,$b){$a||$a})`} {
		_, err := query(t, e, source, transform.XPath31).Evaluate(ctx, nil, transform.XPathContext{})
		if !errors.Is(err, transform.ErrLimit) {
			t.Fatal(source, err)
		}
	}

	_, err := e.Parse(ctx, []byte(`<!DOCTYPE r [<!ENTITY e "boom">]><r>&e;</r>`))
	if err == nil {
		t.Fatal("DTD accepted")
	}

	_, err = query(t, e, `parse-xml('<!DOCTYPE r [<!ENTITY e "boom">]><r>&e;</r>')`, transform.XPath31).Evaluate(ctx, nil, transform.XPathContext{})
	if err == nil {
		t.Fatal("dynamic DTD accepted")
	}

	cancelled, cancel := context.WithCancel(ctx)
	cancel()

	if _, err := e.CompileXPath(cancelled, "1", transform.XPathOptions{}); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}

	ordinary := engine(t, transform.Config{})

	_, err = query(t, ordinary, `doc('file:///etc/passwd')`, transform.XPath31).Evaluate(ctx, nil, transform.XPathContext{})
	if err == nil {
		t.Fatal("implicit resource read")
	}

	s := stylesheet(t, e, sheet(version30, `<xsl:template name="r"><xsl:call-template name="r"/></xsl:template>`))

	_, err = s.Transform(ctx, nil, transform.XSLTContext{Template: transform.Name{Local: "r"}})
	if err == nil {
		t.Fatal("unbounded recursion")
	}

	s = stylesheet(t, e, sheet(version30, `<xsl:template name="r"><xsl:value-of select="string-join(1 to 40, 'abcdefgh')"/></xsl:template>`))

	_, err = s.Transform(ctx, nil, transform.XSLTContext{Template: transform.Name{Local: "r"}})
	if !errors.Is(err, transform.ErrLimit) {
		t.Fatal(err)
	}

	var requested string

	resourceEngine := engine(t, transform.Config{Resolver: transform.ResolverFunc(func(ctx context.Context, uri string) (io.ReadCloser, error) {
		requested = uri
		return io.NopCloser(strings.NewReader(`<r>loaded</r>`)), ctx.Err()
	})})

	result, err := query(t, resourceEngine, `string(doc('urn:test'))`, transform.XPath31).Evaluate(ctx, nil, transform.XPathContext{})
	if err != nil || text(t, result) != "loaded" || requested != "urn:test" {
		t.Fatal(result, requested, err)
	}
}

func TestNumericIntermediateBudget(t *testing.T) {
	for _, tt := range []struct{ name, expression string }{
		{"integer fold", `fold-left(1 to 12, 2, function($a, $b) { $a * $a }) mod 2`},
		{"decimal numerator", `fold-left(1 to 12, xs:decimal('2'), function($a, $b) { $a * $a }) gt 0`},
		{"decimal denominator", `fold-left(1 to 12, xs:decimal('0.5'), function($a, $b) { $a * $a }) gt 0`},
		{"integer constructor", `xs:integer('` + strings.Repeat("9", 160) + `') mod 2`},
		{"decimal constructor", `xs:decimal('0.` + strings.Repeat("0", 160) + `1') gt 0`},
		{"castable", `('` + strings.Repeat("9", 160) + `') castable as xs:integer`},
		{"untyped round precision", `round(1, xs:untypedAtomic('` + strings.Repeat("9", 160) + `'))`},
		{"round scale", `round(1 div 3, 1000000) gt 0`},
		{"function item", `fold-left(1 to 100, 2, sum#2) mod 2`},
		{"format scale", `string-length(format-number(1, '0.` + strings.Repeat("0", 1000) + `'))`},
		{"untyped range", `exists(xs:untypedAtomic('` + strings.Repeat("9", 160) + `') to xs:untypedAtomic('` + strings.Repeat("9", 160) + `'))`},
	} {
		t.Run(tt.name, func(t *testing.T) {
			e := engine(t, transform.Config{Limits: transform.Limits{MaxOutputBytes: 64}})

			q, err := e.CompileXPath(t.Context(), tt.expression, transform.XPathOptions{})
			if err == nil {
				_, err = q.Evaluate(t.Context(), nil, transform.XPathContext{})
			}

			if !errors.Is(err, transform.ErrLimit) {
				t.Fatalf("expected ErrLimit, got %v", err)
			}
		})
	}
}

func TestNumericBudgetBoundaries(t *testing.T) {
	for _, tt := range []struct {
		source string
		limit  int
		fail   bool
	}{
		{"0", 1, false},
		{"255", 1, false},
		{"256", 1, true},
		{"256", 2, false},
		{"65535", 2, false},
		{"65536", 2, true},
		{"65536", 3, false},
		{`'1' castable as xs:numeric`, 5, true},
		{"255 + 0", 2, true}, // Both operands use the cumulative two-byte budget.
	} {
		t.Run(fmt.Sprintf("%s/%d", tt.source, tt.limit), func(t *testing.T) {
			e := engine(t, transform.Config{Limits: transform.Limits{MaxOutputBytes: tt.limit}})

			q, err := e.CompileXPath(t.Context(), tt.source, transform.XPathOptions{})
			if err == nil {
				_, err = q.Evaluate(t.Context(), nil, transform.XPathContext{})
			}

			if errors.Is(err, transform.ErrLimit) != tt.fail || err != nil && !tt.fail {
				t.Fatal(err)
			}
		})
	}
}

func TestNumericBudgetBindingsAndXSLT(t *testing.T) {
	large := transform.BigInteger(new(big.Int).Lsh(big.NewInt(1), 512))

	m, err := transform.Map(transform.MapEntry{Key: large, Value: transform.Values(transform.Boolean(true))})
	if err != nil {
		t.Fatal(err)
	}

	e := engine(t, transform.Config{Limits: transform.Limits{MaxOutputBytes: 64}})
	for _, value := range []transform.Value{large, transform.Array(transform.Values(large)), m} {
		_, err := query(t, e, `true()`, transform.XPath31).Evaluate(t.Context(), nil, transform.XPathContext{Variables: transform.Bindings{{Local: "unused"}: transform.Values(value)}})
		if !errors.Is(err, transform.ErrLimit) {
			t.Fatalf("oversized binding: %v", err)
		}
	}

	decimal, err := transform.Decimal("0." + strings.Repeat("0", 119) + "1")
	if err != nil {
		t.Fatal(err)
	}
	// The exact denominator fits in the binary budget even though its lexical
	// representation is longer; no decimal string is needed for admission.
	if _, err := query(t, e, `true()`, transform.XPath31).Evaluate(t.Context(), nil, transform.XPathContext{Variables: transform.Bindings{{Local: "unused"}: transform.Values(decimal)}}); err != nil {
		t.Fatal(err)
	}

	s := stylesheet(t, e, sheet("3.0", `<xsl:template name="run"><xsl:sequence select="fold-left(1 to 12, 2, function($a,$b){$a*$a}) mod 2"/></xsl:template>`))
	if _, err := s.Execute(t.Context(), nil, transform.XSLTContext{Template: transform.Name{Local: "run"}}); !errors.Is(err, transform.ErrLimit) {
		t.Fatalf("XSLT numeric budget: %v", err)
	}

	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	if _, err := query(t, e, `2*2`, transform.XPath31).Evaluate(ctx, nil, transform.XPathContext{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation: %v", err)
	}
}

func TestNumericSharedWorkBudget(t *testing.T) {
	e := engine(t, transform.Config{Limits: transform.Limits{MaxOutputBytes: 1 << 20, MaxOperations: 32}})

	q := query(t, e, `fold-left(1 to 80, 2, function($a,$b){$a*$a}) mod 2`, transform.XPath31)
	if _, err := q.Evaluate(t.Context(), nil, transform.XPathContext{}); !errors.Is(err, transform.ErrLimit) {
		t.Fatalf("work budget: %v", err)
	}

	fresh := query(t, engine(t, transform.Config{Limits: transform.Limits{MaxOutputBytes: 16}}), `2+2`, transform.XPath31)
	for range 3 {
		if got := text(t, evaluateNumericInvocation(t, fresh)); got != "4" {
			t.Fatal(got)
		}
	}
}

func TestConcurrentReuse(t *testing.T) {
	e := engine(t, transform.Config{})
	q := query(t, e, `$n + 1`, transform.XPath31)
	s := stylesheet(t, e, sheet(version30, `<xsl:param name="n"/><xsl:template name="start"><xsl:value-of select="$n+1"/></xsl:template>`))

	var wg sync.WaitGroup
	for i := range int64(16) {
		wg.Go(func() {
			binding := transform.Bindings{{Local: "n"}: transform.Values(transform.Integer(i))}

			result, err := q.Evaluate(context.Background(), nil, transform.XPathContext{Variables: binding})
			if err != nil {
				t.Error(err)
				return
			}

			v, err := result.Single()
			if err != nil {
				t.Error(err)
				return
			}

			number, err := v.Integer()
			if err != nil || number.Int64() != i+1 {
				t.Error(number, err)
			}

			out, err := s.Transform(context.Background(), nil, transform.XSLTContext{Template: transform.Name{Local: nameStart}, Parameters: binding})
			if err != nil {
				t.Error(err)
				return
			}

			var expected bytes.Buffer
			expected.WriteString(big.NewInt(i + 1).String())

			if !bytes.Equal(out.Primary, expected.Bytes()) {
				t.Error(string(out.Primary))
			}
		})
	}

	wg.Wait()
}

func TestInvocationChecksForeignDocumentLimits(t *testing.T) {
	ctx := context.Background()

	producer := engine(t, transform.Config{})
	for _, tc := range []struct {
		name   string
		limits transform.Limits
		source string
	}{
		{"bytes", transform.Limits{MaxInputBytes: 512}, `<r>` + strings.Repeat("x", 1024) + `</r>`},
		{"nodes", transform.Limits{MaxNodes: 5}, `<r><a/><b/><c/><d/><e/></r>`},
		{"depth", transform.Limits{MaxDepth: 4}, `<a><b><c><d><e/></d></c></b></a>`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d, err := producer.Parse(ctx, []byte(tc.source))
			if err != nil {
				t.Fatal(err)
			}

			e := engine(t, transform.Config{Limits: tc.limits})
			for _, input := range []struct {
				name string
				expr string
				doc  *transform.Document
				opt  transform.XPathContext
			}{
				{"document", `count(/*)`, d, transform.XPathContext{}},
				{"context-item", `count(/*)`, nil, transform.XPathContext{ContextItem: d.Root()}},
				{"binding", `count($source/*)`, nil, transform.XPathContext{Variables: transform.Bindings{{Local: "source"}: transform.Values(d.Root())}}},
			} {
				t.Run(input.name, func(t *testing.T) {
					q := query(t, e, input.expr, transform.XPath31)
					if _, err := q.Evaluate(ctx, input.doc, input.opt); !errors.Is(err, transform.ErrLimit) {
						t.Fatalf("foreign document exceeded consumer policy: %v", err)
					}
				})
			}

			s := stylesheet(t, e, `<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="3.0"><xsl:output method="text"/><xsl:template match="/">ok</xsl:template></xsl:stylesheet>`)
			if out, err := s.Transform(ctx, d, transform.XSLTContext{}); !errors.Is(err, transform.ErrLimit) || out != nil {
				t.Fatalf("XSLT foreign document exceeded consumer policy: %v, %v", out, err)
			}

			params := transform.Bindings{{Local: "source"}: transform.Values(d.Root())}
			if out, err := s.Transform(ctx, nil, transform.XSLTContext{Parameters: params}); !errors.Is(err, transform.ErrLimit) || out != nil {
				t.Fatalf("XSLT parameter exceeded consumer policy: %v, %v", out, err)
			}
		})
	}
}

func TestXPathContextItemSetsNodeFocus(t *testing.T) {
	ctx := context.Background()
	e := engine(t, transform.Config{})

	a, err := e.Parse(ctx, []byte(`<a><child/></a>`))
	if err != nil {
		t.Fatal(err)
	}

	b, err := e.Parse(ctx, []byte(`<b/>`))
	if err != nil {
		t.Fatal(err)
	}

	for _, version := range []transform.XPathVersion{transform.XPath10, transform.XPath20, transform.XPath30, transform.XPath31} {
		q := query(t, e, `name(/*)`, version)
		for _, fallback := range []*transform.Document{nil, b} {
			out, err := q.Evaluate(ctx, fallback, transform.XPathContext{ContextItem: a.Root()})
			if err != nil || text(t, out) != "a" {
				t.Fatalf("version=%d, context root lost: %v, %v", version, out, err)
			}
		}
	}
}

func TestXPathAtomicContextRejectsNodeAxes(t *testing.T) {
	e := engine(t, transform.Config{})
	for _, source := range []string{`/`, `/*`, `child::*`} {
		_, err := query(t, e, source, transform.XPath31).Evaluate(context.Background(), nil, transform.XPathContext{ContextItem: transform.Integer(1)})

		var detail *transform.Error
		if !errors.As(err, &detail) || detail.Code != "XPTY0020" {
			t.Fatalf("%s: got %v, want XPTY0020", source, err)
		}
	}
}

func TestImportChecksDecodedInputBudget(t *testing.T) {
	ctx := context.Background()

	input := []byte{0xff, 0xfe}
	for _, u := range utf16.Encode([]rune(`<r>` + strings.Repeat("中", 100) + `</r>`)) {
		input = binary.LittleEndian.AppendUint16(input, u)
	}

	d, err := document.Parse(ctx, input, document.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}

	e := engine(t, transform.Config{Limits: transform.Limits{MaxInputBytes: len(input)}})
	if _, err := e.Import(ctx, d); !errors.Is(err, transform.ErrLimit) {
		t.Fatalf("decoded input budget lost during import: %v", err)
	}
}
