package consumer_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"runtime"
	"runtime/debug"
	"strings"
	"testing"
	"time"

	"github.com/skarm/xmlsec/c14n"
	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/reference"
	"github.com/skarm/xmlsec/transform"
)

func TestXMLSchemaLexicalContracts(t *testing.T) {
	engine := newEngine(t, transform.Config{})
	for _, tc := range []struct{ expression, want string }{
		{`'0x1p0' castable as xs:double`, "false"},
		{`'1_000' castable as xs:float`, "false"},
		{`xs:double('1e400')`, "INF"},
		{`xs:float('1.00000005960464477539062500000000001') gt 1`, "true"},
		{"'\u00a01\u00a0' castable as xs:integer", "false"},
		{`xs:normalizedString('  x  ')`, "  x  "},
		{"contains-token('\u00a0x\u00a0', '\u00a0x\u00a0')", "true"},
		{"count(xs:NMTOKENS('a\u1680b'))", "1"},
		{`year-from-dateTime(parse-ietf-date('06 Jun 0070 07:29:35 GMT'))`, "70"},
	} {
		query, err := engine.CompileXPath(t.Context(), tc.expression, transform.XPathOptions{})
		if err != nil {
			t.Fatal(err)
		}
		result, err := query.Evaluate(t.Context(), nil, transform.XPathContext{})
		if err != nil {
			t.Fatal(err)
		}
		got, err := result.Text()
		if err != nil || got != tc.want {
			t.Errorf("%s: %q, %v; want %q", tc.expression, got, err, tc.want)
		}
	}
}

func TestUnicodeCollationPoolsReleaseInputs(t *testing.T) {
	const inputVariable = "input"

	for _, tc := range []struct{ name, expression, options string }{
		{"Compare", `compare($input, 'c', $uri)`, "strength=primary"},
		{"Key", `collation-key($input, $uri)`, "strength=primary"},
		{"CaseFirstKey", `collation-key($input, $uri)`, "caseFirst=upper"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			engine := newEngine(t, transform.Config{})

			query, err := engine.CompileXPath(t.Context(), tc.expression, transform.XPathOptions{})
			if err != nil {
				t.Fatal(err)
			}

			runtime.GC()
			runtime.GC()
			// One forced collection tests idle pool retention. Automatic GC is
			// disabled temporarily: two collections would erase a sync.Pool's
			// victims and conceal its retained input references.
			previous := debug.SetGCPercent(-1)
			defer debug.SetGCPercent(previous)

			var before, after runtime.MemStats
			runtime.ReadMemStats(&before)

			for i := range 8 {
				source := "b" + strings.Repeat("x", 2<<20)
				uri := fmt.Sprintf("http://www.w3.org/2013/collation/UCA?%s;unused=%d", tc.options, i)

				result, err := query.Evaluate(t.Context(), nil, transform.XPathContext{Variables: transform.Bindings{
					{Local: inputVariable}: transform.Values(transform.String(source[:1])),
					{Local: "uri"}:         transform.Values(transform.String(uri)),
				}})
				if err != nil || result.Len() != 1 {
					t.Fatal("collation changed", err)
				}

				if tc.name == "Compare" {
					value, err := result.Single()
					if err != nil {
						t.Fatal(err)
					}

					number, err := value.Integer()
					if err != nil || number.Sign() >= 0 {
						t.Fatal("comparison order changed", err)
					}
				}
			}

			runtime.GC()
			runtime.ReadMemStats(&after)
			runtime.KeepAlive(query)

			retained := int64(after.HeapAlloc) - int64(before.HeapAlloc)
			t.Logf("eight warm collation pools: %d retained bytes", retained)

			if retained > 4<<20 {
				t.Fatalf("idle collators retained caller buffers: %d bytes", retained)
			}
		})
	}
}

func TestRegexCacheMemoryPlateausAcrossCalls(t *testing.T) {
	engine := newEngine(t, transform.Config{})

	query, err := engine.CompileXPath(t.Context(), `matches('', $pattern, 'q')`, transform.XPathOptions{})
	if err != nil {
		t.Fatal(err)
	}

	for batch := range 2 {
		retained := retainedHeapDuring(t, func() any {
			for i := range 128 {
				source := fmt.Sprintf("%d/%d/", batch, i) + strings.Repeat("x", 32<<10)

				result, err := query.Evaluate(t.Context(), nil, transform.XPathContext{Variables: transform.Bindings{{Local: "pattern"}: transform.Values(transform.String(source))}})
				if err != nil {
					t.Fatal(err)
				}

				matched, err := result.EffectiveBoolean()
				if err != nil || matched {
					t.Fatal("literal regex changed", err)
				}
			}

			return query
		})
		t.Logf("regex batch %d: %d additional retained bytes", batch, retained)

		if retained > 12<<20 {
			t.Fatalf("regex cache grew with a new batch: %d bytes", retained)
		}
	}

	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	if _, err := query.Evaluate(ctx, nil, transform.XPathContext{}); !errors.Is(err, context.Canceled) {
		t.Fatal("warm cache bypassed cancellation", err)
	}

	runtime.KeepAlive(query)
}

func TestXPathSmallValuesReleaseLargeSources(t *testing.T) {
	for _, tc := range []struct{ name, query, prefix, fill, suffix, want string }{
		{"Before", `substring-before($input, '|')`, "small|", "x", "", "small"},
		{"After", `substring-after($input, '|')`, "", "x", "|small", "small"},
		{"Substring", `substring($input, 1, 5)`, "small", "x", "", "small"},
		{"NormalizeOne", `normalize-space($input)`, "", " ", "small", "small"},
		{"NormalizeMany", `normalize-space($input)`, "a", " ", "b", "a b"},
		{"Tokenize", `head(tokenize($input))`, "small", " ", "", "small"},
		{"RegexTokenize", `head(tokenize($input, '\|'))`, "small|", "x", "", "small"},
		{"Token", `xs:token($input)`, "a", " ", "b", "a b"},
		{"TokenList", `head(xs:NMTOKENS($input))`, "small", " ", "", "small"},
		{"TrimmedCast", `xs:gYear($input)`, "", " ", "2026", "2026"},
		{"QNamePart", `local-name-from-QName(QName('urn:test', $input))`, "", "x", ":small", "small"},
		{"QNameConstructor", `local-name-from-QName(xs:QName($input))`, "", " ", "small", "small"},
		{"QNameCast", `local-name-from-QName($input cast as xs:QName)`, "", " ", "small", "small"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			engine := newEngine(t, transform.Config{Limits: transform.Limits{MaxOperations: 100_000_000}})
			query, err := engine.CompileXPath(t.Context(), tc.query, transform.XPathOptions{})
			if err != nil {
				t.Fatal(err)
			}
			retained := retainedHeapDuring(t, func() any {
				results := make([]transform.Sequence, 8)
				for i := range results {
					source := tc.prefix + strings.Repeat(tc.fill, 1<<20) + tc.suffix
					if tc.name == "RegexTokenize" {
						source = source[:len(tc.prefix)]
					}
					result, err := query.Evaluate(t.Context(), nil, transform.XPathContext{Variables: transform.Bindings{{Local: "input"}: transform.Values(transform.String(source))}})
					if err != nil {
						t.Fatal(err)
					}
					actual, err := result.Text()
					if err != nil || actual != tc.want {
						t.Fatalf("result: %.80q, %v", actual, err)
					}
					results[i] = result
				}
				return results
			})
			t.Logf("eight small results: %d retained heap bytes", retained)
			if retained > 2<<20 {
				t.Fatalf("small results retained their 8 MiB sources: %d bytes", retained)
			}
			runtime.KeepAlive(query)
		})
	}
}

func TestXPathLiteralReleasesProgramSource(t *testing.T) {
	engine := newEngine(t, transform.Config{Limits: transform.Limits{MaxProgramBytes: 3 << 20}})
	retained := retainedHeapDuring(t, func() any {
		results := make([]transform.Sequence, 8)
		for i := range results {
			source := "(:" + strings.Repeat("x", 1<<20) + ":) 'small'"
			query, err := engine.CompileXPath(t.Context(), source, transform.XPathOptions{})
			if err != nil {
				t.Fatal(err)
			}
			results[i], err = query.Evaluate(t.Context(), nil, transform.XPathContext{})
			if err != nil {
				t.Fatal(err)
			}
			if actual, err := results[i].Text(); err != nil || actual != "small" {
				t.Fatal(actual, err)
			}
		}
		return results
	})
	t.Logf("eight literals: %d retained heap bytes", retained)
	if retained > 2<<20 {
		t.Fatalf("literal values retained discarded programs: %d bytes", retained)
	}
}

func TestXPathPeakWorkingHeap(t *testing.T) {
	const size = 8 << 20
	for _, tc := range []struct{ name, query, source, want string }{
		{"Substring", `substring($input, 8388608, 1)`, strings.Repeat("x", size), "x"},
		{"Token", `xs:token($input)`, "a" + strings.Repeat(" ", size) + "b", "a b"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			engine := newEngine(t, transform.Config{Limits: transform.Limits{MaxInputBytes: size + 1024, MaxOutputBytes: size + 1024}})
			query, err := engine.CompileXPath(t.Context(), tc.query, transform.XPathOptions{})
			if err != nil {
				t.Fatal(err)
			}
			input := transform.XPathContext{Variables: transform.Bindings{{Local: "input"}: transform.Values(transform.String(tc.source))}}
			peak := peakHeapDuring(t, func() error {
				result, err := query.Evaluate(t.Context(), nil, input)
				if err != nil {
					return err
				}
				actual, err := result.Text()
				if err != nil || actual != tc.want {
					return fmt.Errorf("result: %q, %v", actual, err)
				}
				return nil
			})
			runtime.KeepAlive(input)
			t.Logf("8 MiB source, observed peak heap growth: %d bytes", peak)
			if peak > 4<<20 {
				t.Fatalf("source-sized temporary storage: %d bytes", peak)
			}
		})
	}
	t.Run("CommentHeavyProgram", func(t *testing.T) {
		engine := newEngine(t, transform.Config{Limits: transform.Limits{MaxProgramBytes: 3 << 20}})
		source := "(:" + strings.Repeat("x", 2<<20) + ":) 'small'"
		var query *transform.XPath
		peak := peakHeapDuring(t, func() error {
			var err error
			query, err = engine.CompileXPath(t.Context(), source, transform.XPathOptions{})
			return err
		})
		runtime.KeepAlive(source)
		runtime.KeepAlive(query)
		t.Logf("2 MiB comment, observed peak heap growth: %d bytes", peak)
		if peak > 2<<20 {
			t.Fatalf("source-sized token reservation: %d bytes", peak)
		}
	})
}

func TestXPathHandlesComposeWithCanonicalization(t *testing.T) {
	ctx := context.Background()
	original, err := document.Parse(ctx, []byte(`<r><n b="2" a="1">value</n><n>other</n></r>`), document.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	e := newEngine(t, transform.Config{})
	d, err := e.Import(ctx, original)
	if err != nil {
		t.Fatal(err)
	}
	exported, err := e.Export(ctx, d)
	if err != nil || exported != original {
		t.Fatalf("snapshot identity: %p != %p: %v", exported, original, err)
	}
	q, err := e.CompileXPath(ctx, `/r/n[1]`, transform.XPathOptions{})
	if err != nil {
		t.Fatal(err)
	}
	result, err := q.Evaluate(ctx, d, transform.XPathContext{})
	if err != nil {
		t.Fatal(err)
	}
	value, err := result.Single()
	if err != nil {
		t.Fatal(err)
	}
	node, ok := value.Node()
	if !ok || node.Reference().Document() != original {
		t.Fatal("foreign XPath handle")
	}
	element, ok := node.Reference().Element()
	if !ok {
		t.Fatal("expected an element")
	}
	var output bytes.Buffer
	if err := c14n.WriteElement(ctx, &output, element, c14n.Options{}); err != nil {
		t.Fatal(err)
	}
	if output.String() != `<n a="1" b="2">value</n>` {
		t.Fatal(output.String())
	}
	imported, err := e.ImportNode(ctx, node.Reference())
	if err != nil {
		t.Fatal(err)
	}
	again, ok := imported.Node()
	if !ok || !again.Reference().Same(node.Reference()) {
		t.Fatal("node identity changed")
	}
}

func TestSortPropagatesAtomizationErrors(t *testing.T) {
	e := newEngine(t, transform.Config{})
	for _, source := range []string{`sort(map{})`, `sort((map{}, map{}))`, `sort((1,2),(),function($x){map{}})`, `sort(1,(),function($x){map{}})`} {
		q, err := e.CompileXPath(t.Context(), source, transform.XPathOptions{})
		if err != nil {
			t.Fatal(err)
		}
		_, err = q.Evaluate(t.Context(), nil, transform.XPathContext{})
		var coded *transform.Error
		if !errors.As(err, &coded) || coded.Code != "FOTY0013" {
			t.Errorf("%s: %v", source, err)
		}
	}
}

func TestFailedIntegerCastsPreserveInputType(t *testing.T) {
	e := newEngine(t, transform.Config{})
	for _, tc := range []struct{ source, diagnostic string }{
		{`format-integer('bad', '1')`, "cannot cast xs:string to xs:integer"},
		{`[1]?(xs:untypedAtomic('bad'))`, "got xs:untypedAtomic"},
	} {
		q, err := e.CompileXPath(t.Context(), tc.source, transform.XPathOptions{})
		if err != nil {
			t.Fatal(err)
		}
		_, err = q.Evaluate(t.Context(), nil, transform.XPathContext{})
		var coded *transform.Error
		if !errors.As(err, &coded) || coded.Code != "XPTY0004" || !strings.Contains(err.Error(), tc.diagnostic) {
			t.Errorf("%s: %v", tc.source, err)
		}
	}
}

func TestIntegerDivisionOverflowReturnsError(t *testing.T) {
	e := newEngine(t, transform.Config{})
	for _, source := range []string{`1e308 idiv 1e-308`, `-1e308 idiv 1e-308`} {
		q, err := e.CompileXPath(t.Context(), source, transform.XPathOptions{})
		if err != nil {
			t.Fatal(err)
		}
		result, err := q.Evaluate(t.Context(), nil, transform.XPathContext{})
		var coded *transform.Error
		if result.Len() != 0 || !errors.As(err, &coded) || coded.Code != "FOAR0002" {
			t.Errorf("%s: %v / %v", source, result, err)
		}
	}
}

func TestSubsequenceRoundsNegativeTiesTowardPositiveInfinity(t *testing.T) {
	e := newEngine(t, transform.Config{})
	for _, version := range []transform.XPathVersion{transform.XPath20, transform.XPath30, transform.XPath31} {
		for _, tc := range []struct{ expr, want string }{
			{`subsequence((1,2,3), -1.5, 3)`, "1"},
			{`subsequence((1,2,3), -0.5, 2)`, "1"},
			{`subsequence((1,2,3), -1.50001, 3)`, ""},
			{`subsequence((1,2,3), 1.5, 2)`, "2 3"},
			{`subsequence((1,2,3), xs:double('NaN'), 3)`, ""},
			{`subsequence((1,2,3), xs:double('-INF'), xs:double('INF'))`, ""},
		} {
			q, err := e.CompileXPath(t.Context(), `string-join((for $x in (`+tc.expr+`) return string($x)), " ")`, transform.XPathOptions{Version: version})
			if err != nil {
				t.Fatal(err)
			}
			seq, err := q.Evaluate(t.Context(), nil, transform.XPathContext{})
			if err != nil {
				t.Fatal(err)
			}
			got, err := seq.Text()
			if err != nil || got != tc.want {
				t.Errorf("v%d %s: got %q, %v; want %q", version, tc.expr, got, err, tc.want)
			}
		}
	}
}

func TestXPathSortUsesDefaultCollation(t *testing.T) {
	e := newEngine(t, transform.Config{})
	const collation = "http://www.w3.org/2005/xpath-functions/collation/html-ascii-case-insensitive"
	for _, expr := range []string{`sort(('a','B'))`, `sort(('a','B'),())`, `array:flatten(array:sort(['a','B']))`, `array:flatten(array:sort(['a','B'],()))`} {
		q, err := e.CompileXPath(t.Context(), `string-join(`+expr+`,',')`, transform.XPathOptions{DefaultCollation: collation})
		if err != nil {
			t.Fatal(err)
		}
		seq, err := q.Evaluate(t.Context(), nil, transform.XPathContext{})
		if err != nil {
			t.Fatal(err)
		}
		got, err := seq.Text()
		if err != nil || got != "a,B" {
			t.Errorf("%s: got %q, %v", expr, got, err)
		}
	}
}

func TestXPathSortOrdersNaNBeforeNumbers(t *testing.T) {
	e := newEngine(t, transform.Config{})
	for _, expr := range []string{`sort((1,xs:double('NaN'),0,xs:float('NaN')))`, `array:flatten(array:sort([1,xs:double('NaN'),0,xs:float('NaN')]))`} {
		q, err := e.CompileXPath(t.Context(), `string-join((`+expr+`)!string(.),',')`, transform.XPathOptions{})
		if err != nil {
			t.Fatal(err)
		}
		seq, err := q.Evaluate(t.Context(), nil, transform.XPathContext{})
		if err != nil {
			t.Fatal(err)
		}
		got, err := seq.Text()
		if err != nil || got != "NaN,NaN,0,1" {
			t.Errorf("%s: got %q, %v", expr, got, err)
		}
	}
}

func TestXPathSortUsesImplicitTimezone(t *testing.T) {
	e := newEngine(t, transform.Config{})
	for _, expr := range []string{`sort((xs:dateTime('2026-01-01T01:00:00'),xs:dateTime('2026-01-01T00:00:00Z')))`, `array:flatten(array:sort([xs:dateTime('2026-01-01T01:00:00'),xs:dateTime('2026-01-01T00:00:00Z')]))`} {
		q, err := e.CompileXPath(t.Context(), `string-join((`+expr+`)!string(.),',')`, transform.XPathOptions{})
		if err != nil {
			t.Fatal(err)
		}
		for _, tc := range []struct {
			offset int
			want   string
		}{
			{-7200, "2026-01-01T00:00:00Z,2026-01-01T01:00:00"},
			{7200, "2026-01-01T01:00:00,2026-01-01T00:00:00Z"},
		} {
			seq, err := q.Evaluate(t.Context(), nil, transform.XPathContext{Context: transform.DynamicContext{ImplicitTimezone: time.FixedZone("test", tc.offset)}})
			if err != nil {
				t.Fatal(err)
			}
			got, err := seq.Text()
			if err != nil || got != tc.want {
				t.Errorf("%s at %d: got %q, %v; want %q", expr, tc.offset, got, err, tc.want)
			}
		}
	}
}

func TestArraySortValidatesSingletonCallbackKey(t *testing.T) {
	e := newEngine(t, transform.Config{})
	q, err := e.CompileXPath(t.Context(), `array:sort([1],(),function($v){map{'bad':1}})`, transform.XPathOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if result, err := q.Evaluate(t.Context(), nil, transform.XPathContext{}); err == nil {
		t.Fatalf("invalid key accepted: %v", result)
	}
}

func TestOptionalXPathAnalysis(t *testing.T) {
	e := newEngine(t, transform.Config{})
	q, err := e.CompileXPath(t.Context(), `let $f := string#1 return (count(/r/a[child::b]), $f(.))`, transform.XPathOptions{})
	if err != nil {
		t.Fatal(err)
	}
	a, err := q.Analyze(t.Context())
	if err != nil || !a.ContextItem || !a.DynamicCalls || !a.NonMotionlessPredicates || a.DownwardSelections == 0 {
		t.Fatalf("analysis: %#v, %v", a, err)
	}
	if len(a.Functions) != 2 || a.Functions[0].Name != (document.Name{Space: "http://www.w3.org/2005/xpath-functions", Local: "count"}) {
		t.Fatal(a.Functions)
	}
	a.Functions[0].Name.Local = "changed"
	again, err := q.Analyze(t.Context())
	if err != nil || again.Functions[0].Name.Local != "count" {
		t.Fatal(again, err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := q.Analyze(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	limited := newEngine(t, transform.Config{Limits: transform.Limits{MaxOperations: 1}})
	program, err := limited.CompileXPath(t.Context(), `concat('a','b','c')`, transform.XPathOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := program.Analyze(t.Context()); !errors.Is(err, transform.ErrLimit) {
		t.Fatal(err)
	}
}

func TestApplicationFunctionsKeepXMLDSigPolicySeparate(t *testing.T) {
	fn := transform.Function{Name: document.Name{Space: "urn:app", Local: "allowed"}, Call: func(context.Context, []transform.Sequence) (transform.Sequence, error) {
		return transform.Values(transform.Boolean(true)), nil
	}}
	_, err := transform.NewEngine(transform.Config{Functions: []transform.Function{fn}, AllowedPrograms: []reference.Transform{{Algorithm: reference.XPath, XPath: []reference.XPathExpression{{Expression: "app:allowed()", Namespaces: map[string]string{"app": "urn:app"}}}}}})
	if err == nil {
		t.Fatal("standalone registry enabled an XMLDSig extension function")
	}
}

func TestXPathXMLParsingUsesReaderStorage(t *testing.T) {
	engine := newEngine(t, transform.Config{})
	text := strings.Repeat("x", 1<<20)
	for _, fragment := range []bool{false, true} {
		t.Run(fmt.Sprint(fragment), func(t *testing.T) {
			source := "<r>" + text + "</r>"
			expression := `parse-xml($xml)`
			if fragment {
				source = text
				expression = `parse-xml-fragment($xml)`
			}
			query, err := engine.CompileXPath(t.Context(), expression, transform.XPathOptions{})
			if err != nil {
				t.Fatal(err)
			}
			baseline := allocatedDuring(t, func() error {
				_, err := engine.ParseReader(t.Context(), io.MultiReader(strings.NewReader("<r>"), strings.NewReader(text), strings.NewReader("</r>")))
				return err
			})
			options := transform.XPathContext{Variables: transform.Bindings{{Local: "xml"}: transform.Values(transform.String(source))}}
			allocated := allocatedDuring(t, func() error {
				result, err := query.Evaluate(t.Context(), nil, options)
				if err != nil {
					return err
				}
				if value, err := result.Text(); err != nil || value != text {
					return fmt.Errorf("XML value changed: %v", err)
				}
				return nil
			})
			t.Logf("XML: %d allocated; parser baseline: %d", allocated, baseline)
			if allocated > baseline+256<<10 {
				t.Fatalf("XML allocated %d bytes; parser baseline %d", allocated, baseline)
			}
		})
	}
}

func TestImmutableValueAccessDoesNotCopyMembers(t *testing.T) {
	values := make([]transform.Value, 8192)
	for i := range values {
		values[i] = transform.Integer(int64(i))
	}
	sequence := transform.Values(values...)
	array := transform.Array(sequence)
	mapping, err := transform.Map(transform.MapEntry{Key: transform.String("items"), Value: sequence})
	if err != nil {
		t.Fatal(err)
	}
	allocated := allocatedDuring(t, func() error {
		for range 8 {
			member, err := array.Member(0)
			if err != nil {
				return err
			}
			entry, ok := mapping.Lookup(transform.String("items"))
			if !ok || member.Len() != len(values) || entry.Len() != len(values) {
				return errors.New("member changed")
			}
			last, _ := entry.At(len(values) - 1)
			number, err := last.Integer()
			if err != nil {
				return err
			}
			number.SetInt64(-1)
		}
		return nil
	})
	if allocated > 16<<10 {
		t.Fatalf("immutable member access copied %d bytes", allocated)
	}
	entry, _ := mapping.Lookup(transform.String("items"))
	last, _ := entry.At(len(values) - 1)
	number, err := last.Integer()
	if err != nil || number.Int64() != int64(len(values)-1) {
		t.Fatal(number, err)
	}

	engine := newEngine(t, transform.Config{Limits: transform.Limits{MaxNodes: 8}})
	query, err := engine.CompileXPath(t.Context(), `$value`, transform.XPathOptions{})
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range []transform.Value{array, mapping} {
		allocated := allocatedDuring(t, func() error {
			_, err := query.Evaluate(t.Context(), nil, transform.XPathContext{Variables: transform.Bindings{{Local: "value"}: transform.Values(value)}})
			if !errors.Is(err, transform.ErrLimit) {
				return fmt.Errorf("nested limit: %w", err)
			}
			return nil
		})
		if allocated > 32<<10 {
			t.Fatalf("nested value copied %d bytes before rejection", allocated)
		}
	}
}

func TestExactNormalizationPublicAPI(t *testing.T) {
	e := newEngine(t, transform.Config{})
	input := "a" + strings.Repeat("\u0315", 63) + "\u0300\u034f\u0301"
	want := "à" + strings.Repeat("\u0315", 63) + "\u034f\u0301"
	for _, expression := range []string{`normalize-unicode($input)`, `serialize($input,map{'method':'text','normalization-form':'NFC'})`} {
		query, err := e.CompileXPath(t.Context(), expression, transform.XPathOptions{})
		if err != nil {
			t.Fatal(err)
		}
		result, err := query.Evaluate(t.Context(), nil, transform.XPathContext{Variables: transform.Bindings{{Local: "input"}: transform.Values(transform.String(input))}})
		if err != nil {
			t.Fatal(err)
		}
		got, err := result.Text()
		if err != nil || got != want {
			t.Fatal("exact normalization", err)
		}
	}
}
