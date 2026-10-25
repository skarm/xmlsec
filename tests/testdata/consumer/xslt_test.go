package consumer_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/transform"
)

const returnedFunctionTemplate = "start"

func TestReturnedXSLTFunctionsReleaseInvocationCaches(t *testing.T) {
	const inputVariable = "input"

	engine := newEngine(t, transform.Config{})
	sheet := compileSheet(t, engine, `<xsl:param name="suffix" select="'!'"/><xsl:function name="f:work" cache="yes"><xsl:param name="input"/><xsl:sequence select="concat(substring-before($input, '|'), $suffix)"/></xsl:function><xsl:template name="start"><xsl:sequence select="f:work#1"/></xsl:template>`)

	created, err := sheet.CallTemplate(t.Context(), nil, document.Name{Local: returnedFunctionTemplate}, transform.XSLTContext{})
	if err != nil {
		t.Fatal(err)
	}

	function := created.Primary()

	query, err := engine.CompileXPath(t.Context(), `$f($input)`, transform.XPathOptions{})
	if err != nil {
		t.Fatal(err)
	}

	for batch := range 2 {
		retained := retainedHeapDuring(t, func() any {
			for i := range 16 {
				source := fmt.Sprintf("small|%d/%d/", batch, i) + strings.Repeat("x", 1<<20)

				result, err := query.Evaluate(t.Context(), nil, transform.XPathContext{Variables: transform.Bindings{{Local: "f"}: function, {Local: inputVariable}: transform.Values(transform.String(source))}})
				if err != nil {
					t.Fatal(err)
				}

				if actual, err := result.Text(); err != nil || actual != "small!" {
					t.Fatal("captured global/result changed", actual, err)
				}
			}

			return function
		})
		t.Logf("escaped XSLT function batch %d: %d retained bytes", batch, retained)

		if retained > 4<<20 {
			t.Fatalf("function accumulated invocation caches: %d bytes", retained)
		}
	}

	var wg sync.WaitGroup
	for range 16 {
		wg.Go(func() {
			result, err := query.Evaluate(t.Context(), nil, transform.XPathContext{Variables: transform.Bindings{{Local: "f"}: function, {Local: inputVariable}: transform.Values(transform.String("small|parallel"))}})
			if err != nil {
				t.Error(err)
				return
			}

			if actual, err := result.Text(); err != nil || actual != "small!" {
				t.Error("concurrent function changed", actual, err)
			}
		})
	}

	wg.Wait()

	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	if _, err := query.Evaluate(ctx, nil, transform.XPathContext{Variables: transform.Bindings{{Local: "f"}: function}}); !errors.Is(err, context.Canceled) {
		t.Fatal("escaped function ignored cancellation", err)
	}

	runtime.KeepAlive(function)
}

func TestReturnedXSLTFunctionIdentityAndBudget(t *testing.T) {
	for _, outputLimit := range []int{128, 8192} {
		engine := newEngine(t, transform.Config{Limits: transform.Limits{MaxOutputBytes: outputLimit}})
		sheet := compileSheet(t, engine, `<xsl:function name="f:node" new-each-time="no"><xsl:param name="n"/><r><xsl:text>`+strings.Repeat("x", 4096)+`</xsl:text></r></xsl:function><xsl:template name="start"><xsl:sequence select="f:node#1"/></xsl:template>`)

		created, err := sheet.CallTemplate(t.Context(), nil, document.Name{Local: returnedFunctionTemplate}, transform.XSLTContext{})
		if err != nil {
			t.Fatal(err)
		}

		query, err := engine.CompileXPath(t.Context(), `$f(1) is $f(1)`, transform.XPathOptions{})
		if err != nil {
			t.Fatal(err)
		}

		for range 2 {
			result, err := query.Evaluate(t.Context(), nil, transform.XPathContext{Variables: transform.Bindings{{Local: "f"}: created.Primary()}})
			if outputLimit == 128 {
				if !errors.Is(err, transform.ErrLimit) || result.Len() != 0 {
					t.Fatal("function bypassed caller output budget", err)
				}

				continue
			}

			if err != nil {
				t.Fatal(err)
			}

			identical, err := result.EffectiveBoolean()
			if err != nil || !identical {
				t.Fatal("new-each-time=no identity lost within invocation", err)
			}
		}
	}
}

func TestReturnedXSLTFunctionChainsReleaseCaches(t *testing.T) {
	for _, expression := range []string{`f:next#1`, `function-lookup(QName('urn:functions', 'f:next'), 1)`, `f:next(?)`, `(f:next#1)(?)`} {
		t.Run(expression, func(t *testing.T) {
			engine := newEngine(t, transform.Config{})
			sheet := compileSheet(t, engine, `<xsl:function name="f:next" cache="yes"><xsl:param name="value"/><xsl:sequence select="`+expression+`"/></xsl:function><xsl:template name="start"><xsl:sequence select="f:next#1"/></xsl:template>`)

			created, err := sheet.CallTemplate(t.Context(), nil, document.Name{Local: returnedFunctionTemplate}, transform.XSLTContext{})
			if err != nil {
				t.Fatal(err)
			}

			function := created.Primary()

			query, err := engine.CompileXPath(t.Context(), `$f($payload)`, transform.XPathOptions{})
			if err != nil {
				t.Fatal(err)
			}

			for batch := range 2 {
				retained := retainedHeapDuring(t, func() any {
					for i := range 16 {
						source := fmt.Sprintf("%d/%d/", batch, i) + strings.Repeat("x", 1<<20)

						next, err := query.Evaluate(t.Context(), nil, transform.XPathContext{Variables: transform.Bindings{{Local: "f"}: function, {Local: "payload"}: transform.Values(transform.String(source))}})
						if err != nil || next.Len() != 1 {
							t.Fatal("function chain changed", err)
						}

						function = next
					}

					return function
				})
				t.Logf("returned-function chain batch %d: %d retained bytes", batch, retained)

				if retained > 4<<20 {
					t.Fatalf("function chain retained prior invocations: %d bytes", retained)
				}
			}

			runtime.KeepAlive(function)
		})
	}
}

func TestReturnedXSLTFunctionArgumentConversion(t *testing.T) {
	for _, expression := range []string{`f:convert#1`, `function-lookup(QName('urn:functions', 'f:convert'), 1)`, `f:convert(?)`} {
		engine := newEngine(t, transform.Config{})
		sheet := compileSheet(t, engine, `<xsl:function name="f:convert" as="xs:double"><xsl:param name="value" as="xs:double"/><xsl:sequence select="$value"/></xsl:function><xsl:function name="f:convert"><xsl:param name="a"/><xsl:param name="b"/><xsl:sequence select="$a+$b"/></xsl:function><xsl:template name="start"><xsl:sequence select="`+expression+`"/></xsl:template>`)

		created, err := sheet.CallTemplate(t.Context(), nil, document.Name{Local: returnedFunctionTemplate}, transform.XSLTContext{})
		if err != nil {
			t.Fatal(err)
		}

		query, err := engine.CompileXPath(t.Context(), `$f(1) instance of xs:double`, transform.XPathOptions{})
		if err != nil {
			t.Fatal(err)
		}

		result, err := query.Evaluate(t.Context(), nil, transform.XPathContext{Variables: transform.Bindings{{Local: "f"}: created.Primary()}})
		if err != nil {
			t.Fatal(expression, err)
		}

		converted, err := result.EffectiveBoolean()
		if err != nil || !converted {
			t.Fatal("function argument promotion lost", expression, err)
		}
	}
}

func TestTypedXSLTEntries(t *testing.T) {
	ctx := t.Context()
	e := newEngine(t, transform.Config{})
	s := compileSheet(t, e, `<xsl:param name="global" select="1"/><xsl:template name="start"><xsl:param name="local" required="yes"/><xsl:param name="tunnel" tunnel="yes" required="yes"/><a/><xsl:sequence select="$local+$tunnel+$global"/><b/><xsl:sequence select="map{'answer':42}"/></xsl:template><xsl:function name="f:double" visibility="public"><xsl:param name="n"/><xsl:sequence select="$n*2"/></xsl:function>`)
	r, err := s.CallTemplate(ctx, nil, document.Name{Local: "start"}, transform.XSLTContext{Parameters: transform.Bindings{{Local: "global"}: transform.Values(transform.Integer(2))}, InitialParameters: transform.Bindings{{Local: "local"}: transform.Values(transform.Integer(3))}, TunnelParameters: transform.Bindings{{Local: "tunnel"}: transform.Values(transform.Integer(4))}})
	if err != nil {
		t.Fatal(err)
	}
	seq := r.Primary()
	if seq.Len() != 4 {
		t.Fatalf("sequence length: %d", seq.Len())
	}
	first, _ := seq.At(0)
	third, _ := seq.At(2)
	a, _ := first.Node()
	b, _ := third.Node()
	if a.Name().Local != "a" || b.Name().Local != "b" {
		t.Fatal("node order lost")
	}
	second, _ := seq.At(1)
	n, err := second.Integer()
	if err != nil || n.Int64() != 9 {
		t.Fatal(n, err)
	}
	fourth, _ := seq.At(3)
	member, ok := fourth.Lookup(transform.String("answer"))
	if !ok || member.Len() != 1 {
		t.Fatal("map type lost")
	}
	f, err := s.CallFunction(ctx, nil, document.Name{Space: "urn:functions", Local: "double"}, []transform.Sequence{transform.Values(transform.Integer(21))}, transform.XSLTContext{})
	if err != nil {
		t.Fatal(err)
	}
	answer, err := f.Primary().Text()
	if err != nil || answer != "42" {
		t.Fatal(answer, err)
	}
}

func TestTypedResultDocumentAndEmptySelection(t *testing.T) {
	ctx := t.Context()
	e := newEngine(t, transform.Config{})
	s := compileSheet(t, e, `<xsl:template name="start"><r><n>42</n></r></xsl:template><xsl:template match="/"><unexpected/></xsl:template>`)
	r, err := s.CallTemplate(ctx, nil, document.Name{Local: "start"}, transform.XSLTContext{})
	if err != nil {
		t.Fatal(err)
	}
	d, err := r.Document(ctx)
	if err != nil {
		t.Fatal(err)
	}
	exported, err := e.Export(ctx, d)
	if err != nil {
		t.Fatal(err)
	}
	data, err := exported.XML(ctx)
	if err != nil || string(data) != `<r><n>42</n></r>` {
		t.Fatal(string(data), err)
	}
	serialized, err := r.Serialize(ctx)
	if err != nil || !bytes.Contains(serialized.Primary, []byte(`<r><n>42</n></r>`)) {
		t.Fatal(serialized, err)
	}
	empty, err := s.ApplyTemplates(ctx, d, transform.Values(), transform.XSLTContext{})
	if err != nil || empty.Primary().Len() != 0 {
		t.Fatal(empty, err)
	}
}

func TestMergePropagatesKeyAtomizationErrors(t *testing.T) {
	e := newEngine(t, transform.Config{})
	for _, tc := range []struct {
		key  string
		code string
	}{
		{`map{}`, "FOTY0013"},
		{`[1,2]`, "XTTE1020"},
	} {
		s := compileSheet(t, e, `<xsl:template name="start"><xsl:merge><xsl:merge-source select="1"><xsl:merge-key select="`+tc.key+`"/></xsl:merge-source><xsl:merge-action><xsl:sequence select="current-merge-key()"/></xsl:merge-action></xsl:merge></xsl:template>`)
		result, err := s.CallTemplate(t.Context(), nil, document.Name{Local: "start"}, transform.XSLTContext{})
		var coded *transform.Error
		if result != nil || !errors.As(err, &coded) || coded.Code != tc.code {
			t.Errorf("%s: %v / %v", tc.key, result, err)
		}
	}
}

func TestMergeAtomizesArrayKeys(t *testing.T) {
	e := newEngine(t, transform.Config{})
	s := compileSheet(t, e, `<xsl:template name="start"><xsl:merge><xsl:merge-source select="1"><xsl:merge-key select="[[2]]"/></xsl:merge-source><xsl:merge-action><xsl:sequence select="current-merge-key()"/></xsl:merge-action></xsl:merge></xsl:template>`)
	result, err := s.CallTemplate(t.Context(), nil, document.Name{Local: "start"}, transform.XSLTContext{})
	if err != nil {
		t.Fatal(err)
	}
	value, err := result.Primary().Single()
	if err != nil {
		t.Fatal(err)
	}
	integer, err := value.Integer()
	if err != nil {
		t.Fatal(err)
	}
	if integer.Int64() != 2 {
		t.Fatal(integer)
	}
}

func TestXSLTSortPreservesTypedPrecision(t *testing.T) {
	e := newEngine(t, transform.Config{})
	for _, tc := range []struct {
		name   string
		values string
		want   string
	}{
		{"integer", `(9007199254740993,9007199254740992)`, "9007199254740992;9007199254740993;"},
		{"decimal", `(1.00000000000000000002,1.00000000000000000001)`, "1.00000000000000000001;1.00000000000000000002;"},
		{"dateTime", `(xs:dateTime('2026-01-01T00:00:00.000000002Z'),xs:dateTime('2026-01-01T00:00:00.000000001Z'))`, "2026-01-01T00:00:00.000000001Z;2026-01-01T00:00:00.000000002Z;"},
		{"promoteFloat", `(16777217,16777216,xs:float(0))`, "0;16777217;16777216;"},
		{"floatMidpoint", `(1.00000005960464477539062500000001,1.0,xs:float(0))`, "0;1;1.00000005960464477539062500000001;"},
		{"promoteDouble", `(9007199254740993,9007199254740992,xs:double(0))`, "0;9007199254740993;9007199254740992;"},
	} {
		for _, minor := range []struct {
			name        string
			instruction string
		}{{"single", ""}, {"multiple", `<xsl:sort select="0"/>`}} {
			for _, group := range []bool{false, true} {
				t.Run(tc.name+"/"+minor.name+"/group="+map[bool]string{false: "no", true: "yes"}[group], func(t *testing.T) {
					start, end, key := `<xsl:for-each select="`+tc.values+`">`, `</xsl:for-each>`, "."
					if group {
						start = `<xsl:for-each-group select="` + tc.values + `" group-by=".">`
						end = `</xsl:for-each-group>`
						key = "current-grouping-key()"
					}
					s := compileSheet(t, e, `<xsl:output method="text"/><xsl:template name="start">`+start+`<xsl:sort select="`+key+`"/>`+minor.instruction+`<xsl:value-of select="."/><xsl:text>;</xsl:text>`+end+`</xsl:template>`)
					out, err := s.Transform(t.Context(), nil, transform.XSLTContext{Template: transform.Name{Local: "start"}})
					if err != nil {
						t.Fatal(err)
					}
					if got := string(out.Primary); got != tc.want {
						t.Errorf("got %q; want %q", got, tc.want)
					}
				})
			}
		}
	}
}

func TestXSLTSortNodeKeysAndExplicitTypes(t *testing.T) {
	e := newEngine(t, transform.Config{})
	for _, tc := range []struct {
		name string
		keys string
		want string
	}{
		{"exact", `<xsl:sort select="xs:integer(@v)"/>`, "9007199254740992;9007199254740993;"},
		{"multiple", `<xsl:sort select="0"/><xsl:sort select="xs:integer(@v)"/>`, "9007199254740992;9007199254740993;"},
		{"descending", `<xsl:sort select="xs:integer(@v)" order="descending"/>`, "9007199254740993;9007199254740992;"},
		{"number", `<xsl:sort select="xs:integer(@v)" data-type="number"/>`, "9007199254740993;9007199254740992;"},
		{"text", `<xsl:sort select="xs:integer(@v)" data-type="text"/>`, "9007199254740992;9007199254740993;"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := compileSheet(t, e, `<xsl:output method="text"/><xsl:template name="start"><xsl:variable name="data"><n v="9007199254740993"/><n v="9007199254740992"/></xsl:variable><xsl:for-each select="$data/n">`+tc.keys+`<xsl:value-of select="@v"/><xsl:text>;</xsl:text></xsl:for-each></xsl:template>`)
			out, err := s.Transform(t.Context(), nil, transform.XSLTContext{Template: transform.Name{Local: "start"}})
			if err != nil {
				t.Fatal(err)
			}
			if got := string(out.Primary); got != tc.want {
				t.Errorf("got %q; want %q", got, tc.want)
			}
		})
	}
}

func TestPackageVersionsAndOverrides(t *testing.T) {
	const library = `<xsl:package xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:f="urn:library" name="urn:library" package-version="1.3.5" version="3.0"><xsl:function name="f:value" visibility="public"><xsl:sequence select="21"/></xsl:function></xsl:package>`
	resolver := transform.PackageResolverFunc(func(ctx context.Context, name, version string) (transform.PackageResource, error) {
		if ctx.Err() != nil {
			return transform.PackageResource{}, ctx.Err()
		}
		return transform.PackageResource{Reader: io.NopCloser(strings.NewReader(library)), BaseURI: "https://packages.test/library.xsl"}, nil
	})
	e := newEngine(t, transform.Config{PackageResolver: resolver})
	for _, version := range []string{"1.3.*", "1 to 1.3.*", "to 1.3.*", "1.3+", "1.0, 1.3.5"} {
		s := compileSheet(t, e, `<xsl:use-package name="urn:library" package-version="`+version+`"><xsl:override><xsl:function name="f:value" xmlns:f="urn:library"><xsl:sequence select="42"/></xsl:function></xsl:override></xsl:use-package><xsl:template name="start"><xsl:sequence select="Q{urn:library}value()"/></xsl:template>`)
		r, err := s.CallTemplate(t.Context(), nil, document.Name{Local: "start"}, transform.XSLTContext{})
		if err != nil {
			t.Fatal(version, err)
		}
		value, err := r.Primary().Text()
		if err != nil || value != "42" {
			t.Fatal(version, value, err)
		}
	}
	for _, version := range []string{"2.*", "1..3", "1+2", "*,1", "1 to"} {
		_, err := e.CompileXSLT(t.Context(), []byte(`<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="3.0"><xsl:use-package name="urn:library" package-version="`+version+`"/></xsl:stylesheet>`), transform.XSLTOptions{})
		if err == nil {
			t.Fatal("invalid or mismatched package accepted", version)
		}
	}
}

func TestPackageCyclesAndResourceLimits(t *testing.T) {
	const cyclic = `<xsl:package xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="3.0" name="urn:cycle" package-version="1"><xsl:use-package name="urn:cycle"/></xsl:package>`
	e := newEngine(t, transform.Config{PackageResolver: transform.PackageResolverFunc(func(context.Context, string, string) (transform.PackageResource, error) {
		return transform.PackageResource{Reader: io.NopCloser(strings.NewReader(cyclic))}, nil
	})})
	_, err := e.CompileXSLT(t.Context(), []byte(cyclic), transform.XSLTOptions{})
	var detail *transform.Error
	if !errors.As(err, &detail) || detail.Code != "XTSE3005" {
		t.Fatal(err)
	}
	for _, bounds := range []struct {
		limits transform.Limits
		loads  int
	}{
		{transform.Limits{MaxResources: 1}, 1},
		{transform.Limits{MaxResourceBytes: 2}, 2},
	} {
		loads := 0
		e = newEngine(t, transform.Config{Limits: bounds.limits, Resolver: transform.ResolverFunc(func(context.Context, string) (io.ReadCloser, error) {
			loads++
			return io.NopCloser(strings.NewReader("42")), nil
		})})
		q, err := e.CompileXPath(t.Context(), `unparsed-text('https://resources.test/a') || unparsed-text('https://resources.test/b')`, transform.XPathOptions{})
		if err != nil {
			t.Fatal(err)
		}
		if _, err = q.Evaluate(t.Context(), nil, transform.XPathContext{}); !errors.Is(err, transform.ErrLimit) || loads != bounds.loads {
			t.Fatal(loads, err)
		}
	}
}

func TestEvaluationCachesReleaseSourceBuffers(t *testing.T) {
	for _, test := range []struct {
		name       string
		expression string
		format     string
	}{
		{"Collation", `compare('a', 'b', $input)`, "http://www.w3.org/2013/collation/UCA?strength=primary;unused=%d"},
		{"Regex", `matches('a', $input)`, "a|%d"},
	} {
		t.Run(test.name, func(t *testing.T) {
			e := newEngine(t, transform.Config{})
			q, err := e.CompileXPath(t.Context(), test.expression, transform.XPathOptions{})
			if err != nil {
				t.Fatal(err)
			}
			runtime.GC()
			runtime.GC()
			var before, after runtime.MemStats
			runtime.ReadMemStats(&before)
			for i := range 16 {
				short := fmt.Sprintf(test.format, i)
				source := short + strings.Repeat("x", 1<<20)
				input := source[:len(short)]
				if _, err := q.Evaluate(t.Context(), nil, transform.XPathContext{Variables: transform.Bindings{{Local: "input"}: transform.Values(transform.String(input))}}); err != nil {
					t.Fatal(err)
				}
			}
			runtime.GC()
			runtime.GC()
			runtime.ReadMemStats(&after)
			// Sixteen tiny keys must not retain sixteen 1 MiB sources. The margin
			// allows runtime/test overhead without asserting exact GC sizes.
			if retained := int64(after.HeapAlloc) - int64(before.HeapAlloc); retained > 8<<20 {
				t.Fatalf("short keys retained %d bytes of caller buffers", retained)
			}
			runtime.KeepAlive(q)
		})
	}
}

func TestXSLTSmallResultsReleaseSourceText(t *testing.T) {
	engine := newEngine(t, transform.Config{})
	sheet := compileSheet(t, engine, `<xsl:template match="/"><r><xsl:value-of select="substring-before(/r, '|')"/></r></xsl:template>`)
	retained := retainedHeapDuring(t, func() any {
		results := make([]*transform.Result, 8)
		for i := range results {
			source, err := engine.ParseReader(t.Context(), io.MultiReader(strings.NewReader("<r>small|"), &repeatedInput{remaining: 1 << 20, block: []byte("x")}, strings.NewReader("</r>")))
			if err != nil {
				t.Fatal(err)
			}
			results[i], err = sheet.Execute(t.Context(), source, transform.XSLTContext{})
			if err != nil {
				t.Fatal(err)
			}
			var serialized bytes.Buffer
			if _, err := results[i].WriterTo(t.Context()).WriteTo(&serialized); err != nil || !strings.Contains(serialized.String(), "<r>small</r>") {
				t.Fatal("result changed", serialized.String(), err)
			}
		}
		return results
	})
	t.Logf("eight small XML results: %d retained heap bytes", retained)
	if retained > 2<<20 {
		t.Fatalf("small output trees retained source text: %d bytes", retained)
	}
}

func TestXSLTAnalyzeStringValuesReleaseSource(t *testing.T) {
	for _, selectValue := range []string{".", "regex-group(1)"} {
		t.Run(selectValue, func(t *testing.T) {
			engine := newEngine(t, transform.Config{})
			sheet := compileSheet(t, engine, `<xsl:param name="input"/><xsl:template name="start"><xsl:analyze-string select="$input" regex="(small)"><xsl:matching-substring><xsl:sequence select="`+selectValue+`"/></xsl:matching-substring></xsl:analyze-string></xsl:template>`)
			retained := retainedHeapDuring(t, func() any {
				results := make([]*transform.Result, 8)
				for i := range results {
					source := "smallx" + strings.Repeat("x", 1<<20)
					result, err := sheet.CallTemplate(t.Context(), nil, document.Name{Local: "start"}, transform.XSLTContext{Parameters: transform.Bindings{{Local: "input"}: transform.Values(transform.String(source[:6]))}})
					if err != nil {
						t.Fatal(err)
					}
					if actual, err := result.Primary().Text(); err != nil || actual != "small" {
						t.Fatal(actual, err)
					}
					results[i] = result
				}
				return results
			})
			t.Logf("eight captured values: %d retained heap bytes", retained)
			if retained > 2<<20 {
				t.Fatalf("captured values retained input buffers: %d bytes", retained)
			}
		})
	}
}

func TestUncachedLargeRegexFlagsPreserveMatching(t *testing.T) {
	e := newEngine(t, transform.Config{})
	q, err := e.CompileXPath(t.Context(), `matches('A', 'a', $flags)`, transform.XPathOptions{})
	if err != nil {
		t.Fatal(err)
	}
	flags := transform.Values(transform.String(strings.Repeat("i", (64<<10)+1)))
	result, err := q.Evaluate(t.Context(), nil, transform.XPathContext{Variables: transform.Bindings{{Local: "flags"}: flags}})
	if err != nil {
		t.Fatal(err)
	}
	matched, err := result.EffectiveBoolean()
	if err != nil || !matched {
		t.Fatalf("uncached flags changed matching: %v, %v", matched, err)
	}
}

func TestXSLTReusesImmutableTextStorage(t *testing.T) {
	for _, size := range []int{16 << 10, 1 << 20} {
		text := strings.Repeat("x", size)
		engine := newEngine(t, transform.Config{})
		input, err := engine.ParseReader(t.Context(), io.MultiReader(strings.NewReader("<r>"), strings.NewReader(text), strings.NewReader("</r>")))
		if err != nil {
			t.Fatal(err)
		}
		for _, tc := range []struct {
			name string
			body string
		}{
			{"value-of", `<xsl:param name="text"/><xsl:template match="/"><r><xsl:value-of select="$text"/></r></xsl:template>`},
			{"copy-of", `<xsl:template match="/"><xsl:copy-of select="/r"/></xsl:template>`},
			{"builtin", `<xsl:template match="/"><r><xsl:apply-templates/></r></xsl:template>`},
		} {
			t.Run(fmt.Sprintf("%s/%d", tc.name, size), func(t *testing.T) {
				sheet := compileSheet(t, engine, tc.body)
				options := transform.XSLTContext{}
				if tc.name == "value-of" {
					options.Parameters = transform.Bindings{{Local: "text"}: transform.Values(transform.String(text))}
				}
				allocated := allocatedDuring(t, func() error {
					result, err := sheet.Execute(t.Context(), input, options)
					if err != nil {
						return err
					}
					actual, err := result.Primary().Text()
					if err != nil || actual != text {
						return fmt.Errorf("text result changed: %v", err)
					}
					return nil
				})
				t.Logf("%d input text bytes: %d allocated", size, allocated)
				if allocated > 128<<10 {
					t.Fatalf("XSLT retained redundant text copies: %d bytes", allocated)
				}
				ctx, cancel := context.WithCancel(t.Context())
				cancel()
				if _, err := sheet.Execute(ctx, input, options); !errors.Is(err, context.Canceled) {
					t.Fatal(err)
				}
			})
		}
	}
}

func TestXSLTTextCopyHonorsOutputBudgetBeforeAllocation(t *testing.T) {
	engine := newEngine(t, transform.Config{Limits: transform.Limits{MaxOutputBytes: 1024}})
	input, err := engine.ParseReader(t.Context(), strings.NewReader(`<r>`+strings.Repeat("x", 1<<20)+`</r>`))
	if err != nil {
		t.Fatal(err)
	}
	for _, body := range []string{`<xsl:template match="/"><xsl:copy-of select="/r"/></xsl:template>`, `<xsl:template match="/"><r><xsl:apply-templates/></r></xsl:template>`} {
		sheet := compileSheet(t, engine, body)
		allocated := allocatedDuring(t, func() error {
			result, err := sheet.Execute(t.Context(), input, transform.XSLTContext{})
			if result != nil || !errors.Is(err, transform.ErrLimit) {
				return fmt.Errorf("copy bypassed the output budget: %v", err)
			}
			return nil
		})
		if allocated > 64<<10 {
			t.Fatalf("budget check copied large text first: %d bytes", allocated)
		}
	}
}

func TestNormalizationEmitsWithoutWholeValueCopy(t *testing.T) {
	e := newEngine(t, transform.Config{Limits: transform.Limits{MaxOutputBytes: 16 << 20}})
	input := strings.Repeat("e\u0301", 1<<20)
	for _, method := range []string{"text", "xml", "html"} {
		t.Run(method, func(t *testing.T) {
			sheet := compileSheet(t, e, `<xsl:param name="data"/><xsl:output method="`+method+`" normalization-form="NFC" omit-xml-declaration="yes" include-content-type="no"/><xsl:template name="start"><r><xsl:value-of select="$data"/></r></xsl:template>`)
			result, err := sheet.CallTemplate(t.Context(), nil, document.Name{Local: returnedFunctionTemplate}, transform.XSLTContext{Parameters: transform.Bindings{{Local: "data"}: transform.Values(transform.String(input))}})
			if err != nil {
				t.Fatal(err)
			}
			allocation := allocatedDuring(t, func() error {
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				sink := &normalizationSink{cancel: cancel}
				_, err := result.WriterTo(ctx).WriteTo(sink)
				if !errors.Is(err, context.Canceled) || !sink.normalized {
					t.Fatalf("no early normalized output/cancellation: %v", err)
				}
				return nil
			})
			t.Logf("allocation before canceled early output: %d", allocation)
			if allocation > 512<<10 {
				t.Fatal("normalization buffered complete value", allocation)
			}
		})
	}
}

func TestNormalizationPeakHeap(t *testing.T) {
	for _, method := range []string{"text", "xml", "html"} {
		t.Run(method, func(t *testing.T) {
			e := newEngine(t, transform.Config{Limits: transform.Limits{MaxOutputBytes: 16 << 20, Timeout: 15 * time.Second}})
			sheet := compileSheet(t, e, `<xsl:param name="data"/><xsl:output method="`+method+`" normalization-form="NFC" omit-xml-declaration="yes" include-content-type="no"/><xsl:template name="start"><r><xsl:value-of select="$data"/></r></xsl:template>`)

			if method == "text" {
				small := strings.Repeat("e\u0301", 1<<20)
				prepared, err := sheet.CallTemplate(t.Context(), nil, document.Name{Local: returnedFunctionTemplate}, transform.XSLTContext{Parameters: transform.Bindings{{Local: "data"}: transform.Values(transform.String(small))}})
				if err != nil {
					t.Fatal(err)
				}
				allocation := allocatedDuring(t, func() error { _, err := prepared.WriterTo(t.Context()).WriteTo(io.Discard); return err })
				t.Logf("text normalization allocation: %d", allocation)
				if allocation > 768<<10 {
					t.Fatal("normalization copied the complete value or each normalized block", allocation)
				}
			}
			var peaks []uint64
			for _, size := range []int{16 << 10, 1 << 20} {
				input := strings.Repeat("e\u0301", size)
				result, err := sheet.CallTemplate(t.Context(), nil, document.Name{Local: returnedFunctionTemplate}, transform.XSLTContext{Parameters: transform.Bindings{{Local: "data"}: transform.Values(transform.String(input))}})
				if err != nil {
					t.Fatal(err)
				}
				writes := 0
				// Collect periodically to distinguish live working storage from dead
				// chunk allocations. Fixture/result storage is excluded from the baseline.
				sink := &streamingSink{afterWrite: func() {
					writes++
					if writes%64 == 0 {
						runtime.GC()
					}
				}}
				peak := peakHeapDuring(t, func() error { _, err := result.WriterTo(t.Context()).WriteTo(sink); return err })
				peaks = append(peaks, peak)
				runtime.KeepAlive(result)
			}
			t.Logf("observed peak heap, small/large: %v", peaks)
			if peaks[1] > peaks[0]+2<<20 {
				t.Fatal("normalization working storage grew with complete input", peaks)
			}
		})
	}
}

type normalizationSink struct {
	cancel     context.CancelFunc
	normalized bool
}

func (w *normalizationSink) Write(p []byte) (int, error) {
	if bytes.Contains(p, []byte("é")) {
		w.normalized = true
		w.cancel()
	}
	return len(p), nil
}
