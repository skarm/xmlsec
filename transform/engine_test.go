package transform_test

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/big"
	"strconv"
	"strings"
	"sync"
	"testing"
	"testing/iotest"
	"unicode/utf16"

	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/transform"
)

func TestSingleByteXMLInputs(t *testing.T) {
	ordinary := engine(t, transform.Config{})
	extended := engine(t, transform.Config{AllowSingleByteEncodings: true})

	for _, tc := range []struct{ encoding, content, want string }{
		{xmlASCIIEncoding, "ascii text", "ascii text"},
		{"ASCII", "alias text", "alias text"},
		{"aScIi", "alias text", "alias text"},
		{xmlASCIIEncoding, "caf&#233;", xmlLatinText},
		{xmlLatinEncoding, "caf\xe9", xmlLatinText},
		{"ISO-8859-15", "\xa4", "€"},
		{"windows-1252", "\x80", "€"},
	} {
		source := `<?xml version="1.0" encoding="` + tc.encoding + `"?><r>` + tc.content + `</r>`
		if _, err := ordinary.Parse(t.Context(), []byte(source)); err == nil {
			t.Fatal("single-byte encoding enabled by default", tc.encoding)
		}

		for _, reader := range []io.Reader{strings.NewReader(source), iotest.OneByteReader(strings.NewReader(source))} {
			doc, err := extended.ParseReader(t.Context(), reader)
			if err != nil {
				t.Fatal(tc.encoding, err)
			}

			value, err := query(t, extended, `string(/r)`, transform.XPath31).Evaluate(t.Context(), doc, transform.XPathContext{})
			if err != nil || text(t, value) != tc.want {
				t.Fatal(tc.encoding, value, err)
			}
		}
	}

	for _, source := range []string{
		`<?xml version="1.0" encoding="US-ASCII"?><r>` + "\xe9" + `</r>`,
		`<?xml version="1.0" encoding="windows-1252"?><r>` + "\x81" + `</r>`,
		`<?xml version="1.0" encoding="UTF-16"?><r/>`,
		`<?xml version="1.0" encoding="not-an-encoding"?><r/>`,
		`<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE r><r/>`,
		"\ufeff" + `<?xml version="1.0" encoding="ISO-8859-1"?><r/>`,
	} {
		if _, err := extended.Parse(t.Context(), []byte(source)); err == nil {
			t.Fatal("invalid or forbidden encoded XML accepted", source)
		}
	}

	source := `<?xml version="1.0" encoding="ISO-8859-1"?><r>` + strings.Repeat("\xe9", 100) + `</r>`

	bounded := engine(t, transform.Config{AllowSingleByteEncodings: true, Limits: transform.Limits{MaxInputBytes: len(source)}})
	if _, err := bounded.Parse(t.Context(), []byte(source)); !errors.Is(err, transform.ErrLimit) {
		t.Fatal("decoded XML escaped the input byte budget", err)
	}
}

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

	value, err := query(t, e, `string(parse-xml('<!DOCTYPE r [<!ENTITY e "boom">]><r>&e;</r>'))`, transform.XPath31).Evaluate(ctx, nil, transform.XPathContext{})
	if err != nil || text(t, value) != "boom" {
		t.Fatal("language DTD processing", value, err)
	}
	_, err = query(t, e, `string(parse-xml('<!DOCTYPE r [<!ENTITY e "`+strings.Repeat("x", 128)+`">]><r>&e;</r>'))`, transform.XPath31).Evaluate(ctx, nil, transform.XPathContext{})
	if !errors.Is(err, transform.ErrLimit) {
		t.Fatal("DTD result escaped the output budget", err)
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

	assertionEngine := engine(t, transform.Config{EnableXSLTAssertions: true, Limits: transform.Limits{MaxOutputBytes: 64, MaxOperations: 100, MaxNodes: 50}})

	for _, instruction := range []string{
		`<xsl:assert test="sum(1 to 10000) = 0"/>`,
		`<xsl:assert test="false()" error-code="{string-join(1 to 40, 'abcdefgh')}"/>`,
		`<xsl:assert test="false()" select="string-join(1 to 40, 'abcdefgh')"/>`,
		`<xsl:message select="string-join(1 to 40, 'abcdefgh')"/>`,
		`<xsl:value-of select="fold-left(1 to 16, [()], function($a,$b){[$a,$a]})"/>`,
	} {
		program := sheet(version30, `<xsl:template name="start">`+instruction+`<xsl:text>after</xsl:text></xsl:template>`)
		for _, nested := range []bool{false, true} {
			_, err := resourceStylesheetResult(t, assertionEngine, program, nested, true)
			if !errors.Is(err, transform.ErrLimit) {
				t.Fatal(instruction, nested, err)
			}
		}
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

func TestXSLTResultNormalizationBudget(t *testing.T) {
	e := engine(t, transform.Config{Limits: transform.Limits{MaxOutputBytes: 64}})
	compiled := stylesheet(t, e, sheet(version30, `<xsl:output item-separator="`+strings.Repeat("|", 64)+`"/><xsl:template name="start"><xsl:sequence select="(1,2)"/></xsl:template>`))
	options := transform.XSLTContext{Template: transform.Name{Local: nameStart}}

	result, err := compiled.Execute(t.Context(), nil, options)
	if err != nil || result.Primary().Len() != 2 {
		t.Fatal(result, err)
	}

	options.ResultMode = transform.ResultDocument

	result, err = compiled.Execute(t.Context(), nil, options)
	if result != nil || !errors.Is(err, transform.ErrLimit) {
		t.Fatal("normalization escaped the shared byte budget", result, err)
	}

	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	result, err = compiled.Execute(ctx, nil, options)
	if result != nil || !errors.Is(err, context.Canceled) {
		t.Fatal(result, err)
	}
}

func TestKeyAtomizationBudget(t *testing.T) {
	const expansion = `fold-left(1 to 16, [()], function($a,$b){[$a,$a]})`

	e := engine(t, transform.Config{Limits: transform.Limits{MaxOperations: 10000}})

	for _, test := range []struct{ use, lookup string }{
		{`@k`, expansion},
		{expansion, `'a'`},
	} {
		source := sheet(version30, `<xsl:key name="k" match="n" use="`+test.use+`"/><xsl:template name="start"><xsl:variable name="d" select="parse-xml('&lt;n k=&quot;a&quot;/>')"/><xsl:value-of select="count(key('k',`+test.lookup+`,$d))"/></xsl:template>`)
		for _, nested := range []bool{false, true} {
			_, err := resourceStylesheetResult(t, e, source, nested)
			if !errors.Is(err, transform.ErrLimit) {
				t.Fatal("empty array expansion escaped key atomization budget", test, nested, err)
			}
		}
	}
}

func TestGlobalDependencyBudget(t *testing.T) {
	var declarations strings.Builder
	for i := range 40 {
		kind := "variable"
		if i%2 == 1 {
			kind = "param"
		}
		value := "1"
		if i < 39 {
			value = "$v" + strconv.Itoa(i+1)
		}
		declarations.WriteString(`<xsl:` + kind + ` name="v` + strconv.Itoa(i) + `" select="` + value + `"/>`)
	}
	source := sheet(version30, declarations.String()+`<xsl:template name="start"><xsl:value-of select="$v0"/></xsl:template>`)
	for _, depth := range []int{8, 128} {
		e := engine(t, transform.Config{Limits: transform.Limits{MaxDepth: depth}})
		for _, nested := range []bool{false, true} {
			got, err := resourceStylesheetResult(t, e, source, nested)
			if depth == 8 {
				if !errors.Is(err, transform.ErrLimit) {
					t.Fatal(nested, got, err)
				}
			} else if err != nil || got != "1" {
				t.Fatal(nested, got, err)
			}
		}
	}
}

func TestPackageExposureBudget(t *testing.T) {
	var declarations, rules strings.Builder

	for i := range 40 {
		name := "target" + strconv.Itoa(i)
		declarations.WriteString(`<xsl:template name="` + name + `"/>`)
		rules.WriteString(`<xsl:expose component="template" names="` + name + `" visibility="public"/>`)
	}

	source := []byte(packageSheet("", declarations.String()+rules.String()))

	for _, work := range []int{1000, 100000} {
		e := engine(t, transform.Config{Limits: transform.Limits{MaxOperations: work}})

		_, err := e.CompileXSLT(t.Context(), source, transform.XSLTOptions{})
		if work == 1000 {
			if !errors.Is(err, transform.ErrLimit) {
				t.Fatal("component matching escaped work budget", err)
			}
		} else if err != nil {
			t.Fatal(err)
		}
	}
}

func TestPackageAcceptanceAndAttributeSetBudgets(t *testing.T) {
	var declarations, rules, chain strings.Builder

	for i := range 40 {
		name := "target" + strconv.Itoa(i)
		declarations.WriteString(`<xsl:template name="` + name + `" visibility="public"/>`)
		rules.WriteString(`<xsl:accept component="template" names="` + name + `" visibility="private"/>`)

		if i < 39 {
			chain.WriteString(`<xsl:attribute-set name="a` + strconv.Itoa(i) + `" use-attribute-sets="a` + strconv.Itoa(i+1) + `"/>`)
		} else {
			chain.WriteString(`<xsl:attribute-set name="a39"/>`)
		}
	}

	for _, work := range []int{1000, 100000} {
		e := engine(t, transform.Config{Limits: transform.Limits{MaxOperations: work}, PackageResolver: transform.PackageResolverFunc(func(ctx context.Context, name, _ string) (transform.PackageResource, error) {
			return transform.PackageResource{BaseURI: name, Reader: io.NopCloser(strings.NewReader(packageSheet(`name="urn:binding-library"`, declarations.String())))}, ctx.Err()
		})})

		_, err := e.CompileXSLT(t.Context(), []byte(packageSheet("", `<xsl:use-package name="urn:binding-library">`+rules.String()+`</xsl:use-package>`)), transform.XSLTOptions{})
		if work == 1000 {
			if !errors.Is(err, transform.ErrLimit) {
				t.Fatal("acceptance escaped work budget", err)
			}
		} else if err != nil {
			t.Fatal(err)
		}
	}

	for _, depth := range []int{8, 128} {
		e := engine(t, transform.Config{Limits: transform.Limits{MaxDepth: depth}})
		source := packageSheet("", chain.String()+`<xsl:template name="start" visibility="public"><r xsl:use-attribute-sets="a0"/></xsl:template>`)

		_, err := resourceStylesheetResult(t, e, source, false)
		if depth == 8 {
			if !errors.Is(err, transform.ErrLimit) {
				t.Fatal("attribute-set graph escaped depth budget", err)
			}
		} else if err != nil {
			t.Fatal(err)
		}
	}
}

func TestPackageModeBudget(t *testing.T) {
	library := packageSheet(`name="urn:mode-library"`, `<xsl:mode name="p:m" visibility="public"/>`+strings.Repeat(`<xsl:template match="n[false()]" mode="p:m"/>`, 300))
	source := []byte(packageSheet("", `<xsl:use-package name="urn:mode-library"><xsl:override><xsl:template match="n" mode="p:m">ok<xsl:next-match/></xsl:template></xsl:override></xsl:use-package>`))

	for _, work := range []int{100, 100000} {
		e := engine(t, transform.Config{Limits: transform.Limits{MaxOperations: work}, PackageResolver: transform.PackageResolverFunc(func(ctx context.Context, name, _ string) (transform.PackageResource, error) {
			return transform.PackageResource{BaseURI: name, Reader: io.NopCloser(strings.NewReader(library))}, ctx.Err()
		})})

		_, err := e.CompileXSLT(t.Context(), source, transform.XSLTOptions{})
		if work == 100 {
			if !errors.Is(err, transform.ErrLimit) {
				t.Fatal("package rule compilation escaped work budget", err)
			}
		} else if err != nil {
			t.Fatal(err)
		}
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

func TestXPathImplementationLimitCodes(t *testing.T) {
	for _, version := range []transform.XPathVersion{transform.XPath20, transform.XPath30, transform.XPath31} {
		t.Run(fmt.Sprint(version), func(t *testing.T) {
			publishedProofVector(t, "4")
			if version >= transform.XPath30 {
				publishedProofVector(t, "XPDY0130")
			}
			publishedProofVector(t, "FOAR0001")
			e := engine(t, transform.Config{Limits: transform.Limits{MaxNodes: 8}})

			q := query(t, e, `count(1 to 100)`, version)
			if got := text(t, evaluate(t, e, `count(1 to 4)`, version)); got != "4" {
				t.Fatal("bounded range failed", got)
			}

			_, err := q.Evaluate(t.Context(), nil, transform.XPathContext{})
			if !errors.Is(err, transform.ErrLimit) {
				t.Fatalf("implementation limit lost its category: %v", err)
			}

			var detail *transform.Error
			if !errors.As(err, &detail) {
				t.Fatal("missing structured error", err)
			}

			want := ""
			if version >= transform.XPath30 {
				want = "XPDY0130"
			}

			if detail.Code != want {
				t.Fatalf("code = %q, want %q", detail.Code, want)
			}

			_, err = query(t, e, `1 div 0`, version).Evaluate(t.Context(), nil, transform.XPathContext{})
			if !errors.As(err, &detail) || detail.Code != "FOAR0001" || errors.Is(err, transform.ErrLimit) {
				t.Fatal("standard arithmetic error changed", err)
			}

			ctx, cancel := context.WithCancel(t.Context())
			cancel()

			_, err = q.Evaluate(ctx, nil, transform.XPathContext{})
			if !errors.Is(err, context.Canceled) || !errors.As(err, &detail) || detail.Code != "" {
				t.Fatal("cancellation was reclassified", err)
			}
		})
	}

	e := engine(t, transform.Config{Limits: transform.Limits{MaxOutputBytes: 1}})
	_, err := e.CompileXPath(t.Context(), "256", transform.XPathOptions{})

	var detail *transform.Error
	if !errors.Is(err, transform.ErrLimit) || !errors.As(err, &detail) || detail.Code != "XPDY0130" {
		t.Fatal("default-version compile limit lacks its standard code", err)
	}
}

func TestRegexImplementationLimitCodes(t *testing.T) {
	input := strings.Repeat("a", 10000)
	for _, version := range []transform.XPathVersion{transform.XPath20, transform.XPath30, transform.XPath31} {
		for _, source := range []string{`matches($input,'z')`, `replace($input,'z','x')`, `tokenize($input,'z')`, `analyze-string($input,'a')`} {
			if version == transform.XPath20 && strings.HasPrefix(source, "analyze-string") {
				continue
			}
			t.Run(fmt.Sprint(version)+source, func(t *testing.T) {
				e := engine(t, transform.Config{Limits: transform.Limits{MaxOperations: 128}})
				q := query(t, e, source, version)
				_, err := q.Evaluate(t.Context(), nil, transform.XPathContext{Variables: transform.Bindings{{Local: "input"}: transform.Values(transform.String(input))}})
				var detail *transform.Error
				if !errors.Is(err, transform.ErrLimit) || !errors.As(err, &detail) {
					t.Fatal("valid regex must retain the resource failure", err)
				}
				want := ""
				if version >= transform.XPath30 {
					want = "XPDY0130"
				}
				if detail.Code != want {
					t.Fatal("resource failure was reported as invalid regex", detail.Code, want, err)
				}
				_, err = query(t, e, `matches('a','[')`, version).Evaluate(t.Context(), nil, transform.XPathContext{})
				if !errors.As(err, &detail) || detail.Code != "FORX0002" || errors.Is(err, transform.ErrLimit) {
					t.Fatal("invalid regex lost its syntax error", err)
				}
			})
		}
	}
}

func TestXSLTImplementationLimitCodes(t *testing.T) {
	for _, version := range []transform.XSLTVersion{transform.XSLT20, transform.XSLT30} {
		for _, body := range []string{
			`<xsl:template name="start"><xsl:call-template name="start"/></xsl:template>`,
			`<xsl:template match="/" name="start"><xsl:apply-templates select="."/></xsl:template>`,
			`<xsl:function name="l:f" xmlns:l="urn:loop"><xsl:sequence select="l:f()"/></xsl:function><xsl:template name="start"><xsl:sequence xmlns:l="urn:loop" select="l:f()"/></xsl:template>`,
		} {
			e := engine(t, transform.Config{Limits: transform.Limits{MaxDepth: 16}})
			source := sheet(map[transform.XSLTVersion]string{transform.XSLT20: version20, transform.XSLT30: version30}[version], body)
			s, err := e.CompileXSLT(t.Context(), []byte(source), transform.XSLTOptions{Version: version})
			if err != nil {
				t.Fatal("recursive stylesheet must compile", err)
			}
			node, err := e.Parse(t.Context(), []byte(`<r/>`))
			if err != nil {
				t.Fatal(err)
			}
			_, err = s.Transform(t.Context(), node, transform.XSLTContext{Template: transform.Name{Local: nameStart}})
			var detail *transform.Error
			if !errors.Is(err, transform.ErrLimit) || !errors.As(err, &detail) || detail.Code != "" {
				t.Fatal("recursion must not masquerade as a computed-name error", version, err)
			}
		}
	}
	e := engine(t, transform.Config{Limits: transform.Limits{MaxOperations: 256}})
	s := stylesheet(t, e, sheet(version30, `<xsl:param name="input"/><xsl:template name="start"><xsl:analyze-string select="$input" regex="z"><xsl:non-matching-substring>x</xsl:non-matching-substring></xsl:analyze-string></xsl:template>`))
	_, err := s.Transform(t.Context(), nil, transform.XSLTContext{Template: transform.Name{Local: nameStart}, Parameters: transform.Bindings{{Local: "input"}: transform.Values(transform.String(strings.Repeat("a", 10000)))}})
	var detail *transform.Error
	if !errors.Is(err, transform.ErrLimit) || !errors.As(err, &detail) || detail.Code != "" {
		t.Fatal("analyze-string budget must not become XTDE1140", err)
	}
}

func TestRegexProgramLimits(t *testing.T) {
	e := engine(t, transform.Config{})
	pattern := strings.Repeat("(", 129) + "a" + strings.Repeat(")", 129)
	expression := `matches('a','` + pattern + `')`
	_, err := query(t, e, expression, transform.XPath31).Evaluate(t.Context(), nil, transform.XPathContext{})
	var detail *transform.Error
	if !errors.Is(err, transform.ErrLimit) || !errors.As(err, &detail) || detail.Code != "XPDY0130" {
		t.Fatal("valid regex exceeding the parser depth was classified as invalid syntax", err)
	}

	source := sheet(version30, `<xsl:template name="start"><xsl:analyze-string select="'a'" regex="`+pattern+`"><xsl:non-matching-substring>x</xsl:non-matching-substring></xsl:analyze-string></xsl:template>`)
	s := stylesheet(t, e, source)
	_, err = s.Transform(t.Context(), nil, transform.XSLTContext{Template: transform.Name{Local: nameStart}})
	if !errors.Is(err, transform.ErrLimit) || !errors.As(err, &detail) || detail.Code != "" {
		t.Fatal("regex compilation limit became XTDE1140", err)
	}
}

func TestTransformSourceOptionFailures(t *testing.T) {
	for _, stage := range []string{"open", "read", "close"} {
		for _, cause := range []error{transform.ErrResource, transform.ErrLimit, context.Canceled, context.DeadlineExceeded} {
			e := engine(t, transform.Config{Resolver: transform.ResolverFunc(func(context.Context, string) (io.ReadCloser, error) {
				if stage == "open" {
					return nil, cause
				}

				// Invalid XML also exercises cleanup alongside a content failure.
				reader := &dtdFailureReader{Reader: strings.NewReader("\x00")}
				if stage == "read" {
					reader.readError = cause
				} else {
					reader.closeError = cause
				}

				return reader, nil
			})})
			_, err := query(t, e, `transform(map{'stylesheet-location':'urn:missing'})`, transform.XPath31).Evaluate(t.Context(), nil, transform.XPathContext{})
			var detail *transform.Error
			if !errors.Is(err, cause) || !errors.As(err, &detail) {
				t.Fatal("stylesheet retrieval lost its cause", cause, err)
			}
			want := "FOXT0003"
			if stage == "open" {
				want = "FOXT0002"
			}
			switch {
			case errors.Is(cause, transform.ErrLimit):
				want = "XPDY0130"
			case errors.Is(cause, context.Canceled), errors.Is(cause, context.DeadlineExceeded):
				want = ""
			}
			if detail.Code != want {
				t.Fatal("source option failure has the wrong category", stage, cause, detail.Code, want)
			}
		}
	}
}

func TestCallbackLimitsCannotBeCaught(t *testing.T) {
	name := transform.Name{Space: namespaceApplication, Local: "budget"}
	e := engine(t, transform.Config{Functions: []transform.Function{{
		Name:  name,
		Arity: 0,
		Call: func(context.Context, []transform.Sequence) (transform.Sequence, error) {
			return transform.Sequence{}, transform.ErrLimit
		},
	}}})
	source := sheet(version30, `<xsl:template name="start"><xsl:try><xsl:sequence xmlns:a="`+namespaceApplication+`" select="a:budget()"/><xsl:catch>caught</xsl:catch></xsl:try></xsl:template>`)
	s := stylesheet(t, e, source)
	_, err := s.Transform(t.Context(), nil, transform.XSLTContext{Template: transform.Name{Local: nameStart}})
	if !errors.Is(err, transform.ErrLimit) {
		t.Fatal("xsl:catch recovered a callback resource limit", err)
	}

	_, err = query(t, e, `transform(map{'stylesheet-text':$sheet,'initial-template':QName('','start')})`, transform.XPath31).Evaluate(t.Context(), nil, transform.XPathContext{Variables: transform.Bindings{{Local: "sheet"}: transform.Values(transform.String(source))}})
	var detail *transform.Error
	if !errors.Is(err, transform.ErrLimit) || !errors.As(err, &detail) || detail.Code != "XPDY0130" {
		t.Fatal("nested transformation reclassified a callback limit", err)
	}
}

func TestErrorCodeNamespaces(t *testing.T) {
	e := engine(t, transform.Config{})

	q := query(t, e, `error(QName($space, 'XPTY0004'))`, transform.XPath31)
	for _, space := range []string{"", namespaceApplication, "http://www.w3.org/2005/xqt-errors"} {
		_, err := q.Evaluate(t.Context(), nil, transform.XPathContext{Variables: transform.Bindings{{Local: "space"}: transform.Values(transform.String(space))}})

		var detail *transform.Error
		if !errors.As(err, &detail) || detail.Code != errCodeXPTY0004 || detail.CodeName() != (transform.Name{Space: space, Local: errCodeXPTY0004}) {
			t.Errorf("namespace %q lost: %v", space, err)
		}
	}

	s := stylesheet(t, e, sheet(version30, `<xsl:template name="start"><xsl:sequence select="error(QName('urn:application', 'a:failure'))"/></xsl:template>`))
	_, err := s.Execute(t.Context(), nil, transform.XSLTContext{Template: transform.Name{Local: nameStart}})

	var detail *transform.Error
	if !errors.As(err, &detail) || detail.CodeName() != (transform.Name{Space: namespaceApplication, Local: "failure"}) {
		t.Fatal("XSLT error QName lost", err)
	}

	var empty *transform.Error
	if empty.CodeName() != (transform.Name{}) || (&transform.Error{}).CodeName() != (transform.Name{}) {
		t.Fatal("nil/zero error has a code")
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
		_, err := query(t, e, trueExpression, transform.XPath31).Evaluate(t.Context(), nil, transform.XPathContext{Variables: transform.Bindings{{Local: "unused"}: transform.Values(value)}})
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
	if _, err := query(t, e, trueExpression, transform.XPath31).Evaluate(t.Context(), nil, transform.XPathContext{Variables: transform.Bindings{{Local: "unused"}: transform.Values(decimal)}}); err != nil {
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
				{"binding", `count($source/*)`, nil, transform.XPathContext{Variables: transform.Bindings{{Local: sourceName}: transform.Values(d.Root())}}},
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

			params := transform.Bindings{{Local: sourceName}: transform.Values(d.Root())}
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
