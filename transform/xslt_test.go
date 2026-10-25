package transform_test

import (
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"io"
	"strconv"
	"strings"
	"testing"

	"github.com/skarm/xmlsec/transform"
)

const nameKept = "kept"

const variableURI = "uri"

const transformSerializedQuery = `transform(map{'stylesheet-text': $stylesheet, 'initial-template': QName('', 'start'), 'delivery-format': 'serialized'})?output`

func TestXSLTResultDelivery(t *testing.T) {
	e := engine(t, transform.Config{})
	for _, test := range []struct {
		name, body, assertion string
		mode                  transform.ResultMode
	}{
		{"raw order", mixedResultTemplate, `count($result) eq 5 and $result[1] instance of xs:integer and $result[2] eq 2 and $result[3] instance of text() and string($result[3]) eq '' and $result[4] instance of element(r) and $result[5] instance of xs:boolean`, transform.ResultRaw},
		{"normalized order", mixedResultTemplate, `$result instance of document-node() and count($result/node()) eq 3 and string($result) eq '1 2true' and $result/node()[2] instance of element(r)`, transform.ResultDefault},
		{"separator and arrays", `<xsl:output item-separator="|"/><xsl:template name="start"><xsl:sequence select="([1,[2]],parse-xml-fragment('AB&lt;r/>'),4)"/></xsl:template>`, `$result instance of document-node() and string($result) eq '1|2|AB|4' and count($result/node()) eq 3`, transform.ResultDocument},
		{"empty raw", `<xsl:template name="start"/>`, `empty($result)`, transform.ResultRaw},
		{"empty document", `<xsl:template name="start"/>`, `$result instance of document-node() and empty($result/node())`, transform.ResultDocument},
		{"build-tree no", unbuiltResultTemplate, `deep-equal($result,(1,2))`, transform.ResultDefault},
		{"forced document", unbuiltResultTemplate, `$result instance of document-node() and string($result) eq '1 2'`, transform.ResultDocument},
		{"JSON default", `<xsl:output method="json"/><xsl:template name="start"><xsl:sequence select="map{'value':3}"/></xsl:template>`, `$result instance of map(*) and $result?value eq 3`, transform.ResultDefault},
		{"adaptive default", `<xsl:output method="adaptive"/><xsl:template name="start"><xsl:sequence select="[1,2]"/></xsl:template>`, `$result instance of array(*) and deep-equal($result?*,(1,2))`, transform.ResultDefault},
	} {
		t.Run(test.name, func(t *testing.T) {
			source := sheetStart + version30 + `">` + test.body + `</xsl:stylesheet>`

			result, err := stylesheet(t, e, source).Execute(t.Context(), nil, transform.XSLTContext{Template: transform.Name{Local: nameStart}, ResultMode: test.mode})
			if err != nil {
				t.Fatal(err)
			}

			check := query(t, e, test.assertion, transform.XPath31)

			value, err := check.Evaluate(t.Context(), nil, transform.XPathContext{Variables: transform.Bindings{{Local: resultBindingName}: result.Primary()}})
			if err != nil || text(t, value) != nameTrue {
				t.Fatal(value, err)
			}

			format := ""

			switch test.mode {
			case transform.ResultRaw:
				format = deliveryRawOption
			case transform.ResultDocument:
				format = deliveryDocumentOption
			}

			expression := `let $result := transform(map{'stylesheet-text':$stylesheet,'initial-template':QName('', 'start')` + format + `})?output return ` + test.assertion

			value, err = query(t, e, expression, transform.XPath31).Evaluate(t.Context(), nil, transform.XPathContext{Variables: transform.Bindings{{Local: variableStylesheet}: transform.Values(transform.String(source))}})
			if err != nil || text(t, value) != nameTrue {
				t.Fatal("fn:transform", value, err)
			}
		})
	}

	for _, mode := range []string{"shallow-copy", "deep-copy"} {
		source := sheet(version30, `<xsl:mode on-no-match="`+mode+`"/><xsl:template name="start"><xsl:apply-templates select="parse-xml('&lt;r/>')"/></xsl:template>`)
		result, err := stylesheet(t, e, source).Execute(t.Context(), nil, transform.XSLTContext{Template: transform.Name{Local: nameStart}, ResultMode: transform.ResultRaw})
		if err != nil {
			t.Fatal(mode, err)
		}
		value, err := query(t, e, `$result instance of document-node() and count($result/r) eq 1`, transform.XPath31).Evaluate(t.Context(), nil, transform.XPathContext{Variables: transform.Bindings{{Local: resultBindingName}: result.Primary()}})
		if err != nil || text(t, value) != nameTrue {
			t.Fatal(mode, value, err)
		}
	}

	for _, mode := range []string{"shallow-copy", "deep-copy"} {
		for _, selection := range []string{"@a", "namespace::p"} {
			source := sheet(version30, `<xsl:mode on-no-match="`+mode+`"/><xsl:template name="start"><xsl:apply-templates select="parse-xml('&lt;r xmlns:p=&quot;urn:p&quot; a=&quot;v&quot;/>')/r/`+selection+`"/></xsl:template>`)
			result, err := stylesheet(t, e, source).Execute(t.Context(), nil, transform.XSLTContext{Template: transform.Name{Local: nameStart}, ResultMode: transform.ResultRaw})
			if err != nil || result.Primary().Len() != 1 {
				t.Fatal(mode, selection, result, err)
			}
			value, err := result.Primary().Single()
			node, ok := value.Node()
			if err != nil || !ok || node.Kind() != map[string]string{"@a": "attribute", "namespace::p": "namespace"}[selection] {
				t.Fatal(mode, selection, node, err)
			}
		}
	}

	for _, item := range []string{emptyMapExpression, `string#1`, `parse-xml('<r a="x"/>')/r/@a`, `parse-xml('<r/>')/r/namespace::xml`} {
		var escaped strings.Builder
		if err := xml.EscapeText(&escaped, []byte(item)); err != nil {
			t.Fatal(err)
		}

		source := sheet(version30, `<xsl:template name="start"><xsl:sequence select="`+escaped.String()+`"/></xsl:template>`)

		compiled := stylesheet(t, e, source)
		if result, err := compiled.Execute(t.Context(), nil, transform.XSLTContext{Template: transform.Name{Local: nameStart}}); err != nil || result.Primary().Len() != 1 {
			t.Fatal(item, result, err)
		}

		result, err := compiled.Execute(t.Context(), nil, transform.XSLTContext{Template: transform.Name{Local: nameStart}, ResultMode: transform.ResultDocument})

		var detail *transform.Error
		if result != nil || !errors.As(err, &detail) || detail.Code != errCodeSENR0001 {
			t.Fatal(item, result, err)
		}
	}
}

func TestXSLTResultDeliveryIdentityAndSecondary(t *testing.T) {
	e := engine(t, transform.Config{})

	doc, err := e.Parse(t.Context(), []byte(`<r xmlns:p="urn:kept"><p:child/></r>`))
	if err != nil {
		t.Fatal(err)
	}

	compiled := stylesheet(t, e, sheet(version30, `<xsl:template name="start"><xsl:sequence select="/r"/><xsl:result-document href="secondary" method="adaptive"><xsl:sequence select="map{'value':3}"/></xsl:result-document></xsl:template>`))
	for _, mode := range []transform.ResultMode{transform.ResultRaw, transform.ResultDefault} {
		result, err := compiled.Execute(t.Context(), doc, transform.XSLTContext{Template: transform.Name{Local: nameStart}, ResultMode: mode, BaseOutputURI: "https://output.invalid/main"})
		if err != nil {
			t.Fatal(err)
		}

		assertion := `$result is $source/r`
		if mode != transform.ResultRaw {
			assertion = `$result instance of document-node() and not($result/r is $source/r) and namespace-uri($result/r/*) eq 'urn:kept' and base-uri($result) eq 'https://output.invalid/main'`
		}

		value, err := query(t, e, assertion, transform.XPath31).Evaluate(t.Context(), nil, transform.XPathContext{Variables: transform.Bindings{{Local: resultBindingName}: result.Primary(), {Local: "source"}: transform.Values(doc.Root())}})
		if err != nil || text(t, value) != nameTrue {
			t.Fatal(mode, value, err)
		}

		secondary := result.Secondary()["https://output.invalid/secondary"]

		value, err = query(t, e, `$result instance of map(*) and $result?value eq 3`, transform.XPath31).Evaluate(t.Context(), nil, transform.XPathContext{Variables: transform.Bindings{{Local: resultBindingName}: secondary}})
		if err != nil || text(t, value) != nameTrue {
			t.Fatal(mode, secondary, err)
		}
	}

	result, err := compiled.Execute(t.Context(), doc, transform.XSLTContext{Template: transform.Name{Local: nameStart}, ResultMode: transform.ResultDocument, BaseOutputURI: "https://output.invalid/main"})

	var detail *transform.Error
	if result != nil || !errors.As(err, &detail) || detail.Code != errCodeSENR0001 {
		t.Fatal(result, err)
	}

	if _, err := compiled.Execute(t.Context(), doc, transform.XSLTContext{ResultMode: transform.ResultMode(255)}); !errors.Is(err, transform.ErrInput) {
		t.Fatal(err)
	}

	value, err := query(t, e, `namespace-uri(/r/*) eq 'urn:kept' and count(/r/*) eq 1`, transform.XPath31).Evaluate(t.Context(), doc, transform.XPathContext{})
	if err != nil || text(t, value) != nameTrue {
		t.Fatal("source changed", value, err)
	}
}

func TestXPathTransformAssertionOption(t *testing.T) {
	source := sheet(version30, `<xsl:template name="start"><xsl:assert test="false()"/><xsl:text>after</xsl:text></xsl:template>`)

	for _, configured := range []bool{false, true} {
		e := engine(t, transform.Config{EnableXSLTAssertions: configured})

		for _, test := range []struct{ option, code string }{
			{"", ""},
			{falseExpression, ""},
			{trueExpression, errCodeXTMM9001},
			{"xs:untypedAtomic('1')", errCodeXTMM9001},
			{"[true()]", errCodeXTMM9001},
			{"()", errCodeXPTY0004},
			{"(true(),false())", errCodeXPTY0004},
			{"'true'", errCodeXPTY0004},
			{"1", errCodeXPTY0004},
			{emptyMapExpression, errCodeFOTY0013},
			{"xs:untypedAtomic('bad')", errCodeFORG0001},
		} {
			option := ""
			if test.option != "" {
				option = ",'enable-assertions':" + test.option
			}

			expression := `transform(map{'stylesheet-text':$stylesheet,'initial-template':QName('', 'start'),'delivery-format':'serialized'` + option + `})?output`

			value, err := query(t, e, expression, transform.XPath31).Evaluate(t.Context(), nil, transform.XPathContext{Variables: transform.Bindings{{Local: variableStylesheet}: transform.Values(transform.String(source))}})
			if test.code == "" {
				if err != nil || text(t, value) != afterAssertionText {
					t.Fatal(configured, test.option, value, err)
				}

				continue
			}

			var detail *transform.Error
			if !errors.As(err, &detail) || detail.Code != test.code {
				t.Fatal(configured, test.option, err, test.code)
			}
		}
	}
}

func contextItemCases() []dynamicXPathCase {
	return []dynamicXPathCase{
		{"absent with type", `<xsl:template name="target"><xsl:context-item use="absent" as="item()"/></xsl:template>`, `ok`, "XTSE3088"},
		{"unnamed absent", `<xsl:template match="node()"><xsl:context-item use="absent"/></xsl:template>`, `ok`, "XTSE0020"},
		{"unnamed optional", `<xsl:template match="node()"><xsl:context-item use="optional"/></xsl:template>`, `ok`, "XTSE0020"},
		{"unknown atomic type", `<xsl:template name="target"><xsl:context-item xmlns:t="urn:types" as="t:missing"/></xsl:template>`, `ok`, "XPST0051"},
		{"unbound type prefix", `<xsl:template name="target"><xsl:context-item as="missing:type"/></xsl:template>`, `ok`, "XPST0081"},
		{"unknown nested type", `<xsl:template name="target"><xsl:context-item as="map(xs:string, xs:missing)"/></xsl:template>`, `ok`, "XPST0051"},
		{"empty type", `<xsl:template name="target"><xsl:context-item as=""/></xsl:template>`, `ok`, "XTSE0020"},
		{"void type", `<xsl:template name="target"><xsl:context-item as="empty-sequence()"/></xsl:template>`, `ok`, "XTSE0020"},
		{"commented occurrence", `<xsl:template name="target"><xsl:context-item as="item() ? (: comment :)"/></xsl:template>`, `ok`, "XTSE0020"},
		{"misplaced declaration", ``, `<xsl:variable name="v"><xsl:context-item as="item()"/></xsl:variable>`, "XTSE0010"},
		{"declaration in dead branch", ``, `<xsl:if test="false()"><xsl:context-item/></xsl:if>`, "XTSE0010"},
		{"atomic declaration scope", `<xsl:template name="target"><xsl:context-item xmlns:t="http://www.w3.org/2001/XMLSchema" as="t:integer"/><xsl:sequence select="."/></xsl:template>`, `<xsl:for-each select="42"><xsl:call-template xmlns:t="urn:other" name="target"/></xsl:for-each>`, "42"},
		{"element declaration scope", `<xsl:template name="target"><xsl:context-item xmlns:p="urn:source" as="element(p:r)"/><xsl:value-of select="name()"/></xsl:template>`, `<xsl:for-each select="parse-xml('&lt;r xmlns=&quot;urn:source&quot;/>')/*"><xsl:call-template xmlns:p="urn:other" name="target"/></xsl:for-each>`, "r"},
		{"default type namespace", `<xsl:template name="target"><xsl:context-item xpath-default-namespace="http://www.w3.org/2001/XMLSchema" as="integer"/><xsl:sequence select="."/></xsl:template>`, `<xsl:for-each select="42"><xsl:call-template name="target"/></xsl:for-each>`, "42"},
		{"map context", `<xsl:template name="target"><xsl:context-item as="map(xs:string, xs:integer)"/><xsl:sequence select=".?n"/></xsl:template>`, `<xsl:for-each select="map{'n':42}"><xsl:call-template name="target"/></xsl:for-each>`, "42"},
		{"wrong map value", `<xsl:template name="target"><xsl:context-item as="map(xs:string, xs:integer)"/></xsl:template>`, `<xsl:for-each select="map{'n':'42'}"><xsl:call-template name="target"/></xsl:for-each>`, "XTTE0590"},
		{"array context", `<xsl:template name="target"><xsl:context-item as="array(xs:integer)"/><xsl:sequence select=".?1"/></xsl:template>`, `<xsl:for-each select="[42]"><xsl:call-template name="target"/></xsl:for-each>`, "42"},
		{"function context", `<xsl:template name="target"><xsl:context-item as="function(xs:integer) as xs:integer"/><xsl:sequence select=".(41)"/></xsl:template>`, `<xsl:for-each select="function($x as xs:integer) as xs:integer {$x + 1}"><xsl:call-template name="target"/></xsl:for-each>`, "42"},
		{"numeric promotion forbidden", `<xsl:template name="target"><xsl:context-item as="xs:double"/></xsl:template>`, `<xsl:for-each select="42"><xsl:call-template name="target"/></xsl:for-each>`, "XTTE0590"},
		{"atomization forbidden", `<xsl:template name="target"><xsl:context-item as="xs:string"/></xsl:template>`, `<xsl:for-each select="parse-xml('&lt;r>text&lt;/r>')/*"><xsl:call-template name="target"/></xsl:for-each>`, "XTTE0590"},
		{"optional absent", `<xsl:template name="target"><xsl:context-item as="xs:integer" use="optional"/>ok</xsl:template>`, `<xsl:call-template name="target"/>`, "ok"},
		{"absent focus", `<xsl:template name="target"><xsl:context-item use="absent"/><xsl:try><xsl:sequence select="."/><xsl:catch>absent</xsl:catch></xsl:try></xsl:template>`, `<xsl:for-each select="42"><xsl:call-template name="target"/></xsl:for-each>`, "absent"},
	}
}

func TestXSLTContextItemContracts(t *testing.T) {
	e := engine(t, transform.Config{})
	for _, test := range contextItemCases() {
		t.Run(test.name, func(t *testing.T) {
			for _, nested := range []bool{false, true} {
				got, err := resourceStylesheetResult(t, e, dynamicXPathSheet(test), nested)
				if comparisonErrorCode(test.want) {
					var detail *transform.Error
					if !errors.As(err, &detail) || detail.Code != test.want {
						t.Fatal(nested, got, err, test.want)
					}
				} else if err != nil || got != test.want {
					t.Fatal(nested, got, err, test.want)
				}
			}
		})
	}
}

func TestXSLTDeclarationContracts(t *testing.T) {
	e := engine(t, transform.Config{})
	for _, processor := range []transform.XSLTVersion{transform.XSLT20, transform.XSLT30} {
		for _, source := range []string{
			sheet("17.0", `<xsl:template name="start">ok</xsl:template><xsl:template name="unused"><xsl:call-template name="missing"/></xsl:template>`),
			sheet("17.0", `<xsl:template name="start"><xsl:call-template name="missing"/></xsl:template>`),
			sheet(version20, `<xsl:template name="start" version="17.0"><xsl:if test="false()"><xsl:call-template name="missing"/></xsl:if></xsl:template>`),
		} {
			_, err := e.CompileXSLT(t.Context(), []byte(source), transform.XSLTOptions{ProcessorVersion: processor})
			var detail *transform.Error
			if !errors.As(err, &detail) || detail.Code != errCodeXTSE0650 {
				t.Fatal("forward call-template must fail during compilation", processor, source, err)
			}
		}
	}

	legacy := sheet("1.1", `<xsl:template name="start"><xsl:if test="false()"><xsl:call-template name="missing"/></xsl:if><xsl:text>ok</xsl:text></xsl:template>`)
	if _, err := e.CompileXSLT(t.Context(), []byte(legacy), transform.XSLTOptions{ProcessorVersion: transform.XSLT10}); err != nil {
		t.Fatal("selected 1.0 legacy forward behavior changed", err)
	}

	for body, code := range map[string]string{
		`<xsl:template name="start"><xsl:if test="false()"><xsl:call-template name="missing"/></xsl:if></xsl:template>`:                           errCodeXTSE0650,
		`<xsl:template name="start"><xsl:call-template name="bad/name"/></xsl:template>`:                                                          errCodeXTSE0020,
		`<xsl:template xmlns:p="urn:application" name="p:target"/><xsl:template name="start"><xsl:call-template name="p:target"/></xsl:template>`: errCodeXTSE0280,
		`<xsl:template name="same"/><xsl:template name="same"/>`:                                                                                  errCodeXTSE0660,
		`<xsl:function name="local"/>`:                                                            errCodeXTSE0740,
		`<xsl:function name="Q{}local"/>`:                                                         errCodeXTSE0740,
		`<xsl:function name="Q{urn:application}bad:name"/>`:                                       errCodeXTSE0020,
		`<xsl:function xmlns:p="urn:application" name="p:first"/><xsl:function name="p:second"/>`: errCodeXTSE0280,
		`<xsl:template name="start"><xsl:include href="urn:missing"/></xsl:template>`:             errCodeXTSE0170,
		`<xsl:template name="start"><xsl:import href="urn:missing"/></xsl:template>`:              errCodeXTSE0190,
		`<xsl:namespace-alias stylesheet-prefix="missing" result-prefix="xsl"/>`:                  errCodeXTSE0812,
		`<xsl:namespace-alias stylesheet-prefix="xsl" result-prefix="missing"/>`:                  errCodeXTSE0812,
	} {
		_, err := e.CompileXSLT(t.Context(), []byte(sheet(version30, body)), transform.XSLTOptions{})

		var detail *transform.Error
		if !errors.As(err, &detail) || detail.Code != code {
			t.Fatal(body, err, code)
		}
	}

	for _, nested := range []bool{false, true} {
		for _, body := range []string{
			`<xsl:template name="start"><xsl:call-template xmlns:p="urn:application" name="p:target"/></xsl:template><xsl:template xmlns:p="urn:application" name="p:target">ok</xsl:template>`,
			`<xsl:template name="start"><xsl:call-template name="Q{urn:application}target"/></xsl:template><xsl:template name="Q{urn:application}target">ok</xsl:template>`,
		} {
			got, err := resourceStylesheetResult(t, e, sheet(version30, body), nested)
			if err != nil || got != "ok" {
				t.Fatal(nested, body, got, err)
			}
		}

		for body, code := range map[string]string{
			`<xsl:variable name="a" select="$b"/><xsl:variable name="b" select="$a"/><xsl:template name="start"><xsl:value-of select="$a"/></xsl:template>`:                 errCodeXTDE0640,
			`<xsl:param name="a" select="$b"/><xsl:param name="b" select="$a"/><xsl:template name="start"><xsl:value-of select="$a"/></xsl:template>`:                       errCodeXTDE0640,
			`<xsl:template name="start"><xsl:call-template name="required"/></xsl:template><xsl:template name="required"><xsl:context-item use="required"/></xsl:template>`: errCodeXTTE3090,
		} {
			_, err := resourceStylesheetResult(t, e, sheet(version30, body), nested)

			var detail *transform.Error
			if !errors.As(err, &detail) || detail.Code != code {
				t.Fatal(nested, body, err, code)
			}
		}
	}

	program := sheet(version30, `<xsl:mode name="m"/><xsl:mode name="private" visibility="private"/><xsl:template match="." mode="m"><xsl:value-of select="."/></xsl:template>`)
	compiled := stylesheet(t, e, program)
	_, err := compiled.Execute(t.Context(), nil, transform.XSLTContext{Mode: transform.Name{Local: "m"}})

	var detail *transform.Error
	if !errors.As(err, &detail) || detail.Code != errCodeXTDE0044 {
		t.Fatal(err)
	}

	value := transform.Integer(7)

	result, err := compiled.Execute(t.Context(), nil, transform.XSLTContext{Mode: transform.Name{Local: "m"}, ContextItem: &value})
	if err != nil || text(t, result.Primary()) != "7" {
		t.Fatal(result, err)
	}

	doc, err := e.Parse(t.Context(), []byte(`<r/>`))
	if err != nil {
		t.Fatal(err)
	}

	_, err = compiled.Execute(t.Context(), doc, transform.XSLTContext{Mode: transform.Name{Local: visibilityPrivate}})
	if !errors.As(err, &detail) || detail.Code != errCodeXTDE0045 {
		t.Fatal(err)
	}
}

func TestXSLTAttributeSetCycles(t *testing.T) {
	e := engine(t, transform.Config{})
	_, err := e.CompileXSLT(t.Context(), []byte(sheet(version20, cyclicAttributeSets+activeAttributeSetTemplate)), transform.XSLTOptions{ProcessorVersion: transform.XSLT20})

	var detail *transform.Error
	if !errors.As(err, &detail) || detail.Code != "XTSE0720" {
		t.Fatal(err)
	}

	for _, body := range []string{cyclicAttributeSets + `<xsl:template name="start">ok</xsl:template>`, cyclicAttributeSets + activeAttributeSetTemplate, indirectAttributeSetCycle + activeAttributeSetTemplate} {
		for _, nested := range []bool{false, true} {
			got, err := resourceStylesheetResult(t, e, sheet(version30, body), nested)
			if strings.Contains(body, `>ok</xsl:template>`) {
				if err != nil || got != "ok" {
					t.Fatal(nested, got, err)
				}

				continue
			}

			if !errors.As(err, &detail) || detail.Code != errCodeXTDE0640 {
				t.Fatal(nested, got, err)
			}
		}
	}
}

func TestXSLTInitialModeEligibility(t *testing.T) {
	e := engine(t, transform.Config{})
	for _, visibility := range []string{"", `<xsl:mode name="m" visibility="private"/>`, `<xsl:expose component="mode" names="*" visibility="private"/>`} {
		compiled := stylesheet(t, e, packageSheet(`declared-modes="no"`, visibility+`<xsl:template match="." mode="m"><xsl:value-of select="."/></xsl:template>`))

		result, err := compiled.ApplyTemplates(t.Context(), nil, transform.Values(transform.Integer(7)), transform.XSLTContext{Mode: transform.Name{Local: "m"}})
		if visibility == "" {
			if err != nil || text(t, result.Primary()) != "7" {
				t.Fatal(result, err)
			}

			continue
		}

		var detail *transform.Error
		if result != nil || !errors.As(err, &detail) || detail.Code != errCodeXTDE0045 {
			t.Fatal(visibility, result, err)
		}
	}
}

func TestXSLTModuleCyclesAndPrecedence(t *testing.T) {
	for _, imported := range []bool{false, true} {
		for _, nestedImport := range []bool{false, true} {
			first, second, code := nameInclude, nameInclude, errCodeXTSE0180
			if imported {
				first, code = nameImport, errCodeXTSE0210
			}

			if nestedImport {
				second, code = nameImport, errCodeXTSE0210
			}

			modules := map[string]string{
				"urn:a": sheet(version30, `<xsl:`+first+` href="urn:b"/>`),
				"urn:b": sheet(version30, `<xsl:`+second+` href="urn:a"/>`),
			}
			e := engine(t, transform.Config{Resolver: transform.ResolverFunc(func(ctx context.Context, uri string) (io.ReadCloser, error) {
				return io.NopCloser(strings.NewReader(modules[uri])), ctx.Err()
			})})
			_, err := e.CompileXSLT(t.Context(), []byte(sheet(version30, `<xsl:import href="urn:a"/>`)), transform.XSLTOptions{})

			var detail *transform.Error
			if !errors.As(err, &detail) || detail.Code != code {
				t.Fatal(imported, nestedImport, err, code)
			}
		}
	}

	e := engine(t, transform.Config{Resolver: transform.ResolverFunc(func(ctx context.Context, _ string) (io.ReadCloser, error) {
		return io.NopCloser(strings.NewReader(sheet(version30, `<xsl:template name="start">first</xsl:template><xsl:template name="start">second</xsl:template>`))), ctx.Err()
	})})
	for _, nested := range []bool{false, true} {
		got, err := resourceStylesheetResult(t, e, sheet(version30, `<xsl:import href="urn:definitions"/><xsl:template name="start">higher</xsl:template>`), nested)
		if err != nil || got != higherResultText {
			t.Fatal(nested, got, err)
		}
	}
}

type globalPrecedenceCase struct{ name, imported, local, want string }

func globalPrecedenceCases() []globalPrecedenceCase {
	return []globalPrecedenceCase{
		{"param over variable", `<xsl:variable name="v" select="'lower'"/>`, `<xsl:param name="v" select="'higher'"/>`, higherResultText},
		{"variable over required param", `<xsl:param name="v" required="yes"/>`, `<xsl:variable name="v" select="'higher'"/>`, higherResultText},
		{"overridden duplicate variables", `<xsl:variable name="v" select="1"/><xsl:variable name="v" select="2"/>`, `<xsl:param name="v" select="'higher'"/>`, higherResultText},
		{"overridden duplicate kinds", `<xsl:param name="v" select="1"/><xsl:variable name="v" select="2"/>`, `<xsl:variable name="v" select="'higher'"/>`, higherResultText},
		{"effective duplicate kinds", `<xsl:param name="v" select="1"/><xsl:variable name="v" select="2"/>`, "", "XTSE0630"},
	}
}

func globalPrecedenceSheet(version, uri, declaration string) string {
	return sheetStart + version + `"><xsl:import href="` + uri + `"/><xsl:output method="text"/>` + declaration + `<xsl:template name="start"><xsl:value-of select="$v"/></xsl:template></xsl:stylesheet>`
}

func TestGlobalImportPrecedence(t *testing.T) {
	for _, version := range []string{version20, version30} {
		for _, test := range globalPrecedenceCases() {
			e := engine(t, transform.Config{Resolver: transform.ResolverFunc(func(ctx context.Context, _ string) (io.ReadCloser, error) {
				return io.NopCloser(strings.NewReader(sheet(version, test.imported))), ctx.Err()
			})})
			for _, nested := range []bool{false, true} {
				got, err := resourceStylesheetResult(t, e, globalPrecedenceSheet(version, "urn:globals", test.local), nested)
				if comparisonErrorCode(test.want) {
					var detail *transform.Error
					if !errors.As(err, &detail) || detail.Code != test.want {
						t.Fatal(version, test.name, nested, got, err)
					}
				} else if err != nil || got != test.want {
					t.Fatal(version, test.name, nested, got, err)
				}
			}
		}
	}
}

func TestXSLTAssertionPolicyAndErrorNames(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		e := engine(t, transform.Config{EnableXSLTAssertions: enabled})

		for _, nested := range []bool{false, true} {
			for attribute, name := range map[string]transform.Name{
				"":                                       {Space: namespaceErrors, Local: errCodeXTMM9001},
				` error-code="p:ALARM"`:                  {Space: namespaceAssertions, Local: nameAssertionAlarm},
				` error-code="Q{{urn:assertions}}ALARM"`: {Space: namespaceAssertions, Local: nameAssertionAlarm},
				` error-code="{concat('p:', 'ALARM')}"`:  {Space: namespaceAssertions, Local: nameAssertionAlarm},
				` error-code="ALARM"`:                    {Local: nameAssertionAlarm},
				` error-code="{'missing:ALARM'}"`:        {Space: namespaceErrors, Local: errCodeXTMM9000},
				` error-code=""`:                         {Space: namespaceErrors, Local: errCodeXTMM9000},
				` error-code="{error()}"`:                {Space: namespaceErrors, Local: errCodeXTMM9000},
			} {
				source := sheet(version30, `<xsl:template name="start"><xsl:assert xmlns:p="urn:assertions" test="false()" select="'broken'"`+attribute+`/><xsl:text>after</xsl:text></xsl:template>`)

				got, err := resourceStylesheetResult(t, e, source, nested, enabled)
				if !enabled {
					if err != nil || got != afterAssertionText {
						t.Fatal(attribute, nested, got, err)
					}

					continue
				}

				var detail *transform.Error
				if !errors.As(err, &detail) || detail.Code != name.Local || detail.CodeName() != name {
					t.Fatal(attribute, nested, err, name)
				}
			}
		}
	}

	e := engine(t, transform.Config{EnableXSLTAssertions: true})

	for _, nested := range []bool{false, true} {
		source := sheet(version30, `<xsl:output method="text"/><xsl:template name="start"><xsl:try xmlns:p="urn:assertions" xmlns:err="http://www.w3.org/2005/xqt-errors"><xsl:assert test="error()" error-code="p:ALARM" select="'broken'"/><xsl:text>unreachable</xsl:text><xsl:catch errors="p:ALARM"><xsl:value-of select="namespace-uri-from-QName($err:code)||':'||local-name-from-QName($err:code)"/></xsl:catch></xsl:try></xsl:template>`)

		got, err := resourceStylesheetResult(t, e, source, nested, true)
		if err != nil || got != assertionErrorText {
			t.Fatal(nested, got, err)
		}
	}
}

func TestXSLTSimpleContentErrors(t *testing.T) {
	e := engine(t, transform.Config{})

	for _, nested := range []bool{false, true} {
		for instruction, code := range map[string]string{
			`<r value="{1 div 0}"/>`:                                                           errCodeFOAR0001,
			`<r value="{error(QName('urn:application', 'oops'))}"/>`:                           applicationErrorLocal,
			`<r value="{string#1}"/>`:                                                          errCodeFOTY0013,
			`<r value="{[1, [map{}]]}"/>`:                                                      errCodeFOTY0013,
			`<xsl:value-of select="[1,[string#1]]"/>`:                                          errCodeFOTY0013,
			`<xsl:comment select="[map{}]"/>`:                                                  errCodeFOTY0013,
			`<xsl:processing-instruction name="p" select="string#1"/>`:                         errCodeFOTY0013,
			`<r><xsl:attribute name="a" select="[map{}]"/></r>`:                                errCodeFOTY0013,
			`<r><xsl:namespace name="p"><xsl:sequence select="map{}"/></xsl:namespace></r>`:    errCodeFOTY0013,
			`<r><xsl:namespace name="p"><xsl:sequence select="string#1"/></xsl:namespace></r>`: errCodeFOTY0013,
		} {
			_, err := resourceStylesheetResult(t, e, sheet(version30, `<xsl:template name="start">`+instruction+`</xsl:template>`), nested)

			var detail *transform.Error
			if !errors.As(err, &detail) || detail.Code != code {
				t.Fatal(nested, instruction, err, code)
			}

			if code == applicationErrorLocal && detail.CodeName() != (transform.Name{Space: namespaceApplication, Local: applicationErrorLocal}) {
				t.Fatal(nested, detail.CodeName())
			}
		}

		program := sheet(version30, `<xsl:template name="start"><xsl:variable name="a" as="text()"><xsl:text>A</xsl:text></xsl:variable><xsl:variable name="b" as="text()"><xsl:text>B</xsl:text></xsl:variable><xsl:variable name="empty" as="text()"><xsl:text/></xsl:variable><xsl:value-of select="[$a, [], [$empty, $b], '', [1,2]]" separator="|"/></xsl:template>`)

		got, err := resourceStylesheetResult(t, e, program, nested)
		if err != nil || got != "A||B||1|2" {
			t.Fatal(nested, got, err)
		}

		program = sheet(version30, `<xsl:template name="start"><xsl:variable name="r" as="element()"><r xsl:version="1.0" value="{[1,2],3}"/></xsl:variable><xsl:value-of select="$r/@value"/></xsl:template>`)

		got, err = resourceStylesheetResult(t, e, program, nested)
		if err != nil || got != "1" {
			t.Fatal(nested, got, err)
		}

		for _, test := range namespaceSimpleContentCases() {
			got, err := resourceStylesheetResult(t, e, test.source, nested)
			if err != nil || got != test.want {
				t.Fatal(test.name, nested, got, err, test.want)
			}
		}
	}
}

func namespaceSimpleContentCases() []struct{ name, source, want string } {
	cases := make([]struct{ name, source, want string }, 0, 4)
	for _, test := range []struct{ name, variable, want string }{
		{"empty text", `<xsl:variable name="v" as="text()"><xsl:text/></xsl:variable>`, "||"},
		{"space text", `<xsl:variable name="v" as="text()"><xsl:text> </xsl:text></xsl:variable>`, " | | "},
		{"empty atomic", `<xsl:variable name="v" as="xs:string" select="''"/>`, " |  | "},
		{"document text", `<xsl:variable name="v"><xsl:sequence select="''"/><xsl:sequence select="''"/></xsl:variable>`, "  |   |  "},
	} {
		body := test.variable + `<xsl:variable name="n" as="node()"><xsl:namespace name="p"><xsl:sequence select="$v"/><xsl:value-of select="'|'"/><xsl:sequence select="$v"/><xsl:value-of select="'|'"/><xsl:sequence select="$v"/></xsl:namespace></xsl:variable><xsl:value-of select="$n"/>`
		cases = append(cases, struct{ name, source, want string }{test.name, sheet(version30, `<xsl:template name="start">`+body+`</xsl:template>`), test.want})
	}
	return cases
}

func TestXSLTExplicitGlobalContext(t *testing.T) {
	e := engine(t, transform.Config{})

	source, err := e.Parse(t.Context(), []byte(`<source/>`))
	if err != nil {
		t.Fatal(err)
	}

	const program = `<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:xs="http://www.w3.org/2001/XMLSchema" version="3.0"><xsl:global-context-item use="required" as="xs:integer"/><xsl:variable name="global" select="."/><xsl:template match="source"><xsl:value-of select="$global || ':' || name()"/></xsl:template><xsl:template name="start"><xsl:value-of select="$global || ':' || . || ':' || position() || ':' || last()"/></xsl:template></xsl:stylesheet>`

	sheet := stylesheet(t, e, program)
	item := transform.Integer(7)
	options := transform.XSLTContext{ContextItem: &item}

	matched, err := sheet.Execute(t.Context(), source, options)
	if err != nil || text(t, matched.Primary()) != "7:source" {
		t.Fatal("global context changed the initial match selection", matched, err)
	}

	named, err := sheet.CallTemplate(t.Context(), source, transform.Name{Local: nameStart}, options)
	if err != nil || text(t, named.Primary()) != "7:7:1:1" {
		t.Fatal("initial template did not inherit the supplied global focus", named, err)
	}

	query, err := e.CompileXPath(t.Context(), `transform(map{'stylesheet-text':$stylesheet, 'global-context-item':7, 'initial-template':QName('', 'start'), 'delivery-format':'raw'})?output`, transform.XPathOptions{})
	if err != nil {
		t.Fatal(err)
	}

	value, err := query.Evaluate(t.Context(), nil, transform.XPathContext{Variables: transform.Bindings{{Local: variableStylesheet}: transform.Values(transform.String(program))}})
	if err != nil || text(t, value) != "7:7:1:1" {
		t.Fatal("fn:transform and direct invocation disagree", value, err)
	}

	absent := transform.Value{}
	_, err = sheet.CallTemplate(t.Context(), source, transform.Name{Local: nameStart}, transform.XSLTContext{ContextItem: &absent})

	var detail *transform.Error
	if !errors.As(err, &detail) || detail.Code != "XTDE3086" {
		t.Fatal("explicitly absent required global context was accepted", err)
	}

	item = transform.String("wrong-type")

	_, err = sheet.CallTemplate(t.Context(), source, transform.Name{Local: nameStart}, options)
	if !errors.As(err, &detail) || detail.Code != "XTTE0590" {
		t.Fatal("wrong global context type was accepted", err)
	}
}

func TestDecimalFormatEmptyStringProperties(t *testing.T) {
	e := engine(t, transform.Config{})

	const expression = `format-number(xs:double('NaN'), '0') || '|' || format-number(xs:double('INF'), '0') || '|' || format-number(xs:double('-INF'), '0')`

	program, err := e.CompileXPath(t.Context(), expression, transform.XPathOptions{DecimalFormats: map[transform.Name]map[string]string{{}: {valueNaN: "", nameInfinityProperty: ""}}})
	if err != nil {
		t.Fatal(err)
	}

	value, err := program.Evaluate(t.Context(), nil, transform.XPathContext{})
	if err != nil || text(t, value) != "||-" {
		t.Fatal(value, err)
	}

	const prefix = `<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:xs="http://www.w3.org/2001/XMLSchema" version="3.0">`

	sheet := stylesheet(t, e, prefix+`<xsl:decimal-format NaN="" infinity=""/><xsl:template name="start"><out><xsl:value-of select="`+expression+`"/></out></xsl:template></xsl:stylesheet>`)

	result, err := sheet.CallTemplate(t.Context(), nil, transform.Name{Local: nameStart}, transform.XSLTContext{})
	if err != nil || text(t, result.Primary()) != "||-" {
		t.Fatal("empty string properties were replaced by defaults", result, err)
	}

	for _, declarations := range []string{
		`<xsl:decimal-format NaN=""/><xsl:decimal-format NaN="other"/>`,
		`<xsl:decimal-format infinity="other"/><xsl:decimal-format infinity=""/>`,
	} {
		_, err := e.CompileXSLT(t.Context(), []byte(prefix+declarations+`</xsl:stylesheet>`), transform.XSLTOptions{})

		var detail *transform.Error
		if !errors.As(err, &detail) || detail.Code != "XTSE1290" {
			t.Fatal("conflicting explicit string property accepted", err)
		}
	}
}

type staticParameterCase struct {
	name, declaration, argument, check, want string
}

func staticParameterCases() []staticParameterCase {
	return []staticParameterCase{
		{"required missing", `required="yes"`, "", `true()`, "XTDE0050"},
		{"implicitly required", `as="xs:integer"`, "", `true()`, "XTDE0050"},
		{"required empty supplied", `required="yes"`, `()`, `empty($p)`, nameTrue},
		{"optional untyped default", "", "", `$p instance of xs:string and $p eq ''`, nameTrue},
		{"optional typed default", `as="xs:integer?"`, "", `empty($p)`, nameTrue},
		{"commented optional type", `as="xs:integer? (: trailing :)"`, "", `empty($p)`, nameTrue},
		{"commented empty type", `as="empty-sequence() (: trailing :)"`, "", `empty($p)`, nameTrue},
		{"supplied integer", `as="xs:integer"`, `41`, `$p instance of xs:integer and $p eq 41`, nameTrue},
		{"untyped conversion", `as="xs:integer"`, `xs:untypedAtomic('41')`, `$p instance of xs:integer and $p eq 41`, nameTrue},
		{"string mismatch", `as="xs:integer"`, `'41'`, `true()`, "XTTE0590"},
		{"untyped lexical error", `as="xs:integer"`, `xs:untypedAtomic('bad')`, `true()`, "XTTE0590"},
		{"empty mismatch", `as="xs:integer"`, `()`, `true()`, "XTTE0590"},
		{"multiple mismatch", `as="xs:integer"`, `(1,2)`, `true()`, "XTTE0590"},
		{"numeric promotion", `as="xs:double"`, `41`, `$p instance of xs:double and $p eq 41`, nameTrue},
		{"URI promotion", `as="xs:string"`, `xs:anyURI('urn:value')`, `$p instance of xs:string and $p eq 'urn:value'`, nameTrue},
		{"node atomization", `as="xs:integer"`, `parse-xml('<n>41</n>')/n`, `$p instance of xs:integer and $p eq 41`, nameTrue},
		{"array atomization", `as="xs:integer*"`, `[1,[2]]`, `deep-equal($p,(1,2))`, nameTrue},
		{"namespace sensitive input", `as="xs:QName"`, `xs:untypedAtomic('local')`, `true()`, "XTTE0590"},
		{"declaration namespace", `xmlns:a="http://www.w3.org/2001/XMLSchema" as="a:integer"`, `xs:untypedAtomic('41')`, `$p instance of xs:integer`, nameTrue},
		{"default type namespace", `xpath-default-namespace="http://www.w3.org/2001/XMLSchema" as="integer"`, `xs:untypedAtomic('41')`, `$p instance of xs:integer`, nameTrue},
		{"default promotion", `as="xs:double" select="41"`, "", `$p instance of xs:double and $p eq 41`, nameTrue},
		{"default mismatch", `as="xs:integer" select="xs:date('2026-01-01')"`, "", `true()`, "XTTE0590"},
		{"unused default mismatch", `as="xs:integer" select="xs:date('2026-01-01')"`, `41`, `$p instance of xs:integer and $p eq 41`, nameTrue},
		{"empty select", `select=""`, "", `true()`, errCodeXPST0003},
		{"empty type", `as=""`, "", `true()`, errCodeXPST0003},
		{"required default", `required="yes" select="41"`, `41`, `true()`, "XTSE0010"},
		{"excluded required", `required="yes" use-when="false()"`, "", `true()`, nameTrue},
		{"excluded supplied mismatch", `as="xs:integer" use-when="false()"`, `'bad'`, `true()`, nameTrue},
		{"use when namespace", `xmlns:a="http://www.w3.org/2001/XMLSchema" use-when="a:boolean('true')" as="a:integer"`, `xs:untypedAtomic('41')`, `$p instance of xs:integer`, nameTrue},
		{"QName value namespace", `as="xs:QName"`, `QName('urn:value','a:local')`, `namespace-uri-from-QName($p) eq 'urn:value'`, nameTrue},
		{"empty use when", `required="yes" use-when="()"`, "", `true()`, nameTrue},
		{"use when boolean error", `use-when="(1,2)"`, "", `true()`, "FORG0006"},
	}
}

func staticParameterSheet(test staticParameterCase) string {
	return sheet(version30, `<xsl:param name="p" static="yes" `+test.declaration+`/><xsl:variable name="checked" static="yes" select="`+test.check+`"/><xsl:template name="start"><xsl:value-of select="$checked"/></xsl:template>`)
}

func staticParameterExpression(argument string) string {
	option := ""
	if argument != "" {
		option = ",'static-params':map{QName('','p'):" + argument + "}"
	}
	return `transform(map{'stylesheet-text':$stylesheet,'initial-template':QName('', 'start'),'delivery-format':'serialized'` + option + `})?output`
}

func staticParameterResult(t *testing.T, e *transform.Engine, source, argument string, nested bool) (string, error) {
	t.Helper()
	if nested {
		result, err := query(t, e, staticParameterExpression(argument), transform.XPath31).Evaluate(t.Context(), nil, transform.XPathContext{Variables: transform.Bindings{
			{Local: variableStylesheet}: transform.Values(transform.String(source)),
		}})
		if err != nil {
			return "", err
		}
		return text(t, result), nil
	}
	bindings := transform.Bindings{}
	if argument != "" {
		bindings[transform.Name{Local: "p"}] = evaluate(t, e, argument, transform.XPath31)
	}
	compiled, err := e.CompileXSLT(t.Context(), []byte(source), transform.XSLTOptions{StaticParameters: bindings})
	if err != nil {
		return "", err
	}
	result, err := compiled.Transform(t.Context(), nil, transform.XSLTContext{Template: transform.Name{Local: nameStart}})
	if err != nil {
		return "", err
	}
	return string(result.Primary), nil
}

func TestXSLTStaticParameterContracts(t *testing.T) {
	e := engine(t, transform.Config{})
	for _, test := range staticParameterCases() {
		t.Run(test.name, func(t *testing.T) {
			source := staticParameterSheet(test)
			bindings := transform.Bindings{}
			if test.argument != "" {
				bindings[transform.Name{Local: "p"}] = evaluate(t, e, test.argument, transform.XPath31)
			}

			compiled, err := e.CompileXSLT(t.Context(), []byte(source), transform.XSLTOptions{StaticParameters: bindings})
			if test.want == nameTrue {
				if err != nil {
					t.Fatal(err)
				}
				result, runErr := compiled.Transform(t.Context(), nil, transform.XSLTContext{Template: transform.Name{Local: nameStart}})
				if runErr != nil || string(result.Primary) != nameTrue {
					t.Fatal(result, runErr)
				}
			} else {
				var detail *transform.Error
				if !errors.As(err, &detail) || detail.Code != test.want {
					t.Errorf("CompileXSLT: %v, want %s", err, test.want)
				}
			}

			expression := staticParameterExpression(test.argument)
			result, err := query(t, e, expression, transform.XPath31).Evaluate(t.Context(), nil, transform.XPathContext{Variables: transform.Bindings{
				{Local: variableStylesheet}: transform.Values(transform.String(source)),
			}})
			if test.want == nameTrue {
				if err != nil || text(t, result) != nameTrue {
					t.Fatal(result, err)
				}
			} else {
				var detail *transform.Error
				if !errors.As(err, &detail) || detail.Code != test.want {
					t.Errorf("fn:transform: %v, want %s", err, test.want)
				}
			}
		})
	}
}

type staticVariableCase struct{ name, declaration, content, check, want string }

func staticVariableCases() []staticVariableCase {
	return []staticVariableCase{
		{"numeric promotion", `as="xs:double" select="41"`, "", `$p instance of xs:double and $p eq 41`, nameTrue},
		{"URI promotion", `as="xs:string" select="xs:anyURI('urn:value')"`, "", `$p instance of xs:string`, nameTrue},
		{"string mismatch", `as="xs:integer" select="'41'"`, "", `true()`, "XTTE0570"},
		{"untyped lexical error", `as="xs:integer" select="xs:untypedAtomic('bad')"`, "", `true()`, "XTTE0570"},
		{"missing select", "", "", `true()`, "XTSE0010"},
		{"empty select", `select=""`, "", `true()`, errCodeXPST0003},
		{"private visibility", `visibility="private" select="41"`, "", `$p eq 41`, nameTrue},
		{"public visibility", `visibility="public" select="41"`, "", `true()`, "XTSE0020"},
		{"default type namespace", `xpath-default-namespace="http://www.w3.org/2001/XMLSchema" as="integer" select="41"`, "", `$p instance of xs:integer`, nameTrue},
		{"excluded content", `select="41"`, `<n xmlns:a="http://www.w3.org/2001/XMLSchema" xsl:use-when="a:boolean('false')"/>`, `$p eq 41`, nameTrue},
		{"ordinary use when attribute", `select="41"`, `<n use-when="false()"/>`, `true()`, "XTSE0620"},
	}
}

func staticVariableSheet(test staticVariableCase) string {
	return sheet(version30, `<xsl:variable name="p" static="yes" `+test.declaration+`>`+test.content+`</xsl:variable><xsl:variable name="checked" static="yes" select="`+test.check+`"/><xsl:template name="start"><xsl:value-of select="$checked"/></xsl:template>`)
}

func TestXSLTStaticVariableContracts(t *testing.T) {
	e := engine(t, transform.Config{})
	for _, test := range staticVariableCases() {
		source := staticVariableSheet(test)
		for _, nested := range []bool{false, true} {
			got, err := resourceStylesheetResult(t, e, source, nested)
			if test.want == nameTrue {
				if err != nil || got != nameTrue {
					t.Fatal(nested, test.declaration, got, err)
				}
			} else {
				var detail *transform.Error
				if !errors.As(err, &detail) || detail.Code != test.want {
					t.Fatal(nested, test.declaration, err, test.want)
				}
			}
		}
	}
}

func TestXSLTDependentStaticParameters(t *testing.T) {
	calls := 0
	e := engine(t, transform.Config{Functions: []transform.Function{{
		Name: transform.Name{Space: "urn:static-functions", Local: "default"},
		Call: func(ctx context.Context, _ []transform.Sequence) (transform.Sequence, error) {
			calls++
			return transform.Values(transform.String("default")), ctx.Err()
		},
	}}})

	for _, test := range []struct{ name, ref, uri, fallback string }{
		{"a", "$a", "", "'old'"},
		{"p:a", "$q:a", "urn:static-parameters", "'old'"},
		{"a", "$a", "", "f:default()"},
	} {
		source := sheet(version30, `<xsl:param name="`+test.name+`" static="yes" select="`+test.fallback+`"/><xsl:param name="b" static="yes" select="upper-case(`+test.ref+`)"/><xsl:template name="start"><xsl:value-of select="concat(`+test.ref+`, '|', $b)"/></xsl:template>`)
		source = strings.Replace(source, `version="3.0"`, `version="3.0" xmlns:p="urn:static-parameters" xmlns:q="urn:static-parameters" xmlns:f="urn:static-functions"`, 1)
		bindings := transform.Bindings{{Space: test.uri, Local: "a"}: transform.Values(transform.String("Hello"))}

		compiled, err := e.CompileXSLT(t.Context(), []byte(source), transform.XSLTOptions{StaticParameters: bindings})
		if err != nil {
			t.Fatal(err)
		}

		output, err := compiled.Transform(t.Context(), nil, transform.XSLTContext{Template: transform.Name{Local: nameStart}})
		if err != nil || string(output.Primary) != "Hello|HELLO" {
			t.Errorf("CompileXSLT %s: %q, %v", test.name, output.Primary, err)
		}

		result, err := query(t, e, `transform(map{'stylesheet-text':$stylesheet,'static-params':map{QName($uri,'a'):'Hello'},'initial-template':QName('', 'start'),'delivery-format':'serialized'})?output`, transform.XPath31).Evaluate(t.Context(), nil, transform.XPathContext{Variables: transform.Bindings{
			{Local: variableStylesheet}: transform.Values(transform.String(source)),
			{Local: variableURI}:        transform.Values(transform.String(test.uri)),
		}})
		if err != nil || text(t, result) != "Hello|HELLO" {
			t.Errorf("fn:transform %s: %v, %v", test.name, result, err)
		}
	}

	if calls != 0 {
		t.Fatal("provided static parameter evaluated its unused default", calls)
	}

	for _, test := range []struct{ source, want string }{
		{sheet(version30, `<xsl:param name="a" static="yes" select="'old'"/><xsl:param name="b" static="yes" select="upper-case($a)"/><xsl:template name="start"><xsl:value-of select="concat($a,'|',$b)"/></xsl:template>`), "old|OLD"},
	} {
		compiled := stylesheet(t, e, test.source)

		output, err := compiled.Transform(t.Context(), nil, transform.XSLTContext{Template: transform.Name{Local: nameStart}})
		if err != nil || string(output.Primary) != test.want {
			t.Fatal(output, err)
		}
	}

	for _, test := range []struct{ body, code string }{
		{`<xsl:param name="a" static="yes" select="1 +"/>`, errCodeXPST0003},
		{`<xsl:template name="start" use-when="$a"/>`, "XPST0008"},
	} {
		_, err := e.CompileXSLT(t.Context(), []byte(sheet(version30, test.body)), transform.XSLTOptions{
			StaticParameters: transform.Bindings{{Local: "a"}: transform.Values(transform.String("Hello"))},
		})

		var detail *transform.Error
		if !errors.As(err, &detail) || detail.Code != test.code {
			t.Fatalf("%s: %v", test.body, err)
		}
	}

	source := sheet(version30, `<xsl:param name="a" static="yes" select="'old'"/><xsl:param name="b" static="yes" select="count($a)"/><xsl:template name="start"><xsl:value-of select="$b"/></xsl:template>`)

	compiled, err := e.CompileXSLT(t.Context(), []byte(source), transform.XSLTOptions{
		StaticParameters: transform.Bindings{{Local: "a"}: transform.Sequence{}},
	})
	if err != nil {
		t.Fatal(err)
	}

	output, err := compiled.Transform(t.Context(), nil, transform.XSLTContext{Template: transform.Name{Local: nameStart}})
	if err != nil || string(output.Primary) != "0" {
		t.Fatal(output, err)
	}
}

func TestXPathTransformFunction(t *testing.T) {
	e := engine(t, transform.Config{})

	for _, version := range []string{version10, version20, version30} {
		source := sheet(version, `<xsl:template name="start"><xsl:text>hello</xsl:text></xsl:template>`)

		for _, call := range []string{"transform", "fn:transform#1", "function-lookup(xs:QName('fn:transform'),1)"} {
			program := query(t, e, strings.Replace(transformSerializedQuery, "transform(", call+"(", 1), transform.XPath31)

			result, err := program.Evaluate(t.Context(), nil, transform.XPathContext{Variables: transform.Bindings{
				{Local: variableStylesheet}: transform.Values(transform.String(source)),
			}})
			if err != nil || text(t, result) != "hello" {
				t.Errorf("XSLT %s via %s: %v, %v", version, call, result, err)
			}
		}
	}

	for _, test := range []struct{ source, expression, want string }{
		{
			sheet(version30, `<xsl:param name="who"/><xsl:template name="start"><xsl:value-of select="concat('hello ', $who)"/></xsl:template>`),
			`transform(map{'stylesheet-node':parse-xml($stylesheet), 'initial-template':QName('', 'start'), 'stylesheet-params':map{QName('', 'who'):'Bob'}, 'delivery-format':'serialized'})?output`, "hello Bob",
		},
		{
			sheet(version30, `<xsl:template name="start"><xsl:sequence select="(2,3)"/></xsl:template>`),
			`sum(transform(map{'stylesheet-text':$stylesheet, 'initial-template':QName('', 'start'), 'delivery-format':'raw'})?output)`, "5",
		},
		{
			sheet(version30, `<xsl:template name="start"><xsl:sequence select="current-dateTime()"/></xsl:template>`),
			`current-dateTime() eq transform(map{'stylesheet-text':$stylesheet, 'initial-template':QName('', 'start'), 'delivery-format':'raw'})?output`, nameTrue,
		},
		{
			sheet(version30, `<xsl:template name="start"><xsl:sequence select="(2,3)"/></xsl:template>`),
			`transform(map{'stylesheet-text':$stylesheet,'initial-template':QName('', 'start'),'delivery-format':'raw','post-process':function($uri,$value){string-join($value ! string(.), ':')}})?output`, "2:3",
		},
		{
			sheet(version30, `<xsl:template name="start">one<xsl:result-document href="secondary.txt" method="text">two</xsl:result-document></xsl:template>`),
			`let $r := transform(map{'stylesheet-text':$stylesheet,'initial-template':QName('', 'start'),'delivery-format':'serialized','base-output-uri':'https://output.invalid/main.txt'}) return concat($r('https://output.invalid/main.txt'), ':', $r('https://output.invalid/secondary.txt'))`, "one:two",
		},
		{
			`<wrapper xmlns:p="urn:inherited" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:stylesheet version="3.0"><xsl:output method="text"/><xsl:template name="p:start">hello</xsl:template></xsl:stylesheet></wrapper>`,
			`let $node := parse-xml($stylesheet), $before := serialize($node), $r := transform(map{'stylesheet-node':$node/*/*,'initial-template':QName('urn:inherited','start'),'delivery-format':'serialized'}) return concat($r?output, ':', serialize($node) eq $before)`, "hello:true",
		},
		{
			sheet(version30, `<xsl:template match="/"><out/></xsl:template>`),
			`count(transform(map{'stylesheet-text':$stylesheet,'initial-match-selection':()})?output/*)`, "0",
		},
		{
			sheet(version30, `<xsl:template name="start"/>`),
			`let $r := transform(map{'stylesheet-text':$stylesheet,'initial-template':QName('', 'start'),'delivery-format':'raw'}) return map:contains($r,'output') and empty($r?output)`, nameTrue,
		},
		{
			sheet(version30, `<xsl:template name="start"/>`),
			`let $r := transform(map{'stylesheet-text':$stylesheet,'initial-template':QName('', 'start')}) return $r?output instance of document-node() and empty($r?output/node())`, nameTrue,
		},
		{
			sheet(version30, `<xsl:template name="start"><xsl:result-document href="secondary" method="adaptive"><xsl:sequence select="(1,map{'value':3},2)"/></xsl:result-document></xsl:template>`),
			`let $r := transform(map{'stylesheet-text':$stylesheet,'initial-template':QName('', 'start'),'base-output-uri':'https://output.invalid/main','delivery-format':'raw'}) return empty($r('https://output.invalid/main')) and map:contains($r,'https://output.invalid/main') and $r('https://output.invalid/secondary')[1] eq 1 and $r('https://output.invalid/secondary')[2]?value eq 3 and $r('https://output.invalid/secondary')[3] eq 2`, nameTrue,
		},
		{
			sheet(version30, `<xsl:template name="start"><xsl:sequence select="(1,2)"/></xsl:template>`),
			`transform(map{'stylesheet-text':$stylesheet,'initial-template':QName('', 'start'),'post-process':function($uri,$value){$value instance of document-node() and string($value) eq '1 2'}})?output`, nameTrue,
		},
	} {
		result, err := query(t, e, test.expression, transform.XPath31).Evaluate(t.Context(), nil, transform.XPathContext{Variables: transform.Bindings{
			{Local: variableStylesheet}: transform.Values(transform.String(test.source)),
		}})
		if err != nil || text(t, result) != test.want {
			t.Error(test.expression, result, err)
		}
	}
}

func TestXPathTransformErrorCodes(t *testing.T) {
	e := engine(t, transform.Config{})
	for _, test := range []struct{ expression, code string }{
		{`transform(1)`, errCodeXPTY0004},
		{`transform(())`, errCodeXPTY0004},
		{`transform(map{})`, "FOXT0002"},
		{`transform(map{'stylesheet-text':$stylesheet,'xslt-version':()})`, errCodeXPTY0004},
		{`transform(map{'stylesheet-text':$stylesheet,'xslt-version':(2,3)})`, errCodeXPTY0004},
		{`transform(map{'stylesheet-text':$stylesheet,'xslt-version':4})`, errCodeFOXT0001},
		{`transform(map{'stylesheet-text':$stylesheet,'xslt-version':3.0000000000000000000000000001})`, errCodeFOXT0001},
		{`transform(map{'stylesheet-text':$stylesheet,'xslt-version':2})`, errCodeXTDE0040},
		{`transform(map{'stylesheet-text':$stylesheet, 'initial-template':QName('', 'missing')})`, errCodeXTDE0040},
		{`transform(map{'stylesheet-text':$invalid})`, errCodeXPST0003},
		{`transform(map{'stylesheet-text':$stylesheet})`, errCodeXTDE0040},
		{`transform(map{'stylesheet-text':$required,'initial-template':QName('', 'start')})`, "XTDE0700"},
		{`transform(map{'stylesheet-text':$application,'initial-template':QName('', 'start')})`, applicationErrorLocal},
		{`transform(map{'stylesheet-text':$stylesheet,'requested-properties':map{QName('http://www.w3.org/1999/XSL/Transform','supports-streaming'):true()}})`, errCodeFOXT0001},
	} {
		result, err := query(t, e, test.expression, transform.XPath31).Evaluate(t.Context(), nil, transform.XPathContext{Variables: transform.Bindings{
			{Local: variableStylesheet}: transform.Values(transform.String(sheet(version30, `<xsl:template name="start"/>`))),
			{Local: invalidValue}:       transform.Values(transform.String(sheet(version30, `<xsl:template name="start"><xsl:sequence select="1 +"/></xsl:template>`))),
			{Local: "application"}:      transform.Values(transform.String(sheet(version30, `<xsl:template name="start"><xsl:sequence select="error(QName('urn:application','x:oops'))"/></xsl:template>`))),
			{Local: "required"}:         transform.Values(transform.String(sheet(version30, `<xsl:template name="start"><xsl:param name="p" required="yes"/></xsl:template>`))),
		}})

		var detail *transform.Error
		if !errors.As(err, &detail) || detail.Code != test.code || result.Len() != 0 {
			t.Errorf("%s: %v, %v", test.expression, result, err)
		}

		if test.code == applicationErrorLocal && detail != nil && detail.CodeName() != (transform.Name{Space: namespaceApplication, Local: applicationErrorLocal}) {
			t.Fatal("application error namespace was lost", detail.CodeName())
		}
	}
}

func TestXSLTValueTemplateErrorCodes(t *testing.T) {
	e := engine(t, transform.Config{})
	for _, test := range []struct{ name, body, code string }{
		{"attribute left brace", `<r a="{1"/>`, "XTSE0350"},
		{"attribute right brace", `<r a="1}"/>`, "XTSE0370"},
		{"text left brace", `<r xsl:expand-text="yes">{1</r>`, "XTSE0350"},
		{"text right brace", `<r xsl:expand-text="yes">1}</r>`, "XTSE0370"},
		{"invalid enclosed expression", `<r a="{1 +}"/>`, errCodeXPST0003},
		{"value-of select and content", `<xsl:value-of select="1">text</xsl:value-of>`, "XTSE0870"},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := e.CompileXSLT(t.Context(), []byte(sheet(version30, `<xsl:template name="start">`+test.body+`</xsl:template>`)), transform.XSLTOptions{})

			var detail *transform.Error
			if !errors.As(err, &detail) || detail.Code != test.code {
				t.Fatalf("want %s, got %v", test.code, err)
			}
		})
	}

	s := stylesheet(t, e, sheet(version30, `<xsl:template name="start"><xsl:text expand-text="yes">{{{map{'key':'}'}?key}}}</xsl:text></xsl:template>`))

	out, err := s.Transform(t.Context(), nil, transform.XSLTContext{Template: transform.Name{Local: nameStart}})
	if err != nil || string(out.Primary) != "{}}" {
		t.Fatal("balanced expression or escaped braces changed", out, err)
	}
}

func TestXSLTStandaloneAttributeValues(t *testing.T) {
	e := engine(t, transform.Config{})
	for _, version := range []string{version20, version30} {
		t.Run(version, func(t *testing.T) {
			source := sheetStart + version + `"><xsl:output method="xml" omit-xml-declaration="yes"/>
			<xsl:template name="start">
			  <xsl:variable name="attrs" as="attribute()*">
			    <xsl:attribute name="plain">p&amp;q&lt;r</xsl:attribute>
			    <xsl:attribute name="n:qualified" namespace="urn:attribute" select="'literal &amp;amp; text'"/>
			    <xsl:attribute name="empty"/>
			  </xsl:variable>
			  <out count="{count($attrs)}" parents="{count($attrs/..)}"><xsl:sequence select="$attrs"/></out>
			</xsl:template></xsl:stylesheet>`
			s := stylesheet(t, e, source)

			out, err := s.Transform(t.Context(), nil, transform.XSLTContext{Template: transform.Name{Local: nameStart}})
			if err != nil {
				t.Fatal(err)
			}

			doc, err := e.Parse(t.Context(), out.Primary)
			if err != nil {
				t.Fatal(err)
			}

			q := query(t, e, `count(/out/@*) = 5 and /out/@count = '3' and /out/@parents = '0' and /out/@plain = 'p&q<r' and /out/@Q{urn:attribute}qualified = 'literal &amp; text' and /out/@empty = ''`, transform.XPath31)

			values, err := q.Evaluate(t.Context(), doc, transform.XPathContext{})
			if err != nil || text(t, values) != nameTrue {
				t.Fatal(string(out.Primary), values, err)
			}

			invalid := stylesheet(t, e, strings.Replace(source, `<xsl:sequence select="$attrs"/>`, `<child/><xsl:sequence select="$attrs"/>`, 1))
			_, err = invalid.Transform(t.Context(), nil, transform.XSLTContext{Template: transform.Name{Local: nameStart}})

			var detail *transform.Error
			if !errors.As(err, &detail) || detail.Code != "XTDE0410" {
				t.Fatal("attribute accepted after child content", err)
			}
		})
	}
}

func TestXSLT20And30(t *testing.T) {
	e := engine(t, transform.Config{})

	d, err := e.Parse(context.Background(), []byte(`<r><item category="b">3</item><item category="a">2</item><item category="b">4</item></r>`))
	if err != nil {
		t.Fatal(err)
	}

	style2 := stylesheet(t, e, sheet(version20, `<xsl:param name="offset" as="xs:integer"/><xsl:template match="/"><xsl:for-each-group select="r/item" group-by="@category"><xsl:sort select="current-grouping-key()"/><xsl:value-of select="current-grouping-key()"/><xsl:text>:</xsl:text><xsl:value-of select="sum(current-group())+$offset"/><xsl:text>;</xsl:text></xsl:for-each-group></xsl:template>`))

	out, err := style2.Transform(context.Background(), d, transform.XSLTContext{Parameters: transform.Bindings{{Local: "offset"}: transform.Values(transform.Integer(10))}})
	if err != nil || string(out.Primary) != "a:12;b:17;" {
		t.Fatal(out, err)
	}

	style3 := stylesheet(t, e, sheet(version30, `<xsl:template name="start"><xsl:iterate select="1 to 5"><xsl:param name="sum" select="0"/><xsl:on-completion><xsl:value-of select="$sum"/></xsl:on-completion><xsl:next-iteration><xsl:with-param name="sum" select="$sum + ."/></xsl:next-iteration></xsl:iterate><xsl:message>done</xsl:message><xsl:result-document href="second.txt" method="text"><xsl:value-of select="map{'answer':42}?answer"/></xsl:result-document></xsl:template>`))

	out, err = style3.Transform(context.Background(), nil, transform.XSLTContext{Template: transform.Name{Local: nameStart}, BaseOutputURI: "urn:outputs:"})
	if err != nil || string(out.Primary) != "15" || len(out.Secondary) != 1 || len(out.Messages) != 1 || out.Messages[0].Text != "done" {
		t.Fatal(out, err)
	}

	for _, b := range out.Secondary {
		if string(b) != "42" {
			t.Fatal(out)
		}
	}

	if style2.Version() != transform.XSLT20 || style3.Version() != transform.XSLT30 {
		t.Fatal("version")
	}
}

func TestXSLTPreservesNonXMLWhitespace(t *testing.T) {
	e := engine(t, transform.Config{})

	for _, version := range []string{version10, version20, version30} {
		for _, text := range []string{"\u00a0", "\u1680", "\u2003"} {
			style := stylesheet(t, e, sheet(version, `<xsl:template name="start">`+text+`</xsl:template>`))

			out, err := style.Transform(t.Context(), nil, transform.XSLTContext{Template: transform.Name{Local: nameStart}})
			if err != nil || string(out.Primary) != text {
				t.Errorf("XSLT %s lost literal %q: %q, %v", version, text, out.Primary, err)
			}
		}
	}

	// A non-XML space before a parameter is real template content, so it
	// cannot be ignored to make an otherwise misplaced declaration valid.
	invalid := sheet(version30, "<xsl:template name='start'>\u00a0<xsl:param name='p'/></xsl:template>")
	if _, err := e.CompileXSLT(t.Context(), []byte(invalid), transform.XSLTOptions{}); err == nil {
		t.Error("significant template text ignored before parameter")
	}

	style := stylesheet(t, e, sheetStart+version30+`"><xsl:output method="xml" indent="yes" omit-xml-declaration="yes"/><xsl:param name="space"/><xsl:template name="start"><r><xsl:value-of select="$space" disable-output-escaping="yes"/><c/></r></xsl:template></xsl:stylesheet>`)

	out, err := style.Transform(t.Context(), nil, transform.XSLTContext{Template: transform.Name{Local: nameStart}, Parameters: transform.Bindings{{Local: "space"}: transform.Values(transform.String("\u00a0"))}})
	if err != nil || !bytes.Contains(out.Primary, []byte("\u00a0")) {
		t.Errorf("indentation lost significant non-XML whitespace: %q, %v", out.Primary, err)
	}
}

func TestXSLTDecimalCompatibilityVersions(t *testing.T) {
	e := engine(t, transform.Config{})
	for _, processor := range []transform.XSLTVersion{transform.XSLT20, transform.XSLT30} {
		for _, version := range []string{"-29", "0", "-0.0", "0.5", "+1.50"} {
			for _, local := range []bool{false, true} {
				body := `<xsl:template name="start"><xsl:value-of select="1 to 5"/></xsl:template>`
				declaration := version
				if local {
					declaration = "3.0"
					body = `<xsl:template name="start"><xsl:value-of version="` + version + `" select="1 to 5"/></xsl:template>`
				}
				compiled, err := e.CompileXSLT(t.Context(), []byte(sheet(declaration, body)), transform.XSLTOptions{ProcessorVersion: processor})
				if err != nil {
					t.Fatal(processor, version, local, err)
				}
				result, err := compiled.Transform(t.Context(), nil, transform.XSLTContext{Template: transform.Name{Local: nameStart}})
				if err != nil || string(result.Primary) != "1" || compiled.Version() != processor {
					t.Fatal(processor, version, local, result, err)
				}
			}
		}
	}
}

func TestXSLTVersionBoundaries(t *testing.T) {
	e := engine(t, transform.Config{})
	for _, test := range booleanProfileCases() {
		compiled, err := e.CompileXSLT(t.Context(), []byte(hostFunctionSheet(version30, test)), transform.XSLTOptions{ProcessorVersion: transform.XSLT20})
		got := ""
		if err == nil {
			out, runErr := compiled.Transform(t.Context(), nil, transform.XSLTContext{Template: transform.Name{Local: nameStart}})
			err = runErr
			if err == nil {
				got = string(out.Primary)
			}
		}
		if err != nil {
			var detail *transform.Error
			if !errors.As(err, &detail) {
				t.Fatal(test.name, err)
			}
			got = detail.Code
		}
		if got != test.want20 {
			t.Fatal("2.0 forward boolean vocabulary", test.name, got, err, test.want20)
		}
	}

	if _, err := e.CompileXSLT(t.Context(), []byte(packageSheet("", `<xsl:template name="start"/>`)), transform.XSLTOptions{ProcessorVersion: transform.XSLT20}); err == nil {
		t.Fatal("2.0 accepted xsl:package as a stylesheet module")
	}

	for _, body := range []string{
		`<xsl:template match="/"><xsl:iterate select="1"/></xsl:template>`,
		`<xsl:param name="p" static="yes" select="1"/>`,
		`<xsl:template match="/"><xsl:value-of select="map{'a':1}?a"/></xsl:template>`,
		`<xsl:template match="/" expand-text="yes">{1+1}</xsl:template>`,
		`<xsl:param name="p" as="array(*)"/>`,
	} {
		if _, err := e.CompileXSLT(context.Background(), []byte(sheet(version20, body)), transform.XSLTOptions{}); err == nil {
			t.Error("2.0 accepted", body)
		}
	}

	for _, version := range []string{"1e0", namePositiveInfinity, "NaN"} {
		_, err := e.CompileXSLT(context.Background(), []byte(sheet(version, `<xsl:template match="/"/>`)), transform.XSLTOptions{})

		var detail *transform.Error
		if !errors.As(err, &detail) || detail.Code != "XTSE0110" {
			t.Fatal(version, err)
		}
	}
}

func TestXSLTBasicSchemaBoundaries(t *testing.T) {
	e := engine(t, transform.Config{})

	for _, version := range []string{version20, version30} {
		for body, code := range map[string]string{
			`<xsl:import-schema namespace="urn:x"/>`:                                             "XTSE1650",
			`<xsl:template name="start"><xsl:element name="r" type="xs:string"/></xsl:template>`: errCodeXTSE1660,
			`<xsl:template name="start"><r xsl:type="xs:integer"/></xsl:template>`:               errCodeXTSE1660,
			`<xsl:template name="start"><r xsl:validation="strict"/></xsl:template>`:             errCodeXTSE1660,
			`<xsl:template name="start" as="element(*, xs:integer)"/>`:                           errCodeXTSE1660,
			`<xsl:param name="typed" as="attribute(*, xs:string)?"/>`:                            errCodeXTSE1660,
			`<xsl:variable name="typed" as="document-node(element(*, xs:date))?" select="()"/>`:  errCodeXTSE1660,
		} {
			_, err := e.CompileXSLT(t.Context(), []byte(sheet(version, body)), transform.XSLTOptions{})

			var detail *transform.Error
			if !errors.As(err, &detail) || detail.Code != code {
				t.Fatal(version, body, err, code)
			}
		}

		for _, validation := range []string{"lax", "preserve", "strip"} {
			body := `<xsl:template name="start"><xsl:variable name="node" as="element(*, xs:untyped)"><xsl:element name="r" validation="` + validation + `"><xsl:attribute name="a" validation="` + validation + `">text</xsl:attribute><child xsl:validation="` + validation + `"/></xsl:element></xsl:variable><xsl:variable name="copy" as="element(*, xs:anyType)"><xsl:copy-of select="$node" validation="` + validation + `"/></xsl:variable><xsl:variable name="doc" as="document-node()"><xsl:document validation="` + validation + `"><xsl:for-each select="$node"><xsl:copy validation="` + validation + `"><xsl:copy-of select="$node/@a, $node/*"/></xsl:copy></xsl:for-each></xsl:document></xsl:variable><xsl:value-of select="$copy instance of element(*, xs:untyped), $copy/@a instance of attribute(*, xs:untypedAtomic), count($doc/r/child)"/></xsl:template>`

			program := strings.Replace(sheet(version, body), `version="`+version+`"`, `default-validation="`+validation+`" version="`+version+`"`, 1)
			for _, nested := range []bool{false, true} {
				got, err := resourceStylesheetResult(t, e, program, nested)
				if version == version20 && !nested && validation != "strip" {
					var detail *transform.Error
					if !errors.As(err, &detail) || detail.Code != errCodeXTSE1660 {
						t.Fatal(version, validation, nested, got, err)
					}
					continue
				}
				if err != nil || got != "true true 1" {
					t.Fatal(version, validation, nested, got, err)
				}
			}
		}
	}
}

func TestXSLTBasicMaterializedStreaming(t *testing.T) {
	e := engine(t, transform.Config{Resolver: transform.ResolverFunc(func(ctx context.Context, _ string) (io.ReadCloser, error) {
		return io.NopCloser(strings.NewReader(`<r><i>1</i><i>2</i></r>`)), ctx.Err()
	})})

	doc, err := e.Parse(t.Context(), []byte(`<r><i/><i/></r>`))
	if err != nil {
		t.Fatal(err)
	}

	program := sheet(version30, `<xsl:mode name="m" streamable="yes" use-accumulators="a"/><xsl:accumulator name="a" as="xs:integer" initial-value="0"><xsl:accumulator-rule match="i" select="$value + 1"/></xsl:accumulator><xsl:variable name="size" select="count(/*/i)"/><xsl:template match="/" mode="m"><xsl:value-of select="$size, system-property('xsl:supports-streaming'), function-lookup(QName('http://www.w3.org/2005/xpath-functions','accumulator-after'),1)('a')"/></xsl:template>`)

	out, err := stylesheet(t, e, program).Transform(t.Context(), doc, transform.XSLTContext{Mode: transform.Name{Local: "m"}})
	if err != nil || string(out.Primary) != "2 no 2" {
		t.Fatal(out, err)
	}

	expression := `transform(map{'stylesheet-text':$stylesheet,'source-node':$source,'initial-mode':QName('', 'm'),'delivery-format':'serialized'})?output`

	result, err := query(t, e, expression, transform.XPath31).Evaluate(t.Context(), nil, transform.XPathContext{Variables: transform.Bindings{
		{Local: variableStylesheet}: transform.Values(transform.String(program)),
		{Local: sourceName}:         transform.Values(doc.Root()),
	}})
	if err != nil || text(t, result) != "2 no 2" {
		t.Fatal(result, err)
	}

	for _, nested := range []bool{false, true} {
		for _, use := range []string{"a", ""} {
			source := sheet(version30, `<xsl:accumulator name="a" as="xs:integer" initial-value="0"><xsl:accumulator-rule match="i" select="$value + 1"/></xsl:accumulator><xsl:template name="start"><xsl:source-document href="urn:materialized" streamable="yes" use-accumulators="`+use+`"><xsl:value-of select="accumulator-after('a')"/></xsl:source-document></xsl:template>`)

			got, callErr := resourceStylesheetResult(t, e, source, nested)
			if use != "" {
				if callErr != nil || got != "2" {
					t.Fatal(nested, got, callErr)
				}
			} else {
				var detail *transform.Error
				if !errors.As(callErr, &detail) || detail.Code != "XTDE3362" {
					t.Fatal(nested, got, callErr)
				}
			}
		}
	}
}

func TestXSLTTransformProcessorVersion(t *testing.T) {
	e := engine(t, transform.Config{})
	program := sheet(version20, `<xsl:output method="text"/><xsl:template name="start"><xsl:value-of select="system-property('xsl:version')"/><xsl:iterate select="1 to 2"><xsl:value-of select="map{'value':.}?value"/></xsl:iterate></xsl:template>`)

	for _, minimum := range []string{"3", "2.5", "2.0000000000000000000000000001"} {
		expression := `transform(map{'stylesheet-text':$stylesheet, 'xslt-version':` + minimum + `, 'initial-template':QName('', 'start'), 'delivery-format':'serialized'})?output`

		result, err := query(t, e, expression, transform.XPath31).Evaluate(t.Context(), nil, transform.XPathContext{Variables: transform.Bindings{{Local: variableStylesheet}: transform.Values(transform.String(program))}})
		if err != nil || text(t, result) != "3.012" {
			t.Fatal(result, err)
		}
	}
}

func TestXSLTProcessorVersion(t *testing.T) {
	e := engine(t, transform.Config{})
	for _, tc := range []struct {
		name, declaration, body, want string
		processor                     transform.XSLTVersion
	}{
		{"modern syntax in 2.0 declaration", version20, `<xsl:iterate select="1 to 2"><xsl:value-of select="map{'value':.}?value"/></xsl:iterate>`, "12", transform.XSLT30},
		{"modern grammar with 1.0 compatibility", version10, `<xsl:value-of select="(10, 20)"/><xsl:value-of version="3.0" select="(30, 40)"/>`, compatSequenceText, transform.XSLT30},
		{"2.0 grammar with 1.0 compatibility", version10, `<xsl:value-of select="(10, 20)"/><xsl:value-of version="2.0" select="(30, 40)"/>`, compatSequenceText, transform.XSLT20},
		{"local compatibility in 2.0", version20, `<xsl:value-of version="1.0" select="(10, 20)"/><xsl:value-of select="(30, 40)"/>`, compatSequenceText, transform.XSLT20},
		{"3.0 processor introspection", version20, `<xsl:value-of select="system-property('xsl:version')"/><xsl:text>:</xsl:text><xsl:value-of select="element-available('xsl:iterate')"/>`, "3.0:true", transform.XSLT30},
		{"2.0 processor introspection", version20, `<xsl:value-of select="system-property('xsl:version')"/><xsl:text>:</xsl:text><xsl:value-of select="element-available('xsl:iterate')"/>`, "2.0:false", transform.XSLT20},
		{"2.0 host functions", version20, `<xsl:value-of select="format-number(1,'000'), format-date(xs:date('2026-01-01'),'[Y]'), empty(unparsed-text(())), unparsed-text-available(())"/>`, "001 2026 true false", transform.XSLT20},
		{"2.0 string join conversion", version20, `<xsl:value-of select="string-join((xs:untypedAtomic('a'),xs:anyURI('b')),'/')"/>`, "a/b", transform.XSLT20},
		{"3.0 string join signature", version20, `<xsl:value-of select="string-join((1,2),'')"/>`, "12", transform.XSLT30},
		{"2.0 top level availability", version20, `<xsl:value-of select="element-available('xsl:stylesheet')"/>`, "false", transform.XSLT20},
		{"3.0 top level availability", version20, `<xsl:value-of select="element-available('xsl:stylesheet')"/>`, "true", transform.XSLT30},
		{"2.0 use when function library", version20, `<xsl:text use-when="function-available('generate-id')">available</xsl:text><xsl:text use-when="not(function-available('generate-id'))">unavailable</xsl:text>`, "unavailable", transform.XSLT20},
		{"3.0 use when function library", version30, `<xsl:text use-when="function-available('generate-id')">available</xsl:text><xsl:text use-when="not(function-available('generate-id'))">unavailable</xsl:text>`, "available", transform.XSLT30},
		{"2.0 function library", version20, `<xsl:value-of xmlns:fn="http://www.w3.org/2005/xpath-functions" select="function-available('json-doc', 1), function-available('current-output-uri', 0), function-available('fn:current-output-uri', 0)"/>`, "false false false", transform.XSLT20},
		{"3.0 function library", version20, `<xsl:value-of xmlns:fn="http://www.w3.org/2005/xpath-functions" select="function-available('json-doc', 1), function-available('current-output-uri', 0), function-available('fn:current-output-uri', 0)"/>`, "true true true", transform.XSLT30},
		{"2.0 processor with future declaration", version30, `<xsl:iterate select="invalid XPath"><xsl:fallback><xsl:text>fallback</xsl:text></xsl:fallback></xsl:iterate>`, nameFallbackResult, transform.XSLT20},
		{"ignored 3.0 attribute", version30, `<xsl:text expand-text="yes">{1+1}</xsl:text>`, "{1+1}", transform.XSLT20},
		{"future declaration", version40, stylesheetFallback, nameFallbackResult, transform.XSLT30},
		{"expanded future decimal", "10.0", stylesheetFallback, nameFallbackResult, transform.XSLT30},
		{"future decimal precision", "3.0000000000000000000000000001", stylesheetFallback, nameFallbackResult, transform.XSLT30},
		{"backwards decimal precision", "1.9999999999999999999999999999", `<xsl:value-of select="(10,20)"/>`, "10", transform.XSLT30},
		{"legacy future syntax in unused branch", "1.1", `<xsl:if test="false()"><xsl:value-of select="future syntax!"/></xsl:if><xsl:text>ok</xsl:text>`, "ok", transform.XSLT10},
	} {
		t.Run(tc.name, func(t *testing.T) {
			program := sheet(tc.declaration, `<xsl:output method="text"/><xsl:template name="start">`+tc.body+`</xsl:template>`)

			s, err := e.CompileXSLT(t.Context(), []byte(program), transform.XSLTOptions{ProcessorVersion: tc.processor})
			if err != nil {
				t.Fatal(err)
			}

			if s.Version() != tc.processor {
				t.Fatalf("processor = %v, want %v", s.Version(), tc.processor)
			}

			out, err := s.Transform(t.Context(), nil, transform.XSLTContext{Template: transform.Name{Local: nameStart}})
			if err != nil || string(out.Primary) != tc.want {
				t.Fatal(out, err, "want", tc.want)
			}
		})
	}

	program := []byte(sheet(version20, `<xsl:template name="start"><xsl:value-of select="map{'value':1}?value"/></xsl:template>`))
	if _, err := e.CompileXSLT(t.Context(), program, transform.XSLTOptions{ProcessorVersion: transform.XSLT20}); err == nil {
		t.Fatal("2.0 processor accepted 3.1 grammar")
	}

	if _, err := e.CompileXSLT(t.Context(), program, transform.XSLTOptions{Version: transform.XSLT30, ProcessorVersion: transform.XSLT30}); !errors.Is(err, transform.ErrUnsupported) {
		t.Fatal("declared-profile guard was bypassed", err)
	}

	if _, err := e.CompileXSLT(t.Context(), program, transform.XSLTOptions{ProcessorVersion: 99}); !errors.Is(err, transform.ErrUnsupported) {
		t.Fatal("invalid processor selection", err)
	}
}

type hostFunctionCase struct{ name, global, body, want20, want30 string }

func hostFunctionCases() []hostFunctionCase {
	nodes := `<xsl:variable name="d"><r><n/><n/></r></xsl:variable>`
	cases := []hostFunctionCase{
		{"nilled overload availability", "", `<xsl:value-of select="function-available('nilled',0)"/>`, nameFalse, nameTrue},
		{"nilled absent context", "", `<xsl:value-of select="nilled()"/>`, errCodeXPST0017, "XPDY0002"},
		{"nilled argument type", "", `<xsl:value-of select="nilled(42)"/>`, errCodeXPTY0004, errCodeXPTY0004},
		{"nilled cardinality", nodes, `<xsl:value-of select="nilled($d/r/n)"/>`, errCodeXPTY0004, errCodeXPTY0004},
		{"host overload gaps", "", `<xsl:value-of select="not(function-available('format-date',3)) and function-available('format-date',2) and function-available('format-date',5)"/>`, nameTrue, nameTrue},
		{"node function signature", "", `<xsl:value-of select="generate-id#1 instance of function(node()?) as xs:string"/>`, errCodeXPST0003, nameTrue},
		{"node identity", nodes, `<xsl:value-of select="generate-id($d/r/n[1]) eq generate-id($d/r/n[1]) and generate-id($d/r/n[1]) ne generate-id($d/r/n[2])"/>`, nameTrue, nameTrue},
		{"namespace identity", nodes, `<xsl:variable name="n" select="$d/r/n[1]"/><xsl:value-of select="generate-id($n/namespace::xml) eq generate-id($n/namespace::xml) and generate-id($n/namespace::xml) ne generate-id($d/r/n[2]/namespace::xml) and generate-id($n) ne generate-id($n/namespace::xml)"/>`, nameTrue, nameTrue},
		{"temporary identities", `<xsl:function name="f:new" xmlns:f="urn:f" as="element()"><xsl:param name="n"/><e n="{$n}"/></xsl:function>`, `<xsl:value-of xmlns:f="urn:f" select="count(distinct-values(for $i in 1 to 1000 return generate-id(f:new($i))))"/>`, "1000", "1000"},
		{"context node", nodes, `<xsl:for-each select="$d/r/n"><xsl:value-of select="generate-id() eq generate-id(.)"/></xsl:for-each>`, "truetrue", "truetrue"},
		{"empty node", "", `<xsl:value-of select="generate-id(()) eq ''"/>`, nameTrue, nameTrue},
		{"constructed attribute annotation", "", `<xsl:variable name="a" as="attribute()"><xsl:attribute name="a" select="1"/></xsl:variable><xsl:value-of select="data($a) instance of xs:untypedAtomic and not(data($a) instance of xs:integer)"/>`, nameTrue, nameTrue},
		{"missing context", "", `<xsl:value-of select="generate-id()"/>`, "XPDY0002", "XPDY0002"},
		{"atomic context", "", `<xsl:for-each select="42"><xsl:value-of select="generate-id()"/></xsl:for-each>`, errCodeXPTY0004, errCodeXPTY0004},
		{"multiple nodes", nodes, `<xsl:value-of select="generate-id($d/r/n)"/>`, errCodeXPTY0004, errCodeXPTY0004},
		{"qualified function", nodes, `<xsl:value-of xmlns:f="http://www.w3.org/2005/xpath-functions" select="f:generate-id($d/r) eq generate-id($d/r)"/>`, nameTrue, nameTrue},
		{"host availability", "", `<xsl:value-of select="function-available('generate-id',0) and function-available('generate-id',1) and not(function-available('generate-id',2))"/>`, nameTrue, nameTrue},
		{"host does not change grammar", "", `<xsl:value-of select="generate-id(map{})"/>`, errCodeXPST0003, errCodeXPTY0004},
		{"format precision", "", `<xsl:value-of select="format-number(xs:decimal('1234567890123456789.25'),'0.00')"/>`, "1234567890123456789.25", "1234567890123456789.25"},
		{"empty decimal special strings", `<xsl:decimal-format NaN="" infinity=""/>`, `<xsl:value-of select="concat(format-number(xs:double('NaN'),'0'),'|',format-number(xs:double('INF'),'0'),'|',format-number(xs:double('-INF'),'0'))"/>`, "||-", "||-"},
		{"invalid picture", "", `<xsl:value-of select="format-number(1,'000.##0')"/>`, "XTDE1310", "FODF1310"},
		{"unknown format", "", `<xsl:value-of select="format-number(1,'0','missing')"/>`, "XTDE1280", "FODF1280"},
		{"missing format prefix", "", `<xsl:value-of select="format-number(1,'0','missing:n')"/>`, "XTDE1280", "FODF1280"},
		{"empty format argument", "", `<xsl:value-of select="format-number(1,'0',())"/>`, errCodeXPTY0004, "1"},
		{"invalid date picture", "", `<xsl:value-of select="format-date(xs:date('2026-01-01'),'[b]')"/>`, "XTDE1340", "FOFD1340"},
		{"unavailable date component", "", `<xsl:value-of select="format-date(xs:date('2026-01-01'),'[H]')"/>`, "XTDE1350", "FOFD1350"},
		{"named format alias", `<xsl:decimal-format xmlns:f="urn:format" name="f:n" decimal-separator="!"/>`, `<xsl:value-of xmlns:g="urn:format" select="format-number(1.5,'0!0','g:n')"/>`, "1!5", "1!5"},
		{"URI qualified format reference", `<xsl:decimal-format xmlns:f="urn:format" name="f:n" decimal-separator="!"/>`, `<xsl:value-of select="format-number(1.5,'0!0','Q{urn:format}n')"/>`, "XTDE1280", "1!5"},
		{"URI qualified declaration", `<xsl:decimal-format name="Q{urn:format}n" decimal-separator="!"/>`, `<xsl:value-of select="format-number(1.5,'0!0','Q{urn:format}n')"/>`, errCodeXTSE0020, "1!5"},
		{"zero length name", `<xsl:decimal-format name=""/>`, `<xsl:text>unused</xsl:text>`, errCodeXTSE0020, errCodeXTSE0020},
		{"unbound declaration prefix", `<xsl:decimal-format name="missing:n"/>`, `<xsl:text>unused</xsl:text>`, "XTSE0280", "XTSE0280"},
		{"multiple separator characters", `<xsl:decimal-format decimal-separator="::"/>`, `<xsl:text>unused</xsl:text>`, errCodeXTSE0020, errCodeXTSE0020},
		{"empty separator character", `<xsl:decimal-format decimal-separator=""/>`, `<xsl:text>unused</xsl:text>`, errCodeXTSE0020, errCodeXTSE0020},
		{"digit family conflict", `<xsl:decimal-format percent="1"/>`, `<xsl:text>unused</xsl:text>`, "XTSE1300", "XTSE1300"},
		{"passive exponent character", `<xsl:decimal-format decimal-separator="e"/>`, `<xsl:value-of select="format-number(1.5,'0e0')"/>`, "1e5", "XTSE1300"},
	}
	cases = append(cases, groupFunctionCases()...)
	cases = append(cases, booleanProfileCases()...)
	cases = append(cases, sortMergeContractCases()...)
	cases = append(cases, numberingContractCases()...)
	cases = append(cases, numericPrecisionCases()...)
	cases = append(cases, xsltAdditionalFunctionProofCases()...)
	return append(cases, instructionContractCases()...)
}

func numericPrecisionCases() []hostFunctionCase {
	return []hostFunctionCase{
		{"power exact integer parity", "", `<xsl:value-of xmlns:math="http://www.w3.org/2005/xpath-functions/math" select="math:pow(-1,9007199254740993)"/>`, "XPST0017", "-1"},
		{"power exact negative zero parity", "", `<xsl:value-of xmlns:math="http://www.w3.org/2005/xpath-functions/math" select="1 div math:pow(-0e0,9007199254740993)"/>`, "XPST0017", "-INF"},
		{"power negative integer exponent", "", `<xsl:value-of xmlns:math="http://www.w3.org/2005/xpath-functions/math" select="math:pow(-2,-3)"/>`, "XPST0017", "-0.125"},
		{"round actual binary negative scale", "", `<xsl:value-of select="round(1.5e24,-24) eq 1e24"/>`, "XPST0017", "true"},
		{"round even actual binary negative scale", "", `<xsl:value-of select="round-half-to-even(1.5e24,-24) eq 1e24"/>`, "true", "true"},
		{"date rejects generic duration", "", `<xsl:value-of select="xs:date('2000-01-01') + xs:duration('P1M')"/>`, "XPTY0004", "XPTY0004"},
		{"datetime rejects generic duration", "", `<xsl:value-of select="xs:dateTime('2000-01-01T12:00:00') - xs:duration('P1D')"/>`, "XPTY0004", "XPTY0004"},
		{"time duration wraps days", "", `<xsl:value-of select="xs:time('23:00:00') + xs:dayTimeDuration('P3DT2H')"/>`, "01:00:00", "01:00:00"},
		{"date ancient leap subtraction", "", `<xsl:value-of select="xs:date('-5004-03-01') - xs:date('-5004-02-28')"/>`, "P2D", "P2D"},
		{"date ancient century subtraction", "", `<xsl:value-of select="xs:date('-5000-03-01') - xs:date('-5000-02-28')"/>`, "P1D", "P1D"},
		{"datetime ancient reverse subtraction", "", `<xsl:value-of select="xs:dateTime('-5200-02-28T23:00:00Z') - xs:dateTime('-5200-03-01T00:00:00Z')"/>`, "-P1DT1H", "-P1DT1H"},
		{"date formatting country fallback", "", `<xsl:value-of select="format-date(xs:date('2000-01-01'),'[Y]','en',(),'de')"/>`, "2000", "2000"},
		{"date formatting unknown place fallback", "", `<xsl:value-of select="format-date(xs:date('2000-01-01'),'[Y]','en',(),'unknown place')"/>`, "2000", "2000"},
		{"datetime formatting known timezone", "", `<xsl:value-of select="format-dateTime(xs:dateTime('2010-02-15T12:00:00Z'),'[H01]:[m01]','en',(),'America/New_York')"/>`, "07:00", "07:00"},
		{"date calendar unbound prefix", "", `<xsl:value-of select="format-date(xs:date('2000-01-01'),'[Y]','en','missing:AD',())"/>`, "XTDE1340", "FOFD1340"},
		{"date calendar bound prefix fallback", "", `<xsl:value-of xmlns:c="urn:calendar" select="format-date(xs:date('2000-01-01'),'[Y]','en','c:AD',())"/>`, "[Calendar: AD]2000", "[Calendar: AD]2000"},
		{"date calendar named function static prefix", `<xsl:variable xmlns:c="urn:calendar" name="format" select="format-date#5"/>`, `<xsl:value-of select="$format(xs:date('2000-01-01'),'[Y]','en','c:AD',())"/>`, "XPST0003", "[Calendar: AD]2000"},
		{"date calendar lookup static prefix", `<xsl:variable name="format" select="function-lookup(QName('http://www.w3.org/2005/xpath-functions','format-date'),5)"/>`, `<xsl:value-of xmlns:c="urn:calendar" select="$format(xs:date('2000-01-01'),'[Y]','en','c:AD',())"/>`, "XPST0017", "FOFD1340"},
		{"date calendar empty rejected", "", `<xsl:value-of select="format-date(xs:date('2000-01-01'),'[Y]','en','',())"/>`, "XTDE1340", "FOFD1340"},
		{"date calendar known fallbacks", "", `<xsl:value-of select="for $calendar in ('AME','VE','VS') return format-date(xs:date('2000-01-01'),'[Y]','en',$calendar,())"/>`, "[Calendar: AD]2000 [Calendar: AD]2000 [Calendar: AD]2000", "[Calendar: AD]2000 [Calendar: AD]2000 [Calendar: AD]2000"},
		{"date calendar unknown rejected", "", `<xsl:value-of select="format-date(xs:date('2000-01-01'),'[Y]','en','US',())"/>`, "XTDE1340", "FOFD1340"},
		{"date formatting minimum width beyond 1000", "", `<xsl:value-of select="string-length(format-date(xs:date('2000-01-01'),'[Y,1001]'))"/>`, "1001", "1001"},
		{"duration published decimal month multiplication", "", `<xsl:value-of select="xs:yearMonthDuration('P2Y11M') * 2.3"/>`, "P6Y9M", "P6Y9M"},
		{"duration published decimal second multiplication", "", `<xsl:value-of select="xs:dayTimeDuration('PT2H10M') * 2.1"/>`, "PT4H33M", "PT4H33M"},
		{"duration preserves decimal seconds", "", `<xsl:value-of select="xs:dayTimeDuration('PT1S') * xs:decimal('10.03')"/>`, "PT10.03S", "PT10.03S"},
		{"duration integer second multiplication", "", `<xsl:value-of select="xs:dayTimeDuration('P3DT4H3M3.100S') * 3 eq xs:dayTimeDuration('P9DT12H9M9.3S')"/>`, "true", "true"},
		{"duration integer second multiplication reversed", "", `<xsl:value-of select="3 * xs:dayTimeDuration('P3DT4H3M3.100S') eq xs:dayTimeDuration('P9DT12H9M9.3S')"/>`, "true", "true"},
		{"duration integer second division", "", `<xsl:value-of select="xs:dayTimeDuration('P8DT4H4M4.400S') div 4 eq xs:dayTimeDuration('P2DT1H1M1.1S')"/>`, "true", "true"},
		{"duration double month multiplication", "", `<xsl:value-of select="xs:yearMonthDuration('P2Y11M') * 2.3e0"/>`, "P6Y9M", "P6Y9M"},
		{"duration double second multiplication", "", `<xsl:value-of select="xs:dayTimeDuration('PT2H10M') * 2.1e0"/>`, "PT4H33M", "PT4H33M"},
		{"duration decimal multiplier exactness", "", `<xsl:value-of select="xs:yearMonthDuration('P1M') * xs:decimal('0.4999999999999999999999999999')"/>`, "P0M", "P0M"},
		{"duration decimal divisor exactness", "", `<xsl:value-of select="xs:yearMonthDuration('P1M') div xs:decimal('2.000000000000000000000000001')"/>`, "P0M", "P0M"},
		{"duration negative month tie", "", `<xsl:value-of select="xs:yearMonthDuration('P1M') * -0.5e0"/>`, "P0M", "P0M"},
		{"duration NaN multiplier", "", `<xsl:value-of select="xs:dayTimeDuration('PT1S') * xs:double('NaN')"/>`, "FOCA0005", "FOCA0005"},
		{"duration divide by zero", "", `<xsl:value-of select="xs:yearMonthDuration('P1M') div 0"/>`, "FODT0002", "FODT0002"},
		{"minimum datetime stamp", "", `<xsl:value-of select="min(xs:dateTimeStamp('2000-01-01T00:00:00Z'))"/>`, "2000-01-01T00:00:00Z", "2000-01-01T00:00:00Z"},
		{"maximum mixed datetime stamp", "", `<xsl:value-of select="max((xs:dateTimeStamp('2000-01-01T00:00:00Z'),xs:dateTime('2001-01-01T00:00:00Z')))"/>`, "2001-01-01T00:00:00Z", "2001-01-01T00:00:00Z"},
		{"derived string calendar cast", "", `<xsl:value-of select="xs:date(xs:token('2000-01-01'))"/>`, "2000-01-01", "2000-01-01"},
		{"derived string duration cast", "", `<xsl:value-of select="xs:duration(xs:Name('P1D'))"/>`, "P1D", "P1D"},
		{"derived string URI cast", "", `<xsl:value-of select="xs:anyURI(xs:token('urn:x'))"/>`, "urn:x", "urn:x"},
		{"derived string QName cast", "", `<xsl:value-of xmlns:p="urn:p" select="xs:QName(xs:token('p:x'))"/>`, "XPTY0004", "p:x"},
		{"date empty language fallback", "", `<xsl:value-of select="format-date(xs:date('2000-01-01'),'[MNn]','',(),())"/>`, "[Language: en]January", "[Language: en]January"},
	}
}

func TestXPathDateFormattingWidthBudgets(t *testing.T) {
	for _, test := range []struct {
		name, picture string
		limit         int
		want          string
	}{
		{"ordinary", "[Y,8]", 4096, "8"},
		{"large valid width", "[Y,1001]", 16384, "1001"},
		{"tight budget", "[Y,1001]", 256, ""},
		{"overflow width", "[Y,999999999999999999999999999999999999]", 4096, ""},
	} {
		t.Run(test.name, func(t *testing.T) {
			e := engine(t, transform.Config{Limits: transform.Limits{MaxOutputBytes: test.limit}})
			for _, version := range []transform.XPathVersion{transform.XPath30, transform.XPath31} {
				query, err := e.CompileXPath(t.Context(), `string-length(format-date(xs:date('2000-01-01'),'`+test.picture+`'))`, transform.XPathOptions{Version: version})
				if err != nil {
					t.Fatal(version, err)
				}

				result, err := query.Evaluate(t.Context(), nil, transform.XPathContext{})
				if test.want == "" {
					if !errors.Is(err, transform.ErrLimit) {
						t.Fatal(version, err)
					}

					continue
				}

				if err != nil {
					t.Fatal(version, err)
				}

				got, err := result.Text()
				if err != nil || got != test.want {
					t.Fatal(version, got, test.want, err)
				}
			}
		})
	}
}

func TestXPathAggregateDateTimeStamp(t *testing.T) {
	for _, edition := range []transform.XMLSchemaVersion{transform.XMLSchema10, transform.XMLSchema11} {
		e := engine(t, transform.Config{XMLSchemaVersion: edition})
		for _, version := range []transform.XPathVersion{transform.XPath20, transform.XPath30, transform.XPath31} {
			for _, test := range []struct{ function, arguments, want string }{
				{"min", `xs:dateTimeStamp('2000-01-01T00:00:00Z')`, "2000-01-01T00:00:00Z"},
				{"max", `(xs:dateTimeStamp('2000-01-01T00:00:00Z'),xs:dateTime('2001-01-01T00:00:00Z'))`, "2001-01-01T00:00:00Z"},
				{"min", `(xs:dateTime('2001-01-01T00:00:00Z'),xs:dateTimeStamp('2000-01-01T00:00:00Z'))`, "2000-01-01T00:00:00Z"},
				{"max", `(xs:dateTimeStamp('2000-01-01T00:00:00Z'),xs:date('2001-01-01Z'))`, "FORG0006"},
			} {
				calls := []string{test.function}
				if version != transform.XPath20 {
					calls = append(calls, "("+test.function+"#1)", "function-lookup(QName('http://www.w3.org/2005/xpath-functions','"+test.function+"'),1)")
				}

				for _, call := range calls {
					compiled, err := e.CompileXPath(t.Context(), call+"("+test.arguments+")", transform.XPathOptions{Version: version})
					if err != nil {
						t.Fatal(edition, version, call, err)
					}

					result, err := compiled.Evaluate(t.Context(), nil, transform.XPathContext{})
					if comparisonErrorCode(test.want) {
						var detail *transform.Error
						if !errors.As(err, &detail) || detail.Code != test.want {
							t.Fatal(edition, version, call, err)
						}

						continue
					}

					if err != nil {
						t.Fatal(edition, version, call, err)
					}

					got, err := result.Text()
					if err != nil || got != test.want {
						t.Fatal(edition, version, call, got, test.want, err)
					}
				}
			}

			if got := text(t, evaluate(t, e, `min((current-dateTime(),current-dateTime())) eq current-dateTime()`, version)); got != "true" {
				t.Fatal(edition, version, got)
			}
		}
	}
}

func TestXPathDerivedStringCasts(t *testing.T) {
	e := engine(t, transform.Config{})
	for _, test := range []struct{ target, source, want string }{
		{"date", `xs:token('2000-01-01')`, "2000-01-01"},
		{"dateTime", `xs:normalizedString('2000-01-01T00:00:00Z')`, "2000-01-01T00:00:00Z"},
		{"dateTimeStamp", `xs:token('2000-01-01T00:00:00Z')`, "2000-01-01T00:00:00Z"},
		{"time", `xs:normalizedString('12:34:56')`, "12:34:56"},
		{"duration", `xs:NCName('P1D')`, "P1D"},
		{"yearMonthDuration", `xs:Name('P1M')`, "P1M"},
		{"dayTimeDuration", `xs:IDREF('P1D')`, "P1D"},
		{"integer", `xs:NMTOKEN('123')`, "123"},
		{"boolean", `xs:NMTOKEN('1')`, "true"},
		{"boolean", `xs:normalizedString('false')`, "false"},
		{"anyURI", `xs:token('urn:x')`, "urn:x"},
		{"anyURI", `xs:language('en')`, "en"},
		{"gYear", `xs:normalizedString('2000')`, "2000"},
		{"QName", `xs:token('p:x')`, "p:x"},
		{"QName", `xs:ID('local')`, "local"},
		{"token", `xs:token('kept')`, "kept"},
		{"date", `xs:token('bad')`, "FORG0001"},
		{"date", `xs:anyURI('2000-01-01')`, "XPTY0004"},
		{"integer", `xs:anyURI('123')`, "XPTY0004"},
		{"integer", `xs:Name('bad')`, "FORG0001"},
		{"QName", `xs:token('not a name')`, "FORG0001"},
	} {
		for _, version := range []transform.XPathVersion{transform.XPath20, transform.XPath30, transform.XPath31} {
			want := test.want
			if test.target == "QName" && version == transform.XPath20 {
				want = "XPTY0004" // This edition requires a literal lexical QName.
			}

			target := "xs:" + test.target
			expressions := []string{target + "(" + test.source + ")", test.source + " cast as " + target}
			if version != transform.XPath20 {
				expressions = append(expressions, "("+target+"#1)("+test.source+")", "function-lookup(QName('http://www.w3.org/2001/XMLSchema','"+test.target+"'),1)("+test.source+")")
			}

			for _, expression := range expressions {
				compiled, err := e.CompileXPath(t.Context(), expression, transform.XPathOptions{Version: version, Namespaces: map[string]string{"p": "urn:p"}})
				if err != nil {
					t.Fatal(version, expression, err)
				}

				result, err := compiled.Evaluate(t.Context(), nil, transform.XPathContext{})
				if comparisonErrorCode(want) {
					var detail *transform.Error
					if !errors.As(err, &detail) || detail.Code != want {
						t.Fatal(version, expression, err, want)
					}

					continue
				}

				if err != nil {
					t.Fatal(version, expression, err)
				}

				got, err := result.Text()
				if err != nil || got != want {
					t.Fatal(version, expression, got, want, err)
				}
			}
		}
	}
}

func TestXPathDateTimeArithmeticBounds(t *testing.T) {
	e := engine(t, transform.Config{})
	for _, test := range []struct{ expression, want string }{
		{`xs:time('12:00:00') + xs:dayTimeDuration('P100000000000000000000DT1H')`, "13:00:00"},
		{`xs:time('12:00:00') - xs:dayTimeDuration('P100000000000000000000DT13H')`, "23:00:00"},
		{`xs:date('2000-01-01') + xs:yearMonthDuration('P9223372036854775807M')`, "FODT0001"},
		{`xs:dateTime('2000-01-01T12:00:00') + xs:dayTimeDuration('P100000000000000000000D')`, "FODT0001"},
		{`xs:yearMonthDuration('P9007199254740993M') * 1`, "P750599937895082Y9M"},
		{`seconds-from-duration(xs:dayTimeDuration('PT9007199254740993S') * 1)`, "33"},
		{`xs:dayTimeDuration('P100000000000000000000D') div xs:double('INF')`, "PT0S"},
		{`xs:dayTimeDuration('P100000000000000000000D') * 0`, "PT0S"},
		{`xs:dayTimeDuration('P9223372036854775807D') div 0.5 eq xs:dayTimeDuration('P18446744073709551614D')`, "true"},
	} {
		for _, version := range []transform.XPathVersion{transform.XPath20, transform.XPath30, transform.XPath31} {
			query, err := e.CompileXPath(t.Context(), test.expression, transform.XPathOptions{Version: version})
			if err != nil {
				t.Fatal(version, test.expression, err)
			}

			result, err := query.Evaluate(t.Context(), nil, transform.XPathContext{})
			if comparisonErrorCode(test.want) {
				var detail *transform.Error
				if !errors.As(err, &detail) || detail.Code != test.want {
					t.Fatal(version, test.expression, test.want, err)
				}

				continue
			}

			if err != nil {
				t.Fatal(version, test.expression, err)
			}

			got, err := result.Text()
			if err != nil || got != test.want {
				t.Fatal(version, test.expression, got, test.want, err)
			}
		}
	}
}

func TestXPathNumericPrecisionContracts(t *testing.T) {
	e := engine(t, transform.Config{})
	for _, test := range []struct{ name, function, namespace, arguments, want string }{
		{"power integer parity", "pow", "http://www.w3.org/2005/xpath-functions/math", "-1,9007199254740993", "-1"},
		{"power negative integer parity", "pow", "http://www.w3.org/2005/xpath-functions/math", "-1,-9007199254740993", "-1"},
		{"power even integer parity", "pow", "http://www.w3.org/2005/xpath-functions/math", "-1,9007199254740994", "1"},
		{"power negative zero parity", "pow", "http://www.w3.org/2005/xpath-functions/math", "-0e0,9007199254740993", "-0"},
		{"power negative exponent", "pow", "http://www.w3.org/2005/xpath-functions/math", "-2,-3", "-0.125"},
		{"power zero exponent", "pow", "http://www.w3.org/2005/xpath-functions/math", "xs:double('NaN'),0", "1"},
		{"round actual binary", "round", "http://www.w3.org/2005/xpath-functions", "1.5e24,-24", "1.0E24"},
		{"round even control", "round-half-to-even", "http://www.w3.org/2005/xpath-functions", "1.5e24,-24", "1.0E24"},
	} {
		t.Run(test.name, func(t *testing.T) {
			name := "Q{" + test.namespace + "}" + test.function
			for _, call := range []string{name, "(" + name + "#2)", "function-lookup(QName('" + test.namespace + "','" + test.function + "'),2)"} {
				for _, version := range []transform.XPathVersion{transform.XPath30, transform.XPath31} {
					query, err := e.CompileXPath(t.Context(), call+"("+test.arguments+")", transform.XPathOptions{Version: version})
					if err != nil {
						t.Fatal(version, call, err)
					}

					result, err := query.Evaluate(t.Context(), nil, transform.XPathContext{})
					if err != nil {
						t.Fatal(version, call, err)
					}

					got, err := result.Text()
					if err != nil || got != test.want {
						t.Fatal(version, call, got, test.want, err)
					}
				}
			}
		})
	}
}

func sortMergeContractCases() []hostFunctionCase {
	return []hostFunctionCase{
		{"streamability zero arity function", `<xsl:function xmlns:f="urn:f" name="f:value" streamability="inspection"><xsl:sequence select="1"/></xsl:function>`, `ok`, "XTSE0090", "XTSE3155"},
		{"streamability attribute set reference", `<xsl:attribute-set name="a" streamable="yes" use-attribute-sets="b"/><xsl:attribute-set name="b"/>`, `ok`, "XTSE0090", "XTSE0730"},
		{"accumulator local declaration namespace", `<xsl:accumulator xmlns:p="urn:acc" xmlns:t="http://www.w3.org/2001/XMLSchema" name="p:a" as="t:integer" initial-value="0"><xsl:accumulator-rule match="n" select="$value+1"/></xsl:accumulator>`, `<xsl:variable name="d"><r><n/><n/></r></xsl:variable><xsl:for-each select="$d/r/n"><xsl:value-of xmlns:q="urn:acc" select="accumulator-before('q:a')"/></xsl:for-each>`, "XTSE0010", "12"},
		{"accumulator absent context", `<xsl:accumulator xmlns:p="urn:acc" xmlns:t="http://www.w3.org/2001/XMLSchema" name="p:a" as="t:integer" initial-value="0"><xsl:accumulator-rule match="n" select="$value+1"/></xsl:accumulator>`, `<xsl:value-of select="accumulator-before('Q{urn:acc}a')"/>`, "XTSE0010", "XTDE3350"},
		{"accumulator atomic context", `<xsl:accumulator xmlns:p="urn:acc" xmlns:t="http://www.w3.org/2001/XMLSchema" name="p:a" as="t:integer" initial-value="0"><xsl:accumulator-rule match="n" select="$value+1"/></xsl:accumulator>`, `<xsl:for-each select="42"><xsl:value-of select="accumulator-before('Q{urn:acc}a')"/></xsl:for-each>`, "XTSE0010", "XTTE3360"},
		{"accumulator unbound name prefix", `<xsl:accumulator xmlns:p="urn:acc" xmlns:t="http://www.w3.org/2001/XMLSchema" name="p:a" as="t:integer" initial-value="0"><xsl:accumulator-rule match="n" select="$value+1"/></xsl:accumulator>`, `<xsl:variable name="d"><n/></xsl:variable><xsl:for-each select="$d/n"><xsl:value-of select="accumulator-before('q:a')"/></xsl:for-each>`, "XTSE0010", "XTDE3340"},
		{"copy function mixed sequence", `<xsl:variable name="n"><n/></xsl:variable>`, `<xsl:variable name="c" select="copy-of((1,$n/n,2))"/><xsl:value-of select="count($c) eq 3 and $c[1] eq 1 and $c[3] eq 2 and $c[2] instance of element(n) and not($c[2] is $n/n) and empty($c[2]/parent::node())"/>`, "XPST0017", "true"},
		{"copy function atomic context", "", `<xsl:for-each select="42"><xsl:value-of select="copy-of()"/></xsl:for-each>`, "XPST0017", "42"},
		{"copy function absent context", "", `<xsl:value-of select="copy-of()"/>`, "XPST0017", "XPDY0002"},
		{"snapshot document accumulator values", `<xsl:accumulator name="a" initial-value="'initial'"><xsl:accumulator-rule match="n" select="generate-id(.)"/></xsl:accumulator>`, `<xsl:variable name="d"><r><n/></r></xsl:variable><xsl:variable name="before" select="$d/r/n/accumulator-before('a')"/><xsl:variable name="s" select="snapshot($d)"/><xsl:value-of select="$s/r/n/accumulator-before('a') eq $before"/>`, "XTSE0010", "true"},
		{"snapshot function atomic context", "", `<xsl:for-each select="42"><xsl:value-of select="snapshot()"/></xsl:for-each>`, "XPST0017", "42"},
		{"snapshot function absent context", "", `<xsl:value-of select="snapshot()"/>`, "XPST0017", "XPDY0002"},
		{"snapshot function mixed sequence", `<xsl:variable name="n"><r><n/></r></xsl:variable>`, `<xsl:variable name="c" select="snapshot((1,$n/r/n,2))"/><xsl:value-of select="count($c) eq 3 and $c[1] eq 1 and $c[3] eq 2 and $c[2] instance of element(n) and not($c[2] is $n/r/n) and exists($c[2]/parent::r)"/>`, "XPST0017", "true"},
		{"sort binary octets", "", `<xsl:for-each select="(xs:base64Binary('////'),xs:base64Binary('AAAA'))"><xsl:sort select="."/><xsl:value-of select="."/></xsl:for-each>`, "XTDE1030", "AAAA////"},
		{"sort binary explicit text", "", `<xsl:for-each select="(xs:base64Binary('////'),xs:base64Binary('AAAA'))"><xsl:sort select="." data-type="text"/><xsl:value-of select="."/></xsl:for-each>`, "////AAAA", "////AAAA"},
		{"sort binary multiple keys", "", `<xsl:for-each select="(xs:base64Binary('////'),xs:base64Binary('AAAA'))"><xsl:sort select="1"/><xsl:sort select="."/><xsl:value-of select="."/></xsl:for-each>`, "XTDE1030", "AAAA////"},
		{"merge binary octets", "", `<xsl:merge><xsl:merge-source select="(xs:base64Binary('////'),xs:base64Binary('AAAA'))" sort-before-merge="yes"><xsl:merge-key select="."/></xsl:merge-source><xsl:merge-action><xsl:value-of select="."/></xsl:merge-action></xsl:merge>`, "XTSE0010", "AAAA////"},
		{"sort relative collation", ``, `<xsl:for-each xml:base="http://www.w3.org/2005/xpath-functions/collation/" select="('b','a')"><xsl:sort select="." collation="codepoint"/><xsl:value-of select="."/></xsl:for-each>`, "ab", "ab"},
		{"sort explicit collation ignores dynamic case", ``, `<xsl:for-each select="('b','a')"><xsl:sort select="." collation="http://www.w3.org/2005/xpath-functions/collation/codepoint" case-order="{error()}"/><xsl:value-of select="."/></xsl:for-each>`, "ab", "ab"},
		{"sort ignored option static function", ``, `<xsl:for-each select="(1,2)"><xsl:sort select="." collation="http://www.w3.org/2005/xpath-functions/collation/codepoint" lang="{missing()}"/></xsl:for-each>`, "XPST0017", "XPST0017"},
		{"sort ignored option malformed AVT", ``, `<xsl:for-each select="(1,2)"><xsl:sort select="." collation="http://www.w3.org/2005/xpath-functions/collation/codepoint" case-order="{"/></xsl:for-each>`, "XTSE0350", "XTSE0350"},
		{"sort language lexical value", ``, `<xsl:for-each select="(1,2)"><xsl:sort select="." lang="{'invalid_language'}"/></xsl:for-each>`, "XTDE0030", "XTDE0030"},
		{"sort empty string ordering", ``, `<xsl:for-each select="('string','empty')"><xsl:sort select="if (. eq 'empty') then () else ''"/><xsl:value-of select="."/></xsl:for-each>`, "emptystring", "emptystring"},
		{"sort empty numeric ordering", ``, `<xsl:for-each select="('zero','NaN','empty')"><xsl:sort select="if (. eq 'empty') then () else if (. eq 'NaN') then xs:double('NaN') else 0"/><xsl:value-of select="."/></xsl:for-each>`, "emptyNaNzero", "emptyNaNzero"},
		{"group lexical default collation", `<xsl:function xmlns:f="urn:f" name="f:groups" default-collation="http://www.w3.org/2005/xpath-functions/collation/html-ascii-case-insensitive"><xsl:for-each-group select="('A','a')" group-by="."><xsl:sequence select="count(current-group())"/></xsl:for-each-group></xsl:function>`, `<xsl:value-of xmlns:f="urn:f" select="f:groups()"/>`, "2", "2"},
		{"merge order difference", ``, `<xsl:merge><xsl:merge-source select="1"><xsl:merge-key select="." order="ascending"/></xsl:merge-source><xsl:merge-source select="2"><xsl:merge-key select="." order="descending"/></xsl:merge-source><xsl:merge-action><xsl:value-of select="."/></xsl:merge-action></xsl:merge>`, "XTSE0010", "XTDE2210"},
		{"merge effective collation", ``, `<xsl:merge><xsl:merge-source select="'a'"><xsl:merge-key select="." collation="{'http://www.w3.org/2005/xpath-functions/collation/codepoint'}"/></xsl:merge-source><xsl:merge-source select="'b'"><xsl:merge-key select="." collation="http://www.w3.org/2005/xpath-functions/collation/codepoint"/></xsl:merge-source><xsl:merge-action><xsl:value-of select="."/></xsl:merge-action></xsl:merge>`, "XTSE0010", "ab"},
		{"merge case avt", ``, `<xsl:merge><xsl:merge-source select="('A','a')"><xsl:merge-key select="." lang="{'en'}" case-order="{'upper-first'}"/></xsl:merge-source><xsl:merge-action><xsl:value-of select="."/></xsl:merge-action></xsl:merge>`, "XTSE0010", "Aa"},
		{"merge bad order", ``, `<xsl:merge><xsl:merge-source select="1"><xsl:merge-key select="." order="{'invalid'}"/></xsl:merge-source><xsl:merge-action><xsl:value-of select="."/></xsl:merge-action></xsl:merge>`, "XTSE0010", "XTDE0030"},
		{"merge text number", ``, `<xsl:merge><xsl:merge-source select="(1,10,2)"><xsl:merge-key select="." data-type="text"/></xsl:merge-source><xsl:merge-action><xsl:value-of select="concat(.,',')"/></xsl:merge-action></xsl:merge>`, "XTSE0010", "1,10,2,"},
		{"merge collation equality", ``, `<xsl:merge><xsl:merge-source select="'A'"><xsl:merge-key select="." collation="http://www.w3.org/2005/xpath-functions/collation/html-ascii-case-insensitive"/></xsl:merge-source><xsl:merge-source select="'a'"><xsl:merge-key select="." collation="http://www.w3.org/2005/xpath-functions/collation/html-ascii-case-insensitive"/></xsl:merge-source><xsl:merge-action><xsl:value-of select="count(current-merge-group())"/></xsl:merge-action></xsl:merge>`, "XTSE0010", "2"},
		{"merge presort collation", ``, `<xsl:merge><xsl:merge-source select="('A','a')" sort-before-merge="yes"><xsl:merge-key select="." lang="en" case-order="lower-first"/></xsl:merge-source><xsl:merge-action><xsl:value-of select="."/></xsl:merge-action></xsl:merge>`, "XTSE0010", "aA"},
		{"merge empty string", ``, `<xsl:merge><xsl:merge-source select="(0,1)"><xsl:merge-key select="if (. eq 0) then () else ''"/></xsl:merge-source><xsl:merge-action><xsl:value-of select="concat(.,':',count(current-merge-group()),':',count(current-merge-key()),';')"/></xsl:merge-action></xsl:merge>`, "XTSE0010", "0:1:0;1:1:1;"},
		{"merge nan group", ``, `<xsl:merge><xsl:merge-source select="('a','b')"><xsl:merge-key select="xs:double('NaN')"/></xsl:merge-source><xsl:merge-action><xsl:value-of select="count(current-merge-group())"/></xsl:merge-action></xsl:merge>`, "XTSE0010", "2"},
		{"merge relative collation", ``, `<xsl:merge xml:base="http://www.w3.org/2005/xpath-functions/collation/"><xsl:merge-source select="('a','b')"><xsl:merge-key select="." collation="codepoint"/></xsl:merge-source><xsl:merge-action><xsl:value-of select="."/></xsl:merge-action></xsl:merge>`, "XTSE0010", "ab"},
		{"merge option presence differs", ``, `<xsl:merge><xsl:merge-source select="1"><xsl:merge-key select="."/></xsl:merge-source><xsl:merge-source select="2"><xsl:merge-key select="." order="ascending"/></xsl:merge-source><xsl:merge-action/></xsl:merge>`, "XTSE0010", "XTDE2210"},
		{"merge ignored language differs", ``, `<xsl:merge><xsl:merge-source select="1"><xsl:merge-key select="." lang="en" collation="http://www.w3.org/2005/xpath-functions/collation/codepoint"/></xsl:merge-source><xsl:merge-source select="2"><xsl:merge-key select="." lang="fi" collation="http://www.w3.org/2005/xpath-functions/collation/codepoint"/></xsl:merge-source><xsl:merge-action/></xsl:merge>`, "XTSE0010", "XTDE2210"},
		{"merge source local namespace", ``, `<xsl:merge><xsl:merge-source xmlns:p="http://www.w3.org/2005/xpath-functions" select="p:reverse((2,1))"><xsl:merge-key select="."/></xsl:merge-source><xsl:merge-action><xsl:value-of select="."/></xsl:merge-action></xsl:merge>`, "XTSE0010", "12"},
		{"merge key local namespace", ``, `<xsl:merge><xsl:merge-source select="(1,2)"><xsl:merge-key xmlns:p="http://www.w3.org/2005/xpath-functions" select="p:number(.)"/></xsl:merge-source><xsl:merge-action><xsl:value-of select="."/></xsl:merge-action></xsl:merge>`, "XTSE0010", "12"},
	}
}

func numberingContractCases() []hostFunctionCase {
	return []hostFunctionCase{
		{"number array atomization", "", `<xsl:number value="[1,2]"/>`, "XPST0003", "1.2"},
		{"number large integer double conversion", "", `<xsl:number value="9007199254740993"/>`, "9007199254740992", "9007199254740992"},
		{"number negative decimal half", "", `<xsl:number value="xs:decimal('-0.5')"/>`, "0", "0"},
		{"number negative double half", "", `<xsl:number value="xs:double('-0.5')"/>`, "0", "0"},
		{"number negative value rejected", "", `<xsl:number value="-1"/>`, "XTDE0980", "XTDE0980"},
		{"number node position single", `<xsl:variable name="d"><r><n/><n/><n/></r></xsl:variable>`, `<xsl:for-each select="$d/r/n"><xsl:number/></xsl:for-each>`, "123", "123"},
		{"number node position multiple", `<xsl:variable name="d"><r><a><b/><b/></a><a><b/></a></r></xsl:variable>`, `<xsl:for-each select="$d/r/a/b"><xsl:number level="multiple" count="a|b"/><xsl:text>;</xsl:text></xsl:for-each>`, "1.1;1.2;2.1;", "1.1;1.2;2.1;"},
		{"number node position any", `<xsl:variable name="d"><r><a><n/><n/></a><a><n/></a></r></xsl:variable>`, `<xsl:for-each select="$d/r/a/n"><xsl:number level="any" count="n" from="a"/></xsl:for-each>`, "121", "121"},
		{"number grouping size dynamic", "", `<xsl:number value="1234" grouping-separator="," grouping-size="{'bad'}"/>`, "XTDE0030", "XTDE0030"},
		{"number grouping size empty", "", `<xsl:number value="1234" grouping-separator="," grouping-size=""/>`, "XTSE0020", "XTSE0020"},
		{"number grouping size XML whitespace", "", `<xsl:number value="1234" grouping-separator="," grouping-size="{' 3 '}"/>`, "1,234", "1,234"},
		{"number grouping size large", "", `<xsl:number value="1234" grouping-separator="," grouping-size="{'999999999999999999999999999999'}"/>`, "1234", "1234"},
		{"number grouping size negative", "", `<xsl:number value="1234" grouping-separator="," grouping-size="{'-1'}"/>`, "1234", "1234"},
		{"number grouping incomplete pair ignored", "", `<xsl:number value="1234" grouping-size="{error()}"/>`, "1234", "1234"},
		{"number letter value dynamic", "", `<xsl:number value="1234" letter-value="{'invalid'}"/>`, "XTDE0030", "XTDE0030"},
		{"number letter value evaluated", "", `<xsl:number value="1234" letter-value="{error()}"/>`, "FOER0000", "FOER0000"},
		{"number letter value empty", "", `<xsl:number value="1234" letter-value=""/>`, "XTSE0020", "XTSE0020"},
		{"number empty format", "", `<xsl:number value="1234" format=""/>`, "1234", "1234"},
		{"number ordinal no", "", `<xsl:number value="1234" ordinal="no" lang="en"/>`, "1234th", "1234"},
		{"number ordinal false", "", `<xsl:number value="1234" ordinal="false" lang="en"/>`, "1234th", "1234"},
		{"number ordinal zero", "", `<xsl:number value="1234" ordinal="0" lang="en"/>`, "1234th", "1234"},
		{"number ordinal yes", "", `<xsl:number value="1234" ordinal="yes" lang="en"/>`, "1234th", "1234th"},
		{"number start at plus rejected", "", `<xsl:number value="1234" start-at="{'+1'}"/>`, "XTSE0090", "XTDE0030"},
		{"number start at XML whitespace", "", `<xsl:number value="1" start-at="{' 2 3 '}"/>`, "XTSE0090", "2"},
		{"number start at nonXML whitespace", "", `<xsl:number value="1" start-at="{concat('1',codepoints-to-string(160),'2')}"/>`, "XTSE0090", "XTDE0030"},
	}
}

func groupFunctionCases() []hostFunctionCase {
	nodes := `<xsl:variable name="d"><r><n/><n/></r></xsl:variable>`
	group := `<xsl:for-each-group select="$d/r/n" group-by="'k'">`
	target := `<xsl:template name="target" match="n"><xsl:value-of select="count(current-group())"/>:<xsl:value-of select="current-grouping-key()"/></xsl:template>`
	function := `<xsl:function xmlns:f="urn:f" name="f:group"><xsl:sequence select="current-group()"/></xsl:function>`
	return []hostFunctionCase{
		{"group absent", "", `<xsl:value-of select="empty(current-group())"/>`, nameTrue, "XTDE1061"},
		{"group key absent", "", `<xsl:value-of select="empty(current-grouping-key())"/>`, nameTrue, "XTDE1071"},
		{"starting group key", nodes, `<xsl:for-each-group select="$d/r/n" group-starting-with="n"><xsl:value-of select="empty(current-grouping-key())"/></xsl:for-each-group>`, "truetrue", "XTDE1071"},
		{"ending group key", nodes, `<xsl:for-each-group select="$d/r/n" group-ending-with="n"><xsl:value-of select="empty(current-grouping-key())"/></xsl:for-each-group>`, "truetrue", "XTDE1071"},
		{"starting atomic population", "", `<xsl:for-each-group select="(1,2)" group-starting-with="node()"><xsl:value-of select="count(current-group())"/></xsl:for-each-group>`, "XTTE1120", "2"},
		{"ending mixed population", nodes, `<xsl:for-each-group select="($d/r/n[1],2)" group-ending-with="n"><xsl:value-of select="count(current-group())"/></xsl:for-each-group>`, "XTTE1120", "11"},
		{"group through named template", nodes + target, group + `<xsl:call-template name="target"/></xsl:for-each-group>`, "2:k", "2:k"},
		{"group through matched template", nodes + target, group + `<xsl:apply-templates select="current-group()[1]"/></xsl:for-each-group>`, "2:k", "2:k"},
		{"group with absent template focus", nodes + strings.Replace(target, `<xsl:value-of`, `<xsl:context-item use="absent"/><xsl:value-of`, 1), group + `<xsl:call-template name="target"/></xsl:for-each-group>`, "XTSE0010", "2:k"},
		{"function clears group", nodes + function, group + `<xsl:value-of xmlns:f="urn:f" select="empty(f:group())"/></xsl:for-each-group>`, nameTrue, "XTDE1061"},
		{"function clears atomic focus", `<xsl:function xmlns:f="urn:f" name="f:focus"><xsl:sequence select="."/></xsl:function>`, `<xsl:for-each select="42"><xsl:value-of xmlns:f="urn:f" select="f:focus()"/></xsl:for-each>`, "XPDY0002", "XPDY0002"},
		{"function global scope", `<xsl:variable name="v" select="'global'"/><xsl:function xmlns:f="urn:f" name="f:value"><xsl:sequence select="$v"/></xsl:function>`, `<xsl:variable name="v" select="'local'"/><xsl:value-of xmlns:f="urn:f" select="f:value()"/>`, "global", "global"},
		{"required function parameter", `<xsl:function xmlns:f="urn:f" name="f:value"><xsl:param name="p" required="yes"/><xsl:sequence select="$p"/></xsl:function>`, "ok", "XTSE0090", "ok"},
		{"optional function parameter", `<xsl:function xmlns:f="urn:f" name="f:value"><xsl:param name="p" required="no"/><xsl:sequence select="$p"/></xsl:function>`, "ok", "XTSE0090", "XTSE0020"},
		{"non tunnel function parameter", `<xsl:function xmlns:f="urn:f" name="f:value"><xsl:param name="p" tunnel="no"/><xsl:sequence select="$p"/></xsl:function>`, "ok", "ok", "ok"},
		{"tunnel function parameter", `<xsl:function xmlns:f="urn:f" name="f:value"><xsl:param name="p" tunnel="yes"/><xsl:sequence select="$p"/></xsl:function>`, "ok", "XTSE0020", "XTSE0020"},
		{"default function parameter", `<xsl:function xmlns:f="urn:f" name="f:value"><xsl:param name="p" select="1"/><xsl:sequence select="$p"/></xsl:function>`, "ok", "XTSE0760", "XTSE0760"},
	}
}

func hostFunctionSheet(version string, test hostFunctionCase) string {
	return sheet(version, test.global+`<xsl:template name="start">`+test.body+`</xsl:template>`)
}

// Boolean spellings are selected by the processor, including a 2.0
// declaration under a 3.0 processor and a future declaration under 2.0.
func booleanProfileCases() []hostFunctionCase {
	return []hostFunctionCase{
		{"boolean copy alias", "", `<xsl:variable name="n"><n>ok</n></xsl:variable><xsl:copy-of select="$n/n" copy-namespaces="true"/>`, "XTSE0020", "ok"},
		{"boolean inherit alias", "", `<xsl:element name="n" inherit-namespaces="1">ok</xsl:element>`, "XTSE0020", "ok"},
		{"boolean inherit false semantics", "", `<xsl:variable name="n"><xsl:element xmlns:p="urn:p" name="p:parent" inherit-namespaces="false"><xsl:element name="child"/></xsl:element></xsl:variable><xsl:value-of select="empty(namespace-uri-for-prefix('p',$n/*/*))"/>`, "XTSE0020", "true"},
		{"boolean inherit zero semantics", "", `<xsl:variable name="n"><xsl:element xmlns:p="urn:p" name="p:parent" inherit-namespaces="0"><xsl:element name="child"/></xsl:element></xsl:variable><xsl:value-of select="empty(namespace-uri-for-prefix('p',$n/*/*))"/>`, "XTSE0020", "true"},
		{"boolean inherit whitespace semantics", "", `<xsl:variable name="n"><xsl:element xmlns:p="urn:p" name="p:parent" inherit-namespaces="&#x9; no &#xA;"><xsl:element name="child"/></xsl:element></xsl:variable><xsl:value-of select="empty(namespace-uri-for-prefix('p',$n/*/*))"/>`, "true", "true"},
		{"boolean composite whitespace semantics", "", `<xsl:variable name="groups" as="element()*"><xsl:for-each-group version="2.0" select="(1,2)" group-by="(.,9)" composite="&#x9; yes &#xA;"><g/></xsl:for-each-group></xsl:variable><xsl:value-of select="count($groups)"/>`, "XTSE0090", "2"},
		{"boolean literal result alias", "", `<out xsl:inherit-namespaces="false">ok</out>`, "XTSE0020", "ok"},
		{"boolean required alias", `<xsl:template name="target"><xsl:param name="p" required="true"/><xsl:value-of select="$p"/></xsl:template>`, `<xsl:call-template name="target"><xsl:with-param name="p" select="'ok'"/></xsl:call-template>`, "XTSE0020", "ok"},
		{"boolean tunnel alias", `<xsl:template name="target"><xsl:param name="p" tunnel="false" select="'ok'"/><xsl:value-of select="$p"/></xsl:template>`, `<xsl:call-template name="target"/>`, "XTSE0020", "ok"},
		{"boolean function override alias", `<xsl:function xmlns:f="urn:f" name="f:value" override="false"><xsl:sequence select="'ok'"/></xsl:function>`, `<xsl:value-of xmlns:f="urn:f" select="f:value()"/>`, "XTSE0020", "ok"},
		{"boolean sort literal alias", "", `<xsl:for-each select="(2,1)"><xsl:sort select="." stable="true"/><xsl:value-of select="."/></xsl:for-each>`, "XTSE0020", "12"},
		{"boolean output alias", `<xsl:output indent="true"/>`, "ok", "XTSE0020", "ok"},
		{"boolean standalone alias", `<xsl:output standalone="1"/>`, "ok", "XTSE0020", "ok"},
		{"boolean escaping alias", "", `<xsl:text disable-output-escaping="false">ok</xsl:text>`, "XTSE0020", "ok"},
		{"boolean message literal alias", "", `<xsl:message terminate="false"/>ok`, "XTSE0020", "ok"},
		{"boolean message computed alias", "", `<xsl:message terminate="{false()}"/>ok`, "XTDE0030", "ok"},
		{"boolean message computed no", "", `<xsl:message terminate="{'no'}"/>ok`, "ok", "ok"},
		{"boolean sort computed alias", "", `<xsl:for-each select="(2,1)"><xsl:sort select="." stable="{true()}"/><xsl:value-of select="."/></xsl:for-each>`, "XTDE0030", "12"},
		{"boolean result document computed alias", "", `<xsl:result-document href="file:///tmp/xmlsec-boolean-output.xml" indent="{true()}">secondary</xsl:result-document>ok`, "XTDE0030", "ok"},
		{"boolean standalone computed alias", "", `<xsl:result-document href="file:///tmp/xmlsec-boolean-output.xml" standalone="{false()}">secondary</xsl:result-document>ok`, "XTDE0030", "ok"},
		{"boolean yes no literals", "", `<out xsl:inherit-namespaces="no"><xsl:element name="n" inherit-namespaces="yes">ok</xsl:element></out>`, "ok", "ok"},
		{"boolean XML whitespace", "", `<xsl:variable name="n"><n>ok</n></xsl:variable><xsl:copy-of select="$n/n" copy-namespaces="&#x9; yes &#xA;"/>`, "ok", "ok"},
		{"boolean sort computed yes", "", `<xsl:for-each select="(2,1)"><xsl:sort select="." stable="{'yes'}"/><xsl:value-of select="."/></xsl:for-each>`, "12", "12"},
	}
}

func instructionContractCases() []hostFunctionCase {
	return []hostFunctionCase{
		{"local variable empty select", "", `<xsl:variable name="p" select=""/>ok`, "XPST0003", "XPST0003"},
		{"attribute empty select", "", `<out><xsl:attribute name="a" select=""/></out>`, "XPST0003", "XPST0003"},
		{"comment empty select", "", `<xsl:comment select=""/>`, "XPST0003", "XPST0003"},
		{"PI empty select", "", `<xsl:processing-instruction name="p" select=""/>`, "XPST0003", "XPST0003"},
		{"copy empty select", "", `<xsl:copy select=""/>`, "XTSE0090", "XPST0003"},
		{"copy-of empty select", "", `<xsl:copy-of select=""/>`, "XPST0003", "XPST0003"},
		{"copy-of missing select", "", `<xsl:copy-of/>`, "XTSE0010", "XTSE0010"},
		{"number empty select", "", `<xsl:number select=""/>`, "XPST0003", "XPST0003"},
		{"number empty value", "", `<xsl:number value=""/>`, "XPST0003", "XPST0003"},
		{"namespace empty select", "", `<out><xsl:namespace name="p" select=""/></out>`, "XPST0003", "XPST0003"},
		{"sequence empty select", "", `<xsl:sequence select=""/>`, "XPST0003", "XPST0003"},
		{"key empty use", `<xsl:key name="k" match="*" use=""/>`, "ok", "XPST0003", "XPST0003"},
		{"character map text child", `<xsl:character-map name="c">invalid<xsl:output-character character="a" string="b"/></xsl:character-map>`, "ok", "XTSE0010", "XTSE0010"},
		{"character map foreign child", `<xsl:character-map name="c"><wrong/></xsl:character-map>`, "ok", "XTSE0010", "XTSE0010"},
		{"character map empty declaration", `<xsl:character-map name="c"/>`, "ok", "ok", "ok"},
		{"accumulator text child", `<xsl:accumulator name="a" initial-value="0">invalid<xsl:accumulator-rule match="*" select="$value+1"/></xsl:accumulator>`, "ok", "XTSE0010", "XTSE0010"},
		{"accumulator foreign child", `<xsl:accumulator name="a" initial-value="0"><wrong/><xsl:accumulator-rule match="*" select="$value+1"/></xsl:accumulator>`, "ok", "XTSE0010", "XTSE0010"},
		{"accumulator empty initial value", `<xsl:accumulator name="a" initial-value=""><xsl:accumulator-rule match="*" select="$value+1"/></xsl:accumulator>`, "ok", "XTSE0010", "XPST0003"},
		{"accumulator rule empty select", `<xsl:accumulator name="a" initial-value="0"><xsl:accumulator-rule match="*" select=""/></xsl:accumulator>`, "ok", "XTSE0010", "XPST0003"},
		{"accumulator rule select and body", `<xsl:accumulator name="a" initial-value="0"><xsl:accumulator-rule match="*" select="1">invalid</xsl:accumulator-rule></xsl:accumulator>`, "ok", "XTSE0010", "XTSE0260"},
		{"atomic template selection", "", `<xsl:apply-templates select="42"/>`, "XTTE0520", "42"},
		{"empty template selection", "", `<xsl:apply-templates select="()"/>ok`, "ok", "ok"},
		{"function argument type error", `<xsl:function xmlns:f="urn:f" name="f:value"><xsl:param name="p" as="xs:integer"/><xsl:sequence select="$p"/></xsl:function>`, `<xsl:value-of xmlns:f="urn:f" select="f:value('bad')"/>`, "XTTE0790", "XPTY0004"},
		{"static transform argument type", `<xsl:variable name="p" static="yes" select="transform(1)"/>`, "ok", "XTSE0090", "XPTY0004"},
		{"static property function type", `<xsl:variable name="p" static="yes" select="available-system-properties#0 instance of function() as xs:integer"/>`, `<xsl:value-of select="$p"/>`, "XTSE0090", "false"},
		{"unparsed entity absent context", "", `<xsl:value-of select="unparsed-entity-uri('x')"/>`, "XTDE1370", "XPDY0002"},
		{"unparsed entity explicit node", "", `<xsl:value-of select="unparsed-entity-uri('x',parse-xml('&lt;r/>')) instance of xs:anyURI"/>`, "XPST0017", "true"},
		{"unparsed entity arity availability", "", `<xsl:value-of select="function-available('unparsed-entity-uri',2)"/>`, "false", "true"},
		{"unknown grouping attribute", "", `<xsl:for-each-group select="1" group-by="." bind-group="g">ok</xsl:for-each-group>`, "XTSE0090", "XTSE0090"},
		{"unknown instruction attribute", "", `<xsl:for-each select="1" bogus="x">ok</xsl:for-each>`, "XTSE0090", "XTSE0090"},
		{"unknown declaration attribute", `<xsl:output bogus="x"/>`, "ok", "XTSE0090", "XTSE0090"},
		{"excluded unknown attribute", "", `<xsl:for-each use-when="false()" select="1" bogus="x">bad</xsl:for-each>ok`, "ok", "ok"},
		{"future instruction attribute", "", `<xsl:for-each version="4.0" select="1" bogus="x">ok</xsl:for-each>`, "ok", "ok"},
		{"foreign instruction attribute", "", `<xsl:for-each xmlns:e="urn:e" select="1" e:bogus="x">ok</xsl:for-each>`, "ok", "ok"},
		{"unknown shadow attribute", "", `<xsl:for-each select="1" _bogus="x">ok</xsl:for-each>`, "XTSE0090", "XTSE0090"},

		{"function argument cast error", `<xsl:function xmlns:f="urn:f" name="f:value"><xsl:param name="p" as="xs:integer"/><xsl:sequence select="$p"/></xsl:function>`, `<xsl:value-of xmlns:f="urn:f" select="f:value(xs:untypedAtomic('bad'))"/>`, "FORG0001", "FORG0001"},
		{"empty value of", "", `<xsl:value-of/>`, "XTSE0870", ""},
		{"PI select and content", "", `<xsl:processing-instruction name="p" select="'x'">body</xsl:processing-instruction>`, "XTSE0880", "XTSE0880"},
		{"number select type", "", `<xsl:number select="42"/>`, "XTTE1000", "XTTE1000"},
		{"sort select error", "", `<xsl:for-each select="(1,2)"><xsl:sort select="1 idiv 0"/>ok</xsl:for-each>`, "FOAR0001", "FOAR0001"},
		{"sort body error", "", `<xsl:for-each select="(1,2)"><xsl:sort><xsl:sequence select="1 idiv 0"/></xsl:sort>ok</xsl:for-each>`, "FOAR0001", "FOAR0001"},
		{"unknown grouping collation", "", `<xsl:for-each-group select="('a','b')" group-by="." collation="urn:missing">ok</xsl:for-each-group>`, "XTDE1110", "XTDE1110"},
		{"zero length analyze regex", "", `<xsl:analyze-string select="'x'" regex="z*"><xsl:matching-substring/></xsl:analyze-string>`, "XTDE1150", ""},
		{"invalid analyze flags", "", `<xsl:analyze-string select="'x'" regex="x" flags="bad"><xsl:matching-substring/></xsl:analyze-string>`, "XTDE1145", "XTDE1145"},
		{"basic preserve validation", `<xsl:template name="unused"><xsl:element name="n" validation="preserve"/></xsl:template>`, "ok", "XTSE1660", "ok"},
		{"basic lax validation", `<xsl:template name="unused"><xsl:element name="n" validation="lax"/></xsl:template>`, "ok", "XTSE1660", "ok"},
		{"missing extension deferred", "", `<xsl:value-of xmlns:f="urn:missing" version="1.0" select="f:missing(1)"/>`, "XTDE1425", "XTDE1425"},
		{"unused missing extension", "", `<xsl:if test="false()"><xsl:value-of xmlns:f="urn:missing" version="1.0" select="f:missing(1)"/></xsl:if>ok`, "ok", "ok"},
		{"backwards missing standard function", "", `<xsl:if test="false()"><xsl:value-of version="1.0" select="missing()"/></xsl:if>ok`, "XPST0017", "XPST0017"},
		{"backwards standard function arity", "", `<xsl:if test="false()"><xsl:value-of version="1.0" select="count()"/></xsl:if>ok`, "XPST0017", "XPST0017"},
		{"backwards unbound XPath prefix", "", `<xsl:if test="false()"><xsl:value-of version="1.0" select="missing:value"/></xsl:if>ok`, "XPST0081", "XPST0081"},
		{"copy select clears template rule", `<xsl:template match="r"><xsl:copy select="."><xsl:next-match/></xsl:copy></xsl:template>`, `<xsl:variable name="d"><r/></xsl:variable><xsl:apply-templates select="$d/r"/>`, "XTSE0090", "XTDE0560"},
		{"implicit copy preserves template rule", `<xsl:template match="r" priority="1"><xsl:copy><xsl:next-match/></xsl:copy></xsl:template><xsl:template match="r" priority="0">next</xsl:template>`, `<xsl:variable name="d"><r/></xsl:variable><xsl:apply-templates select="$d/r"/>`, "next", "next"},
		{"copy select replaces atomic focus", `<xsl:variable name="d"><r>node</r></xsl:variable>`, `<xsl:for-each select="42"><xsl:copy select="$d/r"><xsl:value-of select="string(.)"/></xsl:copy></xsl:for-each>`, "XTSE0090", "node"},
		{"copy select restores atomic focus", `<xsl:variable name="d"><r/></xsl:variable>`, `<xsl:for-each select="42"><xsl:copy select="$d/r"/><xsl:value-of select="."/></xsl:for-each>`, "XTSE0090", "42"},
	}
}

// Each row preserves the edition-sensitive construct behind a named publisher
// residual. The pinned original is tested separately by the proof manifest;
// these paired controls isolate the language-version cause.
func residualEditionProofCases() []hostFunctionCase {
	const initial = `<xsl:template name="xsl:initial-template"/>`
	const chars = `<xsl:value-of select="string-to-codepoints('ab')!codepoints-to-string(.)" separator=""/>`
	return []hostFunctionCase{
		{"backwards-046", initial, "ok", "XTSE0080", "ok"},
		{"choose-0202", initial, `<xsl:choose><xsl:when test="xs:untypedAtomic('3') = 3">ok</xsl:when></xsl:choose>`, "XTSE0080", "ok"},
		{"doe-0409", initial, `<xsl:value-of select="'a' || 'b'"/>`, "XTSE0080", "ab"},
		{"for-each-group-091", initial, `<xsl:for-each-group select="('a','a')" group-by="."><xsl:value-of select="count(current-group())"/></xsl:for-each-group>`, "XTSE0080", "2"},
		{"collations-0128", "", `<xsl:evaluate xpath="'1 + 1'"/>`, "XTSE0010", "2"},
		{"collection-005", `<xsl:mode name="m2" on-no-match="shallow-skip"/>`, "ok", "XTSE0010", "ok"},
		{"for-each-group-084", "", `<xsl:for-each-group select="(1,1)" group-by="."><xsl:value-of select="current-group()!string(.)" separator=""/></xsl:for-each-group>`, "XPST0003", "11"},
		{"function-0302", "", `<xsl:value-of select="element-available('xsl:' || 'value-of')"/>`, "XPST0003", "true"},
		{"function-1902", "", `<xsl:message expand-text="yes">{1+1}</xsl:message>ok`, "XTSE0090", "ok"},
		{"function-1902 library availability", "", `<xsl:value-of select="function-available('function-lookup',2)"/>`, "false", "true"},
		{"id-041", "", `<xsl:value-of select="'a ' || 'b'"/>`, "XPST0003", "a b"},
		{"match-248", "", chars, "XPST0003", "ab"},
		{"match-254", "", chars, "XPST0003", "ab"},
		{"number-1004", "", `<xsl:iterate select="1"><xsl:on-completion><xsl:number/></xsl:on-completion></xsl:iterate>`, "XTSE0010", "XTTE0990"},
		{"output-0725", `<xsl:output html-version="5" suppress-indentation="p"/>`, "ok", "XTSE0090", "ok"},
		{"output-0726", `<xsl:output html-version="5" suppress-indentation="p"/>`, "ok", "XTSE0090", "ok"},
		{"result-document-0286", `<xsl:output name="Q{http://example.com}format2"/>`, "ok", "XTSE0020", "ok"},
		{"result-document-0287", `<xsl:output name="Q{http://example.com/}format2"/>`, "ok", "XTSE0020", "ok"},
		{"result-document-1006", "", `<xsl:value-of select="current-output-uri() instance of xs:anyURI?"/>`, "XPST0017", "true"},
		{"sequence-0132", "", `<xsl:variable name="q" as="xs:date*"><xsl:sequence><xsl:value-of select="1"/></xsl:sequence></xsl:variable><xsl:value-of select="$q"/>`, "XTSE0010", "XTTE0570"},
		{"system-property-022", "", `<xsl:evaluate xpath="'1 + 1'"/>`, "XTSE0010", "2"},
		{"error-0600a", "", `<xsl:call-template name="p"/>`, "XTTE0600", "XTTE0590"},
		{"error-1370a", "", `<xsl:value-of select="unparsed-entity-uri('x')"/>`, "XTDE1370", "XPDY0002"},
		{"error-1380a", "", `<xsl:value-of select="unparsed-entity-public-id('x')"/>`, "XTDE1380", "XPDY0002"},
	}
}

func residualEditionProofSource(test hostFunctionCase) string {
	if test.name == "error-0600a" {
		test.global = `<xsl:template name="p"><xsl:param name="p" as="xs:integer" select="3.5"/><xsl:value-of select="$p"/></xsl:template>`
	}
	return hostFunctionSheet(version20, test)
}

func TestXSLTResidualEditionProofs(t *testing.T) {
	e := engine(t, transform.Config{})
	for _, test := range residualEditionProofCases() {
		for _, processor := range []transform.XSLTVersion{transform.XSLT20, transform.XSLT30} {
			t.Run(test.name+"/"+strconv.Itoa(int(processor)), func(t *testing.T) {
				want := test.want20
				if processor == transform.XSLT30 {
					want = test.want30
				}
				compiled, err := e.CompileXSLT(t.Context(), []byte(residualEditionProofSource(test)), transform.XSLTOptions{ProcessorVersion: processor})
				got := ""
				if err == nil {
					result, executeErr := compiled.Transform(t.Context(), nil, transform.XSLTContext{Template: transform.Name{Local: nameStart}})
					err = executeErr
					if err == nil {
						got = string(result.Primary)
					}
				}
				if comparisonErrorCode(want) {
					var detail *transform.Error
					if !errors.As(err, &detail) || detail.Code != want {
						t.Fatal(got, err, want)
					}
				} else if err != nil || got != want {
					t.Fatal(got, err, want)
				}
			})
		}
	}
}

func TestXSLTHostFunctionContracts(t *testing.T) {
	e := engine(t, transform.Config{})
	for _, test := range hostFunctionCases() {
		t.Run(test.name, func(t *testing.T) {
			for _, version := range []string{version20, version30} {
				for _, nested := range []bool{false, true} {
					want := test.want30
					if version == version20 && !nested {
						want = test.want20
					}
					got, err := resourceStylesheetResult(t, e, hostFunctionSheet(version, test), nested)
					if comparisonErrorCode(want) {
						var detail *transform.Error
						if !errors.As(err, &detail) || detail.Code != want {
							t.Fatal(version, nested, got, err, want)
						}
					} else if err != nil || got != want {
						t.Fatal(version, nested, got, err, want)
					}
				}
			}
		})
	}
}

func conditionalCompilationCases() []hostFunctionCase {
	return []hostFunctionCase{
		{"excluded type", "", `<xsl:element use-when="false()" type="xs:string" name="n"/>ok`, "ok", "ok"},
		{"excluded subtree", "", `<xsl:if use-when="false()" test="true()"><xsl:element type="xs:string"/><xsl:text use-when="error()">bad</xsl:text></xsl:if>ok`, "ok", "ok"},
		{"excluded template attributes", `<xsl:template name="unused" use-when="false()" bogus="x"><xsl:element type="xs:string"/></xsl:template>`, "ok", "ok", "ok"},
		{"empty condition", "", `<xsl:text use-when="">bad</xsl:text>ok`, "XPST0003", "XPST0003"},
		{"instruction type namespace", "", `<xsl:text xpath-default-namespace="http://www.w3.org/2001/XMLSchema" use-when="1 instance of integer">ok</xsl:text>`, "ok", "ok"},
		{"literal type namespace", "", `<n xsl:xpath-default-namespace="http://www.w3.org/2001/XMLSchema" xsl:use-when="1 instance of integer">ok</n>`, "ok", "ok"},
		{"shadow exclusion", "", `<xsl:value-of _use-when="false()" select="error()"/>ok`, "XTSE0090", "ok"},
		{"shadow precedence", "", `<xsl:value-of use-when="error()" _use-when="false()" select="error()"/>ok`, "FOER0000", "ok"},
		{"shadow type namespace", "", `<xsl:text _xpath-default-namespace="http://www.w3.org/2001/XMLSchema" _use-when="1 instance of integer">ok</xsl:text>`, "XTSE0090", "ok"},
		{"shadow declaration namespaces", `<xsl:output xmlns:t="http://www.w3.org/2001/XMLSchema" _method="{if(t:integer('1')=1) then 'text' else 'xml'}"/>`, "ok", "XTSE0090", "ok"},
		{"forward static condition", `<xsl:template name="earlier"><xsl:text use-when="$later">bad</xsl:text></xsl:template><xsl:variable name="later" static="yes" select="true()"/>`, "ok", "XTSE0090", "XPST0008"},
		{"forward static shadow", `<xsl:template name="earlier"><xsl:value-of _select="{$later}"/></xsl:template><xsl:variable name="later" static="yes" select="42"/>`, "ok", "XTSE0090", "XPST0008"},
		{"prior static condition", `<xsl:variable name="enabled" static="yes" select="true()"/>`, `<xsl:text use-when="$enabled">ok</xsl:text>`, "XTSE0090", "ok"},
		{"excluded sort", "", `<xsl:for-each select="(2,1)"><xsl:sort use-when="false()" select="error()"/><xsl:value-of select="."/></xsl:for-each>`, "21", "21"},
		{"excluded choose branch", "", `<xsl:choose><xsl:when use-when="false()" test="error()">bad</xsl:when><xsl:when test="true()">ok</xsl:when></xsl:choose>`, "ok", "ok"},
		{"source preservation", `<xsl:template name="excluded" use-when="false()">bad</xsl:template>`, `<xsl:value-of select="exists(document('')/*/xsl:template[@name='excluded']/@use-when)"/>`, "true", "true"},
	}
}

func TestXSLTConditionalCompilation(t *testing.T) {
	e := engine(t, transform.Config{})
	for _, test := range conditionalCompilationCases() {
		t.Run(test.name, func(t *testing.T) {
			// The nested fn:transform path independently selects its 3.0 processor.
			for _, version := range []string{version20, version30} {
				for _, nested := range []bool{false, true} {
					want := test.want30
					if version == version20 && !nested {
						want = test.want20
					}
					got, err := resourceStylesheetResult(t, e, hostFunctionSheet(version, test), nested)
					if comparisonErrorCode(want) {
						var detail *transform.Error
						if !errors.As(err, &detail) || detail.Code != want {
							t.Fatal(version, nested, got, err, want)
						}
					} else if err != nil || got != want {
						t.Fatal(version, nested, got, err, want)
					}
				}
			}
		})
	}
	for _, version := range []string{version20, version30} {
		source := strings.Replace(sheet(version, `<xsl:template name="start"><xsl:element type="xs:string"/></xsl:template>`), `version="`+version+`"`, `version="`+version+`" use-when="false()"`, 1)
		got, err := resourceStylesheetResult(t, e, source, false)
		var detail *transform.Error
		if !errors.As(err, &detail) || detail.Code != "XTDE0040" {
			t.Fatal(version, got, err)
		}
	}
}

func TestXSLTStaticFunctionResolution(t *testing.T) {
	e := engine(t, transform.Config{})
	for _, processor := range []transform.XSLTVersion{transform.XSLT20, transform.XSLT30} {
		for _, version := range []string{version10, "17.0"} {
			for _, tc := range []struct{ expression, code string }{{"1 +", "XPST0003"}, {"missing()", "XPST0017"}, {"count()", "XPST0017"}, {"p:value", "XPST0081"}} {
				for _, body := range []string{
					`<xsl:template name="start"><xsl:value-of select="` + tc.expression + `"/></xsl:template>`,
					`<xsl:template name="start">ok</xsl:template><xsl:template name="unused"><xsl:value-of select="` + tc.expression + `"/></xsl:template>`,
					`<xsl:template name="start"><xsl:if version="` + version + `" test="false()"><xsl:value-of select="` + tc.expression + `"/></xsl:if></xsl:template>`,
				} {
					_, err := e.CompileXSLT(t.Context(), []byte(sheet(version, body)), transform.XSLTOptions{ProcessorVersion: processor})
					var detail *transform.Error
					if !errors.As(err, &detail) || detail.Code != tc.code {
						t.Fatal("XPath errors must fail compilation", processor, version, tc, err)
					}
				}
			}
		}
	}

	for _, tc := range []struct{ version, body, code string }{
		{version30, `<xsl:template name="start"><xsl:if test="false()"><xsl:sequence select="missing()"/></xsl:if></xsl:template>`, errCodeXPST0017},
		{version20, `<xsl:template name="start"><xsl:value-of select="current-output-uri()"/></xsl:template>`, errCodeXPST0017},
		{version30, `<xsl:function name="f:value" xmlns:f="urn:function"><xsl:param name="a"/><xsl:sequence select="$a"/></xsl:function><xsl:template name="start" xmlns:f="urn:function"><xsl:sequence select="f:value()"/></xsl:template>`, errCodeXPST0017},
		{version30, `<xsl:template name="start" xmlns:p="urn:wrong"><xsl:sequence select="p:value(1)"/></xsl:template><xsl:function name="p:value" xmlns:p="urn:right"><xsl:param name="a"/><xsl:sequence select="$a"/></xsl:function>`, errCodeXPST0017},
	} {
		_, err := e.CompileXSLT(t.Context(), []byte(sheet(tc.version, tc.body)), transform.XSLTOptions{})

		var detail *transform.Error
		if !errors.As(err, &detail) || detail.Code != tc.code {
			t.Fatalf("XSLT %s %s: %v", tc.version, tc.body, err)
		}
	}

	body := `<xsl:template name="start" xmlns:p="urn:right"><xsl:value-of select="p:value(7)"/></xsl:template><xsl:function name="q:value" xmlns:q="urn:right"><xsl:param name="a"/><xsl:sequence select="$a"/></xsl:function>`

	out, err := stylesheet(t, e, sheet(version30, body)).Transform(t.Context(), nil, transform.XSLTContext{Template: transform.Name{Local: nameStart}})
	if err != nil || string(out.Primary) != "7" {
		t.Fatal("forward function declaration", out, err)
	}

	body = `<xsl:template name="start"><xsl:if test="false()"><xsl:value-of select="missing()"/></xsl:if><xsl:text>ok</xsl:text></xsl:template>`

	compiled, err := e.CompileXSLT(t.Context(), []byte(sheet(version10, body)), transform.XSLTOptions{ProcessorVersion: transform.XSLT10})
	if err != nil {
		t.Fatal(err)
	}

	out, err = compiled.Transform(t.Context(), nil, transform.XSLTContext{Template: transform.Name{Local: nameStart}})
	if err != nil || string(out.Primary) != "ok" {
		t.Fatal(out, err)
	}
}

func TestXSLTStaticSyntaxErrorCategories(t *testing.T) {
	e := engine(t, transform.Config{})
	for _, tc := range []struct{ source, code string }{
		{`<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform"/>`, errCodeXTSE0010},
		{`<out/>`, "XTSE0150"},
		{sheet(version30, `<xsl:template name="start"><xsl:unknown/></xsl:template>`), errCodeXTSE0010},
		{sheet(version30, `<xsl:template name="start"><xsl:if/></xsl:template>`), errCodeXTSE0010},
		{sheet(version30, `<xsl:template name="start"><xsl:choose><xsl:when/></xsl:choose></xsl:template>`), errCodeXTSE0010},
		{sheet(version30, `<xsl:template name="start"><xsl:element/></xsl:template>`), errCodeXTSE0010},
		{sheet(version30, `<xsl:template name="start"><xsl:value-of select="missing:function()"/></xsl:template>`), errCodeXPST0081},
	} {
		_, err := e.CompileXSLT(t.Context(), []byte(tc.source), transform.XSLTOptions{})

		var detail *transform.Error
		if !errors.As(err, &detail) || detail.Code != tc.code {
			t.Fatal(tc.source, err, tc.code)
		}
	}
}

func TestXSLTSerializationVersionDoesNotChangeLanguage(t *testing.T) {
	e := engine(t, transform.Config{})

	for _, version := range []string{version20, version30} {
		body := `<xsl:template name="start"><xsl:result-document href="secondary.txt" method="text" version="1.0"><xsl:value-of select="(10,20)"/></xsl:result-document></xsl:template>`

		out, err := stylesheet(t, e, sheet(version, body)).Transform(t.Context(), nil, transform.XSLTContext{Template: transform.Name{Local: nameStart}})
		if err != nil || string(out.Secondary["secondary.txt"]) != "10 20" {
			t.Fatal(version, out, err)
		}
	}

	body := `<xsl:template name="start"><xsl:result-document href="secondary.txt" method="text" version="4.0"><xsl:if test="false()"><xsl:value-of select="missing()"/></xsl:if></xsl:result-document></xsl:template>`
	_, err := e.CompileXSLT(t.Context(), []byte(sheet(version30, body)), transform.XSLTOptions{})

	var detail *transform.Error
	if !errors.As(err, &detail) || detail.Code != errCodeXPST0017 {
		t.Fatal("serialization version enabled forwards processing", err)
	}
}

func TestStaticParametersAndEnvironment(t *testing.T) {
	ctx := context.Background()
	env := map[string]string{"APPLICATION": "visible"}
	e := engine(t, transform.Config{Environment: env})
	env["APPLICATION"] = "changed"

	if got := text(t, evaluate(t, e, `environment-variable('APPLICATION')`, transform.XPath31)); got != "visible" {
		t.Fatal(got)
	}

	if got := evaluate(t, engine(t, transform.Config{}), `available-environment-variables()`, transform.XPath31); got.Len() != 0 {
		t.Fatal(got)
	}

	source := sheet(version30, `<xsl:param name="feature" static="yes" as="xs:boolean"/><xsl:template name="start"><xsl:text use-when="$feature">enabled</xsl:text></xsl:template>`)

	s, err := e.CompileXSLT(ctx, []byte(source), transform.XSLTOptions{StaticParameters: transform.Bindings{{Local: "feature"}: transform.Values(transform.Boolean(true))}})
	if err != nil {
		t.Fatal(err)
	}

	out, err := s.Transform(ctx, nil, transform.XSLTContext{Template: transform.Name{Local: nameStart}})
	if err != nil || string(out.Primary) != "enabled" {
		t.Fatal(out, err)
	}

	d, err := e.Parse(ctx, []byte(`<r xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:schemaLocation="urn:x https://example.invalid/ignored.xsd"/>`))
	if err != nil {
		t.Fatal(err)
	}

	out, err = stylesheet(t, e, sheet(version30, `<xsl:template match="/"><xsl:text>basic</xsl:text></xsl:template>`)).Transform(ctx, d, transform.XSLTContext{})
	if err != nil || string(out.Primary) != "basic" {
		t.Fatal(out, err)
	}

	if _, err = e.CompileXPath(ctx, `not-a-function()`, transform.XPathOptions{}); err == nil {
		t.Fatal("unknown function accepted")
	}
}

func TestStreamingIterateBreakKeepsParameters(t *testing.T) {
	e := engine(t, transform.Config{})
	s := stylesheet(t, e, sheet(version30, `<xsl:template name="start"><xsl:iterate select="1 to 5"><xsl:param name="sum" select="0"/><xsl:on-completion><xsl:text>completed</xsl:text></xsl:on-completion><xsl:choose><xsl:when test=". = 3"><xsl:break select="$sum"/></xsl:when><xsl:otherwise><xsl:next-iteration><xsl:with-param name="sum" select="$sum+."/></xsl:next-iteration></xsl:otherwise></xsl:choose></xsl:iterate></xsl:template>`))

	out, err := s.Transform(context.Background(), nil, transform.XSLTContext{Template: transform.Name{Local: nameStart}})
	if err != nil {
		t.Fatal(err)
	}

	if got := string(out.Primary); got != "3" {
		t.Fatalf("iterate break = %q", got)
	}
}

func sequenceConstructorCases() []dynamicXPathCase {
	return []dynamicXPathCase{
		{"on-empty empty select", "", `<xsl:on-empty select=""/>`, "XPST0003"},
		{"on-non-empty empty select", "", `<xsl:on-non-empty select=""/>`, "XPST0003"},
		{"on-empty select and body", "", `<xsl:on-empty select="1">invalid</xsl:on-empty>`, "XTSE3185"},
		{"on-non-empty select and body", "", `<xsl:on-non-empty select="1">invalid</xsl:on-non-empty>`, "XTSE3185"},
		{"map-entry empty select", "", `<xsl:map><xsl:map-entry key="'a'" select=""/></xsl:map>`, "XPST0003"},
		{"map-entry empty key expression", "", `<xsl:map><xsl:map-entry key="" select="1"/></xsl:map>`, "XPST0003"},
		{"map-entry missing key", "", `<xsl:map><xsl:map-entry select="1"/></xsl:map>`, "XTSE0010"},
		{"iterate empty select", "", `<xsl:iterate select=""/>`, "XPST0003"},
		{"iterate missing select", "", `<xsl:iterate/>`, "XTSE0010"},
		{"completion empty select", "", `<xsl:iterate select="()"><xsl:on-completion select=""/></xsl:iterate>`, "XPST0003"},
		{"break empty select", "", `<xsl:iterate select="1"><xsl:break select=""/></xsl:iterate>`, "XPST0003"},
		{"fork sequence empty select", "", `<xsl:fork><xsl:sequence select=""/></xsl:fork>`, "XPST0003"},
		{"fork text child", "", `<xsl:fork>invalid<xsl:sequence select="1"/></xsl:fork>`, "XTSE0010"},
		{"fork unexpected instruction", "", `<xsl:fork><xsl:value-of select="1"/></xsl:fork>`, "XTSE0010"},
		{"fork mixed branch forms", "", `<xsl:fork><xsl:sequence select="1"/><xsl:for-each-group select="1" group-by="."><xsl:value-of select="."/></xsl:for-each-group></xsl:fork>`, "XTSE0010"},
		{"fork repeated grouping branch", "", `<xsl:fork><xsl:for-each-group select="1" group-by="."/><xsl:for-each-group select="1" group-by="."/></xsl:fork>`, "XTSE0010"},
		{"fork empty body", "", `<xsl:fork/>`, ""},
		{"fork empty sequence branch", "", `<xsl:fork><xsl:sequence/></xsl:fork>`, ""},
		{"fork sequence branches with fallback", "", `<xsl:fork xml:space="preserve"> <xsl:fallback>ignored</xsl:fallback><xsl:sequence select="'a'"/> <xsl:fallback>ignored</xsl:fallback><xsl:sequence select="'b'"/></xsl:fork>`, "a b"},
		{"fork single grouping branch", "", `<xsl:fork><xsl:for-each-group select="(1,2)" group-by="."><xsl:value-of select="."/></xsl:for-each-group></xsl:fork>`, "12"},
		{"fork sequence lexical namespace", "", `<xsl:fork><xsl:sequence xmlns:p="http://www.w3.org/2001/XMLSchema" select="p:integer('7')"/></xsl:fork>`, "7"},
		{"merge text child", "", `<xsl:merge>invalid<xsl:merge-source select="1"><xsl:merge-key select="."/></xsl:merge-source><xsl:merge-action>ok</xsl:merge-action></xsl:merge>`, "XTSE0010"},
		{"merge source text child", "", `<xsl:merge><xsl:merge-source select="1">invalid<xsl:merge-key select="."/></xsl:merge-source><xsl:merge-action>ok</xsl:merge-action></xsl:merge>`, "XTSE0010"},
		{"merge foreign child", "", `<xsl:merge><wrong/><xsl:merge-source select="1"><xsl:merge-key select="."/></xsl:merge-source><xsl:merge-action>ok</xsl:merge-action></xsl:merge>`, "XTSE0010"},
		{"merge source after action", "", `<xsl:merge><xsl:merge-action>ok</xsl:merge-action><xsl:merge-source select="1"><xsl:merge-key select="."/></xsl:merge-source></xsl:merge>`, "XTSE0010"},
		{"merge missing key", "", `<xsl:merge><xsl:merge-source select="1"/><xsl:merge-action>ok</xsl:merge-action></xsl:merge>`, "XTSE0010"},
		{"merge missing select", "", `<xsl:merge><xsl:merge-source for-each-item="1"><xsl:merge-key select="."/></xsl:merge-source><xsl:merge-action>ok</xsl:merge-action></xsl:merge>`, "XTSE0010"},
		{"merge empty action", "", `<xsl:merge><xsl:merge-source select="1"><xsl:merge-key select="."/></xsl:merge-source><xsl:merge-action/></xsl:merge>`, ""},
		{"merge source empty select", "", `<xsl:merge><xsl:merge-source select=""><xsl:merge-key select="."/></xsl:merge-source><xsl:merge-action>ok</xsl:merge-action></xsl:merge>`, "XPST0003"},
		{"merge source empty for-each-item", "", `<xsl:merge><xsl:merge-source for-each-item="" select="."><xsl:merge-key select="."/></xsl:merge-source><xsl:merge-action>ok</xsl:merge-action></xsl:merge>`, "XPST0003"},
		{"merge source empty for-each-source", "", `<xsl:merge><xsl:merge-source for-each-source="" select="."><xsl:merge-key select="."/></xsl:merge-source><xsl:merge-action>ok</xsl:merge-action></xsl:merge>`, "XPST0003"},
		{"merge key empty select", "", `<xsl:merge><xsl:merge-source select="1"><xsl:merge-key select=""/></xsl:merge-source><xsl:merge-action>ok</xsl:merge-action></xsl:merge>`, "XPST0003"},
		{"next iteration text child", "", `<xsl:iterate select="1"><xsl:next-iteration>invalid</xsl:next-iteration></xsl:iterate>`, "XTSE0010"},
		{"next iteration unexpected child", "", `<xsl:iterate select="1"><xsl:next-iteration><wrong/></xsl:next-iteration></xsl:iterate>`, "XTSE0010"},
		{"element empty name", "", `<xsl:element name=""/>`, "XTDE0820"},
		{"element computed empty name", "", `<xsl:element name="{''}"/>`, "XTDE0820"},
		{"element missing name", "", `<xsl:element/>`, "XTSE0010"},
		{"attribute empty name", "", `<out><xsl:attribute name=""/></out>`, "XTDE0850"},
		{"attribute computed empty name", "", `<out><xsl:attribute name="{''}"/></out>`, "XTDE0850"},
		{"attribute missing name", "", `<out><xsl:attribute/></out>`, "XTSE0010"},
		{"PI empty name", "", `<xsl:processing-instruction name=""/>`, "XTDE0890"},
		{"PI computed empty name", "", `<xsl:processing-instruction name="{''}"/>`, "XTDE0890"},
		{"PI missing name", "", `<xsl:processing-instruction/>`, "XTSE0010"},
		{"variable select and preserved body", "", `<xsl:if test="true()" xml:space="preserve"><xsl:variable name="p" select="1"> </xsl:variable><xsl:sequence select="$p"/></xsl:if>`, "XTSE0620"},
		{"template comment text coalescing", "", "A<!--merge-->\n  <xsl:text>X</xsl:text>", "A\n  X"},
		{"template PI text coalescing", "", "A<?merge ignored?>\n  <xsl:text>X</xsl:text>", "A\n  X"},
		{"instruction result exclusion scope", "", `<xsl:variable name="v" as="element()"><xsl:if xmlns:p="urn:policy" exclude-result-prefixes="p" test="true()"><out/></xsl:if></xsl:variable><xsl:value-of select="exists(namespace-uri-for-prefix('p',$v))"/>`, nameFalse},
		{"structural clause result exclusion scope", "", `<xsl:variable name="v" as="element()"><xsl:choose><xsl:when test="false()"/><xsl:otherwise xmlns:p="urn:policy" exclude-result-prefixes="p"><out/></xsl:otherwise></xsl:choose></xsl:variable><xsl:value-of select="exists(namespace-uri-for-prefix('p',$v))"/>`, nameFalse},
		{"instruction result exclusion default prefix", "", `<xsl:variable name="v" as="element()"><xsl:if xmlns="urn:unused" exclude-result-prefixes="#default" test="true()"><out xmlns=""/></xsl:if></xsl:variable><xsl:value-of select="exists(namespace-uri-for-prefix('',$v))"/>`, nameFalse},
		{"break item order and identity", "", `<xsl:variable name="n" as="node()"><n/></xsl:variable><xsl:variable name="v" as="item()*"><xsl:iterate select="1"><xsl:break><xsl:sequence select="1"/><xsl:sequence select="$n"/><xsl:text>X</xsl:text><xsl:sequence select="2"/></xsl:break></xsl:iterate></xsl:variable><xsl:value-of select="count($v),$v[1] instance of xs:integer,$v[2] is $n,$v[3] instance of text(),$v[4] eq 2"/>`, "4 true true true true"},
		{"iterate empty string default", "", `<xsl:iterate select="1"><xsl:param name="p"/><xsl:break select="$p instance of xs:string and $p eq ''"/></xsl:iterate>`, nameTrue},
		{"iterate document default", "", `<xsl:iterate select="1"><xsl:param name="p"><a/><b/></xsl:param><xsl:break select="$p instance of document-node() and count($p/*) eq 2"/></xsl:iterate>`, nameTrue},
		{"iterate typed node identity", "", `<xsl:variable name="n" as="node()"><n/></xsl:variable><xsl:iterate select="1"><xsl:param name="p" as="node()"><xsl:sequence select="$n"/></xsl:param><xsl:break select="$p is $n"/></xsl:iterate>`, nameTrue},
		{"iterate empty typed value", "", `<xsl:iterate select="1"><xsl:param name="p" as="xs:integer" select="()"/><xsl:break select="$p"/></xsl:iterate>`, "XTTE0590"},
		{"next iteration empty typed value", "", `<xsl:iterate select="1 to 2"><xsl:param name="p" as="xs:integer" select="1"/><xsl:value-of select="$p"/><xsl:next-iteration><xsl:with-param name="p" select="()"/></xsl:next-iteration></xsl:iterate>`, "XTTE0590"},
		{"iterate untyped conversion", "", `<xsl:iterate select="1"><xsl:param name="p" as="xs:integer" select="xs:untypedAtomic('7')"/><xsl:break select="$p instance of xs:integer and $p eq 7"/></xsl:iterate>`, nameTrue},
		{"iterate parameter scoped type", "", `<xsl:iterate select="1"><xsl:param xmlns:t="http://www.w3.org/2001/XMLSchema" name="p" as="t:integer" select="xs:untypedAtomic('7')"/><xsl:break select="$p instance of xs:integer and $p eq 7"/></xsl:iterate>`, nameTrue},
		{"iterate parameter scoped name", "", `<xsl:iterate select="1"><xsl:param xmlns:p="urn:parameter" name="p:value" select="7"/><xsl:break xmlns:p="urn:parameter" select="$p:value"/></xsl:iterate>`, "7"},
		{"iterate next scoped type", "", `<xsl:iterate select="1"><xsl:param xmlns:t="http://www.w3.org/2001/XMLSchema" name="p" as="t:integer" select="1"/><xsl:on-completion select="$p instance of xs:integer and $p eq 7"/><xsl:next-iteration><xsl:with-param name="p" select="xs:untypedAtomic('7')"/></xsl:next-iteration></xsl:iterate>`, nameTrue},
		{"iterate preceding parameter scope", "", `<xsl:variable name="p" select="100"/><xsl:iterate select="1"><xsl:param name="p" select="$p+1"/><xsl:param name="q" select="$p+1"/><xsl:break select="concat($p,':',$q)"/></xsl:iterate><xsl:value-of select="concat('|',$p)"/>`, "101:102|100"},
		{"iterate parameter body scope", "", `<xsl:iterate select="1"><xsl:param name="p" select="'body'"/><xsl:param name="q" as="xs:string"><xsl:sequence select="$p"/></xsl:param><xsl:break select="$q"/></xsl:iterate>`, "body"},
		{"iterate empty initial parameter scope", "", `<xsl:iterate select="()"><xsl:param name="p" select="41"/><xsl:param name="q" select="$p+1"/><xsl:on-completion select="$q"/></xsl:iterate>`, "42"},
		{"iterate empty sequence default", "", `<xsl:iterate select="1"><xsl:param name="p" as="empty-sequence()"/><xsl:break select="empty($p)"/></xsl:iterate>`, nameTrue},
		{"iterate commented optional default", "", `<xsl:iterate select="1"><xsl:param name="p" as="xs:integer? (: optional :)"/><xsl:break select="empty($p)"/></xsl:iterate>`, nameTrue},
		{"iterate implicit mandatory default", "", `<xsl:iterate select="1"><xsl:param name="p" as="xs:integer"/><xsl:break select="$p"/></xsl:iterate>`, "XTSE3520"},
		{"iterate required parameter rejected", "", `<xsl:iterate select="1"><xsl:param name="p" required="yes"/><xsl:break select="1"/></xsl:iterate>`, "XTSE0020"},
		{"iterate tunnel parameter rejected", "", `<xsl:iterate select="1"><xsl:param name="p" tunnel="yes"/><xsl:break select="1"/></xsl:iterate>`, "XTSE0020"},
		{"iterate parameter invalid name", "", `<xsl:iterate select="1"><xsl:param name="bad:name:twice"/><xsl:break select="1"/></xsl:iterate>`, "XTSE0020"},
		{"iterate parameter select and body", "", `<xsl:iterate select="1"><xsl:param name="p" select="1"><xsl:text>ignored</xsl:text></xsl:param><xsl:break select="$p"/></xsl:iterate>`, "XTSE0620"},
		{"iterate parameter empty select", "", `<xsl:iterate select="1"><xsl:param name="p" select=""/><xsl:break select="1"/></xsl:iterate>`, "XPST0003"},
		{"nested iterate parameter names", "", `<xsl:iterate select="1"><xsl:param name="outer" select="0"/><xsl:iterate select="1"><xsl:param name="inner" select="0"/><xsl:on-completion select="$inner"/><xsl:next-iteration><xsl:with-param name="inner" select="$inner+1"/></xsl:next-iteration></xsl:iterate></xsl:iterate>`, "1"},
		{"sort text node cardinality", "", `<xsl:for-each select="(2,1)"><xsl:sort><xsl:text>A</xsl:text><xsl:text>B</xsl:text></xsl:sort><xsl:value-of select="."/></xsl:for-each>`, "XTTE1020"},
		{"sort array cardinality", "", `<xsl:for-each select="(2,1)"><xsl:sort select="[1,2]"/><xsl:value-of select="."/></xsl:for-each>`, "XTTE1020"},
		{"sort body atomization error", "", `<xsl:for-each select="(2,1)"><xsl:sort><xsl:sequence select="map{}"/></xsl:sort><xsl:value-of select="."/></xsl:for-each>`, errCodeFOTY0013},
		{"sort body numeric value", "", `<xsl:for-each select="(3,1,2)"><xsl:sort><xsl:sequence select="."/></xsl:sort><xsl:value-of select="."/></xsl:for-each>`, "123"},
		{"sort empty stable key", "", `<xsl:for-each select="(3,2,1)"><xsl:sort><xsl:sequence select="()"/></xsl:sort><xsl:value-of select="."/></xsl:for-each>`, "321"},
		{"sort body compatibility", "", `<xsl:for-each select="(3,1,2)"><xsl:sort version="1.0"><xsl:sequence version="3.0" select="(.,99)"/></xsl:sort><xsl:value-of select="."/></xsl:for-each>`, "123"},
	}
}

func TestXSLTStylesheetPreprocessing(t *testing.T) {
	e := engine(t, transform.Config{})
	source := sheet(version30, "<xsl:template name=\"start\">A<!--merge-->\n  <xsl:text>X</xsl:text><?merge ignored?> </xsl:template>")
	check := `let $style := parse-xml($stylesheet), $before := serialize($style),
        $output := transform(map{'stylesheet-node':$style,'initial-template':QName('','start'),'delivery-format':'serialized'})?output
        return $output eq concat('A',codepoints-to-string(10),'  X') and
        serialize($style) eq $before and count($style//comment()) eq 1 and count($style//processing-instruction()) eq 1`
	result, err := query(t, e, check, transform.XPath31).Evaluate(t.Context(), nil, transform.XPathContext{Variables: transform.Bindings{{Local: variableStylesheet}: transform.Values(transform.String(source))}})
	if err != nil || text(t, result) != nameTrue {
		t.Fatal(result, err)
	}

	for _, standard := range []bool{false, true} {
		module := `<out xsl:version="3.0"><xsl:value-of select="exists(document('')/*/@xml:space)"/></out>`
		if standard {
			module = `<xsl:stylesheet version="3.0"><xsl:template match="/"><out><xsl:value-of select="exists(document('')/*/@xml:space)"/></out></xsl:template></xsl:stylesheet>`
		}
		input := `<wrapper xml:space="preserve" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">` + module + `</wrapper>`
		expression := `let $style := parse-xml($stylesheet), $out := transform(map{'stylesheet-node':$style/*/*,'source-node':parse-xml('<r/>')})?output
            return string($out) eq 'false' and empty($out/*/@xml:space)`
		result, err := query(t, e, expression, transform.XPath31).Evaluate(t.Context(), nil, transform.XPathContext{Variables: transform.Bindings{{Local: variableStylesheet}: transform.Values(transform.String(input))}})
		if err != nil || text(t, result) != nameTrue {
			t.Fatal("embedded stylesheet-node original source", standard, result, err)
		}
	}

	bounded := engine(t, transform.Config{Limits: transform.Limits{MaxOperations: 64}})
	large := sheet(version30, `<xsl:template name="start">A`+strings.Repeat(`<!--removed--> `, 128)+`</xsl:template>`)
	if _, err := bounded.CompileXSLT(t.Context(), []byte(large), transform.XSLTOptions{}); !errors.Is(err, transform.ErrLimit) {
		t.Fatal("stylesheet preprocessing ignored the operation budget", err)
	}

	canceled, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := e.CompileXSLT(canceled, []byte(source), transform.XSLTOptions{}); !errors.Is(err, context.Canceled) {
		t.Fatal("stylesheet preprocessing ignored cancellation", err)
	}
}

func TestSequenceConstructorContracts(t *testing.T) {
	e := engine(t, transform.Config{})
	for _, test := range sequenceConstructorCases() {
		source := sheet(version30, `<xsl:template name="start">`+test.body+`</xsl:template>`)
		for _, nested := range []bool{false, true} {
			got, err := resourceStylesheetResult(t, e, source, nested)
			if comparisonErrorCode(test.want) {
				var detail *transform.Error
				if !errors.As(err, &detail) || detail.Code != test.want {
					t.Fatal(test.name, nested, got, err, test.want)
				}
			} else if err != nil || got != test.want {
				t.Fatal(test.name, nested, got, err, test.want)
			}
		}
	}
}

func TestStreamingMergeOrderAndGroups(t *testing.T) {
	e := engine(t, transform.Config{})
	s := stylesheet(t, e, sheet(version30, `<xsl:template name="start"><xsl:merge><xsl:merge-source name="left" select="(3,1,2)" sort-before-merge="yes"><xsl:merge-key select="." data-type="number"/></xsl:merge-source><xsl:merge-source name="right" select="(2,4)"><xsl:merge-key select="." data-type="number"/></xsl:merge-source><xsl:merge-action><xsl:value-of select="concat(current-merge-key(),':',count(current-merge-group()),':',count(current-merge-group('left')),',')"/></xsl:merge-action></xsl:merge></xsl:template>`))

	out, err := s.Transform(context.Background(), nil, transform.XSLTContext{Template: transform.Name{Local: nameStart}})
	if err != nil {
		t.Fatal(err)
	}

	if got := string(out.Primary); got != "1:1:1,2:2:1,3:1:1,4:1:0," {
		t.Fatalf("merge order/groups = %q", got)
	}
}

func mergeFocusCases() []dynamicXPathCase {
	return []dynamicXPathCase{
		{"atomic action focus", "", `<xsl:for-each select="99"><xsl:merge><xsl:merge-source select="(1,2)"><xsl:merge-key select="."/></xsl:merge-source><xsl:merge-action><xsl:value-of select="concat(.,':',current(),':',position(),':',last(),';')"/></xsl:merge-action></xsl:merge><xsl:value-of select="."/></xsl:for-each>`, "1:1:1:2;2:2:2:2;99"},
		{"node action focus", "", `<xsl:variable name="n"><r>node</r></xsl:variable><xsl:for-each select="99"><xsl:merge><xsl:merge-source select="$n/r"><xsl:merge-key select="."/></xsl:merge-source><xsl:merge-action><xsl:value-of select="concat(.,':',current())"/></xsl:merge-action></xsl:merge><xsl:value-of select="."/></xsl:for-each>`, "node:node99"},
		{"anchor focus", "", `<xsl:merge><xsl:merge-source for-each-item="(10,20,30)" select="concat(.,':',position(),':',last())"><xsl:merge-key select="."/></xsl:merge-source><xsl:merge-action><xsl:value-of select="concat(.,';')"/></xsl:merge-action></xsl:merge>`, "10:1:3;20:2:3;30:3:3;"},
		{"singleton key focus", "", `<xsl:for-each select="(10,20)"><xsl:merge><xsl:merge-source select="(1,2)"><xsl:merge-key select="position()+last()"/></xsl:merge-source><xsl:merge-action><xsl:value-of select="concat(current-merge-key(),':',count(current-merge-group()),';')"/></xsl:merge-action></xsl:merge></xsl:for-each>`, "2:2;2:2;"},
		{"composite current merge key", "", `<xsl:merge><xsl:merge-source select="(1,xs:float(1),2)"><xsl:merge-key select="'k'"/><xsl:merge-key select="."/></xsl:merge-source><xsl:merge-action><xsl:value-of select="concat(count(current-merge-key()),':',current-merge-key()[2] instance of xs:integer,':',string-join(current-merge-key() ! string(.),'|'),':',count(current-merge-group()),';')"/></xsl:merge-action></xsl:merge>`, "2:true:k|1:2;2:true:k|2:1;"},
		{"nested action restores focus", "", `<xsl:merge><xsl:merge-source select="(1,2)"><xsl:merge-key select="."/></xsl:merge-source><xsl:merge-action><xsl:value-of select="."/><xsl:merge><xsl:merge-source select="(8,9)"><xsl:merge-key select="."/></xsl:merge-source><xsl:merge-action><xsl:value-of select="."/></xsl:merge-action></xsl:merge><xsl:value-of select="concat(.,':',position(),':',last(),';')"/></xsl:merge-action></xsl:merge>`, "1891:1:2;2892:2:2;"},
		{"failed action restores focus", "", `<xsl:for-each select="99"><xsl:try><xsl:merge><xsl:merge-source select="1"><xsl:merge-key select="."/></xsl:merge-source><xsl:merge-action><xsl:sequence select="1 idiv 0"/></xsl:merge-action></xsl:merge><xsl:catch><xsl:value-of select="concat(.,':',position(),':',last())"/></xsl:catch></xsl:try></xsl:for-each>`, "99:1:1"},
	}
}

func TestMergeFocusContracts(t *testing.T) {
	e := engine(t, transform.Config{})
	for _, test := range mergeFocusCases() {
		t.Run(test.name, func(t *testing.T) {
			for _, nested := range []bool{false, true} {
				got, err := resourceStylesheetResult(t, e, dynamicXPathSheet(test), nested)
				if err != nil || got != test.want {
					t.Fatal(nested, got, err, test.want)
				}
			}
		})
	}
}

func mergeSnapshotCases() []struct{ name, source, module, want string } {
	module := `<r xmlns:p="urn:p"><header/><a><n k="1">A</n><n k="2">B</n></a><tail/></r>`
	global := `<xsl:accumulator name="a" as="xs:integer" initial-value="0"><xsl:accumulator-rule match="n" select="$value+1"/></xsl:accumulator><xsl:variable name="original" select="doc('module.xsl')"/>`
	action := `<xsl:value-of select="string-join((not(. is $original/r/a/n[@k=current()/@k]),count(root(.)/r/header),count(../n),accumulator-before('a'),accumulator-after('a'),namespace-uri-for-prefix('p',.)),':')"/><xsl:text>;</xsl:text>`
	tests := make([]struct{ name, source, module, want string }, 0, 4)
	for _, stream := range []bool{false, true} {
		want := "false:1:2:1:1:urn:p;false:1:2:2:2:urn:p;"
		if stream {
			want = "true:0:1:1:1:urn:p;true:0:1:2:2:urn:p;"
		}
		body := `<xsl:merge><xsl:merge-source for-each-source="'module.xsl'" select="r/a/n" streamable="` + strconv.FormatBool(stream) + `" use-accumulators="a"><xsl:merge-key select="@k"/></xsl:merge-source><xsl:merge-action>` + action + `</xsl:merge-action></xsl:merge>`
		tests = append(tests, struct{ name, source, module, want string }{"node snapshots " + strconv.FormatBool(stream), sheet(version30, global+`<xsl:template name="start">`+body+`</xsl:template>`), module, want})
	}
	implicit := tests[1]
	tests = append(tests, struct{ name, source, module, want string }{"node explicit snapshots", strings.Replace(strings.Replace(implicit.source, `select="r/a/n"`, `select="snapshot(r/a/n)"`, 1), `streamable="true"`, `streamable="false"`, 1), module, implicit.want})
	body := `<xsl:merge><xsl:merge-source for-each-source="'module.xsl'" select="(10,20)" streamable="yes"><xsl:merge-key select="."/></xsl:merge-source><xsl:merge-action><xsl:value-of select=". instance of xs:integer, current-merge-key(), current-merge-group()"/><xsl:text>;</xsl:text></xsl:merge-action></xsl:merge>`
	return append(tests, struct{ name, source, module, want string }{"atomic snapshots", sheet(version30, `<xsl:template name="start">`+body+`</xsl:template>`), module, "true 10 10;true 20 20;"})
}

func TestMergeSnapshotSemantics(t *testing.T) {
	for _, test := range mergeSnapshotCases() {
		t.Run(test.name, func(t *testing.T) {
			e := engine(t, transform.Config{Resolver: transform.ResolverFunc(func(ctx context.Context, uri string) (io.ReadCloser, error) {
				if uri != "https://example.test/module.xsl" {
					return nil, transform.ErrResource
				}
				return io.NopCloser(strings.NewReader(test.module)), ctx.Err()
			})})
			compiled, err := e.CompileXSLT(t.Context(), []byte(test.source), transform.XSLTOptions{ProcessorVersion: transform.XSLT30, BaseURI: "https://example.test/main.xsl"})
			if err != nil {
				t.Fatal(err)
			}
			result, err := compiled.Transform(t.Context(), nil, transform.XSLTContext{Template: transform.Name{Local: nameStart}})
			if err != nil || string(result.Primary) != test.want {
				t.Fatal(result, err, test.want)
			}
		})
	}
}

func TestStreamingResourceReferenceEscaping(t *testing.T) {
	for _, reference := range []string{"путь a.xml", "%D0%BF%D1%83%D1%82%D1%8C%20a.xml"} {
		for _, merge := range []bool{false, true} {
			t.Run(reference+strconv.FormatBool(merge), func(t *testing.T) {
				var opened []string
				e := engine(t, transform.Config{Resolver: transform.ResolverFunc(func(_ context.Context, uri string) (io.ReadCloser, error) {
					opened = append(opened, uri)
					return io.NopCloser(strings.NewReader(`<r>ok</r>`)), nil
				})})
				body := `<xsl:source-document href="` + reference + `"><xsl:value-of select="r"/></xsl:source-document>`
				if merge {
					body = `<xsl:merge><xsl:merge-source for-each-source="'` + reference + `'" select="r"><xsl:merge-key select="."/></xsl:merge-source><xsl:merge-action><xsl:value-of select="."/></xsl:merge-action></xsl:merge>`
				}
				compiled, err := e.CompileXSLT(t.Context(), []byte(sheet(version30, `<xsl:template name="start">`+body+`</xsl:template>`)), transform.XSLTOptions{BaseURI: "https://example.test/папка/main.xsl"})
				if err != nil {
					t.Fatal(err)
				}
				out, err := compiled.Transform(t.Context(), nil, transform.XSLTContext{Template: transform.Name{Local: nameStart}})
				if err != nil || string(out.Primary) != "ok" || len(opened) != 1 || opened[0] != "https://example.test/%D0%BF%D0%B0%D0%BF%D0%BA%D0%B0/%D0%BF%D1%83%D1%82%D1%8C%20a.xml" {
					t.Fatal(out, opened, err)
				}
			})
		}
	}
}

func TestStreamingRejectsUnsortedMerge(t *testing.T) {
	e := engine(t, transform.Config{})
	s := stylesheet(t, e, sheet(version30, `<xsl:template name="start"><xsl:merge><xsl:merge-source select="(2,1)"><xsl:merge-key select="." data-type="number"/></xsl:merge-source><xsl:merge-action><xsl:value-of select="current-merge-key()"/></xsl:merge-action></xsl:merge></xsl:template>`))

	_, err := s.Transform(context.Background(), nil, transform.XSLTContext{Template: transform.Name{Local: nameStart}})
	if err == nil || !strings.Contains(err.Error(), "XTDE2220") {
		t.Fatalf("unsorted merge error = %v", err)
	}
}

func TestStreamingNestedMergeRestoresFunctions(t *testing.T) {
	e := engine(t, transform.Config{})
	s := stylesheet(t, e, sheet(version30, `<xsl:template name="start"><xsl:merge><xsl:merge-source name="outer" select="(1,2)"><xsl:merge-key select="."/></xsl:merge-source><xsl:merge-action><xsl:value-of select="current-merge-key()"/><xsl:text>[</xsl:text><xsl:merge><xsl:merge-source name="inner" select="(8,9)"><xsl:merge-key select="."/></xsl:merge-source><xsl:merge-action><xsl:value-of select="current-merge-key()"/></xsl:merge-action></xsl:merge><xsl:text>]</xsl:text><xsl:value-of select="current-merge-key()"/><xsl:text>;</xsl:text></xsl:merge-action></xsl:merge></xsl:template>`))

	out, err := s.Transform(context.Background(), nil, transform.XSLTContext{Template: transform.Name{Local: nameStart}})
	if err != nil {
		t.Fatal(err)
	}

	if got := string(out.Primary); got != "1[89]1;2[89]2;" {
		t.Fatalf("nested merge = %q", got)
	}
}

func TestStreamingResultDocumentTransactions(t *testing.T) {
	e := engine(t, transform.Config{})

	cases := []struct{ name, body, primary, secondaryURI, secondaryText string }{
		{"secondary preflight", `<xsl:try><xsl:result-document href="outer.txt" method="text" standalone="{1 idiv 0}"><xsl:result-document href="nested.txt" method="text">bad</xsl:result-document></xsl:result-document><xsl:catch><xsl:result-document href="outer.txt" method="text">ok</xsl:result-document></xsl:catch></xsl:try>`, "", "outer.txt", "ok"},
		{"primary rollback", `<xsl:try><xsl:result-document><xsl:text>partial</xsl:text><xsl:sequence select="error()"/></xsl:result-document><xsl:catch><xsl:result-document>ok</xsl:result-document></xsl:catch></xsl:try>`, "ok", "", ""},
		{"JSON validation rollback", `<xsl:try><xsl:result-document href="data.json" method="json" build-tree="no"><xsl:sequence select="map{1:'a','1':'b'}"/></xsl:result-document><xsl:catch><xsl:result-document href="data.json" method="text">recovered</xsl:result-document></xsl:catch></xsl:try>`, "", "data.json", "recovered"},
		{"primary item capture", `<xsl:result-document method="{'json'}" build-tree="{false()}"><xsl:sequence select="map{'answer':42}"/></xsl:result-document>`, `{"answer":42}`, "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := stylesheet(t, e, sheet(version30, `<xsl:template name="start">`+tc.body+`</xsl:template>`))

			out, err := s.Transform(context.Background(), nil, transform.XSLTContext{Template: transform.Name{Local: nameStart}})
			if err != nil {
				t.Fatal(err)
			}

			if got := string(out.Primary); got != tc.primary {
				t.Fatalf("primary = %q, want %q", got, tc.primary)
			}

			if tc.secondaryURI == "" {
				if len(out.Secondary) != 0 {
					t.Fatalf("unexpected secondary outputs %v", out.Secondary)
				}

				return
			}

			if len(out.Secondary) != 1 || string(out.Secondary[tc.secondaryURI]) != tc.secondaryText {
				t.Fatalf("secondary outputs = %v", out.Secondary)
			}
		})
	}
}

func resultDocumentURICases() []struct{ name, body, check, want string } {
	const principal = `https://output.invalid/base/main`
	const collision = "XTDE1490"

	return []struct{ name, body, check, want string }{
		{"escaped Unicode output URI", `<xsl:result-document href="путь a.xml">ok</xsl:result-document>`, `string($r('https://output.invalid/base/%D0%BF%D1%83%D1%82%D1%8C%20a.xml')) eq 'ok'`, nameTrue},
		{"escaped output URI idempotent", `<xsl:result-document href="a%20b.xml">ok</xsl:result-document>`, `string($r('https://output.invalid/base/a%20b.xml')) eq 'ok'`, nameTrue},
		{"escaped output aliases collide", `<xsl:result-document href="a b.xml">one</xsl:result-document><xsl:result-document href="a%20b.xml">two</xsl:result-document>`, "exists(map:keys($r))", collision},
		{"implicit before explicit", `implicit<xsl:result-document>explicit</xsl:result-document>`, "exists(map:keys($r))", collision},
		{"implicit after explicit", `<xsl:result-document>explicit</xsl:result-document>implicit`, "exists(map:keys($r))", collision},
		{"captured atomic before explicit", `<xsl:sequence select="42"/><xsl:result-document>explicit</xsl:result-document>`, "exists(map:keys($r))", collision},
		{"captured atomic after explicit", `<xsl:result-document>explicit</xsl:result-document><xsl:sequence select="42"/>`, "exists(map:keys($r))", collision},
		{"element containing explicit", `<out><xsl:result-document>explicit</xsl:result-document></out>`, "exists(map:keys($r))", collision},
		{"whitespace is content", `<xsl:result-document>explicit</xsl:result-document><xsl:text> </xsl:text>`, "exists(map:keys($r))", collision},
		{"empty sequence is not content", `<xsl:sequence select="()"/><xsl:result-document>ok</xsl:result-document>`, `string($r('` + principal + `')) eq 'ok'`, nameTrue},
		{"explicit twice", `<xsl:result-document>one</xsl:result-document><xsl:result-document href="">two</xsl:result-document>`, "exists(map:keys($r))", collision},
		{"absolute principal alias", `<xsl:result-document href="` + principal + `">ok</xsl:result-document>`, `string($r('` + principal + `')) eq 'ok'`, nameTrue},
		{"relative principal alias", `<xsl:result-document href="a/../main">ok</xsl:result-document>`, `string($r('` + principal + `')) eq 'ok'`, nameTrue},
		{"implicit and absolute principal", `implicit<xsl:result-document href="` + principal + `">explicit</xsl:result-document>`, "exists(map:keys($r))", collision},
		{"absolute principal and implicit", `<xsl:result-document href="` + principal + `">explicit</xsl:result-document><out/>`, "exists(map:keys($r))", collision},
		{"principal aliases collide", `<xsl:result-document>one</xsl:result-document><xsl:result-document href="` + principal + `">two</xsl:result-document>`, "exists(map:keys($r))", collision},
		{"missing format before URI conflict", `<out><xsl:result-document format="missing">explicit</xsl:result-document></out>`, "exists(map:keys($r))", "XTDE1460"},
		{"invalid format before URI conflict", `<out><xsl:result-document format="not:a:QName">explicit</xsl:result-document></out>`, "exists(map:keys($r))", "XTDE1460"},
		{"secondary aliases collide", `<xsl:result-document href="dir/../out">one</xsl:result-document><xsl:result-document href="https://output.invalid/base/out">two</xsl:result-document>`, "exists(map:keys($r))", collision},
		{"file aliases collide", `<xsl:result-document href="file:///base/dir/../out">one</xsl:result-document><xsl:result-document href="file:///base/out">two</xsl:result-document>`, "exists(map:keys($r))", collision},
		{"nested outputs share base", `<xsl:result-document href="dir/outer"><xsl:value-of select="current-output-uri()"/><xsl:result-document href="inner"><xsl:value-of select="current-output-uri()"/></xsl:result-document><xsl:value-of select="current-output-uri()"/></xsl:result-document>`, `string($r('https://output.invalid/base/inner')) eq 'https://output.invalid/base/inner' and string-join($r('https://output.invalid/base/dir/outer') ! string(.), '') eq 'https://output.invalid/base/dir/outerhttps://output.invalid/base/dir/outer'`, nameTrue},
		{"nested duplicates collide", `<xsl:result-document href="dir/outer"><xsl:result-document href="inner">one</xsl:result-document></xsl:result-document><xsl:result-document href="inner">two</xsl:result-document>`, "exists(map:keys($r))", collision},
		{"nested absent href inherits current URI", `<xsl:result-document href="dir/outer"><xsl:result-document><xsl:value-of select="current-output-uri()"/></xsl:result-document></xsl:result-document>`, `string($r('` + principal + `')) eq 'https://output.invalid/base/dir/outer'`, nameTrue},
		{"nested empty href resets current URI", `<xsl:result-document href="dir/outer"><xsl:result-document href=""><xsl:value-of select="current-output-uri()"/></xsl:result-document></xsl:result-document>`, `string($r('` + principal + `')) eq '` + principal + `'`, nameTrue},
		{"implicit rollback releases principal", `<xsl:try>discard<xsl:sequence select="error()"/><xsl:catch><xsl:result-document>ok</xsl:result-document></xsl:catch></xsl:try>`, `string($r('` + principal + `')) eq 'ok'`, nameTrue},
		{"catch implicit collision", `<xsl:result-document>ok</xsl:result-document><xsl:try><xsl:sequence select="42"/><xsl:catch errors="err:XTDE1490" xmlns:err="http://www.w3.org/2005/xqt-errors"><xsl:result-document href="caught">caught</xsl:result-document></xsl:catch></xsl:try>`, `string($r('` + principal + `')) eq 'ok' and string($r('https://output.invalid/base/caught')) eq 'caught'`, nameTrue},
		{"catch selected collision", `<xsl:result-document>ok</xsl:result-document><xsl:try select="42"><xsl:catch errors="err:XTDE1490" xmlns:err="http://www.w3.org/2005/xqt-errors"><xsl:result-document href="caught">caught</xsl:result-document></xsl:catch></xsl:try>`, `string($r('` + principal + `')) eq 'ok' and string($r('https://output.invalid/base/caught')) eq 'caught'`, nameTrue},
		{"principal preflight rollback", `<xsl:try><xsl:result-document standalone="{1 idiv 0}">discard</xsl:result-document><xsl:catch><xsl:result-document href="` + principal + `">ok</xsl:result-document></xsl:catch></xsl:try>`, `string($r('` + principal + `')) eq 'ok'`, nameTrue},
		{"explicit rollback releases principal", `<xsl:try><xsl:result-document>discard<xsl:sequence select="error()"/></xsl:result-document><xsl:catch><xsl:result-document href="` + principal + `">ok</xsl:result-document></xsl:catch></xsl:try>`, `string($r('` + principal + `')) eq 'ok'`, nameTrue},
	}
}

func resultDocumentURIQuery(body, format, check string) string {
	source := sheet(version30, `<xsl:template name="start">`+body+`</xsl:template>`)
	return `let $r := transform(map{'stylesheet-text':'` + strings.ReplaceAll(source, "'", "''") + `','initial-template':QName('', 'start'),'base-output-uri':'https://output.invalid/base/main','delivery-format':'` + format + `'}) return ` + check
}

func TestXSLTResultDocumentURIs(t *testing.T) {
	e := engine(t, transform.Config{})
	for _, test := range resultDocumentURICases() {
		for _, format := range []string{"raw", "document", "serialized"} {
			t.Run(test.name+"/"+format, func(t *testing.T) {
				result, err := query(t, e, resultDocumentURIQuery(test.body, format, test.check), transform.XPath31).Evaluate(t.Context(), nil, transform.XPathContext{})
				got := ""
				if err != nil {
					var detail *transform.Error
					if !errors.As(err, &detail) {
						t.Fatal(err)
					}
					got = detail.Code
				} else {
					got = text(t, result)
				}
				if got != test.want {
					t.Fatalf("got %q (%v), want %q", got, err, test.want)
				}
			})
		}
		for _, version := range []string{version20, version30} {
			if version == version20 && (strings.Contains(test.body, "current-output-uri()") || strings.Contains(test.body, "<xsl:try")) {
				continue
			}
			for _, mode := range []transform.ResultMode{transform.ResultRaw, transform.ResultDocument} {
				source := sheet(version, `<xsl:template name="start">`+test.body+`</xsl:template>`)
				_, err := stylesheet(t, e, source).Execute(t.Context(), nil, transform.XSLTContext{Template: transform.Name{Local: nameStart}, ResultMode: mode, BaseOutputURI: "https://output.invalid/base/main"})
				if test.want == nameTrue {
					if err != nil {
						t.Fatal(test.name, version, mode, err)
					}
				} else {
					var detail *transform.Error
					if !errors.As(err, &detail) || detail.Code != test.want {
						t.Fatal(test.name, version, mode, err, test.want)
					}
				}
			}
		}
	}
}

func TestXSLTContextualKeywordOperands(t *testing.T) {
	e := engine(t, transform.Config{})
	doc, err := e.Parse(t.Context(), []byte(`<r><div>2</div></r>`))
	if err != nil {
		t.Fatal(err)
	}
	for _, processor := range []transform.XSLTVersion{transform.XSLT20, transform.XSLT30} {
		source := sheet(version10, `<xsl:template match="r"><xsl:value-of select="' 6 '*div"/></xsl:template>`)
		compiled, err := e.CompileXSLT(t.Context(), []byte(source), transform.XSLTOptions{ProcessorVersion: processor})
		if err != nil {
			t.Fatal(err)
		}
		result, err := compiled.Transform(t.Context(), doc, transform.XSLTContext{})
		if err != nil || string(result.Primary) != "12" {
			t.Fatal(processor, result, err)
		}
	}
}

func TestProcessorIdentityDuringCompilationAndExecution(t *testing.T) {
	e := engine(t, transform.Config{})

	doc, err := e.Parse(context.Background(), []byte(`<r/>`))
	if err != nil {
		t.Fatal(err)
	}

	program := stylesheet(t, e, sheet(version30, `<xsl:template match="/">
<xsl:value-of use-when="system-property('xsl:vendor') = 'xmlsec'"
select="concat(system-property('xsl:product-name'), '|', system-property('xsl:vendor-url'))"/>
</xsl:template>`))

	result, err := program.Transform(context.Background(), doc, transform.XSLTContext{})
	if err != nil {
		t.Fatal(err)
	}

	if got, want := string(result.Primary), "xmlsec|https://github.com/skarm/xmlsec"; got != want {
		t.Fatalf("processor identity=%q, want %q", got, want)
	}
}

func TestXSLTProfileResults(t *testing.T) {
	e := engine(t, transform.Config{})
	source := `<r><n category="b">3</n><n category="a">2</n><n category="b">4</n></r>`

	d, err := e.Parse(context.Background(), []byte(source))
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct{ name, version, body, want string }{
		{"grouping", version20, `<xsl:template match="/"><xsl:for-each-group select="r/n" group-by="@category"><xsl:sort select="current-grouping-key()"/><xsl:value-of select="current-grouping-key()"/><xsl:text>:</xsl:text><xsl:value-of select="sum(current-group())"/><xsl:text>;</xsl:text></xsl:for-each-group></xsl:template>`, "a:2;b:7;"},
		{"functions", version20, `<xsl:function name="local:square" xmlns:local="urn:local" as="xs:integer"><xsl:param name="n" as="xs:integer"/><xsl:sequence select="$n*$n"/></xsl:function><xsl:template match="/" xmlns:local="urn:local"><xsl:value-of select="sum(for $n in 1 to 4 return local:square($n))"/></xsl:template>`, "30"},
		{"iteration", version30, `<xsl:template match="/"><xsl:iterate select="1 to 5"><xsl:param name="sum" select="0"/><xsl:on-completion><xsl:value-of select="$sum"/></xsl:on-completion><xsl:next-iteration><xsl:with-param name="sum" select="$sum+."/></xsl:next-iteration></xsl:iterate></xsl:template>`, "15"},
		{"maps-and-arrays", version30, `<xsl:template match="/"><xsl:value-of select="map{'a':[1,2]}?a?2"/></xsl:template>`, "2"},
	}
	for _, c := range cases {
		t.Run(c.version+"/"+c.name, func(t *testing.T) {
			result, err := stylesheet(t, e, sheet(c.version, c.body)).Transform(context.Background(), d, transform.XSLTContext{})
			if err != nil {
				t.Fatal(err)
			}

			if got := string(result.Primary); got != c.want {
				t.Fatalf("expected %q, got %q", c.want, got)
			}
		})
	}
}

func TestXSLTFiniteDecimalDivisionPaths(t *testing.T) {
	e := engine(t, transform.Config{})

	for _, version := range []string{version20, version30} {
		source := sheet(version, `<xsl:template name="start"><xsl:variable name="n" select="1 div 999999999999999999"/><xsl:value-of select="$n eq xs:decimal(string($n))"/></xsl:template>`)

		result, err := stylesheet(t, e, source).Transform(t.Context(), nil, transform.XSLTContext{Template: transform.Name{Local: nameStart}})
		if err != nil || string(result.Primary) != nameTrue {
			t.Fatalf("XSLT %s: %v, %v", version, result, err)
		}

		expression := `transform(map{'stylesheet-text': $stylesheet, 'initial-template': QName('', 'start'), 'delivery-format': 'serialized'})?output`

		value, err := query(t, e, expression, transform.XPath31).Evaluate(t.Context(), nil, transform.XPathContext{Variables: transform.Bindings{{Local: variableStylesheet}: transform.Values(transform.String(source))}})
		if err != nil || text(t, value) != nameTrue {
			t.Fatalf("fn:transform %s: %v, %v", version, value, err)
		}
	}
}

func TestTransformDefaultProcessor(t *testing.T) {
	e := engine(t, transform.Config{})
	source := sheet(version10, `<xsl:template name="start"><xsl:sequence select="42"/></xsl:template>`)
	expression := `transform(map{'stylesheet-text': $stylesheet, 'initial-template': QName('', 'start'), 'delivery-format': 'raw'})?output`

	value, err := query(t, e, expression, transform.XPath31).Evaluate(t.Context(), nil, transform.XPathContext{Variables: transform.Bindings{{Local: variableStylesheet}: transform.Values(transform.String(source))}})
	if err != nil || text(t, value) != "42" {
		t.Fatal(value, err)
	}

	source = sheet(version30, `<xsl:function name="f:value" xmlns:f="urn:function"><xsl:param name="a"/><xsl:sequence select="$a"/></xsl:function>`)
	expression = `transform(map{'stylesheet-text': $stylesheet, 'initial-function': QName('urn:function', 'value')})`
	_, err = query(t, e, expression, transform.XPath31).Evaluate(t.Context(), nil, transform.XPathContext{Variables: transform.Bindings{{Local: variableStylesheet}: transform.Values(transform.String(source))}})

	var detail *transform.Error
	if !errors.As(err, &detail) || detail.Code != "FOXT0002" {
		t.Fatal("missing function-params", err)
	}
}

func TestXSLTDatatypeEditionPaths(t *testing.T) {
	for _, edition := range []transform.XMLSchemaVersion{transform.XMLSchema10, transform.XMLSchema11} {
		e := engine(t, transform.Config{XMLSchemaVersion: edition})

		for _, version := range []string{version20, version30} {
			for _, tc := range []struct{ body, modern, legacyCode string }{
				{`<xsl:value-of select="xs:double('+INF')"/>`, namePositiveInfinity, errCodeFORG0001},
				{`<xsl:variable name="n"><xsl:element name="out" namespace="####"/></xsl:variable><xsl:value-of select="namespace-uri($n/*)"/>`, "####", "XTDE0835"},
				{`<xsl:variable name="n"><out><xsl:attribute name="p:a" namespace="####"/></out></xsl:variable><xsl:value-of select="namespace-uri($n/*/@*)"/>`, "####", "XTDE0865"},
				{`<xsl:variable name="n" as="node()"><xsl:namespace name="p" select="'####'"/></xsl:variable><xsl:value-of select="$n"/>`, "####", "XTDE0905"},
				{`<xsl:variable name="n" as="node()"><xsl:namespace name="p" select="'%gg'"/></xsl:variable><xsl:value-of select="$n"/>`, "%gg", "XTDE0905"},
				{`<xsl:analyze-string select="'-'" regex="[a-z-x]"><xsl:matching-substring><xsl:value-of select="."/></xsl:matching-substring></xsl:analyze-string>`, "-", "XTDE1140"},
			} {
				source := sheet(version, `<xsl:template name="start">`+tc.body+`</xsl:template>`)
				compiled := stylesheet(t, e, source)

				out, err := compiled.Transform(t.Context(), nil, transform.XSLTContext{Template: transform.Name{Local: nameStart}})
				if edition == transform.XMLSchema10 {
					var detail *transform.Error
					if !errors.As(err, &detail) || detail.Code != tc.legacyCode {
						t.Fatal(edition, tc.body, out, err)
					}
				} else if err != nil || string(out.Primary) != tc.modern {
					t.Fatal(edition, tc.body, out, err)
				}

				q := query(t, e, `transform(map{'stylesheet-text':$stylesheet,'initial-template':QName('','start'),'delivery-format':'serialized'})?output`, transform.XPath31)

				value, err := q.Evaluate(t.Context(), nil, transform.XPathContext{Variables: transform.Bindings{{Local: variableStylesheet}: transform.Values(transform.String(source))}})
				if edition == transform.XMLSchema10 {
					var detail *transform.Error
					if !errors.As(err, &detail) || detail.Code != tc.legacyCode {
						t.Fatal(edition, "fn:transform", value, err)
					}
				} else if err != nil || text(t, value) != tc.modern {
					t.Fatal(edition, "fn:transform", value, err)
				}
			}

			for _, value := range []string{"relative/path", "urn:trailing:", "http://[::1]:80/path", "urn:two words", "urn:a\\b^c`d"} {
				source := sheet(version, `<xsl:template name="start"><xsl:variable name="n" as="node()"><xsl:namespace name="p" select="'`+value+`'"/></xsl:variable><xsl:value-of select="$n"/></xsl:template>`)
				for _, nested := range []bool{false, true} {
					got, err := resourceStylesheetResult(t, e, source, nested)
					if err != nil || got != value {
						t.Fatal(edition, value, nested, got, err)
					}
				}
			}
		}
	}
}

func TestXSLTTypeAvailabilityEditions(t *testing.T) {
	for _, edition := range []transform.XMLSchemaVersion{transform.XMLSchema10, transform.XMLSchema11} {
		e := engine(t, transform.Config{XMLSchemaVersion: edition})
		for _, version := range []string{version20, version30} {
			body := `<xsl:template name="start"><xsl:text use-when="type-available('xs:dateTimeStamp')">available:</xsl:text><xsl:text use-when="not(type-available('xs:dateTimeStamp'))">unavailable:</xsl:text><xsl:value-of select="type-available('xs:dateTimeStamp')"/></xsl:template>`
			want := "available:true"
			for _, nested := range []bool{false, true} {
				got, err := resourceStylesheetResult(t, e, sheet(version, body), nested)
				if err != nil || got != want {
					t.Fatal(edition, version, nested, got, err, want)
				}
			}
			body = `<xsl:template name="start"><xsl:text use-when="type-available('xs:numeric')">new:</xsl:text><xsl:text use-when="not(type-available('xs:numeric'))">old:</xsl:text><xsl:value-of select="type-available('xs:numeric'),function-available('xs:NMTOKENS',1)"/></xsl:template>`
			for _, nested := range []bool{false, true} {
				want := "new:true true"
				if version == version20 && !nested {
					want = "old:false false"
				}
				got, err := resourceStylesheetResult(t, e, sheet(version, body), nested)
				if err != nil || got != want {
					t.Fatal(edition, version, nested, got, err, want)
				}
			}
			body = `<xsl:param name="p" as="xs:numeric" select="1"/><xsl:template name="start"><xsl:value-of select="$p instance of xs:numeric"/></xsl:template>`
			for _, nested := range []bool{false, true} {
				got, err := resourceStylesheetResult(t, e, sheet(version, body), nested)
				if version == version20 && !nested {
					var detail *transform.Error
					if !errors.As(err, &detail) || detail.Code != "XPST0051" {
						t.Fatal(edition, version, nested, got, err)
					}
				} else if err != nil || got != nameTrue {
					t.Fatal(edition, version, nested, got, err)
				}
			}
		}
	}
}

func TestXSLTSystemPropertiesStaticAndDynamic(t *testing.T) {
	for _, edition := range []transform.XMLSchemaVersion{transform.XMLSchema10, transform.XMLSchema11} {
		e := engine(t, transform.Config{XMLSchemaVersion: edition})

		for _, processor := range []transform.XSLTVersion{transform.XSLT20, transform.XSLT30} {
			body := `<xsl:template name="start"><xsl:text use-when="system-property('xsl:is-schema-aware') = 'no'">basic:</xsl:text><xsl:text use-when="system-property('xsl:xsd-version') = '1.0'">old:</xsl:text><xsl:text use-when="system-property('xsl:xsd-version') = '1.1'">new:</xsl:text><xsl:value-of select="system-property('xsl:is-schema-aware'),system-property('xsl:xsd-version'),system-property('xsl:xpath-version')"/></xsl:template>`

			compiled, err := e.CompileXSLT(t.Context(), []byte(sheet(version20, body)), transform.XSLTOptions{ProcessorVersion: processor})
			if err != nil {
				t.Fatal(edition, processor, err)
			}

			out, err := compiled.Transform(t.Context(), nil, transform.XSLTContext{Template: transform.Name{Local: nameStart}})

			want := "basic:old:no 1.0 "
			if edition == transform.XMLSchema11 {
				want = "basic:new:no 1.1 "
			}

			want += map[transform.XSLTVersion]string{transform.XSLT20: version20, transform.XSLT30: "3.1"}[processor]
			if err != nil || string(out.Primary) != want {
				t.Fatal(edition, processor, out, err, want)
			}
		}
	}
}

func TestTransformRequestedCapabilities(t *testing.T) {
	e := engine(t, transform.Config{})
	for _, expression := range []string{
		`transform(map{'stylesheet-location':'urn:missing', 'requested-properties':map{QName('http://www.w3.org/1999/XSL/Transform','product-name'):'Xalan'}})`,
		`transform(map{'stylesheet-location':'urn:missing', 'requested-properties':map{QName('http://www.w3.org/1999/XSL/Transform','is-schema-aware'):true()}})`,
	} {
		_, err := query(t, e, expression, transform.XPath31).Evaluate(t.Context(), nil, transform.XPathContext{})

		var detail *transform.Error
		if !errors.As(err, &detail) || detail.Code != errCodeFOXT0001 {
			t.Fatal(expression, err)
		}
	}
}

func TestXSLT10ForwardsAttributesAreIgnored(t *testing.T) {
	e := engine(t, transform.Config{})
	ctx := context.Background()

	d, err := e.Parse(ctx, []byte(`<r/>`))
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct{ name, attrs, body, want string }{
		{"use-when", ``, `<xsl:text use-when="false()">kept</xsl:text>`, nameKept},
		{"expand-text", `expand-text="yes"`, `<xsl:text>{1+1}</xsl:text>`, "{1+1}"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			source := `<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="1.1" ` + tc.attrs + `><xsl:output method="text"/><xsl:template match="/">` + tc.body + `</xsl:template></xsl:stylesheet>`
			s := stylesheet(t, e, source)

			out, err := s.Transform(ctx, d, transform.XSLTContext{})
			if err != nil {
				t.Fatal(err)
			}

			if string(out.Primary) != tc.want {
				t.Fatalf("got %q, want %q", out.Primary, tc.want)
			}
		})
	}
}

func TestXSLT10RequiresSelect(t *testing.T) {
	e := engine(t, transform.Config{})
	for _, instruction := range []string{`<xsl:value-of/>`, `<xsl:value-of>text</xsl:value-of>`, `<xsl:value-of select=""/>`} {
		if _, err := e.CompileXSLT(context.Background(), []byte(xslt10(`<xsl:template match="/">`+instruction+`</xsl:template>`)), transform.XSLTOptions{}); err == nil {
			t.Errorf("accepted XSLT 1.0 value-of without a valid select: %s", instruction)
		}
	}
}

func TestXSLTLiteralExpandTextAttribute(t *testing.T) {
	e := engine(t, transform.Config{})

	d, err := e.Parse(context.Background(), []byte(`<r/>`))
	if err != nil {
		t.Fatal(err)
	}

	s := stylesheet(t, e, `<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="3.0"><xsl:output omit-xml-declaration="yes"/><xsl:template match="/"><out expand-text="yes">{1+1}</out></xsl:template></xsl:stylesheet>`)

	out, err := s.Transform(context.Background(), d, transform.XSLTContext{})
	if err != nil {
		t.Fatal(err)
	}

	if string(out.Primary) != `<out expand-text="yes">{1+1}</out>` {
		t.Fatalf("ordinary result attribute changed XSLT behavior: %s", out.Primary)
	}
}

func TestXSLT10ForwardsModulesPreserveSource(t *testing.T) {
	const module = `<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="1.1" expand-text="yes"><xsl:template name="module"><xsl:text use-when="false()">kept:</xsl:text><xsl:value-of select="document('')/*/@expand-text"/></xsl:template></xsl:stylesheet>`

	e := engine(t, transform.Config{Resolver: transform.ResolverFunc(func(context.Context, string) (io.ReadCloser, error) {
		return io.NopCloser(strings.NewReader(module)), nil
	})})
	ctx := context.Background()

	d, err := e.Parse(ctx, []byte(`<r/>`))
	if err != nil {
		t.Fatal(err)
	}

	for _, instruction := range []string{nameInclude, nameImport} {
		t.Run(instruction, func(t *testing.T) {
			source := `<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="1.1" expand-text="yes"><xsl:` + instruction + ` href="urn:module"/><xsl:output method="text"/><xsl:template match="/"><xsl:value-of select="document('')/*/@expand-text"/>:<xsl:call-template name="module"/></xsl:template></xsl:stylesheet>`
			s := stylesheet(t, e, source)

			out, err := s.Transform(ctx, d, transform.XSLTContext{})
			if err != nil {
				t.Fatal(err)
			}

			if string(out.Primary) != "yes:kept:yes" {
				t.Fatalf("source or forward semantics changed: %s", out.Primary)
			}
		})
	}
}

func TestXSLTSimplifiedExpandText(t *testing.T) {
	e := engine(t, transform.Config{})

	d, err := e.Parse(context.Background(), []byte(`<r/>`))
	if err != nil {
		t.Fatal(err)
	}

	s := stylesheet(t, e, `<out xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xsl:version="3.0" xsl:expand-text="yes">{1+1}</out>`)

	out, err := s.Transform(context.Background(), d, transform.XSLTContext{})
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Contains(out.Primary, []byte(`<out>2</out>`)) {
		t.Fatalf("simplified stylesheet ignored xsl:expand-text: %s", out.Primary)
	}
}

func TestXSLT10ForwardsUnknownOptionalValues(t *testing.T) {
	e := engine(t, transform.Config{})
	ctx := context.Background()

	d, err := e.Parse(ctx, []byte(`<r><n>2</n><n>1</n></r>`))
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct{ body, want string }{
		{`<xsl:text disable-output-escaping="future">kept</xsl:text>`, nameKept},
		{`<xsl:text disable-output-escaping="future" version="1.0">kept</xsl:text>`, nameKept},
		{`<xsl:text version="1.0" disable-output-escaping="future">kept</xsl:text>`, nameKept},
		{`<xsl:message terminate="future">message</xsl:message><xsl:text>kept</xsl:text>`, nameKept},
		{`<xsl:for-each select="r/n"><xsl:sort order="future"/><xsl:value-of select="."/></xsl:for-each>`, "12"},
		{`<xsl:for-each select="r/n"><xsl:sort order="{'future'}" case-order="{'future'}"/><xsl:value-of select="."/></xsl:for-each>`, "12"},
		{`<xsl:message terminate="{'future'}">message</xsl:message><xsl:text>kept</xsl:text>`, nameKept},
	} {
		source := strings.Replace(xslt10(`<xsl:template match="/">`+tc.body+`</xsl:template>`), `version="1.0"`, `version="1.1"`, 1)

		s, err := e.CompileXSLT(ctx, []byte(source), transform.XSLTOptions{})
		if err != nil {
			t.Errorf("optional future value was not ignored: %v", err)
			continue
		}

		out, err := s.Transform(ctx, d, transform.XSLTContext{})
		if err != nil || out == nil || string(out.Primary) != tc.want {
			t.Errorf("got %v, %v; want %q", out, err, tc.want)
		}
	}
}

func TestXSLT10RejectsNonFiniteNestedVersion(t *testing.T) {
	e := engine(t, transform.Config{})

	for _, version := range []string{valueNaN, nameInfinity, namePositiveInfinity} {
		source := xslt10(`<xsl:template match="/"><out xsl:version="` + version + `">text</out></xsl:template>`)
		if _, err := e.CompileXSLT(context.Background(), []byte(source), transform.XSLTOptions{}); err == nil {
			t.Errorf("accepted non-finite XSLT version: %s", version)
		}
	}
}

func TestXSLTForwardsRecoveryKeepsStrictValidation(t *testing.T) {
	e := engine(t, transform.Config{})
	ctx := context.Background()

	d, err := e.Parse(ctx, []byte(`<r><n>1</n></r>`))
	if err != nil {
		t.Fatal(err)
	}

	for _, version := range []string{version10, version20, version30} {
		source := sheet(version, `<xsl:template match="/"><xsl:for-each select="r/n"><xsl:sort order="{'future'}"/><xsl:value-of select="."/></xsl:for-each></xsl:template>`)

		s, err := e.CompileXSLT(ctx, []byte(source), transform.XSLTOptions{})
		if err == nil {
			_, err = s.Transform(ctx, d, transform.XSLTContext{})
		}

		if err == nil {
			t.Errorf("strict %s accepted an invalid order", version)
		}
	}

	source := strings.Replace(xslt10(`<xsl:template match="/"><out xsl:version="1.0"><xsl:text disable-output-escaping="future">text</xsl:text></out></xsl:template>`), `version="1.0"`, `version="1.1"`, 1)
	if _, err := e.CompileXSLT(ctx, []byte(source), transform.XSLTOptions{}); err == nil {
		t.Fatal("nested xsl:version=1.0 did not disable forwards recovery")
	}
}

// XMLDSig hashes the serialized XSLT output. Reusing one compiled stylesheet
// must not randomly reorder its literal element's namespace declarations.
func TestXSLTLiteralNamespaceSerializationStable(t *testing.T) {
	e := engine(t, transform.Config{})
	s := stylesheet(t, e, `<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:a="urn:a" xmlns:b="urn:b" xmlns:c="urn:c" version="1.0"><xsl:output omit-xml-declaration="yes"/><xsl:template match="/"><a:out><b:value c:id="x"/></a:out></xsl:template></xsl:stylesheet>`)

	d, err := e.Parse(t.Context(), []byte(`<r/>`))
	if err != nil {
		t.Fatal(err)
	}

	var first []byte

	for i := range 100 {
		out, err := s.Transform(t.Context(), d, transform.XSLTContext{})
		if err != nil {
			t.Fatal(err)
		}

		if i == 0 {
			first = out.Primary
		} else if !bytes.Equal(out.Primary, first) {
			t.Fatalf("unstable XSLT bytes: %q != %q", out.Primary, first)
		}
	}
}

type messageContractCase struct{ name, body, want string }

func messageContractCases() []messageContractCase {
	const catch = `<xsl:catch xmlns:err="http://www.w3.org/2005/xqt-errors"><xsl:value-of select="namespace-uri-from-QName($err:code)||':'||local-name-from-QName($err:code)"/></xsl:catch>`
	tests := make([]messageContractCase, 0, 23)
	for _, term := range []string{"yes", "true", "1", " 1 ", "{'true'}"} {
		tests = append(tests, messageContractCase{"terminate " + term, `<xsl:try><xsl:message terminate="` + term + `">stop</xsl:message><xsl:text>after</xsl:text>` + catch + `</xsl:try>`, namespaceErrors + ":XTMM9000"})
	}
	for _, term := range []string{"no", "false", "0", " 0 ", "{'false'}"} {
		tests = append(tests, messageContractCase{"continue " + term, `<xsl:message terminate="` + term + `">keep</xsl:message><xsl:text>after</xsl:text>`, "after"})
	}
	for _, test := range []struct{ name, attributes, body, assertion string }{
		{"empty document", ``, ``, `$err:value instance of document-node() and empty($err:value/node())`},
		{"combined sequence", ` select="(1,2)"`, `<xsl:sequence select="3"/><a/>tail`, `$err:value instance of document-node() and string($err:value) eq '1 2 3tail' and count($err:value/node()) eq 3 and exists($err:value/a)`},
		{"interleaved body", ``, `<xsl:sequence select="1"/><a/><xsl:sequence select="2"/>`, `$err:value instance of document-node() and string($err:value) eq '12' and count($err:value/node()) eq 3 and exists($err:value/a)`},
		{"XML text", ` select="'a &amp; b &lt; c'"`, ``, `$err:value instance of document-node() and string($err:value) eq 'a &amp; b &lt; c' and count($err:value/node()) eq 1`},
		{"array flattening", ` select="[1,[2]]"`, ``, `$err:value instance of document-node() and string($err:value) eq '1 2'`},
	} {
		message := `<xsl:message terminate="yes"` + test.attributes + `>` + test.body + `</xsl:message>`
		tests = append(tests, messageContractCase{test.name, `<xsl:try>` + message + `<xsl:catch xmlns:err="http://www.w3.org/2005/xqt-errors"><xsl:value-of select="` + test.assertion + `"/></xsl:catch></xsl:try>`, nameTrue})
	}
	for _, code := range []string{"p:FAIL", "Q{{urn:message}}FAIL", "missing:FAIL", "not a QName"} {
		want := "urn:message:FAIL"
		if code == "not a QName" {
			want = namespaceErrors + ":XTMM9000"
		}
		if code == "missing:FAIL" {
			want = errCodeXTSE0280
		}
		tests = append(tests, messageContractCase{"error code " + code, `<xsl:try><xsl:message xmlns:p="urn:message" terminate="yes" error-code="` + code + `"/>` + catch + `</xsl:try>`, want})
	}
	tests = append(tests, messageContractCase{"invalid dynamic terminate", `<xsl:try><xsl:message terminate="{'bad'}"/>` + catch + `</xsl:try>`, namespaceErrors + ":XTDE0030"})
	tests = append(tests, messageContractCase{"HTML message content", `<xsl:message><html><body>message<td nowrap="nowrap"/></body></html></xsl:message><xsl:text>after</xsl:text>`, "after"})
	tests = append(tests, messageContractCase{"content error recovery", `<xsl:message select="1 idiv 0"/><xsl:text>after</xsl:text>`, "after"})
	tests = append(tests, messageContractCase{"catch local namespace", `<xsl:try><xsl:message xmlns:p="urn:message" error-code="p:FAIL" terminate="yes"/><xsl:catch xmlns:e="urn:message" xmlns:err="http://www.w3.org/2005/xqt-errors" errors="e:*" select="namespace-uri-from-QName($err:code)||':'||local-name-from-QName($err:code)"/></xsl:try>`, "urn:message:FAIL"})

	return tests
}

func TestMessageContracts(t *testing.T) {
	e := engine(t, transform.Config{})
	for _, test := range messageContractCases() {
		t.Run(test.name, func(t *testing.T) {
			source := sheet(version30, `<xsl:template name="start">`+test.body+`</xsl:template>`)
			for _, nested := range []bool{false, true} {
				got, err := resourceStylesheetResult(t, e, source, nested)
				if comparisonErrorCode(test.want) {
					var detail *transform.Error
					if !errors.As(err, &detail) || detail.Code != test.want {
						t.Fatal(nested, got, err, test.want)
					}
				} else if err != nil || got != test.want {
					t.Fatal(nested, got, err, test.want)
				}
			}
		})
	}
	for _, value := range []string{"", "maybe", "\u00a0yes", "yes\u00a0"} {
		_, err := e.CompileXSLT(t.Context(), []byte(sheet(version30, `<xsl:template name="start"><xsl:message terminate="`+value+`"/></xsl:template>`)), transform.XSLTOptions{})
		var detail *transform.Error
		if !errors.As(err, &detail) || detail.Code != "XTSE0020" {
			t.Fatal(value, err)
		}
	}
}

func TestMessageDiagnosticsOnFailure(t *testing.T) {
	e := engine(t, transform.Config{})
	for _, failure := range []string{`<xsl:message terminate="true"><stop/></xsl:message>`, `<xsl:sequence select="1 idiv 0"/>`} {
		compiled := stylesheet(t, e, sheet(version30, `<xsl:template name="start"><xsl:message>before &amp; after</xsl:message>`+failure+`</xsl:template>`))
		for range 2 {
			result, err := compiled.Execute(t.Context(), nil, transform.XSLTContext{Template: transform.Name{Local: nameStart}})
			var detail *transform.Error
			if result != nil || !errors.As(err, &detail) {
				t.Fatal(result, err)
			}
			messages := detail.Messages()
			want := 1
			if detail.Code == "XTMM9000" {
				want = 2
			}
			if len(messages) != want || messages[0].Text != "before &amp; after" {
				t.Fatal(messages, err)
			}
			if want == 2 && (!messages[1].Terminate || messages[1].Text != `<stop xmlns:xs="http://www.w3.org/2001/XMLSchema"/>`) {
				t.Fatal(messages)
			}
			messages[0].Text = "changed"
			if detail.Messages()[0].Text != "before &amp; after" {
				t.Fatal("messages alias caller slice")
			}
		}
	}
	var empty *transform.Error
	if empty.Messages() != nil {
		t.Fatal(empty.Messages())
	}
}

func sourceLineStylesheet(ending string) string {
	source := `<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:err="http://www.w3.org/2005/xqt-errors" version="3.0">
<xsl:output method="text"/>
<!-- first
     second -->
<xsl:template name="start">
  <xsl:try>
    <xsl:sequence
       select="1 idiv 0"/>
    <xsl:catch><xsl:value-of select="$err:line-number"/></xsl:catch>
  </xsl:try>
</xsl:template>
</xsl:stylesheet>`
	return strings.ReplaceAll(source, "\n", ending)
}

func TestXSLTErrorSourceLines(t *testing.T) {
	e := engine(t, transform.Config{})
	for _, ending := range []string{"\n", "\r\n", "\r"} {
		for _, nested := range []bool{false, true} {
			got, err := resourceStylesheetResult(t, e, sourceLineStylesheet(ending), nested)
			if err != nil || got != "7" {
				t.Fatal(ending, nested, got, err)
			}
		}
	}
}

func TestXSLTKeyCycleRecovery(t *testing.T) {
	e := engine(t, transform.Config{})
	source := sheet(version30, `<xsl:output method="text"/><xsl:key name="cycle" match="n" use="key('cycle',@k)"/><xsl:key name="ok" match="n" use="@k"/><xsl:template name="start"><xsl:variable name="d" select="parse-xml('&lt;r>&lt;n k=&quot;a&quot;/>&lt;/r>')"/><xsl:for-each select="1 to 2"><xsl:try><xsl:value-of select="count(key('cycle','a',$d))"/><xsl:catch errors="err:XTDE0640" xmlns:err="http://www.w3.org/2005/xqt-errors">cycle;</xsl:catch></xsl:try></xsl:for-each><xsl:value-of select="count(key('ok','a',$d))"/></xsl:template>`)
	for _, nested := range []bool{false, true} {
		got, err := resourceStylesheetResult(t, e, source, nested)
		if err != nil || got != "cycle;cycle;1" {
			t.Fatal(nested, got, err)
		}
	}
}

func currentOutputURICases() []struct{ expression, want string } {
	return []struct{ expression, want string }{
		{`exists(current-output-uri())`, nameTrue},
		{`empty($global-select) and string($global-body) eq '' and empty($parameter)`, nameTrue},
		{`empty(current-output-uri#0())`, nameTrue},
		{`empty(function-lookup(QName('http://www.w3.org/2005/xpath-functions','current-output-uri'),0)())`, nameTrue},
		{`(function(){empty(current-output-uri())})()`, nameTrue},
		{`for-each(1,function($n){empty(current-output-uri())})`, nameTrue},
		{`apply(current-output-uri#0,[]) => empty()`, nameTrue},
		{`exists((function(){'ignored'})()) and exists(current-output-uri())`, nameTrue},
		{`let $s := '<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="3.0"><xsl:output method="text"/><xsl:template name="start"><xsl:value-of select="exists(current-output-uri())"/></xsl:template></xsl:stylesheet>' return (function(){transform(map{'stylesheet-text':$s,'initial-template':QName('', 'start'),'base-output-uri':'https://output.invalid/inner','delivery-format':'serialized'})('https://output.invalid/inner')})()`, nameTrue},
	}
}

func currentOutputURIStylesheet(expression string) string {
	var escaped strings.Builder
	_ = xml.EscapeText(&escaped, []byte(expression))
	return sheet(version30, `<xsl:output method="text"/><xsl:variable name="global-select" select="current-output-uri()"/><xsl:variable name="global-body"><xsl:value-of select="current-output-uri()"/></xsl:variable><xsl:param name="parameter" select="current-output-uri()"/><xsl:template name="start"><xsl:variable name="local"><xsl:value-of select="`+escaped.String()+`"/></xsl:variable><xsl:value-of select="$local"/></xsl:template>`)
}

func TestXSLTDynamicCurrentOutputURI(t *testing.T) {
	e := engine(t, transform.Config{})
	for _, test := range currentOutputURICases() {
		source := currentOutputURIStylesheet(test.expression)
		result, err := stylesheet(t, e, source).Execute(t.Context(), nil, transform.XSLTContext{Template: transform.Name{Local: nameStart}, BaseOutputURI: "https://output.invalid/main"})
		if err != nil || text(t, result.Primary()) != test.want {
			t.Fatal(test.expression, result, err)
		}
		values, err := query(t, e, `transform(map{'stylesheet-text':$stylesheet,'initial-template':QName('', 'start'),'base-output-uri':'https://output.invalid/main','delivery-format':'serialized'})('https://output.invalid/main')`, transform.XPath31).Evaluate(t.Context(), nil, transform.XPathContext{Variables: transform.Bindings{{Local: variableStylesheet}: transform.Values(transform.String(source))}})
		if err != nil || text(t, values) != test.want {
			t.Fatal("nested", test.expression, values, err)
		}
	}
}

func dynamicHostContextCases() []struct{ name, declarations, body, want string } {
	return []struct{ name, declarations, body, want string }{
		{"key establishes group", `<xsl:key name="k" match="n"><xsl:for-each-group select="(1,1)" group-by="."><xsl:sequence select="count(current-group())"/></xsl:for-each-group></xsl:key>`, `<xsl:value-of select="(function(){count(key('k',2,parse-xml('&lt;r>&lt;n/>&lt;/r>')))})()"/>`, "1"},
		{"function establishes group", `<xsl:function name="Q{urn:context}group"><xsl:for-each-group select="(1,1)" group-by="."><xsl:sequence select="count(current-group())"/></xsl:for-each-group></xsl:function>`, `<xsl:value-of select="Q{urn:context}group#0()"/>`, "2"},
		{"function establishes regex", `<xsl:function name="Q{urn:context}regex"><xsl:analyze-string select="'A'" regex="(A)"><xsl:matching-substring><xsl:sequence select="regex-group(1)"/></xsl:matching-substring></xsl:analyze-string></xsl:function>`, `<xsl:value-of select="Q{urn:context}regex#0()"/>`, "A"},
		{"function establishes merge", `<xsl:function name="Q{urn:context}merge"><xsl:merge><xsl:merge-source select="1"><xsl:merge-key select="."/></xsl:merge-source><xsl:merge-action><xsl:sequence select="current-merge-key()"/></xsl:merge-action></xsl:merge></xsl:function>`, `<xsl:value-of select="Q{urn:context}merge#0()"/>`, "1"},
		{"key group", `<xsl:key name="k" match="n" use="current-group()"/>`, `<xsl:for-each-group select="(1,1)" group-by="."><xsl:try><xsl:value-of select="count(key('k',1,parse-xml('&lt;r>&lt;n/>&lt;/r>')))"/><xsl:catch><xsl:value-of xmlns:err="http://www.w3.org/2005/xqt-errors" select="local-name-from-QName($err:code)"/>:</xsl:catch></xsl:try><xsl:value-of select="count(current-group())"/></xsl:for-each-group>`, "XTDE1061:2"},
		{"key grouping key", `<xsl:key name="k" match="n" use="current-grouping-key()"/>`, `<xsl:for-each-group select="1" group-by="."><xsl:try><xsl:value-of select="count(key('k',1,parse-xml('&lt;r>&lt;n/>&lt;/r>')))"/><xsl:catch><xsl:value-of xmlns:err="http://www.w3.org/2005/xqt-errors" select="local-name-from-QName($err:code)"/>:</xsl:catch></xsl:try><xsl:value-of select="current-grouping-key()"/></xsl:for-each-group>`, "XTDE1071:1"},
		{"key regex group", `<xsl:key name="k" match="n" use="regex-group(1)"/>`, `<xsl:analyze-string select="'A'" regex="(A)"><xsl:matching-substring><xsl:value-of select="count(key('k','',parse-xml('&lt;r>&lt;n/>&lt;/r>')))"/><xsl:value-of select="regex-group(1)"/></xsl:matching-substring></xsl:analyze-string>`, "1A"},
		{"group", "", `<xsl:for-each-group select="(1,1)" group-by="."><xsl:try><xsl:sequence select="(function(){current-group()})()"/><xsl:catch><xsl:value-of xmlns:err="http://www.w3.org/2005/xqt-errors" select="local-name-from-QName($err:code)"/>:</xsl:catch></xsl:try><xsl:value-of select="count(current-group())"/></xsl:for-each-group>`, "XTDE1061:2"},
		{"grouping key", "", `<xsl:for-each-group select="1" group-by="."><xsl:try><xsl:sequence select="for-each(1,function($n){current-grouping-key()})"/><xsl:catch><xsl:value-of xmlns:err="http://www.w3.org/2005/xqt-errors" select="local-name-from-QName($err:code)"/>:</xsl:catch></xsl:try><xsl:value-of select="current-grouping-key()"/></xsl:for-each-group>`, "XTDE1071:1"},
		{"regex group", "", `<xsl:analyze-string select="'A'" regex="(A)"><xsl:matching-substring><xsl:value-of select="(function(){regex-group(1)})()"/><xsl:value-of select="regex-group(1)"/></xsl:matching-substring></xsl:analyze-string>`, "A"},
		{"merge group", "", `<xsl:merge><xsl:merge-source select="1"><xsl:merge-key select="."/></xsl:merge-source><xsl:merge-action><xsl:try><xsl:sequence select="current-merge-group#0()"/><xsl:catch><xsl:value-of xmlns:err="http://www.w3.org/2005/xqt-errors" select="local-name-from-QName($err:code)"/>:</xsl:catch></xsl:try><xsl:value-of select="count(current-merge-group())"/></xsl:merge-action></xsl:merge>`, "XTDE3480:1"},
		{"merge key", "", `<xsl:merge><xsl:merge-source select="1"><xsl:merge-key select="."/></xsl:merge-source><xsl:merge-action><xsl:try><xsl:sequence select="(function(){current-merge-key()})()"/><xsl:catch><xsl:value-of xmlns:err="http://www.w3.org/2005/xqt-errors" select="local-name-from-QName($err:code)"/>:</xsl:catch></xsl:try><xsl:value-of select="current-merge-key()"/></xsl:merge-action></xsl:merge>`, "XTDE3510:1"},
	}
}

func TestXSLTDynamicHostContext(t *testing.T) {
	e := engine(t, transform.Config{})
	for _, test := range dynamicHostContextCases() {
		for _, nested := range []bool{false, true} {
			got, err := resourceStylesheetResult(t, e, sheet(version30, test.declarations+`<xsl:template name="start">`+test.body+`</xsl:template>`), nested)
			if err != nil || got != test.want {
				t.Fatal(test.name, nested, got, err)
			}
		}
	}
}

func TestMessageBudgets(t *testing.T) {
	for _, limits := range []transform.Limits{{MaxOutputBytes: 256}, {MaxOperations: 32}} {
		e := engine(t, transform.Config{Limits: limits})
		source := sheet(version30, `<xsl:template name="start"><xsl:message select="string-join((1 to 1000) ! '&amp;','')"/><xsl:text>after</xsl:text></xsl:template>`)
		result, err := stylesheet(t, e, source).Execute(t.Context(), nil, transform.XSLTContext{Template: transform.Name{Local: nameStart}})
		if result != nil || !errors.Is(err, transform.ErrLimit) {
			t.Fatal(limits, result, err)
		}
	}
}

func TestMessageHTMLContent(t *testing.T) {
	e := engine(t, transform.Config{})
	source := sheet("8.5", `<xsl:template name="start"><out><xsl:message>text</xsl:message><xsl:message><html><body>An HTML message <td nowrap="nowrap"/>.</body></html></xsl:message><xsl:message terminate="yes">done</xsl:message></out></xsl:template>`)
	compiled, err := e.CompileXSLT(t.Context(), []byte(source), transform.XSLTOptions{ProcessorVersion: transform.XSLT30})
	if err != nil {
		t.Fatal(err)
	}
	result, err := compiled.Execute(t.Context(), nil, transform.XSLTContext{Template: transform.Name{Local: nameStart}})
	var detail *transform.Error
	if result != nil || !errors.As(err, &detail) || detail.Code != "XTMM9000" || len(detail.Messages()) != 3 {
		t.Fatal(result, err)
	}
}

type parameterContractCase struct{ name, global, param, call, check, code20, code30 string }

func parameterContractCases() []parameterContractCase {
	return []parameterContractCase{
		{"forward XPath syntax error", `<xsl:template name="unused" version="17.0"><xsl:value-of select="1 +"/></xsl:template>`, ``, ``, `true()`, "XPST0003", "XPST0003"},
		{"forward XPath missing function", `<xsl:template name="unused" version="17.0"><xsl:value-of select="missing()"/></xsl:template>`, ``, ``, `true()`, "XPST0017", "XPST0017"},
		{"forward XPath unbound prefix", `<xsl:template name="unused" version="17.0"><xsl:value-of select="p:value"/></xsl:template>`, ``, ``, `true()`, "XPST0081", "XPST0081"},
		{"forward unused missing template", `<xsl:template name="unused" version="17.0"><xsl:call-template name="missing"/></xsl:template>`, ``, ``, `true()`, "XTSE0650", "XTSE0650"},
		{"forward evaluated missing template", ``, ``, `<xsl:call-template version="17.0" name="missing"/>`, `true()`, "XTSE0650", "XTSE0650"},
		{"forward conditional missing template", ``, ``, `<xsl:if version="17.0" test="false()"><xsl:call-template name="missing"/></xsl:if>`, `true()`, "XTSE0650", "XTSE0650"},
		{"global default", `<xsl:param name="p" as="xs:integer" select="3.5"/>`, ``, ``, `$p`, "XTTE0600", "XTTE0590"},
		{"global implicit mandatory", `<xsl:param name="p" as="xs:integer"/>`, ``, ``, `true()`, "XTDE0610", "XTDE0050"},
		{"global variable select and preserved body", `<xsl:variable name="p" select="1" xml:space="preserve"> </xsl:variable>`, ``, ``, `$p`, "XTSE0620", "XTSE0620"},
		{"global select and body", `<xsl:param name="p" select="1"><xsl:text>ignored</xsl:text></xsl:param>`, ``, ``, `$p`, "XTSE0620", "XTSE0620"},
		{"named select and body", ``, `<xsl:param name="p" select="1"><xsl:text>ignored</xsl:text></xsl:param>`, ``, `$p`, "XTSE0620", "XTSE0620"},
		{"global unbound name prefix", `<xsl:param name="missing:p" select="1"/>`, ``, ``, `true()`, "XTSE0280", "XTSE0280"},
		{"named unbound name prefix", ``, `<xsl:param name="missing:p" select="1"/>`, ``, `true()`, "XTSE0280", "XTSE0280"},
		{"global variable unbound name prefix", `<xsl:variable name="missing:p" select="1"/>`, ``, ``, `true()`, "XTSE0280", "XTSE0280"},
		{"local variable unbound name prefix", ``, ``, `<xsl:variable name="missing:p" select="1"/>`, `true()`, "XTSE0280", "XTSE0280"},
		{"with parameter unbound name prefix", ``, ``, `<xsl:call-template name="target"><xsl:with-param name="missing:p" select="1"/></xsl:call-template>`, `true()`, "XTSE0280", "XTSE0280"},
		{"local variable invalid name", ``, ``, `<xsl:variable name="bad:name:twice" select="1"/>`, `true()`, "XTSE0020", "XTSE0020"},
		{"with parameter invalid name", ``, ``, `<xsl:call-template name="target"><xsl:with-param name="bad:name:twice" select="1"/></xsl:call-template>`, `true()`, "XTSE0020", "XTSE0020"},
		{"local nonstatic parameter", ``, `<xsl:param name="p" static="no" select="1"/>`, ``, `$p eq 1`, "XTSE0090", ""},
		{"local nonstatic variable", ``, `<xsl:variable name="p" static="no" select="1"/>`, ``, `$p eq 1`, "XTSE0090", ""},
		{"local static parameter", ``, `<xsl:param name="p" static="yes" select="1"/>`, ``, `$p`, "XTSE0090", "XTSE0020"},
		{"local static variable", ``, ``, `<xsl:variable name="p" static="yes" select="1"/>`, `true()`, "XTSE0090", "XTSE0020"},
		{"named default", ``, `<xsl:param name="p" as="xs:integer" select="3.5"/>`, ``, `$p`, "XTTE0600", "XTTE0590"},
		{"node default", ``, `<xsl:param name="p" as="xs:integer" select="3.5"/>`, `<xsl:variable name="source"><r/></xsl:variable><xsl:apply-templates select="$source/r"/>`, `$p`, "XTTE0600", "XTTE0590"},
		{"named implicit mandatory", ``, `<xsl:param name="p" as="xs:integer"/>`, ``, `$p`, "XTDE0610", "XTDE0700"},
		{"node implicit mandatory", ``, `<xsl:param name="p" as="xs:integer"/>`, `<xsl:variable name="source"><r/></xsl:variable><xsl:apply-templates select="$source/r"/>`, `$p`, "XTDE0610", "XTDE0700"},
		{"empty explicit default", ``, `<xsl:param name="p" as="xs:integer" select="()"/>`, ``, `$p`, "XTTE0600", "XTTE0590"},
		{"empty supplied value", ``, `<xsl:param name="p" as="xs:integer" select="1"/>`, `<xsl:call-template name="target"><xsl:with-param name="p" select="()"/></xsl:call-template>`, `$p`, "XTTE0590", "XTTE0590"},
		{"empty optional default", ``, `<xsl:param name="p" as="xs:integer?"/>`, ``, `empty($p)`, "", ""},
		{"default string", ``, `<xsl:param name="p"/>`, ``, `exists($p) and $p instance of xs:string and $p eq ''`, "", ""},
		{"default document", ``, `<xsl:param name="p"><n/></xsl:param>`, ``, `$p instance of document-node() and exists($p/n)`, "", ""},
		{"declaration type namespace", ``, `<xsl:param xmlns:a="http://www.w3.org/2001/XMLSchema" name="p" as="a:integer" select="1"/>`, ``, `$p eq 1`, "", ""},
		{"default type namespace", ``, `<xsl:param name="p" as="element(n)" xpath-default-namespace="urn:local"><n xmlns="urn:local"/></xsl:param>`, ``, `local-name($p) eq 'n' and namespace-uri($p) eq 'urn:local'`, "", ""},
		{"unused invalid default", ``, `<xsl:param name="p" as="xs:integer" select="3.5"/>`, `<xsl:call-template name="target"><xsl:with-param name="p" select="1"/></xsl:call-template>`, `$p eq 1`, "", ""},
	}
}

func parameterContractSheet(version string, test parameterContractCase) string {
	call := test.call
	if call == "" {
		call = `<xsl:call-template name="target"/>`
	}
	source := sheet(version, test.global+`<xsl:template name="start">`+call+`</xsl:template><xsl:template name="target" match="r">`+test.param+`<xsl:value-of select="`+test.check+`"/></xsl:template>`)
	if test.name == "declaration type namespace" {
		source = strings.Replace(source, `<xsl:stylesheet `, `<xsl:stylesheet xmlns:a="urn:wrong" `, 1)
	}
	return source
}

func fractionalSecondsCases() []struct{ value, picture, old, modern string } {
	return []struct{ value, picture, old, modern string }{
		{"06.456", "[s].[f,2-2]", "06.46", "06.45"},
		{"06.445", "[s].[f,2-2]", "06.44", "06.44"},
		{"06.455", "[s].[f,2-2]", "06.46", "06.45"},
		{"06.995", "[s].[f,2-2]", "06.00", "06.99"},
		{"06.999", "[s].[f,2-2]", "06.00", "06.99"},
		{"06.4567", "[f,3]", "4567", "456"},
		{"06.4567", "[f001,1-*]", "4567", "4567"},
		{"06.4", "[f001,1-1]", "4", "400"},
		{"06.456", "[f,12-12]", "456000000000", "456000000000"},
	}
}

func fractionalSecondsSheet(version, value, picture string) string {
	return sheet(version, `<xsl:template name="start"><xsl:value-of select="format-time(xs:time('09:15:`+value+`'), '`+picture+`')"/></xsl:template>`)
}

func TestVersionedFractionalSeconds(t *testing.T) {
	e := engine(t, transform.Config{})
	for _, version := range []string{version20, version30} {
		for _, test := range fractionalSecondsCases() {
			for _, nested := range []bool{false, true} {
				want := test.modern
				if version == version20 && !nested {
					want = test.old
				}
				// fn:transform selects a 3.0 processor, independently of a 2.0
				// module declaration (its xslt-version option requests a minimum).
				got, err := resourceStylesheetResult(t, e, fractionalSecondsSheet(version, test.value, test.picture), nested)
				if err != nil || got != want {
					t.Fatal(version, test, nested, got, err, want)
				}
			}
		}
		for _, picture := range []string{"[f,0]", "[f,3-1]", "[f,]", "[f,1x]", "[f,+1]", "[f,-1]", "[f,1-]", "[f,1-2-3]"} {
			_, err := resourceStylesheetResult(t, e, fractionalSecondsSheet(version, "06.456", picture), false)
			code := "FOFD1340"

			if version == version20 {
				code = "XTDE1340"
			}

			var detail *transform.Error
			if !errors.As(err, &detail) || detail.Code != code {
				t.Fatal(version, picture, err, code)
			}
		}
	}
}

func TestXPathFractionalSecondsEditions(t *testing.T) {
	e := engine(t, transform.Config{})
	for _, test := range fractionalSecondsCases() {
		for _, call := range []string{"format-time", "(format-time#2)", "function-lookup(QName('http://www.w3.org/2005/xpath-functions','format-time'),2)"} {
			for _, version := range []transform.XPathVersion{transform.XPath30, transform.XPath31} {
				want := test.modern
				if version == transform.XPath30 {
					want = test.old
				}

				expression := call + `(xs:time('12:13:` + test.value + `'),'` + test.picture + `')`
				compiled, err := e.CompileXPath(t.Context(), expression, transform.XPathOptions{Version: version})
				if err != nil {
					t.Fatal(version, expression, err)
				}

				result, err := compiled.Evaluate(t.Context(), nil, transform.XPathContext{})
				if err != nil {
					t.Fatal(version, expression, err)
				}

				got, err := result.Text()
				if err != nil || got != want {
					t.Fatal(version, expression, got, want, err)
				}
			}
		}
	}
}

func TestXPathFormattingLanguageFallback(t *testing.T) {
	e := engine(t, transform.Config{})
	for _, test := range []struct{ name, function, arity, arguments, want string }{
		{"integer unsupported", "format-integer", "3", `1,'w','zz'`, "eins"},
		{"integer invalid", "format-integer", "3", `1,'w','not a language'`, "eins"},
		{"integer empty", "format-integer", "3", `1,'w',''`, "eins"},
		{"integer omitted", "format-integer", "2", `1,'w'`, "eins"},
		{"integer recognized", "format-integer", "3", `1,'w','fr'`, "un"},
		{"date unsupported", "format-date", "5", `xs:date('2000-01-01'),'[MNn]','zz',(),()`, "[Language: de]Januar"},
		{"date invalid", "format-date", "5", `xs:date('2000-01-01'),'[MNn]','not a language',(),()`, "[Language: de]Januar"},
		{"date empty", "format-date", "5", `xs:date('2000-01-01'),'[MNn]','',(),()`, "[Language: de]Januar"},
		{"date recognized", "format-date", "5", `xs:date('2000-01-01'),'[MNn]','DE',(),()`, "Januar"},
	} {
		t.Run(test.name, func(t *testing.T) {
			for _, version := range []transform.XPathVersion{transform.XPath30, transform.XPath31} {
				for _, call := range []string{test.function, "(" + test.function + "#" + test.arity + ")", "function-lookup(QName('http://www.w3.org/2005/xpath-functions','" + test.function + "')," + test.arity + ")"} {
					compiled, err := e.CompileXPath(t.Context(), call+"("+test.arguments+")", transform.XPathOptions{Version: version})
					if err != nil {
						t.Fatal(version, call, err)
					}

					result, err := compiled.Evaluate(t.Context(), nil, transform.XPathContext{Context: transform.DynamicContext{DefaultLanguage: "de"}})
					if err != nil {
						t.Fatal(version, call, err)
					}

					got, err := result.Text()
					if err != nil || got != test.want {
						t.Fatal(version, call, got, test.want, err)
					}
				}

				producer, err := e.CompileXPath(t.Context(), test.function+"#"+test.arity, transform.XPathOptions{Version: version})
				if err != nil {
					t.Fatal(err)
				}

				callable, err := producer.Evaluate(t.Context(), nil, transform.XPathContext{Context: transform.DynamicContext{DefaultLanguage: "de"}})
				if err != nil {
					t.Fatal(err)
				}

				consumer, err := e.CompileXPath(t.Context(), "$f("+test.arguments+")", transform.XPathOptions{Version: version})
				if err != nil {
					t.Fatal(err)
				}

				result, err := consumer.Evaluate(t.Context(), nil, transform.XPathContext{
					Variables: transform.Bindings{{Local: "f"}: callable},
					Context:   transform.DynamicContext{DefaultLanguage: "en"},
				})
				if err != nil {
					t.Fatal(version, err)
				}

				got, err := result.Text()
				if err != nil || got != test.want {
					t.Fatal("escaped language context", version, got, test.want, err)
				}
			}
		})
	}
}

func TestExtensionNamespaceContracts(t *testing.T) {
	e := engine(t, transform.Config{})
	for _, version := range []string{version20, version30} {
		for _, test := range []struct{ body, code string }{
			{`<xsl:template name="start" extension-element-prefixes="missing"/>`, "XTSE1430"},
			{`<xsl:template name="start"><r xsl:extension-element-prefixes="missing"/></xsl:template>`, "XTSE1430"},
			{`<xsl:template name="start" extension-element-prefixes="#default"/>`, "XTSE1430"},
		} {
			_, err := e.CompileXSLT(t.Context(), []byte(sheet(version, test.body)), transform.XSLTOptions{})
			var detail *transform.Error
			if !errors.As(err, &detail) || detail.Code != test.code {
				t.Fatal(version, test, err)
			}
		}
	}
	for _, body := range []string{
		`<xsl:template name="start" extension-element-prefixes="xs"/>`,
		`<xsl:template name="start"><r xsl:extension-element-prefixes="xs"/></xsl:template>`,
		`<xsl:template name="start"><r xmlns="http://www.w3.org/2001/XMLSchema" xsl:extension-element-prefixes="#default"/></xsl:template>`,
	} {
		_, err := e.CompileXSLT(t.Context(), []byte(sheet(version30, body)), transform.XSLTOptions{})
		var detail *transform.Error
		if !errors.As(err, &detail) || detail.Code != "XTSE0085" {
			t.Fatal(body, err)
		}
	}

	for _, source := range []string{
		strings.Replace(sheet(version30, `<xsl:template name="start"><action><xsl:fallback>ok</xsl:fallback></action></xsl:template>`), `<xsl:stylesheet `, `<xsl:stylesheet xmlns="urn:extension" extension-element-prefixes="#default" `, 1),
		sheet(version30, `<xsl:template name="start"><action xmlns="urn:extension" xsl:extension-element-prefixes="#default"><xsl:fallback>ok</xsl:fallback></action></xsl:template>`),
	} {
		for _, nested := range []bool{false, true} {
			got, err := resourceStylesheetResult(t, e, source, nested)
			if err != nil || got != "ok" {
				t.Fatal(source, nested, got, err)
			}
		}
	}
	// Conditional exclusion precedes checking the discarded extension declaration.
	got, err := resourceStylesheetResult(t, e, sheet(version30, `<xsl:template name="start"><r xsl:use-when="false()" xsl:extension-element-prefixes="missing"/>ok</xsl:template>`), false)
	if err != nil || got != "ok" {
		t.Fatal(got, err)
	}
}

func TestVersionedWhitespaceAndSequenceContracts(t *testing.T) {
	e := engine(t, transform.Config{})
	for _, version := range []string{version20, version30} {
		for _, test := range []struct{ declarations, want20 string }{
			{`<xsl:strip-space elements="r"/><xsl:preserve-space elements="r"/>`, "1"},
			{`<xsl:preserve-space elements="r"/><xsl:strip-space elements="r"/>`, "0"},
			{`<xsl:strip-space elements="*:r"/><xsl:preserve-space elements="p:*" xmlns:p="urn:r"/>`, "1"},
		} {
			source := sheet(version, test.declarations+`<xsl:template name="start"><xsl:value-of select="count(doc('urn:source')/*/text())"/></xsl:template>`)
			configured := engine(t, transform.Config{Resolver: transform.ResolverFunc(func(context.Context, string) (io.ReadCloser, error) {
				return io.NopCloser(strings.NewReader(`<r xmlns="urn:r"> </r>`)), nil
			})})
			// Use the same namespace for exact and wildcard name tests.
			source = strings.Replace(source, `<xsl:stylesheet `, `<xsl:stylesheet xpath-default-namespace="urn:r" `, 1)
			got, err := resourceStylesheetResult(t, configured, source, false)
			if version == version20 {
				if err != nil || got != test.want20 {
					t.Fatal(version, got, err, test.want20)
				}
			} else {
				var detail *transform.Error
				if !errors.As(err, &detail) || detail.Code != "XTSE0270" {
					t.Fatal(version, got, err)
				}
			}
		}

		compiled := stylesheet(t, e, sheet(version, `<xsl:template name="start">ok</xsl:template>`))
		got, entryErr := compiled.Transform(t.Context(), nil, transform.XSLTContext{Template: transform.Name{Local: nameStart}, Mode: transform.Name{Local: "m"}})
		if version == version20 {
			var detail *transform.Error
			if !errors.As(entryErr, &detail) || detail.Code != "XTDE0047" {
				t.Fatal(version, entryErr)
			}
		} else if !errors.Is(entryErr, transform.ErrInput) {
			t.Fatal(version, got, entryErr)
		}
		_, err := e.CompileXSLT(t.Context(), []byte(sheet(version, `<xsl:template name="start"><xsl:sequence select="1"><xsl:text>invalid</xsl:text></xsl:sequence></xsl:template>`)), transform.XSLTOptions{})
		code := "XTSE3185"
		if version == version20 {
			code = "XTSE0010"
		}
		var detail *transform.Error
		if !errors.As(err, &detail) || detail.Code != code {
			t.Fatal(version, err, code)
		}
	}
}

func TestParameterContracts(t *testing.T) {
	e := engine(t, transform.Config{})
	for _, version := range []string{version20, version30} {
		for _, test := range parameterContractCases() {
			t.Run(version+"/"+test.name, func(t *testing.T) {
				want := test.code30
				if version == version20 {
					want = test.code20
				}
				source := parameterContractSheet(version, test)
				nestedPaths := []bool{false}
				if version == version30 {
					nestedPaths = append(nestedPaths, true)
				}
				for _, nested := range nestedPaths {
					got, err := resourceStylesheetResult(t, e, source, nested)
					if want != "" {
						var detail *transform.Error
						if !errors.As(err, &detail) || detail.Code != want {
							t.Fatal(nested, got, err, want)
						}
					} else if err != nil || got != nameTrue {
						t.Fatal(nested, got, err)
					}
				}
			})
		}
	}
}

func TestAtomicParameterContracts(t *testing.T) {
	e := engine(t, transform.Config{})
	for _, test := range parameterContractCases() {
		if test.global != "" || strings.HasPrefix(test.name, "node ") {
			continue
		}
		t.Run(test.name, func(t *testing.T) {
			test.call = strings.NewReplacer(`<xsl:call-template name="target">`, `<xsl:apply-templates select="7">`, `</xsl:call-template>`, `</xsl:apply-templates>`).Replace(test.call)
			if test.call == "" {
				test.call = `<xsl:apply-templates select="7"/>`
			}
			source := strings.Replace(parameterContractSheet(version30, test), `match="r"`, `match=".[. instance of xs:integer]"`, 1)
			for _, nested := range []bool{false, true} {
				got, err := resourceStylesheetResult(t, e, source, nested)
				if test.code30 != "" {
					var detail *transform.Error
					if !errors.As(err, &detail) || detail.Code != test.code30 {
						t.Fatal(nested, got, err, test.code30)
					}
				} else if err != nil || got != nameTrue {
					t.Fatal(nested, got, err)
				}
			}
		})
	}
}

func TestRequiredParameterBooleans(t *testing.T) {
	e := engine(t, transform.Config{})
	for _, required := range []string{"true", "1"} {
		source := sheet(version30, `<xsl:param name="p" required="`+required+`"/><xsl:template name="start">unused</xsl:template>`)
		for _, nested := range []bool{false, true} {
			_, err := resourceStylesheetResult(t, e, source, nested)
			var detail *transform.Error
			if !errors.As(err, &detail) || detail.Code != "XTDE0050" {
				t.Fatal(required, nested, err)
			}
			_, err = resourceStylesheetResult(t, e, sheet(version30, `<xsl:param name="p" tunnel="`+required+`" select="1"/><xsl:template name="start">unused</xsl:template>`), nested)
			if !errors.As(err, &detail) || detail.Code != "XTSE0020" {
				t.Fatal("global tunnel", required, nested, err)
			}
		}
	}
}

func TestInitialTemplateRequiredParameters(t *testing.T) {
	e := engine(t, transform.Config{})
	d, err := e.Parse(t.Context(), []byte(`<r/>`))
	if err != nil {
		t.Fatal(err)
	}
	for _, version := range []string{version20, version30} {
		for _, named := range []bool{false, true} {
			for _, tunnel := range []bool{false, true} {
				for _, supplied := range []bool{false, true} {
					attribute := ""
					if tunnel {
						attribute = ` tunnel="yes"`
					}
					source := sheet(version, `<xsl:template name="start" match="/"><xsl:param name="p" required="yes"`+attribute+`/><xsl:value-of select="$p"/></xsl:template>`)
					s := stylesheet(t, e, source)
					options := transform.XSLTContext{}
					if named {
						options.Template = transform.Name{Local: nameStart}
					}
					if supplied {
						values := transform.Bindings{{Local: "p"}: transform.Values(transform.Integer(41))}
						if tunnel {
							options.TunnelParameters = values
						} else {
							options.InitialParameters = values
						}
					}
					result, err := s.Transform(t.Context(), d, options)
					code := ""
					if version == version20 {
						code = "XTDE0060"
					} else if !supplied {
						code = "XTDE0700"
					}
					if code != "" {
						var detail *transform.Error
						if !errors.As(err, &detail) || detail.Code != code {
							t.Fatal(version, named, tunnel, supplied, result, err, code)
						}
					} else if err != nil || string(result.Primary) != "41" {
						t.Fatal(version, named, tunnel, supplied, result, err)
					}
				}
			}
		}
	}
	// The document's built-in rule is the initial template here. Its recursive
	// element rule uses the ordinary missing-parameter error, not XTDE0060.
	s := stylesheet(t, e, sheet(version20, `<xsl:template match="r"><xsl:param name="p" required="yes"/><xsl:value-of select="$p"/></xsl:template>`))
	_, err = s.Transform(t.Context(), d, transform.XSLTContext{})
	var detail *transform.Error
	if !errors.As(err, &detail) || detail.Code != "XTDE0700" {
		t.Fatal("built-in rule leaked the initial invocation state", err)
	}
}

type functionArgumentCase struct{ name, declaration, argument, check, want string }

func functionArgumentCases() []functionArgumentCase {
	return []functionArgumentCase{
		{"numeric promotion", `as="xs:double"`, `42`, `$v instance of xs:double and $v eq 42`, nameTrue},
		{"URI promotion", `as="xs:string"`, `xs:anyURI('urn:value')`, `$v instance of xs:string and $v eq 'urn:value'`, nameTrue},
		{"untyped conversion", `as="xs:integer"`, `xs:untypedAtomic('42')`, `$v eq 42`, nameTrue},
		{"string mismatch", `as="xs:integer"`, `'42'`, `true()`, errCodeXPTY0004},
		{"invalid untyped", `as="xs:integer"`, `xs:untypedAtomic('bad')`, `true()`, "FORG0001"},
		{"namespace sensitive", `as="xs:QName"`, `xs:untypedAtomic('local')`, `true()`, "XPTY0117"},
		{"atomization error", `as="xs:string"`, `map{}`, `true()`, "FOTY0013"},
		{"empty argument", `as="xs:integer"`, `()`, `true()`, errCodeXPTY0004},
		{"multiple argument", `as="xs:integer"`, `(1,2)`, `true()`, errCodeXPTY0004},
		{"array atomization", `as="xs:integer*"`, `[1,[2]]`, `deep-equal($v,(1,2))`, nameTrue},
		{"declaration prefix", `xmlns:a="http://www.w3.org/2001/XMLSchema" as="a:integer"`, `42`, `$v eq 42`, nameTrue},
		{"declaration default", `xpath-default-namespace="http://www.w3.org/2001/XMLSchema" as="integer"`, `42`, `$v eq 42`, nameTrue},
		{"deferred coercion", `as="function(xs:double) as xs:double"`, `function($x as xs:float) {$x}`, `function-arity($v) eq 1`, nameTrue},
		{"invoked coercion", `as="function(xs:double) as xs:double"`, `function($x as xs:float) {$x}`, `$v(2) eq 2`, errCodeXPTY0004},
		{"function result promotion", `as="function(xs:double) as xs:double"`, `function($x as xs:double) as xs:float {xs:float($x)}`, `$v(2) instance of xs:double`, nameTrue},
	}
}

func functionArgumentSheet(test functionArgumentCase) string {
	return sheet(version30, `<xsl:function xmlns:f="urn:function" xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:a="urn:shadow" name="f:check" visibility="public" as="xs:boolean"><xsl:param name="v" `+test.declaration+`/><xsl:sequence select="`+test.check+`"/></xsl:function>`)
}

func functionArgumentExpression(test functionArgumentCase) string {
	return `transform(map{'stylesheet-text':'` + strings.ReplaceAll(functionArgumentSheet(test), "'", "''") + `','initial-function':QName('urn:function','check'),'function-params':[` + test.argument + `],'delivery-format':'serialized'})?output`
}

func TestXSLTFunctionArguments(t *testing.T) {
	e := engine(t, transform.Config{})
	for _, test := range functionArgumentCases() {
		t.Run(test.name, func(t *testing.T) {
			argument := evaluate(t, e, test.argument, transform.XPath31)
			compiled := stylesheet(t, e, functionArgumentSheet(test))
			result, err := compiled.CallFunction(t.Context(), nil, transform.Name{Space: "urn:function", Local: "check"}, []transform.Sequence{argument}, transform.XSLTContext{ResultMode: transform.ResultRaw})
			if comparisonErrorCode(test.want) {
				var detail *transform.Error
				if result != nil || !errors.As(err, &detail) || detail.Code != test.want {
					t.Fatal(result, err, test.want)
				}
			} else if err != nil || text(t, result.Primary()) != test.want {
				t.Fatal(result, err, test.want)
			}
			for _, call := range []string{`f:check`, `(f:check#1)`, `function-lookup(QName('urn:function','check'),1)`} {
				body := `<xsl:template xmlns:f="urn:function" name="start"><xsl:sequence select="` + call + `(` + test.argument + `)"/></xsl:template></xsl:stylesheet>`
				source := strings.TrimSuffix(functionArgumentSheet(test), `</xsl:stylesheet>`) + body
				got, callErr := resourceStylesheetResult(t, e, source, false)
				if comparisonErrorCode(test.want) {
					var detail *transform.Error
					if !errors.As(callErr, &detail) || detail.Code != test.want {
						t.Fatal(call, got, callErr, test.want)
					}
				} else if callErr != nil || got != test.want {
					t.Fatal(call, got, callErr, test.want)
				}
			}
			value, err := query(t, e, functionArgumentExpression(test), transform.XPath31).Evaluate(t.Context(), nil, transform.XPathContext{})
			if comparisonErrorCode(test.want) {
				var detail *transform.Error
				if value.Len() != 0 || !errors.As(err, &detail) || detail.Code != test.want {
					t.Fatal("fn:transform", value, err, test.want)
				}
			} else if err != nil || text(t, value) != test.want {
				t.Fatal("fn:transform", value, err, test.want)
			}
		})
	}
}

type functionReturnCase struct{ name, declaration, body, check, want string }

func functionReturnCases() []functionReturnCase {
	return []functionReturnCase{
		{"numeric result", `as="xs:double"`, `1`, `$v instance of xs:double`, nameTrue},
		{"array result", `as="xs:integer*"`, `[1,[2]]`, `deep-equal($v,(1,2))`, nameTrue},
		{"string result mismatch", `as="xs:integer"`, `'42'`, `$v eq 42`, "XTTE0780"},
		{"invalid untyped result", `as="xs:integer"`, `xs:untypedAtomic('bad')`, `$v eq 42`, "XTTE0780"},
		{"function atomization result", `as="xs:string"`, `map{}`, `$v eq ''`, "XTTE0780"},
		{"deferred returned coercion", `as="function(xs:double) as xs:double"`, `function($x as xs:float){$x}`, `function-arity($v) eq 1`, nameTrue},
		{"invoked returned coercion", `as="function(xs:double) as xs:double"`, `function($x as xs:float){$x}`, `$v(2) eq 2`, errCodeXPTY0004},
		{"promoted function result", `as="function(xs:double) as xs:double"`, `function($x as xs:double) as xs:float {xs:float($x)}`, `$v(2) instance of xs:double`, nameTrue},
		{"return declaration prefix", `xmlns:a="http://www.w3.org/2001/XMLSchema" as="a:integer"`, `1`, `$v eq 1`, nameTrue},
		{"return declaration default", `xpath-default-namespace="urn:result" as="element(item)"`, `parse-xml('&lt;item xmlns=&quot;urn:result&quot;/>')/*`, `namespace-uri($v) eq 'urn:result'`, nameTrue},
		{"typed node result", `as="element(item,xs:untyped)"`, `parse-xml('&lt;item/>')/*`, `$v instance of element(item,xs:untyped) and f:get#0 instance of function() as element(item,xs:untyped)`, nameTrue},
		{"node signature name", `as="element(item)"`, `parse-xml('&lt;item/>')/*`, `f:get#0 instance of function() as element(item)`, nameTrue},
		{"attribute signature name", `as="attribute(id,xs:untypedAtomic)"`, `parse-xml('&lt;r id=&quot;x&quot;/>')/*/@id`, `f:get#0 instance of function() as attribute(id,xs:untypedAtomic)`, nameTrue},
	}
}

func functionReturnSheet(test functionReturnCase) string {
	return sheet(version30, `<xsl:function xmlns:f="urn:function" xmlns:xs="http://www.w3.org/2001/XMLSchema" name="f:get" `+test.declaration+`><xsl:sequence select="`+test.body+`"/></xsl:function><xsl:template xmlns:f="urn:function" xmlns:xs="http://www.w3.org/2001/XMLSchema" name="start"><xsl:variable name="v" select="f:get()"/><xsl:sequence select="`+test.check+`"/></xsl:template>`)
}

func TestXSLTFunctionReturns(t *testing.T) {
	e := engine(t, transform.Config{})
	for _, test := range functionReturnCases() {
		t.Run(test.name, func(t *testing.T) {
			for _, nested := range []bool{false, true} {
				got, err := resourceStylesheetResult(t, e, functionReturnSheet(test), nested)
				if comparisonErrorCode(test.want) {
					var detail *transform.Error
					if !errors.As(err, &detail) || detail.Code != test.want {
						t.Fatal(nested, got, err, test.want)
					}
				} else if err != nil || got != test.want {
					t.Fatal(nested, got, err, test.want)
				}
			}
		})
	}
}

type dynamicXPathCase struct{ name, global, body, want string }

func builtinTemplateCases() []dynamicXPathCase {
	cases := make([]dynamicXPathCase, 0, 43)
	for _, mode := range []string{"text-only-copy", "shallow-copy", "deep-copy", "shallow-skip", "deep-skip", "fail"} {
		declaration := `<xsl:mode name="m" on-no-match="` + mode + `"/>`
		for _, value := range []struct{ name, expression, check string }{
			{"atomic", `42`, `$v instance of xs:integer and $v eq 42`},
			{"map", `map{'a':1}`, `$v instance of map(*) and $v?a eq 1`},
			{"array", `[1,[2]]`, `$v instance of array(*) and $v?1 eq 1 and $v?2 instance of array(*)`},
			{"function", `function(){7}`, `$v instance of function(*) and $v() eq 7`},
		} {
			check, want := value.check, nameTrue
			if mode == "shallow-skip" || mode == "deep-skip" || mode == "text-only-copy" {
				check = `empty($v)`
				if mode == "text-only-copy" && value.name == "atomic" {
					check = `$v instance of text() and string($v) eq '42'`
				}
				if mode == "text-only-copy" && value.name == "array" {
					check = `count($v) eq 2 and (every $n in $v satisfies $n instance of text()) and string-join($v ! string(.),'') eq '12'`
				}
			}
			if mode == "fail" {
				want = "XTDE0555"
			}
			body := `<xsl:variable name="v" as="item()*"><xsl:apply-templates select="` + value.expression + `" mode="m"/></xsl:variable><xsl:value-of select="` + check + `"/>`
			cases = append(cases, dynamicXPathCase{mode + " " + value.name, declaration, body, want})
		}
	}
	for _, mode := range []string{"shallow-copy", "deep-copy"} {
		for _, selected := range []string{"@a", "namespace::p"} {
			body := `<xsl:variable name="source" select="parse-xml('&lt;r xmlns:p=&quot;urn:p&quot; a=&quot;v&quot;/>')/r"/><xsl:variable name="v" as="item()*"><xsl:apply-templates select="$source/` + selected + `" mode="m"/></xsl:variable>`
			check := `$v instance of attribute(a) and string($v) eq 'v' and not($v is $source/@a) and empty($v/parent::node())`
			if selected == "namespace::p" {
				check = `$v instance of namespace-node() and name($v) eq 'p' and string($v) eq 'urn:p' and empty($v/parent::node())`
			}
			cases = append(cases, dynamicXPathCase{mode + " " + selected, `<xsl:mode name="m" on-no-match="` + mode + `"/>`, body + `<xsl:value-of select="` + check + `"/>`, nameTrue})
		}
		body := `<xsl:variable name="source" select="parse-xml('&lt;r xml:base=&quot;https://example.test/source.xml&quot;>&lt;n a=&quot;v&quot;/>text&lt;!--c-->&lt;?go ok?>&lt;/r>')"/><xsl:variable name="v" as="item()*"><xsl:apply-templates select="$source" mode="m"/></xsl:variable><xsl:value-of select="$v instance of document-node() and not($v is $source) and root($v/r) is $v and deep-equal($v,$source) and base-uri($v/r) eq base-uri($source/r) and count($v/r/node()) eq 4"/>`
		cases = append(cases, dynamicXPathCase{mode + " document", `<xsl:mode name="m" on-no-match="` + mode + `"/>`, body, nameTrue})
	}
	for _, action := range []string{`<xsl:copy-of select="$source"/>`, `<xsl:copy select="$source"><xsl:copy-of select="node()"/></xsl:copy>`, `<xsl:apply-templates select="$source" mode="shallow"/>`, `<xsl:apply-templates select="$source" mode="deep"/>`} {
		global := `<xsl:mode name="shallow" on-no-match="shallow-copy"/><xsl:mode name="deep" on-no-match="deep-copy"/><xsl:variable xml:base="https://example.test/source.xml" name="source" select="parse-xml('&lt;r/>')"/>`
		body := `<xsl:variable name="v" as="document-node()">` + action + `</xsl:variable><xsl:value-of select="base-uri($v) eq 'https://example.test/source.xml' and base-uri($v/r) eq base-uri($v) and empty(document-uri($v))"/>`
		cases = append(cases, dynamicXPathCase{"document metadata " + action, global, body, nameTrue})
	}
	for _, mode := range []string{"text-only-copy", "shallow-copy", "shallow-skip"} {
		global := `<xsl:mode name="m" on-no-match="` + mode + `"/><xsl:template match="@*|n" mode="m"><xsl:value-of select="concat(name(),position(),'/',last(),';')"/></xsl:template>`
		want := "a1/2;b2/2;n1/2;n2/2;"
		if mode == "text-only-copy" {
			want = "n1/2;n2/2;"
		}
		cases = append(cases, dynamicXPathCase{mode + " focus", global, `<xsl:apply-templates select="parse-xml('&lt;r a=&quot;1&quot; b=&quot;2&quot;>&lt;n/>&lt;n/>&lt;/r>')/r" mode="m"/>`, want})
	}
	cases = append(cases,
		dynamicXPathCase{"copied document constructor order", `<xsl:variable name="source" select="parse-xml('&lt;r/>')"/>`, `<xsl:variable name="v"><before/><xsl:copy select="$source"><middle/></xsl:copy><after/></xsl:variable><xsl:value-of select="string-join($v/* ! local-name(),',')"/>`, "before,middle,after"},
		dynamicXPathCase{"array member focus", `<xsl:template match=".[. instance of xs:integer]"><xsl:value-of select="concat(position(),'/',last(),':',.,';')"/></xsl:template>`, `<xsl:apply-templates select="[(1,2),3]"/>`, "1/3:1;2/3:2;3/3:3;"},
		dynamicXPathCase{"array shallow skip rules", `<xsl:mode name="m" on-no-match="shallow-skip"/><xsl:template match=".[. instance of xs:integer and . eq 2]" mode="m"><xsl:value-of select="concat(position(),'/',last(),':',.)"/></xsl:template>`, `<xsl:apply-templates select="[(1,2),3]" mode="m"/>`, "2/3:2"},
		dynamicXPathCase{"fail document before children", `<xsl:mode name="m" on-no-match="fail"/><xsl:template match="r" mode="m">matched</xsl:template>`, `<xsl:apply-templates select="parse-xml('&lt;r/>')" mode="m"/>`, "XTDE0555"},
		dynamicXPathCase{"next match atomic copy", `<xsl:mode name="m" on-no-match="deep-copy"/><xsl:template match=".[. instance of xs:integer]" mode="m"><xsl:next-match/></xsl:template>`, `<xsl:variable name="v" as="item()*"><xsl:apply-templates select="42" mode="m"/></xsl:variable><xsl:value-of select="$v instance of xs:integer and $v eq 42"/>`, nameTrue},
		dynamicXPathCase{"apply imports map copy", `<xsl:mode name="m" on-no-match="deep-copy"/><xsl:template match=".[. instance of map(*)]" mode="m"><xsl:apply-imports/></xsl:template>`, `<xsl:variable name="v" as="item()*"><xsl:apply-templates select="map{'a':42}" mode="m"/></xsl:variable><xsl:value-of select="$v instance of map(*) and $v?a eq 42"/>`, nameTrue},
	)
	return cases
}

func TestXSLTBuiltinTemplates(t *testing.T) {
	e := engine(t, transform.Config{})
	for _, test := range builtinTemplateCases() {
		t.Run(test.name, func(t *testing.T) {
			for _, nested := range []bool{false, true} {
				got, err := resourceStylesheetResult(t, e, dynamicXPathSheet(test), nested)
				if comparisonErrorCode(test.want) {
					var detail *transform.Error
					if !errors.As(err, &detail) || detail.Code != test.want {
						t.Fatal(nested, got, err, test.want)
					}
				} else if err != nil || got != test.want {
					t.Fatal(nested, got, err, test.want)
				}
			}
		})
	}
	capped := engine(t, transform.Config{Limits: transform.Limits{MaxDepth: 32}})
	for _, expression := range []string{`fold-left(1 to 100,1,function($a,$b){[$a]})`, `42`} {
		global := ``
		if expression == `42` {
			global = `<xsl:template match=".[. instance of xs:integer]"><xsl:apply-templates select="."/></xsl:template>`
		}
		_, err := resourceStylesheetResult(t, capped, dynamicXPathSheet(dynamicXPathCase{global: global, body: `<xsl:apply-templates select="` + expression + `"/>`}), false)
		if !errors.Is(err, transform.ErrLimit) {
			t.Fatal("unbounded template recursion", expression, err)
		}
	}
}

func builtinInitialCases() []struct{ mode, expression, check, code string } {
	return []struct{ mode, expression, check, code string }{
		{"deep-copy", `map{'a':42}`, `$result instance of map(*) and $result?a eq 42`, ""},
		{"shallow-copy", `function(){42}`, `$result instance of function(*) and $result() eq 42`, ""},
		{"deep-copy", `[1,[2]]`, `$result instance of array(*) and $result?2 instance of array(*)`, ""},
		{"deep-copy", `42`, `$result instance of xs:integer and $result eq 42`, ""},
		{"text-only-copy", `map{'a':42}`, `empty($result)`, ""},
		{"text-only-copy", `[1,[2]]`, `count($result) eq 2 and string-join($result ! string(.),'') eq '12'`, ""},
		{"shallow-skip", `[1,[2]]`, `empty($result)`, ""},
		{"fail", `map{'a':42}`, "", "XTDE0555"},
	}
}

func builtinInitialSheet(mode string) string {
	return sheet(version30, `<xsl:mode name="m" on-no-match="`+mode+`"/>`)
}

func builtinInitialExpression(test struct{ mode, expression, check, code string }) string {
	source := strings.ReplaceAll(builtinInitialSheet(test.mode), "'", "''")
	expression := `transform(map{'stylesheet-text':'` + source + `','initial-match-selection':` + test.expression + `,'initial-mode':QName('','m'),'delivery-format':'raw'})?output`
	if test.code != "" {
		return expression
	}
	return `let $result := ` + expression + ` return ` + test.check
}

func TestXSLTBuiltinInitialItems(t *testing.T) {
	e := engine(t, transform.Config{})
	for _, test := range builtinInitialCases() {
		t.Run(test.mode+test.expression, func(t *testing.T) {
			selection := evaluate(t, e, test.expression, transform.XPath31)
			compiled := stylesheet(t, e, builtinInitialSheet(test.mode))
			result, err := compiled.ApplyTemplates(t.Context(), nil, selection, transform.XSLTContext{Mode: transform.Name{Local: "m"}, ResultMode: transform.ResultRaw})
			if test.code != "" {
				var detail *transform.Error
				if !errors.As(err, &detail) || detail.Code != test.code {
					t.Fatal(result, err)
				}
			} else {
				if err != nil {
					t.Fatal(err)
				}
				value, err := query(t, e, test.check, transform.XPath31).Evaluate(t.Context(), nil, transform.XPathContext{Variables: transform.Bindings{{Local: resultBindingName}: result.Primary()}})
				if err != nil || text(t, value) != nameTrue {
					t.Fatal(value, err)
				}
			}
			nested, err := query(t, e, builtinInitialExpression(test), transform.XPath31).Evaluate(t.Context(), nil, transform.XPathContext{})
			if test.code != "" {
				var detail *transform.Error
				if !errors.As(err, &detail) || detail.Code != test.code {
					t.Fatal(err)
				}
			} else if err != nil || text(t, nested) != nameTrue {
				t.Fatal(nested, err)
			}
		})
	}
}

func xmlIDConstructionCases() []dynamicXPathCase {
	return []dynamicXPathCase{
		{"literal", "", `<xsl:variable name="v"><r xml:id=" root "/></xsl:variable><xsl:value-of select="string($v/r/@xml:id) eq 'root' and id('root',$v) is $v/r"/>`, nameTrue},
		{"computed", "", `<xsl:variable name="v"><r><xsl:attribute name="xml:id" select="' &#x9;root&#xD; '"/></r></xsl:variable><xsl:value-of select="string($v/r/@xml:id) eq 'root' and id('root',$v) is $v/r"/>`, nameTrue},
		{"expanded name", "", `<xsl:variable name="v"><r><xsl:attribute name="id" namespace="http://www.w3.org/XML/1998/namespace" select="' root '"/></r></xsl:variable><xsl:value-of select="string($v/r/@xml:id) eq 'root' and id('root',$v) is $v/r"/>`, nameTrue},
		{"standalone", "", `<xsl:variable name="v" as="attribute()"><xsl:attribute name="xml:id" select="' one &#x9; two '"/></xsl:variable><xsl:value-of select="string($v)"/>`, "one two"},
		{"attribute set", `<xsl:attribute-set name="ids"><xsl:attribute name="xml:id" select="' root '"/></xsl:attribute-set>`, `<xsl:variable name="v"><r xsl:use-attribute-sets="ids"/></xsl:variable><xsl:value-of select="string($v/r/@xml:id) eq 'root' and id('root',$v) is $v/r"/>`, nameTrue},
		{"copy", "", `<xsl:variable name="v"><r xml:id=" root "/></xsl:variable><xsl:variable name="c"><xsl:for-each select="$v/r"><xsl:copy><xsl:copy-of select="@*"/></xsl:copy></xsl:for-each></xsl:variable><xsl:value-of select="string($c/r/@xml:id) eq 'root' and id('root',$c) is $c/r"/>`, nameTrue},
		{"other attributes", "", `<xsl:variable name="v"><r xml:id=" root " a=" root "/></xsl:variable><xsl:value-of select="string($v/r/@xml:id) eq 'root' and string($v/r/@a) eq ' root '"/>`, nameTrue},
	}
}

func TestXSLTXMLIDConstruction(t *testing.T) {
	e := engine(t, transform.Config{})
	for _, test := range xmlIDConstructionCases() {
		t.Run(test.name, func(t *testing.T) {
			for _, version := range []string{version20, version30} {
				for _, nested := range []bool{false, true} {
					source := sheet(version, test.global+`<xsl:template name="start">`+test.body+`</xsl:template>`)
					got, err := resourceStylesheetResult(t, e, source, nested)
					if err != nil || got != test.want {
						t.Fatal(version, nested, got, err, test.want)
					}
				}
			}
		})
	}
}

func dynamicXPathCases() []dynamicXPathCase {
	functions := `<xsl:function name="Q{urn:dynamic}f" visibility="public"><xsl:sequence select="42"/></xsl:function><xsl:function name="Q{urn:dynamic}f" visibility="private"><xsl:param name="x"/><xsl:sequence select="$x"/></xsl:function><xsl:function name="Q{urn:dynamic}f" visibility="public"><xsl:param name="x"/><xsl:param name="y"/><xsl:sequence select="$x+$y"/></xsl:function>`
	return []dynamicXPathCase{
		{"global not in scope", `<xsl:variable name="secret" select="42"/>`, `<xsl:evaluate xpath="'$secret'"/>`, "XTDE3160"},
		{"local not in scope", "", `<xsl:variable name="secret" select="42"/><xsl:evaluate xpath="'$secret'"/>`, "XTDE3160"},
		{"unselected free variable", `<xsl:variable name="secret" select="42"/>`, `<xsl:evaluate xpath="'if(false()) then $secret else 1'"/>`, "XTDE3160"},
		{"explicit parameter", "", `<xsl:evaluate xpath="'$p instance of xs:double'"><xsl:with-param name="p" select="42" as="xs:double"/></xsl:evaluate>`, nameTrue},
		{"map overrides parameter", "", `<xsl:evaluate xpath="'$p'" with-params="map{QName('','p'):42}"><xsl:with-param name="p" select="99"/></xsl:evaluate>`, "42"},
		{"empty parameter map", "", `<xsl:evaluate xpath="'42'" with-params="()"/>`, "XTTE3165"},
		{"non map parameter", "", `<xsl:evaluate xpath="'42'" with-params="1"/>`, "XTTE3165"},
		{"wrong map key", "", `<xsl:evaluate xpath="'42'" with-params="map{'p':1}"/>`, "XTTE3165"},
		{"unknown unselected function", "", `<xsl:evaluate xpath="'if(false()) then Q{urn:missing}f() else 1'"/>`, "XTDE3160"},
		{"public overload", functions, `<xsl:evaluate xpath="'Q{urn:dynamic}f()'"/>`, "42"},
		{"private overload", functions, `<xsl:evaluate xpath="'Q{urn:dynamic}f(1)'"/>`, "XTDE3160"},
		{"private lookup absent", functions, `<xsl:evaluate xpath="'empty(function-lookup(QName(''urn:dynamic'',''f''),1))'"/>`, nameTrue},
		{"XSLT function unavailable", "", `<xsl:evaluate xpath="'key(''k'',1)'"/>`, "XTDE3160"},
		{"XSLT lookup absent", "", `<xsl:evaluate xpath="'empty(function-lookup(QName(''http://www.w3.org/2005/xpath-functions'',''key''),2))'"/>`, nameTrue},
		{"compatibility disabled", "", `<xsl:evaluate version="1.0" xpath="'string-length(12)'"/>`, errCodeXPTY0004},
		{"result numeric promotion", "", `<xsl:variable name="v"><xsl:evaluate xpath="'42'" as="xs:double"/></xsl:variable><xsl:sequence select="$v/node() instance of text()"/>`, nameTrue},
		{"result typed promotion", "", `<xsl:variable name="v" as="item()*"><xsl:evaluate xpath="'42'" as="xs:double"/></xsl:variable><xsl:sequence select="$v instance of xs:double"/>`, nameTrue},
		{"result cardinality", "", `<xsl:evaluate xpath="'(1,2)'" as="xs:integer"/>`, errCodeXPTY0004},
		{"result invalid cast", "", `<xsl:evaluate xpath="'xs:untypedAtomic(''bad'')'" as="xs:integer"/>`, "FORG0001"},
		{"source type", "", `<xsl:evaluate xpath="12"/>`, errCodeXPTY0004},
		{"source cardinality", "", `<xsl:evaluate xpath="()"/>`, errCodeXPTY0004},
		{"source URI", "", `<xsl:evaluate xpath="xs:anyURI('42')"/>`, "42"},
		{"lexical namespace", "", `<xsl:evaluate xmlns:p="urn:local" xpath="'namespace-uri-from-QName(xs:QName(''p:x''))'"/>`, "urn:local"},
		{"namespace context replaces prefixes", "", `<xsl:variable name="n" select="parse-xml('&lt;r/>')/*"/><xsl:evaluate xmlns:p="urn:removed" namespace-context="$n" context-item="$n" xpath="'count(p:x)'"/>`, "XTDE3160"},
		{"namespace context default", "", `<xsl:variable name="n" select="parse-xml('&lt;r xmlns=&quot;urn:context&quot;>&lt;x/>&lt;/r>')/*"/><xsl:evaluate namespace-context="$n" context-item="$n" xpath-default-namespace="urn:wrong" xpath="'count(x)'"/>`, "1"},
		{"bound variable", "", `<xsl:evaluate xpath="'(function($secret){$secret})(42)'"/>`, "42"},
		{"absent position", "", `<xsl:evaluate xpath="'position()'"/>`, "XPDY0002"},
		{"singleton position", "", `<xsl:evaluate context-item="42" xpath="'position() + last()'"/>`, "2"},
		{"schema type in signature", "", `<xsl:evaluate xmlns:p="urn:no-schema" xpath="'function($v as p:custom){$v}'"/>`, "XTDE3160"},
		{"schema component", "", `<xsl:evaluate xpath="'() instance of schema-element(r)'"/>`, "XTDE3160"},
		{"namespace context excludes xs", "", `<xsl:variable name="n" select="parse-xml('&lt;r/>')/*"/><xsl:evaluate namespace-context="$n" xpath="'xs:integer(1)'"/>`, "XTDE3160"},
		{"result declaration alias", "", `<xsl:variable name="v" as="item()*"><xsl:evaluate xmlns:t="http://www.w3.org/2001/XMLSchema" xpath="'42'" as="t:double"/></xsl:variable><xsl:sequence select="$v instance of xs:double"/>`, nameTrue},
		{"changing parameter map", "", `<xsl:for-each select="1 to 2"><xsl:evaluate xpath="'$p1+$p2'" with-params="if(. eq 1) then map{QName('','p2'):2} else map{}"><xsl:with-param name="p1" select="1"/></xsl:evaluate></xsl:for-each>`, "XTDE3160"},
		{"parameter type failure", "", `<xsl:evaluate xpath="'$p'"><xsl:with-param name="p" as="xs:integer" select="'bad'"/></xsl:evaluate>`, "XTTE0590"},
		{"parameter type alias", "", `<xsl:evaluate xpath="'$p instance of xs:double'"><xsl:with-param xmlns:a="http://www.w3.org/2001/XMLSchema" name="p" as="a:double" select="42"/></xsl:evaluate>`, nameTrue},
		{"parameter array atomization", "", `<xsl:evaluate xpath="'deep-equal($p,(1,2))'"><xsl:with-param name="p" as="xs:integer*" select="[1,[2]]"/></xsl:evaluate>`, nameTrue},
	}
}

func dynamicXPathSheet(test dynamicXPathCase) string {
	return sheet(version30, test.global+`<xsl:template name="start">`+test.body+`</xsl:template>`)
}

func TestDynamicXPathContexts(t *testing.T) {
	e := engine(t, transform.Config{})
	for _, test := range dynamicXPathCases() {
		t.Run(test.name, func(t *testing.T) {
			for _, nested := range []bool{false, true} {
				got, err := resourceStylesheetResult(t, e, dynamicXPathSheet(test), nested)
				if comparisonErrorCode(test.want) {
					var detail *transform.Error
					if !errors.As(err, &detail) || detail.Code != test.want {
						t.Fatal(nested, got, err, test.want)
					}
				} else if err != nil || got != test.want {
					t.Fatal(nested, got, err, test.want)
				}
			}
		})
	}
}

func dynamicEvaluationPolicyCases() []struct{ name, global, body, enabled, disabled string } {
	inner := sheet(version30, `<xsl:template name="start"><xsl:evaluate xpath="'42'"><xsl:fallback>inner disabled</xsl:fallback></xsl:evaluate></xsl:template>`)
	invoke := func(source, options string) string {
		expression := `transform(map{'stylesheet-text':'` + strings.ReplaceAll(source, "'", "''") + `','initial-template':QName('', 'start'),'delivery-format':'serialized'` + options + `})?output`
		return `<xsl:sequence select="` + strings.NewReplacer("&", "&amp;", "<", "&lt;", "\"", "&quot;").Replace(expression) + `"/>`
	}
	plain := sheet(version30, `<xsl:template name="start">selected</xsl:template>`)

	return []struct{ name, global, body, enabled, disabled string }{
		{"runtime availability", "", `<xsl:value-of select="element-available('xsl:evaluate')"/><xsl:text>|</xsl:text><xsl:value-of select="system-property('xsl:supports-dynamic-evaluation')"/>`, "true|yes", "false|no"},
		{"static element availability", `<xsl:variable name="v" use-when="element-available('xsl:evaluate')" select="'enabled'"/><xsl:variable name="v" use-when="not(element-available('xsl:evaluate'))" select="'disabled'"/>`, `<xsl:value-of select="$v"/>`, "enabled", "disabled"},
		{"static property", `<xsl:variable name="v" use-when="system-property('xsl:supports-dynamic-evaluation') eq 'yes'" select="'enabled'"/><xsl:variable name="v" use-when="system-property('xsl:supports-dynamic-evaluation') eq 'no'" select="'disabled'"/>`, `<xsl:value-of select="$v"/>`, "enabled", "disabled"},
		{"fallback", "", `<xsl:evaluate xpath="'42'"><xsl:fallback>fallback</xsl:fallback></xsl:evaluate>`, "42", "fallback"},
		{"empty fallback", "", `<xsl:evaluate xpath="'42'"><xsl:fallback/></xsl:evaluate>`, "42", ""},
		{"multiple fallbacks", "", `<xsl:evaluate xpath="'42'"><xsl:fallback>A</xsl:fallback><xsl:fallback>B</xsl:fallback></xsl:evaluate>`, "42", "AB"},
		{"without fallback", "", `<xsl:evaluate xpath="'42'"/>`, "42", "XTDE3175"},
		{"catch disabled", "", `<xsl:try><xsl:evaluate xpath="'42'"/><xsl:catch errors="*" select="concat('caught:',local-name-from-QName($err:code))"/></xsl:try>`, "42", "caught:XTDE3175"},
		{"unused instruction", "", `<xsl:if test="false()"><xsl:evaluate xpath="'42'"/></xsl:if><xsl:text>unused</xsl:text>`, "unused", "unused"},
		{"disabled target not analyzed", `<xsl:param name="code" select="'Q{urn:missing}call()'"/>`, `<xsl:evaluate xpath="$code"><xsl:fallback>ignored</xsl:fallback></xsl:evaluate>`, "XTDE3160", "ignored"},
		{"nested transform", "", invoke(inner, ""), "42", "inner disabled"},
		{"requested enabled", "", invoke(plain, `, 'requested-properties':map{QName('http://www.w3.org/1999/XSL/Transform','supports-dynamic-evaluation'):true()}`), "selected", "FOXT0001"},
		{"requested disabled", "", invoke(plain, `, 'requested-properties':map{QName('http://www.w3.org/1999/XSL/Transform','supports-dynamic-evaluation'):false()}`), "FOXT0001", "selected"},
		{"fallback namespaces", "", `<xsl:evaluate xpath="'42'"><xsl:fallback xmlns:p="urn:fallback"><xsl:value-of select="namespace-uri-from-QName(xs:QName('p:x'))"/></xsl:fallback></xsl:evaluate>`, "42", "urn:fallback"},
		{"fallback default namespace", "", `<xsl:evaluate xpath="'42'"><xsl:fallback xpath-default-namespace="urn:fallback"><xsl:value-of select="count(parse-xml('&lt;r xmlns=&quot;urn:fallback&quot;/>')/r)"/></xsl:fallback></xsl:evaluate>`, "42", "1"},
		{"fallback expand text", "", `<xsl:evaluate xpath="'42'"><xsl:fallback expand-text="yes">value{6*7}</xsl:fallback></xsl:evaluate>`, "42", "value42"},
		{"fallback collation", "", `<xsl:evaluate xpath="'42'"><xsl:fallback default-collation="http://www.w3.org/2005/xpath-functions/collation/html-ascii-case-insensitive"><xsl:value-of select="compare('a','A')"/></xsl:fallback></xsl:evaluate>`, "42", "0"},
		{"fallback whitespace", "", `<xsl:evaluate xpath="'42'"><xsl:fallback xml:space="preserve"> <xsl:text>x</xsl:text> </xsl:fallback></xsl:evaluate>`, "42", " x "},
		{"fallback use when", "", `<xsl:evaluate xpath="'42'"><xsl:fallback use-when="false()">bad</xsl:fallback><xsl:fallback>yes</xsl:fallback></xsl:evaluate>`, "42", "yes"},
		{"excluded fallback", "", `<xsl:evaluate xpath="'42'"><xsl:fallback use-when="false()">bad</xsl:fallback></xsl:evaluate>`, "42", "XTDE3175"},
	}
}

func dynamicEvaluationPolicySheet(global, body string) string {
	return sheet(version30, global+`<xsl:template xmlns:err="http://www.w3.org/2005/xqt-errors" name="start">`+body+`</xsl:template>`)
}

func TestDynamicEvaluationPolicy(t *testing.T) {
	for _, disabled := range []bool{false, true} {
		e := engine(t, transform.Config{DisableXSLTDynamicEvaluation: disabled})
		for _, test := range dynamicEvaluationPolicyCases() {
			t.Run(test.name+map[bool]string{false: " enabled", true: " disabled"}[disabled], func(t *testing.T) {
				want := test.enabled
				if disabled {
					want = test.disabled
				}
				for _, nested := range []bool{false, true} {
					got, err := resourceStylesheetResult(t, e, dynamicEvaluationPolicySheet(test.global, test.body), nested)
					if comparisonErrorCode(want) {
						var detail *transform.Error
						if !errors.As(err, &detail) || detail.Code != want {
							t.Fatal(nested, got, err, want)
						}
					} else if err != nil || got != want {
						t.Fatal(nested, got, err, want)
					}
				}
			})
		}
	}
}

func introspectionCases() []struct{ name, scope, expression, want string } {
	base := []struct{ name, scope, expression, want string }{
		{"element without default", "", `element-available('evaluate')`, "false"},
		{"element XML default", `xmlns="http://www.w3.org/1999/XSL/Transform"`, `element-available('evaluate')`, "true"},
		{"element XPath default", `xpath-default-namespace="http://www.w3.org/1999/XSL/Transform"`, `element-available('evaluate')`, "false"},
		{"element distinct defaults", `xmlns="urn:other" xpath-default-namespace="http://www.w3.org/1999/XSL/Transform"`, `element-available('evaluate')`, "false"},
		{"element local alias", `xmlns:p="http://www.w3.org/1999/XSL/Transform"`, `element-available('p:evaluate')`, "true"},
		{"element EQName URI whitespace", "", `element-available('Q{  http://www.w3.org/1999/XSL/Transform  }evaluate')`, "true"},
		{"element empty EQName", "", `element-available('Q{}evaluate')`, "false"},
		{"element top level", "", `element-available('xsl:stylesheet')`, "true"},
		{"type without default", "", `type-available('integer')`, "false"},
		{"type XML default", `xmlns="http://www.w3.org/2001/XMLSchema"`, `type-available('integer')`, "true"},
		{"type XPath default", `xpath-default-namespace="http://www.w3.org/2001/XMLSchema"`, `type-available('integer')`, "false"},
		{"type distinct defaults", `xmlns="urn:other" xpath-default-namespace="http://www.w3.org/2001/XMLSchema"`, `type-available('integer')`, "false"},
		{"type shadowed xs", `xmlns:xs="urn:other"`, `type-available('xs:integer')`, "false"},
		{"type local alias", `xmlns:p="http://www.w3.org/2001/XMLSchema"`, `type-available('p:integer')`, "true"},
		{"type unbound xsd", "", `type-available('xsd:integer')`, "XTDE1428"},
		{"type EQName", "", `type-available('Q{http://www.w3.org/2001/XMLSchema}integer')`, "true"},
		{"type empty EQName", "", `type-available('Q{}integer')`, "false"},
		{"property local alias", `xmlns:p="http://www.w3.org/1999/XSL/Transform"`, `system-property('p:version')`, "3.0"},
		{"property ignores default", `xmlns="http://www.w3.org/1999/XSL/Transform"`, `system-property('version')`, ""},
		{"property shadowed prefix", `xmlns:p="urn:other"`, `system-property('p:version')`, ""},
		{"function local alias", `xmlns:p="http://www.w3.org/2005/xpath-functions"`, `function-available('p:concat',2)`, "true"},
		{"function shadowed fn", `xmlns:fn="urn:other"`, `function-available('fn:concat',2)`, "false"},
		{"function ignores default", `xmlns="urn:other"`, `function-available('concat',2)`, "true"},
		{"function negative arity", "", `function-available('concat',-1)`, "false"},
		{"function huge arity", "", `function-available('string',999999999999999999999999999999)`, "false"},
		{"function huge variadic arity", "", `function-available('concat',999999999999999999999999999999)`, "true"},
		{"function huge negative arity", "", `function-available('concat',-999999999999999999999999999999)`, "false"},
		{"function wrong arity", "", `function-available('string',3)`, "false"},
		{"function explicit EQName", "", `function-available('Q{http://www.w3.org/2005/xpath-functions}string',1)`, "true"},
		{"function empty EQName", "", `function-available('Q{}string',1)`, "false"},
		{"function prefixed host", `xmlns:p="http://www.w3.org/2005/xpath-functions"`, `p:function-available('p:element-available',1)`, "true"},
		{"function prefixed host wrong arity", "", `function-available('Q{http://www.w3.org/2005/xpath-functions}element-available',2)`, "false"},
		{"function integer conversion", "", `function-available('concat',xs:untypedAtomic('2'))`, "true"},
		{"function noninteger arity", "", `function-available('concat',2.5)`, "XPTY0004"},
		{"function empty arity", "", `function-available('concat',())`, "XPTY0004"},
		{"element padded name", "", `element-available(' xsl:evaluate ')`, "true"},
		{"type padded name", "", `type-available(' xs:integer ')`, "true"},
		{"function padded name", "", `function-available(' string ')`, "true"},
		{"property padded name", "", `system-property(' xsl:version ')`, "3.0"},
		{"element untyped conversion", "", `element-available(xs:untypedAtomic('xsl:evaluate'))`, "true"},
		{"element URI promotion", "", `element-available(xs:anyURI('xsl:evaluate'))`, "true"},
		{"element array atomization", "", `element-available(['xsl:evaluate'])`, "true"},
		{"element function signature", "", `(element-available#1) instance of function(xs:string) as xs:boolean`, "true"},
		{"property function signature", "", `(system-property#1) instance of function(xs:string) as xs:string`, "true"},
		{"availability function signature", "", `(function-available#2) instance of function(xs:string,xs:integer) as xs:boolean`, "true"},
		{"element named reference", `xmlns:p="http://www.w3.org/1999/XSL/Transform"`, `(element-available#1)('p:evaluate')`, "true"},
		{"element lookup reference", `xmlns:p="http://www.w3.org/1999/XSL/Transform"`, `function-lookup(QName('http://www.w3.org/2005/xpath-functions','element-available'),1)('p:evaluate')`, "true"},
	}
	tests := make([]struct{ name, scope, expression, want string }, 0, len(base)+44)
	tests = append(tests, base...)
	for _, local := range []string{"anyType", "anySimpleType", "anyAtomicType", "untyped", "untypedAtomic", "numeric", "error", "dateTimeStamp", "NMTOKENS", "ENTITIES", "IDREFS", "NOTATION"} {
		tests = append(tests, struct{ name, scope, expression, want string }{"builtin type " + local, "", "type-available('xs:" + local + "')", "true"})
	}
	for _, fn := range []struct{ name, code string }{{"element-available", "XTDE1440"}, {"function-available", "XTDE1400"}, {"type-available", "XTDE1428"}, {"system-property", "XTDE1390"}} {
		for _, arg := range []string{"'Q{broken'", "'Q{urn:x}bad:name'", "'missing:name'", "'bad name'", "'Q{urn:{x}}name'"} {
			tests = append(tests, struct{ name, scope, expression, want string }{fn.name + " " + arg, "", fn.name + "(" + arg + ")", fn.code})
		}
		for _, arg := range []string{"()", "42", "('a','b')"} {
			tests = append(tests, struct{ name, scope, expression, want string }{fn.name + " argument " + arg, "", fn.name + "(" + arg + ")", "XPTY0004"})
		}
	}
	return tests
}

func introspectionSheet(scope, expression, want string, static bool) string {
	escaped := strings.NewReplacer("&", "&amp;", "<", "&lt;", "\"", "&quot;").Replace(expression)
	body := `<xsl:value-of select="` + escaped + `"/>`
	if static {
		body = `<xsl:text use-when="string(` + escaped + `) eq '` + want + `'">ok</xsl:text>`
	}
	return sheet(version30, `<xsl:template xmlns:p="urn:outer" name="start"><xsl:for-each `+scope+` select="1">`+body+`</xsl:for-each></xsl:template>`)
}

func TestXSLTIntrospection(t *testing.T) {
	e := engine(t, transform.Config{})
	for _, test := range introspectionCases() {
		for _, static := range []bool{false, true} {
			t.Run(test.name+map[bool]string{true: " static", false: " runtime"}[static], func(t *testing.T) {
				want := test.want
				if static && !comparisonErrorCode(want) {
					want = "ok"
				}
				for _, nested := range []bool{false, true} {
					got, err := resourceStylesheetResult(t, e, introspectionSheet(test.scope, test.expression, test.want, static), nested)
					if comparisonErrorCode(want) {
						var detail *transform.Error
						if !errors.As(err, &detail) || detail.Code != want {
							t.Fatal(nested, got, err, want)
						}
					} else if err != nil || got != want {
						t.Fatal(nested, got, err, want)
					}
				}
			})
		}
	}
}

func introspectionContextCases() []struct{ name, global, body, want string } {
	return []struct{ name, global, body, want string }{
		{"static variable local aliases", `<xsl:variable static="yes" xmlns:p="http://www.w3.org/1999/XSL/Transform" name="v" select="system-property('p:version')"/>`, `<xsl:value-of xmlns:p="urn:other" select="$v"/>`, "3.0"},
		{"static function keeps XML default", `<xsl:variable static="yes" xmlns="http://www.w3.org/1999/XSL/Transform" name="f" select="function(){element-available('evaluate')}"/>`, `<xsl:sequence xmlns="urn:other" select="$f()"/>`, "true"},
		{"static reference keeps prefix", `<xsl:variable static="yes" xmlns:p="http://www.w3.org/1999/XSL/Transform" name="f" select="system-property#1"/>`, `<xsl:sequence xmlns:p="urn:other" select="$f('p:version')"/>`, "3.0"},
		{"shadow attribute context", "", `<xsl:value-of xmlns:p="http://www.w3.org/1999/XSL/Transform" _select="'{system-property('p:version')}'"/>`, "3.0"},
		{"unrelated prefix does not leak", `<xsl:template name="unused" xmlns:leak="http://www.w3.org/1999/XSL/Transform"/>`, `<xsl:sequence select="element-available('leak:evaluate')"/>`, "XTDE1440"},
		{"runtime reference keeps XML default", "", `<xsl:variable xmlns="http://www.w3.org/1999/XSL/Transform" name="f" select="element-available#1"/><xsl:sequence xmlns="urn:other" select="$f('evaluate')"/>`, "true"},
		{"atomic pattern XML default", `<xsl:template xmlns="http://www.w3.org/1999/XSL/Transform" match=".[element-available('evaluate')]">matched</xsl:template>`, `<xsl:apply-templates select="42"/>`, "matched"},
		{"atomic pattern alias", `<xsl:template xmlns:p="http://www.w3.org/1999/XSL/Transform" match=".[element-available('p:evaluate')]">matched</xsl:template>`, `<xsl:apply-templates select="42"/>`, "matched"},
		{"pattern XML default", `<xsl:template xmlns="http://www.w3.org/1999/XSL/Transform" match="r[element-available('evaluate')]">matched</xsl:template>`, `<xsl:apply-templates select="parse-xml('&lt;r/>')/*"/>`, "matched"},
		{"pattern distinct defaults", `<xsl:template xmlns="urn:other" xpath-default-namespace="http://www.w3.org/1999/XSL/Transform" match="*:r[not(element-available('evaluate'))]">matched</xsl:template>`, `<xsl:apply-templates select="parse-xml('&lt;r/>')/*"/>`, "matched"},
		{"runtime lookup keeps prefix", "", `<xsl:variable xmlns:p="http://www.w3.org/1999/XSL/Transform" name="f" select="function-lookup(QName('http://www.w3.org/2005/xpath-functions','system-property'),1)"/><xsl:sequence xmlns:p="urn:other" select="$f('p:version')"/>`, "3.0"},
	}
}

func TestXSLTIntrospectionContexts(t *testing.T) {
	e := engine(t, transform.Config{})
	for _, test := range introspectionContextCases() {
		t.Run(test.name, func(t *testing.T) {
			for _, nested := range []bool{false, true} {
				got, err := resourceStylesheetResult(t, e, sheet(version30, test.global+`<xsl:template name="start">`+test.body+`</xsl:template>`), nested)
				if comparisonErrorCode(test.want) {
					var detail *transform.Error
					if !errors.As(err, &detail) || detail.Code != test.want {
						t.Fatal(nested, got, err, test.want)
					}
				} else if err != nil || got != test.want {
					t.Fatal(nested, got, err, test.want)
				}
			}
		})
	}
}

func mapInstructionCases() []struct{ name, body, check, want string } {
	return []struct{ name, body, check, want string }{
		{"map type host boundary", `<xsl:map-entry key="'a'" select="1"/>`, `$m instance of map(xs:string,xs:integer) and not($m instance of map(xs:integer,xs:integer))`, "true"},
		{"map constructor host boundary", `<xsl:map/>`, `map:size(map{})=0 and deep-equal(map{'a':(1,2)}?a,(1,2)) and map:size(map{'a':()})=1`, "true"},
		{"map constructor empty key", `<xsl:map/>`, `map:size(map{():1})`, "XPTY0004"},
		{"map constructor duplicate key", `<xsl:map/>`, `map:size(map{1:1,1.0:2})`, "XQDY0137"},
		{"unary lookup host boundary", `<xsl:map-entry key="'a'" select="(1,2)"/>`, `deep-equal(($m ! ?a),(1,2)) and empty($m ! ?missing) and deep-equal(($m ! ?*),(1,2))`, "true"},
		{"unary lookup invalid context", `<xsl:map/>`, `1 ! ?a`, "XPTY0004"},
		{"postfix lookup host boundary", `<xsl:map-entry key="'a'" select="(1,2)"/>`, `deep-equal($m?a,(1,2)) and deep-equal($m?('a','a'),(1,2,1,2)) and empty($m?missing) and [10,20]?1=10`, "true"},
		{"postfix lookup invalid context", `<xsl:map/>`, `1?a`, "XPTY0004"},
		{"map same key host boundary", `<xsl:map-entry key="xs:anyURI('a')" select="1"/>`, `map:contains($m,'a') and map:contains($m,xs:untypedAtomic('a')) and not(map:contains($m,'A'))`, "true"},
		{"map merge host boundary", `<xsl:map-entry key="'a'" select="1"/>`, `let $n:=map:merge(($m,map{'a':2,'b':3}),map{'duplicates':'use-last'}) return $n?a=2 and $n?b=3 and $m?a=1`, "true"},
		{"map size host boundary", `<xsl:map-entry key="'a'" select="()"/>`, `map:size($m)=1 and map:size(map{})=0`, "true"},
		{"map keys host boundary", `<xsl:map><xsl:map-entry key="'b'" select="2"/><xsl:map-entry key="'a'" select="1"/></xsl:map>`, `deep-equal(sort(map:keys($m)),('a','b')) and empty(map:keys(map{}))`, "true"},
		{"map contains host boundary", `<xsl:map-entry key="'a'" select="()"/>`, `map:contains($m,'a') and not(map:contains($m,'missing'))`, "true"},
		{"map get host boundary", `<xsl:map-entry key="'a'" select="(1,2)"/>`, `deep-equal(map:get($m,'a'),(1,2)) and empty(map:get($m,'missing'))`, "true"},
		{"map put host boundary", `<xsl:map-entry key="'a'" select="1"/>`, `let $n:=map:put($m,'a',()) return map:contains($n,'a') and empty($n?a) and $m?a=1`, "true"},
		{"map entry host boundary", `<xsl:map/>`, `let $n:=map:entry('a',()) return map:size($n)=1 and map:contains($n,'a') and empty($n?a)`, "true"},
		{"map remove host boundary", `<xsl:map-entry key="'a'" select="1"/>`, `map:size(map:remove($m,('a','missing')))=0 and map:contains($m,'a') and deep-equal(map:remove($m,()),$m)`, "true"},
		{"map for each host boundary", `<xsl:map><xsl:map-entry key="'a'" select="1"/><xsl:map-entry key="'b'" select="2"/></xsl:map>`, `deep-equal(sort(map:for-each($m,function($k,$v){$v*2})),(2,4)) and empty(map:for-each(map{},function($k,$v){$v}))`, "true"},
		{"map find host boundary", `<xsl:map-entry key="'a'" select="1"/>`, `let $r:=map:find(($m,[map{'a':(2,3)}]),'a') return Q{http://www.w3.org/2005/xpath-functions/array}size($r)=2 and deep-equal($r?1,1) and deep-equal($r?2,(2,3)) and empty(map:find($m,'missing')?*)`, "true"},
		{"collation key host boundary", `<xsl:map/>`, `collation-key('A','http://www.w3.org/2005/xpath-functions/collation/html-ascii-case-insensitive') eq collation-key('a','http://www.w3.org/2005/xpath-functions/collation/html-ascii-case-insensitive') and not(collation-key('A') eq collation-key('a'))`, "true"},
		{"deep equal maps host boundary", `<xsl:map-entry key="'a'" select="[1,map{'b':2}]"/>`, `deep-equal($m,map{'a':[1,map{'b':2}]}) and not(deep-equal($m,map{'a':[1,map{'b':3}]}))`, "true"},
		{"empty map", `<xsl:map/>`, `map:size($m)`, "0"},
		{"merge maps", `<xsl:map><xsl:sequence select="map{'a':(1,2)},map{'b':3}"/></xsl:map>`, `deep-equal($m?a,(1,2)) and $m?b eq 3`, "true"},
		{"nested map", `<xsl:map><xsl:map><xsl:map-entry key="'a'" select="42"/></xsl:map></xsl:map>`, `$m?a`, "42"},
		{"entry outside map", `<xsl:map-entry key="'a'" select="42"/>`, `$m?a`, "42"},
		{"entry empty value", `<xsl:map-entry key="'a'"/>`, `map:contains($m,'a') and empty($m?a)`, "true"},
		{"entry node value", `<xsl:map-entry key="'a'"><r>value</r></xsl:map-entry>`, `$m?a instance of element(r) and string($m?a) eq 'value'`, "true"},
		{"entry array key", `<xsl:map-entry key="[['a']]" select="42"/>`, `$m?a`, "42"},
		{"entry node key", `<xsl:map-entry key="parse-xml('&lt;r>a&lt;/r>')/*" select="42"/>`, `$m?a`, "42"},
		{"catch duplicate key", `<xsl:try><xsl:map><xsl:sequence select="map{'a':1},map{'a':2}"/></xsl:map><xsl:catch errors="*:XTDE3365" select="map{'caught':true()}"/></xsl:try>`, `$m?caught`, "true"},
		{"duplicate string", `<xsl:map><xsl:sequence select="map{'a':1},map{'a':2}"/></xsl:map>`, `map:size($m)`, "XTDE3365"},
		{"duplicate numeric", `<xsl:map><xsl:sequence select="map{1:1},map{xs:decimal('1.0'):2}"/></xsl:map>`, `map:size($m)`, "XTDE3365"},
		{"duplicate nan", `<xsl:map><xsl:sequence select="map{xs:double('NaN'):1},map{xs:float('NaN'):2}"/></xsl:map>`, `map:size($m)`, "XTDE3365"},
		{"duplicate untyped", `<xsl:map><xsl:sequence select="map{'a':1},map{xs:untypedAtomic('a'):2}"/></xsl:map>`, `map:size($m)`, "XTDE3365"},
		{"non map atomic", `<xsl:map><xsl:sequence select="1"/></xsl:map>`, `map:size($m)`, "XTTE3375"},
		{"non map node", `<xsl:map><r/></xsl:map>`, `map:size($m)`, "XTTE3375"},
		{"non map text", `<xsl:map>text</xsl:map>`, `map:size($m)`, "XTTE3375"},
		{"non map array", `<xsl:map><xsl:sequence select="[map{}]"/></xsl:map>`, `map:size($m)`, "XTTE3375"},
		{"non map function", `<xsl:map><xsl:sequence select="function(){42}"/></xsl:map>`, `map:size($m)`, "XTTE3375"},
		{"empty key", `<xsl:map-entry key="()" select="42"/>`, `map:size($m)`, "XPTY0004"},
		{"empty array key", `<xsl:map-entry key="[]" select="42"/>`, `map:size($m)`, "XPTY0004"},
		{"multiple key", `<xsl:map-entry key="1,2" select="42"/>`, `map:size($m)`, "XPTY0004"},
		{"multiple array key", `<xsl:map-entry key="[1,2]" select="42"/>`, `map:size($m)`, "XPTY0004"},
		{"map key", `<xsl:map-entry key="map{}" select="42"/>`, `map:size($m)`, "FOTY0013"},
		{"function key", `<xsl:map-entry key="function(){42}" select="42"/>`, `map:size($m)`, "FOTY0013"},
		{"entry select and body", `<xsl:map-entry key="'a'" select="42">body</xsl:map-entry>`, `map:size($m)`, "XTSE3280"},
		{"entry missing key", `<xsl:map-entry select="42"/>`, `map:size($m)`, "XTSE0010"},
	}
}

func mapInstructionSheet(body, check string) string {
	return sheet(version30, `<xsl:template xmlns:map="http://www.w3.org/2005/xpath-functions/map" name="start"><xsl:variable name="m" as="item()*">`+body+`</xsl:variable><xsl:value-of select="`+check+`"/></xsl:template>`)
}

func TestXSLTMapInstructions(t *testing.T) {
	e := engine(t, transform.Config{})
	for _, test := range mapInstructionCases() {
		t.Run(test.name, func(t *testing.T) {
			for _, nested := range []bool{false, true} {
				got, err := resourceStylesheetResult(t, e, mapInstructionSheet(test.body, test.check), nested)
				if comparisonErrorCode(test.want) {
					var detail *transform.Error
					if !errors.As(err, &detail) || detail.Code != test.want {
						t.Fatal(nested, got, err, test.want)
					}
				} else if err != nil || got != test.want {
					t.Fatal(nested, got, err, test.want)
				}
			}
		})
	}
}

type patternSyntaxCase struct {
	dynamicXPathCase
	only30 bool
}

func patternSyntaxCases() []patternSyntaxCase {
	cases := make([]patternSyntaxCase, 0, 89)
	for _, owner := range []struct {
		name, before, after string
		only30              bool
	}{
		{"template", `<xsl:template match="`, `"/>`, false},
		{"named template", `<xsl:template name="unused" match="`, `"/>`, false},
		{"key", `<xsl:key name="k" match="`, `" use="'k'"/>`, false},
		{"number count", `<xsl:template name="unused"><xsl:number count="`, `"/></xsl:template>`, false},
		{"number from", `<xsl:template name="unused"><xsl:number from="`, `"/></xsl:template>`, false},
		{"group starting", `<xsl:template name="unused"><xsl:for-each-group select="()" group-starting-with="`, `"/></xsl:template>`, false},
		{"group ending", `<xsl:template name="unused"><xsl:for-each-group select="()" group-ending-with="`, `"/></xsl:template>`, false},
		{"accumulator", `<xsl:accumulator name="a" initial-value="0"><xsl:accumulator-rule match="`, `" select="$value+1"/></xsl:accumulator>`, true},
	} {
		for _, pattern := range []string{"", " ", "n |", "| n", "n || m", "n | | m", "processing-instruction(p:n)", "{n}", "n[", "n | m"} {
			want := "XTSE0340"
			if pattern == "n | m" {
				want = "ok"
			}
			cases = append(cases, patternSyntaxCase{dynamicXPathCase{owner.name + " " + pattern, owner.before + pattern + owner.after, "ok", want}, owner.only30})
		}
	}
	for _, test := range []dynamicXPathCase{
		{"missing template identity", `<xsl:template/>`, "ok", "XTSE0500"},
		{"named template mode", `<xsl:template name="unused" mode="m"/>`, "ok", "XTSE0500"},
		{"named template priority", `<xsl:template name="unused" priority="1"/>`, "ok", "XTSE0500"},
		{"missing key match", `<xsl:key name="k" use="'k'"/>`, "ok", "XTSE0010"},
		{"empty group-by expression", `<xsl:template name="unused"><xsl:for-each-group select="()" group-by=""/></xsl:template>`, "ok", "XPST0003"},
		{"empty group-adjacent expression", `<xsl:template name="unused"><xsl:for-each-group select="()" group-adjacent=""/></xsl:template>`, "ok", "XPST0003"},
		{"two grouping attributes", `<xsl:template name="unused"><xsl:for-each-group select="()" group-starting-with="" group-ending-with="n"/></xsl:template>`, "ok", "XTSE1080"},
	} {
		cases = append(cases, patternSyntaxCase{test, false})
	}
	cases = append(cases,
		patternSyntaxCase{dynamicXPathCase{"unnamed template visibility", `<xsl:template match="n" visibility="public"/>`, "ok", "XTSE0500"}, true},
		patternSyntaxCase{dynamicXPathCase{"missing accumulator match", `<xsl:accumulator name="a" initial-value="0"><xsl:accumulator-rule select="$value+1"/></xsl:accumulator>`, "ok", "XTSE0010"}, true})
	return cases
}

func TestXSLTPatternSyntaxContracts(t *testing.T) {
	e := engine(t, transform.Config{})
	for _, test := range patternSyntaxCases() {
		t.Run(test.name, func(t *testing.T) {
			for _, version := range []string{version20, version30} {
				if version == version20 && test.only30 {
					continue
				}
				source := sheet(version, test.global+`<xsl:template name="start">`+test.body+`</xsl:template>`)
				if version == version20 {
					_, err := e.CompileXSLT(t.Context(), []byte(source), transform.XSLTOptions{ProcessorVersion: transform.XSLT20})
					if test.want == "ok" {
						if err != nil {
							t.Fatal("2.0 processor", err)
						}
					} else {
						var detail *transform.Error
						if !errors.As(err, &detail) || detail.Code != test.want {
							t.Fatal("2.0 processor", err, test.want)
						}
					}
				}
				for _, nested := range []bool{false, true} {
					got, err := resourceStylesheetResult(t, e, source, nested)
					if test.want == "ok" {
						if err != nil || got != test.want {
							t.Fatal(version, nested, got, err)
						}
					} else {
						var detail *transform.Error
						if !errors.As(err, &detail) || detail.Code != test.want {
							t.Fatal(version, nested, got, err, test.want)
						}
					}
				}
			}
		})
	}
}

type versionedPatternCase struct {
	pattern, want20, want30 string
}

func versionedPatternCases() []versionedPatternCase {
	return []versionedPatternCase{
		{"n | m", "ok", "ok"},
		{"union | intersect | except", "ok", "ok"},
		{"n union m", "XTSE0340", "ok"},
		{"(n)", "XTSE0340", "ok"},
		{"(n | m)", "XTSE0340", "ok"},
		{"n/(m | r)", "XTSE0340", "ok"},
		{"(: comment with ( and union :) n", "ok", "ok"},
		{"n[(m | r)[true()]]", "ok", "ok"},
		{"n[m union r]", "ok", "ok"},
		{"n[@a = '(union)']", "ok", "ok"},
		{"n[generate-id() = generate-id(.)]", "ok", "ok"},
		{"child::n/attribute::a", "ok", "ok"},
		{"n//@a", "ok", "ok"},
		{"descendant::n", "XTSE0340", "ok"},
		{"self::n", "XTSE0340", "ok"},
		{"parent::n", "XTSE0340", "XTSE0340"},
		{"n[parent::m]", "ok", "ok"},
		{"id('n')", "ok", "ok"},
		{"id($v)//n", "ok", "ok"},
		{"key('k', $v)//n", "ok", "ok"},
		{"key('k', 1)/n", "ok", "ok"},
		{"key('k', 'n')[true()]", "XTSE0340", "ok"},
		{"key($v, 'n')", "XTSE0340", "ok"},
		{"key('k', string($v))", "XTSE0340", "XTSE0340"},
		{"id('n', $nodes)", "XTSE0340", "ok"},
		{"fn:id('n')", "XTSE0340", "ok"},
		{"$nodes", "XTSE0340", "ok"},
		{"$nodes/n", "XTSE0340", "ok"},
		{"doc('input.xml')/n", "XTSE0340", "ok"},
		{"root()/n", "XTSE0340", "ok"},
	}
}

func versionedPatternSheet(version, pattern string) string {
	return sheet(version, `<xsl:variable name="v" select="'n'"/><xsl:variable name="nodes"><n/></xsl:variable><xsl:key name="k" match="n" use="@id"/><xsl:template xmlns:fn="http://www.w3.org/2005/xpath-functions" match="`+pattern+`"/><xsl:template name="start">ok</xsl:template>`)
}

func TestXSLTPatternVersions(t *testing.T) {
	e := engine(t, transform.Config{})
	for _, test := range versionedPatternCases() {
		t.Run(test.pattern, func(t *testing.T) {
			for _, version := range []struct {
				name      string
				processor transform.XSLTVersion
				want      string
			}{
				{version20, transform.XSLT20, test.want20},
				{version30, transform.XSLT30, test.want30},
			} {
				_, err := e.CompileXSLT(t.Context(), []byte(versionedPatternSheet(version.name, test.pattern)), transform.XSLTOptions{ProcessorVersion: version.processor})
				if version.want == "ok" {
					if err != nil {
						t.Fatal(version.name, err)
					}
				} else {
					var detail *transform.Error
					if !errors.As(err, &detail) || detail.Code != version.want {
						t.Fatal(version.name, err, version.want)
					}
				}
			}
		})
	}
}

func unionPatternCases() []dynamicXPathCase {
	cases := make([]dynamicXPathCase, 0, 19)
	for _, pattern := range []string{
		"n | r/m", "n union r/m", "(n | r/m)", "((n union r/m))",
		"(: leading :) (n union r/m) (: trailing :)",
		"n (: quote ' :) | r/m", `n (: quote " :) | r/m`,
		"n (: outer (: ' | :) :) union r/m",
	} {
		cases = append(cases, dynamicXPathCase{pattern, `<xsl:template match="n[@special]">specific</xsl:template><xsl:template match="` + strings.ReplaceAll(pattern, `"`, `&quot;`) + `">union</xsl:template>`, `<xsl:apply-templates select="parse-xml('&lt;r>&lt;n special=&quot;yes&quot;/>&lt;/r>')/r/n"/>`, "specific"})
	}
	cases = append(cases,
		dynamicXPathCase{"EQName URI pipe", `<xsl:template match="*:n[@special]">specific</xsl:template><xsl:template match="Q{urn:pipe|binding}n | r/m">union</xsl:template>`, `<xsl:apply-templates select="parse-xml('&lt;n xmlns=&quot;urn:pipe|binding&quot; special=&quot;yes&quot;/>')/*"/>`, "specific"},
		dynamicXPathCase{"union element name", `<xsl:template match="union[@special]">specific</xsl:template><xsl:template match="union union r/m">union</xsl:template>`, `<xsl:apply-templates select="parse-xml('&lt;union special=&quot;yes&quot;/>')/*"/>`, "specific"},
		dynamicXPathCase{"union axis step name", `<xsl:template match="r/union[@special]">specific</xsl:template><xsl:template match="r/union union m/k">union</xsl:template>`, `<xsl:apply-templates select="parse-xml('&lt;r>&lt;union special=&quot;yes&quot;/>&lt;/r>')/r/union"/>`, "union"},
		dynamicXPathCase{"explicit priority", `<xsl:template match="n[@special]">specific</xsl:template><xsl:template match="n union r/m" priority="1">union</xsl:template>`, `<xsl:apply-templates select="parse-xml('&lt;n special=&quot;yes&quot;/>')/*"/>`, "union"},
		dynamicXPathCase{"predicate union remains inside predicate", `<xsl:template match="n[@special]">specific</xsl:template><xsl:template match="n[. union child::m] | r/m">union</xsl:template>`, `<xsl:apply-templates select="parse-xml('&lt;n special=&quot;yes&quot;/>')/*"/>`, "union"},
		dynamicXPathCase{"parenthesized predicate operand retains priority", `<xsl:template match="n[@special]">specific</xsl:template><xsl:template match="(n | r/m)[true()]">union</xsl:template>`, `<xsl:apply-templates select="parse-xml('&lt;n special=&quot;yes&quot;/>')/*"/>`, "union"},
		dynamicXPathCase{"unterminated union comment", `<xsl:template match="n (: missing |"/>`, "ok", "XTSE0340"},
		dynamicXPathCase{"unterminated EQName URI", `<xsl:template match="Q{urn:missing|"/>`, "ok", "XTSE0340"},
		dynamicXPathCase{"explicit filtered union priority", `<xsl:template match="n[@special]">specific</xsl:template><xsl:template match="(n | r/m)[true()]" priority="2">union</xsl:template>`, `<xsl:apply-templates select="parse-xml('&lt;n special=&quot;yes&quot;/>')/*"/>`, "union"},
		dynamicXPathCase{"dynamic filtered union priority", `<xsl:template match="n[@special]">specific</xsl:template><xsl:template match="(n | r/m)[@special]">union</xsl:template>`, `<xsl:apply-templates select="parse-xml('&lt;n special=&quot;yes&quot;/>')/*"/>`, "union"},
		dynamicXPathCase{"empty union rejected", `<xsl:template match="(n union)"/>`, "ok", "XTSE0340"})
	return cases
}

func TestXSLTUnionPatternPriorities(t *testing.T) {
	e := engine(t, transform.Config{})
	for _, test := range unionPatternCases() {
		t.Run(test.name, func(t *testing.T) {
			for _, nested := range []bool{false, true} {
				got, err := resourceStylesheetResult(t, e, dynamicXPathSheet(test), nested)
				if test.want == "XTSE0340" {
					var detail *transform.Error
					if !errors.As(err, &detail) || detail.Code != test.want {
						t.Fatal(nested, got, err, test.want)
					}
				} else if err != nil || got != test.want {
					t.Fatal(nested, got, err, test.want)
				}
			}
		})
	}
}

func defaultPriorityCases() []dynamicXPathCase {
	const element = `parse-xml('&lt;r>&lt;n special=&quot;yes&quot;/>&lt;/r>')/r/n`
	const namespaced = `parse-xml('&lt;p:n xmlns:p=&quot;urn:p&quot;/>')/*`
	const attribute = `parse-xml('&lt;r a=&quot;v&quot;/>')/r/@a`
	const doc = `parse-xml('&lt;n/>')`
	const pi = `parse-xml('&lt;r>&lt;?p v?>&lt;/r>')/r/processing-instruction()`
	cases := make([]dynamicXPathCase, 0, 74)
	for _, test := range []struct{ pattern, baseline, selectExpr, lower, higher string }{
		{".", ".", element, "-1.1", "-0.9"},
		{".", ".", "7", "-1.1", "-0.9"},
		{".[true()]", ".", element, "0.9", "1.1"},
		{".[true()][true()][true()]", ".", element, "0.9", "1.1"},
		{".[true()]", ".", "7", "0.9", "1.1"},
		{"n intersect *", "n", element, "-0.1", "0.1"},
		{"* intersect n", "n", element, "-0.6", "-0.4"},
		{"n except m", "n", element, "-0.1", "0.1"},
		{"* except m", "n", element, "-0.6", "-0.4"},
		{"n", "n", element, "-0.1", "0.1"},
		{"*", "n", element, "-0.6", "-0.4"},
		{"p:*", "*", namespaced, "-0.3", "-0.2"},
		{"*:n", "*", namespaced, "-0.3", "-0.2"},
		{"element(n)", "n", element, "-0.1", "0.1"},
		{"element()", "n", element, "-0.6", "-0.4"},
		{"element(*)", "n", element, "-0.6", "-0.4"},
		{"element(*,xs:untyped)", "n", element, "-0.1", "0.1"},
		{"element(n,xs:untyped)", "n", element, "0.2", "0.3"},
		{"attribute(a)", "@*", attribute, "-0.1", "0.1"},
		{"attribute()", "@*", attribute, "-0.6", "-0.4"},
		{"attribute(*,xs:untypedAtomic)", "@*", attribute, "-0.1", "0.1"},
		{"attribute(a,xs:untypedAtomic)", "@*", attribute, "0.2", "0.3"},
		{"document-node()", "/", doc, "-0.6", "-0.4"},
		{"document-node(element(n))", "/", doc, "-0.1", "0.1"},
		{"document-node(element(n,xs:untyped))", "/", doc, "0.2", "0.3"},
		{"processing-instruction('p')", "processing-instruction()", pi, "-0.1", "0.1"},
		{"processing-instruction()", "processing-instruction()", pi, "-0.6", "-0.4"},
		{"processing-instruction(p)", "processing-instruction()", pi, "-0.1", "0.1"},
		{"comment()", "node()", `parse-xml('&lt;r>&lt;!--x-->&lt;/r>')/r/comment()`, "-0.6", "-0.4"},
		{"text()", "node()", `parse-xml('&lt;r>x&lt;/r>')/r/text()`, "-0.6", "-0.4"},
		{"node()", "*", element, "-0.6", "-0.4"},
		{"namespace-node()", "namespace-node()", `parse-xml('&lt;r xmlns:p=&quot;urn:p&quot;/>')/r/namespace::p`, "-0.6", "-0.4"},
		{"@*", "@*", attribute, "-0.6", "-0.4"},
		{"document-node(element(*,xs:untyped))", "/", doc, "-0.1", "0.1"},
		{"document-node(element(*))", "/", doc, "-0.6", "-0.4"},
		{"r/n", "n", element, "0.4", "0.6"},
		{"n[@special]", "n", element, "0.4", "0.6"},
	} {
		for _, priority := range []string{test.lower, test.higher} {
			want := "candidate"
			if priority == test.higher {
				want = "baseline"
			}
			global := `<xsl:template match="` + test.baseline + `" priority="` + priority + `">baseline</xsl:template><xsl:template xmlns:p="urn:p" match="` + test.pattern + `">candidate</xsl:template>`
			cases = append(cases, dynamicXPathCase{test.pattern + " " + priority + " " + test.selectExpr, global, `<xsl:apply-templates select="` + test.selectExpr + `"/>`, want})
		}
	}
	return cases
}

func TestXSLTDefaultPatternPriorities(t *testing.T) {
	e := engine(t, transform.Config{})
	for _, test := range defaultPriorityCases() {
		t.Run(test.name, func(t *testing.T) {
			for _, nested := range []bool{false, true} {
				got, err := resourceStylesheetResult(t, e, dynamicXPathSheet(test), nested)
				if err != nil || got != test.want {
					t.Fatal(nested, got, err, test.want)
				}
			}
		})
	}
}

type inputPreprocessingCase struct {
	name, globals, template, context, selection, want string
}

func inputPreprocessingCases() []inputPreprocessingCase {
	return []inputPreprocessingCase{
		{"orphan global tree", "", `concat(root(.) instance of element(),':',count(.//text()),':',base-uri(.))`, `$orphan`, "", "true:0:https://example.test/sources/main.xsl"},
		{"orphan selection tree", "", `concat(root(.) instance of element(),':',count(.//text()),':',base-uri(.))`, `$a`, `$orphan`, "true:0:https://example.test/sources/main.xsl"},
		{"computed global tree", "", `concat(root(.) instance of element(),':',count(.//text()),':',base-uri(.))`, `$computed`, "", "true:0:https://example.test/sources/main.xsl"},
		{"computed selection tree", "", `concat(root(.) instance of element(),':',count(.//text()),':',base-uri(.))`, `$a`, `$computed`, "true:0:https://example.test/sources/main.xsl"},
		{"global document", "", `count(.//text())`, `$a`, "", "0"},
		{"global element", "", `count(root(.)//text())`, `$a/r/a`, "", "0"},
		{"global attribute", "", `count(root(.)//text())`, `$a/r/@id`, "", "0"},
		{"global namespace", "", `count(root(.)//text())`, `$namespace($a)`, "", "0"},
		{"global stripped text", `<xsl:variable name="global" select="."/>`, `$global`, `$a/r/text()[1]`, "", "XPDY0002"},
		{"global required stripped text", `<xsl:global-context-item use="required"/>`, `42`, `$a/r/text()[1]`, "", "XTDE3086"},
		{"global preserved text", "", `count(root(.)//text())`, `$b/r/keep/text()`, "", "1"},
		{"different selection document", "", `count(root(.)//text())`, `$a`, `$b/r/a`, "1"},
		{"two selection documents", "", `concat(count(root(.)//text()),':',position(),':',last(),'|')`, `$a`, `($a/r/a,$b/r/a,$a/r/a)`, "0:1:3|1:2:3|0:3:3|"},
		{"stripped selection focus", "", `concat(local-name(),':',position(),':',last(),'|')`, `$a`, `($a/r/text()[1],$a/r/a,$b/r/text()[1],$b/r/a)`, "a:1:2|a:2:2|"},
		{"empty stripped selection", "", `42`, `$a`, `($a/r/text()[1],$b/r/text()[1])`, ""},
		{"global and selection identity", `<xsl:variable name="global" select="."/>`, `. is $global`, `$b/r/a`, `($b/r/a,$b/r/a)`, "truetrue"},
		{"selected attributes", "", `concat(count(root(.)//text()),':',name())`, `$a`, `$b/r/@id`, "1:id"},
		{"selected namespaces", "", `concat(count(root(.)//text()),':',name())`, `$a`, `$namespace($b)`, "1:p"},
	}
}

func inputPreprocessingSource(test inputPreprocessingCase) string {
	return sheet(version30, `<xsl:strip-space elements="*"/><xsl:preserve-space elements="keep"/>`+test.globals+`<xsl:template name="start" match="."><xsl:value-of select="`+test.template+`"/></xsl:template>`)
}

const preprocessingInputs = `let $make-tree := function($body) {transform(map{'stylesheet-text':concat('<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xml:base="https://example.test/sources/main.xsl" version="3.0"><xsl:template name="start">',$body,'</xsl:template></xsl:stylesheet>'),'stylesheet-base-uri':'https://example.test/sources/main.xsl','base-output-uri':'https://example.test/sources/main.xsl','initial-template':QName('', 'start'),'delivery-format':'raw'})('https://example.test/sources/main.xsl')}, $orphan := $make-tree('<r><xsl:text> </xsl:text><a/><xsl:text> </xsl:text></r>'), $computed := $make-tree('<xsl:element name="r"><xsl:text> </xsl:text><a/><xsl:text> </xsl:text></xsl:element>'), $a := parse-xml('<r xmlns:p="urn:p" id="a"> <a/> </r>'), $b := parse-xml('<r xmlns:p="urn:p" id="b"> <a/> <keep xml:space="preserve"> </keep> </r>'), $namespace := function($doc) { transform(map{'stylesheet-text':'<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="3.0"><xsl:template match="/"><xsl:sequence select="*/namespace::p"/></xsl:template></xsl:stylesheet>','source-node':$doc,'delivery-format':'raw'})?output } `

func inputPreprocessingExpression(test inputPreprocessingCase) string {
	entry := `,'initial-template':QName('', 'start')`
	if test.selection != "" {
		entry = `,'initial-match-selection':` + test.selection
	}
	return preprocessingInputs + `return transform(map{'stylesheet-text':'` + strings.ReplaceAll(inputPreprocessingSource(test), "'", "''") + `','global-context-item':` + test.context + entry + `,'delivery-format':'serialized'})?output`
}

func TestXSLTInputPreprocessing(t *testing.T) {
	e := engine(t, transform.Config{})
	for _, test := range inputPreprocessingCases() {
		t.Run(test.name, func(t *testing.T) {
			compiled := stylesheet(t, e, inputPreprocessingSource(test))
			item := evaluate(t, e, preprocessingInputs+`return `+test.context, transform.XPath31)
			global, err := item.Single()
			if err != nil {
				t.Fatal(err)
			}
			options := transform.XSLTContext{ContextItem: &global, ResultMode: transform.ResultDocument}
			var result *transform.Result
			if test.selection == "" {
				result, err = compiled.CallTemplate(t.Context(), nil, transform.Name{Local: nameStart}, options)
			} else {
				// One evaluation preserves the identity shared by context and selection.
				bindings := evaluate(t, e, preprocessingInputs+`return map{'context':`+test.context+`,'selection':`+test.selection+`}`, transform.XPath31)
				values := transform.XPathContext{Variables: transform.Bindings{{Local: "inputs"}: bindings}}
				contextValue, evalErr := query(t, e, `$inputs?context`, transform.XPath31).Evaluate(t.Context(), nil, values)
				if evalErr != nil {
					t.Fatal(evalErr)
				}
				global, err = contextValue.Single()
				if err != nil {
					t.Fatal(err)
				}
				selection, evalErr := query(t, e, `$inputs?selection`, transform.XPath31).Evaluate(t.Context(), nil, values)
				if evalErr != nil {
					t.Fatal(evalErr)
				}
				result, err = compiled.ApplyTemplates(t.Context(), nil, selection, options)
			}
			if comparisonErrorCode(test.want) {
				var detail *transform.Error
				if !errors.As(err, &detail) || detail.Code != test.want {
					t.Fatal(result, err, test.want)
				}
			} else if err != nil || text(t, result.Primary()) != test.want {
				t.Fatal(result, err, test.want)
			}
			value, err := query(t, e, inputPreprocessingExpression(test), transform.XPath31).Evaluate(t.Context(), nil, transform.XPathContext{})
			if comparisonErrorCode(test.want) {
				var detail *transform.Error
				if !errors.As(err, &detail) || detail.Code != test.want {
					t.Fatal("fn:transform", value, err, test.want)
				}
			} else if err != nil || text(t, value) != test.want {
				t.Fatal("fn:transform", value, err, test.want)
			}
		})
	}
}

type transformExpressionCase struct{ name, expression, want string }

func transformNodeContextCases() []transformExpressionCase {
	cases := make([]transformExpressionCase, 0, 14)
	for _, selection := range []string{`$a`, `$a/r`, `$a/r/@id`, `$namespace($a)`, `42`, `map{}`, `[]`, `string#1`} {
		program := sheet(version30, `<xsl:variable name="global" select="."/><xsl:template match="."><xsl:value-of select="$global"/></xsl:template>`)
		cases = append(cases, transformExpressionCase{"selection " + selection, preprocessingInputs + `return transform(map{'stylesheet-text':'` + strings.ReplaceAll(program, "'", "''") + `','initial-match-selection':` + selection + `,'delivery-format':'serialized'})?output`, "XPDY0002"})
	}
	for _, test := range []struct{ name, global, options, want string }{
		{"required selection context", `<xsl:global-context-item use="required"/><xsl:variable name="global" select="42"/>`, `'initial-match-selection':$a`, "XTDE3086"},
		{"explicit selection context", `<xsl:variable name="global" select="."/>`, `'initial-match-selection':$a,'global-context-item':42`, "42"},
		{"source document root", `<xsl:variable name="global" select=". instance of document-node()"/>`, `'source-node':$a/r/a`, nameTrue},
		{"source namespace root", `<xsl:variable name="global" select=". instance of document-node()"/>`, `'source-node':$namespace($a)`, nameTrue},
		{"parentless source root", `<xsl:variable name="global" select=". instance of element()"/>`, `'source-node':$orphan`, nameTrue},
		{"explicit source context", `<xsl:variable name="global" select="."/>`, `'source-node':$a/r/a,'global-context-item':42`, "42"},
	} {
		program := sheet(version30, test.global+`<xsl:template match="."><xsl:value-of select="$global"/></xsl:template>`)
		cases = append(cases, transformExpressionCase{test.name, preprocessingInputs + `return transform(map{'stylesheet-text':'` + strings.ReplaceAll(program, "'", "''") + `',` + test.options + `,'delivery-format':'serialized'})?output`, test.want})
	}
	return cases
}

func transformStylesheetNodeCases() []transformExpressionCase {
	const uri = "https://example.test/modules/"
	const stylesheetHeader = `<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="3.0"`
	const stylesheetBody = `><xsl:output method="text"/><xsl:template name="start"><xsl:value-of select="static-base-uri()"/></xsl:template></xsl:stylesheet>`
	cases := make([]transformExpressionCase, 0, 5)
	for _, test := range []struct{ name, input, selection, want string }{
		{"document node", stylesheetHeader + ` xml:base="` + uri + `main.xsl"` + stylesheetBody, `$module`, uri + "main.xsl"},
		{"root element", stylesheetHeader + ` xml:base="` + uri + `main.xsl"` + stylesheetBody, `$module/*`, uri + "main.xsl"},
		{"root relative base", `<wrapper xml:base="` + uri + `">` + stylesheetHeader + ` xml:base="inner/"` + stylesheetBody + `</wrapper>`, `$module/*/*`, uri + "inner/"},
		{"inherited base", `<wrapper xml:base="` + uri + `outer/">` + stylesheetHeader + stylesheetBody + `</wrapper>`, `$module/*/*`, uri + "outer/"},
	} {
		expression := `let $module := parse-xml('` + strings.ReplaceAll(test.input, "'", "''") + `') return transform(map{'stylesheet-node':` + test.selection + `,'initial-template':QName('', 'start'),'delivery-format':'serialized'})?output`
		cases = append(cases, transformExpressionCase{test.name, expression, test.want})
	}
	for _, standard := range []bool{false, true} {
		kind := "simplified"
		if standard {
			kind = "standard"
		}
		for _, policy := range []struct {
			name, outer, own string
			length           int
		}{
			{"inherited preserve", "preserve", "", 1},
			{"own default", "preserve", `xml:space="default"`, 0},
			{"own preserve", "default", `xml:space="preserve"`, 1},
			{"inherited default", "default", "", 0},
		} {
			module := `<out xsl:version="3.0" ` + policy.own + `> </out>`
			if standard {
				module = `<xsl:stylesheet version="3.0" ` + policy.own + `><xsl:template match="/"><out> </out></xsl:template></xsl:stylesheet>`
			}
			input := `<wrapper xml:space="` + policy.outer + `" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">` + module + `</wrapper>`
			attributes := 0
			if !standard && policy.own != "" {
				attributes = 1
			}
			expression := `let $module := parse-xml('` + strings.ReplaceAll(input, "'", "''") + `'), $before := serialize($module),
                $out := transform(map{'stylesheet-node':$module/*/*,'source-node':parse-xml('<r/>')})?output
                return string-length($out) eq ` + strconv.Itoa(policy.length) + ` and serialize($module) eq $before
                and count($out/*/@xml:space) eq ` + strconv.Itoa(attributes)
			cases = append(cases, transformExpressionCase{"embedded " + kind + " " + policy.name, expression, nameTrue})
		}
	}

	generator := sheet(version30, `<xsl:template name="start"><xsl:element name="xsl:stylesheet"><xsl:attribute name="version">3.0</xsl:attribute><xsl:attribute name="xml:base">`+uri+`generated.xsl</xsl:attribute><xsl:element name="xsl:output"><xsl:attribute name="method">text</xsl:attribute></xsl:element><xsl:element name="xsl:template"><xsl:attribute name="name">start</xsl:attribute><xsl:element name="xsl:value-of"><xsl:attribute name="select">static-base-uri()</xsl:attribute></xsl:element></xsl:element></xsl:element></xsl:template>`)
	expression := `let $module := transform(map{'stylesheet-text':'` + strings.ReplaceAll(generator, "'", "''") + `','initial-template':QName('', 'start'),'delivery-format':'raw'})?output return transform(map{'stylesheet-node':$module,'initial-template':QName('', 'start'),'delivery-format':'serialized'})?output`
	cases = append(cases, transformExpressionCase{"parentless module", expression, uri + "generated.xsl"})
	return cases
}

func TestTransformNodeContexts(t *testing.T) {
	e := engine(t, transform.Config{})
	for _, test := range append(transformNodeContextCases(), transformStylesheetNodeCases()...) {
		t.Run(test.name, func(t *testing.T) {
			value, err := query(t, e, test.expression, transform.XPath31).Evaluate(t.Context(), nil, transform.XPathContext{})
			if comparisonErrorCode(test.want) {
				var detail *transform.Error
				if !errors.As(err, &detail) || detail.Code != test.want {
					t.Fatal(value, err, test.want)
				}
			} else if err != nil || text(t, value) != test.want {
				t.Fatal(value, err, test.want)
			}
		})
	}
}

func TestTransformStylesheetNodeKinds(t *testing.T) {
	e := engine(t, transform.Config{})
	program := sheet(version30, `<xsl:template name="start"><!--comment--><?pi value?><xsl:text>ok</xsl:text></xsl:template>`)
	for _, selection := range []string{`$module/*/*/comment()`, `$module/*/*/processing-instruction()`, `$module/*/*/*/text()`, `$module/*/@version`, `$module/*/namespace::xsl`} {
		expression := `let $module := parse-xml('` + program + `') return transform(map{'stylesheet-node':` + selection + `,'initial-template':QName('', 'start')})`
		_, err := query(t, e, expression, transform.XPath31).Evaluate(t.Context(), nil, transform.XPathContext{})
		var detail *transform.Error
		if !errors.As(err, &detail) || detail.Code != "FOXT0002" {
			t.Fatal(selection, err)
		}
	}
}
