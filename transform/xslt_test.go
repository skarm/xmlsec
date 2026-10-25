package transform_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/skarm/xmlsec/transform"
)

const nameKept = "kept"

const variableURI = "uri"

const transformSerializedQuery = `transform(map{'stylesheet-text': $stylesheet, 'initial-template': QName('', 'start'), 'delivery-format': 'serialized'})?output`

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
		{`transform(map{'stylesheet-text':$stylesheet,'xslt-version':2})`, errCodeFOXT0001},
		{`transform(map{'stylesheet-text':$stylesheet, 'initial-template':QName('', 'missing')})`, "XTDE0040"},
		{`transform(map{'stylesheet-text':$invalid})`, errCodeXPST0003},
		{`transform(map{'stylesheet-text':$stylesheet})`, "XTDE0040"},
		{`transform(map{'stylesheet-text':$required,'initial-template':QName('', 'start')})`, "XTDE0700"},
		{`transform(map{'stylesheet-text':$application,'initial-template':QName('', 'start')})`, applicationErrorLocal},
		{`transform(map{'stylesheet-text':$stylesheet,'requested-properties':map{QName('http://www.w3.org/1999/XSL/Transform','supports-streaming'):true()}})`, errCodeFOXT0001},
	} {
		result, err := query(t, e, test.expression, transform.XPath31).Evaluate(t.Context(), nil, transform.XPathContext{Variables: transform.Bindings{
			{Local: variableStylesheet}: transform.Values(transform.String(sheet(version30, `<xsl:template name="start"/>`))),
			{Local: "invalid"}:          transform.Values(transform.String(sheet(version30, `<xsl:template name="start"><xsl:sequence select="1 +"/></xsl:template>`))),
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
			if err != nil || text(t, values) != "true" {
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
	if err != nil || !strings.Contains(string(out.Primary), "\u00a0") {
		t.Errorf("indentation lost significant non-XML whitespace: %q, %v", out.Primary, err)
	}
}

func TestXSLTVersionBoundaries(t *testing.T) {
	e := engine(t, transform.Config{})
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

	for _, version := range []string{"0.9", "4.0"} {
		if _, err := e.CompileXSLT(context.Background(), []byte(sheet(version, `<xsl:template match="/"/>`)), transform.XSLTOptions{}); !errors.Is(err, transform.ErrUnsupported) {
			t.Fatal(err)
		}
	}

	for _, body := range []string{`<xsl:import-schema namespace="urn:x"/>`, `<xsl:mode streamable="yes"/>`} {
		if _, err := e.CompileXSLT(context.Background(), []byte(sheet(version30, body)), transform.XSLTOptions{}); !errors.Is(err, transform.ErrUnsupported) {
			t.Fatal(err)
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
		{"modern grammar with 1.0 compatibility", "1.0", `<xsl:value-of select="(10, 20)"/><xsl:value-of version="3.0" select="(30, 40)"/>`, compatSequenceText, transform.XSLT30},
		{"2.0 grammar with 1.0 compatibility", "1.0", `<xsl:value-of select="(10, 20)"/><xsl:value-of version="2.0" select="(30, 40)"/>`, compatSequenceText, transform.XSLT20},
		{"local compatibility in 2.0", version20, `<xsl:value-of version="1.0" select="(10, 20)"/><xsl:value-of select="(30, 40)"/>`, compatSequenceText, transform.XSLT20},
		{"3.0 processor introspection", version20, `<xsl:value-of select="system-property('xsl:version')"/><xsl:text>:</xsl:text><xsl:value-of select="element-available('xsl:iterate')"/>`, "3.0:true", transform.XSLT30},
		{"2.0 processor introspection", version20, `<xsl:value-of select="system-property('xsl:version')"/><xsl:text>:</xsl:text><xsl:value-of select="element-available('xsl:iterate')"/>`, "2.0:false", transform.XSLT20},
		{"2.0 function library", version20, `<xsl:value-of xmlns:fn="http://www.w3.org/2005/xpath-functions" select="function-available('json-doc', 1), function-available('current-output-uri', 0), function-available('fn:current-output-uri', 0)"/>`, "false false false", transform.XSLT20},
		{"3.0 function library", version20, `<xsl:value-of xmlns:fn="http://www.w3.org/2005/xpath-functions" select="function-available('json-doc', 1), function-available('current-output-uri', 0), function-available('fn:current-output-uri', 0)"/>`, "true true true", transform.XSLT30},
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

	for _, instruction := range []string{nameInclude, "import"} {
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

	if !strings.Contains(string(out.Primary), `<out>2</out>`) {
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

	for _, version := range []string{valueNaN, nameInfinity, "INF"} {
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
