package transform_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"

	"github.com/skarm/xmlsec/transform"
)

const (
	errCodeSENR0001      = "SENR0001"
	serializationXML     = "xml"
	serializationHTML    = "html"
	serializationUTF8    = "UTF-8"
	serializationJSON    = "json"
	serializationText    = "text"
	serializationNull    = "null"
	serializationNodeXML = `<p>text</p>`
	errCodeSERE0020      = "SERE0020"
	errCodeSERE0021      = "SERE0021"
	errCodeSERE0022      = "SERE0022"
	errCodeSERE0023      = "SERE0023"
	errCodeSEPM0016      = "SEPM0016"
	errCodeSEPM0017      = "SEPM0017"
	errCodeSEPM0018      = "SEPM0018"
	errCodeSEPM0019      = "SEPM0019"
)

// TestStreamingSequenceAdjacency checks that atomic values are joined before
// document children are expanded.
// See https://www.w3.org/TR/xslt-xquery-serialization-31/#serdm.
func TestStreamingSequenceAdjacency(t *testing.T) {
	e := engine(t, transform.Config{})

	cases := []struct{ body, want string }{
		{`<xsl:sequence select="('a','','b')"/><xsl:sequence select="''"/><xsl:sequence select="'c'"/>`, "a  b  c"},
		{`<xsl:sequence select="'a'"/><xsl:document/><xsl:sequence select="'b'"/>`, "ab"},
		{`<xsl:sequence select="'a'"/><xsl:text/><xsl:sequence select="'b'"/>`, "ab"},
		{`<xsl:variable name="v"><a/><xsl:sequence select="('one','two')"/><b/></xsl:variable><xsl:value-of select="$v"/>`, "one two"},
	}
	for _, tc := range cases {
		s := stylesheet(t, e, sheet(version30, `<xsl:template name="start">`+tc.body+`</xsl:template>`))

		out, err := s.Transform(context.Background(), nil, transform.XSLTContext{Template: transform.Name{Local: nameStart}})
		if err != nil {
			t.Fatal(err)
		}

		if got := string(out.Primary); got != tc.want {
			t.Fatalf("%s: got %q, want %q", tc.body, got, tc.want)
		}
	}
}

func BenchmarkSerializationStreaming(b *testing.B) {
	cases := []struct{ method, encoding string }{
		{serializationXML, serializationUTF8},
		{serializationHTML, serializationUTF8},
		{serializationJSON, serializationUTF8},
		{serializationText, serializationUTF8},
		{serializationXML, "UTF-16"},
		{serializationHTML, xmlLatinEncoding},
	}
	for _, tc := range cases {
		for _, content := range []string{"plain", "escaped"} {
			for _, size := range []int{16 << 10, 1 << 20} {
				b.Run(fmt.Sprintf("%s/%s/%s/%d", tc.method, serializationEncoding(tc.encoding), content, size), func(b *testing.B) {
					payload := serializationPayload(tc.method, content, size)
					result := serializationFixture(b, tc.method, tc.encoding, payload)
					benchmarkSerializationResult(b, result, size)
				})
			}
		}
	}
}

// BenchmarkNormalizationStreaming measures requested NFC over resident results.
// Compilation and result construction are excluded from serialization timings.
func BenchmarkNormalizationStreaming(b *testing.B) {
	for _, method := range []string{serializationXML, serializationHTML, serializationText} {
		for _, size := range []int{16 << 10, 1 << 20} {
			b.Run(fmt.Sprintf("%s/%d", method, size), func(b *testing.B) {
				payload := strings.Repeat("e\u0301", size/3)
				e := engine(b, transform.Config{Limits: transform.Limits{MaxOutputBytes: 16 << 20}})
				compiled := stylesheet(b, e, sheetStart+version30+`"><xsl:param name="normalizationData"/><xsl:output method="`+method+`" normalization-form="NFC" omit-xml-declaration="yes" include-content-type="no"/><xsl:template name="start"><r><xsl:value-of select="$normalizationData"/></r></xsl:template></xsl:stylesheet>`)

				result, err := compiled.CallTemplate(b.Context(), nil, transform.Name{Local: nameStart}, transform.XSLTContext{Parameters: transform.Bindings{{Local: "normalizationData"}: transform.Values(transform.String(payload))}})
				if err != nil {
					b.Fatal(err)
				}

				writer := result.WriterTo(b.Context())
				b.ReportAllocs()
				b.SetBytes(int64(len(payload)))

				for b.Loop() {
					if _, err := writer.WriteTo(io.Discard); err != nil {
						b.Fatal(err)
					}
				}
			})
		}
	}
}

func serializationEncoding(name string) string {
	if name == "" {
		return serializationUTF8
	}

	return name
}

func serializationPayload(method, content string, size int) string {
	character := "x"
	if content == "escaped" {
		character = "&"
		if method == serializationJSON {
			character = "\""
		}
	}

	return strings.Repeat(character, size)
}

func benchmarkSerializationResult(b *testing.B, result *transform.Result, size int) {
	b.Helper()
	b.Run("Writer", func(b *testing.B) {
		writer := result.WriterTo(b.Context())
		b.ReportAllocs()
		b.SetBytes(int64(size))

		for b.Loop() {
			if _, err := writer.WriteTo(io.Discard); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("Buffered", func(b *testing.B) {
		b.ReportAllocs()
		b.SetBytes(int64(size))

		for b.Loop() {
			if _, err := result.Serialize(b.Context()); err != nil {
				b.Fatal(err)
			}
		}
	})
}

func serializationFixture(b *testing.B, method, encoding, payload string) *transform.Result {
	b.Helper()
	e := engine(b, transform.Config{Limits: transform.Limits{MaxOutputBytes: 16 << 20}})

	body := `<r><xsl:value-of select="$data"/></r>`
	if method == serializationJSON {
		body = `<xsl:sequence select="map{'value':$data}"/>`
	}

	compiled := stylesheet(b, e, sheetStart+version30+`"><xsl:param name="data"/><xsl:output method="`+method+`" encoding="`+serializationEncoding(encoding)+`" omit-xml-declaration="yes"/><xsl:template name="start">`+body+`</xsl:template></xsl:stylesheet>`)

	result, err := compiled.CallTemplate(b.Context(), nil, transform.Name{Local: nameStart}, transform.XSLTContext{Parameters: transform.Bindings{{Local: "data"}: transform.Values(transform.String(payload))}})
	if err != nil {
		b.Fatal(err)
	}

	return result
}

func TestSerializationExactNormalization(t *testing.T) {
	e := engine(t, transform.Config{})
	input := "a" + strings.Repeat("\u0315", 4100) + "\u0300\u034f\u0301"
	want := "à" + strings.Repeat("\u0315", 4100) + "\u034f\u0301"

	for _, method := range []string{serializationXML, serializationHTML, serializationText, serializationJSON, "adaptive"} {
		t.Run(method, func(t *testing.T) {
			body := `<r a="{$normalizationData}"><xsl:value-of select="$normalizationData"/></r>`
			if method == "json" || method == "adaptive" {
				body = `<xsl:sequence select="$normalizationData"/>`
			}

			style := stylesheet(t, e, sheetStart+version30+`"><xsl:param name="normalizationData"/><xsl:output method="`+method+`" normalization-form="NFC" omit-xml-declaration="yes" include-content-type="no"/><xsl:template name="start">`+body+`</xsl:template></xsl:stylesheet>`)

			result, err := style.CallTemplate(t.Context(), nil, transform.Name{Local: nameStart}, transform.XSLTContext{Parameters: transform.Bindings{{Local: "normalizationData"}: transform.Values(transform.String(input))}})
			if err != nil {
				t.Fatal(err)
			}

			output, err := result.Serialize(t.Context())
			if err != nil {
				t.Fatal(err)
			}

			if !strings.Contains(string(output.Primary), want) || strings.Count(string(output.Primary), "\u034f") != strings.Count(string(output.Primary), want) {
				t.Fatal("wrong normalization or CGJ insertion")
			}

			var streamed strings.Builder
			if _, err := result.WriterTo(t.Context()).WriteTo(&streamed); err != nil || streamed.String() != string(output.Primary) {
				t.Fatal("writer mismatch", err)
			}
		})
	}
}

// TestJSONSerializationRules exercises the same SER31 §9 values through the
// XPath function and both buffered and streaming XSLT result delivery.
func TestJSONSerializationRules(t *testing.T) {
	e := engine(t, transform.Config{})
	for _, tc := range []struct{ expression, want, code string }{
		{`(1, 2)`, "", errCodeSERE0023},
		{`[(1, 2)]`, "", errCodeSERE0023},
		{`map{'x':(1, 2)}`, "", errCodeSERE0023},
		{`[map{'x':[(1, 2)]}]`, "", errCodeSERE0023},
		{`xs:double('NaN')`, "", errCodeSERE0020},
		{`xs:double('INF')`, "", errCodeSERE0020},
		{`map{'x':[xs:float('-INF')]}`, "", errCodeSERE0020},
		{`string#1`, "", errCodeSERE0021},
		{`[map{'x':string#1}]`, "", errCodeSERE0021},
		{`map{1:'a', '1':'b'}`, "", errCodeSERE0022},
		{`[map{1:'a', '1':'b'}]`, "", errCodeSERE0022},
		{`()`, serializationNull, ""},
		{`[]`, "[]", ""},
		{`map{}`, "{}", ""},
		{`[(), [1, 2], map{'x':()}]`, `[null,[1,2],{"x":null}]`, ""},
		{`[true(), false(), 1.25, 'x']`, `[true,false,1.25,"x"]`, ""},
		{`array{1, 2, (3, 4)}`, `[1,2,3,4]`, ""},
		{`parse-xml('<r/>')`, `"<r\/>"`, ""},
		{`parse-xml('<r><!--c--></r>')/r/comment()`, `"<!--c-->"`, ""},
		{`parse-xml('<r><?p x?></r>')/r/processing-instruction()`, `"<?p x?>"`, ""},
		{`parse-xml('<r>&lt;&amp;</r>')/r/text()`, `"&lt;&amp;"`, ""},
		{`parse-xml('<r a="x"/>')/r/@a`, "", errCodeSENR0001},
		{`parse-xml('<r/>')/r/namespace::*[name()='xml']`, "", errCodeSENR0001},
	} {
		t.Run(tc.expression, func(t *testing.T) {
			expression := tc.expression
			value, err := query(t, e, `serialize(`+expression+`, map{'method':'json'})`, transform.XPath31).Evaluate(t.Context(), nil, transform.XPathContext{})
			assertSerializationSequence(t, "fn:serialize", value, err, tc.want, tc.code)

			source := sheetStart + version30 + `"><xsl:output method="json"/><xsl:template name="start"><xsl:sequence select="` + strings.NewReplacer("&", "&amp;", "<", "&lt;", `"`, "&quot;").Replace(expression) + `"/></xsl:template></xsl:stylesheet>`
			compiled := stylesheet(t, e, source)

			result, err := compiled.CallTemplate(t.Context(), nil, transform.Name{Local: nameStart}, transform.XSLTContext{})
			if err != nil {
				assertSerializationResult(t, "CallTemplate", "", err, tc.want, tc.code)
			} else {
				output, err := result.Serialize(t.Context())
				assertSerializationOutput(t, "Serialize", output, err, tc.want, tc.code)

				var writer strings.Builder

				_, err = result.WriterTo(t.Context()).WriteTo(&writer)
				assertSerializationResult(t, "WriterTo", writer.String(), err, tc.want, tc.code)
			}

			output, err := compiled.Transform(t.Context(), nil, transform.XSLTContext{Template: transform.Name{Local: nameStart}})
			assertSerializationOutput(t, "Transform", output, err, tc.want, tc.code)

			value, err = query(t, e, transformSerializedQuery, transform.XPath31).Evaluate(t.Context(), nil, transform.XPathContext{Variables: transform.Bindings{
				{Local: variableStylesheet}: transform.Values(transform.String(source)),
			}})
			assertSerializationSequence(t, "fn:transform", value, err, tc.want, tc.code)
		})
	}
}

func assertSerializationSequence(t *testing.T, path string, value transform.Sequence, err error, want, code string) {
	t.Helper()

	got := ""
	if err == nil {
		got = text(t, value)
	}

	assertSerializationResult(t, path, got, err, want, code)
}

func assertSerializationOutput(t *testing.T, path string, output *transform.Output, err error, want, code string) {
	t.Helper()

	got := ""
	if output != nil {
		got = string(output.Primary)
	}

	assertSerializationResult(t, path, got, err, want, code)
}

func assertSerializationResult(t *testing.T, path, got string, err error, want, code string) {
	t.Helper()

	if code != "" {
		var detail *transform.Error
		if !errors.As(err, &detail) || detail.Code != code {
			t.Errorf("%s: %q, %v; want %s", path, got, err, code)
		}
	} else if err != nil || got != want {
		t.Errorf("%s: %q, %v; want %q", path, got, err, want)
	}
}

// TestSerializeParameterDocuments keeps argument type errors separate from
// parameter extraction, duplicate parameters and duplicate character mappings.
func TestSerializeParameterDocuments(t *testing.T) {
	e := engine(t, transform.Config{})

	for _, version := range []transform.XPathVersion{transform.XPath30, transform.XPath31} {
		for _, tc := range []struct{ body, code string }{
			{`<indent value="perhaps"/>`, errCodeSEPM0017},
			{`<unknown value="yes"/>`, errCodeSEPM0017},
			{`<indent/>`, errCodeSEPM0017},
			{`<indent value="yes" other="no"/>`, errCodeSEPM0017},
			{`<indent value="yes">text</indent>`, errCodeSEPM0017},
			{`<indent value="yes"/><indent value="no"/>`, errCodeSEPM0019},
			{`<indent xmlns="" value="yes"/>`, errCodeSEPM0017},
			{`<cdata-section-elements value="missing:name"/>`, errCodeSEPM0017},
			{`<use-character-maps value="yes"/>`, errCodeSEPM0017},
			{`<use-character-maps><wrong/></use-character-maps>`, errCodeSEPM0017},
			{`<use-character-maps><character-map character="ab"/></use-character-maps>`, errCodeSEPM0017},
			{`<use-character-maps><character-map character="a" other="x"/></use-character-maps>`, errCodeSEPM0017},
			{`<use-character-maps><character-map character="a" map-string="x"/><character-map character="a" map-string="y"/></use-character-maps>`, errCodeSEPM0018},
			{`<use-character-maps/><use-character-maps/>`, errCodeSEPM0019},
			{`<indent value="true"/>`, ""},
		} {
			params := `<serialization-parameters xmlns="http://www.w3.org/2010/xslt-xquery-serialization"><method value="text"/>` + tc.body + `</serialization-parameters>`
			value, err := query(t, e, `serialize('x', parse-xml($params)/*)`, version).Evaluate(t.Context(), nil, transform.XPathContext{Variables: transform.Bindings{
				{Local: "params"}: transform.Values(transform.String(params)),
			}})
			assertSerializationSequence(t, tc.body, value, err, "x", tc.code)
		}
	}

	for expression, code := range map[string]string{
		`serialize('x', 1)`:                                       errCodeXPTY0004,
		`serialize('x', parse-xml('<wrong/>')/*)`:                 errCodeXPTY0004,
		`serialize('x', (map{}, map{}))`:                          errCodeXPTY0004,
		`serialize('x', map{'indent':'yes'})`:                     errCodeXPTY0004,
		`serialize('x', map{'use-character-maps':map{'ab':'x'}})`: errCodeSEPM0016,
		`serialize('x', parse-xml('<serialization-parameters xmlns="http://www.w3.org/2010/xslt-xquery-serialization" extra="x"/>')/*)`: errCodeSEPM0017,
	} {
		value, err := query(t, e, expression, transform.XPath31).Evaluate(t.Context(), nil, transform.XPathContext{})
		assertSerializationSequence(t, expression, value, err, "", code)
	}
}

func TestJSONResultDocuments(t *testing.T) {
	e := engine(t, transform.Config{})
	for _, tc := range []struct{ expression, want, code string }{
		{`()`, serializationNull, ""},
		{`[(), map{'x':[1,2]}]`, `[null,{"x":[1,2]}]`, ""},
		{`[(1,2)]`, "", errCodeSERE0023},
		{`map{'x':(1,2)}`, "", errCodeSERE0023},
		{`[xs:double('NaN')]`, "", errCodeSERE0020},
		{`map{'x':string#1}`, "", errCodeSERE0021},
		{`map{1:'a','1':'b'}`, "", errCodeSERE0022},
	} {
		t.Run(tc.expression, func(t *testing.T) {
			const uri = "urn:json-result"

			source := sheet(version30, `<xsl:template name="start"><xsl:result-document href="`+uri+`" method="json"><xsl:sequence select="`+tc.expression+`"/></xsl:result-document><xsl:text>done</xsl:text></xsl:template>`)
			compiled := stylesheet(t, e, source)

			result, err := compiled.CallTemplate(t.Context(), nil, transform.Name{Local: nameStart}, transform.XSLTContext{})
			if err != nil {
				assertSerializationResult(t, "CallTemplate", "", err, tc.want, tc.code)
			} else {
				output, err := result.Serialize(t.Context())

				got := ""
				if output != nil {
					got = string(output.Secondary[uri])
				}

				assertSerializationResult(t, "secondary Serialize", got, err, tc.want, tc.code)

				var writer strings.Builder

				_, err = result.WriteSecondary(t.Context(), uri, &writer)
				assertSerializationResult(t, "WriteSecondary", writer.String(), err, tc.want, tc.code)
			}

			value, err := query(t, e, `transform(map{'stylesheet-text':$stylesheet,'initial-template':QName('', 'start'),'delivery-format':'serialized'})('`+uri+`')`, transform.XPath31).Evaluate(t.Context(), nil, transform.XPathContext{Variables: transform.Bindings{
				{Local: variableStylesheet}: transform.Values(transform.String(source)),
			}})
			assertSerializationSequence(t, "fn:transform secondary", value, err, tc.want, tc.code)
		})
	}
}

func TestSerializeMarkupAtomics(t *testing.T) {
	e := engine(t, transform.Config{})
	for _, version := range []transform.XPathVersion{transform.XPath30, transform.XPath31} {
		if got := text(t, evaluate(t, e, `serialize(('a', true(), '<&>'))`, version)); got != "a true &lt;&amp;&gt;" {
			t.Fatal("default XML serialization", version, got)
		}
	}

	for _, method := range []string{serializationXML, serializationHTML} {
		got := text(t, evaluate(t, e, `serialize(('a', true(), '<&>'), map{'method':'`+method+`','use-character-maps':map{'a':'mapped'}})`, transform.XPath31))
		if got != "mapped true &lt;&amp;&gt;" {
			t.Fatal(method, got)
		}
	}
}

func TestSerializeJSONNodeMethods(t *testing.T) {
	e := engine(t, transform.Config{})
	for _, tc := range []struct{ method, node, want string }{
		{serializationXML, serializationNodeXML, serializationNodeXML},
		{serializationText, serializationNodeXML, serializationText},
		{serializationHTML, `<p>text<br/></p>`, `<p>text<br></p>`},
	} {
		value := text(t, evaluate(t, e, `parse-json(serialize(parse-xml('`+tc.node+`'), map{'method':'json','json-node-output-method':'`+tc.method+`'}))`, transform.XPath31))
		if value != tc.want {
			t.Fatal(tc.method, value, tc.want)
		}
	}
}

func TestJSONHTMLHeadMetadata(t *testing.T) {
	e := engine(t, transform.Config{})

	for _, tc := range []struct{ xml, path string }{
		{`<head xmlns=""><title>One</title></head>`, `/*`},
		{`<html xmlns="http://www.w3.org/1999/xhtml"><head><title>Two</title></head></html>`, `/*`},
		{`<html><head><title>Three</title></head></html>`, ""},
	} {
		expression := `parse-xml($source)` + tc.path
		variables := transform.Bindings{{Local: sourceName}: transform.Values(transform.String(tc.xml))}
		program := query(t, e, `let $node := `+expression+` return let $html := parse-json(serialize($node, map{'method':'json','json-node-output-method':'html'})) return contains($html, '<meta http-equiv="Content-Type"') and not(contains($html, '<head xmlns="">')) and not(exists($node//meta))`, transform.XPath31)

		value, err := program.Evaluate(t.Context(), nil, transform.XPathContext{Variables: variables})
		if err != nil || text(t, value) != nameTrue {
			t.Fatal("fn:serialize HTML metadata or source mutation", tc, value, err)
		}

		source := sheetStart + version30 + `"><xsl:param name="source"/><xsl:output method="json" json-node-output-method="html"/><xsl:template name="start"><xsl:sequence select="` + expression + `"/></xsl:template></xsl:stylesheet>`

		output, err := stylesheet(t, e, source).Transform(t.Context(), nil, transform.XSLTContext{Template: transform.Name{Local: nameStart}, Parameters: variables})
		if err != nil {
			t.Fatal(err)
		}

		value, err = query(t, e, `contains(parse-json($json), '<meta http-equiv="Content-Type"')`, transform.XPath31).Evaluate(t.Context(), nil, transform.XPathContext{Variables: transform.Bindings{
			{Local: serializationJSON}: transform.Values(transform.String(string(output.Primary))),
		}})
		if err != nil || text(t, value) != nameTrue {
			t.Fatal("XSLT HTML metadata", tc, value, err)
		}

		variables[transform.Name{Local: variableStylesheet}] = transform.Values(transform.String(source))

		value, err = query(t, e, `contains(parse-json(transform(map{'stylesheet-text':$stylesheet,'initial-template':QName('', 'start'),'delivery-format':'serialized','stylesheet-params':map{QName('', 'source'):$source}})?output), '<meta http-equiv="Content-Type"')`, transform.XPath31).Evaluate(t.Context(), nil, transform.XPathContext{Variables: variables})
		if err != nil || text(t, value) != nameTrue {
			t.Fatal("fn:transform HTML metadata", tc, value, err)
		}
	}
}
