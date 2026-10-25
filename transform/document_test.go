package transform_test

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/transform"
)

func TestParseXMLCharacterInput(t *testing.T) {
	e := engine(t, transform.Config{})

	for _, version := range []transform.XPathVersion{transform.XPath30, transform.XPath31} {
		for _, encoding := range []string{xmlLatinEncoding, "UTF-16", xmlASCIIEncoding, "x-unregistered-encoding"} {
			source := `<?xml version="1.0" encoding="` + encoding + `" standalone="yes"?><r>café 中</r>`

			value, err := query(t, e, `string(parse-xml($source)/r)`, version).Evaluate(t.Context(), nil, transform.XPathContext{Variables: transform.Bindings{{Local: sourceName}: transform.Values(transform.String(source))}})
			if err != nil || text(t, value) != xmlCharacters {
				t.Fatal("XML string was treated as encoded bytes", encoding, value, err)
			}
		}

		for _, source := range []string{
			`<?xml version="1.0" encoding="1bad"?><r/>`,
			`<?xml version="1.0" encoding="bad encoding"?><r/>`,
			`<?xml version="1.0" encoding="ISO-8859-1" encoding="UTF-8"?><r/>`,
			`<?xml version="1.1" encoding="UTF-16"?><r/>`,
			`<?xml version="1.0" standalone="perhaps"?><r/>`,
			`<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE r><r/>`,
		} {
			_, err := query(t, e, `parse-xml($source)`, version).Evaluate(t.Context(), nil, transform.XPathContext{Variables: transform.Bindings{{Local: sourceName}: transform.Values(transform.String(source))}})

			var detail *transform.Error
			if !errors.As(err, &detail) || detail.Code != errCodeFODC0006 {
				t.Fatal("invalid XML declaration accepted", source, err)
			}
		}
	}
}

func TestParseXMLFragmentTextDeclaration(t *testing.T) {
	e := engine(t, transform.Config{})

	for _, version := range []transform.XPathVersion{transform.XPath30, transform.XPath31} {
		for source, want := range map[string]string{
			`<?xml encoding="UTF-16"?>café 中<a/>`:                          xmlCharacters,
			`<?xml version='1.0' encoding='x-unregistered-encoding'?>text`: serializationText,
			`<?xml-stylesheet href="style.xsl"?>text`:                      serializationText,
			`<?xml encoding = 'ISO-8859-1' ?> café 中`:                      " " + xmlCharacters,
		} {
			value, err := query(t, e, `string(parse-xml-fragment($source))`, version).Evaluate(t.Context(), nil, transform.XPathContext{Variables: transform.Bindings{{Local: sourceName}: transform.Values(transform.String(source))}})
			if err != nil || text(t, value) != want {
				t.Errorf("XPath %d %s: %v, %v", version, source, value, err)
			}
		}

		for _, source := range []string{
			`<?xml encoding="1bad"?><a/>`, `<?xml encoding="UTF-8"encoding="UTF-8"?><a/>`,
			`<?xml version="1.0"encoding="UTF-8"?><a/>`, `<?xml version="1.1" encoding="UTF-8"?><a/>`,
			`<?xml version="1.0"?><a/>`, `<?xml encoding="UTF-8" standalone="yes"?><a/>`,
			`<?xml encoding="UTF&#45;8"?><a/>`, `<?xml encoding="UTF-8?><a/>`,
		} {
			_, err := query(t, e, `parse-xml-fragment($source)`, version).Evaluate(t.Context(), nil, transform.XPathContext{Variables: transform.Bindings{{Local: sourceName}: transform.Values(transform.String(source))}})

			var detail *transform.Error
			if !errors.As(err, &detail) || detail.Code != errCodeFODC0006 {
				t.Errorf("XPath %d accepted malformed text declaration %s: %v", version, source, err)
			}
		}
	}

	capped := engine(t, transform.Config{Limits: transform.Limits{MaxInputBytes: 80}})
	source := `<?xml` + strings.Repeat(" ", 80) + `encoding="UTF-8"?><a/>`

	_, err := query(t, capped, `parse-xml-fragment($source)`, transform.XPath31).Evaluate(t.Context(), nil, transform.XPathContext{Variables: transform.Bindings{{Local: sourceName}: transform.Values(transform.String(source))}})
	if !errors.Is(err, transform.ErrLimit) {
		t.Fatal("text declaration bypassed the XML input budget", err)
	}
}

func TestProjectDOMNavigationAndSerialization(t *testing.T) {
	e := engine(t, transform.Config{})

	d, err := e.Parse(context.Background(), []byte(`<r xmlns:p="urn:p" xml:id="root"><p:item a="&amp;">ab</p:item><p:item>c</p:item></r>`))
	if err != nil {
		t.Fatal(err)
	}

	for source, want := range map[string]string{
		`string(id('root')/@xml:id)`:                            "root",
		`count(/r/*[1]/namespace::*)`:                           "2",
		`namespace-uri-for-prefix('xml',/r)`:                    document.XMLNamespace,
		`namespace-uri-for-prefix('p',/r/*[1])`:                 namespaceP,
		`count(/r/*[2]/preceding-sibling::*)`:                   "1",
		`string(/r/*[1]/following-sibling::*[1])`:               "c",
		`count(parse-xml-fragment('a<b/>c')/text())`:            "2",
		`serialize(/r/*[1],map{'omit-xml-declaration':true()})`: `<p:item xmlns:p="urn:p" a="&amp;">ab</p:item>`,
	} {
		q := query(t, e, source, transform.XPath31)

		v, err := q.Evaluate(context.Background(), d, transform.XPathContext{})
		if err != nil {
			t.Errorf("%s: %v", source, err)
			continue
		}

		if got := text(t, v); got != want {
			t.Errorf("%s = %q, want %q", source, got, want)
		}
	}
}

const xmlIDInvalidValueExpression = `let $d := parse-xml('<r xml:id=" one &#x9; two "/>') return string($d/r/@xml:id) eq 'one two' and empty(id('one', $d))`

func xmlIDExpressions() map[string]string {
	return map[string]string{
		`let $d := parse-xml('<r xml:id=" &#x9;root&#xD; "><n xml:id=" child &#xA;"/></r>') return id(' root ', $d) is $d/r and element-with-id('child', $d) is $d/r/n`: nameTrue,
		`let $d := parse-xml('<r xml:id=" &#x9;root&#xD; "/>') return string($d/r/@xml:id) eq 'root' and data($d/r/@xml:id) instance of xs:untypedAtomic`:               nameTrue,
		`string(parse-xml-fragment('<r xml:id=" a &#x9; "/><s xml:id=" b &#xA; "/>')/s/@xml:id)`:                                                                        "b",
		`let $d := parse-xml('<r><n xml:id=" a "/><n xml:id=" b "/></r>') return string-join(id((' b ', 'a', 'a'),$d)/@xml:id, ':')`:                                    "a:b",
		xmlIDInvalidValueExpression: nameTrue,
		`let $d := parse-xml('<r xml:id=" &#xA0;root&#xA0; "/>') return string($d/r/@xml:id) eq codepoints-to-string((160,114,111,111,116,160)) and empty(id('root', $d))`:                                    nameTrue,
		`serialize(parse-xml('<r xml:id=" &#x9;root&#xD; " a=" &#x9;value&#xD; "/>')/*,map{'omit-xml-declaration':true()})`:                                                                                   `<r xml:id="root" a=" &#x9;value&#xD; "/>`,
		`let $n := parse-xml('<r xml:id=" root "/>')/* return every $m in ('xml','html','xhtml','adaptive') satisfies contains(serialize($n,map{'method':$m,'omit-xml-declaration':true()}),'xml:id="root"')`: nameTrue,
		`parse-json(serialize(parse-xml('<r xml:id=" root "/>')/*,map{'method':'json'}))`:                                                                                                                     `<r xml:id="root"/>`,
	}
}

func TestXMLIDValues(t *testing.T) {
	e := engine(t, transform.Config{})
	for expression, want := range xmlIDExpressions() {
		t.Run(expression, func(t *testing.T) {
			value, err := query(t, e, expression, transform.XPath31).Evaluate(t.Context(), nil, transform.XPathContext{})
			if err != nil || text(t, value) != want {
				t.Fatal(value, err, "want", want)
			}
		})
	}
}

func TestXMLIDImportPreservesSnapshot(t *testing.T) {
	ctx := t.Context()
	e := engine(t, transform.Config{})
	xml := []byte(`<r xml:id=" &#x9;root&#xD; "><n xml:id=" child "/></r>`)
	original, err := document.Parse(ctx, xml, document.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	before, err := original.XML(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, imported := range []bool{false, true} {
		var d *transform.Document
		if imported {
			d, err = e.Import(ctx, original)
		} else {
			d, err = e.ParseReader(ctx, bytes.NewReader(xml))
		}
		if err != nil {
			t.Fatal(err)
		}
		for _, version := range []transform.XPathVersion{transform.XPath10, transform.XPath20, transform.XPath30, transform.XPath31} {
			q := query(t, e, `string(id('root')/@xml:id) = 'root' and count(id(' child ')) = 1`, version)
			value, err := q.Evaluate(ctx, d, transform.XPathContext{})
			if err != nil || text(t, value) != nameTrue {
				t.Fatal("parse/import xml:id mismatch", imported, version, value, err)
			}
		}
		if imported {
			exported, err := e.Export(ctx, d)
			if err != nil || exported != original {
				t.Fatal("normalization replaced the original snapshot", err)
			}
		}
	}
	attribute := original.Root().AttributeNodes()[0]
	value, err := e.ImportNode(ctx, attribute)
	if err != nil {
		t.Fatal(err)
	}
	node, ok := value.Node()
	if !ok || node.StringValue() != "root" || node.Reference() != attribute {
		t.Fatal("xml:id view lost normalized value or original identity", value)
	}
	after, err := original.XML(ctx)
	if err != nil || !bytes.Equal(before, after) || attribute.Value() != " \troot\r " {
		t.Fatal("XDM normalization modified the XML snapshot", string(after), err)
	}
}

func TestXSLTBuildsOnProjectDOMWithoutMutatingSource(t *testing.T) {
	e := engine(t, transform.Config{})

	source, err := document.Parse(t.Context(), []byte(`<r xmlns:p="urn:p"> <p:item a="&amp;">x</p:item> <p:item xml:space="preserve"> </p:item> </r>`), document.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}

	before, err := source.XML(t.Context())
	if err != nil {
		t.Fatal(err)
	}

	d, err := e.Import(context.Background(), source)
	if err != nil {
		t.Fatal(err)
	}

	s := stylesheet(t, e, `<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="3.0"><xsl:strip-space elements="*"/><xsl:output omit-xml-declaration="yes"/><xsl:template match="/"><xsl:copy-of select="*"/></xsl:template></xsl:stylesheet>`)

	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			out, err := s.Transform(context.Background(), d, transform.XSLTContext{})
			if err != nil {
				t.Error(err)
				return
			}

			parsed, err := document.Parse(t.Context(), out.Primary, document.DefaultLimits())
			if err != nil {
				t.Error(err)
				return
			}

			if len(parsed.Root().Children()) != 2 || parsed.Root().Children()[1].Text() != " " {
				t.Errorf("strip/space semantics lost: %s", out.Primary)
			}

			if got, _ := parsed.Root().Children()[0].Attribute(document.Name{Local: "a"}); got != "&" {
				t.Errorf("attribute was reinterpreted: %s", out.Primary)
			}
		})
	}

	wg.Wait()

	after, err := source.XML(t.Context())
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("source snapshot changed", string(after), err)
	}
	// Adjacent text instructions form one XDM text node.
	s = stylesheet(t, e, sheet(version30, `<xsl:template name="start"><xsl:variable name="v"><xsl:text>a</xsl:text><xsl:text>b</xsl:text></xsl:variable><xsl:value-of select="concat(count($v/text()),':',string($v))"/></xsl:template>`))

	out, err := s.Transform(context.Background(), nil, transform.XSLTContext{Template: transform.Name{Local: nameStart}})
	if err != nil || string(out.Primary) != "1:ab" {
		t.Fatal("adjacent text nodes were not merged", out, err)
	}
}

func TestXSLTProjectDOMSequenceSplices(t *testing.T) {
	e := engine(t, transform.Config{})
	for body, want := range map[string]string{
		`<xsl:variable name="v"><xsl:text>left</xsl:text><xsl:sequence select="('one','two')"/><xsl:text>right</xsl:text></xsl:variable><xsl:value-of select="concat(count($v/text()),':',string($v))"/>`:                         "1:leftone tworight",
		`<xsl:variable name="v"><a/><xsl:on-non-empty><xsl:text>one</xsl:text><xsl:text>two</xsl:text></xsl:on-non-empty><b/></xsl:variable><xsl:value-of select="concat(name($v/*[1]),':',string($v),':',name($v/*[last()]))"/>`: "a:onetwo:b",
	} {
		s := stylesheet(t, e, sheet(version30, `<xsl:template name="start">`+body+`</xsl:template>`))

		out, err := s.Transform(context.Background(), nil, transform.XSLTContext{Template: transform.Name{Local: nameStart}})
		if err != nil {
			t.Fatal(err)
		}

		if string(out.Primary) != want {
			t.Errorf("%s: got %s, want %s: %v", body, out.Primary, want, err)
		}
	}
}

type conditionalContentCase struct{ name, body, want string }

func conditionalContentCases() []conditionalContentCase {
	check := func(name, body, expression string) conditionalContentCase {
		return conditionalContentCase{name, `<xsl:variable name="v" as="item()*">` + body + `</xsl:variable><xsl:sequence select="` + expression + `"/>`, nameTrue}
	}
	return []conditionalContentCase{
		check("mixed atomic values", `<xsl:where-populated><xsl:sequence select="('', 'a', '', 2, xs:anyURI(''), xs:hexBinary(''), xs:base64Binary(''))"/></xsl:where-populated>`, `deep-equal($v,('a',2))`),
		check("mixed maps", `<xsl:where-populated><xsl:sequence select="(map{},map{'n':()},map{})"/></xsl:where-populated>`, `count($v) eq 1 and map:contains($v,'n')`),
		check("mixed arrays", `<xsl:where-populated><xsl:sequence select="([], [()], [''], [[],['',[]]], [(),['',0]])"/></xsl:where-populated>`, `count($v) eq 1 and $v instance of array(*) and deep-equal($v,[(),['',0]])`),
		check("array flattening preserves nonempty map", `<xsl:where-populated><xsl:sequence select="([map{}],[[map{'n':()}]])"/></xsl:where-populated>`, `count($v) eq 1 and map:contains($v?1?1,'n')`),
		check("element with empty child", `<xsl:where-populated><empty/><outer><inner/></outer><xsl:element name="computed"><inner/></xsl:element></xsl:where-populated>`, `count($v) eq 2 and name($v[1]) eq 'outer' and name($v[2]) eq 'computed'`),
		check("child nodes determine emptiness", `<xsl:where-populated><a><xsl:comment/></a><b><xsl:processing-instruction name="p"/></b><c><xsl:text> </xsl:text></c><d a="value"/></xsl:where-populated>`, `count($v) eq 3 and deep-equal($v/name(),('a','b','c'))`),
		check("document with empty element", `<xsl:where-populated><xsl:document/><xsl:document><a/></xsl:document></xsl:where-populated>`, `count($v) eq 1 and $v instance of document-node() and exists($v/a)`),
		check("comments and instructions individually", `<xsl:where-populated><xsl:comment/><xsl:comment>kept</xsl:comment><xsl:processing-instruction name="p"/><xsl:processing-instruction name="p">kept</xsl:processing-instruction><xsl:text/><xsl:text> </xsl:text></xsl:where-populated>`, `count($v) eq 3 and $v[1] instance of comment() and $v[2] instance of processing-instruction(p) and string($v[3]) eq ' '`),
		check("attribute items individually", `<xsl:where-populated><xsl:attribute name="empty"/><xsl:attribute name="full">value</xsl:attribute></xsl:where-populated>`, `count($v) eq 1 and $v instance of attribute(full) and string($v) eq 'value'`),
		check("empty attribute preserves old value", `<r a="keep"><xsl:where-populated><xsl:attribute name="a"/></xsl:where-populated></r>`, `$v/@a eq 'keep'`),
		check("empty late attribute is removed", `<r a="keep"><a/><xsl:where-populated><xsl:attribute name="a"/></xsl:where-populated></r>`, `$v/@a eq 'keep' and exists($v/a)`),
		check("nested document empty fallback", `<r><xsl:where-populated><xsl:element name="name"><xsl:where-populated><xsl:document/></xsl:where-populated></xsl:element></xsl:where-populated><xsl:on-empty><fallback/></xsl:on-empty></r>`, `exists($v/fallback) and empty($v/name)`),
		check("nested document kept", `<r><xsl:where-populated><xsl:element name="name"><xsl:where-populated><xsl:document><e/></xsl:document></xsl:where-populated></xsl:element></xsl:where-populated><xsl:on-empty><fallback/></xsl:on-empty></r>`, `exists($v/name/e) and empty($v/fallback)`),
		check("conditional output before filtering", `<xsl:where-populated><xsl:sequence select="''"/><xsl:on-empty>fallback</xsl:on-empty></xsl:where-populated>`, `count($v) eq 1 and string($v) eq 'fallback'`),
		check("node identity survives sequence filtering", `<xsl:variable name="n" as="element()"><r><a/></r></xsl:variable><xsl:where-populated><xsl:sequence select="$n"/></xsl:where-populated><xsl:sequence select="$n"/>`, `count($v) eq 2 and $v[1] is $v[2]`),
		check("namespace in constructed element", `<r><xsl:where-populated><xsl:namespace name="p" select="'urn:kept'"/></xsl:where-populated></r>`, `namespace-uri-for-prefix('p',$v) eq 'urn:kept'`),
		check("namespace sequence copy", `<xsl:variable name="n" as="element()"><r xmlns:p="urn:kept"/></xsl:variable><r><xsl:sequence select="$n/namespace::p"/></r>`, `namespace-uri-for-prefix('p',$v) eq 'urn:kept'`),
		check("vacuous values survive unused nonempty action", `<xsl:sequence select="''"/><xsl:on-non-empty select="error()"/>`, `count($v) eq 1 and $v instance of xs:string and $v eq ''`),
		check("empty array triggers replacement", `<xsl:sequence select="[[(),['']]]"/><xsl:on-empty select="'fallback'"/>`, `deep-equal($v,'fallback')`),
		check("empty map is not vacuous", `<xsl:sequence select="map{}"/><xsl:on-empty select="error()"/>`, `count($v) eq 1 and $v instance of map(*) and map:size($v) eq 0`),
		check("empty element is not vacuous", `<empty/><xsl:on-empty select="error()"/>`, `count($v) eq 1 and $v instance of element(empty)`),
		check("nonempty action keeps item order", `<xsl:on-non-empty select="'before'"/><xsl:sequence select="'middle'"/><xsl:on-non-empty select="'after'"/><xsl:on-empty select="error()"/>`, `deep-equal($v,('before','middle','after'))`),
		check("unchosen body has no effects", `<r><xsl:on-non-empty><xsl:message terminate="yes">unused</xsl:message></xsl:on-non-empty></r>`, `count($v) eq 1 and empty($v/node())`),
		{"selected action error", `<xsl:sequence select="''"/><xsl:on-empty select="error()"/>`, "FOER0000"},
		check("xml namespace item", `<xsl:where-populated><xsl:namespace name="xml" select="'http://www.w3.org/XML/1998/namespace'"/></xsl:where-populated>`, `count($v) eq 1 and name($v) eq 'xml' and string($v) eq 'http://www.w3.org/XML/1998/namespace'`),
		{"empty default namespace value", `<r><xsl:where-populated><xsl:namespace name="" select="''"/></xsl:where-populated></r>`, "XTDE0930"},
		check("shallow copy keeps nested filtered content", `<xsl:for-each select="parse-xml('&lt;a>&lt;b/>&lt;/a>')/*"><xsl:where-populated><xsl:copy><xsl:for-each select="*"><xsl:where-populated><xsl:copy><xsl:text>data</xsl:text></xsl:copy></xsl:where-populated></xsl:for-each></xsl:copy></xsl:where-populated></xsl:for-each>`, `count($v) eq 1 and $v/self::a/b eq 'data'`),
		check("shallow document copy keeps complex content", `<xsl:for-each select="parse-xml('&lt;a/>')"><xsl:where-populated><xsl:copy><xsl:sequence select="1,2"/><a/></xsl:copy></xsl:where-populated></xsl:for-each>`, `count($v) eq 1 and $v instance of document-node() and string($v) eq '1 2' and exists($v/a)`),
		{"atomic adjacency after filtering", `<r><xsl:where-populated><xsl:sequence select="1"/><xsl:text/><xsl:sequence select="2"/></xsl:where-populated></r>`, "1 2"},
		{"late attribute", `<r><a/><xsl:where-populated><xsl:attribute name="a">value</xsl:attribute></xsl:where-populated></r>`, "XTDE0410"},
		{"document attribute", `<xsl:document><xsl:where-populated><xsl:attribute name="a">value</xsl:attribute></xsl:where-populated></xsl:document>`, "XTDE0420"},
		{"late namespace", `<r><a/><xsl:where-populated><xsl:namespace name="p" select="'urn:p'"/></xsl:where-populated></r>`, "XTDE0410"},
		{"document namespace", `<xsl:document><xsl:where-populated><xsl:namespace name="p" select="'urn:p'"/></xsl:where-populated></xsl:document>`, "XTDE0420"},
		{"conflicting namespace", `<r xmlns:p="urn:old"><xsl:where-populated><xsl:namespace name="p" select="'urn:new'"/></xsl:where-populated></r>`, "XTDE0430"},
		{"default namespace on no namespace element", `<r><xsl:where-populated><xsl:namespace name="" select="'urn:new'"/></xsl:where-populated></r>`, "XTDE0440"},
	}
}

func conditionalContentSheet(test conditionalContentCase) string {
	return sheet(version30, `<xsl:template xmlns:map="http://www.w3.org/2005/xpath-functions/map" name="start">`+test.body+`</xsl:template>`)
}

func TestXSLTConditionalContent(t *testing.T) {
	e := engine(t, transform.Config{})
	for _, test := range conditionalContentCases() {
		t.Run(test.name, func(t *testing.T) {
			source := conditionalContentSheet(test)
			for _, mode := range []transform.ResultMode{transform.ResultDefault, transform.ResultRaw, transform.ResultDocument} {
				compiled, err := e.CompileXSLT(t.Context(), []byte(source), transform.XSLTOptions{})
				if err != nil {
					t.Fatal(err)
				}
				for range 2 {
					result, err := compiled.Execute(t.Context(), nil, transform.XSLTContext{Template: transform.Name{Local: nameStart}, ResultMode: mode})
					if comparisonErrorCode(test.want) {
						var detail *transform.Error
						if !errors.As(err, &detail) || detail.Code != test.want {
							t.Fatal(mode, result, err, test.want)
						}
					} else {
						if err != nil {
							t.Fatal(mode, err)
						}
						output, err := result.Serialize(t.Context())
						if err != nil || string(output.Primary) != test.want {
							t.Fatal(mode, output, err, test.want)
						}
					}
				}
			}
			got, err := resourceStylesheetResult(t, e, source, true)
			if comparisonErrorCode(test.want) {
				var detail *transform.Error
				if !errors.As(err, &detail) || detail.Code != test.want {
					t.Fatal(got, err, test.want)
				}
			} else if err != nil || got != test.want {
				t.Fatal(got, err, test.want)
			}
		})
	}
}

func templateNodeResultCases() []dynamicXPathCase {
	namespace := `<xsl:template name="nodes" as="node()*"><xsl:namespace name="xml" select="'http://www.w3.org/XML/1998/namespace'"/><xsl:namespace name="p" select="'urn:result'"/></xsl:template>`
	attribute := `<xsl:template name="nodes" as="node()*"><xsl:attribute name="a">value</xsl:attribute></xsl:template>`
	return []dynamicXPathCase{
		{"typed namespace nodes", namespace, `<xsl:variable name="v" as="element()"><r><xsl:call-template name="nodes"/></r></xsl:variable><xsl:sequence select="namespace-uri-for-prefix('p',$v) eq 'urn:result'"/>`, nameTrue},
		{"typed late namespace", namespace, `<r><a/><xsl:call-template name="nodes"/></r>`, "XTDE0410"},
		{"typed document namespace", namespace, `<xsl:document><xsl:call-template name="nodes"/></xsl:document>`, "XTDE0420"},
		{"typed late attribute", attribute, `<r><a/><xsl:call-template name="nodes"/></r>`, "XTDE0410"},
		{"typed document attribute", attribute, `<xsl:document><xsl:call-template name="nodes"/></xsl:document>`, "XTDE0420"},
	}
}

func TestXSLTTemplateNodeResults(t *testing.T) {
	e := engine(t, transform.Config{})
	for _, test := range templateNodeResultCases() {
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

func catchObjectCases() []dynamicXPathCase {
	return []dynamicXPathCase{
		{"atomic object", "", `error(QName('urn:error','e:FAIL'),'details',(1,'two',3))`, `deep-equal($err:value,(1,'two',3))`},
		{"empty object", "", `error((),'details',())`, `empty($err:value)`},
		{"node identity", `<xsl:variable name="n" as="element()"><n/></xsl:variable>`, `error((),'details',$n)`, `count($err:value) eq 1 and $err:value is $n`},
		{"map object", "", `error((),'details',map{'items':[1,2]})`, `$err:value instance of map(*) and $err:value?items?2 eq 2`},
		{"function object", "", `error((),'details',upper-case#1)`, `$err:value instance of function(*) and $err:value('mixed') eq 'MIXED'`},
		{"explicit empty description", "", `error((),'')`, `count($err:description) eq 1 and $err:description eq ''`},
		{"qualified code", "", `error(QName('urn:error','e:FAIL'),'details',42)`, `namespace-uri-from-QName($err:code) eq 'urn:error' and local-name-from-QName($err:code) eq 'FAIL' and $err:description eq 'details' and $err:value eq 42`},
		{"optional coordinates", "", `error()`, `(empty($err:line-number) or $err:line-number gt 0) and (empty($err:column-number) or $err:column-number gt 0) and (empty($err:module) or string-length($err:module) gt 0)`},
	}
}

func catchObjectSheet(test dynamicXPathCase, rollback, form string) string {
	body := `<xsl:sequence select="` + test.body + `"/>`
	selectAttr := ""
	if form == "select" {
		body = ""
		selectAttr = ` select="` + test.body + `"`
	}
	return sheet(version30, test.global+`<xsl:template xmlns:err="http://www.w3.org/2005/xqt-errors" name="start"><xsl:try rollback-output="`+rollback+`"`+selectAttr+`>`+body+`<xsl:catch errors="*" select="`+test.want+`"/></xsl:try></xsl:template>`)
}

func TestXSLTCatchObjects(t *testing.T) {
	e := engine(t, transform.Config{})
	for _, test := range catchObjectCases() {
		t.Run(test.name, func(t *testing.T) {
			for _, rollback := range []string{"yes", "no"} {
				for _, form := range []string{"body", "select"} {
					source := catchObjectSheet(test, rollback, form)
					for _, nested := range []bool{false, true} {
						got, err := resourceStylesheetResult(t, e, source, nested)
						if err != nil || got != nameTrue {
							t.Fatal(rollback, form, nested, got, err)
						}
					}
				}
			}
		})
	}
}

func namespaceInheritanceCases() []dynamicXPathCase {
	cases := make([]dynamicXPathCase, 0, 50)
	for _, sourceNS := range []string{"", "urn:source"} {
		source := `&lt;b:request xmlns:b=&quot;urn:b&quot; xmlns=&quot;` + sourceNS + `&quot;>&lt;header>&lt;x/>&lt;/header>&lt;/b:request>`
		global := `<xsl:variable name="n" select="parse-xml('` + source + `')/*"/><xsl:template name="nodes" as="element()"><xsl:sequence select="$n"/></xsl:template>`
		for _, inherit := range []string{"yes", "no"} {
			for _, constructor := range []string{"literal", "computed", "copy"} {
				opening, closing := `<parent xmlns="urn:destination" xsl:inherit-namespaces="`+inherit+`">`, `</parent>`
				switch constructor {
				case "computed":
					opening, closing = `<xsl:element name="parent" namespace="urn:destination" inherit-namespaces="`+inherit+`">`, `</xsl:element>`
				case "copy":
					opening, closing = `<xsl:for-each select="parse-xml('&lt;parent xmlns=&quot;urn:destination&quot;/>')/*"><xsl:copy inherit-namespaces="`+inherit+`">`, `</xsl:copy></xsl:for-each>`
				}
				for _, delivery := range []string{"sequence", "copy-of", "typed template"} {
					content := `<xsl:sequence select="$n"/>`
					if delivery == "copy-of" {
						content = `<xsl:copy-of select="$n"/>`
					}
					if delivery == "typed template" {
						content = `<xsl:call-template name="nodes"/>`
					}
					want := sourceNS
					if inherit == "yes" && sourceNS == "" {
						want = "urn:destination"
					}
					body := `<xsl:variable name="v" as="element()">` + opening + content + closing + `</xsl:variable><xsl:variable name="roundtrip" select="parse-xml(serialize($v,map{'method':'xml','omit-xml-declaration':true()}))/*"/><xsl:sequence select="string(namespace-uri-for-prefix('', $v/*)) eq '` + want + `' and namespace-uri($v/*/*) eq '` + sourceNS + `' and string(namespace-uri-for-prefix('',$n)) eq '` + sourceNS + `' and string(namespace-uri-for-prefix('', $roundtrip/*)) eq '` + want + `' and namespace-uri($roundtrip/*/*) eq '` + sourceNS + `'"/>`
					cases = append(cases, dynamicXPathCase{constructor + " " + inherit + " " + delivery + " " + sourceNS, global, body, nameTrue})
				}
			}
		}
	}
	source := `<xsl:variable name="n" select="parse-xml('&lt;b:request xmlns:b=&quot;urn:b&quot;>&lt;header/>&lt;/b:request>')/*"/>`
	cases = append(cases,
		dynamicXPathCase{"outer inheritance crosses inner no", source, `<xsl:variable name="v" as="element()"><outer xmlns="urn:destination"><inner xsl:inherit-namespaces="no"><xsl:sequence select="$n"/></inner></outer></xsl:variable><xsl:sequence select="namespace-uri-for-prefix('', $v/*/*) eq 'urn:destination' and namespace-uri($v/*/*/*) eq ''"/>`, nameTrue},
		dynamicXPathCase{"no namespace intermediate blocks inheritance", source, `<xsl:variable name="v" as="element()"><outer xmlns="urn:destination"><inner xmlns=""><xsl:sequence select="$n"/></inner></outer></xsl:variable><xsl:sequence select="string(namespace-uri-for-prefix('', $v/*/*)) eq '' and namespace-uri($v/*/*/*) eq ''"/>`, nameTrue},
		dynamicXPathCase{"copy without namespaces inherits destination", source, `<xsl:variable name="v" as="element()"><parent xmlns="urn:destination"><xsl:copy-of select="$n" copy-namespaces="no"/></parent></xsl:variable><xsl:sequence select="namespace-uri-for-prefix('', $v/*) eq 'urn:destination' and namespace-uri($v/*/*) eq ''"/>`, nameTrue})
	cases = append(cases,
		dynamicXPathCase{"ancestor named namespace crosses inner no", "", `<xsl:variable name="v" as="element()"><outer xmlns:p="urn:ancestor"><inner xsl:inherit-namespaces="no"><leaf/></inner></outer></xsl:variable><xsl:sequence select="namespace-uri-for-prefix('p',$v/*/*) eq 'urn:ancestor'"/>`, nameTrue},
		dynamicXPathCase{"no namespace element retains named inheritance", "", `<xsl:variable name="v" as="element()"><outer xmlns="urn:default" xmlns:p="urn:ancestor"><inner xmlns="" xsl:inherit-namespaces="no"><leaf/></inner></outer></xsl:variable><xsl:sequence select="namespace-uri-for-prefix('p',$v/*/*) eq 'urn:ancestor' and string(namespace-uri-for-prefix('',$v/*/*)) eq ''"/>`, nameTrue},
		dynamicXPathCase{"local named binding blocks ancestor", "", `<xsl:variable name="v" as="element()"><outer xmlns:p="urn:ancestor"><inner xmlns:p="urn:local"><leaf/></inner></outer></xsl:variable><xsl:sequence select="namespace-uri-for-prefix('p',$v/*/*) eq 'urn:local'"/>`, nameTrue})

	cases = append(cases,
		dynamicXPathCase{"conflicting local binding stops ancestor inheritance", "", `<xsl:variable name="v" as="element()"><outer xmlns:p="urn:ancestor"><inner xmlns:p="urn:local" xsl:inherit-namespaces="no"><xsl:element name="leaf"/></inner></outer></xsl:variable><xsl:sequence select="empty(namespace-uri-for-prefix('p',$v/*/*))"/>`, nameTrue},
		dynamicXPathCase{"identical local binding stops ancestor inheritance", "", `<xsl:variable name="v" as="element()"><outer xmlns:p="urn:ancestor"><inner xsl:inherit-namespaces="no"><xsl:element name="leaf"/></inner></outer></xsl:variable><xsl:sequence select="empty(namespace-uri-for-prefix('p',$v/*/*))"/>`, nameTrue},
		dynamicXPathCase{"computed local binding stops ancestor inheritance", "", `<xsl:variable name="v" as="element()"><outer xmlns:p="urn:ancestor"><xsl:element name="p:inner" inherit-namespaces="no"><xsl:element name="leaf"/></xsl:element></outer></xsl:variable><xsl:sequence select="empty(namespace-uri-for-prefix('p',$v/*/*))"/>`, nameTrue},
		dynamicXPathCase{"unrelated local binding is not inherited by ancestor", "", `<xsl:variable name="v" as="element()"><outer><inner xmlns:p="urn:local" xsl:inherit-namespaces="no"><xsl:element name="leaf"/></inner></outer></xsl:variable><xsl:sequence select="empty(namespace-uri-for-prefix('p',$v/*/*))"/>`, nameTrue})

	cases = append(cases,
		dynamicXPathCase{"undeclared prefix is absent from QName functions", "", `<xsl:variable name="v" as="element()"><parent xmlns:p="urn:p" xsl:inherit-namespaces="no"><xsl:element name="child"/></parent></xsl:variable><xsl:sequence select="empty(namespace-uri-for-prefix('p',$v/*)) and not(in-scope-prefixes($v/*)='p')"/>`, nameTrue},
		dynamicXPathCase{"undeclared prefix cannot resolve QName", "", `<xsl:variable name="v" as="element()"><parent xmlns:p="urn:p" xsl:inherit-namespaces="no"><xsl:element name="child"/></parent></xsl:variable><xsl:try select="resolve-QName('p:x',$v/*)"><xsl:catch errors="Q{http://www.w3.org/2005/xqt-errors}FONS0004" select="true()"/></xsl:try>`, nameTrue},
		dynamicXPathCase{"absent default namespace has empty cardinality", "", `<xsl:sequence select="empty(namespace-uri-for-prefix('',parse-xml('&lt;r xmlns=&quot;&quot;/>')/*))"/>`, nameTrue})

	cases = append(cases, dynamicXPathCase{"literal child retains own namespace despite no inheritance", "", `<xsl:variable name="v" as="element()"><parent xmlns:p="urn:p" xsl:inherit-namespaces="no"><child/></parent></xsl:variable><xsl:sequence select="namespace-uri-for-prefix('p',$v/*) eq 'urn:p' and in-scope-prefixes($v/*)='p'"/>`, nameTrue})

	return cases
}

func TestXSLTDefaultNamespaceInheritance(t *testing.T) {
	e := engine(t, transform.Config{})
	for _, test := range namespaceInheritanceCases() {
		t.Run(test.name, func(t *testing.T) {
			source := dynamicXPathSheet(test)
			for _, mode := range []transform.ResultMode{transform.ResultDefault, transform.ResultRaw, transform.ResultDocument} {
				compiled := stylesheet(t, e, source)
				for range 2 {
					result, err := compiled.Execute(t.Context(), nil, transform.XSLTContext{Template: transform.Name{Local: nameStart}, ResultMode: mode})
					if err != nil {
						t.Fatal(mode, err)
					}
					output, err := result.Serialize(t.Context())
					if err != nil || string(output.Primary) != nameTrue {
						t.Fatal(mode, output, err)
					}
				}
			}
			got, err := resourceStylesheetResult(t, e, source, true)
			if err != nil || got != nameTrue {
				t.Fatal(got, err)
			}
		})
	}
}
