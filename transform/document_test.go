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
