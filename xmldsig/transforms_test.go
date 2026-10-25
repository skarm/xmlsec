package xmldsig_test

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/skarm/xmlsec/c14n"
	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/reference"
	"github.com/skarm/xmlsec/transform"
	"github.com/skarm/xmlsec/xmldsig"
)

func TestTransformXMLDSig(t *testing.T) {
	ns := map[string]string{"ds": xmldsig.Namespace, "xml": document.XMLNamespace}

	xslt := `<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:ds="` + xmldsig.Namespace + `" version="1.0"><xsl:output method="text"/><xsl:template match="/"><xsl:value-of select="//fixed"/></xsl:template></xsl:stylesheet>`
	for _, tt := range []struct {
		name string
		tr   reference.Transform
	}{
		{"XPath", reference.Transform{Algorithm: reference.XPath, XPath: []reference.XPathExpression{{Expression: `not(ancestor-or-self::volatile)`, Namespaces: ns}}}},
		{"Filter2", reference.Transform{Algorithm: reference.XPathFilter2, XPath: []reference.XPathExpression{{Expression: `//volatile`, Filter: "subtract", Namespaces: map[string]string{"ds": xmldsig.Namespace, "xf": reference.XPathFilter2, "xml": document.XMLNamespace}}}}},
		{"XSLT", reference.Transform{Algorithm: reference.XSLT, Stylesheet: []byte(xslt)}},
	} {
		t.Run(tt.name, func(t *testing.T) { testTransformXMLDSigCase(t, &tt) })
	}
}

func testTransformXMLDSigCase(t *testing.T, tt *struct {
	name string
	tr   reference.Transform
},
) {
	ctx := context.Background()

	p, err := transform.NewEngine(transform.Config{AllowedPrograms: []reference.Transform{tt.tr}})
	if err != nil {
		t.Fatal(err)
	}

	opt := xmldsig.SignatureOptions{ExpectedURIs: []string{namePayload}, Processing: reference.DefaultOptions()}
	opt.Processing.Extension = p
	opt.Processing.AllowedTransforms = append(opt.Processing.AllowedTransforms, tt.tr.Algorithm)
	input := coreParse(t, `<r><payload ID="payload"><fixed>SIGNED-VALUE</fixed><volatile>old-value</volatile></payload></r>`)

	ts := []reference.Transform{tt.tr}
	if tt.tr.Algorithm != reference.XSLT {
		ts = append(ts, reference.Transform{Algorithm: c14n.Exclusive})
	}

	template, selected, e := xmldsig.BuildTemplate(ctx, input, input.Root(), xmldsig.SignatureTemplate{SignatureMethod: xmldsig.ECDSASHA256, References: []xmldsig.ReferenceTemplate{{URI: namePayload, Transforms: ts}}})
	if e != nil {
		t.Fatal(e)
	}

	k := coreEC(t)

	signed, e := xmldsig.SignTemplate(ctx, template, selected, k, xmldsig.TemplateSignOptions{Validation: opt})
	if e != nil {
		t.Fatal(e)
	}

	r, e := xmldsig.VerifySignature(ctx, signed, xmldsig.Signatures(signed)[0], &k.PublicKey, opt)
	if e != nil {
		t.Fatal(e)
	}

	if r.CoversElement(signed.Root()) || r.CoversElement(signed.Root().Children()[0]) {
		t.Fatal("filtered source coverage overstated")
	}

	raw := coreXML(t, signed)

	changed := coreParse(t, strings.Replace(raw, "old-value", "allowed-change", 1))
	if _, e = xmldsig.VerifySignature(ctx, changed, xmldsig.Signatures(changed)[0], &k.PublicKey, opt); e != nil {
		t.Fatal("excluded data rejected", e)
	}

	bad := coreParse(t, strings.Replace(raw, "SIGNED-VALUE", "tampered", 1))
	if r, e = xmldsig.VerifySignature(ctx, bad, xmldsig.Signatures(bad)[0], &k.PublicKey, opt); r != nil || e == nil {
		t.Fatal("covered data accepted")
	}

	require := opt

	require.RequiredElements = []document.Element{signed.Root().Children()[0]}
	if _, e = xmldsig.VerifySignature(ctx, signed, xmldsig.Signatures(signed)[0], &k.PublicKey, require); e == nil {
		t.Fatal("required source falsely covered")
	}

	if _, e = xmldsig.VerifySignature(ctx, signed, xmldsig.Signatures(signed)[0], &k.PublicKey, xmldsig.SignatureOptions{}); e == nil {
		t.Fatal("extension enabled by default")
	}
}

func TestV1TransformURIsRequireV1Processor(t *testing.T) {
	for _, algorithm := range []string{reference.XPath, reference.XPathFilter2, reference.XSLT} {
		t.Run(algorithm, func(t *testing.T) {
			d := coreParse(t, `<r><payload ID="payload">value</payload></r>`)

			tr := reference.Transform{Algorithm: algorithm}
			if algorithm == reference.XSLT {
				tr.Stylesheet = []byte(`<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="1.0"><xsl:template match="/"/></xsl:stylesheet>`)
			} else {
				tr.XPath = []reference.XPathExpression{{Expression: programTrueXPath}}
				if algorithm == reference.XPathFilter2 {
					tr.XPath[0].Expression = "/"
					tr.XPath[0].Filter = "intersect"
				}
			}

			template, selected, err := xmldsig.BuildTemplate(context.Background(), d, d.Root(), xmldsig.SignatureTemplate{SignatureMethod: xmldsig.ECDSASHA256, References: []xmldsig.ReferenceTemplate{{URI: namePayload, Transforms: []reference.Transform{tr}}}})
			if err != nil {
				t.Fatal(err)
			}

			options := xmldsig.SignatureOptions{ExpectedURIs: []string{namePayload}, Processing: reference.DefaultOptions()}
			options.Processing.AllowedTransforms = append(options.Processing.AllowedTransforms, algorithm)

			result, err := xmldsig.SignTemplate(context.Background(), template, selected, coreEC(t), xmldsig.TemplateSignOptions{Validation: options})
			if result != nil || !errors.Is(err, reference.ErrPolicy) {
				t.Fatal(result, err)
			}
		})
	}
}

func TestTemplateStylesheetNamespaceImport(t *testing.T) {
	for _, literal := range []string{
		`<payload><value>123</value></payload>`,
		`<payload xmlns="urn:payload"><value/><empty xmlns=""/></payload>`,
		`<p:payload xmlns:p="urn:payload" p:a="v"><value/></p:payload>`,
	} {
		t.Run(literal, func(t *testing.T) {
			source := `<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:ds="` + xmldsig.Namespace + `" xmlns:p="urn:conflict" version="1.0"><xsl:output omit-xml-declaration="yes"/><xsl:template match="/">` + literal + `</xsl:template></xsl:stylesheet>`
			program := reference.Transform{Algorithm: reference.XSLT, Stylesheet: []byte(source)}
			host := coreParse(t, `<host xmlns="urn:host" xmlns:p="urn:conflict" ID="host"><data ID="data"/></host>`)

			built, selected, err := xmldsig.BuildTemplate(t.Context(), host, host.Root(), xmldsig.SignatureTemplate{
				SignatureMethod: xmldsig.ECDSASHA256, References: []xmldsig.ReferenceTemplate{{URI: "#data", Transforms: []reference.Transform{program}}},
			})
			if err != nil {
				t.Fatal(err)
			}

			style := findImportElement(t, built.Root(), document.Name{Space: "http://www.w3.org/1999/XSL/Transform", Local: "stylesheet"})
			assertImportedTree(t, style, coreParse(t, source).Root())

			e, err := transform.NewEngine(transform.Config{AllowedPrograms: []reference.Transform{program}})
			if err != nil {
				t.Fatal(err)
			}

			processing := reference.DefaultOptions()
			processing.Extension = e
			processing.AllowedTransforms = append(processing.AllowedTransforms, reference.XSLT)
			options := xmldsig.SignatureOptions{ExpectedURIs: []string{"#data"}, Processing: processing}
			key := coreEC(t)

			signed, err := xmldsig.SignTemplate(t.Context(), built, selected, key, xmldsig.TemplateSignOptions{Validation: options})
			if err != nil {
				t.Fatal(err)
			}

			result, err := xmldsig.VerifySignature(t.Context(), signed, xmldsig.Signatures(signed)[0], key.Public(), options)
			if err != nil {
				t.Fatal(err)
			}

			var output bytes.Buffer
			if _, err := result.References()[0].WriteDigestInput(t.Context(), &output); err != nil {
				t.Fatal(err)
			}

			assertImportedTree(t, coreParse(t, output.String()).Root(), coreParse(t, literal).Root())
		})
	}
}

func TestImportedStylesheetDefaultNamespaceAndQNames(t *testing.T) {
	for _, tt := range []struct{ name, declarations, body, expected string }{
		{"default", `xmlns="urn:literal"`, `<result><empty xmlns=""/></result>`, `<result xmlns="urn:literal"><empty xmlns=""/></result>`},
		{"QName", `xmlns:p="urn:source"`, `<xsl:element name="p:result"><xsl:value-of select="//p:value"/></xsl:element>`, `<p:result xmlns:p="urn:source">123</p:result>`},
	} {
		t.Run(tt.name, func(t *testing.T) {
			source := `<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="1.0" ` + tt.declarations + `><xsl:output omit-xml-declaration="yes"/><xsl:template match="/">` + tt.body + `</xsl:template></xsl:stylesheet>`
			host := coreParse(t, `<host xmlns="urn:host" xmlns:p="urn:conflict"/>`)
			before := coreXML(t, host)

			built, _, err := xmldsig.BuildTemplate(t.Context(), host, host.Root(), xmldsig.SignatureTemplate{SignatureMethod: xmldsig.ECDSASHA256, References: []xmldsig.ReferenceTemplate{{URI: uriUrnData, Transforms: []reference.Transform{{Algorithm: reference.XSLT, Stylesheet: []byte(source)}}}}})
			if err != nil {
				t.Fatal(err)
			}

			style := findImportElement(t, built.Root(), document.Name{Space: "http://www.w3.org/1999/XSL/Transform", Local: "stylesheet"})
			assertImportedTree(t, style, coreParse(t, source).Root())

			var serialized bytes.Buffer
			if err := c14n.WriteElement(t.Context(), &serialized, style, c14n.Options{Algorithm: c14n.Canonical10}); err != nil {
				t.Fatal(err)
			}

			e, err := transform.NewEngine(transform.Config{})
			if err != nil {
				t.Fatal(err)
			}

			sheet, err := e.CompileXSLT(t.Context(), serialized.Bytes(), transform.XSLTOptions{})
			if err != nil {
				t.Fatal(err)
			}

			input, err := e.Parse(t.Context(), []byte(`<data xmlns:q="urn:source"><q:value>123</q:value></data>`))
			if err != nil {
				t.Fatal(err)
			}

			output, err := sheet.Transform(t.Context(), input, transform.XSLTContext{})
			if err != nil {
				t.Fatal(err)
			}

			assertImportedTree(t, coreParse(t, string(output.Primary)).Root(), coreParse(t, tt.expected).Root())

			if coreXML(t, host) != before {
				t.Fatal("source snapshot changed")
			}
		})
	}
}
