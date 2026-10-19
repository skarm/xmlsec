package xmldsig_test

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/reference"
	"github.com/skarm/xmlsec/transform"
	"github.com/skarm/xmlsec/xmldsig"
)

func TestJDKV1Transforms(t *testing.T) {
	dir := filepath.Join("..", "..", "..", "testdata", "transforms")

	raw, e := os.ReadFile(filepath.Join(dir, "manifest.json"))
	if e != nil {
		t.Fatal(e)
	}

	var m struct {
		PublicKey string `json:"public_key"`
		Cases     []struct {
			File, Kind string
			Valid      bool
		}
	}
	if e = json.Unmarshal(raw, &m); e != nil {
		t.Fatal(e)
	}

	raw, e = os.ReadFile(filepath.Join(dir, m.PublicKey))
	if e != nil {
		t.Fatal(e)
	}

	pemBlock, _ := pem.Decode(raw)
	if pemBlock == nil {
		t.Fatal("public PEM")
	}

	key, e := x509.ParsePKIXPublicKey(pemBlock.Bytes)
	if e != nil {
		t.Fatal(e)
	}

	for _, c := range m.Cases {
		t.Run(c.File, func(t *testing.T) {
			tr := fixtureProgram(t, c.Kind)

			engine, err := transform.NewEngine(transform.Config{AllowedPrograms: []reference.Transform{tr}})
			if err != nil {
				t.Fatal(err)
			}

			o := xmldsig.SignatureOptions{ExpectedURIs: []string{"#payload", "#payload"}, Processing: reference.DefaultOptions()}
			o.Processing.AllowedTransforms = append(o.Processing.AllowedTransforms, tr.Algorithm)
			o.Processing.Extension = engine

			raw, e := os.ReadFile(filepath.Join(dir, c.File))
			if e != nil {
				t.Fatal(e)
			}

			d, e := document.Parse(t.Context(), raw, document.DefaultLimits())
			if e != nil {
				t.Fatal(e)
			}

			r, report, e := xmldsig.VerifySignatureDetailed(context.Background(), d, xmldsig.Signatures(d)[0], key, o)
			if c.Valid {
				if e != nil || r == nil || report.Status != "valid" {
					t.Fatal(report, e)
				}
			} else if e == nil || r != nil || report.Status == "valid" {
				t.Fatal("tampered transform fixture accepted", report, e)
			}
		})
	}
}

func fixtureProgram(t testing.TB, kind string) reference.Transform {
	t.Helper()

	ns := map[string]string{"ds": xmldsig.Namespace, "xf": reference.XPathFilter2, "xml": document.XMLNamespace}
	x := reference.XPathExpression{Namespaces: ns}

	switch kind {
	case "xpath", "xpath-context", "xpath-here":
		x.Expression = "not(ancestor-or-self::volatile)"
		if kind == "xpath-context" {
			x.Expression += " and position()=1 and last()=1"
		}

		if kind == "xpath-here" {
			x.Expression += " and count(here()/ancestor::ds:Signature)=1"
		}

		return reference.Transform{Algorithm: reference.XPath, XPath: []reference.XPathExpression{x}}
	case "filter", "filter-here", "filter-sequence":
		x.Expression = "//volatile"

		x.Filter = "subtract"
		if kind == "filter-here" {
			x.Expression = "here()/ancestor::ds:Signature/preceding-sibling::payload/volatile"
		}

		xs := []reference.XPathExpression{x}
		if kind == "filter-sequence" {
			xs = []reference.XPathExpression{{Expression: "//payload", Filter: "intersect", Namespaces: ns}, x, {Expression: "//volatile/keep", Filter: "union", Namespaces: ns}}
		}

		return reference.Transform{Algorithm: reference.XPathFilter2, XPath: xs}
	case "xslt-text":
		return reference.Transform{Algorithm: reference.XSLT, Stylesheet: []byte(`<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:ds="` + xmldsig.Namespace + `" xmlns:xf="` + reference.XPathFilter2 + `" version="1.0"><xsl:output method="text"/><xsl:template match="/"><xsl:value-of select="//fixed"/></xsl:template></xsl:stylesheet>`)}
	}

	t.Fatalf("unknown fixture %q", kind)

	return reference.Transform{}
}
