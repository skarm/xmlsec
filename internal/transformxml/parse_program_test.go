package transformxml_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/internal/transformxml"
	"github.com/skarm/xmlsec/internal/tree"
	"github.com/skarm/xmlsec/reference"
)

func TestParseProgramRejectsInvalidParameterShape(t *testing.T) {
	t.Parallel()
	const dsPrefix = `xmlns:ds="http://www.w3.org/2000/09/xmldsig#"`
	const expressionBytes = 16 << 10
	for _, tc := range []struct {
		name, algorithm, body string
		want                  error
	}{
		{"missing_algorithm", "", `<ds:XPath>true()</ds:XPath>`, reference.ErrInput},
		{"xpath_cannot_use_filter", reference.XPath, `<ds:XPath Filter="intersect">true()</ds:XPath>`, reference.ErrInput},
		{"xpath_must_be_text", reference.XPath, `<ds:XPath><test/></ds:XPath>`, reference.ErrInput},
		{"xpath_requires_one_parameter", reference.XPath, `<ds:XPath>true()</ds:XPath><ds:XPath>false()</ds:XPath>`, reference.ErrInput},
		{"xpath_limit_combines_split_text", reference.XPath, `<ds:XPath>` + strings.Repeat(" ", expressionBytes) + `<!-- boundary -->x</ds:XPath>`, reference.ErrLimit},
		{"xslt_requires_one_stylesheet", reference.XSLT, "", reference.ErrInput},
		{"xslt_requires_stylesheet_element", reference.XSLT, `<test/>`, reference.ErrInput},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			attribute := ""
			if tc.algorithm != "" {
				attribute = ` Algorithm="` + tc.algorithm + `"`
			}
			source := `<ds:Transform ` + dsPrefix + attribute + `>` + tc.body + `</ds:Transform>`
			doc, err := document.Parse(t.Context(), []byte(source), document.DefaultLimits())
			if err != nil {
				t.Fatal(err)
			}
			if _, err := transformxml.ParseProgram(t.Context(), tree.Root(doc), doc); !errors.Is(err, tc.want) {
				t.Fatalf("ParseProgram error = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestParseProgramPropagatesCancellation(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct{ name, algorithm, body string }{
		{"xpath", reference.XPath, `<ds:XPath>true()</ds:XPath>`},
		{"xslt", reference.XSLT, `<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="1.0"/>`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			source := `<ds:Transform xmlns:ds="http://www.w3.org/2000/09/xmldsig#" Algorithm="` + tc.algorithm + `">` + tc.body + `</ds:Transform>`
			doc, err := document.Parse(t.Context(), []byte(source), document.DefaultLimits())
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(t.Context())
			cancel()
			got, err := transformxml.ParseProgram(ctx, tree.Root(doc), doc)
			if !errors.Is(err, context.Canceled) || len(got.XPath) != 0 || len(got.Stylesheet) != 0 {
				t.Fatalf("cancelled ParseProgram = %+v, %v; want no decoded parameters and context.Canceled", got, err)
			}
		})
	}
}
