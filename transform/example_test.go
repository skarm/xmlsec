package transform_test

import (
	"context"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/skarm/xmlsec/transform"
)

func ExampleEngine_CompileXPath() {
	ctx := context.Background()

	engine, err := transform.NewEngine(transform.Config{})
	if err != nil {
		log.Fatal(err)
	}

	doc, err := engine.Parse(ctx, []byte(`<order><price>0.1</price><price>0.2</price></order>`))
	if err != nil {
		log.Fatal(err)
	}

	query, err := engine.CompileXPath(ctx,
		`sum(/order/price ! xs:decimal(.)) + $extra`, transform.XPathOptions{
			Version: transform.XPath31,
		})
	if err != nil {
		log.Fatal(err)
	}

	result, err := query.Evaluate(ctx, doc, transform.XPathContext{
		Variables: transform.Bindings{
			{Local: "extra"}: transform.Values(transform.Integer(2)),
		},
	})
	if err != nil {
		log.Fatal(err)
	}

	text, err := result.Text()
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(text)
	// Output: 2.3
}

func ExampleResult_WriterTo() {
	ctx := context.Background()

	engine, err := transform.NewEngine(transform.Config{})
	if err != nil {
		log.Fatal(err)
	}

	doc, err := engine.ParseReader(ctx, strings.NewReader(`<invoice><amount>42</amount></invoice>`))
	if err != nil {
		log.Fatal(err)
	}

	sheet, err := engine.CompileXSLTReader(ctx, strings.NewReader(`<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="3.0"><xsl:output method="text"/><xsl:template match="/"><xsl:value-of select="invoice/amount"/></xsl:template></xsl:stylesheet>`), transform.XSLTOptions{})
	if err != nil {
		log.Fatal(err)
	}

	result, err := sheet.Execute(ctx, doc, transform.XSLTContext{})
	if err != nil {
		log.Fatal(err)
	}
	// The input and complete XSLT result are resident before serialization starts.
	source := result.WriterTo(ctx)
	if _, err := source.WriteTo(os.Stdout); err != nil {
		log.Fatal(err) // stdout may already contain a prefix.
	}

	// Output: 42
}
