// Command transforms demonstrates the unified modern XPath and XSLT API.
package main

import (
	"context"
	"fmt"
	"os"

	"github.com/skarm/xmlsec/transform"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	ctx := context.Background()

	engine, err := transform.NewEngine(transform.Config{})
	if err != nil {
		return err
	}

	source, err := engine.Parse(ctx, []byte(`<order><price>0.1</price><price>0.2</price></order>`))
	if err != nil {
		return err
	}

	query, err := engine.CompileXPath(ctx, `map{'total': sum(/order/price ! xs:decimal(.))}?total + $extra`, transform.XPathOptions{Version: transform.XPath31})
	if err != nil {
		return err
	}

	parameters := transform.Bindings{{Local: "extra"}: transform.Values(transform.Integer(2))}

	value, err := query.Evaluate(ctx, source, transform.XPathContext{Variables: parameters})
	if err != nil {
		return err
	}

	total, err := value.Text()
	if err != nil {
		return err
	}

	fmt.Println("XPath:", total)

	stylesheet := []byte(`<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="3.0"><xsl:param name="extra"/><xsl:output method="text"/><xsl:template match="/"><xsl:value-of select="sum(/order/price ! xs:decimal(.))+$extra" xmlns:xs="http://www.w3.org/2001/XMLSchema"/></xsl:template></xsl:stylesheet>`)

	compiled, err := engine.CompileXSLT(ctx, stylesheet, transform.XSLTOptions{Version: transform.XSLT30})
	if err != nil {
		return err
	}

	output, err := compiled.Transform(ctx, source, transform.XSLTContext{Parameters: parameters})
	if err != nil {
		return err
	}

	fmt.Println("XSLT:", string(output.Primary))

	return nil
}
