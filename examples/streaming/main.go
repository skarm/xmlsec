// Command streaming transforms independent <item> records from a <feed> on stdin.
// Example: printf '<feed><item id="1"/><item id="2"/></feed>' | go run ./examples/streaming -stdin
// Each record and its result remain in memory until written. A later XML or
// output error can follow already written records; stdout is not transactional.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/transform"
)

func main() {
	stdin := flag.Bool("stdin", false, "read a <feed> from stdin instead of the demonstration input")

	flag.Parse()

	var input io.Reader = strings.NewReader(`<feed><item id="1">a</item><item id="2">b</item></feed>`)
	if *stdin {
		input = os.Stdin
	}

	if err := run(context.Background(), input, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(ctx context.Context, input io.Reader, output io.Writer) error {
	engine, err := transform.NewEngine(transform.Config{Limits: transform.Limits{Timeout: time.Minute}})
	if err != nil {
		return err
	}

	source := []byte(`<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="3.0"><xsl:output method="xml" omit-xml-declaration="yes"/><xsl:template match="/"><record id="{item/@id}"><xsl:value-of select="item"/></record></xsl:template></xsl:stylesheet>`)

	sheet, err := engine.CompileXSLT(ctx, source, transform.XSLTOptions{})
	if err != nil {
		return err
	}

	recordLimits := document.DefaultLimits()
	recordLimits.MaxBytes = 1 << 20

	_, err = sheet.WriteRecords(ctx, output, input, transform.StreamOptions{
		Records: document.RecordOptions{
			Path:          []document.Name{{Local: "feed"}, {Local: "item"}},
			Limits:        recordLimits,
			MaxInputBytes: 64 << 20,
			MaxRecords:    10_000,
		},
		Separator:      "\n",
		MaxOutputBytes: 64 << 20,
	})

	return err
}
