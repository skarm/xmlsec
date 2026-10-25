package transform_test

import (
	"context"
	"testing"

	"github.com/skarm/xmlsec/transform"
)

const sheetStart = `<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:xs="http://www.w3.org/2001/XMLSchema" version="`

const (
	nameInclude           = "include"
	compatSequenceText    = "1030 40"
	namespaceCustom       = "urn:custom"
	errCodeXPST0051       = "XPST0051"
	errCodeXQST0070       = "XQST0070"
	errCodeFODC0006       = "FODC0006"
	errCodeFOXT0001       = "FOXT0001"
	namespaceSchema       = "http://www.w3.org/2001/XMLSchema"
	xmlASCIIEncoding      = "US-ASCII"
	xmlLatinText          = "café"
	xmlCharacters         = "café 中"
	xmlLatinEncoding      = "ISO-8859-1"
	sourceName            = "source"
	variableStylesheet    = "stylesheet"
	namespaceApplication  = "urn:application"
	applicationErrorLocal = "oops"
	name03                = "0.3"
	version10             = "1.0"
	version20             = "2.0"
	version30             = "3.0"
	errCodeFORX0002       = "FORX0002"
	nameInfinity          = "Infinity"
	valueNaN              = "NaN"
	nameDouble            = "double"
	namespaceFunctions    = "http://www.w3.org/2005/xpath-functions"
	nameNumber1e2         = "number('1e2')"
	nameStart             = "start"
	nameTrue              = "true"
	nameItem              = "item"
	nameUnion             = "union"
	namespaceP            = "urn:p"
	nameYes               = "yes"
)

func engine(t testing.TB, config transform.Config) *transform.Engine {
	t.Helper()

	e, err := transform.NewEngine(config)
	if err != nil {
		t.Fatal(err)
	}

	return e
}

func query(t testing.TB, e *transform.Engine, source string, v transform.XPathVersion) *transform.XPath {
	t.Helper()

	q, err := e.CompileXPath(context.Background(), source, transform.XPathOptions{Version: v})
	if err != nil {
		t.Fatal(err)
	}

	return q
}

func text(t testing.TB, seq transform.Sequence) string {
	t.Helper()

	value, err := seq.Text()
	if err != nil {
		t.Fatal(err)
	}

	return value
}

func evaluate(t testing.TB, e *transform.Engine, source string, v transform.XPathVersion) transform.Sequence {
	t.Helper()

	result, err := query(t, e, source, v).Evaluate(context.Background(), nil, transform.XPathContext{})
	if err != nil {
		t.Fatal(err)
	}

	return result
}

func stylesheet(t testing.TB, e *transform.Engine, source string) *transform.Stylesheet {
	t.Helper()

	s, err := e.CompileXSLT(context.Background(), []byte(source), transform.XSLTOptions{})
	if err != nil {
		t.Fatal(err)
	}

	return s
}

func sheet(version, body string) string {
	return sheetStart + version + `"><xsl:output method="text"/>` + body + `</xsl:stylesheet>`
}

func evaluateNumericInvocation(t testing.TB, q *transform.XPath) transform.Sequence {
	t.Helper()

	result, err := q.Evaluate(t.Context(), nil, transform.XPathContext{})
	if err != nil {
		t.Fatal(err)
	}

	return result
}
