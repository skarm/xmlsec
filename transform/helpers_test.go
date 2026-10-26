package transform_test

import (
	"testing"

	"github.com/skarm/xmlsec/transform"
)

const sheetStart = `<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:xs="http://www.w3.org/2001/XMLSchema" version="`

const (
	visibilityPrivate          = "private"
	integerPairText            = "1 2"
	cyclicAttributeSets        = `<xsl:attribute-set name="a" use-attribute-sets="b"/><xsl:attribute-set name="b" use-attribute-sets="a"/>`
	indirectAttributeSetCycle  = `<xsl:attribute-set name="a"><xsl:attribute name="value"><xsl:value-of select="Q{urn:cycle}f()"/></xsl:attribute></xsl:attribute-set><xsl:function name="Q{urn:cycle}f"><xsl:variable name="tree"><r xsl:use-attribute-sets="a"/></xsl:variable><xsl:sequence select="$tree/r/@value"/></xsl:function>`
	activeAttributeSetTemplate = `<xsl:template name="start"><r xsl:use-attribute-sets="a"/></xsl:template>`
)

const (
	packageFunctionInvocation = `<xsl:value-of select="p:f()"/>`
	packageTemplateInvocation = `<xsl:call-template name="p:t"/>`
	emptyPackageFunction      = `<xsl:function name="p:f"/>`
	emptyPackageTemplate      = `<xsl:template name="p:t"/>`
	errCodeXTDE3052           = "XTDE3052"
	errCodeXTSE3070           = "XTSE3070"
)

const (
	emptyPackageVersionAttribute = `package-version=""`
	errCodeXTSE3020              = "XTSE3020"
	invalidValue                 = "invalid"
	errCodeXTSE0090              = "XTSE0090"
	resultBindingName            = `result`
	deliveryRawOption            = `,'delivery-format':'raw'`
	deliveryDocumentOption       = `,'delivery-format':'document'`
	mixedResultTemplate          = `<xsl:template name="start"><xsl:sequence select="(1,2)"/><xsl:text/><r/><xsl:sequence select="true()"/></xsl:template>`
	unbuiltResultTemplate        = `<xsl:output build-tree="no"/><xsl:template name="start"><xsl:sequence select="(1,2)"/></xsl:template>`
	emptyMapExpression           = `map{}`
	falseExpression              = `false()`
	trueExpression               = `true()`
	afterAssertionText           = `after`
)

const (
	higherResultText      = "higher"
	nameImport            = "import"
	errCodeXTSE0740       = "XTSE0740"
	errCodeXTSE0812       = "XTSE0812"
	errCodeXTDE0640       = "XTDE0640"
	errCodeXTSE0650       = "XTSE0650"
	errCodeXTSE0660       = "XTSE0660"
	errCodeXTSE0170       = "XTSE0170"
	errCodeXTSE0180       = "XTSE0180"
	errCodeXTSE0190       = "XTSE0190"
	errCodeXTSE0210       = "XTSE0210"
	errCodeXTTE3090       = "XTTE3090"
	errCodeXTDE0044       = "XTDE0044"
	errCodeXTDE0045       = "XTDE0045"
	errCodeXTSE0020       = "XTSE0020"
	errCodeXTSE0280       = "XTSE0280"
	integerSequenceText   = "1 2 3"
	errCodeXTSE1660       = "XTSE1660"
	errCodeXTMM9001       = "XTMM9001"
	errCodeXTMM9000       = "XTMM9000"
	namespaceAssertions   = "urn:assertions"
	nameAssertionAlarm    = "ALARM"
	assertionErrorText    = "urn:assertions:ALARM"
	namespaceErrors       = "http://www.w3.org/2005/xqt-errors"
	version40             = "4.0"
	nameFallbackResult    = "fallback"
	stylesheetFallback    = `<xsl:new-instruction><xsl:fallback><xsl:text>fallback</xsl:text></xsl:fallback></xsl:new-instruction>`
	errCodeXTSE0010       = "XTSE0010"
	errCodeXTDE0040       = "XTDE0040"
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

	q, err := e.CompileXPath(t.Context(), source, transform.XPathOptions{Version: v})
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

	result, err := query(t, e, source, v).Evaluate(t.Context(), nil, transform.XPathContext{})
	if err != nil {
		t.Fatal(err)
	}

	return result
}

func stylesheet(t testing.TB, e *transform.Engine, source string) *transform.Stylesheet {
	t.Helper()

	s, err := e.CompileXSLT(t.Context(), []byte(source), transform.XSLTOptions{})
	if err != nil {
		t.Fatal(err)
	}

	return s
}

func sheet(version, body string) string {
	return sheetStart + version + `"><xsl:output method="text"/>` + body + `</xsl:stylesheet>`
}

func packageSheet(attributes, body string) string {
	return `<xsl:package xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:p="urn:components" version="3.0" ` + attributes + `><xsl:output method="text"/>` + body + `</xsl:package>`
}

func evaluateNumericInvocation(t testing.TB, q *transform.XPath) transform.Sequence {
	t.Helper()

	result, err := q.Evaluate(t.Context(), nil, transform.XPathContext{})
	if err != nil {
		t.Fatal(err)
	}

	return result
}

func comparisonErrorCode(value string) bool {
	if len(value) != 8 {
		return false
	}

	for i, c := range value {
		if i < 4 {
			if c < 'A' || c > 'Z' {
				return false
			}
		} else if c < '0' || c > '9' {
			return false
		}
	}

	return true
}
