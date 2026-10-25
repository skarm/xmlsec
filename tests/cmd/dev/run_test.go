package main

import (
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/skarm/xmlsec/transform"
)

const (
	suiteQTNamespace = "http://www.w3.org/2010/09/qt-fots-catalog"
)

func TestExternalSuiteOutcomes(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}

	namespace := suiteQTNamespace
	writeFixture(t, root, suiteCatalog, `<catalog xmlns="`+namespace+`"><test-set name="numeric" file="numeric.xml"/></catalog>`)
	writeFixture(t, root, "numeric.xml", `<test-set xmlns="`+namespace+`" name="numeric">
	  <test-case name="pass"><test>1 + 1</test><result><assert-eq>2</assert-eq></result></test-case>
	  <test-case name="fail"><test>1 + 1</test><result><assert-eq>3</assert-eq></result></test-case>
	  <test-case name="standard-error"><test>1 idiv 0</test><result><error code="FOAR0001"/></result></test-case>
	  <test-case name="no-context"><test>.</test><result><error code="XPDY0002"/></result></test-case>
	  <test-case name="schema-optional"><dependency type="feature" value="schemaImport"/><test>1</test><result><assert-eq>1</assert-eq></result></test-case>
	  <test-case name="other-language"><dependency type="feature" value="unknown"/><dependency type="spec" value="XQ31+"/><test>1</test><result><assert-eq>1</assert-eq></result></test-case>
	  <test-case name="unknown-dependency"><dependency type="feature" value="unknown"/><test>1</test><result><assert-eq>1</assert-eq></result></test-case>
	  <test-case name="unsupported-assertion"><test>1</test><result><not><unknown-assertion/></not></result></test-case>
	  <test-case name="execution-error-under-not"><test>1 idiv 0</test><result><not><assert-eq>2</assert-eq></not></result></test-case>
	  <test-case name="false-is-not-true"><test>false()</test><result><assert-true/></result></test-case>
	  <test-case name="filter-out"><test>1</test><result><assert-eq>1</assert-eq></result></test-case>
	</test-set>`)

	options := suiteOptions{kind: suiteQT3, directory: root, version: suiteVersion31, timeout: time.Second, setMatch: regexp.MustCompile(".*"), caseMatch: regexp.MustCompile("^(pass|fail|standard-error|no-context|schema-optional|other-language|unknown-dependency|unsupported-assertion|execution-error-under-not|false-is-not-true)$")}

	report, err := executeSuite(t.Context(), options, suitePin{Catalog: suiteCatalog, Namespace: namespace})
	if err != nil {
		t.Fatal(err)
	}

	want := map[string]string{"pass": suitePassed, "fail": suiteFailed, "standard-error": suitePassed, "no-context": suitePassed, "schema-optional": suiteNotApplicable, "other-language": suiteNotApplicable, "unknown-dependency": suiteFailed, "unsupported-assertion": suiteFailed, "execution-error-under-not": suiteFailed, "false-is-not-true": suiteFailed, "filter-out": suiteSkipped}
	if len(report.Cases) != len(want) {
		t.Fatal("test inventory changed", len(report.Cases))
	}

	for _, outcome := range report.Cases {
		if outcome.Status != want[outcome.Name] {
			t.Fatalf("%s: got %s (%s), want %s", outcome.Name, outcome.Status, outcome.Reason, want[outcome.Name])
		}

		if outcome.Status != suitePassed && outcome.Reason == "" {
			t.Fatal("non-pass lacks a reason", outcome)
		}

		if outcome.Name == "unsupported-assertion" && outcome.Kind != suiteHarnessFailure {
			t.Fatal("an unsupported assertion was mistaken for a successful negative check", outcome)
		}
	}

	if report.Totals[suitePassed] != 3 || report.Totals[suiteFailed] != 5 || report.Totals[suiteNotApplicable] != 2 || report.Totals[suiteSkipped] != 1 {
		t.Fatal("outcome counts changed", report.Totals)
	}
}

func TestSuiteStaticContextsAndReferences(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}

	const namespace = suiteQTNamespace
	writeFixture(t, root, suiteCatalog, `<catalog xmlns="`+namespace+`"><environment name="base"><param name="inherited" select="2"/></environment><test-set name="static" file="static.xml"/></catalog>`)
	writeFixture(t, root, "static.xml", `<test-set xmlns="`+namespace+`" xmlns:app="urn:application">
	  <environment name="parent" ref="base"><param name="ignored" select="1 idiv 0"/></environment>
	  <environment name="cycle" ref="cycle"/>
	  <test-case name="reference"><environment ref="parent"><param name="also-ignored" select="1 idiv 0"/></environment><test>$inherited</test><result><assert-eq>2</assert-eq></result></test-case>
	  <test-case name="decimal"><environment><decimal-format name="f:local" xmlns:f="urn:format" minus-sign="_"/><decimal-format decimal-separator="," grouping-separator="."/><namespace prefix="f" uri="urn:format"/></environment>
	    <test>format-number(12.5, '0,00') || '|' || format-number(-1, '0', 'f:local')</test><result><assert-string-value>12,50|_1</assert-string-value></result></test-case>
	  <test-case name="error-alias"><test>error(QName('urn:application','oops'))</test><result><all-of><error code="app:oops"/><error xmlns:e="urn:application" code="e:oops"/></all-of></result></test-case>
	  <test-case name="assertion-scope"><test>QName('urn:application','selected')</test><result><all-of xmlns:e="urn:application"><assert>$result eq xs:QName('e:selected')</assert><assert xmlns:e="urn:other">$result ne xs:QName('e:selected')</assert><assert>$result eq xs:QName('e:selected')</assert></all-of></result></test-case>
	  <test-case name="cycle"><environment ref="cycle"/><test>1</test><result><error code="*"/></result></test-case>
	  <test-case name="unknown"><environment ref="missing"/><test>1</test><result><error code="*"/></result></test-case>
	  <test-case name="decimal-conflict"><environment><decimal-format name="f" digit="?"/><decimal-format name="f" digit="!"/></environment><test>1</test><result><error code="*"/></result></test-case>
	</test-set>`)
	options := suiteOptions{kind: suiteQT3, directory: root, version: suiteVersion31, timeout: time.Second, setMatch: regexp.MustCompile(".*"), caseMatch: regexp.MustCompile(".*")}

	report, err := executeSuite(t.Context(), options, suitePin{Catalog: suiteCatalog, Namespace: namespace})
	if err != nil {
		t.Fatal(err)
	}

	for index, outcome := range report.Cases {
		if index < 4 && outcome.Status != suitePassed || index >= 4 && (outcome.Status != suiteFailed || outcome.Kind != suiteHarnessFailure) {
			t.Fatal("static-context outcome changed", outcome)
		}
	}
}

func TestSuiteTextMetadata(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}

	const namespace = suiteQTNamespace
	writeFixture(t, root, suiteCatalog, `<catalog xmlns="`+namespace+`"><test-set name="text" file="text.xml"/></catalog>`)
	writeFixture(t, root, "text.dat", "\xfe\xff\x00x")
	writeFixture(t, root, "text.xml", `<test-set xmlns="`+namespace+`"><test-case name="metadata"><environment><resource file="text.dat" uri="urn:text" media-type="text/plain" encoding="utf-16"/></environment><test>unparsed-text('urn:text', 'ascii')</test><result><assert-string-value>x</assert-string-value></result></test-case></test-set>`)
	options := suiteOptions{kind: suiteQT3, directory: root, version: suiteVersion31, timeout: time.Second, setMatch: regexp.MustCompile(".*"), caseMatch: regexp.MustCompile(".*")}

	report, err := executeSuite(t.Context(), options, suitePin{Catalog: suiteCatalog, Namespace: namespace})
	if err != nil || len(report.Cases) != 1 || report.Cases[0].Status != suitePassed {
		t.Fatal("text transport metadata", report, err)
	}
}

func TestSuiteStylesheetVersionDeclarations(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}

	for _, test := range []struct {
		name, stylesheet string
	}{
		{"ordinary20", `<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="2.0"/>`},
		{"ordinary30", `<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="3.0"/>`},
		{"simplified20", `<out xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xsl:version="2.0"/>`},
		{"simplified30", `<out xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xsl:version="3.0"/>`},
		{"alias30", `<out xmlns:s="http://www.w3.org/1999/XSL/Transform" s:version="3.0"/>`},
		{"future", `<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="4.0"/>`},
	} {
		t.Run(test.name, func(t *testing.T) {
			writeFixture(t, root, "main.xsl", test.stylesheet)

			e, err := transform.NewEngine(transform.Config{})
			if err != nil {
				t.Fatal(err)
			}

			for _, version := range []string{suiteVersion20, suiteVersion30} {
				environment := &preparedSuiteEnvironment{engine: e, stylesheet: suiteEnvironmentRef{node: &suiteNode{Attributes: []xml.Attr{{Name: xml.Name{Local: suiteFile}, Value: "main.xsl"}}}, base: root}}

				compiled, err := compileSuiteStylesheet(t.Context(), suiteOptions{directory: root, version: version}, environment)
				if err != nil || int(compiled.Version()) != map[string]int{suiteVersion20: 20, suiteVersion30: 30}[version] {
					t.Fatal("inaccurate selected processor", version, compiled, err)
				}
			}
		})
	}
}

func TestSuiteExplicitBudgets(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}

	const namespace = suiteQTNamespace
	writeFixture(t, root, suiteCatalog, `<catalog xmlns="`+namespace+`"><test-set name="budget" file="budget.xml"/></catalog>`)
	writeFixture(t, root, "budget.xml", `<test-set xmlns="`+namespace+`"><test-case name="sequence"><test>1 to 100001</test><result><assert-count>100001</assert-count></result></test-case></test-set>`)

	for _, profile := range []string{"default", "language"} {
		options := suiteOptions{kind: suiteQT3, directory: root, version: suiteVersion31, limitsProfile: profile, timeout: 3 * time.Second, setMatch: regexp.MustCompile(".*"), caseMatch: regexp.MustCompile(".*")}

		report, err := executeSuite(t.Context(), options, suitePin{Catalog: suiteCatalog, Namespace: namespace})
		if err != nil || len(report.Cases) != 1 {
			t.Fatal(report, err)
		}

		outcome := report.Cases[0]
		if profile == "default" && (outcome.Status != suiteFailed || outcome.Kind != "resource-limit") || profile == "language" && outcome.Status != suitePassed {
			t.Fatal("explicit language budgets did not control execution", profile, outcome)
		}
	}

	var stderr bytes.Buffer
	if _, err := parseSuiteOptions([]string{suiteDirectoryFlag, root, "-limits=unbounded"}, &stderr); err == nil {
		t.Fatal("unbounded suite budget accepted")
	}
}

func TestSuiteDatatypeEditions(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}

	writeFixture(t, root, suiteCatalog, `<catalog xmlns="`+suiteQTNamespace+`"><test-set name="editions" file="editions.xml"/></catalog>`)
	writeFixture(t, root, "editions.xml", `<test-set xmlns="`+suiteQTNamespace+`">
	 <test-case name="old-inf"><dependency type="xsd-version" value="1.0"/><test>xs:double('+INF')</test><result><error code="FORG0001"/></result></test-case>
	 <test-case name="new-inf"><dependency type="xsd-version" value="1.1"/><test>xs:double('+INF')</test><result><assert-eq>xs:double('INF')</assert-eq></result></test-case>
	 <test-case name="old-year"><dependency type="xsd-version" value="1.0"/><test>xs:gYear('0000')</test><result><error code="FORG0001"/></result></test-case>
	 <test-case name="new-year"><dependency type="xsd-version" value="1.1"/><test>xs:gYear('0000')</test><result><assert-string-value>0000</assert-string-value></result></test-case>
	 <test-case name="old-regex"><dependency type="xsd-version" value="1.0"/><test>matches('-', '[a-z-x]')</test><result><error code="FORX0002"/></result></test-case>
	 <test-case name="new-regex"><dependency type="xsd-version" value="1.1"/><test>matches('-', '[a-z-x]')</test><result><assert-true/></result></test-case>
	 <test-case name="normalization"><dependency type="unicode-normalization-form" value="FULLY-NORMALIZED"/><test>normalize-unicode('text', 'FULLY-NORMALIZED')</test><result><assert-string-value>text</assert-string-value></result></test-case>
	</test-set>`)

	for _, version := range []string{suiteVersion10, suiteVersion11} {
		options := suiteOptions{kind: suiteQT3, directory: root, version: suiteVersion31, xsdVersion: version, timeout: time.Second, setMatch: regexp.MustCompile(".*"), caseMatch: regexp.MustCompile(".*")}

		report, err := executeSuite(t.Context(), options, suitePin{Catalog: suiteCatalog, Namespace: suiteQTNamespace})
		if err != nil || report.Totals[suitePassed] != 4 || report.Totals[suiteNotApplicable] != 3 || report.Totals[suiteFailed] != 0 || report.Settings["xsd_version"] != version {
			t.Fatal(version, report, err)
		}
	}

	var stderr bytes.Buffer
	if _, err := parseSuiteOptions([]string{suiteDirectoryFlag, root, "-xsd-version=2.0"}, &stderr); err == nil {
		t.Fatal("invalid datatype edition accepted")
	}
}

func TestSuiteUnicodeEdition(t *testing.T) {
	options := suiteOptions{kind: suiteQT3, version: suiteVersion31}
	for _, version := range []string{"5.2", "6.0", "7.0", "9.0", "17.0"} {
		matched, known := suiteDependency(options, "unicode-version", version)
		if !known || matched != (version == "17.0") {
			t.Fatal("Unicode edition is not a minimum version", version, matched, known)
		}
	}
}

func TestSuiteImplementationChoices(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}

	writeFixture(t, root, suiteCatalog, `<catalog xmlns="`+suiteQTNamespace+`"><test-set name="choices" file="choices.xml"/></catalog>`)
	writeFixture(t, root, "choices.xml", `<test-set xmlns="`+suiteQTNamespace+`">
	<test-case name="strict"><dependency type="feature" value="xpath-1.0-compatibility" satisfied="false"/><test>1+'2'</test><result><error code="XPTY0004"/></result></test-case>
	<test-case name="compat"><dependency type="feature" value="xpath-1.0-compatibility"/><test>1+'2'</test><result><assert-eq>3</assert-eq></result></test-case>
	<test-case name="uca"><dependency type="feature" value="simple-uca-fallback"/><test>compare('a','A','http://www.w3.org/2013/collation/UCA?strength=secondary')</test><result><assert-eq>0</assert-eq></result></test-case>
	<test-case name="range"><dependency type="combinations_for_numbering" value="CIRCLED DIGIT ONE" range="0 to 50"/><test>1</test><result><assert-eq>1</assert-eq></result></test-case>
	<test-case name="other-range"><dependency type="combinations_for_numbering" value="CIRCLED DIGIT ONE" range="0 to 9"/><test>1</test><result><assert-eq>1</assert-eq></result></test-case>
	<test-case name="unknown"><dependency type="feature" value="future-unknown-feature"/><test>1</test><result><assert-eq>1</assert-eq></result></test-case>
	</test-set>`)

	for _, compatible := range []bool{false, true} {
		options := suiteOptions{kind: suiteQT3, directory: root, version: suiteVersion31, xpath10Compatibility: compatible, timeout: time.Second, setMatch: regexp.MustCompile(".*"), caseMatch: regexp.MustCompile(".*")}

		report, err := executeSuite(t.Context(), options, suitePin{Catalog: suiteCatalog, Namespace: suiteQTNamespace})
		if err != nil || report.Totals[suitePassed] != 3 || report.Totals[suiteNotApplicable] != 2 || report.Totals[suiteFailed] != 1 || report.Settings["xpath_1_0_compatibility"] != compatible {
			t.Fatal(compatible, report, err)
		}
	}
}

func TestSuitePackageVersionsShareName(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}

	writeFixture(t, root, suiteCatalog, `<catalog xmlns="`+suiteXSLTNamespace+`"><test-set name="packages" file="packages.xml"/></catalog>`)
	writeFixture(t, root, "packages.xml", `<test-set xmlns="`+suiteXSLTNamespace+`"><environment name="versions"><package role="secondary" file="one.xsl" uri="urn:library" package-version="1"/><package role="secondary" file="two.xsl" uri="urn:library" package-version="2"/></environment><test-case name="highest"><environment ref="versions"/><dependencies><package_version_resolution value="highest_version"/></dependencies><test><package role="principal" file="main.xsl"/><initial-template name="main"/></test><result><assert-string-value>2</assert-string-value></result></test-case></test-set>`)

	for name, value := range map[string]string{"one.xsl": "1", "two.xsl": "2"} {
		writeFixture(t, root, name, `<xsl:package xmlns:xsl="`+suiteStylesheetNS+`" version="3.0" name="urn:library" package-version="`+value+`"><xsl:template name="value" visibility="public"><xsl:text>`+value+`</xsl:text></xsl:template></xsl:package>`)
	}

	writeFixture(t, root, "main.xsl", `<xsl:package xmlns:xsl="`+suiteStylesheetNS+`" version="3.0" name="urn:application" package-version="1"><xsl:use-package name="urn:library" package-version="1+"/><xsl:template name="main" visibility="public"><xsl:call-template name="value"/></xsl:template></xsl:package>`)
	options := suiteOptions{kind: suiteXSLT, directory: root, version: suiteVersion30, timeout: time.Second, setMatch: regexp.MustCompile(".*"), caseMatch: regexp.MustCompile(".*")}

	report, err := executeSuite(t.Context(), options, suitePin{Catalog: suiteCatalog, Namespace: suiteXSLTNamespace})
	if err != nil || report.Totals[suitePassed] != 1 || report.Totals[suiteFailed] != 0 {
		t.Fatal(report, err)
	}
}

func TestSuiteXMLAndStringAssertions(t *testing.T) {
	const xmlOne = `parse-xml('<a>one</a>')`

	const spacedString = `' a  b '`

	engine, err := transform.NewEngine(transform.Config{})
	if err != nil {
		t.Fatal(err)
	}

	environment := &preparedSuiteEnvironment{engine: engine, namespaces: map[string]string{}, variables: transform.Bindings{}}

	for _, test := range []struct {
		name, expression, assertion, kind string
		pass                              bool
	}{
		{"assertion result context", `parse-xml('<out>7</out>')`, `<assert>/out = '7'</assert>`, suiteXSLT, true},
		{"exact QT3 whitespace", spacedString, `<assert-string-value>a b</assert-string-value>`, suiteQT3, false},
		{"default XSLT whitespace", spacedString, `<assert-string-value>a b</assert-string-value>`, suiteXSLT, true},
		{"explicit QT3 normalization", spacedString, `<assert-string-value normalize-space="true">a b</assert-string-value>`, suiteQT3, true},
		{"XML fragment", `parse-xml-fragment('<a/>text<b/>')`, `<assert-xml>&lt;a/>text&lt;b/></assert-xml>`, suiteQT3, true},
		{"XML BOM and declaration", `parse-xml('<a>café 中</a>')`, "<assert-xml>\uFEFF&lt;?xml version=\"1.0\" encoding=\"UTF-8\"?>\n&lt;a>café 中&lt;/a>\n</assert-xml>", suiteQT3, true},
		{"XML fragment declaration", `parse-xml-fragment('<a/>text<b/>')`, `<assert-xml>&lt;?xml version="1.0"?>&lt;a/>text&lt;b/></assert-xml>`, suiteQT3, true},
		{"XML unterminated declaration", xmlOne, `<assert-xml>&lt;?xml version="1.0" &lt;a>one&lt;/a></assert-xml>`, suiteQT3, false},
		{"XML text change", xmlOne, `<assert-xml>&lt;a>two&lt;/a></assert-xml>`, suiteQT3, false},
		{"XML prefix preserved", `parse-xml('<p:a xmlns:p="urn:a"/>')`, `<assert-xml>&lt;q:a xmlns:q="urn:a"/></assert-xml>`, suiteQT3, false},
		{"XML prefix explicitly ignored", `parse-xml('<p:a xmlns:p="urn:a"/>')`, `<assert-xml ignore-prefixes="true">&lt;q:a xmlns:q="urn:a"/></assert-xml>`, suiteQT3, true},
		{"XML document boundary whitespace", xmlOne, "<assert-xml>\n&lt;a>one&lt;/a>\n </assert-xml>", suiteQT3, true},
		{"XML document boundary whitespace and prefixes", `parse-xml('<p:a xmlns:p="urn:a">one</p:a>')`, "<assert-xml ignore-prefixes=\"true\">\n&lt;q:a xmlns:q=\"urn:a\">one&lt;/q:a>\n </assert-xml>", suiteQT3, true},
		{"XML inner whitespace retained", xmlOne, `<assert-xml>&lt;a> one &lt;/a></assert-xml>`, suiteQT3, false},
		{"XML fragment non-whitespace retained", `parse-xml-fragment('before<a/>')`, `<assert-xml>&lt;a/></assert-xml>`, suiteQT3, false},
		{"boolean type", `1`, `<assert-true/>`, suiteQT3, false},
		{"permutation", `(3, 1, 1, xs:double('NaN'))`, `<assert-permutation>(1, xs:double('NaN'), 3, 1)</assert-permutation>`, suiteQT3, true},
		{"permutation multiplicity", `(3, 1, 1)`, `<assert-permutation>(1, 3, 3)</assert-permutation>`, suiteQT3, false},
		{"permutation length", `(3, 1)`, `<assert-permutation>(1, 3, 3)</assert-permutation>`, suiteQT3, false},
		{"permutation nodes", `parse-xml('<a/>')`, `<assert-permutation>parse-xml('&lt;a/>')</assert-permutation>`, suiteQT3, false},
		{"unknown assertion", `1`, `<unknown/>`, suiteQT3, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			sequence, err := environment.query(t.Context(), test.expression, nil)
			if err != nil {
				t.Fatal(err)
			}

			var assertion suiteNode
			if err := xml.Unmarshal([]byte(test.assertion), &assertion); err != nil {
				t.Fatal(err)
			}

			evaluation := &suiteEvaluation{environment: environment, sequence: sequence, options: suiteOptions{kind: test.kind}, item: suiteCase{node: &suiteNode{}}}
			if err := checkSuiteAssertion(t.Context(), evaluation, &assertion); (err == nil) != test.pass {
				t.Fatal("unexpected assertion outcome", err)
			}
		})
	}
}

func TestSuiteSerializedText(t *testing.T) {
	for _, test := range []struct {
		data, encoding, want string
		fail                 bool
	}{
		{"text😀", "UTF-8", "text😀", false},
		{"\xef\xbb\xbftext", "UTF-8", "\uFEFFtext", false},
		{"\xfe\xff\x00A\xd8\x3d\xde\x00", "UTF-16", "\uFEFFA😀", false},
		{"\xff\xfeA\x00\x3d\xd8\x00\xde", "UTF-16", "\uFEFFA😀", false},
		{"\x00A\xd8\x3d\xde\x00", "UTF-16BE", "A😀", false},
		{"A\x00\x3d\xd8\x00\xde", "UTF-16LE", "A😀", false},
		{"\xfe\xff\x00", "UTF-16", "", true},
		{"\xfe\xff\xd8\x3d", "UTF-16", "", true},
		{"\xfe\xff\xde\x00", "UTF-16", "", true},
		{"\xfe\xff\xd8\x3d\x00A", "UTF-16", "", true},
		{"\xff\xfeA\x00", "UTF-16BE", "", true},
		{"\xfe\xff\x00A", "UTF-16LE", "", true},
		{"\x00A", "UTF-16", "", true},
		{"\xfe\xff\x00A", "UTF-8", "", true},
		{"\xc0\xaf", "UTF-8", "", true},
		{"caf\xe9", "ISO-8859-1", "café", false},
		{"\xc3\xa9", "ISO-8859-1", "Ã©", false},
		{"\xff\xfe", "ISO-8859-1", "ÿþ", false},
		{"\xfe\xff", "ISO-8859-1", "þÿ", false},
		{"\x80", "windows-1252", "€", false},
		{"\x81", "windows-1252", "", true},
		{"\x80", "ASCII", "", true},
		{"text", "ASCII", "text", false},
		{"text", "unknown", "", true},
		{"text", "Shift_JIS", "text", false},
		{"\x93\xfa\x96\x7b", "Shift_JIS", "日本", false},
		{"\x82", "Shift_JIS", "", true},
		{"<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?><r>café</r>", "UTF-8", "<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?><r>café</r>", false},
		{"<?xml-stylesheet encoding=\"ISO-8859-1\"?>café", "UTF-8", "<?xml-stylesheet encoding=\"ISO-8859-1\"?>café", false},
		{"caf\xe9", "UTF-8", "", true},
	} {
		got, err := suiteSerializedText([]byte(test.data), test.encoding)
		if (err != nil) != test.fail || got != test.want {
			t.Fatalf("%q (%s): %q, %v; want %q, failure %v", test.data, test.encoding, got, err, test.want, test.fail)
		}
	}
}

func TestSuiteSerializationAssertions(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	writeFixture(t, root, "expected.txt", "line\r\nnext\rdata")
	engine, err := transform.NewEngine(transform.Config{})
	if err != nil {
		t.Fatal(err)
	}
	environment := &preparedSuiteEnvironment{engine: engine, namespaces: map[string]string{}, variables: transform.Bindings{}}
	for _, test := range []struct {
		actual, assertion string
		pass              bool
	}{
		{"line\nnext\rdata", `<assert-serialization file="expected.txt"/>`, true},
		{"line\nnextdata", `<assert-serialization file="expected.txt"/>`, false},
		{"line\r\nnext\rdata", `<assert-serialization file="expected.txt"/>`, false},
		{"line\nnext", `<assert-serialization>line&#13;&#10;next</assert-serialization>`, false},
		{"line\r\nnext", `<assert-serialization>line&#13;&#10;next</assert-serialization>`, true},
		{strings.Repeat("a", 4000), `<assert-serialization>b</assert-serialization>`, false},
	} {
		compiled, err := engine.CompileXSLTReader(t.Context(), strings.NewReader(`<xsl:stylesheet xmlns:xsl="`+suiteStylesheetNS+`" version="3.0"><xsl:output method="text"/><xsl:template name="start"><xsl:param name="text"/><xsl:value-of select="$text"/></xsl:template></xsl:stylesheet>`), transform.XSLTOptions{})
		if err != nil {
			t.Fatal(err)
		}
		result, err := compiled.Execute(t.Context(), nil, transform.XSLTContext{Template: transform.Name{Local: "start"}, InitialParameters: transform.Bindings{{Local: "text"}: transform.Values(transform.String(test.actual))}})
		if err != nil {
			t.Fatal(err)
		}
		var assertion suiteNode
		if err := xml.Unmarshal([]byte(test.assertion), &assertion); err != nil {
			t.Fatal(err)
		}
		evaluation := &suiteEvaluation{environment: environment, result: result, options: suiteOptions{kind: suiteXSLT, directory: root}, item: suiteCase{base: root, node: &suiteNode{}}}
		err = suiteSerializationAssertion(t.Context(), evaluation, &assertion)
		if (err == nil) != test.pass {
			t.Fatal(test.assertion, err)
		}
		if err != nil && (!strings.Contains(err.Error(), "offset ") || len(err.Error()) > 300) {
			t.Fatal("missing or unbounded mismatch diagnostic", err)
		}
	}
}

func TestSuiteSerializationEncodings(t *testing.T) {
	e, err := transform.NewEngine(transform.Config{})
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct{ encoding, value, method string }{
		{"UTF-8", "café😀", "text"},
		{"UTF-16", "café😀", "text"},
		{"UTF-16BE", "café😀", "text"},
		{"UTF-16LE", "café😀", "text"},
		{"ISO-8859-1", "café", "text"},
		{"windows-1252", "café€", "text"},
		{"US-ASCII", "text", "text"},
		{"Shift_JIS", "日本", "text"},
		{"GB18030", "�", "text"},
		{"UTF-8", `<?xml version="1.0" encoding="ISO-8859-1"?><r>café</r>`, "text"},
		{"US-ASCII", "ª", "adaptive"},
	} {
		source := `<xsl:stylesheet xmlns:xsl="` + suiteStylesheetNS + `" version="3.0"><xsl:output method="` + test.method + `" encoding="` + test.encoding + `"/><xsl:param name="value"/><xsl:param name="encoding"/><xsl:template name="start"><xsl:value-of select="$value"/><xsl:result-document href="secondary" encoding="{$encoding}"><xsl:value-of select="$value"/></xsl:result-document></xsl:template></xsl:stylesheet>`
		compiled, err := e.CompileXSLTReader(t.Context(), strings.NewReader(source), transform.XSLTOptions{})
		if err != nil {
			t.Fatal(err)
		}
		result, err := compiled.Execute(t.Context(), nil, transform.XSLTContext{Template: transform.Name{Local: "start"}, Parameters: transform.Bindings{{Local: "value"}: transform.Values(transform.String(test.value)), {Local: "encoding"}: transform.Values(transform.String(test.encoding))}})
		if err != nil {
			t.Fatal(err)
		}
		for _, uri := range []string{"", "secondary"} {
			evaluation := &suiteEvaluation{environment: &preparedSuiteEnvironment{engine: e, namespaces: map[string]string{}, variables: transform.Bindings{}}, result: result, secondaryURI: uri, item: suiteCase{node: &suiteNode{}}}
			assertion := &suiteNode{XMLName: xml.Name{Local: "serialization-matches"}, Text: regexp.QuoteMeta(test.value)}
			if err := suiteSerializationAssertion(t.Context(), evaluation, assertion); err != nil {
				t.Fatal(test.encoding, uri, err)
			}
		}
	}
}

func TestSuiteFileBoundaryAndLimits(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}

	writeFixture(t, root, "valid.xml", `<r/>`)

	for _, name := range []string{"../outside.xml", filepath.Join(root, "valid.xml")} {
		if _, _, err := readSuiteFile(root, root, name); err == nil {
			t.Fatal("nonportable/outside suite path accepted", name)
		}
	}

	if _, _, err := readSuiteFile(root, root, "valid.xml"); err != nil {
		t.Fatal(err)
	}

	if err := suiteErrorAssertion(transform.ErrLimit, "*"); err == nil {
		t.Fatal("unclassified resource failure was accepted as a standard-error assertion")
	}

	engine, err := transform.NewEngine(transform.Config{})
	if err != nil {
		t.Fatal(err)
	}

	query, err := engine.CompileXPath(t.Context(), `error(QName('urn:application', 'XPTY0004'))`, transform.XPathOptions{})
	if err != nil {
		t.Fatal(err)
	}

	_, applicationError := query.Evaluate(t.Context(), nil, transform.XPathContext{})
	if err := suiteErrorAssertion(applicationError, "XPTY0004"); err == nil {
		t.Fatal("application error was confused with the same local standard code")
	}

	if err := suiteErrorAssertion(applicationError, "Q{urn:application}XPTY0004"); err != nil {
		t.Fatal(err)
	}

	var stderr strings.Builder
	for _, args := range [][]string{{suiteDirectoryFlag, root, "-timeout=0s"}, {suiteDirectoryFlag, root, "-limit=-1"}, {suiteDirectoryFlag, root, "-version=4.0"}, {suiteDirectoryFlag, root, "-match=["}, {suiteDirectoryFlag, root, "-current-time=tomorrow"}} {
		if _, err := parseSuiteOptions(args, &stderr); err == nil {
			t.Fatal("invalid suite configuration accepted", args)
		}
	}
}

func TestSuiteResolvedLocalPaths(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"valid.xml", "space name.xml", "hash#name.xml"} {
		writeFixture(t, root, name, `<r/>`)
	}
	resolver := &suiteResourceResolver{root: root}
	for _, name := range []string{"valid.xml", "space name.xml", "hash#name.xml"} {
		path := filepath.Join(root, name)
		for _, uri := range []string{path, suiteFileURI(path)} {
			reader, err := resolver.Resolve(t.Context(), uri)
			if err != nil {
				t.Fatal(uri, err)
			}
			data, err := io.ReadAll(reader)
			closeErr := reader.Close()
			if err != nil || closeErr != nil || string(data) != `<r/>` {
				t.Fatal(uri, string(data), err, closeErr)
			}
		}
	}
	outside := t.TempDir()
	writeFixture(t, outside, "outside.xml", `<secret/>`)
	if err := os.Symlink(filepath.Join(outside, "outside.xml"), filepath.Join(root, "escape.xml")); err != nil {
		t.Fatal(err)
	}
	for _, uri := range []string{filepath.Join(outside, "outside.xml"), filepath.Join(root, "escape.xml"), "https://suite.invalid/file", "valid.xml"} {
		if reader, err := resolver.Resolve(t.Context(), uri); err == nil {
			reader.Close()
			t.Fatal("resolver accepted a resource outside its explicit boundary", uri)
		}
	}
	resolver.fileLimit = 3
	if _, err := resolver.Resolve(t.Context(), filepath.Join(root, "valid.xml")); err == nil {
		t.Fatal("local path bypassed the byte limit")
	}
	canceled, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := resolver.Resolve(canceled, filepath.Join(root, "valid.xml")); !errors.Is(err, context.Canceled) {
		t.Fatal("local path ignored cancellation", err)
	}
}

func TestSuiteDeclaredResourcesAndCollections(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}

	const namespace = suiteQTNamespace
	writeFixture(t, root, suiteCatalog, `<catalog xmlns="`+namespace+`"><test-set name="resources" file="resources.xml"/></catalog>`)
	writeFixture(t, root, "source.xml", `<r>7</r>`)
	writeFixture(t, root, "text.txt", "declared text")
	writeFixture(t, root, "other.txt", "other text")
	const fragmentXML = `<r><n xml:id="one">1</n><n xml:id="two">2</n></r>`
	writeFixture(t, root, "fragments.xml", fragmentXML)
	writeFixture(t, root, "space name.xml", fragmentXML)
	writeFixture(t, root, "hash#name.xml", fragmentXML)
	outside := t.TempDir()
	writeFixture(t, outside, "external.xml", fragmentXML)
	if err := os.Symlink(filepath.Join(outside, "external.xml"), filepath.Join(root, "escape.xml")); err != nil {
		t.Fatal(err)
	}
	writeFixture(t, root, "resources.xml", `<test-set xmlns="`+namespace+`" name="resources">
	  <test-case name="default-collection"><environment><collection><source file="source.xml"/><query>8, 9</query></collection></environment>
	    <test>count(collection()) = 3 and string(collection()[1]/r) = '7' and collection()[3] = 9</test><result><assert-true/></result></test-case>
	  <test-case name="relative-mappings"><environment><resource file="text.txt" uri="text" encoding="UTF-8"/>
	    <collection uri="items"><source file="source.xml" uri="source"/></collection><static-base-uri uri="https://suite.invalid/base/"/></environment>
	    <test>unparsed-text('text') = 'declared text' and count(collection('items')) = 1 and uri-collection('items') = 'https://suite.invalid/base/source'</test><result><assert-true/></result></test-case>
	  <test-case name="no-network"><test>unparsed-text('https://suite.invalid/undeclared')</test><result><error code="FOUT1170"/></result></test-case>
	  <test-case name="conflicting-mapping"><environment><resource file="text.txt" uri="urn:duplicate"/><resource file="other.txt" uri="urn:duplicate"/></environment><test>1</test><result><assert-eq>1</assert-eq></result></test-case>
	  <test-case name="transport-hint"><environment><resource file="text.txt" uri="urn:text" encoding="iso-8859-1"/></environment><test>unparsed-text('urn:text')</test><result><assert-string-value>declared text</assert-string-value></result></test-case>
	  <test-case name="outside"><environment><resource file="../outside.txt" uri="urn:outside"/></environment><test>1</test><result><error code="*"/></result></test-case>
	  <test-case name="fragment-collection"><environment><collection uri="fragments"><source file="fragments.xml#one" uri="urn:fragments#one"/><source file="fragments.xml#two" uri="urn:fragments#two"/><source file="fragments.xml#one" uri="urn:fragments#one"/></collection></environment>
	    <test>let $c := collection('fragments') return count($c) = 3 and $c[1] = '1' and $c[2] = '2' and $c[1] is $c[3] and root($c[1]) is root($c[2]) and root($c[1]) is doc('urn:fragments') and deep-equal(uri-collection('fragments')!string(.), ('urn:fragments#one','urn:fragments#two','urn:fragments#one'))</test><result><assert-true/></result></test-case>
	  <test-case name="fragment-variable"><environment><source role="$n" file="fragments.xml#two" uri="urn:fragments#two"/></environment><test>$n instance of element(n) and $n = '2' and document-uri(root($n)) = 'urn:fragments'</test><result><assert-true/></result></test-case>
	  <test-case name="fragment-context"><environment><source role="." file="fragments.xml#one"/></environment><test>. instance of element(n) and . = '1'</test><result><assert-true/></result></test-case>
	  <test-case name="fragment-selection"><environment><source role="." file="fragments.xml#one" select="../n[@xml:id='two']"/></environment><test>. instance of element(n) and . = '2'</test><result><assert-true/></result></test-case>
	  <test-case name="fragment-alias"><environment><source role="$n" file="fragments.xml#one" uri="urn:alias"/></environment><test>$n instance of element(n) and $n = '1' and document-uri(root($n)) = 'urn:alias'</test><result><assert-true/></result></test-case>
	  <test-case name="escaped-files"><environment><collection><source file="space%20name.xml#%6Fne"/><source file="hash%23name.xml#two"/></collection></environment><test>collection()[1] = '1' and collection()[2] = '2' and ends-with(uri-collection()[1], 'space%20name.xml#%6Fne') and ends-with(uri-collection()[2], 'hash%23name.xml#two')</test><result><assert-true/></result></test-case>
	  <test-case name="missing-fragment"><environment><collection><source file="fragments.xml#missing"/></collection></environment><test>1</test><result><error code="*"/></result></test-case>
	  <test-case name="xpointer-fragment"><environment><collection><source file="fragments.xml#xpointer(/)"/></collection></environment><test>1</test><result><error code="*"/></result></test-case>
	  <test-case name="whitespace-fragment"><environment><collection><source file="fragments.xml#%20one%20"/></collection></environment><test>1</test><result><error code="*"/></result></test-case>
	  <test-case name="conflicting-fragments"><environment><collection><source file="fragments.xml#one" uri="urn:fragments#two"/></collection></environment><test>1</test><result><error code="*"/></result></test-case>
	  <test-case name="conflicting-fragment-mapping"><environment><collection><source file="fragments.xml#one" uri="urn:fragments#one"/><source file="hash%23name.xml#two" uri="urn:fragments#two"/></collection></environment><test>1</test><result><error code="*"/></result></test-case>
	  <test-case name="outside-symlink-fragment"><environment><collection><source file="escape.xml#one"/></collection></environment><test>1</test><result><error code="*"/></result></test-case>
	  <test-case name="file-query"><environment><collection><source file="fragments.xml?query#one"/></collection></environment><test>1</test><result><error code="*"/></result></test-case>
	  <test-case name="remote-file"><environment><collection><source file="https://suite.invalid/fragments.xml#one"/></collection></environment><test>1</test><result><error code="*"/></result></test-case>
	</test-set>`)

	options := suiteOptions{kind: suiteQT3, directory: root, version: suiteVersion31, timeout: time.Second, setMatch: regexp.MustCompile(".*"), caseMatch: regexp.MustCompile(".*")}

	report, err := executeSuite(t.Context(), options, suitePin{Catalog: suiteCatalog, Namespace: namespace})
	if err != nil {
		t.Fatal(err)
	}

	if len(report.Cases) != 20 {
		t.Fatal("missing resource cases", report.Totals)
	}

	for _, outcome := range report.Cases {
		positive := slices.Contains([]string{"default-collection", "relative-mappings", "no-network", "transport-hint", "fragment-collection", "fragment-variable", "fragment-context", "fragment-selection", "fragment-alias", "escaped-files"}, outcome.Name)
		if positive && outcome.Status != suitePassed || !positive && (outcome.Status != suiteFailed || outcome.Kind != suiteHarnessFailure) {
			t.Error("unexpected declared-resource outcome", outcome)
		}
	}
}

func TestSuiteEnvironmentStylesheet(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}

	const namespace = suiteXSLTNamespace
	writeFixture(t, root, suiteCatalog, `<catalog xmlns="`+namespace+`"><test-set name="environment" file="environment.xml"/></catalog>`)
	writeFixture(t, root, "source.xml", `<r>7</r>`)
	writeFixture(t, root, "main.xsl", `<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="3.0"><xsl:include href="urn:part"/><xsl:param name="flag" static="yes" select="false()"/><xsl:param name="required" required="yes"/><xsl:template name="start"><out><xsl:call-template name="part"/><xsl:value-of select="$required"/><xsl:if test="$flag">static</xsl:if></out></xsl:template></xsl:stylesheet>`)
	writeFixture(t, root, "part.xsl", `<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="3.0"><xsl:template name="part">included</xsl:template></xsl:stylesheet>`)
	writeFixture(t, root, "mode.xsl", `<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="3.0"><xsl:template match="/"><out>document</out></xsl:template><xsl:template match="n"><out>selected</out></xsl:template><xsl:template name="start"><out><xsl:value-of select="name(.)"/></out></xsl:template></xsl:stylesheet>`)
	writeFixture(t, root, "environment.xml", `<test-set xmlns="`+namespace+`" name="environment">
	  <environment name="modules"><stylesheet file="main.xsl" uri="urn:main" role="principal"/><stylesheet file="part.xsl" uri="urn:part" role="secondary"/></environment>
	  <test-case name="principal"><environment ref="modules"/><test><param name="required" select="' supplied '"/><param name="flag" select="true()" static="yes"/><initial-template name="start"/></test><result><assert-xml>&lt;out>included supplied static&lt;/out></assert-xml></result></test-case>
	  <test-case name="ambiguous"><environment><stylesheet file="main.xsl"/><stylesheet file="part.xsl"/></environment><test/><result><error code="*"/></result></test-case>
	  <test-case name="source-param"><environment ref="modules"/><test><param name="required" source="source.xml"/><initial-template name="start"/></test><result><assert-xml>&lt;out>included7&lt;/out></assert-xml></result></test-case>
	  <test-case name="unknown-invocation"><environment ref="modules"/><test><unknown/></test><result><error code="*"/></result></test-case>
	  <test-case name="output-override"><environment ref="modules"/><test><param name="required" select="'x'"/><initial-template name="start"/><output file="result.xml" serialize="yes"/></test><result><assert-xml>&lt;out>includedx&lt;/out></assert-xml></result></test-case>
	  <test-case name="context-item"><environment><context-item select="7"/><stylesheet file="main.xsl"/><stylesheet file="part.xsl" uri="urn:part" role="secondary"/></environment><test><param name="required" select="'x'"/><initial-template name="start"/></test><result><assert-xml>&lt;out>includedx&lt;/out></assert-xml></result></test-case>
      <test-case name="selected-source"><environment><source role="." select="/r/n"><content>&lt;r>&lt;n/>&lt;/r></content></source></environment><test><stylesheet file="mode.xsl"/></test><result><assert-xml>&lt;out>selected&lt;/out></assert-xml></result></test-case>
      <test-case name="selected-global"><environment><source role="." select="/r/n"><content>&lt;r>&lt;n/>&lt;/r></content></source></environment><test><stylesheet file="mode.xsl"/><initial-template name="start"/></test><result><assert-xml>&lt;out>n&lt;/out></assert-xml></result></test-case>
      <test-case name="empty-source-selection"><environment><source role="." select="()"><content>&lt;r/></content></source></environment><test><stylesheet file="mode.xsl"/></test><result><error code="*"/></result></test-case>
      <test-case name="multiple-source-selection"><environment><source role="." select="(.,.)"><content>&lt;r/></content></source></environment><test><stylesheet file="mode.xsl"/></test><result><error code="*"/></result></test-case>
	</test-set>`)
	options := suiteOptions{kind: suiteXSLT, directory: root, version: suiteVersion30, timeout: time.Second, setMatch: regexp.MustCompile(".*"), caseMatch: regexp.MustCompile(".*")}

	report, err := executeSuite(t.Context(), options, suitePin{Catalog: suiteCatalog, Namespace: namespace})
	if err != nil {
		t.Fatal(err)
	}

	if len(report.Cases) != 10 {
		t.Fatal("case inventory changed", len(report.Cases))
	}

	for _, outcome := range report.Cases {
		if outcome.Name == "principal" || outcome.Name == "source-param" || outcome.Name == "output-override" || outcome.Name == "context-item" || outcome.Name == "selected-source" || outcome.Name == "selected-global" {
			if outcome.Status != suitePassed {
				t.Fatal("parameter invocation failed", outcome)
			}
		} else if outcome.Status != suiteFailed || outcome.Kind != suiteHarnessFailure {
			t.Fatal("unsupported metadata was silently ignored", outcome)
		}
	}
}

func TestSuiteXSLTInvocationsAndResults(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}

	const namespace = suiteXSLTNamespace
	writeFixture(t, root, suiteCatalog, `<catalog xmlns="`+namespace+`"><test-set name="invocation" file="invocation.xml"/></catalog>`)

	for _, version := range []string{"1", "2"} {
		writeFixture(t, root, "dep"+version+".xsl", `<xsl:package xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:p="urn:package" name="urn:package" package-version="`+version+`" version="3.0"><xsl:function name="p:value" visibility="public"><xsl:sequence select="`+version+`"/></xsl:function></xsl:package>`)
	}

	writeFixture(t, root, "main.xsl", `<xsl:package xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:p="urn:package" xmlns:f="urn:function" name="urn:main" package-version="1" version="3.0"><xsl:use-package name="urn:package" package-version="1+"/><xsl:output omit-xml-declaration="yes"/><xsl:mode name="mode" visibility="public"/>
	<xsl:template name="start" visibility="public"><xsl:param name="local" required="yes"/><xsl:param name="tunnel" tunnel="yes" required="yes"/><out><xsl:value-of select="$local || $tunnel || p:value()"/></out><xsl:message><message>hello</message></xsl:message><xsl:result-document href="secondary.xml" encoding="ISO-8859-1"><secondary>café</secondary></xsl:result-document></xsl:template>
	<xsl:template match="/" mode="mode"><xsl:param name="local" required="yes"/><mode><xsl:value-of select="$local"/></mode></xsl:template><xsl:function name="f:add" visibility="public"><xsl:param name="a"/><xsl:param name="b"/><xsl:sequence select="$a + $b"/></xsl:function></xsl:package>`)
	writeFixture(t, root, "secondary-expected.xml", "<secondary xmlns:f=\"urn:function\" xmlns:p=\"urn:package\">caf\xe9</secondary>")
	writeFixture(t, root, "invocation.xml", `<test-set xmlns="`+namespace+`" xmlns:f="urn:function">
	<environment name="dependencies"><package file="dep1.xsl" role="secondary"/><package file="dep2.xsl" role="secondary"/></environment>
	<test-case name="named"><environment ref="dependencies"/><test><package file="main.xsl" role="principal"/><initial-template name="start"><param name="local" select="'l'"/><param name="tunnel" tunnel="yes" select="'t'"/></initial-template><output file="result/main.xml" serialize="yes"/></test><result><all-of><assert-xml>&lt;out>lt2&lt;/out></assert-xml><assert-result-document uri="secondary.xml"><all-of><assert-xml>&lt;secondary>café&lt;/secondary></assert-xml><assert-serialization file="secondary-expected.xml"/></all-of></assert-result-document><assert-message><assert-xml>&lt;message>hello&lt;/message></assert-xml></assert-message></all-of></result></test-case>
	<test-case name="mode"><environment><package file="dep1.xsl" role="secondary"/><package file="dep2.xsl" role="secondary"/><source role="."><content>&lt;r/></content></source></environment><test><package file="main.xsl"/><initial-mode name="mode"><param name="local" select="'value'"/></initial-mode></test><result><assert-xml>&lt;mode>value&lt;/mode></assert-xml></result></test-case>
	<test-case name="function"><environment ref="dependencies"/><test><package file="main.xsl"/><initial-function name="f:add"><param select="2"/><param select="4"/></initial-function><output tree="no" serialize="no" result-var="raw"/></test><result><assert>$raw eq 6</assert></result></test-case>
	<test-case name="missing-secondary"><environment ref="dependencies"/><test><package file="main.xsl"/><initial-function name="f:add"><param select="2"/><param select="4"/></initial-function></test><result><assert-result-document uri="missing.xml"><assert-empty/></assert-result-document></result></test-case>
	</test-set>`)
	options := suiteOptions{kind: suiteXSLT, directory: root, version: suiteVersion30, timeout: time.Second, setMatch: regexp.MustCompile(".*"), caseMatch: regexp.MustCompile(".*")}

	report, err := executeSuite(t.Context(), options, suitePin{Catalog: suiteCatalog, Namespace: namespace})
	if err != nil {
		t.Fatal(err)
	}

	for index, outcome := range report.Cases {
		if index < 3 && outcome.Status != suitePassed || index == 3 && outcome.Status != suiteFailed {
			t.Fatal("invocation/result outcome changed", outcome)
		}
	}

	if _, err := os.Stat(filepath.Join(root, "result")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("the output URI caused a filesystem write", err)
	}
}

func TestSuiteTerminatedMessages(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	writeFixture(t, root, suiteCatalog, `<catalog xmlns="`+suiteXSLTNamespace+`"><test-set name="messages" file="messages.xml"/></catalog>`)
	writeFixture(t, root, "message.xsl", `<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="3.0"><xsl:template name="start"><xsl:message>before &amp; after</xsl:message><xsl:message terminate="true"><stop/></xsl:message></xsl:template></xsl:stylesheet>`)
	writeFixture(t, root, "messages.xml", `<test-set xmlns="`+suiteXSLTNamespace+`"><test-case name="captured"><test><stylesheet file="message.xsl"/><initial-template name="start"/></test><result><all-of><error code="XTMM9000"/><assert-message><assert-string-value>before &amp; after</assert-string-value></assert-message><assert-message><assert-xml>&lt;stop/></assert-xml></assert-message></all-of></result></test-case><test-case name="absent"><test><stylesheet file="message.xsl"/><initial-template name="start"/></test><result><assert-message><assert-xml>&lt;absent/></assert-xml></assert-message></result></test-case></test-set>`)
	options := suiteOptions{kind: suiteXSLT, directory: root, version: suiteVersion30, timeout: time.Second, setMatch: regexp.MustCompile(".*"), caseMatch: regexp.MustCompile(".*")}
	report, err := executeSuite(t.Context(), options, suitePin{Catalog: suiteCatalog, Namespace: suiteXSLTNamespace})
	if err != nil || len(report.Cases) != 2 {
		t.Fatal(report, err)
	}
	if report.Cases[0].Status != suitePassed || report.Cases[1].Status != suiteFailed || report.Cases[1].Kind != "assertion" {
		t.Fatal(report.Cases)
	}
}

func TestSuiteXSLTSchemaResources(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}

	writeFixture(t, root, suiteCatalog, `<catalog xmlns="`+suiteXSLTNamespace+`"><test-set name="schema" file="schema.xml"/></catalog>`)

	for _, name := range []string{"first.xsd", "second.xsd"} {
		writeFixture(t, root, name, `<xs:schema xmlns:xs="http://www.w3.org/2001/XMLSchema" targetNamespace="urn:types"/>`)
	}

	writeFixture(t, root, "unused.xsl", `<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:xs="http://www.w3.org/2001/XMLSchema" version="3.0"><xsl:template match="/"><xsl:value-of select=". instance of document-node(element(*,xs:untyped))"/></xsl:template></xsl:stylesheet>`)
	writeFixture(t, root, "import.xsl", `<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="3.0"><xsl:import-schema namespace="urn:types" schema-location="first.xsd"/></xsl:stylesheet>`)
	writeFixture(t, root, "typed.xsl", `<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:xs="http://www.w3.org/2001/XMLSchema" version="3.0"><xsl:template match="/"><out xsl:type="xs:string"/></xsl:template></xsl:stylesheet>`)
	writeFixture(t, root, "schema.xml", `<test-set xmlns="`+suiteXSLTNamespace+`">
	<environment name="available"><schema role="stylesheet-import" uri="urn:types" file="first.xsd"/><schema role="secondary" uri="urn:types" file="second.xsd"/><source role="."><content>&lt;r/></content></source></environment>
	<test-case name="unused"><environment ref="available"/><test><stylesheet file="unused.xsl"/></test><result><assert-string-value>true</assert-string-value></result></test-case>
	<test-case name="import"><environment ref="available"/><test><stylesheet file="import.xsl"/></test><result><error code="XTSE1650"/></result></test-case>
	<test-case name="type"><environment ref="available"/><test><stylesheet file="typed.xsl"/></test><result><error code="XTSE1660"/></result></test-case>
	<test-case name="validation"><environment><schema role="source-reference" file="first.xsd"/><source role="." validation="strict"><content>&lt;r/></content></source></environment><test><stylesheet file="unused.xsl"/></test><result><assert-string-value>true</assert-string-value></result></test-case>
	<test-case name="bad-role"><environment><schema role="unknown" file="first.xsd"/></environment><test><stylesheet file="unused.xsl"/></test><result><assert-string-value>true</assert-string-value></result></test-case>
	<test-case name="outside"><environment><schema role="stylesheet-import" file="../outside.xsd"/></environment><test><stylesheet file="unused.xsl"/></test><result><error code="XTSE1650"/></result></test-case>
	</test-set>`)
	options := suiteOptions{kind: suiteXSLT, directory: root, version: suiteVersion30, timeout: time.Second, setMatch: regexp.MustCompile(".*"), caseMatch: regexp.MustCompile(".*")}

	report, err := executeSuite(t.Context(), options, suitePin{Catalog: suiteCatalog, Namespace: suiteXSLTNamespace})
	if err != nil {
		t.Fatal(err)
	}

	if len(report.Cases) != 6 {
		t.Fatal(report)
	}

	for index, outcome := range report.Cases {
		if index < 3 {
			if outcome.Status != suitePassed {
				t.Fatal(outcome)
			}
		} else if outcome.Status != suiteFailed || outcome.Kind != suiteHarnessFailure {
			t.Fatal("schema preparation hid a harness boundary", outcome)
		}
	}
}

func TestSuiteXSLTResultDelivery(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}

	writeFixture(t, root, suiteCatalog, `<catalog xmlns="`+suiteXSLTNamespace+`"><test-set name="results" file="results.xml"/></catalog>`)
	writeFixture(t, root, "numbers.xsl", `<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="3.0"><xsl:output method="text"/><xsl:template name="start"><xsl:sequence select="(1,2)"/></xsl:template></xsl:stylesheet>`)
	writeFixture(t, root, "results.xml", `<test-set xmlns="`+suiteXSLTNamespace+`">
	<environment name="numbers"><stylesheet file="numbers.xsl"/></environment>
	<test-case name="default"><environment ref="numbers"/><test><initial-template name="start"/></test><result><assert>. instance of document-node() and string(.) eq '1 2'</assert></result></test-case>
	<test-case name="tree"><environment ref="numbers"/><test><initial-template name="start"/><output tree="yes"/></test><result><assert>$result instance of document-node() and string($result) eq '1 2'</assert></result></test-case>
	<test-case name="raw"><environment ref="numbers"/><test><initial-template name="start"/><output tree="no"/></test><result><assert>deep-equal($result,(1,2))</assert></result></test-case>
	</test-set>`)
	options := suiteOptions{kind: suiteXSLT, directory: root, version: suiteVersion30, timeout: time.Second, setMatch: regexp.MustCompile(".*"), caseMatch: regexp.MustCompile(".*")}

	report, err := executeSuite(t.Context(), options, suitePin{Catalog: suiteCatalog, Namespace: suiteXSLTNamespace})
	if err != nil {
		t.Fatal(err)
	}

	if len(report.Cases) != 3 {
		t.Fatal(report)
	}

	for _, outcome := range report.Cases {
		if outcome.Status != suitePassed {
			t.Fatal(outcome)
		}
	}
}

func TestFuzzDiscovery(t *testing.T) {
	t.Setenv("GOWORK", "off")

	root := t.TempDir()
	writeFixture(t, root, "go.mod", "module example.test/fixture\n\ngo 1.27.0\n")
	writeFixture(t, root, "internal_test.go", `package fixture
import tst "testing"
func FuzzOne(f *tst.F) {}
func TestOne(t *tst.T) {}
// func FuzzComment(f *tst.F) {}
type fixture struct{}
func (fixture) FuzzMethod(f *tst.F) {}
`)
	writeFixture(t, root, "external_test.go", `package fixture_test
import "testing"
func FuzzTwo(f *testing.F) {}
`)
	writeFixture(t, root, "excluded_test.go", `//go:build ignore

package fixture
import "testing"
func FuzzExcluded(f *testing.F) {}
`)

	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()

	var stderr bytes.Buffer

	want := []fuzzTarget{{Package: "example.test/fixture", Name: "FuzzOne"}, {Package: "example.test/fixture", Name: "FuzzTwo"}}

	targets, err := discoverFuzz(ctx, root, ".*", &stderr)
	if err != nil || !slices.Equal(targets, want) {
		t.Fatal("Go-selected fuzz targets changed", targets, err, stderr.String())
	}

	selected, err := discoverFuzz(ctx, root, "^FuzzTwo$", &stderr)
	if err != nil || !slices.Equal(selected, want[1:]) {
		t.Fatal("fuzz selection changed", selected, err, stderr.String())
	}

	if _, err := discoverFuzz(ctx, root, "^Missing$", &stderr); err == nil {
		t.Fatal("empty fuzz selection succeeded")
	}

	writeFixture(t, root, "broken_test.go", "package fixture\nimport \"testing\"\nfunc FuzzWrongType(f *testing.T) {}\n")

	if _, err := discoverFuzz(ctx, root, ".*", &stderr); err == nil {
		t.Fatal("Go test discovery failure ignored")
	}
}

func TestCanceledFuzzDiscovery(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	var stderr bytes.Buffer
	if _, err := discoverFuzz(ctx, t.TempDir(), ".*", &stderr); !errors.Is(err, context.Canceled) {
		t.Fatal("cancellation lost", err)
	}
}

func TestSuiteDynamicClock(t *testing.T) {
	for _, clock := range []struct{ flag, year, report string }{
		{"", "2026", suiteDefaultCurrentTime},
		{"-current-time=2041-12-31T19:00:00-05:00", "2042", "2042-01-01T00:00:00Z"},
	} {
		for _, kind := range []string{suiteQT3, suiteXSLT} {
			root, err := filepath.EvalSymlinks(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}

			namespace := suiteQTNamespace
			test := `<test>year-from-date(current-date())</test>`
			version := suiteVersion31

			if kind == suiteXSLT {
				namespace = suiteXSLTNamespace
				version = suiteVersion30
				test = `<test><stylesheet file="main.xsl"/><initial-template name="start"/></test>`

				writeFixture(t, root, "main.xsl", `<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="3.0"><xsl:output method="text"/><xsl:template name="start"><xsl:value-of select="year-from-date(current-date())"/></xsl:template></xsl:stylesheet>`)
			}

			writeFixture(t, root, suiteCatalog, `<catalog xmlns="`+namespace+`"><test-set name="clock" file="clock.xml"/></catalog>`)
			writeFixture(t, root, "clock.xml", `<test-set xmlns="`+namespace+`"><test-case name="clock">`+test+`<result><assert>string($result) eq '`+clock.year+`' and string($result) eq string(year-from-date(current-date()))</assert></result></test-case></test-set>`)

			args := []string{suiteDirectoryFlag, root, "-suite=" + kind, "-version=" + version}
			if clock.flag != "" {
				args = append(args, clock.flag)
			}

			var stderr strings.Builder

			options, err := parseSuiteOptions(args, &stderr)
			if err != nil {
				t.Fatal(err)
			}

			report, err := executeSuite(t.Context(), options, suitePin{Catalog: suiteCatalog, Namespace: namespace})
			if err != nil || report.Totals[suitePassed] != 1 || report.Settings["current_time"] != clock.report {
				t.Fatal(kind, clock, report, err)
			}
		}
	}
}

func TestSuiteEncodedInputs(t *testing.T) {
	for _, kind := range []string{suiteQT3, suiteXSLT} {
		root, err := filepath.EvalSymlinks(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}

		namespace := suiteQTNamespace
		version := suiteVersion31
		test := `<test>string(/*)</test>`

		if kind == suiteXSLT {
			namespace = suiteXSLTNamespace
			version = suiteVersion30
			test = `<test><stylesheet file="main.xsl"/></test>`

			writeFixture(t, root, "main.xsl", `<?xml version="1.0" encoding="US-ASCII"?><xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="3.0"><xsl:output method="text"/><xsl:template match="/"><xsl:value-of select="/*"/></xsl:template></xsl:stylesheet>`)
		}

		writeFixture(t, root, suiteCatalog, `<catalog xmlns="`+namespace+`"><test-set name="encoded" file="encoded.xml"/></catalog>`)
		writeFixture(t, root, "encoded.xml", `<test-set xmlns="`+namespace+`"><test-case name="encoded"><environment><source role="." file="source.xml"/></environment>`+test+`<result><assert-string-value>café</assert-string-value></result></test-case></test-set>`)

		original := `<?xml version="1.0" encoding="ISO-8859-1"?><r>caf` + "\xe9" + `</r>`
		writeFixture(t, root, "source.xml", original)

		var stderr strings.Builder

		options, err := parseSuiteOptions([]string{suiteDirectoryFlag, root, "-suite=" + kind, "-version=" + version}, &stderr)
		if err != nil {
			t.Fatal(err)
		}

		report, err := executeSuite(t.Context(), options, suitePin{Catalog: suiteCatalog, Namespace: namespace})
		if err != nil || report.Totals[suitePassed] != 1 || report.Settings["allow_single_byte_encodings"] != true {
			t.Fatal(kind, report, err)
		}

		raw, err := os.ReadFile(filepath.Join(root, "source.xml"))
		if err != nil || string(raw) != original {
			t.Fatal("publisher input was rewritten", err)
		}
	}
}

func TestSuiteTimeoutClassification(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	writeFixture(t, root, suiteCatalog, `<catalog xmlns="`+suiteQTNamespace+`"><test-set name="budget" file="budget.xml"/></catalog>`)
	writeFixture(t, root, "budget.xml", `<test-set xmlns="`+suiteQTNamespace+`"><test-case name="large-object"><test>error((), 'details', 1 to 100001)</test><result><error code="FOER0000"/></result></test-case><test-case name="ordinary-error"><test>1 idiv 0</test><result><error code="*"/></result></test-case><test-case name="allowed-resource-error"><test>1 to 100001</test><result><error code="XPDY0130"/></result></test-case></test-set>`)
	options := suiteOptions{kind: suiteQT3, directory: root, version: suiteVersion31, limitsProfile: "default", timeout: time.Second, setMatch: regexp.MustCompile(".*"), caseMatch: regexp.MustCompile(".*")}
	for _, timeout := range []time.Duration{time.Second, time.Nanosecond} {
		options.timeout = timeout
		report, err := executeSuite(t.Context(), options, suitePin{Catalog: suiteCatalog, Namespace: suiteQTNamespace})
		if err != nil || len(report.Cases) != 3 {
			t.Fatal(report, err)
		}
		for _, outcome := range report.Cases {
			if timeout == time.Second && outcome.Name != "large-object" {
				if outcome.Status != suitePassed {
					t.Fatal(outcome)
				}
			} else if outcome.Status != suiteFailed || outcome.Kind != suiteResourceLimit {
				t.Fatal("budget/deadline satisfied an expected language error", timeout, outcome)
			}
		}
	}
}
