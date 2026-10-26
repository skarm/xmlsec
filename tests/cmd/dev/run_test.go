package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/skarm/xmlsec/internal/lexicon"
	"github.com/skarm/xmlsec/transform"
)

const (
	suiteQTNamespace = "http://www.w3.org/2010/09/qt-fots-catalog"
)

func BenchmarkSuiteReport(b *testing.B) {
	for _, size := range []int{32, 31821} {
		report := &suiteReport{Suite: suiteQT3, Language: suiteVersion31, Totals: map[string]int{suitePassed: size}}
		for range size {
			report.Cases = append(report.Cases, suiteOutcome{Set: "fn-string", Name: "case", File: "fn/string.xml", Status: suitePassed, Reason: strings.Repeat("escaped <data> & Unicode é ", 4)})
		}
		for _, file := range []bool{false, true} {
			b.Run(fmt.Sprintf("%d/File=%v", size, file), func(b *testing.B) {
				path := ""
				if file {
					path = filepath.Join(b.TempDir(), "report.json")
				}
				b.ReportAllocs()
				for b.Loop() {
					if err := writeSuiteReport(path, io.Discard, report); err != nil {
						b.Fatal(err)
					}
				}
			})
		}
	}
}

func BenchmarkSuiteReportEncoders(b *testing.B) {
	report := &suiteReport{Cases: make([]suiteOutcome, 31821)}
	for i := range report.Cases {
		report.Cases[i] = suiteOutcome{Name: "case", Reason: strings.Repeat("<&é", 128)}
	}
	for _, method := range []string{"Indent", "Encoder", "Records"} {
		b.Run(method, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				var err error
				switch method {
				case "Indent":
					_, err = json.MarshalIndent(report, "", "  ")
				case "Encoder":
					err = json.NewEncoder(io.Discard).Encode(report)
				case "Records":
					err = writeSuiteReport("", io.Discard, report)
				}
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func TestIncrementalSuiteReport(t *testing.T) {
	var minimal bytes.Buffer
	err := writeJSONListObject(&minimal, struct{}{}, "items", []int{42}, func(dst io.Writer, value *int) error { return json.NewEncoder(dst).Encode(value) })
	if err != nil || !json.Valid(minimal.Bytes()) {
		t.Fatal("empty metadata object", minimal.String(), err)
	}

	for _, cases := range [][]suiteOutcome{nil, {}, {{Name: "é <&\"\n", Reason: strings.Repeat("漢字", 4096), Status: suiteFailed}}} {
		report := &suiteReport{Suite: suiteQT3, Cases: cases, Settings: map[string]any{"escaping": "<&\""}}
		var output bytes.Buffer
		if err := writeSuiteReport("", &output, report); err != nil {
			t.Fatal(err)
		}
		var decoded suiteReport
		if err := json.Unmarshal(output.Bytes(), &decoded); err != nil {
			t.Fatal(err)
		}
		want, _ := json.Marshal(report)
		got, _ := json.Marshal(&decoded)
		if !bytes.Equal(want, got) {
			t.Fatal("report changed JSON values")
		}
	}

	report := &suiteReport{Cases: []suiteOutcome{{Name: "one"}, {Name: "two"}}}
	var complete bytes.Buffer
	if err := writeSuiteReport("", &complete, report); err != nil {
		t.Fatal(err)
	}
	failure := errors.New("report sink failed")
	for _, after := range []int{0, 1, complete.Len() / 2, complete.Len() - 1} {
		writer := &reportFailWriter{remaining: after, err: failure}
		if err := writeSuiteReport("", writer, report); !errors.Is(err, failure) {
			t.Fatal("lost sink error", after, err)
		}
	}
	if err := writeSuiteReport("", &reportFailWriter{remaining: 1}, report); !errors.Is(err, io.ErrShortWrite) {
		t.Fatal("accepted short write", err)
	}

	path := filepath.Join(t.TempDir(), "report.json")
	if err := os.WriteFile(path, []byte("preserved"), 0o600); err != nil {
		t.Fatal(err)
	}
	report.Settings = map[string]any{"unsupported": make(chan int)}
	if err := writeSuiteReport(path, io.Discard, report); err == nil {
		t.Fatal("accepted unencodable metadata")
	}
	got, err := os.ReadFile(path)
	if err != nil || string(got) != "preserved" {
		t.Fatal("failed report replaced destination", string(got), err)
	}
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil || len(entries) != 1 {
		t.Fatal("temporary report leaked", entries, err)
	}
}

type reportFailWriter struct {
	remaining int
	err       error
}

func (w *reportFailWriter) Write(p []byte) (int, error) {
	n := min(len(p), w.remaining)
	w.remaining -= n
	if n < len(p) {
		return n, w.err
	}
	return n, nil
}

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

func TestSuiteTypedFailureIdentity(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name       string
		expression string
		assertion  string
		status     string
		kind       string
		code       string
		cause      string
	}{
		{"execution", "1 idiv 0", "<assert-true/>", suiteFailed, "assertion", "FOAR0001", "execution-error"},
		{"assertion evaluation", "1", "<assert>1 idiv 0</assert>", suiteFailed, suiteHarnessFailure, "FOAR0001", "assertion-error"},
		{"literal mismatch", "2", "<assert-eq>3</assert-eq>", suiteFailed, "assertion", "", "assertion-mismatch"},
		{"expected error passes", "1 idiv 0", `<error code="FOAR0001"/>`, suitePassed, "", "", ""},
		{"implementation bound", "1 to 1000000", "<assert-true/>", suiteFailed, suiteResourceLimit, "XPDY0130", "resource-bound"},
	} {
		t.Run(test.name, func(t *testing.T) {
			writeFixture(t, root, "case.xml", `<test-case name="identity"><test>`+test.expression+`</test><result>`+test.assertion+`</result></test-case>`)
			node, _, err := readSuiteNode(root, root, "case.xml")
			if err != nil {
				t.Fatal(err)
			}
			options := suiteOptions{kind: suiteQT3, directory: root, version: suiteVersion31, xsdVersion: suiteVersion10, timeout: time.Second, limitsProfile: "default"}
			actual := executeSuiteCase(t.Context(), options, suiteCase{node: node, base: root}, suiteOutcome{Name: "identity"})
			if actual.Status != test.status || actual.Kind != test.kind || actual.ErrorCode != test.code || actual.FailureCause != test.cause {
				t.Fatal(actual, test)
			}
			wantSignature := test.status == suiteFailed && test.kind != suiteResourceLimit
			if (actual.FailureSignature != "") != wantSignature {
				t.Fatal("stable non-resource signatures only", actual)
			}
		})
	}
	path := suiteFileURI(root) + `/tests/absent.xml`
	first := `cannot load document "` + path + `": resource unavailable` + "\nlstat " + filepath.Join(root, "tests") + ": OS-specific failure"
	if got := normalizeSuiteFailureReason(first, root); got != `cannot load document "suite:/tests/absent.xml": resource unavailable` {
		t.Fatal("machine paths must not enter the reviewed signature", got)
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

func TestSuiteBuiltinJSONSchema(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	const functions = "http://www.w3.org/2005/xpath-functions"
	writeFixture(t, root, suiteCatalog, `<catalog xmlns="`+suiteQTNamespace+`"><test-set name="json" file="json.xml"/></catalog>`)
	writeFixture(t, root, "json.xml", `<test-set xmlns="`+suiteQTNamespace+`">
	<environment name="json"><schema uri="`+functions+`" role="import"/><namespace prefix="j" uri="`+functions+`"/></environment>
	<test-case name="untyped"><environment ref="json"/><test>json-to-xml('{"a":1}')</test><result><all-of><assert-type>document-node(element(j:map))</assert-type><assert>$result/*/* instance of element(j:number,xs:untyped)</assert><assert-xml ignore-prefixes="true">&lt;map xmlns="`+functions+`">&lt;number key="a">1&lt;/number>&lt;/map></assert-xml></all-of></result></test-case>
	<test-case name="validate"><environment ref="json"/><test>json-to-xml('{}',map{'validate':true()})</test><result><error code="FOJS0004"/></result></test-case>
	<test-case name="other-uri"><environment><schema uri="urn:application" role="import"/></environment><test>1</test><result><assert-eq>1</assert-eq></result></test-case>
	<test-case name="other-role"><environment><schema uri="`+functions+`" role="source-reference"/></environment><test>1</test><result><assert-eq>1</assert-eq></result></test-case>
	<test-case name="file"><environment><schema uri="`+functions+`" role="import" file="missing.xsd"/></environment><test>1</test><result><assert-eq>1</assert-eq></result></test-case>
	<test-case name="source-validation"><environment><schema uri="`+functions+`" role="import"/><source role="." validation="strict"><content>&lt;r/></content></source></environment><test>.</test><result><assert-count>1</assert-count></result></test-case>
	</test-set>`)
	options := suiteOptions{kind: suiteQT3, directory: root, version: suiteVersion31, timeout: time.Second, setMatch: regexp.MustCompile(".*"), caseMatch: regexp.MustCompile(".*")}
	report, err := executeSuite(t.Context(), options, suitePin{Catalog: suiteCatalog, Namespace: suiteQTNamespace})
	if err != nil || len(report.Cases) != 6 {
		t.Fatal(report, err)
	}
	for i, outcome := range report.Cases {
		if i < 2 && outcome.Status != suitePassed || i >= 2 && i < 5 && (outcome.Status != suiteNotApplicable || !strings.Contains(outcome.Reason, "schema-awareness")) || i == 5 && (outcome.Status != suiteFailed || outcome.Kind != suiteHarnessFailure) {
			t.Fatal("built-in schema boundary", outcome)
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
		name       string
		stylesheet string
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

	writeFixture(t, root, suiteCatalog, `<catalog xmlns="`+suiteQTNamespace+`"><test-set name="choices" file="choices.xml"/><test-set name="compat-set" file="compat-set.xml"/></catalog>`)
	writeFixture(t, root, "choices.xml", `<test-set xmlns="`+suiteQTNamespace+`">
	<test-case name="strict"><dependency type="feature" value="xpath-1.0-compatibility" satisfied="false"/><test>1+'2'</test><result><error code="XPTY0004"/></result></test-case>
	<test-case name="implicit-strict"><test>1+'2'</test><result><error code="XPTY0004"/></result></test-case>
	<test-case name="compat"><dependency type="feature" value="xpath-1.0-compatibility"/><test>1+'2'</test><result><assert-eq>3</assert-eq></result></test-case>
	<test-case name="uca"><dependency type="feature" value="simple-uca-fallback"/><test>compare('a','A','http://www.w3.org/2013/collation/UCA?strength=secondary')</test><result><assert-eq>0</assert-eq></result></test-case>
	<test-case name="range"><dependency type="combinations_for_numbering" value="CIRCLED DIGIT ONE" range="0 to 50"/><test>1</test><result><assert-eq>1</assert-eq></result></test-case>
	<test-case name="other-range"><dependency type="combinations_for_numbering" value="CIRCLED DIGIT ONE" range="0 to 9"/><test>1</test><result><assert-eq>1</assert-eq></result></test-case>
	<test-case name="unknown"><dependency type="feature" value="future-unknown-feature"/><test>1</test><result><assert-eq>1</assert-eq></result></test-case>
	<test-case name="unknown-compat"><dependency type="feature" value="xpath-1.0-compatibility"/><dependency type="feature" value="future-unknown-feature"/><test>1</test><result><assert-eq>1</assert-eq></result></test-case>
	</test-set>`)
	writeFixture(t, root, "compat-set.xml", `<test-set xmlns="`+suiteQTNamespace+`"><dependency type="feature" value="xpath-1.0-compatibility"/><test-case name="inherited-compat"><test>1+'2'</test><result><assert-eq>3</assert-eq></result></test-case></test-set>`)

	for _, compatible := range []bool{false, true} {
		options := suiteOptions{kind: suiteQT3, directory: root, version: suiteVersion31, xpath10Compatibility: compatible, timeout: time.Second, setMatch: regexp.MustCompile(".*"), caseMatch: regexp.MustCompile(".*")}

		report, err := executeSuite(t.Context(), options, suitePin{Catalog: suiteCatalog, Namespace: suiteQTNamespace})
		passed, notApplicable := 4, 4
		if compatible {
			passed, notApplicable = 2, 6
		}
		if err != nil || report.Totals[suitePassed] != passed || report.Totals[suiteNotApplicable] != notApplicable || report.Totals[suiteFailed] != 1 || report.Settings["xpath_1_0_compatibility"] != compatible {
			t.Fatal(compatible, report, err)
		}
		for _, outcome := range report.Cases {
			if compatible && outcome.Name == "implicit-strict" && (outcome.Status != suiteNotApplicable || !strings.Contains(outcome.Reason, "default false compatibility")) {
				t.Fatal("unannotated expressions must retain QT3's default static context", outcome)
			}
		}
	}
}

func TestSuitePackageVersionsShareName(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}

	writeFixture(t, root, suiteCatalog, `<catalog xmlns="`+suiteXSLTNamespace+`"><test-set name="packages" file="packages.xml"/></catalog>`)
	writeFixture(t, root, "packages.xml", `<test-set xmlns="`+suiteXSLTNamespace+`">
  <environment name="versions"><package role="secondary" file="one.xsl" uri="urn:library" package-version="1"/><package role="secondary" file="two.xsl" uri="urn:library" package-version="2"/></environment>
  <environment name="stale"><package role="secondary" file="one.xsl" uri="urn:library" package-version="99"/><package role="secondary" file="two.xsl" uri="urn:library" name="urn:stale-name" package-version="0"/></environment>
  <test-case name="highest"><environment ref="versions"/><dependencies><package_version_resolution value="highest_version"/></dependencies><test><package role="principal" file="main.xsl"/><initial-template name="main"/></test><result><assert-string-value>2</assert-string-value></result></test-case>
  <test-case name="declaration-identity"><environment ref="stale"/><test><package role="principal" file="main.xsl"/><initial-template name="main"/></test><result><assert-string-value>2</assert-string-value></result></test-case>
  <test-case name="default-version"><environment><package role="secondary" file="default.xsl" name="urn:default" package-version="99"/></environment><test><package role="principal" file="default-main.xsl"/><initial-template name="main"/></test><result><assert-string-value>default</assert-string-value></result></test-case>
  <test-case name="shadow-identity"><environment><package role="secondary" file="shadow.xsl" name="urn:shadow" package-version="3"/></environment><test><package role="principal" file="shadow-main.xsl"/><initial-template name="main"/></test><result><assert-string-value>shadow</assert-string-value></result></test-case>
  <test-case name="foreign-root"><environment><package role="secondary" file="foreign.xsl" name="urn:foreign" package-version="4"/></environment><test><package role="principal" file="foreign-main.xsl"/><initial-template name="main"/></test><result><error code="XTSE3000"/></result></test-case>
</test-set>`)

	for name, value := range map[string]string{"one.xsl": "1", "two.xsl": "2"} {
		writeFixture(t, root, name, `<xsl:package xmlns:xsl="`+lexicon.NamespaceXSLT+`" version="3.0" name="urn:library" package-version="`+value+`"><xsl:template name="value" visibility="public"><xsl:text>`+value+`</xsl:text></xsl:template></xsl:package>`)
	}

	writeFixture(t, root, "main.xsl", `<xsl:package xmlns:xsl="`+lexicon.NamespaceXSLT+`" version="3.0" name="urn:application" package-version="1"><xsl:use-package name="urn:library" package-version="1+"/><xsl:template name="main" visibility="public"><xsl:call-template name="value"/></xsl:template></xsl:package>`)
	writeFixture(t, root, "default.xsl", `<xsl:package xmlns:xsl="`+lexicon.NamespaceXSLT+`" version="3.0" name="urn:default"><xsl:template name="value" visibility="public">default</xsl:template></xsl:package>`)
	writeFixture(t, root, "shadow.xsl", `<xsl:package xmlns:xsl="`+lexicon.NamespaceXSLT+`" version="3.0" name="urn:stale" _name="urn:shadow" package-version="invalid" _package-version="3"><xsl:template name="value" visibility="public">shadow</xsl:template></xsl:package>`)
	writeFixture(t, root, "foreign.xsl", `<package xmlns="urn:foreign-vocabulary" name="urn:wrong" package-version="99"/>`)
	for _, packageName := range []string{"default", "shadow", "foreign"} {
		version := map[string]string{"default": "1", "shadow": "3", "foreign": "4"}[packageName]
		writeFixture(t, root, packageName+"-main.xsl", `<xsl:package xmlns:xsl="`+lexicon.NamespaceXSLT+`" version="3.0" name="urn:application"><xsl:use-package name="urn:`+packageName+`" package-version="`+version+`"/><xsl:template name="main" visibility="public"><xsl:call-template name="value"/></xsl:template></xsl:package>`)
	}

	options := suiteOptions{kind: suiteXSLT, directory: root, version: suiteVersion30, timeout: time.Second, setMatch: regexp.MustCompile(".*"), caseMatch: regexp.MustCompile(".*")}

	report, err := executeSuite(t.Context(), options, suitePin{Catalog: suiteCatalog, Namespace: suiteXSLTNamespace})
	if err != nil || report.Totals[suitePassed] != 5 || report.Totals[suiteFailed] != 0 {
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
		name       string
		expression string
		assertion  string
		kind       string
		pass       bool
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
		{"relative namespace", `parse-xml('<a xmlns="relative"/>')`, `<assert-xml>&lt;a xmlns="relative"/></assert-xml>`, suiteQT3, true},
		{"relative namespace literal identity", `parse-xml('<a xmlns="relative"/>')`, `<assert-xml>&lt;a xmlns="./relative"/></assert-xml>`, suiteQT3, false},
		{"relative namespace fragment", `parse-xml-fragment('<a xmlns="relative"/>text<b/>')`, `<assert-xml>&lt;a xmlns="relative"/>text&lt;b/></assert-xml>`, suiteQT3, true},
		{"XML attribute order and unused namespace", `parse-xml('<a xmlns:unused="relative" b="2" a="1"/>')`, `<assert-xml>&lt;a a="1" b="2"/></assert-xml>`, suiteQT3, true},
		{"XML attribute prefix retained", `parse-xml('<a xmlns:p="relative" p:n="1"/>')`, `<assert-xml>&lt;a xmlns:q="relative" q:n="1"/></assert-xml>`, suiteQT3, false},
		{"XML attribute prefix ignored", `parse-xml('<a xmlns:p="relative" p:n="1"/>')`, `<assert-xml ignore-prefixes="true">&lt;a xmlns:q="relative" q:n="1"/></assert-xml>`, suiteQT3, true},
		{"XML comment retained", `parse-xml('<a><!--one--></a>')`, `<assert-xml>&lt;a>&lt;!--two-->&lt;/a></assert-xml>`, suiteQT3, false},
		{"XML comment retained ignoring prefixes", `parse-xml('<a><!--one--></a>')`, `<assert-xml ignore-prefixes="true">&lt;a/></assert-xml>`, suiteQT3, false},
		{"XML PI retained", `parse-xml('<a><?one data?></a>')`, `<assert-xml ignore-prefixes="true">&lt;a>&lt;?two data?>&lt;/a></assert-xml>`, suiteQT3, false},
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
		data     string
		encoding string
		want     string
		fail     bool
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

func TestSuiteXMLNamespaceComparison(t *testing.T) {
	engine, err := transform.NewEngine(transform.Config{})
	if err != nil {
		t.Fatal(err)
	}
	environment := &preparedSuiteEnvironment{engine: engine, namespaces: map[string]string{}, variables: transform.Bindings{}}
	for _, test := range []struct {
		name      string
		namespace string
		body      string
		expected  string
		pass      bool
	}{
		{"space namespace", "urn:two words", ``, `<p:r xmlns:p="urn:two words"/>`, true},
		{"different namespace", "urn:two words", ``, `<p:r xmlns:p="urn:other words"/>`, false},
		{"alias collision", "urn:two words", ``, `<p:r xmlns:p="urn:0"/>`, false},
		{"comment and PI", "urn:two words", `<xsl:comment> xmlns:p="unchanged" </xsl:comment><xsl:processing-instruction name="pi">xmlns:p="unchanged"</xsl:processing-instruction>`, `<p:r xmlns:p="urn:two words"><!-- xmlns:p="unchanged" --><?pi xmlns:p="unchanged"?></p:r>`, true},
		{"text whitespace", "urn:two words", `<xsl:text> a  b </xsl:text>`, `<p:r xmlns:p="urn:two words">a b</p:r>`, false},
		{"attribute reference", "urn:two words", `<xsl:attribute name="a" select="codepoints-to-string(9)"/>`, `<p:r xmlns:p="urn:two words" a="&#9;"/>`, true},
		{"attribute literal tab", "urn:two words", `<xsl:attribute name="a" select="codepoints-to-string(9)"/>`, "<p:r xmlns:p=\"urn:two words\" a=\"\t\"/>", false},
		{"attribute literal CRLF", "urn:two words", `<xsl:attribute name="a" select="codepoints-to-string(13)"/>`, "<p:r xmlns:p=\"urn:two words\" a=\"\r\n\"/>", false},
		{"namespace character reference", "urn:a&#9;b", ``, `<p:r xmlns:p="urn:a&#9;b"/>`, true},
		{"namespace literal tab", "urn:a&#9;b", ``, "<p:r xmlns:p=\"urn:a\tb\"/>", false},
		{"undeclared prefix", "urn:two words", ``, `<p:r xmlns:q="urn:two words"/>`, false},
		{"reserved binding", "urn:two words", ``, `<p:r xmlns:p="urn:two words" xmlns:xml="urn:other"/>`, false},
		{"missing attribute separator", "urn:two words", ``, `<p:r xmlns:p="urn:two words"a="1"/>`, false},
		{"unclosed element", "urn:two words", ``, `<p:r xmlns:p="urn:two words">`, false},
		{"directive", "urn:two words", ``, `<!DOCTYPE r SYSTEM "https://example.invalid/never"><p:r xmlns:p="urn:two words"/>`, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			source := `<xsl:stylesheet xmlns:xsl="` + lexicon.NamespaceXSLT + `" version="3.0"><xsl:template name="start"><xsl:element name="p:r" namespace="` + test.namespace + `">` + test.body + `</xsl:element></xsl:template></xsl:stylesheet>`
			expression := `transform(map{'stylesheet-text':$sheet,'initial-template':QName('','start'),'delivery-format':'raw'})?output`
			result, err := environment.query(t.Context(), expression, transform.Bindings{{Local: "sheet"}: transform.Values(transform.String(source))})
			if err != nil {
				t.Fatal(err)
			}
			evaluation := &suiteEvaluation{environment: environment, sequence: result, options: suiteOptions{kind: suiteXSLT}, item: suiteCase{node: &suiteNode{}}}
			assertion := &suiteNode{XMLName: xml.Name{Local: "assert-xml"}, Text: test.expected}
			if err := checkSuiteAssertion(t.Context(), evaluation, assertion); (err == nil) != test.pass {
				t.Fatal(err, test.pass)
			}
		})
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := rewriteSuiteNamespaceNames(ctx, []byte(`<r/>`), make(map[string]string), 100); !errors.Is(err, context.Canceled) {
		t.Fatal("cancellation", err)
	}
	if _, err := rewriteSuiteNamespaceNames(t.Context(), []byte(`<r/>`), make(map[string]string), 1); !errors.Is(err, transform.ErrLimit) {
		t.Fatal("input limit", err)
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
		actual    string
		assertion string
		pass      bool
	}{
		{"line\nnext\rdata", `<assert-serialization file="expected.txt"/>`, true},
		{"line\nnextdata", `<assert-serialization file="expected.txt"/>`, false},
		{"line\r\nnext\rdata", `<assert-serialization file="expected.txt"/>`, false},
		{"line\nnext", `<assert-serialization>line&#13;&#10;next</assert-serialization>`, false},
		{"line\r\nnext", `<assert-serialization>line&#13;&#10;next</assert-serialization>`, true},
		{strings.Repeat("a", 4000), `<assert-serialization>b</assert-serialization>`, false},
	} {
		compiled, err := engine.CompileXSLTReader(t.Context(), strings.NewReader(`<xsl:stylesheet xmlns:xsl="`+lexicon.NamespaceXSLT+`" version="3.0"><xsl:output method="text"/><xsl:template name="start"><xsl:param name="text"/><xsl:value-of select="$text"/></xsl:template></xsl:stylesheet>`), transform.XSLTOptions{})
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
	for _, test := range []struct {
		encoding string
		value    string
		method   string
	}{
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
		source := `<xsl:stylesheet xmlns:xsl="` + lexicon.NamespaceXSLT + `" version="3.0"><xsl:output method="` + test.method + `" encoding="` + test.encoding + `"/><xsl:param name="value"/><xsl:param name="encoding"/><xsl:template name="start"><xsl:value-of select="$value"/><xsl:result-document href="secondary" encoding="{$encoding}"><xsl:value-of select="$value"/></xsl:result-document></xsl:template></xsl:stylesheet>`
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
			want := test.value
			if test.method == "adaptive" {
				want = "&#170;"
			} // The delegated XML method retains the ASCII repertoire.
			assertion := &suiteNode{XMLName: xml.Name{Local: "serialization-matches"}, Text: regexp.QuoteMeta(want)}
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

func TestSuiteFileURI(t *testing.T) {
	for _, name := range []string{"valid.xml", "suite files/hash#percent%é.xml"} {
		path := filepath.Join(t.TempDir(), filepath.FromSlash(name))
		uri := suiteFileURI(path)
		parsed, err := url.Parse(uri)
		if err != nil {
			t.Fatal(err)
		}
		if parsed.Scheme != suiteFile || parsed.Host != "" || parsed.Opaque != "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || !strings.HasPrefix(parsed.Path, "/") || strings.Contains(parsed.Path, "\\") {
			t.Fatalf("local path %q produced an invalid file URI: %q", path, uri)
		}
		if got := suiteFileURIPath(parsed.Path); got != path {
			t.Fatalf("file URI %q resolved to %q, want %q", uri, got, path)
		}
	}
}

func TestSuiteResolvedLocalPaths(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"valid.xml", "space name.xml", "hash#name.xml", "percent%é.xml"} {
		writeFixture(t, root, name, `<r/>`)
	}
	resolver := &suiteResourceResolver{root: root}
	for _, name := range []string{"valid.xml", "space name.xml", "hash#name.xml", "percent%é.xml"} {
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
	writeFixture(t, root, "latin.txt", "caf\xe9")
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
      <test-case name="text-collection"><environment><collection uri="urn:mixed"><source file="source.xml"/><resource file="latin.txt" uri="urn:latin" media-type="text/plain" encoding="ISO-8859-1"/><query>8,9</query></collection></environment><test>collection('urn:mixed')[1]/r = '7' and collection('urn:mixed')[2] instance of xs:string and collection('urn:mixed')[2] = 'café' and deep-equal(subsequence(collection('urn:mixed'),3),(8,9)) and uri-collection('urn:mixed')[2] = 'urn:latin'</test><result><assert-true/></result></test-case>
      <test-case name="scoped-query"><environment><collection><query xmlns:q="urn:q">xs:QName('q:k')</query></collection></environment><test>collection()[1] = QName('urn:q','k')</test><result><assert-true/></result></test-case>
      <test-case name="resource-fragment"><environment><collection><resource file="text.txt" uri="urn:text#fragment"/></collection></environment><test>1</test><result><error code="*"/></result></test-case>
	  <test-case name="no-network"><test>unparsed-text('https://suite.invalid/undeclared')</test><result><error code="FOUT1170"/></result></test-case>
	  <test-case name="unused-remote"><environment><resource file="https://suite.invalid/remote" uri="urn:remote"/></environment><test>1</test><result><assert-eq>1</assert-eq></result></test-case>
      <test-case name="remote-unavailable"><environment><resource file="https://suite.invalid/remote" uri="urn:remote"/></environment><test>not(unparsed-text-available('urn:remote'))</test><result><assert-true/></result></test-case>
      <test-case name="remote-read-error"><environment><resource file="https://suite.invalid/remote" uri="urn:remote"/></environment><test>unparsed-text('urn:remote')</test><result><error code="FOUT1170"/></result></test-case>
      <test-case name="remote-local-collision"><environment><resource file="https://suite.invalid/remote" uri="urn:duplicate"/><resource file="text.txt" uri="urn:duplicate"/></environment><test>1</test><result><assert-eq>1</assert-eq></result></test-case>
      <test-case name="local-remote-collision"><environment><resource file="text.txt" uri="urn:duplicate"/><resource file="https://suite.invalid/remote" uri="urn:duplicate"/></environment><test>1</test><result><assert-eq>1</assert-eq></result></test-case>
        <test-case name="conflicting-mapping"><environment><resource file="text.txt" uri="urn:duplicate"/><resource file="other.txt" uri="urn:duplicate"/></environment><test>1</test><result><assert-eq>1</assert-eq></result></test-case>
	  <test-case name="transport-hint"><environment><resource file="text.txt" uri="urn:text" encoding="iso-8859-1"/></environment><test>unparsed-text('urn:text')</test><result><assert-string-value>declared text</assert-string-value></result></test-case>
	  <test-case name="outside"><environment><resource file="../outside.txt" uri="urn:outside"/></environment><test>1</test><result><error code="*"/></result></test-case>
	  <test-case name="fragment-collection"><environment><collection uri="fragments"><source file="fragments.xml#one" uri="urn:fragments#one"/><source file="fragments.xml#two" uri="urn:fragments#two"/><source file="fragments.xml#one" uri="urn:fragments#one"/></collection></environment>
	    <test>let $c := collection('fragments') return count($c) = 3 and $c[1] = '1' and $c[2] = '2' and $c[1] is $c[3] and root($c[1]) is root($c[2]) and root($c[1]) is doc('urn:fragments') and deep-equal(uri-collection('fragments')!string(.), ('urn:fragments#one','urn:fragments#two','urn:fragments#one'))</test><result><assert-true/></result></test-case>
	  <test-case name="scoped-source-name"><environment><source xmlns:p="urn:source-name" role="$p:n" file="source.xml"/></environment><test>$Q{urn:source-name}n = '7'</test><result><assert-true/></result></test-case>
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

	if len(report.Cases) != 29 {
		t.Fatal("missing resource cases", report.Totals)
	}

	for _, outcome := range report.Cases {
		positive := slices.Contains([]string{"unused-remote", "remote-unavailable", "remote-read-error", "default-collection", "relative-mappings", "text-collection", "scoped-query", "no-network", "transport-hint", "fragment-collection", "fragment-variable", "scoped-source-name", "fragment-context", "fragment-selection", "fragment-alias", "escaped-files"}, outcome.Name)
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
	writeFixture(t, root, "content-base/source.xml", `<loaded/>`)
	writeFixture(t, root, "inline-base.xsl", `<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="3.0"><xsl:template match="/"><out><xsl:value-of select="document(r/@href) is document('source.xml', /) and contains(base-uri(/),'content-base/')"/></out></xsl:template></xsl:stylesheet>`)
	writeFixture(t, root, "output-uri.xsl", `<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="3.0"><xsl:template name="start"><out><xsl:value-of select="current-output-uri()"/></out></xsl:template></xsl:stylesheet>`)
	writeFixture(t, root, "environment.xml", `<test-set xmlns="`+namespace+`" name="environment">
	  <environment name="modules"><stylesheet file="main.xsl" uri="urn:main" role="principal"/><stylesheet file="part.xsl" uri="urn:part" role="secondary"/></environment>
	  <test-case name="principal"><environment ref="modules"/><test><param name="required" select="' supplied '"/><param name="flag" select="true()" static="yes"/><initial-template name="start"/></test><result><assert-xml>&lt;out>included supplied static&lt;/out></assert-xml></result></test-case>
	  <test-case name="ambiguous"><environment><stylesheet file="main.xsl"/><stylesheet file="part.xsl"/></environment><test/><result><error code="*"/></result></test-case>
	  <test-case name="source-param"><environment ref="modules"/><test><param name="required" source="source.xml"/><initial-template name="start"/></test><result><assert-xml>&lt;out>included7&lt;/out></assert-xml></result></test-case>
	  <test-case name="unknown-invocation"><environment ref="modules"/><test><unknown/></test><result><error code="*"/></result></test-case>
	  <test-case name="output-override"><environment ref="modules"/><test><param name="required" select="'x'"/><initial-template name="start"/><output file="result.xml" serialize="yes"/></test><result><assert-xml>&lt;out>includedx&lt;/out></assert-xml></result></test-case>
	  <test-case name="output-default"><test><stylesheet file="output-uri.xsl"/><initial-template name="start"/><output/></test><result><assert>string(/out) eq 'file:///xmlsec-suite-output/'</assert></result></test-case>
      <test-case name="output-empty"><test><stylesheet file="output-uri.xsl"/><initial-template name="start"/><output file=""/></test><result><assert>ends-with(string(/out), '/environment.xml')</assert></result></test-case>
      <test-case name="output-absent"><test><stylesheet file="output-uri.xsl"/><initial-template name="start"/><output file="#absent"/></test><result><assert>string(/out) eq ''</assert></result></test-case>
      <test-case name="output-base"><test><stylesheet file="output-uri.xsl"/><initial-template name="start"/><output xml:base="output/" file=""/></test><result><assert>ends-with(string(/out), '/output/')</assert></result></test-case>
      <test-case name="context-item"><environment><context-item select="7"/><stylesheet file="main.xsl"/><stylesheet file="part.xsl" uri="urn:part" role="secondary"/></environment><test><param name="required" select="'x'"/><initial-template name="start"/></test><result><assert-xml>&lt;out>includedx&lt;/out></assert-xml></result></test-case>
      <test-case name="select-only-variable"><environment><source role="$n" select="parse-xml('&lt;r/>')"/></environment><test><stylesheet file="mode.xsl"/></test><result><error code="*"/></result></test-case>
      <test-case name="select-only-source"><environment><source role="." select="parse-xml('&lt;r>&lt;n/>&lt;/r>')/r/n"/></environment><test><stylesheet file="mode.xsl"/></test><result><assert-xml>&lt;out>selected&lt;/out></assert-xml></result></test-case>
      <test-case name="selected-source"><environment><source role="." select="/r/n"><content>&lt;r>&lt;n/>&lt;/r></content></source></environment><test><stylesheet file="mode.xsl"/></test><result><assert-xml>&lt;out>selected&lt;/out></assert-xml></result></test-case>
      <test-case name="selected-global"><environment><source role="." select="/r/n"><content>&lt;r>&lt;n/>&lt;/r></content></source></environment><test><stylesheet file="mode.xsl"/><initial-template name="start"/></test><result><assert-xml>&lt;out>n&lt;/out></assert-xml></result></test-case>
      <test-case name="empty-source-selection"><environment><source role="." select="()"><content>&lt;r/></content></source></environment><test><stylesheet file="mode.xsl"/></test><result><error code="*"/></result></test-case>
      <test-case name="multiple-source-selection"><environment><source role="." select="(.,.)"><content>&lt;r/></content></source></environment><test><stylesheet file="mode.xsl"/></test><result><error code="*"/></result></test-case>
      <test-case name="inline-source-base"><environment><source role="."><content xml:base="content-base/">&lt;r href="source.xml"/></content></source></environment><test><stylesheet file="inline-base.xsl"/></test><result><assert-xml>&lt;out>true&lt;/out></assert-xml></result></test-case>
      <test-case name="inline-base-independent"><environment><static-base-uri uri="#UNDEFINED"/><source role="."><content xml:base="content-base/">&lt;r href="source.xml"/></content></source></environment><test><stylesheet file="inline-base.xsl"/></test><result><assert-xml>&lt;out>true&lt;/out></assert-xml></result></test-case>
	</test-set>`)
	options := suiteOptions{kind: suiteXSLT, directory: root, version: suiteVersion30, timeout: time.Second, setMatch: regexp.MustCompile(".*"), caseMatch: regexp.MustCompile(".*")}

	report, err := executeSuite(t.Context(), options, suitePin{Catalog: suiteCatalog, Namespace: namespace})
	if err != nil {
		t.Fatal(err)
	}

	if len(report.Cases) != 18 {
		t.Fatal("case inventory changed", len(report.Cases))
	}

	for _, outcome := range report.Cases {
		if outcome.Name == "select-only-source" || outcome.Name == "principal" || outcome.Name == "source-param" || strings.HasPrefix(outcome.Name, "output-") || outcome.Name == "context-item" || outcome.Name == "selected-source" || outcome.Name == "selected-global" || outcome.Name == "inline-source-base" || outcome.Name == "inline-base-independent" {
			if outcome.Status != suitePassed {
				t.Fatal("parameter invocation failed", outcome)
			}
		} else if outcome.Status != suiteFailed || outcome.Kind != suiteHarnessFailure {
			t.Fatal("unsupported metadata was silently ignored", outcome)
		}
	}
}

func TestSuiteReferencedFileURIs(t *testing.T) {
	for _, kind := range []string{suiteQT3, suiteXSLT} {
		t.Run(kind, func(t *testing.T) {
			root, err := filepath.EvalSymlinks(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			namespace, version := suiteQTNamespace, suiteVersion31
			if kind == suiteXSLT {
				namespace, version = suiteXSLTNamespace, suiteVersion30
			}
			writeFixture(t, root, suiteCatalog, `<catalog xmlns="`+namespace+`"><test-set name="files" xml:base="sets/" file="cases%20one.xml"/></catalog>`)
			writeFixture(t, root, "data/source one.xml", `<r>42</r>`)
			writeFixture(t, root, "expected/result one.xml", `<out>42</out>`)
			invocation := `<test xml:base="../queries/" file="expression%20one.xq"/>`
			writeFixture(t, root, "queries/expression one.xq", `parse-xml('<out>42</out>')`)
			if kind == suiteXSLT {
				invocation = `<test><stylesheet xml:base="../styles/" file="main%20one.xsl"/></test>`
				writeFixture(t, root, "styles/main one.xsl", `<xsl:stylesheet xmlns:xsl="`+lexicon.NamespaceXSLT+`" version="3.0"><xsl:include href="part%20one.xsl"/><xsl:template match="/"><out><xsl:call-template name="value"/></out></xsl:template></xsl:stylesheet>`)
				writeFixture(t, root, "styles/part one.xsl", `<xsl:stylesheet xmlns:xsl="`+lexicon.NamespaceXSLT+`" version="3.0"><xsl:template name="value"><xsl:value-of select="doc('../data/source%20one.xml')/r"/></xsl:template></xsl:stylesheet>`)
			}
			writeFixture(t, root, "sets/cases one.xml", `<test-set xmlns="`+namespace+`"><test-case name="local"><environment><source role="." xml:base="../data/" file="source%20one.xml"/></environment>`+invocation+`<result><assert-xml xml:base="../expected/" file="result%20one.xml"/></result></test-case></test-set>`)
			options := suiteOptions{kind: kind, directory: root, version: version, timeout: time.Second, setMatch: regexp.MustCompile(".*"), caseMatch: regexp.MustCompile(".*")}
			report, err := executeSuite(t.Context(), options, suitePin{Catalog: suiteCatalog, Namespace: namespace})
			if err != nil || report.Totals[suitePassed] != 1 || len(report.Cases) != 1 {
				t.Fatal(report, err)
			}
		})
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
	for _, clock := range []struct {
		flag   string
		year   string
		report string
	}{
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

func TestSuiteCaseDeadlineClassification(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		root := t.TempDir()
		set, _, err := decodeSuiteNode([]byte(`<test-set><test-case name="ordinary-error"><test>1 idiv 0</test><result><error code="*"/></result></test-case></test-set>`), filepath.Join(root, "deadline.xml"))
		if err != nil {
			t.Fatal(err)
		}
		options := suiteOptions{kind: suiteQT3, directory: root, version: suiteVersion31, timeout: time.Hour}
		item := suiteCase{base: root, setNode: set, node: set.child("test-case")}
		ctx, cancel := context.WithTimeout(t.Context(), time.Second)
		defer cancel()

		if outcome := executeSuiteCase(ctx, options, item, suiteOutcome{}); outcome.Status != suitePassed {
			t.Fatal("expected language error failed before the deadline", outcome)
		}

		synctest.Sleep(time.Second)
		if outcome := executeSuiteCase(ctx, options, item, suiteOutcome{}); outcome.Status != suiteFailed || outcome.Kind != suiteResourceLimit || outcome.FailureCause != "resource-bound" {
			t.Fatal("expired deadline satisfied an expected language error", outcome)
		}
	})
}

func TestSuiteTimeoutClassification(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		root, err := filepath.EvalSymlinks(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		writeFixture(t, root, suiteCatalog, `<catalog xmlns="`+suiteQTNamespace+`"><test-set name="budget" file="budget.xml"/></catalog>`)
		writeFixture(t, root, "budget.xml", `<test-set xmlns="`+suiteQTNamespace+`"><test-case name="large-object"><test>error((), 'details', 1 to 100001)</test><result><error code="FOER0000"/></result></test-case><test-case name="ordinary-error"><test>1 idiv 0</test><result><error code="*"/></result></test-case><test-case name="allowed-resource-error"><test>1 to 100001</test><result><error code="XPDY0130"/></result></test-case>
<test-case name="parameter-budget"><environment><param name="p" select="1 to 100001"/></environment><test>1</test><result><error code="*"/></result></test-case>
<test-case name="context-budget"><environment><context-item select="1 to 100001"/></environment><test>1</test><result><error code="*"/></result></test-case>
<test-case name="collection-budget"><environment><collection><query>1 to 100001</query></collection></environment><test>1</test><result><error code="*"/></result></test-case>
<test-case name="assertion-budget"><test>1</test><result><not><assert>count((1 to 100001) ! string(.)) = 0</assert></not></result></test-case>
</test-set>`)
		options := suiteOptions{kind: suiteQT3, directory: root, version: suiteVersion31, limitsProfile: "default", timeout: time.Second, setMatch: regexp.MustCompile(".*"), caseMatch: regexp.MustCompile(".*")}
		// Virtual time keeps budget checks active; zero expires the case immediately.
		for _, timeout := range []time.Duration{time.Second, 0} {
			options.timeout = timeout
			report, err := executeSuite(t.Context(), options, suitePin{Catalog: suiteCatalog, Namespace: suiteQTNamespace})
			if err != nil || len(report.Cases) != 7 {
				t.Fatal(report, err)
			}
			for _, outcome := range report.Cases {
				if timeout == time.Second && slices.Contains([]string{"ordinary-error", "allowed-resource-error"}, outcome.Name) {
					if outcome.Status != suitePassed {
						t.Fatal(outcome)
					}
				} else if outcome.Status != suiteFailed || outcome.Kind != suiteResourceLimit {
					t.Fatal("budget/deadline satisfied an expected language error", timeout, outcome)
				}
			}
		}
	})
}

func TestSuiteDTDInput(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	writeFixture(t, root, suiteCatalog, `<catalog xmlns="`+suiteQTNamespace+`"><test-set name="dtd" file="dtd.xml"/></catalog>`)
	writeFixture(t, root, "source.xml", `<!DOCTYPE r SYSTEM "defaults.dtd"><r/>`)
	writeFixture(t, root, "defaults.dtd", `<!ATTLIST r identity ID "a">`)
	writeFixture(t, root, "dtd.xml", `<test-set xmlns="`+suiteQTNamespace+`"><test-case name="enabled"><dependency type="feature" value="infoset-dtd"/><environment><source role="." file="source.xml"/></environment><test>count(id('a',.))</test><result><assert-eq>1</assert-eq></result></test-case><test-case name="disabled"><dependency type="feature" value="dtd" satisfied="false"/><test>error()</test><result><assert-eq>1</assert-eq></result></test-case></test-set>`)
	options := suiteOptions{kind: suiteQT3, directory: root, version: suiteVersion31, timeout: time.Second, setMatch: regexp.MustCompile(".*"), caseMatch: regexp.MustCompile(".*")}
	report, err := executeSuite(t.Context(), options, suitePin{Catalog: suiteCatalog, Namespace: suiteQTNamespace})
	if err != nil || report.Totals[suitePassed] != 1 || report.Totals[suiteNotApplicable] != 1 || report.Totals[suiteFailed] != 0 {
		t.Fatal(report, err)
	}
}

func TestSuiteDeferredXMLSources(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	writeFixture(t, root, suiteCatalog, `<catalog xmlns="`+suiteQTNamespace+`"><test-set name="deferred" file="deferred.xml"/></catalog>`)
	writeFixture(t, root, "bad.xml", `<r a=unquoted/>`)
	writeFixture(t, root, "deferred.xml", `<test-set xmlns="`+suiteQTNamespace+`"><environment name="source"><source file="bad.xml" uri="urn:bad"/></environment><test-case name="unused"><environment ref="source"/><test>1</test><result><assert-eq>1</assert-eq></result></test-case><test-case name="load-error"><environment ref="source"/><test>doc('urn:bad')</test><result><error code="FODC0002"/></result></test-case></test-set>`)
	options := suiteOptions{kind: suiteQT3, directory: root, version: suiteVersion31, timeout: time.Second, setMatch: regexp.MustCompile(".*"), caseMatch: regexp.MustCompile(".*")}
	report, err := executeSuite(t.Context(), options, suitePin{Catalog: suiteCatalog, Namespace: suiteQTNamespace})
	if err != nil || report.Totals[suitePassed] != 2 || report.Totals[suiteFailed] != 0 {
		t.Fatal(report, err)
	}
}

func TestSuiteSourceOptions(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	writeFixture(t, root, "source.xml", `<r/>`)
	writeFixture(t, root, suiteCatalog, `<catalog xmlns="`+suiteQTNamespace+`"><test-set name="source-options" file="options.xml"/></catalog>`)
	cases := []struct {
		name       string
		attributes string
		status     string
	}{
		{"disabled", `role="." file="source.xml" xinclude="false" streaming="0" defines-stylesheet="false" xml-version="1.00"`, suitePassed},
		{"xinclude", `file="missing.xml" xinclude="true"`, suiteNotApplicable},
		{"streaming", `role="." file="missing.xml" streaming="1"`, suiteNotApplicable},
		{"association", `role="." file="missing.xml" defines-stylesheet="true"`, suiteNotApplicable},
		{"xml11", `file="missing.xml" xml-version="1.10"`, suiteNotApplicable},
		{"decimal-version", `file="source.xml" xml-version="+0001.000"`, suitePassed},
		{"invalid-boolean", `file="source.xml" xinclude="yes"`, suiteFailed},
		{"invalid-version", `file="source.xml" xml-version="2.0"`, suiteFailed},
		{"inexact-version", `file="source.xml" xml-version="1.00000000000000000001"`, suiteFailed},
		{"exponent-version", `file="source.xml" xml-version="1e0"`, suiteFailed},
		{"multiple-dots", `file="source.xml" xml-version="1.0.0"`, suiteFailed},
		{"validation", `role="." file="source.xml" validation="strict"`, suiteFailed},
		{"irrelevant-streaming", `role="$n" file="source.xml" streaming="true"`, suitePassed},
	}
	var source strings.Builder
	source.WriteString(`<test-set xmlns="` + suiteQTNamespace + `"><environment name="optional"><source file="missing.xml" xinclude="true"/></environment>`)
	for _, test := range cases {
		source.WriteString(`<test-case name="` + test.name + `"><environment><source ` + test.attributes + `/></environment><test>true()</test><result><assert-true/></result></test-case>`)
	}
	source.WriteString(`<test-case name="referenced"><environment ref="optional"><source file="source.xml" xinclude="false"/></environment><test>true()</test><result><assert-true/></result></test-case>`)
	source.WriteString(`<test-case name="nested"><environment><collection><source file="missing.xml" xinclude="true"/></collection></environment><test>true()</test><result><assert-true/></result></test-case></test-set>`)
	writeFixture(t, root, "options.xml", source.String())
	options := suiteOptions{kind: suiteQT3, directory: root, version: suiteVersion31, timeout: time.Second, setMatch: regexp.MustCompile(".*"), caseMatch: regexp.MustCompile(".*")}
	report, err := executeSuite(t.Context(), options, suitePin{Catalog: suiteCatalog, Namespace: suiteQTNamespace})
	if err != nil || len(report.Cases) != len(cases)+2 {
		t.Fatal(report, err)
	}
	for i, outcome := range report.Cases {
		want := suiteNotApplicable
		if i < len(cases) {
			want = cases[i].status
		}
		if outcome.Status != want || want != suitePassed && outcome.Reason == "" {
			t.Error(outcome, want)
		}
		if outcome.Name == "validation" && outcome.Kind != suiteHarnessFailure {
			t.Error("schema processing must remain a visible harness failure", outcome)
		}
	}
}

// residualCaseResult retains typed errors; a report's explanatory string alone
// cannot establish that a failure was caused by a configured resource limit.
type residualCaseResult struct {
	Evaluation     *suiteEvaluation
	Environment    *preparedSuiteEnvironment
	PrepareError   error
	AssertionError error
}

func (r residualCaseResult) executionError() error {
	if r.PrepareError != nil {
		return r.PrepareError
	}
	return r.Evaluation.err
}

func residualRequired(t *testing.T, name string) string {
	t.Helper()
	value := os.Getenv(name)
	if value == "" {
		if os.Getenv("XMLSEC_REQUIRE_P3_PROOFS") == "1" {
			t.Fatal("required proof input is missing:", name)
		}
		t.Skip("set " + name + " to run pinned external causal proofs")
	}
	return value
}

func loadPinnedResidualCase(t *testing.T, directory, kind, file, name string) suiteCase {
	t.Helper()
	pinsData, err := os.ReadFile(filepath.Join("..", "..", "..", "build", "w3c-suites.json"))
	if err != nil {
		t.Fatal(err)
	}
	var pins map[string]suitePin
	if err := json.Unmarshal(pinsData, &pins); err != nil {
		t.Fatal(err)
	}
	pin := pins[kind]
	if err := verifySuiteCheckout(t.Context(), directory, pin); err != nil {
		t.Fatal(err)
	}
	catalog, _, err := readSuiteNode(directory, directory, pin.Catalog)
	if err != nil {
		t.Fatal(err)
	}
	set, path, err := readSuiteNode(directory, directory, file)
	if err != nil {
		t.Fatal(err)
	}
	listed := slices.ContainsFunc(catalog.children("test-set"), func(entry *suiteNode) bool { return entry.attr(suiteFile) == file })
	if !listed || catalog.XMLName.Space != pin.Namespace || set.XMLName.Space != pin.Namespace {
		t.Fatal("proof case is not listed in the pinned catalog", file)
	}
	for _, node := range set.children("test-case") {
		if node.attr("name") == name {
			return suiteCase{
				set: set.attr("name"), file: file, base: filepath.Dir(path), setNode: set, node: node,
				environments: suiteEnvironments(set, filepath.Dir(path), suiteEnvironments(catalog, directory, nil)),
			}
		}
	}
	t.Fatal("pinned case missing", kind, file, name)
	return suiteCase{}
}

func evaluateResidualCase(t *testing.T, options suiteOptions, item suiteCase) residualCaseResult {
	t.Helper()
	ctx := t.Context()
	if options.timeout > 0 {
		bounded, cancel := context.WithTimeout(ctx, options.timeout)
		defer cancel()
		ctx = bounded
	}
	if status, reason := suiteApplicability(options, item); status != "" {
		t.Fatal("proof must execute an applicable original case", status, reason)
	}
	environment, err := prepareSuiteEnvironment(ctx, options, item)
	if err != nil {
		return residualCaseResult{PrepareError: err}
	}
	evaluation := evaluateSuiteCase(ctx, options, item, environment)
	return residualCaseResult{
		Evaluation: evaluation, Environment: environment,
		AssertionError: checkSuiteAssertion(ctx, evaluation, item.node.child(suiteResultVariable)),
	}
}

func cloneResidualNode(node *suiteNode) *suiteNode {
	if node == nil {
		return nil
	}
	cloned := *node
	cloned.Attributes = slices.Clone(node.Attributes)
	cloned.namespaces = make(map[string]string, len(node.namespaces))
	maps.Copy(cloned.namespaces, node.namespaces)
	cloned.Children = make([]*suiteNode, len(node.Children))
	for index, child := range node.Children {
		cloned.Children[index] = cloneResidualNode(child)
	}
	return &cloned
}

func residualErrorCode(err error) string {
	if detail, ok := errors.AsType[*transform.Error](err); ok {
		return detail.Code
	}
	return ""
}

func residualSequenceText(t *testing.T, value transform.Sequence) string {
	t.Helper()
	parts := make([]string, 0, value.Len())
	for index := range value.Len() {
		item, ok := value.At(index)
		if !ok {
			t.Fatal("missing result", index)
		}
		part, err := item.Text()
		if err != nil {
			t.Fatal(err)
		}
		parts = append(parts, part)
	}
	return strings.Join(parts, " ")
}

func residualXPath(t *testing.T, environment *preparedSuiteEnvironment, version, expression string) (transform.Sequence, error) {
	t.Helper()
	selected := transform.XPath31
	switch version {
	case suiteVersion20:
		selected = transform.XPath20
	case suiteVersion30:
		selected = transform.XPath30
	}
	query, err := environment.engine.CompileXPath(t.Context(), expression, transform.XPathOptions{Version: selected, Namespaces: environment.namespaces, BaseURI: environment.baseURI, DefaultCollation: environment.collation, DecimalFormats: environment.decimalFormats})
	if err != nil {
		return transform.Sequence{}, err
	}
	return query.Evaluate(t.Context(), environment.document, transform.XPathContext{Variables: environment.variables, ContextItem: environment.contextItem, Context: suiteDynamicContext(environment.currentTime)})
}

type qtResidualProofControl struct {
	Name        string `json:"name"`
	Expression  string `json:"expression,omitempty"`
	Native      string `json:"native"`
	Independent string `json:"independent,omitempty"`
	Obligation  string `json:"obligation"`
}

type qtResidualProof struct {
	Name              string
	File              string
	Version           string
	Category          string
	XSDVersion        string                   `json:"xsd_version"`
	CaseTimeout       string                   `json:"case_timeout"`
	LimitsProfile     string                   `json:"limits_profile"`
	SourceSHA256      string                   `json:"source_sha256"`
	OriginalLimit     bool                     `json:"original_typed_limit"`
	OriginalDeadline  bool                     `json:"original_typed_deadline"`
	OriginalError     string                   `json:"original_error,omitempty"`
	OriginalAssertion string                   `json:"original_assertion_error,omitempty"`
	Controls          []qtResidualProofControl `json:"controls"`
}

// This table identifies original publisher cases, not replacement expectations.
// The test keeps their non-passing assertions visible and separately checks why.
// The original publisher serialization regex remains untouched. These controls
// distinguish required character/namespace semantics from a particular spelling.
func runXSLTResidualSerialization(t *testing.T, directory string) {
	for _, test := range []struct {
		name string
		file string
		kind string
	}{
		{"attribute-0301", "tests/insn/attribute/_attribute-test-set.xml", "uri"},
		{"output-0102c", "tests/decl/output/_output-test-set.xml", "xml-attribute"},
		{"output-0103c", "tests/decl/output/_output-test-set.xml", "xml-attribute"},
		{"output-0602a", "tests/decl/output/_output-test-set.xml", "namespace"},
		{"output-0603a", "tests/decl/output/_output-test-set.xml", "namespace"},
		{"output-0724", "tests/decl/output/_output-test-set.xml", "uri"},
	} {
		t.Run(test.name, func(t *testing.T) {
			item := loadPinnedResidualCase(t, directory, suiteXSLT, test.file, test.name)
			options := suiteOptions{kind: suiteXSLT, directory: directory, version: suiteVersion30, xsdVersion: suiteVersion10, timeout: time.Second, limitsProfile: "default"}
			original := evaluateResidualCase(t, options, item)
			if original.executionError() != nil || original.AssertionError == nil {
				t.Fatal("unchanged original residual", original.executionError(), original.AssertionError)
			}
			actual, err := original.Evaluation.serialized(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			proof := qtResidualProof{Name: test.name, File: test.file, Version: suiteVersion30, Category: "permitted-outcome"}
			switch test.kind {
			case "xml-attribute":
				want := `% %C2%96 %C2%96 a "  %C2%A1 < > & end`
				if test.name == "output-0103c" {
					want = "% %C2%96 \u0096 a \"  ¡ < > & end"
				}
				file := filepath.Join(t.TempDir(), "actual.xml")
				if err := os.WriteFile(file, actual, 0o600); err != nil {
					t.Fatal(err)
				}
				oracle := residualSaxonQuery(t, `string(doc('`+suiteFileURI(file)+`')/*/@href)`, "")
				if oracle != want {
					t.Fatal("independent XML parsing changed attribute meaning", oracle, want)
				}
				residualControl(t, &proof, original.Environment, suiteVersion31, "legal XML attribute quote spellings", `parse-xml('<a href="&quot;"/>')/a/@href eq parse-xml('<a href="&#34;"/>')/a/@href`, "true", "XML10 2.3/4.6 permit named and numeric quote references")
				residualControl(t, &proof, original.Environment, suiteVersion31, "legal literal and escaped greater-than", `parse-xml('<a href=">"/>')/a/@href eq parse-xml('<a href="&gt;"/>')/a/@href`, "true", "XML10 attribute value grammar permits literal greater-than; SER character expansion must preserve value")
				t.Log("P3_ORACLE published-vector")
			case "uri":
				if test.name == "attribute-0301" {
					residualLegacyAttribute301(t, directory, item, options)
				}
				originalValue := "père"
				if test.name == "output-0724" {
					originalValue = "✈"
				}
				want := residualSaxonQuery(t, `iri-to-uri('`+originalValue+`')`, "")
				values := residualHTMLInputValues(t, actual)
				if len(values) == 0 {
					t.Fatal("no serialized input/@value")
				}
				for _, value := range values {
					if value != want {
						t.Fatal("published URI table escaping", value, want)
					}
				}
				controlled := residualSerializationVariant(t, options, item, original.Environment, func(raw []byte) []byte {
					if !bytes.Contains(raw, []byte(`method="html"`)) {
						t.Fatal("publisher output method changed")
					}
					return bytes.ReplaceAll(raw, []byte(`method="html"`), []byte(`method="html" escape-uri-attributes="no"`))
				})
				decoded := residualHTMLInputValues(t, controlled)
				if len(decoded) != len(values) {
					t.Fatal("controlled input count", decoded, values)
				}
				for _, value := range decoded {
					if value != originalValue {
						t.Fatal("explicit escaping=no must retain original value", value, originalValue)
					}
				}
				t.Log("P3_ORACLE published-vector")
			case "namespace":
				originalBinding, originalAttribute := residualHTMLNamespaceState(t, actual)
				if !originalBinding || test.name == "output-0603a" && !originalAttribute {
					t.Fatal("ancestor namespace is not bound", originalBinding, originalAttribute, string(actual))
				}
				controlled := residualXHTMLNamespaceControl(t, options, item, original.Environment)
				bodyBinding, attribute := residualHTMLNamespaceState(t, controlled)
				if bodyBinding || test.name == "output-0603a" && !attribute {
					t.Fatal("XHTML prefix-normalization intervention", bodyBinding, attribute, string(controlled))
				}
				residualControl(t, &proof, original.Environment, suiteVersion31, "ancestor/local declarations bind the same expanded attribute", `deep-equal(parse-xml('<body xmlns:svg="http://www.w3.org/2000/svg"><mi svg:att="34"/></body>')/body/mi/@*,parse-xml('<body><mi xmlns:svg="http://www.w3.org/2000/svg" svg:att="34"/></body>')/body/mi/@*)`, "true", "Namespaces in XML 1.0 6.2 namespace scope; SER31 HTML 7.1 differs from XHTML global prefix normalization")
				t.Log("P3_ORACLE published-vector")
			}
		})
	}
}

func residualXHTMLNamespaceControl(t *testing.T, options suiteOptions, item suiteCase, environment *preparedSuiteEnvironment) []byte {
	t.Helper()
	invalid := evaluateXSLTResidualSourceVariant(t, options, item, `method="html"`, `method="xhtml"`)
	if got := residualErrorCode(invalid.executionError()); got != "SESU0013" {
		t.Fatal("changing only the method retains unsupported XML version 5.0", got, invalid.executionError())
	}
	// XHTML has separate HTML and XML version parameters. The pinned HTML5
	// declaration uses version 5.0; change that output attribute, never the
	// stylesheet's independent version 3.0 attribute, when selecting XHTML5.
	const before = `method="html" version="5.0" html-version="5.0"`
	const after = `method="xhtml" version="1.0" html-version="5.0"`
	var source []byte
	controlled := residualSerializationVariant(t, options, item, environment, func(raw []byte) []byte {
		if bytes.Count(raw, []byte(before)) != 1 {
			t.Fatal("the pinned output's HTML5 version tuple changed")
		}
		source = bytes.Replace(raw, []byte(before), []byte(after), 1)
		return source
	})
	main := filepath.Join(t.TempDir(), "xhtml5.xsl")
	if err := os.WriteFile(main, source, 0o600); err != nil {
		t.Fatal(err)
	}
	_, input := xsltResidualInputBytes(t, options, item)
	oracle, err := xsltResidualOracleTransform(t, suiteVersion30, main, input, "", "")
	if err != nil {
		t.Fatal(err)
	}
	nativeBinding, nativeAttribute := residualHTMLNamespaceState(t, controlled)
	oracleBinding, oracleAttribute := residualHTMLNamespaceState(t, oracle)
	if nativeBinding != oracleBinding || nativeAttribute != oracleAttribute {
		t.Fatal("independent XHTML5 namespace intervention", nativeBinding, nativeAttribute, oracleBinding, oracleAttribute, string(oracle))
	}
	t.Log("P3_ORACLE saxon-12.10")
	return controlled
}

func residualSerializationVariant(t *testing.T, options suiteOptions, item suiteCase, environment *preparedSuiteEnvironment, edit func([]byte) []byte) []byte {
	t.Helper()
	raw, compileOptions, err := suiteStylesheetSource(options, environment)
	if err != nil {
		t.Fatal(err)
	}
	changed := edit(slices.Clone(raw))
	if bytes.Equal(raw, changed) {
		t.Fatal("causal intervention did not change the input")
	}
	compiled, err := environment.engine.CompileXSLT(t.Context(), changed, compileOptions)
	if err != nil {
		t.Fatal(err)
	}
	result, err := evaluateCompiledXSLTSuite(t.Context(), item, environment, compiled)
	if err != nil {
		t.Fatal(err)
	}
	output, err := result.Serialize(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	return output.Primary
}

func residualLegacyAttribute301(t *testing.T, directory string, item suiteCase, options suiteOptions) {
	t.Helper()
	options.version = suiteVersion20
	original := evaluateResidualCase(t, options, item)
	if original.executionError() != nil || original.AssertionError != nil {
		t.Fatal("selected SER20 must satisfy every unchanged publisher assertion", original.executionError(), original.AssertionError)
	}
	classpath := residualRequired(t, "SAXON20_CLASSPATH")
	binary, err := exec.LookPath("java")
	if err != nil {
		t.Fatal(err)
	}
	identity, err := exec.CommandContext(t.Context(), binary, "-cp", classpath, "net.sf.saxon.Version").CombinedOutput()
	if err != nil || !strings.Contains(string(identity), "SAXON 9.4.0.9") {
		t.Fatal("independent old processor identity", string(identity), err)
	}
	style := filepath.Join(directory, "tests", "insn", "attribute", "attribute-0301.xsl")
	input := filepath.Join(directory, "tests", "insn", "attribute", "attribute-03.xml")
	output, err := exec.CommandContext(t.Context(), binary, "-cp", classpath, "net.sf.saxon.Transform", "-xsl:"+style, "-s:"+input).Output()
	if err != nil {
		if failure, ok := errors.AsType[*exec.ExitError](err); ok {
			t.Fatalf("original Saxon9.4: %s: %v", failure.Stderr, err)
		}
		t.Fatal(err)
	}
	for _, assertion := range item.node.child(suiteResultVariable).child("all-of").Children {
		if assertion.XMLName.Local != "serialization-matches" {
			t.Fatal("original assertion type changed", assertion.XMLName)
		}
		value, err := original.Environment.query(t.Context(), `matches($s,$pattern,$flags)`, transform.Bindings{
			{Local: "s"}: transform.Values(transform.String(string(output))), {Local: "pattern"}: transform.Values(transform.String(assertion.Text)), {Local: "flags"}: transform.Values(transform.String(assertion.attr("flags"))),
		})
		if err != nil || residualSequenceText(t, value) != "true" {
			t.Fatal("independent unchanged original assertion", assertion.Text, string(output), err)
		}
	}
	t.Log("P3_ORACLE saxon-9.4")
}

func residualHTMLInputValues(t *testing.T, data []byte) []string {
	t.Helper()
	// A trailing lexical boundary lets encoding/xml close a final HTML void
	// element; it is not part of the original bytes or an asserted result.
	decoder := xml.NewDecoder(io.MultiReader(bytes.NewReader(data), strings.NewReader("<__end/>")))
	decoder.Strict = false
	decoder.AutoClose = xml.HTMLAutoClose
	decoder.Entity = xml.HTMLEntity
	var values []string
	for {
		token, err := decoder.Token()
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}

			t.Fatal(err)
		}
		if start, ok := token.(xml.StartElement); ok && start.Name.Local == "input" {
			for _, attribute := range start.Attr {
				if attribute.Name.Local == "value" {
					values = append(values, attribute.Value)
				}
			}
		}
	}
	return values
}

func residualHTMLNamespaceState(t *testing.T, data []byte) (bool, bool) {
	t.Helper()
	decoder := xml.NewDecoder(bytes.NewReader(data))
	decoder.Strict = false
	decoder.AutoClose = xml.HTMLAutoClose
	decoder.Entity = xml.HTMLEntity
	bodyBinding, attribute := false, false
	for {
		token, err := decoder.Token()
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}

			t.Fatal(err)
		}
		if start, ok := token.(xml.StartElement); ok {
			for _, a := range start.Attr {
				if start.Name.Local == "body" && a.Name.Space == "xmlns" && a.Name.Local == "svg" && a.Value == "http://www.w3.org/2000/svg" {
					bodyBinding = true
				}
				if start.Name.Local == "mi" && a.Name.Space == "http://www.w3.org/2000/svg" && a.Name.Local == "att" && a.Value == "34" {
					attribute = true
				}
			}
		}
	}
	return bodyBinding, attribute
}

func qtResidualCases() []struct {
	name     string
	file     string
	version  string
	category string
} {
	return []struct {
		name     string
		file     string
		version  string
		category string
	}{
		{"ForExpr013", "prod/ForClause.xml", "2.0", "limit"},
		{"cbcl-codepoints-to-string-005", "fn/codepoints-to-string.xml", "2.0", "limit"},
		{"cbcl-count-001", "fn/count.xml", "2.0", "limit"},
		{"cbcl-matches-004", "fn/matches.xml", "2.0", "limit"},
		{"cbcl-subsequence-010", "fn/subsequence.xml", "2.0", "limit"},
		{"cbcl-subsequence-011", "fn/subsequence.xml", "2.0", "limit"},
		{"cbcl-subsequence-012", "fn/subsequence.xml", "2.0", "limit"},
		{"cbcl-subsequence-013", "fn/subsequence.xml", "2.0", "limit"},
		{"cbcl-subsequence-014", "fn/subsequence.xml", "2.0", "limit"},
		{"environment-variable-012", "fn/environment-variable.xml", "3.1", "limit"},
		{"fn-transform-27", "fn/transform.xml", "3.1", "limit"},
		{"fn-transform-43", "fn/transform.xml", "3.1", "transform43"},
		{"fold-left-020", "fn/fold-left.xml", "3.1", "limit"},
		{"fold-right-013", "fn/fold-right.xml", "3.1", "limit"},
		{"format-dateTime-002g", "fn/format-dateTime.xml", "3.0", "format"},
		{"format-dateTime-002h", "fn/format-dateTime.xml", "3.0", "format"},
		{"format-dateTime-002i", "fn/format-dateTime.xml", "3.0", "format"},
		{"format-dateTime-003m", "fn/format-dateTime.xml", "3.0", "format"},
		{"format-dateTime-003n", "fn/format-dateTime.xml", "3.0", "format"},
		{"format-dateTime-003p", "fn/format-dateTime.xml", "3.0", "format"},
		{"format-dateTime-013s", "fn/format-dateTime.xml", "3.0", "format"},
		{"format-dateTime-013u", "fn/format-dateTime.xml", "3.0", "format"},
		{"map-for-each-014", "map/for-each.xml", "3.1", "limit"},
		{"map-keys-014", "map/keys.xml", "3.1", "limit"},
		{"map-remove-012", "map/remove.xml", "3.1", "limit"},
		{"millisecs-018", "fn/format-time.xml", "3.0", "format"},
		{"millisecs-022", "fn/format-time.xml", "3.0", "format"},
		{"serialize-xml-007b", "fn/serialize.xml", "3.1", "serialize"},
		{"serialize-xml-007c", "fn/serialize.xml", "3.0", "serialize"},
		{"serialize-xml-015b", "fn/serialize.xml", "3.1", "serialize"},
		{"serialize-xml-016b", "fn/serialize.xml", "3.1", "serialize"},
		{"serialize-xml-020b", "fn/serialize.xml", "3.1", "serialize"},
		{"serialize-xml-025b", "fn/serialize.xml", "3.0", "serialize"},
		{"serialize-xml-026b", "fn/serialize.xml", "3.0", "serialize"},
	}
}

func TestQT3ResidualCauses(t *testing.T) {
	directory, err := filepath.EvalSymlinks(residualRequired(t, "XMLSEC_QT3_DIR"))
	if err != nil {
		t.Fatal(err)
	}
	residualRequired(t, "SAXON_CLASSPATH")
	residualRequired(t, "SAXON20_CLASSPATH")
	residualRequired(t, "SERIALIZATION_SCHEMA_DIR")
	proofs := make([]qtResidualProof, 0, len(qtResidualCases()))
	t.Cleanup(func() {
		if file := os.Getenv("XMLSEC_QT3_PROOF_REPORT"); file != "" {
			data, err := json.MarshalIndent(proofs, "", "  ")
			if err != nil {
				t.Error(err)
				return
			}
			if err := os.WriteFile(file, append(data, '\n'), 0o600); err != nil {
				t.Error(err)
			}
		}
	})
	for _, test := range qtResidualCases() {
		t.Run(test.name, func(t *testing.T) {
			item := loadPinnedResidualCase(t, directory, suiteQT3, test.file, test.name)
			options := suiteOptions{kind: suiteQT3, directory: directory, version: test.version, xsdVersion: suiteVersion10, timeout: time.Second, limitsProfile: "default"}
			original := evaluateResidualCase(t, options, item)
			data, err := os.ReadFile(filepath.Join(directory, test.file))
			if err != nil {
				t.Fatal(err)
			}
			digest := sha256.Sum256(data)
			// The configured case budget covers evaluation and its original
			// publisher assertion; retain the typed cause from either phase.
			resourceCause := errors.Join(original.executionError(), original.AssertionError)
			proof := qtResidualProof{Name: test.name, File: test.file, Version: test.version, Category: test.category, XSDVersion: suiteXSDVersionName(options), CaseTimeout: options.timeout.String(), LimitsProfile: options.limitsProfile, SourceSHA256: hex.EncodeToString(digest[:]), OriginalLimit: errors.Is(resourceCause, transform.ErrLimit), OriginalError: fmt.Sprint(original.executionError()), OriginalAssertion: fmt.Sprint(original.AssertionError)}
			proof.OriginalDeadline = errors.Is(resourceCause, context.DeadlineExceeded)
			defer func() { proofs = append(proofs, proof) }()
			switch test.category {
			case "limit":
				if !proof.OriginalLimit && !proof.OriginalDeadline {
					t.Fatal("original cause is neither a typed implementation limit nor the configured deadline", original.executionError())
				}
				qtResidualLimitControls(t, options, item, &proof)
			case "format":
				qtResidualFormatControls(t, options, item, original, &proof)
			case "serialize":
				qtResidualSerializationControls(t, options, item, original, &proof)
			case "transform43":
				qtResidualTransform43Controls(t, original, &proof)
			}
		})
	}
}

func residualSaxonQuery(t *testing.T, expression, source string) string {
	t.Helper()
	classpath := residualRequired(t, "SAXON_CLASSPATH")
	binary, err := exec.LookPath("java")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	queryFile := filepath.Join(t.TempDir(), "proof.xq")
	// Inputs are XPath expressions. XQuery resolves entity references inside
	// string literals; quote ampersands once so Saxon sees the same strings.
	if err := os.WriteFile(queryFile, []byte(strings.ReplaceAll(expression, "&", "&amp;")), 0o600); err != nil {
		t.Fatal(err)
	}
	arguments := []string{"-cp", classpath, "net.sf.saxon.Query", "-q:" + queryFile, "!method=text", "!omit-xml-declaration=yes"}
	if source != "" {
		arguments = append(arguments, "-s:"+source)
	}
	command := exec.CommandContext(ctx, binary, arguments...)
	var diagnostic bytes.Buffer
	command.Stderr = &diagnostic
	output, err := command.Output()
	if err != nil {
		t.Fatalf("independent query: %s: %v", diagnostic.String(), err)
	}
	return string(output)
}

func residualSaxon20Expression(t *testing.T, expression string) string {
	t.Helper()
	classpath := residualRequired(t, "SAXON20_CLASSPATH")
	binary, err := exec.LookPath("java")
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	file := filepath.Join(directory, "proof.xsl")
	var escaped strings.Builder
	if err := xml.EscapeText(&escaped, []byte(expression)); err != nil {
		t.Fatal(err)
	}
	source := `<xsl:stylesheet version="2.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:xs="http://www.w3.org/2001/XMLSchema"><xsl:output method="text"/><xsl:template name="start"><xsl:value-of select="` + escaped.String() + `"/></xsl:template></xsl:stylesheet>`
	if err := os.WriteFile(file, []byte(source), 0o600); err != nil {
		t.Fatal(err)
	}
	command := exec.CommandContext(t.Context(), binary, "-cp", classpath, "net.sf.saxon.Transform", "-xsl:"+file, "-it:start")
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("independent old-edition transform: %s: %v", output, err)
	}
	return string(output)
}

func residualControl(t *testing.T, proof *qtResidualProof, environment *preparedSuiteEnvironment, version, name, expression, want, obligation string) {
	t.Helper()
	value, err := residualXPath(t, environment, version, expression)
	actual := residualSequenceText(t, value)
	if err != nil {
		actual = residualErrorCode(err)
	}
	if actual != want {
		t.Fatal(name, "native", actual, err, "want", want)
	}
	oracleExpression := `try { (` + expression + `) } catch * { local-name-from-QName($err:code) }`
	independent := residualSaxonQuery(t, oracleExpression, "")
	if independent != want {
		t.Fatal(name, "independent", independent, "want", want)
	}
	proof.Controls = append(proof.Controls, qtResidualProofControl{Name: name, Expression: expression, Native: actual, Independent: independent, Obligation: obligation})
}

func qtResidualLimitControls(t *testing.T, options suiteOptions, item suiteCase, proof *qtResidualProof) {
	t.Helper()
	options.limitsProfile = suiteLanguage
	options.timeout = 30 * time.Second
	environment, err := prepareSuiteEnvironment(t.Context(), options, item)
	if err != nil {
		t.Fatal(err)
	}
	if proof.Name == "ForExpr013" {
		control := evaluateResidualCase(t, options, item)
		if control.executionError() != nil || control.AssertionError != nil {
			t.Fatal("raised bounded profile did not reproduce publisher value", control.executionError(), control.AssertionError)
		}
		evaluation := control.Evaluation
		expression := "count((" + item.node.child("test").Text + "))"
		want := strconv.Itoa(evaluation.sequence.Len())
		oracle := residualSaxonQuery(t, expression, filepath.Join(options.directory, "prod", "ForClause", "fsx.xml"))
		if oracle != want {
			t.Fatal(oracle, want)
		}
		proof.Controls = append(proof.Controls, qtResidualProofControl{Name: "same source and publisher assertion; explicit language profile and 30s case deadline", Expression: expression, Native: want, Independent: oracle, Obligation: "XPath20 2.3.1 implementation limits; exact unmodified publisher input/output"})
		return
	}
	if proof.Name == "fn-transform-27" {
		qtResidualTransform27Controls(t, options, item, environment, proof)
		return
	}
	expression, want := "", ""
	switch proof.Name {
	case "cbcl-codepoints-to-string-005":
		expression, want = `string-length(codepoints-to-string(65536 to 65539))`, "4"
	case "cbcl-count-001":
		expression, want = `count(1 to 1000)`, "1000"
	case "cbcl-matches-004":
		expression, want = `matches('aaa','a{4}')`, "false"
	case "cbcl-subsequence-010":
		expression, want = `count(subsequence(1 to 1000,-5,4))`, "0"
	case "cbcl-subsequence-011":
		expression, want = `count(subsequence(1 to 1000,-5))`, "1000"
	case "cbcl-subsequence-012":
		expression, want = `count(subsequence(1 to 1000,748))`, "253"
	case "cbcl-subsequence-013":
		expression, want = `count(subsequence(1 to 1000,747))`, "254"
	case "cbcl-subsequence-014":
		expression, want = `subsequence(2147483647 to 2147483651,1,5)`, "2147483647 2147483648 2147483649 2147483650 2147483651"
	case "environment-variable-012":
		expression, want = strings.ReplaceAll(item.node.child("test").Text, "1024 * 1024", "1000"), "true"
	case "fold-left-020", "fold-right-013":
		expression, want = strings.ReplaceAll(item.node.child("test").Text, "1000000", "1000"), "1000"
	case "map-for-each-014", "map-keys-014":
		expression, want = `let $result := (`+strings.ReplaceAll(item.node.child("test").Text, "500000", "1000")+`) return count($result)=1000 and $result=1 and $result=1000`, "true"
	case "map-remove-012":
		expression, want = `let $result := (`+strings.NewReplacer("500000", "1000", "123456", "456").Replace(item.node.child("test").Text)+`) return map:size($result)=999 and map:contains($result,1) and map:contains($result,1000) and not(map:contains($result,456))`, "true"
	default:
		t.Fatal("missing case-specific limit control", proof.Name)
	}
	residualControl(t, proof, environment, options.version, "bounded same-operator control", expression, want, "XPath implementation-limit permission; the operator succeeds with independently verified bounded operands")
	if proof.Name == "cbcl-codepoints-to-string-005" {
		residualControl(t, proof, environment, options.version, "semantic invalid scalar remains FOCH0001", `codepoints-to-string(1114112)`, "FOCH0001", "FO 5.2.1 invalid Unicode codepoint error independent of range materialization")
	}
	if proof.Name == "cbcl-matches-004" {
		residualControl(t, proof, environment, options.version, "actual invalid regex remains FORX0002", `matches('aaa','a{')`, "FORX0002", "FO matches invalid grammar differs from valid enormous quantifier implementation cap")
	}
}

func qtResidualTransform27Controls(t *testing.T, options suiteOptions, item suiteCase, environment *preparedSuiteEnvironment, proof *qtResidualProof) {
	t.Helper()
	original := evaluateSuiteCase(t.Context(), options, item, environment)
	if original.err != nil || residualSequenceText(t, original.sequence) != "true" {
		t.Fatal("raised original case", original.err, residualSequenceText(t, original.sequence))
	}
	proof.Controls = append(proof.Controls, qtResidualProofControl{Name: "original expression with raised bounded profile and fixed host clock", Native: "true", Obligation: "FO31 16.3.2 cache option has no effect on transformation result; repeated results may be identical"})
	bounded := strings.NewReplacer("-100000", "-100", "+100000", "+100").Replace(item.node.child("test").Text)
	for _, cache := range []string{"false()", "true()"} {
		expression := strings.ReplaceAll(bounded, `"cache":false()`, `"cache":`+cache)
		value, err := residualXPath(t, environment, suiteVersion31, expression)
		if err != nil || residualSequenceText(t, value) != "true" {
			t.Fatal(cache, value, err)
		}
		proof.Controls = append(proof.Controls, qtResidualProofControl{Name: "fixed host clock, cache hint " + cache, Expression: expression, Native: "true", Obligation: "FO31 16.3.2 cache is an efficiency hint, not a promise of unequal current-dateTime values"})
	}
	residualControl(t, proof, environment, suiteVersion31, "current-dateTime is stable within one dynamic context", `current-dateTime() eq current-dateTime()`, "true", "FO31 15.3 same dynamic current-dateTime; host controls the supplied instant")
	// A fresh public invocation can receive another explicit host clock. This
	// isolates clock input from stylesheet caching without sleeping or wall time.
	clockExpression := `transform(map{'stylesheet-text':"<xsl:stylesheet version='3.0' xmlns:xsl='http://www.w3.org/1999/XSL/Transform'><xsl:variable name='t' static='yes' select='current-dateTime()'/><xsl:template name='start'><xsl:value-of select='$t'/></xsl:template></xsl:stylesheet>",'initial-template':xs:QName('start'),'cache':false()})?output/string()`
	for _, instant := range []string{"2026-01-01T00:00:00Z", "2026-01-02T00:00:00Z"} {
		environment.currentTime, _ = time.Parse(time.RFC3339, instant)
		value, err := residualXPath(t, environment, suiteVersion31, clockExpression)
		if err != nil || residualSequenceText(t, value) != instant {
			t.Fatal(value, err, instant)
		}
		proof.Controls = append(proof.Controls, qtResidualProofControl{Name: "explicit independent host clock " + instant, Expression: clockExpression, Native: instant, Obligation: "Configured per-invocation clock, not the cache hint, determines static current-dateTime here"})
	}
}

func residualInlineBindings(t *testing.T, expression string, environment *preparedSuiteEnvironment) string {
	t.Helper()
	for name, value := range environment.variables {
		if name.Space != "" {
			t.Fatal("proof needs an explicit namespace binding", name)
		}
		item, err := value.Single()
		if err != nil {
			t.Fatal(err)
		}
		text, err := item.Text()
		if err != nil {
			t.Fatal(err)
		}
		expression = strings.ReplaceAll(expression, "$"+name.Local, "xs:"+item.Type().Local+"('"+strings.ReplaceAll(text, "'", "''")+"')")
	}
	return expression
}

func qtResidualFormatControls(t *testing.T, options suiteOptions, item suiteCase, original residualCaseResult, proof *qtResidualProof) {
	t.Helper()
	if original.executionError() != nil || original.AssertionError == nil {
		t.Fatal("expected original publisher value mismatch", original.executionError(), original.AssertionError)
	}
	old := map[string]string{"format-dateTime-002g": "9:15:06.5", "format-dateTime-002h": "9:15:06.5", "format-dateTime-002i": "9:15:06.46", "format-dateTime-003m": "9:15:06.5", "format-dateTime-003n": "9:15:06.5", "format-dateTime-003p": "9:15:06.46", "format-dateTime-013s": "46", "format-dateTime-013u": "46", "millisecs-018": "12", "millisecs-022": "00"}[proof.Name]
	if residualSequenceText(t, original.Evaluation.sequence) != old {
		t.Fatal("old-edition algorithm changed", original.Evaluation.sequence, old)
	}
	expression := residualInlineBindings(t, item.node.child("test").Text, original.Environment)
	oracle := residualSaxon20Expression(t, expression)
	if oracle != old {
		t.Fatal("published old-formatting algorithm disagreement", oracle, old)
	}
	proof.Controls = append(proof.Controls, qtResidualProofControl{Name: "same literal date/picture under pre-3.1 formatting", Expression: expression, Native: old, Independent: oracle, Obligation: "FO30 9.8.4.1 old rounding/width precedence; FO31 9.8.4.5 truncation is a later algorithm"})
	options.version = suiteVersion31
	modern := evaluateResidualCase(t, options, item)
	if modern.executionError() != nil || modern.AssertionError != nil {
		t.Fatal("same pinned fixture must match its later-edition expectation", modern.executionError(), modern.AssertionError)
	}
	want := residualSequenceText(t, modern.Evaluation.sequence)
	oracle = residualSaxonQuery(t, expression, "")
	if oracle != want {
		t.Fatal("modern oracle", oracle, want)
	}
	proof.Controls = append(proof.Controls, qtResidualProofControl{Name: "same publisher input/assertion under processor 3.1", Expression: expression, Native: want, Independent: oracle, Obligation: "FO31 9.8.4.5 explicit fractional-second/width algorithm; publisher modifications in 2016 reference bugs 29749/29788"})
}

func qtResidualTransform43Controls(t *testing.T, original residualCaseResult, proof *qtResidualProof) {
	t.Helper()
	if original.executionError() != nil || !strings.Contains(fmt.Sprint(original.AssertionError), "FODC0006") {
		t.Fatal("expected assertion's document parse error", original.executionError(), original.AssertionError)
	}
	assertions := original.Evaluation.item.node.child(suiteResultVariable).child("all-of").Children
	if len(assertions) != 4 {
		t.Fatal("publisher assertion inventory changed")
	}
	for index := range 3 {
		if err := checkSuiteAssertion(t.Context(), original.Evaluation, assertions[index]); err != nil {
			t.Fatal(index, err)
		}
	}
	value, err := original.Evaluation.sequence.Single()
	if err != nil {
		t.Fatal(err)
	}
	keys, err := value.Keys()
	if err != nil || len(keys) != 4 {
		t.Fatal(keys, err)
	}
	principal := ""
	for _, key := range keys {
		name, err := key.Text()
		if err != nil {
			t.Fatal(err)
		}
		if strings.HasSuffix(name, "/output.html") {
			part, found := value.Lookup(key)
			if !found {
				t.Fatal(name)
			}
			principal = residualSequenceText(t, part)
		}
	}
	if principal == "" {
		t.Fatal("missing principal serialization")
	}
	environment := original.Environment
	literal := "'" + strings.ReplaceAll(principal, "'", "''") + "'"
	residualControl(t, proof, environment, suiteVersion31, "principal is a valid empty external parsed entity", `count(parse-xml-fragment(`+literal+`)/node())`, "0", "SER31 5 XML external parsed entity; empty principal need not be a well-formed XML document")
	residualControl(t, proof, environment, suiteVersion31, "the same principal is not an XML document", `parse-xml(`+literal+`)`, "FODC0006", "FO31 14.7.1 parse-xml requires a document element")
	residualControl(t, proof, environment, suiteVersion31, "quantifier error binding visited first", `boolean(some $s in ('','<h1>Header for section 2</h1>') satisfies parse-xml($s)//h1='Header for section 2')`, "FODC0006", "XPath31 3.13 permits a satisfies error before the true witness; boolean does not catch errors")
	residualControl(t, proof, environment, suiteVersion31, "quantifier witness visited first", `some $s in ('<h1>Header for section 2</h1>','') satisfies parse-xml($s)//h1='Header for section 2'`, "true", "XPath31 3.13 true witness is an allowed outcome; map keys have implementation-dependent order")
	filtered, err := environment.query(t.Context(), `some $key in map:keys($result)[contains(.,'section')] satisfies parse-xml($result?($key))//h1='Header for section 2'`, transform.Bindings{{Local: "result"}: original.Evaluation.sequence})
	if err != nil || residualSequenceText(t, filtered) != "true" {
		t.Fatal("secondary map entry was lost", filtered, err)
	}
	proof.Controls = append(proof.Controls, qtResidualProofControl{Name: "unchanged result map contains the required secondary document", Native: "true; first three exact catalog assertions also pass", Obligation: "FO31 16.3.2 serialized result map preserves secondary results; no reordering or publisher assertion rewrite"})
}

func qtResidualSerializationControls(t *testing.T, options suiteOptions, item suiteCase, original residualCaseResult, proof *qtResidualProof) {
	t.Helper()
	if original.AssertionError == nil {
		t.Fatal("the original catalog assertion unexpectedly passed")
	}
	for _, version := range []string{suiteVersion30, suiteVersion31} {
		options.version = version
		value := evaluateResidualCase(t, options, item)
		want := ""
		if version == suiteVersion30 {
			want = "SEPM0017"
		} else if proof.Name == "serialize-xml-025b" {
			want = "SEPM0019"
		}
		code := residualErrorCode(value.executionError())
		if code != want || want == "" && value.executionError() != nil {
			t.Fatal("edition-specific extraction", version, value.executionError(), want)
		}
		actual := code
		if want == "" {
			actual = residualSequenceText(t, value.Evaluation.sequence)
			if !strings.Contains(actual, "atomic") {
				t.Fatal("source document was not serialized", actual)
			}
		}
		proof.Controls = append(proof.Controls, qtResidualProofControl{Name: "same source and parameter document under " + version, Native: actual, Obligation: "SER30 3.1 assesses the whole parameter document; SER31 3.1 first selects known standard parameter children; duplicate QNames have their own SEPM0019 rule"})
	}
	parameterFile := ""
	for _, source := range item.node.child("environment").children("source") {
		if source.attr("role") == "$params" {
			_, parameterFile, _ = readSuiteReferencedFile(options.directory, item.base, source)
		}
	}
	if parameterFile == "" {
		t.Fatal("publisher parameter resource missing")
	}
	for _, edition := range []struct {
		version  string
		checksum string
	}{
		{"30", "1cbcc49ac5ed8942ba58276699254469ca2144e229f68faeeb48f784c1037953"},
		{"31", "256736a2f4e7923e888047dee757c17bc3ee707e285f00639fd8fb1d962d11b0"},
	} {
		schema := filepath.Join(residualRequired(t, "SERIALIZATION_SCHEMA_DIR"), "ser"+edition.version+".xsd")
		data, err := os.ReadFile(schema)
		if err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256(data)
		if hex.EncodeToString(digest[:]) != edition.checksum {
			t.Fatal("published schema pin changed", schema)
		}
		parts := []string{}
		if edition.version == "30" {
			raw, err := os.ReadFile(parameterFile)
			if err != nil {
				t.Fatal(err)
			}
			parts = append(parts, string(raw))
		} else {
			declared, _, err := decodeSuiteNode(data, schema)
			if err != nil {
				t.Fatal(err)
			}
			names := []string{}
			for _, element := range declared.children("element") {
				if name := element.attr("name"); name != "" && name != "serialization-parameters" {
					names = append(names, "'"+name+"'")
				}
			}
			if len(names) < 20 {
				t.Fatal("published serialization declaration inventory", len(names))
			}
			// Selection names come from the independent published XSD, rather
			// than the engine's parameter registry. Saxon performs the projection.
			expression := `serialize(array{for $p in doc('` + suiteFileURI(parameterFile) + `')/*/*[namespace-uri()='http://www.w3.org/2010/xslt-xquery-serialization'][local-name()=(` + strings.Join(names, ",") + `)] return serialize($p,map{'method':'xml','omit-xml-declaration':true()})},map{'method':'json'})`
			selected := residualSaxonQuery(t, expression, "")
			if err := json.Unmarshal([]byte(selected), &parts); err != nil {
				t.Fatal("independent projection result", selected, err)
			}
		}
		valid := true
		for _, part := range parts {
			binary, err := exec.LookPath("xmllint")
			if err != nil {
				t.Fatal(err)
			}
			command := exec.CommandContext(t.Context(), binary, "--nonet", "--noout", "--schema", schema, "-")
			command.Stdin = strings.NewReader(part)
			output, err := command.CombinedOutput()
			if err != nil {
				var exit *exec.ExitError
				if !errors.As(err, &exit) || exit.ExitCode() != 3 {
					t.Fatalf("published XSD validator: %s: %v; selected part %q", output, err, part)
				}
				valid = false
			}
		}
		want := edition.version == "31"
		if valid != want {
			t.Fatal("published schema assessment", edition.version, valid, want)
		}
		t.Log("P3_ORACLE published-schema")
		proof.Controls = append(proof.Controls, qtResidualProofControl{Name: "published SER" + edition.version + " schema after prescribed extraction", Native: strconv.FormatBool(valid), Independent: fmt.Sprintf("xmllint validity=%t; selected parts=%d; schema SHA256=%s", valid, len(parts), edition.checksum), Obligation: "Published SER30/31 3.1 parameter-document extraction and associated XSD; no extension schema declarations supplied"})
	}
	if proof.Name == "serialize-xml-025b" {
		data, err := os.ReadFile(parameterFile)
		if err != nil {
			t.Fatal(err)
		}
		expression := `let $p:=parse-xml('` + strings.ReplaceAll(string(data), "'", "''") + `')/*/* return count($p)=2 and node-name($p[1]) eq node-name($p[2])`
		residualControl(t, proof, original.Environment, suiteVersion31, "duplicate foreign QName exists independently of schema validity", expression, "true", "SER31 3.1 duplicate parameter QName SEPM0019; SER30 also has a simultaneous whole-document SEPM0017")
	}
}

// The original publisher case is always executed before changing its selected
// processor. The second run retains the same fixture, parameters and assertion.
type xsltResidualEditionCase struct {
	name    string
	file    string
	version string
	code    string
}

func xsltResidualEditionCases() []xsltResidualEditionCase {
	return []xsltResidualEditionCase{
		{"backwards-046", "tests/misc/backwards/_backwards-test-set.xml", "2.0", "XTSE0080"},
		{"character-map-026", "tests/decl/character-map/_character-map-test-set.xml", "2.0", "XTSE0020"},
		{"character-map-901", "tests/decl/character-map/_character-map-test-set.xml", "2.0", "XTSE0080"},
		{"choose-0202", "tests/insn/choose/_choose-test-set.xml", "2.0", "XTSE0080"},
		{"collations-0128", "tests/misc/collations/_collations-test-set.xml", "2.0", "XTSE0010"},
		{"collection-005", "tests/fn/collection/_collection-test-set.xml", "2.0", "XTSE0010"},
		{"doe-0409", "tests/attr/disable-output-escaping/_disable-output-escaping-test-set.xml", "2.0", "XTSE0080"},
		{"error-0600a", "tests/misc/error/_error-test-set.xml", "3.0", "XTTE0590"},
		{"error-0720a", "tests/misc/error/_error-test-set.xml", "3.0", "XTDE0640"},
		{"error-0720b", "tests/misc/error/_error-test-set.xml", "3.0", "XTDE0640"},
		{"error-0720c", "tests/misc/error/_error-test-set.xml", "3.0", "XTDE0640"},
		{"error-0720d", "tests/misc/error/_error-test-set.xml", "3.0", "XTDE0640"},
		{"error-1370a", "tests/misc/error/_error-test-set.xml", "3.0", "XPDY0002"},
		{"error-1380a", "tests/misc/error/_error-test-set.xml", "3.0", "XPDY0002"},
		{"for-each-group-084", "tests/insn/for-each-group/_for-each-group-test-set.xml", "2.0", "XPST0003"},
		{"for-each-group-091", "tests/insn/for-each-group/_for-each-group-test-set.xml", "2.0", "XTSE0080"},
		{"function-0302", "tests/decl/function/_function-test-set.xml", "2.0", "XPST0003"},
		{"function-1902", "tests/decl/function/_function-test-set.xml", "2.0", "XTSE0090"},
		{"id-041", "tests/fn/id/_id-test-set.xml", "2.0", "XPST0003"},
		{"match-248", "tests/attr/match/_match-test-set.xml", "2.0", "XPST0003"},
		{"match-254", "tests/attr/match/_match-test-set.xml", "2.0", "XPST0003"},
		{"namespace-0912", "tests/type/namespace/_namespace-test-set.xml", "2.0", "XTTE0570"},
		{"number-1004", "tests/insn/number/_number-test-set.xml", "2.0", "XTSE0010"},
		{"output-0725", "tests/decl/output/_output-test-set.xml", "2.0", "XTSE0090"},
		{"output-0726", "tests/decl/output/_output-test-set.xml", "2.0", "XTSE0090"},
		{"result-document-0286", "tests/insn/result-document/_result-document-test-set.xml", "2.0", "XTSE0020"},
		{"result-document-0287", "tests/insn/result-document/_result-document-test-set.xml", "2.0", "XTSE0020"},
		{"result-document-1006", "tests/insn/result-document/_result-document-test-set.xml", "2.0", "XPST0017"},
		{"sequence-0132", "tests/insn/sequence/_sequence-test-set.xml", "2.0", "XTSE0010"},
		{"system-property-022", "tests/fn/system-property/_system-property-test-set.xml", "2.0", "XTSE0010"},
		{"variable-4802", "tests/decl/variable/_variable-test-set.xml", "2.0", ""},
	}
}

func evaluateXSLTResidualVariant(t *testing.T, options suiteOptions, item suiteCase) residualCaseResult {
	t.Helper()
	// Some source fixtures declare a 2.0-only dependency while containing
	// 3.0 syntax. This explicit controlled run bypasses applicability alone;
	// it retains the pinned stylesheet and the complete publisher assertion.
	environment, err := prepareSuiteEnvironment(t.Context(), options, item)
	if err != nil {
		return residualCaseResult{PrepareError: err}
	}
	evaluation := evaluateSuiteCase(t.Context(), options, item, environment)
	return residualCaseResult{
		Evaluation: evaluation, Environment: environment,
		AssertionError: checkSuiteAssertion(t.Context(), evaluation, item.node.child(suiteResultVariable)),
	}
}

func TestXSLTResidualCauses(t *testing.T) {
	configured := os.Getenv("XMLSEC_XSLT_DIR")
	if configured == "" {
		configured = residualRequired(t, "XMLSEC_XSLT30_DIR")
	}
	directory, err := filepath.EvalSymlinks(configured)
	if err != nil {
		t.Fatal(err)
	}
	runXSLTResidualCompetingErrors(t, directory)
	runXSLTResidualLimits(t, directory)
	runXSLTResidualMetadataControls(t, directory)
	runXSLTResidualSingleCorrections(t, directory)
	runXSLTResidualRegexEditions(t, directory)
	runXSLTResidualExplicitResources(t, directory)
	runXSLTResidualSerialization(t, directory)
	runXSLTResidualWhitespace(t, directory)
	runXSLTResidualWarnings(t, directory)
	runXSLTResidualOptionalLibraries(t, directory)
	runXSLTResidualPackageCorrections(t, directory)
	runXSLTResidualTypeProfiles(t, directory)
	runXSLTResidualPriming(t, directory)
	runXSLTResidualEvaluateLibrary(t, directory)
	runXSLTResidualJSONTyping(t, directory)
	runXSLTResidualNumberProfiles(t, directory)
	runXSLTResidualNamedOutput(t, directory)
	for _, test := range xsltResidualEditionCases() {
		t.Run(test.name, func(t *testing.T) {
			item := loadPinnedResidualCase(t, directory, suiteXSLT, test.file, test.name)
			options := suiteOptions{
				kind: suiteXSLT, directory: directory, version: test.version,
				xsdVersion: suiteVersion10, timeout: time.Second, limitsProfile: "default",
			}
			t.Run("original", func(t *testing.T) {
				original := evaluateResidualCase(t, options, item)
				if original.AssertionError == nil {
					t.Fatal("the unchanged publisher assertion no longer reproduces the residual")
				}
				if got := residualErrorCode(original.executionError()); got != test.code {
					t.Fatal("typed original error", got, original.executionError(), test.code)
				}
				if test.name == "variable-4802" {
					value, err := original.Evaluation.assertionValue(t.Context(), `exists(//out[. = '{.}'])`, nil)
					if err != nil || residualSequenceText(t, value) != suiteTrue {
						t.Fatal("2.0 must preserve the unexpanded text-template literal", value, err)
					}
				}
			})
			t.Run("matching-edition", func(t *testing.T) {
				var controlled residualCaseResult
				switch test.name {
				case "function-0302":
					controlled = evaluateXSLTResidualSourceVariant(t, options, item, `$zls || 'value-of'`, `concat($zls, 'value-of')`)
				case "function-1902":
					controlled = evaluateXSLTResidualSourceVariant(t, options, item, ` expand-text="yes"`, "")
				default:
					options.version = suiteVersion30
					if test.version == suiteVersion30 {
						options.version = suiteVersion20
					}
					controlled = evaluateXSLTResidualVariant(t, options, item)
				}
				if controlled.PrepareError != nil || controlled.AssertionError != nil {
					if test.name == "function-1902" && controlled.Evaluation != nil {
						names, _ := controlled.Evaluation.assertionValue(t.Context(), `string-join(//incorrectly-available-function/concat(@name,'#',@arity),',')`, nil)
						t.Log("functions available after grammar-only correction", residualSequenceText(t, names))
					}
					t.Fatal("matching selected edition must satisfy the unchanged assertion", controlled.executionError(), controlled.AssertionError)
				}
			})
		})
	}
	t.Run("collection-006", func(t *testing.T) {
		item := loadPinnedResidualCase(t, directory, suiteXSLT, "tests/fn/collection/_collection-test-set.xml", "collection-006")
		options := suiteOptions{
			kind: suiteXSLT, directory: directory, version: suiteVersion30,
			xsdVersion: suiteVersion10, timeout: time.Second, limitsProfile: "default",
		}
		t.Run("original-30", func(t *testing.T) {
			result := evaluateResidualCase(t, options, item)
			if result.executionError() != nil || result.AssertionError != nil {
				t.Fatal("fixed package-local collection views must pass the exact original", result.executionError(), result.AssertionError)
			}
		})
		t.Run("original-20", func(t *testing.T) {
			options.version = suiteVersion20
			result := evaluateResidualCase(t, options, item)
			if result.AssertionError == nil || residualErrorCode(result.executionError()) != "XTSE0080" {
				t.Fatal("XSLT20 reserves the XSLT namespace even when a source 3.0 module names its initial template", result.executionError(), result.AssertionError)
			}
		})
		runXSLTResidualCollectionEdition(t, options, item)
	})
}

func xsltResidualOracleTransform(t *testing.T, version, main, input, initial, library string) ([]byte, error) {
	t.Helper()
	classpath, identity := "SAXON_CLASSPATH", "SAXON-J-HE 12.10"
	if version == suiteVersion20 {
		classpath, identity = "SAXON20_CLASSPATH", "SAXON 9.4.0.9"
	}
	binary, err := exec.LookPath("java")
	if err != nil {
		t.Fatal(err)
	}
	cp := residualRequired(t, classpath)
	actual, err := exec.CommandContext(t.Context(), binary, "-cp", cp, "net.sf.saxon.Version").CombinedOutput()
	if err != nil || !strings.Contains(string(actual), identity) {
		t.Fatal("independent processor identity", string(actual), err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	arguments := []string{"-cp", cp, "net.sf.saxon.Transform", "-xsl:" + main}
	if version == suiteVersion20 {
		arguments = append(arguments, "-xsltversion:2.0")
	}
	if input != "" {
		arguments = append(arguments, "-s:"+input)
	}
	if initial != "" {
		arguments = append(arguments, "-it:"+initial)
	}
	if library != "" {
		arguments = append(arguments, "-lib:"+library)
	}
	command := exec.CommandContext(ctx, binary, arguments...)
	var diagnostics bytes.Buffer
	command.Stderr = &diagnostics
	output, err := command.Output()
	if err != nil {
		return nil, fmt.Errorf("independent selected %s transform: %w: %s", version, err, diagnostics.String())
	}
	return output, nil
}

func runXSLTResidualNamedOutput(t *testing.T, directory string) {
	t.Helper()
	t.Run("output-0308", func(t *testing.T) {
		item := loadPinnedResidualCase(t, directory, suiteXSLT, "tests/decl/output/_output-test-set.xml", "output-0308")
		for _, version := range []string{suiteVersion20, suiteVersion30} {
			t.Run(version, func(t *testing.T) {
				options := suiteOptions{kind: suiteXSLT, directory: directory, version: version, xsdVersion: suiteVersion10, timeout: time.Second, limitsProfile: "default"}
				original := evaluateResidualCase(t, options, item)
				if original.executionError() != nil || original.AssertionError != nil {
					t.Fatal("selected named output must retain its import-merged character maps for the complete original assertion", original.executionError(), original.AssertionError)
				}
				ref, err := resolveSuiteEnvironment(item, suiteEnvironmentRef{node: item.node.child("environment"), base: item.base}, make(map[*suiteNode]struct{}))
				if err != nil {
					t.Fatal(err)
				}
				source := filepath.Join(t.TempDir(), "input.xml")
				if err := os.WriteFile(source, []byte(ref.node.child("source").child("content").Text), 0o600); err != nil {
					t.Fatal(err)
				}
				output, err := xsltResidualOracleTransform(t, version, filepath.Join(item.base, "output-0308.xsl"), source, "", "")
				if err != nil {
					t.Fatal(err)
				}
				for _, assertion := range item.node.child(suiteResultVariable).child("all-of").Children {
					if assertion.XMLName.Local != "serialization-matches" {
						t.Fatal("the complete original serialization assertion shape changed", assertion.XMLName)
					}
					value, err := original.Environment.query(t.Context(), `matches($s,$pattern)`, transform.Bindings{
						{Local: "s"}: transform.Values(transform.String(string(output))), {Local: "pattern"}: transform.Values(transform.String(assertion.Text)),
					})
					if err != nil || residualSequenceText(t, value) != suiteTrue {
						t.Fatal("independent full original assertion", assertion.Text, string(output), err)
					}
				}
				t.Log("P3_ORACLE saxon selected " + version)
			})
		}
	})
}

func runXSLTResidualCollectionEdition(t *testing.T, options suiteOptions, item suiteCase) {
	t.Helper()
	directory := t.TempDir()
	main := filepath.Join(directory, "collection-006b.xsl")
	library := filepath.Join(directory, "collection-006a.xsl")
	for _, path := range []string{main, library} {
		raw, err := os.ReadFile(filepath.Join(item.base, filepath.Base(path)))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, raw, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	collection := `<collection stable="true"><doc href="` + suiteFileURI(filepath.Join(item.base, "doc14.xml")) + `"/></collection>`
	if err := os.WriteFile(filepath.Join(directory, "collection-006.cxn"), []byte(collection), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Run("independent-original-30", func(t *testing.T) {
		output, err := xsltResidualOracleTransform(t, suiteVersion30, main, "", "{http://www.w3.org/1999/XSL/Transform}initial-template", library)
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(directory, "original.xml")
		if err := os.WriteFile(path, output, 0o600); err != nil {
			t.Fatal(err)
		}
		query := `let $d := doc('` + suiteFileURI(path) + `') return $d/out/pack-a/doc/a = '' and $d/out/pack-b/doc/a = ' '`
		if got := residualSaxonQuery(t, query, ""); got != suiteTrue {
			t.Fatal("independent complete original package assertions", got, string(output))
		}
		t.Log("P3_ORACLE saxon-12.10")
	})
	t.Run("independent-original-20", func(t *testing.T) {
		_, err := xsltResidualOracleTransform(t, suiteVersion20, main, "", "{http://www.w3.org/1999/XSL/Transform}initial-template", "")
		if err == nil || !strings.Contains(err.Error(), "XTSE0080") {
			t.Fatal("the unchanged source also violates the independent selected20 reserved namespace rule", err)
		}
		t.Log("P3_ORACLE saxon-9.4")
	})
	t.Run("package-free-20-control", func(t *testing.T) {
		controlled := item
		controlled.node = cloneResidualNode(item.node)
		test := controlled.node.child("test")
		test.Children = append(test.Children, &suiteNode{XMLName: xml.Name{Space: test.XMLName.Space, Local: "initial-template"}, Attributes: []xml.Attr{{Name: xml.Name{Local: "name"}, Value: "start"}}})
		for _, result := range controlled.node.Children {
			if result.XMLName.Local == suiteResultVariable {
				result.Children = []*suiteNode{{XMLName: xml.Name{Space: result.XMLName.Space, Local: "assert"}, Text: `count(/out/doc/a) = 1 and /out/doc/a = ' '`}}
			}
		}
		options.version = suiteVersion20
		var source []byte
		result := evaluateXSLTResidualSourceEdit(t, options, controlled, func(raw []byte) []byte {
			packages := regexp.MustCompile(`(?s)<t:use-package\b.*?</t:use-package>`)
			if len(packages.FindAllIndex(raw, -1)) != 1 || bytes.Count(raw, []byte(`name="t:initial-template"`)) != 1 || bytes.Count(raw, []byte(`<t:call-template name="a"/>`)) != 1 {
				t.Fatal("the exact pinned package/entry construct changed")
			}
			source = packages.ReplaceAll(raw, nil)
			source = bytes.Replace(source, []byte(`name="t:initial-template"`), []byte(`name="start"`), 1)
			source = bytes.Replace(source, []byte(`<t:call-template name="a"/>`), []byte(`<t:copy-of select="collection('collection-006.cxn')"/>`), 1)
			return source
		})
		if result.executionError() != nil || result.AssertionError != nil {
			t.Fatal("the explicit package-free named-template control must preserve source whitespace in20", result.executionError(), result.AssertionError)
		}
		if err := os.WriteFile(main, source, 0o600); err != nil {
			t.Fatal(err)
		}
		output, err := xsltResidualOracleTransform(t, suiteVersion20, main, "", "start", "")
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(directory, "controlled.xml")
		if err := os.WriteFile(path, output, 0o600); err != nil {
			t.Fatal(err)
		}
		query := `count(doc('` + suiteFileURI(path) + `')/out/doc/a) = 1 and doc('` + suiteFileURI(path) + `')/out/doc/a = ' '`
		if got := residualSaxon20Expression(t, query); got != suiteTrue {
			t.Fatal("independent selected20 package-free whitespace control", got, string(output))
		}
		t.Log("P3_ORACLE saxon-9.4")
	})
}

func evaluateXSLTResidualSourceVariant(t *testing.T, options suiteOptions, item suiteCase, before, after string) residualCaseResult {
	t.Helper()
	return evaluateXSLTResidualSourceEdit(t, options, item, func(raw []byte) []byte {
		if bytes.Count(raw, []byte(before)) != 1 {
			t.Fatal("the pinned causal construct must occur exactly once", before)
		}
		return bytes.Replace(raw, []byte(before), []byte(after), 1)
	})
}

func evaluateXSLTResidualSourceEdit(t *testing.T, options suiteOptions, item suiteCase, edit func([]byte) []byte) residualCaseResult {
	t.Helper()
	environment, err := prepareSuiteEnvironment(t.Context(), options, item)
	if err != nil {
		return residualCaseResult{PrepareError: err}
	}
	if err := prepareSuiteInvocation(t.Context(), options, item, item.node.child("test"), environment); err != nil {
		return residualCaseResult{PrepareError: err}
	}
	raw, settings, err := suiteStylesheetSource(options, environment)
	if err != nil {
		return residualCaseResult{PrepareError: err}
	}
	controlled := edit(raw)
	compiled, err := environment.engine.CompileXSLT(t.Context(), controlled, settings)
	evaluation := &suiteEvaluation{environment: environment, options: options, item: item, err: err}
	if err == nil {
		evaluation.result, evaluation.err = evaluateCompiledXSLTSuite(t.Context(), item, environment, compiled)
		if evaluation.result != nil {
			evaluation.sequence = evaluation.result.Primary()
			if environment.output != nil && evaluation.err == nil {
				evaluation.err = evaluation.prepareOutput(t.Context())
			}
		}
	}
	return residualCaseResult{
		Evaluation: evaluation, Environment: environment,
		AssertionError: checkSuiteAssertion(t.Context(), evaluation, item.node.child(suiteResultVariable)),
	}
}

func runXSLTResidualCompetingErrors(t *testing.T, directory string) {
	t.Helper()
	for _, test := range []struct {
		name   string
		file   string
		code   string
		before string
		after  string
	}{
		{"accumulator-038", "tests/decl/accumulator/_accumulator-test-set.xml", "XTDE0040", `name="main"`, `name="main" visibility="public"`},
		{"expose-925", "tests/decl/expose/_expose-test-set.xml", "XTSE0020", `names="t1#0"`, `names="missing"`},
		{"package-200", "tests/decl/package/_package-test-set.xml", "XTSE0020", `package-version="'1.0.0'"`, `package-version="1.0.0"`},
		{"merge-049", "tests/insn/merge/_merge-test-set.xml", "XTSE1660", `validation="strict">`, `>`},
		{"merge-050", "tests/insn/merge/_merge-test-set.xml", "XTSE1660", `validation="strict">`, `>`},
		{"merge-052", "tests/insn/merge/_merge-test-set.xml", "XTSE1660", `type="BOOKLIST-type">`, `>`},
		{"merge-053", "tests/insn/merge/_merge-test-set.xml", "XTSE1660", `type="BOOKLIST-type">`, `>`},
		{"merge-054", "tests/insn/merge/_merge-test-set.xml", "XTSE1660", `type="BOOKLIST-type">`, `>`},
		{"error-1535b", "tests/misc/error/_error-test-set.xml", "XTSE1660", ` type="Q{http://err1535.com/}c"`, ``},
		{"key-092", "tests/fn/key/_key-test-set.xml", "XTSE1205", ` use=".//term"`, ``},
		{"iterate-023", "tests/insn/iterate/_iterate-test-set.xml", "XTSE3120", `<xsl:next-iteration>`, `<xsl:next-iteration use-when="false()">`},
		{"iterate-024", "tests/insn/iterate/_iterate-test-set.xml", "XTSE0090", ` export="yes"`, ``},
	} {
		t.Run(test.name, func(t *testing.T) {
			item := loadPinnedResidualCase(t, directory, suiteXSLT, test.file, test.name)
			options := suiteOptions{
				kind: suiteXSLT, directory: directory, version: suiteVersion30,
				xsdVersion: suiteVersion10, timeout: time.Second, limitsProfile: "default",
			}
			t.Run("original", func(t *testing.T) {
				original := evaluateResidualCase(t, options, item)
				if original.AssertionError == nil || residualErrorCode(original.executionError()) != test.code {
					t.Fatal("original independently forbidden construct", original.executionError(), original.AssertionError, test.code)
				}
			})
			t.Run("remove-first-error", func(t *testing.T) {
				controlled := evaluateXSLTResidualSourceVariant(t, options, item, test.before, test.after)
				if test.name == "package-200" {
					if controlled.executionError() != nil {
						t.Fatal("the supplied package matches the corrected range", controlled.executionError())
					}
					value, err := controlled.Evaluation.assertionValue(t.Context(), `exists(/ok)`, nil)
					if err != nil || residualSequenceText(t, value) != suiteTrue {
						t.Fatal("the corrected version selects the supplied package", value, err)
					}
					return
				}
				if controlled.PrepareError != nil || controlled.AssertionError != nil {
					t.Fatal("removing the first forbidden construct must expose the unchanged expected error", controlled.executionError(), controlled.AssertionError)
				}
			})
		})
	}
}

func runXSLTResidualLimits(t *testing.T, directory string) {
	t.Helper()
	for _, test := range []struct {
		name  string
		file  string
		depth bool
	}{
		{"call-template-1001", "tests/insn/call-template/_call-template-test-set.xml", true},
		{"call-template-1002", "tests/insn/call-template/_call-template-test-set.xml", true},
		{"call-template-1003", "tests/insn/call-template/_call-template-test-set.xml", true},
		{"higher-order-functions-068", "tests/expr/higher-order-functions/_higher-order-functions-test-set.xml", true},
		{"date-020", "tests/type/date/_date-test-set.xml", false},
		{"regex-syntax-0986", "tests/misc/regex-syntax/_regex-syntax-test-set.xml", false},
		{"regex-syntax-0987", "tests/misc/regex-syntax/_regex-syntax-test-set.xml", false},
		{"regex-syntax-xslt20-0986", "tests/misc/regex-syntax-xslt20/_regex-syntax-xslt20-test-set.xml", false},
		{"regex-syntax-xslt20-0987", "tests/misc/regex-syntax-xslt20/_regex-syntax-xslt20-test-set.xml", false},
		{"bug-6301", "tests/misc/bug/_bug-test-set.xml", false},
		{"catalog-002", "tests/misc/catalog/_catalog-test-set.xml", false},
		{"catalog-003", "tests/misc/catalog/_catalog-test-set.xml", false},
		{"catalog-006b", "tests/misc/catalog/_catalog-test-set.xml", false},
		{"catalog-007", "tests/misc/catalog/_catalog-test-set.xml", false},
		{"function-0701", "tests/decl/function/_function-test-set.xml", false},
		{"normalize-unicode-008", "tests/fn/normalize-unicode/_normalize-unicode-test-set.xml", false},
		{"result-document-1501", "tests/insn/result-document/_result-document-test-set.xml", false},
		{"result-document-1502", "tests/insn/result-document/_result-document-test-set.xml", false},
		{"variable-0108", "tests/decl/variable/_variable-test-set.xml", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			item := loadPinnedResidualCase(t, directory, suiteXSLT, test.file, test.name)
			options := suiteOptions{
				kind: suiteXSLT, directory: directory, version: suiteVersion30,
				xsdVersion: suiteVersion10, timeout: time.Second, limitsProfile: "default",
			}
			if strings.HasPrefix(test.name, "regex-syntax-xslt20-") {
				options.version = suiteVersion20
			}
			t.Run("original", func(t *testing.T) {
				original := evaluateResidualCase(t, options, item)
				if !errors.Is(original.executionError(), transform.ErrLimit) && !errors.Is(original.executionError(), context.DeadlineExceeded) {
					t.Fatal("original must retain the typed resource cause", original.executionError())
				}
			})
			t.Run("raised-finite-budget", func(t *testing.T) {
				if test.name == "call-template-1002" || test.name == "call-template-1003" {
					xsltResidualBoundedRecursion(t, options, item, test.name)
					return
				}
				if !test.depth {
					options.limitsProfile = suiteLanguage
				}
				limits := suiteLimits(options)
				if test.depth {
					limits.MaxDepth = 512
				} else {
					limits.MaxNodes, limits.MaxOperations = 5_000_000, 200_000_000
					limits.MaxResourceBytes, limits.MaxResources = 256<<20, 16_384
					limits.MaxOutputBytes, limits.MaxDepth = 256<<20, 512
				}
				limits.Timeout = 30 * time.Second
				if test.name == "normalize-unicode-008" || strings.HasPrefix(test.name, "result-document-150") {
					xsltResidualBoundedRegexInput(t, options, item, limits, test.name)
					return
				}
				ctx, cancel := context.WithTimeout(t.Context(), limits.Timeout)
				defer cancel()
				environment, err := prepareSuiteEnvironmentWithLimits(ctx, options, item, limits)
				if err != nil {
					t.Fatal("prepare with explicit raised finite limits", err)
				}
				controlled := evaluateSuiteCase(ctx, options, item, environment)
				if err := checkSuiteAssertion(ctx, controlled, item.node.child(suiteResultVariable)); err != nil {
					t.Fatal("the unchanged publisher assertion must pass under the explicit raised finite limits", controlled.err, err)
				}
			})
		})
	}
}

func xsltResidualBoundedRegexInput(t *testing.T, options suiteOptions, item suiteCase, limits transform.Limits, name string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), limits.Timeout)
	defer cancel()
	environment, err := prepareSuiteEnvironmentWithLimits(ctx, options, item, limits)
	if err != nil {
		t.Fatal(err)
	}
	if name == "normalize-unicode-008" {
		path := filepath.Join(item.base, "NormalizationTest.txt")
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		lines := bytes.SplitAfter(raw, []byte("\n"))
		end, vectors := 0, 0
		for _, line := range lines {
			end += len(line)
			trimmed := bytes.TrimSpace(line)
			if len(trimmed) > 0 && trimmed[0] != '#' && trimmed[0] != '@' {
				vectors++
			}
			if vectors == 1 {
				break
			}
		}
		if vectors != 1 || end >= len(raw) {
			t.Fatal("one nonempty bounded published Unicode vector is required")
		}
		resolver := &xsltResidualModuleResolver{base: environment.resources, edits: map[string][]xsltResidualModuleEdit{"NormalizationTest.txt": {{string(raw), string(raw[:end])}}}}
		xsltResidualEngineWithLimits(t, options, environment, limits, resolver, resolver, nil)
	} else {
		text, err := environment.query(ctx, `string(.)`, nil)
		if err != nil {
			t.Fatal(err)
		}
		original := residualSequenceText(t, text)
		matches := regexp.MustCompile(`[A-Z][a-z]+`).FindAllStringIndex(original, 161)
		if len(matches) != 161 {
			t.Fatal("the full original input must exceed the bounded regex prefix")
		}
		prefix := original[:matches[159][1]]
		var source bytes.Buffer
		source.WriteString("<doc>")
		if err := xml.EscapeText(&source, []byte(prefix)); err != nil {
			t.Fatal(err)
		}
		source.WriteString("</doc>")
		environment.document, err = environment.engine.Parse(ctx, source.Bytes())
		if err != nil {
			t.Fatal(err)
		}
	}
	controlled := evaluateSuiteCase(ctx, options, item, environment)
	if err := checkSuiteAssertion(ctx, controlled, item.node.child(suiteResultVariable)); err != nil {
		t.Fatal("the unchanged stylesheet and assertion must pass with the explicitly bounded published input", controlled.err, err)
	}
	main := filepath.Join(item.base, name+".xsl")
	quote := func(value string) string { return "'" + strings.ReplaceAll(value, "'", "''") + "'" }
	if name == "normalize-unicode-008" {
		expression := `empty(transform(map{'stylesheet-location':` + quote(suiteFileURI(main)) + `,'source-node':parse-xml('<dummy/>'),'delivery-format':'raw'})?output//failure)`
		if got := residualSaxonQuery(t, expression, ""); got != suiteTrue {
			t.Fatal("independent original complete Unicode fixture", got)
		}
		return
	}
	// The independent processor evaluates the complete unmodified original
	// source. Native evaluates its exact text prefix, retaining every position
	// inspected by the publisher assertion.
	_, sourcePath := xsltResidualInputBytes(t, options, item)
	call := `transform(map{'stylesheet-location':` + quote(suiteFileURI(main)) + `,'source-node':doc(` + quote(suiteFileURI(sourcePath)) + `),'base-output-uri':'file:///xmlsec-suite-output/','delivery-format':'raw'})`
	expression := ""
	if name == "result-document-1501" {
		expression = `let $r:=` + call + ` return every $p in ('Person188.xml','Christendom202.xml','Majesty224.xml','England258.xml') satisfies (let $k:=map:keys($r)[ends-with(.,'/'||$p)],$out:=($r($k)/self::out,$r($k)/out) return count($k)=1 and count($out)=1 and $out=substring(replace($p,'[0-9]+\.xml$',''),2))`
	} else {
		expression = `try { ` + call + ` ! 'unexpected-success' } catch * { local-name-from-QName($err:code) }`
	}
	want := suiteTrue
	if name == "result-document-1502" {
		want = "FOAR0001"
	}
	if got := residualSaxonQuery(t, expression, ""); got != want {
		t.Fatal("independent full original result-document fixture", got, want)
	}
}

func xsltResidualBoundedRecursion(t *testing.T, options suiteOptions, item suiteCase, name string) {
	t.Helper()
	before, after := `select="1000"`, `select="100"`
	var expected strings.Builder
	for i := 1; i <= 101; i++ {
		expected.WriteString(strconv.Itoa(i))
		expected.WriteByte('|')
	}
	originalExpected := ""
	if name == "call-template-1003" {
		before, after = `select="1 to 1000"`, `select="1 to 100"`
		expected.Reset()
		expected.WriteString("1 ")
		originalExpected = "1 101 201 301 401 501 601 701 801 901 "
	} else {
		output, _, err := readSuiteReferencedNode(options.directory, item.base, item.node.child(suiteResultVariable).child("assert-xml"))
		if err != nil {
			t.Fatal(err)
		}
		originalExpected = output.Text
	}
	controlled := evaluateXSLTResidualSourceVariant(t, options, item, before, after)
	if controlled.executionError() != nil {
		t.Fatal("100-call bounded variant", controlled.executionError())
	}
	if got := residualSequenceText(t, controlled.Evaluation.sequence); got != expected.String() {
		t.Fatal("bounded literal vector", got, expected.String())
	}
	raw, _, err := suiteStylesheetSource(options, controlled.Environment)
	if err != nil {
		t.Fatal(err)
	}
	quote := func(value string) string {
		return "'" + strings.ReplaceAll(value, "'", "''") + "'"
	}
	for _, run := range []struct {
		source string
		want   string
	}{
		{string(raw), originalExpected},
		{strings.Replace(string(raw), before, after, 1), expected.String()},
	} {
		entry := `,'source-node':parse-xml('<dummy/>')`
		if name == "call-template-1003" {
			entry += `,'initial-template':QName('http://www.w3.org/1999/XSL/Transform','initial-template')`
		}
		expression := `string-join(transform(map{'stylesheet-text':` + quote(run.source) + entry + `,'delivery-format':'raw'})?output!string(.),'')`
		if got := residualSaxonQuery(t, expression, ""); got != run.want {
			t.Fatal("independent original/bounded recursion vector", got, run.want)
		}
	}
}

func setXSLTResidualAttribute(node *suiteNode, name, value string) {
	for index := range node.Attributes {
		if node.Attributes[index].Name.Space == "" && node.Attributes[index].Name.Local == name {
			node.Attributes[index].Value = value
			return
		}
	}
	node.Attributes = append(node.Attributes, xml.Attr{Name: xml.Name{Local: name}, Value: value})
}

func runXSLTResidualMetadataControls(t *testing.T, directory string) {
	t.Helper()
	for _, test := range []struct {
		name    string
		file    string
		version string
		code    string
	}{
		{"analyze-string-097a", "tests/insn/analyze-string/_analyze-string-test-set.xml", suiteVersion30, ""},
		{"static-013c", "tests/attr/static/_static-test-set.xml", suiteVersion30, ""},
		{"format-number-070", "tests/fn/format-number/_format-number-test-set.xml", suiteVersion20, "XTDE0040"},
	} {
		t.Run(test.name, func(t *testing.T) {
			item := loadPinnedResidualCase(t, directory, suiteXSLT, test.file, test.name)
			options := suiteOptions{
				kind: suiteXSLT, directory: directory, version: test.version,
				xsdVersion: suiteVersion10, timeout: time.Second, limitsProfile: "default",
			}
			original := evaluateResidualCase(t, options, item)
			if original.AssertionError == nil || residualErrorCode(original.executionError()) != test.code {
				t.Fatal("unchanged catalog metadata residual", original.executionError(), original.AssertionError)
			}
			controlled := item
			controlled.node = cloneResidualNode(item.node)
			switch test.name {
			case "analyze-string-097a":
				assertion := cloneResidualNode(item.node.child(suiteResultVariable))
				setXSLTResidualAttribute(assertion.child("assert-xml"), "ignore-prefixes", suiteTrue)
				if err := checkSuiteAssertion(t.Context(), original.Evaluation, assertion); err != nil {
					t.Fatal("permitted namespace prefix must retain all expanded names and text", err)
				}
				bad := cloneResidualNode(assertion)
				xmlExpected := bad.child("assert-xml")
				xmlExpected.Text = strings.ReplaceAll(xmlExpected.Text, "http://www.w3.org/2005/xpath-functions", "urn:wrong-result-namespace")
				if err := checkSuiteAssertion(t.Context(), original.Evaluation, bad); err == nil {
					t.Fatal("prefix-independent comparison must still reject the wrong expanded namespace")
				}
				return
			case "static-013c":
				parameter := controlled.node.child("test").child(suiteParam)
				if parameter.attr("as") != "xs:string" || parameter.attr("select") != "111" {
					t.Fatal("the pinned documentation-only type must remain unchanged")
				}
				setXSLTResidualAttribute(parameter, "select", "xs:string(111)")
			case "format-number-070":
				invocation := controlled.node.child("test")
				var entries []*suiteNode
				for _, child := range invocation.Children {
					if child.XMLName.Local != "initial-template" {
						entries = append(entries, child)
					}
				}
				invocation.Children = entries
			}
			result := evaluateXSLTResidualVariant(t, options, controlled)
			if result.PrepareError != nil || result.AssertionError != nil {
				t.Fatal("single metadata correction must satisfy the complete original assertion", result.executionError(), result.AssertionError)
			}
		})
	}
}

func runXSLTResidualSingleCorrections(t *testing.T, directory string) {
	t.Helper()
	for _, test := range []struct {
		name      string
		file      string
		code      string
		before    string
		after     string
		assertion string
	}{
		{"context-item-903", "tests/decl/context-item/_context-item-test-set.xml", "XTSE1660", `as="element(*, my:percentage)"`, `as="item()"`, `/out = '1 2 3 4 5'`},
		{"static-012", "tests/attr/static/_static-test-set.xml", "XTDE0050", `as="xs:integer" />`, `as="xs:integer" select="0" />`, `normalize-space(.) = '0'`},
		{"static-013", "tests/attr/static/_static-test-set.xml", "XTTE0590", `select="xs:date('2014-03-03')"`, `select="0"`, `normalize-space(.) = '0'`},
		{"expose-926", "tests/decl/expose/_expose-test-set.xml", "", `names="p:f1"`, `names="p:f1#99"`, ""},
		{"evaluate-042", "tests/insn/evaluate/_evaluate-test-set.xml", "XTDE3160", `xs:QName('p'||.)`, `xs:QName('p2')`, `count(/Result/out) = 9 and deep-equal(/Result/out/xs:integer(.), (21,22,23,24,20,21,22,23,24))`},
		{"extension-functions-0105", "tests/fn/extension-functions/_extension-functions-test-set.xml", "XTSE0085", `xmlns:xs="http://www.w3.org/2001/XMLSchema"`, `xmlns:xs="urn:application-extension"`, `exists(/out) and empty(/out/*)`},
		{"mode-1439", "tests/attr/mode/_mode-test-set.xml", "XTSE1660", `on-no-match="shallow-copy" typed="yes"`, `on-no-match="shallow-copy" typed="no"`, `deep-equal($result, $source)`},
		{"override-f-020", "tests/decl/override/_override-test-set.xml", "XTSE3055", `select="'TWO'"`, `select="'TWO'"`, ""},
	} {
		t.Run(test.name, func(t *testing.T) {
			item := loadPinnedResidualCase(t, directory, suiteXSLT, test.file, test.name)
			options := suiteOptions{
				kind: suiteXSLT, directory: directory, version: suiteVersion30,
				xsdVersion: suiteVersion10, timeout: time.Second, limitsProfile: "default",
			}
			original := evaluateResidualCase(t, options, item)
			if original.AssertionError == nil || residualErrorCode(original.executionError()) != test.code {
				t.Fatal("original selected REC outcome", original.executionError(), original.AssertionError, test.code)
			}
			before, after := test.before, test.after
			if test.name == "override-f-020" {
				// Hide only the homonymous local declaration; retain the override.
				before = "</xsl:use-package>\n  \n    " + `<xsl:function name="p:f"`
				after = "</xsl:use-package>\n  \n    " + `<xsl:function use-when="false()" name="p:f"`
			}
			controlled := evaluateXSLTResidualSourceVariant(t, options, item, before, after)
			if test.name == "override-f-020" {
				if controlled.executionError() != nil {
					t.Fatal("removing only the local override conflict", controlled.executionError())
				}
				result, err := controlled.Evaluation.assertionValue(t.Context(), `exists(/wrong[@value='ONE'])`, nil)
				if err != nil || residualSequenceText(t, result) != suiteTrue {
					t.Fatal("the remaining override must supply ONE", result, err)
				}
				return
			}
			if test.assertion == "" {
				if controlled.PrepareError != nil || controlled.AssertionError != nil {
					t.Fatal("explicit absent arity must produce the publisher's missing-component error", controlled.executionError(), controlled.AssertionError)
				}
				return
			}
			if controlled.executionError() != nil {
				t.Fatal("single-construct correction", controlled.executionError())
			}
			bindings := transform.Bindings(nil)
			if test.name == "mode-1439" {
				bindings = transform.Bindings{{Local: "source"}: transform.Values(controlled.Environment.document.Root())}
			}
			result, err := controlled.Evaluation.assertionValue(t.Context(), test.assertion, bindings)
			if err != nil || residualSequenceText(t, result) != suiteTrue {
				t.Fatal("explicit corrected literal result", result, err, test.assertion)
			}
		})
	}
}

func runXSLTResidualRegexEditions(t *testing.T, directory string) {
	t.Helper()
	for _, test := range []struct {
		name     string
		obsolete string
	}{
		{"regex-syntax-xslt20-0056", ""},
		{"regex-syntax-xslt20-0086", ""},
		{"regex-syntax-xslt20-0102", ""},
		{"regex-syntax-xslt20-0984", "⌈⌉"},
		{"regex-syntax-xslt20-0985", "፩፪፫፬፭፮፯፰፱"},
	} {
		t.Run(test.name, func(t *testing.T) {
			item := loadPinnedResidualCase(t, directory, suiteXSLT, "tests/misc/regex-syntax-xslt20/_regex-syntax-xslt20-test-set.xml", test.name)
			options := suiteOptions{
				kind: suiteXSLT, directory: directory, version: suiteVersion20,
				xsdVersion: suiteVersion10, timeout: time.Second, limitsProfile: "default",
			}
			original := evaluateResidualCase(t, options, item)
			if original.AssertionError == nil {
				t.Fatal("unchanged legacy regex fixture no longer reproduces its residual")
			}
			if test.obsolete == "" {
				if residualErrorCode(original.executionError()) != "FORX0002" {
					t.Fatal("XSD 1.0 interior literal hyphen must be rejected", original.executionError())
				}
				options.xsdVersion = suiteVersion11
				controlled := evaluateXSLTResidualVariant(t, options, item)
				if controlled.PrepareError != nil || controlled.AssertionError != nil {
					t.Fatal("same pattern/input under XSD 1.1 must pass its unchanged assertion", controlled.executionError(), controlled.AssertionError)
				}
				return
			}
			if original.executionError() != nil {
				t.Fatal("Unicode classification mismatch must be a value difference", original.executionError())
			}
			controlled := item
			controlled.node = cloneResidualNode(item.node)
			var match, nonmatch *suiteNode
			for _, parameter := range controlled.node.child("test").children(suiteParam) {
				switch parameter.attr("name") {
				case "match":
					match = parameter
				case "nonmatch":
					nonmatch = parameter
				}
			}
			value := match.attr("select")
			for _, character := range test.obsolete {
				fragment := string(character) + ","
				if strings.Count(value, fragment) != 1 {
					t.Fatal("pinned old category member missing or duplicated", character)
				}
				value = strings.Replace(value, fragment, "", 1)
			}
			setXSLTResidualAttribute(match, "select", value)
			characters := strings.Split(test.obsolete, "")
			negative := strings.TrimSuffix(nonmatch.attr("select"), "'")
			if negative != "'" {
				negative += ","
			}
			setXSLTResidualAttribute(nonmatch, "select", negative+strings.Join(characters, ",")+"'")
			result := evaluateResidualCase(t, options, controlled)
			if result.executionError() != nil || result.AssertionError != nil {
				t.Fatal("only the independently reclassified Unicode characters moved between vectors", result.executionError(), result.AssertionError)
			}
		})
	}
}

func runXSLTResidualExplicitResources(t *testing.T, directory string) {
	t.Helper()
	for _, test := range []struct {
		name string
		file string
		code string
	}{
		{"merge-008", "tests/insn/merge/_merge-test-set.xml", "FODC0002"},
		{"merge-097", "tests/insn/merge/_merge-test-set.xml", "FODC0002"},
		{"unparsed-text-2003", "tests/fn/unparsed-text/_unparsed-text-test-set.xml", ""},
	} {
		t.Run(test.name, func(t *testing.T) {
			item := loadPinnedResidualCase(t, directory, suiteXSLT, test.file, test.name)
			options := suiteOptions{
				kind: suiteXSLT, directory: directory, version: suiteVersion30,
				xsdVersion: suiteVersion10, timeout: time.Second, limitsProfile: "default",
			}
			original := evaluateResidualCase(t, options, item)
			if original.AssertionError == nil || residualErrorCode(original.executionError()) != test.code {
				t.Fatal("unchanged offline resource residual", original.executionError(), original.AssertionError)
			}
			environment, err := prepareSuiteEnvironment(t.Context(), options, item)
			if err != nil {
				t.Fatal(err)
			}
			switch test.name {
			case "merge-008":
				for _, name := range []string{"log-file-1.xml", "log-file-2.xml"} {
					requested, err := resolveSuiteURI(suiteFileURI(item.base)+"/", "TestInputs/merge/"+name)
					if err != nil {
						t.Fatal(err)
					}
					environment.resources.resources[requested] = filepath.Join(item.base, name)
				}
			case "merge-097":
				requested, err := resolveSuiteURI(suiteFileURI(item.base)+"/", ".?select=merge-097-*.xml")
				if err != nil {
					t.Fatal(err)
				}
				files, err := filepath.Glob(filepath.Join(item.base, "merge-097-*.xml"))
				if err != nil || len(files) != 2 {
					t.Fatal("pinned declared collection members", files, err)
				}
				for _, file := range files {
					environment.resources.uriCollections[requested] = append(environment.resources.uriCollections[requested], suiteFileURI(file))
				}
			case "unparsed-text-2003":
				const uri = "http://www.w3.org/Consortium/mission.html"
				delete(environment.resources.unavailable, uri)
				// Availability is independent of the content. Supply known pinned
				// UTF-8 bytes explicitly; this proof never fetches the remote URI.
				environment.resources.resources[uri] = filepath.Join(item.base, "unparsed-text-2003.xsl")
			}
			controlled := evaluateSuiteCase(t.Context(), options, item, environment)

			if err := checkSuiteAssertion(t.Context(), controlled, item.node.child(suiteResultVariable)); err != nil {
				t.Fatal("explicit declared resources must reach the unchanged publisher assertion", controlled.err, err)
			}
		})
	}
}

func xsltResidualInputBytes(t *testing.T, options suiteOptions, item suiteCase) ([]byte, string) {
	t.Helper()
	selected := item.node.child("environment")
	if selected == nil {
		t.Fatal("causal whitespace proof requires the declared source")
	}
	ref, err := resolveSuiteEnvironment(item, suiteEnvironmentRef{node: selected, base: item.base}, make(map[*suiteNode]struct{}))
	if err != nil {
		t.Fatal(err)
	}
	for _, source := range ref.node.children("source") {
		if source.attr("role") != "." {
			continue
		}
		if source.attr(suiteFile) != "" {
			raw, path, err := readSuiteReferencedFile(options.directory, ref.base, source)
			if err != nil {
				t.Fatal(err)
			}
			return raw, path
		}
		if content := source.child("content"); content != nil {
			return []byte(content.Text), ""
		}
	}
	t.Fatal("declared original source not found")
	return nil, ""
}

func xsltResidualSaxonOriginal(t *testing.T, options suiteOptions, item suiteCase, environment *preparedSuiteEnvironment, input []byte, inputPath string, extra ...string) ([]byte, []byte) {
	t.Helper()
	binary, err := exec.LookPath("java")
	if err != nil {
		t.Fatal(err)
	}
	classpath := residualRequired(t, "SAXON_CLASSPATH")
	if options.version == suiteVersion20 {
		classpath = residualRequired(t, "SAXON20_CLASSPATH")
	}
	_, main, err := readSuiteReferencedFile(options.directory, environment.stylesheet.base, environment.stylesheet.node)
	if err != nil {
		t.Fatal(err)
	}
	if inputPath == "" {
		inputPath = filepath.Join(t.TempDir(), "source.xml")
		if err := os.WriteFile(inputPath, input, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	arguments := []string{"-cp", classpath, "net.sf.saxon.Transform", "-xsl:" + main, "-s:" + inputPath, "-strip:none", "!indent=no", "!omit-xml-declaration=yes", "!encoding=UTF-8"}
	for _, entry := range []struct {
		element string
		option  string
	}{{"initial-template", "-it:"}, {"initial-mode", "-im:"}} {
		if initial := item.node.child("test").child(entry.element); initial != nil {
			name, err := suiteQName(initial.attr("name"), suiteScopedNamespaces(environment, initial))
			if err != nil {
				t.Fatal(err)
			}
			lexical := name.Local
			if name.Space != "" {
				lexical = "{" + name.Space + "}" + lexical
			}
			arguments = append(arguments, entry.option+lexical)
		}
	}
	if environment.document == nil && item.node.child("test").child("initial-template") == nil && item.node.child("test").child("initial-mode") == nil {
		arguments = append(arguments, "-it")
	}
	libraries := make([]string, 0, len(environment.resources.packages))
	for _, library := range environment.resources.packages {
		path := environment.resources.resources[library.uri]
		if path == "" {
			t.Fatal("pinned package resource path missing", library.uri)
		}
		libraries = append(libraries, path)
	}
	if len(libraries) != 0 {
		arguments = append(arguments, "-lib:"+strings.Join(libraries, string(os.PathListSeparator)))
	}
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	for _, argument := range extra {
		if strings.HasPrefix(argument, "-xsl:") {
			arguments[3] = argument
		} else {
			arguments = append(arguments, argument)
		}
	}
	command := exec.CommandContext(ctx, binary, arguments...)
	var diagnostics bytes.Buffer
	command.Stderr = &diagnostics
	output, err := command.Output()
	if err != nil {
		t.Log(diagnostics.String())
		t.Fatal("independent original stylesheet/input", err)
	}
	return output, diagnostics.Bytes()
}

// The stdlib decoder provides a separate lexical check of the diagnostic
// projection. Removing whitespace is confined to this causal proof; the real
// catalog assertion above continues to compare all original text nodes.
func xsltResidualXMLTokens(t *testing.T, raw []byte, dropWhitespace, expanded bool) []string {
	t.Helper()
	decoder := xml.NewDecoder(bytes.NewReader(raw))
	read := decoder.RawToken
	if expanded {
		read = decoder.Token
	}
	var tokens []string
	for {
		token, err := read()
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}

			t.Fatal("independent XML tokenization", err)
		}
		switch value := token.(type) {
		case xml.StartElement:
			var attributes []string
			for _, attribute := range value.Attr {
				if attribute.Name.Space == "xmlns" || attribute.Name.Space == "" && attribute.Name.Local == "xmlns" {
					continue
				}
				attributes = append(attributes, strconv.Quote(attribute.Name.Space)+":"+strconv.Quote(attribute.Name.Local)+"="+strconv.Quote(attribute.Value))
			}
			slices.Sort(attributes)
			tokens = append(tokens, "S"+strconv.Quote(value.Name.Space)+":"+strconv.Quote(value.Name.Local)+strings.Join(attributes, ";"))
		case xml.EndElement:
			tokens = append(tokens, "E"+strconv.Quote(value.Name.Space)+":"+strconv.Quote(value.Name.Local))
		case xml.CharData:
			if len(tokens) != 0 && strings.HasPrefix(tokens[len(tokens)-1], "T") {
				tokens[len(tokens)-1] += string(value)
			} else {
				tokens = append(tokens, "T"+string(value))
			}
		case xml.Comment:
			tokens = append(tokens, "C"+string(value))
		case xml.ProcInst:
			if value.Target != "xml" {
				tokens = append(tokens, "P"+value.Target+":"+string(value.Inst))
			}
		}
	}
	if dropWhitespace {
		tokens = slices.DeleteFunc(tokens, func(value string) bool {
			return strings.HasPrefix(value, "T") && strings.Trim(value[1:], " \t\r\n") == ""
		})
	}
	return tokens
}

func runXSLTResidualWhitespace(t *testing.T, directory string) {
	t.Helper()
	for _, test := range []struct {
		name        string
		file        string
		inputLayout bool
	}{
		{"as-1303", "tests/attr/as/_as-test-set.xml", false},
		{"as-1304", "tests/attr/as/_as-test-set.xml", false},
		{"attribute-set-1508", "tests/decl/attribute-set/_attribute-set-test-set.xml", false},
		{"attribute-set-1509", "tests/decl/attribute-set/_attribute-set-test-set.xml", false},
		{"function-1701", "tests/decl/function/_function-test-set.xml", false},
		{"for-each-group-085", "tests/insn/for-each-group/_for-each-group-test-set.xml", true},
		{"id-003", "tests/fn/id/_id-test-set.xml", true},
		{"id-036", "tests/fn/id/_id-test-set.xml", true},
		{"number-4501", "tests/insn/number/_number-test-set.xml", true},
		{"on-non-empty-004", "tests/insn/on-non-empty/_on-non-empty-test-set.xml", true},
		{"on-non-empty-005", "tests/insn/on-non-empty/_on-non-empty-test-set.xml", true},
		{"use-package-170", "tests/decl/use-package/_use-package-test-set.xml", true},
		{"use-package-171", "tests/decl/use-package/_use-package-test-set.xml", true},
		{"use-package-172", "tests/decl/use-package/_use-package-test-set.xml", true},
		{"use-package-173", "tests/decl/use-package/_use-package-test-set.xml", true},
	} {
		t.Run(test.name, func(t *testing.T) {
			item := loadPinnedResidualCase(t, directory, suiteXSLT, test.file, test.name)
			options := suiteOptions{
				kind: suiteXSLT, directory: directory, version: suiteVersion30,
				xsdVersion: suiteVersion10, timeout: time.Second, limitsProfile: "default",
			}
			original := evaluateResidualCase(t, options, item)
			if original.executionError() != nil || original.AssertionError == nil {
				t.Fatal("the original exact whitespace assertion must fail as a value comparison", original.executionError(), original.AssertionError)
			}
			raw, sourcePath := xsltResidualInputBytes(t, options, item)
			oracle, _ := xsltResidualSaxonOriginal(t, options, item, original.Environment, raw, sourcePath)
			actual, err := original.Evaluation.assertionValue(t.Context(), `serialize($result,map{'method':'xml','omit-xml-declaration':true(),'indent':false()})`, nil)
			if err != nil {
				t.Fatal(err)
			}
			actualXML := []byte(residualSequenceText(t, actual))
			if !slices.Equal(xsltResidualXMLTokens(t, actualXML, false, true), xsltResidualXMLTokens(t, oracle, false, true)) {
				t.Fatal("independent engine must preserve the same original result whitespace", string(actualXML), string(oracle))
			}
			if !test.inputLayout {
				expected, err := suiteExpectedBytes(original.Evaluation, item.node.child(suiteResultVariable).child("assert-xml"))
				if err != nil {
					t.Fatal(err)
				}
				for _, expanded := range []bool{false, true} {
					if !slices.Equal(xsltResidualXMLTokens(t, actualXML, true, expanded), xsltResidualXMLTokens(t, expected, true, expanded)) {
						t.Fatal("the publisher/native difference must consist only of whitespace text nodes", string(actualXML), string(expected))
					}
				}
				return
			}
			// Intervene on the supplied source, retaining the DTD and every
			// non-whitespace byte. The stylesheet and expected result stay fixed.
			compact := regexp.MustCompile(`>[ \t\r\n]+<`).ReplaceAll(raw, []byte("><"))
			if bytes.Equal(raw, compact) {
				t.Fatal("the declared source must contain removable layout text")
			}
			environment, err := prepareSuiteEnvironment(t.Context(), options, item)
			if err != nil {
				t.Fatal(err)
			}
			parsed, err := environment.query(t.Context(), `parse-xml($controlledSource)`, transform.Bindings{{Local: "controlledSource"}: transform.Values(transform.String(string(compact)))})
			if err != nil {
				t.Fatal(err)
			}
			environment.document, err = suiteParsedDocument(parsed)
			if err != nil {
				t.Fatal(err)
			}
			controlled := evaluateSuiteCase(t.Context(), options, item, environment)
			if err := checkSuiteAssertion(t.Context(), controlled, item.node.child(suiteResultVariable)); err != nil {
				t.Fatal("removing only supplied input layout must satisfy the unchanged assertion", controlled.err, err)
			}
		})
	}
}

func withoutXSLTResidualWarnings(node *suiteNode) *suiteNode {
	cloned := cloneResidualNode(node)
	cloned.Children = slices.DeleteFunc(cloned.Children, func(child *suiteNode) bool { return child.XMLName.Local == "assert-warning" })
	for index, child := range cloned.Children {
		cloned.Children[index] = withoutXSLTResidualWarnings(child)
	}
	return cloned
}

func runXSLTResidualWarnings(t *testing.T, directory string) {
	t.Helper()
	for _, name := range []string{"mode-0802", "mode-0804", "mode-1427", "mode-1440", "mode-1442"} {
		t.Run(name, func(t *testing.T) {
			item := loadPinnedResidualCase(t, directory, suiteXSLT, "tests/attr/mode/_mode-test-set.xml", name)
			options := suiteOptions{
				kind: suiteXSLT, directory: directory, version: suiteVersion30,
				xsdVersion: suiteVersion10, timeout: time.Second, limitsProfile: "default",
			}
			original := evaluateResidualCase(t, options, item)
			if original.executionError() != nil || original.AssertionError == nil || !strings.Contains(original.AssertionError.Error(), `assertion "assert-warning" is not implemented`) {
				t.Fatal("the sole unsupported assertion must be the optional diagnostic", original.executionError(), original.AssertionError)
			}
			assertions := withoutXSLTResidualWarnings(item.node.child(suiteResultVariable))
			if err := checkSuiteAssertion(t.Context(), original.Evaluation, assertions); err != nil {
				t.Fatal("all unchanged output and xsl:message assertions must pass", err)
			}
			messages := original.Evaluation.result.Messages()
			wantMessages := 0
			if strings.HasPrefix(name, "mode-14") {
				wantMessages = 1
			}
			if len(messages) != wantMessages {
				t.Fatal("observable messages contain only the explicit xsl:message", messages)
			}
			raw, path := xsltResidualInputBytes(t, options, item)
			oracle, diagnostics := xsltResidualSaxonOriginal(t, options, item, original.Environment, raw, path)
			if !bytes.Contains(diagnostics, []byte("Ambiguous rule match")) && !bytes.Contains(diagnostics, []byte("No user-defined template")) {
				t.Fatal("the independent positive control must observe the requested warning", string(diagnostics))
			}
			source, _, err := suiteStylesheetSource(options, original.Environment)
			if err != nil {
				t.Fatal(err)
			}
			noWarning := regexp.MustCompile(`warning-on-(multiple|no)-match="[^"]*"`).ReplaceAll(source, []byte(`warning-on-$1-match="no"`))
			if bytes.Equal(source, noWarning) {
				t.Fatal("the diagnostic control must change the requested warning attribute")
			}
			controlledPath := filepath.Join(t.TempDir(), "no-warning.xsl")
			if err := os.WriteFile(controlledPath, noWarning, 0o600); err != nil {
				t.Fatal(err)
			}
			controlled, controlledDiagnostics := xsltResidualSaxonOriginal(t, options, item, original.Environment, raw, path, "-xsl:"+controlledPath)
			if bytes.Contains(controlledDiagnostics, []byte("Ambiguous rule match")) || bytes.Contains(controlledDiagnostics, []byte("No user-defined template")) {
				t.Fatal("the independent warning-off control must suppress only the optional diagnostic", string(controlledDiagnostics))
			}
			if !bytes.Equal(oracle, controlled) {
				t.Fatal("optional warning selection must not change the transformation output", string(oracle), string(controlled))
			}
			actual, err := original.Evaluation.serialized(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(xsltResidualXMLTokens(t, actual, false, true), xsltResidualXMLTokens(t, oracle, false, true)) {
				t.Fatal("suppressing optional diagnostics must retain the same result", string(actual), string(oracle))
			}
		})
	}
}

func xsltResidualEngine(t *testing.T, options suiteOptions, environment *preparedSuiteEnvironment, resolver transform.Resolver, packages transform.PackageResolver, functions []transform.Function) {
	t.Helper()
	xsltResidualEngineWithLimits(t, options, environment, suiteLimits(options), resolver, packages, functions)
}

func xsltResidualEngineWithLimits(t *testing.T, options suiteOptions, environment *preparedSuiteEnvironment, limits transform.Limits, resolver transform.Resolver, packages transform.PackageResolver, functions []transform.Function) {
	t.Helper()
	engine, err := transform.NewEngine(transform.Config{
		Limits: limits, XMLSchemaVersion: suiteXSDVersion(options),
		EnableXSLTAssertions: options.xsltAssertions, AllowSingleByteEncodings: true,
		Resolver: resolver, CollectionResolver: environment.resources, PackageResolver: packages, Functions: functions,
	})
	if err != nil {
		t.Fatal(err)
	}
	environment.engine = engine
}

func runXSLTResidualOptionalLibraries(t *testing.T, directory string) {
	t.Helper()
	for _, name := range []string{"docbook-001", "docbook-002"} {
		t.Run(name, func(t *testing.T) {
			item := loadPinnedResidualCase(t, directory, suiteXSLT, "tests/misc/docbook/_docbook-test-set.xml", name)
			options := suiteOptions{
				kind: suiteXSLT, directory: directory, version: suiteVersion30,
				xsdVersion: suiteVersion10, timeout: time.Second, limitsProfile: "default",
			}
			original := evaluateResidualCase(t, options, item)
			want := ""
			if name == "docbook-001" {
				want = "XTDE1425"
			}
			if residualErrorCode(original.executionError()) != want || original.AssertionError == nil {
				t.Fatal("original unavailable optional EXSLT profile", original.executionError(), original.AssertionError)
			}
			environment, err := prepareSuiteEnvironment(t.Context(), options, item)
			if err != nil {
				t.Fatal(err)
			}
			calls := 0
			functions := []transform.Function{{
				Name: transform.Name{Space: "http://exslt.org/common", Local: "node-set"}, Arity: 1,
				Call: func(ctx context.Context, arguments []transform.Sequence) (transform.Sequence, error) {
					calls++
					return arguments[0], ctx.Err()
				},
			}}
			xsltResidualEngine(t, options, environment, environment.resources, environment.resources, functions)
			controlled := evaluateSuiteCase(t.Context(), options, item, environment)
			if name == "docbook-001" {
				if residualErrorCode(controlled.err) != "XTMM9000" || !strings.Contains(controlled.err.Error(), "Can't make chunks") {
					t.Fatal("after supplying node-set, the next absent optional feature must be the stylesheet's explicit chunk writer", controlled.err)
				}
				const before = "<xsl:message terminate=\"yes\">\n        <xsl:text>Can't make chunks with </xsl:text>\n        <xsl:value-of select=\"system-property('xsl:vendor')\"/>\n        <xsl:text>'s processor.</xsl:text>\n      </xsl:message>"
				const after = `<xsl:result-document href="{$filename}" method="{$method}" encoding="{$encoding}"><xsl:copy-of select="$content"/></xsl:result-document>`
				resolver := &xsltResidualModuleResolver{base: environment.resources, edits: map[string][]xsltResidualModuleEdit{"chunker.xsl": {{before, after}}}}
				xsltResidualEngine(t, options, environment, resolver, resolver, functions)
				controlled = evaluateSuiteCase(t.Context(), options, item, environment)
			}
			if err := checkSuiteAssertion(t.Context(), controlled, item.node.child(suiteResultVariable)); err != nil {
				t.Fatal("supplying only the actual EXSLT node-set extension must satisfy the unchanged publisher assertion", controlled.err, err)
			}
			if calls == 0 {
				t.Fatal("the supplied extension must be exercised")
			}
			raw, sourcePath := xsltResidualInputBytes(t, options, item)
			var oracle []byte
			if name == "docbook-001" {
				binary, err := exec.LookPath("xsltproc")
				if err != nil {
					t.Fatal("the independent EXSLT-enabled libxslt executable is required", err)
				}
				_, main, err := readSuiteReferencedFile(options.directory, environment.stylesheet.base, environment.stylesheet.node)
				if err != nil {
					t.Fatal(err)
				}
				directory := t.TempDir()
				output := filepath.Join(directory, "result.xml")
				command := exec.CommandContext(t.Context(), binary, "--nonet", "--output", output, main, sourcePath)
				command.Dir = directory
				if diagnostics, err := command.CombinedOutput(); err != nil {
					t.Fatal("independent optional EXSLT provider", err, string(diagnostics))
				}
				oracle, err = os.ReadFile(output)
				if err != nil {
					t.Fatal(err)
				}
			} else {
				oracle, _ = xsltResidualSaxonOriginal(t, options, item, environment, raw, sourcePath)
			}
			// generate-id() spelling is implementation dependent. Compare the
			// complete publisher contract (root, element and attribute counts),
			// without asserting equality of those generated identifier strings.
			parsed, err := environment.query(t.Context(), `parse-xml($oracle)`, transform.Bindings{{Local: "oracle"}: transform.Values(transform.String(string(oracle)))})
			if err != nil {
				t.Fatal(err)
			}
			oracleEvaluation := *controlled
			oracleEvaluation.sequence = parsed
			if err := checkSuiteAssertion(t.Context(), &oracleEvaluation, item.node.child(suiteResultVariable)); err != nil {
				t.Fatal("the independent optional extension provider must satisfy the complete unchanged publisher contract", err)
			}
		})
	}
}

type xsltResidualModuleEdit struct {
	before string
	after  string
}

type xsltResidualModuleResolver struct {
	base  *suiteResourceResolver
	edits map[string][]xsltResidualModuleEdit
}

func (r *xsltResidualModuleResolver) replace(uri string, raw []byte) ([]byte, error) {
	parsed, err := url.Parse(uri)
	if err != nil {
		return nil, err
	}
	for _, edit := range r.edits[filepath.Base(parsed.Path)] {
		if !bytes.Contains(raw, []byte(edit.before)) {
			return nil, fmt.Errorf("pinned secondary module %s no longer contains %q", uri, edit.before)
		}
		raw = bytes.ReplaceAll(raw, []byte(edit.before), []byte(edit.after))
	}
	return raw, nil
}

func (r *xsltResidualModuleResolver) Resolve(ctx context.Context, uri string) (io.ReadCloser, error) {
	reader, err := r.base.Resolve(ctx, uri)
	if err != nil {
		return nil, err
	}
	raw, readErr := io.ReadAll(reader)
	closeErr := reader.Close()
	if err := errors.Join(readErr, closeErr); err != nil {
		return nil, err
	}
	raw, err = r.replace(uri, raw)
	return io.NopCloser(bytes.NewReader(raw)), err
}

func (r *xsltResidualModuleResolver) ResolvePackage(ctx context.Context, name, version string) (transform.PackageResource, error) {
	resource, err := r.base.ResolvePackage(ctx, name, version)
	if err != nil {
		return resource, err
	}
	raw, readErr := io.ReadAll(resource.Reader)
	closeErr := resource.Reader.Close()
	if err := errors.Join(readErr, closeErr); err != nil {
		return transform.PackageResource{}, err
	}
	raw, err = r.replace(resource.BaseURI, raw)
	resource.Reader = io.NopCloser(bytes.NewReader(raw))
	return resource, err
}

func runXSLTResidualPackageCorrections(t *testing.T, directory string) {
	t.Helper()
	for _, name := range []string{"package-021err", "package-022err"} {
		t.Run(name, func(t *testing.T) {
			item := loadPinnedResidualCase(t, directory, suiteXSLT, "tests/decl/package/_package-test-set.xml", name)
			options := suiteOptions{
				kind: suiteXSLT, directory: directory, version: suiteVersion30,
				xsdVersion: suiteVersion10, timeout: time.Second, limitsProfile: "default",
			}
			original := evaluateResidualCase(t, options, item)
			if residualErrorCode(original.executionError()) != "XTSE0020" || original.AssertionError == nil {
				t.Fatal("the invalid secondary module attribute must fail before component conflicts", original.executionError(), original.AssertionError)
			}
			environment, err := prepareSuiteEnvironment(t.Context(), options, item)
			if err != nil {
				t.Fatal(err)
			}
			edits := map[string][]xsltResidualModuleEdit{}
			if name == "package-021err" {
				edits[name+"-used.xsl"] = []xsltResidualModuleEdit{{`name="me:function1#0"`, `name="me:function1"`}, {`name="me:function2#0"`, `name="me:function2"`}}
			} else {
				edits[name+"-includeC.xsl"] = []xsltResidualModuleEdit{{`component="function#0"`, `component="function"`}}
			}
			resolver := &xsltResidualModuleResolver{base: environment.resources, edits: edits}
			xsltResidualEngine(t, options, environment, resolver, resolver, nil)
			controlled := evaluateSuiteCase(t.Context(), options, item, environment)
			if err := checkSuiteAssertion(t.Context(), controlled, item.node.child(suiteResultVariable)); err != nil {
				t.Fatal("correcting only malformed secondary attributes must expose the unchanged component-conflict assertion", controlled.err, err)
			}
		})
	}
}

func runXSLTResidualTypeProfiles(t *testing.T, directory string) {
	t.Helper()
	for _, test := range []struct {
		name      string
		version   string
		before    string
		after     string
		assertion string
	}{
		{"type-available-0148", suiteVersion20, `xmlns:xs="http://www.w3.org/2001/XMLSchema"`, `xmlns:xs="urn:unavailable-schema"`, `count(/out/*)=7 and (every $v in /out/* satisfies $v='true')`},
		{"type-available-0151", suiteVersion30, `'Q{http://www.w3.org/2001/XMLSchema}'`, `'Q{urn:unavailable-schema}'`, `/out/a='true'`},
	} {
		t.Run(test.name, func(t *testing.T) {
			item := loadPinnedResidualCase(t, directory, suiteXSLT, "tests/fn/type-available/_type-available-test-set.xml", test.name)
			options := suiteOptions{
				kind: suiteXSLT, directory: directory, version: test.version,
				xsdVersion: suiteVersion10, timeout: time.Second, limitsProfile: "default",
			}
			original := evaluateResidualCase(t, options, item)
			if original.executionError() != nil || original.AssertionError == nil {
				t.Fatal("the optional imported builtin profile must differ only in availability", original.executionError(), original.AssertionError)
			}
			value, err := original.Evaluation.assertionValue(t.Context(), test.assertion, nil)
			if err != nil || residualSequenceText(t, value) != suiteTrue {
				t.Fatal("all exact optional types in the pinned fixture must be available", value, err)
			}
			controlled := evaluateXSLTResidualSourceVariant(t, options, item, test.before, test.after)
			if controlled.executionError() != nil || controlled.AssertionError != nil {
				t.Fatal("unimported namespace control must satisfy the unchanged false-availability assertion", controlled.executionError(), controlled.AssertionError)
			}
			raw, sourcePath := []byte("<dummy/>"), ""
			if original.Environment.document != nil {
				raw, sourcePath = xsltResidualInputBytes(t, options, item)
			}
			oracle, _ := xsltResidualSaxonOriginal(t, options, item, original.Environment, raw, sourcePath)
			actual, err := original.Evaluation.serialized(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			if test.name == "type-available-0148" {
				minimum, err := controlled.Evaluation.serialized(t.Context())
				if err != nil || !slices.Equal(xsltResidualXMLTokens(t, minimum, false, true), xsltResidualXMLTokens(t, oracle, false, true)) {
					t.Fatal("the independent 2.0 Basic processor must reproduce the publisher's minimum imported-type profile", err)
				}
				// The 3.0 processor imports additional built-in schema types even
				// for this unchanged version=2.0 module. Both profiles are allowed;
				// Basic conformance does not require the minimum-only registry.
				modern := options
				modern.version = suiteVersion30
				oracle, _ = xsltResidualSaxonOriginal(t, modern, item, original.Environment, raw, sourcePath)
			}
			if !slices.Equal(xsltResidualXMLTokens(t, actual, false, true), xsltResidualXMLTokens(t, oracle, false, true)) {
				t.Fatal("the independent builtin profile must confirm the exact optional type availability", string(actual), string(oracle))
			}
		})
	}
}

func runXSLTResidualPriming(t *testing.T, directory string) {
	t.Helper()
	t.Run("error-0610d", func(t *testing.T) {
		item := loadPinnedResidualCase(t, directory, suiteXSLT, "tests/misc/error/_error-test-set.xml", "error-0610d")
		options := suiteOptions{
			kind: suiteXSLT, directory: directory, version: suiteVersion30,
			xsdVersion: suiteVersion10, timeout: time.Second, limitsProfile: "default",
		}
		original := evaluateResidualCase(t, options, item)
		if residualErrorCode(original.executionError()) != "XTDE0050" || original.AssertionError == nil {
			t.Fatal("missing implicitly mandatory global parameter must fail priming", original.executionError(), original.AssertionError)
		}
		controlled := item
		controlled.node = cloneResidualNode(item.node)
		controlled.node.child("test").Children = append(controlled.node.child("test").Children, &suiteNode{XMLName: xml.Name{Local: suiteParam}, Attributes: []xml.Attr{{Name: xml.Name{Local: "name"}, Value: "records"}, {Name: xml.Name{Local: "select"}, Value: "1"}}})
		result := evaluateResidualCase(t, options, controlled)
		if result.executionError() != nil {
			t.Fatal("supplying the missing global parameter must allow execution", result.executionError())
		}
		secondary := result.Evaluation.result.Secondary()
		if len(secondary) != 1 {
			t.Fatal("one requested secondary document", secondary)
		}
		for uri, output := range secondary {
			if !strings.HasSuffix(uri, "/1.xml") {
				t.Fatal("global parameter must determine the output URI", uri)
			}
			value, err := result.Environment.query(t.Context(), `count($output/booklist/book)=1 and $output/booklist/book/@title='Dune'`, transform.Bindings{{Local: "output"}: output})
			if err != nil || residualSequenceText(t, value) != suiteTrue {
				t.Fatal("the supplied parameter must determine the exact generated content", value, err)
			}
		}
	})
}

func runXSLTResidualEvaluateLibrary(t *testing.T, directory string) {
	t.Helper()
	t.Run("evaluate-048", func(t *testing.T) {
		item := loadPinnedResidualCase(t, directory, suiteXSLT, "tests/insn/evaluate/_evaluate-test-set.xml", "evaluate-048")
		options := suiteOptions{
			kind: suiteXSLT, directory: directory, version: suiteVersion30,
			xsdVersion: suiteVersion10, timeout: time.Second, limitsProfile: "default",
		}
		original := evaluateResidualCase(t, options, item)
		if residualErrorCode(original.executionError()) != "XPTY0004" || original.AssertionError == nil {
			t.Fatal("invoking the absent optional fn:document must fail as an empty function target", original.executionError(), original.AssertionError)
		}
		query := `exists(function-lookup(QName('http://www.w3.org/2005/xpath-functions','document'),1))`
		controlled := item
		controlled.node = cloneResidualNode(item.node)
		setParameter := func(expression string) {
			controlled.node.child("test").Children = []*suiteNode{
				cloneResidualNode(item.node.child("test").child("stylesheet")),
				{XMLName: xml.Name{Local: suiteParam}, Attributes: []xml.Attr{{Name: xml.Name{Local: "name"}, Value: "p"}, {Name: xml.Name{Local: "select"}, Value: strconv.Quote(expression)}}},
			}
		}
		setParameter(query)
		absence := evaluateXSLTResidualVariant(t, options, controlled)
		if absence.executionError() != nil || residualSequenceText(t, absence.Evaluation.sequence) != "false" {
			t.Fatal("lookup alone must prove absence without a remote resource attempt", absence.executionError())
		}
		if got := residualSaxonQuery(t, query, ""); got != "false" {
			t.Fatal("the independent standard XPath library must permit the same absence", got)
		}
		uri := suiteFileURI(filepath.Join(item.base, "evaluate-048.xsl"))
		standard := `function-lookup(QName('http://www.w3.org/2005/xpath-functions','doc'),1)('` + uri + `')`
		setParameter(standard)
		available := evaluateXSLTResidualVariant(t, options, controlled)
		if available.executionError() != nil {
			t.Fatal("the required fn:doc with an explicitly supplied local file must be usable", available.executionError())
		}
		value, err := available.Evaluation.assertionValue(t.Context(), `exists(/out/Q{http://www.w3.org/1999/XSL/Transform}stylesheet)`, nil)
		if err != nil || residualSequenceText(t, value) != suiteTrue || residualSaxonQuery(t, `exists((`+standard+`)/Q{http://www.w3.org/1999/XSL/Transform}stylesheet)`, "") != suiteTrue {
			t.Fatal("the independent required-library positive control", value, err)
		}
	})
}

func runXSLTResidualJSONTyping(t *testing.T, directory string) {
	t.Helper()
	t.Run("json-to-xml-typed-010", func(t *testing.T) {
		item := loadPinnedResidualCase(t, directory, suiteXSLT, "tests/fn/json-to-xml/_json-to-xml-test-set.xml", "json-to-xml-typed-010")
		options := suiteOptions{
			kind: suiteXSLT, directory: directory, version: suiteVersion30,
			xsdVersion: suiteVersion10, timeout: time.Second, limitsProfile: "default",
		}
		original := evaluateResidualCase(t, options, item)
		if residualErrorCode(original.executionError()) != "XTSE1650" || original.AssertionError == nil {
			t.Fatal("the unconditional schema import must be rejected by the Basic processor", original.executionError(), original.AssertionError)
		}
		withoutPSVI := func(raw []byte) []byte {
			importSchema := []byte(`<xsl:import-schema namespace="http://www.w3.org/2005/xpath-functions"/>`)
			if bytes.Count(raw, importSchema) != 1 {
				t.Fatal("the exact schema prerequisite must occur once")
			}
			raw = bytes.Replace(raw, importSchema, nil, 1)
			// The typed tests elsewhere in this shared stylesheet are also
			// schema-aware prerequisites. Preserve all names and expressions,
			// removing only their optional PSVI annotations.
			annotations := regexp.MustCompile(`element\((j:[A-Za-z]+),[^)]+\)`)
			return annotations.ReplaceAll(raw, []byte(`element($1)`))
		}
		controlled := evaluateXSLTResidualSourceEdit(t, options, item, withoutPSVI)
		if residualErrorCode(controlled.executionError()) != "FOJS0004" {
			t.Fatal("after removing only static schema prerequisites, the selected FO3.1 validate=true call must reject unavailable typed data", controlled.executionError())
		}
		const minimal = `<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="3.0"><xsl:template name="start"><xsl:sequence select="json-to-xml('{}',map{'validate':true()})"/></xsl:template></xsl:stylesheet>`
		call := `transform(map{'stylesheet-text':'` + strings.ReplaceAll(minimal, "'", "''") + `','initial-template':QName('','start'),'delivery-format':'raw'})`
		if got := residualSaxonQuery(t, `try { `+call+` } catch * { local-name-from-QName($err:code) }`, ""); got != "FOJS0004" {
			t.Fatal("independent direct XSLT3.0 selected-library JSON validation error", got)
		}
		nonvalidating := evaluateXSLTResidualSourceEdit(t, options, item, func(raw []byte) []byte {
			return bytes.Replace(withoutPSVI(raw), []byte(`map{'validate':true()}`), []byte(`map{'validate':false()}`), 1)
		})
		if nonvalidating.executionError() != nil || residualSequenceText(t, nonvalidating.Evaluation.sequence) != suiteTrue {
			t.Fatal("the same untyped JSON structure without validation must be accepted", nonvalidating.executionError())
		}
		if got := residualSaxonQuery(t, `local-name(json-to-xml('{}',map{'validate':false()})/*)`, ""); got != "map" {
			t.Fatal("independent nonvalidating JSON positive control", got)
		}
	})
}

func runXSLTResidualNumberProfiles(t *testing.T, directory string) {
	t.Helper()
	t.Run("number-0111", func(t *testing.T) {
		item := loadPinnedResidualCase(t, directory, suiteXSLT, "tests/insn/number/_number-test-set.xml", "number-0111")
		options := suiteOptions{
			kind: suiteXSLT, directory: directory, version: suiteVersion30,
			xsdVersion: suiteVersion10, timeout: time.Second, limitsProfile: "default",
		}
		original := evaluateResidualCase(t, options, item)
		if original.executionError() != nil || original.AssertionError == nil {
			t.Fatal("the exact large-integer publisher expectation must differ only as a value", original.executionError(), original.AssertionError)
		}
		const expected = "[1:881676371:789154819:525050370(1:881676371:789154819:525050369)(١:٨٨١٦٧٦٣٧١:٧٨٩١٥٤٨١٩:٥٢٥٠٥٠٣٦٨)]"
		if got := residualSequenceText(t, original.Evaluation.sequence); got != expected {
			t.Fatal("published REC number() conversion and start-at rebasing vector", got)
		}
		formula := `let $big:=1234567890,$huge:=$big*$big*$big return string-join(for $i in 1 to 3 return string(xs:integer(round(number($huge+$i)))+3-$i),'|')`
		if got := residualSaxonQuery(t, formula, ""); got != "1881676371789154819525050370|1881676371789154819525050369|1881676371789154819525050368" {
			t.Fatal("independent execution of the exact published conversion formula", got)
		}
		controlled := evaluateXSLTResidualSourceVariant(t, options, item, `select="1234567890"`, `select="10"`)
		if controlled.executionError() != nil || residualSequenceText(t, controlled.Evaluation.sequence) != "[1003(1003)(١٠٠٣)]" {
			t.Fatal("below the binary precision boundary all three supplied numbers must agree", controlled.executionError(), residualSequenceText(t, controlled.Evaluation.sequence))
		}
		raw, _, err := suiteStylesheetSource(options, original.Environment)
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(t.TempDir(), "bounded-number.xsl")
		if err := os.WriteFile(path, bytes.Replace(raw, []byte(`select="1234567890"`), []byte(`select="10"`), 1), 0o600); err != nil {
			t.Fatal(err)
		}
		oracle, _ := xsltResidualSaxonOriginal(t, options, item, original.Environment, []byte("<dummy/>"), "", "-xsl:"+path)
		if !slices.Equal(xsltResidualXMLTokens(t, []byte("<out>[1003(1003)(١٠٠٣)]</out>"), false, true), xsltResidualXMLTokens(t, oracle, false, true)) {
			t.Fatal("independent xsl:number below the binary precision boundary", string(oracle))
		}
	})
	t.Run("number-0902", func(t *testing.T) {
		item := loadPinnedResidualCase(t, directory, suiteXSLT, "tests/insn/number/_number-test-set.xml", "number-0902")
		options := suiteOptions{
			kind: suiteXSLT, directory: directory, version: suiteVersion30,
			xsdVersion: suiteVersion10, timeout: time.Second, limitsProfile: "default",
		}
		original := evaluateResidualCase(t, options, item)
		if original.executionError() != nil || original.AssertionError == nil {
			t.Fatal("the exact Greek-alphabet publisher vector must differ as a value", original.executionError(), original.AssertionError)
		}
		actual, err := original.Evaluation.assertionValue(t.Context(), `serialize($result,map{'method':'xml','omit-xml-declaration':true(),'indent':false()})`, nil)
		if err != nil {
			t.Fatal(err)
		}
		rawInput, sourcePath := xsltResidualInputBytes(t, options, item)
		oracle, _ := xsltResidualSaxonOriginal(t, options, item, original.Environment, rawInput, sourcePath)
		actualText, oracleText := residualSequenceText(t, actual), string(oracle)
		withoutGreek := func(raw string) []string {
			tokens := xsltResidualXMLTokens(t, []byte(raw), false, true)
			for i, token := range tokens {
				if strings.HasPrefix(token, "T") {
					tokens[i] = strings.Map(func(r rune) rune {
						if r >= 'α' && r <= 'ω' {
							return -1
						}
						return r
					}, token)
				}
			}
			return tokens
		}
		if !slices.Equal(withoutGreek(actualText), withoutGreek(oracleText)) {
			t.Fatal("the exact original engines may differ only in implementation-defined Greek numbering glyphs")
		}
		text := residualSequenceText(t, original.Evaluation.sequence)
		for _, fragment := range []string{"σrrr", "τsss", "ωxxx", "ααyyy"} {
			if !strings.Contains(text, fragment) {
				t.Fatal("the declared 24-letter Greek alphabet vector", fragment)
			}
		}
		controlled := evaluateXSLTResidualSourceVariant(t, options, item, `format="&#x03b1;"`, `format="1"`)
		if controlled.executionError() != nil {
			t.Fatal(controlled.executionError())
		}
		source, _, err := suiteStylesheetSource(options, original.Environment)
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(t.TempDir(), "decimal-number.xsl")
		if err := os.WriteFile(path, bytes.Replace(source, []byte(`format="&#x03b1;"`), []byte(`format="1"`), 1), 0o600); err != nil {
			t.Fatal(err)
		}
		decimalOracle, _ := xsltResidualSaxonOriginal(t, options, item, original.Environment, rawInput, sourcePath, "-xsl:"+path)
		decimalNative, err := controlled.Evaluation.assertionValue(t.Context(), `serialize($result,map{'method':'xml','omit-xml-declaration':true(),'indent':false()})`, nil)
		if err != nil || !slices.Equal(xsltResidualXMLTokens(t, []byte(residualSequenceText(t, decimalNative)), false, true), xsltResidualXMLTokens(t, decimalOracle, false, true)) {
			t.Fatal("changing only the optional numbering alphabet to mandatory decimal must yield exact agreement", err)
		}
	})
}
