package xslt //nolint:testpackage // Exercises result-document state in the internal invocation.

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
)

func TestResultDocumentRollbackReleasesOutput(t *testing.T) {
	t.Parallel()
	const base = "https://output.example/run/main"
	for _, tc := range []struct{ name, href, wantPrimary, wantSecondary string }{
		{name: "principal", href: "", wantPrimary: "recovered"},
		{name: "secondary", href: ` href="side.txt"`, wantSecondary: "recovered"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			body := `<xsl:try>
				<xsl:result-document` + tc.href + `><xsl:text>discard</xsl:text><xsl:sequence select="error(QName('urn:unit','f:stop'))"/></xsl:result-document>
				<xsl:catch errors="f:stop"><xsl:result-document` + tc.href + `><xsl:text>recovered</xsl:text></xsl:result-document></xsl:catch>
			</xsl:try>`
			result, err := compileTestStylesheet(t, "", body).Transform(parseTestDocument(t, `<r/>`)).BaseOutputURI(base).Execute(t.Context())
			if err != nil {
				t.Fatalf("execute with retry after failed result document: %v", err)
			}
			var primary strings.Builder
			err = SerializeValue(t.Context(), &primary, result.Primary)
			requireSerialization(t, primary.String(), err, tc.wantPrimary, "")
			if tc.wantSecondary == "" {
				if len(result.Secondary) != 0 {
					t.Fatalf("secondary output count = %d, want none", len(result.Secondary))
				}
				return
			}
			const side = "https://output.example/run/side.txt"
			value, found := result.Secondary[side]
			if !found || len(result.Secondary) != 1 {
				t.Fatalf("secondary outputs = %v, want only %q", result.Secondary, side)
			}
			var secondary strings.Builder
			err = SerializeValue(t.Context(), &secondary, value)
			requireSerialization(t, secondary.String(), err, tc.wantSecondary, "")
		})
	}
}

func TestResultDocumentPreservesEmptyPathSegment(t *testing.T) {
	t.Parallel()

	const base = "https://example.test/a/b/main.xml"
	for _, tc := range []struct{ name, href string }{
		{"relative", "../..//report.txt"},
		{"absolute", "https://example.test/a/b/../..//report.txt"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			body := `<xsl:result-document href="` + tc.href + `"><xsl:text>double</xsl:text></xsl:result-document>
				<xsl:result-document href="../../report.txt"><xsl:text>single</xsl:text></xsl:result-document>`
			result, err := compileTestStylesheet(t, "", body).Transform(parseTestDocument(t, `<r/>`)).BaseOutputURI(base).Execute(t.Context())
			if err != nil {
				t.Fatal(err)
			}

			if len(result.Secondary) != 2 {
				t.Fatalf("output = %v; want two different secondary destinations", result.Secondary)
			}
			for uri, want := range map[string]string{
				"https://example.test//report.txt": "double",
				"https://example.test/report.txt":  "single",
			} {
				value, ok := result.Secondary[uri]
				if !ok {
					t.Fatalf("missing output URI %q", uri)
				}
				var output strings.Builder
				err := SerializeValue(t.Context(), &output, value)
				requireSerialization(t, output.String(), err, want, "")
			}
		})
	}
}

func TestTryNormalizesItemSeparatorOnlyAtCommit(t *testing.T) {
	t.Parallel()

	const prefix = `<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="3.0">
		<xsl:output method="xml" omit-xml-declaration="yes" item-separator="|"/><xsl:template match="/">`
	const suffix = `</xsl:template></xsl:stylesheet>`
	for _, tc := range []struct{ name, body, want string }{
		{"nodes", `<first/><xsl:try><middle/><last/><xsl:catch select="error()"/></xsl:try><end/>`, `<first/>|<middle/>|<last/>|<end/>`},
		{"atomics", `<xsl:sequence select="0"/><xsl:try select="(1,2)"><xsl:catch select="error()"/></xsl:try><xsl:sequence select="3"/>`, `0|1|2|3`},
		{"mixed", `<xsl:sequence select="0"/><xsl:try><xsl:sequence select="1"/><middle/><xsl:sequence select="2"/><xsl:catch select="error()"/></xsl:try><end/>`, `0|1|<middle/>|2|<end/>`},
		{"nested", `<first/><xsl:try><xsl:try><middle/><last/><xsl:catch select="error()"/></xsl:try><xsl:catch select="error()"/></xsl:try><end/>`, `<first/>|<middle/>|<last/>|<end/>`},
		{"rollback", `<first/><xsl:try><discard/><xsl:sequence select="error()"/><xsl:catch><recovered/></xsl:catch></xsl:try><end/>`, `<first/>|<recovered/>|<end/>`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ss, err := NewCompiler().Compile(t.Context(), parseTestDocument(t, prefix+tc.body+suffix))
			if err != nil {
				t.Fatal(err)
			}

			got, err := ss.Transform(parseTestDocument(t, `<r/>`)).Serialize(t.Context())
			requireSerialization(t, got, err, tc.want, "")
		})
	}
}

func TestResultDocumentInheritsAndOverridesAbsentItemSeparator(t *testing.T) {
	t.Parallel()
	const base = "https://output.example/run/"
	const declarations = `
		<xsl:output method="text" item-separator="#absent"/>
		<xsl:output name="side" method="text" item-separator="#absent"/>`
	const body = `
		<xsl:result-document item-separator="|">
			<xsl:sequence select="(2,3)"/>
		</xsl:result-document>
		<xsl:result-document href="absent.txt" format="side">
			<xsl:sequence select="(2,3)"/>
		</xsl:result-document>
		<xsl:result-document href="empty.txt" format="side" item-separator="">
			<xsl:sequence select="(2,3)"/>
		</xsl:result-document>
		<xsl:result-document href="absent-avt.txt" item-separator="{'#absent'}">
			<xsl:sequence select="(2,3)"/>
		</xsl:result-document>
		<xsl:result-document href="empty-avt.txt" item-separator="{''}">
			<xsl:sequence select="(2,3)"/>
		</xsl:result-document>`
	result, err := compileTestStylesheet(t, declarations, body).Transform(parseTestDocument(t, `<r/>`)).BaseOutputURI(base + "main.txt").Execute(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Secondary) != 4 {
		t.Fatalf("secondary output count = %d, want 4", len(result.Secondary))
	}
	for _, tc := range []struct {
		name, want string
		value      ValueResult
		absent     bool
	}{
		{"primary", "2|3", result.Primary, false},
		{"inherited absent", "2 3", result.Secondary[base+"absent.txt"], true},
		{"overridden with empty", "23", result.Secondary[base+"empty.txt"], false},
		{"overridden with absent AVT", "2 3", result.Secondary[base+"absent-avt.txt"], true},
		{"overridden with empty AVT", "23", result.Secondary[base+"empty-avt.txt"], false},
	} {
		if tc.value.Output == nil {
			t.Errorf("%s: missing output definition", tc.name)
			continue
		}
		if tc.value.Output.ItemSeparatorAbsent != tc.absent {
			t.Errorf("%s: explicit item-separator absence = %t, want %t", tc.name, tc.value.Output.ItemSeparatorAbsent, tc.absent)
		}
		var output strings.Builder
		err := SerializeValue(t.Context(), &output, tc.value)
		requireSerialization(t, output.String(), err, tc.want, "")
	}
}

func TestResultDocumentSerializationParameterCache(t *testing.T) {
	t.Parallel()
	const paramsURI = "https://styles.example/report/params.xml"
	const parameterDocument = `<serialization-parameters xmlns="http://www.w3.org/2010/xslt-xquery-serialization"><method value="text"/><item-separator value="|"/></serialization-parameters>`
	const body = `<xsl:for-each select="1 to 2">
		<xsl:result-document href="report-{.}.txt" method="xml" item-separator="," parameter-document="{'params.xml'}">
			<xsl:sequence select="(., . + 10)"/>
		</xsl:result-document>
	</xsl:for-each>`
	ss, err := NewCompiler().BaseURI("https://styles.example/report/main.xsl").Compile(t.Context(), stylesheetDocument(t, "", body))
	if err != nil {
		t.Fatal(err)
	}
	reader := &closeTrackingReader{reader: strings.NewReader(parameterDocument)}
	var opens int
	resolver := contractURIResolver(func(_ context.Context, uri string) (io.ReadCloser, error) {
		opens++
		if uri != paramsURI || opens != 1 {
			return nil, fmt.Errorf("parameter document opened %d times, last URI %q, want one open of %q", opens, uri, paramsURI)
		}
		return reader, nil
	})
	result, err := ss.Transform(parseTestDocument(t, `<r/>`)).BaseOutputURI("https://output.example/run/main").URIResolver(resolver).Execute(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if opens != 1 || reader.closed != 1 || len(result.Secondary) != 2 {
		t.Fatalf("parameter reader opened=%d, closed=%d, secondary count=%d, want 1, 1, 2", opens, reader.closed, len(result.Secondary))
	}
	for uri, want := range map[string]string{"https://output.example/run/report-1.txt": "1|11", "https://output.example/run/report-2.txt": "2|12"} {
		value, found := result.Secondary[uri]
		if !found || value.Output == nil || value.Output.Method != "text" {
			t.Fatalf("output definition at %q = %+v, found=%t, want text method from the parameter document", uri, value.Output, found)
		}
		var output strings.Builder
		if err := SerializeValue(t.Context(), &output, value); err != nil || output.String() != want {
			t.Errorf("serialized %q = %q, error=%v, want %q", uri, output.String(), err, want)
		}
	}
}

func TestExecResultDocumentOverridesNamedOutput(t *testing.T) {
	t.Parallel()
	const declarations = `<xsl:output name="f:report" method="text" media-type="text/plain"
		cdata-section-elements="f:title" omit-xml-declaration="yes"/>`
	const body = `
		<xsl:result-document href="report.xml" format="{'f:report'}" method="{'xml'}"
			standalone="{false()}" omit-xml-declaration="{false()}"
			encoding="{' UTF-8 '}" version="{' 1.0 '}" byte-order-mark="{true()}" indent="{false()}"
			media-type="{' application/xml '}" cdata-section-elements="{'f:title f:body'}"
			doctype-system="{'report.dtd'}" doctype-public="{'-//EXAMPLE//Report//EN'}">
			<report><f:title>A&amp;B</f:title><f:body>C&amp;D</f:body></report>
		</xsl:result-document>
		<xsl:result-document href="report.txt" format="f:report">plain</xsl:result-document>`
	const base = "https://output.example/results/"

	ss := compileTestStylesheet(t, declarations, body)
	result, err := ss.Transform(parseTestDocument(t, `<r/>`)).BaseOutputURI(base).Execute(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	xml, ok := result.Secondary[base+"report.xml"]
	if !ok || xml.Output == nil {
		t.Fatal("missing XML result or its output definition")
	}
	if xml.Output.MediaType != "application/xml" {
		t.Errorf("XML media type = %q, want application/xml", xml.Output.MediaType)
	}
	var out strings.Builder
	if err := SerializeValue(t.Context(), &out, xml); err != nil {
		t.Fatal(err)
	}
	const declaration = "\xef\xbb\xbf" + `<?xml version="1.0" encoding="UTF-8" standalone="no"?>`
	for _, want := range []string{
		declaration,
		`<!DOCTYPE report PUBLIC "-//EXAMPLE//Report//EN" "report.dtd">`,
		`<![CDATA[A&B]]>`,
		`<![CDATA[C&D]]>`,
	} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("serialized XML = %q, want segment %q", out.String(), want)
		}
	}
	txt, ok := result.Secondary[base+"report.txt"]
	if !ok || txt.Output == nil || txt.Output.Method != "text" || txt.Output.MediaType != "text/plain" {
		t.Fatalf("second result output = %+v, want original named text output", txt.Output)
	}
	out.Reset()
	err = SerializeValue(t.Context(), &out, txt)
	requireSerialization(t, out.String(), err, "plain", "")
}

func TestExecResultDocumentRejectsNestedJSONDuplicates(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct{ name, href string }{
		{name: "principal"},
		{name: "secondary", href: ` href="result.json"`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			body := `<xsl:try>
				<xsl:result-document` + tc.href + ` method="{'json'}" build-tree="{false()}" allow-duplicate-names="{false()}">
					<xsl:sequence select="map{'rows': [map{1: 'numeric', '1': 'string'}]}"/>
				</xsl:result-document>
				<xsl:catch xmlns:err="http://www.w3.org/2005/xqt-errors" errors="err:SERE0022">
					<xsl:result-document` + tc.href + ` method="{'json'}" build-tree="{false()}" allow-duplicate-names="{true()}">
						<xsl:sequence select="map{'rows': [map{1: 'numeric', '1': 'string'}]}"/>
					</xsl:result-document>
				</xsl:catch>
			</xsl:try>`
			const base = "https://output.example/results/"
			ss := compileTestStylesheet(t, "", body)
			result, err := ss.Transform(parseTestDocument(t, `<r/>`)).BaseOutputURI(base).Execute(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			value := result.Primary
			if tc.href != "" {
				var ok bool
				value, ok = result.Secondary[base+"result.json"]
				if !ok {
					t.Fatal("missing recovered secondary result")
				}
			}
			if value.Output == nil || !value.Output.AllowDuplicateNames {
				t.Fatal("expected the serialization settings from the recovery branch")
			}
			var out strings.Builder
			if err := SerializeValue(t.Context(), &out, value); err != nil {
				t.Fatal(err)
			}
			got := out.String()
			const numericFirst = `{"rows":[{"1":"numeric","1":"string"}]}`
			const stringFirst = `{"rows":[{"1":"string","1":"numeric"}]}`
			if got != numericFirst && got != stringFirst {
				t.Errorf("recovered JSON = %q, want both entries in %s", got, numericFirst)
			}
		})
	}
}

func TestPrincipalResultDocumentFormat(t *testing.T) {
	t.Parallel()
	const declarations = `
		<xsl:output method="xml" cdata-section-elements="r" omit-xml-declaration="yes"/>
		<xsl:output name="fmt" method="xml" omit-xml-declaration="yes"/>
		<xsl:output xmlns:o="urn:output" name="o:fmt" method="text"/>`
	for _, tc := range []struct {
		name, attr, want, code string
		static                 bool
	}{
		{"omitted", "", "<r><![CDATA[example]]></r>", "", false},
		{"named", ` format="fmt"`, "<r>example</r>", "", false},
		{"named with XML whitespace", ` format="&#x9;fmt "`, "<r>example</r>", "", false},
		{"named AVT with XML whitespace", ` format="{' fmt '}"`, "<r>example</r>", "", false},
		{"lexical QName", ` xmlns:o="urn:output" format="o:fmt"`, "example", "", false},
		{"lexical QName in AVT", ` xmlns:o="urn:output" format="{'o:fmt'}"`, "example", "", false},
		{"URIQualifiedName in AVT", ` format="Q{{urn:output}}fmt"`, "example", "", false},
		{"empty", ` format=""`, "", "XTDE1460", true},
		{"empty AVT", ` format="{''}"`, "", "XTDE1460", false},
		{"XML whitespace only", ` format="&#x9; "`, "", "XTDE1460", true},
		{"non-XML whitespace", ` format="&#xA0;fmt"`, "", "XTDE1460", false},
		{"non-XML whitespace in AVT", ` format="{concat(codepoints-to-string(160), 'fmt')}"`, "", "XTDE1460", false},
		{"unknown static prefix", ` format="missing:fmt"`, "", "XTSE0280", true},
		{"unknown prefix in AVT", ` format="{'missing:fmt'}"`, "", "XTDE0290", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			body := `<xsl:result-document` + tc.attr + `><r>example</r></xsl:result-document>`
			stylesheet := parseTestDocument(t, `<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="3.0">`+
				declarations+`<xsl:template match="/">`+body+`</xsl:template></xsl:stylesheet>`)
			ss, err := NewCompiler().Compile(t.Context(), stylesheet)
			if tc.static != (err != nil && errors.Is(err, ErrStaticError)) {
				t.Fatalf("compile error = %v, want static error = %t", err, tc.static)
			}
			if err != nil {
				requireSerialization(t, "", err, tc.want, tc.code)
				return
			}
			got, err := ss.Transform(parseTestDocument(t, `<source/>`)).Serialize(t.Context())
			requireSerialization(t, got, err, tc.want, tc.code)
		})
	}
}
