package xslt //nolint:testpackage // Exercises result-document state in the internal invocation.

import (
	"context"
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
