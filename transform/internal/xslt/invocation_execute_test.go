package xslt //nolint:testpackage // Exercises result documents at the invocation boundary.

import (
	"strings"
	"testing"
)

func TestInvocationDeliversDistinctResultDocuments(t *testing.T) {
	t.Parallel()
	const base = "https://output.example/jobs/main"
	const summaryURI = "https://output.example/jobs/reports/summary"
	const auditURI = "https://output.example/jobs/audit.json"
	ss := compileTestStylesheet(t, `<xsl:output name="summary" method="text" item-separator="|"/>`, `
		<xsl:value-of select="current-output-uri()"/>
		<xsl:result-document href="reports/summary" format="summary">
			<xsl:sequence select="(1,2,current-output-uri())"/>
		</xsl:result-document>
		<xsl:result-document href="audit.json" method="json" indent="no">
			<xsl:sequence select="[true(), 3]"/>
		</xsl:result-document>`)
	inv := ss.Transform(parseTestDocument(t, `<r/>`)).BaseOutputURI(base)
	result, err := inv.Execute(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Secondary) != 2 {
		t.Fatalf("secondary output count = %d, want 2", len(result.Secondary))
	}
	for _, tc := range []struct {
		name   string
		result ValueResult
		method string
		want   string
	}{
		{"primary", result.Primary, "text", base},
		{"summary", result.Secondary[summaryURI], "text", "1|2|" + summaryURI},
		{"audit", result.Secondary[auditURI], "json", "[true,3]"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if tc.result.Output == nil || tc.result.Output.Method != tc.method {
				t.Fatalf("output definition = %+v, want method %q", tc.result.Output, tc.method)
			}
			var output strings.Builder
			err := SerializeValue(t.Context(), &output, tc.result)
			requireSerialization(t, output.String(), err, tc.want, "")
		})
	}
}
