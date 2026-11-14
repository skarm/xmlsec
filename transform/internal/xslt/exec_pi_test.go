package xslt //nolint:testpackage // Exercises processing instruction construction.

import "testing"

func TestExecPI(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct{ name, body, want, code string }{
		{"computed_target_and_escaped_content", `<xsl:variable name="pi" as="processing-instruction()"><xsl:processing-instruction name="{r/@target}" select="'a?&gt;b?&gt;'"/></xsl:variable><xsl:value-of select="(name($pi),string($pi))" separator="|"/>`, "note|a? >b? >", ""},
		{"body_applies_simple_content_rules", `<xsl:variable name="pi" as="processing-instruction()"><xsl:processing-instruction name="note"><xsl:sequence select="('one',2,'three')"/></xsl:processing-instruction></xsl:variable><xsl:value-of select="$pi"/>`, "one 2 three", ""},
		{"target_must_be_ncname", `<xsl:processing-instruction name="{concat('p',':note')}"/>`, "", "XTDE0890"},
		{"xml_target_is_reserved_regardless_of_case", `<xsl:processing-instruction name="{concat('X','mL')}"/>`, "", "XTDE0890"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ss := compileTestStylesheet(t, "", tc.body)
			got, err := ss.Transform(parseTestDocument(t, `<r target="note"/>`)).Serialize(t.Context())
			requireSerialization(t, got, err, tc.want, tc.code)
		})
	}
}
