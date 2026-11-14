package xslt //nolint:testpackage // Exercises accumulator phase and mode semantics.

import "testing"

func TestAccumulatorPhasesRespectModeAndDocumentOrder(t *testing.T) {
	t.Parallel()
	ss := compileTestStylesheet(t, `
		<xsl:mode name="account" use-accumulators="count"/>
		<xsl:accumulator name="count" as="xs:integer" initial-value="0">
			<xsl:accumulator-rule match="n" select="$value + 1"/>
			<xsl:accumulator-rule match="n" phase="end" select="$value + 10"/>
		</xsl:accumulator>
		<xsl:template match="n" mode="account">
			<xsl:value-of select="accumulator-before('count') || '/' || accumulator-after('count') || ';'"/>
		</xsl:template>`, `<xsl:apply-templates select="r/n" mode="account"/>`)
	for _, tc := range []struct {
		input, want string
	}{
		{`<r><n/><n/><n/></r>`, "1/11;12/22;23/33;"},
		{`<r><n/></r>`, "1/11;"},
	} {
		got, err := ss.Transform(parseTestDocument(t, tc.input)).Serialize(t.Context())
		requireSerialization(t, got, err, tc.want, "")
	}
}
