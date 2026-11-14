package xslt //nolint:testpackage // Exercises internal template dispatch.

import "testing"

func TestTemplateDispatchModes(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name, behavior, rules, want, code string
	}{
		{"text_only_copy", "text-only-copy", "", "AB", ""},
		{"shallow_skip_visits_descendants", "shallow-skip", `<xsl:template match="leaf" mode="m"><xsl:text>visited</xsl:text></xsl:template>`, "visited", ""},
		{"deep_skip_ignores_descendants", "deep-skip", `<xsl:template match="leaf" mode="m"><xsl:text>visited</xsl:text></xsl:template>`, "", ""},
		{"fail_without_rule", "fail", "", "", "XTDE0555"},
		{"next_match_uses_lower_priority", "fail", `<xsl:template match="root" mode="m" priority="2"><xsl:text>first:</xsl:text><xsl:next-match/></xsl:template><xsl:template match="root" mode="m" priority="1"><xsl:text>second</xsl:text></xsl:template>`, "first:second", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ss := compileTestStylesheet(t, `<xsl:mode name="m" on-no-match="`+tc.behavior+`"/>`+tc.rules, `<xsl:apply-templates select="root" mode="m"/>`)
			source := parseTestDocument(t, `<root>A<leaf>B</leaf></root>`)
			got, err := ss.Transform(source).Serialize(t.Context())
			requireSerialization(t, got, err, tc.want, tc.code)
		})
	}
}
