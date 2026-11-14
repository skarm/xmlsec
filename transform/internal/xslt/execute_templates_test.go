package xslt //nolint:testpackage // Exercises template selection and binding through local stylesheets.

import "testing"

func TestTemplateDispatchHandlesMultipleMatches(t *testing.T) {
	t.Parallel()

	const first = `<xsl:template match="n[@a]" mode="m" priority="1">first</xsl:template>`
	for _, tc := range []struct {
		name, policy, second, want, code string
	}{
		{"last_rule_wins", "use-last", `<xsl:template match="n[@b]" mode="m" priority="1">second</xsl:template>`, "second", ""},
		{"equal_priority_matches_conflict", "fail", `<xsl:template match="n[@b]" mode="m" priority="1">second</xsl:template>`, "", "XTDE0540"},
		{"equal_priority_nonmatching_rule_is_ignored", "fail", `<xsl:template match="n[@c]" mode="m" priority="1">second</xsl:template>`, "first", ""},
		{"lower_priority_does_not_conflict", "fail", `<xsl:template match="n[@b]" mode="m" priority="0">second</xsl:template>`, "first", ""},
		{"union_branches_of_one_rule_do_not_conflict", "fail", `<xsl:template match="n[@a] | n[@b]" mode="m" priority="1">union</xsl:template>`, "union", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			rules := tc.second
			if tc.name != "union_branches_of_one_rule_do_not_conflict" {
				rules = first + rules
			}
			ss := compileTestStylesheet(t, `<xsl:mode name="m" on-multiple-match="`+tc.policy+`"/>`+rules,
				`<xsl:apply-templates select="r/n" mode="m"/>`)
			got, err := ss.Transform(parseTestDocument(t, `<r><n a="1" b="1"/></r>`)).Serialize(t.Context())
			requireSerialization(t, got, err, tc.want, tc.code)
		})
	}
}

func TestAtomicTemplateDispatchHandlesMultipleMatches(t *testing.T) {
	t.Parallel()

	const first = `<xsl:template match=".[. instance of xs:integer]" mode="m" priority="1">integer</xsl:template>`
	for _, tc := range []struct {
		name, second, want, code string
	}{
		{"equal_priority_matches_conflict", `<xsl:template match=".[. gt 0]" mode="m" priority="1">positive</xsl:template>`, "", "XTDE0540"},
		{"equal_priority_nonmatching_rule_is_ignored", `<xsl:template match=".[. lt 0]" mode="m" priority="1">negative</xsl:template>`, "integer", ""},
		{"lower_priority_does_not_conflict", `<xsl:template match=".[. gt 0]" mode="m" priority="0">positive</xsl:template>`, "integer", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ss := compileTestStylesheet(t, `<xsl:mode name="m" on-multiple-match="fail"/>`+first+tc.second,
				`<xsl:apply-templates select="7" mode="m"/>`)
			got, err := ss.Transform(parseTestDocument(t, `<r/>`)).Serialize(t.Context())
			requireSerialization(t, got, err, tc.want, tc.code)
		})
	}
}

func TestApplyTemplatesBindsParameters(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name, selectItems, rule, params, applyParams, value, want, code string
	}{
		{"node_select_default_uses_matched_node", "r/n", "n", `<xsl:param name="p" select="@label"/>`, "", "$p", "node", ""},
		{"atomic_select_default_uses_matched_item", "7", ".[. instance of xs:integer]", `<xsl:param name="p" as="xs:integer" select=". + 1"/>`, "", "$p", "8", ""},
		{"untyped_body_default_builds_document", "r/n", "n", `<xsl:param name="p"><part>body</part></xsl:param>`, "", "$p/part", "body", ""},
		{"typed_body_default_keeps_atomic_items", "r/n", "n", `<xsl:param name="p" as="xs:integer+"><xsl:sequence select="(2,3)"/></xsl:param>`, "", "sum($p)", "5", ""},
		{"tunnel_parameter_overrides_default", "r/n", "n", `<xsl:param name="p" tunnel="yes" select="'default'"/>`, `<xsl:with-param name="p" tunnel="yes" select="'caller'"/>`, "$p", "caller", ""},
		{"ordinary_parameter_does_not_override_tunnel_default", "r/n", "n", `<xsl:param name="p" tunnel="yes" select="'default'"/>`, `<xsl:with-param name="p" select="'caller'"/>`, "$p", "default", ""},
		{"missing_required_parameter", "r/n", "n", `<xsl:param name="p" required="yes"/>`, "", "$p", "", "XTDE0700"},
		{"caller_value_must_match_declared_type", "r/n", "n", `<xsl:param name="p" as="xs:integer" select="1"/>`, `<xsl:with-param name="p" select="'invalid'"/>`, "$p", "", "XTTE0590"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ss := compileTestStylesheet(t, `<xsl:template mode="m" match="`+tc.rule+`">`+tc.params+`<xsl:value-of select="`+tc.value+`"/></xsl:template>`,
				`<xsl:apply-templates select="`+tc.selectItems+`" mode="m">`+tc.applyParams+`</xsl:apply-templates>`)
			got, err := ss.Transform(parseTestDocument(t, `<r><n label="node"/></r>`)).Serialize(t.Context())
			requireSerialization(t, got, err, tc.want, tc.code)
		})
	}
}

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
