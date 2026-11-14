package xslt //nolint:testpackage // Exercises miscellaneous instructions through the internal compiler and invocation.

import "testing"

func TestAnalyzeStringSetsSegmentFocusAndRestoresOuterFocus(t *testing.T) {
	t.Parallel()
	const body = `<xsl:for-each select="r/n">
		<xsl:analyze-string select="string(.)" regex="([a-z])([0-9]+)">
			<xsl:matching-substring><xsl:value-of select="concat(position(), '/', last(), ':', regex-group(2), regex-group(1), '|')"/></xsl:matching-substring>
			<xsl:non-matching-substring><xsl:value-of select="concat(position(), '/', last(), ':', ., regex-group(1), '|')"/></xsl:non-matching-substring>
		</xsl:analyze-string>
		<xsl:value-of select="concat(position(), '/', last(), ':', @id, ';')"/>
	</xsl:for-each>`
	doc := parseTestDocument(t, `<r><n id="first">[a12-b3]</n><n id="second">abc</n></r>`)
	got, err := compileTestStylesheet(t, "", body).Transform(doc).Serialize(t.Context())
	requireSerialization(t, got, err, "1/5:[|2/5:12a|3/5:-|4/5:3b|5/5:]|1/2:first;1/1:abc|2/2:second;", "")
}

func TestAnalyzeStringEnforcesVersionAndRegexRules(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name, version, selectExpr, regex, flags, want, code string
	}{
		{name: "zero_length_matches_in_xslt_30", version: "3.0", selectExpr: "'é'", regex: "z*", want: "[]é[]"},
		{name: "zero_length_matches_rejected_in_xslt_20", version: "2.0", selectExpr: "'é'", regex: "z*", code: "XTDE1150"},
		{name: "quoted_regex_in_xslt_30", version: "3.0", selectExpr: "'a.b'", regex: ".", flags: "q", want: "a[.]b"},
		{name: "quoted_regex_rejected_in_xslt_20", version: "2.0", selectExpr: "'a.b'", regex: ".", flags: "q", code: "XTDE1145"},
		{name: "noncapturing_group_rejected_in_xslt_20", version: "2.0", selectExpr: "'a'", regex: "(?:a)", code: "XTDE1140"},
		{name: "empty_selection_in_xslt_30", version: "3.0", selectExpr: "()", regex: "z*"},
		{name: "empty_selection_rejected_in_xslt_20", version: "2.0", selectExpr: "()", regex: "z*", code: "XPTY0004"},
		{name: "multiple_values_are_rejected", version: "3.0", selectExpr: "('a', 'b')", regex: "a", code: "XPTY0004"},
		{name: "non_string_value_is_rejected", version: "3.0", selectExpr: "1", regex: "a", code: "XPTY0004"},
		{name: "invalid_flags_are_reported", version: "3.0", selectExpr: "'a'", regex: "a", flags: "j", code: "XTDE1145"},
		{name: "invalid_pattern_is_reported", version: "3.0", selectExpr: "'a'", regex: "[", code: "XTDE1140"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			body := `<xsl:analyze-string select="` + tc.selectExpr + `" regex="` + tc.regex + `" flags="` + tc.flags + `">
				<xsl:matching-substring><xsl:value-of select="concat('[', ., ']')"/></xsl:matching-substring>
				<xsl:non-matching-substring><xsl:value-of select="."/></xsl:non-matching-substring>
			</xsl:analyze-string>`
			sheet := stylesheetDocument(t, "", body)
			compiler := NewCompiler()
			if tc.version == "2.0" {
				compiler = compiler.ProcessorVersion(processorXSLT20)
			}
			ss, err := compiler.Compile(t.Context(), sheet)
			if err != nil {
				t.Fatalf("compile analyze-string: %v", err)
			}
			got, err := ss.Transform(parseTestDocument(t, `<r/>`)).Serialize(t.Context())
			requireSerialization(t, got, err, tc.want, tc.code)
		})
	}
}
