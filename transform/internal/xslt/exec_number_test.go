package xslt //nolint:testpackage // Exercises xsl:number through the internal stylesheet compiler.

import "testing"

func TestNumberSelectCountAndFrom(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct{ name, body, want, code string }{
		{"single_counts_matching_ancestors", `<xsl:for-each select="r/chapter/section/title"><xsl:number count="section" from="chapter" format="01"/><xsl:text>|</xsl:text></xsl:for-each>`, "01|02|01|", ""},
		{"multiple_counts_each_ancestor", `<xsl:for-each select="r/chapter/section/title"><xsl:number level="multiple" count="chapter|section" format="[I-01]"/></xsl:for-each>`, "[I-01][I-02][II-01]", ""},
		{"any_counts_across_branches", `<xsl:for-each select="r/chapter/section/title"><xsl:number level="any" count="title" from="r" start-at="10"/><xsl:text>|</xsl:text></xsl:for-each>`, "10|11|12|", ""},
		{"any_resets_at_from", `<xsl:for-each select="r/chapter/section/title"><xsl:number level="any" count="title" from="chapter"/><xsl:text>|</xsl:text></xsl:for-each>`, "1|2|1|", ""},
		{"selected_attribute_counts_in_its_chapter", `<xsl:number select="r/chapter[2]/@id" level="any" count="@id" from="chapter"/>`, "1", ""},
		{"no_matching_ancestor_produces_no_number", `<xsl:number select="r/chapter[1]/section[1]" count="other"/>`, "", ""},
		{"select_multiple_nodes", `<xsl:number select="r/chapter"/>`, "", "XTTE1000"},
		{"select_empty_sequence", `<xsl:number select="r/missing"/>`, "", "XTTE1000"},
		{"select_atomic_value", `<xsl:number select="1"/>`, "", "XTTE1000"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			const input = `<r><chapter id="one"><section><title>A</title></section><section><title>B</title></section></chapter><chapter id="two"><section><title>C</title></section></chapter></r>`
			got, err := compileTestStylesheet(t, "", tc.body).Transform(parseTestDocument(t, input)).Serialize(t.Context())
			requireSerialization(t, got, err, tc.want, tc.code)
		})
	}
}

func TestNumberFormatsRoundedValuesAndStartOffsets(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct{ name, attributes, want, code string }{
		{"grouped_arabic_digits", `value="12345" format="٠٠٠٠٠٠" grouping-size="3" grouping-separator="·"`, "٠١٢·٣٤٥", ""},
		{"picture_prefix_suffix_and_repeated_separator", `value="(3, 28, 52)" format="[I::a]"`, "[III::ab::az]", ""},
		{"rounding_and_offsets_apply_per_component", `value="(2.5, 4.4, 9)" start-at="2 10" format="(01-01)"`, "(04-13-18)", ""},
		{"english_ordinal_exceptions", `value="(11, 22, 113)" format="1" ordinal="yes" lang="en"`, "11th.22nd.113th", ""},
		{"words_for_number_list", `value="(12, 40)" format="w" lang="en"`, "twelve.forty", ""},
		{"invalid_dynamic_letter_value", `value="1" letter-value="{'unknown'}"`, "", "XTDE0030"},
		{"invalid_dynamic_start_at", `value="2" start-at="{'1 invalid'}"`, "", "XTDE0030"},
		{"infinite_value_has_no_ordinal", `value="xs:double('INF')"`, "", "XTDE0980"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := compileTestStylesheet(t, "", `<xsl:number `+tc.attributes+`/>`).Transform(parseTestDocument(t, `<r/>`)).Serialize(t.Context())
			requireSerialization(t, got, err, tc.want, tc.code)
		})
	}
}
