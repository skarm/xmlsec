package xslt //nolint:testpackage // Exercises internal XSLT sorting through stylesheet execution.

import "testing"

func TestPerformSortPreservesItemsAndStableOrder(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct{ name, body, want, code string }{
		{"numeric_items", `<xsl:perform-sort select="(10, 2, -1, 2)"><xsl:sort select="."/></xsl:perform-sort>`, "-1 2 2 10", ""},
		{"constructor_keys", `<xsl:perform-sort select="('bee','a','cat')"><xsl:sort><xsl:sequence select="string-length(.)"/></xsl:sort></xsl:perform-sort>`, "a bee cat", ""},
		{"multiple_node_keys_and_stable_ties", `<xsl:variable name="items" as="element()*"><xsl:perform-sort select="r/n"><xsl:sort select="@group"/><xsl:sort select="xs:integer(@rank)" order="descending"/></xsl:perform-sort></xsl:variable><xsl:value-of select="$items/@id" separator="|"/>`, "a3|a1|a2|b1", ""},
		{"exact_integer_keys", `<xsl:for-each select="(9007199254740993,9007199254740992)"><xsl:sort select="."/><xsl:value-of select=". || '|'"/></xsl:for-each>`, "9007199254740992|9007199254740993|", ""},
		{"float_promotion_preserves_tie", `<xsl:for-each select="('high','low')"><xsl:sort select="if (. = 'high') then 16777217 else xs:float('16777216')"/><xsl:value-of select=". || '|'"/></xsl:for-each>`, "high|low|", ""},
		{"temporal_keys_compare_instants", `<xsl:for-each select="('later','earlier')"><xsl:sort select="if (. = 'later') then xs:dateTime('2024-01-02T00:00:00Z') else xs:dateTime('2024-01-02T00:30:00+01:00')"/><xsl:value-of select=". || '|'"/></xsl:for-each>`, "earlier|later|", ""},
		{"empty_and_nan_descending", `<xsl:for-each select="('empty','invalid','two','ten')"><xsl:sort select="if (. = 'empty') then () else if (. = 'invalid') then xs:double('NaN') else if (. = 'two') then 2 else 10" order="descending"/><xsl:value-of select=". || '|'"/></xsl:for-each>`, "ten|two|invalid|empty|", ""},
		{"explicit_collation_ignores_case_order_avt", `<xsl:for-each select="('a','B','A')"><xsl:sort select="." collation="http://www.w3.org/2005/xpath-functions/collation/html-ascii-case-insensitive" case-order="{error()}"/><xsl:value-of select=". || '|'"/></xsl:for-each>`, "a|A|B|", ""},
		{"invalid_dynamic_order", `<xsl:for-each select="(1,2)"><xsl:sort select="." order="{'sideways'}"/></xsl:for-each>`, "", "XTDE0030"},
		{"mixed_incomparable_key_types", `<xsl:for-each select="(1,'two')"><xsl:sort select="."/><xsl:value-of select="."/></xsl:for-each>`, "", "XTDE1030"},
		{"multiple_atomic_keys_per_item", `<xsl:for-each select="(1,2)"><xsl:sort select="(., . + 1)"/><xsl:value-of select="."/></xsl:for-each>`, "", "XTTE1020"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			const input = `<r><n id="b1" group="B" rank="1"/><n id="a1" group="A" rank="1"/><n id="a3" group="A" rank="3"/><n id="a2" group="A" rank="1"/></r>`
			got, err := compileTestStylesheet(t, "", tc.body).Transform(parseTestDocument(t, input)).Serialize(t.Context())
			requireSerialization(t, got, err, tc.want, tc.code)
		})
	}
}
