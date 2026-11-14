package xslt //nolint:testpackage // Exercises internal node construction and rollback.

import "testing"

func TestInstructionConstructionAndRollback(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name, declarations, body, want string
	}{
		{"map_entries_keep_typed_keys", "", `<xsl:variable name="m" as="map(*)"><xsl:map><xsl:map-entry key="1" select="'numeric'"/><xsl:map-entry key="'1'" select="'string'"/></xsl:map></xsl:variable><xsl:value-of select="($m(1),$m('1'))" separator="|"/>`, "numeric|string"},
		{"attribute_set_uses_focus_and_overrides_in_order", `<xsl:attribute-set name="labels"><xsl:attribute name="id" select="@id"/><xsl:attribute name="kind">inherited</xsl:attribute></xsl:attribute-set>`, `<xsl:for-each select="r/n"><xsl:variable name="node" as="element()"><xsl:element name="item" use-attribute-sets="labels"><xsl:attribute name="kind">explicit</xsl:attribute></xsl:element></xsl:variable><xsl:value-of select="($node/@id, $node/@kind)" separator="|"/></xsl:for-each>`, "source|explicit"},
		{"copy_and_copy_of_keep_content", "", `<xsl:for-each select="r/n"><xsl:variable name="copied" as="element()"><xsl:copy><xsl:copy-of select="@* | node()"/></xsl:copy></xsl:variable><xsl:value-of select="(name($copied),$copied/@id,string($copied/child))" separator="|"/></xsl:for-each>`, "n|source|text"},
		{"catch_discards_partial_result", "", `<xsl:text>before|</xsl:text><xsl:try><xsl:text>discard|</xsl:text><xsl:sequence select="error(QName('urn:unit','f:stop'))"/><xsl:catch errors="f:stop"><xsl:text>recovered|</xsl:text></xsl:catch></xsl:try><xsl:text>after</xsl:text>`, "before|recovered|after"},
		{"iterate_break_skips_completion", "", `<xsl:iterate select="1 to 3"><xsl:on-completion select="'unexpected'"/><xsl:choose><xsl:when test=". eq 2"><xsl:break select="'stop'"/></xsl:when><xsl:otherwise><xsl:value-of select="."/></xsl:otherwise></xsl:choose></xsl:iterate>`, "1stop"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ss := compileTestStylesheet(t, tc.declarations, tc.body)
			got, err := ss.Transform(parseTestDocument(t, `<r><n id="source"><child>text</child></n></r>`)).Serialize(t.Context())
			requireSerialization(t, got, err, tc.want, "")
		})
	}
}
