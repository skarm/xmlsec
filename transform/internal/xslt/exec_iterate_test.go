package xslt //nolint:testpackage // Exercises iterate parameter and focus state.

import "testing"

func TestExecIterateCompletionAndFocus(t *testing.T) {
	t.Parallel()
	const body = `
		<xsl:for-each select="/r/batch">
			<xsl:iterate select="n">
				<xsl:param name="total" as="xs:integer"><xsl:sequence select="xs:integer(@seed)"/></xsl:param>
				<xsl:param name="initial" select="$total"/>
				<xsl:on-completion>
					<xsl:value-of select="concat($initial, '->', $total, ';')"/>
				</xsl:on-completion>
				<xsl:value-of select="concat(., ':', position(), '/', last(), ',')"/>
				<xsl:next-iteration>
					<xsl:with-param name="total" select="$total + xs:integer(.)"/>
				</xsl:next-iteration>
			</xsl:iterate>
			<xsl:value-of select="concat(@seed, ':', position(), '/', last(), ';')"/>
		</xsl:for-each>`
	ss := compileTestStylesheet(t, "", body)
	source := parseTestDocument(t, `<r><batch seed="4"><n>2</n><n>5</n></batch><batch seed="3"/></r>`)
	got, err := ss.Transform(source).Serialize(t.Context())
	requireSerialization(t, got, err, "2:1/2,5:2/2,4->11;4:1/2;3->3;3:2/2;", "")
}

func TestExecIterateBreakInSequenceConstructor(t *testing.T) {
	t.Parallel()
	const body = `
		<xsl:variable name="result" as="item()*">
			<xsl:iterate select="1 to 3">
				<xsl:param name="seen" select="0"/>
				<xsl:on-completion select="'unexpected completion'"/>
				<xsl:choose>
					<xsl:when test=". = 2">
						<xsl:break><xsl:sequence select="($seen, .)"/><end/></xsl:break>
					</xsl:when>
					<xsl:otherwise>
						<xsl:next-iteration><xsl:with-param name="seen" select="$seen + ."/></xsl:next-iteration>
					</xsl:otherwise>
				</xsl:choose>
			</xsl:iterate>
		</xsl:variable>
		<xsl:value-of select="($result[1] + $result[2], name($result[3]), count($result))" separator="|"/>`
	ss := compileTestStylesheet(t, "", body)
	got, err := ss.Transform(parseTestDocument(t, `<r/>`)).Serialize(t.Context())
	requireSerialization(t, got, err, "3|end|3", "")
}

func TestExecIterateRejectsWrongParameterType(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct{ name, initial, updated string }{
		{name: "initial_value", initial: "'not an integer'", updated: "$value"},
		{name: "next_iteration_value", initial: "0", updated: "'not an integer'"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			body := `<xsl:iterate select="1 to 2">
				<xsl:param name="value" as="xs:integer" select="` + tc.initial + `"/>
				<xsl:on-completion select="$value"/>
				<xsl:next-iteration><xsl:with-param name="value" select="` + tc.updated + `"/></xsl:next-iteration>
			</xsl:iterate>`
			ss := compileTestStylesheet(t, "", body)
			got, err := ss.Transform(parseTestDocument(t, `<r/>`)).Serialize(t.Context())
			requireSerialization(t, got, err, "", "XTTE0590")
		})
	}
}
