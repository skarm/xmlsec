package xslt //nolint:testpackage // Exercises the fork branch execution contract.

import "testing"

func TestExecForkKeepsBranchOrderAndFocus(t *testing.T) {
	t.Parallel()
	const body = `
		<xsl:for-each select="/r/n">
			<xsl:variable name="branches" as="item()*">
				<xsl:fork>
					<xsl:sequence select="(position(), data(@label))"/>
					<xsl:sequence select="(last(), string(.))"/>
				</xsl:fork>
			</xsl:variable>
			<xsl:value-of select="string-join($branches, ':') || ';'"/>
		</xsl:for-each>`
	ss := compileTestStylesheet(t, "", body)
	got, err := ss.Transform(parseTestDocument(t, `<r><n label="x">A</n><n label="y">B</n></r>`)).Serialize(t.Context())
	requireSerialization(t, got, err, "1:x:2:A;2:y:2:B;", "")
}
