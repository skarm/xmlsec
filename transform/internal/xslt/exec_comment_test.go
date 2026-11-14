package xslt //nolint:testpackage // Exercises comment node construction.

import "testing"

func TestExecCommentNormalizesContent(t *testing.T) {
	t.Parallel()
	body := `<xsl:variable name="out" as="element()"><out>
		<xsl:comment select="'before---end-'"/>
		<xsl:comment><xsl:sequence select="('one',2,'three')"/></xsl:comment>
		<xsl:comment/>
	</out></xsl:variable><xsl:value-of select="$out/comment() ! concat('[',string(.),']')" separator="|"/>`
	got, err := compileTestStylesheet(t, "", body).Transform(parseTestDocument(t, `<r/>`)).Serialize(t.Context())
	requireSerialization(t, got, err, "[before- - -end- ]|[one 2 three]|[]", "")
}
