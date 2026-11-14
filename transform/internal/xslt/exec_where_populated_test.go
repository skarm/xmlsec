package xslt //nolint:testpackage // Exercises miscellaneous instructions through the internal compiler and invocation.

import "testing"

func TestWherePopulatedFiltersItemsBeforeConstruction(t *testing.T) {
	t.Parallel()
	const body = `<xsl:variable name="population" as="item()*">
		<xsl:where-populated>
			<xsl:sequence select="('', false(), 0, map{}, map{'k':''}, [(), ['', []]], [(), [0]], /*/empty, /*/present)"/>
		</xsl:where-populated>
	</xsl:variable>
	<xsl:value-of select="$population ! (if (. instance of map(*)) then 'map' else if (. instance of array(*)) then 'array' else if (. instance of element()) then local-name(.) else string(.))" separator="|"/>`
	doc := parseTestDocument(t, `<r><empty attr="ignored"/><present><child/></present></r>`)
	got, err := compileTestStylesheet(t, "", body).Transform(doc).Serialize(t.Context())
	requireSerialization(t, got, err, "false|0|map|array|present", "")
}
