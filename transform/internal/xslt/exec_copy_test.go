package xslt //nolint:testpackage // Exercises shallow copying within the executor.

import "testing"

func TestExecCopy(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name, body, want, code string
	}{
		{
			name: "selected_node_has_its_own_focus_and_restores_caller",
			body: `<xsl:for-each select="r/n">
				<xsl:variable name="copy" as="element()">
					<xsl:copy select="../p:label" xmlns:p="urn:label">
						<xsl:value-of select="(name(), position(), last())" separator="/"/>
					</xsl:copy>
				</xsl:variable>
				<xsl:value-of select="(namespace-uri($copy), $copy, @id, position(), last())" separator="|"/>
				<xsl:text>;</xsl:text>
			</xsl:for-each>`,
			want: "urn:label|p:label/1/1|a|1|2;urn:label|p:label/1/1|b|2|2;",
		},
		{
			name: "empty_and_atomic_selection_skip_constructor",
			body: `<xsl:variable name="values" as="item()*">
				<xsl:copy select="()"><xsl:sequence select="error()"/></xsl:copy>
				<xsl:copy select="42"><xsl:sequence select="error()"/></xsl:copy>
				<xsl:for-each select="true()"><xsl:copy><xsl:sequence select="error()"/></xsl:copy></xsl:for-each>
			</xsl:variable>
			<xsl:value-of select="(count($values), $values[1] instance of xs:integer, $values[2] instance of xs:boolean)" separator="|"/>`,
			want: "2|true|true",
		},
		{
			name: "selection_must_be_a_single_item",
			body: `<xsl:copy select="r/n"/>`,
			code: "XTTE3180",
		},
		{
			name: "document_constructor_can_capture_a_document_item",
			body: `<xsl:variable name="copy" as="document-node()">
				<xsl:copy select="/"><new><xsl:value-of select="r/n/@id" separator=","/></new></xsl:copy>
			</xsl:variable>
			<xsl:value-of select="(name($copy/*), string($copy), count($copy/*))" separator="|"/>`,
			want: "new|a,b|1",
		},
		{
			name: "document_constructor_contributes_its_children",
			body: `<xsl:variable name="out" as="element()">
				<out><xsl:copy><a/><b/></xsl:copy></out>
			</xsl:variable>
			<xsl:value-of select="$out/*/name()" separator="|"/>`,
			want: "a|b",
		},
		{
			name: "comment_processing_instruction_and_text_are_shallow_copied",
			body: `<xsl:variable name="out" as="element()">
				<out><xsl:for-each select="r/n[1]/node()"><xsl:copy/></xsl:for-each></out>
			</xsl:variable>
			<xsl:value-of select="($out/comment(), name($out/processing-instruction()), $out/processing-instruction(), $out/text())" separator="|"/>`,
			want: "note|mark|data|payload",
		},
		{
			name: "attribute_copy_preserves_expanded_name_and_value",
			body: `<xsl:variable name="out" as="attribute()">
				<xsl:copy select="r/p:label/@q:code" xmlns:p="urn:label" xmlns:q="urn:code"/>
			</xsl:variable>
			<xsl:value-of select="(local-name($out), namespace-uri($out), string($out), empty($out/parent::*))" separator="|"/>`,
			want: "code|urn:code|007|true",
		},
		{
			name: "shallow_copy_uses_attribute_set_and_runtime_namespace_option",
			body: `<xsl:variable name="out" as="element()">
				<xsl:copy select="r/p:label" xmlns:p="urn:label" _copy-namespaces="{'no'}" use-attribute-sets="marker"/>
			</xsl:variable>
			<xsl:value-of select="(name($out), $out/namespace::p, $out/@marker, empty($out/namespace::other), empty($out/node()))" separator="|"/>`,
			want: "p:label|urn:label|label|true|true",
		},
		{
			name: "late_attribute_is_rejected",
			body: `<out><child/><xsl:copy select="r/n[1]/@id"/></out>`,
			code: "XTDE0410",
		},
		{
			name: "document_cannot_contain_an_attribute",
			body: `<xsl:copy select="r/n[1]/@id"/>`,
			code: "XTDE0420",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			source := parseTestDocument(t, `<r xmlns:p="urn:label" xmlns:q="urn:code" xmlns:other="urn:other"><n id="a"><!--note--><?mark data?>payload</n><n id="b"/><p:label q:code="007">body</p:label></r>`)
			ss := compileTestStylesheet(t, `<xsl:attribute-set name="marker"><xsl:attribute name="marker" select="local-name()"/></xsl:attribute-set>`, tc.body)
			got, err := ss.Transform(source).Serialize(t.Context())
			requireSerialization(t, got, err, tc.want, tc.code)
		})
	}
}
