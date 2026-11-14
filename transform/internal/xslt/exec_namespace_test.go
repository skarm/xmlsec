package xslt //nolint:testpackage // Exercises computed namespace construction.

import "testing"

func TestExecNamespace(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct{ name, body, want, code string }{
		{"namespace_node_can_be_returned_as_item", `<xsl:variable name="ns" as="namespace-node()"><xsl:namespace name="{r/@prefix}" select="r/@uri"/></xsl:variable><xsl:value-of select="(name($ns),string($ns),empty($ns/parent::node()))" separator="|"/>`, "p|urn:new|true", ""},
		{"constructor_body_supplies_namespace_uri", `<xsl:variable name="out" as="element()"><out><xsl:namespace name="p"><xsl:value-of select="r/@uri"/></xsl:namespace><child/></out></xsl:variable><xsl:value-of select="(namespace-uri($out),namespace-uri-for-prefix('p',$out),namespace-uri-for-prefix('p',$out/child))" separator="|"/>`, "|urn:new|urn:new", ""},
		{"prefix_fixup_preserves_expanded_element_name", `<xsl:variable name="out" as="element()"><xsl:element name="p:item" namespace="urn:original"><xsl:namespace name="p" select="'urn:new'"/></xsl:element></xsl:variable><xsl:value-of select="(local-name($out),namespace-uri($out),namespace-uri-for-prefix('p',$out))" separator="|"/>`, "item|urn:original|urn:new", ""},
		{"literal_element_prefix_cannot_be_rebound", `<p:out xmlns:p="urn:original"><xsl:namespace name="p" select="'urn:new'"/></p:out>`, "", "XTDE0430"},
		{"default_binding_cannot_change_expanded_name", `<out><xsl:namespace name="" select="'urn:new'"/></out>`, "", "XTDE0440"},
		{"namespace_cannot_follow_child", `<out><child/><xsl:namespace name="p" select="'urn:new'"/></out>`, "", "XTDE0410"},
		{"namespace_cannot_attach_to_document", `<xsl:namespace name="p" select="'urn:new'"/>`, "", "XTDE0420"},
		{"prefix_must_be_ncname", `<out><xsl:namespace name="{concat('p',':x')}" select="'urn:new'"/></out>`, "", "XTDE0920"},
		{"xml_prefix_must_use_xml_uri", `<out><xsl:namespace name="{concat('x','ml')}" select="'urn:new'"/></out>`, "", "XTDE0925"},
		{"xml_uri_requires_xml_prefix", `<out><xsl:namespace name="p" select="'http://www.w3.org/XML/1998/namespace'"/></out>`, "", "XTDE0925"},
		{"xmlns_uri_is_reserved", `<out><xsl:namespace name="p" select="'http://www.w3.org/2000/xmlns/'"/></out>`, "", "XTDE0905"},
		{"empty_uri_is_rejected", `<out><xsl:namespace name="p" select="''"/></out>`, "", "XTDE0930"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ss := compileTestStylesheet(t, "", tc.body)
			got, err := ss.Transform(parseTestDocument(t, `<r prefix="p" uri="urn:new"/>`)).Serialize(t.Context())
			requireSerialization(t, got, err, tc.want, tc.code)
		})
	}
}
