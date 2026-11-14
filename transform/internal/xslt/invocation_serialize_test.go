package xslt //nolint:testpackage // Checks internal serialization for each output method.

import "testing"

func TestSerializationDeliveryMethods(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name, declarations, body, want string
	}{
		{"xml_character_map_is_applied_to_text_and_attributes", `<xsl:output method="xml" omit-xml-declaration="yes" use-character-maps="m"/><xsl:character-map name="base"><xsl:output-character character="@" string="base"/><xsl:output-character character="+" string="plus"/></xsl:character-map><xsl:character-map name="m" use-character-maps="base"><xsl:output-character character="@" string="local"/></xsl:character-map>`, `<r id="@">@+</r>`, `<r id="local">localplus</r>`},
		{"html_void_elements_and_text_escaping", `<xsl:output method="html" version="4.01" indent="no" include-content-type="no"/>`, `<p><br/><span>&lt;&amp;</span></p>`, `<p><br><span>&lt;&amp;</span></p>`},
		{"xhtml_empty_element_spacing", `<xsl:output method="xhtml" version="1.0" omit-xml-declaration="yes" indent="no" include-content-type="no"/>`, `<p xmlns="http://www.w3.org/1999/xhtml"><br/><span/></p>`, `<p xmlns="http://www.w3.org/1999/xhtml"><br /><span></span></p>`},
		{"json_serializes_array_and_null", `<xsl:output method="json" indent="no"/>`, `<xsl:sequence select="[true(), (), 3.5, 'hello']"/>`, `[true,null,3.5,"hello"]`},
		{"adaptive_keeps_type_sensitive_quoting", `<xsl:output method="adaptive" item-separator="|"/>`, `<xsl:sequence select="(true(), 'text', 9)"/>`, `true()|"text"|9`},
		{"text_uses_item_separator", `<xsl:output method="text" item-separator="|"/>`, `<xsl:sequence select="(1,2,3)"/>`, "1|2|3"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			doc := parseTestDocument(t, `<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="3.0">`+tc.declarations+`<xsl:template match="/">`+tc.body+`</xsl:template></xsl:stylesheet>`)
			ss, err := NewCompiler().Compile(t.Context(), doc)
			if err != nil {
				t.Fatal(err)
			}
			got, err := ss.Transform(parseTestDocument(t, `<source/>`)).Serialize(t.Context())
			requireSerialization(t, got, err, tc.want, "")
		})
	}
}
