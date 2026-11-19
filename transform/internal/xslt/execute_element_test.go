package xslt //nolint:testpackage // Exercises comment node construction.

import "testing"

func TestExecElementResolvesLexicalNamespaces(t *testing.T) {
	t.Parallel()

	const declarations = `<xsl:variable xmlns:p="urn:unrelated" name="unrelated" select="42"/>`
	for _, tc := range []struct{ name, element, want, code string }{
		{"undeclared_prefix", `<xsl:element name="{$name}"/>`, "", "XTDE0830"},
		{"instruction_namespace", `<xsl:element name="{$name}" xmlns:p="urn:local"/>`, "item|urn:local", ""},
		{"explicit_namespace", `<xsl:element name="{$name}" namespace="urn:explicit"/>`, "item|urn:explicit", ""},
		{"explicit_empty_namespace", `<xsl:element name="{$name}" namespace=""/>`, "item|", ""},
		{"implicit_xml_namespace", `<xsl:element name="{concat('xml:', 'item')}"/>`, "item|http://www.w3.org/XML/1998/namespace", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			body := `<xsl:variable name="name" select="'p:item'"/>` +
				`<xsl:variable name="node" as="element()">` + tc.element + `</xsl:variable>` +
				`<xsl:value-of select="(local-name($node), namespace-uri($node))" separator="|"/>`
			ss := compileTestStylesheet(t, declarations, body)
			got, err := ss.Transform(parseTestDocument(t, `<r/>`)).Serialize(t.Context())
			requireSerialization(t, got, err, tc.want, tc.code)
		})
	}
}

func TestComputedQNameWhitespaceByProcessorEdition(t *testing.T) {
	t.Parallel()

	for _, edition := range []struct {
		name    string
		version int
	}{
		{"1.0", processorXSLT10},
		{"2.0", processorXSLT20},
		{"3.0", processorXSLT30},
	} {
		for _, tc := range []struct{ kind, body, want, code string }{
			{"element", `<xsl:element name="{r/@name}">value</xsl:element>`, "<item>value</item>", "XTDE0820"},
			{"attribute", `<out><xsl:attribute name="{r/@name}">value</xsl:attribute></out>`, `<out item="value"/>`, "XTDE0850"},
		} {
			t.Run(edition.name+"/"+tc.kind, func(t *testing.T) {
				t.Parallel()

				const prefix = `<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="`
				sheet := prefix + edition.name + `"><xsl:output method="xml" omit-xml-declaration="yes"/><xsl:template match="/">` + tc.body + `</xsl:template></xsl:stylesheet>`
				compiler := NewCompiler().ProcessorVersion(edition.version)
				compiled, err := compiler.Compile(t.Context(), parseTestDocument(t, sheet))
				if err != nil {
					t.Fatal(err)
				}

				for _, input := range []struct {
					label, name string
					valid       bool
				}{
					{"bare", "item", true},
					{"xml_whitespace", " &#x9;item&#xA; ", edition.version >= processorXSLT20},
					{"nonbreaking_spaces", "&#160;item&#160;", false},
					{"uri_qualified_empty", "Q{}item", false},
					{"uri_qualified_named", "Q{urn:test}item", false},
				} {
					t.Run(input.label, func(t *testing.T) {
						t.Parallel()
						doc := parseTestDocument(t, `<r name="`+input.name+`"/>`)
						got, err := compiled.Transform(doc).Serialize(t.Context())
						if input.valid {
							requireSerialization(t, got, err, tc.want, "")
						} else {
							requireSerialization(t, got, err, "", tc.code)
						}
					})
				}
			})
		}
	}
}

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

func TestExecPI(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct{ name, body, want, code string }{
		{"computed_target_and_escaped_content", `<xsl:variable name="pi" as="processing-instruction()"><xsl:processing-instruction name="{r/@target}" select="'a?&gt;b?&gt;'"/></xsl:variable><xsl:value-of select="(name($pi),string($pi))" separator="|"/>`, "note|a? >b? >", ""},
		{"body_applies_simple_content_rules", `<xsl:variable name="pi" as="processing-instruction()"><xsl:processing-instruction name="note"><xsl:sequence select="('one',2,'three')"/></xsl:processing-instruction></xsl:variable><xsl:value-of select="$pi"/>`, "one 2 three", ""},
		{"target_must_be_ncname", `<xsl:processing-instruction name="{concat('p',':note')}"/>`, "", "XTDE0890"},
		{"xml_target_is_reserved_regardless_of_case", `<xsl:processing-instruction name="{concat('X','mL')}"/>`, "", "XTDE0890"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ss := compileTestStylesheet(t, "", tc.body)
			got, err := ss.Transform(parseTestDocument(t, `<r target="note"/>`)).Serialize(t.Context())
			requireSerialization(t, got, err, tc.want, tc.code)
		})
	}
}

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

func TestLiteralResultDefaultNamespace(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct{ name, ancestorAttrs, literal, want string }{
		{"inherited", "", `<p:item/>`, "urn:item|urn:default"},
		{"excluded", ` exclude-result-prefixes="#default"`, `<p:item/>`, "urn:item|"},
		{"undeclared", "", `<p:item xmlns=""/>`, "urn:item|"},
		{"locally rebound", "", `<p:item xmlns="urn:local"/>`, "urn:item|urn:local"},
		{"retained for element name", ` exclude-result-prefixes="#default"`, `<item/>`, "urn:default|urn:default"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			body := `<xsl:variable name="node" as="element()">
				<xsl:if xmlns:p="urn:item" xmlns="urn:default" test="true()"` + tc.ancestorAttrs + `>` + tc.literal + `</xsl:if>
			</xsl:variable>
			<xsl:value-of select="concat(namespace-uri($node),'|',string(namespace-uri-for-prefix('',$node)))"/>`
			ss := compileTestStylesheet(t, "", body)
			got, err := ss.Transform(parseTestDocument(t, `<r/>`)).Serialize(t.Context())
			requireSerialization(t, got, err, tc.want, "")
		})
	}
}

func TestReviewComputedNCNameStripsXMLWhitespace(t *testing.T) {
	for _, tc := range []struct{ name, body string }{
		{"processing instruction", `<xsl:variable name="node" as="processing-instruction()"><xsl:processing-instruction name="{r/@name}"/></xsl:variable><xsl:value-of select="name($node)"/>`},
		{"namespace", `<xsl:variable name="node" as="namespace-node()"><xsl:namespace name="{r/@name}" select="'urn:example'"/></xsl:variable><xsl:value-of select="name($node)"/>`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ss := compileTestStylesheet(t, "", tc.body)
			got, err := ss.Transform(parseTestDocument(t, `<r name=" &#x9;item&#xA; "/>`)).Serialize(t.Context())
			requireSerialization(t, got, err, "item", "")
		})
	}
}
