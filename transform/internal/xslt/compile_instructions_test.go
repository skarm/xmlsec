package xslt //nolint:testpackage // Exercises the instruction compiler without the public transform adapter.

import (
	"errors"
	"testing"

	"github.com/skarm/xmlsec/transform/internal/xdm"
)

func TestCompileInstructionScopesLocalStaticContext(t *testing.T) {
	t.Parallel()

	const source = `<r xmlns:p="urn:items"><p:item>namespaced</p:item><item>plain</item></r>`
	for _, tc := range []struct {
		name, body, want string
	}{
		{"xpath_default_namespace", `<xsl:value-of xpath-default-namespace="urn:items" select="/*/item"/><xsl:text>|</xsl:text><xsl:value-of select="/*/item"/>`, "namespaced|plain"},
		{"literal_result_expand_text", `<part xsl:expand-text="yes">{1 + 2}<off xsl:expand-text="no">{3 + 4}</off>{5 + 6}</part><xsl:text>{7 + 8}</xsl:text>`, "3{3 + 4}11{7 + 8}"},
		{"default_collation", `<xsl:value-of default-collation="http://www.w3.org/2005/xpath-functions/collation/html-ascii-case-insensitive" select="'A' eq 'a'"/><xsl:text>|</xsl:text><xsl:value-of select="'A' eq 'a'"/>`, "true|false"},
		{"use_when_precedes_attribute_validation", `<xsl:value-of use-when="false()" unknown="yes" select="("/><part xsl:use-when="false()">omit</part><xsl:value-of use-when="function-available('concat', 2) and not(function-available('concat', 1))" select="'kept'"/>`, "kept"},
		{"forward_compatible_attributes", `<xsl:value-of version="4.0" xsl:future="on" future="on" select="'kept'"/>`, "kept"},
		{"fallback_keeps_local_namespaces_and_text_mode", `<xsl:future version="4.0"><xsl:fallback use-when="false()">omit</xsl:fallback><xsl:fallback xmlns:p="urn:items" expand-text="yes">{/*/p:item}</xsl:fallback></xsl:future>`, "namespaced"},
		{"empty_fallback_is_valid", `<xsl:future version="4.0"><xsl:fallback/></xsl:future><xsl:text>kept</xsl:text>`, "kept"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ss := compileTestStylesheet(t, "", tc.body)
			got, err := ss.Transform(parseTestDocument(t, source)).Serialize(t.Context())
			requireSerialization(t, got, err, tc.want, "")
		})
	}
}

func TestCompileInstructionRejectsInvalidStaticAttributes(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name, body, code string
	}{
		{"unknown_instruction_attribute", `<xsl:value-of select="1" extra="yes"/>`, "XTSE0090"},
		{"xslt_namespace_attribute", `<xsl:value-of select="1" xsl:extra="yes"/>`, "XTSE0090"},
		{"instruction_expand_text_requires_boolean", `<xsl:value-of expand-text="sometimes" select="1"/>`, "XTSE0020"},
		{"literal_expand_text_requires_boolean", `<part xsl:expand-text="sometimes">text</part>`, "XTSE0020"},
		{"invalid_use_when_expression", `<xsl:text use-when="(">text</xsl:text>`, "XPST0003"},
		{"invalid_use_when_effective_boolean_value", `<xsl:text use-when="(1, 2)">text</xsl:text>`, "FORG0006"},
		{"future_instruction_requires_fallback", `<xsl:future version="4.0"/>`, "XTSE0010"},
		{"excluded_fallback_does_not_count", `<xsl:future version="4.0"><xsl:fallback use-when="false()"/></xsl:future>`, "XTSE0010"},
		{"variable_cannot_combine_select_and_body", `<xsl:variable name="v" select="1"><xsl:sequence select="2"/></xsl:variable>`, "XTSE0620"},
		{"message_terminate_requires_boolean", `<xsl:message terminate="sometimes">text</xsl:message>`, "XTSE0020"},
		{"message_error_code_prefix_must_be_bound", `<xsl:message error-code="missing:note">text</xsl:message>`, "XTSE0280"},
		{"result_document_html_version_requires_number", `<xsl:result-document href="out.html" html-version="latest"/>`, "XTSE0020"},
		{"result_document_indent_requires_boolean", `<xsl:result-document href="out.xml" indent="sometimes"/>`, "SEPM0016"},
		{"result_document_standalone_requires_valid_keyword", `<xsl:result-document href="out.xml" standalone="sometimes"/>`, "SEPM0016"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ss, err := NewCompiler().Compile(t.Context(), stylesheetDocument(t, "", tc.body))
			static, isStatic := errors.AsType[*XSLTError](err)
			xpath, isXPath := errors.AsType[*xdm.Error](err)
			matches := isStatic && static.Code == tc.code || isXPath && xpath.Code == tc.code
			if ss != nil || !matches {
				t.Errorf("Compile(%s) = (stylesheet present: %t, %v), want no stylesheet and %s", tc.body, ss != nil, err, tc.code)
			}
		})
	}
}
