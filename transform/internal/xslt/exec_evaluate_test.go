package xslt //nolint:testpackage // Exercises miscellaneous instructions through the internal compiler and invocation.

import (
	"errors"
	"testing"

	"github.com/skarm/xmlsec/transform/internal/xdm"
)

func TestEvaluateUsesExplicitContextAndParameters(t *testing.T) {
	t.Parallel()
	const source = `<r xmlns="urn:data" xmlns:p="urn:data"><item n="7"/></r>`
	for _, tc := range []struct {
		name, body, want, code string
		xpathError             bool
	}{
		{name: "map_parameter_overrides_explicit_parameter", body: `<xsl:evaluate xpath="'$f:value * 2'" with-params="map{QName('urn:unit','value'):21}"><xsl:with-param name="f:value" select="7"/></xsl:evaluate>`, want: "42"},
		{name: "atomic_context_has_singleton_focus", body: `<xsl:evaluate context-item="20" xpath="'. * position() + last()'"/>`, want: "21"},
		{name: "node_context_uses_its_in_scope_prefixes", body: `<xsl:evaluate context-item="/*" namespace-context="/*" xmlns:p="urn:unused" xpath="'p:item/@n ! string(.)'"/>`, want: "7"},
		{name: "node_context_uses_its_default_namespace", body: `<xsl:evaluate context-item="/*" namespace-context="/*" xpath-default-namespace="urn:unused" xpath="'count(item)'"/>`, want: "1"},
		{name: "absent_context_does_not_inherit_caller_focus", body: `<xsl:evaluate xpath="'position()'"/>`, code: "XPDY0002", xpathError: true},
		{name: "context_item_rejects_multiple_items", body: `<xsl:evaluate context-item="(1, 2)" xpath="'1'"/>`, code: "XTTE3210"},
		{name: "namespace_context_requires_a_node", body: `<xsl:evaluate namespace-context="1" xpath="'1'"/>`, code: "XTTE3170"},
		{name: "namespace_context_requires_a_single_item", body: `<xsl:evaluate namespace-context="()" xpath="'1'"/>`, code: "XTTE3170"},
		{name: "params_map_requires_qname_keys", body: `<xsl:evaluate xpath="'1'" with-params="map{'value':21}"/>`, code: "XTTE3165"},
		{name: "params_map_requires_single_item", body: `<xsl:evaluate xpath="'1'" with-params="()"/>`, code: "XTTE3165"},
		{name: "caller_variable_is_out_of_scope", body: `<xsl:variable name="caller" select="7"/><xsl:evaluate xpath="'$caller'"/>`, code: "XTDE3160"},
		{name: "blank_xpath_source_is_rejected", body: `<xsl:evaluate xpath="'   '"/>`, code: "XTDE3160"},
		{name: "invalid_xpath_source_is_rejected", body: `<xsl:evaluate xpath="'1 +'"/>`, code: "XTDE3160"},
		{name: "result_type_enforces_cardinality", body: `<xsl:evaluate xpath="'(1, 2)'" as="xs:integer"/>`, code: "XPTY0004", xpathError: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := compileTestStylesheet(t, "", tc.body).Transform(parseTestDocument(t, source)).Serialize(t.Context())
			if tc.xpathError {
				var detail *xdm.Error
				if got != "" || !errors.As(err, &detail) || detail.Code != tc.code {
					t.Fatalf("evaluate output = %q, error = %v; want no output and XPath error %s", got, err, tc.code)
				}
			} else {
				requireSerialization(t, got, err, tc.want, tc.code)
			}
		})
	}
}

func TestEvaluateBaseURIAppliesOnlyToDynamicExpression(t *testing.T) {
	t.Parallel()
	const body = `<xsl:value-of select="static-base-uri()"/>
		<xsl:text>|</xsl:text>
		<xsl:evaluate base-uri="{'https://example.test/temporary/'}" xpath="'resolve-uri(''report.xml'')'"/>
		<xsl:text>|</xsl:text>
		<xsl:evaluate xpath="'resolve-uri(''report.xml'')'"/>
		<xsl:text>|</xsl:text>
		<xsl:value-of select="static-base-uri()"/>`
	const baseURI = "https://example.test/styles/main.xsl"
	ss, err := NewCompiler().BaseURI(baseURI).Compile(t.Context(), stylesheetDocument(t, "", body))
	if err != nil {
		t.Fatalf("compile stylesheet: %v", err)
	}
	got, err := ss.Transform(parseTestDocument(t, `<r/>`)).Serialize(t.Context())
	const want = baseURI + "|https://example.test/temporary/report.xml|https://example.test/styles/report.xml|" + baseURI
	requireSerialization(t, got, err, want, "")
}
