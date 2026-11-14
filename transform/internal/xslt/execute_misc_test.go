package xslt //nolint:testpackage // Exercises miscellaneous instructions through the internal compiler and invocation.

import (
	"errors"
	"testing"

	"github.com/skarm/xmlsec/transform/internal/xdm"
)

func TestAnalyzeStringSetsSegmentFocusAndRestoresOuterFocus(t *testing.T) {
	t.Parallel()
	const body = `<xsl:for-each select="r/n">
		<xsl:analyze-string select="string(.)" regex="([a-z])([0-9]+)">
			<xsl:matching-substring><xsl:value-of select="concat(position(), '/', last(), ':', regex-group(2), regex-group(1), '|')"/></xsl:matching-substring>
			<xsl:non-matching-substring><xsl:value-of select="concat(position(), '/', last(), ':', ., regex-group(1), '|')"/></xsl:non-matching-substring>
		</xsl:analyze-string>
		<xsl:value-of select="concat(position(), '/', last(), ':', @id, ';')"/>
	</xsl:for-each>`
	doc := parseTestDocument(t, `<r><n id="first">[a12-b3]</n><n id="second">abc</n></r>`)
	got, err := compileTestStylesheet(t, "", body).Transform(doc).Serialize(t.Context())
	requireSerialization(t, got, err, "1/5:[|2/5:12a|3/5:-|4/5:3b|5/5:]|1/2:first;1/1:abc|2/2:second;", "")
}

func TestAnalyzeStringEnforcesVersionAndRegexRules(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name, version, selectExpr, regex, flags, want, code string
	}{
		{name: "zero_length_matches_in_xslt_30", version: "3.0", selectExpr: "'é'", regex: "z*", want: "[]é[]"},
		{name: "zero_length_matches_rejected_in_xslt_20", version: "2.0", selectExpr: "'é'", regex: "z*", code: "XTDE1150"},
		{name: "quoted_regex_in_xslt_30", version: "3.0", selectExpr: "'a.b'", regex: ".", flags: "q", want: "a[.]b"},
		{name: "quoted_regex_rejected_in_xslt_20", version: "2.0", selectExpr: "'a.b'", regex: ".", flags: "q", code: "XTDE1145"},
		{name: "noncapturing_group_rejected_in_xslt_20", version: "2.0", selectExpr: "'a'", regex: "(?:a)", code: "XTDE1140"},
		{name: "empty_selection_in_xslt_30", version: "3.0", selectExpr: "()", regex: "z*"},
		{name: "empty_selection_rejected_in_xslt_20", version: "2.0", selectExpr: "()", regex: "z*", code: "XPTY0004"},
		{name: "multiple_values_are_rejected", version: "3.0", selectExpr: "('a', 'b')", regex: "a", code: "XPTY0004"},
		{name: "non_string_value_is_rejected", version: "3.0", selectExpr: "1", regex: "a", code: "XPTY0004"},
		{name: "invalid_flags_are_reported", version: "3.0", selectExpr: "'a'", regex: "a", flags: "j", code: "XTDE1145"},
		{name: "invalid_pattern_is_reported", version: "3.0", selectExpr: "'a'", regex: "[", code: "XTDE1140"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			body := `<xsl:analyze-string select="` + tc.selectExpr + `" regex="` + tc.regex + `" flags="` + tc.flags + `">
				<xsl:matching-substring><xsl:value-of select="concat('[', ., ']')"/></xsl:matching-substring>
				<xsl:non-matching-substring><xsl:value-of select="."/></xsl:non-matching-substring>
			</xsl:analyze-string>`
			sheet := stylesheetDocument(t, "", body)
			compiler := NewCompiler()
			if tc.version == "2.0" {
				compiler = compiler.ProcessorVersion(processorXSLT20)
			}
			ss, err := compiler.Compile(t.Context(), sheet)
			if err != nil {
				t.Fatalf("compile analyze-string: %v", err)
			}
			got, err := ss.Transform(parseTestDocument(t, `<r/>`)).Serialize(t.Context())
			requireSerialization(t, got, err, tc.want, tc.code)
		})
	}
}

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

func TestAssertionsFollowInvocationPolicy(t *testing.T) {
	t.Parallel()
	const body = `<xsl:assert test="/*/@approved = 'yes'" error-code="f:required" select="'approval required'"/><xsl:text>accepted</xsl:text>`
	for _, tc := range []struct {
		name, source, want, code string
		enabled                  bool
	}{
		{name: "disabled_assertion_does_not_terminate", source: `<r/>`, want: "accepted"},
		{name: "successful_assertion_does_not_terminate", source: `<r approved="yes"/>`, want: "accepted", enabled: true},
		{name: "failed_assertion_reports_custom_code", source: `<r/>`, code: "required", enabled: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var message recordingMessageHandler
			invocation := compileTestStylesheet(t, "", body).Transform(parseTestDocument(t, tc.source)).MessageHandler(&message)
			got, err := invocation.Serialize(WithAssertions(t.Context(), tc.enabled))
			requireSerialization(t, got, err, tc.want, tc.code)
			if tc.code == "" {
				if message.calls != 0 {
					t.Errorf("assertion delivered %d messages, want none", message.calls)
				}
			} else {
				var detail *XSLTError
				if !errors.As(err, &detail) || detail.CodeQName().URI != "urn:unit" {
					t.Errorf("assertion error = %v, want an expanded code in urn:unit", err)
				}
				if message.calls != 1 || !message.terminate || message.message != "approval required" {
					t.Errorf("assertion message = %q; calls = %d, terminate = %t; want one terminating approval message", message.message, message.calls, message.terminate)
				}
			}
		})
	}
}

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
