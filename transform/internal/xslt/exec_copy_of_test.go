package xslt //nolint:testpackage // Exercises copy instruction contracts within the executor.

import (
	"testing"
)

func TestExecCopyOf(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name, body, want, code string
	}{
		{
			name: "deep_copy_retains_in_scope_namespaces_and_creates_fresh_nodes",
			body: `<xsl:variable name="copy" as="element()"><xsl:copy-of select="r/p:label" xmlns:p="urn:label"/></xsl:variable>
			<xsl:value-of select="($copy/namespace::unused, $copy/namespace::alias, string($copy/child), $copy is r/*[1], empty($copy/parent::*))" separator="|"/>`,
			want: "urn:unused|urn:near|text|false|true",
		},
		{
			name: "namespace_stripping_keeps_required_bindings_and_limits_inheritance",
			body: `<xsl:variable name="copy" as="element()">
				<xsl:copy-of select="r/p:label" xmlns:p="urn:label" copy-namespaces="no"/>
			</xsl:variable>
			<xsl:value-of select="(namespace-uri($copy), namespace-uri($copy/@*), namespace-uri($copy/child/@*),
				empty($copy/namespace::unused), empty($copy/child/namespace::p), string($copy/child))" separator="|"/>`,
			want: "urn:label|urn:code|urn:code|true|true|text",
		},
		{
			name: "captured_document_keeps_children_and_base_uri",
			body: `<xsl:variable name="copy" as="document-node()"><xsl:copy-of select="/" copy-namespaces="no"/></xsl:variable>
			<xsl:value-of select="(count($copy/node()), name($copy/*), base-uri($copy),
				empty($copy/r/namespace::unused), $copy is /)" separator="|"/>`,
			want: "3|r|urn:source|true|false",
		},
		{
			name: "document_contributes_children_in_order",
			body: `<xsl:variable name="out" as="element()"><out><xsl:copy-of select="/"/></out></xsl:variable>
			<xsl:value-of select="($out/comment(), name($out/*), name($out/processing-instruction()))" separator="|"/>`,
			want: "first|r|last",
		},
		{
			name: "sequence_mode_preserves_atomics_and_arrays",
			body: `<xsl:variable name="out" as="item()*"><xsl:copy-of select="(1, [2,3], r/p:label)" xmlns:p="urn:label"/></xsl:variable>
			<xsl:value-of select="(count($out), $out[1] instance of xs:integer, $out[2] instance of array(*), ($out[2])(2), name($out[3]))" separator="|"/>`,
			want: "3|true|true|3|p:label",
		},
		{
			name: "tree_mode_flattens_arrays_and_separates_adjacent_atomics",
			body: `<out><xsl:copy-of select="(1, [2,3], r/p:label, 4, 5)" xmlns:p="urn:label"/></out>`,
			want: "1 2 3text4 5",
		},
		{
			name: "namespace_copy_can_be_captured_or_attached",
			body: `<xsl:variable name="ns" as="namespace-node()"><xsl:copy-of select="r/namespace::unused"/></xsl:variable>
			<xsl:variable name="out" as="element()"><out><xsl:copy-of select="$ns"/></out></xsl:variable>
			<xsl:value-of select="(name($ns), string($ns), string($out/namespace::unused))" separator="|"/>`,
			want: "unused|urn:unused|urn:unused",
		},
		{
			name: "namespace_after_child_is_rejected",
			body: `<out><child/><xsl:copy-of select="r/namespace::unused"/></out>`,
			code: "XTDE0410",
		},
		{
			name: "document_cannot_contain_a_namespace",
			body: `<xsl:copy-of select="r/namespace::unused"/>`,
			code: "XTDE0420",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			source := parseTestDocument(t, `<!--first--><r xmlns:p="urn:label" xmlns:q="urn:code" xmlns:unused="urn:unused" xmlns:alias="urn:outer"><p:label xmlns:alias="urn:near" q:code="one"><child q:code="two">text</child></p:label></r><?last done?>`)
			source.SetURL("urn:source")
			ss := compileTestStylesheet(t, "", tc.body)
			got, err := ss.Transform(source).Serialize(t.Context())
			requireSerialization(t, got, err, tc.want, tc.code)
		})
	}
}

func TestExecCopyOfAccumulators(t *testing.T) {
	t.Parallel()

	const accumulator = `
		<xsl:accumulator name="seen" as="xs:integer" initial-value="0">
			<xsl:accumulator-rule match="n" select="$value + 1"/>
		</xsl:accumulator>`

	for _, tc := range []struct {
		name, mode, want, code string
	}{
		{name: "explicit_list_transfers_source_values", mode: `<xsl:mode use-accumulators="seen"/>`, want: "3"},
		{name: "all_transfers_source_values", mode: `<xsl:mode use-accumulators="#all"/>`, want: "3"},
		{name: "mode_without_accumulators_rejects_copy", mode: `<xsl:mode use-accumulators=""/>`, code: "XTDE3362"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ss := compileTestStylesheet(t, tc.mode+accumulator, `
				<xsl:variable name="last" as="element()"><xsl:copy-of select="r/n[3]" copy-accumulators="yes"/></xsl:variable>
				<xsl:for-each select="$last"><xsl:value-of select="accumulator-before('seen')"/></xsl:for-each>`)
			got, err := ss.Transform(parseTestDocument(t, `<r><n/><n/><n/></r>`)).Serialize(t.Context())
			requireSerialization(t, got, err, tc.want, tc.code)
		})
	}
}
