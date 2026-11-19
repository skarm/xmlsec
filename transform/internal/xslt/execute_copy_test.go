package xslt //nolint:testpackage // Exercises shallow copying within the executor.

import (
	"errors"
	"testing"

	"github.com/skarm/xmlsec/transform/internal/xdm"
)

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
		<xsl:accumulator name="seen" as="xs:integer" initial-value="0" streamable="yes">
			<xsl:accumulator-rule match="n" select="$value + 1"/>
		</xsl:accumulator>
		<xsl:accumulator name="other" initial-value="0"><xsl:accumulator-rule match="n" select="$value + 10"/></xsl:accumulator>`

	for _, tc := range []struct {
		name, mode, want, code string
	}{
		{name: "explicit_list_transfers_source_values", mode: `<xsl:mode use-accumulators="seen"/>`, want: "3"},
		{name: "all_transfers_source_values", mode: `<xsl:mode use-accumulators="#all"/>`, want: "3"},
		{name: "the_copy_without_grant_rejects_lookup", mode: `<xsl:mode use-accumulators=""/>`, code: "XTDE3362"},
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

func TestExecCopyOfPropagatesAccumulatorComputationFailure(t *testing.T) {
	t.Parallel()

	const declarations = `
		<xsl:mode use-accumulators="#all"/>
		<xsl:accumulator name="total" initial-value="0">
			<xsl:accumulator-rule match="item" select="accumulator-before('total') + 1"/>
		</xsl:accumulator>`
	const temporary = `<xsl:variable name="temporary" as="element()"><item/></xsl:variable>`
	const copyOf = `<xsl:copy-of select="$temporary" copy-accumulators="yes"/>`
	const caughtCopy = `<xsl:try xmlns:err="http://www.w3.org/2005/xqt-errors">` + copyOf + `<xsl:catch errors="err:XTDE3400"/></xsl:try>`
	for _, tc := range []struct{ name, body string }{
		{"reports_initial_failure", temporary + copyOf},
		{"reports_failure_again_after_catch", temporary + caughtCopy + copyOf},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ss := compileTestStylesheet(t, declarations, tc.body)
			got, err := ss.Transform(parseTestDocument(t, `<source/>`)).Serialize(t.Context())
			requireSerialization(t, got, err, "", "XTDE3400")
		})
	}
}

func TestCheckCopyOfNamespaceContent(t *testing.T) {
	t.Parallel()

	doc := parseTestDocument(t, `<root xmlns:q="urn:value"><child ref="q:value">q:value</child></root>`)
	root := doc.DocumentElement()
	child, ok := xdm.AsNode[*xdm.Element](root.FirstChild())
	if !ok {
		t.Fatal("source child is not an element")
	}
	attribute := child.Attributes()[0]

	for _, tc := range []struct {
		name        string
		node        xdm.Node
		annotated   xdm.Node
		annotation  string
		keepBinding bool
		wantCode    string
	}{
		{"element_can_keep_qname_content_with_bindings", root, child, xdm.TypeQName, true, ""},
		{"stripping_cannot_remove_qname_binding_from_descendant", root, child, xdm.TypeQName, false, "XTTE0950"},
		{"stripping_cannot_remove_notation_binding_from_attribute", root, attribute, xdm.TypeNOTATION, false, "XTTE0950"},
		{"standalone_qname_attribute_cannot_keep_binding", attribute, attribute, xdm.TypeQName, true, "XTTE0950"},
		{"prefixed_string_is_not_a_namespace_sensitive_value", root, child, xdm.TypeString, false, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ec := &execContext{typeAnnotations: map[xdm.Node]string{tc.annotated: tc.annotation}}
			err := ec.checkCopyOfNamespaceContent(tc.node, tc.keepBinding)
			if tc.wantCode == "" {
				if err != nil {
					t.Fatalf("namespace check: %v", err)
				}
				return
			}
			var detail *XSLTError
			if !errors.As(err, &detail) || detail.Code != tc.wantCode {
				t.Fatalf("namespace check error = %v; want %s", err, tc.wantCode)
			}
		})
	}
}

func TestCopyOfOrphanBaseURI(t *testing.T) {
	t.Parallel()
	const source = `<r xml:base="https://example.test/source/"><child xml:base="relative/"><leaf/><?item text?></child></r>`
	for _, copyNS := range []string{"yes", "no"} {
		t.Run(copyNS, func(t *testing.T) {
			t.Parallel()
			body := `<xsl:variable name="nodes" as="node()*" xml:base="https://example.test/style/">
				<xsl:copy-of xml:base="copy/" select="r/child, r/child/leaf, r/child/processing-instruction()" copy-namespaces="` + copyNS + `"/>
			</xsl:variable>
			<xsl:value-of select="($nodes[1], $nodes[1]/leaf, $nodes[2], $nodes[3]) ! base-uri(.)" separator="|"/>`
			ss := compileTestStylesheet(t, "", body)
			got, err := ss.Transform(parseTestDocument(t, source)).Serialize(t.Context())
			const fromStyle = "https://example.test/style/copy/relative/"
			const fromSource = "https://example.test/source/relative/"
			requireSerialization(t, got, err, fromStyle+"|"+fromStyle+"|"+fromSource+"|"+fromSource, "")
		})
	}
}

func TestCopyOrphanBaseURI(t *testing.T) {
	t.Parallel()
	const source = `<r xml:base="https://example.test/source/"><child xml:base="relative/"><?item text?></child></r>`
	const sourceBase = "https://example.test/source/relative/"
	for _, tc := range []struct{ name, instruction, want string }{
		{"omit source attribute", `<xsl:copy/>`, sourceBase},
		{"copy source attribute", `<xsl:copy xml:base="copy/"><xsl:copy-of select="@xml:base"/></xsl:copy>`, "https://example.test/style/copy/relative/"},
		{"construct another attribute", `<xsl:copy><xsl:attribute name="xml:base">new/</xsl:attribute></xsl:copy>`, "https://example.test/style/new/"},
		{"copy processing instruction", `<xsl:copy select="processing-instruction()"/>`, sourceBase},
		{"attach to new parent", `<parent xml:base="https://example.test/parent/"><xsl:copy><xsl:copy-of select="@xml:base"/></xsl:copy></parent>`, "https://example.test/parent/relative/"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			body := `<xsl:variable name="node" as="node()" xml:base="https://example.test/style/"><xsl:for-each select="r/child">` + tc.instruction + `</xsl:for-each></xsl:variable>
			<xsl:value-of select="base-uri(if ($node/self::parent) then $node/child else $node)"/>`
			ss := compileTestStylesheet(t, "", body)
			got, err := ss.Transform(parseTestDocument(t, source)).Serialize(t.Context())
			requireSerialization(t, got, err, tc.want, "")
		})
	}
}

func TestReviewConstructedAndCopiedNodeBaseURI(t *testing.T) {
	for _, tc := range []struct{ name, body, want string }{
		{"processing instruction constructor", `<xsl:variable name="node" as="processing-instruction()"><xsl:processing-instruction xml:base="https://example.test/styles/" name="item"/></xsl:variable><xsl:value-of select="base-uri($node)"/>`, "https://example.test/styles/"},
		{"element copy namespaces yes", `<xsl:variable name="node" as="element()"><xsl:copy-of select="r/child"/></xsl:variable><xsl:value-of select="base-uri($node)"/>`, "https://example.test/source/"},
		{"element copy namespaces no", `<xsl:variable name="node" as="element()"><xsl:copy-of select="r/child" copy-namespaces="no"/></xsl:variable><xsl:value-of select="base-uri($node)"/>`, "https://example.test/source/"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ss := compileTestStylesheet(t, "", tc.body)
			got, err := ss.Transform(parseTestDocument(t, `<r xml:base="https://example.test/source/"><child/></r>`)).Serialize(t.Context())
			requireSerialization(t, got, err, tc.want, "")
		})
	}
}
