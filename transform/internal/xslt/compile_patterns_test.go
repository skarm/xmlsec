package xslt //nolint:testpackage // Exercises match-pattern compilation and dispatch directly.

import (
	"errors"
	"testing"
)

func TestMatchPatternPathAndPredicateFocus(t *testing.T) {
	t.Parallel()
	const input = `<r><b><n id="a" keep="yes"/><n id="b"/><box><n id="c" keep="yes"/></box><n id="d" keep="yes"/></b><b><n id="e" keep="yes"/><n id="f" keep="yes"/></b><outside><n id="g" keep="yes"/></outside></r>`
	for _, tc := range []struct {
		name, pattern, want string
	}{
		{"child_path_uses_immediate_parent", `b/n`, "abdef"},
		{"absolute_path_requires_document_root", `/r/b/n`, "abdef"},
		{"descendant_axis_positions_are_per_ancestor", `b/descendant::n[@keep][2]`, "cf"},
		{"child_predicates_filter_before_numbering", `b/n[@keep][2]`, "df"},
		{"descendant_or_self_can_match_ancestor_itself", `b/descendant-or-self::b/n`, "abdef"},
		{"parenthesized_step_checks_its_predecessor", `b/(n | box)`, "abdef"},
		{"abbreviated_descendant_path_finds_ancestor", `b//n`, "abcdef"},
		{"union_does_not_select_twice", `b/n | b/n[@keep] | outside/n`, "abdefg"},
		{"except_excludes_nodes_by_identity", `b//n except b/n[@keep]`, "bc"},
		{"intersect_keeps_nodes_selected_by_both_sides", `/r/b//n intersect /r//n[@keep]`, "acdef"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ss := compileTestStylesheet(t, `<xsl:template mode="select" match="`+tc.pattern+`"><xsl:value-of select="@id"/></xsl:template>`,
				`<xsl:apply-templates mode="select" select="r//n"/>`)
			got, err := ss.Transform(parseTestDocument(t, input)).Serialize(t.Context())
			requireSerialization(t, got, err, tc.want, "")
		})
	}
}

func TestMatchPatternExpandedNamesAndNodeKinds(t *testing.T) {
	t.Parallel()
	const input = `<?label main?><r xmlns:p="urn:sample" xmlns:q="urn:other" p:id="P" id="plain"><p:n>A</p:n><q:n>B</q:n><n>C</n><!--note--><?label local?><?other ignored?></r>`
	for _, tc := range []struct {
		name, pattern, selectNodes, value, want string
	}{
		{"kind_test_matches_expanded_element_name", `element(f:n)`, `r/*`, `.`, "A"},
		{"kind_test_matches_untyped_element", `element(f:n, xs:untyped)`, `r/*`, `.`, "A"},
		{"kind_test_matches_untyped_attribute", `attribute(f:id, xs:untypedAtomic)`, `r/@*`, `.`, "P"},
		{"attribute_name_ignores_element_default_namespace", `attribute(id)`, `r/@*`, `.`, "plain"},
		{"attribute_axis_keeps_node_identity_through_self", `@f:id/self::node()`, `r/@*`, `.`, "P"},
		{"namespace_wildcard_selects_other_local_names", `f:*`, `r/*`, `.`, "A"},
		{"local_wildcard_selects_all_matching_local_names", `*:n`, `r/*`, `.`, "ABC"},
		{"document_test_ignores_prolog_processing_instruction", `document-node(element(r))`, `/`, `local-name(*)`, "r"},
		{"document_test_rejects_wrong_root_name", `document-node(element(missing))`, `/`, `local-name(*)`, ""},
		{"processing_instruction_matches_its_target", `processing-instruction('label')`, `/processing-instruction() | r/processing-instruction()`, `.`, "mainlocal"},
		{"comments_have_their_own_node_kind", `comment()`, `r/node()`, `.`, "note"},
		{"namespace_pattern_matches_prefix", `namespace::p`, `r/namespace::*`, `.`, "urn:sample"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ss := compileTestStylesheet(t, `<xsl:mode name="select" on-no-match="deep-skip"/><xsl:template mode="select" xmlns:f="urn:sample" match="`+tc.pattern+`"><xsl:value-of select="`+tc.value+`"/></xsl:template>`,
				`<xsl:apply-templates mode="select" select="`+tc.selectNodes+`"/>`)
			got, err := ss.Transform(parseTestDocument(t, input)).Serialize(t.Context())
			requireSerialization(t, got, err, tc.want, "")
		})
	}
}

func TestMatchPatternGroupingUsesPopulationFocus(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name, selectItems, boundary, want string
	}{
		{"atomic_boundary_uses_value_and_position", `('red', 'green', 'blue', 'yellow')`, `.[position() eq 3 and . eq 'blue']`, "red,green;blue,yellow;"},
		{"node_boundary_uses_reordered_population", `reverse(r/n)`, `.[position() eq 2 and last() eq 4]`, "four;three,two,one;"},
		{"numeric_predicate_starts_group_at_given_position", `(9,8,7,6)`, `.[2]`, "9;8,7,6;"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ss := compileTestStylesheet(t, "", `<xsl:for-each-group select="`+tc.selectItems+`" group-starting-with="`+tc.boundary+`"><xsl:value-of select="string-join(current-group() ! string(.), ',') || ';'"/></xsl:for-each-group>`)
			got, err := ss.Transform(parseTestDocument(t, `<r><n>one</n><n>two</n><n>three</n><n>four</n></r>`)).Serialize(t.Context())
			requireSerialization(t, got, err, tc.want, "")
		})
	}
}

func TestCompilePatternReportsStaticErrors(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name, pattern, code string
	}{
		{"unbalanced_predicate", `n[1`, "XTSE0340"},
		{"undeclared_prefix", `missing:n`, "XTSE0340"},
		{"reverse_axis", `ancestor::n`, "XTSE0340"},
		{"binary_operator", `n + 1`, "XTSE0340"},
		{"function_cannot_start_path", `string('n')/child::n`, "XTSE0340"},
		{"predicate_pattern_cannot_be_union_member", `n | .[true()]`, "XTSE0340"},
		{"predicate_pattern_cannot_be_parenthesized", `(.[true()])`, "XTSE0340"},
		{"group_members_not_available_in_match_pattern", `n[current-group()]`, "XTSE1060"},
		{"group_key_not_available_in_match_pattern", `n[Q{http://www.w3.org/2005/xpath-functions}current-grouping-key()]`, "XTSE1070"},
		{"merge_members_not_available_in_match_pattern", `n[current-merge-group()]`, "XTSE3470"},
		{"merge_key_not_available_in_match_pattern", `n[current-merge-key()]`, "XTSE3500"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			doc := stylesheetDocument(t, `<xsl:template match="`+tc.pattern+`"/>`, "")
			sheet, err := NewCompiler().Compile(t.Context(), doc)
			var detail *XSLTError
			if sheet != nil || !errors.As(err, &detail) || detail.Code != tc.code {
				t.Errorf("compile match=%q returned stylesheet=%v, error=%v; want no stylesheet and %s", tc.pattern, sheet != nil, err, tc.code)
			}
		})
	}
}

func TestCompilePatternRespectsXSLT20Grammar(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name, pattern, want, code string
	}{
		{"id_with_literal_followed_by_child_step", `id('picked')/n`, "A", ""},
		{"id_with_variable", `id($ids)/n`, "A", ""},
		{"key_with_literal_name_and_value", `key('by-kind','x')/n`, "A", ""},
		{"function_prefix_disallowed_in_pattern_head", `fn:id('picked')/n`, "", "XTSE0340"},
		{"id_expression_is_not_literal_or_variable", `id(concat('pick','ed'))/n`, "", "XTSE0340"},
		{"id_argument_must_be_string_literal", `id(1)/n`, "", "XTSE0340"},
		{"key_name_must_be_string_literal", `key($ids,'x')/n`, "", "XTSE0340"},
		{"key_has_two_arguments", `key('by-kind','x',/)/n`, "", "XTSE0340"},
		{"predicate_pattern_requires_xslt_3", `.[true()]`, "", "XTSE0340"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			doc := parseTestDocument(t, `<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:fn="http://www.w3.org/2005/xpath-functions" version="2.0">
				<xsl:output method="text"/><xsl:variable name="ids" select="'picked'"/><xsl:key name="by-kind" match="group" use="@kind"/>
				<xsl:template match="/"><xsl:apply-templates select="r/group/n"/></xsl:template>
				<xsl:template match="n" priority="-1"/><xsl:template match="`+tc.pattern+`"><xsl:value-of select="@id"/></xsl:template>
			</xsl:stylesheet>`)
			ss, err := NewCompiler().ProcessorVersion(20).Compile(t.Context(), doc)
			if tc.code != "" {
				var detail *XSLTError
				if ss != nil || !errors.As(err, &detail) || detail.Code != tc.code {
					t.Fatalf("compile match=%q returned stylesheet=%v, error=%v; want no stylesheet and %s", tc.pattern, ss != nil, err, tc.code)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			got, err := ss.Transform(parseTestDocument(t, `<r><group xml:id="picked" kind="x"><n id="A"/></group><group xml:id="other" kind="y"><n id="B"/></group></r>`)).Serialize(t.Context())
			requireSerialization(t, got, err, tc.want, "")
		})
	}
}
