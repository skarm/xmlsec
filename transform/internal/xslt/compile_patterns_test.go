package xslt //nolint:testpackage // Exercises match-pattern compilation and dispatch directly.

import (
	"context"
	"errors"
	"io"
	"testing"

	"github.com/skarm/xmlsec/transform/internal/xdm"
)

func TestMatchPatternResolvesExpandedKindTestNames(t *testing.T) {
	t.Parallel()

	const input = `<r xmlns="https://example.test/items" xmlns:p="https://example.test/items" xmlns:q="urn:other" id="plain" p:id="bound"><p:n>A</p:n><q:n>B</q:n><n xmlns="">C</n></r>`
	for _, tc := range []struct {
		name, pattern, population, want string
	}{
		{"braced_uri_with_colon", `element(Q{https://example.test/items}n)`, `/*/*`, "A"},
		{"bare_element_uses_xpath_default_namespace", `element(n)`, `/*/*`, "A"},
		{"explicit_empty_uri_overrides_xpath_default", `element(Q{}n)`, `/*/*`, "C"},
		{"bare_attribute_has_no_namespace", `attribute(id)`, `/*/@*`, "plain"},
		{"braced_attribute_uri", `attribute(Q{https://example.test/items}id)`, `/*/@*`, "bound"},
		{"wildcard_with_attribute_type", `attribute(*, xs:untypedAtomic)`, `/*/@*`, "plainbound"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ss := compileTestStylesheet(t, `<xsl:mode name="m" on-no-match="deep-skip"/><xsl:template mode="m" xpath-default-namespace="https://example.test/items" match="`+tc.pattern+`"><xsl:value-of select="."/></xsl:template>`,
				`<xsl:apply-templates mode="m" select="`+tc.population+`"/>`)
			got, err := ss.Transform(parseTestDocument(t, input)).Serialize(t.Context())
			requireSerialization(t, got, err, tc.want, "")
		})
	}
}

func TestMatchElementPatternChecksTypeAndNilledStatus(t *testing.T) {
	t.Parallel()

	doc := parseTestDocument(t, `<root><n/><n/><n/></root>`)
	nodes := doc.DocumentElement()
	typed := nodes.FirstChild().(*xdm.Element)
	nilled := typed.NextSibling().(*xdm.Element)
	untyped := nilled.NextSibling().(*xdm.Element)
	ec := &execContext{stylesheet: &Stylesheet{}}
	ec.annotateNode(typed, xdm.TypeInteger)
	ec.annotateNode(nilled, xdm.TypeInteger)
	ec.markNilled(nilled)
	for _, tc := range []struct {
		name string
		node xdm.Node
		test xdm.ElementTest
		want bool
	}{
		{"integer_matches_decimal_supertype", typed, xdm.ElementTest{Name: "n", TypeName: "xs:decimal"}, true},
		{"unrelated_type", typed, xdm.ElementTest{Name: "n", TypeName: "xs:string"}, false},
		{"non_nillable_rejects_nilled_node", nilled, xdm.ElementTest{Name: "n", TypeName: "xs:integer"}, false},
		{"nillable_accepts_nilled_node", nilled, xdm.ElementTest{Name: "n", TypeName: "xs:integer", Nillable: true}, true},
		{"unannotated_node_is_untyped", untyped, xdm.ElementTest{Name: "n", TypeName: "xs:untyped"}, true},
		{"document_does_not_match_element_test", doc, xdm.ElementTest{}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := matchElementTest(t.Context(), ec, tc.test, tc.node); got != tc.want {
				t.Errorf("matchElementTest(%+v) = %t, want %t", tc.test, got, tc.want)
			}
		})
	}
}

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
		{"exact_decimal_at_position_matches", `b/n[1.0]`, "ae"},
		{"decimal_near_position_does_not_match", `b/n[1.0000000000000000001]`, ""},
		{"double_rounded_to_position_matches", `b/n[1.0000000000000000001e0]`, "ae"},
		{"descendant_or_self_can_match_ancestor_itself", `b/descendant-or-self::b/n`, "abdef"},
		{"following_axis_is_allowed_in_predicate", `n[following::n]`, "abcdef"},
		{"following_sibling_axis_is_allowed_in_predicate", `n[following-sibling::n]`, "abe"},
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
		{"document_test_rejects_text_beside_root", `document-node(element(r))`, `parse-xml-fragment('text&lt;r/>')`, `local-name(*)`, ""},
		{"unconstrained_document_test_accepts_text_beside_root", `document-node()`, `parse-xml-fragment('text&lt;r/>')`, `string(text())`, "text"},
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

func TestMatchPatternGroupingUsesSingletonFocus(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name, selectItems, boundary, want string
		ending                            bool
	}{
		{"atomic_boundary_does_not_see_population_position", `('red', 'green', 'blue', 'yellow')`, `.[position() eq 3 and . eq 'blue']`, "red,green,blue,yellow;", false},
		{"node_boundary_does_not_see_population_size", `reverse(r/n)`, `.[position() eq 2 and last() eq 4]`, "four,three,two,one;", false},
		{"numeric_predicate_above_one_never_matches", `(9,8,7,6)`, `.[2]`, "9,8,7,6;", false},
		{"decimal_near_one_never_matches", `(9,8,7,6)`, `.[1.0000000000000000001]`, "9,8,7,6;", false},
		{"exact_decimal_one_matches_every_item", `(9,8,7,6)`, `.[1.0]`, "9;8;7;6;", false},
		{"double_rounded_to_one_matches_every_item", `(9,8,7,6)`, `.[1.0000000000000000001e0]`, "9;8;7;6;", false},
		{"ending_boundary_matches_value_at_singleton_focus", `(9,8,7,6)`, `.[position() eq 1 and last() eq 1 and . eq 8]`, "9,8;7,6;", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			attribute := "group-starting-with"
			if tc.ending {
				attribute = "group-ending-with"
			}
			ss := compileTestStylesheet(t, "", `<xsl:for-each-group select="`+tc.selectItems+`" `+attribute+`="`+tc.boundary+`"><xsl:value-of select="string-join(current-group() ! string(.), ',') || ';'"/></xsl:for-each-group>`)
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
		{"following_axis", `following::n`, "XTSE0340"},
		{"following_sibling_axis", `following-sibling::n`, "XTSE0340"},
		{"following_sibling_axis_after_id", `id('x')/following-sibling::n`, "XTSE0340"},
		{"ancestor_axis_after_id", `id('x')/ancestor::n`, "XTSE0340"},
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

func TestPatternConsumersPreserveResourceFailure(t *testing.T) {
	const itemPattern = ".[doc('https://example.test/unavailable')]"
	const nodePattern = "r[doc('https://example.test/unavailable')]"
	for _, tc := range []struct{ name, declarations, body string }{
		{"atomic rule", `<xsl:template mode="m" match="` + itemPattern + `">matched</xsl:template>`, `<xsl:apply-templates select="1" mode="m"/>`},
		{"group boundary", "", `<xsl:for-each-group select="1 to 3" group-ending-with="` + itemPattern + `">group</xsl:for-each-group>`},
		{"number", "", `<xsl:number select="r" count="` + nodePattern + `"/>`},
		{"key index", `<xsl:key name="k" match="` + nodePattern + `" use="'id'"/>`, `<xsl:value-of select="count(key('k', 'id'))"/>`},
		{"next match", `<xsl:template mode="m" match="r" priority="2"><xsl:next-match/></xsl:template><xsl:template mode="m" match="` + nodePattern + `">matched</xsl:template>`, `<xsl:apply-templates select="r" mode="m"/>`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ss := compileTestStylesheet(t, tc.declarations, tc.body)
			input := parseTestDocument(t, `<r/>`)
			resolver := contractURIResolver(func(context.Context, string) (io.ReadCloser, error) {
				return nil, ErrResourceTooLarge
			})
			if _, err := ss.Transform(input).URIResolver(resolver).Serialize(t.Context()); !errors.Is(err, ErrResourceTooLarge) {
				t.Fatalf("got %v; want original resource limit", err)
			}
		})
	}
}

func TestReviewAtomicPatternUsesDeclaredCollation(t *testing.T) {
	const declarations = `<xsl:mode name="m" on-no-match="deep-skip"/><xsl:template mode="m" match=".[. eq 'a']" default-collation="http://www.w3.org/2005/xpath-functions/collation/html-ascii-case-insensitive">matched</xsl:template>`
	ss := compileTestStylesheet(t, declarations, `<xsl:apply-templates mode="m" select="'A'"/>`)
	got, err := ss.Transform(parseTestDocument(t, `<r/>`)).Serialize(t.Context())
	requireSerialization(t, got, err, "matched", "")
}

func TestReviewPatternsPreserveControlFailures(t *testing.T) {
	for _, cause := range []error{context.Canceled, ErrResourceTooLarge} {
		ss := compileTestStylesheet(t, `<xsl:template match="r[doc('https://example.test/probe')]"><xsl:text>matched</xsl:text></xsl:template>`, `<xsl:apply-templates select="r"/>`)
		resolver := contractURIResolver(func(context.Context, string) (io.ReadCloser, error) { return nil, cause })
		got, err := ss.Transform(parseTestDocument(t, `<r/>`)).URIResolver(resolver).Serialize(t.Context())
		if !errors.Is(err, cause) {
			t.Errorf("pattern returned %q, %v; want control cause %v", got, err, cause)
		}
	}
}
