package xslt //nolint:testpackage // Exercises template selection and binding through local stylesheets.

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"

	"github.com/skarm/xmlsec/internal/lexicon"
	"github.com/skarm/xmlsec/transform/internal/xdm"
)

func TestStripDOEMarkersPreservesOrdinaryPI(t *testing.T) {
	t.Parallel()

	doc := xdm.NewDefaultDocument()
	note := xdm.NodeItem{Node: doc.CreatePI(lexicon.DisableOutputEscapingPITarget, "note")}
	text := xdm.NodeItem{Node: doc.CreateText("sample")}
	input := xdm.ItemSlice{note, xdm.NodeItem{Node: doc.CreateDOEMarker(true)}, text, xdm.NodeItem{Node: doc.CreateDOEMarker(false)}}
	result, marked := stripDOEMarkers(input)
	if xdm.SequenceLen(result) != 2 {
		t.Fatalf("stripped sequence = %v, want ordinary PI and text", result)
	}

	first, firstIsNode := result.Get(0).(xdm.NodeItem)
	second, secondIsNode := result.Get(1).(xdm.NodeItem)

	if !firstIsNode || !secondIsNode || first.Node != note.Node || second.Node != text.Node {
		t.Fatalf("stripped sequence = %v, want original node identities", result)
	}

	if _, ok := marked[1]; !ok || len(marked) != 1 {
		t.Fatalf("marked text positions = %v, want position 1", marked)
	}
}

func TestTemplateDispatchHandlesMultipleMatches(t *testing.T) {
	t.Parallel()

	const first = `<xsl:template match="n[@a]" mode="m" priority="1">first</xsl:template>`
	for _, tc := range []struct {
		name, policy, second, want, code string
	}{
		{"last_rule_wins", "use-last", `<xsl:template match="n[@b]" mode="m" priority="1">second</xsl:template>`, "second", ""},
		{"equal_priority_matches_conflict", "fail", `<xsl:template match="n[@b]" mode="m" priority="1">second</xsl:template>`, "", "XTDE0540"},
		{"equal_priority_nonmatching_rule_is_ignored", "fail", `<xsl:template match="n[@c]" mode="m" priority="1">second</xsl:template>`, "first", ""},
		{"lower_priority_does_not_conflict", "fail", `<xsl:template match="n[@b]" mode="m" priority="0">second</xsl:template>`, "first", ""},
		{"union_branches_of_one_rule_do_not_conflict", "fail", `<xsl:template match="n[@a] | n[@b]" mode="m" priority="1">union</xsl:template>`, "union", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			rules := tc.second
			if tc.name != "union_branches_of_one_rule_do_not_conflict" {
				rules = first + rules
			}
			ss := compileTestStylesheet(t, `<xsl:mode name="m" on-multiple-match="`+tc.policy+`"/>`+rules,
				`<xsl:apply-templates select="r/n" mode="m"/>`)
			got, err := ss.Transform(parseTestDocument(t, `<r><n a="1" b="1"/></r>`)).Serialize(t.Context())
			requireSerialization(t, got, err, tc.want, tc.code)
		})
	}
}

func TestAtomicTemplateDispatchHandlesMultipleMatches(t *testing.T) {
	t.Parallel()

	const first = `<xsl:template match=".[. instance of xs:integer]" mode="m" priority="1">integer</xsl:template>`
	for _, tc := range []struct {
		name, second, want, code string
	}{
		{"equal_priority_matches_conflict", `<xsl:template match=".[. gt 0]" mode="m" priority="1">positive</xsl:template>`, "", "XTDE0540"},
		{"equal_priority_nonmatching_rule_is_ignored", `<xsl:template match=".[. lt 0]" mode="m" priority="1">negative</xsl:template>`, "integer", ""},
		{"lower_priority_does_not_conflict", `<xsl:template match=".[. gt 0]" mode="m" priority="0">positive</xsl:template>`, "integer", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ss := compileTestStylesheet(t, `<xsl:mode name="m" on-multiple-match="fail"/>`+first+tc.second,
				`<xsl:apply-templates select="7" mode="m"/>`)
			got, err := ss.Transform(parseTestDocument(t, `<r/>`)).Serialize(t.Context())
			requireSerialization(t, got, err, tc.want, tc.code)
		})
	}
}

func TestApplyTemplatesBindsParameters(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name, selectItems, rule, params, applyParams, value, want, code string
	}{
		{"node_select_default_uses_matched_node", "r/n", "n", `<xsl:param name="p" select="@label"/>`, "", "$p", "node", ""},
		{"atomic_select_default_uses_matched_item", "7", ".[. instance of xs:integer]", `<xsl:param name="p" as="xs:integer" select=". + 1"/>`, "", "$p", "8", ""},
		{"untyped_body_default_builds_document", "r/n", "n", `<xsl:param name="p"><part>body</part></xsl:param>`, "", "$p/part", "body", ""},
		{"typed_body_default_keeps_atomic_items", "r/n", "n", `<xsl:param name="p" as="xs:integer+"><xsl:sequence select="(2,3)"/></xsl:param>`, "", "sum($p)", "5", ""},
		{"tunnel_parameter_overrides_default", "r/n", "n", `<xsl:param name="p" tunnel="yes" select="'default'"/>`, `<xsl:with-param name="p" tunnel="yes" select="'caller'"/>`, "$p", "caller", ""},
		{"ordinary_parameter_does_not_override_tunnel_default", "r/n", "n", `<xsl:param name="p" tunnel="yes" select="'default'"/>`, `<xsl:with-param name="p" select="'caller'"/>`, "$p", "default", ""},
		{"missing_required_parameter", "r/n", "n", `<xsl:param name="p" required="yes"/>`, "", "$p", "", "XTDE0700"},
		{"caller_value_must_match_declared_type", "r/n", "n", `<xsl:param name="p" as="xs:integer" select="1"/>`, `<xsl:with-param name="p" select="'invalid'"/>`, "$p", "", "XTTE0590"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ss := compileTestStylesheet(t, `<xsl:template mode="m" match="`+tc.rule+`">`+tc.params+`<xsl:value-of select="`+tc.value+`"/></xsl:template>`,
				`<xsl:apply-templates select="`+tc.selectItems+`" mode="m">`+tc.applyParams+`</xsl:apply-templates>`)
			got, err := ss.Transform(parseTestDocument(t, `<r><n label="node"/></r>`)).Serialize(t.Context())
			requireSerialization(t, got, err, tc.want, tc.code)
		})
	}
}

func TestTemplateContextItemAbsent(t *testing.T) {
	t.Parallel()
	for _, entry := range []struct{ name, match, invoke, arguments, current string }{
		{
			"node", ` match="n"`, `<xsl:apply-templates select="r/n">%s</xsl:apply-templates>`,
			`<xsl:with-param name="p" select="count(r/n)"/>`, "ab",
		},
		{
			"atomic", ` match=".[. instance of xs:integer]"`, `<xsl:apply-templates select="(1,2)">%s</xsl:apply-templates>`,
			`<xsl:with-param name="p" select="count(r/n)"/>`, "12",
		},
		{
			"named", "", `<xsl:for-each select="r/n"><xsl:call-template name="target">%s</xsl:call-template></xsl:for-each>`,
			`<xsl:with-param name="p" select="last()"/>`, "ab",
		},
	} {
		for _, tc := range []struct {
			name, param, selectValue, want, code string
			absent, supply                       bool
		}{
			{name: "body has no item", selectValue: ".", code: "XPDY0002", absent: true},
			{name: "body has no current item", selectValue: "current()", code: "XTDE1360", absent: true},
			{name: "body has no context size", selectValue: "last()", code: "XPDY0002", absent: true},
			{name: "default has no context item", param: `<xsl:param name="p" select="."/>`, selectValue: "$p", code: "XPDY0002", absent: true},
			{name: "default has no position", param: `<xsl:param name="p" select="position()"/>`, selectValue: "$p", code: "XPDY0002", absent: true},
			{name: "next match has no current rule", code: "XTDE0560", absent: true},
			{name: "argument has caller focus", param: `<xsl:param name="p" select="."/>`, selectValue: "$p", want: "22", absent: true, supply: true},
			{name: "ordinary focus position and size", param: `<xsl:param name="p" select="position() || '/' || last()"/>`, selectValue: "$p || ';'", want: "1/2;2/2;"},
			{name: "ordinary focus current item", selectValue: "current()", want: entry.current},
		} {
			t.Run(entry.name+"/"+tc.name, func(t *testing.T) {
				t.Parallel()
				decl := `<xsl:template name="target"` + entry.match + `>`
				if tc.absent {
					decl += `<xsl:context-item use="absent"/>`
				}
				body := `<xsl:value-of select="` + tc.selectValue + `"/>`
				if tc.selectValue == "" {
					body = `<xsl:next-match/>`
				}
				decl += tc.param + body + `</xsl:template>`
				arg := ""
				if tc.supply {
					arg = entry.arguments
				}
				ss := compileTestStylesheet(t, decl, fmt.Sprintf(entry.invoke, arg))
				got, err := ss.Transform(parseTestDocument(t, `<r><n>a</n><n>b</n></r>`)).Serialize(t.Context())
				if tc.code == "XPDY0002" {
					detail, ok := errors.AsType[*xdm.Error](err)
					if got != "" || !ok || detail.Code != tc.code {
						t.Fatalf("serialized output = %q, error = %v; want no output and %s", got, err, tc.code)
					}
					return
				}
				requireSerialization(t, got, err, tc.want, tc.code)
			})
		}
	}
}

func TestTemplateDispatchModes(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name, behavior, rules, want, code string
	}{
		{"text_only_copy", "text-only-copy", "", "AB", ""},
		{"shallow_skip_visits_descendants", "shallow-skip", `<xsl:template match="leaf" mode="m"><xsl:text>visited</xsl:text></xsl:template>`, "visited", ""},
		{"deep_skip_ignores_descendants", "deep-skip", `<xsl:template match="leaf" mode="m"><xsl:text>visited</xsl:text></xsl:template>`, "", ""},
		{"fail_without_rule", "fail", "", "", "XTDE0555"},
		{"next_match_uses_lower_priority", "fail", `<xsl:template match="root" mode="m" priority="2"><xsl:text>first:</xsl:text><xsl:next-match/></xsl:template><xsl:template match="root" mode="m" priority="1"><xsl:text>second</xsl:text></xsl:template>`, "first:second", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ss := compileTestStylesheet(t, `<xsl:mode name="m" on-no-match="`+tc.behavior+`"/>`+tc.rules, `<xsl:apply-templates select="root" mode="m"/>`)
			source := parseTestDocument(t, `<root>A<leaf>B</leaf></root>`)
			got, err := ss.Transform(source).Serialize(t.Context())
			requireSerialization(t, got, err, tc.want, tc.code)
		})
	}
}

func TestApplyImportsResolvesTiedRules(t *testing.T) {
	t.Parallel()
	for _, item := range []struct{ name, selectItems, match, firstMode string }{
		{"node", "r/n", "n", "m"},
		{"atomic", "7", ".[. instance of xs:integer]", "m"},
		{"imported_all_mode", "r/n", "n", "#all"},
	} {
		for _, tc := range []struct{ policy, secondPriority, want, code string }{
			{"fail", "1", "", "XTDE0540"},
			{"use-last", "1", "second", ""},
			{"fail", "0", "first", ""},
		} {
			t.Run(item.name+"/"+tc.policy+"/"+tc.secondPriority, func(t *testing.T) {
				t.Parallel()
				const ns = ` xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:xs="http://www.w3.org/2001/XMLSchema" version="3.0">`
				imported := `<xsl:stylesheet` + ns +
					`<xsl:template match="` + item.match + `" mode="` + item.firstMode + `" priority="1">first</xsl:template>` +
					`<xsl:template match="` + item.match + `" mode="m" priority="` + tc.secondPriority + `">second</xsl:template></xsl:stylesheet>`
				principal := `<xsl:stylesheet` + ns + `<xsl:import href="rules.xsl"/><xsl:output method="text"/>` +
					`<xsl:mode name="m" on-multiple-match="` + tc.policy + `"/>` +
					`<xsl:template match="/"><xsl:apply-templates select="` + item.selectItems + `" mode="m"/></xsl:template>` +
					`<xsl:template match="` + item.match + `" mode="m"><xsl:apply-imports/></xsl:template></xsl:stylesheet>`
				resolver := contractURIResolver(func(_ context.Context, uri string) (io.ReadCloser, error) {
					if uri != "https://example.test/rules.xsl" {
						t.Errorf("unexpected stylesheet URI %q", uri)
					}
					return io.NopCloser(strings.NewReader(imported)), nil
				})
				ss, err := NewCompiler().BaseURI("https://example.test/main.xsl").URIResolver(resolver).
					Compile(t.Context(), parseTestDocument(t, principal))
				if err != nil {
					t.Fatal(err)
				}
				got, err := ss.Transform(parseTestDocument(t, `<r><n/></r>`)).Serialize(t.Context())
				requireSerialization(t, got, err, tc.want, tc.code)
			})
		}
	}
}

func TestAllModeRulesKeepDeclarationOrder(t *testing.T) {
	t.Parallel()
	const (
		all   = `<xsl:template match="n" mode="#all">all</xsl:template>`
		named = `<xsl:template match="n" mode="m">named</xsl:template>`
		mode  = `<xsl:mode name="m"/>`
	)
	for _, tc := range []struct{ name, rules, applyMode, want string }{
		{"first_named_rule_follows_all", mode + all + named, "m", "named"},
		{"all_follows_named_rule", mode + named + all, "m", "all"},
		{"explicit_priority_beats_declaration_order", mode + `<xsl:template match="n" mode="#all" priority="2">all</xsl:template>` + named, "m", "all"},
		{"unnamed_rule_follows_all", all + `<xsl:template match="n">unnamed</xsl:template>`, "#unnamed", "unnamed"},
		{"all_applies_once_per_split_branch", mode + all + `<xsl:template match="n | element(n)" mode="#all">split:<xsl:next-match/></xsl:template>`, "m", "split:split:all"},
		{"implicitly_declared_mode_keeps_next_match", all + `<xsl:template match="n" mode="#all" priority="2">next:<xsl:next-match/></xsl:template>`, "m", "next:all"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ss := compileTestStylesheet(t, tc.rules, `<xsl:apply-templates select="r/n" mode="`+tc.applyMode+`"/>`)
			got, err := ss.Transform(parseTestDocument(t, `<r><n/></r>`)).Serialize(t.Context())
			requireSerialization(t, got, err, tc.want, "")
			for name, rules := range ss.modeTemplates {
				seen := make(map[*template]bool, len(rules))
				for _, rule := range rules {
					if seen[rule] {
						t.Errorf("mode %q registered the same rule twice", name)
					}
					seen[rule] = true
				}
			}
		})
	}
}

func TestCallTemplateMergeContext(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct{ name, param, value, args, want, code string }{
		{"caller argument retains group", `<xsl:param name="p"/>`, "$p", `<xsl:with-param name="p" select="count(current-merge-group())"/>`, "2:1", ""},
		{"callee default has no group", `<xsl:param name="p" select="count(current-merge-group())"/>`, "$p", "", "", "XTDE3480"},
		{"callee body has no key", "", "string(current-merge-key())", "", "", "XTDE3510"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ss := compileTestStylesheet(t, `<xsl:template name="receiver">`+tc.param+
				`<xsl:value-of select="`+tc.value+`"/></xsl:template>`,
				`<xsl:merge><xsl:merge-source select="(1,1)"><xsl:merge-key select="."/></xsl:merge-source>
				<xsl:merge-action><xsl:call-template name="receiver">`+tc.args+`</xsl:call-template>
				<xsl:value-of select="':' || current-merge-key()"/></xsl:merge-action></xsl:merge>`)
			got, err := ss.Transform(parseTestDocument(t, `<r/>`)).Serialize(t.Context())
			requireSerialization(t, got, err, tc.want, tc.code)
		})
	}
}

func TestApplyTemplatesSortPreservesVariableOrder(t *testing.T) {
	t.Parallel()
	ss := compileTestStylesheet(t, `<xsl:template match="n" mode="m"><xsl:value-of select="@id"/></xsl:template>`,
		`<xsl:variable name="items" as="element()*" select="r/n"/>
		<xsl:apply-templates select="$items" mode="m"><xsl:sort select="@id"/></xsl:apply-templates>
		<xsl:text>|</xsl:text><xsl:value-of select="$items/@id" separator=""/>
		<xsl:text>|</xsl:text><xsl:apply-templates select="$items" mode="m"/>`)
	got, err := ss.Transform(parseTestDocument(t, `<r><n id="b"/><n id="a"/></r>`)).Serialize(t.Context())
	requireSerialization(t, got, err, "ab|ba|ba", "")
}

func TestTypedNamedTemplateArrayUsesDestinationContentRules(t *testing.T) {
	t.Parallel()
	const declarations = `
		<xsl:template name="items" as="item()*">
			<xsl:param name="node" as="element(n)"/>
			<xsl:sequence select="('start', ['first', [], ('second', [$node, 'third'])], 'end')"/>
		</xsl:template>
		<xsl:template name="invalid-content" as="array(*)">
			<xsl:sequence select="['text', [map{'letter':'a'}]]"/>
		</xsl:template>`
	const call = `<xsl:call-template name="items"><xsl:with-param name="node" select="r/n"/></xsl:call-template>`
	for _, tc := range []struct{ name, body, want, code string }{
		{
			name: "complex_content_flattens_arrays_and_copies_nodes",
			body: `<xsl:variable name="result" as="element(out)"><out>` + call + `</out></xsl:variable>
				<xsl:value-of select="($result/text()[1], string($result/n), $result/text()[2],
					$result/n is r/n)" separator="|"/>`,
			want: "start first second|node|third end|false",
		},
		{
			name: "sequence_capture_keeps_array_and_node_identity",
			body: `<xsl:variable name="result" as="item()*">` + call + `</xsl:variable>
				<xsl:value-of select="(count($result), $result[1], $result[2] instance of array(*),
					($result[2]?3)[2]?1 is r/n, $result[3])" separator="|"/>`,
			want: "3|start|true|true|end",
		},
		{
			name: "map_member_is_rejected_in_complex_content",
			body: `<out><xsl:call-template name="invalid-content"/></out>`,
			code: "XTDE0450",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ss := compileTestStylesheet(t, declarations, tc.body)
			got, err := ss.Transform(parseTestDocument(t, `<r><n>node</n></r>`)).Serialize(t.Context())
			requireSerialization(t, got, err, tc.want, tc.code)
		})
	}

	t.Run("raw_delivery_keeps_array", func(t *testing.T) {
		t.Parallel()
		ss := compileTestStylesheet(t, declarations, call)
		invocation := ss.Transform(parseTestDocument(t, `<r><n>node</n></r>`))
		result, err := invocation.Execute(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		items := result.Primary.Items
		if xdm.SequenceLen(items) != 3 {
			t.Fatalf("raw output has %d items, want 3", xdm.SequenceLen(items))
		}
		if array, ok := items.Get(1).(xdm.ArrayItem); !ok || array.Size() != 3 {
			t.Fatalf("raw item 2 = %v, want an unexpanded array of 3 members", items.Get(1))
		}
	})
}

func TestTypedTemplateAtomicOutput(t *testing.T) {
	t.Parallel()

	const (
		prefix = `<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
			xmlns:xs="http://www.w3.org/2001/XMLSchema" exclude-result-prefixes="xs" version="3.0">
			<xsl:output method="xml" omit-xml-declaration="yes" item-separator="|"/>
			<xsl:template name="typed" as="item()*"><xsl:sequence select="`
		match = `"/></xsl:template><xsl:template match="/">`
		call  = `<xsl:call-template name="typed"/>`
		tail  = `</xsl:template></xsl:stylesheet>`
	)

	for _, tc := range []struct{ name, value, body, want string }{
		{"discard_vacuous_separator", "('', '')", `<out>` + call + `<xsl:on-empty select="'fallback'"/></out>`, "<out>fallback</out>"},
		{"vacuous_separator_does_not_trigger_on_non_empty", "('', '')", `<out>` + call + `<xsl:on-non-empty><extra/></xsl:on-non-empty></out>`, "<out> </out>"},
		{"retain_an_ordinary_empty_atomic_gap", "(1, '', 2)", `<out>` + call + `</out>`, "<out>1  2</out>"},
		{"apply_primary_item_separator_only_at_boundary", "(1, 2)", `<before/>` + call + `<inside>` + call + `</inside><after/>`, "<before/>|1|2|<inside>1 2</inside>|<after/>"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ss, err := NewCompiler().Compile(t.Context(), parseTestDocument(t, prefix+tc.value+match+tc.body+tail))
			if err != nil {
				t.Fatal(err)
			}
			got, err := ss.Transform(parseTestDocument(t, "<r/>")).Serialize(t.Context())
			requireSerialization(t, got, err, tc.want, "")
		})
	}
}

func TestReviewTemplateReturnTypeUsesDeclarationNamespaces(t *testing.T) {
	for _, tc := range []struct{ name, declarations, body string }{
		{"named prefix", `<xsl:template name="first" xmlns:p="urn:first" as="element(p:n)"><p:n>ok</p:n></xsl:template><xsl:template name="other" xmlns:p="urn:other"/>`, `<xsl:call-template name="first"/>`},
		{"atomic default", `<xsl:template match=".[. instance of xs:integer]" xpath-default-namespace="urn:first" as="element(n)"><n xmlns="urn:first">ok</n></xsl:template>`, `<xsl:apply-templates select="1"/>`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ss := compileTestStylesheet(t, tc.declarations, tc.body)
			got, err := ss.Transform(parseTestDocument(t, `<r/>`)).Serialize(t.Context())
			requireSerialization(t, got, err, "ok", "")
		})
	}
}
