package xslt //nolint:testpackage // Exercises internal XSLT sorting through stylesheet execution.

import (
	"context"
	"errors"
	"testing"

	"github.com/skarm/xmlsec/transform/internal/xdm"
	"github.com/skarm/xmlsec/transform/internal/xpath"
)

func TestPerformSortPreservesItemsAndStableOrder(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct{ name, body, want, code string }{
		{"numeric_items", `<xsl:perform-sort select="(10, 2, -1, 2)"><xsl:sort select="."/></xsl:perform-sort>`, "-1 2 2 10", ""},
		{"constructor_keys", `<xsl:perform-sort select="('bee','a','cat')"><xsl:sort><xsl:sequence select="string-length(.)"/></xsl:sort></xsl:perform-sort>`, "a bee cat", ""},
		{"multiple_node_keys_and_stable_ties", `<xsl:variable name="items" as="element()*"><xsl:perform-sort select="r/n"><xsl:sort select="@group"/><xsl:sort select="xs:integer(@rank)" order="descending"/></xsl:perform-sort></xsl:variable><xsl:value-of select="string-join($items ! string(@id), '|') || '/' || string-join($items/@id, '|')"/>`, "a3|a1|a2|b1/b1|a1|a3|a2", ""},
		{"exact_integer_keys", `<xsl:for-each select="(9007199254740993,9007199254740992)"><xsl:sort select="."/><xsl:value-of select=". || '|'"/></xsl:for-each>`, "9007199254740992|9007199254740993|", ""},
		{"float_promotion_preserves_tie", `<xsl:for-each select="('high','low')"><xsl:sort select="if (. = 'high') then 16777217 else xs:float('16777216')"/><xsl:value-of select=". || '|'"/></xsl:for-each>`, "high|low|", ""},
		{"temporal_keys_compare_instants", `<xsl:for-each select="('later','earlier')"><xsl:sort select="if (. = 'later') then xs:dateTime('2024-01-02T00:00:00Z') else xs:dateTime('2024-01-02T00:30:00+01:00')"/><xsl:value-of select=". || '|'"/></xsl:for-each>`, "earlier|later|", ""},
		{"empty_and_nan_descending", `<xsl:for-each select="('empty','invalid','two','ten')"><xsl:sort select="if (. = 'empty') then () else if (. = 'invalid') then xs:double('NaN') else if (. = 'two') then 2 else 10" order="descending"/><xsl:value-of select=". || '|'"/></xsl:for-each>`, "ten|two|invalid|empty|", ""},
		{"explicit_collation_ignores_case_order_avt", `<xsl:for-each select="('a','B','A')"><xsl:sort select="." collation="http://www.w3.org/2005/xpath-functions/collation/html-ascii-case-insensitive" case-order="{error()}"/><xsl:value-of select=". || '|'"/></xsl:for-each>`, "a|A|B|", ""},
		{"invalid_dynamic_order", `<xsl:for-each select="(1,2)"><xsl:sort select="." order="{'sideways'}"/></xsl:for-each>`, "", "XTDE0030"},
		{"mixed_incomparable_key_types", `<xsl:for-each select="(1,'two')"><xsl:sort select="."/><xsl:value-of select="."/></xsl:for-each>`, "", "XTDE1030"},
		{"multiple_atomic_keys_per_item", `<xsl:for-each select="(1,2)"><xsl:sort select="(., . + 1)"/><xsl:value-of select="."/></xsl:for-each>`, "", "XTTE1020"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			const input = `<r><n id="b1" group="B" rank="1"/><n id="a1" group="A" rank="1"/><n id="a3" group="A" rank="3"/><n id="a2" group="A" rank="1"/></r>`
			got, err := compileTestStylesheet(t, "", tc.body).Transform(parseTestDocument(t, input)).Serialize(t.Context())
			requireSerialization(t, got, err, tc.want, tc.code)
		})
	}
}

func TestSortGroupsUsesGroupFocusAndStableTies(t *testing.T) {
	t.Parallel()

	const input = `<r><n g="a">1</n><n g="b">2</n><n g="c">3</n><n g="d">4</n><n g="b">5</n><n g="d">6</n></r>`
	const result = `<xsl:value-of select="current-grouping-key() || ':' || string-join(current-group() ! string(.), ',') || ';'"/>`
	for _, tc := range []struct {
		name, keys, want, code string
	}{
		{"single_key_preserves_equal_key_group_order", `<xsl:sort select="count(current-group())" order="descending"/>`, "b:2,5;d:4,6;a:1;c:3;", ""},
		{"secondary_key_breaks_group_size_ties", `<xsl:sort select="count(current-group())" order="descending"/><xsl:sort select="current-grouping-key()" order="descending"/>`, "d:4,6;b:2,5;c:3;a:1;", ""},
		{"group_key_exposes_unsorted_group_position", `<xsl:sort select="position()" order="descending"/>`, "d:4,6;c:3;b:2,5;a:1;", ""},
		{"secondary_key_must_be_orderable_across_groups", `<xsl:sort select="count(current-group())"/><xsl:sort select="if (current-grouping-key() eq 'a') then 1 else 'text'"/>`, "", "XTDE1030"},
		{"group_sort_key_must_be_singleton", `<xsl:sort select="current-group()"/>`, "", "XTTE1020"},
		{"dynamic_unknown_collation", `<xsl:sort select="current-grouping-key()" collation="{'urn:unknown-collation'}"/>`, "", "XTDE1035"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			body := `<xsl:for-each-group select="r/n" group-by="@g">` + tc.keys + result + `</xsl:for-each-group>`
			ss := compileTestStylesheet(t, "", body)
			got, err := ss.Transform(parseTestDocument(t, input)).Serialize(t.Context())
			requireSerialization(t, got, err, tc.want, tc.code)
		})
	}
}

func TestSortDataTypeNamespace(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name, option, want, code string
	}{
		{"local_prefix", `xmlns:custom="urn:sort" data-type="custom:key"`, "102", ""},
		{"dynamic_local_prefix", `xmlns:local="http://www.w3.org/2005/xpath-functions" data-type="{local:string('text')}"`, "102", ""},
		{"dynamic_eqname", `data-type="{concat('Q', codepoints-to-string(123), 'urn:sort', codepoints-to-string(125), 'key')}"`, "102", ""},
		{"empty_eqname_namespace", `data-type="Q{{}}key"`, "", "XTSE0020"},
		{"whitespace_eqname_namespace", `data-type="Q{{ }}key"`, "", "XTSE0020"},
		{"unbound_prefix", `data-type="custom:key"`, "", "XTSE0020"},
		{"dynamic_empty_eqname_namespace", `data-type="{concat('Q', codepoints-to-string(123), codepoints-to-string(125), 'key')}"`, "", "XTDE0030"},
		{"dynamic_unbound_prefix", `data-type="{'custom:key'}"`, "", "XTDE0030"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			for _, inst := range []struct{ name, body string }{
				{"sort", `<xsl:for-each select="(2,10)"><xsl:sort select="." ` + tc.option + `/><xsl:value-of select="."/></xsl:for-each>`},
				{"merge", `<xsl:merge><xsl:merge-source select="(2,10)" sort-before-merge="yes"><xsl:merge-key select="." ` + tc.option + `/></xsl:merge-source><xsl:merge-action><xsl:value-of select="current-merge-key()"/></xsl:merge-action></xsl:merge>`},
			} {
				t.Run(inst.name, func(t *testing.T) {
					ss, err := NewCompiler().Compile(t.Context(), stylesheetDocument(t, "", inst.body))
					if tc.code == "XTSE0020" {
						requireSerialization(t, "", err, "", tc.code)
						return
					}

					if err != nil {
						t.Fatal(err)
					}

					got, err := ss.Transform(parseTestDocument(t, `<r/>`)).Serialize(t.Context())
					requireSerialization(t, got, err, tc.want, tc.code)
				})
			}
		})
	}
}

func TestSortDayTimeDurationPrecision(t *testing.T) {
	t.Parallel()

	const input = `<r><n id="high" key="PT100000000.000000001S"/><n id="low" key="PT100000000S"/>
		<n id="minus-low" key="-PT100000000S"/><n id="minus-high" key="-PT100000000.000000001S"/></r>`
	for _, tc := range []struct{ name, body, want string }{
		{"selected_key", `<xsl:for-each select="r/n">
			<xsl:sort select="xs:dayTimeDuration(@key)"/>
			<xsl:value-of select="concat(@id, '|')"/>
		</xsl:for-each>`, "minus-high|minus-low|low|high|"},
		{"group_constructor_key", `<xsl:for-each-group select="reverse(r/n)" group-by="@id">
			<xsl:sort order="descending"><xsl:sequence select="xs:dayTimeDuration(@key)"/></xsl:sort>
			<xsl:value-of select="concat(current-grouping-key(), '|')"/>
		</xsl:for-each-group>`, "high|low|minus-low|minus-high|"},
		{"merge_distinct_groups", `<xsl:merge>
			<xsl:merge-source select="r/n" sort-before-merge="yes">
				<xsl:merge-key select="xs:dayTimeDuration(@key)"/>
			</xsl:merge-source>
			<xsl:merge-action>
				<xsl:value-of select="concat(@id, ':', count(current-merge-group()), '|')"/>
			</xsl:merge-action>
		</xsl:merge>`, "minus-high:1|minus-low:1|low:1|high:1|"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ss := compileTestStylesheet(t, "", tc.body)
			got, err := ss.Transform(parseTestDocument(t, input)).Serialize(t.Context())
			requireSerialization(t, got, err, tc.want, "")
		})
	}
}

func TestExplicitNumericSortUsesXPathConversion(t *testing.T) {
	t.Parallel()

	const lexicalInput = `<r><n id="hex" key="0x1p1"/><n id="minus" key="-1"/><n id="underscore" key="1_0"/>
		<n id="nbsp" key="&#xA0;3&#xA0;"/><n id="xml-space" key="&#x9;2&#xA;"/><n id="invalid" key="Infinity"/>
		<n id="exp" key="1e1"/><n id="empty"/><n id="infinite" key="INF"/></r>`
	const typedInput = `<r><n id="one" key="1"/><n id="true"/><n id="false"/><n id="minus" key="-1"/></r>`
	const typedKey = "if (@id eq 'true') then true() else if (@id eq 'false') then false() else xs:integer(@key)"

	for _, profile := range []struct {
		name      string
		processor int
	}{
		{"2.0", processorXSLT20},
		{"3.0", processorXSLT30},
	} {
		for _, tc := range []struct{ name, input, key, want string }{
			{"lexical", lexicalInput, "@key", "hex|underscore|nbsp|invalid|empty|minus|xml-space|exp|infinite|"},
			{"typed", typedInput, typedKey, "minus|false|one|true|"},
		} {
			t.Run(profile.name+"/"+tc.name, func(t *testing.T) {
				t.Parallel()

				sheet := `<xsl:stylesheet version="` + profile.name + `" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
					xmlns:xs="http://www.w3.org/2001/XMLSchema">
					<xsl:output method="text"/>
					<xsl:template match="/">
						<xsl:for-each select="r/n">
							<xsl:sort data-type="number" select="` + tc.key + `"/>
							<xsl:value-of select="concat(@id, '|')"/>
						</xsl:for-each>
					</xsl:template>
				</xsl:stylesheet>`
				ss, err := NewCompiler().ProcessorVersion(profile.processor).Compile(t.Context(), parseTestDocument(t, sheet))
				if err != nil {
					t.Fatal(err)
				}

				got, err := ss.Transform(parseTestDocument(t, tc.input)).Serialize(t.Context())
				requireSerialization(t, got, err, tc.want, "")
			})
		}
	}
}

func TestExplicitNumericSortPreservesControlErrors(t *testing.T) {
	t.Parallel()

	atom := xdm.AtomicValue{TypeName: xdm.TypeString, Value: "1"}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	if _, err := explicitNumberSortValue(ctx, atom); !errors.Is(err, context.Canceled) {
		t.Errorf("canceled key conversion error = %v, want context.Canceled", err)
	}

	ctx = xpath.WithBudget(t.Context(), 0, 0, 0, 0)
	if _, err := explicitNumberSortValue(ctx, atom); !errors.Is(err, xpath.ErrBudget) {
		t.Errorf("exhausted key conversion error = %v, want xpath.ErrBudget", err)
	}
}

func TestReviewSortKeepsStaticContext(t *testing.T) {
	for _, tc := range []struct{ name, body, want string }{
		{"base URI", `<xsl:for-each select="(2,1)"><xsl:sort xml:base="https://example.test/sort/" select="if(static-base-uri() eq 'https://example.test/sort/') then . else -."/><xsl:value-of select="."/></xsl:for-each>`, "12"},
		{"default collation", `<xsl:for-each select="('B','A')"><xsl:sort default-collation="http://www.w3.org/2005/xpath-functions/collation/html-ascii-case-insensitive" select="if(. eq 'a') then 0 else 1"/><xsl:value-of select="."/></xsl:for-each>`, "AB"},
		{"option base URI", `<xsl:for-each select="(2,1)"><xsl:sort xml:base="https://example.test/sort/" order="{if (static-base-uri() eq 'https://example.test/sort/') then 'ascending' else 'descending'}"/><xsl:value-of select="."/></xsl:for-each>`, "12"},
		{"merge key base URI", `<xsl:merge><xsl:merge-source select="(1,2)"><xsl:merge-key xml:base="https://example.test/key/" select="if (static-base-uri() eq 'https://example.test/key/') then . else -."/></xsl:merge-source><xsl:merge-action><xsl:value-of select="current-merge-key()"/></xsl:merge-action></xsl:merge>`, "12"},
		{"merge standard attribute", `<xsl:merge><xsl:merge-source select="(1,2)"><xsl:merge-key default-collation="http://www.w3.org/2005/xpath-functions/collation/codepoint" select="."/></xsl:merge-source><xsl:merge-action><xsl:value-of select="current-merge-key()"/></xsl:merge-action></xsl:merge>`, "12"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ss, err := NewCompiler().Compile(t.Context(), stylesheetDocument(t, "", tc.body))
			if err != nil {
				t.Fatal(err)
			}
			got, err := ss.Transform(parseTestDocument(t, `<r/>`)).Serialize(t.Context())
			requireSerialization(t, got, err, tc.want, "")
		})
	}
}
