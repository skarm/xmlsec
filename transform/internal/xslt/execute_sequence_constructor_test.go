package xslt //nolint:testpackage // Exercises conditional sequence construction.

import (
	"errors"
	"testing"

	"github.com/skarm/xmlsec/transform/internal/xdm"
)

func TestExecuteSequenceConstructorConditionalOutput(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name, body, want, code string
	}{
		{
			name: "on_empty_handles_vacuous_strings_without_separator",
			body: `<out>
				<xsl:sequence select="('', '')"/>
				<xsl:on-non-empty select="error()"/>
				<xsl:on-empty><xsl:text>fallback</xsl:text></xsl:on-empty>
			</out>`,
			want: "fallback",
		},
		{
			name: "on_non_empty_splices_before_and_after_ordinary_output",
			body: `<out>
				<xsl:on-non-empty><before>begin|</before></xsl:on-non-empty>
				<xsl:text>middle</xsl:text>
				<xsl:on-non-empty select="('|end', 3)"/>
				<xsl:on-empty select="error()"/>
			</out>`,
			want: "begin|middle|end 3",
		},
		{
			name: "sequence_mode_preserves_type_and_replacement_order",
			body: `<xsl:variable name="values" as="item()*">
				<xsl:on-non-empty select="(1, 2)"/>
				<xsl:sequence select="map{'k': 'value'}"/>
				<xsl:on-non-empty select="[3, 4]"/>
				<xsl:on-empty select="error()"/>
			</xsl:variable>
			<xsl:value-of select="(count($values), $values[1] + $values[2], ($values[3])('k'), ($values[4])(2))" separator="|"/>`,
			want: "4|3|value|4",
		},
		{
			name: "sequence_mode_replaces_nested_vacuous_arrays",
			body: `<xsl:variable name="values" as="item()*">
				<xsl:sequence select="[[(), ''], ['']]"/>
				<xsl:on-empty select="(4, 5)"/>
			</xsl:variable>
			<xsl:value-of select="(count($values), sum($values))" separator="|"/>`,
			want: "2|9",
		},
		{
			name: "deferred_constructor_uses_lexical_binding_at_registration",
			body: `<xsl:variable name="label" select="'outer'"/>
			<out>
				<xsl:on-non-empty select="$label"/>
				<xsl:variable name="label" select="'inner'"/>
				<xsl:text>|</xsl:text>
				<xsl:on-non-empty select="$label"/>
			</out>
			<xsl:value-of select="'|' || $label"/>`,
			want: "outer|inner|outer",
		},
		{
			name: "deferred_document_contributes_children_in_order",
			body: `<xsl:variable name="out" as="element()"><out>
				<xsl:on-non-empty><xsl:document><first/><second/></xsl:document></xsl:on-non-empty>
				<third/>
			</out></xsl:variable>
			<xsl:value-of select="$out/*/name()" separator="|"/>`,
			want: "first|second|third",
		},
		{
			name: "deferred_attribute_attaches_to_output_element",
			body: `<xsl:variable name="out" as="element()"><out>
				<xsl:on-non-empty><xsl:attribute name="status">ready</xsl:attribute></xsl:on-non-empty>
				<child/>
			</out></xsl:variable>
			<xsl:value-of select="($out/@status, name($out/*))" separator="|"/>`,
			want: "ready|child",
		},
		{
			name: "deferred_map_cannot_be_inserted_into_tree",
			body: `<out><xsl:on-empty select="map{'k': 1}"/></out>`,
			code: "XTDE0450",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ss := compileTestStylesheet(t, "", tc.body)
			got, err := ss.Transform(parseTestDocument(t, `<r/>`)).Serialize(t.Context())
			requireSerialization(t, got, err, tc.want, tc.code)
		})
	}
}

func TestExecuteSequenceConstructorConditionalError(t *testing.T) {
	t.Parallel()

	ss := compileTestStylesheet(t, "", `<out><xsl:on-empty select="error(QName('urn:unit', 'f:stopped'))"/></out>`)
	got, err := ss.Transform(parseTestDocument(t, `<r/>`)).Serialize(t.Context())
	wantErr := &xdm.Error{QualifiedCode: xdm.QNameValue{URI: "urn:unit", Local: "stopped"}}
	if got != "" || !errors.Is(err, wantErr) {
		t.Fatalf("output = %q, error = %v; want no output and %v", got, err, wantErr)
	}
}
