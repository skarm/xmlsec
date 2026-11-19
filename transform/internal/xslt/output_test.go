package xslt //nolint:testpackage // Exercises the serializer with XDM documents and output definitions.

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/skarm/xmlsec/internal/lexicon"
	"github.com/skarm/xmlsec/transform/internal/xdm"
	"github.com/skarm/xmlsec/transform/internal/xpath"
)

func TestSerializeResultValidatesOutputParametersBeforeWriting(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name       string
		definition OutputDef
		multiple   bool
		text       bool
		code       string
	}{
		{name: "unknown_method", definition: OutputDef{Method: "Q{urn:app}custom"}, code: "SEPM0016"},
		{name: "unsupported_xml_version", definition: OutputDef{Method: "xml", Version: "1.2"}, code: "SESU0013"},
		{name: "standalone_requires_single_root", definition: OutputDef{Method: "xml", Standalone: "no"}, multiple: true, code: "SEPM0004"},
		{name: "doctype_requires_single_root", definition: OutputDef{Method: "xhtml", DoctypeSystem: "example.dtd"}, multiple: true, code: "SEPM0004"},
		{name: "standalone_rejects_top_level_text", definition: OutputDef{Method: "xml", Standalone: "yes"}, text: true, code: "SEPM0004"},
		{name: "doctype_rejects_top_level_text", definition: OutputDef{Method: "xhtml", DoctypeSystem: "example.dtd"}, text: true, code: "SEPM0004"},
		{name: "standalone_conflicts_with_omitted_declaration", definition: OutputDef{Method: "xml", Standalone: "yes", OmitDeclaration: true}, code: "SEPM0009"},
		{name: "xml_11_doctype_conflicts_with_omitted_declaration", definition: OutputDef{Method: "xml", Version: "1.1", DoctypeSystem: "example.dtd", OmitDeclaration: true}, code: "SEPM0009"},
		{name: "xml_10_disallows_prefix_undeclaration", definition: OutputDef{Method: "xml", UndeclarePrefixes: true}, code: "SEPM0010"},
		{name: "doctype_public_identifier_rejects_non_ascii", definition: OutputDef{Method: "xml", DoctypePublic: "café"}, code: "SEPM0016"},
		{name: "doctype_system_identifier_requires_available_delimiter", definition: OutputDef{Method: "xml", DoctypeSystem: `"'example.dtd`}, code: "SEPM0016"},
		{name: "unsupported_encoding", definition: OutputDef{Method: "text", Encoding: "made-up-encoding"}, code: "SESU0007"},
		{name: "html_version_overrides_version", definition: OutputDef{Method: "html", Version: "5.0", HTMLVersion: "6.0"}, code: "SESU0013"},
		{name: "unsupported_normalization_form", definition: OutputDef{Method: "text", NormalizationForm: "bogus"}, code: "SESU0011"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			doc := parseTestDocument(t, `<first/>`)
			if tc.multiple {
				element, err := doc.CreateElement("second")
				if err != nil {
					t.Fatalf("create second result element: %v", err)
				}
				if err := doc.AddChild(element); err != nil {
					t.Fatalf("add second result element: %v", err)
				}
			}
			if tc.text {
				if err := doc.AddChild(doc.CreateText("trailing text")); err != nil {
					t.Fatal(err)
				}
			}
			tc.definition.ByteOrderMark = true
			var output strings.Builder
			err := SerializeResult(&output, doc, &tc.definition)
			requireSerialization(t, output.String(), err, "", tc.code)
		})
	}

	t.Run("implicit method selection bounds examination before writing", func(t *testing.T) {
		t.Parallel()
		prefixed := parseTestDocument(t, `<!--one--><!--two--><html/>`)
		first := parseTestDocument(t, `<html><body><br/></body></html>`)
		zeroWork := xpath.WithBudget(t.Context(), 0, 100, 100, 32)
		if root, err := firstDocumentSerializationElement(zeroWork, first); err != nil || root != first.DocumentElement() {
			t.Fatalf("root-first selection returned %v, %v", root, err)
		}

		canceled, cancel := context.WithCancel(t.Context())
		cancel()
		for _, tc := range []struct {
			ctx  context.Context
			want error
		}{
			{xpath.WithBudget(t.Context(), 1, 100, 100, 32), xpath.ErrBudget},
			{canceled, context.Canceled},
		} {
			var output strings.Builder
			err := serializeResult(tc.ctx, &output, prefixed, nil)
			if !errors.Is(err, tc.want) || output.Len() != 0 {
				t.Errorf("document serialization wrote %q with %v; want %v before writing", output.String(), err, tc.want)
			}
		}

		whitespace := xdm.XMLItem{Text: strings.Repeat(" ", 32<<10)}
		if _, err := leadingSerializationText(xpath.WithBudget(t.Context(), 1, 100, 100, 32), whitespace); !errors.Is(err, xpath.ErrBudget) {
			t.Errorf("large whitespace scan returned %v; want budget error", err)
		}
	})
}

func TestSerializeResultFullyNormalizedUsesOutputBoundaries(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name    string
		source  string
		method  string
		charMap map[rune]string
		want    string
		code    string
	}{
		{name: "canonical_composition", source: `<r>e&#x301;</r>`, want: "<r>é</r>"},
		{name: "combining_mark_at_text_start", source: `<r>&#x301;a</r>`, code: "SERE0012"},
		{name: "comment_ends_preceding_text_run", source: `<r>a<!--gap-->&#x301;</r>`, code: "SERE0012"},
		{name: "processing_instruction_ends_preceding_text_run", source: `<r>a<?gap value?>&#x301;</r>`, code: "SERE0012"},
		{name: "expanded_entity_is_character_data", source: `<r>&lt;&#x301;</r>`, want: "<r>&lt;\u0301</r>"},
		{name: "map_generated_comment_ends_preceding_text_run", source: `<r>aX&#x301;</r>`, charMap: map[rune]string{'X': "<!--gap-->"}, code: "SERE0012"},
		{name: "map_generated_reference_remains_opaque", source: `<r>X</r>`, charMap: map[rune]string{'X': "&#x301;"}, want: "<r>&#x301;</r>"},
		{name: "map_generated_cdata_starts_character_data", source: `<r>X&#x301;Y</r>`, charMap: map[rune]string{'X': "<![CDATA[", 'Y': "]]>"}, code: "SERE0012"},
		{name: "mapped_tag_delimiter_inside_quoted_attribute", source: `<r>X&#x301;</r>`, charMap: map[rune]string{'X': "<tag val='>'/>"}, code: "SERE0012"},
		{name: "html_script_preserves_raw_text", source: `<script><e>&lt;&#x1161;</e></script>`, method: "html", want: "<script><e><ᅡ</e></script>"},
		{name: "html_foreign_script_uses_markup_boundaries", source: `<script xmlns="urn:foreign">X&#x301;</script>`, method: "html", charMap: map[rune]string{'X': "<e/>"}, code: "SERE0012"},
		{name: "text_method_omits_markup_between_letters", source: `<r>e<empty/>&#x301;</r>`, method: "text", want: "é"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			definition := OutputDef{
				Method:            tc.method,
				OmitDeclaration:   true,
				NormalizationForm: lexicon.NormFullyNormalized,
				ResolvedCharMap:   tc.charMap,
			}
			if definition.Method == "" {
				definition.Method = "xml"
			}
			var output strings.Builder
			err := SerializeResult(&output, parseTestDocument(t, tc.source), &definition)
			requireSerialization(t, output.String(), err, tc.want, tc.code)
		})
	}
}

func TestSerializeResultDiscardsSourceDoctypeWithoutMutatingDocument(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct{ name, system, want string }{
		{name: "source_doctype_is_omitted", want: "<r/>"},
		{name: "requested_doctype_replaces_source_doctype", system: "output.dtd", want: "<!DOCTYPE r SYSTEM \"output.dtd\"><r/>"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			doc := parseTestDocument(t, `<r/>`)
			doctype := &xdm.Doctype{Name: "r", SystemID: "source.dtd"}
			doc.Doctype = doctype
			definition := OutputDef{Method: "xml", OmitDeclaration: true, DoctypeSystem: tc.system}
			var output strings.Builder
			err := SerializeResult(&output, doc, &definition)
			requireSerialization(t, output.String(), err, tc.want, "")
			if doc.Doctype != doctype {
				t.Fatal("serialization changed the source document's doctype")
			}
		})
	}
}

func TestSerializeResultEncodesNormalizedTextAndByteOrderMark(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name, encoding, want string
		bom                  bool
	}{
		{name: "utf8_without_bom", encoding: "UTF-8", want: "é"},
		{name: "utf8_with_bom", encoding: "UTF-8", bom: true, want: "\xef\xbb\xbfé"},
		{name: "utf16_uses_big_endian_and_bom", encoding: "UTF-16", want: "\xfe\xff\x00\xe9"},
		{name: "windows_1252_transcodes_composed_character", encoding: "windows-1252", want: "\xe9"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			doc := parseTestDocument(t, `<r>e&#x301;</r>`)
			definition := OutputDef{Method: "text", Encoding: tc.encoding, ByteOrderMark: tc.bom, NormalizationForm: "NFC"}
			var output strings.Builder
			err := SerializeResult(&output, doc, &definition)
			requireSerialization(t, output.String(), err, tc.want, "")
		})
	}
}

func TestSerializeValueUsesEncodingLabelForMarkup(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		method, label, want string
	}{
		{method: "xml", label: "latin1", want: "&#8364;\xe9</p>"},
		{method: "xhtml", label: "L1", want: "&#8364;\xe9</p>"},
		{method: "xml", label: "ISO-8859-1", want: "&#8364;\xe9</p>"},
		{method: "xml", label: "windows-1252", want: "\x80\xe9</p>"},
		{method: "html", label: "latin1", want: "\x80\xe9</p>"},
		{method: "text", label: "windows-1252", want: "\x80\xe9"},
	} {
		t.Run(tc.method+"/"+tc.label, func(t *testing.T) {
			t.Parallel()
			doc := parseTestDocument(t, `<p xmlns="http://www.w3.org/1999/xhtml">€é</p>`)
			result := ValueResult{
				Document: doc,
				Items:    xdm.ItemSlice{xdm.NodeItem{Node: doc}},
				Output:   &OutputDef{Method: tc.method, Encoding: tc.label},
			}
			var output strings.Builder
			if err := SerializeValue(t.Context(), &output, result); err != nil {
				t.Fatal(err)
			}
			got := output.String()
			if !strings.HasSuffix(got, tc.want) {
				t.Errorf("serialized bytes %q, want suffix %q", got, tc.want)
			}
			if (tc.method == "xml" || tc.method == "xhtml") && !strings.Contains(got, `encoding="`+tc.label+`"`) {
				t.Errorf("serialized declaration %q, want encoding %q", got, tc.label)
			}
			if tc.method == "text" && got != tc.want {
				t.Errorf("serialized text bytes %q, want %q", got, tc.want)
			}
		})
	}
}

func TestCharacterMapExpansionUsesLastMapping(t *testing.T) {
	t.Parallel()
	const declarations = `
	<xsl:character-map name="shared">
		<xsl:output-character character="a" string="shared"/>
		<xsl:output-character character="b" string="base"/>
	</xsl:character-map>
	<xsl:character-map name="override" use-character-maps="shared"><xsl:output-character character="a" string="override"/></xsl:character-map>
	<xsl:character-map name="later" use-character-maps="shared"/>
	<xsl:character-map name="composite" use-character-maps="override later"><xsl:output-character character="b" string="top"/></xsl:character-map>
	`
	for _, tc := range []struct{ maps, want string }{
		{"shared override", "override|base"},
		{"shared override shared", "shared|base"},
		{"override later", "shared|base"},
		{"composite", "shared|top"},
	} {
		t.Run(tc.maps, func(t *testing.T) {
			t.Parallel()
			ss := compileTestStylesheet(t, declarations+`<xsl:output use-character-maps="`+tc.maps+`"/>`, `<xsl:text>a|b</xsl:text>`)
			got, err := ss.Transform(parseTestDocument(t, `<r/>`)).Serialize(t.Context())
			requireSerialization(t, got, err, tc.want, "")
		})
	}
}

func TestSerializeItemsUsesRequestedSeparator(t *testing.T) {
	t.Parallel()
	const delimiter = "|"
	for _, tc := range []struct {
		name, want string
		separator  *string
		absent     bool
	}{
		{name: "default_newline", want: "alpha\n<item/>\nomega"},
		{name: "custom_separator", want: "alpha|<item/>|omega", separator: new(delimiter)},
		{name: "absent_separator", want: "alpha<item/>omega", absent: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			doc := parseTestDocument(t, `<item/>`)
			items := xdm.ItemSlice{stringItem("alpha"), xdm.NodeItem{Node: doc.DocumentElement()}, stringItem("omega")}
			definition := OutputDef{Method: "xml", OmitDeclaration: true, ItemSeparator: tc.separator, ItemSeparatorAbsent: tc.absent}
			var output strings.Builder
			err := SerializeItems(t.Context(), &output, items, doc, &definition)
			requireSerialization(t, output.String(), err, tc.want, "")
		})
	}
}

func TestReviewReturnedSequencePreservesEmptyAtomicSpacing(t *testing.T) {
	for _, tc := range []struct{ name, declarations, body string }{
		{"typed template", `<xsl:template name="values" as="xs:string*"><xsl:sequence select="('a', '')"/></xsl:template>`, `<xsl:call-template name="values"/>`},
		{"try select", "", `<xsl:try select="('a', '')"><xsl:catch/></xsl:try>`},
		{"direct sequence", "", `<xsl:sequence select="('a', '')"/>`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ss := compileTestStylesheet(t, tc.declarations, tc.body)
			got, err := ss.Transform(parseTestDocument(t, `<r/>`)).Serialize(t.Context())
			requireSerialization(t, got, err, "a ", "")
		})
	}
}
