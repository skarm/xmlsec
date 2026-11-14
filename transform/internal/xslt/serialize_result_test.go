package xslt //nolint:testpackage // Exercises the serializer with XDM documents and output definitions.

import (
	"strings"
	"testing"

	"github.com/skarm/xmlsec/internal/lexicon"
	"github.com/skarm/xmlsec/transform/internal/xdm"
)

func TestSerializeResultValidatesOutputParametersBeforeWriting(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name       string
		definition OutputDef
		multiple   bool
		code       string
	}{
		{name: "unknown_method", definition: OutputDef{Method: "Q{urn:app}custom"}, code: "SEPM0016"},
		{name: "unsupported_xml_version", definition: OutputDef{Method: "xml", Version: "1.2"}, code: "SESU0013"},
		{name: "standalone_requires_single_root", definition: OutputDef{Method: "xml", Standalone: "no"}, multiple: true, code: "SEPM0004"},
		{name: "doctype_requires_single_root", definition: OutputDef{Method: "xhtml", DoctypeSystem: "example.dtd"}, multiple: true, code: "SEPM0004"},
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
			tc.definition.ByteOrderMark = true
			var output strings.Builder
			err := SerializeResult(&output, doc, &tc.definition)
			requireSerialization(t, output.String(), err, "", tc.code)
		})
	}
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
