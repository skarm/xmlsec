package tree_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"

	"github.com/skarm/xmlsec/internal/tree"
)

func TestWriteXMLFragmentOptionsControlsElementFormatting(t *testing.T) {
	t.Parallel()

	const source = `<r><p xml:space="preserve"><a/><a/></p><q><a/><v/></q><inline><v/><a/></inline><compact><q><a/></q></compact><suppressed><q><a/></q></suppressed><q><a/></q></r>`
	doc, err := tree.Parse(t.Context(), []byte(source), tree.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}

	options := tree.XMLWriteOptions{
		Indent:       true,
		IndentString: ". ",
		SelfClose:    true,
		EmptyElement: func(name tree.Name) tree.EmptyElementMode {
			switch name.Local {
			case "a":
				return tree.EmptyElementSpaced
			case "v":
				return tree.EmptyElementExpanded
			default:
				return tree.EmptyElementDefault
			}
		},
		PreserveContent: func(name tree.Name) bool { return name.Local == "compact" },
		InlineElement:   func(name tree.Name) bool { return name.Local == "v" },
		SuppressIndent:  map[string]struct{}{"{}suppressed": {}},
	}
	var output strings.Builder
	n, err := tree.WriteXMLFragmentOptions(t.Context(), &output, tree.Children(doc), 1024, options)
	const want = `<r>
. <p xml:space="preserve"><a /><a /></p>
. <q><a /><v></v></q>
. <inline><v></v><a /></inline>
. <compact><q><a /></q></compact>
. <suppressed><q><a /></q></suppressed>
. <q>
. . <a />
. </q>
</r>`
	if err != nil || output.String() != want || n != int64(len(want)) {
		t.Fatalf("WriteXMLFragmentOptions = (%d, %v)\n%s\nwant (%d, nil)\n%s", n, err, output.String(), len(want), want)
	}
}

func TestWriteXMLFragmentOptionsAppliesCharacterPolicies(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name, source, want string
		options            tree.XMLWriteOptions
	}{
		{
			name:    "map_matches_before_normalization",
			source:  "<r>e\u0301@é</r>",
			want:    "<r>é<b/>mapped</r>",
			options: tree.XMLWriteOptions{Normalization: "NFC", CharacterMap: map[rune]string{'@': "<b/>", 'é': "mapped"}},
		},
		{
			name:    "namespace_uris_do_not_use_character_map",
			source:  `<r xmlns:p="urn:x"><p:e>x</p:e></r>`,
			want:    `<r xmlns:p="urn:x"><p:e>mapped</p:e></r>`,
			options: tree.XMLWriteOptions{CharacterMap: map[rune]string{'x': "mapped"}},
		},
		{
			name:    "unencodable_text_is_replaced_by_reference",
			source:  `<r a="café">éΩ</r>`,
			want:    `<r a="café">é&#937;</r>`,
			options: tree.XMLWriteOptions{CanEncode: func(r rune) bool { return r <= 255 }},
		},
		{
			name:    "control_reference_rules",
			source:  "<r>\u007f\u0085\u2028</r>",
			want:    "<r>&#127;&#133;&#8232;</r>",
			options: tree.XMLWriteOptions{EscapeControlChars: true},
		},
		{
			name:    "normalize_id_without_modifying_original",
			source:  `<r xml:id="  key  "/>`,
			want:    `<r xml:id="key"></r>`,
			options: tree.XMLWriteOptions{NormalizeXMLID: true},
		},
		{
			name:   "attribute_writer_handles_selected_value",
			source: `<r marked="a&amp;b" other="&quot;&amp;"/>`,
			want:   `<r marked="a&amp;b!" other="&quot;&amp;"></r>`,
			options: tree.XMLWriteOptions{AttributeWriter: func(_ context.Context, w io.Writer, element tree.Name, a tree.Attribute) (bool, error) {
				if element != (tree.Name{Local: "r"}) || a.Name != (tree.Name{Local: "marked"}) {
					return false, nil
				}
				if a.Value != "a&b" {
					return true, fmt.Errorf("handler received %q, want a&b", a.Value)
				}
				_, err := io.WriteString(w, "a&amp;b!")
				return true, err
			}},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			doc, err := tree.Parse(t.Context(), []byte(tc.source), tree.DefaultLimits())
			if err != nil {
				t.Fatal(err)
			}
			var output strings.Builder
			n, err := tree.WriteXMLFragmentOptions(t.Context(), &output, tree.Children(doc), 1024, tc.options)
			if err != nil || output.String() != tc.want || n != int64(len(tc.want)) {
				t.Fatalf("WriteXMLFragmentOptions = (%q, %d, %v), want (%q, %d, nil)", output.String(), n, err, tc.want, len(tc.want))
			}
			if tc.options.NormalizeXMLID {
				id, ok := doc.Root().Attribute(tree.Name{Space: tree.XMLNamespace, Local: "id"})
				if !ok || id != "  key  " {
					t.Errorf("serialization changed original xml:id to %q", id)
				}
			}
		})
	}
}

func TestWriteXMLFragmentOptionsStopAtFailure(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name, local, text string
		kind              tree.Kind
		options           tree.XMLWriteOptions
		wantErr           error
	}{
		{name: "invalid_element_name", kind: tree.ElementNode, local: "two names", wantErr: tree.ErrMalformed},
		{name: "element_name_outside_output_repertoire", kind: tree.ElementNode, local: "café", options: tree.XMLWriteOptions{ASCII: true}, wantErr: tree.ErrUnencodable},
		{name: "invalid_comment", kind: tree.CommentNode, text: "a--b", wantErr: tree.ErrMalformed},
		{name: "trailing_dash_in_comment", kind: tree.CommentNode, text: "a-", wantErr: tree.ErrMalformed},
		{name: "comment_outside_output_repertoire", kind: tree.CommentNode, text: "café", options: tree.XMLWriteOptions{ASCII: true}, wantErr: tree.ErrUnencodable},
		{name: "malformed_utf8_in_comment", kind: tree.CommentNode, text: "\xff", wantErr: tree.ErrMalformed},
		{name: "comment_with_disallowed_character", kind: tree.CommentNode, text: "a\x01b", wantErr: tree.ErrMalformed},
		{name: "xml_declaration_is_not_a_pi", kind: tree.PINode, local: "xMl", wantErr: tree.ErrMalformed},
		{name: "pi_closing_delimiter_in_content", kind: tree.PINode, local: "note", text: "a?>b", wantErr: tree.ErrMalformed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			nodes := []*tree.Node{
				{Kind: tree.TextNode, Data: "prior"},
				{Kind: tc.kind, Name: tree.Name{Local: tc.local}, Data: tc.text},
				{Kind: tree.TextNode, Data: "later"},
			}
			var output strings.Builder
			n, err := tree.WriteXMLFragmentOptions(t.Context(), &output, nodes, 100, tc.options)
			if !errors.Is(err, tc.wantErr) || n != 5 || output.String() != "prior" {
				t.Fatalf("WriteXMLFragmentOptions = (%q, %d, %v), want prior text and %v", output.String(), n, err, tc.wantErr)
			}
		})
	}
}
