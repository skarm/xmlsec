package tree_test

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"strings"
	"testing"
	"testing/iotest"
	"unicode/utf16"

	"github.com/skarm/xmlsec/internal/tree"
)

func TestXMLPrologValidation(t *testing.T) {
	for _, test := range []struct {
		source string
		valid  bool
	}{
		{`<r/>`, true},
		{`<r>`, true},
		{`<r><unfinished`, true},
		{`<r/><s/>`, true},
		{`<?xml version="1.0"?><!--ok--><r a="v">`, true},
		{``, false},
		{`<?xml version="1.0"?>`, false},
		{`<r a=>`, false},
		{`<r a="1" a="2">`, false},
		{`<p:r>`, false},
		{`<!DOCTYPE r><r>`, false},
		{`text<r>`, false},
		{`<!--invalid--comment--><r>`, false},
	} {
		encoded := make([]byte, 2, 2+2*len(test.source))
		encoded[0], encoded[1] = 0xff, 0xfe
		for _, value := range utf16.Encode([]rune(test.source)) {
			encoded = append(encoded, byte(value), byte(value>>8))
		}
		for _, data := range [][]byte{[]byte(test.source), encoded} {
			err := tree.CheckXMLProlog(t.Context(), bytes.NewReader(data), tree.DefaultLimits(), false)
			if (err == nil) != test.valid {
				t.Fatal(test.source, data, err, test.valid)
			}
		}
	}
	limits := tree.DefaultLimits()
	limits.MaxBytes = 32
	if err := tree.CheckXMLProlog(t.Context(), strings.NewReader(strings.Repeat(" ", 64)+`<r/>`), limits, false); !errors.Is(err, tree.ErrLimit) {
		t.Fatal(err)
	}
	if err := tree.CheckXMLProlog(t.Context(), iotest.ErrReader(io.ErrClosedPipe), tree.DefaultLimits(), false); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := tree.CheckXMLProlog(ctx, strings.NewReader(`<r>`), tree.DefaultLimits(), false); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

func TestParseReaderUTF16CodeUnitBoundaries(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name  string
		order binary.AppendByteOrder
		bom   []byte
	}{
		{"little_endian", binary.LittleEndian, []byte{0xff, 0xfe}},
		{"big_endian", binary.BigEndian, []byte{0xfe, 0xff}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			encode := func(s string) []byte {
				raw := bytes.Clone(tc.bom)
				for _, unit := range utf16.Encode([]rune(s)) {
					raw = tc.order.AppendUint16(raw, unit)
				}
				return raw
			}
			doc, err := tree.ParseReader(t.Context(), iotest.OneByteReader(bytes.NewReader(encode("<r>é😀</r>"))), tree.DefaultLimits())
			if err != nil || doc == nil || doc.Root().Text() != "é😀" {
				t.Fatalf("UTF-16 parse returned document present=%t, error=%v; want text é😀", doc != nil, err)
			}
			complete := encode("<r/>")
			open := encode("<r>")
			for _, invalid := range []struct {
				name string
				raw  []byte
			}{
				{"partial_trailing_code_unit", append(bytes.Clone(complete), 0)},
				{"lone_low_surrogate", tc.order.AppendUint16(bytes.Clone(open), 0xdc00)},
				{"unpaired_high_surrogate", tc.order.AppendUint16(bytes.Clone(open), 0xd800)},
				{"high_surrogate_followed_by_letter", tc.order.AppendUint16(tc.order.AppendUint16(bytes.Clone(open), 0xd800), 'a')},
			} {
				t.Run(invalid.name, func(t *testing.T) {
					t.Parallel()
					doc, err := tree.ParseReader(t.Context(), iotest.OneByteReader(bytes.NewReader(invalid.raw)), tree.DefaultLimits())
					if doc != nil || !errors.Is(err, tree.ErrMalformed) {
						t.Fatalf("document present=%t, error=%v; want no document and ErrMalformed", doc != nil, err)
					}
				})
			}
		})
	}
}

func TestParsedElementSourceLines(t *testing.T) {
	const source = "<r>\n<!--x\n y-->\n<a\n key='x&#xA;\n y'/>\n<![CDATA[x\n y]]>\n<b/>\n</r>"
	for _, ending := range []string{"\n", "\r\n", "\r"} {
		input := strings.ReplaceAll(source, "\n", ending)
		encoded := make([]byte, 2, 2+2*len(input))
		encoded[0], encoded[1] = 0xff, 0xfe
		for _, value := range utf16.Encode([]rune(input)) {
			encoded = append(encoded, byte(value), byte(value>>8))
		}
		for _, data := range [][]byte{[]byte(input), encoded} {
			doc, err := tree.ParseReader(t.Context(), bytes.NewReader(data), tree.DefaultLimits())
			if err != nil {
				t.Fatal(err)
			}
			clone, err := tree.Clone(t.Context(), doc)
			if err != nil {
				t.Fatal(err)
			}
			for _, snapshot := range []*tree.Document{doc, clone} {
				root := tree.Root(snapshot)
				if root.SourceLine != 1 {
					t.Fatal(ending, root.SourceLine)
				}
				lines := map[string]int{"a": 4, "b": 9}
				for _, node := range root.Children {
					if node.Kind == tree.ElementNode && int(node.SourceLine) != lines[node.Name.Local] {
						t.Fatal(ending, node.Name, node.SourceLine)
					}
				}
			}
		}
	}
}

func TestParseReaderWithSingleByteEncodings(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name, encoding, input, want string
		wantErr                     error
	}{
		{"latin_1", "ISO-8859-1", "caf\xe9", "café", nil},
		{"windows_1252", "windows-1252", "\x80", "€", nil},
		{"ascii_alias", "ASCII", "a&#xE9;", "aé", nil},
		{"ascii_rejects_high_byte", "US-ASCII", "\xe9", "", tree.ErrMalformed},
		{"unknown_label", "example-unknown", "plain", "", tree.ErrUnsupported},
		{"multibyte_codec", "Shift_JIS", "plain", "", tree.ErrUnsupported},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			raw := `<?xml version="1.0" encoding="` + tc.encoding + `"?><r>` + tc.input + `</r>`
			doc, err := tree.ParseReaderWithSingleByteEncodings(t.Context(), iotest.OneByteReader(strings.NewReader(raw)), tree.DefaultLimits())
			if tc.wantErr != nil {
				if doc != nil || !errors.Is(err, tc.wantErr) {
					t.Fatalf("document present=%t, error=%v; want no document and %v", doc != nil, err, tc.wantErr)
				}
				return
			}
			if err != nil || doc == nil {
				t.Fatalf("parse %s: %v", tc.encoding, err)
			}
			if got := doc.Root().Text(); got != tc.want {
				t.Errorf("text=%q, want %q", got, tc.want)
			}
		})
	}
}

func TestParseTextPreservesDecodedCharacters(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name, source, want string
		wantErr            error
	}{
		{"declaration_does_not_redecode_unicode", `<?xml version="1.0" encoding="ISO-8859-1"?><r>café ☃</r>`, "café ☃", nil},
		{"utf16_label_does_not_require_bom", `<?xml version="1.0" encoding="UTF-16"?><r>😀</r>`, "😀", nil},
		{"normalizes_line_endings_in_text", "<r>a\r\nb\rc</r>", "a\nb\nc", nil},
		{"nul_bytes_are_not_utf16_input", "<\x00?\x00", "", tree.ErrMalformed},
		{"invalid_declaration_name", `<?xml version="1.0" encoding="utf 8"?><r/>`, "", tree.ErrMalformed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			doc, err := tree.ParseText(t.Context(), tc.source, tree.DefaultLimits())
			if tc.wantErr != nil {
				if doc != nil || !errors.Is(err, tc.wantErr) {
					t.Fatalf("document present=%t, error=%v; want no document and %v", doc != nil, err, tc.wantErr)
				}
				return
			}
			if err != nil || doc == nil {
				t.Fatalf("parse text: %v", err)
			}
			if got := doc.Root().Text(); got != tc.want {
				t.Errorf("text=%q, want %q", got, tc.want)
			}
		})
	}
}
