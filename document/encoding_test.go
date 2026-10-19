package document_test

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"strings"
	"testing"
	"unicode/utf16"

	"github.com/skarm/xmlsec/document"
)

func TestUTF16(t *testing.T) {
	payload := `<r a="é&#x9;">Привет 😀` + "\uFEFF" + `</r>`
	expected := []byte(`<r a="é&#x9;">Привет 😀` + "\uFEFF" + `</r>`)

	for _, little := range []bool{false, true} {
		name := "UTF-16BE"
		if little {
			name = "UTF-16LE"
		}

		cases := []struct {
			name, declaration string
			bom               bool
		}{
			{"BOM only", "", true},
			{"BOM generic", `<?xml version="1.0" encoding="UTF-16"?>`, true},
			{"BOM declaration", `<?xml version="1.0"?>`, true},
			{"endian declaration", `<?xml version="1.0" encoding="` + name + `"?>`, false},
		}
		for _, tt := range cases {
			t.Run(name+"/"+tt.name, func(t *testing.T) {
				d, err := document.Parse(t.Context(), encoded16(tt.declaration+payload, little, tt.bom), document.DefaultLimits())
				if err != nil {
					t.Fatal(err)
				}

				got, err := d.XML(t.Context())
				if err != nil || !bytes.Equal(got, expected) {
					t.Fatalf("got %q err %v", got, err)
				}
			})
		}
	}
}

func TestEncodingRejects(t *testing.T) {
	cases := []struct {
		name  string
		input []byte
	}{
		{"odd", []byte{0xFF, 0xFE, '<'}},
		{"high surrogate", []byte{0xFF, 0xFE, 0, 0xD8}},
		{"low surrogate", []byte{0xFF, 0xFE, 0, 0xDC}},
		{"surrogate followed by letter", []byte{0xFF, 0xFE, 0, 0xD8, 'a', 0}},
		{"wrong endian declaration", encoded16(`<?xml version="1.0" encoding="UTF-16BE"?><r/>`, true, true)},
		{"utf8 declaration in utf16", encoded16(`<?xml version="1.0" encoding="UTF-8"?><r/>`, true, true)},
		{"generic utf16 without BOM", encoded16(`<?xml version="1.0" encoding="UTF-16"?><r/>`, true, false)},
		{"missing encoding without BOM", encoded16(`<?xml version="1.0"?><r/>`, false, false)},
		{"utf16 declaration in utf8", []byte(`<?xml version="1.0" encoding="UTF-16"?><r/>`)},
		{"unsupported latin1", []byte(`<?xml version="1.0" encoding="ISO-8859-1"?><r/>`)},
		{"UTF32LE", []byte{0xFF, 0xFE, 0, 0, '<', 0, 0, 0}},
		{"UTF32BE", []byte{0, 0, 0xFE, 0xFF, 0, 0, 0, '<'}},
		{"double utf8 BOM", append([]byte{0xEF, 0xBB, 0xBF, 0xEF, 0xBB, 0xBF}, []byte(`<r/>`)...)},
		{"double utf16 BOM", encoded16("\uFEFF<r/>", true, true)},
		{"reference prolog", []byte(`&#32;<r/>`)},
		{"reference epilog", []byte(`<r/>&#xA;`)},
		{"CDATA terminator", []byte(`<r>]]></r>`)},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := document.Parse(t.Context(), tt.input, document.DefaultLimits()); err == nil {
				t.Fatal("accepted invalid/unsupported XML")
			}
		})
	}

	if _, err := document.Parse(t.Context(), []byte(`<r>]]&gt;</r>`), document.DefaultLimits()); err != nil {
		t.Fatal("escaped terminator is valid", err)
	}
}

func TestUTF16DecodedBudget(t *testing.T) {
	input := encoded16(`<r>`+strings.Repeat("中", 100)+`</r>`, true, true)
	limits := document.DefaultLimits()

	limits.MaxBytes = len(input)
	if _, err := document.Parse(context.Background(), input, limits); !errors.Is(err, document.ErrLimit) {
		t.Fatal(err)
	}
}

func TestCoalescingBeforeNodeLimit(t *testing.T) {
	limits := document.DefaultLimits()
	limits.MaxNodes = 2

	d, err := document.Parse(context.Background(), []byte(`<r>a<![CDATA[b]]>&amp;<![CDATA[]]>c</r>`), limits)
	if err != nil {
		t.Fatal(err)
	}

	if got := d.Root().Node().Children(); len(got) != 1 || got[0].Value() != "ab&c" {
		t.Fatal(got)
	}
}

func TestLexicalScratchPreservesNormalizationAndOwnership(t *testing.T) {
	text := strings.Repeat("abc", 4096)
	source := []byte(`<r a="first` + "\r\n\t" + `&#xD;&#xA;&#x9;">` + text + "\r\n" + `<s b="second"/>tail<![CDATA[` + text + `]]><!--comment--><?p data?></r>`)

	doc, err := document.Parse(t.Context(), source, document.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}

	clear(source)

	if attr, _ := doc.Root().Attribute(document.Name{Local: "a"}); attr != "first  \r\n\t" {
		t.Fatalf("attribute normalization: %q", attr)
	}

	if got := doc.Root().Text(); got != text+"\ntail"+text {
		t.Fatalf("reused lexical storage changed text: %d bytes", len(got))
	}

	for _, split := range []int{4094, 4095} {
		xml := `<r>` + strings.Repeat("x", split) + `]]></r>`
		if _, err := document.Parse(t.Context(), []byte(xml), document.DefaultLimits()); !errors.Is(err, document.ErrMalformed) {
			t.Fatal("accepted split CDATA terminator", split, err)
		}
	}
}

func encoded16(s string, little, bom bool) []byte {
	var (
		out   []byte
		order binary.AppendByteOrder = binary.BigEndian
	)
	if little {
		order = binary.LittleEndian
	}

	if bom {
		out = order.AppendUint16(out, 0xFEFF)
	}

	for _, u := range utf16.Encode([]rune(s)) {
		out = order.AppendUint16(out, u)
	}

	return out
}
