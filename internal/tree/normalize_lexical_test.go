package tree_test

import (
	"bytes"
	"testing"

	treepkg "github.com/skarm/xmlsec/internal/tree"
)

func TestLexicalNormalizationOwnsOneCopyAndPreservesReferences(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want string
	}{
		{"<r a=\"a\r\nb\rc\nd\te&#xA;&#xD;&#x9;\">x\r\ny\rz</r>", "<r a=\"a b c d e&#xA;&#xD;&#x9;\">x\ny\nz</r>"},
		{"<!--a\r\nb--><?p a\rb?><r><![CDATA[a\r\nb\rc]]></r>", "<!--a\nb--><?p a\nb?><r><![CDATA[a\nb\nc]]></r>"},
		{"<r>\r\r\n\n\r</r>", "<r>\n\n\n\n</r>"},
		{"<r a='x\ny'>ж</r>", "<r a='x y'>ж</r>"},
	} {
		input := []byte(tc.in)
		original := bytes.Clone(input)

		got, err := treepkg.NormalizeLexicalForTest(input)
		if err != nil || string(got) != tc.want {
			t.Fatalf("%q: %q, %v", tc.in, got, err)
		}

		if !bytes.Equal(input, original) {
			t.Fatal("normalization mutated caller bytes")
		}

		got[0] = '!'

		if !bytes.Equal(input, original) {
			t.Fatal("normalization returned caller storage")
		}
	}
}
