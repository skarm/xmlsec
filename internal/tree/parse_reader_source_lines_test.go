package tree_test

import (
	"bytes"
	"strings"
	"testing"
	"unicode/utf16"

	treepkg "github.com/skarm/xmlsec/internal/tree"
)

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
			doc, err := treepkg.ParseReader(t.Context(), bytes.NewReader(data), treepkg.DefaultLimits())
			if err != nil {
				t.Fatal(err)
			}
			clone, err := treepkg.Clone(t.Context(), doc)
			if err != nil {
				t.Fatal(err)
			}
			for _, tree := range []*treepkg.Document{doc, clone} {
				root := treepkg.Root(tree)
				if root.SourceLine != 1 {
					t.Fatal(ending, root.SourceLine)
				}
				lines := map[string]int{"a": 4, "b": 9}
				for _, node := range root.Children {
					if node.Kind == treepkg.ElementNode && int(node.SourceLine) != lines[node.Name.Local] {
						t.Fatal(ending, node.Name, node.SourceLine)
					}
				}
			}
		}
	}
}
