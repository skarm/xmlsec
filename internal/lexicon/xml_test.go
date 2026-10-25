package lexicon_test

import (
	"encoding/xml"
	"strings"
	"testing"

	"github.com/skarm/xmlsec/internal/lexicon"
)

// The standard decoder resolves the reserved xml prefix independently of this
// project's vocabulary, catching inconsistent qualified/expanded spellings.
func TestReservedXMLNames(t *testing.T) {
	source := `<root ` + lexicon.QNameXMLBase + `="https://example.test/" ` + lexicon.QNameXMLID + `="item" ` + lexicon.QNameXMLLang + `="en" ` + lexicon.QNameXMLSpace + `="preserve"/>`
	token, err := xml.NewDecoder(strings.NewReader(source)).Token()
	if err != nil {
		t.Fatal(err)
	}

	root, ok := token.(xml.StartElement)
	if !ok || len(root.Attr) != 4 {
		t.Fatal("reserved attribute vocabulary did not produce one element")
	}

	want := map[string]string{lexicon.AttrBase: "https://example.test/", lexicon.AttrID: "item", lexicon.AttrLang: "en", lexicon.AttrSpace: lexicon.SpacePreserve}
	for _, attr := range root.Attr {
		value, exists := want[attr.Name.Local]
		if !exists || attr.Name.Space != lexicon.NamespaceXML || attr.Value != value {
			t.Fatalf("reserved XML name mismatch: %+v", attr)
		}

		delete(want, attr.Name.Local)
	}

	if len(want) != 0 {
		t.Fatal("reserved attributes collided:", want)
	}
}
