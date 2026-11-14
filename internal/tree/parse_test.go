package tree_test

import (
	"bytes"
	"errors"
	"slices"
	"testing"

	"github.com/skarm/xmlsec/internal/tree"
)

func TestParseRejectsInvalidDocumentStructure(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name, source string
	}{
		{"missing_root", `<!--note--><?status ready?>`},
		{"unclosed_root", `<r>text`},
		{"unexpected_end_tag", `</r>`},
		{"second_root", `<r/><s/>`},
		{"different_end_tag_prefix", `<p:r xmlns:p="urn:r" xmlns:q="urn:r"></q:r>`},
		{"unbound_attribute_prefix", `<r p:a="value"/>`},
		{"duplicate_expanded_attribute", `<r xmlns:p="urn:a" xmlns:q="urn:a" p:id="1" q:id="2"/>`},
		{"reserved_namespace_binding", `<r xmlns:p="http://www.w3.org/XML/1998/namespace"/>`},
		{"prefixed_namespace_undeclaration", `<r xmlns:p="urn:a"><s xmlns:p=""/></r>`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			doc, err := tree.Parse(t.Context(), []byte(tc.source), tree.DefaultLimits())
			if doc != nil || !errors.Is(err, tree.ErrMalformed) {
				t.Fatalf("Parse(%q) = (%v, %v), want (nil, %v)", tc.source, doc, err, tree.ErrMalformed)
			}
		})
	}
}

func TestParseRejectsInvalidXMLDeclarations(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name, declaration string
		wantErr           error
	}{
		{"empty_declaration", `<?xml ?>`, tree.ErrMalformed},
		{"encoding_before_version", `<?xml encoding="UTF-8" version="1.0"?>`, tree.ErrUnsupported},
		{"invalid_standalone", `<?xml version="1.0" standalone="maybe"?>`, tree.ErrMalformed},
		{"encoding_after_standalone", `<?xml version="1.0" standalone="yes" encoding="UTF-8"?>`, tree.ErrMalformed},
		{"character_reference_in_version", `<?xml version="1.&#48;"?>`, tree.ErrMalformed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			doc, err := tree.Parse(t.Context(), []byte(tc.declaration+`<r/>`), tree.DefaultLimits())
			if doc != nil || !errors.Is(err, tc.wantErr) {
				t.Fatalf("Parse(%q + root) = (%v, %v), want (nil, %v)", tc.declaration, doc, err, tc.wantErr)
			}
		})
	}
}

func TestParseCountsCoalescedTextAndDocumentChildren(t *testing.T) {
	t.Parallel()

	const source = "<?xml version='1.0' standalone='no'?>\n<!--before--><r>a<![CDATA[b]]>&amp;c</r>\n<?status done?>"
	limits := tree.DefaultLimits()
	limits.MaxNodes = 4
	doc, err := tree.Parse(t.Context(), []byte(source), limits)
	if err != nil {
		t.Fatalf("Parse with MaxNodes=4: %v", err)
	}

	children := tree.Children(doc)
	if len(children) != 3 {
		t.Fatalf("document has %d children, want 3", len(children))
	}
	if got := children[0]; got.Kind != tree.CommentNode || got.Data != "before" {
		t.Errorf("first child = %+v, want comment %q", got, "before")
	}
	if got := children[2]; got.Kind != tree.PINode || got.Name.Local != "status" || got.Data != "done" {
		t.Errorf("last child = %+v, want PI <?status done?>", got)
	}
	root := tree.Root(doc)
	if root != children[1] || root.Name.Local != "r" || len(root.Children) != 1 {
		t.Fatalf("root = %+v, want middle child <r> with one text node", root)
	}
	if got := root.Children[0]; got.Kind != tree.TextNode || got.Data != "ab&c" || got.Parent != root {
		t.Errorf("root child = %+v, want text %q with <r> as parent", got, "ab&c")
	}

	limits.MaxNodes--
	doc, err = tree.Parse(t.Context(), []byte(source), limits)
	if doc != nil || !errors.Is(err, tree.ErrLimit) {
		t.Fatalf("Parse with MaxNodes=3 = (%v, %v), want (nil, %v)", doc, err, tree.ErrLimit)
	}
}

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

		got, err := tree.NormalizeLexicalForTest(input)
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

func TestParserOwnsReusedAttributeTokens(t *testing.T) {
	t.Parallel()
	doc, err := tree.Parse(t.Context(), []byte(`<r xmlns:p="urn:outer" marker="root"><p:a p:first="1" b="2" c="3"/><n only="4"/><plain/><p:b xmlns:p="urn:inner" p:second="5" other="6"/><tail marker="last"/></r>`), tree.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	root := tree.Root(doc)
	want := [][]tree.Attribute{
		{{Name: tree.Name{Local: "marker"}, Value: "root"}},
		{{Name: tree.Name{Space: "urn:outer", Local: "first"}, Prefix: "p", Value: "1"}, {Name: tree.Name{Local: "b"}, Value: "2"}, {Name: tree.Name{Local: "c"}, Value: "3"}},
		{{Name: tree.Name{Local: "only"}, Value: "4"}},
		{},
		{{Name: tree.Name{Space: "urn:inner", Local: "second"}, Prefix: "p", Value: "5"}, {Name: tree.Name{Local: "other"}, Value: "6"}},
		{{Name: tree.Name{Local: "marker"}, Value: "last"}},
	}
	nodes := append([]*tree.Node{root}, root.Children...)
	if len(nodes) != len(want) {
		t.Fatal("self-closing elements changed", len(nodes))
	}
	for i, node := range nodes {
		if !slices.Equal(node.Attrs, want[i]) {
			t.Fatalf("node %d attributes overwritten: got %+v; want %+v", i, node.Attrs, want[i])
		}
	}
	if root.Children[0].Name.Space != "urn:outer" || root.Children[3].Name.Space != "urn:inner" || root.NS[0].URI != "urn:outer" {
		t.Fatal("namespace token storage escaped into another element")
	}
}

func TestParserOwnsReusedContentTokens(t *testing.T) {
	t.Parallel()
	doc, err := tree.Parse(t.Context(), []byte(`<r>first<!--one--><?p x?><a>inner</a>last<![CDATA[ tail]]><!--two--><?q y?></r>`), tree.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	want := []struct {
		kind tree.Kind
		name string
		data string
	}{
		{tree.TextNode, "", "first"},
		{tree.CommentNode, "", "one"},
		{tree.PINode, "p", "x"},
		{tree.ElementNode, "a", ""},
		{tree.TextNode, "", "last tail"},
		{tree.CommentNode, "", "two"},
		{tree.PINode, "q", "y"},
	}
	nodes := tree.Root(doc).Children
	if len(nodes) != len(want) {
		t.Fatal("token kinds or text coalescing changed", len(nodes))
	}
	for i, node := range nodes {
		if node.Kind != want[i].kind || node.Name.Local != want[i].name || node.Data != want[i].data {
			t.Fatalf("node %d changed after token reuse: %+v", i, node)
		}
	}
	if got := nodes[3].Children; len(got) != 1 || got[0].Data != "inner" {
		t.Fatal("child text changed after the next character token")
	}
}
