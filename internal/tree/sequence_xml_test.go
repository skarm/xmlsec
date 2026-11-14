package tree_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/skarm/xmlsec/internal/lexicon"
	"github.com/skarm/xmlsec/internal/tree"
)

func TestWriteXMLCharactersModes(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name, input, want string
		mode              tree.XMLCharacterMode
		options           tree.XMLWriteOptions
	}{
		{"text", "<&>\r", "&lt;&amp;&gt;&#xD;", tree.XMLTextContent, tree.XMLWriteOptions{}},
		{"attribute", "\"\t\n\r&", "&quot;&#x9;&#xA;&#xD;&amp;", tree.XMLAttributeValue, tree.XMLWriteOptions{}},
		{"cdata_splits_terminator", "a]]>b", "<![CDATA[a]]]]><![CDATA[>b]]>", tree.XMLCDATAContent, tree.XMLWriteOptions{}},
		{"cdata_ignores_character_map", "@é", "<![CDATA[@é]]>", tree.XMLCDATAContent, tree.XMLWriteOptions{CharacterMap: map[rune]string{'@': "mapped"}}},
		{"normalization_and_repertoire", "e\u0301Ω", "é&#937;", tree.XMLTextContent, tree.XMLWriteOptions{Normalization: "NFC", CanEncode: func(r rune) bool { return r <= 255 }}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var out strings.Builder
			n, err := tree.WriteXMLCharacters(t.Context(), &out, tc.input, tc.mode, len(tc.want), tc.options)
			if err != nil || out.String() != tc.want || n != int64(len(tc.want)) {
				t.Fatalf("WriteXMLCharacters(%q) = (%q, %d, %v), want (%q, %d, nil)", tc.input, out.String(), n, err, tc.want, len(tc.want))
			}
		})
	}
}

func TestWriteXMLCharactersRejectsInvalidOutput(t *testing.T) {
	t.Parallel()

	canceled, cancel := context.WithCancel(t.Context())
	cancel()
	for _, tc := range []struct {
		name    string
		ctx     context.Context
		mode    tree.XMLCharacterMode
		maximum int
		wantErr error
	}{
		{"unknown_mode", t.Context(), 99, 100, tree.ErrMalformed},
		{"nonpositive_budget", t.Context(), tree.XMLTextContent, 0, tree.ErrMalformed},
		{"canceled", canceled, tree.XMLTextContent, 100, context.Canceled},
		{"limit_uses_escaped_size", t.Context(), tree.XMLTextContent, 4, tree.ErrLimit},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var out strings.Builder
			n, err := tree.WriteXMLCharacters(tc.ctx, &out, "&", tc.mode, tc.maximum, tree.XMLWriteOptions{})
			if n != 0 || out.Len() != 0 || !errors.Is(err, tc.wantErr) {
				t.Fatalf("WriteXMLCharacters = (%q, %d, %v), want empty output and %v", out.String(), n, err, tc.wantErr)
			}
		})
	}
}

func TestWriteXMLSequencePreservesEachNodesInScopeNamespaces(t *testing.T) {
	t.Parallel()

	const source = `<r xmlns="urn:outer" xmlns:p="urn:old"><p:first p:a="1"/><branch xmlns:p="urn:new"><p:second p:a="2"/></branch></r>`
	doc, err := tree.Parse(t.Context(), []byte(source), tree.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	root := tree.Root(doc)
	first, second := root.Children[0], root.Children[1].Children[0]
	options := tree.XMLWriteOptions{SelfClose: true, Reconcile: true, InheritedNamespaces: map[string]string{"p": "urn:old"}}
	nodes := func(yield func(*tree.Node, error) bool) {
		for _, node := range []*tree.Node{first, second, first} {
			if !yield(node, nil) {
				return
			}
		}
	}

	var out strings.Builder
	const want = `<p:first xmlns="urn:outer" p:a="1"/><p:second xmlns="urn:outer" xmlns:p="urn:new" p:a="2"/><p:first xmlns="urn:outer" p:a="1"/>`
	n, err := tree.WriteXMLSequence(t.Context(), &out, nodes, len(want), options)
	if err != nil || out.String() != want || n != int64(len(want)) {
		t.Fatalf("WriteXMLSequence = (%q, %d, %v), want (%q, %d, nil)", out.String(), n, err, want, len(want))
	}
	if first.Parent != root || second.Parent != root.Children[1] || len(first.NS) != 0 || len(second.NS) != 0 || options.InheritedNamespaces["p"] != "urn:old" || len(options.InheritedNamespaces) != 1 {
		t.Fatal("WriteXMLSequence changed source nodes or inherited namespace options")
	}
}

func TestWriteXMLSequenceResumesEscapingAfterMarker(t *testing.T) {
	t.Parallel()

	nodes := func(yield func(*tree.Node, error) bool) {
		for _, node := range []tree.Node{
			{Kind: tree.TextNode, Data: "<&"},
			{Kind: tree.PINode, Name: tree.Name{Local: lexicon.DisableOutputEscapingPITarget}},
			{Kind: tree.TextNode, Data: "<p>text</p>"},
			{Kind: tree.PINode, Name: tree.Name{Local: lexicon.EnableOutputEscapingPITarget}},
			{Kind: tree.TextNode, Data: "&>"},
		} {
			if !yield(&node, nil) {
				return
			}
		}
	}

	var out strings.Builder
	const want = "&lt;&amp;<p>text</p>&amp;&gt;"
	n, err := tree.WriteXMLSequence(t.Context(), &out, nodes, len(want), tree.XMLWriteOptions{DOEMarkers: true})
	if err != nil || out.String() != want || n != int64(len(want)) {
		t.Fatalf("WriteXMLSequence = (%q, %d, %v), want (%q, %d, nil)", out.String(), n, err, want, len(want))
	}
}

func TestWriteXMLSequenceStopsOnFailure(t *testing.T) {
	t.Parallel()

	sourceErr := errors.New("source stopped")
	for _, tc := range []struct {
		name    string
		node    *tree.Node
		err     error
		budget  int
		wantErr error
	}{
		{"iterator_error", nil, sourceErr, 20, sourceErr},
		{"nil_node", nil, nil, 20, tree.ErrMalformed},
		{"output_limit", &tree.Node{Kind: tree.TextNode, Data: "more"}, nil, 2, tree.ErrLimit},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			nextRequested := false
			nodes := func(yield func(*tree.Node, error) bool) {
				if !yield(&tree.Node{Kind: tree.TextNode, Data: "ok"}, nil) || !yield(tc.node, tc.err) {
					return
				}
				nextRequested = true
				yield(&tree.Node{Kind: tree.TextNode, Data: "extra"}, nil)
			}

			var out strings.Builder
			n, err := tree.WriteXMLSequence(t.Context(), &out, nodes, tc.budget, tree.XMLWriteOptions{})
			if !errors.Is(err, tc.wantErr) || n != 2 || out.String() != "ok" || nextRequested {
				t.Fatalf("WriteXMLSequence = (%q, %d, %v), requested next = %t; want previous output and %v", out.String(), n, err, nextRequested, tc.wantErr)
			}
		})
	}
}
