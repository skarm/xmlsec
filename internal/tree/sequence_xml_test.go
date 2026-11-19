package tree_test

import (
	"context"
	"errors"
	"io"
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
		for _, node := range []*tree.Node{
			{Kind: tree.TextNode, Data: "<&"},
			tree.NewDOEMarker(true),
			{Kind: tree.TextNode, Data: "<p>text</p>"},
			tree.NewDOEMarker(false),
			{Kind: tree.TextNode, Data: "&>"},
		} {
			if !yield(node, nil) {
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

func TestWriteXMLSequencePreservesOrdinaryPI(t *testing.T) {
	t.Parallel()

	pi := &tree.Node{Kind: tree.PINode, Name: tree.Name{Local: lexicon.DisableOutputEscapingPITarget}, Data: "note"}
	var out strings.Builder

	nodes := func(yield func(*tree.Node, error) bool) { yield(pi, nil) }

	const want = "<?disable-output-escaping note?>"
	n, err := tree.WriteXMLSequence(t.Context(), &out, nodes, len(want), tree.XMLWriteOptions{DOEMarkers: true})
	if err != nil || out.String() != want || n != int64(len(want)) {
		t.Fatalf("ordinary PI output = (%q, %d, %v), want (%q, %d, nil)", out.String(), n, err, want, len(want))
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

func TestWriteXMLSequenceCancellation(t *testing.T) {
	t.Parallel()

	t.Run("before_iteration", func(t *testing.T) {
		t.Parallel()
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		visited := false
		nodes := func(func(*tree.Node, error) bool) { visited = true }
		n, err := tree.WriteXMLSequence(ctx, io.Discard, nodes, 10, tree.XMLWriteOptions{})
		if n != 0 || !errors.Is(err, context.Canceled) || visited {
			t.Errorf("WriteXMLSequence = (%d, %v), iterator started = %t", n, err, visited)
		}
	})

	t.Run("during_last_write", func(t *testing.T) {
		t.Parallel()
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		var output strings.Builder
		dst := fragmentWriteFunc(func(p []byte) (int, error) {
			cancel()
			return output.Write(p)
		})
		nodes := func(yield func(*tree.Node, error) bool) {
			yield(&tree.Node{Kind: tree.TextNode, Data: "ok"}, nil)
		}
		n, err := tree.WriteXMLSequence(ctx, dst, nodes, 10, tree.XMLWriteOptions{})
		if n != 2 || !errors.Is(err, context.Canceled) || output.String() != "ok" {
			t.Errorf("WriteXMLSequence = (%d, %v), output = %q", n, err, output.String())
		}
	})
}

func TestWriteXMLSequenceRejectsMissingInput(t *testing.T) {
	t.Parallel()

	n, err := tree.WriteXMLSequence(t.Context(), io.Discard, nil, 10, tree.XMLWriteOptions{})
	if n != 0 || !errors.Is(err, tree.ErrMalformed) {
		t.Errorf("nil iterator returned (%d, %v)", n, err)
	}

	var dst *strings.Builder
	nodes := func(func(*tree.Node, error) bool) { t.Error("iterator started with nil writer") }
	n, err = tree.WriteXMLSequence(t.Context(), dst, nodes, 10, tree.XMLWriteOptions{})
	if n != 0 || !errors.Is(err, tree.ErrMalformed) {
		t.Errorf("nil writer returned (%d, %v)", n, err)
	}
}
