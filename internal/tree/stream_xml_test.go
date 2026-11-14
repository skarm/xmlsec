package tree_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"maps"
	"strings"
	"testing"

	"github.com/skarm/xmlsec/internal/tree"
)

func TestDocumentWriteXMLRetainsDocumentOrder(t *testing.T) {
	t.Parallel()

	const source = `<?xml version="1.0"?><?before ready?><p:r xmlns:p="urn:p" a="&quot;"><p:item/>é&amp;</p:r><!--after-->`
	const want = `<?before ready?><p:r xmlns:p="urn:p" a="&quot;"><p:item></p:item>é&amp;</p:r><!--after-->`
	doc, err := tree.Parse(t.Context(), []byte(source), tree.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	var output strings.Builder
	n, err := doc.WriteXML(t.Context(), &output, len(want))
	if err != nil || n != int64(len(want)) || output.String() != want {
		t.Errorf("WriteXML = (%q, %d, %v), want (%q, %d, nil)", output.String(), n, err, want, len(want))
	}

	output.Reset()
	maxBytes := len(want) - 1
	n, err = doc.WriteXML(t.Context(), &output, maxBytes)
	if !errors.Is(err, tree.ErrLimit) || n != int64(output.Len()) || output.Len() > maxBytes || !strings.HasPrefix(want, output.String()) {
		t.Errorf("WriteXML with budget %d = (%q, %d, %v), want a counted prefix within budget and %v", maxBytes, output.String(), n, err, tree.ErrLimit)
	}
}

func TestDocumentWriteXMLRespectsInheritedContext(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name, inherited, want string
		wantErr               error
	}{
		{name: "inherited_namespace_is_declared", inherited: ` xmlns:p="urn:p"`, want: `<p:item xmlns:p="urn:p"></p:item>`},
		{name: "inherited_xml_attribute_cannot_be_copied", inherited: ` xmlns:p="urn:p" xml:lang="en"`, wantErr: tree.ErrUnsupported},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			source, err := tree.Parse(t.Context(), []byte("<r"+tc.inherited+"><p:item/><sibling/></r>"), tree.DefaultLimits())
			if err != nil {
				t.Fatal(err)
			}
			scope, err := tree.ScopeDocument(source, source.Root().Children()[0])
			if err != nil {
				t.Fatal(err)
			}
			var output strings.Builder
			n, err := scope.WriteXML(t.Context(), &output, 128)
			if !errors.Is(err, tc.wantErr) || n != int64(len(tc.want)) || output.String() != tc.want {
				t.Errorf("WriteXML = (%q, %d, %v), want (%q, %d, %v)", output.String(), n, err, tc.want, len(tc.want), tc.wantErr)
			}
		})
	}
}

func TestDocumentWriteXMLRejectsRequestsBeforeWriting(t *testing.T) {
	t.Parallel()

	doc, err := tree.Parse(t.Context(), []byte("<r/>"), tree.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	canceled, cancel := context.WithCancel(t.Context())
	cancel()
	for _, tc := range []struct {
		name    string
		doc     *tree.Document
		ctx     context.Context
		max     int
		wantErr error
	}{
		{name: "missing_document", ctx: t.Context(), max: 32, wantErr: tree.ErrMalformed},
		{name: "nil_context", doc: doc, max: 32, wantErr: tree.ErrMalformed},
		{name: "zero_output_budget", doc: doc, ctx: t.Context(), wantErr: tree.ErrMalformed},
		{name: "canceled", doc: doc, ctx: canceled, max: 32, wantErr: context.Canceled},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var output strings.Builder
			n, err := tc.doc.WriteXML(tc.ctx, &output, tc.max)
			if !errors.Is(err, tc.wantErr) || n != 0 || output.Len() != 0 {
				t.Errorf("WriteXML = (%q, %d, %v), want empty output and %v", output.String(), n, err, tc.wantErr)
			}
		})
	}
}

func TestWriteXMLFragmentCountsOnlyDeliveredBytes(t *testing.T) {
	t.Parallel()

	failure := errors.New("destination failure")
	for _, tc := range []struct {
		name      string
		limit     int
		failWrite bool
		cancel    bool
		writeErr  error
		want      string
		wantErr   error
	}{
		{name: "exact_byte_limit", limit: 5, want: "éend"},
		{name: "limit_rejects_next_chunk", limit: 4, want: "é", wantErr: tree.ErrLimit},
		{name: "short_write", limit: 10, failWrite: true, want: "ée", wantErr: io.ErrShortWrite},
		{name: "partial_failure", limit: 10, failWrite: true, writeErr: failure, want: "ée", wantErr: failure},
		{name: "cancellation_from_writer", limit: 10, cancel: true, want: "é", wantErr: context.Canceled},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			var output strings.Builder
			calls := 0
			writer := fragmentWriteFunc(func(p []byte) (int, error) {
				calls++
				if tc.failWrite && calls == 2 {
					n, _ := output.Write(p[:1])
					return n, tc.writeErr
				}
				n, err := output.Write(p)
				if tc.cancel {
					cancel()
				}
				return n, err
			})
			nodes := []*tree.Node{{Kind: tree.TextNode, Data: "é"}, {Kind: tree.TextNode, Data: "end"}}
			n, err := tree.WriteXMLFragment(ctx, writer, nodes, tc.limit)
			if !errors.Is(err, tc.wantErr) || n != int64(len(tc.want)) || output.String() != tc.want {
				t.Fatalf("WriteXMLFragment = (%q, %d, %v), want (%q, %d, %v)", output.String(), n, err, tc.want, len(tc.want), tc.wantErr)
			}
		})
	}
}

type fragmentWriteFunc func([]byte) (int, error)

func (f fragmentWriteFunc) Write(p []byte) (int, error) { return f(p) }

func TestWriteXMLFragmentOptionsControlsElementFormatting(t *testing.T) {
	t.Parallel()

	const source = `<r><p xml:space="preserve"><a/><reset xml:space="default"><a/></reset><a/></p><q><a/><v/></q><inline><v/><a/></inline><compact><q><a/></q></compact><suppressed><q><a/></q></suppressed><q><a/></q></r>`
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
. <p xml:space="preserve"><a /><reset xml:space="default">
. . . <a />
. . </reset><a /></p>
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
			name:    "canonical_decomposition",
			source:  `<r a="é">éﬀ</r>`,
			want:    "<r a=\"e\u0301\">e\u0301ﬀ</r>",
			options: tree.XMLWriteOptions{Normalization: "NFD"},
		},
		{
			name:    "compatibility_composition",
			source:  `<r a="é">éﬀ</r>`,
			want:    `<r a="é">éff</r>`,
			options: tree.XMLWriteOptions{Normalization: "NFKC"},
		},
		{
			name:    "compatibility_decomposition",
			source:  `<r a="é">éﬀ</r>`,
			want:    "<r a=\"e\u0301\">e\u0301ff</r>",
			options: tree.XMLWriteOptions{Normalization: "NFKD"},
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

func TestXMLWriterRestoresNamespaceScopes(t *testing.T) {
	ctx := t.Context()

	d, err := tree.Parse(ctx, []byte(`<r xmlns="urn:r" xmlns:p="urn:p"><a xmlns="" xmlns:p="urn:a"><p:x/></a><p:y/><b xmlns:p="urn:b"><p:z/></b><p:w/></r>`), tree.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}

	inherited := map[string]string{"p": "urn:outside", "q": "urn:q"}
	before := maps.Clone(inherited)

	for _, selfClose := range []bool{false, true} {
		var out bytes.Buffer

		_, err := tree.WriteXMLFragmentOptions(ctx, &out, tree.Children(d), 4096, tree.XMLWriteOptions{Reconcile: true, SelfClose: selfClose, InheritedNamespaces: inherited})
		if err != nil {
			t.Fatal(err)
		}

		roundtrip, err := tree.Parse(ctx, out.Bytes(), tree.DefaultLimits())
		if err != nil {
			t.Fatal(out.String(), err)
		}

		children := roundtrip.Root().Children()
		if children[0].Name().Space != "" || children[0].Children()[0].Name().Space != "urn:a" || children[1].Name().Space != "urn:p" || children[2].Children()[0].Name().Space != "urn:b" || children[3].Name().Space != "urn:p" {
			t.Fatal("namespace scope leaked across siblings", out.String())
		}

		if !maps.Equal(inherited, before) {
			t.Fatal("caller namespace map mutated", inherited)
		}
	}
}

func TestXMLWriterReconcilesEmptyDefaultNamespace(t *testing.T) {
	doc, err := tree.Parse(t.Context(), []byte(`<p:r xmlns:p="urn:p" xmlns=""/>`), tree.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}

	for _, test := range []struct {
		reconcile bool
		inherited string
		reset     bool
	}{
		{true, "", false}, {true, "urn:destination", true}, {false, "", true},
	} {
		var output bytes.Buffer

		_, err := tree.WriteXMLFragmentOptions(t.Context(), &output, tree.Children(doc), 1024,
			tree.XMLWriteOptions{Reconcile: test.reconcile, SelfClose: true, InheritedNamespaces: map[string]string{"": test.inherited}})
		if err != nil {
			t.Fatal(err)
		}

		if strings.Contains(output.String(), `xmlns=""`) != test.reset {
			t.Errorf("reconcile=%v inherited=%q: %s", test.reconcile, test.inherited, output.String())
		}
	}
}

func TestXMLWriterCDATAUsesSharedEscapingAndNormalization(t *testing.T) {
	ctx := t.Context()

	d, err := tree.Parse(ctx, []byte("<r>e&#x301;]]&gt;ж&#13;</r>"), tree.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}

	options := tree.XMLWriteOptions{ASCII: true, Normalization: "NFC", CDATA: map[string]struct{}{"{}r": {}}}

	var b bytes.Buffer
	if _, err = tree.WriteXMLFragmentOptions(ctx, &b, tree.Children(d), 4096, options); err != nil {
		t.Fatal(err)
	}

	roundtrip, err := tree.Parse(ctx, b.Bytes(), tree.DefaultLimits())
	if err != nil || roundtrip.Root().Text() != "é]]>ж\r" || strings.ContainsAny(b.String(), "éж") {
		t.Fatal("CDATA normalization/character references lost", b.String(), err)
	}

	options.ASCII = false
	options.CharacterMap = map[rune]string{'@': "<p/>"}
	n := &tree.Node{Kind: tree.ElementNode, Name: tree.Name{Local: "r"}, Children: []*tree.Node{{Kind: tree.TextNode, Data: "a@b"}}}

	b.Reset()

	if _, err = tree.WriteXMLFragmentOptions(ctx, &b, []*tree.Node{n}, 4096, options); err != nil || b.String() != "<r><![CDATA[a@b]]></r>" {
		t.Fatal("character map affected CDATA", b.String(), err)
	}

	for _, bad := range []string{"\x00", "\xff", "\ufffe"} {
		n.Children[0].Data = bad

		b.Reset()

		if _, err = tree.WriteXMLFragmentOptions(ctx, &b, []*tree.Node{n}, 4096, options); !errors.Is(err, tree.ErrMalformed) {
			t.Fatalf("invalid CDATA accepted: %q, %v", bad, err)
		}
	}
}

func TestXMLWriterPrefixUndeclarations(t *testing.T) {
	nodes := []*tree.Node{{Kind: tree.ElementNode, Name: tree.Name{Local: "r"}, NS: []tree.Namespace{{Prefix: "p", URI: "urn:p"}}, Children: []*tree.Node{{Kind: tree.ElementNode, Name: tree.Name{Local: "c"}, NS: []tree.Namespace{{Prefix: "p", URI: ""}}, Children: []*tree.Node{{Kind: tree.ElementNode, Name: tree.Name{Space: "urn:p", Local: "again"}, Prefix: "p"}}}}}}
	for _, test := range []struct {
		version   string
		undeclare bool
		want      string
	}{
		{"1.0", false, `<r xmlns:p="urn:p"><c><p:again/></c></r>`},
		{"1.1", false, `<r xmlns:p="urn:p"><c><p:again/></c></r>`},
		{"1.1", true, `<r xmlns:p="urn:p"><c xmlns:p=""><p:again xmlns:p="urn:p"/></c></r>`},
	} {
		var output bytes.Buffer
		_, err := tree.WriteXMLFragmentOptions(t.Context(), &output, nodes, 4096, tree.XMLWriteOptions{Version: test.version, PrefixUndeclarations: test.undeclare, Reconcile: true, SelfClose: true})
		if err != nil || output.String() != test.want {
			t.Fatal(test.version, test.undeclare, output.String(), err, test.want)
		}
	}
}
