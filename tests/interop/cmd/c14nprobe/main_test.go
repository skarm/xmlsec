package main

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/skarm/xmlsec/c14n"
	"github.com/skarm/xmlsec/document"
)

func TestCanonicalRequestSelection(t *testing.T) {
	empty := []selector{}
	root := []selector{{Path: []int{1}}}
	for _, test := range []struct {
		name    string
		request request
		want    string
		invalid bool
	}{
		{"document", request{XML: `<r a="1"><c>é&amp;</c><!--C--></r>`, Comments: true}, `<r a="1"><c>é&amp;</c><!--C--></r>`, false},
		{"comments suppressed", request{XML: `<r><!--C--><c>é&amp;</c></r>`}, `<r><c>é&amp;</c></r>`, false},
		{"input overrides XML", request{XML: `<invalid`, Input: []byte(`<r/>`)}, `<r></r>`, false},
		{"empty input is present", request{XML: `<r/>`, Input: []byte{}}, "", true},
		{"empty explicit set", request{XML: `<r/>`, Select: &empty}, "", false},
		{"root set", request{XML: `<r/>`, Select: &root}, `<r></r>`, false},
		{"subtree", request{XML: `<r><c>é&amp;</c></r>`, Subtree: []int{1, 1}}, `<c>é&amp;</c>`, false},
		{"document is not subtree element", request{XML: `<r/>`, Subtree: []int{}}, "", true},
	} {
		t.Run(test.name, func(t *testing.T) {
			test.request.Algorithm = c14n.Exclusive
			result, err := process(test.request)
			if test.invalid {
				if err == nil || len(result.Canonical) != 0 {
					t.Fatalf("invalid input produced data: %+v %v", result, err)
				}
				return
			}
			if len(result.Nodes) != 0 {
				t.Fatal("description was computed without being requested")
			}
			if err != nil || string(result.Canonical) != test.want {
				t.Fatalf("canonical=%q error=%v want=%q", result.Canonical, err, test.want)
			}
		})
	}
}

func TestSelectorAxesAndDescriptionOwnership(t *testing.T) {
	doc, err := document.Parse(t.Context(), []byte(`<r xmlns:p="urn:p" p:a="A">text<p:c/></r>`), document.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		selection selector
		want      string
		invalid   bool
	}{
		{selector{Path: []int{1}, Kind: nameAttribute, Local: "a", Space: "urn:p"}, "A", false},
		{selector{Path: []int{1}, Kind: "namespace", Prefix: "p"}, "urn:p", false},
		{selector{Path: []int{1, 1}, Kind: "text"}, "text", false},
		{selector{Path: []int{0}}, "", true},
		{selector{Path: []int{2}}, "", true},
		{selector{Path: []int{1, 1}, Kind: nameAttribute}, "", true},
		{selector{Path: []int{1}, Kind: nameAttribute, Local: "missing"}, "", true},
		{selector{Path: []int{1}, Kind: "text"}, "", true},
	} {
		node, err := resolve(doc, test.selection)
		if test.invalid {
			if err == nil || node.Valid() {
				t.Fatalf("invalid selector accepted: %+v %v", test.selection, err)
			}
			continue
		}
		if err != nil || node.Value() != test.want {
			t.Fatalf("selector %+v value=%q error=%v", test.selection, node.Value(), err)
		}
	}
	result, err := process(request{XML: `<r a="1"><c/></r>`, Describe: true, Algorithm: c14n.Exclusive})
	if err != nil {
		t.Fatal(err)
	}
	var rootPath, attributePath []int
	for _, node := range result.Nodes {
		if node.Kind == "element" && len(node.Path) == 1 {
			rootPath = node.Path
		}
		if node.Kind == nameAttribute {
			attributePath = node.Path
		}
	}
	if len(rootPath) != 1 || len(attributePath) != 1 || rootPath[0] != 1 || attributePath[0] != 1 {
		t.Fatalf("missing described axes: %+v", result.Nodes)
	}
	failed, err := process(request{XML: `<r/>`, Describe: true, Subtree: []int{2}, Algorithm: c14n.Exclusive})
	if err == nil || len(failed.Nodes) < 2 || len(failed.Canonical) != 0 {
		t.Fatalf("selection error lost its diagnostic description: %+v %v", failed, err)
	}
	attributePath[0] = 99
	if rootPath[0] != 1 {
		t.Fatal("description paths share mutable storage")
	}
}

func TestSelectionPropagatesSinkFailure(t *testing.T) {
	doc, err := document.ParseReader(t.Context(), strings.NewReader(`<r>`+strings.Repeat("x", 4096)+`</r>`), document.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	failure := errors.New("sink failure")
	writer := &failingWriter{remaining: 8, failure: failure}
	if err := writeSelection(writer, doc, request{}, c14n.Options{Algorithm: c14n.Exclusive}); !errors.Is(err, failure) || writer.output.Len() == 0 {
		t.Fatalf("late error/output: %v %d", err, writer.output.Len())
	}
	if err := writeSelection(&failingWriter{}, doc, request{}, c14n.Options{Algorithm: c14n.Exclusive}); !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("short write: %v", err)
	}
}

type failingWriter struct {
	remaining int
	failure   error
	output    bytes.Buffer
}

func (w *failingWriter) Write(p []byte) (int, error) {
	n := min(w.remaining, len(p))
	w.remaining -= n
	w.output.Write(p[:n])
	if n < len(p) {
		return n, w.failure
	}
	return n, nil
}
