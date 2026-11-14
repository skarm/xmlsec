package tree_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/skarm/xmlsec/internal/tree"
)

func TestParseFragmentTextKeepsDecodedContentAndOrder(t *testing.T) {
	t.Parallel()

	for _, declaration := range []struct {
		name, text string
	}{
		{name: "without_declaration"},
		{name: "encoding_only", text: `<?xml encoding="ISO-8859-1"?>`},
		{name: "version_and_encoding", text: `<?xml version="1.0" encoding="ISO-8859-1"?>`},
	} {
		t.Run(declaration.name, func(t *testing.T) {
			t.Parallel()

			const content = `<?xml-stylesheet href="style.css"?>café<a/>end<!--note--><b/>`
			doc, err := tree.ParseFragmentText(t.Context(), declaration.text+content, tree.DefaultLimits())
			if err != nil {
				t.Fatal(err)
			}
			want := []struct {
				kind tree.Kind
				name string
				data string
			}{
				{tree.PINode, "xml-stylesheet", `href="style.css"`},
				{tree.TextNode, "", "café"},
				{tree.ElementNode, "a", ""},
				{tree.TextNode, "", "end"},
				{tree.CommentNode, "", "note"},
				{tree.ElementNode, "b", ""},
			}
			children := doc.Node().Children()
			if len(children) != len(want) {
				t.Fatalf("fragment has %d children, want %d", len(children), len(want))
			}
			for i, child := range children {
				if child.Kind() != want[i].kind || child.Name().Local != want[i].name || child.Value() != want[i].data {
					t.Errorf("child %d = (%s, %q, %q), want (%s, %q, %q)", i, child.Kind(), child.Name().Local, child.Value(), want[i].kind, want[i].name, want[i].data)
				}
				if !child.Parent().Same(doc.Node()) {
					t.Errorf("child %d parent = %s, want document", i, child.Parent().Kind())
				}
			}
		})
	}
}

func TestParseFragmentTextRejectsInvalidDeclarations(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name, text string
		wantErr    error
	}{
		{name: "unterminated", text: `<?xml encoding="UTF-8"`, wantErr: tree.ErrMalformed},
		{name: "missing_attributes", text: `<?xml ?><a/>`, wantErr: tree.ErrMalformed},
		{name: "missing_encoding", text: `<?xml version="1.0"?><a/>`, wantErr: tree.ErrMalformed},
		{name: "invalid_encoding_name", text: `<?xml encoding="1UTF"?><a/>`, wantErr: tree.ErrMalformed},
		{name: "standalone_attribute", text: `<?xml encoding="UTF-8" standalone="yes"?><a/>`, wantErr: tree.ErrMalformed},
		{name: "unsupported_version", text: `<?xml version="1.1" encoding="UTF-8"?><a/>`, wantErr: tree.ErrUnsupported},
		{name: "malformed_content", text: `<?xml encoding="UTF-8"?><a></b>`, wantErr: tree.ErrMalformed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			doc, err := tree.ParseFragmentText(t.Context(), tc.text, tree.DefaultLimits())
			if doc != nil || !errors.Is(err, tc.wantErr) {
				t.Errorf("ParseFragmentText(%q) returned document=%t, error=%v, want nil document and %v", tc.text, doc != nil, err, tc.wantErr)
			}
		})
	}
}

func TestParseFragmentTextCountsDeclarationBytes(t *testing.T) {
	t.Parallel()

	const input = `<?xml encoding="UTF-8"?><a>é</a>`
	limits := tree.DefaultLimits()
	limits.MaxBytes = len(input)
	doc, err := tree.ParseFragmentText(t.Context(), input, limits)
	if err != nil {
		t.Fatal(err)
	}
	if got := doc.Root().Text(); got != "é" {
		t.Errorf("root text = %q, want é", got)
	}

	limits.MaxBytes--
	if err := tree.CheckSnapshotLimits(t.Context(), doc, limits); !errors.Is(err, tree.ErrLimit) {
		t.Errorf("CheckSnapshotLimits at %d bytes = %v, want %v", limits.MaxBytes, err, tree.ErrLimit)
	}
	if got, err := tree.ParseFragmentText(t.Context(), input, limits); got != nil || !errors.Is(err, tree.ErrLimit) {
		t.Errorf("ParseFragmentText at %d bytes returned document=%t, error=%v, want nil document and %v", limits.MaxBytes, got != nil, err, tree.ErrLimit)
	}
}

func TestParseFragmentTextRejectsInvalidSetup(t *testing.T) {
	t.Parallel()

	limits := tree.DefaultLimits()
	invalid := limits
	invalid.MaxNodes = 0
	canceled, cancel := context.WithCancel(t.Context())
	cancel()
	for _, tc := range []struct {
		name    string
		ctx     context.Context
		limits  tree.Limits
		wantErr error
	}{
		{name: "nil_context", limits: limits, wantErr: tree.ErrMalformed},
		{name: "canceled", ctx: canceled, limits: limits, wantErr: context.Canceled},
		{name: "invalid_limits", ctx: t.Context(), limits: invalid, wantErr: tree.ErrLimit},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			doc, err := tree.ParseFragmentText(tc.ctx, "<a/>", tc.limits)
			if doc != nil || !errors.Is(err, tc.wantErr) {
				t.Errorf("ParseFragmentText returned document=%t, error=%v, want nil document and %v", doc != nil, err, tc.wantErr)
			}
		})
	}
}

func TestFragmentUsesSemanticLimits(t *testing.T) {
	limits := tree.DefaultLimits()
	limits.MaxBytes = 1
	limits.MaxNodes = 1
	limits.MaxDepth = 1

	d, err := tree.ParseFragment(t.Context(), []byte("a"), limits)
	if err != nil || len(tree.Children(d)) != 1 || tree.Children(d)[0].Data != "a" {
		t.Fatal(d, err)
	}

	if _, err := tree.ParseFragment(t.Context(), []byte("ab"), limits); !errors.Is(err, tree.ErrLimit) {
		t.Fatal("fragment bytes were not bounded", err)
	}

	limits = tree.DefaultLimits()
	limits.MaxDepth = 512
	limits.MaxNodes = 512

	data := []byte(strings.Repeat("<n>", 512) + strings.Repeat("</n>", 512))
	if _, err := tree.ParseFragment(t.Context(), data, limits); err != nil {
		t.Fatal("synthetic root consumed a depth/node slot", err)
	}

	for _, xml := range []string{`<!DOCTYPE r [<!ENTITY x "x">]><r>&x;</r>`, `<p:r/>`, `<r a="1" a="2"/>`} {
		if _, err := tree.ParseFragment(t.Context(), []byte(xml), tree.DefaultLimits()); err == nil {
			t.Error("invalid fragment accepted", xml)
		}
	}
}
