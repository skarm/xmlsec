package tree_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/skarm/xmlsec/internal/tree"
)

func TestParseOptionsPreservesRelativeNamespaceNames(t *testing.T) {
	t.Parallel()

	const source = `<p:r xmlns:p="schema/item" p:id="7"/>`
	for _, tc := range []struct {
		name  string
		parse func(tree.ParseOptions, context.Context, string) (*tree.Document, error)
	}{
		{"reader", func(options tree.ParseOptions, ctx context.Context, source string) (*tree.Document, error) {
			return options.ParseReader(ctx, strings.NewReader(source))
		}},
		{"text", tree.ParseOptions.ParseText},
		{"fragment", tree.ParseOptions.ParseFragment},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			options := tree.ParseOptions{Limits: tree.DefaultLimits(), BaseURI: "https://example.test/catalog/"}
			doc, err := tc.parse(options, t.Context(), source)
			if doc != nil || !errors.Is(err, tree.ErrUnsupported) {
				t.Fatalf("strict parse = (%v, %v), want (nil, %v)", doc, err, tree.ErrUnsupported)
			}

			options.AllowRelativeNamespaces = true
			doc, err = tc.parse(options, t.Context(), source)
			if err != nil {
				t.Fatalf("parse allowing relative namespaces: %v", err)
			}
			root := doc.Root()
			wantName := tree.Name{Space: "schema/item", Local: "r"}
			if got := root.Name(); got != wantName {
				t.Errorf("root name = %+v, want %+v", got, wantName)
			}
			if got, ok := root.Attribute(tree.Name{Space: "schema/item", Local: "id"}); !ok || got != "7" {
				t.Errorf("relative namespace attribute = (%q, %t), want (%q, true)", got, ok, "7")
			}
		})
	}
}

func TestParseOptionsParseTextVersionPolicyWithoutDoctype(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name, version string
		allowDTD      bool
		wantErr       error
	}{
		{"strict_xml_10", "1.0", false, nil},
		{"strict_rejects_later_minor", "1.2", false, tree.ErrUnsupported},
		{"language_accepts_later_minor", "1.2", true, nil},
		{"language_rejects_major_2", "2.0", true, tree.ErrUnsupported},
		{"language_requires_numeric_minor", "1.x", true, tree.ErrMalformed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			options := tree.ParseOptions{Limits: tree.DefaultLimits(), AllowDTD: tc.allowDTD}
			source := `<?xml version="` + tc.version + `"?><r>café</r>`
			doc, err := options.ParseText(t.Context(), source)
			if tc.wantErr != nil {
				if doc != nil || !errors.Is(err, tc.wantErr) {
					t.Fatalf("ParseText(%q) = (%v, %v), want (nil, %v)", source, doc, err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseText(%q): %v", source, err)
			}
			if got := doc.Root().Text(); got != "café" {
				t.Errorf("root text = %q, want %q", got, "café")
			}
		})
	}
}

func TestParseOptionsCheckXMLPrologAppliesNamespacePolicy(t *testing.T) {
	t.Parallel()

	const source = `<p:r xmlns:p="schema/item"><unfinished`
	options := tree.ParseOptions{Limits: tree.DefaultLimits()}
	if err := options.CheckXMLProlog(t.Context(), strings.NewReader(source)); !errors.Is(err, tree.ErrUnsupported) {
		t.Fatalf("strict CheckXMLProlog = %v, want %v", err, tree.ErrUnsupported)
	}

	options.AllowRelativeNamespaces = true
	if err := options.CheckXMLProlog(t.Context(), strings.NewReader(source)); err != nil {
		t.Errorf("CheckXMLProlog through the root start tag: %v", err)
	}

	options.Limits.MaxBytes = 0
	if err := options.CheckXMLProlog(t.Context(), strings.NewReader(source)); !errors.Is(err, tree.ErrLimit) {
		t.Errorf("CheckXMLProlog with invalid limits = %v, want %v", err, tree.ErrLimit)
	}
}
