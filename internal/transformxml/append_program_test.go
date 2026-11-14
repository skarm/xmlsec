package transformxml_test

import (
	"context"
	"errors"
	"reflect"
	"slices"
	"testing"

	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/internal/transformxml"
	"github.com/skarm/xmlsec/internal/tree"
	"github.com/skarm/xmlsec/reference"
)

func TestAppendProgramXPathBindings(t *testing.T) {
	t.Parallel()
	input := reference.Transform{Algorithm: reference.XPath, XPath: []reference.XPathExpression{{
		Expression: `self::p:item and @xml:lang = "en"`,
		Namespaces: map[string]string{"p": "urn:item", "": "urn:default", "xml": document.XMLNamespace},
	}}}
	draft := newTransformDraft(input.Algorithm)
	if err := transformxml.AppendProgram(t.Context(), draft, input); err != nil {
		t.Fatal(err)
	}
	if len(draft.Children) != 1 || len(draft.Children[0].Children) != 1 {
		t.Fatalf("unexpected XPath subtree: %+v", draft.Children)
	}
	child := draft.Children[0]
	wantNS := []tree.Namespace{
		{URI: "urn:default"},
		{Prefix: "ds", URI: transformxml.Namespace},
		{Prefix: "p", URI: "urn:item"},
	}
	if !slices.Equal(child.NS, wantNS) || len(child.Attrs) != 0 || child.Children[0].Data != input.XPath[0].Expression {
		t.Fatalf("XPath namespaces = %v, attributes = %v, expression = %q", child.NS, child.Attrs, child.Children[0].Data)
	}
	if want := map[string]string{"p": "urn:item", "": "urn:default", "xml": document.XMLNamespace}; !reflect.DeepEqual(input.XPath[0].Namespaces, want) {
		t.Fatalf("input namespace map changed to %v", input.XPath[0].Namespaces)
	}
}

func TestAppendProgramRejectsInvalidXPathBeforeAppending(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name, algorithm, prefix, filter string
		want                            error
	}{
		{"xpath_reserved_prefix", reference.XPath, "ds", "", reference.ErrPolicy},
		{"filter2_reserved_prefix", reference.XPathFilter2, "xf", "intersect", reference.ErrPolicy},
		{"invalid_filter_operation", reference.XPathFilter2, "p", "replace", reference.ErrInput},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			input := reference.Transform{Algorithm: tc.algorithm, XPath: []reference.XPathExpression{{
				Expression: "//item", Filter: tc.filter, Namespaces: map[string]string{tc.prefix: "urn:item"},
			}}}
			draft := newTransformDraft(tc.algorithm)
			err := transformxml.AppendProgram(t.Context(), draft, input)
			if !errors.Is(err, tc.want) || len(draft.Children) != 0 {
				t.Fatalf("AppendProgram error = %v and appended %d children, want %v and no children", err, len(draft.Children), tc.want)
			}
		})
	}
}

func TestAppendProgramStylesheet(t *testing.T) {
	t.Parallel()
	const source = `<xsl:transform xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:p="urn:item" version="1.0"><xsl:template match="p:item"><result/></xsl:template></xsl:transform>`
	input := reference.Transform{Algorithm: reference.XSLT, Stylesheet: []byte(source)}
	draft := newTransformDraft(input.Algorithm)
	if err := transformxml.AppendProgram(t.Context(), draft, input); err != nil {
		t.Fatal(err)
	}
	if len(draft.Children) != 1 || draft.Children[0].Parent != draft {
		t.Fatal("stylesheet root was not attached to the transform")
	}
	doc := tree.FromNodes([]*tree.Node{draft}, tree.DefaultLimits())
	parsed, err := transformxml.ParseProgram(t.Context(), draft, doc)
	if err != nil {
		t.Fatal(err)
	}
	stylesheet, err := document.Parse(t.Context(), parsed.Stylesheet, document.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	root := stylesheet.Root()
	wantName := document.Name{Space: "http://www.w3.org/1999/XSL/Transform", Local: "transform"}
	if uri, ok := root.Namespace("p"); root.Name() != wantName || !ok || uri != "urn:item" {
		t.Fatalf("stylesheet root = %+v, p = %q (%t)", root.Name(), uri, ok)
	}
	template := root.Children()
	if len(template) != 1 {
		t.Fatalf("stylesheet has %d children, want one template", len(template))
	}
	if value, present := template[0].Attribute(document.Name{Local: "match"}); !present || value != "p:item" {
		t.Fatalf("match = %q (%t), want p:item", value, present)
	}

	t.Run("cancelled_stylesheet_parse", func(t *testing.T) {
		t.Parallel()
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		draft := newTransformDraft(input.Algorithm)
		if err := transformxml.AppendProgram(ctx, draft, input); !errors.Is(err, context.Canceled) || len(draft.Children) != 0 {
			t.Fatalf("cancelled AppendProgram appended %d children and returned %v", len(draft.Children), err)
		}
	})
}
