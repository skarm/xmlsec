package transformxml_test

import (
	"errors"
	"slices"
	"testing"

	"github.com/skarm/xmlsec/c14n"
	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/internal/transformxml"
	"github.com/skarm/xmlsec/internal/tree"
	"github.com/skarm/xmlsec/reference"
)

func newTransformDraft(algorithm string) *tree.Node {
	return &tree.Node{
		Kind: tree.ElementNode, Name: document.Name{Space: transformxml.Namespace, Local: "Transform"},
		Prefix: "ds", NS: []tree.Namespace{{Prefix: "ds", URI: transformxml.Namespace}},
		Attrs: []tree.Attribute{{Name: document.Name{Local: "Algorithm"}, Value: algorithm}},
	}
}

func TestAppendParametersCanonicalPrefixes(t *testing.T) {
	t.Parallel()
	for _, algorithm := range []string{c14n.Exclusive, c14n.ExclusiveWithComments} {
		t.Run(algorithm, func(t *testing.T) {
			t.Parallel()
			input := reference.Transform{Algorithm: algorithm, InclusivePrefixes: []string{"z", "#default", "a"}}
			draft := newTransformDraft(algorithm)
			if err := transformxml.AppendParameters(t.Context(), draft, input); err != nil {
				t.Fatal(err)
			}
			if len(draft.Children) != 1 {
				t.Fatalf("number of parameters = %d, want 1", len(draft.Children))
			}
			child := draft.Children[0]
			wantName := document.Name{Space: c14n.Exclusive, Local: "InclusiveNamespaces"}
			wantAttrs := []tree.Attribute{{Name: document.Name{Local: "PrefixList"}, Value: "z #default a"}}
			if child.Name != wantName || child.Parent != draft || !slices.Equal(child.Attrs, wantAttrs) {
				t.Fatalf("parameter name = %+v, parent ownership = %t, attributes = %+v", child.Name, child.Parent == draft, child.Attrs)
			}
			roundTrip, err := transformxml.ParseCanonical(draft, "Transform")
			if err != nil || roundTrip.Algorithm != algorithm || !slices.Equal(roundTrip.InclusivePrefixes, input.InclusivePrefixes) {
				t.Fatalf("ParseCanonical = %+v, %v, want algorithm %q and prefixes %v", roundTrip, err, algorithm, input.InclusivePrefixes)
			}
		})
	}
}

func TestAppendParametersValidatesAlgorithmContract(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name  string
		input reference.Transform
		want  error
	}{
		{"inclusive_canonicalization_without_parameters", reference.Transform{Algorithm: c14n.Canonical11}, nil},
		{"base64_without_parameters", reference.Transform{Algorithm: reference.Base64}, nil},
		{"enveloped_without_parameters", reference.Transform{Algorithm: reference.EnvelopedSignature}, nil},
		{"unsupported_algorithm", reference.Transform{Algorithm: "urn:example:unknown"}, reference.ErrUnsupported},
		{"inclusive_canonicalization_cannot_declare_prefixes", reference.Transform{Algorithm: c14n.Canonical11, InclusivePrefixes: []string{"p"}}, reference.ErrInput},
		{"forbidden_inclusive_prefix", reference.Transform{Algorithm: c14n.Exclusive, InclusivePrefixes: []string{"xmlns"}}, reference.ErrInput},
		{"base64_cannot_carry_xpath", reference.Transform{Algorithm: reference.Base64, XPath: []reference.XPathExpression{{Expression: "true()"}}}, reference.ErrInput},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			draft := newTransformDraft(tc.input.Algorithm)
			err := transformxml.AppendParameters(t.Context(), draft, tc.input)
			if !errors.Is(err, tc.want) {
				t.Fatalf("AppendParameters(%+v) error = %v, want %v", tc.input, err, tc.want)
			}
			if tc.want == nil && len(draft.Children) != 0 {
				t.Fatalf("parameterless algorithm unexpectedly appended %d children", len(draft.Children))
			}
		})
	}
}
