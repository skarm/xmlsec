package transformxml_test

import (
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/skarm/xmlsec/c14n"
	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/internal/transformxml"
	"github.com/skarm/xmlsec/internal/tree"
	"github.com/skarm/xmlsec/reference"
)

func TestParseCanonicalPrefixLimit(t *testing.T) {
	t.Parallel()
	const maximumPrefixes = 128
	const start = `<ds:CanonicalizationMethod xmlns:ds="http://www.w3.org/2000/09/xmldsig#" Algorithm="` + c14n.Exclusive + `"><ec:InclusiveNamespaces xmlns:ec="` + c14n.Exclusive + `" PrefixList="`
	const end = `"/></ds:CanonicalizationMethod>`
	prefixes := append(strings.Fields(strings.Repeat("p ", maximumPrefixes-1)), "#default")
	for _, tc := range []struct {
		name, prefixList string
		want             error
	}{
		{"exact_limit", strings.Join(prefixes, "&#x9;&#xA;"), nil},
		{"exceeds_limit", strings.Join(prefixes, " ") + " extra", reference.ErrLimit},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			doc, err := document.Parse(t.Context(), []byte(start+tc.prefixList+end), document.DefaultLimits())
			if err != nil {
				t.Fatal(err)
			}
			got, err := transformxml.ParseCanonical(tree.Root(doc), "CanonicalizationMethod")
			if !errors.Is(err, tc.want) {
				t.Fatalf("ParseCanonical error = %v, want %v", err, tc.want)
			}
			if tc.want == nil && (got.Algorithm != c14n.Exclusive || !slices.Equal(got.InclusivePrefixes, prefixes)) {
				t.Fatalf("ParseCanonical returned %q and %d prefixes, want exclusive canonicalization and %d ordered prefixes", got.Algorithm, len(got.InclusivePrefixes), len(prefixes))
			}
		})
	}
}
