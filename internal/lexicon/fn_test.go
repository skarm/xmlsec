package lexicon_test

import (
	"testing"

	"github.com/skarm/xmlsec/internal/lexicon"
)

func TestStreamFnLocalName(t *testing.T) {
	const positionName = "position"

	for _, tc := range []struct {
		name, prefix, want string
		builtin            bool
	}{
		{positionName, "", positionName, true},
		{"last", "fn", "last", true},
		{positionName, "custom", positionName, false},
		{"Q{http://www.w3.org/2005/xpath-functions}position", "", positionName, true},
		{"Q{urn:custom}position", "", positionName, false},
		{"Q{unterminated", "", "Q{unterminated", false},
	} {
		got, builtin := lexicon.StreamFnLocalName(tc.name, tc.prefix)
		if got != tc.want || builtin != tc.builtin {
			t.Errorf("%q/%q = %q,%v; want %q,%v", tc.name, tc.prefix, got, builtin, tc.want, tc.builtin)
		}
	}
}
