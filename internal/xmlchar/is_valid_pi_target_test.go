package xmlchar_test

import (
	"testing"

	"github.com/skarm/xmlsec/internal/xmlchar"
)

func TestIsValidPITarget(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name, target string
		want         bool
	}{
		{"ordinary", "xml-stylesheet", true},
		{"non_ascii_name", "étiquette", true},
		{"encoded_replacement_character", "\ufffd", true},
		{"reserved_in_any_case", "xMl", false},
		{"empty", "", false},
		{"colon_is_disallowed", "p:target", false},
		{"invalid_encoding", "\xff", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := xmlchar.IsValidPITarget(tc.target); got != tc.want {
				t.Errorf("IsValidPITarget(%q) = %t, want %t", tc.target, got, tc.want)
			}
		})
	}
}
