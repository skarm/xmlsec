package xmlchar_test

import (
	"testing"

	"github.com/skarm/xmlsec/internal/xmlchar"
)

func TestIsValidEncName(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name, label string
		want        bool
	}{
		{"single_ascii_letter", "Z", true},
		{"mixed_case_and_punctuation", "Iso_8859-1.0", true},
		{"empty", "", false},
		{"starts_with_digit", "8bit", false},
		{"space_inside", "utf 8", false},
		{"non_ascii_letter", "café", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := xmlchar.IsValidEncName(tc.label); got != tc.want {
				t.Errorf("IsValidEncName(%q) = %t, want %t", tc.label, got, tc.want)
			}
		})
	}
}
