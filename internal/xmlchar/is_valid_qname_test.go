package xmlchar_test

import (
	"testing"

	"github.com/skarm/xmlsec/internal/xmlchar"
)

func TestIsValidQName(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name, qname string
		want        bool
	}{
		{"unprefixed", "item", true},
		{"unicode_prefix_and_local", "préfixe:名", true},
		{"empty", "", false},
		{"missing_prefix", ":item", false},
		{"missing_local", "prefix:", false},
		{"more_than_one_colon", "a:b:c", false},
		{"local_starts_with_digit", "a:1b", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := xmlchar.IsValidQName(tc.qname); got != tc.want {
				t.Errorf("IsValidQName(%q) = %t, want %t", tc.qname, got, tc.want)
			}
		})
	}
}
