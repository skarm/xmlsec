package normalization_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/skarm/xmlsec/internal/normalization"
)

func TestIsNormalStopsAtCancellation(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	for _, tc := range []struct{ name, value string }{
		{"empty", ""},
		{"already_normal", strings.Repeat("é", 4096)},
		{"needs_composition", "a" + strings.Repeat("\u0301", 4096)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if _, err := normalization.IsNormal(ctx, normalization.NFC, []byte(tc.value)); !errors.Is(err, context.Canceled) {
				t.Fatalf("IsNormal error = %v, want context.Canceled", err)
			}
		})
	}
}
