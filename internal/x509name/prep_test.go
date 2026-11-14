package x509name //nolint:testpackage // Checks internal Unicode preparation before key assembly.

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestNormalize32UsesUnicode32CanonicalMappings(t *testing.T) {
	t.Parallel()

	// Unicode Corrigendum #4 lists these original Unicode 3.2 mappings.
	// https://www.unicode.org/versions/corrigendum4.html
	const input = "\U0002f868\U0002f874\U0002f91f\U0002f95f\U0002f9bf"
	const want = "\U0002136a\u5f33\u43ab\u7aae\u4d57"
	if got, err := normalize32(t.Context(), input); err != nil || got != want {
		t.Fatalf("normalize32(%+q) = (%+q, %v), want (%+q, nil)", input, got, err, want)
	}
}

func TestPrepareObservesCancellationForShortValue(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if got, err := prepare(ctx, "Alice"); got != "" || !errors.Is(err, context.Canceled) {
		t.Fatalf("prepare with canceled context = (%q, %v), want (empty, %v)", got, err, context.Canceled)
	}
}

func TestPrepareEnforcesByteBudgetAfterExpansion(t *testing.T) {
	t.Parallel()

	const keyLimit = 1 << 20
	for _, tc := range []struct {
		name, unit string
		repeat     int
	}{
		// U+FDFA is a three-byte Arabic compatibility ligature. Its NFKC
		// decomposition, including spaces, takes 33 bytes.
		{name: "compatibility_decomposition", unit: "\ufdfa", repeat: keyLimit/33 + 1},
		{name: "space_preparation", unit: "a ", repeat: keyLimit / 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			input := strings.Repeat(tc.unit, tc.repeat)
			if got, err := prepare(t.Context(), input); got != "" || !errors.Is(err, ErrLimit) {
				t.Fatalf("prepare with %d input bytes = (%d output bytes, %v), want (0, %v)", len(input), len(got), err, ErrLimit)
			}
		})
	}
}
