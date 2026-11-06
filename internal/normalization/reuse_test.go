package normalization_test

import (
	"context"
	"errors"
	"math/rand/v2"
	"strings"
	"testing"

	"github.com/skarm/xmlsec/internal/normalization"
)

func TestNormalizerIndependentRuns(t *testing.T) {
	var normalizer normalization.Normalizer
	random := rand.New(rand.NewPCG(17, 43))
	alphabet := []rune("abé\u0300\u0301\u0315\u034f①ﬁ\u1100\u1161雪😀")
	var retained []string
	var expected strings.Builder
	for i := range 1000 {
		var input strings.Builder
		for range random.IntN(80) {
			input.WriteRune(alphabet[random.IntN(len(alphabet))])
		}
		if i%10 == 0 {
			input.WriteString(strings.Repeat("\u0301", 4096))
		}
		form := []normalization.Form{normalization.NFC, normalization.NFD, normalization.NFKC, normalization.NFKD}[i%4]
		source := input.String()
		want, err := normalization.String(t.Context(), form, source)
		if err != nil {
			t.Fatal(err)
		}
		var actual strings.Builder
		if err := normalizer.Each(t.Context(), form, source, func(part string) error {
			retained = append(retained, part)
			actual.WriteString(part)
			return nil
		}); err != nil || actual.String() != want {
			t.Fatalf("normalization differs for form %d: %v", form, err)
		}
		expected.WriteString(want)
	}
	if strings.Join(retained, "") != expected.String() {
		t.Fatal("later normalization overwrote an emitted string")
	}
}

func TestNormalizerErrors(t *testing.T) {
	var normalizer normalization.Normalizer
	failure := errors.New("sink failure")
	calls := 0
	if err := normalizer.Each(t.Context(), normalization.NFC, strings.Repeat("e\u0301", 4096), func(string) error {
		calls++
		return failure
	}); !errors.Is(err, failure) || calls != 1 {
		t.Fatal("emitter failure was not terminal", err, calls)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := normalizer.Each(ctx, normalization.NFC, "text", func(string) error {
		t.Fatal("canceled normalization emitted text")
		return nil
	}); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}
