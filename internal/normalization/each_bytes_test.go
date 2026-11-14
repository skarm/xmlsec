package normalization_test

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/skarm/xmlsec/internal/normalization"
)

func TestEachBytesStopsAfterCancellationAtSegmentBoundary(t *testing.T) {
	t.Parallel()
	const fragmentBytes = 4096
	const marks = 2300
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	source := "a" + strings.Repeat("\u0301", marks) + strings.Repeat("b", fragmentBytes+1)
	want := "á" + strings.Repeat("\u0301", marks-1)
	var emitted bytes.Buffer
	calls := 0
	err := normalization.NFC.EachBytes(ctx, source, func(part []byte) error {
		if !utf8.Valid(part) {
			t.Error("EachBytes split a UTF-8 scalar")
		}
		emitted.Write(part)
		calls++
		cancel()
		return nil
	})
	if !errors.Is(err, context.Canceled) || calls != 1 || emitted.String() != want {
		t.Fatalf("EachBytes emitted %d bytes in %d calls, exact first segment = %t, error = %v", emitted.Len(), calls, emitted.String() == want, err)
	}
}
