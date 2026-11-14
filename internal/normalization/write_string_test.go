package normalization_test

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/skarm/xmlsec/internal/normalization"
)

func TestWriteStringCombinesAcrossUTF8AndInputBoundaries(t *testing.T) {
	t.Parallel()
	const chunkSize = 4096
	prefix := strings.Repeat("x", chunkSize-1)
	var output bytes.Buffer
	writer := normalization.NewWriter(t.Context(), &output, normalization.NFC)

	for _, piece := range []string{prefix + "é" + "a", "\u0315", "\u0300", "雪"} {
		if n, err := writer.WriteString(piece); err != nil || n != len(piece) {
			t.Fatalf("WriteString(%d bytes) = %d, %v", len(piece), n, err)
		}
	}
	want := prefix + "éà\u0315雪"
	if err := writer.Close(); err != nil || output.String() != want {
		t.Fatalf("Close error = %v, output length = %d, complete normalized output matches = %t", err, output.Len(), output.String() == want)
	}
}

func TestWriteStringPreservesFailureAfterNonASCIIFlush(t *testing.T) {
	t.Parallel()
	const chunkSize = 4096
	failure := errors.New("sink rejected normalized bytes")
	sink := &failingWriter{err: failure}
	writer := normalization.NewWriter(t.Context(), sink, normalization.NFC)
	prefix := strings.Repeat("a", chunkSize)
	if n, err := writer.WriteString(prefix); err != nil || n != len(prefix) || sink.calls != 0 {
		t.Fatalf("WriteString(prefix) = %d, %v with %d sink calls", n, err, sink.calls)
	}
	if n, err := writer.WriteString("é and trailing text"); !errors.Is(err, failure) || n > len("é") || sink.calls != 1 {
		t.Fatalf("WriteString after flush = %d, %v with %d sink calls", n, err, sink.calls)
	}
	if n, err := writer.WriteString("again"); n != 0 || !errors.Is(err, failure) {
		t.Fatalf("WriteString after failure = %d, %v, want zero and sink error", n, err)
	}
	if err := writer.Close(); !errors.Is(err, failure) || sink.calls != 1 {
		t.Fatalf("Close = %v with %d sink calls, want one call and sink error", err, sink.calls)
	}
}
