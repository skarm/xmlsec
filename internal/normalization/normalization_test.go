package normalization_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"strconv"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/skarm/xmlsec/internal/normalization"
)

func TestExactNormalization(t *testing.T) {
	for _, tc := range []struct {
		name   string
		form   normalization.Form
		source string
		want   string
	}{
		{"compose", normalization.NFC, "e\u0301", "é"},
		{"decompose", normalization.NFD, "é", "e\u0301"},
		{"compatibility compose", normalization.NFKC, "① ﬁ", "1 fi"},
		{"compatibility decompose", normalization.NFKD, "① é", "1 e\u0301"},
		{"Hangul", normalization.NFC, "\u1100\u1161", "가"},
		{"canonical order", normalization.NFC, "a\u0315\u0300", "à\u0315"},
		{"long nonstarter run", normalization.NFC, "a" + strings.Repeat("\u0301", 4096), "á" + strings.Repeat("\u0301", 4095)},
		{"existing joiner", normalization.NFC, "a\u034f" + strings.Repeat("\u0301", 65), "a\u034f" + strings.Repeat("\u0301", 65)},
		{"ASCII boundary", normalization.NFC, strings.Repeat("x", 4095) + "e\u0301", strings.Repeat("x", 4095) + "é"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := normalization.String(t.Context(), tc.form, tc.source)
			if err != nil || got != tc.want || tc.form.String(tc.source) != tc.want {
				t.Fatalf("normalized value differs: bytes=%d, want=%d, err=%v", len(got), len(tc.want), err)
			}

			input := []byte(tc.source)
			if got := tc.form.Bytes(input); string(got) != tc.want || string(input) != tc.source {
				t.Fatal("byte normalization changed its input or produced different output")
			}

			if normal, err := normalization.IsNormal(t.Context(), tc.form, []byte(tc.want)); err != nil || !normal {
				t.Fatal("normalized result was not recognized:", normal, err)
			}

			if normal, err := normalization.IsNormal(t.Context(), tc.form, input); err != nil || normal != (tc.source == tc.want) {
				t.Fatal("input normalization status:", normal, err)
			}

			var text strings.Builder
			if err := tc.form.Each(t.Context(), tc.source, func(part string) error {
				text.WriteString(part)
				return nil
			}); err != nil || text.String() != tc.want {
				t.Fatal("string segments differ:", err)
			}

			var octets bytes.Buffer
			if err := tc.form.EachBytes(t.Context(), tc.source, func(part []byte) error {
				_, _ = octets.Write(part)
				return nil
			}); err != nil || octets.String() != tc.want {
				t.Fatal("byte segments differ:", err)
			}

			for _, chunk := range []int{1, 2, 7, 4095, 4096} {
				t.Run(strconv.Itoa(chunk), func(t *testing.T) {
					var output bytes.Buffer
					writer := normalization.NewWriter(t.Context(), &output, tc.form)
					for offset := 0; offset < len(input); offset += chunk {
						part := input[offset:min(len(input), offset+chunk)]
						if n, err := writer.Write(part); err != nil || n != len(part) {
							t.Fatalf("Write = %d, %v", n, err)
						}
					}

					if err := writer.Close(); err != nil || output.String() != tc.want {
						t.Fatalf("chunked result differs: bytes=%d, want=%d, err=%v", output.Len(), len(tc.want), err)
					}
				})
			}
		})
	}
}

func TestNormalizationErrors(t *testing.T) {
	t.Parallel()

	failure := errors.New("sink failure")
	for _, short := range []bool{false, true} {
		sink := &failingWriter{err: failure}
		want := failure
		if short {
			sink.err, want = nil, io.ErrShortWrite
		}

		writer := normalization.NewWriter(t.Context(), sink, normalization.NFC)
		if n, err := writer.WriteString("e\u0301"); err != nil || n != 3 {
			t.Fatal("pending segment:", n, err)
		}

		if sink.calls != 0 {
			t.Fatal("last normalization segment flushed before Close")
		}

		if err := writer.Close(); !errors.Is(err, want) {
			t.Fatal("close lost sink failure:", err)
		}

		if n, err := writer.Write([]byte("again")); n != 0 || !errors.Is(err, want) || sink.calls != 1 {
			t.Fatal("writer retried after terminal failure:", n, err, sink.calls)
		}
	}

	for _, source := range []string{"\xff", "e\xcc"} {
		writer := normalization.NewWriter(t.Context(), io.Discard, normalization.NFC)
		_, writeErr := writer.Write([]byte(source))
		if err := errors.Join(writeErr, writer.Close()); !errors.Is(err, io.ErrUnexpectedEOF) {
			t.Fatalf("invalid/incomplete UTF-8 %x: %v", source, err)
		}
	}

	t.Run("incomplete_close_is_terminal", func(t *testing.T) {
		t.Parallel()

		var output bytes.Buffer
		writer := normalization.NewWriter(t.Context(), &output, normalization.NFC)
		if _, err := writer.WriteString("e\xcc"); err != nil {
			t.Fatal(err)
		}

		if err := writer.Close(); !errors.Is(err, io.ErrUnexpectedEOF) {
			t.Fatalf("Close = %v; want io.ErrUnexpectedEOF", err)
		}

		if n, err := writer.WriteString("\x81"); n != 0 || !errors.Is(err, io.ErrUnexpectedEOF) {
			t.Fatalf("WriteString after failed Close = (%d, %v)", n, err)
		}

		if err := writer.Close(); !errors.Is(err, io.ErrUnexpectedEOF) || output.Len() != 0 {
			t.Fatalf("repeated Close = %v; output = %q", err, output.String())
		}
	})

	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := normalization.String(ctx, normalization.NFC, "text"); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled normalization:", err)
	}

	writer := normalization.NewWriter(ctx, io.Discard, normalization.NFC)
	if n, err := writer.Write([]byte("text")); n != 0 || !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled writer:", n, err)
	}

	calls := 0
	if err := normalization.NFC.Each(t.Context(), strings.Repeat("x", 10000), func(string) error {
		calls++
		return failure
	}); !errors.Is(err, failure) || calls != 1 {
		t.Fatal("callback failure did not stop iteration:", err, calls)
	}

	calls = 0
	if err := normalization.NFC.EachBytes(t.Context(), strings.Repeat("x", 10000), func([]byte) error {
		calls++
		return failure
	}); !errors.Is(err, failure) || calls != 1 {
		t.Fatal("byte callback failure did not stop iteration:", err, calls)
	}
}

type failingWriter struct {
	err   error
	calls int
}

func TestPendingFlushDoesNotConsumeNextByte(t *testing.T) {
	const prefixBytes = 4096
	prefix := strings.Repeat("a", prefixBytes)
	failure := errors.New("destination rejected pending output")

	for _, short := range []bool{false, true} {
		t.Run(strconv.FormatBool(short), func(t *testing.T) {
			sink := &failingWriter{err: failure}
			want := failure
			if short {
				sink.err, want = nil, io.ErrShortWrite
			}

			writer := normalization.NewWriter(t.Context(), sink, normalization.NFC)
			if n, err := writer.Write([]byte(prefix)); n != prefixBytes || err != nil || sink.calls != 0 {
				t.Fatalf("pending input: n=%d error=%v calls=%d", n, err, sink.calls)
			}

			if n, err := writer.Write([]byte("b")); n != 0 || !errors.Is(err, want) || sink.calls != 1 {
				t.Fatalf("unaccepted byte counted: n=%d error=%v calls=%d", n, err, sink.calls)
			}

			if n, err := writer.Write([]byte("c")); n != 0 || !errors.Is(err, want) || sink.calls != 1 {
				t.Fatalf("failure was not terminal: n=%d error=%v calls=%d", n, err, sink.calls)
			}
			if err := writer.Close(); !errors.Is(err, want) || sink.calls != 1 {
				t.Fatal("close retried failed output", err, sink.calls)
			}
		})
	}

	t.Run("successful flush", func(t *testing.T) {
		var output bytes.Buffer
		writer := normalization.NewWriter(t.Context(), &output, normalization.NFC)
		if n, err := writer.Write([]byte(prefix)); n != prefixBytes || err != nil {
			t.Fatal(n, err)
		}
		if n, err := writer.Write([]byte("b")); n != 1 || err != nil {
			t.Fatal(n, err)
		}
		if err := writer.Close(); err != nil || output.String() != prefix+"b" {
			t.Fatal("successful flush lost current input", err, output.Len())
		}
	})
}

func (w *failingWriter) Write([]byte) (int, error) {
	w.calls++
	return 0, w.err
}

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

func TestEachBytesStopsOnFailureInOneCombiningRun(t *testing.T) {
	t.Parallel()

	failure := errors.New("consumer stopped")
	for _, tc := range []struct {
		name  string
		marks int
	}{
		{"short_batch", 40},
		{"long_segment", 2300},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			source := "a" + strings.Repeat("\u0301", tc.marks)
			want := "á" + strings.Repeat("\u0301", tc.marks-1)
			var emitted bytes.Buffer
			err := normalization.NFC.EachBytes(t.Context(), source, func(part []byte) error {
				emitted.Write(part)
				return failure
			})
			if !errors.Is(err, failure) || emitted.String() != want {
				t.Errorf("EachBytes emitted %d bytes, exact segment = %t, error = %v, want %v", emitted.Len(), emitted.String() == want, err, failure)
			}
		})
	}
}

func TestEachBytesReportsCancellationOnLastEmission(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	var emitted bytes.Buffer
	err := normalization.NFC.EachBytes(ctx, "e\u0301", func(part []byte) error {
		emitted.Write(part)
		cancel()
		return nil
	})
	if !errors.Is(err, context.Canceled) || emitted.String() != "é" {
		t.Errorf("EachBytes emitted %q, error = %v, want %q and %v", emitted.String(), err, "é", context.Canceled)
	}
}

func TestEachBytesReportsCancellationBetweenEmissions(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	calls := 0
	err := normalization.NFC.EachBytes(ctx, "one sentence", func([]byte) error {
		calls++
		cancel()
		return nil
	})
	if !errors.Is(err, context.Canceled) || calls != 1 {
		t.Fatalf("EachBytes invoked the consumer %d times, error = %v; want one call and %v", calls, err, context.Canceled)
	}
}

func TestNormalizationPreservesMarkOrderWithinEachStarter(t *testing.T) {
	t.Parallel()

	const runs = 35
	input := "é" + strings.Repeat("\u0315\u0301\u0300", runs) + "o\u0315\u0300\u0301"
	want := "e\u0301" + strings.Repeat("\u0301\u0300", runs) + strings.Repeat("\u0315", runs) + "o\u0300\u0301\u0315"
	got, err := normalization.String(t.Context(), normalization.NFD, input)
	if err != nil || got != want {
		t.Fatalf("NFD normalized %q to %q, want %q; error = %v", input, got, want, err)
	}
	assertByteNormalization(t, normalization.NFD, input, want)
	assertNormalizationWriter(t, normalization.NFD, input, want)
}

func TestWriterCloseDiscardsPendingTextOnCancellation(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	var output bytes.Buffer
	writer := normalization.NewWriter(ctx, &output, normalization.NFC)
	const input = "e\u0301"
	if n, err := writer.WriteString(input); n != len(input) || err != nil {
		t.Fatalf("WriteString(%q) = (%d, %v), want (%d, nil)", input, n, err, len(input))
	}
	cancel()
	if err := writer.Close(); !errors.Is(err, context.Canceled) || output.Len() != 0 {
		t.Errorf("Close = %v with output %q, want %v and no output", err, output.String(), context.Canceled)
	}
}

func TestWriterCloseReportsCancellationDuringFinalWrite(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	writer := normalization.NewWriter(ctx, normalizationCancelWriter{cancel}, normalization.NFC)
	if _, err := writer.WriteString("e\u0301"); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); !errors.Is(err, context.Canceled) {
		t.Fatalf("final write canceled context, Close returned %v", err)
	}
}

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
	if n, err := writer.WriteString("é and trailing text"); !errors.Is(err, failure) || n != 0 || sink.calls != 1 {
		t.Fatalf("WriteString after flush = %d, %v with %d sink calls", n, err, sink.calls)
	}
	if n, err := writer.WriteString("again"); n != 0 || !errors.Is(err, failure) {
		t.Fatalf("WriteString after failure = %d, %v, want zero and sink error", n, err)
	}
	if err := writer.Close(); !errors.Is(err, failure) || sink.calls != 1 {
		t.Fatalf("Close = %v with %d sink calls, want one call and sink error", err, sink.calls)
	}
}

// TestUnicodeNormalizationConformance exercises all five columns and all four
// forms of Unicode 17's official NormalizationTest, including the fallback for
// a long combining sequence in the same normalization block.
func TestUnicodeNormalizationConformance(t *testing.T) {
	data, err := os.ReadFile("../../tests/testdata/unicode/NormalizationTest-17.0.0.txt")
	if err != nil {
		t.Fatal(err)
	}

	// Pin the complete official Unicode 17 corpus, not only a minimum row count.
	const expectedSHA256 = "5019ffd530751a741900c849c0e010332f142a3612234639bd200b82138a87db"
	if digest := sha256.Sum256(data); hex.EncodeToString(digest[:]) != expectedSHA256 {
		t.Fatalf("Unicode 17 normalization corpus SHA-256 mismatch: %x", digest)
	}

	prefix := "q" + strings.Repeat("\u0315", 31) + "\u0300\u034f"
	normalizedPrefix := "q\u0300" + strings.Repeat("\u0315", 31) + "\u034f"
	count := 0

	for lineNo, line := range strings.Split(string(data), "\n") {
		line, _, _ = strings.Cut(line, "#")
		if line == "" || strings.HasPrefix(line, "@") {
			continue
		}

		columns := strings.Split(line, ";")
		if len(columns) < 5 {
			t.Fatalf("line %d: invalid fixture", lineNo+1)
		}

		values := make([]string, 5)
		for i := range values {
			var value strings.Builder

			for encoded := range strings.FieldsSeq(columns[i]) {
				r, err := strconv.ParseInt(encoded, 16, 32)
				if err != nil {
					t.Fatal(err)
				}

				value.WriteRune(rune(r))
			}

			values[i] = value.String()
		}

		for _, tc := range []struct {
			form     normalization.Form
			expected []int
		}{
			{normalization.NFC, []int{1, 1, 1, 3, 3}},
			{normalization.NFD, []int{2, 2, 2, 4, 4}},
			{normalization.NFKC, []int{3, 3, 3, 3, 3}},
			{normalization.NFKD, []int{4, 4, 4, 4, 4}},
		} {
			for column, input := range values {
				want := values[tc.expected[column]]
				if got := tc.form.String(input); got != want {
					t.Fatalf("line %d form %d column %d: %U != %U", lineNo+1, tc.form, column+1, []rune(got), []rune(want))
				}

				assertByteNormalization(t, tc.form, input, want)
				assertNormalizationWriter(t, tc.form, input, want)
			}

			if got := tc.form.String(prefix + values[0]); got != normalizedPrefix+values[tc.expected[0]] {
				t.Fatalf("long run, line %d form %d: %U", lineNo+1, tc.form, []rune(got))
			}
		}

		count++
	}

	if count < 19000 {
		t.Fatal("incomplete official corpus", count)
	}

	t.Logf("checked %d official normalization rows", count)
}

func assertNormalizationWriter(t *testing.T, form normalization.Form, input, want string) {
	t.Helper()

	var output bytes.Buffer

	writer := normalization.NewWriter(t.Context(), &output, form)
	if _, err := io.WriteString(writer, input); err != nil {
		t.Fatal(err)
	}

	if err := writer.Close(); err != nil || output.String() != want {
		t.Fatalf("writer form %d: %U != %U, %v", form, []rune(output.String()), []rune(want), err)
	}
}

func TestExactNormalizationWriter(t *testing.T) {
	marks := strings.Repeat("\u0315", 4100)
	input := "a" + marks + "\u0300\u034f\u0300\u1100\u1161\u11a8\ufb03"

	for _, tc := range []struct {
		form normalization.Form
		want string
	}{
		{normalization.NFC, "à" + marks + "\u034f\u0300각\ufb03"},
		{normalization.NFD, "a\u0300" + marks + "\u034f\u0300\u1100\u1161\u11a8\ufb03"},
		{normalization.NFKC, "à" + marks + "\u034f\u0300각ffi"},
		{normalization.NFKD, "a\u0300" + marks + "\u034f\u0300\u1100\u1161\u11a8ffi"},
	} {
		form, want := tc.form, tc.want
		if got := form.String(input); got != want {
			t.Fatalf("string normalization form %d differs from the expected Unicode sequence", form)
		}
		assertByteNormalization(t, form, input, want)

		var borrowed bytes.Buffer
		if err := form.EachBytes(t.Context(), input, func(part []byte) error { _, err := borrowed.Write(part); return err }); err != nil || borrowed.String() != want {
			t.Fatal("borrowed normalization segments", err)
		}

		var output bytes.Buffer

		writer := normalization.NewWriter(t.Context(), &output, form)
		for i := 0; i < len(input); i++ {
			if _, err := writer.Write([]byte{input[i]}); err != nil {
				t.Fatal(err)
			}
		}

		if err := writer.Close(); err != nil {
			t.Fatal(err)
		}

		if output.String() != want {
			t.Fatal("normalization changed across byte boundaries")
		}

		output.Reset()

		writer = normalization.NewWriter(t.Context(), &output, form)
		if _, err := io.WriteString(writer, input); err != nil {
			t.Fatal(err)
		}

		if err := writer.Close(); err != nil || output.String() != want {
			t.Fatal("string writer changed long normalization segments", err)
		}

		normal, err := normalization.IsNormal(t.Context(), form, []byte(want))
		if err != nil || !normal {
			t.Fatal("exact normalization check", err)
		}
	}

	ctx, cancel := context.WithCancel(t.Context())

	writer := normalization.NewWriter(ctx, io.Discard, normalization.NFC)
	if _, err := writer.Write([]byte("a")); err != nil {
		t.Fatal(err)
	}

	cancel()

	if err := writer.Close(); !errors.Is(err, context.Canceled) {
		t.Fatal("close ignored cancellation", err)
	}

	if _, err := normalization.IsNormal(ctx, normalization.NFC, []byte("é")); !errors.Is(err, context.Canceled) {
		t.Fatal("normalization check ignored cancellation", err)
	}

	writer = normalization.NewWriter(t.Context(), normalizationFailWriter{}, normalization.NFC)
	if _, err := writer.Write([]byte("abc")); err != nil {
		t.Fatal(err)
	}

	if err := writer.Close(); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatal("close lost write error", err)
	}

	writer = normalization.NewWriter(t.Context(), io.Discard, normalization.NFC)
	if _, err := writer.Write([]byte{0xe2}); err != nil {
		t.Fatal(err)
	}

	if err := writer.Close(); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatal("incomplete UTF-8 accepted", err)
	}
}

func TestByteNormalizationBoundaries(t *testing.T) {
	for _, form := range []normalization.Form{normalization.NFC, normalization.NFD, normalization.NFKC, normalization.NFKD} {
		for _, input := range []string{"", "\xff", "e\u0301\xff", "a" + strings.Repeat("\u0315", 4100) + "\xe2\x82", strings.Repeat("é", 2100) + "e\u0301"} {
			assertByteNormalization(t, form, input, form.String(input))
		}
	}
}

func BenchmarkExactNormalizationWriter(b *testing.B) {
	for _, tc := range []struct {
		name string
		unit string
	}{{"ASCII", "hello world "}, {"Unicode", "café e\u0301 日本語 "}, {"Combining", "a" + strings.Repeat("\u0315", 64) + "\u0300"}} {
		for _, size := range []int{64, 1 << 20} {
			input := []byte(strings.Repeat(tc.unit, max(1, size/len(tc.unit))))
			b.Run(tc.name+"/"+strconv.Itoa(size), func(b *testing.B) {
				b.ReportAllocs()
				b.SetBytes(int64(len(input)))
				for b.Loop() {
					w := normalization.NewWriter(b.Context(), io.Discard, normalization.NFC)
					if _, err := w.Write(input); err != nil {
						b.Fatal(err)
					}
					if err := w.Close(); err != nil {
						b.Fatal(err)
					}
				}
			})
		}
	}
}

func TestNormalizationASCIIBatchBoundary(t *testing.T) {
	for _, form := range []normalization.Form{normalization.NFC, normalization.NFD, normalization.NFKC, normalization.NFKD} {
		for _, size := range []int{4095, 4096, 4097, 8191, 8192, 8193} {
			input := strings.Repeat("a", size-1) + "e\u0301\u0323" + strings.Repeat("x", 4100) + "\u0301"
			want := form.String(input)
			for _, split := range []int{size - 1, size, size + 1, size + 2} {
				var got bytes.Buffer
				w := normalization.NewWriter(t.Context(), &got, form)
				for _, part := range []string{input[:split], input[split:]} {
					if _, err := w.Write([]byte(part)); err != nil {
						t.Fatal(err)
					}
				}
				if err := w.Close(); err != nil || got.String() != want {
					t.Fatalf("form %d size %d split %d: changed normalization, %v", form, size, split, err)
				}
			}
		}
	}
}

func TestNormalizationASCIICancellationInterval(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	w := normalization.NewWriter(ctx, normalizationCancelWriter{cancel}, normalization.NFC)
	if _, err := w.Write(bytes.Repeat([]byte{'a'}, 100)); err != nil {
		t.Fatal(err)
	}
	// The first new batch fills an existing buffer after 3996 bytes. Cancellation
	// during its flush must be observed at the original 4096-byte polling boundary.
	n, err := w.Write(bytes.Repeat([]byte{'b'}, 8192))
	if n != 4096 || !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation after %d bytes: %v", n, err)
	}
	if err := w.Close(); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

func assertByteNormalization(t *testing.T, form normalization.Form, input, want string) {
	t.Helper()

	source := []byte(input)

	got := form.Bytes(source)
	if string(got) != want || string(source) != input {
		t.Fatalf("byte normalization form %d: got %U, source %U; want %U", form, []rune(string(got)), []rune(string(source)), []rune(want))
	}

	if input == want && len(source) != 0 && &got[0] != &source[0] {
		t.Fatal("already normalized bytes were copied")
	}
}

type normalizationFailWriter struct{}

func (normalizationFailWriter) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }

type normalizationCancelWriter struct{ cancel context.CancelFunc }

func (w normalizationCancelWriter) Write(p []byte) (int, error) { w.cancel(); return len(p), nil }
