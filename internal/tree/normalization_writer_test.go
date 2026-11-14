package tree_test

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

	"github.com/skarm/xmlsec/internal/normalization"
)

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
	for _, form := range []normalization.Form{normalization.NFC, normalization.NFD, normalization.NFKC, normalization.NFKD} {
		input := "a" + strings.Repeat("\u0315", 4100) + "\u0300\u034f\u0300\u1100\u1161\u11a8\ufb03"

		want := form.String(input)
		if strings.Count(want, "\u034f") != 1 {
			t.Fatal("inserted or removed CGJ")
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
