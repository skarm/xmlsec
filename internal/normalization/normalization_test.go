package normalization_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strconv"
	"strings"
	"testing"

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
