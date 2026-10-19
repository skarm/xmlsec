package streamio_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/skarm/xmlsec/internal/streamio"
)

type writeOnly struct{ io.Writer }

func TestWriteStringGrowingChunks(t *testing.T) {
	var target bytes.Buffer

	w := streamio.Writer{Context: t.Context(), Target: writeOnly{&target}, Limit: 1 << 20, LimitError: io.ErrShortWrite}

	var expected strings.Builder

	for i, size := range []int{1, 511, 512, 513, 1025, 32767, 32768, 32769, 65537} {
		chunk := strings.Repeat(string(rune('a'+i)), size)

		n, err := w.WriteString(chunk)
		if err != nil || n != len(chunk) {
			t.Fatalf("chunk %d: %d, %v", size, n, err)
		}

		expected.WriteString(chunk)
	}

	if target.String() != expected.String() || w.Written != int64(expected.Len()) {
		t.Fatal("growing string buffer changed output or byte count")
	}
}

func TestWriterStringBudget(t *testing.T) {
	var sink stringSink

	w := streamio.Writer{Target: &sink, Context: t.Context(), Limit: 3, LimitError: io.ErrShortBuffer}
	if n, err := io.WriteString(&w, "é"); n != 2 || err != nil || 3-int(w.Written) != 1 || sink.stringWrites != 1 {
		t.Fatal(n, err, 3-int(w.Written))
	}

	if n, err := io.WriteString(&w, "é"); n != 0 || !errors.Is(err, io.ErrShortBuffer) || sink.String() != "é" || 3-int(w.Written) != 1 {
		t.Fatal("limit changed destination", n, err)
	}

	if n, err := w.Write([]byte{'!'}); n != 1 || err != nil || 3-int(w.Written) != 0 {
		t.Fatal(n, err)
	}
}

func TestWriterCounts(t *testing.T) {
	failure := errors.New("destination failed")
	for _, tc := range []struct {
		n                    int
		writerErr, errorWant error
		countWant, remaining int
	}{
		{-1, nil, io.ErrShortWrite, 0, 3},
		{4, nil, io.ErrShortWrite, 0, 3},
		{1, nil, io.ErrShortWrite, 1, 2},
		{1, failure, failure, 1, 2},
		{3, nil, nil, 3, 0},
	} {
		for _, stringMode := range []bool{false, true} {
			w := streamio.Writer{Target: countWriter{tc.n, tc.writerErr}, Context: t.Context(), Limit: 3, LimitError: io.ErrShortBuffer}

			var (
				n   int
				err error
			)
			if stringMode {
				n, err = w.WriteString("abc")
			} else {
				n, err = w.Write([]byte("abc"))
			}

			if n != tc.countWant || !errors.Is(err, tc.errorWant) || 3-int(w.Written) != tc.remaining {
				t.Fatalf("count=%d error=%v remaining=%d", n, err, 3-int(w.Written))
			}
		}
	}
}

func TestXMLWhitespaceReader(t *testing.T) {
	for _, size := range []int{1, 3, 4096, 8192} {
		text := strings.Repeat(" \t\r\nA\vB\u00a0", 1024)
		source := &streamio.XMLWhitespaceReader{Source: strings.NewReader(text)}

		var output bytes.Buffer
		if _, err := io.CopyBuffer(&output, struct{ io.Reader }{source}, make([]byte, size)); err != nil || output.String() != strings.Repeat("A\vB\u00a0", 1024) {
			t.Fatal("non-XML whitespace removed or output changed", size, err)
		}
	}

	for _, count := range []int{-1, 10000} {
		source := &streamio.XMLWhitespaceReader{Source: inputFunc(func([]byte) (int, error) { return count, nil })}
		if _, err := io.ReadAll(source); !errors.Is(err, io.ErrShortBuffer) {
			t.Fatal("invalid source count", count, err)
		}
	}

	source := &streamio.XMLWhitespaceReader{Source: inputFunc(func([]byte) (int, error) { return 0, nil })}
	if _, err := io.ReadAll(source); !errors.Is(err, io.ErrNoProgress) {
		t.Fatal("non-progressing source", err)
	}

	failure := errors.New("source failed")

	source = &streamio.XMLWhitespaceReader{Source: inputFunc(func(dst []byte) (int, error) { return copy(dst, " A "), failure })}
	if got, err := io.ReadAll(source); string(got) != "A" || !errors.Is(err, failure) {
		t.Fatal("final data/source error lost", got, err)
	}
}

func TestReaderRetainsErrorsDeliveredWithData(t *testing.T) {
	failure := errors.New("last source read failed")
	calls := 0
	source := inputFunc(func(dst []byte) (int, error) {
		calls++
		if calls == 1 {
			return copy(dst, "full"), failure
		}

		return 0, io.EOF
	})
	reader := &streamio.Reader{Context: t.Context(), Source: source, Limit: 4, LimitError: io.ErrShortBuffer}

	var data [4]byte
	if n, err := io.ReadFull(reader, data[:]); n != 4 || err != nil {
		t.Fatal("standard ReadFull contract", n, err)
	}

	if n, err := reader.Read(data[:1]); n != 0 || !errors.Is(err, failure) || calls != 1 {
		t.Fatal("completion lost source error", n, err, calls)
	}
}

func TestReaderWriteTo(t *testing.T) {
	for _, size := range []int{0, 1, 32768, 65537} {
		text := strings.Repeat("x", size)
		for _, knownSize := range []bool{false, true} {
			var source io.Reader = strings.NewReader(text)
			if !knownSize {
				source = struct{ io.Reader }{source}
			}

			var target bytes.Buffer

			reader := &streamio.Reader{Context: t.Context(), Source: source, Limit: int64(size), LimitError: io.ErrShortBuffer}

			n, err := io.Copy(writeOnly{&target}, reader)
			if err != nil || n != int64(size) || target.String() != text || reader.ReadBytes != n {
				t.Fatalf("size=%d known=%v: count=%d read=%d error=%v", size, knownSize, n, reader.ReadBytes, err)
			}
		}
	}
}

func TestReaderWriteToErrors(t *testing.T) {
	const text = "abc"

	failure := errors.New("source failed")
	for _, tc := range []struct {
		name   string
		source io.Reader
		limit  int64
		want   string
		err    error
	}{
		{"overflow", strings.NewReader("abcd"), 3, text, io.ErrShortBuffer},
		{"data and error", inputFunc(func(p []byte) (int, error) { return copy(p, text), failure }), 3, text, failure},
		{"wrapped EOF", inputFunc(func([]byte) (int, error) { return 0, errors.Join(io.EOF, failure) }), 3, "", failure},
		{"data and EOF", inputFunc(func(p []byte) (int, error) { return copy(p, text), io.EOF }), 3, text, nil},
		{"no progress", inputFunc(func([]byte) (int, error) { return 0, nil }), 3, "", io.ErrNoProgress},
		{"negative count", inputFunc(func([]byte) (int, error) { return -1, nil }), 3, "", io.ErrShortBuffer},
		{"excess count", inputFunc(func(p []byte) (int, error) { return len(p) + 1, nil }), 3, "", io.ErrShortBuffer},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var target bytes.Buffer

			reader := &streamio.Reader{Context: t.Context(), Source: tc.source, Limit: tc.limit, LimitError: io.ErrShortBuffer}

			n, err := reader.WriteTo(&target)
			if n != int64(len(tc.want)) || target.String() != tc.want || !errors.Is(err, tc.err) {
				t.Fatalf("count=%d output=%q error=%v", n, target.String(), err)
			}
		})
	}

	for _, count := range []int{-1, 0, 1, 4} {
		reader := &streamio.Reader{Context: t.Context(), Source: strings.NewReader(text), Limit: 3, LimitError: io.ErrShortBuffer}
		n, err := reader.WriteTo(countWriter{count, nil})

		var want int64
		if count > 0 && count <= 3 {
			want = int64(count)
		}

		if !errors.Is(err, io.ErrShortWrite) || n != want {
			t.Fatal("invalid destination count", count, n, err)
		}
	}

	ctx, cancel := context.WithCancel(t.Context())

	reader := &streamio.Reader{Context: ctx, Source: inputFunc(func(p []byte) (int, error) {
		cancel()
		return copy(p, text), nil
	}), Limit: 3, LimitError: io.ErrShortBuffer}
	if n, err := reader.WriteTo(io.Discard); n != 3 || !errors.Is(err, context.Canceled) {
		t.Fatal("cancellation lost", n, err)
	}

	reader.Source = inputFunc(func([]byte) (int, error) {
		t.Fatal("cancelled copy read the source")
		return 0, nil
	})
	if n, err := reader.WriteTo(io.Discard); n != 0 || !errors.Is(err, context.Canceled) {
		t.Fatal(n, err)
	}
}

type stringSink struct {
	bytes.Buffer
	stringWrites int
}

func (s *stringSink) WriteString(value string) (int, error) {
	s.stringWrites++
	return s.Buffer.WriteString(value)
}

type countWriter struct {
	n   int
	err error
}

func (w countWriter) Write([]byte) (int, error) { return w.n, w.err }

type inputFunc func([]byte) (int, error)

func (f inputFunc) Read(dst []byte) (int, error) { return f(dst) }
