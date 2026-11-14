package streamio_test

import (
	"bytes"
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
		n         int
		writerErr error
		errorWant error
		countWant int
		remaining int
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
