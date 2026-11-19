package streamio_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strconv"
	"strings"
	"testing"

	"github.com/skarm/xmlsec/internal/streamio"
)

func TestXMLWhitespaceReader(t *testing.T) {
	for _, size := range []int{1, 3, 4096, 8192} {
		text := strings.Repeat(" \t\r\nA\vB\u00a0", 1024)
		source := &streamio.XMLWhitespaceReader{Source: strings.NewReader(text)}

		var output bytes.Buffer
		if _, err := io.CopyBuffer(writeOnly{&output}, source, make([]byte, size)); err != nil || output.String() != strings.Repeat("A\vB\u00a0", 1024) {
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

func BenchmarkXMLWhitespaceReader(b *testing.B) {
	for _, lines := range []int{1, 128} {
		text := strings.Repeat(strings.Repeat("A", 76)+"\r\n", lines)
		b.Run(strconv.Itoa(lines), func(b *testing.B) {
			b.ReportAllocs()
			b.SetBytes(int64(len(text)))
			for b.Loop() {
				reader := &streamio.XMLWhitespaceReader{Source: strings.NewReader(text)}
				if count, err := io.Copy(io.Discard, reader); err != nil || count != int64(76*lines) {
					b.Fatal(count, err)
				}
			}
		})
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

func TestReaderReportsCancellationFromFinalRead(t *testing.T) {
	failure := errors.New("source failed on final read")
	for _, terminal := range []error{io.EOF, failure} {
		t.Run(terminal.Error(), func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			source := inputFunc(func(dst []byte) (int, error) {
				cancel()
				return copy(dst, "input"), terminal
			})
			reader := &streamio.Reader{Context: ctx, Source: source, Limit: 5, LimitError: io.ErrShortBuffer}
			data, err := io.ReadAll(reader)
			if string(data) != "input" || !errors.Is(err, context.Canceled) || errors.Is(err, failure) != errors.Is(terminal, failure) {
				t.Fatalf("ReadAll = (%q, %v), want final bytes, cancellation and any source failure", data, err)
			}
		})
	}
}

func TestReaderWriteToReportsCancellationFromFinalWrite(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	source := inputFunc(func(dst []byte) (int, error) { return copy(dst, "input"), io.EOF })
	reader := &streamio.Reader{Context: ctx, Source: source, Limit: 5, LimitError: io.ErrShortBuffer}
	var target bytes.Buffer
	written, err := reader.WriteTo(writeFunc(func(data []byte) (int, error) {
		cancel()
		return target.Write(data)
	}))
	if written != 5 || target.String() != "input" || !errors.Is(err, context.Canceled) {
		t.Fatalf("WriteTo = (%d, %v), output %q, want five written bytes and cancellation", written, err, target.String())
	}
}

func TestReaderCompletionProbePreservesFailureAfterCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	failure := errors.New("final input read failed")
	source := inputFunc(func(dst []byte) (int, error) {
		cancel()
		return copy(dst, "input"), failure
	})
	reader := &streamio.Reader{Context: ctx, Source: source, Limit: 5, LimitError: io.ErrShortBuffer}
	var data [5]byte
	if count, err := io.ReadFull(reader, data[:]); count != 5 || err != nil {
		t.Fatalf("ReadFull = (%d, %v), want five bytes", count, err)
	}
	if count, err := reader.Read(data[:1]); count != 0 || !errors.Is(err, failure) || !errors.Is(err, context.Canceled) {
		t.Fatalf("completion probe = (%d, %v), want source failure and cancellation", count, err)
	}
	if count, err := io.Copy(io.Discard, reader); count != 0 || !errors.Is(err, failure) || !errors.Is(err, context.Canceled) {
		t.Fatalf("copy after cancellation = (%d, %v), want retained failure and cancellation", count, err)
	}
}

type writeFunc func([]byte) (int, error)

func (f writeFunc) Write(data []byte) (int, error) { return f(data) }

func TestReaderRetainsOverflow(t *testing.T) {
	source := strings.NewReader("abcd")
	reader := &streamio.Reader{Context: t.Context(), Source: source, Limit: 2, LimitError: io.ErrShortBuffer}
	var buffer [2]byte
	if n, err := reader.Read(buffer[:]); n != 2 || err != nil || string(buffer[:]) != "ab" {
		t.Fatalf("initial read = %d, %v, %q", n, err, buffer)
	}
	for range 3 {
		if n, err := reader.Read(buffer[:]); n != 0 || !errors.Is(err, io.ErrShortBuffer) || source.Len() != 1 {
			t.Fatalf("read after limit = %d, %v, remaining source = %d", n, err, source.Len())
		}
	}
}

func TestReaderRetainsSourceErrorAtOverflow(t *testing.T) {
	failure := errors.New("source failed delivering last byte")
	for _, tc := range []struct {
		name    string
		last    error
		wantEOF bool
	}{
		{"terminal failure", failure, false},
		{"joined EOF", errors.Join(io.EOF, failure), true},
		{"ordinary EOF", io.EOF, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			source := inputFunc(func(dst []byte) (int, error) {
				calls++
				if calls == 1 {
					return copy(dst, "ab"), nil
				}

				return copy(dst, "c"), tc.last
			})
			reader := &streamio.Reader{Context: t.Context(), Source: source, Limit: 2, LimitError: io.ErrShortBuffer}
			var target bytes.Buffer
			n, err := reader.WriteTo(&target)
			if n != 2 || target.String() != "ab" || reader.ReadBytes != 2 || calls != 2 {
				t.Fatalf("copy = %d bytes %q, counted %d, %d reads", n, target.String(), reader.ReadBytes, calls)
			}
			checkError := func(err error) {
				t.Helper()
				if !errors.Is(err, io.ErrShortBuffer) || errors.Is(err, failure) != errors.Is(tc.last, failure) || errors.Is(err, io.EOF) != tc.wantEOF {
					t.Fatalf("wrong limit or source cause: %v (last source result %v)", err, tc.last)
				}
			}
			checkError(err)
			var byteBuffer [1]byte
			next, retained := reader.Read(byteBuffer[:])
			if next != 0 || calls != 2 {
				t.Fatalf("follow-up = (%d, %v), %d reads; want retained error without another read", next, retained, calls)
			}
			checkError(retained)
		})
	}
}

func TestReaderWriteTo(t *testing.T) {
	for _, size := range []int{0, 1, 4095, 4096, 4097, 32768, 65537} {
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

// BenchmarkReaderWriteTo separates resident buffers from opaque streams such
// as canonicalization and decoder readers. Fixtures are outside the timed loop.
func BenchmarkReaderWriteTo(b *testing.B) {
	for _, size := range []int{256, 4096, 16384, 1 << 20} {
		text := strings.Repeat("x", size)
		for _, knownSize := range []bool{false, true} {
			b.Run(strconv.Itoa(size)+"/"+strconv.FormatBool(knownSize), func(b *testing.B) {
				b.ReportAllocs()
				b.SetBytes(int64(size))
				for b.Loop() {
					var source io.Reader = strings.NewReader(text)
					if !knownSize {
						source = struct{ io.Reader }{source}
					}
					reader := &streamio.Reader{Context: b.Context(), Source: source, Limit: int64(size), LimitError: io.ErrShortBuffer}
					if count, err := reader.WriteTo(io.Discard); err != nil || count != int64(size) {
						b.Fatal(count, err)
					}
				}
			})
		}
	}
}

// BenchmarkReaderCollection includes the destination's backing-array growth,
// as pure Ed25519 and attached CMS must collect one complete opaque message.
func BenchmarkReaderCollection(b *testing.B) {
	for _, size := range []int{16384, 1 << 20, 8 << 20} {
		b.Run(strconv.Itoa(size), func(b *testing.B) {
			text := strings.Repeat("x", size)
			b.ReportAllocs()
			b.SetBytes(int64(size))
			for b.Loop() {
				source := struct{ io.Reader }{strings.NewReader(text)}
				reader := &streamio.Reader{Context: b.Context(), Source: source, Limit: int64(size), LimitError: io.ErrShortBuffer}
				var target bytes.Buffer
				if count, err := reader.WriteTo(&target); err != nil || count != int64(size) || target.Len() != size {
					b.Fatal(count, err)
				}
			}
		})
	}
}

type inputFunc func([]byte) (int, error)

func (f inputFunc) Read(dst []byte) (int, error) { return f(dst) }
