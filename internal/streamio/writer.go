// Package streamio supplies bounded, context-aware I/O shared by public APIs.
package streamio

import (
	"context"
	"io"
)

const (
	minimumWriteBufferBytes = 512
)

// Writer counts successful bytes and rejects writes exceeding an explicit limit.
// It never closes the caller-owned destination.
type Writer struct {
	// Context supplies cancellation and must be non-nil.
	Context context.Context
	// Target is the caller-owned destination; this wrapper never closes it.
	Target io.Writer
	// Limit is the maximum number of bytes permitted in the output.
	Limit int64
	// Written counts bytes successfully accepted by Target.
	Written int64
	// LimitError is returned before a write would exceed Limit.
	LimitError error
	// buffer is reusable scratch storage for bounded string writes.
	buffer []byte
}

// Write checks cancellation, bounds and the io.Writer short-write contract.
func (w *Writer) Write(p []byte) (int, error) {
	if err := w.Context.Err(); err != nil {
		return 0, err
	}

	if int64(len(p)) > w.Limit-w.Written {
		return 0, w.LimitError
	}

	n, err := w.Target.Write(p)
	if n < 0 || n > len(p) {
		return 0, io.ErrShortWrite
	}

	w.Written += int64(n)
	if err == nil && n != len(p) {
		err = io.ErrShortWrite
	}

	return n, err
}

// WriteString forwards bounded chunks without allocating a whole byte copy.
func (w *Writer) WriteString(s string) (int, error) {
	const bufferGrowthFactor = 2

	total := 0

	for len(s) > 0 {
		if err := w.Context.Err(); err != nil {
			return total, err
		}

		chunk := s[:min(len(s), copyChunkBytes)]
		if int64(len(chunk)) > w.Limit-w.Written {
			return total, w.LimitError
		}

		var (
			n   int
			err error
		)
		if writer, ok := w.Target.(io.StringWriter); ok {
			n, err = writer.WriteString(chunk)
		} else {
			if len(w.buffer) < len(chunk) {
				// Most canonical fragments are short. Grow geometrically to retain the
				// 32 KiB ceiling without allocating it for every small signature digest.
				size := min(copyChunkBytes, max(minimumWriteBufferBytes, len(chunk), bufferGrowthFactor*len(w.buffer)))
				w.buffer = make([]byte, size)
			}

			copy(w.buffer, chunk)
			n, err = w.Target.Write(w.buffer[:len(chunk)])
		}

		if n < 0 || n > len(chunk) {
			return total, io.ErrShortWrite
		}

		w.Written += int64(n)

		total += n
		if err == nil && n != len(chunk) {
			err = io.ErrShortWrite
		}

		if err != nil {
			return total, err
		}

		s = s[n:]
	}

	return total, nil
}
