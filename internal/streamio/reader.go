package streamio

import (
	"context"
	"errors"
	"io"
)

const (
	// Caps one copy or string-write chunk and the retained scratch buffer, in bytes.
	copyChunkBytes           = 32 << 10
	initialReadBufferBytes   = 4 << 10
	maximumStalledReads      = 100
	whitespaceReadChunkBytes = 4096
)

// Reader checks cancellation and a byte limit without retaining input.
// At the limit it reads one sentinel byte to distinguish exact EOF from overflow.
// It never closes the caller-owned source.
type Reader struct {
	// Context supplies cancellation and must be non-nil.
	Context context.Context
	// Source is the caller-owned reader; this wrapper never closes it.
	Source io.Reader
	// Limit is the maximum number of input bytes to return. The overflow probe is
	// not returned.
	Limit int64
	// ReadBytes counts bytes returned from Source within the limit.
	ReadBytes int64
	// LimitError is returned when the sentinel read detects input beyond Limit.
	// A source failure delivered with that byte is also preserved.
	LimitError error
	// stalled counts consecutive reads that return neither data nor an error.
	stalled int
	// readErr retains a terminal source error so later reads do not resume the
	// source.
	readErr error
}

// Read rejects invalid reader counts and repeated reads that make no progress.
func (r *Reader) Read(p []byte) (int, error) {
	if err := r.Context.Err(); err != nil {
		return 0, withReadCancellation(r.readErr, err)
	}

	if r.readErr != nil {
		return 0, r.readErr
	}

	if len(p) == 0 {
		return 0, nil
	}

	remaining := r.Limit - r.ReadBytes
	if remaining <= 0 {
		var probe [1]byte

		n, err := r.Source.Read(probe[:])
		if n < 0 || n > 1 {
			return 0, io.ErrShortBuffer
		}

		if n > 0 {
			failure := r.LimitError
			if err != nil && !plainEOF(err) {
				failure = errors.Join(failure, err)
			}

			return 0, r.progress(n, failure)
		}

		return 0, r.progress(n, err)
	}

	if int64(len(p)) > remaining {
		p = p[:int(remaining)]
	}

	n, err := r.Source.Read(p)
	if n < 0 || n > len(p) {
		return 0, io.ErrShortBuffer
	}

	r.ReadBytes += int64(n)

	return n, r.progress(n, err)
}

// WriteTo copies through Read so cancellation, limits and source errors remain
// enforced. Resident sources with Len need at most their remaining byte count
// as scratch space. Unknown streams start at 4 KiB and grow to 32 KiB only
// after filling two initial chunks. Power-of-two write boundaries also keep
// collecting destinations from growing to a misaligned backing-array size.
func (r *Reader) WriteTo(dst io.Writer) (int64, error) {
	if err := r.Context.Err(); err != nil {
		return 0, withReadCancellation(r.readErr, err)
	}

	size := initialReadBufferBytes

	source, resident := r.Source.(interface{ Len() int })
	if resident {
		size = max(1, min(copyChunkBytes, source.Len()))
	}

	buffer := make([]byte, size)

	var written int64

	for {
		n, readErr := r.Read(buffer[:size])
		if n > 0 {
			count, err := dst.Write(buffer[:n])
			if count < 0 || count > n {
				return written, copyCompletionError(readErr, io.ErrShortWrite, r.Context.Err())
			}

			written += int64(count)
			if err == nil && count != n {
				err = io.ErrShortWrite
			}

			if err != nil {
				return written, copyCompletionError(readErr, err, r.Context.Err())
			}
		}

		if readErr != nil {
			return written, copyCompletionError(readErr, nil, r.Context.Err())
		}

		if !resident && n == size && size < copyChunkBytes {
			// Write 4, 4, 8, 16, then 32 KiB chunks. A 4+32 KiB start
			// would make bytes.Buffer retain 36 KiB * 2^k instead of
			// 32 KiB * 2^k when collecting a large opaque stream.
			size = int(min(copyChunkBytes, written))
			if size > len(buffer) {
				buffer = make([]byte, copyChunkBytes)
			}
		}
	}
}

func copyCompletionError(readErr, writeErr, canceled error) error {
	if readErr != nil && !plainEOF(readErr) {
		if writeErr == nil {
			writeErr = readErr
		} else {
			writeErr = errors.Join(writeErr, readErr)
		}
	}

	if writeErr == nil {
		return canceled
	}

	if canceled != nil && !errors.Is(writeErr, canceled) {
		return errors.Join(writeErr, canceled)
	}

	return writeErr
}

func (r *Reader) progress(n int, err error) error {
	if canceled := r.Context.Err(); canceled != nil {
		err = withReadCancellation(err, canceled)
	}

	if n > 0 {
		r.stalled = 0
	} else if err == nil {
		r.stalled++
		if r.stalled >= maximumStalledReads {
			err = io.ErrNoProgress
		}
	}
	// ReadFull may suppress an error delivered with a full buffer. Retain it
	// for the next read so completion probes still observe resource failures.
	r.readErr = err

	return err
}

func plainEOF(err error) bool {
	return err == io.EOF //nolint:errorlint // Wrapped or joined EOF can carry a resource failure.
}

func withReadCancellation(err, canceled error) error {
	if err == nil || plainEOF(err) {
		return canceled
	}

	if errors.Is(err, canceled) {
		return err
	}

	return errors.Join(err, canceled)
}

// XMLWhitespaceReader skips only XML S characters in fixed storage. Source
// supplies its own context and byte budget; non-XML whitespace is retained.
type XMLWhitespaceReader struct {
	Source io.Reader
}

func (r *XMLWhitespaceReader) Read(dst []byte) (int, error) {
	if len(dst) == 0 {
		return 0, nil
	}

	// Compact in place. The write index never passes the current read index.
	dst = dst[:min(len(dst), whitespaceReadChunkBytes)]
	for stalled := 0; ; {
		n, err := r.Source.Read(dst)
		if n < 0 || n > len(dst) {
			return 0, io.ErrShortBuffer
		}

		used := 0

		for _, c := range dst[:n] {
			if c != ' ' && c != '\t' && c != '\r' && c != '\n' {
				dst[used] = c
				used++
			}
		}

		if used > 0 || err != nil {
			return used, err
		}

		if n == 0 {
			stalled++
			if stalled >= maximumStalledReads {
				return 0, io.ErrNoProgress
			}
		} else {
			stalled = 0
		}
	}
}
