package streamio

import (
	"context"
	"io"
)

// Reader checks cancellation and a byte limit without retaining input.
// At the limit it reads one sentinel byte to distinguish exact EOF from overflow.
// It never closes the caller-owned source.
type Reader struct {
	Context    context.Context
	Source     io.Reader
	Limit      int64
	ReadBytes  int64
	LimitError error
	stalled    int
	readErr    error
}

// Read rejects invalid reader counts and repeated reads that make no progress.
func (r *Reader) Read(p []byte) (int, error) {
	if err := r.Context.Err(); err != nil {
		return 0, err
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
			return 0, r.LimitError
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
		return 0, err
	}

	size := 4 << 10

	source, resident := r.Source.(interface{ Len() int })
	if resident {
		size = max(1, min(32<<10, source.Len()))
	}

	buffer := make([]byte, size)

	var written int64

	for {
		n, readErr := r.Read(buffer[:size])
		if n > 0 {
			count, err := dst.Write(buffer[:n])
			if count < 0 || count > n {
				return written, io.ErrShortWrite
			}

			written += int64(count)
			if err != nil {
				return written, err
			}

			if count != n {
				return written, io.ErrShortWrite
			}
		}

		if readErr != nil {
			if readErr == io.EOF { //nolint:errorlint // Wrapped or joined EOF can carry a resource failure.
				return written, nil
			}

			return written, readErr
		}

		if !resident && n == size && size < 32<<10 {
			// Write 4, 4, 8, 16, then 32 KiB chunks. A 4+32 KiB start
			// would make bytes.Buffer retain 36 KiB * 2^k instead of
			// 32 KiB * 2^k when collecting a large opaque stream.
			size = int(min(32<<10, written))
			if size > len(buffer) {
				buffer = make([]byte, 32<<10)
			}
		}
	}
}

func (r *Reader) progress(n int, err error) error {
	if n > 0 {
		r.stalled = 0
	} else if err == nil {
		r.stalled++
		if r.stalled >= 100 {
			err = io.ErrNoProgress
		}
	}
	// ReadFull may suppress an error delivered with a full buffer. Retain it
	// for the next read so completion probes still observe resource failures.
	r.readErr = err

	return err
}

// XMLWhitespaceReader skips only XML S characters in fixed storage. Source
// supplies its own context and byte budget; non-XML whitespace is retained.
type XMLWhitespaceReader struct {
	Source io.Reader
	buffer [4096]byte
}

func (r *XMLWhitespaceReader) Read(dst []byte) (int, error) {
	if len(dst) == 0 {
		return 0, nil
	}

	for stalled := 0; ; {
		n, err := r.Source.Read(r.buffer[:min(len(dst), len(r.buffer))])
		if n < 0 || n > min(len(dst), len(r.buffer)) {
			return 0, io.ErrShortBuffer
		}

		used := 0

		for _, c := range r.buffer[:n] {
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
			if stalled >= 100 {
				return 0, io.ErrNoProgress
			}
		} else {
			stalled = 0
		}
	}
}
