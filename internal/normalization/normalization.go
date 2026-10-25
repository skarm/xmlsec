// Package normalization implements exact Unicode normalization using x/text's
// versioned Unicode tables, without its Stream-Safe CGJ insertion. Only an
// unfinished normalization segment needs buffering; a combining sequence can
// be arbitrarily long and is subject to the caller's input/output budgets.
package normalization

import (
	"bytes"
	"context"
	"io"
	"iter"
	"strings"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"
)

// Form selects a Unicode normalization form.
type Form norm.Form

const (
	NFC  = Form(norm.NFC)
	NFD  = Form(norm.NFD)
	NFKC = Form(norm.NFKC)
	NFKD = Form(norm.NFKD)
)

type character struct {
	value rune
	class uint8
}

// PropertiesString returns the underlying Unicode properties of the first rune.
func (f Form) PropertiesString(s string) norm.Properties { return norm.Form(f).PropertiesString(s) }

// Each emits complete normalization segments, batching short segments. It never
// introduces CGJ. Callers must bound their source before entering this function.
func (f Form) Each(ctx context.Context, s string, emit func(string) error) error {
	return f.each(ctx, s, func(_, result string) error { return emit(result) })
}

// EachBytes emits borrowed UTF-8 segments with reusable iterator storage. The
// callback must consume each segment before returning. Safe blocks need no
// normalized copy; long runs use the same exact fallback as Each.
func (f Form) EachBytes(ctx context.Context, s string, emit func([]byte) error) error {
	var iterator norm.Iter

	return f.segments(ctx, s, func(source string) error {
		if len(source) > 4096+utf8.UTFMax {
			result, err := f.longSegment(ctx, source)
			if err != nil {
				return err
			}

			return emit([]byte(result))
		}

		iterator.InitString(norm.Form(f), source)

		joiners := 0
		for !iterator.Done() {
			joiners += bytes.Count(iterator.Next(), []byte("\u034f"))
		}

		if joiners != strings.Count(source, "\u034f") {
			result, err := f.longSegment(ctx, source)
			if err != nil {
				return err
			}

			return emit([]byte(result))
		}

		iterator.InitString(norm.Form(f), source)

		for !iterator.Done() {
			if err := emit(iterator.Next()); err != nil {
				return err
			}
		}

		return ctx.Err()
	})
}

// String normalizes a bounded in-memory value. I/O paths should use Each or Writer.
func (f Form) String(s string) string {
	result, _ := String(context.Background(), f, s)
	return result
}

// Bytes normalizes an in-memory value, reusing it if it is already normalized.
func (f Form) Bytes(s []byte) []byte {
	if norm.Form(f).IsNormal(s) {
		return s
	}

	out := make([]byte, 0, len(s))
	ctx := context.Background()

	for source, err := range f.byteSegments(ctx, s) {
		if err != nil {
			return nil
		}

		result, err := f.segmentBytes(ctx, source)
		if err != nil {
			return nil
		}

		out = append(out, result...)
	}

	if bytes.Equal(out, s) {
		return s
	}

	return out
}

func (f Form) each(ctx context.Context, s string, emit func(string, string) error) error {
	return f.segments(ctx, s, func(source string) error {
		result, err := f.segment(ctx, source)
		if err != nil {
			return err
		}

		return emit(source, result)
	})
}

func (f Form) segments(ctx context.Context, s string, emit func(string) error) error {
	for len(s) > 0 {
		if err := ctx.Err(); err != nil {
			return err
		}

		end := len(s)
		for at := 0; at < len(s); {
			if at >= 4096 && f.PropertiesString(s[at:]).BoundaryBefore() {
				end = at
				break
			}

			_, size := utf8.DecodeRuneInString(s[at:])

			at += size
			if at%4096 < utf8.UTFMax {
				if err := ctx.Err(); err != nil {
					return err
				}
			}
		}

		if err := emit(s[:end]); err != nil {
			return err
		}

		s = s[end:]
	}

	return ctx.Err()
}

func (f Form) segment(ctx context.Context, s string) (string, error) {
	if len(s) > 4096+utf8.UTFMax {
		return f.longSegment(ctx, s)
	}

	result := norm.Form(f).String(s)
	if strings.Count(result, "\u034f") == strings.Count(s, "\u034f") {
		return result, ctx.Err()
	}

	return f.longSegment(ctx, s)
}

func (f Form) longSegment(ctx context.Context, s string) (string, error) {
	chars, err := f.normalizedCharacters(ctx, len(s), func(yield func(int, rune) bool) {
		for at, r := range s {
			if !yield(at, r) {
				return
			}
		}
	})
	if err != nil {
		return "", err
	}

	var out strings.Builder
	out.Grow(len(s))

	for at, c := range chars {
		if at%4096 == 0 {
			if err := ctx.Err(); err != nil {
				return "", err
			}
		}

		out.WriteRune(c.value)
	}

	return out.String(), nil
}

func (f Form) longSegmentBytes(ctx context.Context, s []byte) ([]byte, error) {
	chars, err := f.normalizedCharacters(ctx, len(s), func(yield func(int, rune) bool) {
		for at := 0; at < len(s); {
			r, size := utf8.DecodeRune(s[at:])
			if !yield(at, r) {
				return
			}

			at += size
		}
	})
	if err != nil {
		return nil, err
	}

	out := make([]byte, 0, len(s))

	for at, c := range chars {
		if at%4096 == 0 {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
		}

		out = utf8.AppendRune(out, c.value)
	}

	return out, nil
}

func (f Form) normalizedCharacters(ctx context.Context, size int, input iter.Seq2[int, rune]) ([]character, error) {
	decomposition := norm.NFD
	if f == NFKC || f == NFKD {
		decomposition = norm.NFKD
	}

	chars := make([]character, 0, size/2)

	for at, r := range input {
		if at%4096 < utf8.UTFMax {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
		}
		// A single scalar's complete decomposition fits x/text's reorder buffer.
		// Hangul's algorithmic decomposition is handled by the same table API.
		for _, d := range decomposition.String(string(r)) {
			chars = append(chars, character{d, norm.NFD.PropertiesString(string(d)).CCC()})
		}
	}

	if err := reorder(ctx, chars); err != nil {
		return nil, err
	}

	if f == NFC || f == NFKC {
		var err error

		chars, err = compose(ctx, chars)
		if err != nil {
			return nil, err
		}
	}

	return chars, nil
}

// reorder uses stable counting sort on each non-starter run: long adversarial
// combining sequences must not turn canonical ordering into quadratic work.
func reorder(ctx context.Context, chars []character) error {
	var scratch []character

	for at := 0; at < len(chars); {
		if err := ctx.Err(); err != nil {
			return err
		}

		if chars[at].class == 0 {
			at++
			continue
		}

		end := at + 1
		ordered := true

		for end < len(chars) && chars[end].class != 0 {
			if end%4096 == 0 {
				if err := ctx.Err(); err != nil {
					return err
				}
			}

			ordered = ordered && chars[end-1].class <= chars[end].class
			end++
		}

		if !ordered {
			if cap(scratch) < end-at {
				scratch = make([]character, end-at)
			} else {
				scratch = scratch[:end-at]
			}

			if err := sortRun(ctx, chars[at:end], scratch); err != nil {
				return err
			}
		}

		at = end
	}

	return nil
}

func sortRun(ctx context.Context, chars, scratch []character) error {
	var counts [256]int
	for i, c := range chars {
		counts[c.class]++

		if i%4096 == 0 {
			if err := ctx.Err(); err != nil {
				return err
			}
		}
	}

	offset := 0
	for i, count := range counts {
		counts[i] = offset
		offset += count
	}

	for i, c := range chars {
		scratch[counts[c.class]] = c
		counts[c.class]++

		if i%4096 == 0 {
			if err := ctx.Err(); err != nil {
				return err
			}
		}
	}

	copy(chars, scratch)

	return ctx.Err()
}

func compose(ctx context.Context, chars []character) ([]character, error) {
	out := chars[:0]
	starter, previous := -1, uint8(0)

	for at, c := range chars {
		if at%4096 == 0 {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
		}

		if starter >= 0 && (previous < c.class || previous == 0) {
			var pair [utf8.UTFMax * 2]byte

			n := utf8.EncodeRune(pair[:], out[starter].value)
			n += utf8.EncodeRune(pair[n:], c.value)
			combined := norm.NFC.Bytes(pair[:n])

			r, size := utf8.DecodeRune(combined)
			if size == len(combined) {
				out[starter].value = r
				continue
			}
		}

		if c.class == 0 {
			starter = len(out)
		}

		out = append(out, c)
		previous = c.class
	}

	return out, nil
}

// Writer preserves incomplete UTF-8 and the last normalization segment across
// writes. Close flushes it without closing the destination. No global pool
// retains large segments after completion.
type Writer struct {
	ctx        context.Context
	dst        io.Writer
	form       Form
	pending    []byte
	normalized []byte
	tail       [utf8.UTFMax]byte
	tailSize   int
	err        error
}

// NewWriter creates an exact normalizing writer over a caller-bounded stream.
func NewWriter(ctx context.Context, dst io.Writer, form Form) *Writer {
	return &Writer{ctx: ctx, dst: dst, form: form}
}

func (w *Writer) Write(p []byte) (int, error) {
	if w.err != nil {
		return 0, w.err
	}

	for i, nextCheck := 0, 0; i < len(p); {
		if i >= nextCheck {
			if w.err = w.ctx.Err(); w.err != nil {
				return i, w.err
			}

			nextCheck = i + 4096
		}

		// Every ASCII scalar has BoundaryBefore in all four forms. Batch it
		// without flushing the final scalar: the next Write may begin with a
		// combining mark which must still compose with that pending starter.
		if w.tailSize == 0 && p[i] < utf8.RuneSelf {
			n, err := w.writeASCII(p[i:min(len(p), nextCheck)])
			i += n

			if err != nil {
				w.err = err
				return i, err
			}

			continue
		}

		w.tail[w.tailSize] = p[i]
		i++

		w.tailSize++
		if !utf8.FullRune(w.tail[:w.tailSize]) {
			continue
		}

		r, size := utf8.DecodeRune(w.tail[:w.tailSize])
		if r == utf8.RuneError && size == 1 {
			w.err = io.ErrUnexpectedEOF
			return i, w.err
		}

		if norm.Form(w.form).Properties(w.tail[:w.tailSize]).BoundaryBefore() && len(w.pending) >= 4096 {
			if w.err = w.flush(); w.err != nil {
				return i, w.err
			}
		}

		w.pending = append(w.pending, w.tail[:w.tailSize]...)
		w.tailSize = 0
	}

	return len(p), nil
}

func (w *Writer) writeASCII(p []byte) (int, error) {
	if len(w.pending) >= 4096 {
		if err := w.flush(); err != nil {
			return 1, err
		}
	}

	end := 1
	limit := min(len(p), 4096-len(w.pending))

	for end < limit && p[end] < utf8.RuneSelf {
		end++
	}

	w.pending = append(w.pending, p[:end]...)

	return end, nil
}

// WriteString feeds bounded chunks without copying the complete source string.
func (w *Writer) WriteString(s string) (int, error) {
	var buffer [4096]byte

	written := 0

	for len(s) > 0 {
		size := copy(buffer[:], s)
		n, err := w.Write(buffer[:size])

		written += n
		if err != nil {
			return written, err
		}

		s = s[size:]
	}

	return written, w.err
}

// Close flushes the final segment and releases pending storage, including on error.
func (w *Writer) Close() error {
	defer func() {
		w.pending = nil
		w.normalized = nil
	}()

	if w.err != nil {
		return w.err
	}

	if w.tailSize != 0 {
		return io.ErrUnexpectedEOF
	}

	w.err = w.flush()

	return w.err
}

func (w *Writer) flush() error {
	if err := w.ctx.Err(); err != nil {
		return err
	}

	if len(w.pending) == 0 {
		return nil
	}

	var result []byte

	if len(w.pending) <= 4096+utf8.UTFMax {
		w.normalized = norm.Form(w.form).Append(w.normalized[:0], w.pending...)
		if bytes.Count(w.normalized, []byte("\u034f")) == bytes.Count(w.pending, []byte("\u034f")) {
			result = w.normalized
		}
	}

	if result == nil {
		part, err := w.form.longSegmentBytes(w.ctx, w.pending)
		if err != nil {
			return err
		}

		result = part
	}

	if err := w.ctx.Err(); err != nil {
		return err
	}

	n, err := w.dst.Write(result)
	if err == nil && n != len(result) {
		err = io.ErrShortWrite
	}

	if cap(w.pending) > 8192 {
		w.pending = nil
	} else {
		w.pending = w.pending[:0]
	}

	return err
}

// String normalizes a value while observing cancellation between bounded steps.
func String(ctx context.Context, f Form, s string) (string, error) {
	var out strings.Builder

	at := 0
	changed := false

	err := f.each(ctx, s, func(source, part string) error {
		if !changed && source == part {
			at += len(source)
			return nil
		}

		if !changed {
			out.WriteString(s[:at])

			changed = true
		}

		out.WriteString(part)

		return nil
	})
	if err != nil {
		return "", err
	}

	if !changed && at == len(s) {
		return s, nil
	}

	return out.String(), nil
}

// IsNormal checks normalization while observing cancellation. Already normal
// short segments do not allocate copies of the complete input.
func IsNormal(ctx context.Context, f Form, s []byte) (bool, error) {
	for part, err := range f.byteSegments(ctx, s) {
		if err != nil {
			return false, err
		}

		if len(part) > 4096 || !norm.Form(f).IsNormal(part) {
			result, err := f.segmentBytes(ctx, part)
			if err != nil {
				return false, err
			}

			if !bytes.Equal(result, part) {
				return false, nil
			}
		}
	}

	return true, ctx.Err()
}

func (f Form) segmentBytes(ctx context.Context, s []byte) ([]byte, error) {
	if len(s) > 4096+utf8.UTFMax {
		return f.longSegmentBytes(ctx, s)
	}

	result := norm.Form(f).Bytes(s)
	if bytes.Count(result, []byte("\u034f")) == bytes.Count(s, []byte("\u034f")) {
		return result, ctx.Err()
	}

	return f.longSegmentBytes(ctx, s)
}

func (f Form) byteSegments(ctx context.Context, s []byte) iter.Seq2[[]byte, error] {
	return func(yield func([]byte, error) bool) {
		for len(s) > 0 {
			if err := ctx.Err(); err != nil {
				yield(nil, err)
				return
			}

			end := len(s)
			for at := 0; at < len(s); {
				if at >= 4096 && norm.Form(f).Properties(s[at:]).BoundaryBefore() {
					end = at
					break
				}

				_, size := utf8.DecodeRune(s[at:])

				at += size
				if at%4096 < utf8.UTFMax {
					if err := ctx.Err(); err != nil {
						yield(nil, err)
						return
					}
				}
			}

			if !yield(s[:end], nil) {
				return
			}

			s = s[end:]
		}
	}
}
