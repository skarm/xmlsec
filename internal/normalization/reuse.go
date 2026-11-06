package normalization

import (
	"bytes"
	"context"
	"strings"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"
)

// Normalizer reuses bounded scratch storage across independent text runs, such
// as runs separated by character-map replacements. Its zero value is ready to
// use. It must not be used concurrently; emitted strings remain owned by callers.
type Normalizer struct {
	iterator *norm.Iter
	buffer   []byte
}

// Each has Form.Each's exact normalization and cancellation semantics. Every
// call starts a fresh normalization boundary, preserving mapped text verbatim.
func (n *Normalizer) Each(ctx context.Context, form Form, s string, emit func(string) error) error {
	defer func() {
		if n.iterator != nil {
			// Iter holds a slice of its source. Keep scratch storage reusable
			// without pinning a larger backing string after the call returns.
			*n.iterator = norm.Iter{}
		}
	}()

	return form.segments(ctx, s, func(source string) error {
		if len(source) > segmentChunkBytes+utf8.UTFMax {
			result, err := form.longSegment(ctx, source)
			if err != nil {
				return err
			}

			return emit(result)
		}

		// Use the same normalized-prefix boundary as Form.String. Iterating
		// already normalized ASCII one rune at a time is much more expensive.
		prefix := norm.Form(form).QuickSpanString(source)
		if prefix == len(source) {
			return emit(source)
		}

		if n.iterator == nil {
			n.iterator = &norm.Iter{}
		}

		n.iterator.InitString(norm.Form(form), source[prefix:])

		n.buffer = append(n.buffer[:0], source[:prefix]...)
		for !n.iterator.Done() {
			n.buffer = append(n.buffer, n.iterator.Next()...)
		}

		if bytes.Count(n.buffer, []byte(combiningGraphemeJoiner)) != strings.Count(source, combiningGraphemeJoiner) {
			result, err := form.longSegment(ctx, source)
			if err != nil {
				return err
			}

			return emit(result)
		}

		if string(n.buffer) == source {
			return emit(source)
		}

		return emit(string(n.buffer))
	})
}
