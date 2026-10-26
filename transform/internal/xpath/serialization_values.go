package xpath

import (
	"context"
	"io"
	"unicode/utf8"

	"github.com/skarm/xmlsec/internal/lexicon"
	"github.com/skarm/xmlsec/transform/internal/xdm"
)

// enterValue bounds recursive JSON/adaptive containers independently of the
// evaluator's own call depth, including values received from an application.
func (opts serializeOptions) enterValue() error {
	ctx := opts.serializationContext()
	if opts.depth > DepthLimit(ctx, 128) {
		return ErrBudget
	}

	return Charge(ctx, 1)
}

// join charges each copied part and delimiter before growing the result.
func (opts serializeOptions) join(open string, parts []string, separator, closeBracket string) (string, error) {
	var buf serializationBuffer

	buf.ctx = opts.serializationContext()
	if _, err := buf.WriteString(open); err != nil {
		return "", err
	}

	for i, part := range parts {
		if i != 0 {
			if _, err := buf.WriteString(separator); err != nil {
				return "", err
			}
		}

		if _, err := buf.WriteString(part); err != nil {
			return "", err
		}
	}

	if _, err := buf.WriteString(closeBracket); err != nil {
		return "", err
	}

	return buf.String(), nil
}

func (opts serializeOptions) jsonComposite(open, closeBracket string, parts []string) (string, error) {
	if !opts.indent || len(parts) == 0 {
		return opts.join(open, parts, ",", closeBracket)
	}

	return opts.join(open+"\n  ", parts, ",\n  ", "\n"+closeBracket)
}

// characterRuns chooses mappings on the original characters, normalizes only
// unmapped runs and emits replacement strings verbatim without buffering their
// potentially much larger concatenation.
func (opts serializeOptions) characterRuns(value string, plain, mapped func(string) error) error {
	ctx := opts.serializationContext()
	if err := Charge(ctx, 1+len(value)/64); err != nil {
		return err
	}

	form, normalize := serializeCharMapNorm(opts)

	emit := func(run string) error {
		if normalize {
			return form.Each(ctx, run, plain)
		}

		return plain(run)
	}
	if len(opts.charMap) == 0 {
		return emit(value)
	}

	start := 0

	for offset, r := range value {
		replacement, ok := opts.charMap[r]
		if !ok {
			continue
		}

		if err := emit(value[start:offset]); err != nil {
			return err
		}

		if err := mapped(replacement); err != nil {
			return err
		}

		start = offset + utf8.RuneLen(r)
	}

	return emit(value[start:])
}

// SerializeTextValue shares bounded character expansion with item serializers.
func SerializeTextValue(ctx context.Context, value string, charMap map[rune]string, form string) (string, error) {
	opts := serializeOptions{ctx: ctx, method: lexicon.MethodText, charMap: charMap, normalizationForm: form}
	if len(charMap) == 0 {
		return applySerializeNormalization(value, opts)
	}

	return applyCharMapToString(value, opts)
}

// WriteJSONString applies JSON character expansion directly to the destination.
// Character-map replacements cannot force an unbounded intermediate string.
func WriteJSONString(ctx context.Context, dst io.Writer, value string, charMap map[rune]string, normalizationForm string, canEncode func(rune) bool) error {
	opts := serializeOptions{ctx: ctx, method: lexicon.MethodJSON, charMap: charMap, normalizationForm: normalizationForm}

	if err := writeSerializationString(dst, `"`); err != nil {
		return err
	}

	err := opts.characterRuns(value, func(run string) error {
		return writeSerializedJSONRun(ctx, dst, run, canEncode)
	}, func(replacement string) error { return writeSerializationString(dst, replacement) })
	if err != nil {
		return err
	}

	return writeSerializationString(dst, `"`)
}

// WriteJSONNode fuses XML node serialization with JSON escaping when character
// expansion needs no cross-write state. Other node methods and mapped/normalized
// values retain their established value-local expansion path.
func WriteJSONNode(ctx context.Context, dst io.Writer, value xdm.NodeItem, method string, charMap map[rune]string, normalizationForm string, canEncode func(rune) bool) error {
	if method != "" && method != lexicon.MethodXML || len(charMap) != 0 || serializeNormalizationActive(normalizationForm) {
		text, err := SerializeNodeForJSON(ctx, value, method)
		if err != nil {
			return err
		}

		return WriteJSONString(ctx, dst, text, charMap, normalizationForm, canEncode)
	}

	opts := serializeOptions{ctx: ctx, method: lexicon.MethodXML, omitXMLDeclaration: true, standalone: lexicon.ValueOmit, includeContentType: true, escapeURIAttributes: true}
	if err := opts.validate(); err != nil {
		return err
	}

	if err := writeSerializationString(dst, `"`); err != nil {
		return err
	}

	escaped := jsonNodeWriter{ctx: ctx, dst: dst, canEncode: canEncode}
	if err := writeXMLSequence(xdm.ItemSlice{value}, opts, &escaped); err != nil {
		return err
	}

	if escaped.tailSize != 0 {
		return io.ErrUnexpectedEOF
	}

	return writeSerializationString(dst, `"`)
}

// Keep normalization out of markup and character-map replacement strings.
func normalizeSerializedValue(value string, opts serializeOptions) (string, error) {
	form, normalize := serializeNormForm(opts.normalizationForm)
	if !normalize || !opts.methodAppliesNormalization() {
		return value, nil
	}

	ctx := opts.serializationContext()
	if err := Charge(ctx, 1+len(value)/64); err != nil {
		return "", err
	}

	var buf serializationBuffer

	buf.ctx = ctx
	err := form.Each(ctx, value, func(part string) error { _, err := buf.WriteString(part); return err })

	return buf.String(), err
}

func writeSerializationString(dst io.Writer, value string) error {
	n, err := io.WriteString(dst, value)
	if err == nil && n != len(value) {
		return io.ErrShortWrite
	}

	return err
}

func writeSerializedJSONRun(ctx context.Context, dst io.Writer, run string, canEncode func(rune) bool) error {
	if err := Charge(ctx, 1+len(run)/64); err != nil {
		return err
	}

	start := 0

	for offset, r := range run {
		escaped := serializedJSONRune(r, canEncode)
		if escaped == "" {
			continue
		}

		if err := writeSerializationString(dst, run[start:offset]); err != nil {
			return err
		}

		if err := writeSerializationString(dst, escaped); err != nil {
			return err
		}

		start = offset + utf8.RuneLen(r)
	}

	return writeSerializationString(dst, run[start:])
}

func serializedJSONRune(r rune, canEncode func(rune) bool) string {
	switch r {
	case '"':
		return `\"`
	case '\\':
		return `\\`
	case '/':
		return `\/`
	case '\b':
		return `\b`
	case '\f':
		return `\f`
	case '\n':
		return `\n`
	case '\r':
		return `\r`
	case '\t':
		return `\t`
	}

	if r >= 0x20 && !(r >= 0x7F && r <= 0x9F) && isValidXMLCodepoint(int(r)) && (canEncode == nil || canEncode(r)) {
		return ""
	}

	var data [12]byte

	unit := func(offset int, value uint16) {
		data[offset], data[offset+1] = '\\', 'u'
		for i := range 4 {
			data[offset+2+i] = jsonHexUpper[(value>>uint(12-i*4))&15]
		}
	}
	if r <= 0xFFFF {
		unit(0, uint16(r)) // #nosec G115 -- r is a decoded Unicode rune and this branch restricts it to the BMP.
		return string(data[:6])
	}

	hi, lo := utf16SurrogatePair(r)
	unit(0, hi)
	unit(6, lo)

	return string(data[:])
}

type jsonNodeWriter struct {
	ctx       context.Context
	dst       io.Writer
	canEncode func(rune) bool
	tail      [utf8.UTFMax]byte
	tailSize  int
}

func (w *jsonNodeWriter) Write(p []byte) (int, error) {
	if err := ChargeString(w.ctx, len(p)); err != nil {
		return 0, err
	}
	// Preserve work accounting for the former XML buffer and its two JSON
	// expansion passes. Chunk boundaries may conservatively charge more work.
	if err := Charge(w.ctx, 3+3*(len(p)/64)); err != nil {
		return 0, err
	}

	offset := 0
	if w.tailSize != 0 {
		for offset < len(p) && !utf8.FullRune(w.tail[:w.tailSize]) {
			w.tail[w.tailSize] = p[offset]
			w.tailSize++
			offset++
		}

		if !utf8.FullRune(w.tail[:w.tailSize]) {
			return len(p), nil
		}

		r, size := utf8.DecodeRune(w.tail[:w.tailSize])
		if r == utf8.RuneError && size == 1 {
			return offset, io.ErrUnexpectedEOF
		}

		if err := w.rune(r, w.tail[:w.tailSize]); err != nil {
			return offset, err
		}

		w.tailSize = 0
	}

	start := offset
	for offset < len(p) {
		r, size := utf8.DecodeRune(p[offset:])
		if r == utf8.RuneError && size == 1 {
			if utf8.FullRune(p[offset:]) {
				return offset, io.ErrUnexpectedEOF
			}

			break
		}

		if replacement := serializedJSONRune(r, w.canEncode); replacement != "" {
			if err := w.bytes(p[start:offset]); err != nil {
				return offset, err
			}

			if err := writeSerializationString(w.dst, replacement); err != nil {
				return offset, err
			}

			start = offset + size
		}

		offset += size
	}

	if err := w.bytes(p[start:offset]); err != nil {
		return offset, err
	}

	w.tailSize = copy(w.tail[:], p[offset:])

	return len(p), nil
}

func (w *jsonNodeWriter) rune(r rune, encoded []byte) error {
	if replacement := serializedJSONRune(r, w.canEncode); replacement != "" {
		return writeSerializationString(w.dst, replacement)
	}

	return w.bytes(encoded)
}

func (w *jsonNodeWriter) bytes(p []byte) error {
	if len(p) == 0 {
		return nil
	}

	n, err := w.dst.Write(p)
	if err == nil && n != len(p) {
		return io.ErrShortWrite
	}

	return err
}
