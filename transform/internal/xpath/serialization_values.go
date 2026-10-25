package xpath

import (
	"context"
	"io"
	"unicode/utf8"

	"github.com/skarm/xmlsec/internal/lexicon"
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
		unit(0, uint16(r))
		return string(data[:6])
	}

	hi, lo := utf16SurrogatePair(r)
	unit(0, hi)
	unit(6, lo)

	return string(data[:])
}
