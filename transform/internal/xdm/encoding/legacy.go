package encoding

import (
	"bytes"

	enc "golang.org/x/text/encoding"
	"golang.org/x/text/transform"
)

// Legacy and single-byte wrappers recognize this exact UTF-8 replacement
// sequence. Unicode codecs can represent it genuinely and validate source units.
const replacementUTF8 = "\xef\xbf\xbd"

// DecodeRune reports one consumed byte for malformed, nonempty UTF-8 input.
// Encoders share this discriminator while retaining their existing error path.
const malformedUTF8Width = 1

// These legacy codecs cannot represent U+FFFD. When their decoders emit it,
// they have replaced malformed source bytes; XML and unparsed-text must report
// that failure instead of accepting the substituted text. Unicode codecs can
// represent U+FFFD and require source-unit validation instead (see strict.go).
func withStrictLegacyDecode(codec enc.Encoding) enc.Encoding {
	return strictLegacyEncoding{Encoding: codec}
}

type strictLegacyEncoding struct{ enc.Encoding }

func (e strictLegacyEncoding) NewDecoder() *enc.Decoder {
	return &enc.Decoder{Transformer: strictLegacyDecoder{Transformer: e.Encoding.NewDecoder()}}
}

type strictLegacyDecoder struct{ transform.Transformer }

func (d strictLegacyDecoder) Transform(dst, src []byte, atEOF bool) (int, int, error) {
	nDst, nSrc, err := d.Transformer.Transform(dst, src, atEOF)
	if bytes.Contains(dst[:nDst], []byte(replacementUTF8)) {
		return nDst, nSrc, ErrInvalidEncodedChar
	}

	return nDst, nSrc, err
}
