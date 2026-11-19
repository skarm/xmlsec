package encoding

import (
	"encoding/binary"
	"unicode/utf16"

	enc "golang.org/x/text/encoding"
	"golang.org/x/text/encoding/unicode"
	"golang.org/x/text/transform"
)

// IANA registers ISO-10646-UCS-2 as the two-octet Basic Multilingual Plane
// in network byte order. Each code unit is a complete character.
type ucs2Encoding struct{}

func (ucs2Encoding) NewDecoder() *enc.Decoder {
	decoder := unicode.UTF16(unicode.BigEndian, unicode.IgnoreBOM).NewDecoder()
	return &enc.Decoder{Transformer: transform.Chain(ucs2Units{}, decoder)}
}

func (ucs2Encoding) NewEncoder() *enc.Encoder {
	encoder := unicode.UTF16(unicode.BigEndian, unicode.IgnoreBOM).NewEncoder()
	return &enc.Encoder{Transformer: transform.Chain(encoder, ucs2Units{})}
}

// ucs2Units copies complete non-surrogate units between a UTF-16BE codec
// and the byte stream. It leaves an incomplete unit for the caller to retry.
type ucs2Units struct{ transform.NopResetter }

func (ucs2Units) Transform(dst, src []byte, atEOF bool) (int, int, error) {
	n := 0
	for len(src)-n >= utf16CodeUnitBytes {
		if utf16.IsSurrogate(rune(binary.BigEndian.Uint16(src[n:]))) {
			return n, n, ErrInvalidEncodedChar
		}

		if len(dst)-n < utf16CodeUnitBytes {
			return n, n, transform.ErrShortDst
		}

		copy(dst[n:n+utf16CodeUnitBytes], src[n:n+utf16CodeUnitBytes])
		n += utf16CodeUnitBytes
	}

	if n < len(src) {
		if atEOF {
			return n, n, ErrInvalidEncodedChar
		}

		return n, n, transform.ErrShortSrc
	}

	return n, n, nil
}
