// Derived from lestrrat-go/helium at 7362c0a70122a757780f4d0b545a9b370dead6ab.
// Copyright (c) 2015 lestrrat. MIT License; see licenses/MIT-helium.txt at the repository root.

package encoding

// c1fallback.go provides wrappers for single-byte charmap encodings where
// Go's x/text library (following the WHATWG spec) maps bytes 0x80-0x9F to
// U+FFFD instead of C1 control characters U+0080-U+009F.
//
// libxml2 (which uses iconv) follows the IANA/ISO standard where these bytes
// map to the corresponding C1 control code points. Since the RuneCursor in
// github.com/lestrrat-go/strcursor treats U+FFFD (== utf8.RuneError) as a
// decode failure, we need to avoid emitting U+FFFD for these bytes.
//
// This file provides:
// - c1Encoding: wraps an enc.Encoding to add C1 fallback support
// - c1DecoderTransformer: wraps a decoder Transformer, post-processing its
//   output to replace U+FFFD with the C1 character corresponding to the
//   original byte
// - c1EncoderTransformer: wraps an encoder Transformer, pre-processing its
//   input to reverse the decoder's fallback for otherwise unassigned C1 bytes

import (
	"encoding/binary"
	"unicode/utf8"

	enc "golang.org/x/text/encoding"
	"golang.org/x/text/encoding/charmap"
	"golang.org/x/text/transform"
)

// C1 fallback covers only the unassigned control-code range, not every
// undefined single-byte mapping. The ASCII fast path handles one uint64 word
// in bytes; its mask selects the high bit of each octet.
const (
	c1ControlStart    = 0x80
	c1ControlEnd      = 0x9F
	asciiWordBytes    = 8
	asciiWordHighBits = 0x8080808080808080
)

// c1Encoding wraps a charmap Encoding to provide C1 control character support.
// Unassigned bytes 0x80-0x9F are mapped to/from U+0080-U+009F instead of U+FFFD.
type c1Encoding struct {
	*charmap.Charmap
}

func (e *c1Encoding) NewDecoder() *enc.Decoder {
	return &enc.Decoder{Transformer: &c1DecoderTransformer{
		base: e.Charmap.NewDecoder().Transformer,
	}}
}

func (e *c1Encoding) NewEncoder() *enc.Encoder {
	return &enc.Encoder{Transformer: &c1EncoderTransformer{
		base:    e.Charmap.NewEncoder().Transformer,
		charmap: e.Charmap,
	}}
}

func withC1Fallback(e *charmap.Charmap) enc.Encoding {
	return &c1Encoding{Charmap: e}
}

// c1DecoderTransformer wraps a decoder transformer. After the base decoder
// produces output, it scans for U+FFFD sequences and replaces them with the
// UTF-8 encoding of the original byte value (treating it as a C1 code point).
type c1DecoderTransformer struct {
	base transform.Transformer
	// A decoder owns this scratch across calls. A local array escapes through
	// base.Transform's interface and otherwise allocates per non-ASCII byte.
	decoded [utf8.UTFMax]byte
}

func (t *c1DecoderTransformer) Reset() {
	t.base.Reset()
}

func (t *c1DecoderTransformer) Transform(dst, src []byte, atEOF bool) (nDst, nSrc int, err error) {
	// For single-byte charmap encodings, each source byte produces one
	// Unicode character in UTF-8. We process one byte at a time to maintain
	// the mapping between source bytes and output characters.
	for nSrc < len(src) {
		// Copy a run of ASCII eight bytes at a time: a word with no high bit
		// set holds eight ASCII bytes, each of which the branch below would
		// copy unchanged. A word that does not fit in dst is left to that
		// branch, which reports ErrShortDst after the bytes that fit.
		for len(src)-nSrc >= asciiWordBytes && len(dst)-nDst >= asciiWordBytes {
			w := binary.LittleEndian.Uint64(src[nSrc:])
			if w&asciiWordHighBits != 0 {
				break
			}

			binary.LittleEndian.PutUint64(dst[nDst:], w)

			nSrc += asciiWordBytes
			nDst += asciiWordBytes
		}

		if nSrc >= len(src) {
			break
		}

		b := src[nSrc]

		// ASCII bytes pass through unchanged
		if b < utf8.RuneSelf {
			if nDst >= len(dst) {
				err = transform.ErrShortDst
				return
			}

			dst[nDst] = b
			nDst++
			nSrc++

			continue
		}

		written, consumed, decodeErr := t.decodeByte(dst[nDst:], src[nSrc:nSrc+1], atEOF && nSrc+1 == len(src))
		nDst += written

		nSrc += consumed
		if decodeErr != nil {
			return nDst, nSrc, decodeErr
		}
	}

	return
}

func (t *c1DecoderTransformer) decodeByte(dst, src []byte, atEOF bool) (int, int, error) {
	decoded := t.decoded[:]
	written, consumed, err := t.base.Transform(decoded, src, atEOF)

	fallback := consumed == 0

	replacement := written == len(replacementUTF8) && decoded[0] == replacementUTF8[0] && decoded[1] == replacementUTF8[1] && decoded[2] == replacementUTF8[2]
	if src[0] <= c1ControlEnd {
		// C1 bytes use their own code points when the base decoder has no mapping.
		fallback = fallback || replacement
	} else if replacement {
		// Outside C1, the replacement denotes an undefined source octet.
		return 0, 0, ErrInvalidEncodedChar
	} else if fallback && (err == transform.ErrShortDst || err == transform.ErrShortSrc) { //nolint:errorlint // Only exact transform retry sentinels permit conversion to continue.
		// Only the Transformer's exact retry signals request more input/output space.
		return 0, 0, err
	}

	if fallback {
		written = utf8.EncodeRune(decoded[:], rune(src[0]))

		if consumed == 0 {
			consumed = 1
		}
	}

	if written > len(dst) {
		return 0, 0, transform.ErrShortDst
	}

	copy(dst, decoded[:written])

	return written, consumed, nil
}

// c1EncoderTransformer wraps an encoder transformer. It handles C1 control
// characters (U+0080-U+009F) by reversing the decoder's fallback for unassigned
// bytes. Characters with an existing mapping stay with the base encoder.
type c1EncoderTransformer struct {
	base    transform.Transformer
	charmap *charmap.Charmap
}

func (t *c1EncoderTransformer) Reset() {
	t.base.Reset()
}

func (t *c1EncoderTransformer) Transform(dst, src []byte, atEOF bool) (nDst, nSrc int, err error) {
	for nSrc < len(src) {
		// Decode the next rune from the UTF-8 source
		if src[nSrc] < utf8.RuneSelf {
			// ASCII byte - pass through to base encoder
			if nDst >= len(dst) {
				err = transform.ErrShortDst
				return
			}

			dst[nDst] = src[nSrc]
			nDst++
			nSrc++

			continue
		}

		r, size := utf8.DecodeRune(src[nSrc:])
		if r == utf8.RuneError && size <= malformedUTF8Width {
			if !atEOF && !utf8.FullRune(src[nSrc:]) {
				err = transform.ErrShortSrc
				return
			}
			// Invalid UTF-8, pass through to base encoder to handle
			nd, ns, eerr := t.base.Transform(dst[nDst:], src[nSrc:nSrc+1], atEOF && nSrc+1 == len(src))
			nDst += nd
			nSrc += ns

			if eerr != nil {
				err = eerr
				return
			}

			continue
		}

		// Add only missing C1 mappings. An already assigned byte (for example
		// Windows-1252's 0x80 for U+20AC) must retain its original character;
		// writing U+0080 there would silently change it on the next decode.
		if r >= c1ControlStart && r <= c1ControlEnd && t.charmap.DecodeByte(byte(r)) == utf8.RuneError {
			if nDst >= len(dst) {
				err = transform.ErrShortDst
				return
			}

			dst[nDst] = byte(r)
			nDst++
			nSrc += size

			continue
		}

		// For all other runes, use the base encoder
		nd, ns, eerr := t.base.Transform(dst[nDst:], src[nSrc:nSrc+size], atEOF && nSrc+size >= len(src))
		nDst += nd
		nSrc += ns

		if eerr != nil {
			err = eerr
			return
		}
	}

	return
}
