// Derived from lestrrat-go/helium at 7362c0a70122a757780f4d0b545a9b370dead6ab.
// Copyright (c) 2015 lestrrat. MIT License; see licenses/MIT-helium.txt at the repository root.

package encoding

// Fixed-width decoders can replace malformed input with U+FFFD without an
// error. Validate consumed source units because the decoded replacement is
// indistinguishable from a genuinely encoded U+FFFD, which XML permits.
// Validation retains incomplete units across calls and resolves a leading BOM
// before interpreting units; without a BOM it uses the decoder's default order.

import (
	"errors"

	enc "golang.org/x/text/encoding"
	"golang.org/x/text/transform"
)

// ErrInvalidEncodedChar is returned when the source contains malformed input
// that the base decoder would otherwise silently replace with U+FFFD (for
// example an unpaired UTF-16 surrogate or an out-of-range UTF-32 scalar).
var ErrInvalidEncodedChar = errors.New("encoding: malformed input substituted with U+FFFD")

// byteOrder maps each big-endian scalar byte position to its source index.
// For example, UTF-16LE uses {1, 0}.
type byteOrder string

const (
	orderBE2  byteOrder = "\x00\x01"
	orderLE2  byteOrder = "\x01\x00"
	orderBE4  byteOrder = "\x00\x01\x02\x03"
	orderLE4  byteOrder = "\x03\x02\x01\x00"
	order2143 byteOrder = "\x01\x00\x03\x02"
	order3412 byteOrder = "\x02\x03\x00\x01"
)

// scalar reads a code unit of at least len(o) bytes.
func (o byteOrder) scalar(unit []byte) uint32 {
	var v uint32
	for _, idx := range o {
		v = v<<8 | uint32(unit[idx])
	}

	return v
}

// withStrictDecode rejects malformed fixed-width Unicode input while leaving
// the encoder unchanged. width is the code-unit size in bytes. When useBOM is
// true, a leading BOM overrides order; otherwise order must match the decoder.
func withStrictDecode(e enc.Encoding, width int, order byteOrder, useBOM bool) enc.Encoding {
	return &strictEncoding{Encoding: e, width: width, order: order, useBOM: useBOM}
}

type strictEncoding struct {
	enc.Encoding
	width  int
	order  byteOrder
	useBOM bool
}

func (e *strictEncoding) NewDecoder() *enc.Decoder {
	return &enc.Decoder{Transformer: &strictDecoderTransformer{
		base:   e.Encoding.NewDecoder().Transformer,
		width:  e.width,
		order:  e.order,
		useBOM: e.useBOM,
	}}
}

type unitStatus int

const (
	unitGood       unitStatus = iota // valid; next offset is returned
	unitBad                          // malformed
	unitIncomplete                   // needs more bytes (high surrogate, pair not yet present)
)

// strictDecoderTransformer validates the source units consumed by base.
type strictDecoderTransformer struct {
	base   transform.Transformer
	width  int
	order  byteOrder
	useBOM bool

	// bomResolved records whether the leading BOM has been inspected (UseBOM
	// encodings only). order is fixed once resolved. carry holds source bytes
	// that span Transform calls (a unit straddling a chunk boundary, or a BOM
	// not yet fully seen).
	bomResolved bool
	resolved    byteOrder
	carry       []byte
}

func (t *strictDecoderTransformer) Reset() {
	t.base.Reset()
	t.bomResolved = false
	t.resolved = ""
	t.carry = t.carry[:0]
}

func (t *strictDecoderTransformer) Transform(dst, src []byte, atEOF bool) (nDst, nSrc int, err error) {
	nDst, nSrc, err = t.base.Transform(dst, src, atEOF)
	if err != nil && err != transform.ErrShortSrc && err != transform.ErrShortDst {
		return nDst, nSrc, err
	}

	// Validate exactly the bytes the base decoder consumed this call. Carry over
	// any partial trailing unit so it is validated once the rest arrives.
	if verr := t.validate(src[:nSrc], atEOF); verr != nil {
		return nDst, nSrc, verr
	}

	return nDst, nSrc, err
}

// validate walks the freshly-consumed source bytes (combined with any carry
// from a previous call) one code unit at a time in the resolved byte order and
// returns ErrInvalidEncodedChar on the first malformed unit. Bytes that do not
// yet form a complete unit are buffered in carry; at EOF an incomplete trailing
// unit is malformed.
func (t *strictDecoderTransformer) validate(src []byte, atEOF bool) error {
	buf := src
	if len(t.carry) > 0 {
		buf = append(append([]byte{}, t.carry...), src...)
	}

	t.carry = t.carry[:0]

	order := t.order
	off := 0

	if t.useBOM {
		// Resolve big- vs little-endian from a leading BOM. An actual BOM is
		// consumed by the decoder and skipped from validation; absent a BOM the
		// decoder falls back to its configured default order (t.order) and the
		// first unit is real content, so it must be validated from offset 0.
		if !t.bomResolved {
			if len(buf) < t.width {
				if atEOF {
					// Fewer than a full unit before EOF: malformed trailing bytes
					// (an empty stream is fine — no bytes to validate).
					if len(buf) > 0 {
						return ErrInvalidEncodedChar
					}

					return nil
				}

				t.carry = append(t.carry, buf...)

				return nil
			}

			resolved, isBOM := t.resolveBOM(buf[:t.width])
			t.resolved = resolved

			t.bomResolved = true
			if isBOM {
				off = t.width // skip the BOM unit
			}
		}

		order = t.resolved
	}

	for off+t.width <= len(buf) {
		next, status := t.unitOK(buf, off, order)
		switch status {
		case unitBad:
			return ErrInvalidEncodedChar
		case unitIncomplete:
			// A high surrogate whose low half has not arrived yet. Before EOF,
			// buffer the surrogate (and any trailing partial unit) for the next
			// call; at EOF it is an unpaired surrogate and therefore malformed.
			if atEOF {
				return ErrInvalidEncodedChar
			}

			t.carry = append(t.carry, buf[off:]...)

			return nil
		}

		off = next
	}

	// Leftover bytes that do not fill a unit.
	if off < len(buf) {
		if atEOF {
			return ErrInvalidEncodedChar
		}

		t.carry = append(t.carry, buf[off:]...)
	}

	return nil
}

// resolveBOM inspects the leading unit. If it is an actual byte-order mark it
// returns the order it selects and true (the caller skips it). Otherwise it
// returns the configured default order (t.order) and false: there is no BOM, so
// the decoder uses its default endianness and the first unit is real content
// that must be validated. The default matches x/text's UseBOM fallback, which
// keeps the encoding's configured endianness when no BOM is present.
func (t *strictDecoderTransformer) resolveBOM(bom []byte) (byteOrder, bool) {
	if t.width == 2 {
		// LE BOM: FF FE. BE BOM: FE FF.
		if bom[0] == 0xFF && bom[1] == 0xFE {
			return orderLE2, true
		}

		if bom[0] == 0xFE && bom[1] == 0xFF {
			return orderBE2, true
		}

		return t.order, false
	}
	// width 4. LE BOM: FF FE 00 00. BE BOM: 00 00 FE FF.
	if bom[0] == 0xFF && bom[1] == 0xFE && bom[2] == 0x00 && bom[3] == 0x00 {
		return orderLE4, true
	}

	if bom[0] == 0x00 && bom[1] == 0x00 && bom[2] == 0xFE && bom[3] == 0xFF {
		return orderBE4, true
	}

	return t.order, false
}

// unitOK validates the code unit at off and returns the offset just past the
// last byte it consumed (a surrogate pair consumes two units) together with a
// status. unitIncomplete is returned for a high surrogate whose low half has
// not arrived yet so the caller can decide based on EOF.
func (t *strictDecoderTransformer) unitOK(buf []byte, off int, order byteOrder) (int, unitStatus) {
	v := order.scalar(buf[off : off+t.width])

	if t.width == 4 {
		if v == 0xFFFD {
			return off + 4, unitGood
		}

		if v > 0x10FFFF || (v >= 0xD800 && v <= 0xDFFF) {
			return off, unitBad
		}

		return off + 4, unitGood
	}

	// width == 2 (UTF-16 / UCS-2).
	switch {
	case v >= 0xD800 && v <= 0xDBFF:
		// High surrogate: must be followed by a low surrogate.
		if off+2*t.width > len(buf) {
			return off, unitIncomplete
		}

		lo := order.scalar(buf[off+t.width : off+2*t.width])
		if lo < 0xDC00 || lo > 0xDFFF {
			return off, unitBad
		}

		return off + 2*t.width, unitGood
	case v >= 0xDC00 && v <= 0xDFFF:
		// Lone low surrogate.
		return off, unitBad
	default:
		// BMP scalar (includes a genuine 0xFFFD).
		return off + t.width, unitGood
	}
}
