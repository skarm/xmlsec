package xslt

import (
	"context"
	"io"
	"math"
	"strings"
	"unicode/utf8"

	"golang.org/x/text/encoding"
	"golang.org/x/text/encoding/htmlindex"
	textunicode "golang.org/x/text/encoding/unicode"
	texttransform "golang.org/x/text/transform"

	"github.com/skarm/xmlsec/internal/lexicon"
	"github.com/skarm/xmlsec/internal/streamio"
	xdmencoding "github.com/skarm/xmlsec/transform/internal/xdm/encoding"
	"github.com/skarm/xmlsec/transform/internal/xpath"
)

// encodedOutput keeps encoder state across chunks and never closes dst.
func encodedOutput(ctx context.Context, dst io.Writer, definition *OutputDef) (io.Writer, func() error, error) {
	const (
		outputEncodingASCII   = "ascii"
		outputEncodingUTF16BE = "utf-16be"
		outputEncodingUTF16LE = "utf-16le"
	)

	name := strings.ToLower(definition.Encoding)

	var (
		encoder *encoding.Encoder
		bom     []byte
	)

	switch name {
	case "", lexicon.EncodingUTF8, lexicon.EncodingUTF8Alt:
		if definition.ByteOrderMark {
			bom = []byte(lexicon.BOMUTF8)
		}
	case lexicon.EncodingUTF16, nameUTF16:
		encoder = textunicode.UTF16(textunicode.BigEndian, textunicode.IgnoreBOM).NewEncoder()
		bom = []byte(lexicon.BOMUTF16BE)
	case outputEncodingUTF16BE:
		encoder = textunicode.UTF16(textunicode.BigEndian, textunicode.IgnoreBOM).NewEncoder()

		if definition.ByteOrderMark {
			bom = []byte(lexicon.BOMUTF16BE)
		}
	case outputEncodingUTF16LE:
		encoder = textunicode.UTF16(textunicode.LittleEndian, textunicode.IgnoreBOM).NewEncoder()

		if definition.ByteOrderMark {
			bom = []byte(lexicon.BOMUTF16LE)
		}
	case outputEncodingASCII, encodingASCII:
		encoder = &encoding.Encoder{Transformer: asciiEncoder{}}
		definition.canEncode = func(r rune) bool { return r < utf8.RuneSelf }
	default:
		codec, err := htmlindex.Get(name)
		if err != nil {
			return nil, nil, dynamicError(errCodeSESU0007, "unsupported output encoding %q", definition.Encoding)
		}

		encoder = codec.NewEncoder()

		definition.canEncode = xdmencoding.Repertoire(codec.NewEncoder())
	}

	if len(bom) > 0 {
		if err := writeFullBytes(dst, bom); err != nil {
			return nil, nil, err
		}
	}

	if encoder == nil {
		return dst, func() error { return nil }, nil
	}

	writer := texttransform.NewWriter(dst, encoder)

	return &streamio.Writer{Context: ctx, Target: writer, Limit: math.MaxInt64, LimitError: xpath.ErrBudget}, writer.Close, nil
}

type asciiEncoder struct{ texttransform.NopResetter }

func (asciiEncoder) Transform(dst, src []byte, _ bool) (int, int, error) {
	for i, c := range src {
		if c >= utf8.RuneSelf {
			return i, i, dynamicError(lexicon.ErrSERE0008, "character cannot be represented in ASCII")
		}

		if i == len(dst) {
			return i, i, texttransform.ErrShortDst
		}

		dst[i] = c
	}

	return len(src), len(src), nil
}
