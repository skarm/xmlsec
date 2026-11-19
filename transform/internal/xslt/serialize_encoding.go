package xslt

import (
	"context"
	"errors"
	"io"
	"math"
	"strings"
	"unicode/utf8"

	"github.com/skarm/xmlsec/internal/lexicon"
	"github.com/skarm/xmlsec/internal/streamio"
	"github.com/skarm/xmlsec/internal/xmlchar"
	xdmencoding "github.com/skarm/xmlsec/transform/internal/xdm/encoding"
	"github.com/skarm/xmlsec/transform/internal/xpath"

	"golang.org/x/text/encoding"
	"golang.org/x/text/encoding/htmlindex"
	textunicode "golang.org/x/text/encoding/unicode"
	texttransform "golang.org/x/text/transform"
)

func validateOutputEncoding(method, name string) error {
	switch strings.ToLower(name) {
	case "", lexicon.EncodingUTF8, lexicon.EncodingUTF8Alt, lexicon.EncodingUTF16, nameUTF16:
		return nil
	default:
		if _, err := htmlindex.Get(name); err != nil {
			return dynamicError(errCodeSESU0007, "unsupported encoding %q for %s output method", name, method)
		}
	}

	// The codec registry accepts padding under WHATWG rules, whereas XML and
	// XHTML require an XML EncName even if the declaration is omitted.
	if (method == lexicon.MethodXML || method == lexicon.MethodXHTML) && !xmlchar.IsValidEncName(name) {
		return dynamicError(lexicon.ErrSERE0006, "invalid XML encoding name %q", name)
	}

	return nil
}

// encodedOutput keeps encoder state across chunks and never closes dst.
func encodedOutput(ctx context.Context, dst io.Writer, definition *OutputDef) (io.Writer, func() error, error) {
	const (
		outputEncodingASCII   = "ascii"
		outputEncodingLatin1  = "iso-8859-1"
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

		// WHATWG maps ISO-8859-1 labels to Windows-1252 for HTML. XML, XHTML,
		// and text use the actual ISO-8859-1 repertoire named by the caller.
		if (definition.Method == lexicon.MethodXML || definition.Method == lexicon.MethodXHTML || definition.Method == lexicon.MethodText) && xdmencoding.IsISO88591(name) {
			codec = xdmencoding.Load(outputEncodingLatin1)
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

	writer := texttransform.NewWriter(dst, outputEncoder{Transformer: encoder, label: definition.Encoding})

	return &streamio.Writer{Context: ctx, Target: writer, Limit: math.MaxInt64, LimitError: xpath.ErrBudget}, writer.Close, nil
}

type outputEncoder struct {
	texttransform.Transformer
	label string
}

func (t outputEncoder) Transform(dst, src []byte, atEOF bool) (int, int, error) {
	nDst, nSrc, err := t.Transformer.Transform(dst, src, atEOF)
	if err == nil || err == texttransform.ErrShortDst || err == texttransform.ErrShortSrc { //nolint:errorlint // Only exact transform retry sentinels can be retried.
		return nDst, nSrc, err
	}

	// x/text's repertoire error type is internal; its replacement byte is
	// also the criterion used by x/text's own encoding wrappers.
	type repertoireError interface {
		error
		Replacement() byte
	}

	if _, ok := errors.AsType[repertoireError](err); ok {
		return nDst, nSrc, dynamicErrorCause(lexicon.ErrSERE0008, err, "character cannot be represented in %q", t.label)
	}

	return nDst, nSrc, err
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
