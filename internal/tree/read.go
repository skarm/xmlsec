package tree

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strings"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/skarm/xmlsec/internal/nilcheck"
	"github.com/skarm/xmlsec/internal/streamio"
	"github.com/skarm/xmlsec/internal/xmlchar"

	"golang.org/x/text/encoding/charmap"
	"golang.org/x/text/encoding/ianaindex"
)

// ParseReader constructs a snapshot incrementally, without retaining source XML.
// The snapshot itself occupies memory proportional to its nodes and text.
func ParseReader(ctx context.Context, src io.Reader, limits Limits) (*Document, error) {
	return parseXMLReader(ctx, src, limits, false, false)
}

// ParseReaderWithSingleByteEncodings additionally accepts declared, ASCII-
// compatible IANA single-byte encodings. The DTD-free grammar and limits remain.
func ParseReaderWithSingleByteEncodings(ctx context.Context, src io.Reader, limits Limits) (*Document, error) {
	return parseXMLReader(ctx, src, limits, false, true)
}

// ParseText parses Unicode characters. A declaration's encoding has no effect
// on characters already decoded by the caller, but its grammar is still checked.
func ParseText(ctx context.Context, text string, limits Limits) (*Document, error) {
	return parseXMLReader(ctx, strings.NewReader(text), limits, true, false)
}

func parseXMLReader(ctx context.Context, src io.Reader, limits Limits, characterInput, singleByteEncodings bool) (*Document, error) {
	parser, err := newDocumentReader(ctx, src, limits, characterInput, singleByteEncodings)
	if err != nil {
		return nil, err
	}

	doc, err := parser.parse(ctx)
	if err != nil {
		return nil, err
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	doc.inputBytes = int(max(parser.input.source.ReadBytes, parser.input.decoded))

	return doc, nil
}

// CheckXMLProlog validates XML through the first complete element start tag.
// It uses the document parser's encoding, namespace, DTD and resource policy.
func CheckXMLProlog(ctx context.Context, src io.Reader, limits Limits, singleByteEncodings bool) error {
	parser, err := newDocumentReader(ctx, src, limits, false, singleByteEncodings)
	if err != nil {
		return err
	}

	parser.stopAtRoot = true
	_, err = parser.parse(ctx)

	return err
}

func newDocumentReader(ctx context.Context, src io.Reader, limits Limits, characterInput, singleByteEncodings bool) (documentParser, error) {
	if ctx == nil || nilcheck.IsNil(src) {
		return documentParser{}, ErrMalformed
	}

	if err := limits.Validate(); err != nil {
		return documentParser{}, err
	}

	input, err := newXMLInputMode(ctx, src, int64(limits.MaxBytes), limits.MaxBytes, characterInput)
	if err != nil {
		return documentParser{}, err
	}

	parser := readerParser(input, limits)
	parser.characterInput = characterInput
	parser.singleByteEncodings = singleByteEncodings

	return parser, nil
}

func readerParser(input *xmlInput, limits Limits) documentParser {
	return documentParser{doc: &Document{limits: limits}, decoder: &xmlTokenizer{input: input}, encoding: input.encoding, input: input, scope: newNamespaceContext(nil)}
}

// xmlInput validates and normalizes one bounded lexical unit at a time.
// The document parser copies borrowed token values before the unit buffer is reused.
type xmlInput struct {
	charmap          *charmap.Charmap
	order            binary.ByteOrder
	source           *streamio.Reader
	reader           *bufio.Reader
	encoding         sourceEncoding
	unit             []byte
	decoded, maximum int64
	tokenLimit       int
	lineBreaks       uint64
	tokenLine        uint64
	textTailLen      int
	pending          rune
	textTail         [2]byte
	hasPending       bool
	outside          bool
	ascii            bool
}

func newXMLInput(ctx context.Context, src io.Reader, maximum int64, tokenLimit int) (*xmlInput, error) {
	return newXMLInputMode(ctx, src, maximum, tokenLimit, false)
}

func newXMLInputMode(ctx context.Context, src io.Reader, maximum int64, tokenLimit int, characterInput bool) (*xmlInput, error) {
	source := &streamio.Reader{Context: ctx, Source: src, Limit: maximum, LimitError: ErrLimit}
	r := &xmlInput{source: source, reader: bufio.NewReaderSize(source, 4096), encoding: sourceEncoding{name: nameUTF8}, maximum: maximum, tokenLimit: tokenLimit}

	prefix, err := r.reader.Peek(4)
	if err != nil && err != io.EOF {
		return nil, err
	}

	skip := 0

	switch {
	case bytes.HasPrefix(prefix, []byte{0xef, 0xbb, 0xbf}):
		r.encoding.bom = true
		skip = 3
	case characterInput:
		// NUL-containing strings must fail XML character validation rather than
		// being reinterpreted as UTF-16/32 octets.
	case bytes.HasPrefix(prefix, []byte{0, 0, 0xfe, 0xff}), bytes.HasPrefix(prefix, []byte{0xff, 0xfe, 0, 0}):
		return nil, ErrUnsupported
	case bytes.HasPrefix(prefix, []byte{0xfe, 0xff}):
		r.encoding = sourceEncoding{encodingUTF16BE, true}
		r.order = binary.BigEndian
		skip = 2
	case bytes.HasPrefix(prefix, []byte{0xff, 0xfe}):
		r.encoding = sourceEncoding{encodingUTF16LE, true}
		r.order = binary.LittleEndian
		skip = 2
	case bytes.HasPrefix(prefix, []byte{0, '<', 0, '?'}):
		r.encoding.name = encodingUTF16BE
		r.order = binary.BigEndian
	case bytes.HasPrefix(prefix, []byte{'<', 0, '?', 0}):
		r.encoding.name = encodingUTF16LE
		r.order = binary.LittleEndian
	}

	if skip > 0 {
		if _, err := r.reader.Discard(skip); err != nil {
			return nil, err
		}
	}

	return r, nil
}

func (r *xmlInput) rune() (rune, error) {
	if r.hasPending {
		r.hasPending = false
		return r.pending, nil
	}

	value, err := r.encodedRune()
	if err != nil {
		return 0, err
	}

	if !xmlchar.IsChar(value) {
		return 0, fmt.Errorf("%w: invalid XML character", ErrMalformed)
	}

	size := int64(utf8.RuneLen(value))
	if size > r.maximum-r.decoded {
		return 0, ErrLimit
	}

	r.decoded += size

	return value, nil
}

func (r *xmlInput) encodedRune() (rune, error) {
	if r.charmap != nil || r.ascii {
		return r.singleByteRune()
	}

	if r.order != nil {
		return r.utf16Rune()
	}

	value, size, err := r.reader.ReadRune()
	if err != nil {
		return 0, err
	}

	if value == utf8.RuneError && size == 1 {
		return 0, fmt.Errorf("%w: invalid UTF-8", ErrUnsupported)
	}

	return value, nil
}

func (r *xmlInput) singleByteRune() (rune, error) {
	b, err := r.reader.ReadByte()
	if err != nil {
		return 0, err
	}

	value := rune(b)
	if r.charmap != nil {
		value = r.charmap.DecodeByte(b)
	}

	if r.ascii && b > 127 || value == utf8.RuneError {
		return 0, fmt.Errorf("%w: invalid byte in declared XML encoding", ErrMalformed)
	}

	return value, nil
}

func (r *xmlInput) utf16Rune() (rune, error) {
	var pair [2]byte
	if _, err := io.ReadFull(r.reader, pair[:]); err != nil {
		if err == io.EOF {
			return 0, err
		}

		return 0, fmt.Errorf("%w: UTF-16 unit: %w", ErrMalformed, err)
	}

	u := r.order.Uint16(pair[:])
	if !utf16.IsSurrogate(rune(u)) {
		return rune(u), nil
	}

	if u < 0xd800 || u > 0xdbff {
		return 0, fmt.Errorf("%w: UTF-16 surrogate", ErrMalformed)
	}

	if _, err := io.ReadFull(r.reader, pair[:]); err != nil {
		return 0, fmt.Errorf("%w: UTF-16 surrogate: %w", ErrMalformed, err)
	}

	v := r.order.Uint16(pair[:])
	if v < 0xdc00 || v > 0xdfff {
		return 0, fmt.Errorf("%w: UTF-16 surrogate", ErrMalformed)
	}

	return utf16.DecodeRune(rune(u), rune(v)), nil
}

func (r *xmlInput) singleByteEncoding(label string) error {
	codec, err := ianaindex.IANA.Encoding(label)
	if err != nil || codec == nil {
		return fmt.Errorf("%w: unknown XML encoding", ErrUnsupported)
	}

	canonical, err := ianaindex.IANA.Name(codec)
	if err == nil && canonical == "US-ASCII" {
		r.ascii = true
		return nil
	}

	mapping, ok := codec.(*charmap.Charmap)
	if !ok {
		return fmt.Errorf("%w: XML encoding is not a supported single-byte encoding", ErrUnsupported)
	}

	for b := range 128 {
		if mapping.DecodeByte(byte(b)) != rune(b) {
			return fmt.Errorf("%w: XML encoding is not ASCII-compatible", ErrUnsupported)
		}
	}

	r.charmap = mapping

	return nil
}

func (r *xmlInput) nextUnit() ([]byte, error) {
	r.tokenLine = r.lineBreaks + 1

	first, err := r.rune()
	if err != nil {
		return nil, err
	}

	unit := utf8.AppendRune(r.unit[:0], first)
	markup := first == '<'
	quote := rune(0)
	inReference := first == '&'

	for {
		if len(unit) > r.tokenLimit {
			return nil, fmt.Errorf("%w: XML token bytes", ErrLimit)
		}

		complete, err := lexicalUnitComplete(unit, markup, quote, inReference)
		if err != nil {
			return nil, err
		}

		if complete {
			break
		}

		value, e := r.rune()
		if errors.Is(e, io.EOF) && !markup {
			break
		}

		if errors.Is(e, io.EOF) {
			return nil, fmt.Errorf("%w: unterminated XML token", ErrMalformed)
		}

		if e != nil {
			return nil, e
		}

		if !markup && value == '<' {
			r.pending = value
			r.hasPending = true

			break
		}

		if markup {
			quote = lexicalQuote(unit, value, quote)
		} else if value == '&' {
			inReference = true
		} else if value == ';' {
			inReference = false
		}

		unit = utf8.AppendRune(unit, value)
	}

	if r.outside && (!markup && !IsXMLSpace(string(unit)) || bytes.HasPrefix(unit, []byte("<![CDATA["))) {
		return nil, fmt.Errorf("%w: content outside root", ErrMalformed)
	}

	if !markup {
		var boundary [4]byte

		n := copy(boundary[:], r.textTail[:r.textTailLen])

		n += copy(boundary[n:], unit[:min(len(unit), 2)])
		if bytes.Contains(boundary[:n], []byte("]]>")) {
			return nil, fmt.Errorf("%w: CDATA terminator in text", ErrMalformed)
		}

		r.textTailLen = copy(r.textTail[:], unit[max(0, len(unit)-2):])
	} else {
		r.textTailLen = 0
	}

	// Count source line endings before lexical normalization rewrites attribute
	// whitespace and CDATA. Units cannot split a CR/LF pair.
	r.lineBreaks += sourceLineBreaks(unit)

	return normalizeOwnedLexical(unit)
}

func sourceLineBreaks(data []byte) uint64 {
	var count uint64

	for i := 0; i < len(data); i++ {
		switch data[i] {
		case '\r':
			count++

			if i+1 < len(data) && data[i+1] == '\n' {
				i++
			}
		case '\n':
			count++
		}
	}

	return count
}

func lexicalUnitComplete(unit []byte, markup bool, quote rune, inReference bool) (bool, error) {
	if !markup {
		return len(unit) >= 4096 && unit[len(unit)-1] != '\r' && !inReference, nil
	}

	switch {
	case bytes.HasPrefix(unit, []byte("<!--")):
		return len(unit) >= 7 && bytes.HasSuffix(unit, []byte("-->")), nil
	case bytes.HasPrefix(unit, []byte("<![CDATA[")):
		return len(unit) >= 12 && bytes.HasSuffix(unit, []byte("]]>")), nil
	case bytes.HasPrefix(unit, []byte("<?")):
		return len(unit) >= 4 && bytes.HasSuffix(unit, []byte("?>")), nil
	case bytes.HasPrefix(unit, []byte("<!")):
		// Partial declaration openers are accepted only until they can be classified.
		candidate := string(unit)

		comment, cdata := "<!--", "<![CDATA["
		if !strings.HasPrefix(comment, candidate) && !strings.HasPrefix(cdata, candidate) {
			return false, ErrUnsupported
		}

		return false, nil
	default:
		return len(unit) > 1 && quote == 0 && unit[len(unit)-1] == '>', nil
	}
}

func lexicalQuote(unit []byte, value, quote rune) rune {
	if bytes.HasPrefix(unit, []byte("<!")) || bytes.HasPrefix(unit, []byte("<?")) {
		return quote
	}

	if quote != 0 {
		if value == quote {
			return 0
		}

		return quote
	}

	if value == '\'' || value == '"' {
		return value
	}

	return 0
}
