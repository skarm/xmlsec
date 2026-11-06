package tree

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/skarm/xmlsec/internal/lexicon"
)

// xmlTokenizer consumes already bounded, validated and lexically normalized
// units. Names are checked by the project's Fifth Edition predicates, rather
// than encoding/xml's older name tables. Token pointers and their byte and
// attribute slices borrow storage until the next RawToken call; documentParser
// copies them into owned tree values.
type xmlTokenizer struct {
	input      *xmlInput
	start      xml.StartElement
	end        xml.EndElement
	text       xml.CharData
	comment    xml.Comment
	pi         xml.ProcInst
	offset     int64
	pendingEnd bool
}

func (d *xmlTokenizer) InputOffset() int64 { return d.offset }

func (d *xmlTokenizer) RawToken() (xml.Token, error) {
	// Release borrowed payloads before the next unit can grow its buffer. Only
	// the cleared attribute backing array is kept for reuse across start tags.
	clear(d.start.Attr)
	d.start = xml.StartElement{Attr: d.start.Attr[:0]}
	d.text, d.comment = nil, nil
	d.pi = xml.ProcInst{}

	if d.pendingEnd {
		d.pendingEnd = false

		return &d.end, nil
	}

	d.end = xml.EndElement{}

	unit, err := d.input.nextUnit()
	if err != nil {
		return nil, err
	}

	d.input.unit = unit
	d.offset += int64(len(unit))

	switch {
	case bytes.HasPrefix(unit, []byte(dtdCommentOpen)):
		d.comment = unit[4 : len(unit)-3]
		return &d.comment, nil
	case bytes.HasPrefix(unit, []byte("<![CDATA[")):
		d.text = unit[9 : len(unit)-3]
		return &d.text, nil
	case bytes.HasPrefix(unit, []byte(dtdPIOpen)):
		content := unit[2 : len(unit)-2]

		end := 0
		for end < len(content) && !spaceByte(content[end]) {
			end++
		}

		d.pi = xml.ProcInst{Target: string(content[:end]), Inst: content[lexicalSpaceEnd(content, end):]}

		return &d.pi, nil
	case bytes.HasPrefix(unit, []byte("</")):
		name := bytes.TrimRight(unit[2:len(unit)-1], lexicon.XMLWhitespace)
		d.end = xml.EndElement{Name: tokenName(string(name))}

		return &d.end, nil
	case unit[0] == '<':
		start, empty, err := startToken(unit, d.start.Attr[:0])
		d.start = start

		if err != nil {
			return nil, err
		}

		if empty {
			d.end = xml.EndElement{Name: start.Name}
			d.pendingEnd = true
		}

		return &d.start, nil
	default:
		value, err := tokenValue(unit, false)
		d.text = value

		return &d.text, err
	}
}

func tokenName(value string) xml.Name {
	prefix, local, found := strings.Cut(value, ":")
	if found && prefix != "" {
		return xml.Name{Space: prefix, Local: local}
	}

	return xml.Name{Local: value}
}

// startToken requires a single start tag accepted by normalizeOwnedLexical.
func startToken(unit []byte, attrs []xml.Attr) (xml.StartElement, bool, error) {
	end := 1
	for end < len(unit) && !spaceByte(unit[end]) && unit[end] != '/' && unit[end] != '>' {
		end++
	}

	start := xml.StartElement{Name: tokenName(string(unit[1:end])), Attr: attrs}

	empty := unit[len(unit)-2] == '/'
	for at := lexicalSpaceEnd(unit, end); at < len(unit)-1 && unit[at] != '/' && unit[at] != '>'; {
		end = at
		for end < len(unit) && !spaceByte(unit[end]) && unit[end] != '=' {
			end++
		}

		name := tokenName(string(unit[at:end]))
		at = lexicalSpaceEnd(unit, end)
		at = lexicalSpaceEnd(unit, at+1) // '=' was checked by normalizeAttribute.
		quote := unit[at]
		at++
		end = at + bytes.IndexByte(unit[at:], quote)

		value, err := tokenValue(unit[at:end], true)
		if err != nil {
			return xml.StartElement{}, false, err
		}

		start.Attr = append(start.Attr, xml.Attr{Name: name, Value: string(value)})
		at = lexicalSpaceEnd(unit, end+1)
	}

	return start, empty, nil
}

// tokenValue expands only XML's predefined entities and character references.
// Literal whitespace has already been normalized; referenced whitespace is kept.
// Expansion reuses private lexical storage: every reference is at least as long
// as its decoded UTF-8 value, so writes cannot overtake unread source bytes.
func tokenValue(value []byte, attribute bool) ([]byte, error) {
	if attribute && bytes.IndexByte(value, '<') >= 0 {
		return nil, fmt.Errorf("%w: '<' in attribute", ErrMalformed)
	}

	if bytes.IndexByte(value, '&') < 0 {
		return value, nil
	}

	out := value[:0]
	for len(value) > 0 {
		at := bytes.IndexByte(value, '&')
		if at < 0 {
			out = append(out, value...)
			break
		}

		out = append(out, value[:at]...)
		value = value[at+1:]

		end := bytes.IndexByte(value, ';')
		if end < 0 {
			return nil, fmt.Errorf("%w: unterminated entity", ErrMalformed)
		}

		entity := string(value[:end])

		var r rune

		switch entity {
		case entityAmp:
			r = '&'
		case entityLt:
			r = '<'
		case entityGt:
			r = '>'
		case entityApos:
			r = '\''
		case entityQuot:
			r = '"'
		default:
			if !strings.HasPrefix(entity, "#") {
				return nil, fmt.Errorf("%w: unknown entity", ErrMalformed)
			}

			digits, base := entity[1:], 10
			if strings.HasPrefix(digits, "x") {
				digits, base = digits[1:], 16
			}

			n, err := strconv.ParseUint(digits, base, 32)
			if err != nil || n > utf8.MaxRune {
				return nil, fmt.Errorf("%w: character reference", ErrMalformed)
			}

			r = rune(n) // validateCharReference checked the XML character range.
		}

		out = utf8.AppendRune(out, r)
		value = value[end+1:]
	}

	return out, nil
}
