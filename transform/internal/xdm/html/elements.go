// Derived from lestrrat-go/helium at 7362c0a70122a757780f4d0b545a9b370dead6ab.
// Copyright (c) 2015 lestrrat. MIT License; see licenses/MIT-helium.txt at the repository root.

package html

import "strings"

// HTML element name constants used throughout the html package.
// Extracted to satisfy the goconst linter; these names appear many times
// in the element tables and parseOptions logic below.
const (
	elemBasefont = "basefont"
	elemIsindex  = "isindex"
	elemArea     = "area"
	elemFrame    = "frame"
	elemImg      = "img"
	elemObject   = "object"
	elemData     = "data"
	elemEmbed    = "embed"
	elemInput    = "input"
	elemKeygen   = "keygen"
	elemSource   = "source"
	elemTrack    = "track"
	elemAudio    = "audio"
	elemVideo    = "video"
	elemWbr      = "wbr"
	elemAddress  = "address"
	elemBody     = "body"
	elemCaption  = "caption"
	elemCenter   = "center"
	elemCol      = "col"
	elemColgroup = "colgroup"
	elemDir      = "dir"
	elemDiv      = "div"
	elemFieldset = "fieldset"
	elemFont     = "font"
	elemForm     = "form"
	elemFrameset = "frameset"
	elemHead     = "head"
	elemHTML     = "html"
	elemListing  = "listing"
	elemMenu     = "menu"
	elemPre      = "pre"
	elemTable    = "table"
	elemTbody    = "tbody"
	elemTfoot    = "tfoot"
	elemThead    = "thead"
	elemTitle    = "title"
	elemXmp      = "xmp"
)

// HTML5 named character entity keys that collide with element-name literals.
// These are entity names (e.g. &div; == U+00F7), not HTML element references,
// so they are kept distinct from the elem* constants.
const ()

// LowerASCII folds HTML names without changing non-ASCII code points. Unicode
// lowercasing would turn U+0130 into i and falsely recognize an HTML element.
func LowerASCII(value string) string {
	first := strings.IndexFunc(value, func(r rune) bool { return r >= 'A' && r <= 'Z' })
	if first < 0 {
		return value
	}

	var result strings.Builder
	result.Grow(len(value))
	result.WriteString(value[:first])

	for i := first; i < len(value); i++ {
		c := value[i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}

		result.WriteByte(c)
	}

	return result.String()
}

// EqualFoldASCII compares HTML names/keywords using only ASCII case aliases.
// Unicode SimpleFold would incorrectly recognize U+017F as the s in script.
func EqualFoldASCII(a, b string) bool {
	if len(a) != len(b) {
		return false
	}

	for i := range len(a) {
		x, y := a[i], b[i]
		if x >= 'A' && x <= 'Z' {
			x += 'a' - 'A'
		}

		if y >= 'A' && y <= 'Z' {
			y += 'a' - 'A'
		}

		if x != y {
			return false
		}
	}

	return true
}

// dataMode controls how element content is parsed.
type dataMode int

const (
	dataNormal    dataMode = 0 // normal HTML parsing
	dataRCDATA    dataMode = 1 // RCDATA: entities expanded but no tag parsing (title, textarea)
	dataRawText   dataMode = 2 // raw text: no parsing at all (script, style, iframe, xmp, noembed, noframes)
	dataScript    dataMode = 3 // script: like raw text but with special </script> handling
	dataPlaintext dataMode = 4 // plaintext: raw text until end of file
)

// htmlElemDesc describes an HTML element's parsing behavior.
// Ported from libxml2's html40ElementTable (HTMLparser.c:502).
type htmlElemDesc struct {
	empty    bool
	inline   int
	dataMode dataMode
}

// SerializationVoidElement applies the pinned serializer's HTML empty-element
// tables independently of the broader parser descriptors. For HTML5 this host
// retains basefont, frame and isindex, an explicitly permitted choice.
func SerializationVoidElement(name string, html5 bool, edition int) bool {
	switch LowerASCII(name) {
	case elemArea, "base", "br", elemCol, "hr", elemImg, elemInput, nameLink, "meta", "param", elemBasefont, elemFrame, elemIsindex:
		return true
	case elemEmbed:
		return html5 || edition != 20
	case elemKeygen, elemSource, elemTrack, elemWbr:
		return html5
	default:
		return false
	}
}

// lookupElement returns a descriptor for a case-insensitive HTML element name.
// Elements with the same libxml2 HTML 4.0 parsing behavior share a case; the
// returned descriptor belongs to the caller rather than mutable package state.
func lookupElement(name string) *htmlElemDesc {
	name = LowerASCII(name)
	switch name {
	case "a", "abbr", "acronym", "bdo", "cite", "code", "dfn", "kbd", "label", "q", "samp", "select", nameSpan, "var":
		return &htmlElemDesc{empty: false, inline: 1, dataMode: dataNormal}
	case elemAddress, nameBlockquote, elemCaption, elemDiv, "dl", elemFieldset, elemForm, "h1", "h2", "h3", "h4", "h5", "h6", "legend", "noscript", "ol", "optgroup", elemPre, elemTable, "td", "tr", "ul":
		return &htmlElemDesc{empty: false, inline: 0, dataMode: dataNormal}
	case "applet":
		return &htmlElemDesc{empty: false, inline: 2, dataMode: dataNormal}
	case elemArea, "base", elemCol, "hr", nameLink, "meta", "param":
		return &htmlElemDesc{empty: true, inline: 0, dataMode: dataNormal}
	case "b", nameBig, "em", "i", "nobr", nameSmall, "strong", nameSub, "sup", "tt":
		return &htmlElemDesc{empty: false, inline: 1, dataMode: dataNormal}
	case elemBasefont:
		return &htmlElemDesc{empty: true, inline: 1, dataMode: dataNormal}
	case "bgsound", elemKeygen, elemSource, elemTrack, elemWbr:
		return &htmlElemDesc{empty: true, inline: 0, dataMode: dataNormal}
	case elemBody, elemHead, elemHTML:
		return &htmlElemDesc{empty: false, inline: 0, dataMode: dataNormal}
	case "br", elemImg, elemInput:
		return &htmlElemDesc{empty: true, inline: 1, dataMode: dataNormal}
	case "button", "del", "ins", "map", elemObject:
		return &htmlElemDesc{empty: false, inline: 2, dataMode: dataNormal}
	case elemCenter:
		return &htmlElemDesc{empty: false, inline: 0, dataMode: dataNormal}
	case elemColgroup, "dd", "dt", nameOption, "p", elemTfoot, "th", elemThead:
		return &htmlElemDesc{empty: false, inline: 0, dataMode: dataNormal}
	case elemDir, elemMenu:
		return &htmlElemDesc{empty: false, inline: 0, dataMode: dataNormal}
	case elemEmbed:
		return &htmlElemDesc{empty: true, inline: 1, dataMode: dataNormal}
	case elemFont, "s", nameStrike, "u":
		return &htmlElemDesc{empty: false, inline: 1, dataMode: dataNormal}
	case elemFrame:
		return &htmlElemDesc{empty: true, inline: 0, dataMode: dataNormal}
	case elemFrameset:
		return &htmlElemDesc{empty: false, inline: 0, dataMode: dataNormal}
	case "iframe":
		return &htmlElemDesc{empty: false, inline: 2, dataMode: dataRawText}
	case elemIsindex:
		return &htmlElemDesc{empty: true, inline: 0, dataMode: dataNormal}
	case "li":
		return &htmlElemDesc{empty: false, inline: 0, dataMode: dataNormal}
	case "noembed", nameStyle:
		return &htmlElemDesc{empty: false, inline: 0, dataMode: dataRawText}
	case "noframes":
		return &htmlElemDesc{empty: false, inline: 0, dataMode: dataRawText}
	case "plaintext":
		return &htmlElemDesc{empty: false, inline: 0, dataMode: dataPlaintext}
	case nameScript:
		return &htmlElemDesc{empty: false, inline: 2, dataMode: dataScript}
	case elemTbody:
		return &htmlElemDesc{empty: false, inline: 0, dataMode: dataNormal}
	case "textarea":
		return &htmlElemDesc{empty: false, inline: 1, dataMode: dataRCDATA}
	case elemTitle:
		return &htmlElemDesc{empty: false, inline: 0, dataMode: dataRCDATA}
	case elemXmp:
		return &htmlElemDesc{empty: false, inline: 1, dataMode: dataRawText}
	default:
		return nil
	}
}
