// Derived from lestrrat-go/helium at 7362c0a70122a757780f4d0b545a9b370dead6ab.
// Copyright (c) 2015 lestrrat. MIT License; see licenses/MIT-helium.txt at the repository root.

package html

import "strings"

// HTML element name constants used throughout the html package.
// Extracted to satisfy the goconst linter; these names appear many times
// in the element tables and parseOptions logic below.
const (
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

// lookupElement returns a descriptor for a case-insensitive HTML element name.
// Elements with the same libxml2 HTML 4.0 parsing behavior share a case; the
// returned descriptor belongs to the caller rather than mutable package state.
func lookupElement(name string) *htmlElemDesc {
	name = strings.ToLower(name)
	switch name {
	case "a", "abbr", "acronym", "bdo", "cite", "code", "dfn", "kbd", "label", "q", "samp", "select", nameSpan, "var":
		return &htmlElemDesc{empty: false, inline: 1, dataMode: dataNormal}
	case elemAddress, nameBlockquote, elemCaption, elemDiv, "dl", elemFieldset, elemForm, "h1", "h2", "h3", "h4", "h5", "h6", "legend", "noscript", "ol", "optgroup", elemPre, elemTable, "td", "tr", "ul":
		return &htmlElemDesc{empty: false, inline: 0, dataMode: dataNormal}
	case "applet":
		return &htmlElemDesc{empty: false, inline: 2, dataMode: dataNormal}
	case "area", "base", elemCol, "hr", nameLink, "meta", "param":
		return &htmlElemDesc{empty: true, inline: 0, dataMode: dataNormal}
	case "b", nameBig, "em", "i", "nobr", nameSmall, "strong", nameSub, "sup", "tt":
		return &htmlElemDesc{empty: false, inline: 1, dataMode: dataNormal}
	case "basefont":
		return &htmlElemDesc{empty: true, inline: 1, dataMode: dataNormal}
	case "bgsound", "keygen", "source", "track", "wbr":
		return &htmlElemDesc{empty: true, inline: 0, dataMode: dataNormal}
	case elemBody, elemHead, elemHTML:
		return &htmlElemDesc{empty: false, inline: 0, dataMode: dataNormal}
	case "br", "img", "input":
		return &htmlElemDesc{empty: true, inline: 1, dataMode: dataNormal}
	case "button", "del", "ins", "map", "object":
		return &htmlElemDesc{empty: false, inline: 2, dataMode: dataNormal}
	case elemCenter:
		return &htmlElemDesc{empty: false, inline: 0, dataMode: dataNormal}
	case elemColgroup, "dd", "dt", nameOption, "p", elemTfoot, "th", elemThead:
		return &htmlElemDesc{empty: false, inline: 0, dataMode: dataNormal}
	case elemDir, elemMenu:
		return &htmlElemDesc{empty: false, inline: 0, dataMode: dataNormal}
	case "embed":
		return &htmlElemDesc{empty: true, inline: 1, dataMode: dataNormal}
	case elemFont, "s", nameStrike, "u":
		return &htmlElemDesc{empty: false, inline: 1, dataMode: dataNormal}
	case "frame":
		return &htmlElemDesc{empty: true, inline: 0, dataMode: dataNormal}
	case elemFrameset:
		return &htmlElemDesc{empty: false, inline: 0, dataMode: dataNormal}
	case "iframe":
		return &htmlElemDesc{empty: false, inline: 2, dataMode: dataRawText}
	case "isindex":
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
