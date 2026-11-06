// Derived from lestrrat-go/helium at 7362c0a70122a757780f4d0b545a9b370dead6ab.
// Copyright (c) 2015 lestrrat. MIT License; see licenses/MIT-helium.txt at the repository root.

package html

import "strings"

// Exact HTML element spellings are shared by descriptor lookup, HTML/XHTML
// serialization rules and attribute-context tables. Recognition remains ASCII
// case-insensitive at the existing call sites.
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

// Descriptor layout codes preserve the libxml2 table distinctions. Both
// nonzero codes suppress automatic formatting line breaks. Empty-element
// metadata selects whether this table treats a tag as having no content.
const (
	blockLayout       = 0
	inlineLayout      = 1
	mixedInlineLayout = 2
	emptyElement      = true
	pairedElement     = false
)

// Additional element vocabulary follows the pinned HTML4/HTML5 descriptor
// and XHTML classification tables; these names do not add table membership.
const (
	elemA          = "a"
	elemAbbr       = "abbr"
	elemAcronym    = "acronym"
	elemApplet     = "applet"
	elemArticle    = "article"
	elemAside      = "aside"
	elemB          = "b"
	elemBase       = "base"
	elemBdi        = "bdi"
	elemBdo        = "bdo"
	elemBgsound    = "bgsound"
	elemBr         = "br"
	elemButton     = "button"
	elemCanvas     = "canvas"
	elemCite       = "cite"
	elemCode       = "code"
	elemCommand    = "command"
	elemDatalist   = "datalist"
	elemDd         = "dd"
	elemDel        = "del"
	elemDetails    = "details"
	elemDfn        = "dfn"
	elemDialog     = "dialog"
	elemDl         = "dl"
	elemDt         = "dt"
	elemEm         = "em"
	elemFigcaption = "figcaption"
	elemFigure     = "figure"
	elemFooter     = "footer"
	elemH1         = "h1"
	elemH2         = "h2"
	elemH3         = "h3"
	elemH4         = "h4"
	elemH5         = "h5"
	elemH6         = "h6"
	elemHeader     = "header"
	elemHgroup     = "hgroup"
	elemHr         = "hr"
	elemI          = "i"
	elemIframe     = "iframe"
	elemIns        = "ins"
	elemKbd        = "kbd"
	elemLabel      = "label"
	elemLegend     = "legend"
	elemLi         = "li"
	elemMain       = "main"
	elemMap        = "map"
	elemMark       = "mark"
	elemMath       = "math"
	elemMenuitem   = "menuitem"
	elemMeta       = "meta"
	elemMeter      = "meter"
	elemNav        = "nav"
	elemNobr       = "nobr"
	elemNoembed    = "noembed"
	elemNoframes   = "noframes"
	elemNoscript   = "noscript"
	elemOl         = "ol"
	elemOptgroup   = "optgroup"
	elemOutput     = "output"
	elemP          = "p"
	elemParam      = "param"
	elemPicture    = "picture"
	elemPlaintext  = "plaintext"
	elemProgress   = "progress"
	elemQ          = "q"
	elemRb         = "rb"
	elemRp         = "rp"
	elemRt         = "rt"
	elemRtc        = "rtc"
	elemRuby       = "ruby"
	elemS          = "s"
	elemSamp       = "samp"
	elemSection    = "section"
	elemSelect     = "select"
	elemSlot       = "slot"
	elemStrong     = "strong"
	elemSummary    = "summary"
	elemSup        = "sup"
	elemSVG        = "svg"
	elemTd         = "td"
	elemTemplate   = "template"
	elemTextarea   = "textarea"
	elemTh         = "th"
	elemTime       = "time"
	elemTr         = "tr"
	elemTt         = "tt"
	elemU          = "u"
	elemUl         = "ul"
	elemVar        = "var"
)

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
	case elemArea, elemBase, elemBr, elemCol, elemHr, elemImg, elemInput, nameLink, elemMeta, elemParam, elemBasefont, elemFrame, elemIsindex:
		return true
	case elemEmbed:
		return html5 || edition != serializationEdition20
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
	case elemA, elemAbbr, elemAcronym, elemBdo, elemCite, elemCode, elemDfn, elemKbd, elemLabel, elemQ, elemSamp, elemSelect, nameSpan, elemVar:
		return &htmlElemDesc{empty: pairedElement, inline: inlineLayout, dataMode: dataNormal}
	case elemAddress, nameBlockquote, elemCaption, elemDiv, elemDl, elemFieldset, elemForm, elemH1, elemH2, elemH3, elemH4, elemH5, elemH6, elemLegend, elemNoscript, elemOl, elemOptgroup, elemPre, elemTable, elemTd, elemTr, elemUl:
		return &htmlElemDesc{empty: pairedElement, inline: blockLayout, dataMode: dataNormal}
	case elemApplet:
		return &htmlElemDesc{empty: pairedElement, inline: mixedInlineLayout, dataMode: dataNormal}
	case elemArea, elemBase, elemCol, elemHr, nameLink, elemMeta, elemParam:
		return &htmlElemDesc{empty: emptyElement, inline: blockLayout, dataMode: dataNormal}
	case elemB, nameBig, elemEm, elemI, elemNobr, nameSmall, elemStrong, nameSub, elemSup, elemTt:
		return &htmlElemDesc{empty: pairedElement, inline: inlineLayout, dataMode: dataNormal}
	case elemBasefont:
		return &htmlElemDesc{empty: emptyElement, inline: inlineLayout, dataMode: dataNormal}
	case elemBgsound, elemKeygen, elemSource, elemTrack, elemWbr:
		return &htmlElemDesc{empty: emptyElement, inline: blockLayout, dataMode: dataNormal}
	case elemBody, elemHead, elemHTML:
		return &htmlElemDesc{empty: pairedElement, inline: blockLayout, dataMode: dataNormal}
	case elemBr, elemImg, elemInput:
		return &htmlElemDesc{empty: emptyElement, inline: inlineLayout, dataMode: dataNormal}
	case elemButton, elemDel, elemIns, elemMap, elemObject:
		return &htmlElemDesc{empty: pairedElement, inline: mixedInlineLayout, dataMode: dataNormal}
	case elemCenter:
		return &htmlElemDesc{empty: pairedElement, inline: blockLayout, dataMode: dataNormal}
	case elemColgroup, elemDd, elemDt, nameOption, elemP, elemTfoot, elemTh, elemThead:
		return &htmlElemDesc{empty: pairedElement, inline: blockLayout, dataMode: dataNormal}
	case elemDir, elemMenu:
		return &htmlElemDesc{empty: pairedElement, inline: blockLayout, dataMode: dataNormal}
	case elemEmbed:
		return &htmlElemDesc{empty: emptyElement, inline: inlineLayout, dataMode: dataNormal}
	case elemFont, elemS, nameStrike, elemU:
		return &htmlElemDesc{empty: pairedElement, inline: inlineLayout, dataMode: dataNormal}
	case elemFrame:
		return &htmlElemDesc{empty: emptyElement, inline: blockLayout, dataMode: dataNormal}
	case elemFrameset:
		return &htmlElemDesc{empty: pairedElement, inline: blockLayout, dataMode: dataNormal}
	case elemIframe:
		return &htmlElemDesc{empty: pairedElement, inline: mixedInlineLayout, dataMode: dataRawText}
	case elemIsindex:
		return &htmlElemDesc{empty: emptyElement, inline: blockLayout, dataMode: dataNormal}
	case elemLi:
		return &htmlElemDesc{empty: pairedElement, inline: blockLayout, dataMode: dataNormal}
	case elemNoembed, nameStyle:
		return &htmlElemDesc{empty: pairedElement, inline: blockLayout, dataMode: dataRawText}
	case elemNoframes:
		return &htmlElemDesc{empty: pairedElement, inline: blockLayout, dataMode: dataRawText}
	case elemPlaintext:
		return &htmlElemDesc{empty: pairedElement, inline: blockLayout, dataMode: dataPlaintext}
	case nameScript:
		return &htmlElemDesc{empty: pairedElement, inline: mixedInlineLayout, dataMode: dataScript}
	case elemTbody:
		return &htmlElemDesc{empty: pairedElement, inline: blockLayout, dataMode: dataNormal}
	case elemTextarea:
		return &htmlElemDesc{empty: pairedElement, inline: inlineLayout, dataMode: dataRCDATA}
	case elemTitle:
		return &htmlElemDesc{empty: pairedElement, inline: blockLayout, dataMode: dataRCDATA}
	case elemXmp:
		return &htmlElemDesc{empty: pairedElement, inline: inlineLayout, dataMode: dataRawText}
	default:
		return nil
	}
}
