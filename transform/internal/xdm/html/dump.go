// Derived from lestrrat-go/helium at 7362c0a70122a757780f4d0b545a9b370dead6ab.
// Copyright (c) 2015 lestrrat. MIT License; see licenses/MIT-helium.txt at the repository root.

package html

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"iter"
	"maps"
	"strconv"
	"strings"
	"unicode/utf8"

	norm "github.com/skarm/xmlsec/internal/normalization"
	"github.com/skarm/xmlsec/internal/tree"
	"github.com/skarm/xmlsec/internal/xmlchar"

	"github.com/skarm/xmlsec/internal/lexicon"
	"github.com/skarm/xmlsec/transform/internal/xdm"
)

// HTML attribute value escaping sequences.
const (
	htmlAttrEscAmp  = "&amp;"
	htmlAttrEscLt   = "&lt;"
	htmlAttrEscGt   = "&gt;"
	htmlAttrEscQuot = "&quot;"
)

const (
	markupEncodingError = "SERE0008"
)

// windows1252Runes and windows1252Bytes retain the reverse Windows-1252
// mapping as immutable, parallel sequences. Each rune has one encoded byte.
const (
	windows1252Runes = "\u20AC\u201A\u0192\u201E\u2026\u2020\u2021\u02C6\u2030\u0160\u2039\u0152\u017D\u2018\u2019\u201C\u201D\u2022\u2013\u2014\u02DC\u2122\u0161\u203A\u0153\u017E\u0178"
	windows1252Bytes = "\x80\x82\x83\x84\x85\x86\x87\x88\x89\x8A\x8B\x8C\x8E\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9A\x9B\x9C\x9E\x9F"
)

// defaultHTMLDTD is the default DOCTYPE for HTML documents without one.
// Mirrors libxml2's htmlDocContentDumpOutput behavior.

// Write serializes an HTML node to the given writer using default settings.
func Write(out io.Writer, node xdm.Node) error {
	return NewWriter().WriteTo(out, node)
}

// WriteString serializes an HTML node to a string using default settings.
func WriteString(node xdm.Node) (string, error) {
	var buf strings.Builder
	if err := Write(&buf, node); err != nil {
		return "", err
	}

	return buf.String(), nil
}

// WriteTo serializes an HTML node to the given writer.
func (w Writer) WriteTo(out io.Writer, node xdm.Node) error {
	d := w.dumper()
	return d.dumpNode(out, node)
}

// WriteSequence serializes borrowed nodes and text without constructing a DOM.
func (w Writer) WriteSequence(ctx context.Context, out io.Writer, items iter.Seq2[xdm.XMLItem, error]) error {
	d := w.dumper()
	d.ctx = ctx

	for item, err := range items {
		if err != nil {
			return err
		}

		if err := ctx.Err(); err != nil {
			return err
		}

		if item.Node != nil {
			if err := d.dumpNode(out, item.Node); err != nil {
				return err
			}
		} else if err := d.dumpTextContent(out, item.Text, false); err != nil {
			return err
		}
	}

	return d.err
}

func (w Writer) dumper() htmlDumper {
	cfg := w.dumpConfig

	return htmlDumper{
		ctx:                   context.Background(),
		canEncode:             cfg.canEncode,
		cdataElements:         cfg.cdataElements,
		contentType:           cfg.contentType,
		normalizationForm:     cfg.normalizationForm,
		foreignNamespaces:     cfg.foreignNamespaces,
		format:                !cfg.noFormat,
		preserveCase:          cfg.preserveCase,
		noDefaultDTD:          cfg.noDefaultDTD,
		noEscapeURIAttributes: cfg.noEscapeURIAttributes,
		escapeControlChars:    cfg.escapeControlChars,
		nullNamespaceHTMLOnly: cfg.nullNamespaceHTMLOnly,
		charMap:               cfg.charMap,
		normalize:             cfg.normalize,
		normForm:              cfg.normForm,
		doeMarkers:            cfg.doeMarkers,
	}
}

type htmlDumper struct {
	ctx           context.Context
	cdataElements map[string]struct{}
	// err is a sticky serialization error. Once set, all checked write
	// helpers become no-ops and terminal methods return it. This mirrors
	// the writeSession sticky-error pattern in writer.go so that a writer
	// failing mid-stream surfaces an error instead of silently truncating.
	err       error
	canEncode func(rune) bool
	// charMap substitutes a mapped rune in text and attribute-value content with
	// its literal (unescaped) replacement string (Serialization 3.1 character
	// maps). Empty/nil disables the feature.
	charMap map[rune]string
	// entities is initialized once, only when named-entity escaping is needed.
	entities map[rune]string
	// nsEmitted tracks namespace prefix→URI bindings that were actually
	// emitted (serialized) by ancestor elements. Used to suppress
	// redundant declarations.
	nsEmitted map[string]string
	// nsAvailable tracks ALL namespace prefix→URI bindings from ancestor
	// elements, including those suppressed on non-root HTML elements.
	// Used to find URIs for attribute namespace prefixes.
	nsAvailable           map[string]string
	contentType           string
	normalizationForm     string
	normForm              norm.Form
	foreignNamespaces     bool
	format                bool
	preserveCase          bool
	noDefaultDTD          bool
	noEscapeURIAttributes bool
	escapeControlChars    bool
	nullNamespaceHTMLOnly bool
	doeMarkers            bool
	doeActive             bool
	// normalize / normForm request Unicode normalization of text-node and
	// attribute-value character content (Serialization 3.1 §4), scoped to text and
	// attribute nodes. false keeps output byte-identical.
	normalize bool
}

func (d *htmlDumper) dumpDocument(out io.Writer, doc *xdm.Document) error {
	if doc == nil {
		return nil
	}

	// If the document was parsed from Latin-1/Windows-1252, convert
	// UTF-8 output back to single-byte encoding to match libxml2.
	// strict=true for explicit ISO-8859-1 charset (numeric char refs for
	// runes > 0xFF); strict=false for auto-detected Win-1252 (raw bytes).
	enc := doc.Encoding()
	switch enc {
	case encISO88591:
		out = &latin1EncodingWriter{w: out, strict: true}
	case encWindows1252:
		out = &latin1EncodingWriter{w: out, strict: false}
	}

	// Output DTD if present, or default DTD for HTML documents
	if dtd := doc.Doctype; dtd != nil {
		d.dumpDTD(out, dtd)
	}

	// Serialize all children of the document
	for child := range xdm.Children(doc) {
		if err := d.dumpNode(out, child); err != nil {
			return err
		}
	}

	if d.format {
		d.writeString(out, "\n")
	}

	return d.err
}

// check records err as the sticky error if no error has been recorded yet.
func (d *htmlDumper) check(err error) {
	if d.err == nil && err != nil {
		d.err = err
	}
}

// writeString writes s to out, recording the first failure as the sticky
// error. It is a no-op once an error has been recorded. A short write
// reported with a nil error by a non-conformant io.Writer is promoted to
// io.ErrShortWrite, mirroring latin1EncodingWriter, so silent truncation
// is never reported as success.
func (d *htmlDumper) writeString(out io.Writer, s string) {
	if d.err != nil {
		return
	}

	n, err := io.WriteString(out, s)
	if err == nil && n < len(s) {
		err = io.ErrShortWrite
	}

	d.check(err)
}

// checkName verifies that an element or attribute name is safe to write into
// an HTML tag. Names built through public DOM construction paths
// (CreateElement, SetAttribute, ...) are not validated, so a name
// containing characters that terminate or escape a tag — whitespace, quotes,
// '<', '>', '=', '/', or control characters — would otherwise be written
// verbatim and produce malformed or injected markup. When name is unsafe (or
// empty), the first such failure is recorded as the sticky error so
// serialization aborts before writing.
//
// This is intentionally permissive about characters HTML tolerates but XML
// does not (e.g. '?' or '.' in "gentus?.?"), matching libxml2's HTML
// serializer, which preserves such names verbatim. Only characters that can
// break out of the tag are rejected.
func (d *htmlDumper) checkName(kind, name string) {
	if d.err != nil {
		return
	}

	if name == "" {
		d.check(fmt.Errorf("invalid HTML %s name: empty", kind))
		return
	}
	// Decode rune-by-rune. A range loop yields utf8.RuneError both for
	// genuinely invalid bytes and for a validly-encoded U+FFFD, so it cannot
	// tell them apart by rune alone.
	// DecodeRuneInString returns size==1 for invalid encodings, letting us
	// reject only the former while permitting a real U+FFFD (size==3), which
	// the parseOptions accepts and which does not break out of the tag.
	for i := 0; i < len(name); {
		r, size := utf8.DecodeRuneInString(name[i:])
		if r == utf8.RuneError && size == 1 {
			d.check(fmt.Errorf("invalid HTML %s name %q", kind, name))
			return
		}

		if d.canEncode != nil && !d.canEncode(r) {
			d.check(&xdm.Error{Code: markupEncodingError, Message: "HTML attribute name is not representable in output encoding"})
			return
		}

		if isUnsafeNameRune(r) {
			d.check(fmt.Errorf("invalid HTML %s name %q", kind, name))
			return
		}

		i += size
	}
}

// isUnsafeNameRune reports whether r may not appear in a serialized HTML
// element or attribute name because it would terminate or escape the tag.
// The set mirrors the characters that terminate an attribute name in the
// HTML parseOptions (see parseOptions.parseAttrName) plus ASCII control characters.
// '&' is intentionally excluded: the parseOptions's liberal attribute-name rule
// accepts it and it does not break out of the tag, so rejecting it would
// regress parse/serialize round-trip parity. A validly-encoded U+FFFD is
// likewise accepted; only invalid UTF-8 is rejected, by the caller.
//
// This is the loose rule used for ATTRIBUTE names. Element names use the
// stricter checkElementName / isElementNameRune grammar instead.
func isUnsafeNameRune(r rune) bool {
	switch r {
	case ' ', '\t', '\n', '\r', '\f', '"', '\'', '<', '>', '=', '/':
		return true
	}

	return r < 0x20 || r == 0x7f
}

// checkElementName verifies that an element name is a valid HTML tag name
// before it is written into a tag. Unlike checkName (the loose attribute
// rule), this enforces the HTML tag-name grammar so that names libxml2 treats
// as malformed — e.g. CreateElement("a?b") or CreateElement("a&b") — are
// rejected, and never serialized verbatim as <a?b> / <a&b>.
//
// The accepted set is derived from what the HTML parseOptions tokenizes as a tag
// name (parseOptions.parseName via isNameChar): ASCII letters, digits, ':', '-',
// '_', '.'. ASCII punctuation outside that set — '?', '&', '=', '/', quotes,
// angle brackets, whitespace, control chars — is rejected. Non-ASCII runes
// are permitted so that legitimate Unicode element names (e.g. produced by
// XSLT HTML output) are not over-rejected; a validly-encoded U+FFFD is one
// such rune and is accepted, while invalid UTF-8 is rejected.
func (d *htmlDumper) checkElementName(name string) {
	if d.err != nil {
		return
	}

	if name == "" {
		d.check(fmt.Errorf("invalid HTML element name: empty"))
		return
	}
	// Decode rune-by-rune. A range loop yields utf8.RuneError both for
	// genuinely invalid bytes and for a validly-encoded U+FFFD. DecodeRuneInString returns size==1 for invalid
	// encodings, letting us reject only the former while permitting a real
	// U+FFFD (size==3), which the parseOptions accepts and which does not break out
	// of the tag.
	for i := 0; i < len(name); {
		r, size := utf8.DecodeRuneInString(name[i:])
		if r == utf8.RuneError && size == 1 {
			d.check(fmt.Errorf("invalid HTML element name %q", name))
			return
		}

		if d.canEncode != nil && !d.canEncode(r) {
			d.check(&xdm.Error{Code: markupEncodingError, Message: "HTML element name is not representable in output encoding"})
			return
		}

		if !isElementNameRune(r) {
			d.check(fmt.Errorf("invalid HTML element name %q", name))
			return
		}

		i += size
	}
}

// isElementNameRune reports whether r may appear in a serialized HTML element
// name. ASCII runes must be a valid HTML tag-name character (letters, digits,
// ':', '-', '_', '.'), mirroring the parseOptions's isNameChar; this rejects
// tag-breaking and clearly-malformed characters such as '?', '&', '=', '/',
// quotes, angle brackets, whitespace and control characters. Non-ASCII runes
// are permitted to avoid over-rejecting legitimate Unicode element names.
func isElementNameRune(r rune) bool {
	if r >= 0x80 {
		return true
	}

	switch {
	case r >= 'A' && r <= 'Z':
		return true
	case r >= 'a' && r <= 'z':
		return true
	case r >= '0' && r <= '9':
		return true
	}

	switch r {
	case ':', '-', '_', '.':
		return true
	}

	return false
}

func (d *htmlDumper) dumpNode(out io.Writer, n xdm.Node) error {
	switch n.Type() {
	case xdm.DocumentNode:
		doc, ok := xdm.AsNode[*xdm.Document](n)
		if !ok {
			return nil
		}

		return d.dumpDocument(out, doc)

	case xdm.CommentNode:
		if d.xmlIslandNode(n) {
			if err := d.checkXMLMarkup(n); err != nil {
				return err
			}
		}

		d.writeString(out, "<!--")
		d.writeString(out, xdm.CharacterData(n))
		d.writeString(out, "-->")

		return d.err
	case xdm.ProcessingInstructionNode:
		if d.doeMarkers {
			switch n.Name() {
			case "disable-output-escaping":
				d.doeActive = true
				return d.err
			case "enable-output-escaping":
				d.doeActive = false
				return d.err
			}
		}

		xml := d.xmlIslandNode(n)
		if xml {
			if err := d.checkXMLMarkup(n); err != nil {
				return err
			}
		}

		d.writeString(out, "<?")
		d.writeString(out, n.Name())

		if c := xdm.CharacterData(n); len(c) > 0 {
			d.writeString(out, " ")
			d.writeString(out, c)
		}

		if xml {
			d.writeString(out, "?>")
		} else {
			d.writeString(out, ">")
		}

		return d.err

	case xdm.TextNode:
		return d.dumpText(out, n)
	case xdm.ElementNode:
		elem, ok := xdm.AsNode[*xdm.Element](n)
		if !ok {
			return nil
		}

		return d.dumpElement(out, elem)
	}

	return nil
}

func (d *htmlDumper) xmlIslandNode(node xdm.Node) bool {
	parent, ok := node.Parent().(*xdm.Element)
	return ok && !d.isHTMLElement(parent)
}

func (d *htmlDumper) checkXMLMarkup(node xdm.Node) error {
	for _, value := range []string{node.Name(), xdm.CharacterData(node)} {
		if !utf8.ValidString(value) {
			return &xdm.Error{Code: lexicon.ErrSERE0006, Message: "invalid XML island markup characters"}
		}

		for _, r := range value {
			if !xmlchar.IsChar(r) {
				return &xdm.Error{Code: lexicon.ErrSERE0006, Message: "character is not permitted in XML 1.0 island markup"}
			}

			if d.canEncode != nil && !d.canEncode(r) {
				return &xdm.Error{Code: markupEncodingError, Message: "XML island markup cannot be represented in output encoding"}
			}
		}
	}

	return nil
}

// dumpDTD outputs <!DOCTYPE name PUBLIC "extID" "sysID">\n
func (d *htmlDumper) dumpDTD(out io.Writer, dtd *xdm.Doctype) {
	d.writeString(out, "<!DOCTYPE ")
	d.writeString(out, dtd.Name)

	extID := dtd.PublicID

	sysID := dtd.SystemID
	if extID != "" {
		d.writeString(out, " PUBLIC \"")
		d.writeString(out, extID)
		d.writeString(out, "\"")

		if sysID != "" {
			d.writeString(out, " \"")
			d.writeString(out, sysID)
			d.writeString(out, "\"")
		}
	} else if sysID != "" && sysID != "about:legacy-compat" {
		d.writeString(out, " SYSTEM \"")
		d.writeString(out, sysID)
		d.writeString(out, "\"")
	}

	d.writeString(out, ">\n")
}

// normalizedContent applies character maps before normalization. Replacements
// are emitted verbatim; ordinary runs are normalized and emitted incrementally.
func (d *htmlDumper) normalizedContent(s string, emit func(string, bool) error) error {
	plain := func(value string) error {
		return d.normForm.Each(d.ctx, value, func(part string) error { return emit(part, false) })
	}
	start := 0

	for at, r := range s {
		replacement, mapped := d.charMap[r]
		if !mapped {
			continue
		}

		if err := plain(s[start:at]); err != nil {
			return err
		}

		if err := emit(replacement, true); err != nil {
			return err
		}

		start = at + utf8.RuneLen(r)
	}

	return plain(s[start:])
}

// dumpText outputs text content, escaping &, <, > unless inside a raw text element.
func (d *htmlDumper) dumpText(out io.Writer, n xdm.Node) error {
	content := xdm.CharacterData(n)
	rawText := d.doeActive

	parent := n.Parent()
	if element, ok := parent.(*xdm.Element); ok && !d.isHTMLElement(element) && !rawText {
		mode := tree.XMLTextContent
		if _, selected := d.cdataElements[xdm.ClarkName(element.URI(), element.LocalName())]; selected {
			mode = tree.XMLCDATAContent
		}

		return d.dumpXMLCharacters(out, content, mode)
	}

	if element, ok := parent.(*xdm.Element); ok && d.isHTMLElement(element) {
		parentName := strings.ToLower(element.LocalName())
		if desc := lookupElement(parentName); desc != nil && desc.dataMode >= dataRawText {
			rawText = true
		}
	}

	return d.dumpTextContent(out, content, rawText)
}

func (d *htmlDumper) dumpXMLCharacters(out io.Writer, content string, mode tree.XMLCharacterMode) error {
	options := tree.XMLWriteOptions{CanEncode: d.canEncode, CharacterMap: d.charMap, Normalization: d.normalizationForm, EscapeControlChars: true}

	_, err := tree.WriteXMLCharacters(d.ctx, out, content, mode, int(^uint(0)>>1), options)
	if errors.Is(err, tree.ErrMalformed) {
		err = &xdm.Error{Code: lexicon.ErrSERE0006, Message: "character is not permitted in an XML 1.0 island", Cause: err}
	}

	d.check(err)

	return d.err
}

func (d *htmlDumper) dumpTextContent(out io.Writer, content string, rawText bool) error {
	// Unicode normalization is scoped to text nodes: normalizeContent splits the
	// content at each mapped rune (matching decided on the pre-normalization
	// content), each non-mapped run is normalized and escaped with a nil map, and
	// each replacement is emitted verbatim.
	if d.normalize {
		return d.writeNormalizedText(out, content, rawText)
	}

	if rawText {
		// Raw text element: no escaping (character maps still apply).
		if len(d.charMap) == 0 {
			d.writeString(out, content)
		} else {
			d.check(writeHTMLCharMapped(out, content, d.charMap))
		}

		return d.err
	}

	// Normal text: escape &, <, >
	if d.err != nil {
		return d.err
	}

	d.check(htmlEscapeString(out, content, d.escapeControlChars, d.charMap, d.canEncode))

	return d.err
}

// writeHTMLCharMapped writes s to w, substituting each character-map rune with
// its literal (unescaped) replacement string. With a nil/empty map it writes s
// unchanged.
func writeHTMLCharMapped(w io.Writer, s string, charMap map[rune]string) error {
	if len(charMap) == 0 {
		_, err := io.WriteString(w, s)
		return err
	}

	last := 0

	for i := 0; i < len(s); {
		r, width := utf8.DecodeRuneInString(s[i:])
		if repl, ok := charMap[r]; ok {
			if _, err := io.WriteString(w, s[last:i]); err != nil {
				return err
			}

			if _, err := io.WriteString(w, repl); err != nil {
				return err
			}

			i += width
			last = i

			continue
		}

		i += width
	}

	_, err := io.WriteString(w, s[last:])

	return err
}

// writeNormalizedText writes a text node's character content under an active
// Normalization request: each non-mapped segment is normalized and (outside a
// raw text element) escaped as ordinary text with no character map, and each
// replacement segment is emitted verbatim. Only called when d.normalize is true.
func (d *htmlDumper) writeNormalizedText(out io.Writer, content string, rawText bool) error {
	return d.normalizedContent(content, func(part string, mapped bool) error {
		if d.err != nil {
			return d.err
		}

		if mapped || rawText {
			d.writeString(out, part)
			return d.err
		}

		return htmlEscapeString(out, part, d.escapeControlChars, nil, d.canEncode)
	})
}

// writeNormalizedAttrValue normalizes ordinary content before URI or XML
// escaping; character-map replacements remain literal.
func (d *htmlDumper) writeNormalizedAttrValue(out io.Writer, val string, isURI bool) {
	d.check(d.normalizedContent(val, func(part string, mapped bool) error {
		if d.err != nil {
			return d.err
		}

		if mapped {
			d.writeString(out, part)
			return d.err
		}

		return d.htmlEscapeAttrValue(out, part, isURI, d.preserveCase, nil)
	}))
}

// htmlEscapeAttrValue escapes attribute values for HTML output.
// For non-URI attributes: escapes &, ", <, >.
// For URI attributes: escapes only & and " (matching libxml2's htmlAttrDumpOutput).
// Non-ASCII characters with named HTML4 entities are output as &name;
// unless noEntityEnc is true (used by XSLT HTML output which emits UTF-8 directly).
func (d *htmlDumper) htmlEscapeAttrValue(w io.Writer, s string, isURI bool, noEntityEnc bool, charMap map[rune]string) error {
	last := 0

	for i := 0; i < len(s); {
		r, width := utf8.DecodeRuneInString(s[i:])

		replacement, mapped := charMap[r]
		entity := false

		if !mapped {
			replacement, entity = d.attributeRuneEscape(r, isURI, noEntityEnc)
			if replacement == "" {
				i += width

				continue
			}
		}

		if err := writeHTMLAttributeReplacement(w, s[last:i], replacement, entity); err != nil {
			return err
		}

		i += width
		last = i
	}

	_, err := io.WriteString(w, s[last:])

	return err
}

func writeHTMLAttributeReplacement(w io.Writer, prefix, replacement string, entity bool) error {
	if _, err := io.WriteString(w, prefix); err != nil {
		return err
	}

	if entity {
		if _, err := io.WriteString(w, "&"); err != nil {
			return err
		}
	}

	if _, err := io.WriteString(w, replacement); err != nil {
		return err
	}

	if entity {
		if _, err := io.WriteString(w, ";"); err != nil {
			return err
		}
	}

	return nil
}

func (d *htmlDumper) attributeRuneEscape(r rune, isURI, noEntityEnc bool) (string, bool) {
	switch {
	case d.escapeControlChars && r >= 0x80 && r <= 0x9f:
		return fmt.Sprintf("&#%d;", r), false
	case r > 127 && d.canEncode != nil && !d.canEncode(r):
		return fmt.Sprintf("&#%d;", r), false
	case r == '&':
		return htmlAttrEscAmp, false
	case r == '"':
		return htmlAttrEscQuot, false
	case r == '<' && !isURI:
		return htmlAttrEscLt, false
	case r == '>' && !isURI:
		return htmlAttrEscGt, false
	case r >= 0x80 && !noEntityEnc:
		return d.lookupEntityByRune(r), true
	default:
		return "", false
	}
}

func (d *htmlDumper) dumpElement(out io.Writer, e *xdm.Element) error {
	name := e.Name()
	if d.foreign(e) {
		name = e.LocalName()
	}

	nameLower := strings.ToLower(name)

	var info *htmlElemDesc
	if d.isHTMLElement(e) {
		info = lookupElement(strings.ToLower(e.LocalName()))
	}

	if !d.preserveCase {
		name = nameLower
	}

	// Reject element names that are not valid HTML tag names (malformed names
	// such as "a?b" or "a&b", or names containing tag-breaking characters)
	// before writing them into the tag.
	d.checkElementName(name)

	if d.err != nil {
		return d.err
	}

	// Opening tag
	d.writeString(out, "<")
	d.writeString(out, name)

	d.emitElementNSDecls(out, e)

	// Attributes
	if err := d.dumpAttributes(out, e); err != nil {
		return err
	}

	// Void element: no closing tag. Under HTML 4.01 rules
	// (nullNamespaceHTMLOnly), an element in a non-null namespace is not an
	// HTML element and is serialized with an explicit end tag instead.
	isVoid := info != nil && info.empty
	if d.nullNamespaceHTMLOnly && e.URI() != "" {
		isVoid = false
	}

	if isVoid {
		d.writeString(out, ">")

		if d.format && shouldNewlineAfterVoid(e, info) {
			d.writeString(out, "\n")
		}

		return d.err
	}

	d.writeString(out, ">")

	if d.format && shouldNewlineAfterOpen(e, info) {
		d.writeString(out, "\n")
	}

	// Only bindings emitted by ancestors suppress descendant declarations.
	savedEmitted, savedAvailable := d.pushElementNamespaces(e)

	// Children
	if d.metadataHead(e) {
		d.writeString(out, `<meta http-equiv="Content-Type" content="`)
		d.check(d.htmlEscapeAttrValue(out, d.contentType, false, true, d.charMap))
		d.writeString(out, `">`)
	}

	savedDOE := d.doeActive

	d.doeActive = false
	for child := range xdm.Children(e) {
		if meta, ok := child.(*xdm.Element); ok && d.metadataHead(e) && d.isHTMLElement(meta) && strings.EqualFold(meta.LocalName(), "meta") && isContentTypeMeta(meta) {
			continue
		}

		if err := d.dumpNode(out, child); err != nil {
			return err
		}
	}

	d.doeActive = savedDOE

	// Restore namespace scope
	if d.preserveCase {
		d.nsEmitted = savedEmitted
		d.nsAvailable = savedAvailable
	}

	if d.format && shouldNewlineBeforeClose(e, info) {
		d.writeString(out, "\n")
	}

	// Closing tag
	d.writeString(out, "</")
	d.writeString(out, name)
	d.writeString(out, ">")

	if d.format && shouldNewlineAfterClose(e, info) {
		d.writeString(out, "\n")
	}

	return d.err
}

// Format newline helper functions matching libxml2's HTMLtree.c:968-1108.

func parentNameStartsWithP(n xdm.Node) bool {
	parent := n.Parent()
	if parent == nil || parent.Type() != xdm.ElementNode {
		return false
	}

	name := strings.ToLower(parent.Name())

	return len(name) > 0 && name[0] == 'p'
}

func isTextOrEntityRef(n xdm.Node) bool {
	if n == nil {
		return false
	}

	t := n.Type()

	return t == xdm.TextNode
}

func shouldNewlineAfterOpen(e *xdm.Element, info *htmlElemDesc) bool {
	if info != nil && info.inline != 0 {
		return false
	}

	first := e.FirstChild()
	if first == nil {
		return false
	}

	if isTextOrEntityRef(first) {
		return false
	}

	if e.FirstChild() == e.LastChild() {
		return false
	}

	name := strings.ToLower(e.Name())
	if len(name) > 0 && name[0] == 'p' {
		return false
	}

	return true
}

func shouldNewlineAfterVoid(e *xdm.Element, info *htmlElemDesc) bool {
	if info != nil && info.inline != 0 {
		return false
	}

	next := e.NextSibling()
	if next == nil {
		return false
	}

	if isTextOrEntityRef(next) {
		return false
	}

	if parentNameStartsWithP(e) {
		return false
	}

	return true
}

func shouldNewlineBeforeClose(e *xdm.Element, info *htmlElemDesc) bool {
	if info != nil && info.inline != 0 {
		return false
	}

	last := e.LastChild()
	if last == nil {
		return false
	}

	if isTextOrEntityRef(last) {
		return false
	}

	if e.FirstChild() == e.LastChild() {
		return false
	}

	name := strings.ToLower(e.Name())
	if len(name) > 0 && name[0] == 'p' {
		return false
	}

	return true
}

func shouldNewlineAfterClose(e *xdm.Element, info *htmlElemDesc) bool {
	if info != nil && info.inline != 0 {
		return false
	}

	next := e.NextSibling()
	if next == nil {
		return false
	}

	if isTextOrEntityRef(next) {
		return false
	}

	if parentNameStartsWithP(e) {
		return false
	}

	return true
}

func (d *htmlDumper) foreign(e *xdm.Element) bool {
	return d.foreignNamespaces && e.Prefix() != "" && (e.URI() == lexicon.NamespaceSVG || e.URI() == lexicon.NamespaceMathML || e.URI() == lexicon.NamespaceXHTML)
}

// Special HTML element/attribute rules never apply within an XML island.
func (d *htmlDumper) isHTMLElement(e *xdm.Element) bool {
	return IsHTMLNamespace(e.URI(), !d.nullNamespaceHTMLOnly)
}

func (d *htmlDumper) namespaceAllowed(e *xdm.Element, ns *xdm.Namespace) bool {
	if ns.URI() == lexicon.NamespaceXML {
		return false
	}

	if !d.foreign(e) {
		return true
	}

	if ns.Prefix() == "" {
		return ns.URI() == e.URI()
	}

	if ns.Prefix() == e.Prefix() {
		for _, attr := range e.Attributes() {
			if attr.Prefix() == ns.Prefix() {
				return true
			}
		}

		return false
	}

	return true
}

func (d *htmlDumper) metadataHead(e *xdm.Element) bool {
	return d.contentType != "" && d.metadataHeadElement(e)
}

func (d *htmlDumper) metadataHeadElement(n xdm.Node) bool {
	e, ok := n.(*xdm.Element)
	return ok && d.isHTMLElement(e) && strings.EqualFold(e.LocalName(), "head")
}

// Namespace suppression and scope tracking share the same HTML5 rules.
func (d *htmlDumper) emitElementNSDecls(out io.Writer, e *xdm.Element) {
	if !d.preserveCase {
		return
	}

	defaultEmitted := false

	for _, namespace := range e.Namespaces() {
		prefix := namespace.Prefix()

		uri := namespace.URI()

		if !d.namespaceAllowed(e, namespace) {
			continue
		}

		if (prefix == "" || d.nsEmitted != nil) && d.nsEmitted[prefix] == uri {
			continue
		}

		d.writeNSDecl(out, prefix, uri)
		defaultEmitted = defaultEmitted || prefix == ""
	}

	if d.foreign(e) && !defaultEmitted && d.nsEmitted[""] != e.URI() {
		d.writeNSDecl(out, "", e.URI())
	}

	d.emitAttrNSDecls(out, e)
}

func (d *htmlDumper) pushElementNamespaces(e *xdm.Element) (map[string]string, map[string]string) {
	if !d.preserveCase {
		return nil, nil
	}

	savedEmitted := d.nsEmitted
	savedAvailable := d.nsAvailable
	emitted := copyMap(d.nsEmitted)
	available := copyMap(d.nsAvailable)

	for _, namespace := range e.Namespaces() {
		available[namespace.Prefix()] = namespace.URI()
		if d.namespaceAllowed(e, namespace) {
			emitted[namespace.Prefix()] = namespace.URI()
		}
	}

	if d.foreign(e) {
		emitted[""] = e.URI()
		available[""] = e.URI()
	}

	for _, attribute := range e.Attributes() {
		prefix := attribute.Prefix()
		if prefix != "" && attribute.URI() != "" {
			emitted[prefix] = attribute.URI()
			available[prefix] = attribute.URI()
		}
	}

	d.nsEmitted = emitted
	d.nsAvailable = available

	return savedEmitted, savedAvailable
}

// copyMap returns a shallow copy of a string map. If src is nil, returns
// an empty map.
func copyMap(src map[string]string) map[string]string {
	m := make(map[string]string, len(src))
	maps.Copy(m, src)

	return m
}

func (d *htmlDumper) dumpAttributes(out io.Writer, e *xdm.Element) error {
	for _, attr := range e.Attributes() {
		attrNameLower := strings.ToLower(attr.Name())

		attrName := attrNameLower
		if d.preserveCase {
			attrName = attr.Name()
		}
		// Reject names that would inject markup into the tag.
		d.checkName("attribute", attrName)

		if d.err != nil {
			return d.err
		}

		d.writeString(out, " ")
		d.writeString(out, attrName)

		// HTML boolean attributes: minimize when value equals the
		// attribute name (case-insensitive), per XSLT serialization spec.
		if d.isHTMLElement(e) && attr.URI() == "" && isHTMLBooleanAttribute(attrNameLower) {
			val := attr.Value()
			if strings.EqualFold(val, attrNameLower) {
				continue
			}
		}

		val := attr.Value()
		elemName := strings.ToLower(e.LocalName())
		isURI := d.isHTMLElement(e) && attr.URI() == "" && isURIAttr(attrNameLower, elemName)

		uriEscaped := isURI && !d.noEscapeURIAttributes

		d.writeString(out, "=\"")

		if d.err == nil {
			// Serialization 3.1 §7 (character-expansion phase): when URI escaping
			// is applied to a URI attribute value (escape-uri-attributes=yes), the
			// serializer skips character mapping for that value. Character maps
			// apply to non-URI attributes, and to URI attributes only when URI
			// escaping is disabled (escape-uri-attributes=no). Unicode normalization
			// is likewise scoped to the attribute value's character content; a
			// URI-escaped value is already ASCII (percent-encoded), so normalization
			// is a no-op there and character mapping is skipped.
			switch {
			case !d.isHTMLElement(e) || attr.URI() != "":
				d.check(d.dumpXMLCharacters(out, val, tree.XMLAttributeValue))
			case uriEscaped:
				d.check(writeURIAttribute(d.ctx, out, val))
			case d.normalize:
				d.writeNormalizedAttrValue(out, val, isURI)
			default:
				d.check(d.htmlEscapeAttrValue(out, val, isURI, d.preserveCase, d.charMap))
			}
		}

		d.writeString(out, "\"")
	}

	return d.err
}

// isURIAttr reports HTML attributes whose values contain URIs.
// Serialization 3.1 Appendix D defines URI attributes by both element and
// attribute name. Unknown elements and namespace-qualified names are excluded
// by the caller (section 7.1).
func isURIAttr(attribute, element string) bool {
	var elements string

	switch attribute {
	case "action":
		elements = "form"
	case "archive", "classid", elemData:
		elements = "object"
	case "background":
		elements = "body"
	case "cite":
		elements = "blockquote del ins q"
	case "codebase":
		elements = "applet object"
	case "datasrc":
		elements = "button div input object select span table textarea"
	case "for":
		elements = "script"
	case "formaction":
		elements = "button input"
	case "href":
		elements = "a area base link"
	case "icon":
		elements = "command"
	case "longdesc":
		elements = "frame iframe img"
	case "manifest":
		elements = "html"
	case "name":
		elements = "a"
	case "poster":
		elements = elemVideo
	case "profile":
		elements = "head"
	case "src":
		elements = "audio embed frame iframe img input script source track video"
	case "usemap":
		elements = "img input object"
	case "value":
		elements = elemInput
	}

	for name := range strings.FieldsSeq(elements) {
		if name == element {
			return true
		}
	}

	return false
}

// isHTMLBooleanAttribute reports attributes minimized when their value matches
// their name (XSLT/XQuery Serialization 3.1, HTML boolean attributes).
func isHTMLBooleanAttribute(name string) bool {
	switch name {
	case "checked", "compact", "declare", "defer", "disabled", "ismap",
		"multiple", "nohref", "noresize", "noshade", "nowrap", "readonly", "selected":
		return true
	default:
		return false
	}
}

// writeURIAttribute normalizes an IRI to NFC and emits percent-encoded bytes,
// escaping ampersands for the surrounding HTML attribute. Working storage does
// not depend on the length of the attribute.
func writeURIAttribute(ctx context.Context, out io.Writer, s string) error {
	const hex = "0123456789ABCDEF"

	var buffer [4096]byte

	n := 0
	flush := func() error {
		written, err := out.Write(buffer[:n])
		if err == nil && written != n {
			err = io.ErrShortWrite
		}

		n = 0

		return err
	}

	if err := norm.NFC.EachBytes(ctx, s, func(part []byte) error {
		for _, c := range part {
			if n+6 > len(buffer) {
				if err := flush(); err != nil {
					return err
				}
			}

			switch {
			case c == '&':
				n += copy(buffer[n:], htmlAttrEscAmp)
			case c == '"':
				n += copy(buffer[n:], htmlAttrEscQuot)
			case c == '<':
				n += copy(buffer[n:], htmlAttrEscLt)
			case c >= 0x20 && c <= 0x7e:
				buffer[n] = c
				n++
			default:
				buffer[n], buffer[n+1], buffer[n+2] = '%', hex[c>>4], hex[c&15]
				n += 3
			}
		}

		return nil
	}); err != nil {
		return err
	}

	if n > 0 {
		return flush()
	}

	return nil
}

func (d *htmlDumper) writeNSDecl(out io.Writer, prefix, uri string) {
	// The "xml" prefix is predefined by the Namespaces in XML spec (bound
	// implicitly to the XML namespace everywhere), so a literal
	// xmlns:xml="http://www.w3.org/XML/1998/namespace" declaration is
	// redundant and non-canonical and must never be emitted.
	if prefix == "xml" {
		return
	}

	if prefix == "" {
		d.writeString(out, " xmlns=\"")
		d.writeString(out, uri)
		d.writeString(out, "\"")

		return
	}
	// A non-empty prefix is written verbatim into the xmlns: attribute name,
	// so an unsafe prefix could break out of the tag (e.g. a prefix
	// containing a space and quote yields a separate injected attribute).
	// Reject it the same way element/attribute names are rejected.
	d.checkName("namespace prefix", prefix)

	if d.err != nil {
		return
	}

	d.writeString(out, " xmlns:")
	d.writeString(out, prefix)
	d.writeString(out, "=\"")
	d.writeString(out, uri)
	d.writeString(out, "\"")
}

// emitAttrNSDecls emits namespace declarations for attribute prefixes
// that aren't already declared on the element or emitted by an ancestor.
func (d *htmlDumper) emitAttrNSDecls(out io.Writer, e *xdm.Element) {
	declared := make(map[string]struct{})

	for _, ns := range e.Namespaces() {
		if d.namespaceAllowed(e, ns) {
			declared[ns.Prefix()] = struct{}{}
		}
	}

	seen := make(map[string]struct{})

	for _, attr := range e.Attributes() {
		prefix := attr.Prefix()
		if prefix == "" || prefix == "xml" {
			continue
		}

		if _, ok := declared[prefix]; ok {
			continue
		}

		if _, ok := seen[prefix]; ok {
			continue
		}

		uri := attr.URI()
		if uri == "" {
			continue
		}

		if d.nsEmitted != nil && d.nsEmitted[prefix] == uri {
			continue
		}

		seen[prefix] = struct{}{}
		d.writeNSDecl(out, prefix, uri)
	}
}

func htmlEscapeString(w io.Writer, s string, escCtrl bool, charMap map[rune]string, canEncode func(rune) bool) error {
	var esc string

	last := 0

	for i := 0; i < len(s); {
		r, width := utf8.DecodeRuneInString(s[i:])

		i += width
		if repl, ok := charMap[r]; ok {
			// Character map: emit the literal replacement verbatim (not escaped).
			if _, err := io.WriteString(w, s[last:i-width]); err != nil {
				return err
			}

			if _, err := io.WriteString(w, repl); err != nil {
				return err
			}

			last = i

			continue
		}

		switch {
		case r == '&':
			esc = htmlAttrEscAmp
		case r == '<':
			esc = htmlAttrEscLt
		case r == '>':
			esc = htmlAttrEscGt
		case escCtrl && r >= 0x7F && r <= 0x9F || r > 127 && canEncode != nil && !canEncode(r):
			if _, err := io.WriteString(w, s[last:i-width]); err != nil {
				return err
			}

			ref := fmt.Sprintf("&#x%X;", r)
			if _, err := io.WriteString(w, ref); err != nil {
				return err
			}

			last = i

			continue
		default:
			continue
		}

		if _, err := io.WriteString(w, s[last:i-width]); err != nil {
			return err
		}

		if _, err := io.WriteString(w, esc); err != nil {
			return err
		}

		last = i
	}

	if _, err := io.WriteString(w, s[last:]); err != nil {
		return err
	}

	return nil
}

func isContentTypeMeta(e *xdm.Element) bool {
	for _, a := range e.Attributes() {
		if a.URI() == "" && strings.EqualFold(a.Name(), "http-equiv") && strings.EqualFold(strings.Trim(a.Value(), " \t\r\n"), "Content-Type") {
			return true
		}
	}

	return false
}

// htmlNormalizationForm maps a normalization-form parameter name to its
// golang.org/x/text norm.Form and reports whether normalization is active.
func htmlNormalizationForm(form string) (norm.Form, bool) {
	switch form {
	case "NFC":
		return norm.NFC, true
	case "NFD":
		return norm.NFD, true
	case "NFKC":
		return norm.NFKC, true
	case "NFKD":
		return norm.NFKD, true
	}

	return norm.NFC, false
}

// alignPoint records that consuming inputBytes of the source produced
// outputBytes of encoded output at a clean rune boundary.
type alignPoint struct{ inputBytes, outputBytes int }

// latin1EncodingWriter wraps an io.Writer and converts multi-byte UTF-8
// runes in the Latin-1/Windows-1252 range back to single bytes.
// When strict is true (explicit ISO-8859-1 charset), runes > 0xFF that
// have no Latin-1 representation are emitted as numeric character references.
// When strict is false (auto-detected Win-1252), Win-1252 reverse mapping
// is used and unmapped runes pass through as UTF-8.
type latin1EncodingWriter struct {
	w      io.Writer
	strict bool
}

func (lw *latin1EncodingWriter) Write(p []byte) (int, error) {
	out, align := utf8ToLatin1WithAlign(p, lw.strict)
	n, err := lw.w.Write(out)
	// A well-behaved [io.Writer] reports err != nil when n < len(out).
	// Defensively promote a silent short write to io.ErrShortWrite so a
	// non-conformant inner writer cannot mask data loss as success.
	if err == nil && n < len(out) {
		err = io.ErrShortWrite
	}

	if err != nil {
		// align is nil on the ASCII fast path (1:1 mapping); otherwise it
		// records (inputBytes, outputBytes) at every rune boundary. Return
		// the largest input prefix whose encoded output fully fit within
		// the inner writer's reported n bytes, so callers see an honest
		// consumed count for io.Copy-style bookkeeping.
		if align == nil {
			return n, err
		}

		return inputConsumedAt(align, n), err
	}

	return len(p), nil
}

func windows1252Byte(r rune) (byte, bool) {
	index := 0

	for _, candidate := range windows1252Runes {
		if candidate == r {
			return windows1252Bytes[index], true
		}

		index++
	}

	return 0, false
}

// inputConsumedAt returns the largest inputBytes from align where
// outputBytes <= n. align must be monotonically increasing in both fields.
func inputConsumedAt(align []alignPoint, n int) int {
	consumed := 0

	for _, ap := range align {
		if ap.outputBytes > n {
			break
		}

		consumed = ap.inputBytes
	}

	return consumed
}

// utf8ToLatin1WithAlign converts UTF-8 encoded data back to Latin-1 /
// Windows-1252 and additionally returns an alignment table recording
// (inputBytes, outputBytes) at every rune boundary, so callers can map a
// partial-output byte count back to a precise consumed-input prefix.
//
// Runes U+0080-U+00FF are written as single bytes.
// When strict is true (explicit ISO-8859-1), runes > U+00FF are emitted
// as numeric character references (&#N;).
// When strict is false (auto-detected Win-1252), Windows-1252 runes are
// reverse-mapped to single bytes and other runes pass through as UTF-8.
//
// On the all-ASCII fast path the returned slice is the input verbatim and
// align is nil — input and output are 1:1 so no table is needed.
func utf8ToLatin1WithAlign(data []byte, strict bool) ([]byte, []alignPoint) {
	allASCII := true

	for _, b := range data {
		if b >= 0x80 {
			allASCII = false
			break
		}
	}

	if allASCII {
		return data, nil
	}

	var buf bytes.Buffer
	buf.Grow(len(data))
	align := make([]alignPoint, 0, len(data)/2+1)
	align = append(align, alignPoint{0, 0})

	for i := 0; i < len(data); {
		b := data[i]
		if b < 0x80 {
			buf.WriteByte(b)

			i++
			align = append(align, alignPoint{i, buf.Len()})

			continue
		}

		r, size := utf8.DecodeRune(data[i:])
		if r >= 0x80 && r <= 0xFF {
			buf.WriteByte(byte(r))
		} else if strict {
			ref := append(buf.AvailableBuffer(), '&', '#')
			ref = strconv.AppendInt(ref, int64(r), 10)
			buf.Write(append(ref, ';'))
		} else if wb, ok := windows1252Byte(r); ok {
			buf.WriteByte(wb)
		} else {
			buf.Write(data[i : i+size])
		}

		i += size
		align = append(align, alignPoint{i, buf.Len()})
	}

	return buf.Bytes(), align
}
