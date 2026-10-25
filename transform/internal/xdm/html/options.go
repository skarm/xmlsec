// Derived from lestrrat-go/helium at 7362c0a70122a757780f4d0b545a9b370dead6ab.
// Copyright (c) 2015 lestrrat. MIT License; see licenses/MIT-helium.txt at the repository root.

package html

import (
	"strconv"

	norm "github.com/skarm/xmlsec/internal/normalization"
	"github.com/skarm/xmlsec/transform/internal/xdm/lexicon"
)

// IsHTMLNamespace selects names subject to the special HTML output rules.
func IsHTMLNamespace(uri string, html5 bool) bool {
	return uri == "" || html5 && uri == lexicon.NamespaceXHTML
}

// RequestedVersion applies the serialization parameter precedence. Modern
// language hosts select HTML 5 when neither parameter supplies a value.
func RequestedVersion(htmlVersion, version string) string {
	if htmlVersion != "" {
		return htmlVersion
	}

	if version != "" {
		return version
	}

	return "5"
}

// SupportedVersion identifies the HTML versions selected by this engine.
func SupportedVersion(version string) bool {
	value, err := strconv.ParseFloat(version, 64)
	return err == nil && (value == 4 || value == 4.01 || value == 5)
}

// Writer configures HTML serialization. It is a value-style wrapper:
// fluent methods return updated copies and the original is never mutated.
type Writer struct {
	dumpConfig
}

type dumpConfig struct {
	canEncode     func(rune) bool
	cdataElements map[string]struct{}
	// charMap substitutes a mapped rune in text and attribute-value content with
	// its literal replacement string (Serialization 3.1 character maps).
	// Empty/nil disables the feature.
	charMap               map[rune]string
	contentType           string
	normalizationForm     string
	normForm              norm.Form
	foreignNamespaces     bool
	noDefaultDTD          bool
	noFormat              bool
	preserveCase          bool
	noEscapeURIAttributes bool
	escapeControlChars    bool
	nullNamespaceHTMLOnly bool
	doeMarkers            bool
	// normalize / normForm request Unicode normalization of text-node and
	// attribute-value character content (the normalization-form serialization
	// parameter, Serialization 3.1 §4). Scoped to text and attribute nodes; false
	// by default, keeping output byte-identical.
	normalize bool
}

// NewWriter creates a new HTML Writer with default settings.
func NewWriter() Writer {
	return Writer{}
}

// DefaultDTD controls whether a default DOCTYPE is emitted when the document
// has no DTD.
func (w Writer) DefaultDTD(v bool) Writer {
	w.noDefaultDTD = !v
	return w
}

// Format controls whether formatting whitespace is emitted in HTML output.
func (w Writer) Format(v bool) Writer {
	w.noFormat = !v
	return w
}

// PreserveCase controls whether the original case of element and attribute
// names is preserved instead of lowercasing them.
func (w Writer) PreserveCase(v bool) Writer {
	w.preserveCase = v
	return w
}

// EscapeURIAttributes controls whether non-ASCII characters in URI attributes
// are percent-encoded.
func (w Writer) EscapeURIAttributes(v bool) Writer {
	w.noEscapeURIAttributes = !v
	return w
}

// EscapeControlChars controls whether characters in the U+007F-U+009F range
// are emitted as numeric character references.
func (w Writer) EscapeControlChars(v bool) Writer {
	w.escapeControlChars = v
	return w
}

// CharacterMap installs a character map: each mapped rune appearing in text or
// attribute-value content is replaced by its literal replacement string, emitted
// verbatim (not re-escaped), per XSLT/XQuery Serialization 3.1 §7 (character maps
// apply to the html output method). A nil or empty map disables the feature,
// leaving output byte-identical.
func (w Writer) CharacterMap(m map[rune]string) Writer {
	w.charMap = m
	return w
}

// CDATAElements selects expanded names in XML islands. HTML elements ignore
// this serialization parameter (Serialization 3.1 section 7.4.4).
func (w Writer) CDATAElements(names map[string]struct{}) Writer {
	w.cdataElements = names
	return w
}

// Normalization requests Unicode normalization of text-node and attribute-value
// character content (the normalization-form serialization parameter). form is one
// of "NFC", "NFD", "NFKC", "NFKD"; "", "none", or any other value disables it,
// leaving output byte-identical. Normalization is scoped to text and attribute
// nodes (Serialization 3.1 §4 character-expansion phase) — element/attribute
// names, comments, PIs, and the DOCTYPE are never normalized. Character-map
// matches are decided on the pre-normalization content: the content is split at
// each mapped rune, each non-mapped run is normalized on its own, and each
// replacement is emitted verbatim, never normalized (Serialization 3.1 §11).
func (w Writer) Normalization(form string) Writer {
	w.normForm, w.normalize = htmlNormalizationForm(form)
	w.normalizationForm = form

	return w
}

// NullNamespaceHTMLOnly controls whether an element is recognized as an HTML
// void element (serialized with no closing tag) only when it is in no
// namespace. When true, an otherwise-void element (e.g. <meta>) in a non-null
// namespace such as XHTML is serialized with an explicit end tag. This matches
// HTML 4.01 serialization, where only no-namespace elements are HTML elements;
// HTML5 (the default, v=false) recognizes HTML void elements by local name
// regardless of namespace.
func (w Writer) NullNamespaceHTMLOnly(v bool) Writer {
	w.nullNamespaceHTMLOnly = v
	return w
}

// ContentType supplies virtual head metadata without mutating the source tree.
func (w Writer) ContentType(value string) Writer {
	w.contentType = value
	return w
}

// ForeignNamespaces serializes HTML5 XHTML, SVG and MathML elements without prefixes.
func (w Writer) ForeignNamespaces(value bool) Writer {
	w.foreignNamespaces = value
	return w
}

// Repertoire identifies characters representable in the destination encoding.
func (w Writer) Repertoire(check func(rune) bool) Writer {
	w.canEncode = check
	return w
}

// DOEMarkers honors the private disable/enable-output-escaping processing
// instructions carried by XSLT result trees. Ordinary HTML writing leaves them
// as processing instructions.
func (w Writer) DOEMarkers(value bool) Writer {
	w.doeMarkers = value
	return w
}
