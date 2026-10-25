package tree

import (
	"context"
	"errors"
	"fmt"
	"io"
	"maps"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/skarm/xmlsec/internal/lexicon"

	"github.com/skarm/xmlsec/internal/nilcheck"
	norm "github.com/skarm/xmlsec/internal/normalization"
	"github.com/skarm/xmlsec/internal/streamio"
	"github.com/skarm/xmlsec/internal/xmlchar"
)

// XMLWriteOptions configures ordinary and XPath/XSLT XML serialization over the
// same document storage. The zero value preserves the document writer format.
type XMLWriteOptions struct {
	// EmptyElement optionally selects name-dependent empty-element syntax.
	EmptyElement func(Name) EmptyElementMode
	// PreserveContent disables added indentation throughout selected content;
	// InlineElement also prevents whitespace adjacent to selected children.
	PreserveContent, InlineElement func(Name) bool
	// AttributeWriter handles selected values before ordinary character expansion.
	// A handled value is already escaped for its surrounding double quotes.
	AttributeWriter func(context.Context, io.Writer, Name, Attribute) (bool, error)
	// CanEncode reports the output character repertoire. Unrepresentable content
	// is written as numeric references; markup names still have to be encodable.
	CanEncode                            func(rune) bool
	CharacterMap                         map[rune]string
	CDATA, SuppressIndent                map[string]struct{}
	InheritedNamespaces                  map[string]string
	IndentString, Version, Normalization string
	// NormalizeXMLID applies the XDM xml:id string value during serialization,
	// without changing the original XML snapshot. Ordinary XML output leaves it off.
	NormalizeXMLID bool
	// EscapeControlChars applies serialization's C1/NEL/LS reference rules in
	// both XML editions; ordinary document output leaves this disabled.
	EscapeControlChars                                        bool
	DOEMarkers                                                bool
	Indent, SelfClose, ASCII, PrefixUndeclarations, Reconcile bool
}

type EmptyElementMode uint8

const (
	EmptyElementDefault EmptyElementMode = iota
	EmptyElementExpanded
	EmptyElementSpaced
)

// WriteXMLFragment serializes a private content sequence, including empty or
// text-only content, with the same escaping, cancellation and output budget.
func WriteXMLFragment(ctx context.Context, dst io.Writer, nodes []*Node, maxBytes int) (int64, error) {
	return WriteXMLFragmentOptions(ctx, dst, nodes, maxBytes, XMLWriteOptions{})
}

// WriteXMLFragmentOptions serializes private or immutable nodes without mutation.
func WriteXMLFragmentOptions(ctx context.Context, dst io.Writer, nodes []*Node, maxBytes int, options XMLWriteOptions) (int64, error) {
	if ctx == nil || nilcheck.IsNil(dst) || maxBytes <= 0 {
		return 0, fmt.Errorf("%w: XML output configuration", ErrMalformed)
	}

	if err := ctx.Err(); err != nil {
		return 0, err
	}

	bindings := maps.Clone(options.InheritedNamespaces)
	if bindings == nil {
		bindings = make(map[string]string)
	}

	w := &xmlStream{ctx: ctx, output: streamio.Writer{Context: ctx, Target: dst, Limit: int64(maxBytes), LimitError: fmt.Errorf("%w: XML output bytes", ErrLimit)}, options: options, ns: namespaceContext{bindings: bindings}}

	doe := false
	for _, n := range nodes {
		w.sibling(n, &doe, false)

		if w.err != nil {
			break
		}
	}

	return w.output.Written, errors.Join(w.err, ctx.Err())
}

// WriteXML serializes the snapshot incrementally in the same format as XML,
// checking cancellation and a positive output-byte budget. The tree remains
// resident; no complete serialized buffer is built unless dst collects it.
// It leaves dst open. On failure discard any partial output. An arbitrary
// blocked Write requires cancellation support from dst itself.
func (d *Document) WriteXML(ctx context.Context, dst io.Writer, maxBytes int) (int64, error) {
	if ctx == nil || nilcheck.IsNil(dst) || d == nil || d.root == nil || maxBytes <= 0 {
		return 0, fmt.Errorf("%w: XML output configuration", ErrMalformed)
	}

	return WriteXMLFragment(ctx, dst, d.children, maxBytes)
}

type xmlStream struct {
	ctx           context.Context
	output        streamio.Writer
	escaper       xmlEscaper
	reference     [16]byte
	err           error
	options       XMLWriteOptions
	ns            namespaceContext
	spacePreserve bool
	depth         int
}

func (w *xmlStream) Write(p []byte) (int, error) {
	if w.err != nil {
		return 0, w.err
	}

	n, e := w.output.Write(p)
	w.err = e

	return n, e
}

func (w *xmlStream) WriteString(s string) (int, error) {
	if w.err != nil {
		return 0, w.err
	}

	n, e := w.output.WriteString(s)
	w.err = e

	return n, e
}

func (w *xmlStream) text(s string) { _, _ = w.WriteString(s) }

func (w *xmlStream) node(n *Node) {
	if w.err != nil {
		return
	}

	if e := w.ctx.Err(); e != nil {
		w.err = e
		return
	}

	switch n.Kind {
	case ElementNode:
		w.writeElement(n)
	case TextNode:
		w.escaped(n.Data, false)
	case CommentNode:
		if strings.Contains(n.Data, "--") || strings.HasSuffix(n.Data, "-") {
			w.err = ErrMalformed
			return
		}

		if !w.markupCharacters(n.Data) {
			return
		}

		w.text("<!--")
		w.text(n.Data)
		w.text("-->")
	case PINode:
		if strings.Contains(n.Data, "?>") || strings.EqualFold(n.Name.Local, lexicon.PrefixXML) {
			w.err = ErrMalformed
			return
		}

		if !w.markupCharacters(n.Name.Local) || !w.markupCharacters(n.Data) {
			return
		}

		w.text("<?")
		w.text(n.Name.Local)

		if n.Data != "" {
			w.text(" ")
			w.text(n.Data)
		}

		w.text("?>")
	}
}

func (w *xmlStream) markupCharacters(value string) bool {
	if w.err != nil {
		return false
	}

	if !utf8.ValidString(value) {
		w.err = ErrMalformed
		return false
	}

	for _, r := range value {
		if !xmlchar.IsLiteralChar(r, w.options.Version == lexicon.XMLVersion11) {
			w.err = ErrMalformed
			return false
		}

		if w.options.ASCII && r > 127 || w.options.CanEncode != nil && !w.options.CanEncode(r) {
			w.err = fmt.Errorf("%w: %U", ErrUnencodable, r)
			return false
		}
	}

	return true
}

func (w *xmlStream) newline() {
	w.text("\n")

	indent := w.options.IndentString
	if indent == "" {
		indent = "  "
	}

	for range w.depth {
		w.text(indent)
	}
}

func (w *xmlStream) normalized(s string, emit func(string)) {
	var form norm.Form

	switch w.options.Normalization {
	case "NFC":
		form = norm.NFC
	case "NFD":
		form = norm.NFD
	case "NFKC":
		form = norm.NFKC
	case "NFKD":
		form = norm.NFKD
	default:
		emit(s)
		return
	}

	if err := form.Each(w.ctx, s, func(part string) error {
		emit(part)
		return w.err
	}); err != nil {
		w.err = err
	}
}

func (w *xmlStream) cdata(s string) {
	// SER31 section 11 excludes text selected for CDATA from character maps,
	// including characters emitted outside CDATA as numeric references.
	charMap := w.options.CharacterMap
	w.options.CharacterMap = nil
	w.normalized(s, w.cdataPart)
	w.options.CharacterMap = charMap
}

func (w *xmlStream) cdataPart(s string) {
	if !utf8.ValidString(s) {
		w.err = ErrMalformed
		return
	}

	start := 0

	write := func(s string) {
		if s != "" {
			w.text("<![CDATA[")

			for s != "" && w.err == nil {
				i := strings.Index(s, "]]>")
				if i < 0 {
					w.text(s)
					break
				}

				w.text(s[:i])
				w.text("]]]]><![CDATA[>")

				s = s[i+3:]
			}

			w.text("]]>")
		}
	}
	for i, r := range s {
		_, mapped := w.options.CharacterMap[r]
		if mapped || r == '\r' || w.needsCharacterReference(r) || !xmlchar.IsChar(r) {
			write(s[start:i])
			w.escaped(string(r), false)
			start = i + utf8.RuneLen(r)
		}

		if w.err != nil {
			return
		}
	}

	write(s[start:])
}

func (w *xmlStream) escaped(s string, attribute bool) {
	if w.err != nil {
		return
	}

	emit := func(value string) { w.escapedPart(value, attribute) }

	charMap := w.options.CharacterMap
	if len(charMap) == 0 {
		w.normalized(s, emit)
		return
	}

	if !utf8.ValidString(s) {
		w.err = ErrMalformed
		return
	}

	// Match original characters before normalization. Neither replacements
	// nor characters introduced by normalization may be mapped again.
	w.options.CharacterMap = nil
	defer func() { w.options.CharacterMap = charMap }()

	start := 0

	for at, r := range s {
		if replacement, mapped := charMap[r]; mapped {
			w.normalized(s[start:at], emit)
			w.text(replacement)

			start = at + utf8.RuneLen(r)

			if w.err != nil {
				return
			}
		}
	}

	w.normalized(s[start:], emit)
}

func (w *xmlStream) escapedPart(s string, attribute bool) {
	if w.err != nil {
		return
	}

	if !utf8.ValidString(s) {
		w.err = ErrMalformed
		return
	}

	if len(w.options.CharacterMap) == 0 && !w.options.ASCII && !w.options.EscapeControlChars && w.options.Version != lexicon.XMLVersion11 && w.options.CanEncode == nil {
		for _, r := range s {
			if !xmlchar.IsChar(r) {
				w.err = ErrMalformed
				return
			}
		}

		if w.err == nil {
			w.err = w.escaper.write(w, s, func(c byte) string { return xmlEscape(c, attribute) })
		}

		return
	}

	start := 0

	for i, r := range s {
		replacement, mapped := w.characterReplacement(r, attribute)
		if w.err != nil {
			return
		}

		numeric := !mapped && w.needsCharacterReference(r)
		if mapped || numeric {
			w.text(s[start:i])

			if numeric {
				w.writeCharacterReference(r)
			} else {
				w.text(replacement)
			}

			start = i + utf8.RuneLen(r)

			if w.err != nil {
				return
			}
		}
	}

	w.text(s[start:])
}

func (w *xmlStream) characterReplacement(r rune, attribute bool) (string, bool) {
	if replacement, ok := w.options.CharacterMap[r]; ok {
		return replacement, true
	}

	if w.options.Version == lexicon.XMLVersion11 && !xmlchar.IsXML11Char(r) || w.options.Version != lexicon.XMLVersion11 && !xmlchar.IsChar(r) {
		w.err = ErrMalformed
		return "", false
	}

	if r >= 0 && r < utf8.RuneSelf {
		if replacement := xmlEscape(byte(r), attribute); replacement != "" {
			return replacement, true
		}
	}

	return "", false
}

func (w *xmlStream) needsCharacterReference(r rune) bool {
	return w.options.ASCII && r > 127 ||
		w.options.EscapeControlChars && (r >= 0x7f && r <= 0x9f || r == 0x2028) ||
		w.options.Version == lexicon.XMLVersion11 && xmlchar.IsXML11SerializeAsCharRef(r) ||
		r > 127 && w.options.CanEncode != nil && !w.options.CanEncode(r)
}

func (w *xmlStream) writeCharacterReference(r rune) {
	buffer := append(w.reference[:0], '&', '#')
	buffer = strconv.AppendInt(buffer, int64(r), 10)
	buffer = append(buffer, ';')
	_, _ = w.Write(buffer)
}

func (w *xmlStream) writeElement(n *Node) {
	if !NCName(n.Name.Local) || n.Prefix != "" && !NCName(n.Prefix) {
		w.err = ErrMalformed
		return
	}

	if !w.markupCharacters(QName(n.Prefix, n.Name.Local)) {
		return
	}

	w.text("<")
	w.text(QName(n.Prefix, n.Name.Local))
	mark := len(w.ns.undo)
	scope := w.ns.bindings
	emitted := make(map[string]bool, len(n.NS)+2)

	declare := func(prefix, uri string) {
		if prefix == lexicon.PrefixXML || emitted[prefix] {
			return
		}

		if prefix != "" && uri == "" && !w.options.PrefixUndeclarations {
			return
		}

		if w.options.Reconcile && scope[prefix] == uri {
			emitted[prefix] = true
			return
		}

		emitted[prefix] = true
		w.ns.push([]Namespace{{Prefix: prefix, URI: uri}})
		w.text(" xmlns")

		if prefix != "" {
			w.text(":")
			w.text(prefix)
		}

		w.text("=\"")
		// Namespace nodes are markup, outside the character-expansion phase.
		charMap := w.options.CharacterMap
		w.options.CharacterMap = nil
		w.escapedPart(uri, true)
		w.options.CharacterMap = charMap
		w.text("\"")
	}
	for _, ns := range n.NS {
		declare(ns.Prefix, ns.URI)
	}

	nodeReconcile(w, scope, n, declare)

	w.writeAttributes(n)

	if len(n.Children) == 0 && w.closeEmptyElement(n.Name) {
		w.ns.pop(mark)
		return
	}

	w.text(">")
	previousSpace := w.applySpace(n)

	pretty := w.indentContent(n)

	key := "{" + n.Name.Space + "}" + n.Name.Local

	indent := w.options.Indent
	if w.options.PreserveContent != nil && w.options.PreserveContent(n.Name) {
		pretty = false
		w.options.Indent = false
	}

	if _, suppressed := w.options.SuppressIndent[key]; suppressed {
		pretty = false
		w.options.Indent = false
	}

	_, cdata := w.options.CDATA[key]
	w.depth++

	nodeChildren(n, pretty, w, cdata)

	w.depth--

	w.options.Indent = indent

	w.spacePreserve = previousSpace
	if pretty && len(n.Children) > 0 {
		w.newline()
	}

	w.text("</")
	w.text(QName(n.Prefix, n.Name.Local))
	w.text(">")
	w.ns.pop(mark)
}

func (w *xmlStream) indentContent(n *Node) bool {
	if !w.options.Indent || w.spacePreserve {
		return false
	}

	for _, child := range n.Children {
		if child.Kind == TextNode || child.Kind == ElementNode && w.options.InlineElement != nil && w.options.InlineElement(child.Name) {
			return false
		}
	}

	return true
}

func (w *xmlStream) applySpace(n *Node) bool {
	previousSpace := w.spacePreserve

	for _, attribute := range n.Attrs {
		if attribute.Name == (Name{Space: XMLNamespace, Local: xmlSpaceName}) {
			switch attribute.Value {
			case "preserve":
				w.spacePreserve = true
			case "default":
				w.spacePreserve = false
			}
		}
	}

	return previousSpace
}

func (w *xmlStream) writeAttributes(n *Node) {
	for _, a := range n.Attrs {
		if !w.markupCharacters(QName(a.Prefix, a.Name.Local)) {
			return
		}

		w.text(" ")
		w.text(QName(a.Prefix, a.Name.Local))
		w.text("=\"")

		value := a.Value
		if w.options.NormalizeXMLID && a.Name == (Name{Space: XMLNamespace, Local: "id"}) {
			value = xmlchar.CollapseSpace(value)
		}

		handled := false

		if w.options.AttributeWriter != nil {
			a.Value = value
			handled, w.err = w.options.AttributeWriter(w.ctx, w, n.Name, a)
		}

		if !handled && w.err == nil {
			w.escaped(value, true)
		}

		w.text("\"")
	}
}

func (w *xmlStream) closeEmptyElement(name Name) bool {
	if !w.options.SelfClose {
		return false
	}

	mode := EmptyElementDefault
	if w.options.EmptyElement != nil {
		mode = w.options.EmptyElement(name)
	}

	if mode == EmptyElementExpanded {
		return false
	}

	if mode == EmptyElementSpaced {
		w.text(" />")
	} else {
		w.text("/>")
	}

	return true
}

func nodeChildren(n *Node, pretty bool, w *xmlStream, cdata bool) {
	doe := false

	for _, c := range n.Children {
		if pretty {
			w.newline()
		}

		w.sibling(c, &doe, cdata)

		if w.err != nil {
			break
		}
	}
}

func (w *xmlStream) sibling(n *Node, doe *bool, cdata bool) {
	if w.options.DOEMarkers && n.Kind == PINode && n.Name.Space == "" {
		switch n.Name.Local {
		case "disable-output-escaping":
			*doe = true
			return
		case "enable-output-escaping":
			*doe = false
			return
		}
	}

	if n.Kind == TextNode && *doe {
		w.normalized(n.Data, w.text)
	} else if n.Kind == TextNode && cdata {
		w.cdata(n.Data)
	} else {
		w.node(n)
	}
}

func nodeReconcile(w *xmlStream, scope map[string]string, n *Node, declare func(prefix string, uri string)) {
	if w.options.Reconcile {
		if scope[n.Prefix] != n.Name.Space {
			declare(n.Prefix, n.Name.Space)
		}

		for _, a := range n.Attrs {
			if a.Prefix != "" && scope[a.Prefix] != a.Name.Space {
				declare(a.Prefix, a.Name.Space)
			}
		}
	}
}
