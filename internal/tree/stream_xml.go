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

	norm "github.com/skarm/xmlsec/internal/normalization"

	"github.com/skarm/xmlsec/internal/nilcheck"
	"github.com/skarm/xmlsec/internal/streamio"
	"github.com/skarm/xmlsec/internal/xmlchar"
)

// XMLWriteOptions configures ordinary and XPath/XSLT XML serialization over the
// same document storage. The zero value preserves the document writer format.
type XMLWriteOptions struct {
	// CanEncode reports the output character repertoire. Unrepresentable content
	// is written as numeric references; markup names still have to be encodable.
	CanEncode                            func(rune) bool
	CharacterMap                         map[rune]string
	CDATA, SuppressIndent                map[string]struct{}
	InheritedNamespaces                  map[string]string
	IndentString, Version, Normalization string
	// NormalizeXMLID applies the XDM xml:id string value during serialization,
	// without changing the original XML snapshot. Ordinary XML output leaves it off.
	NormalizeXMLID                                            bool
	Indent, SelfClose, ASCII, PrefixUndeclarations, Reconcile bool
}

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
	for _, n := range nodes {
		w.node(n)

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
	ctx       context.Context
	output    streamio.Writer
	escaper   xmlEscaper
	reference [16]byte
	err       error
	options   XMLWriteOptions
	ns        namespaceContext
	depth     int
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

		w.text("<!--")
		w.text(n.Data)
		w.text("-->")
	case PINode:
		if strings.Contains(n.Data, "?>") || strings.EqualFold(n.Name.Local, nameXML) {
			w.err = ErrMalformed
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

	if len(w.options.CharacterMap) == 0 && !w.options.ASCII && w.options.Version != version11 && w.options.CanEncode == nil {
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

	if w.options.Version == version11 && !xmlchar.IsXML11Char(r) || w.options.Version != version11 && !xmlchar.IsChar(r) {
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
		w.options.Version == version11 && xmlchar.IsXML11SerializeAsCharRef(r) ||
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

	w.text("<")
	w.text(QName(n.Prefix, n.Name.Local))
	mark := len(w.ns.undo)
	scope := w.ns.bindings
	emitted := make(map[string]bool, len(n.NS)+2)

	declare := func(prefix, uri string) {
		if prefix == nameXML || emitted[prefix] {
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

	for _, a := range n.Attrs {
		w.text(" ")
		w.text(QName(a.Prefix, a.Name.Local))
		w.text("=\"")

		value := a.Value
		if w.options.NormalizeXMLID && a.Name == (Name{Space: XMLNamespace, Local: "id"}) {
			value = xmlchar.CollapseSpace(value)
		}

		w.escaped(value, true)
		w.text("\"")
	}

	if len(n.Children) == 0 && w.options.SelfClose {
		w.text("/>")
		w.ns.pop(mark)

		return
	}

	w.text(">")
	pretty := w.options.Indent

	for _, c := range n.Children {
		if c.Kind == TextNode {
			pretty = false
		}
	}

	key := "{" + n.Name.Space + "}" + n.Name.Local

	indent := w.options.Indent
	if _, suppressed := w.options.SuppressIndent[key]; suppressed {
		pretty = false
		w.options.Indent = false
	}

	_, cdata := w.options.CDATA[key]
	w.depth++

	nodeChildren(n, pretty, w, cdata)

	w.depth--

	w.options.Indent = indent
	if pretty && len(n.Children) > 0 {
		w.newline()
	}

	w.text("</")
	w.text(QName(n.Prefix, n.Name.Local))
	w.text(">")
	w.ns.pop(mark)
}

func nodeChildren(n *Node, pretty bool, w *xmlStream, cdata bool) {
	for _, c := range n.Children {
		if pretty {
			w.newline()
		}

		if cdata && c.Kind == TextNode {
			w.cdata(c.Data)
		} else {
			w.node(c)
		}

		if w.err != nil {
			break
		}
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
