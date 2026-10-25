package tree

import (
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/skarm/xmlsec/internal/xmlchar"
)

// Parse implements a bounded UTF-8/UTF-16, XML 1.0, DTD-free profile.
func Parse(ctx context.Context, data []byte, limits Limits) (*Document, error) {
	return ParseReader(ctx, bytes.NewReader(data), limits)
}

type parseFrame struct {
	node          *Node
	namespaceMark int
}

type documentParser struct {
	doc                 *Document
	decoder             *xmlTokenizer
	input               *xmlInput
	scope               namespaceContext
	pendingText         strings.Builder
	encoding            sourceEncoding
	stack               []parseFrame
	count               int
	seenDecl            bool
	characterInput      bool
	singleByteEncodings bool
	stopAtRoot          bool
	relativeNamespaces  bool
}

func (p *documentParser) parse(ctx context.Context) (*Document, error) {
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		offset := p.decoder.InputOffset()

		p.input.outside = len(p.stack) == 0

		token, err := p.decoder.RawToken()
		if errors.Is(err, io.EOF) {
			if err := p.flushText(); err != nil {
				return nil, err
			}

			break
		}

		if err != nil {
			return nil, fmt.Errorf("%w at byte %d: %w", ErrMalformed, offset, err)
		}

		if _, text := token.(xml.CharData); !text {
			if err := p.flushText(); err != nil {
				return nil, err
			}
		}

		if err := p.consumeToken(token, offset); err != nil {
			return nil, err
		}

		if p.stopAtRoot && p.doc.root != nil {
			break
		}
	}

	if p.encoding.name != nameUTF8 && !p.encoding.bom && !p.seenDecl {
		return nil, fmt.Errorf("%w: UTF-16 without BOM requires an endian-specific declaration", ErrMalformed)
	}

	if p.doc.root == nil || !p.stopAtRoot && len(p.stack) != 0 {
		return nil, fmt.Errorf("%w: missing or unclosed root", ErrMalformed)
	}

	return p.doc, nil
}

func (p *documentParser) consumeToken(token xml.Token, offset int64) error {
	switch token := token.(type) {
	case xml.StartElement:
		return p.startElement(token)
	case xml.EndElement:
		return p.endElement(token)
	case xml.CharData:
		return p.characterData(token)
	case xml.Comment:
		if bytes.Contains(token, []byte("--")) || bytes.HasSuffix(token, []byte("-")) {
			return fmt.Errorf("%w: invalid comment", ErrMalformed)
		}

		return p.appendNode(&Node{Kind: CommentNode, Data: string(token)})
	case xml.ProcInst:
		return p.processingInstruction(token, offset)
	case xml.Directive:
		return fmt.Errorf("%w: DTD/directives are disabled", ErrUnsupported)
	}

	return nil
}

func (p *documentParser) appendNode(n *Node) error {
	p.count++
	if p.count > p.doc.limits.MaxNodes {
		return fmt.Errorf("%w: nodes", ErrLimit)
	}

	if len(p.stack) > 0 {
		parent := p.stack[len(p.stack)-1].node
		n.Parent = parent
		parent.Children = append(parent.Children, n)
	} else {
		p.doc.children = append(p.doc.children, n)
	}

	return nil
}

func (p *documentParser) flushText() error {
	if p.pendingText.Len() == 0 {
		return nil
	}

	n := &Node{Kind: TextNode, Data: p.pendingText.String()}
	p.pendingText.Reset()

	return p.appendNode(n)
}

func (p *documentParser) startElement(element xml.StartElement) error {
	if len(p.stack) >= p.doc.limits.MaxDepth {
		return fmt.Errorf("%w: depth", ErrLimit)
	}

	if len(element.Attr) > p.doc.limits.MaxAttributesPerElement {
		return fmt.Errorf("%w: attributes", ErrLimit)
	}

	if !validQName(element.Name) {
		return fmt.Errorf("%w: element QName", ErrMalformed)
	}

	n := &Node{Kind: ElementNode, Prefix: element.Name.Space, Name: Name{Local: element.Name.Local}}
	if line := p.input.tokenLine; line <= 1<<32-1 {
		n.SourceLine = uint32(line)
	}

	if n.Prefix != "" {
		// The tokenizer splits both parts from one QName string. Each part can
		// escape independently through a name or prefix accessor.
		n.Prefix = strings.Clone(n.Prefix)
		n.Name.Local = strings.Clone(n.Name.Local)
	}

	if len(p.stack) > 0 {
		n.Parent = p.stack[len(p.stack)-1].node
	} else if p.doc.root != nil {
		return fmt.Errorf("%w: multiple roots", ErrMalformed)
	}

	var err error

	n.NS, err = parseNamespaceAttributes(element.Attr, p.relativeNamespaces)
	if err != nil {
		return err
	}

	mark := p.scope.push(n.NS)
	if p.scope.size() > p.doc.limits.namespaceLimit() {
		return fmt.Errorf("%w: in-scope namespaces", ErrLimit)
	}

	namespace, ok := p.scope.resolve(n.Prefix)
	if !ok || n.Prefix == nameXmlns {
		return fmt.Errorf("%w: unbound element prefix", ErrMalformed)
	}

	n.Name.Space = namespace

	n.Attrs, err = parseExpandedAttributes(element.Attr, &p.scope)
	if err != nil {
		return err
	}

	if err := p.appendNode(n); err != nil {
		return err
	}

	if n.Parent == nil {
		p.doc.root = n
	}

	p.stack = append(p.stack, parseFrame{n, mark})

	return nil
}

func parseNamespaceAttributes(attrs []xml.Attr, relativeNamespaces bool) ([]Namespace, error) {
	lexical := make(map[xml.Name]bool, len(attrs))

	var namespaces []Namespace

	for _, attribute := range attrs {
		if !validQName(attribute.Name) || lexical[attribute.Name] {
			return nil, fmt.Errorf("%w: invalid or duplicate attribute", ErrMalformed)
		}

		lexical[attribute.Name] = true
		if !isNamespaceAttribute(attribute.Name) {
			continue
		}

		prefix := attribute.Name.Local
		if attribute.Name.Space == "" {
			prefix = ""
		}

		if err := validateNamespace(prefix, attribute.Value, relativeNamespaces); err != nil {
			return nil, err
		}

		namespaces = append(namespaces, Namespace{prefix, attribute.Value})
	}

	return namespaces, nil
}

func isNamespaceAttribute(name xml.Name) bool {
	return name.Space == nameXmlns || name.Space == "" && name.Local == nameXmlns
}

func parseExpandedAttributes(attrs []xml.Attr, scope *namespaceContext) ([]Attribute, error) {
	expanded := make(map[Name]bool, len(attrs))

	count := 0

	for _, attribute := range attrs {
		if !isNamespaceAttribute(attribute.Name) {
			count++
		}
	}

	attributes := make([]Attribute, 0, count)

	for _, attribute := range attrs {
		if isNamespaceAttribute(attribute.Name) {
			continue
		}

		name := Name{Local: attribute.Name.Local}

		prefix := attribute.Name.Space
		if prefix != "" {
			namespace, ok := scope.resolve(prefix)
			if !ok {
				return nil, fmt.Errorf("%w: unbound attribute prefix", ErrMalformed)
			}

			name.Space = namespace
			name.Local = strings.Clone(name.Local)
			prefix = strings.Clone(prefix)
		}

		if expanded[name] {
			return nil, fmt.Errorf("%w: duplicate expanded attribute", ErrMalformed)
		}

		expanded[name] = true
		attributes = append(attributes, Attribute{Name: name, Prefix: prefix, Value: attribute.Value})
	}

	return attributes, nil
}

func validQName(n xml.Name) bool { return NCName(n.Local) && (n.Space == "" || NCName(n.Space)) }

func validateNamespace(p, v string, relativeNamespaces bool) error {
	if p == nameXmlns || v == XMLNSNamespace || p == nameXML && v != XMLNamespace || p != nameXML && v == XMLNamespace {
		return fmt.Errorf("%w: reserved namespace binding", ErrMalformed)
	}

	if p != "" && v == "" {
		return fmt.Errorf("%w: prefix undeclaration", ErrMalformed)
	}

	if v != "" {
		u, e := url.Parse(v)
		if e != nil || !relativeNamespaces && !u.IsAbs() || strings.ContainsAny(v, " \t\r\n") {
			return fmt.Errorf("%w: namespace URI must be absolute", ErrUnsupported)
		}
	}

	return nil
}

func (p *documentParser) endElement(element xml.EndElement) error {
	if len(p.stack) == 0 {
		return fmt.Errorf("%w: unexpected end element", ErrMalformed)
	}

	frame := p.stack[len(p.stack)-1]
	if frame.node.Prefix != element.Name.Space || frame.node.Name.Local != element.Name.Local {
		return fmt.Errorf("%w: mismatched end element", ErrMalformed)
	}

	p.scope.pop(frame.namespaceMark)
	p.stack = p.stack[:len(p.stack)-1]

	return nil
}

func (p *documentParser) characterData(data xml.CharData) error {
	if len(p.stack) == 0 {
		// xmlInput already rejected lexical references, CDATA and nonspace
		// characters outside the root, before entity decoding.
		return nil
	}

	if p.pendingText.Cap()-p.pendingText.Len() < len(data) {
		p.pendingText.Grow(max(len(data), p.pendingText.Cap()))
	}

	p.pendingText.Write(data)

	return nil
}

func (p *documentParser) processingInstruction(instruction xml.ProcInst, offset int64) error {
	if strings.EqualFold(instruction.Target, nameXML) {
		if instruction.Target != nameXML || offset != 0 || p.seenDecl {
			return fmt.Errorf("%w: XML declaration position", ErrMalformed)
		}

		if err := p.declaration(instruction.Inst); err != nil {
			return err
		}

		p.seenDecl = true

		return nil
	}

	if !NCName(instruction.Target) {
		return fmt.Errorf("%w: PI target", ErrMalformed)
	}

	return p.appendNode(&Node{Kind: PINode, Name: Name{Local: instruction.Target}, Data: string(instruction.Inst)})
}

// normalizeLexical performs XML 1.0 end-of-line and CDATA-attribute whitespace
// normalization BEFORE entity decoding. Character references to whitespace must
// not be normalized to spaces. encoding/xml by itself does not do this step.
// It also enforces separators that encoding/xml accepts too permissively.
func normalizeLexical(data []byte) ([]byte, error) {
	return normalizeOwnedLexical(bytes.Clone(data))
}

// normalizeOwnedLexical reuses a private lexical buffer. The decoder copies
// token data before this buffer is reused for the next unit.
func normalizeOwnedLexical(data []byte) ([]byte, error) {
	if err := validateXMLCharacters(data); err != nil {
		return nil, err
	}

	out := normalizeLineEndings(data)
	for i := 0; i < len(out); {
		if out[i] != '<' {
			if bytes.HasPrefix(out[i:], []byte("]]>")) {
				return nil, fmt.Errorf("%w: CDATA terminator in character data", ErrMalformed)
			}

			if out[i] == '&' {
				if err := validateCharReference(out[i:]); err != nil {
					return nil, err
				}
			}

			i++

			continue
		}

		next, err := normalizeMarkup(out, i)
		if err != nil {
			return nil, err
		}

		i = next
	}

	return out, nil
}

func validateXMLCharacters(data []byte) error {
	if !utf8.Valid(data) {
		return fmt.Errorf("%w: invalid UTF-8 data", ErrUnsupported)
	}

	for offset := 0; offset < len(data); {
		r, size := rune(data[offset]), 1
		if r >= utf8.RuneSelf {
			r, size = utf8.DecodeRune(data[offset:])
		}

		if !xmlchar.IsChar(r) {
			return fmt.Errorf("%w: invalid XML character", ErrMalformed)
		}

		offset += size
	}

	return nil
}

func normalizeLineEndings(data []byte) []byte {
	out := data
	if bytes.IndexByte(out, '\r') < 0 {
		return out
	}

	write := 0

	for read := 0; read < len(out); read++ {
		c := out[read]
		if c == '\r' {
			c = '\n'

			if read+1 < len(out) && out[read+1] == '\n' {
				read++
			}
		}

		out[write] = c
		write++
	}

	return out[:write]
}

func normalizeMarkup(out []byte, offset int) (int, error) {
	tail := out[offset:]

	var end []byte

	prefix := 0

	switch {
	case bytes.HasPrefix(tail, []byte("<!--")):
		end = []byte("-->")
		prefix = 4
	case bytes.HasPrefix(tail, []byte("<![CDATA[")):
		end = []byte("]]>")
		prefix = 9
	case bytes.HasPrefix(tail, []byte("<?")):
		end = []byte("?>")
		prefix = 2
	case bytes.HasPrefix(tail, []byte("<!")):
		return 0, fmt.Errorf("%w: DTD/directives are disabled", ErrUnsupported)
	}

	if end != nil {
		index := bytes.Index(tail[prefix:], end)
		if index < 0 {
			return 0, fmt.Errorf("%w: unterminated markup", ErrMalformed)
		}

		return offset + prefix + index + len(end), nil
	}

	index := offset + 1
	if index < len(out) && out[index] == '/' {
		return normalizeEndTag(out, index+1)
	}

	for index < len(out) && !spaceByte(out[index]) && out[index] != '/' && out[index] != '>' {
		index++
	}

	return normalizeStartTag(out, index)
}

func normalizeEndTag(out []byte, index int) (int, error) {
	for index < len(out) && !spaceByte(out[index]) && out[index] != '>' {
		index++
	}

	index = lexicalSpaceEnd(out, index)
	if index >= len(out) || out[index] != '>' {
		return 0, fmt.Errorf("%w: end tag", ErrMalformed)
	}

	return index + 1, nil
}

func normalizeStartTag(out []byte, index int) (int, error) {
	for {
		start := index
		index = lexicalSpaceEnd(out, index)

		if index >= len(out) {
			return 0, fmt.Errorf("%w: unterminated start tag", ErrMalformed)
		}

		if out[index] == '>' {
			return index + 1, nil
		}

		if out[index] == '/' {
			if index+1 >= len(out) || out[index+1] != '>' {
				return 0, fmt.Errorf("%w: empty element syntax", ErrMalformed)
			}

			return index + 2, nil
		}

		if start == index {
			return 0, fmt.Errorf("%w: attributes require whitespace", ErrMalformed)
		}

		next, err := normalizeAttribute(out, index)
		if err != nil {
			return 0, err
		}

		index = next
	}
}

func normalizeAttribute(out []byte, index int) (int, error) {
	begin := index
	for index < len(out) && !spaceByte(out[index]) && out[index] != '=' && out[index] != '>' && out[index] != '/' {
		index++
	}

	if index == begin {
		return 0, fmt.Errorf("%w: attribute name", ErrMalformed)
	}

	index = lexicalSpaceEnd(out, index)
	if index >= len(out) || out[index] != '=' {
		return 0, fmt.Errorf("%w: attribute assignment", ErrMalformed)
	}

	index = lexicalSpaceEnd(out, index+1)
	if index >= len(out) || (out[index] != '\'' && out[index] != '"') {
		return 0, fmt.Errorf("%w: quoted attribute required", ErrMalformed)
	}

	return normalizeAttributeValue(out, index+1, out[index])
}

func normalizeAttributeValue(out []byte, index int, quote byte) (int, error) {
	for index < len(out) && out[index] != quote {
		if out[index] == '&' {
			if err := validateCharReference(out[index:]); err != nil {
				return 0, err
			}
		}

		if out[index] == '\n' || out[index] == '\t' {
			out[index] = ' '
		}

		index++
	}

	if index >= len(out) {
		return 0, fmt.Errorf("%w: unterminated attribute", ErrMalformed)
	}

	return index + 1, nil
}

func lexicalSpaceEnd(out []byte, index int) int {
	for index < len(out) && spaceByte(out[index]) {
		index++
	}

	return index
}

func spaceByte(b byte) bool { return b == ' ' || b == '\t' || b == '\n' || b == '\r' }

func (p *documentParser) declaration(s []byte) error {
	label, err := validateDeclaration(s)
	if err != nil {
		return err
	}

	if label == "" {
		if p.encoding.name != nameUTF8 && !p.encoding.bom {
			return fmt.Errorf("%w: missing endian-specific encoding declaration", ErrMalformed)
		}

		return nil
	}

	if p.characterInput || p.encoding.accepts(label) {
		return nil
	}

	if !p.singleByteEncodings || p.encoding.name != nameUTF8 || p.encoding.bom {
		return fmt.Errorf("%w: unsupported or conflicting encoding declaration", ErrUnsupported)
	}

	return p.input.singleByteEncoding(label)
}

func validateDeclaration(s []byte) (string, error) {
	attrs, err := declarationAttributes(s)
	if err != nil {
		return "", err
	}

	if attrs[0].Name != (xml.Name{Local: nameXMLVersion}) || attrs[0].Value != "1.0" {
		return "", fmt.Errorf("%w: XML 1.0 is required", ErrUnsupported)
	}

	label := ""

	at := 1
	if at < len(attrs) && attrs[at].Name == (xml.Name{Local: "encoding"}) {
		label = attrs[at].Value
		if !validEncodingName(label) {
			return "", fmt.Errorf("%w: encoding name", ErrMalformed)
		}

		at++
	}

	if at < len(attrs) && attrs[at].Name == (xml.Name{Local: "standalone"}) {
		if v := attrs[at].Value; v != "yes" && v != "no" {
			return "", fmt.Errorf("%w: standalone value", ErrMalformed)
		}

		at++
	}

	if at != len(attrs) {
		return "", fmt.Errorf("%w: declaration attributes", ErrMalformed)
	}

	return label, nil
}

func declarationAttributes(s []byte) ([]xml.Attr, error) {
	if bytes.ContainsAny(s, "&<>") {
		return nil, fmt.Errorf("%w: declaration content", ErrMalformed)
	}
	// Parse declaration pseudo-attributes with the same lexical checks.
	b := make([]byte, 0, len(s)+8)
	b = append(b, "<decl "...)
	b = append(b, s...)
	b = append(b, "/>"...)

	b, err := normalizeOwnedLexical(b)
	if err != nil {
		return nil, err
	}

	el, _, err := startToken(b)
	if err != nil || len(el.Attr) == 0 || len(el.Attr) > 3 {
		return nil, fmt.Errorf("%w: declaration", ErrMalformed)
	}

	return el.Attr, nil
}

func validEncodingName(label string) bool {
	if label == "" {
		return false
	}

	for i := range len(label) {
		b := label[i]

		letter := b >= 'A' && b <= 'Z' || b >= 'a' && b <= 'z'
		if !letter && (i == 0 || !(b >= '0' && b <= '9' || b == '.' || b == '_' || b == '-')) {
			return false
		}
	}

	return true
}

// validateCharReference rejects non-XML scalars before entity expansion.
func validateCharReference(s []byte) error {
	if len(s) < 2 || s[1] != '#' {
		return nil
	}

	end := bytes.IndexByte(s, ';')
	if end < 0 {
		return fmt.Errorf("%w: character reference", ErrMalformed)
	}

	digits := s[2:end]

	base := 10
	if len(digits) > 0 && digits[0] == 'x' {
		base = 16
		digits = digits[1:]
	}

	if len(digits) == 0 {
		return fmt.Errorf("%w: character reference", ErrMalformed)
	}

	for _, r := range digits {
		if !(r >= '0' && r <= '9' || base == 16 && (r >= 'a' && r <= 'f' || r >= 'A' && r <= 'F')) {
			return fmt.Errorf("%w: character reference digits", ErrMalformed)
		}
	}

	r, err := strconv.ParseUint(string(digits), base, 32)
	if err != nil || r > utf8.MaxRune || !xmlchar.IsChar(rune(r)) {
		return fmt.Errorf("%w: illegal character reference", ErrMalformed)
	}

	return nil
}
