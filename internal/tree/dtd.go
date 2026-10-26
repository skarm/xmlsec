package tree

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"unicode/utf8"

	"github.com/skarm/xmlsec/internal/lexicon"
	"github.com/skarm/xmlsec/internal/nilcheck"
	"github.com/skarm/xmlsec/internal/xmlchar"
)

var errDTDPresent = errors.New("XML DOCTYPE present")

// DTDEntityResolver resolves a SYSTEM identifier against the entity containing
// its declaration. It returns both the authorized stream and its absolute URI.
// No filesystem or network fallback is supplied by the XML parser.
type DTDEntityResolver func(context.Context, string, string) (io.ReadCloser, string, error)

type dtdEntity struct {
	value    string
	systemID string
	publicID string
	notation string
	base     string
	external bool
}

type dtdAttribute struct {
	name       string
	kind       string
	value      string
	hasDefault bool
}

type dtdLoaded struct {
	text string
	base string
}

type dtdState struct {
	ctx          context.Context
	options      ParseOptions
	entities     map[string]dtdEntity
	parameters   map[string]dtdEntity
	attributes   map[string]map[string]dtdAttribute
	defaults     map[string][]dtdAttribute
	active       map[string]struct{}
	work         int
	declarations int
	inputBytes   int
	loaded       map[string]dtdLoaded
}

func newDTDState(ctx context.Context, options ParseOptions) *dtdState {
	return &dtdState{
		ctx:        ctx,
		options:    options,
		entities:   make(map[string]dtdEntity),
		parameters: make(map[string]dtdEntity),
		attributes: make(map[string]map[string]dtdAttribute),
		defaults:   make(map[string][]dtdAttribute),
		active:     make(map[string]struct{}),
		work:       options.Limits.MaxBytes,
		loaded:     make(map[string]dtdLoaded),
	}
}

func (d *dtdState) declare() error {
	d.declarations++
	if d.declarations > d.options.Limits.MaxNodes {
		return fmt.Errorf("%w: DTD declarations", ErrLimit)
	}

	return d.ctx.Err()
}

func (d *dtdState) charge(n int) error {
	if err := d.ctx.Err(); err != nil {
		return err
	}

	if n < 0 || n > d.work {
		return fmt.Errorf("%w: DTD expansion work", ErrLimit)
	}

	d.work -= n

	return nil
}

func (d *dtdState) enter(name string, size int) (func(), error) {
	if _, exists := d.active[name]; exists {
		return nil, fmt.Errorf("%w: recursive entity %q", ErrMalformed, name)
	}

	if len(d.active) >= d.options.Limits.MaxDepth {
		return nil, fmt.Errorf("%w: entity depth", ErrLimit)
	}

	if err := d.charge(size + 1); err != nil {
		return nil, err
	}

	d.active[name] = struct{}{}

	return func() { delete(d.active, name) }, nil
}

func (d *dtdState) load(entity dtdEntity) (string, string, error) {
	key := entity.base + "\x00" + entity.systemID
	if loaded, ok := d.loaded[key]; ok {
		return loaded.text, loaded.base, nil
	}

	if d.options.DTDResolver == nil {
		return "", "", fmt.Errorf("%w: external XML entity requires an explicit resolver", ErrUnsupported)
	}

	r, base, err := d.options.DTDResolver(d.ctx, entity.systemID, entity.base)
	if err != nil {
		if !nilcheck.IsNil(r) {
			err = errors.Join(err, r.Close())
		}

		return "", "", err
	}

	if nilcheck.IsNil(r) {
		return "", "", fmt.Errorf("%w: nil external entity stream", ErrMalformed)
	}

	counter := dtdCountingReader{source: r}

	text, err := decodeDTDInput(d.ctx, &counter, d.options, true)
	if err = errors.Join(err, r.Close()); err != nil {
		return "", "", err
	}

	size := max(counter.total, len(text))
	if size > d.options.Limits.MaxBytes-d.inputBytes {
		return "", "", fmt.Errorf("%w: total XML entity input", ErrLimit)
	}

	d.inputBytes += size
	d.loaded[key] = dtdLoaded{text: text, base: base}

	return text, base, nil
}

// decodeDTDInput decodes one physical entity once. Internal replacement text
// never passes through this function, preserving CR created by character refs.
func decodeDTDInput(ctx context.Context, source io.Reader, options ParseOptions, external bool) (string, error) {
	p, err := newDocumentReader(ctx, source, options.Limits, false, options.AllowSingleByteEncodings, options.AllowRelativeNamespaces)
	if err != nil {
		return "", err
	}

	var result strings.Builder

	checked := false
	lineEnd := dtdLineEnd{}

	for {
		if err := ctx.Err(); err != nil {
			return "", err
		}

		r, err := p.input.rune()
		if err != nil {
			if err == io.EOF { //nolint:errorlint // Preserve resource failures joined with EOF.
				break
			}

			return "", err
		}

		var keep bool

		r, keep = lineEnd.decode(r)
		if !keep {
			continue
		}

		result.WriteRune(r)

		if !checked {
			prefix := result.String()
			if len(prefix) >= 6 && (!strings.HasPrefix(prefix, "<?xml") || !spaceByte(prefix[5])) {
				checked = true
			}

			if !checked && strings.HasSuffix(prefix, "?>") {
				if err := processDTDDeclaration(&p, prefix, external); err != nil {
					return "", err
				}

				p.seenDecl, checked = true, true
			}
		}
	}

	if p.encoding.name != nameUTF8 && !p.encoding.bom && !p.seenDecl {
		return "", fmt.Errorf("%w: missing encoding declaration", ErrMalformed)
	}

	text := result.String()
	if external {
		return stripTextDeclaration(text)
	}

	return text, nil
}

func normalizeDTDLineEndings(text string) string {
	if !strings.ContainsRune(text, '\r') {
		return text
	}

	return strings.NewReplacer("\r\n", "\n", "\r", "\n").Replace(text)
}

// parseDTDText validates and expands the complete internal subset before the
// ordinary namespace-aware parser sees the resulting XML. Both the original
// characters and expanded lexical output have independent MaxBytes bounds.
func (o ParseOptions) parseDTDText(ctx context.Context, text string) (*Document, error) {
	if ctx == nil {
		return nil, ErrMalformed
	}

	if err := o.Limits.Validate(); err != nil {
		return nil, err
	}

	if len(text) > o.Limits.MaxBytes {
		return nil, ErrLimit
	}

	if err := validateXMLCharacters([]byte(text)); err != nil {
		return nil, err
	}

	state := newDTDState(ctx, o)
	state.inputBytes = len(text)

	var output dtdOutput

	output.maximum = o.Limits.MaxBytes

	output.maximumNodes = o.Limits.MaxNodes
	if err := state.content(normalizeDTDLineEndings(strings.TrimPrefix(text, "\uFEFF")), o.BaseURI, &output, true); err != nil {
		return nil, err
	}

	doc, err := parseXMLReader(ctx, strings.NewReader(output.String()), o.Limits, true, false, o.AllowRelativeNamespaces)
	if err != nil {
		return nil, err
	}

	metadata := dtdMetadata{doc: doc, state: state, output: &output}
	for _, child := range doc.children {
		if err := metadata.visit(child); err != nil {
			return nil, err
		}
	}

	doc.unparsedEntities = make(map[string]UnparsedEntity)

	for name, entity := range state.entities {
		if entity.notation != "" {
			doc.unparsedEntities[name] = UnparsedEntity{SystemID: entity.systemID, PublicID: entity.publicID, BaseURI: entity.base}
		}
	}

	doc.inputBytes = state.inputBytes

	return doc, nil
}

func (o ParseOptions) parseDTDReader(ctx context.Context, source io.Reader) (*Document, error) {
	captured := dtdProbeReader{source: source}

	probe, err := newDocumentReader(ctx, &captured, o.Limits, false, o.AllowSingleByteEncodings, o.AllowRelativeNamespaces)
	if err != nil {
		return nil, err
	}

	probe.input.dtdProbe, probe.stopAtRoot = true, true

	_, probeErr := probe.parse(ctx)
	if probeErr != nil && !errors.Is(probeErr, errDTDPresent) {
		return nil, probeErr
	}

	captured.replay = true

	replay := io.MultiReader(bytes.NewReader(captured.prefix.Bytes()), &captured)
	if !errors.Is(probeErr, errDTDPresent) {
		return parseXMLReader(ctx, replay, o.Limits, false, o.AllowSingleByteEncodings, o.AllowRelativeNamespaces)
	}

	text, err := decodeDTDInput(ctx, replay, o, false)
	if err != nil {
		return nil, err
	}

	doc, err := o.parseDTDText(ctx, text)
	if err != nil {
		return nil, err
	}

	if difference := captured.total - len(text); difference > 0 {
		if difference > o.Limits.MaxBytes-doc.inputBytes {
			return nil, ErrLimit
		}

		doc.inputBytes += difference
	}

	return doc, nil
}

type dtdOutput struct {
	strings.Builder
	maximum      int
	maximumNodes int
	fixes        []dtdTextFix
	bases        []string
}

func (b *dtdOutput) nodeBudget() error {
	if len(b.bases)+len(b.fixes) >= b.maximumNodes {
		return fmt.Errorf("%w: expanded XML nodes", ErrLimit)
	}

	return nil
}

func (b *dtdOutput) write(text string) error {
	if len(text) > b.maximum-b.Len() {
		return fmt.Errorf("%w: expanded XML bytes", ErrLimit)
	}

	_, _ = b.WriteString(text)

	return nil
}

func (b *dtdOutput) attribute(name, value string) error {
	if err := b.write(" " + name + `="`); err != nil {
		return err
	}

	if err := b.writeEscaped(value, true); err != nil {
		return err
	}

	return b.write(`"`)
}

// Expand one bounded lexical chunk directly, rather than allocating an escaped
// string before checking the expanded-output byte limit.
func (b *dtdOutput) writeEscaped(text string, attribute bool) error {
	start := 0

	for at, r := range text {
		replacement := ""

		switch r {
		case '&':
			replacement = "&amp;"
		case '<':
			replacement = "&lt;"
		case '>':
			if !attribute {
				replacement = "&gt;"
			}
		case '"':
			if attribute {
				replacement = "&quot;"
			}
		case '\r':
			replacement = "&#13;"
		case '\n':
			if attribute {
				replacement = "&#10;"
			}
		case '\t':
			if attribute {
				replacement = "&#9;"
			}
		}

		if replacement == "" {
			continue
		}

		if err := b.write(text[start:at]); err != nil {
			return err
		}

		if err := b.write(replacement); err != nil {
			return err
		}

		start = at + utf8.RuneLen(r)
	}

	return b.write(text[start:])
}

func dtdReference(text string) (name string, rest string, err error) {
	before, after, ok := strings.Cut(text, ";")
	if !ok {
		return "", "", fmt.Errorf("%w: unterminated entity reference", ErrMalformed)
	}

	name = before
	if !xmlchar.IsValidNCName(name) {
		return "", "", fmt.Errorf("%w: entity name", ErrMalformed)
	}

	return name, after, nil
}

func dtdCharacterReference(text string) (string, int, error) {
	end := strings.IndexByte(text, ';')
	if end < 0 {
		return "", 0, fmt.Errorf("%w: unterminated character reference", ErrMalformed)
	}

	lexical := []byte(text[:end+1])
	if err := validateCharReference(lexical); err != nil {
		return "", 0, err
	}

	value, err := tokenValue(lexical, false)

	return string(value), end + 1, err
}

func dtdPredefined(name string) (string, bool) {
	switch name {
	case entityAmp:
		return "&", true
	case "lt":
		return "<", true
	case "gt":
		return ">", true
	case "apos":
		return "'", true
	case "quot":
		return `"`, true
	default:
		return "", false
	}
}

func dtdNameEnd(text string) int {
	at := 0
	for at < len(text) {
		r, n := utf8.DecodeRuneInString(text[at:])

		valid := r == ':' || xmlchar.IsNCNameChar(r)
		if at == 0 {
			valid = r == ':' || xmlchar.IsNCNameStartChar(r)
		}

		if !valid {
			break
		}

		at += n
	}

	return at
}

// dtdMarkupEnd respects quotes, comments and processing instructions. The
// scanner used for a DOCTYPE additionally tracks internal-subset brackets.
func dtdDelimitedEnd(text string) (int, bool, error) {
	if strings.HasPrefix(text, "<!--") {
		end := strings.Index(text[4:], "-->")
		if end < 0 || strings.Contains(text[4:4+end], "--") || strings.HasSuffix(text[4:4+end], "-") {
			return 0, true, fmt.Errorf("%w: comment", ErrMalformed)
		}

		return end + 7, true, nil
	}

	if strings.HasPrefix(text, "<?") {
		end := strings.Index(text[2:], "?>")
		if end < 0 {
			return 0, true, ErrMalformed
		}

		return end + 4, true, nil
	}

	return 0, false, nil
}

func dtdMarkupEnd(text string, doctype bool) (int, error) {
	if end, special, err := dtdDelimitedEnd(text); special {
		return end, err
	}

	if !doctype {
		return dtdTagEnd(text)
	}

	quote, brackets := byte(0), 0
	for at := 0; at < len(text); at++ {
		if quote != 0 {
			if text[at] == quote {
				quote = 0
			}

			continue
		}

		if end, special, err := dtdDelimitedEnd(text[at:]); special {
			if err != nil {
				return 0, err
			}

			at += end - 1

			continue
		}

		switch text[at] {
		case '\'', '"':
			quote = text[at]
		case '[':
			brackets++
		case ']':
			brackets--
		case '>':
			if brackets == 0 {
				return at + 1, nil
			}
		}
	}

	return 0, fmt.Errorf("%w: unterminated DOCTYPE", ErrMalformed)
}

func dtdTagEnd(text string) (int, error) {
	quote := byte(0)
	for at := 0; at < len(text); at++ {
		if quote != 0 {
			if text[at] == quote {
				quote = 0
			}

			continue
		}

		switch text[at] {
		case '\'', '"':
			quote = text[at]
		case '>':
			return at + 1, nil
		}
	}

	return 0, fmt.Errorf("%w: unterminated XML markup", ErrMalformed)
}

// Once replay starts, a prefetched terminal error is delivered after the
// captured bytes, even when the root start tag made the probe return early.
type dtdProbeReader struct {
	source   io.Reader
	prefix   bytes.Buffer
	terminal error
	replay   bool
	total    int
}

func (r *dtdProbeReader) Read(dst []byte) (int, error) {
	if r.replay && r.terminal != nil {
		return 0, r.terminal
	}

	n, err := r.source.Read(dst)

	r.total += n
	if !r.replay {
		r.prefix.Write(dst[:n])
		r.terminal = err
	}

	return n, err
}

type dtdCountingReader struct {
	source io.Reader
	total  int
}

func (r *dtdCountingReader) Read(dst []byte) (int, error) {
	n, err := r.source.Read(dst)
	r.total += n

	return n, err
}

func processDTDDeclaration(p *documentParser, prefix string, external bool) error {
	declaration := []byte(prefix[5 : len(prefix)-2])
	if external {
		attrs, err := declarationAttributes(declaration)
		if err != nil {
			return err
		}

		if attrs[0].Name.Local != lexicon.DeclVersion {
			declaration = append([]byte(` version="1.0" `), declaration...)
		}

		if _, err := stripTextDeclaration(prefix); err != nil {
			return err
		}
	}

	if err := p.declaration(declaration); err != nil {
		return err
	}

	return nil
}

type dtdMetadata struct {
	doc       *Document
	state     *dtdState
	output    *dtdOutput
	baseIndex int
	fixIndex  int
}

func (m *dtdMetadata) visit(node *Node) error {
	if err := m.state.ctx.Err(); err != nil {
		return err
	}

	switch node.Kind {
	case ElementNode:
		if m.baseIndex >= len(m.output.bases) {
			return ErrMalformed
		}

		if base := m.output.bases[m.baseIndex]; base != "" {
			if m.doc.nodeBases == nil {
				m.doc.nodeBases = make(map[*Node]string)
			}

			m.doc.nodeBases[node] = base
		}

		m.baseIndex++

		name := node.Name.Local
		if node.Prefix != "" {
			name = node.Prefix + ":" + name
		}

		for i := range node.Attrs {
			attribute := &node.Attrs[i]

			attrName := attribute.Name.Local
			if attribute.Prefix != "" {
				attrName = attribute.Prefix + ":" + attrName
			}

			if declaration, ok := m.state.attributes[name][attrName]; ok {
				kind := DTDNoType
				switch declaration.kind {
				case "ID":
					kind = DTDID
				case "IDREF":
					kind = DTDIDRef
				case "IDREFS":
					kind = DTDIDRefs
				}

				SetAttributeDTDType(m.doc, node, attribute.Name, kind)
			}
		}
	case CommentNode, PINode:
		if m.fixIndex >= len(m.output.fixes) || m.output.fixes[m.fixIndex].kind != node.Kind {
			return ErrMalformed
		}

		node.Data = strings.Clone(m.output.fixes[m.fixIndex].value)
		SetNodeBase(m.doc, node, m.output.fixes[m.fixIndex].base)
		m.fixIndex++
	}

	for _, child := range node.Children {
		if err := m.visit(child); err != nil {
			return err
		}
	}

	return nil
}

type dtdLineEnd struct{ cr bool }

func (s *dtdLineEnd) decode(r rune) (rune, bool) {
	if s.cr && r == '\n' {
		s.cr = false
		return r, false
	}

	s.cr = r == '\r'
	if s.cr {
		r = '\n'
	}

	return r, true
}
