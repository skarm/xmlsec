package tree

import (
	"fmt"
	"strings"

	"github.com/skarm/xmlsec/internal/lexicon"
	"github.com/skarm/xmlsec/internal/xmlchar"
)

type dtdTextFix struct {
	kind  Kind
	value string
	base  string
}

func (d *dtdState) attributeValue(text string) (string, error) {
	var output dtdOutput

	output.maximum = d.options.Limits.MaxBytes
	for text != "" {
		if err := d.ctx.Err(); err != nil {
			return "", err
		}

		at := strings.IndexByte(text, '&')
		if at < 0 {
			at = len(text)
		}

		literal := text[:at]
		if strings.ContainsRune(literal, '<') {
			return "", fmt.Errorf("%w: '<' in attribute value", ErrMalformed)
		}

		literal = strings.ReplaceAll(strings.ReplaceAll(strings.ReplaceAll(literal, "\r", " "), "\n", " "), "\t", " ")
		if err := output.write(literal); err != nil {
			return "", err
		}

		text = text[at:]
		if text == "" {
			break
		}

		value, rest, err := d.attributeReference(text)
		if err != nil {
			return "", err
		}

		if err := output.write(value); err != nil {
			return "", err
		}

		text = rest
	}

	return output.String(), nil
}

func (d *dtdState) attributeReference(text string) (string, string, error) {
	if strings.HasPrefix(text, "&#") {
		value, n, err := dtdCharacterReference(text)
		return value, text[n:], err
	}

	name, rest, err := dtdReference(text[1:])
	if err != nil {
		return "", "", err
	}

	if value, ok := dtdPredefined(name); ok {
		return value, rest, nil
	}

	entity, ok := d.entities[name]
	if !ok {
		return "", "", fmt.Errorf("%w: undeclared entity %q", ErrMalformed, name)
	}

	if entity.external || entity.notation != "" {
		return "", "", fmt.Errorf("%w: external entity in attribute", ErrMalformed)
	}

	release, err := d.enter("&"+name, len(entity.value))
	if err != nil {
		return "", "", err
	}
	defer release()

	value, err := d.attributeValue(entity.value)

	return value, rest, err
}

type dtdRawAttribute struct {
	name  string
	value string
}

func readDTDAttribute(text string) (dtdRawAttribute, int, error) {
	end := dtdNameEnd(text)
	if end == 0 {
		return dtdRawAttribute{}, 0, ErrMalformed
	}

	attribute := dtdRawAttribute{name: text[:end]}

	at := end
	for at < len(text) && spaceByte(text[at]) {
		at++
	}

	if at >= len(text) || text[at] != '=' {
		return attribute, 0, ErrMalformed
	}

	at++
	for at < len(text) && spaceByte(text[at]) {
		at++
	}

	if at >= len(text) || text[at] != '\'' && text[at] != '"' {
		return attribute, 0, ErrMalformed
	}

	quote := text[at]
	at++

	end = strings.IndexByte(text[at:], quote)
	if end < 0 {
		return attribute, 0, ErrMalformed
	}

	attribute.value = text[at : at+end]

	return attribute, at + end + 1, nil
}

func readDTDStartTag(text string, maximum int) (string, []dtdRawAttribute, bool, error) {
	end := dtdNameEnd(text[1:])
	if end == 0 {
		return "", nil, false, ErrMalformed
	}

	name := text[1 : 1+end]
	at := 1 + end

	var attributes []dtdRawAttribute

	for at < len(text) {
		before := at
		for at < len(text) && spaceByte(text[at]) {
			at++
		}

		switch text[at:] {
		case "/>":
			return name, attributes, true, nil
		case ">":
			return name, attributes, false, nil
		}

		if before == at {
			return "", nil, false, fmt.Errorf("%w: attribute separator", ErrMalformed)
		}

		if len(attributes) >= maximum {
			return "", nil, false, ErrLimit
		}

		attribute, n, err := readDTDAttribute(text[at:])
		if err != nil {
			return "", nil, false, err
		}

		attributes = append(attributes, attribute)
		at += n
	}

	return "", nil, false, ErrMalformed
}

func (d *dtdState) startTag(text string, output *dtdOutput) (string, bool, error) {
	name, attributes, empty, err := readDTDStartTag(text, d.options.Limits.MaxAttributesPerElement)
	if err != nil {
		return "", false, err
	}

	if err := output.write("<" + name); err != nil {
		return "", false, err
	}

	seen := make(map[string]struct{}, len(attributes))

	count := len(attributes)
	for _, attribute := range attributes {
		if _, exists := seen[attribute.name]; exists {
			return "", false, fmt.Errorf("%w: duplicate attribute", ErrMalformed)
		}

		seen[attribute.name] = struct{}{}

		value, err := d.attributeValue(attribute.value)
		if err != nil {
			return "", false, err
		}

		if declaration, ok := d.attributes[name][attribute.name]; ok && declaration.kind != dtdCDATA {
			value = collapseDTDSpace(value)
		}

		if err := output.attribute(attribute.name, value); err != nil {
			return "", false, err
		}
	}

	for _, declaration := range d.defaults[name] {
		if _, exists := seen[declaration.name]; exists {
			continue
		}

		count++
		if count > d.options.Limits.MaxAttributesPerElement {
			return "", false, ErrLimit
		}

		if err := output.attribute(declaration.name, declaration.value); err != nil {
			return "", false, err
		}
	}

	ending := ">"
	if empty {
		ending = "/>"
	}

	return name, empty, output.write(ending)
}

func (d *dtdState) content(text, base string, output *dtdOutput, document bool) error {
	return d.entityContent(text, base, output, document, "")
}

// Each entity's element stack is independent: replacement text cannot close
// its parent's element, nor leave a start tag for the containing entity to close.
func (d *dtdState) entityContent(text, base string, output *dtdOutput, document bool, rootBase string) error {
	p := dtdContentParser{state: d, text: text, base: base, output: output, document: document, rootBase: rootBase, first: true}
	for p.text != "" {
		if err := d.ctx.Err(); err != nil {
			return err
		}

		if err := p.step(); err != nil {
			return err
		}

		p.first = false
	}

	if len(p.stack) != 0 {
		return fmt.Errorf("%w: unclosed entity element", ErrMalformed)
	}

	return nil
}

type dtdContentParser struct {
	state       *dtdState
	text        string
	base        string
	rootBase    string
	output      *dtdOutput
	stack       []string
	document    bool
	first       bool
	seenRoot    bool
	seenDoctype bool
}

func (p *dtdContentParser) step() error {
	switch {
	case strings.HasPrefix(p.text, dtdDoctypeOpen):
		return p.doctype()
	case strings.HasPrefix(p.text, "<!--"):
		return p.comment()
	case strings.HasPrefix(p.text, "<![CDATA["):
		return p.cdata()
	case strings.HasPrefix(p.text, "<?"):
		return p.processingInstruction()
	case strings.HasPrefix(p.text, "</"):
		return p.endTag()
	case p.text[0] == '<':
		return p.startTag()
	case p.text[0] == '&':
		return p.reference()
	default:
		return p.characters()
	}
}

func (p *dtdContentParser) doctype() error {
	if !p.document || p.seenRoot || p.seenDoctype {
		return fmt.Errorf("%w: DOCTYPE position", ErrMalformed)
	}

	end, err := dtdMarkupEnd(p.text, true)
	if err != nil {
		return err
	}

	if err := p.state.doctype(p.text[:end], p.base); err != nil {
		return err
	}

	p.text = p.text[end:]
	p.seenDoctype = true

	return nil
}

func (p *dtdContentParser) comment() error {
	end, err := dtdMarkupEnd(p.text, false)
	if err != nil {
		return err
	}

	if err := p.output.nodeBudget(); err != nil {
		return err
	}

	p.output.fixes = append(p.output.fixes, dtdTextFix{kind: CommentNode, value: p.text[4 : end-3]})
	if err := p.output.write(p.text[:end]); err != nil {
		return err
	}

	p.text = p.text[end:]

	return nil
}

func (p *dtdContentParser) cdata() error {
	if p.document && len(p.stack) == 0 {
		return fmt.Errorf("%w: CDATA outside document element", ErrMalformed)
	}

	end := strings.Index(p.text[9:], "]]>")
	if end < 0 {
		return fmt.Errorf("%w: CDATA terminator", ErrMalformed)
	}

	if err := p.output.writeEscaped(p.text[9:9+end], false); err != nil {
		return err
	}

	p.text = p.text[end+12:]

	return nil
}

func (p *dtdContentParser) piBase() string {
	if len(p.stack) == 0 {
		return p.rootBase
	}

	return ""
}

func (p *dtdContentParser) processingInstruction() error {
	end, err := dtdMarkupEnd(p.text, false)
	if err != nil {
		return err
	}

	body := p.text[2 : end-2]

	nameEnd := dtdNameEnd(body)
	if nameEnd == 0 {
		return ErrMalformed
	}

	if body[:nameEnd] == lexicon.PrefixXML && (!p.document || !p.first) {
		return fmt.Errorf("%w: XML declaration position", ErrMalformed)
	}

	if body[:nameEnd] != lexicon.PrefixXML {
		at := nameEnd
		for at < len(body) && spaceByte(body[at]) {
			at++
		}

		if err := p.output.nodeBudget(); err != nil {
			return err
		}

		p.output.fixes = append(p.output.fixes, dtdTextFix{kind: PINode, value: body[at:], base: p.piBase()})
	}

	if err := p.output.write(p.text[:end]); err != nil {
		return err
	}

	p.text = p.text[end:]

	return nil
}

func (p *dtdContentParser) endTag() error {
	end, err := dtdMarkupEnd(p.text, false)
	if err != nil {
		return err
	}

	name := strings.TrimRight(p.text[2:end-1], " \t\r\n")
	if len(p.stack) == 0 || p.stack[len(p.stack)-1] != name {
		return fmt.Errorf("%w: unbalanced entity elements", ErrMalformed)
	}

	p.stack = p.stack[:len(p.stack)-1]

	if err := p.output.write(p.text[:end]); err != nil {
		return err
	}

	p.text = p.text[end:]

	return nil
}

func (p *dtdContentParser) startTag() error {
	end, err := dtdMarkupEnd(p.text, false)
	if err != nil {
		return err
	}

	name, empty, err := p.state.startTag(p.text[:end], p.output)
	if err != nil {
		return err
	}

	nodeBase := ""
	if len(p.stack) == 0 {
		nodeBase = p.rootBase
	}

	if err := p.output.nodeBudget(); err != nil {
		return err
	}

	p.output.bases = append(p.output.bases, nodeBase)
	p.seenRoot = true

	if !empty {
		p.stack = append(p.stack, name)
		if len(p.stack) > p.state.options.Limits.MaxDepth {
			return ErrLimit
		}
	}

	p.text = p.text[end:]

	return nil
}

func (p *dtdContentParser) reference() error {
	if p.document && len(p.stack) == 0 {
		return fmt.Errorf("%w: entity outside document element", ErrMalformed)
	}

	if strings.HasPrefix(p.text, "&#") {
		value, n, err := dtdCharacterReference(p.text)
		if err != nil {
			return err
		}

		if err := p.output.writeEscaped(value, false); err != nil {
			return err
		}

		p.text = p.text[n:]

		return nil
	}

	name, rest, err := dtdReference(p.text[1:])
	if err != nil {
		return err
	}

	if value, ok := dtdPredefined(name); ok {
		if err := p.output.writeEscaped(value, false); err != nil {
			return err
		}
	} else {
		entity, ok := p.state.entities[name]
		if !ok {
			return fmt.Errorf("%w: undeclared entity %q", ErrMalformed, name)
		}

		if entity.notation != "" {
			return fmt.Errorf("%w: reference to unparsed entity", ErrMalformed)
		}

		value, entityBase, override := entity.value, p.base, ""
		if entity.external {
			value, entityBase, err = p.state.load(entity)
			if err != nil {
				return err
			}

			override = entityBase
		}

		release, err := p.state.enter("&"+name, len(value))
		if err != nil {
			return err
		}

		err = p.state.entityContent(value, entityBase, p.output, false, override)

		release()

		if err != nil {
			return err
		}
	}

	p.text = rest

	return nil
}

func (p *dtdContentParser) characters() error {
	end := strings.IndexAny(p.text, "<&")
	if end < 0 {
		end = len(p.text)
	}

	value := p.text[:end]
	if strings.Contains(value, "]]>") {
		return fmt.Errorf("%w: CDATA terminator in text", ErrMalformed)
	}

	if p.document && len(p.stack) == 0 && !xmlchar.IsAllSpace(value) {
		return fmt.Errorf("%w: text outside document element", ErrMalformed)
	}

	if err := p.output.writeEscaped(value, false); err != nil {
		return err
	}

	p.text = p.text[end:]

	return nil
}

// XML 1.0 section 3.3.3 collapses only #x20 after reference expansion.
// Referenced TAB, CR and LF survive this non-CDATA normalization step.
func collapseDTDSpace(text string) string {
	var result strings.Builder

	space := false

	for _, r := range text {
		if r == ' ' {
			space = result.Len() > 0
			continue
		}

		if space {
			result.WriteByte(' ')

			space = false
		}

		result.WriteRune(r)
	}

	return result.String()
}
