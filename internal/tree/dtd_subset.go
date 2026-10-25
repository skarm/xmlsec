package tree

import (
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/skarm/xmlsec/internal/lexicon"
	"github.com/skarm/xmlsec/internal/xmlchar"
)

type dtdFrame struct {
	text     string
	base     string
	at       int
	external bool
	release  func()
}

type dtdScanner struct {
	state         *dtdState
	frames        []dtdFrame
	err           error
	inDeclaration bool
}

func (d *dtdState) scanner(text, base string, external bool) *dtdScanner {
	return &dtdScanner{state: d, frames: []dtdFrame{{text: text, base: base, external: external}}}
}

func (s *dtdScanner) raw() string {
	for len(s.frames) > 0 {
		frame := &s.frames[len(s.frames)-1]

		if frame.at < len(frame.text) {
			return frame.text[frame.at:]
		}

		if frame.release != nil {
			frame.release()
		}

		s.frames = s.frames[:len(s.frames)-1]
	}

	return ""
}

func (s *dtdScanner) fail(message string) {
	if s.err == nil {
		s.err = fmt.Errorf("%w: DTD %s", ErrMalformed, message)
	}
}

func (s *dtdScanner) external() bool {
	s.raw()
	return len(s.frames) > 0 && s.frames[len(s.frames)-1].external
}

func (s *dtdScanner) base() string {
	s.raw()

	if len(s.frames) == 0 {
		return ""
	}

	return s.frames[len(s.frames)-1].base
}

func (s *dtdScanner) advance(n int) {
	if n < 0 || len(s.frames) == 0 || n > len(s.raw()) {
		s.fail("token boundary")
		return
	}

	s.frames[len(s.frames)-1].at += n
}

func (s *dtdScanner) text() string {
	for s.err == nil {
		text := s.raw()

		if !strings.HasPrefix(text, "%") {
			return text
		}

		if s.inDeclaration && !s.external() {
			s.fail("parameter reference within internal markup declaration")
			return ""
		}

		name, rest, err := dtdReference(text[1:])
		if err != nil {
			s.err = err
			return ""
		}

		base, external := s.base(), s.external()
		s.advance(len(text) - len(rest))

		entity, ok := s.state.parameters[name]
		if !ok {
			s.fail("undeclared parameter entity")
			return ""
		}

		value := entity.value

		if entity.external {
			value, base, err = s.state.load(entity)
			external = true

			if err != nil {
				s.err = err
				return ""
			}
		}

		release, err := s.state.enter("%"+name, len(value))
		if err != nil {
			s.err = err
			return ""
		}

		s.frames = append(s.frames, dtdFrame{text: " " + value + " ", base: base, external: external, release: release})
	}

	return ""
}

func (s *dtdScanner) take(token string) bool {
	if !strings.HasPrefix(s.text(), token) {
		return false
	}

	s.advance(len(token))

	return true
}

func (s *dtdScanner) require(token string) {
	if !s.take(token) {
		s.fail("expected " + token)
	}
}

func (s *dtdScanner) space(required bool) {
	count := 0

	for {
		text := s.text()
		at := 0

		for at < len(text) && spaceByte(text[at]) {
			at++
		}

		if at == 0 {
			break
		}

		count += at
		s.advance(at)
	}

	if required && count == 0 {
		s.fail("missing whitespace")
	}
}

func (s *dtdScanner) name() string {
	text := s.text()

	end := dtdNameEnd(text)
	if end == 0 {
		s.fail("expected XML name")

		return ""
	}

	s.advance(end)

	return strings.Clone(text[:end])
}

func (s *dtdScanner) qualifiedName() string {
	name := s.name()
	if !xmlchar.IsValidQName(name) {
		s.fail("QName")
	}

	return name
}

func (s *dtdScanner) quoted() string {
	text := s.text()
	if len(text) == 0 || text[0] != '\'' && text[0] != '"' {
		s.fail("expected quoted literal")

		return ""
	}

	end := strings.IndexByte(text[1:], text[0])
	if end < 0 {
		s.fail("unterminated literal")

		return ""
	}

	value := strings.Clone(text[1 : end+1])
	s.advance(end + 2)

	return value
}

func (s *dtdScanner) close() {
	for _, frame := range s.frames {
		if frame.release != nil {
			frame.release()
		}
	}

	s.frames = nil
}

func (d *dtdState) doctype(text, base string) error {
	s := d.scanner(text, base, false)
	defer s.close()

	s.require(dtdDoctypeOpen)
	s.space(true)
	s.qualifiedName()
	s.space(false)

	entity := dtdEntity{base: base}

	if strings.HasPrefix(s.text(), "SYSTEM") || strings.HasPrefix(s.text(), "PUBLIC") {
		entity.systemID, entity.publicID = s.externalID(false)
		entity.external = true

		s.space(false)
	}

	if s.take("[") {
		if err := s.declarations("]"); err != nil {
			return err
		}

		s.require("]")
		s.space(false)
	}

	s.require(">")

	if s.raw() != "" {
		s.fail("trailing DOCTYPE content")
	}

	if s.err != nil {
		return s.err
	}

	if entity.external {
		text, base, err := d.load(entity)
		if err != nil {
			return err
		}

		external := d.scanner(text, base, true)
		defer external.close()

		return external.declarations("")
	}

	return nil
}

func (s *dtdScanner) externalID(publicOnly bool) (string, string) {
	public := ""

	if s.take("SYSTEM") {
		s.space(true)
		return s.quoted(), public
	}

	s.require("PUBLIC")
	s.space(true)
	public = s.quoted()

	for _, r := range public {
		if !(r == '\r' || r == '\n' || r == ' ' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("-'()+,./:=?;!*#@$_%", r)) {
			s.fail("public identifier character")
		}
	}

	public = xmlchar.CollapseSpace(public)
	before := s.text()
	s.space(false)

	if publicOnly && (s.text() == "" || s.text()[0] != '\'' && s.text()[0] != '"') {
		return "", public
	}

	if before == s.text() {
		s.fail("missing system identifier separator")
	}

	return s.quoted(), public
}

func (s *dtdScanner) declarations(stop string) error {
	for s.err == nil {
		if err := s.state.ctx.Err(); err != nil {
			return err
		}

		s.space(false)

		text := s.text()
		if text == "" || stop != "" && strings.HasPrefix(text, stop) {
			return s.err
		}

		switch {
		case strings.HasPrefix(text, "<!--"):
			end, err := dtdMarkupEnd(text, false)
			if err != nil {
				return err
			}

			s.advance(end)
		case strings.HasPrefix(text, "<?"):
			if err := s.processingInstruction(text); err != nil {
				return err
			}
		case strings.HasPrefix(text, "<!["):
			if !s.external() {
				s.fail("conditional section in internal subset")
				break
			}

			if err := s.conditional(); err != nil {
				return err
			}
		default:
			if err := s.state.declare(); err != nil {
				return err
			}

			s.inDeclaration = true

			switch {
			case s.take("<!ENTITY"):
				s.entity()
			case s.take("<!ATTLIST"):
				s.attlist()
			case s.take("<!ELEMENT"):
				s.element()
			case s.take("<!NOTATION"):
				s.notation()
			default:
				s.fail("markup declaration")
			}

			s.inDeclaration = false
		}
	}

	return s.err
}

func (s *dtdScanner) processingInstruction(text string) error {
	end, err := dtdMarkupEnd(text, false)
	if err != nil {
		return err
	}

	body := text[2 : end-2]

	nameEnd := dtdNameEnd(body)
	if nameEnd == 0 || !xmlchar.IsValidNCName(body[:nameEnd]) || strings.EqualFold(body[:nameEnd], lexicon.PrefixXML) || nameEnd < len(body) && !spaceByte(body[nameEnd]) {
		s.fail("processing instruction")
	}

	s.advance(end)

	return s.err
}

func (s *dtdScanner) conditional() error {
	s.require("<![")
	s.space(false)
	kind := s.name()
	s.space(false)
	s.require("[")

	if kind == "INCLUDE" {
		if err := s.declarations("]]>"); err != nil {
			return err
		}

		s.require("]]>")

		return s.err
	}

	if kind != "IGNORE" {
		s.fail("conditional section keyword")
		return s.err
	}

	depth := 1

	for depth > 0 && s.err == nil {
		text := s.raw()
		if text == "" {
			s.fail("unterminated ignored section")
			break
		}

		if strings.HasPrefix(text, "<![") {
			depth++

			s.advance(3)
		} else if strings.HasPrefix(text, "]]>") {
			depth--

			s.advance(3)
		} else {
			s.advance(1)
		}

		if depth > s.state.options.Limits.MaxDepth {
			return fmt.Errorf("%w: DTD conditional depth", ErrLimit)
		}

		if err := s.state.ctx.Err(); err != nil {
			return err
		}
	}

	return s.err
}

func (s *dtdScanner) rawSpace(required bool) {
	text := s.raw()
	at := 0

	for at < len(text) && spaceByte(text[at]) {
		at++
	}

	if required && at == 0 {
		s.fail("missing whitespace")
	}

	s.advance(at)
}

func (s *dtdScanner) entity() {
	s.rawSpace(true)

	parameter := false
	// A declaration's percent sign is followed by S, unlike a reference.
	if strings.HasPrefix(s.raw(), "%") {
		parameter = true

		s.advance(1)
		s.rawSpace(true)
	}

	name := s.name()
	if !xmlchar.IsValidNCName(name) {
		s.fail("entity NCName")
	}

	s.space(true)
	entity := dtdEntity{base: s.base()}

	if strings.HasPrefix(s.text(), "SYSTEM") || strings.HasPrefix(s.text(), "PUBLIC") {
		entity.external = true
		entity.systemID, entity.publicID = s.externalID(false)
	} else {
		external := s.external()
		raw := s.quoted()

		value, err := s.state.entityValue(raw, external)
		if err != nil {
			s.err = err
			return
		}

		entity.value = value
	}

	before := s.text()
	s.space(false)
	separated := before != s.text()

	if !parameter && s.take("NDATA") {
		if !separated {
			s.fail("NDATA separator")
		}

		if !entity.external {
			s.fail("NDATA on internal entity")
		}

		s.space(true)

		entity.notation = s.name()
		if !xmlchar.IsValidNCName(entity.notation) {
			s.fail("notation NCName")
		}

		s.space(false)
	}

	s.require(">")

	if wanted, predefined := dtdPredefined(name); predefined && !parameter {
		valid := !entity.external && entity.notation == ""

		if valid && strings.HasPrefix(entity.value, "&#") {
			value, n, err := dtdCharacterReference(entity.value)
			valid = err == nil && n == len(entity.value) && value == wanted
		} else {
			valid = valid && name != entityAmp && name != "lt" && entity.value == wanted
		}

		if !valid {
			s.fail("invalid predefined entity declaration")
		}
	}

	entities := s.state.entities

	if parameter {
		entities = s.state.parameters
	}

	if _, exists := entities[name]; !exists && s.err == nil {
		entities[name] = entity
	}
}

func (d *dtdState) entityValue(text string, external bool) (string, error) {
	var output dtdOutput

	output.maximum = d.options.Limits.MaxBytes
	for text != "" {
		if err := d.ctx.Err(); err != nil {
			return "", err
		}

		at := strings.IndexAny(text, "&%")
		if at < 0 {
			at = len(text)
		}

		if err := output.write(text[:at]); err != nil {
			return "", err
		}

		text = text[at:]
		if text == "" {
			break
		}

		value, rest, err := d.entityValueReference(text, external)
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

func (d *dtdState) entityValueReference(text string, external bool) (string, string, error) {
	if strings.HasPrefix(text, "&#") {
		value, n, err := dtdCharacterReference(text)
		return value, text[n:], err
	}

	marker := text[0]

	name, rest, err := dtdReference(text[1:])
	if err != nil {
		return "", "", err
	}

	if marker == '&' {
		return text[:len(text)-len(rest)], rest, nil
	}

	if !external {
		return "", "", fmt.Errorf("%w: parameter entity in internal entity value", ErrMalformed)
	}

	value, err := d.parameterValue(name)

	return value, rest, err
}

func (d *dtdState) parameterValue(name string) (string, error) {
	entity, ok := d.parameters[name]
	if !ok {
		return "", fmt.Errorf("%w: undeclared parameter entity", ErrMalformed)
	}

	value := entity.value
	if entity.external {
		var err error

		value, _, err = d.load(entity)
		if err != nil {
			return "", err
		}
	}

	release, err := d.enter("%"+name, len(value))
	if err != nil {
		return "", err
	}
	defer release()

	return d.entityValue(value, true)
}

func (s *dtdScanner) attlist() {
	s.space(true)

	element := s.qualifiedName()

	for s.err == nil {
		before := s.text()
		s.space(false)

		if s.take(">") {
			return
		}

		if before == s.text() {
			s.fail("attribute declaration separator")
			return
		}

		attribute := s.attributeDeclaration()
		if s.err != nil {
			return
		}

		existing := s.state.attributes[element]
		if existing == nil {
			existing = make(map[string]dtdAttribute)
			s.state.attributes[element] = existing
		}

		if _, duplicate := existing[attribute.name]; !duplicate {
			existing[attribute.name] = attribute
			if attribute.hasDefault {
				s.state.defaults[element] = append(s.state.defaults[element], attribute)
			}
		}
	}
}

func (s *dtdScanner) attributeDeclaration() dtdAttribute {
	var attribute dtdAttribute

	if err := s.state.declare(); err != nil {
		s.err = err
		return attribute
	}

	attribute.name = s.name()
	if !xmlchar.IsValidQName(attribute.name) {
		s.fail("attribute QName")
	}

	s.space(true)

	if strings.HasPrefix(s.text(), "(") {
		attribute.kind = "NMTOKEN"

		s.enumeration(false)
	} else {
		attribute.kind = s.name()

		switch attribute.kind {
		case dtdCDATA, "ID", "IDREF", "IDREFS", "ENTITY", "ENTITIES", "NMTOKEN", "NMTOKENS":
		case "NOTATION":
			s.space(true)
			s.enumeration(true)
		default:
			s.fail("attribute type")
		}
	}

	s.space(true)

	if !s.take("#REQUIRED") && !s.take("#IMPLIED") {
		if s.take("#FIXED") {
			s.space(true)
		}

		attribute.hasDefault = true

		value, err := s.state.attributeValue(s.quoted())
		if err != nil {
			s.err = err
			return attribute
		}

		if attribute.kind != dtdCDATA {
			value = collapseDTDSpace(value)
		}

		attribute.value = value
	}

	return attribute
}

func (s *dtdScanner) enumeration(notation bool) {
	s.require("(")
	s.space(false)

	for s.err == nil {
		text := s.text()
		end := 0

		for end < len(text) {
			r, n := utf8.DecodeRuneInString(text[end:])
			if r != ':' && !xmlchar.IsNCNameChar(r) {
				break
			}

			end += n
		}

		if end == 0 || notation && !xmlchar.IsValidNCName(text[:end]) {
			s.fail("enumeration token")
			return
		}

		s.advance(end)
		s.space(false)

		if s.take(")") {
			return
		}

		s.require("|")
		s.space(false)
	}
}

func (s *dtdScanner) notation() {
	s.space(true)

	if !xmlchar.IsValidNCName(s.name()) {
		s.fail("notation NCName")
	}

	s.space(true)
	s.externalID(true)
	s.space(false)
	s.require(">")
}

func (s *dtdScanner) element() {
	s.space(true)
	s.qualifiedName()
	s.space(true)

	if strings.HasPrefix(s.text(), "(") {
		s.require("(")
		s.space(false)

		if s.take("#PCDATA") {
			count := 0

			s.space(false)

			for s.take("|") {
				s.space(false)
				s.name()

				count++

				s.space(false)
			}

			s.require(")")

			star := s.take("*")
			if count > 0 && !star {
				s.fail("mixed content repetition")
			}
		} else {
			s.group(1)
			s.quantifier()
		}
	} else if kind := s.name(); kind != "EMPTY" && kind != "ANY" {
		s.fail("element content model")
	}

	s.space(false)
	s.require(">")
}

func (s *dtdScanner) quantifier() {
	if !s.take("?") && !s.take("*") {
		s.take("+")
	}
}

// group starts just after '(', and consumes the matching ')'.
func (s *dtdScanner) group(depth int) {
	if depth > s.state.options.Limits.MaxDepth {
		s.err = fmt.Errorf("%w: content model depth", ErrLimit)
		return
	}

	s.cp(depth)
	s.space(false)

	separator := ""

	for s.err == nil {
		if s.take(")") {
			return
		}

		if separator == "" {
			if s.take("|") {
				separator = "|"
			} else {
				s.require(",")

				separator = ","
			}
		} else {
			s.require(separator)
		}

		s.space(false)
		s.cp(depth)
		s.space(false)
	}
}

func (s *dtdScanner) cp(depth int) {
	if s.take("(") {
		s.space(false)
		s.group(depth + 1)
	} else {
		s.qualifiedName()
	}

	s.quantifier()
}
