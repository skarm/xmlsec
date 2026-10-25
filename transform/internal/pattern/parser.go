// Adapted from github.com/knroy/go-xml, xpath/regex_backtrack.go.
// Commit eb327e4c08420169c271e94708b5c803d58e91f9.
// Copyright (c) 2026 Komol Nath Roy. MIT License; see licenses/MIT-knroy-go-xml.txt.

package pattern

import (
	"errors"
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"
)

// maxBacktrackGroups bounds the capture count. The capture vector is copied on
// each saved branch, so the limit bounds snapshot size.
const maxBacktrackGroups = 128

type btNode interface{ isBTNode() }

// btAlt is an alternation. Branches are tried left to right, which is the
// order the language requires.
type btAlt struct{ branches []btNode }

func (*btAlt) isBTNode() {}

type btSeq struct{ items []btNode }

func (*btSeq) isBTNode() {}

// btRepeat is a quantified sub-expression. most < 0 means unbounded.
type btRepeat struct {
	node  btNode
	least int
	most  int
	lazy  bool
}

func (*btRepeat) isBTNode() {}

// btGroup is a parenthesised sub-expression. index is 0 for a non-capturing
// group, otherwise its 1-based capture number.
type btGroup struct {
	index int
	node  btNode
}

func (*btGroup) isBTNode() {}

type btChar struct {
	set *characterSet
	src string
}

func (*btChar) isBTNode() {}

// btLiteral is a run of ordinary characters, kept whole so the common case
// costs one comparison rather than one per character.
type btLiteral struct {
	text []rune
	fold bool
}

func (*btLiteral) isBTNode() {}

// btBackref is a \N reference. literal holds the digits that turned out not to
// be part of the number, under the same greedy rule splitBackrefs uses:
// "\12" is group 12 when twelve groups exist and group 1 followed by "2"
// otherwise.
type btBackref struct {
	group   int
	literal []rune
	fold    bool
}

func (*btBackref) isBTNode() {}

type btAnchor struct {
	end       bool
	absolute  bool
	multiline bool
}

func (*btAnchor) isBTNode() {}

type btEmpty struct{}

func (*btEmpty) isBTNode() {}

// ---------------------------------------------------------------------------
// Parser
// ---------------------------------------------------------------------------

// btParser parses translated XPath/XSD expressions into an immutable tree.
// Unicode classes and subtraction retain their structure through compilation.
type btParser struct {
	src    string
	pos    int
	groups int
	// closed is the set of capturing groups whose ")" has already been read.
	// It is what a backreference may name, and the reason the resolution
	// happens during the parse rather than after it: Appendix F's backReference
	// is "'\\' [1-9][0-9]*" constrained to a group that *precedes* it, so
	// "\\1(abc)" and "(a\\1)" are malformed patterns, not patterns that match
	// nothing. Resolving afterwards, when every group is known, accepted both.
	closed map[int]struct{}
	dotAll bool
	fold   bool
	// multiline is the "m" flag, which decides whether ^ and $ match at line
	// boundaries as well as at the ends of the input.
	multiline bool
	depth     int
	resolver  func(string) *unicode.RangeTable
}

func (p *btParser) errf(format string, a ...any) error {
	return fmt.Errorf("FORX0002: "+format, a...)
}

// parseAlternation is the top level: branch ("|" branch)*.
func (p *btParser) parseAlternation() (btNode, error) {
	first, err := p.parseSequence()
	if err != nil {
		return nil, err
	}

	if p.pos >= len(p.src) || p.src[p.pos] != '|' {
		return first, nil
	}

	branches := []btNode{first}

	for p.pos < len(p.src) && p.src[p.pos] == '|' {
		p.pos++

		b, err := p.parseSequence()
		if err != nil {
			return nil, err
		}

		branches = append(branches, b)
	}

	return &btAlt{branches: branches}, nil
}

// parseSequence reads pieces until "|" or ")" or the end.
func (p *btParser) parseSequence() (btNode, error) {
	var items []btNode

	for p.pos < len(p.src) {
		if c := p.src[p.pos]; c == '|' || c == ')' {
			break
		}

		n, err := p.parsePiece()
		if err != nil {
			return nil, err
		}

		if n == nil {
			continue
		}

		items = append(items, n)
	}

	switch len(items) {
	case 0:
		return &btEmpty{}, nil
	case 1:
		return items[0], nil
	}

	return &btSeq{items: items}, nil
}

// parsePiece is one atom with its optional quantifier.
func (p *btParser) parsePiece() (btNode, error) {
	atom, err := p.parseAtom()
	if err != nil {
		return nil, err
	}

	least, most, lazy, ok, err := p.parseQuantifier()
	if err != nil {
		return nil, err
	}

	if !ok {
		return atom, nil
	}
	// A quantifier binds to the last *character* of a literal run, not to the
	// whole run: "abc*" is "ab" then "c*". The run is split rather than
	// re-lexed so the common unquantified case still coalesces.
	if lit, isLit := atom.(*btLiteral); isLit && len(lit.text) > 1 {
		last := &btLiteral{text: lit.text[len(lit.text)-1:], fold: lit.fold}
		head := &btLiteral{text: lit.text[:len(lit.text)-1], fold: lit.fold}

		return &btSeq{items: []btNode{
			head, &btRepeat{node: last, least: least, most: most, lazy: lazy},
		}}, nil
	}

	return &btRepeat{node: atom, least: least, most: most, lazy: lazy}, nil
}

// parseQuantifier reads "*", "+", "?" or "{n,m}", each optionally followed by
// "?" for the lazy form.
func (p *btParser) parseQuantifier() (least, most int, lazy, ok bool, err error) {
	if p.pos >= len(p.src) {
		return 0, 0, false, false, nil
	}

	switch p.src[p.pos] {
	case '*':
		least, most = 0, -1
	case '+':
		least, most = 1, -1
	case '?':
		least, most = 0, 1
	case '{':
		n, m, end, e := p.parseBraces(p.pos)
		if e != nil {
			return 0, 0, false, false, e
		}

		least, most = n, m
		p.pos = end - 1 // the shared advance below steps past "}"
	default:
		return 0, 0, false, false, nil
	}

	p.pos++
	if p.pos < len(p.src) && p.src[p.pos] == '?' {
		lazy = true
		p.pos++
	}

	return least, most, lazy, true, nil
}

// parseBraces reads "{n}", "{n,}" or "{n,m}" starting at the "{".
func (p *btParser) parseBraces(at int) (least, most, end int, err error) {
	closing := strings.IndexByte(p.src[at:], '}')
	if closing < 0 {
		return 0, 0, 0, p.errf("unterminated quantifier")
	}

	body := p.src[at+1 : at+closing]
	end = at + closing + 1
	lo, hi, found := strings.Cut(body, ",")

	least, err = parseCount(lo)
	if err != nil {
		return 0, 0, 0, fmt.Errorf("invalid quantifier {%s}: %w", body, err)
	}

	if !found {
		return least, least, end, nil
	}

	if hi == "" {
		return least, -1, end, nil
	}

	most, err = parseCount(hi)
	if err != nil {
		return 0, 0, 0, fmt.Errorf("invalid quantifier {%s}: %w", body, err)
	}

	if most < least {
		return 0, 0, 0, p.errf("invalid quantifier {%s}", body)
	}

	return least, most, end, nil
}

func parseCount(s string) (int, error) {
	if s == "" {
		return 0, errors.New("empty repeat count")
	}

	n := 0

	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, errors.New("invalid repeat count")
		}

		if n > (int(^uint(0)>>1)-int(c-'0'))/10 {
			return 0, ErrLimit
		}

		n = n*10 + int(c-'0')
	}

	return n, nil
}

// parseAtom reads one atom: a group, a class, an escape, a dot, an anchor, or
// a run of literal characters.
func (p *btParser) parseAtom() (btNode, error) {
	c := p.src[p.pos]
	switch c {
	case '(':
		return p.parseGroup()
	case '[':
		return p.parseClass()
	case '.':
		p.pos++
		return p.compileCharAtom(".")
	case '^':
		p.pos++
		return &btAnchor{end: false, multiline: p.multiline}, nil
	case '$':
		p.pos++
		return &btAnchor{end: true, multiline: p.multiline}, nil
	case '\\':
		return p.parseEscape()
	case '*', '+', '?':
		return nil, p.errf("quantifier %q has nothing to repeat", string(c))
	case '{':
		// A brace that does not open a valid quantifier is a literal in some
		// dialects; XML Schema's grammar makes "{" a metacharacter that must
		// be escaped, and checkRegexGrammar has already had its say, so
		// reaching here means a quantifier with nothing before it.
		return nil, p.errf("quantifier has nothing to repeat")
	}

	return p.parseLiteralRun()
}

// parseLiteralRun coalesces ordinary characters into one node, stopping one
// character short if a quantifier follows so the quantifier binds correctly.
func (p *btParser) parseLiteralRun() (btNode, error) {
	start := p.pos
	for p.pos < len(p.src) {
		c := p.src[p.pos]
		if strings.IndexByte(`()[].^$\|*+?{`, c) >= 0 {
			break
		}

		_, size := utf8.DecodeRuneInString(p.src[p.pos:])
		p.pos += size
	}

	if p.pos == start {
		return nil, p.errf("unexpected character %q", string(p.src[start]))
	}

	return &btLiteral{text: []rune(p.src[start:p.pos]), fold: p.fold}, nil
}

// parseGroup reads "(" ... ")", capturing unless it begins "(?:".
func (p *btParser) parseGroup() (btNode, error) {
	p.depth++
	defer func() { p.depth-- }()

	if p.depth > 128 {
		return nil, ErrLimit
	}

	p.pos++ // "("
	index := 0

	fold, dotAll, multiline := p.fold, p.dotAll, p.multiline
	if strings.HasPrefix(p.src[p.pos:], "?:") {
		p.pos += 2
	} else if p.pos < len(p.src) && p.src[p.pos] == '?' {
		empty, err := p.parseGroupModifiers()
		if err != nil {
			return nil, err
		}

		if empty {
			return &btEmpty{}, nil
		}
	} else {
		p.groups++

		index = p.groups
		if p.groups > maxBacktrackGroups {
			return nil, ErrLimit
		}
	}

	defer func() { p.fold, p.dotAll, p.multiline = fold, dotAll, multiline }()

	inner, err := p.parseAlternation()
	if err != nil {
		return nil, err
	}

	if p.pos >= len(p.src) || p.src[p.pos] != ')' {
		return nil, p.errf("unbalanced parenthesis")
	}

	p.pos++
	if index > 0 {
		if p.closed == nil {
			p.closed = map[int]struct{}{}
		}

		p.closed[index] = struct{}{}
	}

	return &btGroup{index: index, node: inner}, nil
}

// parseClass reads a bracketed character class whole, including a subtraction's
// nested class, and builds native character predicates.
func (p *btParser) parseClass() (btNode, error) {
	start := p.pos

	p.pos++ // "["
	if p.pos < len(p.src) && p.src[p.pos] == '^' {
		p.pos++
	}
	// A "]" in first position is a literal in some dialects but not in XML
	// Schema's grammar, so the scan does not special-case it.
	depth := 1
	for p.pos < len(p.src) && depth > 0 {
		switch p.src[p.pos] {
		case '\\':
			p.pos++
		case '[':
			// Only a subtraction can nest, and it has already been validated.
			depth++
		case ']':
			depth--
			if depth == 0 {
				p.pos++
				return p.compileCharAtom(p.src[start:p.pos])
			}
		}

		p.pos++
	}

	return nil, p.errf("unterminated character class")
}

// parseEscape reads a backslash escape: a backreference, or anything else,
// which is a native single-character matcher.
func (p *btParser) parseEscape() (btNode, error) {
	if p.pos+1 >= len(p.src) {
		return nil, p.errf("trailing backslash")
	}

	esc := p.src[p.pos+1]
	if esc >= '1' && esc <= '9' {
		return p.parseBackref()
	}

	if esc == 'A' || esc == 'z' {
		p.pos += 2
		return &btAnchor{end: esc == 'z', absolute: true}, nil
	}

	start := p.pos
	p.pos += 2
	// \p and \P take a braced property name, which is part of the atom.
	if esc == 'x' || esc == 'p' || esc == 'P' {
		if p.pos < len(p.src) && p.src[p.pos] == '{' {
			end := strings.IndexByte(p.src[p.pos:], '}')
			if end < 0 {
				return nil, p.errf("unterminated property name")
			}

			p.pos += end + 1
		}
	}

	return p.compileCharAtom(p.src[start:p.pos])
}

// parseBackref resolves the longest closed group number, retaining all digits
// outside that number as literal characters. Long digit strings never wrap int.
func (p *btParser) parseBackref() (btNode, error) {
	p.pos++

	start := p.pos
	for p.pos < len(p.src) && p.src[p.pos] >= '0' && p.src[p.pos] <= '9' {
		p.pos++
	}

	digits := p.src[start:p.pos]

	value, group, prefix := 0, 0, 0
	for at := 0; at < len(digits) && value <= p.groups; at++ {
		value = value*10 + int(digits[at]-'0')
		if _, closed := p.closed[value]; closed {
			group = value
			prefix = at + 1
		}
	}

	if _, closed := p.closed[value]; value <= p.groups && !closed {
		return nil, p.errf("backreference names a group that is not yet closed")
	}

	if group == 0 {
		return nil, p.errf("backreference names no preceding group")
	}

	return &btBackref{group: group, literal: []rune(digits[prefix:]), fold: p.fold}, nil
}

func (p *btParser) compileCharAtom(src string) (btNode, error) {
	set, err := parseCharacterSet(src, p.dotAll, p.fold, p.resolver)
	if err != nil {
		return nil, err
	}

	return &btChar{set: set, src: src}, nil
}

func (p *btParser) parseGroupModifiers() (bool, error) {
	p.pos++
	enable, flags := true, 0

	for p.pos < len(p.src) {
		c := p.src[p.pos]
		if c == ':' || c == ')' {
			break
		}

		p.pos++

		if c == '-' && enable {
			enable = false
			continue
		}

		switch c {
		case 'i':
			p.fold = enable
		case 's':
			p.dotAll = enable
		case 'm':
			p.multiline = enable
		default:
			return false, p.errf("unsupported group modifier")
		}

		flags++
	}

	if flags == 0 || p.pos == len(p.src) {
		return false, p.errf("invalid group modifier")
	}

	if p.src[p.pos] == ')' {
		p.pos++
		return true, nil
	}

	p.pos++ // ':'

	return false, nil
}
