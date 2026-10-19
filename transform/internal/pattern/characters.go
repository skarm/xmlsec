package pattern

import (
	"errors"
	"fmt"
	"math/bits"
	"sort"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

type (
	interval struct{ lo, hi rune }
	property struct {
		table  *unicode.RangeTable
		negate bool
	}
)

type characterSet struct {
	ranges       []interval
	properties   []property
	negate, fold bool
	subtract     *characterSet
}

// Literal/range folding precedes complement and subtraction. Property
// escapes keep their original meaning even within a case-insensitive union.
func (s *characterSet) contains(r rune) bool {
	in := s.rangeMember(r)
	if s.fold {
		for f := unicode.SimpleFold(r); f != r; f = unicode.SimpleFold(f) {
			in = in || s.rangeMember(f)
		}
	}

	for _, p := range s.properties {
		// XPath's i flag changes literals and ranges, not property escapes.
		in = in || unicode.Is(p.table, r) != p.negate
	}

	if s.negate {
		in = !in
	}

	return in && (s.subtract == nil || !s.subtract.contains(r))
}

// complexity charges the binary searches, property predicates and subtraction
// depth before evaluation. Large unions cannot consume unaccounted match work.
func (s *characterSet) complexity() int {
	cost := 1 + 4*bits.Len(uint(len(s.ranges)))
	for _, p := range s.properties {
		cost += 1 + bits.Len(uint(len(p.table.R16)+len(p.table.R32)))
	}

	if s.subtract != nil {
		cost += s.subtract.complexity()
	}

	return cost
}

func (s *characterSet) rangeMember(r rune) bool {
	at := sort.Search(len(s.ranges), func(i int) bool { return s.ranges[i].hi >= r })
	return at < len(s.ranges) && s.ranges[at].lo <= r
}

func (s *characterSet) normalize() {
	sort.Slice(s.ranges, func(i, j int) bool { return s.ranges[i].lo < s.ranges[j].lo })

	var merged []interval
	for _, v := range s.ranges {
		if len(merged) > 0 && v.lo <= merged[len(merged)-1].hi+1 {
			merged[len(merged)-1].hi = max(merged[len(merged)-1].hi, v.hi)
		} else {
			merged = append(merged, v)
		}
	}

	s.ranges = merged
}

func parseCharacterSet(src string, dotAll, fold bool, resolver func(string) *unicode.RangeTable) (*characterSet, error) {
	if src == "." {
		s := &characterSet{negate: !dotAll}
		if !dotAll {
			s.ranges = []interval{{'\n', '\n'}, {'\r', '\r'}}
		} else {
			s.ranges = []interval{{0, unicode.MaxRune}}
		}

		return s, nil
	}

	p := classParser{src: src, fold: fold, resolver: resolver}

	var (
		s   *characterSet
		err error
	)
	if strings.HasPrefix(src, "[") {
		s, err = p.bracket(0)
	} else {
		s = &characterSet{fold: fold}

		var atom classAtom

		atom, err = p.atom()
		if err != nil {
			return nil, err
		}

		s.ranges = atom.ranges
		s.properties = atom.properties
	}

	if err != nil {
		return nil, err
	}

	if p.pos != len(src) {
		return nil, fmt.Errorf("invalid character atom %q", src)
	}

	s.normalize()

	return s, nil
}

type classAtom struct {
	ranges     []interval
	properties []property
	singleton  bool
	value      rune
}

type classParser struct {
	src      string
	pos      int
	fold     bool
	resolver func(string) *unicode.RangeTable
}

func (p *classParser) bracket(depth int) (*characterSet, error) {
	if depth > 128 {
		return nil, ErrLimit
	}

	p.pos++

	s := &characterSet{fold: p.fold}
	if p.pos < len(p.src) && p.src[p.pos] == '^' {
		s.negate = true
		p.pos++
	}

	members := 0

	for p.pos < len(p.src) && p.src[p.pos] != ']' {
		if strings.HasPrefix(p.src[p.pos:], "-[") {
			if err := p.subtraction(s, depth, members); err != nil {
				return nil, err
			}

			break
		}

		member, err := p.member()
		if err != nil {
			return nil, err
		}

		members++

		s.ranges = append(s.ranges, member.ranges...)
		s.properties = append(s.properties, member.properties...)
	}

	if members == 0 || p.pos >= len(p.src) || p.src[p.pos] != ']' {
		return nil, errors.New("unterminated or empty character class")
	}

	p.pos++

	s.normalize()

	return s, nil
}

func (p *classParser) subtraction(s *characterSet, depth, members int) error {
	if members == 0 {
		return errors.New("empty subtraction base")
	}

	p.pos++

	var err error

	s.subtract, err = p.bracket(depth + 1)
	if err != nil {
		return err
	}

	if p.pos >= len(p.src) || p.src[p.pos] != ']' {
		return errors.New("subtraction must be last")
	}

	return nil
}

func (p *classParser) member() (classAtom, error) {
	left, err := p.atom()
	if err != nil {
		return classAtom{}, err
	}

	if !left.singleton || p.pos+1 >= len(p.src) || p.src[p.pos] != '-' || p.src[p.pos+1] == ']' || p.src[p.pos+1] == '[' {
		return left, nil
	}

	p.pos++

	right, err := p.atom()
	if err != nil {
		return classAtom{}, err
	}

	if !right.singleton || right.value < left.value {
		return classAtom{}, errors.New("invalid character range")
	}

	return classAtom{ranges: []interval{{left.value, right.value}}}, nil
}

func (p *classParser) atom() (classAtom, error) {
	if p.pos >= len(p.src) {
		return classAtom{}, errors.New("missing character")
	}

	r, size := utf8.DecodeRuneInString(p.src[p.pos:])
	p.pos += size

	if r == '[' || r == ']' {
		return classAtom{}, errors.New("unescaped class delimiter")
	}

	if r == '\\' {
		return p.escapedAtom()
	}

	return classAtom{ranges: []interval{{r, r}}, singleton: true, value: r}, nil
}

func (p *classParser) escapedAtom() (classAtom, error) {
	if p.pos >= len(p.src) {
		return classAtom{}, errors.New("trailing escape")
	}

	e := p.src[p.pos]
	p.pos++

	var r rune

	switch e {
	case 'n':
		r = '\n'
	case 'r':
		r = '\r'
	case 't':
		r = '\t'
	case 'x':
		var err error

		r, err = p.hexRune()
		if err != nil {
			return classAtom{}, err
		}
	case 'p', 'P':
		return p.propertyAtom(e == 'P')
	case 'd', 'D':
		return classAtom{properties: []property{{unicode.Digit, e == 'D'}}}, nil
	case 's', 'S':
		return classAtom{properties: []property{{xmlWhitespace(), e == 'S'}}}, nil
	default:
		if !strings.ContainsRune(`\|.-^?*+{}()[]$`, rune(e)) {
			return classAtom{}, fmt.Errorf("invalid escape \\%c", e)
		}

		r = rune(e)
	}

	return classAtom{ranges: []interval{{r, r}}, singleton: true, value: r}, nil
}

func xmlWhitespace() *unicode.RangeTable {
	return &unicode.RangeTable{R16: []unicode.Range16{
		{Lo: '\t', Hi: '\n', Stride: 1}, {Lo: '\r', Hi: '\r', Stride: 1}, {Lo: ' ', Hi: ' ', Stride: 1},
	}}
}

func (p *classParser) hexRune() (rune, error) {
	if p.pos >= len(p.src) || p.src[p.pos] != '{' {
		return 0, errors.New("hex escape requires braces")
	}

	end := strings.IndexByte(p.src[p.pos:], '}')
	if end < 0 {
		return 0, errors.New("unterminated hex escape")
	}

	n, err := strconv.ParseUint(p.src[p.pos+1:p.pos+end], 16, 32)
	if err != nil || n > unicode.MaxRune {
		return 0, errors.New("invalid codepoint")
	}

	p.pos += end + 1

	return rune(n), nil
}

func (p *classParser) propertyAtom(negate bool) (classAtom, error) {
	if p.pos >= len(p.src) || p.src[p.pos] != '{' {
		return classAtom{}, errors.New("property requires braces")
	}

	end := strings.IndexByte(p.src[p.pos:], '}')
	if end < 0 {
		return classAtom{}, errors.New("unterminated property")
	}

	name := p.src[p.pos+1 : p.pos+end]
	p.pos += end + 1

	table := p.propertyTable(name)
	if table == nil {
		return classAtom{}, fmt.Errorf("unknown Unicode property %q", name)
	}

	return classAtom{properties: []property{{table, negate}}}, nil
}

func (p *classParser) propertyTable(name string) *unicode.RangeTable {
	table := unicode.Categories[name]
	if table == nil {
		table = unicode.Scripts[name]
	}

	if table == nil {
		table = unicode.Properties[name]
	}

	if table == nil && p.resolver != nil {
		table = p.resolver(name)
	}

	return table
}
