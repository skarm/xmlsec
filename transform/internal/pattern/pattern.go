// Package pattern implements bounded, immutable Unicode pattern programs.
// It uses an explicit work stack and returns resource/cancellation errors.
package pattern

import (
	"context"
	"encoding/binary"
	"errors"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"
)

// ErrLimit reports an exhausted parser, work or storage limit.
var ErrLimit = errors.New("pattern: resource limit exceeded")

// Options selects matching semantics; it is copied during compilation.
type Options struct {
	// IgnoreCase enables Unicode case-insensitive matching.
	IgnoreCase bool
	// Multiline lets anchors match line boundaries within the input.
	Multiline bool
	// DotAll lets the dot operator match newline characters.
	DotAll bool
	// Literal treats the complete pattern as literal text instead of pattern syntax.
	Literal bool
	// XPathAnchors excludes the position after a final newline from multiline ^.
	XPathAnchors bool
	// Property resolves additional Unicode properties during compilation only.
	Property func(string) *unicode.RangeTable
}

// Work supplies invocation policy. Zero limits use bounded defaults.
// Charge may account for work in the caller's shared budget.
type Work struct {
	// MaxSteps bounds matching work. Zero selects the internal bounded default.
	MaxSteps int
	// MaxCells bounds matching state storage. Zero selects the internal bounded default.
	MaxCells int
	// Charge optionally charges matching work to the caller's shared budget. Its errors
	// stop matching.
	Charge func(int) error
}

// Program is immutable and safe to use concurrently.
type Program struct {
	// code holds the immutable instructions shared by matching invocations.
	code []instruction
	// start identifies the entry instruction in code.
	start int
	// groups counts capture groups for per-match capture storage.
	groups int
	// counters sizes per-match state for counted repetitions.
	counters int
	// backrefs selects matching paths that retain captured text for backreferences.
	backrefs bool
	// xpathAnchors applies XPath line-boundary rules during matching.
	xpathAnchors bool
}

// Compile parses a pattern without expanding counted repetitions.
func Compile(source string, options Options) (*Program, error) {
	if len(source) > 64<<10 {
		return nil, ErrLimit
	}

	if !utf8.ValidString(source) {
		return nil, errors.New("invalid UTF-8 pattern")
	}

	p := btParser{src: source, fold: options.IgnoreCase, dotAll: options.DotAll, multiline: options.Multiline, resolver: options.Property}

	var (
		root btNode
		err  error
	)

	if options.Literal {
		root = &btLiteral{text: []rune(source), fold: p.fold}
	} else {
		root, err = p.parseAlternation()
	}

	if err != nil {
		return nil, err
	}

	if !options.Literal && p.pos != len(source) {
		return nil, errors.New("unbalanced pattern")
	}

	program := &Program{groups: p.groups, code: []instruction{{op: opMatch}}, xpathAnchors: options.XPathAnchors}

	program.start, err = program.emit(root, 0)
	if err != nil {
		return nil, err
	}

	return program, nil
}

// CacheCost estimates retained storage conservatively, saturating at limit.
// Fixed weights cover struct/allocator overhead on supported 32/64-bit targets;
// capacities include unused backing storage. Shared Unicode tables are counted
// for each reference, so this is an admission/eviction weight, not a heap census.
func (p *Program) CacheCost(limit int) int {
	cost := 0

	charge := func(n int) bool {
		if n >= limit-cost {
			cost = limit
			return false
		}

		cost += n

		return true
	}
	if !charge(128 + cap(p.code)*128) {
		return cost
	}

	for _, inst := range p.code {
		if !charge(cap(inst.text) * 8) {
			return cost
		}

		for set := inst.set; set != nil; set = set.subtract {
			if !charge(128 + cap(set.ranges)*16 + cap(set.properties)*32) {
				return cost
			}

			for _, property := range set.properties {
				if !charge(128 + cap(property.table.R16)*16 + cap(property.table.R32)*32) {
					return cost
				}
			}
		}
	}

	return cost
}

// Groups reports the number of capturing groups.
func (p *Program) Groups() int { return p.groups }

// Match reports whether the input contains a match, preserving policy errors.
func (p *Program) Match(ctx context.Context, s string, work Work) (bool, error) {
	m, err := newMachine(ctx, p, s, work)
	if err != nil {
		return false, err
	}

	loc, err := m.find(0)

	return loc != nil, err
}

// Each streams non-overlapping matches using byte offsets for captures.
// A zero limit means no matches, and a negative limit means uncapped.
func (p *Program) Each(ctx context.Context, s string, limit int, work Work, fn func([]int) bool) error {
	m, err := newMachine(ctx, p, s, work)
	if err != nil {
		return err
	}

	pos, previousEnd, count := 0, -1, 0
	for pos <= len(s) && (limit < 0 || count < limit) {
		loc, err := m.find(pos)
		if err != nil {
			return err
		}

		if loc == nil {
			return nil
		}

		empty := loc[0] == loc[1]
		if !empty || loc[0] != previousEnd {
			count++

			if !fn(loc) {
				return nil
			}
		}

		previousEnd = loc[1]

		pos = loc[1]
		if empty {
			if pos == len(s) {
				break
			}

			_, size := utf8.DecodeRuneInString(s[pos:])
			pos += size
		}
	}

	return nil
}

func (p *Program) append(i instruction) (int, error) {
	if len(p.code) >= 8192 {
		return 0, ErrLimit
	}

	p.code = append(p.code, i)

	return len(p.code) - 1, nil
}

func (p *Program) emit(node btNode, next int) (int, error) {
	switch n := node.(type) {
	case *btEmpty:
		return next, nil
	case *btLiteral:
		return p.append(instruction{op: opLiteral, text: n.text, fold: n.fold, x: next})
	case *btChar:
		return p.append(instruction{op: opChar, set: n.set, cost: n.set.complexity(), x: next})
	case *btAnchor:
		return p.append(instruction{op: opAnchor, end: n.end, absolute: n.absolute, multiline: n.multiline, x: next})
	case *btBackref:
		p.backrefs = true
		return p.append(instruction{op: opReference, index: n.group, text: n.literal, fold: n.fold, x: next})
	case *btSeq:
		return p.emitSequence(n, next)
	case *btAlt:
		return p.emitAlternation(n, next)
	case *btGroup:
		return p.emitGroup(n, next)
	case *btRepeat:
		return p.emitRepeat(n, next)
	}

	return 0, errors.New("unknown pattern node")
}

func (p *Program) emitSequence(n *btSeq, next int) (int, error) {
	var err error
	for _, v := range slices.Backward(n.items) {
		next, err = p.emit(v, next)
		if err != nil {
			return 0, err
		}
	}

	return next, nil
}

func (p *Program) emitAlternation(n *btAlt, next int) (int, error) {
	last, err := p.emit(n.branches[len(n.branches)-1], next)
	if err != nil {
		return 0, err
	}

	for i := len(n.branches) - 2; i >= 0; i-- {
		first, err := p.emit(n.branches[i], next)
		if err != nil {
			return 0, err
		}

		last, err = p.append(instruction{op: opSplit, x: first, y: last})
		if err != nil {
			return 0, err
		}
	}

	return last, nil
}

func (p *Program) emitGroup(n *btGroup, next int) (int, error) {
	if n.index == 0 {
		return p.emit(n.node, next)
	}

	end, err := p.append(instruction{op: opSave, index: 2*n.index + 1, x: next})
	if err != nil {
		return 0, err
	}

	inner, err := p.emit(n.node, end)
	if err != nil {
		return 0, err
	}

	return p.append(instruction{op: opSave, index: 2 * n.index, x: inner})
}

func (p *Program) emitRepeat(n *btRepeat, next int) (int, error) {
	// Plain stars use a split, so matching work and memory never grow with
	// an artificial repeat count. Visited states break zero-width cycles.
	if n.most < 0 && n.least <= 1 {
		loop, err := p.append(instruction{op: opSplit, y: next, lazy: n.lazy})
		if err != nil {
			return 0, err
		}

		body, err := p.emit(n.node, loop)
		if err != nil {
			return 0, err
		}

		p.code[loop].x = body
		if n.lazy {
			p.code[loop].x, p.code[loop].y = next, body
		}

		if n.least == 1 {
			return body, nil
		}

		return loop, nil
	}

	id := p.counters

	p.counters++
	if p.counters > 128 {
		return 0, ErrLimit
	}

	loop, err := p.append(instruction{op: opRepeat, index: id, least: n.least, most: n.most, lazy: n.lazy, y: next})
	if err != nil {
		return 0, err
	}

	increment, err := p.append(instruction{op: opIncrement, index: id, x: loop})
	if err != nil {
		return 0, err
	}

	body, err := p.emit(n.node, increment)
	if err != nil {
		return 0, err
	}

	p.code[loop].x = body

	return p.append(instruction{op: opInitialize, index: id, x: loop})
}

// AppendReplacement expands normalized ${n}/$$ tokens, charging each fragment
// before it is appended so a failed output budget cannot trigger a large copy.
func AppendReplacement(dst []byte, replacement, source string, match []int, charge func(int) error) ([]byte, error) {
	for at := 0; at < len(replacement); {
		part, next, appendPart := replacementPart(replacement, source, match, at)
		if appendPart {
			if charge != nil {
				if err := charge(len(part)); err != nil {
					return nil, err
				}
			}

			dst = append(dst, part...)
		}

		at = next
	}

	return dst, nil
}

func replacementPart(replacement, source string, match []int, at int) (string, int, bool) {
	if replacement[at] != '$' {
		end := strings.IndexByte(replacement[at:], '$')
		if end < 0 {
			end = len(replacement) - at
		}

		return replacement[at : at+end], at + end, true
	}

	if at+1 < len(replacement) && replacement[at+1] == '$' {
		return "$", at + 2, true
	}

	if at+1 < len(replacement) && replacement[at+1] == '{' {
		if closing := strings.IndexByte(replacement[at+2:], '}'); closing >= 0 {
			group, err := parseCount(replacement[at+2 : at+2+closing])
			next := at + closing + 3

			if err == nil && group < len(match)/2 && match[2*group] >= 0 {
				return source[match[2*group]:match[2*group+1]], next, true
			}

			return "", next, false
		}
	}

	return "$", at + 1, true
}

type operation uint8

const (
	opMatch operation = iota
	opChar
	opLiteral
	opSplit
	opSave
	opAnchor
	opReference
	opInitialize
	opRepeat
	opIncrement
)

type instruction struct {
	set       *characterSet
	text      []rune
	x         int
	y         int
	index     int
	least     int
	most      int
	cost      int
	op        operation
	lazy      bool
	fold      bool
	absolute  bool
	end       bool
	multiline bool
}

type (
	counter struct {
		count int
		prior int
		start int
	}
	state struct {
		pc       int
		pos      int
		caps     []int
		counters []counter
	}
)

func (s state) clone() state {
	s.caps = append([]int(nil), s.caps...)
	s.counters = append([]counter(nil), s.counters...)

	return s
}

type machine struct {
	ctx     context.Context
	work    Work
	steps   int
	cells   int
	source  string
	program *Program
	seen    map[string]struct{}
}

func newMachine(ctx context.Context, p *Program, s string, work Work) (*machine, error) {
	if ctx == nil {
		return nil, errors.New("nil context")
	}

	if work.MaxSteps == 0 {
		work.MaxSteps = 2_000_000
	}

	if work.MaxCells == 0 {
		work.MaxCells = 1 << 20
	}

	if work.MaxSteps < 0 || work.MaxCells < 0 {
		return nil, ErrLimit
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	return &machine{ctx: ctx, program: p, source: s, work: work, seen: make(map[string]struct{})}, nil
}

func (m *machine) charge(n int) error {
	if err := m.ctx.Err(); err != nil {
		return err
	}

	if n < 0 || n > m.work.MaxSteps-m.steps {
		return ErrLimit
	}

	m.steps += n
	if m.work.Charge != nil {
		return m.work.Charge(n)
	}

	return nil
}

func (m *machine) stateKey(s state) string {
	size := 20 + 30*len(s.counters)
	if m.program.backrefs {
		size += 10 * len(s.caps)
	}

	buffer := make([]byte, 0, size)
	buffer = binary.AppendVarint(buffer, int64(s.pc))

	buffer = binary.AppendVarint(buffer, int64(s.pos))
	for _, c := range s.counters {
		buffer = binary.AppendVarint(buffer, int64(c.count))
		buffer = binary.AppendVarint(buffer, int64(c.prior))
		buffer = binary.AppendVarint(buffer, int64(c.start))
	}

	if m.program.backrefs {
		for _, v := range s.caps {
			buffer = binary.AppendVarint(buffer, int64(v))
		}
	}

	return string(buffer)
}

func (m *machine) literal(pos int, text []rune, fold bool) (int, bool, error) {
	for _, want := range text {
		if err := m.charge(1); err != nil {
			return pos, false, err
		}

		if pos >= len(m.source) {
			return pos, false, nil
		}

		got, size := utf8.DecodeRuneInString(m.source[pos:])
		if !equalRune(got, want, fold) {
			return pos, false, nil
		}

		pos += size
	}

	return pos, true, nil
}

func (m *machine) attempt(start int) ([]int, error) {
	p := m.program
	if err := m.charge(2*(p.groups+1) + 3*p.counters + 2); err != nil {
		return nil, err
	}

	s := state{pc: p.start, pos: start, caps: make([]int, 2*(p.groups+1)), counters: make([]counter, p.counters)}
	for i := range s.caps {
		s.caps[i] = -1
	}

	stack := stateStack{weight: len(s.caps) + 3*len(s.counters) + 2}

	for {
		if err := m.charge(1); err != nil {
			return nil, err
		}

		fresh, err := m.visit(s, stack.cells)
		if err != nil {
			return nil, err
		}

		if fresh {
			i := p.code[s.pc]
			if i.op == opMatch {
				s.caps[0], s.caps[1] = start, s.pos
				return s.caps, nil
			}

			advance, err := m.execute(&s, i, &stack)
			if err != nil {
				return nil, err
			}

			if advance {
				continue
			}
		}

		if !stack.pop(&s) {
			return nil, nil
		}
	}
}

func (m *machine) visit(s state, stackCells int) (bool, error) {
	key := m.stateKey(s)
	if _, seen := m.seen[key]; seen {
		return false, nil
	}

	cells := len(key)/8 + 4
	if cells > m.work.MaxCells-m.cells-stackCells {
		return false, ErrLimit
	}

	m.cells += cells
	m.seen[key] = struct{}{}

	return true, nil
}

func (m *machine) execute(s *state, i instruction, stack *stateStack) (bool, error) {
	switch i.op {
	case opChar:
		return m.character(s, i)
	case opLiteral:
		pos, ok, err := m.literal(s.pos, i.text, i.fold)
		if err != nil {
			return false, err
		}

		s.pos, s.pc = pos, i.x

		return ok, nil
	case opSplit:
		branch := *s
		branch.pc = i.y

		if err := stack.push(m, branch); err != nil {
			return false, err
		}

		s.pc = i.x
	case opSave:
		s.caps[i.index] = s.pos
		s.pc = i.x
	case opAnchor:
		advance := m.anchor(s.pos, i)
		s.pc = i.x

		return advance, nil
	case opReference:
		return m.reference(s, i)
	case opInitialize:
		s.counters[i.index] = counter{prior: -1}
		s.pc = i.x
	case opIncrement:
		c := &s.counters[i.index]
		c.count++
		c.prior = c.start
		s.pc = i.x
	case opRepeat:
		return m.repeat(s, i, stack)
	}

	return true, nil
}

func (m *machine) character(s *state, i instruction) (bool, error) {
	if s.pos >= len(m.source) {
		return false, nil
	}

	r, n := utf8.DecodeRuneInString(m.source[s.pos:])
	if err := m.charge(i.cost); err != nil {
		return false, err
	}

	if !i.set.contains(r) {
		return false, nil
	}

	s.pos += n
	s.pc = i.x

	return true, nil
}

func (m *machine) anchor(pos int, i instruction) bool {
	if i.end {
		return pos == len(m.source) || !i.absolute && i.multiline && pos < len(m.source) && m.source[pos] == '\n'
	}

	return pos == 0 || !i.absolute && i.multiline && pos > 0 && m.source[pos-1] == '\n' && (!m.program.xpathAnchors || pos < len(m.source))
}

func (m *machine) reference(s *state, i instruction) (bool, error) {
	advance, err := m.captured(s, i)
	if err != nil {
		return false, err
	}

	if advance {
		pos, ok, err := m.literal(s.pos, i.text, i.fold)
		if err != nil {
			return false, err
		}

		s.pos = pos
		advance = ok
	}

	s.pc = i.x

	return advance, nil
}

func (m *machine) captured(s *state, i instruction) (bool, error) {
	a, b := s.caps[2*i.index], s.caps[2*i.index+1]
	if a < 0 || b < a {
		return true, nil
	}

	if err := m.charge(b - a); err != nil {
		return false, err
	}

	if i.fold {
		pos, ok, err := m.literal(s.pos, []rune(m.source[a:b]), true)
		if err != nil {
			return false, err
		}

		s.pos = pos

		return ok, nil
	}

	advance := strings.HasPrefix(m.source[s.pos:], m.source[a:b])
	if advance {
		s.pos += b - a
	}

	return advance, nil
}

func (m *machine) repeat(s *state, i instruction, stack *stateStack) (bool, error) {
	c := &s.counters[i.index]
	stop := c.count >= i.least
	more := i.most < 0 || c.count < i.most

	if c.count > 0 && c.prior == s.pos && stop {
		more = false
	}

	if i.most < 0 && stop {
		c.count = i.least
	}

	if !more {
		s.pc = i.y
		return stop, nil
	}

	c.start = s.pos
	if !stop {
		s.pc = i.x
		return true, nil
	}

	branch := *s
	if i.lazy {
		branch.pc, s.pc = i.x, i.y
	} else {
		branch.pc, s.pc = i.y, i.x
	}

	if err := stack.push(m, branch); err != nil {
		return false, err
	}

	return true, nil
}

func (m *machine) find(from int) ([]int, error) {
	m.seen = make(map[string]struct{})

	m.cells = 0
	for at := from; at <= len(m.source); {
		match, err := m.attempt(at)
		if err != nil || match != nil {
			return match, err
		}

		if at == len(m.source) {
			break
		}

		_, size := utf8.DecodeRuneInString(m.source[at:])
		at += size
	}

	return nil, nil
}

func equalRune(a, b rune, fold bool) bool {
	if a == b {
		return true
	}

	if !fold {
		return false
	}

	for r := unicode.SimpleFold(a); r != a; r = unicode.SimpleFold(r) {
		if r == b {
			return true
		}
	}

	return false
}

type stateStack struct {
	states []state
	cells  int
	weight int
}

func (stack *stateStack) push(m *machine, branch state) error {
	if stack.weight > m.work.MaxCells-m.cells-stack.cells {
		return ErrLimit
	}

	if err := m.charge(stack.weight); err != nil {
		return err
	}

	stack.states = append(stack.states, branch.clone())
	stack.cells += stack.weight

	return nil
}

func (stack *stateStack) pop(s *state) bool {
	if len(stack.states) == 0 {
		return false
	}

	*s = stack.states[len(stack.states)-1]
	stack.states = stack.states[:len(stack.states)-1]
	stack.cells -= stack.weight

	return true
}
