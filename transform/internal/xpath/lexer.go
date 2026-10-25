// Derived from lestrrat-go/helium at 7362c0a70122a757780f4d0b545a9b370dead6ab.
// Copyright (c) 2015 lestrrat. MIT License; see licenses/MIT-helium.txt at the repository root.

package xpath

import (
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/skarm/xmlsec/internal/xmlchar"
	"github.com/skarm/xmlsec/transform/internal/xdm"
	"github.com/skarm/xmlsec/transform/internal/xdm/lexicon"
)

const (
	keywordWhere      = "where"
	keywordAscending  = "ascending"
	keywordDescending = "descending"
	keywordStable     = "stable"
)

type lexer struct {
	input    string
	pos      int
	tokens   []Token
	idx      int  // read cursor into tokens
	hadSpace bool // true if whitespace was skipped before current token
	version  int
}

// newLexer creates a lexer and tokenizes the entire input.
func newLexer(input string) (*lexer, error) {
	return newVersionLexer(input, 0)
}

func newVersionLexer(input string, version int) (*lexer, error) {
	return newVersionLexerSpans(input, version, nil)
}

type sourceSpan struct{ start, end int }

func newVersionLexerSpans(input string, version int, spans *[]sourceSpan) (*lexer, error) {
	l := &lexer{
		input:   input,
		version: version,
		tokens:  make([]Token, 0, estimateTokenCapacity(input)),
	}
	if err := l.tokenizeSpans(spans); err != nil {
		return nil, err
	}

	return l, nil
}

// SplitUnion returns the outer union operands, using XPath's lexical rules.
// Parentheses enclosing an entire union are stripped, as required by XSLT's
// default-priority rules. Other expressions retain their original source.
func SplitUnion(input string, version int) ([]string, error) {
	return splitUnion(input, version, false)
}

// SplitPatternUnion retains the narrower XSLT 1.0/2.0 pattern grammar:
// only a top-level pipe separates alternatives, and grouping parentheses
// and explicit non-pattern axes remain forbidden outside predicates.
func SplitPatternUnion(input string, version int) ([]string, error) {
	return splitUnion(input, version, version == 10 || version == 20)
}

func splitUnion(input string, version int, legacyPattern bool) ([]string, error) {
	if !legacyPattern && !strings.Contains(input, "|") && !strings.Contains(input, "union") {
		return []string{input}, nil
	}

	var spans []sourceSpan

	l, err := newVersionLexerSpans(input, version, &spans)
	if err != nil {
		return nil, err
	}

	lo, hi := 0, len(l.tokens)
	if legacyPattern {
		if err := validateLegacyPatternTokens(l.tokens); err != nil {
			return nil, err
		}
	} else {
		lo, hi = unionTokenBounds(l.tokens)
	}

	if lo == hi {
		return []string{input}, nil
	}

	var parts []string

	depth, start := 0, spans[lo].start
	for i := lo; i < hi; i++ {
		switch l.tokens[i].Type {
		case TokenLParen, TokenLBracket, TokenLBrace:
			depth++
		case TokenRParen, TokenRBracket, TokenRBrace:
			depth--
		case TokenPipe, TokenUnion:
			if depth == 0 && (!legacyPattern || l.tokens[i].Type == TokenPipe) {
				if parts == nil {
					parts = make([]string, 0, 2)
				}

				parts = append(parts, input[start:spans[i].start])
				start = spans[i].end
			}
		}
	}

	if len(parts) == 0 {
		return []string{input}, nil
	}

	return append(parts, input[start:spans[hi-1].end]), nil
}

func validateLegacyPatternTokens(tokens []Token) error {
	brackets := 0

	for i, token := range tokens {
		switch token.Type {
		case TokenLBracket:
			brackets++
		case TokenRBracket:
			brackets--
		case TokenLParen:
			if brackets == 0 && (i == 0 || tokens[i-1].Type != TokenName) {
				return fmt.Errorf("grouping parentheses require XSLT 3.0 patterns")
			}
		case TokenColonColon:
			if brackets == 0 && (i == 0 || tokens[i-1].Value != "child" && tokens[i-1].Value != "attribute") {
				return fmt.Errorf("axis is unavailable in XSLT 1.0/2.0 patterns")
			}
		}
	}

	return nil
}

func unionTokenBounds(tokens []Token) (int, int) {
	lo, hi := 0, len(tokens)
	if hi == 0 || tokens[0].Type != TokenLParen {
		return lo, hi
	}
	// Build pairs once: repeatedly scanning nested parentheses is quadratic.
	closing := make([]int, hi)

	var opening []int
	for i, token := range tokens {
		if token.Type == TokenLParen {
			opening = append(opening, i)
		} else if token.Type == TokenRParen && len(opening) > 0 {
			last := len(opening) - 1
			closing[opening[last]] = i + 1
			opening = opening[:last]
		}
	}

	for lo < hi && tokens[lo].Type == TokenLParen && closing[lo] == hi {
		lo++
		hi--
	}

	return lo, hi
}

func estimateTokenCapacity(input string) int {
	if len(input) < 8 {
		return 8
	}

	// Comments and whitespace can dominate the source without producing tokens.
	// Grow for actual tokens rather than reserving a source-sized token array.
	return min(len(input)/2+1, 256)
}

// Next returns the next token and advances the cursor.
func (l *lexer) Next() Token {
	if l.idx >= len(l.tokens) {
		return Token{Type: TokenEOF}
	}

	t := l.tokens[l.idx]
	l.idx++

	return t
}

// Peek returns the next token without advancing.
func (l *lexer) Peek() Token {
	if l.idx >= len(l.tokens) {
		return Token{Type: TokenEOF}
	}

	return l.tokens[l.idx]
}

// PeekAt returns the token at offset positions ahead of the cursor (0 = current).
func (l *lexer) PeekAt(offset int) Token {
	i := l.idx + offset
	if i >= len(l.tokens) {
		return Token{Type: TokenEOF}
	}

	return l.tokens[i]
}

// Backup moves the cursor back by one token.
func (l *lexer) Backup() {
	if l.idx > 0 {
		l.idx--
	}
}

// PrettyTokens returns a human-readable representation of all tokens.
func (l *lexer) PrettyTokens() string {
	var b strings.Builder

	for i, t := range l.tokens {
		if i > 0 {
			b.WriteString(" ")
		}

		b.WriteString(t.String())
	}

	return b.String()
}

func (l *lexer) tokenizeSpans(spans *[]sourceSpan) error {
	for l.pos < len(l.input) {
		posBefore := l.pos
		l.skipWhitespace()

		l.hadSpace = l.hadSpace || l.pos > posBefore
		if l.pos >= len(l.input) {
			break
		}

		tokenCount := len(l.tokens)

		start := l.pos
		if err := l.scanToken(); err != nil {
			return err
		}

		if spans != nil {
			for range len(l.tokens) - tokenCount {
				*spans = append(*spans, sourceSpan{start, l.pos})
			}
		}
		// A comment separates tokens just like whitespace. Keep that boundary
		// until the next token is emitted, including across adjacent comments.
		l.hadSpace = len(l.tokens) == tokenCount
	}

	return nil
}

func (l *lexer) scanToken() error {
	r := l.peekRune()
	if token, ok := singleRuneToken(r); ok {
		l.emit(token, string(r))
		l.advanceRune(r)

		return nil
	}

	switch r {
	case '(':
		return l.scanParenthesisOrComment()
	case '|', '=', '!', '<', '>', '/', ':':
		l.scanOperator(r)
	case '.':
		return l.scanDotOrNumber()
	case '$':
		return l.scanVariableReference()
	case '"', '\'':
		value, err := l.scanString()
		if err != nil {
			return err
		}

		l.emit(TokenString, value)
	default:
		if r >= '0' && r <= '9' {
			return l.scanNumber()
		}

		if !xmlchar.IsNCNameStartChar(r) {
			return fmt.Errorf("%w: %q at position %d", ErrUnexpectedChar, string(r), l.pos)
		}

		return l.scanNameOrKeyword()
	}

	return nil
}

func singleRuneToken(r rune) (TokenType, bool) {
	switch r {
	case ')':
		return TokenRParen, true
	case '[':
		return TokenLBracket, true
	case ']':
		return TokenRBracket, true
	case '{':
		return TokenLBrace, true
	case '}':
		return TokenRBrace, true
	case '@':
		return TokenAt, true
	case ',':
		return TokenComma, true
	case '+':
		return TokenPlus, true
	case '#':
		return TokenHash, true
	case '?':
		return TokenQMark, true
	case '-':
		return TokenMinus, true
	case '*':
		return TokenStar, true
	default:
		return TokenEOF, false
	}
}

func (l *lexer) scanParenthesisOrComment() error {
	if l.pos+1 < len(l.input) && l.input[l.pos+1] == ':' {
		if l.version == 10 {
			return profileError(errCodeXPST0003, "comments", 10)
		}

		return l.skipComment()
	}

	l.emit(TokenLParen, "(")
	l.advanceRune('(')

	return nil
}

func (l *lexer) scanOperator(r rune) {
	switch r {
	case '|':
		l.emitPairedOperator(r, '|', TokenPipe, TokenConcat)
	case '=':
		l.emitPairedOperator(r, '>', TokenEquals, TokenArrow)
	case '!':
		l.emitPairedOperator(r, '=', TokenBang, TokenNotEquals)
	case '<':
		l.scanComparisonOperator(r, TokenLess, TokenLessEq, TokenNodePre)
	case '>':
		l.scanComparisonOperator(r, TokenGreater, TokenGreaterEq, TokenNodeFol)
	case '/':
		l.emitPairedOperator(r, '/', TokenSlash, TokenSlashSlash)
	case ':':
		l.emitPairedOperator(r, ':', TokenColon, TokenColonColon)
	}
}

func (l *lexer) emitPairedOperator(r rune, next byte, single, paired TokenType) {
	l.advanceRune(r)

	if l.pos < len(l.input) && l.input[l.pos] == next {
		l.emit(paired, string(r)+string(next))
		l.pos++

		return
	}

	l.emit(single, string(r))
}

func (l *lexer) scanComparisonOperator(r rune, single, equal, nodeOrder TokenType) {
	l.advanceRune(r)

	if l.pos < len(l.input) && l.input[l.pos] == byte(r) {
		l.emit(nodeOrder, string(r)+string(r))
		l.pos++

		return
	}

	if l.pos < len(l.input) && l.input[l.pos] == '=' {
		l.emit(equal, string(r)+"=")
		l.pos++

		return
	}

	l.emit(single, string(r))
}

func (l *lexer) scanDotOrNumber() error {
	l.advanceRune('.')

	switch {
	case l.pos < len(l.input) && l.input[l.pos] == '.':
		l.emit(TokenDotDot, "..")
		l.pos++
	case l.pos < len(l.input) && l.input[l.pos] >= '0' && l.input[l.pos] <= '9':
		l.pos-- // .5-style numbers include the opening dot.
		return l.scanNumber()
	default:
		l.emit(TokenDot, ".")
	}

	return nil
}

func (l *lexer) scanVariableReference() error {
	l.advanceRune('$')

	name := l.scanNCName()
	if name == "" {
		return fmt.Errorf("%w: variable name after '$' at position %d", ErrUnexpectedToken, l.pos)
	}
	// URIQualifiedName: $Q{uri}local
	if name == "Q" && l.pos < len(l.input) && l.input[l.pos] == '{' {
		qualified, err := l.scanURIQualifiedName(false)
		if err != nil {
			return err
		}

		name = qualified
	} else if l.pos < len(l.input) && l.input[l.pos] == ':' && l.pos+1 < len(l.input) {
		// Check for QName (prefix:local) — e.g., $err:code
		r2, _ := utf8.DecodeRuneInString(l.input[l.pos+1:])
		if xmlchar.IsNCNameStartChar(r2) {
			l.pos++ // consume ':'
			local := l.scanNCName()
			name = name + ":" + local
		}
	}

	l.emit(TokenVariableRef, name)

	return nil
}

func (l *lexer) peekRune() rune {
	r, _ := utf8.DecodeRuneInString(l.input[l.pos:])
	return r
}

func (l *lexer) advanceRune(r rune) {
	l.pos += utf8.RuneLen(r)
}

func (l *lexer) emit(typ TokenType, value string) {
	l.tokens = append(l.tokens, Token{Type: typ, Value: value, SpaceBefore: l.hadSpace})
}

func (l *lexer) skipWhitespace() {
	for l.pos < len(l.input) {
		r, size := utf8.DecodeRuneInString(l.input[l.pos:])
		if r != ' ' && r != '\t' && r != '\n' && r != '\r' {
			break
		}

		l.pos += size
	}
}

// skipComment skips an XPath comment delimited by (: and :).
// The lexer position must be at the opening '('. Nested comments are supported.
func (l *lexer) skipComment() error {
	start := l.pos
	l.pos += 2 // skip "(:"

	depth := 1
	for l.pos < len(l.input) && depth > 0 {
		if l.pos+1 < len(l.input) && l.input[l.pos] == '(' && l.input[l.pos+1] == ':' {
			depth++
			l.pos += 2
		} else if l.pos+1 < len(l.input) && l.input[l.pos] == ':' && l.input[l.pos+1] == ')' {
			depth--
			l.pos += 2
		} else {
			l.pos++
		}
	}

	if depth > 0 {
		return fmt.Errorf("%w: unterminated comment starting at position %d", ErrUnexpectedToken, start)
	}

	return nil
}

func (l *lexer) scanNCName() string {
	start := l.pos
	for l.pos < len(l.input) {
		r, size := utf8.DecodeRuneInString(l.input[l.pos:])
		if l.pos == start {
			if !xmlchar.IsNCNameStartChar(r) {
				return ""
			}
		} else if !xmlchar.IsNCNameChar(r) {
			break
		}

		l.pos += size
	}

	return l.input[start:l.pos]
}

func (l *lexer) scanString() (string, error) {
	quote := l.input[l.pos]
	l.pos++

	start := l.pos
	for l.pos < len(l.input) {
		if l.input[l.pos] == quote {
			// XPath 3.1: doubled quote is an escape ('' → ', "" → ")
			if l.pos+1 < len(l.input) && l.input[l.pos+1] == quote {
				if l.version == 10 {
					return "", profileError(errCodeXPST0003, "doubled quote escape", 10)
				}

				l.pos += 2

				continue
			}

			s := l.input[start:l.pos]
			l.pos++
			// Unescape doubled quotes
			esc := string(quote) + string(quote)
			if strings.Contains(s, esc) {
				return strings.ReplaceAll(s, esc, string(quote)), nil
			}

			// Literals can outlive the compiled expression through its results.
			return strings.Clone(s), nil
		}

		l.pos++
	}

	return "", fmt.Errorf("%w: starting at position %d", ErrUnterminatedString, start-1)
}

func (l *lexer) scanNumber() error {
	start := l.pos
	for l.pos < len(l.input) && l.input[l.pos] >= '0' && l.input[l.pos] <= '9' {
		l.pos++
	}

	if l.pos < len(l.input) && l.input[l.pos] == '.' {
		l.pos++
		for l.pos < len(l.input) && l.input[l.pos] >= '0' && l.input[l.pos] <= '9' {
			l.pos++
		}
	}
	// Scientific notation: e.g. 1e2, 1.5E-3
	if l.pos < len(l.input) && (l.input[l.pos] == 'e' || l.input[l.pos] == 'E') {
		l.pos++
		if l.pos < len(l.input) && (l.input[l.pos] == '+' || l.input[l.pos] == '-') {
			l.pos++
		}

		digits := l.pos
		for l.pos < len(l.input) && l.input[l.pos] >= '0' && l.input[l.pos] <= '9' {
			l.pos++
		}

		if l.pos == digits {
			return fmt.Errorf("%w: exponent digits expected at position %d", ErrUnexpectedToken, digits)
		}
	}
	// XPath 3.1 A.2.1: a numeric literal immediately followed by a name start
	// character (letter, underscore) is a lexical error.
	if l.pos < len(l.input) {
		r, _ := utf8.DecodeRuneInString(l.input[l.pos:])
		if xmlchar.IsNCNameStartChar(r) {
			return fmt.Errorf("%w: numeric literal immediately followed by name at position %d", ErrUnexpectedToken, start)
		}
	}

	l.emit(TokenNumber, l.input[start:l.pos])

	return nil
}

// scanNameOrKeyword scans an NCName and determines if it's a keyword or name.
// Colon handling is done in the main tokenize loop, not here.
func (l *lexer) scanNameOrKeyword() error {
	name := l.scanNCName()

	// URIQualifiedName: Q{uri}local
	if name == "Q" && l.pos < len(l.input) && l.input[l.pos] == '{' {
		qualified, err := l.scanURIQualifiedName(true)
		if err != nil {
			return err
		}

		l.emit(TokenName, qualified)

		return nil
	}

	// Disambiguate operator keywords from names.
	// Per XPath spec: keywords are operators ONLY when preceded by
	// a value-producing token (where an operator is expected).
	if l.isOperatorContext() {
		if tokType, ok := lookupOperatorKeyword(name); ok {
			l.emit(tokType, name)
			return nil
		}
	}

	// Always-keywords: for, let, some, every, if, try, catch, function, map, array
	// These start sub-expressions, so they are recognized regardless of context —
	// EXCEPT after '/' or '//' where they must be treated as element name tests,
	// unless immediately followed by '{' (curly array/map constructor).
	if tokType, ok := lookupAlwaysKeyword(name); ok {
		if !l.isNameTestContext() {
			l.emit(tokType, name)
			return nil
		}
		// After '/', array{ and map{ are still constructors, not name tests
		if (tokType == TokenArray || tokType == TokenMap) && l.pos < len(l.input) && l.input[l.pos] == '{' {
			l.emit(tokType, name)
			return nil
		}
	}

	l.emit(TokenName, name)

	return nil
}

func (l *lexer) scanURIQualifiedName(wildcard bool) (string, error) {
	l.pos++ // '{' after Q

	start := l.pos
	for l.pos < len(l.input) && l.input[l.pos] != '}' {
		if l.input[l.pos] == '{' {
			return "", fmt.Errorf("%w: '{' in braced URI", ErrUnexpectedToken)
		}

		l.pos++
	}

	if l.pos == len(l.input) {
		return "", fmt.Errorf("%w: unterminated braced URI", ErrUnexpectedToken)
	}

	uri := collapseWhitespace(l.input[start:l.pos])
	l.pos++ // '}'

	if uri == lexicon.NamespaceXMLNS {
		return "", &xdm.Error{Code: "XQST0070", Message: "the xmlns namespace URI cannot be used in an EQName"}
	}

	local := l.scanNCName()
	if local == "" && wildcard && l.pos < len(l.input) && l.input[l.pos] == '*' {
		local = "*"
		l.pos++
	}

	if local == "" {
		return "", fmt.Errorf("%w: local name after braced URI", ErrUnexpectedToken)
	}

	return "Q{" + uri + "}" + local, nil
}

// lookupOperatorKeyword recognizes keywords only after a value-producing token.
// The groups follow XPath comparison, type, clause and arithmetic/set operators.
func lookupOperatorKeyword(name string) (TokenType, bool) {
	switch name {
	case "eq", "ne", "lt", "le", "gt", "ge", "is":
		return lookupComparisonKeyword(name)
	case nameInstance, nameCast, nameCastable, nameTreat, "as", "of":
		return lookupTypeOperatorKeyword(name)
	case "in", nameReturn, nameSatisfies, nameThen, nameElse, keywordWhere, "by", keywordAscending, keywordDescending, keywordStable:
		return lookupClauseKeyword(name)
	default:
		return lookupArithmeticKeyword(name)
	}
}

func lookupComparisonKeyword(name string) (TokenType, bool) {
	switch name {
	case "eq":
		return TokenEq, true
	case "ne":
		return TokenNe, true
	case "lt":
		return TokenLt, true
	case "le":
		return TokenLe, true
	case "gt":
		return TokenGt, true
	case "ge":
		return TokenGe, true
	case "is":
		return TokenIs, true
	default:
		return TokenEOF, false
	}
}

func lookupTypeOperatorKeyword(name string) (TokenType, bool) {
	switch name {
	case nameInstance:
		return TokenInstanceOf, true
	case nameCast:
		return TokenCastAs, true
	case nameCastable:
		return TokenCastableAs, true
	case nameTreat:
		return TokenTreatAs, true
	case "as":
		return TokenAs, true
	case "of":
		return TokenOf, true
	default:
		return TokenEOF, false
	}
}

func lookupClauseKeyword(name string) (TokenType, bool) {
	switch name {
	case "in":
		return TokenIn, true
	case nameReturn:
		return TokenReturn, true
	case nameSatisfies:
		return TokenSatisfies, true
	case nameThen:
		return TokenThen, true
	case nameElse:
		return TokenElse, true
	case keywordWhere:
		return TokenWhere, true
	case "by":
		return TokenBy, true
	case keywordAscending:
		return TokenAscending, true
	case keywordDescending:
		return TokenDescending, true
	case keywordStable:
		return TokenStable, true
	default:
		return TokenEOF, false
	}
}

func lookupArithmeticKeyword(name string) (TokenType, bool) {
	switch name {
	case nameAnd:
		return TokenAnd, true
	case "or":
		return TokenOr, true
	case nameDiv:
		return TokenDiv, true
	case nameMod:
		return TokenMod, true
	case nameIdiv:
		return TokenIdiv, true
	case nameIntersect:
		return TokenIntersect, true
	case nameExcept:
		return TokenExcept, true
	case "to":
		return TokenTo, true
	case nameUnion:
		return TokenUnion, true
	default:
		return TokenEOF, false
	}
}

// alwaysKeywords are recognized regardless of context because they appear
// only at the start of an expression or sub-expression.
func lookupAlwaysKeyword(key string) (TokenType, bool) {
	switch key {
	case nameFor:
		return TokenFor, true
	case nameLet:
		return TokenLet, true
	case nameSome:
		return TokenSome, true
	case nameEvery:
		return TokenEvery, true
	case "if":
		return TokenIf, true
	case "try":
		return TokenTry, true
	case "catch":
		return TokenCatch, true
	case nameFunction:
		return TokenFunction, true
	case keywordMap:
		return TokenMap, true
	case keywordArray:
		return TokenArray, true
	default:
		return TokenEOF, false
	}
}

// isNameTestContext returns true if the previous token indicates that the
// next name should be treated as a name test, and never a keyword.
// This occurs after '/', '//', '@', and '::'.
func (l *lexer) isNameTestContext() bool {
	if len(l.tokens) == 0 {
		return false
	}

	prev := l.tokens[len(l.tokens)-1]

	return prev.Type == TokenSlash || prev.Type == TokenSlashSlash ||
		prev.Type == TokenAt || prev.Type == TokenColonColon
}

// isOperatorContext returns true if an operator keyword is expected at
// this point. Per the XPath spec disambiguation rules, an operator is
// expected when the preceding token is a value-producing token.
func (l *lexer) isOperatorContext() bool {
	if len(l.tokens) == 0 {
		return false
	}

	prev := l.tokens[len(l.tokens)-1]
	switch prev.Type {
	// Value-producing tokens: an operator is expected after these.
	// Note: TokenQMark is NOT here — after '?' we expect a lookup key (NCName),
	// so keywords like 'or', 'and' must be treated as names, not operators.
	case TokenName, TokenNumber, TokenString, TokenRParen, TokenRBracket,
		TokenDot, TokenDotDot, TokenStar, TokenVariableRef, TokenRBrace:
		return true
	case TokenQMark:
		// '?' is value-producing when it follows a type name (occurrence indicator
		// in "cast as xs:double ?", "instance of xs:integer ?"), but NOT when it
		// starts a unary lookup expression ("?key"). Check second-to-last token:
		// if it's a name, this '?' is an occurrence indicator.
		if len(l.tokens) >= 2 {
			prev2 := l.tokens[len(l.tokens)-2]
			if prev2.Type == TokenName {
				return true
			}
		}

		return false
	// Multi-token keyword pairs: "instance of", "cast as", "castable as",
	// "treat as" — the secondary keyword follows the primary keyword.
	case TokenInstanceOf, TokenCastAs, TokenCastableAs, TokenTreatAs:
		return true
	// "for $x in", "let $x := ... return", "where ... order by",
	// "some/every $x in ... satisfies", "if (...) then ... else"
	// — these keywords precede other keywords in their clauses.
	case TokenFor, TokenLet, TokenSome, TokenEvery:
		return true
	}

	return false
}
