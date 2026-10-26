// Derived from lestrrat-go/helium at 7362c0a70122a757780f4d0b545a9b370dead6ab.
// Copyright (c) 2015 lestrrat. MIT License; see licenses/MIT-helium.txt at the repository root.

package xpath

import (
	"errors"
	"fmt"
	"math/big"
	"strconv"
	"strings"

	"github.com/skarm/xmlsec/internal/lexicon"
	"github.com/skarm/xmlsec/internal/xmlchar"
	"github.com/skarm/xmlsec/transform/internal/xdm"
)

const maxParseDepth = 200

// Parse parses an XPath 3.1 expression string into an AST.
func Parse(expr string) (Expr, error) {
	l, err := newLexer(expr)
	if err != nil {
		return nil, err
	}

	return parseWithLexer(l)
}

// ParseSequenceType parses a standalone sequence type expression such as
// "xs:integer?", "element(e)*", or "function(xs:string) as xs:boolean".
func ParseSequenceType(s string) (xdm.SequenceType, error) {
	l, err := newLexer(s)
	if err != nil {
		return xdm.SequenceType{}, err
	}

	p := &parseOptions{lexer: l}

	st, err := p.parseSequenceType()
	if err != nil {
		return xdm.SequenceType{}, err
	}

	if tok := p.lexer.Peek(); tok.Type != TokenEOF {
		return xdm.SequenceType{}, fmt.Errorf("%w: %s after sequence type", ErrUnexpectedToken, tok)
	}

	return st, nil
}

type tokenStream interface {
	Next() Token
	Peek() Token
	PeekAt(offset int) Token
	Backup()
}

type parseOptions struct {
	lexer   tokenStream
	depth   int
	version int
}

// parseExpression parses → ExprSingle (',' ExprSingle)* (sequence constructor).
func (p *parseOptions) parseExpression() (Expr, error) {
	p.depth++
	if p.depth > maxParseDepth {
		return nil, ErrExprTooDeep
	}
	defer func() { p.depth-- }()

	first, err := p.parseExprSingle()
	if err != nil {
		return nil, err
	}

	if p.lexer.Peek().Type != TokenComma {
		return first, nil
	}

	items := make([]Expr, 0, 4)
	items = append(items, first)

	for p.lexer.Peek().Type == TokenComma {
		p.lexer.Next()

		item, err := p.parseExprSingle()
		if err != nil {
			return nil, err
		}

		items = append(items, item)
	}

	return SequenceExpr{Items: items}, nil
}

// parseExprSingle parses → ForExpr | LetExpr | QuantifiedExpr | IfExpr | TryCatchExpr | OrExpr.
func (p *parseOptions) parseExprSingle() (Expr, error) {
	tok := p.lexer.Peek()
	switch tok.Type {
	case TokenFor, TokenLet:
		if p.lexer.PeekAt(1).Type == TokenVariableRef {
			return p.parseFLWOR()
		}
	case TokenSome:
		if p.lexer.PeekAt(1).Type == TokenVariableRef {
			return p.parseQuantifiedExpr(true)
		}
	case TokenEvery:
		if p.lexer.PeekAt(1).Type == TokenVariableRef {
			return p.parseQuantifiedExpr(false)
		}
	case TokenIf:
		if p.lexer.PeekAt(1).Type == TokenLParen {
			return p.parseIfExpr()
		}
	case TokenTry:
		if p.lexer.PeekAt(1).Type == TokenLBrace {
			return p.parseTryCatchExpr()
		}
	}

	return p.parseOrExpr()
}

// peekOperator resolves a word where the grammar expects an operator or
// clause delimiter. The lexer's preceding-token heuristic cannot distinguish
// the two meanings of '*' or a keyword subsequently consumed as a name.
func (p *parseOptions) peekOperator() Token {
	tok := p.lexer.Peek()
	if tok.Type == TokenName {
		if keyword, ok := lookupOperatorKeyword(tok.Value); ok {
			tok.Type = keyword
		}
	}

	return tok
}

// parseOrExpr parses → AndExpr ('or' AndExpr)*.
func (p *parseOptions) parseOrExpr() (Expr, error) {
	left, err := p.parseAndExpr()
	if err != nil {
		return nil, err
	}

	for p.peekOperator().Type == TokenOr {
		p.lexer.Next()

		right, err := p.parseAndExpr()
		if err != nil {
			return nil, err
		}

		left = BinaryExpr{Op: TokenOr, Left: left, Right: right}
	}

	return left, nil
}

// parseAndExpr parses → ComparisonExpr ('and' ComparisonExpr)*.
func (p *parseOptions) parseAndExpr() (Expr, error) {
	left, err := p.parseComparisonExpr()
	if err != nil {
		return nil, err
	}

	for p.peekOperator().Type == TokenAnd {
		p.lexer.Next()

		right, err := p.parseComparisonExpr()
		if err != nil {
			return nil, err
		}

		left = BinaryExpr{Op: TokenAnd, Left: left, Right: right}
	}

	return left, nil
}

// parseComparisonExpr parses → ConcatExpr ((GeneralComp | ValueComp) ConcatExpr)?.
// General: = != < <= > >=
// Value: eq ne lt le gt ge
func (p *parseOptions) parseComparisonExpr() (Expr, error) {
	left, err := p.parseConcatExpr()
	if err != nil {
		return nil, err
	}

	tok := p.peekOperator()
	if isGeneralComp(tok.Type) || isValueComp(tok.Type) || isNodeComp(tok.Type) {
		p.lexer.Next()

		right, err := p.parseConcatExpr()
		if err != nil {
			return nil, err
		}

		return BinaryExpr{Op: tok.Type, Left: left, Right: right}, nil
	}

	return left, nil
}

// parseConcatExpr parses → RangeExpr ('||' RangeExpr)*.
func (p *parseOptions) parseConcatExpr() (Expr, error) {
	left, err := p.parseRangeExpr()
	if err != nil {
		return nil, err
	}

	for p.peekOperator().Type == TokenConcat {
		p.lexer.Next()

		right, err := p.parseRangeExpr()
		if err != nil {
			return nil, err
		}

		left = ConcatExpr{Left: left, Right: right}
	}

	return left, nil
}

// parseRangeExpr parses → AdditiveExpr ('to' AdditiveExpr)?.
func (p *parseOptions) parseRangeExpr() (Expr, error) {
	left, err := p.parseAdditiveExpr()
	if err != nil {
		return nil, err
	}

	if p.peekOperator().Type == TokenTo {
		p.lexer.Next()

		right, err := p.parseAdditiveExpr()
		if err != nil {
			return nil, err
		}

		return RangeExpr{Start: left, End: right}, nil
	}

	return left, nil
}

// parseAdditiveExpr parses → MultiplicativeExpr (('+' | '-') MultiplicativeExpr)*.
func (p *parseOptions) parseAdditiveExpr() (Expr, error) {
	left, err := p.parseMultiplicativeExpr()
	if err != nil {
		return nil, err
	}

	for {
		tok := p.peekOperator()
		if tok.Type != TokenPlus && tok.Type != TokenMinus {
			break
		}

		p.lexer.Next()

		right, err := p.parseMultiplicativeExpr()
		if err != nil {
			return nil, err
		}

		left = BinaryExpr{Op: tok.Type, Left: left, Right: right}
	}

	return left, nil
}

// parseMultiplicativeExpr parses → UnionExpr (('*' | 'div' | 'idiv' | 'mod') UnionExpr)*.
func (p *parseOptions) parseMultiplicativeExpr() (Expr, error) {
	left, err := p.parseUnionExpr()
	if err != nil {
		return nil, err
	}

	for {
		tok := p.peekOperator()
		if tok.Type != TokenStar && tok.Type != TokenDiv && tok.Type != TokenIdiv && tok.Type != TokenMod {
			break
		}

		p.lexer.Next()

		right, err := p.parseUnionExpr()
		if err != nil {
			return nil, err
		}

		left = BinaryExpr{Op: tok.Type, Left: left, Right: right}
	}

	return left, nil
}

// parseUnionExpr parses → IntersectExceptExpr (('|' | 'union') IntersectExceptExpr)*.
func (p *parseOptions) parseUnionExpr() (Expr, error) {
	left, err := p.parseIntersectExceptExpr()
	if err != nil {
		return nil, err
	}

	for {
		tok := p.peekOperator()
		if tok.Type != TokenPipe && tok.Type != TokenUnion {
			break
		}

		p.lexer.Next()

		right, err := p.parseIntersectExceptExpr()
		if err != nil {
			return nil, err
		}

		left = UnionExpr{Left: left, Right: right}
	}

	return left, nil
}

// parseIntersectExceptExpr parses → InstanceOfExpr (('intersect' | 'except') InstanceOfExpr)*.
func (p *parseOptions) parseIntersectExceptExpr() (Expr, error) {
	left, err := p.parseInstanceOfExpr()
	if err != nil {
		return nil, err
	}

	for {
		tok := p.peekOperator()
		if tok.Type != TokenIntersect && tok.Type != TokenExcept {
			break
		}

		p.lexer.Next()

		right, err := p.parseInstanceOfExpr()
		if err != nil {
			return nil, err
		}

		left = IntersectExceptExpr{Op: tok.Type, Left: left, Right: right}
	}

	return left, nil
}

// parseInstanceOfExpr parses → TreatAsExpr ('instance' 'of' SequenceType)?.
func (p *parseOptions) parseInstanceOfExpr() (Expr, error) {
	left, err := p.parseTreatAsExpr()
	if err != nil {
		return nil, err
	}

	if p.peekOperator().Type == TokenInstanceOf {
		p.lexer.Next() // consume 'instance'

		if p.peekOperator().Type != TokenOf {
			return nil, fmt.Errorf("%w: 'of' after 'instance' but got %s", ErrExpectedToken, p.peekOperator())
		}

		p.lexer.Next() // consume 'of'

		st, err := p.parseSequenceType()
		if err != nil {
			return nil, err
		}

		return InstanceOfExpr{Expr: left, Type: st}, nil
	}

	return left, nil
}

// parseTreatAsExpr parses → CastableAsExpr ('treat' 'as' SequenceType)?.
func (p *parseOptions) parseTreatAsExpr() (Expr, error) {
	left, err := p.parseCastableAsExpr()
	if err != nil {
		return nil, err
	}

	if p.peekOperator().Type == TokenTreatAs {
		p.lexer.Next() // consume 'treat'

		if p.peekOperator().Type != TokenAs {
			return nil, fmt.Errorf("%w: 'as' after 'treat' but got %s", ErrExpectedToken, p.peekOperator())
		}

		p.lexer.Next() // consume 'as'

		st, err := p.parseSequenceType()
		if err != nil {
			return nil, err
		}

		return TreatAsExpr{Expr: left, Type: st}, nil
	}

	return left, nil
}

// parseCastableAsExpr parses → CastAsExpr ('castable' 'as' SingleType)?.
func (p *parseOptions) parseCastableAsExpr() (Expr, error) {
	left, err := p.parseCastAsExpr()
	if err != nil {
		return nil, err
	}

	if p.peekOperator().Type == TokenCastableAs {
		p.lexer.Next() // consume 'castable'

		if p.peekOperator().Type != TokenAs {
			return nil, fmt.Errorf("%w: 'as' after 'castable' but got %s", ErrExpectedToken, p.peekOperator())
		}

		p.lexer.Next() // consume 'as'

		typeName, allowEmpty, err := p.parseSingleType()
		if err != nil {
			return nil, err
		}

		return CastableExpr{Expr: left, Type: typeName, AllowEmpty: allowEmpty}, nil
	}

	return left, nil
}

// parseCastAsExpr parses → ArrowExpr ('cast' 'as' SingleType)?.
func (p *parseOptions) parseCastAsExpr() (Expr, error) {
	left, err := p.parseArrowExpr()
	if err != nil {
		return nil, err
	}

	if p.peekOperator().Type == TokenCastAs {
		p.lexer.Next() // consume 'cast'

		if p.peekOperator().Type != TokenAs {
			return nil, fmt.Errorf("%w: 'as' after 'cast' but got %s", ErrExpectedToken, p.peekOperator())
		}

		p.lexer.Next() // consume 'as'

		typeName, allowEmpty, err := p.parseSingleType()
		if err != nil {
			return nil, err
		}

		return CastExpr{Expr: left, Type: typeName, AllowEmpty: allowEmpty}, nil
	}

	return left, nil
}

// parseArrowExpr parses → UnaryExpr ('=>' ArrowFunctionSpecifier ArgumentList)*.
// Desugared: $x => f(a, b) becomes f($x, a, b).
func (p *parseOptions) parseArrowExpr() (Expr, error) {
	left, err := p.parseUnaryExpr()
	if err != nil {
		return nil, err
	}

	for p.lexer.Peek().Type == TokenArrow {
		p.lexer.Next() // consume '=>'
		// ArrowFunctionSpecifier: Name or VarRef or ParenthesizedExpr
		funcSpec, prefix, name, err := p.parseArrowTarget()
		if err != nil {
			return nil, err
		}

		if p.lexer.Peek().Type != TokenLParen {
			return nil, fmt.Errorf("%w: '(' after arrow target but got %s", ErrExpectedToken, p.lexer.Peek())
		}

		args, err := p.parseArgumentList()
		if err != nil {
			return nil, err
		}
		// Desugar: prepend left as first argument
		allArgs := make([]Expr, 0, len(args)+1)
		allArgs = append(allArgs, left)
		allArgs = append(allArgs, args...)

		if funcSpec != nil {
			// Dynamic call: ($expr)(args...)
			left = DynamicFunctionCall{Func: funcSpec, Args: allArgs}
		} else {
			left = FunctionCall{Prefix: prefix, Name: name, Args: allArgs}
		}
	}

	return left, nil
}

// parseArrowTarget parses the function specifier after =>.
// Returns either (expr, "", "", nil) for dynamic targets or (nil, prefix, name, nil) for static.
func (p *parseOptions) parseArrowTarget() (Expr, string, string, error) {
	tok := p.lexer.Peek()
	if tok.Type == TokenVariableRef {
		p.lexer.Next()
		return variableExprFromToken(tok.Value), "", "", nil
	}

	if tok.Type == TokenLParen {
		expr, err := p.parseParenExpr()
		if err != nil {
			return nil, "", "", err
		}

		return expr, "", "", nil
	}

	if isNameLikeToken(tok.Type) {
		p.lexer.Next()

		prefix := ""
		name := tok.Value

		if colonTok := p.lexer.Peek(); colonTok.Type == TokenColon && !colonTok.SpaceBefore {
			p.lexer.Next() // consume ':'

			localTok := p.lexer.Next()
			if !isNameLikeToken(localTok.Type) {
				return nil, "", "", fmt.Errorf("%w: name after '%s:' in arrow but got %s", ErrExpectedToken, name, localTok)
			}

			prefix = name
			name = localTok.Value
		}

		return nil, prefix, name, nil
	}

	return nil, "", "", fmt.Errorf("%w: arrow function target but got %s", ErrExpectedToken, tok)
}

// parseUnaryExpr parses → ('-' | '+')* ValueExpr.
// ValueExpr ::= SimpleMapExpr.
func (p *parseOptions) parseUnaryExpr() (Expr, error) {
	negate := 0
	hasUnary := false

loop:
	for {
		tok := p.lexer.Peek()
		switch tok.Type {
		case TokenMinus:
			p.lexer.Next()

			negate++
			hasUnary = true
		case TokenPlus:
			p.lexer.Next()

			hasUnary = true
			// unary + is a no-op for negate count but still marks as having unary
		default:
			break loop
		}
	}

	expr, err := p.parseSimpleMapExpr()
	if err != nil {
		return nil, err
	}

	if hasUnary && negate == 0 {
		// Pure unary plus: wrap to enforce numeric type check
		expr = UnaryExpr{Operand: expr, Negate: false}
	}

	for range negate {
		expr = UnaryExpr{Operand: expr, Negate: true}
	}

	return expr, nil
}

// parseSimpleMapExpr parses → PathExpr ('!' PathExpr)*.
func (p *parseOptions) parseSimpleMapExpr() (Expr, error) {
	left, err := p.parsePathExpr()
	if err != nil {
		return nil, err
	}

	for p.lexer.Peek().Type == TokenBang {
		p.lexer.Next()

		right, err := p.parsePathExpr()
		if err != nil {
			return nil, err
		}

		left = SimpleMapExpr{Left: left, Right: right}
	}

	return left, nil
}

// parsePathExpr → LocationPath | PostfixExpr (('/' | '//') RelativeLocationPath)?
func (p *parseOptions) parsePathExpr() (Expr, error) {
	expr, err := p.parsePathStart()
	if err != nil {
		return nil, err
	}

	// Apply postfix operations
	expr, err = p.parsePostfixOps(expr)
	if err != nil {
		return nil, err
	}

	return p.parsePathContinuation(expr)
}

func (p *parseOptions) parsePathStart() (Expr, error) {
	tok := p.lexer.Peek()
	switch tok.Type {
	case TokenSlash:
		return p.parseAbsolutePath(false)
	case TokenSlashSlash:
		return p.parseAbsolutePath(true)
	}

	if p.looksLikeStep() {
		steps, err := p.parseRelativeLocationPath()
		if err != nil {
			return nil, err
		}

		return &LocationPath{Steps: steps}, nil
	}

	return p.parsePostfixExpr()
}

func (p *parseOptions) parseAbsolutePath(descendant bool) (Expr, error) {
	p.lexer.Next() // consume / or //

	root := &LocationPath{Absolute: true}
	if descendant {
		root.Steps = []Step{{Axis: AxisDescendantOrSelf, NodeTest: xdm.TypeTest{Kind: xdm.NodeKindNode}}}
	}

	if p.looksLikeStep() {
		steps, err := p.parseRelativeLocationPath()
		if err != nil {
			return nil, err
		}

		root.Steps = append(root.Steps, steps...)

		return root, nil
	}

	// A bare / selects the document root; // always requires a following expression.
	if !descendant && !p.canStartPostfixExpr() {
		return root, nil
	}

	right, err := p.parsePostfixExpr()
	if err != nil {
		return nil, err
	}

	return PathStepExpr{Left: root, Right: right}, nil
}

// parsePathContinuation handles trailing / or // after the initial part of a path.
// It chains additional axis steps (via PathExpr) or non-step expressions (via PathStepExpr).
func (p *parseOptions) parsePathContinuation(expr Expr) (Expr, error) {
	for {
		tok := p.lexer.Peek()
		if tok.Type != TokenSlash && tok.Type != TokenSlashSlash {
			return expr, nil
		}

		descOrSelf := tok.Type == TokenSlashSlash

		p.lexer.Next()

		if p.looksLikeStep() {
			// Collect consecutive axis steps into a LocationPath
			path := &LocationPath{}
			if descOrSelf {
				path.Steps = append(path.Steps, Step{
					Axis:     AxisDescendantOrSelf,
					NodeTest: xdm.TypeTest{Kind: xdm.NodeKindNode},
				})
			}

			steps, err := p.parseRelativeLocationPath()
			if err != nil {
				return nil, err
			}

			path.Steps = append(path.Steps, steps...)
			expr = PathExpr{Filter: expr, Path: path}
		} else {
			// Non-step expression: function call, variable, etc.
			if descOrSelf {
				// E1 // nonStep → E1 / descendant-or-self::node() / nonStep
				expr = PathExpr{
					Filter: expr,
					Path: &LocationPath{Steps: []Step{{
						Axis:     AxisDescendantOrSelf,
						NodeTest: xdm.TypeTest{Kind: xdm.NodeKindNode},
					}}},
				}
			}

			right, err := p.parsePostfixExpr()
			if err != nil {
				return nil, err
			}

			expr = PathStepExpr{Left: expr, Right: right}
		}

		// Apply postfix operations on the result (predicates, lookups)
		var err error

		expr, err = p.parsePostfixOps(expr)
		if err != nil {
			return nil, err
		}
	}
}

func (p *parseOptions) canStartPostfixExpr() bool {
	tok := p.lexer.Peek()
	switch tok.Type {
	case TokenVariableRef, TokenLParen, TokenString, TokenNumber,
		TokenDot, TokenQMark, TokenLBracket:
		return true
	default:
		return isNameLikeToken(tok.Type)
	}
}

// parsePostfixExpr parses → PrimaryExpr (Predicate | ArgumentList | Lookup)*.
func (p *parseOptions) parsePostfixExpr() (Expr, error) {
	primary, err := p.parsePrimaryExpr()
	if err != nil {
		return nil, err
	}

	return p.parsePostfixOps(primary)
}

// parsePostfixOps applies predicates, argument lists (dynamic calls), and lookups.
func (p *parseOptions) parsePostfixOps(expr Expr) (Expr, error) {
	for {
		tok := p.lexer.Peek()
		switch tok.Type {
		case TokenLBracket:
			pred, err := p.parsePredicate()
			if err != nil {
				return nil, err
			}

			if fe, ok := expr.(FilterExpr); ok {
				fe.Predicates = append(fe.Predicates, pred)
				expr = fe
			} else {
				expr = FilterExpr{Expr: expr, Predicates: []Expr{pred}}
			}
		case TokenLParen:
			// Dynamic function call: expr(args)
			args, err := p.parseArgumentList()
			if err != nil {
				return nil, err
			}

			expr = DynamicFunctionCall{Func: expr, Args: args}
		case TokenQMark:
			// Lookup: expr ? key
			p.lexer.Next()

			key, all, err := p.parseLookupKey()
			if err != nil {
				return nil, err
			}

			expr = LookupExpr{Expr: expr, Key: key, All: all}
		default:
			return expr, nil
		}
	}
}

func (p *parseOptions) parsePrimaryExpr() (Expr, error) {
	tok := p.lexer.Peek()

	switch tok.Type {
	case TokenVariableRef:
		p.lexer.Next()
		return variableExprFromToken(tok.Value), nil

	case TokenLParen:
		return p.parseParenExprOrEmpty()

	case TokenString:
		p.lexer.Next()
		return LiteralExpr{Value: tok.Value}, nil

	case TokenNumber:
		p.lexer.Next()
		return parseNumberLiteral(tok.Value)

	case TokenDot:
		p.lexer.Next()
		return ContextItemExpr{}, nil

	case TokenQMark:
		// Unary lookup: ? key
		p.lexer.Next()

		key, all, err := p.parseLookupKey()
		if err != nil {
			return nil, err
		}

		return UnaryLookupExpr{Key: key, All: all}, nil

	case TokenFunction:
		// nameFunction followed by "(" is an inline function or function test.
		// Otherwise it's a name test (e.g., child::function or xs:QName(function)).
		if (p.version == 0 || p.version >= 30) && p.lexer.PeekAt(1).Type == TokenLParen {
			return p.parseFunctionKeyword()
		}
		// Treat as a regular name (name test / path step).
		return p.parseNamePrimary()

	case TokenMap:
		if p.lexer.PeekAt(1).Type == TokenLBrace {
			return p.parseMapConstructor()
		}

		return p.parseNamePrimary()

	case TokenArray:
		if p.lexer.PeekAt(1).Type == TokenLBrace {
			return p.parseArrayCurlyConstructor()
		}

		return p.parseNamePrimary()

	case TokenLBracket:
		return p.parseArraySquareConstructor()

	case TokenName:
		return p.parseNamePrimary()

	case TokenIf:
		if p.lexer.PeekAt(1).Type == TokenLParen {
			return p.parseIfExpr()
		}

		return p.parseNamePrimary()
	case TokenFor, TokenLet, TokenSome, TokenEvery, TokenTry, TokenCatch:
		return p.parseNamePrimary()

	default:
		if isNameLikeToken(tok.Type) {
			return p.parseNamePrimary()
		}

		return nil, fmt.Errorf("%w: %s in primary expression", ErrUnexpectedToken, tok)
	}
}

// parseNamePrimary handles a Name at the start of a primary expression:
// function call, named function ref, or error.
func (p *parseOptions) parseNamePrimary() (Expr, error) {
	tok := p.lexer.Next()
	prefix := ""
	name := tok.Value

	// Check for QName: prefix:name (no whitespace around colon per XPath 3.1 A.2.1)
	if p.joinedQNameAt(0) {
		p.lexer.Next() // consume ':'

		localTok := p.lexer.Peek()
		if isNameLikeToken(localTok.Type) && !localTok.SpaceBefore {
			p.lexer.Next()

			prefix = name
			name = localTok.Value
		} else {
			p.lexer.Backup() // put ':' back
			p.lexer.Backup() // put name back

			return nil, fmt.Errorf("%w: %s in primary expression", ErrUnexpectedToken, tok)
		}
	}

	// Named function ref: name#arity
	if p.lexer.Peek().Type == TokenHash {
		p.lexer.Next() // consume '#'

		arityTok := p.lexer.Next()
		if arityTok.Type != TokenNumber {
			return nil, fmt.Errorf("%w: arity number after '#' but got %s", ErrExpectedToken, arityTok)
		}

		for _, digit := range arityTok.Value {
			if digit < '0' || digit > '9' {
				return nil, fmt.Errorf("%w: arity must be an integer literal", ErrUnexpectedToken)
			}
		}
		// Arity is observable through function-arity, so capacity overflow must
		// not saturate to a different arity on a smaller platform.
		arity, err := strconv.Atoi(arityTok.Value)
		if err != nil {
			if errors.Is(err, strconv.ErrRange) {
				return nil, &xdm.Error{Code: errCodeFOAR0002, Message: "function arity exceeds the supported integer range", Cause: err}
			}

			return nil, fmt.Errorf("%w: invalid arity %q: %w", ErrUnexpectedToken, arityTok.Value, err)
		}

		return NamedFunctionRef{Prefix: prefix, Name: name, Arity: arity}, nil
	}

	// Function call: name(args)
	if p.lexer.Peek().Type == TokenLParen {
		args, err := p.parseArgumentList()
		if err != nil {
			return nil, err
		}

		return FunctionCall{Prefix: prefix, Name: name, Args: args}, nil
	}

	// Not a primary — put back
	if prefix != "" {
		p.lexer.Backup() // local name
		p.lexer.Backup() // ':'
	}

	p.lexer.Backup() // name

	return nil, fmt.Errorf("%w: %s in primary expression", ErrUnexpectedToken, tok)
}

// parseParenExprOrEmpty handles '(' which could be an empty sequence () or a parenthesized expression.
func (p *parseOptions) parseParenExprOrEmpty() (Expr, error) {
	p.lexer.Next() // consume '('

	if p.lexer.Peek().Type == TokenRParen {
		p.lexer.Next() // consume ')'
		return SequenceExpr{Items: nil}, nil
	}

	expr, err := p.parseExpression()
	if err != nil {
		return nil, err
	}

	if p.lexer.Peek().Type != TokenRParen {
		return nil, fmt.Errorf("%w: ')' but got %s", ErrExpectedToken, p.lexer.Peek())
	}

	p.lexer.Next()

	return expr, nil
}

// parseParenExpr parses '(' Expr ')'.
func (p *parseOptions) parseParenExpr() (Expr, error) {
	p.lexer.Next() // consume '('

	expr, err := p.parseExpression()
	if err != nil {
		return nil, err
	}

	if p.lexer.Peek().Type != TokenRParen {
		return nil, fmt.Errorf("%w: ')' but got %s", ErrExpectedToken, p.lexer.Peek())
	}

	p.lexer.Next()

	return expr, nil
}

// parseArgumentList parses '(' (ExprSingle (',' ExprSingle)*)? ')'.
// ? in argument position produces PlaceholderExpr (partial application).
func (p *parseOptions) parseArgumentList() ([]Expr, error) {
	if p.lexer.Peek().Type != TokenLParen {
		return nil, fmt.Errorf("%w: '(' but got %s", ErrExpectedToken, p.lexer.Peek())
	}

	p.lexer.Next() // consume '('

	if p.lexer.Peek().Type != TokenRParen {
		args := make([]Expr, 0, 4)

		for {
			if p.lexer.Peek().Type == TokenQMark {
				// Disambiguate: ? followed by a key specifier (NCName, integer, *, '(')
				// is a unary lookup expression, not a placeholder.
				next := p.lexer.PeekAt(1).Type
				if next == TokenName || next == TokenNumber || next == TokenStar || next == TokenLParen {
					arg, err := p.parseExprSingle()
					if err != nil {
						return nil, err
					}

					args = append(args, arg)
				} else {
					p.lexer.Next()

					args = append(args, PlaceholderExpr{})
				}
			} else {
				arg, err := p.parseExprSingle()
				if err != nil {
					return nil, err
				}

				args = append(args, arg)
			}

			if p.lexer.Peek().Type != TokenComma {
				break
			}

			p.lexer.Next() // consume ','
		}

		if p.lexer.Peek().Type != TokenRParen {
			return nil, fmt.Errorf("%w: ')' in argument list but got %s", ErrExpectedToken, p.lexer.Peek())
		}

		p.lexer.Next()

		return args, nil
	}

	if p.lexer.Peek().Type != TokenRParen {
		return nil, fmt.Errorf("%w: ')' in argument list but got %s", ErrExpectedToken, p.lexer.Peek())
	}

	p.lexer.Next()

	return nil, nil
}

// parseLookupKey parses the key after '?': NCName, integer, '*', or '(' expr ')'.
func (p *parseOptions) parseLookupKey() (Expr, bool, error) {
	tok := p.lexer.Peek()
	switch tok.Type {
	case TokenStar:
		p.lexer.Next()
		return nil, true, nil
	case TokenNumber:
		// Only integer literals are valid lookup keys (no dot, no exponent)
		if strings.ContainsAny(tok.Value, ".eE") {
			return nil, false, fmt.Errorf("%w: integer lookup key but got %s", ErrExpectedToken, tok)
		}

		p.lexer.Next()

		n := new(big.Int)
		if _, ok := n.SetString(tok.Value, 10); !ok {
			return nil, false, fmt.Errorf("%w: invalid lookup index %q", ErrUnexpectedToken, tok.Value)
		}

		return LiteralExpr{Value: n}, false, nil
	case TokenLParen:
		expr, err := p.parseParenExprOrEmpty()
		if err != nil {
			return nil, false, err
		}

		return expr, false, nil
	default:
		// Accept any keyword or name token as an NCName key
		if name := tokenAsNCName(tok); name != "" {
			p.lexer.Next()
			return LiteralExpr{Value: name}, false, nil
		}

		return nil, false, fmt.Errorf("%w: lookup key but got %s", ErrExpectedToken, tok)
	}
}

// parseRelativeLocationPath parses → Step (('/' | '//') Step)*.
func (p *parseOptions) parseRelativeLocationPath() ([]Step, error) {
	step, err := p.parseStep()
	if err != nil {
		return nil, err
	}

	steps := make([]Step, 0, 4)
	steps = append(steps, step)

loop:
	for {
		tok := p.lexer.Peek()
		switch tok.Type {
		case TokenSlash:
			if !p.looksLikeStepOffset(1) {
				break loop
			}

			p.lexer.Next()

			s, err := p.parseStep()
			if err != nil {
				return nil, err
			}

			steps = append(steps, s)
		case TokenSlashSlash:
			if !p.looksLikeStepOffset(1) {
				break loop
			}

			p.lexer.Next()

			steps = append(steps, Step{
				Axis:     AxisDescendantOrSelf,
				NodeTest: xdm.TypeTest{Kind: xdm.NodeKindNode},
			})

			s, err := p.parseStep()
			if err != nil {
				return nil, err
			}

			steps = append(steps, s)
		default:
			break loop
		}
	}

	return steps, nil
}

// parseStep parses → AxisSpecifier NodeTest Predicate* | AbbreviatedStep.
func (p *parseOptions) parseStep() (Step, error) {
	tok := p.lexer.Peek()

	// Abbreviated step: .
	if tok.Type == TokenDot {
		p.lexer.Next()

		return Step{
			Axis:     AxisSelf,
			NodeTest: xdm.TypeTest{Kind: xdm.NodeKindNode},
		}, nil
	}

	// Abbreviated step: ..
	if tok.Type == TokenDotDot {
		p.lexer.Next()

		return Step{
			Axis:     AxisParent,
			NodeTest: xdm.TypeTest{Kind: xdm.NodeKindNode},
		}, nil
	}

	// @ is short for attribute::
	axis := AxisChild
	axisSpecified := false

	switch tok.Type {
	case TokenAt:
		axis = AxisAttribute
		axisSpecified = true

		p.lexer.Next()
	default:
		if isNameLikeToken(tok.Type) && p.lexer.PeekAt(1).Type == TokenColonColon {
			if a, ok := xdm.AxisFromName(tok.Value); ok {
				axis = a
				axisSpecified = true

				p.lexer.Next()
				p.lexer.Next() // consume '::'
			} else {
				return Step{}, fmt.Errorf("%w: %q", ErrUnknownAxis, tok.Value)
			}
		}
	}

	nodeTest, err := p.parseNodeTest(axis)
	if err != nil {
		return Step{}, err
	}
	// The default axis is child, except when the (unabbreviated) node test is
	// an attribute/schema-attribute or namespace-node kind test, in which case
	// the default axis is attribute or namespace respectively (XPath 3.0
	// §3.3.2.1). This substitution applies ONLY when no axis was written
	// explicitly: an explicit "child::attribute(x)" keeps the child axis (and so
	// selects nothing, since attributes are never children).
	if axis == AxisChild && !axisSpecified {
		switch nodeTest.(type) {
		case xdm.NamespaceNodeTest:
			axis = AxisNamespace
		case xdm.AttributeTest, xdm.SchemaAttributeTest:
			axis = AxisAttribute
		}
	}

	var predicates []Expr
	if p.lexer.Peek().Type == TokenLBracket {
		predicates = make([]Expr, 0, 2)
	}

	for p.lexer.Peek().Type == TokenLBracket {
		pred, err := p.parsePredicate()
		if err != nil {
			return Step{}, err
		}

		predicates = append(predicates, pred)
	}

	return Step{
		Axis:       axis,
		NodeTest:   nodeTest,
		Predicates: predicates,
	}, nil
}

// parseNodeTest parses → NameTest | KindTest.
func (p *parseOptions) parseNodeTest(_ AxisType) (xdm.NodeTest, error) {
	tok := p.lexer.Peek()

	// * wildcard or *:local
	if tok.Type == TokenStar {
		p.lexer.Next()

		if p.joinedQNameAt(0) {
			p.lexer.Next() // consume ':'

			local := p.lexer.Peek()
			if isNameLikeToken(local.Type) && !local.SpaceBefore {
				p.lexer.Next()
				return xdm.NameTest{Prefix: "*", Local: local.Value}, nil
			}

			return nil, fmt.Errorf("%w: local name after '*:'", ErrExpectedToken)
		}

		return xdm.NameTest{Local: "*"}, nil
	}

	if !isNameLikeToken(tok.Type) {
		return nil, fmt.Errorf("%w: node test but got %s", ErrExpectedToken, tok)
	}

	p.lexer.Next()

	if p.lexer.Peek().Type == TokenLParen {
		if nt, ok, err := p.parseKindTest(tok.Value); ok || err != nil {
			return nt, err
		}
		// Not a kind test — back up past the name
		p.lexer.Backup()
	}

	if strings.HasPrefix(tok.Value, "Q{") {
		if idx := strings.Index(tok.Value, "}"); idx >= 0 {
			uri := tok.Value[2:idx]
			local := tok.Value[idx+1:]

			if uri == lexicon.NamespaceXMLNS {
				return nil, &xdm.Error{Code: errCodeXPST0081, Message: "the xmlns namespace URI cannot be used in name tests"}
			}

			return xdm.NameTest{URI: uri, Local: local}, nil
		}
	}

	// Check for QName: prefix:local or prefix:*
	// Per XPath 3.1 A.2.1: a QName has no whitespace around the colon.
	// If whitespace precedes ':', this name stands alone (the ':' is a
	// map-entry separator or similar context-dependent delimiter).
	if p.joinedQNameAt(0) {
		return p.parseQNameTest(tok.Value)
	}

	return xdm.NameTest{Local: tok.Value}, nil
}

// parseKindTest attempts to parse a kind test function.
// Returns (result, true, nil) on success, (nil, false, nil) when name is not a kind test keyword.
func (p *parseOptions) parseKindTest(name string) (xdm.NodeTest, bool, error) {
	switch name {
	case "node":
		p.lexer.Next() // consume '('

		if err := p.expectToken(TokenRParen); err != nil {
			return nil, true, err
		}

		return xdm.TypeTest{Kind: xdm.NodeKindNode}, true, nil
	case "text":
		p.lexer.Next()

		if err := p.expectToken(TokenRParen); err != nil {
			return nil, true, err
		}

		return xdm.TypeTest{Kind: xdm.NodeKindText}, true, nil
	case "comment":
		p.lexer.Next()

		if err := p.expectToken(TokenRParen); err != nil {
			return nil, true, err
		}

		return xdm.TypeTest{Kind: xdm.NodeKindComment}, true, nil
	case nameProcessingInstruction:
		p.lexer.Next()

		target := ""

		hasTarget := false
		if p.lexer.Peek().Type == TokenString || tokenAsNCName(p.lexer.Peek()) != "" {
			hasTarget = true
			target = p.lexer.Next().Value
		}

		if err := p.expectToken(TokenRParen); err != nil {
			return nil, true, err
		}

		test := xdm.PITest{Target: target, HasTarget: hasTarget}

		if p.version != 10 {
			var err error

			test, err = normalizePITest(test)
			if err != nil {
				return nil, true, err
			}
		}

		return test, true, nil
	case lexicon.KindElement:
		return p.parseElementOrAttributeTest(true)
	case lexicon.KindAttribute:
		return p.parseElementOrAttributeTest(false)
	case "document-node":
		return p.parseDocumentNodeTest()
	case lexicon.KindSchemaElement:
		return p.parseSchemaTest(true)
	case "schema-attribute":
		return p.parseSchemaTest(false)
	case "namespace-node":
		p.lexer.Next()

		if err := p.expectToken(TokenRParen); err != nil {
			return nil, true, err
		}

		return xdm.NamespaceNodeTest{}, true, nil
	case "item":
		p.lexer.Next()

		if err := p.expectToken(TokenRParen); err != nil {
			return nil, true, err
		}

		return xdm.AnyItemTest{}, true, nil
	}

	return nil, false, nil
}

// parseElementOrAttributeTest parses element(name?, type?) or attribute(name?, type?).
func (p *parseOptions) parseElementOrAttributeTest(isElement bool) (xdm.NodeTest, bool, error) {
	p.lexer.Next() // consume '('

	name := ""
	typeName := ""
	nillable := false

	if p.lexer.Peek().Type != TokenRParen {
		if p.lexer.Peek().Type == TokenStar {
			p.lexer.Next()

			name = "*"
		} else if p.lexer.Peek().Type == TokenName {
			name = p.scanQName()
		}

		if p.lexer.Peek().Type == TokenComma {
			p.lexer.Next()
			typeName = p.scanQName()
			// element(name, type?) — trailing ? means nillable
			if isElement && p.lexer.Peek().Type == TokenQMark {
				p.lexer.Next()

				nillable = true
			}
		}
	}

	if err := p.expectToken(TokenRParen); err != nil {
		if isElement {
			return nil, true, fmt.Errorf("%w: ')' after element(", ErrExpectedToken)
		}

		return nil, true, fmt.Errorf("%w: ')' after attribute(", ErrExpectedToken)
	}

	if isElement {
		return xdm.ElementTest{Name: name, TypeName: typeName, Nillable: nillable}, true, nil
	}

	return xdm.AttributeTest{Name: name, TypeName: typeName}, true, nil
}

// parseDocumentNodeTest parses document-node(element(...)?) or document-node(schema-element(...)) or document-node().
func (p *parseOptions) parseDocumentNodeTest() (xdm.NodeTest, bool, error) {
	p.lexer.Next() // consume '('

	var inner xdm.NodeTest

	tok := p.lexer.Peek()
	if tok.Type == TokenName {
		switch tok.Value {
		case lexicon.KindElement:
			p.lexer.Next() // consume 'element'

			nt, _, err := p.parseElementOrAttributeTest(true)
			if err != nil {
				return nil, true, err
			}

			inner = nt
		case lexicon.KindSchemaElement:
			p.lexer.Next() // consume 'schema-element'

			nt, _, err := p.parseSchemaTest(true)
			if err != nil {
				return nil, true, err
			}

			inner = nt
		}
	}

	if err := p.expectToken(TokenRParen); err != nil {
		return nil, true, fmt.Errorf("%w: ')' after document-node(", ErrExpectedToken)
	}

	return xdm.DocumentTest{Inner: inner}, true, nil
}

// parseSchemaTest parses schema-element(name) or schema-attribute(name).
func (p *parseOptions) parseSchemaTest(isElement bool) (xdm.NodeTest, bool, error) {
	p.lexer.Next() // consume '('

	name := p.scanQName()
	if name == "" {
		return nil, true, fmt.Errorf("%w: declaration name in schema test", ErrExpectedToken)
	}

	if err := p.expectToken(TokenRParen); err != nil {
		if isElement {
			return nil, true, fmt.Errorf("%w: ')' after schema-element(", ErrExpectedToken)
		}

		return nil, true, fmt.Errorf("%w: ')' after schema-attribute(", ErrExpectedToken)
	}

	if isElement {
		return xdm.SchemaElementTest{Name: name}, true, nil
	}

	return xdm.SchemaAttributeTest{Name: name}, true, nil
}

// parseQNameTest parses a prefix:local or prefix:* name test.
func (p *parseOptions) parseQNameTest(prefix string) (xdm.NodeTest, error) {
	p.lexer.Next() // consume ':'

	next := p.lexer.Peek()
	if next.SpaceBefore {
		return nil, fmt.Errorf("%w: whitespace or comment inside QName", ErrUnexpectedToken)
	}

	if next.Type == TokenStar {
		p.lexer.Next()
		return xdm.NameTest{Prefix: prefix, Local: "*"}, nil
	}

	if isNameLikeToken(next.Type) {
		p.lexer.Next()
		return xdm.NameTest{Prefix: prefix, Local: next.Value}, nil
	}

	return nil, fmt.Errorf("%w: name or '*' after '%s:'", ErrExpectedToken, prefix)
}

// parsePredicate parses → '[' Expr ']'.
func (p *parseOptions) parsePredicate() (Expr, error) {
	if p.lexer.Peek().Type != TokenLBracket {
		return nil, fmt.Errorf("%w: '[' but got %s", ErrExpectedToken, p.lexer.Peek())
	}

	p.lexer.Next()

	expr, err := p.parseExpression()
	if err != nil {
		return nil, err
	}

	if p.lexer.Peek().Type != TokenRBracket {
		return nil, fmt.Errorf("%w: ']' but got %s", ErrExpectedToken, p.lexer.Peek())
	}

	p.lexer.Next()

	return expr, nil
}

func isGeneralComp(t TokenType) bool {
	return t == TokenEquals || t == TokenNotEquals ||
		t == TokenLess || t == TokenLessEq ||
		t == TokenGreater || t == TokenGreaterEq
}

func isValueComp(t TokenType) bool {
	return t == TokenEq || t == TokenNe ||
		t == TokenLt || t == TokenLe ||
		t == TokenGt || t == TokenGe
}

func isNodeComp(t TokenType) bool {
	return t == TokenIs || t == TokenNodePre || t == TokenNodeFol
}

// parseNumberLiteral converts a numeric token value to a LiteralExpr.
// Per XPath 3.1: no dot and no e/E → xs:integer (*big.Int),
// dot but no e/E → xs:decimal (*big.Rat),
// e/E → xs:double (float64).
func parseNumberLiteral(s string) (LiteralExpr, error) {
	hasE := strings.ContainsAny(s, "eE")

	hasDot := strings.Contains(s, ".")
	if !hasDot && !hasE {
		// Integer literal → *big.Int (arbitrary precision)
		v, ok := new(big.Int).SetString(s, 10)
		if !ok {
			return LiteralExpr{}, fmt.Errorf("%w: invalid integer %q", ErrUnexpectedToken, s)
		}

		return LiteralExpr{Value: v}, nil
	}

	if !hasE {
		// Decimal literal → *big.Rat (exact rational)
		v, ok := new(big.Rat).SetString(s)
		if !ok {
			return LiteralExpr{}, fmt.Errorf("%w: invalid decimal %q", ErrUnexpectedToken, s)
		}

		return LiteralExpr{Value: v}, nil
	}
	// Double literal → float64
	v, err := parseXPathDouble(s)
	if err != nil {
		return LiteralExpr{}, fmt.Errorf("%w: invalid number %q: %w", ErrUnexpectedToken, s, err)
	}

	return LiteralExpr{Value: v}, nil
}

// tokenAsNCName returns the NCName string for a token that can be used as an
// NCName in lookup keys and other non-keyword contexts. Returns "" if the
// token is not a valid NCName.
func tokenAsNCName(tok Token) string {
	switch tok.Type {
	case TokenName:
		// Reject URIQualifiedNames (Q{uri}local) — they are not NCNames
		if strings.HasPrefix(tok.Value, "Q{") {
			return ""
		}
		// Reject prefixed names (prefix:local) — they are QNames, not NCNames
		if strings.Contains(tok.Value, ":") {
			return ""
		}

		return tok.Value
	case TokenDiv, TokenMod, TokenAnd, TokenOr, TokenReturn, TokenElse, TokenEq, TokenNe, TokenLt, TokenLe, TokenGt, TokenGe, TokenIdiv, TokenIf, TokenThen, TokenFor, TokenLet, TokenIn, TokenSome, TokenEvery, TokenSatisfies, TokenIs, TokenTo, TokenUnion, TokenIntersect, TokenExcept, TokenInstanceOf, TokenTreatAs, TokenCastableAs, TokenCastAs, TokenAs, TokenOf:
		return tok.Type.String()
	}

	return ""
}

// XPath 2.0 erratum XP.E19 and 3.x kind tests compare normalized PI targets.
// An explicitly empty or otherwise invalid NCName is XPTY0004, not a syntax
// error; an absent target continues to match every processing instruction.
func normalizePITest(test xdm.PITest) (xdm.PITest, error) {
	if !test.HasTarget {
		return test, nil
	}

	test.Target = collapseXMLWhitespace(test.Target)
	if !xmlchar.IsValidNCName(test.Target) {
		return test, &xdm.Error{Code: lexicon.ErrXPTY0004, Message: "processing-instruction target must be an NCName"}
	}

	return test, nil
}

// --- XPath 3.1 Expression Extensions ---

// parseFLWOR parses for/let expressions (XPath 3.1 simple for/let only).
// XPath 3.1 does not support full FLWOR — only a single for or let clause
// (with comma-separated bindings) followed by "return".
func (p *parseOptions) parseFLWOR() (Expr, error) {
	var clauses []FLWORClause

	tok := p.lexer.Peek()
	switch tok.Type {
	case TokenFor:
		p.lexer.Next()

		fc, err := p.parseForBindings()
		if err != nil {
			return nil, err
		}

		clauses = append(clauses, fc...)
	case TokenLet:
		p.lexer.Next()

		lc, err := p.parseLetBindings()
		if err != nil {
			return nil, err
		}

		clauses = append(clauses, lc...)
	}

	if p.peekOperator().Type != TokenReturn {
		return nil, fmt.Errorf("%w: 'return' but got %s", ErrExpectedToken, p.lexer.Peek())
	}

	p.lexer.Next()

	ret, err := p.parseExprSingle()
	if err != nil {
		return nil, err
	}

	return FLWORExpr{Clauses: clauses, Return: ret}, nil
}

// parseForBindings parses "for $var in expr (, $var in expr)*".
func (p *parseOptions) parseForBindings() ([]FLWORClause, error) {
	var clauses []FLWORClause

	for {
		if p.lexer.Peek().Type != TokenVariableRef {
			return nil, fmt.Errorf("%w: variable after 'for' but got %s", ErrExpectedToken, p.lexer.Peek())
		}

		varName := p.lexer.Next().Value
		// Optional positional variable: "at $pos"
		var posVar string

		if tok := p.lexer.Peek(); tok.Type == TokenName && tok.Value == "at" {
			p.lexer.Next()

			if p.lexer.Peek().Type != TokenVariableRef {
				return nil, fmt.Errorf("%w: variable after 'at' but got %s", ErrExpectedToken, p.lexer.Peek())
			}

			posVar = p.lexer.Next().Value
		}

		if p.peekOperator().Type != TokenIn {
			return nil, fmt.Errorf("%w: 'in' after variable but got %s", ErrExpectedToken, p.lexer.Peek())
		}

		p.lexer.Next()

		expr, err := p.parseExprSingle()
		if err != nil {
			return nil, err
		}

		clauses = append(clauses, ForClause{Var: varName, PosVar: posVar, Expr: expr})

		if p.lexer.Peek().Type != TokenComma {
			break
		}

		p.lexer.Next()
	}

	return clauses, nil
}

// parseLetBindings parses "let $var := expr (, $var := expr)*".
func (p *parseOptions) parseLetBindings() ([]FLWORClause, error) {
	var clauses []FLWORClause

	for {
		if p.lexer.Peek().Type != TokenVariableRef {
			return nil, fmt.Errorf("%w: variable after 'let' but got %s", ErrExpectedToken, p.lexer.Peek())
		}

		varName := p.lexer.Next().Value
		// Expect ':=' — colon then equals
		if p.lexer.Peek().Type != TokenColon {
			return nil, fmt.Errorf("%w: ':=' after variable but got %s", ErrExpectedToken, p.lexer.Peek())
		}

		p.lexer.Next()

		if p.lexer.Peek().Type != TokenEquals {
			return nil, fmt.Errorf("%w: '=' after ':' in let binding but got %s", ErrExpectedToken, p.lexer.Peek())
		}

		p.lexer.Next()

		expr, err := p.parseExprSingle()
		if err != nil {
			return nil, err
		}

		clauses = append(clauses, LetClause{Var: varName, Expr: expr})

		if p.lexer.Peek().Type != TokenComma {
			break
		}

		p.lexer.Next()
	}

	return clauses, nil
}

// parseQuantifiedExpr parses "some/every $var in domain satisfies test".
func (p *parseOptions) parseQuantifiedExpr(some bool) (Expr, error) {
	p.lexer.Next() // consume 'some' or 'every'

	var bindings []QuantifiedBinding

	for {
		if p.lexer.Peek().Type != TokenVariableRef {
			return nil, fmt.Errorf("%w: variable after 'some'/'every' but got %s", ErrExpectedToken, p.lexer.Peek())
		}

		varName := p.lexer.Next().Value
		if p.peekOperator().Type != TokenIn {
			return nil, fmt.Errorf("%w: 'in' after variable but got %s", ErrExpectedToken, p.lexer.Peek())
		}

		p.lexer.Next()

		domain, err := p.parseExprSingle()
		if err != nil {
			return nil, err
		}

		bindings = append(bindings, QuantifiedBinding{Var: varName, Domain: domain})

		if p.lexer.Peek().Type != TokenComma {
			break
		}

		p.lexer.Next()
	}

	if p.peekOperator().Type != TokenSatisfies {
		return nil, fmt.Errorf("%w: 'satisfies' but got %s", ErrExpectedToken, p.lexer.Peek())
	}

	p.lexer.Next()

	satisfies, err := p.parseExprSingle()
	if err != nil {
		return nil, err
	}

	return QuantifiedExpr{Some: some, Bindings: bindings, Satisfies: satisfies}, nil
}

// parseIfExpr parses "if (cond) then thenExpr else elseExpr".
func (p *parseOptions) parseIfExpr() (Expr, error) {
	p.lexer.Next() // consume 'if'

	if p.lexer.Peek().Type != TokenLParen {
		return nil, fmt.Errorf("%w: '(' after 'if' but got %s", ErrExpectedToken, p.lexer.Peek())
	}

	p.lexer.Next()

	cond, err := p.parseExpression()
	if err != nil {
		return nil, err
	}

	if p.lexer.Peek().Type != TokenRParen {
		return nil, fmt.Errorf("%w: ')' after if condition but got %s", ErrExpectedToken, p.lexer.Peek())
	}

	p.lexer.Next()

	if p.peekOperator().Type != TokenThen {
		return nil, fmt.Errorf("%w: 'then' but got %s", ErrExpectedToken, p.lexer.Peek())
	}

	p.lexer.Next()

	thenExpr, err := p.parseExprSingle()
	if err != nil {
		return nil, err
	}

	if p.peekOperator().Type != TokenElse {
		return nil, fmt.Errorf("%w: 'else' but got %s", ErrExpectedToken, p.lexer.Peek())
	}

	p.lexer.Next()

	elseExpr, err := p.parseExprSingle()
	if err != nil {
		return nil, err
	}

	return IfExpr{Cond: cond, Then: thenExpr, Else: elseExpr}, nil
}

// parseTryCatchExpr parses "try { expr } catch code { expr }".
func (p *parseOptions) parseTryCatchExpr() (Expr, error) {
	p.lexer.Next() // consume 'try'

	if p.lexer.Peek().Type != TokenLBrace {
		return nil, fmt.Errorf("%w: '{' after 'try' but got %s", ErrExpectedToken, p.lexer.Peek())
	}

	p.lexer.Next()

	tryExpr, err := p.parseExpression()
	if err != nil {
		return nil, err
	}

	if p.lexer.Peek().Type != TokenRBrace {
		return nil, fmt.Errorf("%w: '}' after try body but got %s", ErrExpectedToken, p.lexer.Peek())
	}

	p.lexer.Next()

	var catches []CatchClause

	for p.lexer.Peek().Type == TokenCatch {
		p.lexer.Next()
		// Parse error codes (NameTest ("|" NameTest)*)
		// NameTest ::= EQName | Wildcard
		// ::= "*" | NCName ":*" | "*:" NCName | "BracedURILiteral" "*"
		var codes []string

		for {
			code, err := p.parseCatchCode()
			if err != nil {
				return nil, err
			}

			codes = append(codes, code)

			if p.lexer.Peek().Type != TokenPipe {
				break
			}

			p.lexer.Next()
		}

		if p.lexer.Peek().Type != TokenLBrace {
			return nil, fmt.Errorf("%w: '{' after catch but got %s", ErrExpectedToken, p.lexer.Peek())
		}

		p.lexer.Next()

		catchExpr, err := p.parseExpression()
		if err != nil {
			return nil, err
		}

		if p.lexer.Peek().Type != TokenRBrace {
			return nil, fmt.Errorf("%w: '}' after catch body but got %s", ErrExpectedToken, p.lexer.Peek())
		}

		p.lexer.Next()

		catches = append(catches, CatchClause{Codes: codes, Expr: catchExpr})
	}

	if len(catches) == 0 {
		return nil, fmt.Errorf("%w: at least one 'catch' clause", ErrExpectedToken)
	}

	return TryCatchExpr{Try: tryExpr, Catches: catches}, nil
}

// parseCatchCode parses a single catch error code.
// Supports: "*", "prefix:local", "prefix:*", "*:local", "Q{uri}local", "Q{uri}*"
func (p *parseOptions) parseCatchCode() (string, error) {
	tok := p.lexer.Peek()

	// * or *:local
	if tok.Type == TokenStar {
		p.lexer.Next()

		if p.lexer.Peek().Type == TokenColon {
			p.lexer.Next()

			localTok := p.lexer.Peek()
			if localTok.Type == TokenName {
				p.lexer.Next()
				return "*:" + localTok.Value, nil
			}

			p.lexer.Backup() // put ':' back
		}

		return "*", nil
	}

	// Q{uri}local or Q{uri}* (already scanned as single TokenName by lexer)
	if tok.Type == TokenName && len(tok.Value) > 2 && tok.Value[0] == 'Q' && tok.Value[1] == '{' {
		p.lexer.Next()

		if p.lexer.Peek().Type == TokenStar {
			p.lexer.Next()
			return tok.Value + "*", nil
		}

		return tok.Value, nil
	}

	// NCName or NCName:NCName or NCName:*
	if tok.Type == TokenName {
		p.lexer.Next()

		name := tok.Value

		if colonTok := p.lexer.Peek(); colonTok.Type == TokenColon && !colonTok.SpaceBefore {
			p.lexer.Next()

			next := p.lexer.Peek()
			if next.Type == TokenStar {
				p.lexer.Next()
				return name + ":*", nil
			}

			if next.Type == TokenName {
				p.lexer.Next()
				return name + ":" + next.Value, nil
			}

			p.lexer.Backup() // put ':' back
		}

		return name, nil
	}

	// "catch" keyword may appear as a name in some contexts
	if tok.Type == TokenCatch {
		p.lexer.Next()
		return tok.Value, nil
	}

	return "", fmt.Errorf("%w: error code in catch clause but got %s", ErrExpectedToken, tok)
}

// --- Constructor Parsing ---

// parseFunctionKeyword handles nameFunction which could be:
// - inline function: function($x) { ... }
// - function test: function(*) in sequence types
func (p *parseOptions) parseFunctionKeyword() (Expr, error) {
	p.lexer.Next() // consume 'function'

	if p.lexer.Peek().Type != TokenLParen {
		return nil, fmt.Errorf("%w: '(' after 'function' but got %s", ErrExpectedToken, p.lexer.Peek())
	}

	p.lexer.Next() // consume '('

	if p.lexer.Peek().Type == TokenStar {
		p.lexer.Next()

		if err := p.expectToken(TokenRParen); err != nil {
			return nil, fmt.Errorf("%w: ')' after function(*", ErrExpectedToken)
		}
		// This is a FunctionTest, not an expression — should only appear in sequence types.
		// Return a dummy expression; the parseOptions will handle this in sequence type context.
		return nil, fmt.Errorf("%w: function(*) outside sequence type", ErrUnexpectedToken)
	}

	params, err := p.parseInlineFunctionParams()
	if err != nil {
		return nil, err
	}

	var returnType *xdm.SequenceType

	if p.peekOperator().Type == TokenAs {
		p.lexer.Next()

		st, err := p.parseSequenceType()
		if err != nil {
			return nil, err
		}

		returnType = &st
	}

	emptyBody := p.lexer.Peek().Type == TokenLBrace && p.lexer.PeekAt(1).Type == TokenRBrace

	body, err := p.parseInlineFunctionBody()
	if err != nil {
		return nil, err
	}

	return InlineFunctionExpr{Params: params, ReturnType: returnType, Body: body, EmptyBody: emptyBody}, nil
}

func (p *parseOptions) parseInlineFunctionParams() ([]FunctionParam, error) {
	// Inline function: function($param as type, ...) as returnType { body }
	var params []FunctionParam

	if p.lexer.Peek().Type != TokenRParen {
		for {
			if p.lexer.Peek().Type != TokenVariableRef {
				return nil, fmt.Errorf("%w: parameter variable but got %s", ErrExpectedToken, p.lexer.Peek())
			}

			paramName := p.lexer.Next().Value
			param := FunctionParam{Name: paramName}

			if p.peekOperator().Type == TokenAs {
				p.lexer.Next()

				st, err := p.parseSequenceType()
				if err != nil {
					return nil, err
				}

				param.TypeHint = &st
			}

			params = append(params, param)

			if p.lexer.Peek().Type != TokenComma {
				break
			}

			p.lexer.Next()
		}
	}

	if err := p.expectToken(TokenRParen); err != nil {
		return nil, fmt.Errorf("%w: ')' in inline function parameters", ErrExpectedToken)
	}

	// Check for duplicate parameter names (XQST0039)
	seen := make(map[string]struct{}, len(params))
	for _, param := range params {
		if _, ok := seen[param.Name]; ok {
			return nil, &xdm.Error{Code: "XQST0039", Message: fmt.Sprintf("duplicate parameter name $%s in inline function", param.Name)}
		}

		seen[param.Name] = struct{}{}
	}

	return params, nil
}

func (p *parseOptions) parseInlineFunctionBody() (Expr, error) {
	if p.lexer.Peek().Type != TokenLBrace {
		return nil, fmt.Errorf("%w: '{' for function body but got %s", ErrExpectedToken, p.lexer.Peek())
	}

	p.lexer.Next()

	var body Expr
	if p.lexer.Peek().Type == TokenRBrace {
		// Empty function body: function(){} returns empty sequence
		body = SequenceExpr{Items: nil}
	} else {
		var err error

		body, err = p.parseExpression()
		if err != nil {
			return nil, err
		}
	}

	if p.lexer.Peek().Type != TokenRBrace {
		return nil, fmt.Errorf("%w: '}' after function body but got %s", ErrExpectedToken, p.lexer.Peek())
	}

	p.lexer.Next()

	return body, nil
}

// parseMapConstructor parses "map { key: value, ... }".
func (p *parseOptions) parseMapConstructor() (Expr, error) {
	p.lexer.Next() // consume 'map'

	if p.lexer.Peek().Type != TokenLBrace {
		return nil, fmt.Errorf("%w: '{' after 'map' but got %s", ErrExpectedToken, p.lexer.Peek())
	}

	p.lexer.Next()

	var pairs []MapConstructorPair

	if p.lexer.Peek().Type != TokenRBrace {
		for {
			key, err := p.parseExprSingle()
			if err != nil {
				return nil, err
			}

			if p.lexer.Peek().Type != TokenColon {
				return nil, fmt.Errorf("%w: ':' in map entry but got %s", ErrExpectedToken, p.lexer.Peek())
			}

			p.lexer.Next()

			value, err := p.parseExprSingle()
			if err != nil {
				return nil, err
			}

			pairs = append(pairs, MapConstructorPair{Key: key, Value: value})

			if p.lexer.Peek().Type != TokenComma {
				break
			}

			p.lexer.Next()
		}
	}

	if p.lexer.Peek().Type != TokenRBrace {
		return nil, fmt.Errorf("%w: '}' after map constructor but got %s", ErrExpectedToken, p.lexer.Peek())
	}

	p.lexer.Next()

	return MapConstructorExpr{Pairs: pairs}, nil
}

// parseArrayCurlyConstructor parses "array { expr }".
func (p *parseOptions) parseArrayCurlyConstructor() (Expr, error) {
	p.lexer.Next() // consume 'array'

	if p.lexer.Peek().Type != TokenLBrace {
		return nil, fmt.Errorf("%w: '{' after 'array' but got %s", ErrExpectedToken, p.lexer.Peek())
	}

	p.lexer.Next()

	var items []Expr

	if p.lexer.Peek().Type != TokenRBrace {
		// array { expr } — the expr is a single sequence expression
		expr, err := p.parseExpression()
		if err != nil {
			return nil, err
		}

		items = []Expr{expr}
	}

	if p.lexer.Peek().Type != TokenRBrace {
		return nil, fmt.Errorf("%w: '}' after array constructor but got %s", ErrExpectedToken, p.lexer.Peek())
	}

	p.lexer.Next()

	return ArrayConstructorExpr{Items: items, SquareBracket: false}, nil
}

// parseArraySquareConstructor parses "[item1, item2, ...]".
func (p *parseOptions) parseArraySquareConstructor() (Expr, error) {
	p.lexer.Next() // consume '['

	var items []Expr

	if p.lexer.Peek().Type != TokenRBracket {
		for {
			item, err := p.parseExprSingle()
			if err != nil {
				return nil, err
			}

			items = append(items, item)

			if p.lexer.Peek().Type != TokenComma {
				break
			}

			p.lexer.Next()
		}
	}

	if p.lexer.Peek().Type != TokenRBracket {
		return nil, fmt.Errorf("%w: ']' after array constructor but got %s", ErrExpectedToken, p.lexer.Peek())
	}

	p.lexer.Next()

	return ArrayConstructorExpr{Items: items, SquareBracket: true}, nil
}

// --- Sequence Type Parsing ---

// parseSequenceType parses a sequence type (used in instance-of, treat-as, etc.).
func (p *parseOptions) parseSequenceType() (xdm.SequenceType, error) {
	tok := p.lexer.Peek()

	// empty-sequence()
	if tok.Type == TokenName && tok.Value == nameEmptySequence {
		p.lexer.Next()

		if err := p.expectToken(TokenLParen); err != nil {
			return xdm.SequenceType{}, err
		}

		if err := p.expectToken(TokenRParen); err != nil {
			return xdm.SequenceType{}, err
		}

		return xdm.SequenceType{Void: true}, nil
	}

	itemTest, err := p.parseItemType()
	if err != nil {
		return xdm.SequenceType{}, err
	}

	occ := xdm.OccurrenceExactlyOne

	switch p.lexer.Peek().Type {
	case TokenQMark:
		p.lexer.Next()

		occ = xdm.OccurrenceZeroOrOne
	case TokenStar:
		p.lexer.Next()

		occ = xdm.OccurrenceZeroOrMore
	case TokenPlus:
		p.lexer.Next()

		occ = xdm.OccurrenceOneOrMore
	}

	return xdm.SequenceType{ItemTest: itemTest, Occurrence: occ}, nil
}

// parseItemType parses an item type within a sequence type.
func (p *parseOptions) parseItemType() (xdm.NodeTest, error) {
	p.depth++
	if p.depth > maxParseDepth {
		return nil, ErrExprTooDeep
	}
	defer func() { p.depth-- }()

	tok := p.lexer.Peek()

	switch tok.Type {
	case TokenLParen:
		return p.parseParenthesizedItemType()
	case TokenName:
		return p.parseNamedItemType(tok)
	case TokenFunction:
		return p.parseFunctionItemType()
	case TokenMap:
		return p.parseMapItemType()
	case TokenArray:
		return p.parseArrayItemType()
	}

	return nil, fmt.Errorf("%w: item type but got %s", ErrExpectedToken, tok)
}

func (p *parseOptions) parseParenthesizedItemType() (xdm.NodeTest, error) {
	p.lexer.Next()

	itemType, err := p.parseItemType()
	if err != nil {
		return nil, err
	}

	if err := p.expectToken(TokenRParen); err != nil {
		return nil, fmt.Errorf("%w: ')' after parenthesized item type", ErrExpectedToken)
	}

	return itemType, nil
}

func (p *parseOptions) parseNamedItemType(tok Token) (xdm.NodeTest, error) {
	// Could be: item(), node(), element(), attribute(), xs:integer, etc.
	if p.lexer.PeekAt(1).Type == TokenLParen {
		p.lexer.Next() // consume name

		nt, ok, err := p.parseKindTest(tok.Value)
		if err != nil {
			return nil, err
		}

		if ok {
			return nt, nil
		}
		// Not a kind test — treat as function test or atomic type
		p.lexer.Backup()
	}
	// Atomic or union type name (possibly prefixed)
	return p.parseAtomicOrUnionType()
}

func (p *parseOptions) parseFunctionItemType() (xdm.NodeTest, error) {
	p.lexer.Next()

	if p.lexer.Peek().Type != TokenLParen {
		return nil, fmt.Errorf("%w: '(' after 'function' but got %s", ErrExpectedToken, p.lexer.Peek())
	}

	p.lexer.Next()
	// function(*) - any function test
	if p.lexer.Peek().Type == TokenStar {
		p.lexer.Next()

		if err := p.expectToken(TokenRParen); err != nil {
			return nil, fmt.Errorf("%w: ')' after function(*", ErrExpectedToken)
		}

		return xdm.FunctionTest{AnyFunction: true}, nil
	}
	// function() as ReturnType or function(ParamTypes) as ReturnType
	var paramTypes []xdm.SequenceType

	if p.lexer.Peek().Type != TokenRParen {
		for {
			st, err := p.parseSequenceType()
			if err != nil {
				return nil, err
			}

			paramTypes = append(paramTypes, st)

			if p.lexer.Peek().Type != TokenComma {
				break
			}

			p.lexer.Next()
		}
	}

	if err := p.expectToken(TokenRParen); err != nil {
		return nil, fmt.Errorf("%w: ')' in function type test", ErrExpectedToken)
	}

	var returnType xdm.SequenceType

	if p.peekOperator().Type == TokenAs {
		p.lexer.Next()

		rt, err := p.parseSequenceType()
		if err != nil {
			return nil, err
		}

		returnType = rt
	} else if len(paramTypes) > 0 {
		// Per XPath 3.1 §3.1.5.4: when parameter types are present,
		// "as SequenceType" is required.
		return nil, &xdm.Error{
			Code:    lexicon.ErrXPST0003,
			Message: "function type with parameter types requires 'as ReturnType'",
		}
	}

	return xdm.FunctionTest{ParamTypes: paramTypes, ReturnType: returnType}, nil
}

func (p *parseOptions) parseMapItemType() (xdm.NodeTest, error) {
	p.lexer.Next()

	if p.lexer.Peek().Type != TokenLParen {
		return nil, fmt.Errorf("%w: '(' after 'map' but got %s", ErrExpectedToken, p.lexer.Peek())
	}

	p.lexer.Next()
	// map(*) or map(KeyType, ValueType)
	if p.lexer.Peek().Type == TokenStar {
		p.lexer.Next() // consume *

		if err := p.expectToken(TokenRParen); err != nil {
			return nil, fmt.Errorf("%w: ')' after map(*", ErrExpectedToken)
		}

		return xdm.MapTest{AnyType: true}, nil
	}

	keyType, err := p.parseAtomicOrUnionType()
	if err != nil {
		return nil, err
	}

	if p.lexer.Peek().Type != TokenComma {
		return nil, fmt.Errorf("%w: ',' in map(K, V) type test", ErrExpectedToken)
	}

	p.lexer.Next() // consume comma

	valType, err := p.parseSequenceType()
	if err != nil {
		return nil, err
	}

	if err := p.expectToken(TokenRParen); err != nil {
		return nil, fmt.Errorf("%w: ')' after map type test", ErrExpectedToken)
	}

	return xdm.MapTest{KeyType: keyType, ValType: valType}, nil
}

func (p *parseOptions) parseArrayItemType() (xdm.NodeTest, error) {
	p.lexer.Next()

	if p.lexer.Peek().Type != TokenLParen {
		return nil, fmt.Errorf("%w: '(' after 'array' but got %s", ErrExpectedToken, p.lexer.Peek())
	}

	p.lexer.Next()
	// array(*) or array(MemberType)
	if p.lexer.Peek().Type == TokenStar {
		p.lexer.Next() // consume *

		if err := p.expectToken(TokenRParen); err != nil {
			return nil, fmt.Errorf("%w: ')' after array(*", ErrExpectedToken)
		}

		return xdm.ArrayTest{AnyType: true}, nil
	}

	memberType, err := p.parseSequenceType()
	if err != nil {
		return nil, err
	}

	if err := p.expectToken(TokenRParen); err != nil {
		return nil, fmt.Errorf("%w: ')' after array type test", ErrExpectedToken)
	}

	return xdm.ArrayTest{MemberType: memberType}, nil
}

func (p *parseOptions) parseAtomicOrUnionType() (xdm.NodeTest, error) {
	name := p.scanQName()
	if name == "" {
		return nil, fmt.Errorf("%w: type name", ErrExpectedToken)
	}
	// Split prefix:local
	prefix, local := splitQName(name)

	return xdm.AtomicOrUnionType{Prefix: prefix, Name: local}, nil
}

// parseSingleType parses an atomic type name with optional '?' (for cast/castable).
func (p *parseOptions) parseSingleType() (AtomicTypeName, bool, error) {
	name := p.scanQName()
	if name == "" {
		return AtomicTypeName{}, false, fmt.Errorf("%w: type name in cast", ErrExpectedToken)
	}

	prefix, local := splitQName(name)
	allowEmpty := false

	if p.lexer.Peek().Type == TokenQMark {
		p.lexer.Next()

		allowEmpty = true
	}

	return AtomicTypeName{Prefix: prefix, Name: local}, allowEmpty, nil
}

// --- Helpers ---

// scanQName scans a possibly-prefixed QName (prefix:local) from the token stream.
func (p *parseOptions) scanQName() string {
	tok := p.lexer.Peek()
	if tok.Type != TokenName {
		return ""
	}

	p.lexer.Next()

	name := tok.Value

	if p.joinedQNameAt(0) {
		p.lexer.Next()
		localTok := p.lexer.Peek()
		// Accept both plain names and keywords (map, array, etc.)
		// as the local part of a prefixed QName.
		if localTok.Type == TokenName || isKeywordToken(localTok.Type) {
			p.lexer.Next()
			return name + ":" + localTok.Value
		}

		p.lexer.Backup() // put ':' back
	}

	return name
}

func (p *parseOptions) expectToken(expected TokenType) error {
	if p.lexer.Peek().Type != expected {
		return fmt.Errorf("%w: %s but got %s", ErrExpectedToken, expected, p.lexer.Peek())
	}

	p.lexer.Next()

	return nil
}

func (p *parseOptions) looksLikeStep() bool {
	return p.looksLikeStepOffset(0)
}

func (p *parseOptions) looksLikeStepOffset(offset int) bool {
	tok := p.lexer.PeekAt(offset)
	if tok.Type == TokenDotDot || tok.Type == TokenAt || tok.Type == TokenStar {
		return true
	}

	if !isNameLikeToken(tok.Type) {
		return false
	}

	next := p.lexer.PeekAt(offset + 1)

	if next.Type == TokenColonColon {
		return true // axis::
	}

	if next.Type == TokenLParen {
		// node(), text(), comment(), processing-instruction(),
		// element(), attribute(), document-node(), schema-element(),
		// schema-attribute(), namespace-node() are steps
		switch tok.Value {
		case "node", "text", "comment", nameProcessingInstruction,
			lexicon.KindElement, "attribute", "document-node", lexicon.KindSchemaElement,
			"schema-attribute":
			return true
		case "namespace-node":
			return p.version == 0 || p.version >= 30
		}

		return false // function call
	}

	if next.Type == TokenColon {
		// Per XPath 3.1 A.2.1: a QName is Name:Name with NO whitespace
		// around the colon. If whitespace precedes ':', this is a plain
		// name test (the ':' is a map-entry separator, not a QName colon).
		if !p.joinedQNameAt(offset + 1) {
			return true // plain name test; ':' is map entry separator
		}
		// prefix:local (name test) vs prefix:name( (QName function call)
		// vs prefix:name# (named function ref)
		localTok := p.lexer.PeekAt(offset + 2)
		if isNameLikeToken(localTok.Type) {
			afterLocal := p.lexer.PeekAt(offset + 3)
			if afterLocal.Type == TokenLParen {
				return false // QName function call
			}

			if afterLocal.Type == TokenHash {
				return false // named function ref
			}

			return true // QName step
		}

		return true
	}

	if next.Type == TokenHash {
		return false // named function ref: name#arity
	}
	// map{} and array{} are constructors, not name tests
	if next.Type == TokenLBrace && (tok.Type == TokenMap || tok.Type == TokenArray) {
		return false
	}

	return true // plain name test
}

// joinedQNameAt recognizes a colon joined to both adjacent QName components.
// A separated colon can still be a map-entry delimiter; the caller decides
// whether that delimiter is valid in its grammar context.
func (p *parseOptions) joinedQNameAt(offset int) bool {
	colon := p.lexer.PeekAt(offset)
	return colon.Type == TokenColon && !colon.SpaceBefore && !p.lexer.PeekAt(offset+1).SpaceBefore
}

// isKeywordToken returns true if the token type is an XPath keyword
// that can still be used as a local name in a QName (e.g., prefix:map).
func isKeywordToken(t TokenType) bool {
	switch t {
	case TokenMap, TokenArray, TokenFunction,
		TokenAs, TokenOf, TokenIn,
		TokenReturn, TokenFor, TokenLet,
		TokenSome, TokenEvery, TokenIf, TokenThen, TokenElse,
		TokenInstanceOf, TokenCastAs, TokenCastableAs, TokenTreatAs,
		TokenAnd, TokenOr, TokenDiv, TokenMod, TokenIdiv,
		TokenTo, TokenUnion, TokenIntersect, TokenExcept,
		TokenEq, TokenNe, TokenLt, TokenLe, TokenGt, TokenGe,
		TokenIs, TokenSatisfies, TokenWhere, TokenBy,
		TokenAscending, TokenDescending, TokenStable,
		TokenTry, TokenCatch:
		return true
	}

	return false
}

// isNameLikeToken recognizes names wherever the grammar requires an operand
// or QName component. An operator keyword is not reserved in these positions,
// even when the lexer saw an ambiguous preceding '*' token.
func isNameLikeToken(t TokenType) bool {
	return t == TokenName || isKeywordToken(t)
}

func splitQName(qname string) (string, string) {
	for i, c := range qname {
		if c == ':' {
			return qname[:i], qname[i+1:]
		}
	}

	return "", qname
}

func variableExprFromToken(name string) VariableExpr {
	if strings.HasPrefix(name, "Q{") {
		return VariableExpr{Name: name}
	}

	prefix := ""
	if p2, _, ok := strings.Cut(name, ":"); ok {
		prefix = p2
	}

	return VariableExpr{Prefix: prefix, Name: name}
}
