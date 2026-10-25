// Derived from lestrrat-go/helium at 7362c0a70122a757780f4d0b545a9b370dead6ab.
// Copyright (c) 2015 lestrrat. MIT License; see licenses/MIT-helium.txt at the repository root.

package xpath

import (
	"fmt"

	"github.com/skarm/xmlsec/internal/lexicon"
)

// TokenType identifies the kind of lexical token.
type TokenType int

// Token constants. The first group (EOF through Div) is shared with XPath 1.0.
// The second group adds XPath 3.1 operators, keywords, and punctuation.
const (
	TokenEOF         TokenType = iota // end of input
	TokenNumber                       // 42, 3.14, 1e2
	TokenString                       // "hello", 'hello'
	TokenName                         // NCName (foo, bar)
	TokenStar                         // * (wildcard name test or multiply)
	TokenVariableRef                  // $name

	// TokenSlash and the following are operators inherited from XPath 1.0.
	TokenSlash      // /
	TokenSlashSlash // //
	TokenPipe       // |
	TokenPlus       // +
	TokenMinus      // -
	TokenEquals     // =
	TokenNotEquals  // !=
	TokenLess       // <
	TokenLessEq     // <=
	TokenGreater    // >
	TokenGreaterEq  // >=
	TokenAnd        // and
	TokenOr         // or
	TokenMod        // mod
	TokenDiv        // div

	// TokenLParen and the following are punctuation inherited from XPath 1.0.
	TokenLParen     // (
	TokenRParen     // )
	TokenLBracket   // [
	TokenRBracket   // ]
	TokenAt         // @
	TokenColonColon // ::
	TokenComma      // ,
	TokenDot        // .
	TokenDotDot     // ..
	TokenColon      // : (in QName prefix:local)

	// TokenConcat and the following are new operators in XPath 3.1.
	TokenConcat    // ||
	TokenBang      // ! (simple map)
	TokenArrow     // =>
	TokenHash      // # (named function ref)
	TokenQMark     // ? (lookup / partial application)
	TokenIdiv      // idiv (integer division)
	TokenIntersect // intersect
	TokenExcept    // except
	TokenTo        // to (range)
	TokenUnion     // union (keyword form of |)

	// TokenLBrace and the following are new punctuation in XPath 3.1.
	TokenLBrace // {
	TokenRBrace // }

	// TokenEq and the following are value comparison keywords.
	TokenEq // eq
	TokenNe // ne
	TokenLt // lt
	TokenLe // le
	TokenGt // gt
	TokenGe // ge

	// TokenFor and the following are FLWOR keywords.
	TokenFor        // for
	TokenLet        // let
	TokenIn         // in
	TokenReturn     // return
	TokenWhere      // where
	TokenOrderBy    // order (followed by "by")
	TokenBy         // by
	TokenAscending  // ascending
	TokenDescending // descending
	TokenStable     // stable

	// TokenSome and the following are quantified expression keywords.
	TokenSome      // some
	TokenEvery     // every
	TokenSatisfies // satisfies

	// TokenIf and the following are control flow keywords.
	TokenIf    // if
	TokenThen  // then
	TokenElse  // else
	TokenTry   // try
	TokenCatch // catch

	// TokenInstanceOf and the following are type expression keywords.
	TokenInstanceOf // instance (followed by "of")
	TokenOf         // of
	TokenCastAs     // cast (followed by "as")
	TokenCastableAs // castable (followed by "as")
	TokenTreatAs    // treat (followed by "as")
	TokenAs         // as

	// TokenFunction and the following are constructor / inline function keywords.
	TokenFunction // function
	TokenMap      // map
	TokenArray    // array

	// TokenIs and the following are node comparison operators.
	TokenIs      // is
	TokenNodePre // << (node precedes)
	TokenNodeFol // >> (node follows)
)

// String returns the token's lexical spelling or a numeric diagnostic label when
// unknown.
func (t TokenType) String() string {
	names := [...]string{
		TokenEOF:         "EOF",
		TokenNumber:      "Number",
		TokenString:      "String",
		TokenName:        lexicon.TypeName,
		TokenStar:        "*",
		TokenVariableRef: "VariableRef",
		TokenSlash:       "/",
		TokenSlashSlash:  "//",
		TokenPipe:        "|",
		TokenPlus:        "+",
		TokenMinus:       "-",
		TokenEquals:      "=",
		TokenNotEquals:   "!=",
		TokenLess:        "<",
		TokenLessEq:      "<=",
		TokenGreater:     ">",
		TokenGreaterEq:   ">=",
		TokenAnd:         nameAnd,
		TokenOr:          "or",
		TokenMod:         nameMod,
		TokenDiv:         nameDiv,
		TokenLParen:      "(",
		TokenRParen:      ")",
		TokenLBracket:    "[",
		TokenRBracket:    "]",
		TokenAt:          "@",
		TokenColonColon:  "::",
		TokenComma:       ",",
		TokenDot:         ".",
		TokenDotDot:      "..",
		TokenColon:       ":",
		TokenConcat:      "||",
		TokenBang:        "!",
		TokenArrow:       "=>",
		TokenHash:        "#",
		TokenQMark:       "?",
		TokenIdiv:        nameIdiv,
		TokenIntersect:   nameIntersect,
		TokenExcept:      nameExcept,
		TokenTo:          "to",
		TokenUnion:       nameUnion,
		TokenLBrace:      "{",
		TokenRBrace:      "}",
		TokenEq:          "eq",
		TokenNe:          "ne",
		TokenLt:          "lt",
		TokenLe:          "le",
		TokenGt:          "gt",
		TokenGe:          "ge",
		TokenFor:         nameFor,
		TokenLet:         nameLet,
		TokenIn:          "in",
		TokenReturn:      nameReturn,
		TokenWhere:       "where",
		TokenOrderBy:     "order",
		TokenBy:          "by",
		TokenAscending:   "ascending",
		TokenDescending:  "descending",
		TokenStable:      "stable",
		TokenSome:        nameSome,
		TokenEvery:       nameEvery,
		TokenSatisfies:   nameSatisfies,
		TokenIf:          "if",
		TokenThen:        nameThen,
		TokenElse:        nameElse,
		TokenTry:         "try",
		TokenCatch:       "catch",
		TokenInstanceOf:  nameInstance,
		TokenOf:          "of",
		TokenCastAs:      nameCast,
		TokenCastableAs:  nameCastable,
		TokenTreatAs:     nameTreat,
		TokenAs:          "as",
		TokenFunction:    nameFunction,
		TokenMap:         keywordMap,
		TokenArray:       keywordArray,
		TokenIs:          "is",
		TokenNodePre:     "<<",
		TokenNodeFol:     ">>",
	}
	if t >= 0 && int(t) < len(names) && names[t] != "" {
		return names[t]
	}

	return fmt.Sprintf("TokenType(%d)", int(t))
}

// Token is a single lexical token from an XPath 3.1 expression.
type Token struct {
	// Type identifies the lexical token category.
	Type TokenType
	// Value retains token-specific text, such as a name or literal value.
	Value       string
	SpaceBefore bool // true when whitespace preceded this token
}

// String formats the token category and any retained value for diagnostics.
func (t Token) String() string {
	if t.Value != "" {
		return fmt.Sprintf("%s(%q)", t.Type, t.Value)
	}

	return t.Type.String()
}
