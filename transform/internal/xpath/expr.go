// Derived from lestrrat-go/helium at 7362c0a70122a757780f4d0b545a9b370dead6ab.
// Copyright (c) 2015 lestrrat. MIT License; see licenses/MIT-helium.txt at the repository root.

package xpath

import (
	"github.com/skarm/xmlsec/transform/internal/xdm"
)

const (
	AxisChild            = xdm.AxisChild
	AxisDescendant       = xdm.AxisDescendant
	AxisParent           = xdm.AxisParent
	AxisAncestor         = xdm.AxisAncestor
	AxisFollowingSibling = xdm.AxisFollowingSibling
	AxisPrecedingSibling = xdm.AxisPrecedingSibling
	AxisFollowing        = xdm.AxisFollowing
	AxisPreceding        = xdm.AxisPreceding
	AxisAttribute        = xdm.AxisAttribute
	AxisNamespace        = xdm.AxisNamespace
	AxisSelf             = xdm.AxisSelf
	AxisDescendantOrSelf = xdm.AxisDescendantOrSelf
	AxisAncestorOrSelf   = xdm.AxisAncestorOrSelf
)

// Expr is the interface implemented by all XPath 3.1 AST nodes.
type Expr interface {
	exprNode()
}

// AxisType identifies one of the 13 axes shared by all XPath versions.
type AxisType = xdm.AxisType

// --- Node Tests ---

// --- Sequence Type ---

// --- Literals & Variables ---

// LiteralExpr represents a string or numeric literal.
type LiteralExpr struct {
	Value any // string, float64, *big.Int, or *big.Rat
}

func (LiteralExpr) exprNode() {}

// VariableExpr represents a variable reference ($prefix:name or $name).
type VariableExpr struct {
	Prefix string
	Name   string
}

func (VariableExpr) exprNode() {}

// RootExpr represents a bare / (document root).
type RootExpr struct{}

func (RootExpr) exprNode() {}

// ContextItemExpr represents a bare . (context item).
type ContextItemExpr struct{}

func (ContextItemExpr) exprNode() {}

// --- Location Paths ---

// LocationPath represents an absolute or relative location path.
type LocationPath struct {
	Absolute bool
	Steps    []Step
}

func (LocationPath) exprNode() {}

// Step is a single step in a location path: axis::node-test[predicates].
type Step struct {
	Axis       AxisType
	NodeTest   xdm.NodeTest
	Predicates []Expr
}

// --- Operators ---

// BinaryExpr represents binary operations (arithmetic, comparison, logic).
type BinaryExpr struct {
	Op    TokenType
	Left  Expr
	Right Expr
}

func (BinaryExpr) exprNode() {}

// UnaryExpr represents unary negation (-expr) or unary plus (+expr).
type UnaryExpr struct {
	Operand Expr
	Negate  bool
}

func (UnaryExpr) exprNode() {}

// ConcatExpr represents string concatenation (||).
type ConcatExpr struct {
	Left  Expr
	Right Expr
}

func (ConcatExpr) exprNode() {}

// SimpleMapExpr represents the simple map operator (!).
type SimpleMapExpr struct {
	Left  Expr
	Right Expr
}

func (SimpleMapExpr) exprNode() {}

// RangeExpr represents a range expression (start to end).
type RangeExpr struct {
	Start Expr
	End   Expr
}

func (RangeExpr) exprNode() {}

// UnionExpr represents the union of two node-sets (expr | expr or expr union expr).
type UnionExpr struct {
	Left  Expr
	Right Expr
}

func (UnionExpr) exprNode() {}

// IntersectExceptExpr represents intersect/except operations.
type IntersectExceptExpr struct {
	Op    TokenType // TokenIntersect or TokenExcept
	Left  Expr
	Right Expr
}

func (IntersectExceptExpr) exprNode() {}

// --- Filter & Path ---

// FilterExpr represents a primary expression followed by predicates.
type FilterExpr struct {
	Expr       Expr
	Predicates []Expr
}

func (FilterExpr) exprNode() {}

// PathExpr represents a filter expression followed by steps.
type PathExpr struct {
	Filter Expr
	Path   *LocationPath
}

func (PathExpr) exprNode() {}

// PathStepExpr represents E1/E2 or E1//E2 where E2 is a non-axis expression
// (function call, variable ref, etc.) used as a step in a path expression.
// Per XPath 3.1, StepExpr := PostfixExpr | AxisStep.
// Evaluation: for each node in E1, evaluate E2 with that node as context.
type PathStepExpr struct {
	Left       Expr
	Right      Expr
	DescOrSelf bool // true for //, inserts descendant-or-self::node() before Right
}

func (PathStepExpr) exprNode() {}

// --- Lookup ---

// LookupExpr represents postfix lookup: expr ? key.
type LookupExpr struct {
	Expr Expr
	Key  Expr // nil when All is true
	All  bool // ? * (all entries)
}

func (LookupExpr) exprNode() {}

// UnaryLookupExpr represents unary lookup: ? key (uses context item).
type UnaryLookupExpr struct {
	Key Expr // nil when All is true
	All bool // ? * (all entries)
}

func (UnaryLookupExpr) exprNode() {}

// --- FLWOR ---

// FLWORExpr represents a for/let/where/order-by/return expression.
type FLWORExpr struct {
	Clauses []FLWORClause
	Return  Expr
}

func (FLWORExpr) exprNode() {}

// FLWORClause is implemented by ForClause and LetClause.
type FLWORClause interface {
	flworClause()
}

// ForClause represents "for $var in expr" or "for $var at $pos in expr".
type ForClause struct {
	Var    string
	PosVar string // positional variable from "at $pos" (empty if none)
	Expr   Expr
}

func (ForClause) flworClause() {}

// LetClause represents "let $var := expr".
type LetClause struct {
	Var  string
	Expr Expr
}

func (LetClause) flworClause() {}

// --- Control Flow ---

// QuantifiedBinding is a single "$var in expr" binding in a quantified expression.
// It is used by QuantifiedExpr which represents "some/every $var in domain satisfies test".
type QuantifiedBinding struct {
	Var    string
	Domain Expr
}

type QuantifiedExpr struct {
	Some      bool // true = some, false = every
	Bindings  []QuantifiedBinding
	Satisfies Expr
}

func (QuantifiedExpr) exprNode() {}

// IfExpr represents "if (cond) then thenExpr else elseExpr".
type IfExpr struct {
	Cond Expr
	Then Expr
	Else Expr
}

func (IfExpr) exprNode() {}

// TryCatchExpr represents "try { expr } catch code { expr }".
type TryCatchExpr struct {
	Try     Expr
	Catches []CatchClause
}

func (TryCatchExpr) exprNode() {}

// CatchClause represents a single catch branch.
type CatchClause struct {
	Codes []string // error codes to match; empty = catch all (*)
	Expr  Expr
}

// --- Type Expressions ---

// InstanceOfExpr represents "expr instance of sequenceType".
type InstanceOfExpr struct {
	Expr Expr
	Type xdm.SequenceType
}

func (InstanceOfExpr) exprNode() {}

// CastExpr represents "expr cast as atomicType?".
type CastExpr struct {
	Expr       Expr
	Type       AtomicTypeName
	AllowEmpty bool
}

func (CastExpr) exprNode() {}

// CastableExpr represents "expr castable as atomicType?".
type CastableExpr struct {
	Expr       Expr
	Type       AtomicTypeName
	AllowEmpty bool
}

func (CastableExpr) exprNode() {}

// TreatAsExpr represents "expr treat as sequenceType".
type TreatAsExpr struct {
	Expr Expr
	Type xdm.SequenceType
}

func (TreatAsExpr) exprNode() {}

// AtomicTypeName identifies a target type for cast/castable.
type AtomicTypeName struct {
	Prefix string
	Name   string
}

// --- Functions ---

// FunctionCall represents a static function invocation: prefix:name(args...).
type FunctionCall struct {
	Prefix string
	Name   string
	Args   []Expr
}

func (FunctionCall) exprNode() {}

// DynamicFunctionCall represents a dynamic function call: $f(args...).
type DynamicFunctionCall struct {
	Func Expr
	Args []Expr
}

func (DynamicFunctionCall) exprNode() {}

// NamedFunctionRef represents a named function reference: fn:name#arity.
type NamedFunctionRef struct {
	Prefix string
	Name   string
	Arity  int
}

func (NamedFunctionRef) exprNode() {}

// InlineFunctionExpr represents an inline function definition.
type InlineFunctionExpr struct {
	Params     []FunctionParam
	ReturnType *xdm.SequenceType // nil if not specified
	Body       Expr
}

func (InlineFunctionExpr) exprNode() {}

// PlaceholderExpr represents ? in partial function application.
type PlaceholderExpr struct{}

func (PlaceholderExpr) exprNode() {}

// FunctionParam is a parameter in an inline function definition.
type FunctionParam struct {
	Name     string
	TypeHint *xdm.SequenceType // nil if not specified
}

// --- Constructors ---

// MapConstructorExpr represents map { key: value, ... }.
type MapConstructorExpr struct {
	Pairs []MapConstructorPair
}

func (MapConstructorExpr) exprNode() {}

// MapConstructorPair is one key:value entry in a map constructor.
type MapConstructorPair struct {
	Key   Expr
	Value Expr
}

// ArrayConstructorExpr represents [items] or array { items }.
type ArrayConstructorExpr struct {
	Items         []Expr
	SquareBracket bool // true = [a, b], false = array { expr }
}

func (ArrayConstructorExpr) exprNode() {}

// SequenceExpr represents a comma-separated sequence: (a, b, c).
type SequenceExpr struct {
	Items []Expr
}

func (SequenceExpr) exprNode() {}

// AsExpr performs a safe type assertion, returning the concrete Expr
// type T and true if the assertion succeeds, or the zero value of T
// and false otherwise.
func AsExpr[T Expr](v any) (T, bool) {
	if v == nil {
		var zero T
		return zero, false
	}

	if e, ok := v.(T); ok {
		return e, true
	}

	var zero T

	return zero, false
}
