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

// Expr represents a node in the shared XPath syntax tree. The selected language
// profile determines which node forms are permitted.
type Expr interface {
	// exprNode restricts syntax-tree nodes to implementations declared in this package.
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
	// Prefix is the lexical variable prefix, or empty for an unprefixed name.
	Prefix string
	// Name is the local variable name without the dollar sign.
	Name string
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
	// Absolute starts the path from the document root when true.
	Absolute bool
	// Steps contains axis steps in evaluation order.
	Steps []Step
}

func (LocationPath) exprNode() {}

// Step is a single step in a location path: axis::node-test[predicates].
type Step struct {
	// Axis selects the navigation axis for this step.
	Axis AxisType
	// NodeTest filters nodes reached through Axis.
	NodeTest xdm.NodeTest
	// Predicates applies filters in source order.
	Predicates []Expr
}

// --- Operators ---

// BinaryExpr represents binary operations (arithmetic, comparison, logic).
type BinaryExpr struct {
	// Op selects the arithmetic, comparison or logical operator.
	Op TokenType
	// Left is the operator's left operand.
	Left Expr
	// Right is the operator's right operand.
	Right Expr
}

func (BinaryExpr) exprNode() {}

// UnaryExpr represents unary negation (-expr) or unary plus (+expr).
type UnaryExpr struct {
	// Operand is the value to which unary plus or minus applies.
	Operand Expr
	// Negate selects unary minus when true and unary plus when false.
	Negate bool
}

func (UnaryExpr) exprNode() {}

// ConcatExpr represents string concatenation (||).
type ConcatExpr struct {
	// Left is the first string-converted operand.
	Left Expr
	// Right is the second string-converted operand.
	Right Expr
}

func (ConcatExpr) exprNode() {}

// SimpleMapExpr represents the simple map operator (!).
type SimpleMapExpr struct {
	// Left produces the input items for the simple map operation.
	Left Expr
	// Right is evaluated with each left item as the context item.
	Right Expr
}

func (SimpleMapExpr) exprNode() {}

// RangeExpr represents a range expression (start to end).
type RangeExpr struct {
	// Start supplies the inclusive first integer of the range.
	Start Expr
	// End supplies the inclusive last integer of the range.
	End Expr
}

func (RangeExpr) exprNode() {}

// UnionExpr represents the union of two node-sets (expr | expr or expr union expr).
type UnionExpr struct {
	// Left produces the first node sequence to combine.
	Left Expr
	// Right produces the second node sequence to combine.
	Right Expr
}

func (UnionExpr) exprNode() {}

// IntersectExceptExpr represents intersect/except operations.
type IntersectExceptExpr struct {
	Op TokenType // TokenIntersect or TokenExcept
	// Left supplies the node sequence being intersected or filtered.
	Left Expr
	// Right supplies the nodes used by the selected set operation.
	Right Expr
}

func (IntersectExceptExpr) exprNode() {}

// --- Filter & Path ---

// FilterExpr represents a primary expression followed by predicates.
type FilterExpr struct {
	// Expr produces the sequence to filter.
	Expr Expr
	// Predicates filters the sequence in source order.
	Predicates []Expr
}

func (FilterExpr) exprNode() {}

// PathExpr represents a filter expression followed by steps.
type PathExpr struct {
	// Filter produces the starting nodes for Path.
	Filter Expr
	// Path supplies the location steps evaluated from each starting node.
	Path *LocationPath
}

func (PathExpr) exprNode() {}

// PathStepExpr represents E1/E2 or E1//E2 where E2 is a non-axis expression
// (function call, variable ref, etc.) used as a step in a path expression.
// Per XPath 3.1, StepExpr := PostfixExpr | AxisStep.
// Evaluation: for each node in E1, evaluate E2 with that node as context.
type PathStepExpr struct {
	// Left produces the nodes used as focus for the right expression.
	Left Expr
	// Right is the non-axis step evaluated under each selected focus.
	Right      Expr
	DescOrSelf bool // true for //, inserts descendant-or-self::node() before Right
}

func (PathStepExpr) exprNode() {}

// --- Lookup ---

// LookupExpr represents postfix lookup: expr ? key.
type LookupExpr struct {
	// Expr supplies the map or array being queried.
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

// FLWORExpr represents for or let bindings followed by a return expression. The
// selected XPath profile checks the permitted clause combinations.
type FLWORExpr struct {
	// Clauses contains ordered for and let variable bindings.
	Clauses []FLWORClause
	// Return produces the result under the clause bindings.
	Return Expr
}

func (FLWORExpr) exprNode() {}

// FLWORClause is implemented by ForClause and LetClause.
type FLWORClause interface {
	// flworClause restricts binding clauses to implementations declared in this package.
	flworClause()
}

// ForClause represents "for $var in expr" or "for $var at $pos in expr".
type ForClause struct {
	// Var is the lexical range variable name without the dollar sign.
	Var    string
	PosVar string // positional variable from "at $pos" (empty if none)
	// Expr supplies the sequence whose items bind Var.
	Expr Expr
}

func (ForClause) flworClause() {}

// LetClause represents "let $var := expr".
type LetClause struct {
	// Var is the lexical variable name without the dollar sign.
	Var string
	// Expr supplies the complete sequence bound to Var.
	Expr Expr
}

func (LetClause) flworClause() {}

// --- Control Flow ---

// QuantifiedBinding is a single "$var in expr" binding in a quantified expression.
// It is used by QuantifiedExpr which represents "some/every $var in domain satisfies test".
type QuantifiedBinding struct {
	// Var is the lexical variable name without the dollar sign.
	Var string
	// Domain supplies the values over which the variable ranges.
	Domain Expr
}

// QuantifiedExpr represents some or every bindings followed by a satisfies
// expression.
type QuantifiedExpr struct {
	Some bool // true = some, false = every
	// Bindings contains ordered variable domains for the quantified expression.
	Bindings []QuantifiedBinding
	// Satisfies is tested for each combination of bound values.
	Satisfies Expr
}

func (QuantifiedExpr) exprNode() {}

// IfExpr represents "if (cond) then thenExpr else elseExpr".
type IfExpr struct {
	// Cond supplies the effective boolean condition.
	Cond Expr
	// Then is evaluated when Cond is true.
	Then Expr
	// Else is evaluated when Cond is false.
	Else Expr
}

func (IfExpr) exprNode() {}

// TryCatchExpr represents "try { expr } catch code { expr }".
type TryCatchExpr struct {
	// Try supplies the expression whose dynamic errors can be caught.
	Try Expr
	// Catches contains catch clauses in source order.
	Catches []CatchClause
}

func (TryCatchExpr) exprNode() {}

// CatchClause represents a single catch branch.
type CatchClause struct {
	Codes []string // error codes to match; empty = catch all (*)
	// Expr is evaluated for a matching caught error.
	Expr Expr
}

// --- Type Expressions ---

// InstanceOfExpr represents "expr instance of sequenceType".
type InstanceOfExpr struct {
	// Expr supplies the value whose sequence type is tested.
	Expr Expr
	// Type is the required item type and occurrence constraint.
	Type xdm.SequenceType
}

func (InstanceOfExpr) exprNode() {}

// CastExpr represents "expr cast as atomicType?".
type CastExpr struct {
	// Expr supplies the value to cast.
	Expr Expr
	// Type identifies the target atomic type.
	Type AtomicTypeName
	// AllowEmpty permits an empty input sequence when the target includes ?.
	AllowEmpty bool
}

func (CastExpr) exprNode() {}

// CastableExpr represents "expr castable as atomicType?".
type CastableExpr struct {
	// Expr supplies the value whose castability is tested.
	Expr Expr
	// Type identifies the target atomic type.
	Type AtomicTypeName
	// AllowEmpty permits an empty input sequence when the target includes ?.
	AllowEmpty bool
}

func (CastableExpr) exprNode() {}

// TreatAsExpr represents "expr treat as sequenceType".
type TreatAsExpr struct {
	// Expr supplies the sequence whose declared type is asserted.
	Expr Expr
	// Type is the item type and occurrence constraint to enforce.
	Type xdm.SequenceType
}

func (TreatAsExpr) exprNode() {}

// AtomicTypeName identifies a target type for cast/castable.
type AtomicTypeName struct {
	// Prefix is the lexical type-name prefix.
	Prefix string
	// Name is the local target type name.
	Name string
}

// --- Functions ---

// FunctionCall represents a static function invocation: prefix:name(args...).
type FunctionCall struct {
	// Prefix is the lexical function prefix, or empty for an unprefixed call.
	Prefix string
	// Name is the local function name.
	Name string
	// Args contains argument expressions in call order.
	Args []Expr
}

func (FunctionCall) exprNode() {}

// DynamicFunctionCall represents a dynamic function call: $f(args...).
type DynamicFunctionCall struct {
	// Func produces the function item to invoke.
	Func Expr
	// Args contains argument expressions in call order.
	Args []Expr
}

func (DynamicFunctionCall) exprNode() {}

// NamedFunctionRef represents a named function reference: fn:name#arity.
type NamedFunctionRef struct {
	// Prefix is the lexical function-name prefix.
	Prefix string
	// Name is the local function name.
	Name string
	// Arity is the argument count after the # delimiter.
	Arity int
}

func (NamedFunctionRef) exprNode() {}

// InlineFunctionExpr represents an inline function definition.
type InlineFunctionExpr struct {
	// Params contains parameter names and optional types in declaration order.
	Params     []FunctionParam
	ReturnType *xdm.SequenceType // nil if not specified
	// Body supplies the function result expression.
	Body      Expr
	EmptyBody bool // lexically empty FunctionBody, distinct from { () }
	// Retain the definition for nonlocal-variable analysis after VM lowering
	// replaces expression children with opaque instruction references.
	nonlocalBody Expr
}

func (InlineFunctionExpr) exprNode() {}

// PlaceholderExpr represents ? in partial function application.
type PlaceholderExpr struct{}

func (PlaceholderExpr) exprNode() {}

// FunctionParam is a parameter in an inline function definition.
type FunctionParam struct {
	// Name is the lexical parameter name without the dollar sign.
	Name     string
	TypeHint *xdm.SequenceType // nil if not specified
}

// --- Constructors ---

// MapConstructorExpr represents map { key: value, ... }.
type MapConstructorExpr struct {
	// Pairs contains key and value expressions in source order.
	Pairs []MapConstructorPair
}

func (MapConstructorExpr) exprNode() {}

// MapConstructorPair is one key:value entry in a map constructor.
type MapConstructorPair struct {
	// Key supplies the atomic map key.
	Key Expr
	// Value supplies the sequence associated with the key.
	Value Expr
}

// ArrayConstructorExpr represents [items] or array { items }.
type ArrayConstructorExpr struct {
	// Items contains member expressions for square brackets or the input sequence
	// expression for a curly array constructor.
	Items         []Expr
	SquareBracket bool // true = [a, b], false = array { expr }
}

func (ArrayConstructorExpr) exprNode() {}

// SequenceExpr represents a comma-separated sequence: (a, b, c).
type SequenceExpr struct {
	// Items contains expressions whose results are concatenated in order.
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
