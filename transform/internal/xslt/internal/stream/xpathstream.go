// Derived from lestrrat-go/helium at 7362c0a70122a757780f4d0b545a9b370dead6ab.
// Copyright (c) 2015 lestrrat. MIT License; see licenses/MIT-helium.txt at the repository root.

// Package xpathstream analyzes XPath 3.1 expressions for XSLT streamability.
package xpathstream

import (
	"github.com/skarm/xmlsec/transform/internal/xpath"
)

// WalkExpr walks an XPath 3.1 AST, calling fn for each Expr node.
// If fn returns false, children of that node are not visited.
func WalkExpr(expr xpath.Expr, fn func(xpath.Expr) bool) {
	if expr == nil {
		return
	}

	expr = derefExpr(expr)
	if !fn(expr) {
		return
	}

	walkChildren(expr, fn)
}

func derefExpr(expr xpath.Expr) xpath.Expr {
	switch e := expr.(type) {
	case *xpath.LocationPath:
		if e == nil {
			return nil
		}

		return *e
	case *xpath.BinaryExpr:
		if e == nil {
			return nil
		}

		return *e
	case *xpath.FilterExpr:
		if e == nil {
			return nil
		}

		return *e
	case *xpath.PathExpr:
		if e == nil {
			return nil
		}

		return *e
	case *xpath.FunctionCall:
		if e == nil {
			return nil
		}

		return *e
	default:
		return expr
	}
}

func walkChildren(expr xpath.Expr, fn func(xpath.Expr) bool) {
	if walkPathChildren(expr, fn) {
		return
	}

	if walkBindingChildren(expr, fn) {
		return
	}

	walkValueChildren(expr, fn)
}

func walkPathChildren(expr xpath.Expr, fn func(xpath.Expr) bool) bool {
	switch e := expr.(type) {
	case xpath.LocationPath:
		for _, step := range e.Steps {
			for _, pred := range step.Predicates {
				WalkExpr(pred, fn)
			}
		}

		return true

	case xpath.FilterExpr:
		WalkExpr(e.Expr, fn)

		for _, pred := range e.Predicates {
			WalkExpr(pred, fn)
		}

		return true

	case xpath.PathExpr:
		WalkExpr(e.Filter, fn)

		if e.Path != nil {
			WalkExpr(*e.Path, fn)
		}

		return true

	case xpath.PathStepExpr:
		WalkExpr(e.Left, fn)
		WalkExpr(e.Right, fn)

		return true

	case xpath.LookupExpr:
		WalkExpr(e.Expr, fn)
		WalkExpr(e.Key, fn)

		return true

	case xpath.UnaryLookupExpr:
		WalkExpr(e.Key, fn)

		return true
	}

	return false
}

func walkBindingChildren(expr xpath.Expr, fn func(xpath.Expr) bool) bool {
	switch e := expr.(type) {
	case xpath.FLWORExpr:
		for _, clause := range e.Clauses {
			switch c := clause.(type) {
			case xpath.ForClause:
				WalkExpr(c.Expr, fn)
			case xpath.LetClause:
				WalkExpr(c.Expr, fn)
			}
		}

		WalkExpr(e.Return, fn)

		return true

	case xpath.QuantifiedExpr:
		for _, b := range e.Bindings {
			WalkExpr(b.Domain, fn)
		}

		WalkExpr(e.Satisfies, fn)

		return true

	case xpath.IfExpr:
		WalkExpr(e.Cond, fn)
		WalkExpr(e.Then, fn)
		WalkExpr(e.Else, fn)

		return true

	case xpath.TryCatchExpr:
		WalkExpr(e.Try, fn)

		for _, cc := range e.Catches {
			WalkExpr(cc.Expr, fn)
		}

		return true

	case xpath.InlineFunctionExpr:
		WalkExpr(e.Body, fn)

		return true
	}

	return false
}

func walkValueChildren(expr xpath.Expr, fn func(xpath.Expr) bool) {
	switch e := expr.(type) {
	case xpath.LiteralExpr, xpath.VariableExpr, xpath.RootExpr, xpath.ContextItemExpr, xpath.PlaceholderExpr:
		// leaf nodes

	case xpath.BinaryExpr:
		WalkExpr(e.Left, fn)
		WalkExpr(e.Right, fn)

	case xpath.UnaryExpr:
		WalkExpr(e.Operand, fn)

	case xpath.ConcatExpr:
		WalkExpr(e.Left, fn)
		WalkExpr(e.Right, fn)

	case xpath.SimpleMapExpr:
		WalkExpr(e.Left, fn)
		WalkExpr(e.Right, fn)

	case xpath.RangeExpr:
		WalkExpr(e.Start, fn)
		WalkExpr(e.End, fn)

	case xpath.UnionExpr:
		WalkExpr(e.Left, fn)
		WalkExpr(e.Right, fn)

	case xpath.IntersectExceptExpr:
		WalkExpr(e.Left, fn)
		WalkExpr(e.Right, fn)

	case xpath.InstanceOfExpr:
		WalkExpr(e.Expr, fn)

	case xpath.CastExpr:
		WalkExpr(e.Expr, fn)

	case xpath.CastableExpr:
		WalkExpr(e.Expr, fn)

	case xpath.TreatAsExpr:
		WalkExpr(e.Expr, fn)

	case xpath.FunctionCall:
		for _, arg := range e.Args {
			WalkExpr(arg, fn)
		}

	case xpath.DynamicFunctionCall:
		WalkExpr(e.Func, fn)

		for _, arg := range e.Args {
			WalkExpr(arg, fn)
		}

	case xpath.NamedFunctionRef:
		// leaf

	case xpath.MapConstructorExpr:
		for _, pair := range e.Pairs {
			WalkExpr(pair.Key, fn)
			WalkExpr(pair.Value, fn)
		}

	case xpath.ArrayConstructorExpr:
		for _, item := range e.Items {
			WalkExpr(item, fn)
		}

	case xpath.SequenceExpr:
		for _, item := range e.Items {
			WalkExpr(item, fn)
		}
	}
}

// ExprUsesFunction returns true if the expression contains a call to the named function
// (with no namespace prefix, e.g. "last", "position").
func ExprUsesFunction(expr *xpath.Expression, name string) bool {
	if expr == nil {
		return false
	}

	_, ok := expr.StreamInfo().UsedFunctions[name]

	return ok
}

// ExprHasDownwardStep returns true if the expression contains any child::, descendant::,
// or descendant-or-self:: axis step.
func ExprHasDownwardStep(expr *xpath.Expression) bool {
	if expr == nil {
		return false
	}

	return expr.StreamInfo().HasDownwardStep
}

// ExprUsesUpwardAxis returns true if the expression uses parent::, ancestor::,
// ancestor-or-self::, preceding::, or preceding-sibling:: axes.
func ExprUsesUpwardAxis(expr *xpath.Expression) bool {
	if expr == nil {
		return false
	}

	const upwardMask = 1<<uint(xpath.AxisParent) |
		1<<uint(xpath.AxisAncestor) |
		1<<uint(xpath.AxisAncestorOrSelf) |
		1<<uint(xpath.AxisPreceding) |
		1<<uint(xpath.AxisPrecedingSibling)

	return expr.StreamInfo().AxisUsed&upwardMask != 0
}

// ExprUsesDescendantOrSelf returns true if the expression uses descendant:: or
// descendant-or-self:: axis.
func ExprUsesDescendantOrSelf(expr *xpath.Expression) bool {
	if expr == nil {
		return false
	}

	si := expr.StreamInfo()

	const descMask = 1<<uint(xpath.AxisDescendant) | 1<<uint(xpath.AxisDescendantOrSelf)

	return si.AxisUsed&descMask != 0 || si.HasDescOrSelf
}

// ExprUsesContextItem returns true if the expression references the context
// item (.) at any level.
func ExprUsesContextItem(expr *xpath.Expression) bool {
	if expr == nil {
		return false
	}

	found := false

	WalkExpr(expr.AST(), func(e xpath.Expr) bool {
		if found {
			return false
		}

		switch e.(type) {
		case xpath.ContextItemExpr:
			found = true
			return false
		}

		return true
	})

	return found
}
