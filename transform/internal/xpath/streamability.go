// Derived from lestrrat-go/helium at 7362c0a70122a757780f4d0b545a9b370dead6ab.
// Copyright (c) 2015 lestrrat. MIT License; see licenses/MIT-helium.txt at the repository root.

package xpath

import (
	"maps"
	"math/big"

	"github.com/skarm/xmlsec/transform/internal/xdm"
	"github.com/skarm/xmlsec/transform/internal/xdm/lexicon"
)

// StreamInfo exposes precomputed streamability properties for use by
// internal packages (e.g. xslt streamability analysis). This struct
// is not intended for end-user consumption; it lives in an internal
// package that re-exports query helpers.
type StreamInfo struct {
	UsedFunctions   map[string]struct{}
	AxisUsed        uint16
	HasDownwardStep bool
	HasDescOrSelf   bool
	IsContextItem   bool
}

// AST returns the root AST node of the compiled expression.
// This is used by streamability analysis in xslt via internal/xpathstream.
func (e *Expression) AST() Expr {
	return e.astExpr()
}

// StreamInfo returns a snapshot of the precomputed streamability
// properties for this expression.
func (e *Expression) StreamInfo() StreamInfo {
	if e == nil || e.program == nil {
		return StreamInfo{}
	}

	s := e.program.stream

	return StreamInfo{
		AxisUsed:        s.axisUsed,
		HasDownwardStep: s.hasDownwardStep,
		HasDescOrSelf:   s.hasDescOrSelf,
		UsedFunctions:   maps.Clone(s.usedFunctions),
		IsContextItem:   s.isContextItem,
	}
}

// computeStreamInfo performs a single AST walk to precompute all
// streamability properties stored on vmProgram.stream.
func computeStreamInfo(ast Expr) streamInfo {
	si := streamInfo{
		usedFunctions: make(map[string]struct{}),
	}

	switch v := derefExpr(ast).(type) {
	case ContextItemExpr:
		si.isContextItem = true
	case vmLocationPathExpr:
		// The direct compiler lowers "." to self::node(); recognize it.
		computeStreamInfoAbsolute(&v, &si)
	}

	walkExpr(ast, si.observe)

	return si
}

// walkExpr walks an XPath 3.1 AST, calling fn for each Expr node.
// If fn returns false, children of that node are not visited.
func walkExpr(expr Expr, fn func(Expr) bool) {
	if expr == nil {
		return
	}
	// Dereference pointer types to value types so type switches work uniformly.
	expr = derefExpr(expr)
	if !fn(expr) {
		return
	}

	walkChildren(expr, fn)
}

func derefExpr(expr Expr) Expr {
	switch e := expr.(type) {
	case *LocationPath:
		if e == nil {
			return nil
		}

		return *e
	case *BinaryExpr:
		if e == nil {
			return nil
		}

		return *e
	case *FilterExpr:
		if e == nil {
			return nil
		}

		return *e
	case *PathExpr:
		if e == nil {
			return nil
		}

		return *e
	case *FunctionCall:
		if e == nil {
			return nil
		}

		return *e
	default:
		return expr
	}
}

func walkChildren(expr Expr, fn func(Expr) bool) {
	if walkPathChildren(expr, fn) {
		return
	}

	if walkBindingChildren(expr, fn) {
		return
	}

	walkValueChildren(expr, fn)
}

func walkPathChildren(expr Expr, fn func(Expr) bool) bool {
	switch e := expr.(type) {
	case LocationPath:
		for _, step := range e.Steps {
			for _, pred := range step.Predicates {
				walkExpr(pred, fn)
			}
		}

		return true

	case vmLocationPathExpr:
		for _, step := range e.Steps {
			for _, pred := range step.Predicates {
				walkExpr(pred, fn)
			}
		}

		return true

	case FilterExpr:
		walkExpr(e.Expr, fn)

		for _, pred := range e.Predicates {
			walkExpr(pred, fn)
		}

		return true

	case PathExpr:
		walkExpr(e.Filter, fn)

		if e.Path != nil {
			walkExpr(*e.Path, fn)
		}

		return true

	case vmPathExpr:
		walkExpr(e.Filter, fn)

		if e.Path != nil {
			walkExpr(*e.Path, fn)
		}

		return true

	case PathStepExpr:
		walkExpr(e.Left, fn)
		walkExpr(e.Right, fn)

		return true

	case LookupExpr:
		walkExpr(e.Expr, fn)
		walkExpr(e.Key, fn)

		return true

	case UnaryLookupExpr:
		walkExpr(e.Key, fn)

		return true
	}

	return false
}

func walkBindingChildren(expr Expr, fn func(Expr) bool) bool {
	switch e := expr.(type) {
	case FLWORExpr:
		for _, clause := range e.Clauses {
			switch c := clause.(type) {
			case ForClause:
				walkExpr(c.Expr, fn)
			case LetClause:
				walkExpr(c.Expr, fn)
			}
		}

		walkExpr(e.Return, fn)

		return true

	case QuantifiedExpr:
		for _, b := range e.Bindings {
			walkExpr(b.Domain, fn)
		}

		walkExpr(e.Satisfies, fn)

		return true

	case IfExpr:
		walkExpr(e.Cond, fn)
		walkExpr(e.Then, fn)
		walkExpr(e.Else, fn)

		return true

	case TryCatchExpr:
		walkExpr(e.Try, fn)

		for _, cc := range e.Catches {
			walkExpr(cc.Expr, fn)
		}

		return true

	case InlineFunctionExpr:
		walkExpr(e.Body, fn)

		return true
	}

	return false
}

func walkValueChildren(expr Expr, fn func(Expr) bool) {
	switch e := expr.(type) {
	case LiteralExpr, VariableExpr, RootExpr, ContextItemExpr, PlaceholderExpr:
		// leaf nodes

	case BinaryExpr:
		walkExpr(e.Left, fn)
		walkExpr(e.Right, fn)

	case UnaryExpr:
		walkExpr(e.Operand, fn)

	case ConcatExpr:
		walkExpr(e.Left, fn)
		walkExpr(e.Right, fn)

	case SimpleMapExpr:
		walkExpr(e.Left, fn)
		walkExpr(e.Right, fn)

	case RangeExpr:
		walkExpr(e.Start, fn)
		walkExpr(e.End, fn)

	case UnionExpr:
		walkExpr(e.Left, fn)
		walkExpr(e.Right, fn)

	case IntersectExceptExpr:
		walkExpr(e.Left, fn)
		walkExpr(e.Right, fn)

	case InstanceOfExpr:
		walkExpr(e.Expr, fn)

	case CastExpr:
		walkExpr(e.Expr, fn)

	case CastableExpr:
		walkExpr(e.Expr, fn)

	case TreatAsExpr:
		walkExpr(e.Expr, fn)

	case FunctionCall:
		for _, arg := range e.Args {
			walkExpr(arg, fn)
		}

	case DynamicFunctionCall:
		walkExpr(e.Func, fn)

		for _, arg := range e.Args {
			walkExpr(arg, fn)
		}

	case NamedFunctionRef:
		// leaf

	case MapConstructorExpr:
		for _, pair := range e.Pairs {
			walkExpr(pair.Key, fn)
			walkExpr(pair.Value, fn)
		}

	case ArrayConstructorExpr:
		for _, item := range e.Items {
			walkExpr(item, fn)
		}

	case SequenceExpr:
		for _, item := range e.Items {
			walkExpr(item, fn)
		}
	}
}

func stepSelectsAtomicNodes(step *Step) bool {
	if step.Axis == AxisAttribute {
		return true
	}

	switch v := step.NodeTest.(type) {
	case xdm.TypeTest:
		switch v.Kind {
		case xdm.NodeKindText, xdm.NodeKindComment, xdm.NodeKindProcessingInstruction:
			return true
		}
	case xdm.AttributeTest:
		return true
	case xdm.NamespaceNodeTest:
		return true
	case xdm.PITest:
		return true
	}

	return false
}

func computeStreamInfoAbsolute(v *vmLocationPathExpr, si *streamInfo) {
	if !v.Absolute && len(v.Steps) == 1 {
		s := v.Steps[0]
		if s.Axis == AxisSelf && len(s.Predicates) == 0 {
			if tt, ok := s.NodeTest.(xdm.TypeTest); ok && tt.Kind == xdm.NodeKindNode {
				si.isContextItem = true
			}
		}
	}
}

func (si *streamInfo) observe(e Expr) bool {
	switch v := e.(type) {
	case LocationPath:
		for _, step := range v.Steps {
			si.observeStep(step.Axis)
		}
	case vmLocationPathExpr:
		for _, step := range v.Steps {
			si.observeStep(step.Axis)
		}
	case PathStepExpr:
		if v.DescOrSelf {
			si.hasDownwardStep = true
			si.hasDescOrSelf = true
		}
	case FunctionCall:
		if local, ok := streamFnLocalName(v); ok {
			si.usedFunctions[local] = struct{}{}
		}
	}

	return true
}

// streamFnLocalName resolves a FunctionCall to its streamability local name via
// the shared lexicon.StreamFnLocalName helper, normalizing the EQName
// (Q{...}local) spelling the parseOptions keeps in FunctionCall.Name.
func streamFnLocalName(fc FunctionCall) (string, bool) {
	return lexicon.StreamFnLocalName(fc.Name, fc.Prefix)
}

func (si *streamInfo) observeStep(axis AxisType) {
	si.axisUsed |= 1 << uint(axis)
	switch axis {
	case AxisChild, AxisDescendant, AxisDescendantOrSelf:
		si.hasDownwardStep = true
	}
}

func inspectPredicateMotion(e, pred Expr, step *Step) (bool, bool) {
	switch v := e.(type) {
	case LocationPath:
		for _, step := range v.Steps {
			switch step.Axis {
			case AxisChild, AxisDescendant, AxisDescendantOrSelf:
				return true, false
			}
		}
	case vmLocationPathExpr:
		for _, step := range v.Steps {
			switch step.Axis {
			case AxisChild, AxisDescendant, AxisDescendantOrSelf:
				return true, false
			}
		}
	case PathStepExpr:
		if v.DescOrSelf {
			return true, false
		}
	case FunctionCall:
		local, isFn := streamFnLocalName(v)
		if isFn && (local == nameLast || local == lexicon.FnPosition) {
			return true, false
		}

		if isFn {
			switch local {
			case nameName2, nameLocalName, nameNamespaceUri, nameNodeName,
				"self", nameGenerateId, "base-uri", "document-uri",
				"nilled", nameHasChildren, nameStringLength, "current":
				return false, false
			}
		}
	case LiteralExpr:
		if e == pred {
			switch v.Value.(type) {
			case float64, *big.Int, *big.Rat:
				return true, false
			}
		}
	case InstanceOfExpr, CastableExpr:
		return false, false
	case ContextItemExpr:
		if step != nil && stepSelectsAtomicNodes(step) {
			return false, false
		}

		return true, false
	}

	return false, true
}
