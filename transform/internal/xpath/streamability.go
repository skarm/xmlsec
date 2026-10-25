// Derived from lestrrat-go/helium at 7362c0a70122a757780f4d0b545a9b370dead6ab.
// Copyright (c) 2015 lestrrat. MIT License; see licenses/MIT-helium.txt at the repository root.

package xpath

import (
	"maps"
	"math/big"
	"strings"

	"github.com/skarm/xmlsec/internal/lexicon"
	"github.com/skarm/xmlsec/transform/internal/xdm"
)

// StreamInfo exposes precomputed expression properties to internal consumers,
// including XSLT pattern analysis. It grants no W3C streamability claim.
type StreamInfo struct {
	UsedFunctions   map[string]struct{}
	AxisUsed        uint16
	HasDownwardStep bool
	HasDescOrSelf   bool
	IsContextItem   bool
}

// AST returns the root AST node of the compiled expression.
// XSLT pattern analysis traverses it with WalkExpr.
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

	WalkExpr(ast, si.observe)

	return si
}

// WalkExpr walks an XPath 3.1 AST, calling fn for each Expr node.
// If fn returns false, children of that node are not visited.
func WalkExpr(expr Expr, fn func(Expr) bool) {
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
				WalkExpr(pred, fn)
			}
		}

		return true

	case vmLocationPathExpr:
		for _, step := range e.Steps {
			for _, pred := range step.Predicates {
				WalkExpr(pred, fn)
			}
		}

		return true

	case FilterExpr:
		WalkExpr(e.Expr, fn)

		for _, pred := range e.Predicates {
			WalkExpr(pred, fn)
		}

		return true

	case PathExpr:
		WalkExpr(e.Filter, fn)

		if e.Path != nil {
			WalkExpr(*e.Path, fn)
		}

		return true

	case vmPathExpr:
		WalkExpr(e.Filter, fn)

		if e.Path != nil {
			WalkExpr(*e.Path, fn)
		}

		return true

	case PathStepExpr:
		WalkExpr(e.Left, fn)
		WalkExpr(e.Right, fn)

		return true

	case LookupExpr:
		WalkExpr(e.Expr, fn)
		WalkExpr(e.Key, fn)

		return true

	case UnaryLookupExpr:
		WalkExpr(e.Key, fn)

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
				WalkExpr(c.Expr, fn)
			case LetClause:
				WalkExpr(c.Expr, fn)
			}
		}

		WalkExpr(e.Return, fn)

		return true

	case QuantifiedExpr:
		for _, b := range e.Bindings {
			WalkExpr(b.Domain, fn)
		}

		WalkExpr(e.Satisfies, fn)

		return true

	case IfExpr:
		WalkExpr(e.Cond, fn)
		WalkExpr(e.Then, fn)
		WalkExpr(e.Else, fn)

		return true

	case TryCatchExpr:
		WalkExpr(e.Try, fn)

		for _, cc := range e.Catches {
			WalkExpr(cc.Expr, fn)
		}

		return true

	case InlineFunctionExpr:
		WalkExpr(e.Body, fn)

		return true
	}

	return false
}

func walkValueChildren(expr Expr, fn func(Expr) bool) {
	switch e := expr.(type) {
	case LiteralExpr, VariableExpr, RootExpr, ContextItemExpr, PlaceholderExpr:
		// leaf nodes

	case BinaryExpr:
		WalkExpr(e.Left, fn)
		WalkExpr(e.Right, fn)

	case UnaryExpr:
		WalkExpr(e.Operand, fn)

	case ConcatExpr:
		WalkExpr(e.Left, fn)
		WalkExpr(e.Right, fn)

	case SimpleMapExpr:
		WalkExpr(e.Left, fn)
		WalkExpr(e.Right, fn)

	case RangeExpr:
		WalkExpr(e.Start, fn)
		WalkExpr(e.End, fn)

	case UnionExpr:
		WalkExpr(e.Left, fn)
		WalkExpr(e.Right, fn)

	case IntersectExceptExpr:
		WalkExpr(e.Left, fn)
		WalkExpr(e.Right, fn)

	case InstanceOfExpr:
		WalkExpr(e.Expr, fn)

	case CastExpr:
		WalkExpr(e.Expr, fn)

	case CastableExpr:
		WalkExpr(e.Expr, fn)

	case TreatAsExpr:
		WalkExpr(e.Expr, fn)

	case FunctionCall:
		for _, arg := range e.Args {
			WalkExpr(arg, fn)
		}

	case DynamicFunctionCall:
		WalkExpr(e.Func, fn)

		for _, arg := range e.Args {
			WalkExpr(arg, fn)
		}

	case NamedFunctionRef:
		// leaf

	case MapConstructorExpr:
		for _, pair := range e.Pairs {
			WalkExpr(pair.Key, fn)
			WalkExpr(pair.Value, fn)
		}

	case ArrayConstructorExpr:
		for _, item := range e.Items {
			WalkExpr(item, fn)
		}

	case SequenceExpr:
		for _, item := range e.Items {
			WalkExpr(item, fn)
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
// the lexicalFnLocalName helper, normalizing the EQName
// (Q{...}local) spelling the parseOptions keeps in FunctionCall.Name.
func streamFnLocalName(fc FunctionCall) (string, bool) {
	return lexicalFnLocalName(fc.Name, fc.Prefix)
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
		if isFn && (local == lexicon.FnLast || local == lexicon.FnPosition) {
			return true, false
		}

		if isFn {
			switch local {
			case lexicon.FnName, nameLocalName, nameNamespaceUri, nameNodeName,
				"self", lexicon.FnGenerateID, "base-uri", fnNameDocumentURI,
				fnNameNilled, nameHasChildren, nameStringLength, "current":
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

// isFnNamespacePrefix reports whether a function-call prefix names the XPath
// functions namespace (http://www.w3.org/2005/xpath-functions) for the purpose
// of streamability analysis. For function calls an empty prefix defaults to that
// namespace, and "fn" is the conventional reserved prefix bound to it, so both
// lexical forms name the same built-in. Streamability special-cases functions
// such as position()/last() by (namespace, local-name) and must therefore treat
// the unprefixed and "fn:"-prefixed spellings identically.
//
// This is a deliberately lexical check, not a namespace-resolved one: the
// analysis runs over the static AST with no access to a prefix->URI map (the map
// only exists at eval time, via the xpath evaluator's namespace bindings). We
// make the same assumption the xpath evaluator's own static-shape recognition
// already makes (eval_path.go positionCall: Prefix == "" || Prefix == "fn").
// Edge case: a caller that rebinds "fn" to a custom namespace and then calls
// fn:position() would have it resolve to a user function at eval time while
// streamability still treats it as the built-in. Rebinding the reserved "fn"
// prefix is pathological and unsupported here; consistency with the evaluator is
// preferred.
func isFnNamespacePrefix(prefix string) bool {
	return prefix == "" || prefix == "fn"
}

// lexicalFnLocalName resolves a function call's lexical (name, prefix) to its
// local name for streamability analysis, reporting whether the call names the
// XPath functions namespace.
//
// The parseOptions keeps an EQName function call's whole braced spelling in the name
// (e.g. "Q{http://www.w3.org/2005/xpath-functions}position"), so a bare lexical
// comparison against "position"/"last" would miss it. This normalizes that form
// to its local part when the braced URI is the functions namespace. For the
// lexical (unprefixed or "fn:") forms it defers to isFnNamespacePrefix and
// returns name unchanged.
func lexicalFnLocalName(name, prefix string) (string, bool) {
	if strings.HasPrefix(name, "Q{") {
		if idx := strings.Index(name, "}"); idx >= 0 {
			return name[idx+1:], name[2:idx] == lexicon.NamespaceFn
		}

		return name, false
	}

	return name, isFnNamespacePrefix(prefix)
}
