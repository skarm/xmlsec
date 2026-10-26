// Copyright (c) 2026 xmlsec contributors. MIT License.

package xpath

import (
	"context"
	"math"
	"math/big"
	"reflect"
	"strconv"
	"strings"

	"github.com/skarm/xmlsec/internal/lexicon"
	"github.com/skarm/xmlsec/transform/internal/xdm"
)

// XPath10String implements XPath 1.0 string(), including double formatting.
func XPath10String(seq xdm.Sequence) (string, error) { return xpath10String(seq) }

// XPath10Value admits the four XPath 1.0 value kinds and normalizes a node-set
// to document order without losing node identity. Numeric values are doubles.
func XPath10Value(ctx context.Context, seq xdm.Sequence) (xdm.Sequence, error) {
	if xdm.SequenceLen(seq) == 0 {
		return nil, nil
	}

	if a, ok := seq.Get(0).(xdm.AtomicValue); ok {
		if seq.Len() != 1 {
			return nil, &xdm.Error{Code: lexicon.ErrXPTY0004, Message: "XPath 1.0 has no atomic sequences"}
		}

		if a.IsNumeric() {
			return xpath10Double(a.ToFloat64()), nil
		}

		if a.TypeName == xdm.TypeString || a.TypeName == xdm.TypeBoolean {
			return seq, nil
		}

		return nil, &xdm.Error{Code: lexicon.ErrXPTY0004, Message: "value type is unavailable in XPath 1.0"}
	}

	var nodes []xdm.Node

	for item := range seq.Items() {
		if err := Charge(ctx, 1); err != nil {
			return nil, err
		}

		n, ok := item.(xdm.NodeItem)
		if !ok || n.ResultTreeFragment {
			return nil, &xdm.Error{Code: lexicon.ErrXPTY0004, Message: "XPath 1.0 requires a node-set"}
		}

		nodes = append(nodes, n.Node)
	}

	return sequenceFromDocOrderedNodes(ctx, nodes)
}

// XPath10FunctionArity reports the core function's minimum and maximum arity.
// A maximum of -1 is variadic. Host functions live in the host's own registry.
func XPath10FunctionArity(name string) ([2]int, bool) {
	v, ok := lookupXPath10FunctionArity(name)
	return v, ok
}

// XPath10Number implements XPath 1.0 number() for stylesheet host functions.
func XPath10Number(seq xdm.Sequence) (xdm.AtomicValue, error) { return xpath10Number(seq) }

// XPath 1.0 section 4.2 requires decimal notation, including Infinity and -0.
// Adapted from lestrrat-go/helium number.ToString; Copyright (c) 2015
// lestrrat, MIT license in licenses/MIT-helium.txt.
func xpath10NumberString(v float64) string {
	switch {
	case math.IsNaN(v):
		return lexicon.FloatNaN
	case math.IsInf(v, 1):
		return "Infinity"
	case math.IsInf(v, -1):
		return "-Infinity"
	case v == 0:
		return "0"
	}

	return strconv.FormatFloat(v, 'f', -1, 64)
}

func xpath10String(seq xdm.Sequence) (string, error) {
	if xdm.SequenceLen(seq) == 0 {
		return "", nil
	}

	if n, ok := seq.Get(0).(xdm.NodeItem); ok {
		return xdm.StringValue(n.Node), nil
	}

	a, err := AtomizeItem(seq.Get(0))
	if err != nil {
		return "", err
	}

	if a.IsNumeric() {
		return xpath10NumberString(a.ToFloat64()), nil
	}

	return atomicToString(a)
}

func xpath10Double(v float64) xdm.Sequence {
	return xdm.SingleAtomic(xdm.AtomicValue{TypeName: xdm.TypeDouble, Value: xdm.NewDouble(v)})
}

// XPath 1.0 uses the same parseOptions, VM, axes and builtins. This table specifies
// its core library; stylesheet functions and explicitly registered extensions
// are checked by their host, rather than being mistaken for newer builtins.
func lookupXPath10FunctionArity(key string) ([2]int, bool) {
	switch key {
	case lexicon.FnLast, lexicon.FnPosition, lexicon.ValueTrue, lexicon.ValueFalse:
		return [2]int{0, 0}, true
	case fnNameCount, "id", fnNameBoolean, fnNameNot, lexicon.AttrLang, nameSum, nameFloor, nameCeiling, nameRound:
		return [2]int{1, 1}, true
	case nameLocalName, nameNamespaceURI, lexicon.FnName, lexicon.TypeString, nameStringLength, fnNameNormalizeSpace, lexicon.TypeNumber:
		return [2]int{0, 1}, true
	case nameConcat:
		return [2]int{2, -1}, true
	case fnNameStartsWith, fnNameContains, fnNameSubstringBefore, fnNameSubstringAfter:
		return [2]int{2, 2}, true
	case fnNameSubstring:
		return [2]int{2, 3}, true
	case fnNameTranslate:
		return [2]int{3, 3}, true
	}

	var zero [2]int

	return zero, false
}

func xpath10Number(seq xdm.Sequence) (xdm.AtomicValue, error) {
	if xdm.SequenceLen(seq) == 0 {
		return doubleNaNAtom(), nil
	}

	a, err := AtomizeItem(seq.Get(0))
	if err != nil {
		return xdm.AtomicValue{}, err
	}

	if a.IsNumeric() {
		return xdm.AtomicValue{TypeName: xdm.TypeDouble, Value: xdm.NewDouble(a.ToFloat64())}, nil
	}

	if a.TypeName == xdm.TypeBoolean {
		if a.Value == true {
			return xdm.AtomicValue{TypeName: xdm.TypeDouble, Value: xdm.NewDouble(1)}, nil
		}

		return xdm.AtomicValue{TypeName: xdm.TypeDouble, Value: xdm.NewDouble(0)}, nil
	}

	s, err := atomicToString(a)
	if err != nil {
		return xdm.AtomicValue{}, err
	}

	s = strings.Trim(s, " \t\r\n")
	body := strings.TrimPrefix(s, "-")
	digits, dot := 0, false

	for _, r := range body {
		switch {
		case r >= '0' && r <= '9':
			digits++
		case r == '.' && !dot:
			dot = true
		default:
			return doubleNaNAtom(), nil
		}
	}

	if digits == 0 {
		return doubleNaNAtom(), nil
	}

	v, err := strconv.ParseFloat(s, 64)
	if err != nil && !math.IsInf(v, 0) {
		return doubleNaNAtom(), nil
	}

	return xdm.AtomicValue{TypeName: xdm.TypeDouble, Value: xdm.NewDouble(v)}, nil
}

func xpath10FunctionArity(name string, arity int) bool {
	a, ok := lookupXPath10FunctionArity(name)
	return ok && arity >= a[0] && (a[1] < 0 || arity <= a[1])
}

func validateXPath10Expr(ast Expr) error {
	return walkProfile(reflect.ValueOf(ast), func(node any) error {
		switch n := node.(type) {
		case Expr:
			switch n := n.(type) {
			case LiteralExpr, VariableExpr, RootExpr, ContextItemExpr, LocationPath, FunctionCall, UnionExpr, FilterExpr, PathExpr:
			case BinaryExpr:
				switch n.Op {
				case TokenPlus, TokenMinus, TokenStar, TokenDiv, TokenMod, TokenAnd, TokenOr, TokenEquals, TokenNotEquals, TokenLess, TokenLessEq, TokenGreater, TokenGreaterEq:
				default:
					return profileError(lexicon.ErrXPST0003, "operator", 10)
				}
			case UnaryExpr:
				if !n.Negate {
					return profileError(lexicon.ErrXPST0003, "unary plus", 10)
				}
			default:
				return profileError(lexicon.ErrXPST0003, "expression", 10)
			}
		case xdm.NameTest:
			if n.URI != "" || n.Prefix == "*" {
				return profileError(lexicon.ErrXPST0003, "name test", 10)
			}
		case xdm.NodeTest:
			switch n.(type) {
			case xdm.NameTest, xdm.TypeTest, xdm.PITest:
			default:
				return profileError(lexicon.ErrXPST0003, "kind test", 10)
			}
		}

		return nil
	})
}

// Literals are doubles before VM compilation, so predicate fast paths and
// constant folding observe the same IEEE 754 values as runtime arithmetic.
func xpath10Literals(e Expr) Expr {
	e = derefExpr(e)
	rewrite := xpath10Literals
	preds := func(es []Expr) {
		for i := range es {
			es[i] = rewrite(es[i])
		}
	}

	switch n := e.(type) {
	case LiteralExpr:
		switch v := n.Value.(type) {
		case *big.Int:
			f, _ := new(big.Float).SetInt(v).Float64()
			n.Value = f
		case *big.Rat:
			f, _ := v.Float64()
			n.Value = f
		}

		return n
	case BinaryExpr:
		n.Left = rewrite(n.Left)
		n.Right = rewrite(n.Right)

		return n
	case UnaryExpr:
		n.Operand = rewrite(n.Operand)
		return n
	case UnionExpr:
		n.Left = rewrite(n.Left)
		n.Right = rewrite(n.Right)

		return n
	case FunctionCall:
		preds(n.Args)
		return n
	case LocationPath:
		for i := range n.Steps {
			preds(n.Steps[i].Predicates)
		}

		return n
	case FilterExpr:
		n.Expr = rewrite(n.Expr)
		preds(n.Predicates)

		return n
	case PathExpr:
		n.Filter = rewrite(n.Filter)
		if n.Path != nil {
			p, ok := rewrite(*n.Path).(LocationPath)
			if !ok {
				panic("invalid internal XPath path")
			}

			n.Path = &p
		}

		return n
	}

	return e
}

func xpath10NodeSet(seq xdm.Sequence) error {
	for item := range xdm.SequenceItems(seq) {
		if n, ok := item.(xdm.NodeItem); !ok || n.ResultTreeFragment {
			return &xdm.Error{Code: lexicon.ErrXPTY0004, Message: "XPath 1.0 requires a node-set"}
		}
	}

	return nil
}

// callXPath10Builtin supplies the 1.0 conversion rules, then calls the shared
// builtin. Only the functions whose definitions changed need their own case.
func callXPath10Builtin(ctx context.Context, ec *evalContext, function resolvedFunction, args []xdm.Sequence) (xdm.Sequence, error) {
	switch function.name {
	case lexicon.TypeString, lexicon.TypeNumber:
		return callXPath10ContextConversion(ctx, ec, function.name, args)
	case nameSum:
		return sumXPath10Nodes(ctx, args[0])
	}

	for i, argument := range args {
		converted, err := coerceXPath10Argument(ctx, function.name, i, argument)
		if err != nil {
			return nil, err
		}

		args[i] = converted
	}

	result, err := function.fn.Call(ec.fnContext(ctx), args)
	if err != nil {
		return nil, err
	}

	return normalizeXPath10BuiltinResult(result)
}

func callXPath10ContextConversion(ctx context.Context, ec *evalContext, name string, args []xdm.Sequence) (xdm.Sequence, error) {
	argument, err := xpath10ContextArgument(ec, args)
	if err != nil {
		return nil, err
	}

	if name == lexicon.TypeString {
		return coerceXPath10StringArgument(ctx, argument)
	}

	value, err := xpath10Number(argument)

	return xdm.SingleAtomic(value), err
}

func xpath10ContextArgument(ec *evalContext, args []xdm.Sequence) (xdm.Sequence, error) {
	var argument xdm.Sequence
	if ec.contextItem != nil {
		argument = xdm.ItemSlice{ec.contextItem}
	} else if ec.node != nil {
		argument = xdm.ItemSlice{xdm.NodeItem{Node: ec.node}}
	}

	if len(args) > 0 {
		return args[0], nil
	}

	if ec.node == nil && ec.contextItem == nil {
		return nil, &xdm.Error{Code: lexicon.ErrXPDY0002, Message: "context item absent"}
	}

	return argument, nil
}

func coerceXPath10Argument(ctx context.Context, name string, index int, argument xdm.Sequence) (xdm.Sequence, error) {
	switch name {
	case fnNameCount, nameLocalName, nameNamespaceURI, lexicon.FnName:
		if err := xpath10NodeSet(argument); err != nil {
			return nil, err
		}

		if name != fnNameCount && xdm.SequenceLen(argument) > 1 {
			return xdm.ItemSlice{argument.Get(0)}, nil
		}

		return argument, nil
	case nameConcat, fnNameStartsWith, fnNameContains, fnNameSubstringBefore, fnNameSubstringAfter, fnNameTranslate, nameStringLength, fnNameNormalizeSpace, lexicon.AttrLang:
		return coerceXPath10StringArgument(ctx, argument)
	case fnNameSubstring:
		if index == 0 {
			return coerceXPath10StringArgument(ctx, argument)
		}

		return coerceXPath10NumberArgument(argument)
	case nameFloor, nameCeiling, nameRound:
		return coerceXPath10NumberArgument(argument)
	case "id":
		return coerceXPath10IDArgument(ctx, argument)
	default:
		return argument, nil
	}
}

func coerceXPath10StringArgument(ctx context.Context, argument xdm.Sequence) (xdm.Sequence, error) {
	text, err := xpath10String(argument)
	if err != nil {
		return nil, err
	}

	if err := ChargeString(ctx, len(text)); err != nil {
		return nil, err
	}

	return xdm.SingleString(text), nil
}

func coerceXPath10NumberArgument(argument xdm.Sequence) (xdm.Sequence, error) {
	value, err := xpath10Number(argument)
	if err != nil {
		return nil, err
	}

	return xdm.SingleAtomic(value), nil
}

func coerceXPath10IDArgument(ctx context.Context, argument xdm.Sequence) (xdm.Sequence, error) {
	if xdm.SequenceLen(argument) == 0 {
		return coerceXPath10StringArgument(ctx, argument)
	}

	if _, ok := argument.Get(0).(xdm.NodeItem); !ok {
		return coerceXPath10StringArgument(ctx, argument)
	}

	// A node-set supplies one string per item without charging string coercion.
	var values xdm.ItemSlice

	for item := range xdm.SequenceItems(argument) {
		text, err := xpath10String(xdm.ItemSlice{item})
		if err != nil {
			return nil, err
		}

		values = append(values, xdm.AtomicValue{TypeName: xdm.TypeString, Value: text})
	}

	return values, nil
}

func normalizeXPath10BuiltinResult(result xdm.Sequence) (xdm.Sequence, error) {
	if xdm.SequenceLen(result) != 1 {
		return result, nil
	}

	atom, ok := result.Get(0).(xdm.AtomicValue)
	if !ok {
		return result, nil
	}

	if atom.IsNumeric() {
		return xpath10Double(atom.ToFloat64()), nil
	}

	if atom.TypeName == xdm.TypeAnyURI {
		text, err := atomicToString(atom)
		return xdm.SingleString(text), err
	}

	return result, nil
}

func sumXPath10Nodes(ctx context.Context, nodes xdm.Sequence) (xdm.Sequence, error) {
	// Validate the whole node-set before charging or converting any item.
	if err := xpath10NodeSet(nodes); err != nil {
		return nil, err
	}

	sum := 0.0

	for item := range xdm.SequenceItems(nodes) {
		if err := Charge(ctx, 1); err != nil {
			return nil, err
		}

		value, err := xpath10Number(xdm.ItemSlice{item})
		if err != nil {
			return nil, err
		}

		sum += value.ToFloat64()
	}

	return xpath10Double(sum), nil
}
