// Derived from lestrrat-go/helium at 7362c0a70122a757780f4d0b545a9b370dead6ab.
// Copyright (c) 2015 lestrrat. MIT License; see licenses/MIT-helium.txt at the repository root.

package xpath

import (
	"context"
	"fmt"

	"github.com/skarm/xmlsec/transform/internal/xdm"
	"github.com/skarm/xmlsec/transform/internal/xdm/lexicon"
)

// NewFunctionReference creates a typed reference without retaining an evaluation.
// Argument conversion and calls use the live caller's context and resource policy.
func NewFunctionReference(name QualifiedName, arity int, fn TypedFunction) xdm.FunctionItem {
	qv := xdm.QNameValue{URI: name.URI, Local: name.Name}

	return xdm.FunctionItem{
		Arity: arity, Name: name.Name, Namespace: name.URI,
		ParamTypes: fn.FuncParamTypes(), ReturnType: fn.FuncReturnType(),
		Invoke: lookupFunctionInvoker(nil, fn.FuncParamTypes(), false, qv, arity, fn),
	}
}

// CallFunctionLookup is an exported wrapper around the built-in
// function-lookup implementation. It is used by the XSLT layer to
// delegate to the standard function-lookup before applying
// package-specific adjustments.
func CallFunctionLookup(ctx context.Context, args []xdm.Sequence) (xdm.Sequence, error) {
	return fnFunctionLookup(ctx, args)
}

func fnFunctionLookup(ctx context.Context, args []xdm.Sequence) (xdm.Sequence, error) {
	nameArg, err := extractSingleAtomicArg(args[0], "function-lookup()")
	if err != nil {
		return nil, err
	}

	if nameArg.TypeName != xdm.TypeQName {
		return nil, &xdm.Error{Code: lexicon.ErrXPTY0004, Message: "function-lookup() first argument must be QName"}
	}

	arityArg, err := extractSingleAtomicArg(args[1], "function-lookup()")
	if err != nil {
		return nil, err
	}

	arityArg, err = coerceToInteger(ctx, arityArg)
	if err != nil {
		return nil, err
	}

	arityVal, ok := arityArg.Int64Val()
	if !ok {
		return nil, nil
	}
	// Reject negative or out-of-int arities (no such function); checking on
	// int64 first avoids a wrap to a valid-looking arity on 32-bit platforms.
	const maxInt = int(^uint(0) >> 1)
	if arityVal < 0 || arityVal > int64(maxInt) {
		return nil, nil
	}

	arity := int(arityVal)

	fi, ok := lookupFunctionItem(ctx, nameArg.QNameVal(), arity)

	if !ok {
		return nil, nil
	}

	return xdm.ItemSlice{fi}, nil
}

func lookupFunctionItem(ctx context.Context, qv xdm.QNameValue, arity int) (xdm.FunctionItem, bool) {
	var (
		fn        Function
		ok        bool
		isBuiltin bool
	)

	if ec := getFnContext(ctx); ec != nil {
		fn, ok = lookupRegisteredFunction(ec, qv, arity)
	}

	if !ok {
		fn, ok = lookupBuiltin(QualifiedName{URI: qv.URI, Name: qv.Local})
		if ec := getFnContext(ctx); ec != nil && !functionVisible(ec.version, qv.URI, qv.Local, arity) {
			fn, ok = nil, false
		}

		if ok && isExtensionBuiltin(fn) {
			// helium EXTENSION functions (e.g. fn:flatten, array:flat-map) are
			// STATIC-CALL-ONLY: not dynamically reachable via fn:function-lookup. This
			// keeps a conformance-restricted static context (XSD 1.1 CTA, which rejects a
			// static extension call via StandardFunctionAcceptsArity) from invoking an
			// extension through a computed-name lookup that the static gate cannot see.
			// (A user-registered function of the same name still resolves above.)
			fn, ok = nil, false
		}

		if ok && checkArity(fn, qv.Local, arity) != nil {
			ok = false
		}

		isBuiltin = ok
	}

	if !ok {
		return xdm.FunctionItem{}, false
	}

	if provider, ok := fn.(DynamicRefSnapshotProvider); ok {
		if item, captured := provider.DynamicRefSnapshot(ctx, arity); captured {
			return item, true
		}
	}

	var capturedEC *evalContext

	if ec := getFnContext(ctx); ec != nil {
		capturedECValue := *ec
		capturedECValue.invocation = nil
		capturedEC = &capturedECValue
	}

	var (
		paramTypes []xdm.SequenceType
		repeated   bool
		returnType *xdm.SequenceType
		sig        *functionSignature
	)
	// The built-in signature registry is consulted only when the resolved function
	// is the built-in itself; a user override of a built-in name binds its own
	// signature, mirroring the direct call path (lookupParamTypes).
	if isBuiltin {
		sig = lookupFunctionSignature(qv.URI, qv.Local, arity)
	}

	if sig != nil {
		paramTypes = sig.ParamTypes
		repeated = sig.RepeatParamType
		returnType = sig.ReturnType
	} else if tf, ok := fn.(TypedFunction); ok {
		// User-defined typed functions expose their signature directly;
		// mirror evalNamedFunctionRef so function-lookup enforces the same
		// argument-type checks as the named-reference path (f#1).
		paramTypes = tf.FuncParamTypes()
		returnType = tf.FuncReturnType()
	} else if tfa, ok := fn.(TypedFunctionByArity); ok {
		paramTypes = tfa.FuncParamTypesForArity(arity)
		returnType = tfa.FuncReturnTypeForArity(arity)
	}

	fi := xdm.FunctionItem{
		Arity:           arity,
		Name:            qv.Local,
		Namespace:       qv.URI,
		ParamTypes:      paramTypes,
		RepeatParamType: repeated,
		ReturnType:      returnType,
	}
	fi.Invoke = lookupFunctionInvoker(capturedEC, paramTypes, repeated, qv, arity, fn)

	return fi, true
}

func lookupRegisteredFunction(ec *evalContext, qv xdm.QNameValue, arity int) (Function, bool) {
	if qv.URI == "" && ec.functions != nil {
		if fn, ok := ec.functions[qv.Local]; ok && checkArity(fn, qv.Local, arity) == nil {
			return fn, true
		}
	}

	if ec.fnsNS != nil {
		if fn, ok := ec.fnsNS[QualifiedName{URI: qv.URI, Name: qv.Local}]; ok && checkArity(fn, qv.Local, arity) == nil {
			return fn, true
		}
	}

	return nil, false
}

func lookupFunctionsHof(name string) (*builtinFunc, bool) {
	switch name {
	case nameForEach:
		return &builtinFunc{name: name, min: 2, max: 2, fn: fnForEach}, true
	case nameFilter:
		return &builtinFunc{name: name, min: 2, max: 2, fn: fnFilter}, true
	case nameFoldLeft:
		return &builtinFunc{name: name, min: 3, max: 3, fn: fnFoldLeft}, true
	case nameFoldRight:
		return &builtinFunc{name: name, min: 3, max: 3, fn: fnFoldRight}, true
	case nameForEachPair:
		return &builtinFunc{name: name, min: 3, max: 3, fn: fnForEachPair}, true
	case "apply":
		return &builtinFunc{name: name, min: 2, max: 2, fn: fnApply}, true
	case "function-lookup":
		return &builtinFunc{name: name, min: 2, max: 2, fn: fnFunctionLookup}, true
	case "function-arity":
		return &builtinFunc{name: name, min: 1, max: 1, fn: fnFunctionArity}, true
	case "function-name":
		return &builtinFunc{name: name, min: 1, max: 1, fn: fnFunctionName}, true
	}

	return nil, false
}

// fnMaxNodes returns the node-set/sequence length limit that accumulating
// built-ins (for-each, for-each-pair, map:for-each, array:flatten, ...) must
// honor via appendBounded. When the function is called outside an evaluation
// (ec == nil) or the evaluation did not set an explicit limit, the package
// default applies so unbounded materialization is still rejected.
func fnMaxNodes(ec *evalContext) int {
	if ec == nil || ec.maxNodes <= 0 {
		return maxNodeSetLength
	}

	return ec.maxNodes
}

// fnRemainingOps reports the op budget still available to this evaluation and
// whether a budget is in force. bounded is false when no OpLimit is configured
// (opLimit <= 0) or the function runs outside an evaluation (ec == nil); the
// returned count is meaningless in that case. A negative remainder (the budget
// is already exhausted) is clamped to 0. Built-ins that produce a slice up
// front use this to cap production at the EFFECTIVE budget actually in force,
// not just maxNodes, so a small OpLimit does not first materialize a slice
// proportional to the input before the op charge rejects it.
func fnRemainingOps(ec *evalContext) (remaining int, bounded bool) {
	if ec == nil || ec.opLimit <= 0 || ec.opCount == nil {
		return 0, false
	}

	return max(ec.opLimit-*ec.opCount, 0), true
}

// fnCountOp charges one operation against the evaluation's op-counter and
// honors context cancellation. It is a no-op (other than the cancellation
// check) when called outside an evaluation. Accumulating built-ins call it once
// per iteration so a long-running higher-order call respects op/time limits.
func fnCountOp(ctx context.Context, ec *evalContext) error {
	if ec != nil {
		return ec.countOps(ctx, 1)
	}

	return ctx.Err()
}

// fnCountOps charges n operations against the evaluation's op-counter and
// honors context cancellation. It is a no-op (other than the cancellation
// check) when called outside an evaluation. Built-ins that clone or materialize
// a whole sub-sequence in one shot (array:for-each, array:for-each-pair,
// array:join, array:flat-map, map:find) call it with the sub-sequence length
// BEFORE the bulk clone/append so the work is charged against OpLimit — a length
// below maxNodes but above OpLimit is still rejected with ErrOpLimit.
func fnCountOps(ctx context.Context, ec *evalContext, n int) error {
	if ec != nil {
		return ec.countOps(ctx, n)
	}

	return ctx.Err()
}

// appendArrayMember enforces BOTH result-array bounds before adding one member
// to an array builder (array:for-each, array:filter, array:join, array:flat-map,
// map:find, ...) and charges the per-member op cost. It returns the grown member
// slice and the running item total.
//
// Two independent limits must hold at every append site, because a member can
// add zero items yet still add a member:
//
//   - member count: many EMPTY members (each seqLen 0) could otherwise build an
//     array with more than maxNodes members while the item total stays at zero,
//     so len(dst)+1 is bounded against maxNodes.
//   - item count: a single member with a huge (possibly lazy) sequence could
//     otherwise be cloned by NewArray past maxNodes items, so member length is
//     bounded against the remaining headroom (maxNodes-total). The subtraction is
//     overflow-safe because it only runs when maxNodes > 0.
//
// The op charge is max(seqLen(member), 1): NewArray clones each member, so a
// member with many items below maxNodes but above OpLimit must be rejected, AND
// empty members must still each cost an op so a flood of them cannot bypass
// OpLimit.
func appendArrayMember(ctx context.Context, ec *evalContext, maxNodes int, dst []xdm.Sequence, total int, member xdm.Sequence) ([]xdm.Sequence, int, error) {
	if maxNodes > 0 && len(dst)+1 > maxNodes {
		return dst, total, ErrNodeSetLimit
	}

	mLen := xdm.SequenceLen(member)
	if maxNodes > 0 && mLen > maxNodes-total {
		return dst, total, ErrNodeSetLimit
	}

	if err := fnCountOps(ctx, ec, max(mLen, 1)); err != nil {
		return dst, total, err
	}

	return append(dst, member), total + mLen, nil
}

func fnForEach(ctx context.Context, args []xdm.Sequence) (xdm.Sequence, error) {
	seq := args[0]

	fi, err := extractFunctionItem(args[1])
	if err != nil {
		return nil, err
	}

	ec := getFnContext(ctx)
	maxNodes := fnMaxNodes(ec)

	var result xdm.ItemSlice

	callArgs := make([]xdm.Sequence, 1)

	for item := range xdm.SequenceItems(seq) {
		if err := fnCountOp(ctx, ec); err != nil {
			return nil, err
		}

		callArgs[0] = xdm.ItemSlice{item}

		r, err := fi.Invoke(ctx, callArgs)
		if err != nil {
			return nil, err
		}

		result, err = appendBoundedSeq(ctx, ec, result, r, maxNodes)
		if err != nil {
			return nil, err
		}
	}

	return result, nil
}

func fnFilter(ctx context.Context, args []xdm.Sequence) (xdm.Sequence, error) {
	seq := args[0]

	fi, err := extractFunctionItem(args[1])
	if err != nil {
		return nil, err
	}
	// Per XPath 3.1, the callback must have arity 1
	if fi.Arity >= 0 && fi.Arity != 1 {
		return nil, &xdm.Error{Code: lexicon.ErrXPTY0004, Message: fmt.Sprintf("fn:filter callback must have arity 1, got %d", fi.Arity)}
	}

	ec := getFnContext(ctx)
	maxNodes := fnMaxNodes(ec)

	var result xdm.ItemSlice

	callArgs := make([]xdm.Sequence, 1)

	for item := range xdm.SequenceItems(seq) {
		if err := fnCountOp(ctx, ec); err != nil {
			return nil, err
		}

		callArgs[0] = xdm.ItemSlice{item}

		r, err := fi.Invoke(ctx, callArgs)
		if err != nil {
			return nil, err
		}
		// Per XPath 3.1, the callback must return exactly one xs:boolean
		if xdm.SequenceLen(r) != 1 {
			return nil, &xdm.Error{Code: lexicon.ErrXPTY0004, Message: "fn:filter callback must return a single xs:boolean value"}
		}

		av, ok := r.Get(0).(xdm.AtomicValue)
		if !ok || av.TypeName != xdm.TypeBoolean {
			return nil, &xdm.Error{Code: lexicon.ErrXPTY0004, Message: "fn:filter callback must return a single xs:boolean value"}
		}

		if av.BooleanVal() {
			result, err = appendBounded(result, []xdm.Item{item}, maxNodes)
			if err != nil {
				return nil, err
			}
		}
	}

	return result, nil
}

func fnFoldLeft(ctx context.Context, args []xdm.Sequence) (xdm.Sequence, error) {
	seq := args[0]
	acc := args[1]

	fi, err := extractFunctionItem(args[2])
	if err != nil {
		return nil, err
	}

	ec := getFnContext(ctx)
	maxNodes := fnMaxNodes(ec)
	callArgs := make([]xdm.Sequence, 2)

	for item := range xdm.SequenceItems(seq) {
		if err := fnCountOp(ctx, ec); err != nil {
			return nil, err
		}

		callArgs[0] = acc
		callArgs[1] = xdm.ItemSlice{item}

		acc, err = fi.Invoke(ctx, callArgs)
		if err != nil {
			return nil, err
		}
		// The accumulator can grow without bound across iterations; reject once
		// it would exceed the configured sequence/node-set limit.
		if maxNodes > 0 && xdm.SequenceLen(acc) > maxNodes {
			return nil, ErrNodeSetLimit
		}
	}

	return acc, nil
}

func fnFoldRight(ctx context.Context, args []xdm.Sequence) (xdm.Sequence, error) {
	seq := args[0]
	acc := args[1]

	fi, err := extractFunctionItem(args[2])
	if err != nil {
		return nil, err
	}

	ec := getFnContext(ctx)
	maxNodes := fnMaxNodes(ec)
	// Iterate from last to first WITHOUT materializing the input sequence, so a
	// lazy/borrowed input is never fully realized before the per-item op-count
	// and accumulator size-bound checks run (mirrors fnFoldLeft's streaming).
	callArgs := make([]xdm.Sequence, 2)

	for i := xdm.SequenceLen(seq); i > 0; i-- {
		if err := fnCountOp(ctx, ec); err != nil {
			return nil, err
		}

		callArgs[0] = xdm.ItemSlice{seq.Get(i - 1)}
		callArgs[1] = acc

		acc, err = fi.Invoke(ctx, callArgs)
		if err != nil {
			return nil, err
		}
		// The accumulator can grow without bound across iterations; reject once
		// it would exceed the configured sequence/node-set limit.
		if maxNodes > 0 && xdm.SequenceLen(acc) > maxNodes {
			return nil, ErrNodeSetLimit
		}
	}

	return acc, nil
}

func fnForEachPair(ctx context.Context, args []xdm.Sequence) (xdm.Sequence, error) {
	seq1 := args[0]
	seq2 := args[1]

	fi, err := extractFunctionItem(args[2])
	if err != nil {
		return nil, err
	}
	// Per XPath 3.1, the callback must have arity 2
	if fi.Arity >= 0 && fi.Arity != 2 {
		return nil, &xdm.Error{Code: lexicon.ErrXPTY0004, Message: fmt.Sprintf("fn:for-each-pair callback must have arity 2, got %d", fi.Arity)}
	}

	ec := getFnContext(ctx)
	maxNodes := fnMaxNodes(ec)
	size := min(xdm.SequenceLen(seq1), xdm.SequenceLen(seq2))

	var result xdm.ItemSlice

	callArgs := make([]xdm.Sequence, 2)

	for i := range size {
		if err := fnCountOp(ctx, ec); err != nil {
			return nil, err
		}

		callArgs[0] = xdm.ItemSlice{seq1.Get(i)}
		callArgs[1] = xdm.ItemSlice{seq2.Get(i)}

		r, err := fi.Invoke(ctx, callArgs)
		if err != nil {
			return nil, err
		}

		result, err = appendBoundedSeq(ctx, ec, result, r, maxNodes)
		if err != nil {
			return nil, err
		}
	}

	return result, nil
}

func fnApply(ctx context.Context, args []xdm.Sequence) (xdm.Sequence, error) {
	fi, err := extractFunctionItem(args[0])
	if err != nil {
		return nil, err
	}

	if xdm.SequenceLen(args[1]) != 1 {
		return nil, &xdm.Error{Code: lexicon.ErrXPTY0004, Message: "apply() second argument must be a single array"}
	}

	arr, ok := args[1].Get(0).(xdm.ArrayItem)
	if !ok {
		return nil, &xdm.Error{Code: lexicon.ErrXPTY0004, Message: "apply() second argument must be array"}
	}

	if fi.Arity >= 0 && arr.Size() != fi.Arity {
		return nil, &xdm.Error{Code: errCodeFOAP0001, Message: fmt.Sprintf("fn:apply: function has arity %d but array has %d members", fi.Arity, arr.Size())}
	}

	members := arr.MembersView()
	fnArgs := make([]xdm.Sequence, len(members))
	copy(fnArgs, members)

	return fi.Invoke(ctx, fnArgs)
}

func fnFunctionArity(_ context.Context, args []xdm.Sequence) (xdm.Sequence, error) {
	fi, err := extractFunctionItem(args[0])
	if err != nil {
		return nil, err
	}

	return xdm.SingleInteger(int64(fi.Arity)), nil
}

func fnFunctionName(_ context.Context, args []xdm.Sequence) (xdm.Sequence, error) {
	fi, err := extractFunctionItem(args[0])
	if err != nil {
		return nil, err
	}

	if fi.Name == "" {
		return nil, nil
	}

	ns := fi.Namespace
	if ns == "" {
		ns = NSFn
	}

	prefix := namespacePrefixFor(ns)

	return xdm.SingleAtomic(xdm.AtomicValue{
		TypeName: xdm.TypeQName,
		Value:    xdm.QNameValue{Prefix: prefix, Local: fi.Name, URI: ns},
	}), nil
}

func extractFunctionItem(seq xdm.Sequence) (xdm.FunctionItem, error) {
	if xdm.SequenceLen(seq) != 1 {
		return xdm.FunctionItem{}, &xdm.Error{Code: lexicon.ErrXPTY0004, Message: "expected single function item"}
	}
	// asFunctionItem is the single source of truth for adapting maps and arrays
	// (arity-1 lookup functions) into FunctionItem; see eval_funcall.go.
	fi, ok := asFunctionItem(seq.Get(0))
	if !ok {
		return xdm.FunctionItem{}, &xdm.Error{Code: lexicon.ErrXPTY0004, Message: fmt.Sprintf("expected function item, got %T", seq.Get(0))}
	}

	return fi, nil
}

func lookupFunctionInvoker(capturedEC *evalContext, paramTypes []xdm.SequenceType, repeated bool, qv xdm.QNameValue, arity int, fn Function) func(context.Context, []xdm.Sequence) (xdm.Sequence, error) {
	return func(ctx context.Context, callArgs []xdm.Sequence) (xdm.Sequence, error) {
		callEC := getFnContext(ctx)
		if capturedEC != nil {
			callEC = calleeContext(ctx, capturedEC)
			ctx = withFnContext(ctx, callEC)
		}

		if len(callArgs) != arity {
			return nil, &xdm.Error{Code: lexicon.ErrXPTY0004, Message: fmt.Sprintf("fn:%s requires %d arguments, got %d", qv.Local, arity, len(callArgs))}
		}
		// Enforce the recorded parameter types, mirroring the named
		// function-reference path in eval_funcall.go. Coercion may convert an
		// argument (e.g. xs:untypedAtomic -> xs:integer); the coerced value must
		// be what the function observes, so store it back into a copy of the
		// argument slice, discarding nothing and invoking with no original.
		if paramTypes != nil {
			coerced := make([]xdm.Sequence, len(callArgs))
			copy(coerced, callArgs)

			for i, arg := range callArgs {
				if parameter, declared := xdm.FunctionParameterType(paramTypes, repeated, i); declared {
					// coerceFuncallArg surfaces a real typed error (FOTY0012 from
					// atomizing an element-only node, FOTY0013, FORG0001, …) and maps
					// only a plain mismatch to XPTY0004 — the boolean
					// coerceToSequenceType would collapse FOTY0012 into XPTY0004.
					c, err := coerceFuncallArg(ctx, arg, parameter, qv.Local, i, callEC)
					if err != nil {
						return nil, err
					}

					coerced[i] = c
				}
			}

			callArgs = coerced
		}

		return fn.Call(ctx, callArgs)
	}
}
