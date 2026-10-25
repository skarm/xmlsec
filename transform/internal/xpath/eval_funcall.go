// Derived from lestrrat-go/helium at 7362c0a70122a757780f4d0b545a9b370dead6ab.
// Copyright (c) 2015 lestrrat. MIT License; see licenses/MIT-helium.txt at the repository root.

package xpath

import (
	"context"
	"errors"
	"fmt"

	"github.com/skarm/xmlsec/internal/lexicon"
	"github.com/skarm/xmlsec/transform/internal/xdm"
)

func evalFunctionCall(evalFn exprEvaluator, ctx context.Context, ec *evalContext, e FunctionCall) (xdm.Sequence, error) {
	args := make([]xdm.Sequence, len(e.Args))
	hasPlaceholders := false

	for i, argExpr := range e.Args {
		if _, ok := argExpr.(PlaceholderExpr); ok {
			hasPlaceholders = true
			continue
		}

		a, err := evalFn(ctx, ec, argExpr)
		if err != nil {
			return nil, err
		}

		args[i] = enrichNodeItems(ctx, ec, a)
	}

	// Partial application: if any args are placeholders, return FunctionItem
	if hasPlaceholders {
		return partialApply(ctx, ec, e, args)
	}

	// Resolve function, keeping the resolved identity so signature enforcement
	// keys off the resolved URI/local name (handles Q{uri}local) and only applies
	// the built-in signature when the resolved function is the actual built-in.
	r, err := resolveFunctionInfo(ctx, ec, e.Prefix, e.Name, len(args))
	if err != nil {
		return nil, err
	}

	return callResolvedFunction(ctx, ec, r, args, e.Args)
}

// callResolvedFunction coerces args to the declared parameter types of r and
// calls it. args holds evaluated, enriched arguments and no placeholders.
func callResolvedFunction(ctx context.Context, ec *evalContext, r resolvedFunction, args []xdm.Sequence, sourceArgs []Expr) (xdm.Sequence, error) {
	if ec.version == 10 && r.isBuiltin {
		return callXPath10Builtin(ctx, ec, r, args)
	}

	if ec.version == 20 && r.isBuiltin && r.uri == NSXS && r.name == lexicon.TypeQName && len(args) == 1 {
		value, empty, err := atomizeConstructorArg(args[0], xdm.TypeQName)
		if err != nil {
			return nil, err
		}

		if !empty && !qnameCastOperandAllowed(ec, sourceArgs[0], value) {
			return nil, &xdm.Error{Code: lexicon.ErrXPTY0004, Message: "XPath 2.0 QName construction requires a string literal or QName value"}
		}
	}
	// Enforce declared parameter signatures, mirroring the function-item /
	// named-function-reference path. Coerced values are stored back into args so
	// typed functions observe the converted values (e.g. xs:integer→xs:double).

	paramTypes, repeated := lookupParamTypes(ec, r, len(args))
	if paramTypes != nil {
		for i, arg := range args {
			if parameter, declared := xdm.FunctionParameterType(paramTypes, repeated, i); declared {
				coerced, err := coerceFuncallArg(ctx, arg, parameter, r.name, i, ec)
				if err != nil {
					return nil, err
				}

				args[i] = coerced
			}
		}
	}

	return r.fn.Call(ec.fnContext(ctx), args)
}

// lookupParamTypes returns the declared parameter types for a resolved function.
// The built-in signature registry is consulted only when the resolved function is
// the built-in; user/registered functions use their own TypedFunction metadata.
// The second result marks a sole type repeated for every parameter.
// A nil slice means no declared signature is available.
func lookupParamTypes(ec *evalContext, r resolvedFunction, arity int) ([]xdm.SequenceType, bool) {
	if unavailableModuleFunction(r.fn) {
		return nil, false
	}

	if signature := resolvedFunctionSignature(ec, r, arity); signature != nil {
		return signature.ParamTypes, signature.RepeatParamType
	}

	return nil, false
}

func resolvedFunctionSignature(ec *evalContext, r resolvedFunction, arity int) *functionSignature {
	version := 0
	if ec != nil {
		version = ec.version
	}

	if r.isBuiltin && r.uri == NSFn && r.name == "current-dateTime" && arity == 0 && ec != nil && ec.xmlSchemaVersion == 10 {
		// F&O permits xs:dateTime when XSD 1.1 datatypes are unavailable.
		return lookupStandardSignature(20, sigKey{URI: NSFn, Name: r.name, Arity: arity})
	}

	if r.isBuiltin {
		if signature := lookupFunctionSignature(version, r.uri, r.name, arity); signature != nil {
			return signature
		}
	}

	if typed, ok := r.fn.(TypedFunction); ok {
		return &functionSignature{ParamTypes: typed.FuncParamTypes(), ReturnType: typed.FuncReturnType()}
	}

	if typed, ok := r.fn.(TypedFunctionByArity); ok {
		return &functionSignature{ParamTypes: typed.FuncParamTypesForArity(arity), ReturnType: typed.FuncReturnTypeForArity(arity)}
	}

	return nil
}

func evalDynamicFunctionCall(evalFn exprEvaluator, ctx context.Context, ec *evalContext, e DynamicFunctionCall) (xdm.Sequence, error) {
	funcSeq, err := evalFn(ctx, ec, e.Func)
	if err != nil {
		return nil, err
	}

	if xdm.SequenceLen(funcSeq) != 1 {
		return nil, &xdm.Error{Code: lexicon.ErrXPTY0004, Message: "dynamic function call requires single function item"}
	}

	hasPlaceholders := false

	for _, argExpr := range e.Args {
		if _, ok := argExpr.(PlaceholderExpr); ok {
			hasPlaceholders = true
			break
		}
	}

	args := make([]xdm.Sequence, len(e.Args))
	if err := evalDynamicFunctionCallArgs(ctx, &e, evalFn, ec, args); err != nil {
		return nil, err
	}

	if hasPlaceholders {
		fi, ok := asFunctionItem(funcSeq.Get(0))
		if !ok {
			return nil, &xdm.Error{Code: lexicon.ErrXPTY0004, Message: "partial application requires function item"}
		}

		if fi.Arity >= 0 && len(e.Args) != fi.Arity {
			return nil, languageError(fmt.Errorf("%w: expected %d arguments, got %d", ErrArityMismatch, fi.Arity, len(e.Args)), lexicon.ErrXPTY0004, ec.version)
		}

		var placeholderIndices []int

		for i, argExpr := range e.Args {
			if _, ok := argExpr.(PlaceholderExpr); ok {
				placeholderIndices = append(placeholderIndices, i)
			}
		}

		return partialFunctionItem(fi, args, placeholderIndices), nil
	}

	switch v := funcSeq.Get(0).(type) {
	case xdm.FunctionItem:
		if v.Arity >= 0 && len(args) != v.Arity {
			return nil, languageError(fmt.Errorf("%w: expected %d arguments, got %d", ErrArityMismatch, v.Arity, len(args)), lexicon.ErrXPTY0004, ec.version)
		}

		return v.Invoke(withDynamicCall(ec.fnContext(ctx)), args)
	case xdm.MapItem:
		// Maps are functions: $map($key) → value
		return mapLookup(v, args)
	case xdm.ArrayItem:
		// Arrays are functions: $array($index) → member
		return arrayLookup(v, args)
	default:
		return nil, &xdm.Error{Code: lexicon.ErrXPTY0004, Message: fmt.Sprintf("dynamic function call requires function item, got %T", funcSeq.Get(0))}
	}
}

func partialParameterTypes(parameters []xdm.SequenceType, repeated bool, indices []int) []xdm.SequenceType {
	if parameters == nil {
		return nil
	}

	result := make([]xdm.SequenceType, len(indices))
	for i, index := range indices {
		result[i], _ = xdm.FunctionParameterType(parameters, repeated, index)
	}

	return result
}

func partialFunctionItem(fn xdm.FunctionItem, args []xdm.Sequence, indices []int) xdm.Sequence {
	fixed := append([]xdm.Sequence(nil), args...)

	parameters := partialParameterTypes(fn.ParamTypes, fn.RepeatParamType, indices)

	return xdm.ItemSlice{xdm.FunctionItem{
		Arity:      len(indices),
		ParamTypes: parameters, ReturnType: fn.ReturnType,
		Invoke: func(ctx context.Context, partial []xdm.Sequence) (xdm.Sequence, error) {
			if len(partial) != len(indices) {
				return nil, &xdm.Error{Code: lexicon.ErrXPTY0004, Message: fmt.Sprintf("arity mismatch: expected %d arguments, got %d", len(indices), len(partial))}
			}

			full := append([]xdm.Sequence(nil), fixed...)
			for i, index := range indices {
				full[index] = partial[i]
			}

			return fn.Invoke(ctx, full)
		},
	}}
}

// asFunctionItem adapts a callee item into a FunctionItem. In XPath 3.1 maps and
// arrays are function items of arity 1 (the lookup function), so they support
// both dynamic invocation and partial function application (e.g. $m(?), $a(?)).
func asFunctionItem(item xdm.Item) (xdm.FunctionItem, bool) {
	resultType := stItem(xdm.OccurrenceZeroOrMore)

	switch v := item.(type) {
	case xdm.FunctionItem:
		return v, true
	case xdm.MapItem:
		return xdm.FunctionItem{
			Arity:      1,
			ParamTypes: []xdm.SequenceType{stAtomic(xdm.TypeAnyAtomicType, xdm.OccurrenceExactlyOne)},
			ReturnType: &resultType,
			Invoke:     func(_ context.Context, args []xdm.Sequence) (xdm.Sequence, error) { return mapLookup(v, args) },
		}, true
	case xdm.ArrayItem:
		return xdm.FunctionItem{
			Arity:      1,
			ParamTypes: []xdm.SequenceType{stAtomic(xdm.TypeInteger, xdm.OccurrenceExactlyOne)}, ReturnType: &resultType,
			Invoke: func(_ context.Context, args []xdm.Sequence) (xdm.Sequence, error) { return arrayLookup(v, args) },
		}, true
	default:
		return xdm.FunctionItem{}, false
	}
}

// mapLookup implements the map-as-function call $map($key) → value.
func mapLookup(m xdm.MapItem, args []xdm.Sequence) (xdm.Sequence, error) {
	if len(args) != 1 || xdm.SequenceLen(args[0]) != 1 {
		return nil, &xdm.Error{Code: lexicon.ErrXPTY0004, Message: "map lookup requires exactly one argument"}
	}

	key, err := AtomizeItem(args[0].Get(0))
	if err != nil {
		return nil, err
	}

	val, ok := m.Get(key)
	if !ok {
		return nil, nil
	}

	return val, nil
}

// arrayLookup implements the array-as-function call $array($index) → member.
func arrayLookup(a xdm.ArrayItem, args []xdm.Sequence) (xdm.Sequence, error) {
	if len(args) != 1 || xdm.SequenceLen(args[0]) != 1 {
		return nil, &xdm.Error{Code: lexicon.ErrXPTY0004, Message: "array lookup requires exactly one argument"}
	}

	key, err := AtomizeItem(args[0].Get(0))
	if err != nil {
		return nil, err
	}

	if key.TypeName == xdm.TypeUntypedAtomic {
		key, err = CastAtomic(key, xdm.TypeInteger)
		if err != nil {
			return nil, &xdm.Error{Code: lexicon.ErrXPTY0004, Message: "array lookup requires xs:integer index"}
		}
	}

	if !xdm.IsIntegerDerived(key.TypeName) {
		return nil, &xdm.Error{Code: lexicon.ErrXPTY0004, Message: "array lookup requires xs:integer index"}
	}

	idx, err := checkedArrayIndex(key)
	if err != nil {
		return nil, err
	}

	return a.Get(idx)
}

func evalNamedFunctionRef(ctx context.Context, ec *evalContext, e NamedFunctionRef) (xdm.Sequence, error) {
	r, err := resolveFunctionInfo(ctx, ec, e.Prefix, e.Name, e.Arity)
	if err != nil {
		return nil, err
	}

	fn := bindFunctionReference(r.fn)

	// Check if the function needs to capture state at reference creation time.
	if sp, ok := fn.(DynamicRefSnapshotProvider); ok {
		if fi, ok := sp.DynamicRefSnapshot(ctx, e.Arity); ok {
			return xdm.ItemSlice{fi}, nil
		}
	}

	minArity := fn.MinArity()
	ns, _ := resolvePrefix(ec, e.Prefix)
	// Per XPath 3.1 Section 3.1.6: if the function is focus-dependent,
	// the dynamic context (including focus) is fixed at reference creation time.
	// Capture the evalContext snapshot for focus/variables, but use the caller's
	// context.Context at invocation time for cancellation propagation.
	capturedECValue := *ec
	capturedECValue.invocation = nil
	capturedECValue.documentSnapshots = nil
	capturedEC := &capturedECValue
	// Populate type signature. The built-in signature registry is consulted only
	// when the resolved function is the built-in itself; a user override of a
	// built-in name (e.g. abs#1) binds its own signature, mirroring the direct
	// call path (lookupParamTypes).
	var signature functionSignature
	if declared := resolvedFunctionSignature(ec, resolvedFunction{fn: fn, isBuiltin: r.isBuiltin, uri: r.uri, name: r.name}, e.Arity); declared != nil {
		signature = *declared
	}

	paramTypes, repeated, returnType := signature.ParamTypes, signature.RepeatParamType, signature.ReturnType

	// Check if the function restricts dynamic references (e.g. current-group#0).
	// If so, create a function item that always raises the specified error.
	if dr, ok := fn.(DynamicRefRestricted); ok && dr.NoDynamicRef() {
		errCode := dr.DynRefErrorCode()
		fnName := e.Name
		ns, _ := resolvePrefix(ec, e.Prefix)
		fi := xdm.FunctionItem{
			Arity:      e.Arity,
			ParamTypes: paramTypes, RepeatParamType: repeated, ReturnType: returnType,
			Name:      fnName,
			Namespace: ns,
			Invoke: func(_ context.Context, _ []xdm.Sequence) (xdm.Sequence, error) {
				return nil, &xdm.Error{Code: errCode, Message: fmt.Sprintf("%s: dynamic call to %s is not allowed", errCode, fnName)}
			},
		}

		return xdm.ItemSlice{fi}, nil
	}

	fi := xdm.FunctionItem{
		Arity:           e.Arity,
		Name:            e.Name,
		Namespace:       ns,
		ParamTypes:      paramTypes,
		RepeatParamType: repeated,
		ReturnType:      returnType,
		Invoke: func(ctx context.Context, args []xdm.Sequence) (xdm.Sequence, error) {
			ctx = withDynamicCall(ctx)
			callEC := calleeContext(ctx, capturedEC)
			ctx = withFnContext(ctx, callEC)

			if len(args) < minArity {
				return nil, &xdm.Error{Code: lexicon.ErrXPTY0004, Message: fmt.Sprintf("fn:%s requires at least %d arguments, got %d", e.Name, minArity, len(args))}
			}
			// Type-check arguments against declared parameter types. Coercion may
			// convert an argument (e.g. xs:integer -> xs:double); the coerced value
			// must be what the function observes, so store it back into a copy of the
			// argument slice, discarding nothing and invoking with no original
			// — mirroring the direct call path and fn:function-lookup.
			if paramTypes != nil && !unavailableModuleFunction(fn) {
				coerced := make([]xdm.Sequence, len(args))
				copy(coerced, args)

				for i, arg := range args {
					if parameter, declared := xdm.FunctionParameterType(paramTypes, repeated, i); declared {
						// coerceFuncallArg propagates a real typed error (FOTY0012 from
						// atomizing an element-only node, FOTY0013, FORG0001, …) and
						// maps only a plain mismatch to XPTY0004 — the boolean
						// coerceToSequenceType would flatten FOTY0012 into a generic
						// XPTY0004.
						c, err := coerceFuncallArg(ctx, arg, parameter, e.Name, i, callEC)
						if err != nil {
							return nil, err
						}

						coerced[i] = c
					}
				}

				args = coerced
			}
			// Use caller's ctx for cancellation, captured ec for focus/eval state
			return fn.Call(withFnContext(ctx, callEC), args)
		},
	}

	return xdm.ItemSlice{fi}, nil
}

func evalInlineFunctionExpr(evalFn exprEvaluator, ctx context.Context, ec *evalContext, e InlineFunctionExpr) (xdm.Sequence, error) {
	// Capture current variable scope snapshot
	closedVars := ec.vars
	captured := *ec

	captured.invocation = nil
	captured.documentSnapshots = nil

	if provider, ok := ec.variableResolver.(VariableResolverSnapshotProvider); ok {
		// XPath 3.1 §3.1.7 captures nonlocal values at the definition site.
		// A host resolver can otherwise defer a private global until after the
		// producing transformation, recreating its nodes in every invocation.
		collector := staticRefCollector{bound: map[string]int{}, namespaces: ec.namespaces}

		definition := e
		if e.nonlocalBody != nil {
			definition.Body = e.nonlocalBody
		}

		collector.walkInlineFunction(definition)

		if err := fnCountOps(ctx, ec, max(collector.visits, 1)); err != nil {
			return nil, err
		}

		for _, name := range collector.freeVars {
			key := VariableKey(name, ec.namespaces)
			if _, exists := closedVars.Lookup(key); exists {
				continue
			}

			value, err := evalVariable(ctx, ec, VariableExpr{Name: name})
			if err != nil {
				return nil, err
			}

			closedVars = scopeWithBinding(closedVars, key, value)
		}

		captured.variableResolver = provider.SnapshotVariableResolver()
	}
	// Omitted annotations mean item()*, including in a mixed typed/untyped
	// parameter list. Preserve these defaults for function subtype checks.
	defaultType := stItem(xdm.OccurrenceZeroOrMore)
	paramTypes := make([]xdm.SequenceType, len(e.Params))

	for i, p := range e.Params {
		paramTypes[i] = defaultType

		if p.TypeHint != nil {
			bound, err := BindSequenceType(ctx, *p.TypeHint, ec.namespaces, ec.namespaces[""])
			if err != nil {
				return nil, err
			}

			paramTypes[i] = bound
		}
	}

	returnType := e.ReturnType
	if returnType == nil {
		returnType = &defaultType
	} else {
		bound, err := BindSequenceType(ctx, *returnType, ec.namespaces, ec.namespaces[""])
		if err != nil {
			return nil, err
		}

		returnType = &bound
	}

	fi := xdm.FunctionItem{
		Arity:      len(e.Params),
		ParamTypes: paramTypes,
		ReturnType: returnType,
		Invoke: func(ctx context.Context, args []xdm.Sequence) (xdm.Sequence, error) {
			return invokeInlineFunction(ctx, args, &captured, closedVars, e, evalFn)
		},
	}

	return xdm.ItemSlice{fi}, nil
}

func partialApply(ctx context.Context, ec *evalContext, e FunctionCall, fixedArgs []xdm.Sequence) (xdm.Sequence, error) {
	// Count placeholders to determine new arity
	var placeholderIndices []int

	for i, argExpr := range e.Args {
		if _, ok := argExpr.(PlaceholderExpr); ok {
			placeholderIndices = append(placeholderIndices, i)
		}
	}

	// Resolve the target function keeping its identity, so signature enforcement
	// keys off the resolved URI/local name and consults TypedFunction metadata —
	// mirroring evalFunctionCall. This closes the partial-application bypass where
	// a registered TypedFunction's parameter types went unenforced.
	r, err := resolveFunctionInfo(ctx, ec, e.Prefix, e.Name, len(e.Args))
	if err != nil {
		return nil, err
	}

	paramTypes, repeated := lookupParamTypes(ec, r, len(e.Args))

	// Coerce the fixed (curried) arguments now, before the placeholders are
	// supplied: they are known at partial-application time, so the function body
	// must observe the converted values (e.g. xs:integer→xs:double) just like a
	// direct call.
	coercedFixed := make([]xdm.Sequence, len(fixedArgs))
	copy(coercedFixed, fixedArgs)

	if paramTypes != nil {
		if err := partialApplyArgs(ctx, &e, paramTypes, repeated, fixedArgs, &r, ec, coercedFixed); err != nil {
			return nil, err
		}
	}

	r.fn = bindFunctionReference(r.fn)
	if provider, ok := r.fn.(DynamicRefSnapshotProvider); ok {
		if item, captured := provider.DynamicRefSnapshot(ctx, len(e.Args)); captured {
			return partialFunctionItem(item, coercedFixed, placeholderIndices), nil
		}
	}

	captured := *ec
	captured.invocation = nil
	captured.documentSnapshots = nil

	// Per XPath 3.1, partial applications are anonymous functions
	partialTypes := partialParameterTypes(paramTypes, repeated, placeholderIndices)

	var returnType *xdm.SequenceType
	if signature := resolvedFunctionSignature(ec, r, len(e.Args)); signature != nil {
		returnType = signature.ReturnType
		if paramTypes == nil {
			partialTypes = partialParameterTypes(signature.ParamTypes, signature.RepeatParamType, placeholderIndices)
		}
	}

	fi := xdm.FunctionItem{
		Arity:      len(placeholderIndices),
		ParamTypes: partialTypes, ReturnType: returnType,
		Invoke: func(ctx context.Context, partialArgs []xdm.Sequence) (xdm.Sequence, error) {
			ctx = withDynamicCall(ctx)
			callEC := calleeContext(ctx, &captured)
			ctx = withFnContext(ctx, callEC)

			if len(partialArgs) != len(placeholderIndices) {
				return nil, &xdm.Error{
					Code:    lexicon.ErrXPTY0004,
					Message: fmt.Sprintf("arity mismatch in partial application: expected %d arguments, got %d", len(placeholderIndices), len(partialArgs)),
				}
			}

			fullArgs := make([]xdm.Sequence, len(e.Args))
			copy(fullArgs, coercedFixed)

			for pi, idx := range placeholderIndices {
				fullArgs[idx] = partialArgs[pi]
			}
			// Coerce the placeholder-supplied arguments against the declared
			// parameter types and store the converted values back, mirroring
			// evalFunctionCall so typed functions observe promoted values and
			// typed errors (FOTY0013/FORG0001) propagate unchanged.
			if paramTypes != nil {
				for _, idx := range placeholderIndices {
					parameter, declared := xdm.FunctionParameterType(paramTypes, repeated, idx)
					if !declared {
						continue
					}

					coerced, err := coerceFuncallArg(ctx, fullArgs[idx], parameter, r.name, idx, callEC)
					if err != nil {
						return nil, err
					}

					fullArgs[idx] = coerced
				}
			}

			return r.fn.Call(ctx, fullArgs)
		},
	}

	return xdm.ItemSlice{fi}, nil
}

// coerceFuncallArg coerces one argument against its declared parameter type,
// translating the result into the funcall-enforcement error contract: a typed
// atomization/cast error (FOTY0013, FORG0001, …) surfaces unchanged so try/catch
// can dispatch on it; a plain type/cardinality mismatch becomes XPTY0004. This is
// the shared helper for evalFunctionCall's direct path and partialApply.
func coerceFuncallArg(ctx context.Context, arg xdm.Sequence, st xdm.SequenceType, fnName string, idx int, ec *evalContext) (xdm.Sequence, error) {
	coerced, err := coerceToSequenceTypeE(ctx, arg, st, ec)
	if err != nil {
		if !errors.Is(err, errCoerceMismatch) {
			return nil, err
		}

		message := fmt.Sprintf("fn:%s: argument %d does not match required type %v", fnName, idx+1, st)

		if xdm.SequenceLen(arg) == 1 {
			if actual, atomic := arg.Get(0).(xdm.AtomicValue); atomic {
				message += "; got " + actual.TypeName
			}
		}

		return nil, &xdm.Error{Code: lexicon.ErrXPTY0004, Message: message}
	}

	return coerced, nil
}

func evalMapConstructorExpr(evalFn exprEvaluator, ctx context.Context, ec *evalContext, e MapConstructorExpr) (xdm.Sequence, error) {
	maxNodes := ec.maxNodes
	entries := make([]xdm.MapEntry, 0, len(e.Pairs))

	seen := make(map[xdm.MapKey]struct{}, len(e.Pairs))
	for _, pair := range e.Pairs {
		keySeq, err := evalFn(ctx, ec, pair.Key)
		if err != nil {
			return nil, err
		}

		var keyAtoms []xdm.AtomicValue

		if err := atomizeBounded(ctx, ec, keySeq, func(atom xdm.AtomicValue) (bool, error) {
			keyAtoms = append(keyAtoms, atom)
			return len(keyAtoms) < 2, nil
		}); err != nil {
			return nil, err
		}

		if len(keyAtoms) != 1 {
			return nil, &xdm.Error{Code: lexicon.ErrXPTY0004, Message: "map key must atomize to a single atomic value"}
		}

		ka := keyAtoms[0]
		// Per XPath 3.1, duplicate keys in a map constructor raise XQDY0137
		nk := xdm.NormalizeMapKey(ka)
		if _, dup := seen[nk]; dup {
			return nil, &xdm.Error{Code: "XQDY0137", Message: fmt.Sprintf("duplicate key in map constructor: %v", ka.Value)}
		}

		seen[nk] = struct{}{}

		valSeq, err := evalFn(ctx, ec, pair.Value)
		if err != nil {
			return nil, err
		}
		// NewMap clones every value (materializing it), so bound the value length
		// against maxNodes and charge its length (min 1) of ops — honoring
		// OpLimit / context cancellation — BEFORE storing the entry. A huge/lazy
		// value is rejected here via the O(1) seqLen check instead of OOMing the
		// engine when NewMap materializes it.
		vLen := xdm.SequenceLen(valSeq)
		if maxNodes > 0 && vLen > maxNodes {
			return nil, ErrNodeSetLimit
		}

		if err := fnCountOps(ctx, ec, max(vLen, 1)); err != nil {
			return nil, err
		}

		entries = append(entries, xdm.MapEntry{Key: ka, Value: valSeq})
	}

	return xdm.ItemSlice{xdm.NewMap(entries)}, nil
}

func evalArrayConstructorExpr(evalFn exprEvaluator, ctx context.Context, ec *evalContext, e ArrayConstructorExpr) (xdm.Sequence, error) {
	maxNodes := ec.maxNodes

	if e.SquareBracket {
		// [a, b, c] — each expr is one member. appendArrayMember bounds both the
		// member count and the total item count (NewArray clones every member,
		// materializing it) and charges the per-member op cost, so a huge/lazy
		// member cannot OOM the engine or bypass OpLimit / context cancellation.
		var members []xdm.Sequence

		total := 0

		for _, item := range e.Items {
			seq, err := evalFn(ctx, ec, item)
			if err != nil {
				return nil, err
			}

			members, total, err = appendArrayMember(ctx, ec, maxNodes, members, total, seq)
			if err != nil {
				return nil, err
			}
		}

		return xdm.ItemSlice{xdm.NewArray(members)}, nil
	}
	// array { expr } — evaluate as sequence, each item is a singleton member.
	if len(e.Items) == 0 {
		return xdm.ItemSlice{xdm.NewArray(nil)}, nil
	}

	seq, err := evalFn(ctx, ec, e.Items[0])
	if err != nil {
		return nil, err
	}
	// Drain the source lazily and bound each appended member: a huge/lazy source
	// is rejected once the member count would exceed maxNodes (or OpLimit /
	// cancellation fires), materializing no whole structure up front.
	var members []xdm.Sequence

	total := 0
	for item := range xdm.SequenceItems(seq) {
		members, total, err = appendArrayMember(ctx, ec, maxNodes, members, total, xdm.ItemSlice{item})
		if err != nil {
			return nil, err
		}
	}

	return xdm.ItemSlice{xdm.NewArray(members)}, nil
}

// calleeContext preserves the captured static context/focus but borrows the
// caller's mutable work state and live resource policy. Returned function items
// can therefore be reused after their producing invocation ends, concurrently.
func calleeContext(ctx context.Context, captured *evalContext) *evalContext {
	local := *captured
	if caller := getFnContext(ctx); caller != nil {
		local.opCount, local.opLimit = caller.opCount, caller.opLimit
		local.depth, local.maxRecursionDepth = caller.depth, caller.maxRecursionDepth
		local.maxNodes = caller.maxNodes
		local.docOrder, local.docCache = caller.docOrder, caller.docCache
		local.documentSnapshots = caller.documentSnapshots
		local.invocation = caller.invocation
		local.uriResolver, local.collectionResolver = caller.uriResolver, caller.collectionResolver
		local.resourceReads = caller.resourceReads
		local.maxResourceBytes, local.parseOptions = caller.maxResourceBytes, caller.parseOptions
		local.traceWriter = caller.traceWriter
	} else {
		local.resourceReads = nil
		count := 0
		local.opCount = &count
		local.docCache = make(map[string]xdm.Node)
		local.documentSnapshots = &documentSnapshotStore{}
		local.invocation = &invocationState{}
	}

	return &local
}

func evalDynamicFunctionCallArgs(ctx context.Context, e *DynamicFunctionCall, evalFn exprEvaluator, ec *evalContext, args []xdm.Sequence) error {
	for i, argExpr := range e.Args {
		if _, ok := argExpr.(PlaceholderExpr); ok {
			continue
		}

		a, err := evalFn(ctx, ec, argExpr)
		if err != nil {
			return err
		}

		args[i] = enrichNodeItems(ctx, ec, a)
	}

	return nil
}

func partialApplyArgs(ctx context.Context, e *FunctionCall, paramTypes []xdm.SequenceType, repeated bool, fixedArgs []xdm.Sequence, r *resolvedFunction, ec *evalContext, coercedFixed []xdm.Sequence) error {
	for i, argExpr := range e.Args {
		if _, ok := argExpr.(PlaceholderExpr); ok {
			continue // placeholder slot: coerced at invocation time
		}

		parameter, declared := xdm.FunctionParameterType(paramTypes, repeated, i)
		if !declared {
			continue
		}

		coerced, err := coerceFuncallArg(ctx, fixedArgs[i], parameter, r.name, i, ec)
		if err != nil {
			return err
		}

		coercedFixed[i] = coerced
	}

	return nil
}

func invokeInlineFunction(ctx context.Context, args []xdm.Sequence, ec *evalContext, closedVars *variableScope, e InlineFunctionExpr, evalFn exprEvaluator) (xdm.Sequence, error) {
	ctx = withDynamicCall(ctx)

	if len(args) != len(e.Params) {
		return nil, &xdm.Error{Code: lexicon.ErrXPTY0004, Message: fmt.Sprintf("inline function requires %d arguments, got %d", len(e.Params), len(args))}
	}
	// Inline functions retain their static context while borrowing the caller's
	// live work/resource state, just like named and partially applied functions.
	innerCtx := *calleeContext(ctx, ec)
	innerCtx.node = nil
	innerCtx.contextItem = nil
	innerCtx.position = 0
	innerCtx.size = 0
	innerCtx.vars = closedVars
	ctx = withFnContext(ctx, &innerCtx)

	for i, param := range e.Params {
		arg := args[i]
		// Apply function coercion rules if type specified. Propagate a real
		// typed error (FOTY0012 from atomizing an element-only node, FOTY0013,
		// FORG0001, …) unchanged; map only a plain mismatch to XPTY0004.
		if param.TypeHint != nil {
			coerced, err := coerceToSequenceTypeE(ctx, arg, *param.TypeHint, &innerCtx)
			if err != nil && !errors.Is(err, errCoerceMismatch) {
				return nil, err
			}

			if err != nil {
				return nil, &xdm.Error{Code: lexicon.ErrXPTY0004, Message: fmt.Sprintf("inline function parameter $%s: value does not match required type %v", param.Name, *param.TypeHint)}
			}

			arg = coerced
		}

		innerCtx.vars = scopeWithBinding(innerCtx.vars, VariableKey(param.Name, innerCtx.namespaces), arg)
	}

	result, err := evalFn(ctx, &innerCtx, e.Body)
	if err != nil {
		return nil, err
	}
	// Apply function coercion rules for return type if specified. Propagate a
	// real typed error (FOTY0012 from atomizing an element-only node result,
	// FOTY0013, FORG0001, …); map only a plain mismatch to XPTY0004.
	if e.ReturnType != nil {
		coerced, err := coerceToSequenceTypeE(ctx, result, *e.ReturnType, &innerCtx)
		if err != nil && !errors.Is(err, errCoerceMismatch) {
			return nil, err
		}

		if err != nil {
			return nil, &xdm.Error{Code: lexicon.ErrXPTY0004, Message: fmt.Sprintf("inline function return value does not match required type %v", *e.ReturnType)}
		}

		result = coerced
	}

	return result, nil
}
