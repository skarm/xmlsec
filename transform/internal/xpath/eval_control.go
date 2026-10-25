// Derived from lestrrat-go/helium at 7362c0a70122a757780f4d0b545a9b370dead6ab.
// Copyright (c) 2015 lestrrat. MIT License; see licenses/MIT-helium.txt at the repository root.

package xpath

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"strings"

	"github.com/skarm/xmlsec/internal/lexicon"
	"github.com/skarm/xmlsec/transform/internal/xdm"
)

// checkedArrayIndex converts an xs:integer array index to int. An index outside
// the int range (above 2^31-1 where int is 32 bits) raises FOAY0001: no array
// has that many members, and converting it would wrap to a valid index.
func checkedArrayIndex(a xdm.AtomicValue) (int, error) {
	switch v := a.Value.(type) {
	case int64:
		return arrayIndexFromInt64(v)
	case *big.Int:
		if !v.IsInt64() {
			return 0, &xdm.Error{Code: lexicon.ErrFOAY0001, Message: textArrayIndexOutOfRange}
		}

		return arrayIndexFromInt64(v.Int64())
	default:
		return 0, &xdm.Error{Code: lexicon.ErrXPTY0004, Message: fmt.Sprintf("array lookup key must be xs:integer, got %s", a.TypeName)}
	}
}

func arrayIndexFromInt64(v int64) (int, error) {
	n := int(v)
	if int64(n) != v {
		return 0, &xdm.Error{Code: lexicon.ErrFOAY0001, Message: textArrayIndexOutOfRange}
	}

	return n, nil
}

func evalLookupExpr(evalFn exprEvaluator, ctx context.Context, ec *evalContext, e LookupExpr) (xdm.Sequence, error) {
	base, err := evalFn(ctx, ec, e.Expr)
	if err != nil {
		return nil, err
	}

	var result xdm.ItemSlice

	for item := range xdm.SequenceItems(base) {
		r, err := lookupItem(evalFn, ctx, ec, item, e.Key, e.All)
		if err != nil {
			return nil, err
		}
		// lookupItem already bounds its internal accumulation; bound the
		// cross-item concatenation here too so the running total is enforced.
		result, err = appendBounded(result, xdm.Materialize(r), ec.maxNodes)
		if err != nil {
			return nil, err
		}
	}

	return result, nil
}

func evalUnaryLookupExpr(evalFn exprEvaluator, ctx context.Context, ec *evalContext, e UnaryLookupExpr) (xdm.Sequence, error) {
	if ec.contextItem != nil {
		return lookupItem(evalFn, ctx, ec, ec.contextItem, e.Key, e.All)
	}

	if ec.node == nil {
		return nil, &xdm.Error{Code: lexicon.ErrXPDY0002, Message: errMsgContextItemAbsent}
	}

	return lookupItem(evalFn, ctx, ec, xdm.NodeItem{Node: ec.node}, e.Key, e.All)
}

// lookupItem evaluates a `?` lookup against a single map or array item. It
// enforces ec.maxNodes on every accumulating branch (map/array all-values and
// keyed lookups), so both unary (`evalUnaryLookupExpr`) and postfix
// (`evalLookupExpr`) lookups bound their output through this single helper.
func lookupItem(evalFn exprEvaluator, ctx context.Context, ec *evalContext, item xdm.Item, keyExpr Expr, all bool) (xdm.Sequence, error) {
	switch v := item.(type) {
	case xdm.MapItem:
		if all {
			var (
				result   xdm.ItemSlice
				boundErr error
			)
			// Bounded internal walk: iterate the stored values in place without
			// cloning (mirroring the get0/entries0 walkers) so a borrowed lazy
			// value is bound-checked, and never eagerly cloned.
			// appendBoundedClonedSeq drains each value lazily, enforcing maxNodes
			// (and OpLimit / cancellation) BEFORE the value is materialized — so a
			// lazy value whose Materialize is unbounded/panics trips the bound
			// first — and appends a defensive clone of each item so mutating the
			// `?*` output cannot reach the source map's stored values.
			_ = v.ForEachView(func(_ xdm.AtomicValue, val xdm.Sequence) error {
				result, boundErr = appendBoundedClonedSeq(ctx, ec, result, val, ec.maxNodes)
				return boundErr
			})

			if boundErr != nil {
				return nil, boundErr
			}

			return result, nil
		}

		keySeq, err := evalFn(ctx, ec, keyExpr)
		if err != nil {
			return nil, err
		}

		if xdm.SequenceLen(keySeq) == 0 {
			return nil, nil
		}

		var result xdm.ItemSlice

		keys, err := FnAtomize(ctx, keySeq)
		if err != nil {
			return nil, err
		}

		for _, ka := range keys {
			// Use get0 to borrow the stored value WITHOUT cloning, then drain it
			// through appendBoundedClonedSeq so maxNodes / OpLimit / cancellation
			// fire BEFORE the value is materialized (public Get deep-clones by
			// materializing eagerly, defeating the bound for a borrowed lazy
			// value). Cloning each appended item keeps value semantics.
			val, ok := v.GetView(ka)
			if !ok {
				continue
			}

			result, err = appendBoundedClonedSeq(ctx, ec, result, val, ec.maxNodes)
			if err != nil {
				return nil, err
			}
		}

		return result, nil
	case xdm.ArrayItem:
		return lookupItemArrayItem(ctx, all, &v, ec, evalFn, keyExpr)
	default:
		return nil, &xdm.Error{Code: lexicon.ErrXPTY0004, Message: fmt.Sprintf("lookup requires map or array, got %T", item)}
	}
}

type tupleConsumerFunc func(scope *variableScope) error

func (f tupleConsumerFunc) ConsumeTuple(scope *variableScope) error {
	return f(scope)
}

func evalFLWOR(evalFn exprEvaluator, ctx context.Context, ec *evalContext, e FLWORExpr) (xdm.Sequence, error) {
	var result xdm.ItemSlice

	consumer := tupleConsumerFunc(func(scope *variableScope) error {
		oldScope := ec.pushScope(scope)
		r, err := evalFn(ctx, ec, e.Return)
		ec.restoreScope(oldScope)

		if err != nil {
			return err
		}
		// Accumulate the return sequence lazily so the aggregate maxNodes /
		// OpLimit / cancellation bound is enforced item-by-item BEFORE the whole
		// per-tuple sub-sequence is materialized — a return expression bound to a
		// large lazy Sequence (e.g. a borrowed range variable) is rejected without
		// first materializing it in full, matching evalSimpleMapExpr.
		result, err = appendBoundedSeq(ctx, ec, result, r, ec.maxNodes)
		if err != nil {
			return err
		}

		return nil
	})

	if err := iterateFLWORClauses(evalFn, ctx, ec, e.Clauses, 0, ec.vars, consumer); err != nil {
		return nil, err
	}

	return result, nil
}

// tupleConsumer receives completed variable scopes from the FLWOR clause
// pipeline. Each call to ConsumeTuple represents one binding tuple that
// has passed through all clauses.
type tupleConsumer interface {
	ConsumeTuple(scope *variableScope) error
}

// iterateFLWORClauses processes clauses[i..] recursively, streaming each
// completed scope to the consumer instead of materializing all tuples.
func iterateFLWORClauses(evalFn exprEvaluator, ctx context.Context, ec *evalContext, clauses []FLWORClause, i int, scope *variableScope, consumer tupleConsumer) error {
	if i >= len(clauses) {
		return consumer.ConsumeTuple(scope)
	}

	if err := ec.countOps(ctx, 1); err != nil {
		return err
	}

	switch c := clauses[i].(type) {
	case ForClause:
		oldScope := ec.pushScope(scope)
		domain, err := evalFn(ctx, ec, c.Expr)
		ec.restoreScope(oldScope)

		if err != nil {
			return err
		}

		pos := 0

		for item := range xdm.SequenceItems(domain) {
			inner := scopeWithBinding(scope, VariableKey(c.Var, ec.namespaces), xdm.ItemSlice{item})
			if c.PosVar != "" {
				inner = scopeWithBinding(inner, VariableKey(c.PosVar, ec.namespaces), xdm.ItemSlice{xdm.AtomicValue{TypeName: xdm.TypeInteger, Value: int64(pos + 1)}})
			}

			if err := iterateFLWORClauses(evalFn, ctx, ec, clauses, i+1, inner, consumer); err != nil {
				return err
			}

			pos++
		}

		return nil

	case LetClause:
		oldScope := ec.pushScope(scope)
		val, err := evalFn(ctx, ec, c.Expr)
		ec.restoreScope(oldScope)

		if err != nil {
			return err
		}

		inner := scopeWithBinding(scope, VariableKey(c.Var, ec.namespaces), val)

		return iterateFLWORClauses(evalFn, ctx, ec, clauses, i+1, inner, consumer)

	default:
		return iterateFLWORClauses(evalFn, ctx, ec, clauses, i+1, scope, consumer)
	}
}

func evalQuantifiedExpr(evalFn exprEvaluator, ctx context.Context, ec *evalContext, e QuantifiedExpr) (xdm.Sequence, error) {
	return evalQuantifiedBindings(evalFn, ctx, ec, e, 0)
}

func evalQuantifiedBindings(evalFn exprEvaluator, ctx context.Context, ec *evalContext, e QuantifiedExpr, idx int) (xdm.Sequence, error) {
	if idx >= len(e.Bindings) {
		// All bindings bound — evaluate satisfies
		r, err := evalFn(ctx, ec, e.Satisfies)
		if err != nil {
			return nil, err
		}

		b, err := EBV(r)
		if err != nil {
			return nil, err
		}

		return xdm.SingleBoolean(b), nil
	}

	binding := e.Bindings[idx]

	domain, err := evalFn(ctx, ec, binding.Domain)
	if err != nil {
		return nil, err
	}

	for item := range xdm.SequenceItems(domain) {
		oldScope := ec.pushScope(scopeWithBinding(ec.vars, VariableKey(binding.Var, ec.namespaces), xdm.ItemSlice{item}))
		result, err := evalQuantifiedBindings(evalFn, ctx, ec, e, idx+1)
		ec.restoreScope(oldScope)

		if err != nil {
			return nil, err
		}

		b, err := EBV(result)
		if err != nil {
			return nil, err
		}

		if e.Some && b {
			return xdm.SingleBoolean(true), nil
		}

		if !e.Some && !b {
			return xdm.SingleBoolean(false), nil
		}
	}

	if e.Some {
		return xdm.SingleBoolean(false), nil
	}

	return xdm.SingleBoolean(true), nil
}

func evalIfExpr(evalFn exprEvaluator, ctx context.Context, ec *evalContext, e IfExpr) (xdm.Sequence, error) {
	cond, err := evalFn(ctx, ec, e.Cond)
	if err != nil {
		return nil, err
	}

	b, err := EBV(cond)
	if err != nil {
		return nil, err
	}

	if b {
		return evalFn(ctx, ec, e.Then)
	}

	return evalFn(ctx, ec, e.Else)
}

func evalTryCatchExpr(evalFn exprEvaluator, ctx context.Context, ec *evalContext, e TryCatchExpr) (xdm.Sequence, error) {
	result, err := evalFn(ctx, ec, e.Try)
	if err == nil {
		return result, nil
	}

	xpErr, ok := errors.AsType[*xdm.Error](err)
	if !ok {
		return nil, err // non-XPath errors propagate through
	}

	for _, catch := range e.Catches {
		if catchMatchesError(catch, xpErr) {
			return evalFn(ctx, buildCatchContext(ec, xpErr), catch.Expr)
		}
	}

	return nil, err // no matching catch
}

func catchMatchesError(catch CatchClause, xpErr *xdm.Error) bool {
	if len(catch.Codes) == 0 {
		return true // wildcard catch (*)
	}

	errQName := xpErr.CodeQName()
	for _, code := range catch.Codes {
		if catchCodeMatches(code, errQName) {
			return true
		}
	}

	return false
}

// catchCodeMatches compares a catch clause code against an XPath error QName.
// The catch code may be:
//   - "*" — matches anything
//   - "err:FOAR0002" or "FOAR0002" — matches specific error code
//   - "err:*" — matches any code in the err namespace (all XPath errors)
//   - "*:FOAR0002" — matches any namespace with that local name
//   - "Q{http://...}FOAR0002" — matches by URI + local name
//   - "Q{http://...}*" — matches any code in that namespace
func catchCodeMatches(catchCode string, errQName xdm.QNameValue) bool {
	if catchCode == "*" {
		return true
	}

	// Handle Q{uri}local and Q{uri}*
	if strings.HasPrefix(catchCode, "Q{") {
		if idx := strings.Index(catchCode, "}"); idx >= 0 {
			uri := catchCode[2:idx]

			local := catchCode[idx+1:]
			if local == "*" {
				return errQName.URI == uri
			}

			return errQName.URI == uri && errQName.Local == local
		}
	}

	catchLocal := catchCode

	catchPrefix := ""
	if p, l, ok := strings.Cut(catchCode, ":"); ok {
		catchPrefix = p
		catchLocal = l
	}

	// Wildcard forms
	if catchLocal == "*" {
		// prefix:* — for err:*, matches all XPath errors
		return catchPrefix == "" || (catchPrefix == lexicon.PrefixErr && errQName.URI == NSErr)
	}

	if catchPrefix == "*" {
		return catchLocal == errQName.Local // *:CODE matches the bare code
	}

	if catchPrefix == lexicon.PrefixErr {
		return errQName.URI == NSErr && catchLocal == errQName.Local
	}

	if catchPrefix != "" {
		return false
	}

	// Compare the local part of the catch code against the error code
	return catchLocal == errQName.Local
}

func buildCatchContext(ec *evalContext, xpErr *xdm.Error) *evalContext {
	errQName := xpErr.CodeQName()
	if errQName.Local == "" {
		errQName = xdm.QNameValue{Prefix: lexicon.PrefixErr, URI: NSErr, Local: errCodeFOER0000}
	}

	errQN := xdm.SingleAtomic(xdm.AtomicValue{
		TypeName: xdm.TypeQName,
		Value:    errQName,
	})
	ctx := ec.withVar("err:code", errQN)
	ctx = ctx.withVar("err:description", xdm.SingleString(xpErr.Message))
	ctx = ctx.withVar("err:value", xpErr.Value)
	ctx = ctx.withVar("err:module", nil)
	ctx = ctx.withVar("err:line-number", nil)
	ctx = ctx.withVar("err:column-number", nil)
	ctx = ctx.withVar("err:additional", nil)

	return ctx
}

func lookupItemArrayItem(ctx context.Context, all bool, v *xdm.ArrayItem, ec *evalContext, evalFn exprEvaluator, keyExpr Expr) (xdm.Sequence, error) {
	if all {
		var result xdm.ItemSlice
		// Borrow each stored member WITHOUT cloning (members0), then drain
		// it through appendBoundedClonedSeq so maxNodes / OpLimit /
		// cancellation fire BEFORE the member is materialized, and each
		// appended item is a defensive clone — so mutating the `?*` output
		// cannot reach the source array's pointer-backed atomics.
		for _, m := range v.MembersView() {
			var err error

			result, err = appendBoundedClonedSeq(ctx, ec, result, m, ec.maxNodes)
			if err != nil {
				return nil, err
			}
		}

		return result, nil
	}

	keySeq, err := evalFn(ctx, ec, keyExpr)
	if err != nil {
		return nil, err
	}

	if xdm.SequenceLen(keySeq) == 0 {
		return nil, nil
	}

	var result xdm.ItemSlice

	keys, err := FnAtomize(ctx, keySeq)
	if err != nil {
		return nil, err
	}

	for _, ka := range keys {
		if ka.TypeName == xdm.TypeUntypedAtomic {
			converted, err := CastAtomic(ka, xdm.TypeInteger)
			if err != nil {
				return nil, &xdm.Error{Code: lexicon.ErrXPTY0004, Message: fmt.Sprintf("array lookup key must be xs:integer, got %s", ka.TypeName), Cause: err}
			}

			ka = converted
		}

		if !xdm.IsIntegerDerived(ka.TypeName) {
			return nil, &xdm.Error{Code: lexicon.ErrXPTY0004, Message: fmt.Sprintf("array lookup key must be xs:integer, got %s", ka.TypeName)}
		}

		idx, err := checkedArrayIndex(ka)
		if err != nil {
			return nil, err
		}
		// Borrow the stored member WITHOUT cloning (get0), then drain it
		// through appendBoundedClonedSeq so maxNodes / OpLimit /
		// cancellation fire BEFORE the member is materialized, and each
		// appended item is a defensive clone — so mutating the keyed lookup
		// output cannot reach the source array's pointer-backed atomics.
		member, err := v.GetView(idx)
		if err != nil {
			return nil, err
		}

		result, err = appendBoundedClonedSeq(ctx, ec, result, member, ec.maxNodes)
		if err != nil {
			return nil, err
		}
	}

	return result, nil
}
