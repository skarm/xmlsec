// Derived from lestrrat-go/helium at 7362c0a70122a757780f4d0b545a9b370dead6ab.
// Copyright (c) 2015 lestrrat. MIT License; see licenses/MIT-helium.txt at the repository root.

package xpath

import (
	"context"
	"fmt"
	"math"
	"math/big"

	"github.com/skarm/xmlsec/transform/internal/xdm"
	"github.com/skarm/xmlsec/transform/internal/xdm/lexicon"
)

func evalArithmetic(evalFn exprEvaluator, ctx context.Context, ec *evalContext, e BinaryExpr) (xdm.Sequence, error) {
	left, err := evalFn(ctx, ec, e.Left)
	if err != nil {
		return nil, err
	}

	right, err := evalFn(ctx, ec, e.Right)
	if err != nil {
		return nil, err
	}
	// XPath 1.0 compatibility mode: each operand becomes xs:double (fn:number of
	// its FIRST item; empty or non-numeric → NaN), so division by zero yields ±INF
	// and there is no XPTY0004 for a >1 operand. The first-item rule is applied
	// BEFORE atomization, so a discarded later item that cannot be atomized does not
	// error. Reached only under XSLT backwards-compatible processing.
	if ec.xpath10CompatMode() {
		la, lerr := xpath10CompatNumberItem(left, ec)
		if lerr != nil {
			return nil, lerr
		}

		ra, rerr := xpath10CompatNumberItem(right, ec)
		if rerr != nil {
			return nil, rerr
		}

		return floatArith(e.Op, la, ra)
	}
	// Atomize THROUGH the stream (atomizeSingletonOperand) so a schema-typed node
	// whose typed value is a list/union expands; the single-operand cardinality is
	// then checked on the ATOMIZED result (a node atomizing to >1 value is an
	// XPTY0004), not the raw item count.
	lAtoms, err := atomizeSingletonOperand(left)
	if err != nil {
		return nil, err
	}

	rAtoms, err := atomizeSingletonOperand(right)
	if err != nil {
		return nil, err
	}

	if len(lAtoms) == 0 || len(rAtoms) == 0 {
		return nil, nil // empty sequence
	}

	if len(lAtoms) > 1 || len(rAtoms) > 1 {
		return nil, &xdm.Error{Code: lexicon.ErrXPTY0004, Message: "arithmetic operand must be a single item"}
	}

	la := lAtoms[0]
	ra := rAtoms[0]

	// Duration/date/time arithmetic — handle before numeric promotion.
	// Contract: evalDateTimeArithmetic returns handled==false only when both
	// operands are non-duration/non-datetime, in which case err is always nil.
	if result, handled, err := evalDateTimeArithmetic(ec, e.Op, la, ra); err != nil || handled {
		return result, err
	}

	// Promote xs:untypedAtomic to xs:double for arithmetic
	if la.TypeName == xdm.TypeUntypedAtomic {
		castVal, err := CastAtomic(la, xdm.TypeDouble)
		if err != nil {
			return nil, err
		}

		la = castVal
	}

	if ra.TypeName == xdm.TypeUntypedAtomic {
		castVal, err := CastAtomic(ra, xdm.TypeDouble)
		if err != nil {
			return nil, err
		}

		ra = castVal
	}

	// Both operands must be numeric after promotion
	if !la.IsNumeric() {
		return nil, &xdm.Error{Code: lexicon.ErrXPTY0004, Message: "arithmetic operand must be numeric, got " + la.TypeName}
	}

	if !ra.IsNumeric() {
		return nil, &xdm.Error{Code: lexicon.ErrXPTY0004, Message: "arithmetic operand must be numeric, got " + ra.TypeName}
	}

	// Promote user-defined schema types to their built-in numeric base.
	la = promoteSchemaNumeric(la)
	ra = promoteSchemaNumeric(ra)

	// Tier 1: both integer → try int64 fast path, fall back to big.Int
	if xdm.IsIntegerDerived(la.TypeName) && xdm.IsIntegerDerived(ra.TypeName) {
		lv, lok := la.Int64Val()

		rv, rok := ra.Int64Val()
		if lok && rok {
			return integerArithInt64(ctx, e.Op, lv, rv)
		}

		return integerArith(ctx, e.Op, la.BigInt(), ra.BigInt())
	}
	// Tier 2: either decimal (or integer promoted) → big.Rat arithmetic
	if needsDecimalArith(la.TypeName, ra.TypeName) {
		return decimalArith(ctx, e.Op, toRat(la), toRat(ra))
	}
	// Tier 3: float/double → float64 arithmetic
	return floatArith(e.Op, la, ra)
}

// promoteSchemaNumeric promotes a user-defined numeric type to its built-in base.
func promoteSchemaNumeric(a xdm.AtomicValue) xdm.AtomicValue {
	return xdm.PromoteSchemaType(a)
}

// integerArithInt64 performs integer arithmetic using int64 values.
// Falls back to big.Int on overflow.
func integerArithInt64(ctx context.Context, op TokenType, a, b int64) (xdm.Sequence, error) {
	switch op { //nolint:exhaustive
	case TokenPlus:
		r, ok := addInt64(a, b)
		if ok {
			return xdm.SingleInteger(r), nil
		}

		return integerArith(ctx, op, big.NewInt(a), big.NewInt(b))
	case TokenMinus:
		r, ok := subInt64(a, b)
		if ok {
			return xdm.SingleInteger(r), nil
		}

		return integerArith(ctx, op, big.NewInt(a), big.NewInt(b))
	case TokenStar:
		r, ok := mulInt64(a, b)
		if ok {
			return xdm.SingleInteger(r), nil
		}

		return integerArith(ctx, op, big.NewInt(a), big.NewInt(b))
	case TokenDiv:
		if b == 0 {
			return nil, &xdm.Error{Code: errCodeFOAR0001, Message: textDivisionByZero}
		}

		if err := preflightNumeric(ctx, int64Bits(a), int64Bits(b)); err != nil {
			return nil, err
		}

		r := new(big.Rat).SetFrac64(a, b)

		return xdm.SingleDecimal(r), nil
	case TokenIdiv:
		if b == 0 {
			return nil, &xdm.Error{Code: errCodeFOAR0001, Message: textIntegerDivisionByZero}
		}

		if a == math.MinInt64 && b == -1 {
			return integerArith(ctx, op, big.NewInt(a), big.NewInt(b))
		}

		return xdm.SingleInteger(a / b), nil
	case TokenMod:
		if b == 0 {
			return nil, &xdm.Error{Code: errCodeFOAR0001, Message: textModuloByZero}
		}

		return xdm.SingleInteger(a % b), nil
	default:
		return nil, &xdm.Error{Code: lexicon.ErrXPTY0004, Message: "unsupported integer arithmetic operator"}
	}
}

// addInt64 returns a+b and true if no overflow, or (0, false) on overflow.
func addInt64(a, b int64) (int64, bool) {
	r := a + b
	if (b > 0 && r < a) || (b < 0 && r > a) {
		return 0, false
	}

	return r, true
}

// subInt64 returns a-b and true if no overflow, or (0, false) on overflow.
func subInt64(a, b int64) (int64, bool) {
	r := a - b
	if (b > 0 && r > a) || (b < 0 && r < a) {
		return 0, false
	}

	return r, true
}

// mulInt64 returns a*b and true if no overflow, or (0, false) on overflow.
func mulInt64(a, b int64) (int64, bool) {
	if a == 0 || b == 0 {
		return 0, true
	}
	// Go's MinInt64 / -1 wraps to MinInt64, so the inverse division
	// check alone cannot detect this product in both operand orders.
	if a == -1 && b == math.MinInt64 || b == -1 && a == math.MinInt64 {
		return 0, false
	}

	r := a * b
	if r/a != b {
		return 0, false
	}

	return r, true
}

func integerArith(ctx context.Context, op TokenType, a, b *big.Int) (xdm.Sequence, error) {
	if err := preflightInteger(ctx, op, a, b); err != nil {
		return nil, err
	}

	result := new(big.Int)

	switch op { //nolint:exhaustive // only arithmetic operators are valid here; default handles the rest
	case TokenPlus:
		result.Add(a, b)
	case TokenMinus:
		result.Sub(a, b)
	case TokenStar:
		result.Mul(a, b)
	case TokenDiv:
		// integer / integer → decimal
		if b.Sign() == 0 {
			return nil, &xdm.Error{Code: errCodeFOAR0001, Message: textDivisionByZero}
		}

		r := new(big.Rat).SetFrac(new(big.Int).Set(a), new(big.Int).Set(b))

		return xdm.SingleDecimal(r), nil
	case TokenIdiv:
		if b.Sign() == 0 {
			return nil, &xdm.Error{Code: errCodeFOAR0001, Message: textIntegerDivisionByZero}
		}

		result.Quo(a, b) // truncates toward zero
	case TokenMod:
		if b.Sign() == 0 {
			return nil, &xdm.Error{Code: errCodeFOAR0001, Message: textModuloByZero}
		}

		result.Rem(a, b)
	default:
		return nil, &xdm.Error{Code: lexicon.ErrXPTY0004, Message: "unsupported integer arithmetic operator"}
	}

	return xdm.SingleIntegerBig(result), nil
}

func decimalArith(ctx context.Context, op TokenType, a, b *big.Rat) (xdm.Sequence, error) {
	if err := preflightDecimal(ctx, op, a, b); err != nil {
		return nil, err
	}

	result := new(big.Rat)

	switch op { //nolint:exhaustive // only arithmetic operators are valid here; default handles the rest
	case TokenPlus:
		result.Add(a, b)
	case TokenMinus:
		result.Sub(a, b)
	case TokenStar:
		result.Mul(a, b)
	case TokenDiv:
		if b.Sign() == 0 {
			return nil, &xdm.Error{Code: errCodeFOAR0001, Message: textDivisionByZero}
		}

		result.Quo(a, b)
	case TokenIdiv:
		if b.Sign() == 0 {
			return nil, &xdm.Error{Code: errCodeFOAR0001, Message: textIntegerDivisionByZero}
		}
		// Truncate quotient toward zero
		q := new(big.Rat).Quo(a, b)
		if err := ChargeNumber(ctx, xdm.AtomicValue{TypeName: xdm.TypeDecimal, Value: q}); err != nil {
			return nil, err
		}

		num := q.Num()

		den := q.Denom()
		if err := preflightInteger(ctx, TokenIdiv, num, den); err != nil {
			return nil, err
		}

		intPart := new(big.Int).Quo(num, den)

		return xdm.SingleIntegerBig(intPart), nil
	case TokenMod:
		if b.Sign() == 0 {
			return nil, &xdm.Error{Code: errCodeFOAR0001, Message: textModuloByZero}
		}
		// a mod b = a - (a idiv b) * b
		q := new(big.Rat).Quo(a, b)
		if err := ChargeNumber(ctx, xdm.AtomicValue{TypeName: xdm.TypeDecimal, Value: q}); err != nil {
			return nil, err
		}

		if err := preflightInteger(ctx, TokenIdiv, q.Num(), q.Denom()); err != nil {
			return nil, err
		}

		intPart := new(big.Int).Quo(q.Num(), q.Denom())
		if err := ChargeNumber(ctx, xdm.AtomicValue{TypeName: xdm.TypeInteger, Value: intPart}); err != nil {
			return nil, err
		}

		if err := preflightNumeric(ctx, intPart.BitLen(), 1); err != nil {
			return nil, err
		}

		qr := new(big.Rat).SetInt(intPart)
		if err := preflightDecimal(ctx, TokenStar, qr, b); err != nil {
			return nil, err
		}

		product := new(big.Rat).Mul(qr, b)
		if err := ChargeNumber(ctx, xdm.AtomicValue{TypeName: xdm.TypeDecimal, Value: product}); err != nil {
			return nil, err
		}

		if err := preflightDecimal(ctx, TokenMinus, a, product); err != nil {
			return nil, err
		}

		result.Sub(a, product)
	default:
		return nil, &xdm.Error{Code: lexicon.ErrXPTY0004, Message: "unsupported decimal arithmetic operator"}
	}

	return xdm.SingleDecimal(result), nil
}

func floatArith(op TokenType, la, ra xdm.AtomicValue) (xdm.Sequence, error) {
	// Guard: floatArith should only be called with float/double operands.
	// Integer and decimal operands are handled by integerArith/decimalArith.
	if !isFloatOrDouble(la.TypeName) && !isFloatOrDouble(ra.TypeName) {
		return nil, &xdm.Error{Code: lexicon.ErrXPTY0004, Message: fmt.Sprintf("unexpected types in float arithmetic: %s, %s", la.TypeName, ra.TypeName)}
	}

	ln := la.ToFloat64()
	rn := ra.ToFloat64()

	resultType := xdm.TypeDouble
	if la.TypeName != xdm.TypeDouble && ra.TypeName != xdm.TypeDouble {
		resultType = xdm.TypeFloat
	}

	var result float64

	switch op { //nolint:exhaustive // only arithmetic operators are valid here; default handles the rest
	case TokenPlus:
		result = ln + rn
	case TokenMinus:
		result = ln - rn
	case TokenStar:
		result = ln * rn
	case TokenDiv:
		result = ln / rn
	case TokenIdiv:
		if math.IsNaN(ln) || math.IsNaN(rn) {
			return nil, &xdm.Error{Code: errCodeFOAR0002, Message: "idiv with NaN"}
		}

		if rn == 0 {
			return nil, &xdm.Error{Code: errCodeFOAR0001, Message: textIntegerDivisionByZero}
		}

		if math.IsInf(ln, 0) {
			return nil, &xdm.Error{Code: errCodeFOAR0002, Message: "idiv with infinite dividend"}
		}
		// Per F&O §6.2.4: finite idiv ±INF = 0 (math.Trunc(finite/Inf) = 0).
		truncated := math.Trunc(ln / rn)

		bi, _ := new(big.Float).SetFloat64(truncated).Int(nil)
		if bi == nil {
			return nil, &xdm.Error{Code: errCodeFOAR0002, Message: "idiv quotient overflow"}
		}

		return xdm.SingleIntegerBig(bi), nil
	case TokenMod:
		result = math.Mod(ln, rn)
	default:
		return nil, &xdm.Error{Code: lexicon.ErrXPTY0004, Message: "unsupported float arithmetic operator"}
	}

	if resultType == xdm.TypeFloat {
		return xdm.SingleAtomic(xdm.AtomicValue{TypeName: xdm.TypeFloat, Value: xdm.NewFloat(result)}), nil
	}

	return xdm.SingleAtomic(xdm.AtomicValue{TypeName: xdm.TypeDouble, Value: xdm.NewDouble(result)}), nil
}

func evalUnaryExpr(evalFn exprEvaluator, ctx context.Context, ec *evalContext, e UnaryExpr) (xdm.Sequence, error) {
	r, err := evalFn(ctx, ec, e.Operand)
	if err != nil {
		return nil, err
	}
	// XPath 1.0 compatibility mode: the operand becomes xs:double (fn:number of its
	// FIRST item; empty or non-numeric → NaN), the first-item rule applied before
	// atomization. Reached only under XSLT backwards-compatible processing.
	if ec.xpath10CompatMode() {
		d, derr := xpath10CompatNumberItem(r, ec)
		if derr != nil {
			return nil, derr
		}

		if !e.Negate {
			return xdm.SingleAtomic(d), nil
		}

		return xdm.SingleAtomic(xdm.AtomicValue{TypeName: xdm.TypeDouble, Value: xdm.NewDouble(-d.ToFloat64())}), nil
	}
	// Atomize through the stream so a schema-typed list/union node expands; the
	// single-operand cardinality is checked on the atomized result.
	rAtoms, err := atomizeSingletonOperand(r)
	if err != nil {
		return nil, err
	}

	if len(rAtoms) == 0 {
		return nil, nil
	}

	if len(rAtoms) > 1 {
		return nil, &xdm.Error{Code: lexicon.ErrXPTY0004, Message: "unary minus operand must be a single item"}
	}

	a := rAtoms[0]
	// Promote xs:untypedAtomic to xs:double per XPath 3.1 spec
	if a.TypeName == xdm.TypeUntypedAtomic {
		castVal, err := CastAtomic(a, xdm.TypeDouble)
		if err != nil {
			return nil, err
		}

		a = castVal
	}
	// Promote schema-derived numerics (custom TypeName with a built-in numeric
	// BaseType) to their built-in base so the unary type check and negation
	// below operate on a recognized numeric type.
	a = xdm.PromoteSchemaType(a)
	if !e.Negate {
		// Unary plus: type check only, return value unchanged
		if !xdm.IsSubtypeOf(a.TypeName, xdm.TypeDecimal) && a.TypeName != xdm.TypeFloat && a.TypeName != xdm.TypeDouble {
			return nil, &xdm.Error{Code: lexicon.ErrXPTY0004, Message: "unary operator requires numeric type, got " + a.TypeName}
		}

		return xdm.SingleAtomic(a), nil
	}

	if xdm.IsIntegerDerived(a.TypeName) {
		if v, ok := a.Value.(int64); ok {
			if v != math.MinInt64 {
				return xdm.SingleInteger(-v), nil
			}
			// MinInt64 overflows on negation; fall through to big.Int
		}

		return xdm.SingleIntegerBig(new(big.Int).Neg(a.BigInt())), nil
	}

	if a.TypeName == xdm.TypeDecimal {
		return xdm.SingleDecimal(new(big.Rat).Neg(a.BigRat())), nil
	}

	if a.TypeName == xdm.TypeFloat {
		return xdm.SingleAtomic(xdm.AtomicValue{TypeName: xdm.TypeFloat, Value: a.FloatVal().Neg()}), nil
	}

	if a.TypeName == xdm.TypeDouble {
		return xdm.SingleAtomic(xdm.AtomicValue{TypeName: xdm.TypeDouble, Value: a.FloatVal().Neg()}), nil
	}

	return nil, &xdm.Error{Code: lexicon.ErrXPTY0004, Message: "unary operator requires numeric type, got " + a.TypeName}
}

func needsDecimalArith(lt, rt string) bool {
	lDec := lt == xdm.TypeDecimal || xdm.IsIntegerDerived(lt)

	rDec := rt == xdm.TypeDecimal || xdm.IsIntegerDerived(rt)
	if !lDec || !rDec {
		return false
	}
	// At least one must be decimal (not both integer — that's tier 1)
	return lt == xdm.TypeDecimal || rt == xdm.TypeDecimal
}

func toRat(a xdm.AtomicValue) *big.Rat {
	if xdm.IsIntegerDerived(a.TypeName) {
		if v, ok := a.Value.(int64); ok {
			return new(big.Rat).SetInt64(v)
		}

		return new(big.Rat).SetInt(a.BigInt())
	}

	return a.BigRat()
}
