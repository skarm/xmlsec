// Derived from lestrrat-go/helium at 7362c0a70122a757780f4d0b545a9b370dead6ab.
// Copyright (c) 2015 lestrrat. MIT License; see licenses/MIT-helium.txt at the repository root.

package xpath

import (
	"context"
	"math"
	"math/big"

	"github.com/skarm/xmlsec/transform/internal/xdm"
)

func lookupFunctionsMath(name string) (*builtinFunc, bool) {
	switch name {
	case "pi":
		return &builtinFunc{name: name, min: 0, max: 0, fn: fnMathPi}, true
	case "exp":
		return &builtinFunc{name: name, min: 1, max: 1, fn: fnMathExp}, true
	case "exp10":
		return &builtinFunc{name: name, min: 1, max: 1, fn: fnMathExp10}, true
	case "log":
		return &builtinFunc{name: name, min: 1, max: 1, fn: fnMathLog}, true
	case "log10":
		return &builtinFunc{name: name, min: 1, max: 1, fn: fnMathLog10}, true
	case "pow":
		return &builtinFunc{name: name, min: 2, max: 2, fn: fnMathPow}, true
	case "sqrt":
		return &builtinFunc{name: name, min: 1, max: 1, fn: fnMathSqrt}, true
	case "sin":
		return &builtinFunc{name: name, min: 1, max: 1, fn: fnMathSin}, true
	case "cos":
		return &builtinFunc{name: name, min: 1, max: 1, fn: fnMathCos}, true
	case "tan":
		return &builtinFunc{name: name, min: 1, max: 1, fn: fnMathTan}, true
	case "asin":
		return &builtinFunc{name: name, min: 1, max: 1, fn: fnMathAsin}, true
	case "acos":
		return &builtinFunc{name: name, min: 1, max: 1, fn: fnMathAcos}, true
	case "atan":
		return &builtinFunc{name: name, min: 1, max: 1, fn: fnMathAtan}, true
	case "atan2":
		return &builtinFunc{name: name, min: 2, max: 2, fn: fnMathAtan2}, true
	}

	return nil, false
}

func fnMathPi(_ context.Context, _ []xdm.Sequence) (xdm.Sequence, error) {
	return xdm.SingleDouble(math.Pi), nil
}

// coerceMathArg coerces an xs:double? math argument. Empty sequences yield
// (0, false, nil) so the caller can return an empty result; otherwise the
// argument is required to be a single numeric/untypedAtomic item, rejecting
// multi-item and non-numeric values with XPTY0004.
func coerceMathArg(ctx context.Context, seq xdm.Sequence) (float64, bool, error) {
	if xdm.SequenceLen(seq) == 0 {
		return 0, false, nil
	}

	f, err := coerceArgToDoubleRequired(ctx, seq)
	if err != nil {
		return 0, false, err
	}

	return f, true, nil
}

func mathUnary(ctx context.Context, args []xdm.Sequence, fn func(float64) float64) (xdm.Sequence, error) {
	a, ok, err := coerceMathArg(ctx, args[0])
	if err != nil {
		return nil, err
	}

	if !ok {
		return nil, nil
	}

	return xdm.SingleDouble(fn(a)), nil
}

func fnMathExp(ctx context.Context, args []xdm.Sequence) (xdm.Sequence, error) {
	return mathUnary(ctx, args, math.Exp)
}

func fnMathExp10(ctx context.Context, args []xdm.Sequence) (xdm.Sequence, error) {
	return mathUnary(ctx, args, func(x float64) float64 { return math.Pow(10, x) })
}

func fnMathLog(ctx context.Context, args []xdm.Sequence) (xdm.Sequence, error) {
	return mathUnary(ctx, args, math.Log)
}

func fnMathLog10(ctx context.Context, args []xdm.Sequence) (xdm.Sequence, error) {
	return mathUnary(ctx, args, math.Log10)
}

func fnMathPow(ctx context.Context, args []xdm.Sequence) (xdm.Sequence, error) {
	// math:pow($x as xs:double?, $y as xs:numeric): empty $x yields empty, but
	// only once $y has been validated. $y is a required single numeric value,
	// so a malformed or empty $y must raise XPTY0004 even when $x is empty —
	// function-conversion validates each argument independently of the others.
	b, err := coerceArgToDoubleRequired(ctx, args[1])
	if err != nil {
		return nil, err
	}

	a, aOK, err := coerceMathArg(ctx, args[0])
	if err != nil {
		return nil, err
	}

	if !aOK {
		return nil, nil
	}

	exponent, err := promoteToNumeric(args[1].Get(0))
	if err != nil {
		return nil, err
	}

	if xdm.IsIntegerDerived(exponent.TypeName) {
		result, err := mathIntegerPower(ctx, a, exponent.BigInt())
		if err != nil {
			return nil, err
		}

		return xdm.SingleDouble(result), nil
	}

	return xdm.SingleDouble(math.Pow(a, b)), nil
}

// mathIntegerPower implements the integer-exponent pown operation required by
// F&O 4.8.6 without first rounding the exponent to xs:double. The wider working
// precision also avoids accumulating binary64 rounding at every multiplication.
func mathIntegerPower(ctx context.Context, base float64, exponent *big.Int) (float64, error) {
	if err := fnCountOp(ctx, getFnContext(ctx)); err != nil {
		return 0, err
	}

	if exponent.Sign() == 0 {
		return 1, nil
	}

	negative := math.Signbit(base) && exponent.Bit(0) != 0
	if math.IsNaN(base) {
		return math.NaN(), nil
	}

	if base == 0 || math.IsInf(base, 0) || math.Abs(base) == 1 {
		surrogate := 2.0
		if negative {
			surrogate = 1
		}

		if exponent.Sign() < 0 {
			surrogate = -surrogate
		}

		return math.Pow(base, surrogate), nil
	}

	if err := preflightNumeric(ctx, exponent.BitLen(), 256); err != nil {
		return 0, err
	}

	magnitude := new(big.Int).Abs(exponent)
	factor := new(big.Float).SetPrec(256).SetFloat64(math.Abs(base))
	result := new(big.Float).SetPrec(256).SetInt64(1)

	if exponent.Sign() < 0 {
		factor.Quo(result, factor)
	}

	for bit := magnitude.BitLen() - 1; bit >= 0; bit-- {
		if err := fnCountOp(ctx, getFnContext(ctx)); err != nil {
			return 0, err
		}

		result.Mul(result, result)

		if magnitude.Bit(bit) != 0 {
			result.Mul(result, factor)
		}

		value, _ := result.Float64()
		if value == 0 || math.IsInf(value, 0) || bit == 0 {
			if negative {
				value = -value
			}

			return value, nil
		}
	}

	return 1, nil
}

func fnMathSqrt(ctx context.Context, args []xdm.Sequence) (xdm.Sequence, error) {
	return mathUnary(ctx, args, math.Sqrt)
}

func fnMathSin(ctx context.Context, args []xdm.Sequence) (xdm.Sequence, error) {
	return mathUnary(ctx, args, math.Sin)
}

func fnMathCos(ctx context.Context, args []xdm.Sequence) (xdm.Sequence, error) {
	return mathUnary(ctx, args, math.Cos)
}

func fnMathTan(ctx context.Context, args []xdm.Sequence) (xdm.Sequence, error) {
	return mathUnary(ctx, args, math.Tan)
}

func fnMathAsin(ctx context.Context, args []xdm.Sequence) (xdm.Sequence, error) {
	return mathUnary(ctx, args, math.Asin)
}

func fnMathAcos(ctx context.Context, args []xdm.Sequence) (xdm.Sequence, error) {
	return mathUnary(ctx, args, math.Acos)
}

func fnMathAtan(ctx context.Context, args []xdm.Sequence) (xdm.Sequence, error) {
	return mathUnary(ctx, args, math.Atan)
}

func fnMathAtan2(ctx context.Context, args []xdm.Sequence) (xdm.Sequence, error) {
	// math:atan2($y as xs:double, $x as xs:double): both required, exactly one
	// numeric value each.
	a, err := coerceArgToDoubleRequired(ctx, args[0])
	if err != nil {
		return nil, err
	}

	b, err := coerceArgToDoubleRequired(ctx, args[1])
	if err != nil {
		return nil, err
	}

	return xdm.SingleDouble(math.Atan2(a, b)), nil
}
