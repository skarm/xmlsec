package xpath

import (
	"context"
	"math"
	"math/big"
	"math/bits"
	"strconv"
	"strings"

	"github.com/skarm/xmlsec/internal/lexicon"
	"github.com/skarm/xmlsec/transform/internal/xdm"
)

// Representation sizes count magnitude bytes, with a one-byte minimum per
// integer component. IEEE storage sizes stay separate from accounting quanta:
// numeric work charges per eight BYTES, while preflight words contain 64 BITS.
// These are logical representation costs, not measured Go allocation sizes.
const (
	bitsPerByte               = 8
	minimumNumericBytes       = 1
	singleNumericStorageBytes = 4
	doubleNumericStorageBytes = 8
	numericChargeBytes        = 8
	minimumNumericWork        = 1
	numericWorkWordBits       = 64
	minimumPreflightWords     = 1
	constructedDurationWork   = 1
	additionCarryBits         = 1
	numericDecimalRadix       = 10
	numericParseBits          = 64
)

// Numeric preflight retains its rational upper estimate 3322/1000 for log2(10),
// ceiling offset and independent overflow margin. Round temporaries keep their
// existing spare-bit bounds; a binary64 subnormal denominator can need 1075 bits.
const (
	decimalBitEstimateNumerator    = 3322
	decimalBitEstimateDenominator  = 1000
	decimalBitCeilOffset           = 999
	numericLexicalOverflowMargin   = 1000
	decimalPowerExtraBits          = 1
	decimalRoundSpareBits          = 3
	integerRoundSpareBits          = 1
	minimumRationalDenominatorBits = 1
	invalidNumericBitCount         = -1
	doubleRationalMarginBits       = xdm.PrecisionDouble + 1
	doubleMaxRationalComponentBits = 1075
)

// NumericSize measures unsigned binary magnitudes, with at least one byte per
// integer component (including zero). Decimals count numerator AND denominator;
// IEEE float/double values count four/eight bytes. It never formats a number.
func NumericSize(value xdm.AtomicValue) (int, bool) {
	value = xdm.PromoteSchemaType(value)
	if xdm.IsIntegerDerived(value.TypeName) {
		if n, ok := value.Value.(int64); ok {
			return magnitudeBytes(int64Bits(n)), true
		}

		return magnitudeBytes(value.BigInt().BitLen()), true
	}

	switch value.TypeName {
	case xdm.TypeDecimal:
		r := value.BigRat()
		return magnitudeBytes(r.Num().BitLen()) + magnitudeBytes(r.Denom().BitLen()), true
	case xdm.TypeFloat:
		return singleNumericStorageBytes, true
	case xdm.TypeDouble:
		return doubleNumericStorageBytes, true
	}

	return 0, false
}

// ChargeNumber counts an evaluated numeric occurrence or an arithmetic
// temporary against the same cumulative bytes as strings and constructed trees.
func ChargeNumber(ctx context.Context, value xdm.AtomicValue) error {
	n, numeric := NumericSize(value)
	if !numeric {
		return ctx.Err()
	}

	if err := Charge(ctx, max(minimumNumericWork, n/numericChargeBytes)); err != nil {
		return err
	}

	return ChargeString(ctx, n)
}

// CastAtomicContext applies invocation limits before exact numeric conversion.
// CastAtomic remains available for public value constructors outside an engine.
func CastAtomicContext(ctx context.Context, value xdm.AtomicValue, target string) (xdm.AtomicValue, error) {
	if err := ctx.Err(); err != nil {
		return xdm.AtomicValue{}, err
	}

	if target == xdm.TypeDecimal || xdm.IsIntegerDerived(target) {
		source := normalizeCastSource(value)

		var err error

		switch {
		case source.TypeName == xdm.TypeUntypedAtomic || xdm.IsStringDerived(source.TypeName):
			err = preflightNumericLexical(ctx, source.StringVal(), target)
		case source.TypeName == xdm.TypeFloat || source.TypeName == xdm.TypeDouble:
			f := source.ToFloat64()
			if !math.IsNaN(f) && !math.IsInf(f, eitherInfinitySign) {
				_, exponent := math.Frexp(f)
				if target == xdm.TypeDecimal {
					err = preflightNumeric(ctx, max(0, exponent)+xdm.PrecisionDouble, max(minimumRationalDenominatorBits, doubleRationalMarginBits-exponent))
				} else {
					err = preflightNumeric(ctx, max(0, exponent))
				}
			}
		default:
			if n, numeric := NumericSize(source); numeric {
				err = preflightNumeric(ctx, n*bitsPerByte)
			}
		}

		if err != nil {
			return xdm.AtomicValue{}, err
		}
	}

	if err := validateVersionedCast(ctx, value, target); err != nil {
		return xdm.AtomicValue{}, err
	}

	result, err := CastAtomic(value, target)
	if err == nil {
		err = chargeConstructedAtomic(ctx, result)
	}

	return result, err
}

// Duration values use the same canonical lexical size as public result checks.
// Input length is not that size: long fractional zeros can reduce to PT0S.
func chargeConstructedAtomic(ctx context.Context, value xdm.AtomicValue) error {
	switch value.TypeName {
	case xdm.TypeDuration, xdm.TypeDayTimeDuration, xdm.TypeYearMonthDuration:
		if err := Charge(ctx, constructedDurationWork); err != nil {
			return err
		}

		text, err := CastAtomic(value, xdm.TypeString)
		if err != nil {
			return err
		}

		return ChargeString(ctx, len(text.StringVal()))
	default:
		return ChargeNumber(ctx, value)
	}
}

// boundedDurationResult applies the canonical size guard before publishing a
// newly constructed duration from an aggregate or timezone accessor.
func boundedDurationResult(ctx context.Context, value xdm.AtomicValue) (xdm.Sequence, error) {
	if err := chargeConstructedAtomic(ctx, value); err != nil {
		return nil, err
	}

	return xdm.SingleAtomic(value), nil
}

func int64Bits(n int64) int {
	u := uint64(n) // #nosec G115 -- Unsigned conversion and negation compute the magnitude even for MinInt64.
	if n < 0 {
		u = -u
	}

	return bits.Len64(u)
}

func magnitudeBytes(n int) int {
	return max(minimumNumericBytes, n/bitsPerByte+boolInt(n%bitsPerByte != 0))
}

func boolInt(b bool) int {
	if b {
		return 1
	}

	return 0
}

// preflightNumeric bounds component sizes and a conservative quadratic work
// estimate before math/big allocates. Bounds may exceed a reduced result's size.
// The actual value is charged when produced, not the conservative bound.
func preflightNumeric(ctx context.Context, componentBits ...int) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	b := getBudget(ctx)
	if b == nil {
		return nil
	}

	remaining := b.bytes - b.usedBytes
	work := 0

	for _, size := range componentBits {
		if size < 0 {
			return ErrBudget
		}

		n := magnitudeBytes(size)
		if n > remaining {
			return ErrBudget
		}

		remaining -= n
		words := max(minimumPreflightWords, size/numericWorkWordBits+boolInt(size%numericWorkWordBits != 0))

		available := b.operations - b.usedOperations - work
		if words > available/words {
			return ErrBudget
		}

		work += words * words
	}

	return Charge(ctx, work)
}

func addBits(a, b int) int {
	if a < 0 || b < 0 || a > math.MaxInt-b {
		return invalidNumericBitCount
	}

	return a + b
}

func productBits(a, b *big.Int) int {
	if a.Sign() == 0 || b.Sign() == 0 {
		return 0
	}

	return addBits(a.BitLen(), b.BitLen())
}

func preflightInteger(ctx context.Context, op TokenType, a, b *big.Int) error {
	size := a.BitLen()

	switch op {
	case TokenPlus, TokenMinus:
		size = addBits(max(size, b.BitLen()), additionCarryBits)
	case TokenStar:
		size = productBits(a, b)
	case TokenDiv:
		return preflightNumeric(ctx, a.BitLen(), b.BitLen())
	case TokenMod:
		size = min(size, b.BitLen())
	}

	return preflightNumeric(ctx, size)
}

func preflightDecimal(ctx context.Context, op TokenType, a, b *big.Rat) error {
	var numerator, denominator int

	switch op {
	case TokenPlus, TokenMinus:
		numerator = addBits(max(productBits(a.Num(), b.Denom()), productBits(b.Num(), a.Denom())), additionCarryBits)
		denominator = productBits(a.Denom(), b.Denom())
	case TokenStar:
		numerator, denominator = productBits(a.Num(), b.Num()), productBits(a.Denom(), b.Denom())
	default: // division and the quotient temporary in idiv/mod
		numerator, denominator = productBits(a.Num(), b.Denom()), productBits(a.Denom(), b.Num())
	}

	return preflightNumeric(ctx, numerator, denominator)
}

func preflightRound(ctx context.Context, value xdm.AtomicValue, scale int) error {
	if scale < 0 || scale > (math.MaxInt-decimalBitCeilOffset)/decimalBitEstimateNumerator {
		return ErrBudget
	}

	powerBits := (scale*decimalBitEstimateNumerator+decimalBitCeilOffset)/decimalBitEstimateDenominator + decimalPowerExtraBits

	if value.TypeName == xdm.TypeDecimal {
		r := value.BigRat()
		return preflightNumeric(ctx, addBits(r.Num().BitLen(), powerBits+decimalRoundSpareBits), addBits(r.Denom().BitLen(), powerBits))
	}

	if xdm.IsIntegerDerived(value.TypeName) {
		return preflightNumeric(ctx, addBits(value.BigInt().BitLen(), powerBits+integerRoundSpareBits))
	}

	return preflightNumeric(ctx, addBits(powerBits, doubleMaxRationalComponentBits))
}

// preflightNumericLexical bounds numeric storage using a safe rational upper
// approximation to log2(10).
// Leading integer zeroes are ignored. Decimal denominator scale is counted
// even when normalization could subsequently cancel factors.
func preflightNumericLexical(ctx context.Context, source, target string) error {
	source = strings.Trim(source, lexicon.XMLWhitespace)

	source = strings.TrimPrefix(strings.TrimPrefix(source, "+"), "-")
	if strings.ContainsAny(source, "eE") {
		return nil
	} // parsed as IEEE double

	whole, fraction, decimal := strings.Cut(source, ".")

	digits := len(strings.TrimLeft(whole, "0")) + len(fraction)
	if digits > (math.MaxInt-numericLexicalOverflowMargin)/decimalBitEstimateNumerator || len(fraction) > (math.MaxInt-numericLexicalOverflowMargin)/decimalBitEstimateNumerator {
		return ErrBudget
	}

	numerator := (digits*decimalBitEstimateNumerator + decimalBitCeilOffset) / decimalBitEstimateDenominator

	if fraction == "" {
		if number, err := strconv.ParseUint(whole, numericDecimalRadix, numericParseBits); err == nil {
			numerator = bits.Len64(number)
		}
	}

	if decimal || target == xdm.TypeDecimal {
		return preflightNumeric(ctx, numerator, (len(fraction)*decimalBitEstimateNumerator+decimalBitCeilOffset)/decimalBitEstimateDenominator+decimalPowerExtraBits)
	}

	return preflightNumeric(ctx, numerator)
}
