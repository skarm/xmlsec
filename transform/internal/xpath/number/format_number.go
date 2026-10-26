// Derived from lestrrat-go/helium at 7362c0a70122a757780f4d0b545a9b370dead6ab.
// Copyright (c) 2015 lestrrat. MIT License; see licenses/MIT-helium.txt at the repository root.

// Package number parses decimal pictures and formats numbers for XPath and XSLT.
// It is implemented in Go and does not require an external ICU runtime.
package number

import (
	"fmt"
	"math"
	"math/big"
	"slices"
	"strings"
)

// DecimalFormat defines picture symbols and special-value text for XPath and XSLT
// format-number processing.
type DecimalFormat struct {
	// Infinity is the string emitted for infinite values.
	Infinity string
	// NaN is the string emitted for a not-a-number value.
	NaN string
	// DecimalSeparator marks the decimal point in pictures and formatted output.
	DecimalSeparator rune
	// GroupingSeparator marks digit grouping in pictures and formatted output.
	GroupingSeparator rune
	// Percent selects percent scaling and its output symbol.
	Percent rune
	// PerMille selects per-mille scaling and its output symbol.
	PerMille rune
	// ZeroDigit is the first rune of the ten-digit alphabet used for output.
	ZeroDigit rune
	// Digit marks an optional digit position in a picture.
	Digit rune
	// PatternSeparator separates positive and negative subpictures.
	PatternSeparator rune
	// ExponentSeparator marks exponent syntax and output.
	ExponentSeparator rune
	// MinusSign is the sign emitted for negative values when required.
	MinusSign rune
	// ExponentDisabled treats the exponent symbol as ordinary picture text for older host
	// contracts.
	ExponentDisabled bool
}

// DefaultDecimalFormat returns the default picture symbols and special-value text,
// including e as the exponent separator.
func DefaultDecimalFormat() DecimalFormat {
	return DecimalFormat{
		Infinity:          "Infinity",
		NaN:               "NaN",
		DecimalSeparator:  '.',
		GroupingSeparator: ',',
		Percent:           '%',
		PerMille:          '\u2030',
		ZeroDigit:         '0',
		Digit:             '#',
		PatternSeparator:  ';',
		ExponentSeparator: 'e',
		MinusSign:         '-',
		ExponentDisabled:  false,
	}
}

// ParsedPicture holds the parsed components of a number format picture string.
type ParsedPicture struct {
	// Prefix is literal text preceding the numeric part.
	Prefix string
	// Suffix is literal text following the numeric part.
	Suffix         string
	GroupingSizes  []int // from right, repeating
	FracGroupSizes []int // from left
	// MinIntDigits is the minimum required integer digit count.
	MinIntDigits int
	// MaxIntDigits is the integer digit-position count parsed from the picture.
	MaxIntDigits int
	// MaxFracDigits is the maximum fractional digit count.
	MaxFracDigits int
	// MinFracDigits is the minimum required fractional digit count.
	MinFracDigits int
	// MinExpDigits is the minimum exponent digit count.
	MinExpDigits int
	// RepeatGrouping repeats a regular integer grouping interval beyond explicitly marked
	// positions.
	RepeatGrouping bool
	// IsPercent applies percent scaling.
	IsPercent bool
	// IsPerMille applies per-mille scaling.
	IsPerMille bool
	// HasDecimalPoint records an explicit decimal separator in the picture.
	HasDecimalPoint bool
	// HasExponent records an exponent part in the picture.
	HasExponent bool
}

// ParsePicture parses a single picture sub-pattern into its components.
func ParsePicture(pic string, df DecimalFormat) (ParsedPicture, error) {
	mantissa, exponent, hasExponent := splitPictureExponent([]rune(pic), df)
	pp := ParsedPicture{HasExponent: hasExponent}

	start, end := pictureNumericBounds(mantissa, df, &pp)
	if start < 0 {
		return pp, nil
	}

	if err := validatePictureMultipliers(mantissa, df); err != nil {
		return ParsedPicture{}, err
	}

	pp.Prefix = string(mantissa[:start])
	if err := parsePictureSuffix(&pp, mantissa[end:], exponent, df); err != nil {
		return ParsedPicture{}, err
	}

	if err := parsePictureDigits(&pp, mantissa[start:end], df); err != nil {
		return ParsedPicture{}, err
	}

	return pp, nil
}

// FormatNumber formats a numeric value according to the given picture string
// and decimal format. The caller provides pre-extracted numeric properties:
//   - f: the float64 value
//   - isNaN, isPosInf, isNegInf: special value flags
//   - negative: true if the value is negative (or negative zero)
//   - precise: if non-nil, use precise decimal formatting via *big.Rat
//   - picture: the format picture string
//   - df: the decimal format specification
func FormatNumber(f float64, isNaN, isPosInf, isNegInf, negative bool, precise *big.Rat, picture string, df DecimalFormat) (string, error) {
	parts := strings.Split(picture, string(df.PatternSeparator))
	if len(parts) > 2 {
		return "", fmt.Errorf("picture %q contains more than one pattern separator", picture)
	}

	positive, negativePicture := parts[0], ""
	if len(parts) > 1 {
		negativePicture = parts[1]
	}

	if isNaN {
		return df.NaN, nil
	}

	if isPosInf {
		return formatInfinityPicture(positive, false, df)
	}

	if isNegInf {
		if negativePicture != "" {
			return formatInfinityPicture(negativePicture, false, df)
		}

		return formatInfinityPicture(positive, true, df)
	}

	if negative {
		f = math.Abs(f)
	}

	selected := positive
	if negative && negativePicture != "" {
		selected = negativePicture
	}

	pp, err := ParsePicture(selected, df)
	if err != nil {
		return "", err
	}

	if pp.IsPercent {
		f *= 100
	} else if pp.IsPerMille {
		f *= 1000
	}

	prefix := pp.Prefix
	if negative && negativePicture == "" {
		prefix = string(df.MinusSign) + prefix
	}

	// Multiplier overflow takes priority even when a precise value is supplied.
	if math.IsInf(f, 0) {
		return prefix + df.Infinity + pp.Suffix, nil
	}

	return prefix + formatParsedNumber(f, precise, pp, df) + pp.Suffix, nil
}

// FormatFloat formats a float64 value using the parsed picture and decimal format.
func FormatFloat(f float64, pp ParsedPicture, df DecimalFormat) string {
	// Round to maxFracDigits. Only scale when both the power-of-ten scale and the
	// scaled product stay finite: a huge MaxFracDigits overflows math.Pow to +Inf
	// (which would turn a finite f into NaN), and a large f overflows f*scale to
	// +Inf (which would yield a non-finite result). In either case rounding is a
	// no-op for the representable value, so leaving f unchanged is correct and
	// keeps big.Float.SetFloat64 from ever seeing NaN/Inf.
	if pp.MaxFracDigits >= 0 {
		scale := math.Pow(10, float64(pp.MaxFracDigits))
		if scaled := f * scale; isFinite(scale) && isFinite(scaled) {
			f = math.Round(scaled) / scale
		}
	}

	// Split into integer and fractional parts.
	// Use math.Trunc to avoid int64 overflow for large floats.
	trunc := math.Trunc(f)

	frac := f - trunc
	if frac < 0 {
		frac = -frac
	}

	// Format integer part
	bigTrunc, _ := new(big.Float).SetFloat64(trunc).Int(nil)
	intStr := FormatBigInt(bigTrunc, pp.MinIntDigits, pp.GroupingSizes, pp.RepeatGrouping, df)

	if !pp.HasDecimalPoint && pp.MaxFracDigits == 0 {
		if intStr == "" {
			intStr = "0"
		}

		return intStr
	}

	// Format fractional part
	fracStr := FormatFrac(frac, pp.MinFracDigits, pp.MaxFracDigits, df)

	// XPath F&O: when both integer and fractional parts are empty (value rounds
	// to zero with MinIntDigits=0 and MinFracDigits=0), show at least one digit.
	if intStr == "" && fracStr == "" {
		if pp.MaxFracDigits > 0 {
			fracStr = "0"
		} else {
			intStr = "0"
		}
	}

	if fracStr == "" {
		return intStr
	}

	fracStr = applyFractionGrouping(fracStr, pp.FracGroupSizes, df)

	return intStr + string(df.DecimalSeparator) + fracStr
}

// FormatDecimalPrecise formats a *big.Rat value with exact decimal arithmetic.
// The rat value should already have its sign removed (absolute value).
func FormatDecimalPrecise(r *big.Rat, pp ParsedPicture, df DecimalFormat) string {
	r = new(big.Rat).Set(r)

	if pp.IsPercent {
		r.Mul(r, new(big.Rat).SetInt64(100))
	} else if pp.IsPerMille {
		r.Mul(r, new(big.Rat).SetInt64(1000))
	}

	if r.Sign() < 0 {
		r.Neg(r)
	}

	// Round to maxFracDigits
	rounded := RatRoundHalfToEven(r, pp.MaxFracDigits)

	intPart := new(big.Int).Quo(rounded.Num(), rounded.Denom())
	fracRat := new(big.Rat).Sub(rounded, new(big.Rat).SetInt(intPart))

	intStr := FormatBigInt(intPart, pp.MinIntDigits, pp.GroupingSizes, pp.RepeatGrouping, df)

	if !pp.HasDecimalPoint && pp.MaxFracDigits == 0 {
		if intStr == "" {
			intStr = "0"
		}

		return intStr
	}

	fracStr := FormatRatFrac(fracRat, pp.MinFracDigits, pp.MaxFracDigits, df)

	// XPath F&O: when both integer and fractional parts are empty (value rounds
	// to zero with MinIntDigits=0 and MinFracDigits=0), show at least one digit.
	if intStr == "" && fracStr == "" {
		if pp.MaxFracDigits > 0 {
			fracStr = "0"
		} else {
			intStr = "0"
		}
	}

	if fracStr == "" {
		return intStr
	}

	fracStr = applyFractionGrouping(fracStr, pp.FracGroupSizes, df)

	return intStr + string(df.DecimalSeparator) + fracStr
}

// FormatBigInt formats an integer with minimum digits and grouping separators.
func FormatBigInt(n *big.Int, minDigits int, groupingSizes []int, repeatGrouping bool, df DecimalFormat) string {
	s := n.String()
	if minDigits == 0 && s == "0" {
		s = ""
	}
	// Pad to minDigits
	if padding := minDigits - len(s); padding > 0 {
		s = strings.Repeat("0", padding) + s
	}

	if len(groupingSizes) == 0 || len(s) == 0 {
		return localizeDigits(s, df.ZeroDigit)
	}

	// Insert grouping separators from right
	// groupingSizes[0] is the primary (rightmost) group size.
	var result []rune

	runes := []rune(s)
	groupIdx := 0
	count := 0
	groupSize := groupingSizes[0]

	for _, v := range slices.Backward(runes) {
		if groupSize > 0 && count > 0 && count == groupSize {
			result = append(result, df.GroupingSeparator)
			count = 0

			if groupIdx+1 < len(groupingSizes) {
				groupIdx++
				groupSize = groupingSizes[groupIdx]
			} else if !repeatGrouping {
				groupSize = 0
			}
		}

		result = append(result, v)
		count++
	}

	// Reverse
	for i, j := 0, len(result)-1; i < j; i, j = i+1, j-1 {
		result[i], result[j] = result[j], result[i]
	}

	return localizeDigits(string(result), df.ZeroDigit)
}

// FormatFrac formats the fractional part of a float64.
func FormatFrac(frac float64, minDigits, maxDigits int, df DecimalFormat) string {
	if maxDigits == 0 {
		return ""
	}

	var digits []byte

	remaining := frac
	for range maxDigits {
		remaining *= 10
		d := int(remaining)
		digits = append(digits, byte('0'+d))
		remaining -= float64(d)
	}

	// Trim trailing zeros beyond minDigits
	end := len(digits)
	for end > minDigits && digits[end-1] == '0' {
		end--
	}

	return localizeDigits(string(digits[:end]), df.ZeroDigit)
}

// FormatRatFrac formats the fractional part of a *big.Rat.
func FormatRatFrac(frac *big.Rat, minDigits, maxDigits int, df DecimalFormat) string {
	if maxDigits == 0 {
		return ""
	}

	var digits []byte

	// Long division keeps the denominator fixed. Rebuilding and reducing a
	// rational for each digit needlessly allocates big integers and runs GCD.
	// The private remainder also preserves the caller's reusable fraction.
	ten := big.NewInt(10)

	var rem, digit big.Int
	rem.Set(frac.Num())

	for range maxDigits {
		rem.Mul(&rem, ten)
		digit.QuoRem(&rem, frac.Denom(), &rem)
		digits = append(digits, byte('0'+digit.Int64()))
	}

	end := len(digits)
	for end > minDigits && digits[end-1] == '0' {
		end--
	}

	return localizeDigits(string(digits[:end]), df.ZeroDigit)
}

// RatRoundHalfToEven rounds a *big.Rat to the given precision using
// half-to-even rounding.
func RatRoundHalfToEven(r *big.Rat, precision int) *big.Rat {
	if precision < 0 {
		// Guard against absurdly large negative precision
		if -precision > 1000 {
			return new(big.Rat) // rounds to zero
		}
		// Round to 10^(-precision) — convert to integer, round, convert back
		scale := new(big.Int).Exp(big.NewInt(10), big.NewInt(int64(-precision)), nil)
		scaleRat := new(big.Rat).SetInt(scale)
		divided := new(big.Rat).Quo(r, scaleRat)
		rounded := RatRoundHalfToEvenInt(divided)

		return new(big.Rat).Mul(new(big.Rat).SetInt(rounded), scaleRat)
	}
	// If precision is very large and already exceeds the denominator's decimal
	// digits, the value is already exact — return as-is. This avoids computing
	// astronomically large powers of 10 (e.g. 10^4294967296).
	if precision > 1000 || RatDecimalDigits(r) <= precision {
		return new(big.Rat).Set(r)
	}
	// Multiply by 10^precision, round to integer, divide back
	scale := new(big.Int).Exp(big.NewInt(10), big.NewInt(int64(precision)), nil)
	scaleRat := new(big.Rat).SetInt(scale)
	shifted := new(big.Rat).Mul(r, scaleRat)
	rounded := RatRoundHalfToEvenInt(shifted)

	return new(big.Rat).SetFrac(rounded, new(big.Int).Set(scale))
}

// RatDecimalDigits returns the number of decimal digits needed to represent
// the fractional part of r exactly. Returns 0 for integers.
func RatDecimalDigits(r *big.Rat) int {
	if r.IsInt() {
		return 0
	}
	// Factor out 2s and 5s from denominator; count max
	d := new(big.Int).Set(r.Denom())
	twos, fives := 0, 0

	for d.Bit(0) == 0 {
		d.Rsh(d, 1)

		twos++
	}

	five := big.NewInt(5)

	mod := new(big.Int)
	for {
		d.QuoRem(d, five, mod)

		if mod.Sign() != 0 {
			break
		}

		fives++
	}
	// If d != 1 after removing all 2s and 5s, the decimal is non-terminating
	if d.Cmp(big.NewInt(1)) != 0 {
		return math.MaxInt
	}

	if twos > fives {
		return twos
	}

	return fives
}

// RatRoundHalfToEvenInt rounds a *big.Rat to the nearest integer using
// half-to-even rounding.
func RatRoundHalfToEvenInt(r *big.Rat) *big.Int {
	if r.IsInt() {
		return new(big.Int).Set(r.Num())
	}

	intPart := new(big.Int).Quo(r.Num(), r.Denom())
	// Fractional remainder
	rem := new(big.Rat).Sub(r, new(big.Rat).SetInt(intPart))
	rem.Abs(rem)

	half := new(big.Rat).SetFrac64(1, 2)
	cmp := rem.Cmp(half)

	if cmp < 0 {
		// Closer to floor
		return intPart
	}

	if cmp > 0 {
		// Closer to ceil
		if r.Sign() > 0 {
			return intPart.Add(intPart, big.NewInt(1))
		}

		return intPart.Sub(intPart, big.NewInt(1))
	}
	// Exactly half — round to even
	if new(big.Int).And(intPart, big.NewInt(1)).Sign() == 0 {
		return intPart // already even
	}

	if r.Sign() > 0 {
		return intPart.Add(intPart, big.NewInt(1))
	}

	return intPart.Sub(intPart, big.NewInt(1))
}

func isMandatoryDigit(r, zeroDigit rune) bool {
	return r >= zeroDigit && r <= zeroDigit+9
}

func isPatternDigit(r rune, df DecimalFormat) bool {
	return isMandatoryDigit(r, df.ZeroDigit) || r == df.Digit
}

func parseGroupedPart(part []rune, sep rune, df DecimalFormat) ([]int, int, int, error) {
	if len(part) == 0 {
		return nil, 0, 0, nil
	}

	var groups []int

	currentGroupSize := 0
	minDigits := 0
	maxDigits := 0
	prevSep := false

	for i, r := range part {
		switch {
		case r == sep:
			if i == len(part)-1 || prevSep {
				return nil, 0, 0, fmt.Errorf("invalid grouping separator placement")
			}

			groups = append(groups, currentGroupSize)
			currentGroupSize = 0
			prevSep = true
		case isPatternDigit(r, df):
			if isMandatoryDigit(r, df.ZeroDigit) {
				minDigits++
			}

			maxDigits++
			currentGroupSize++
			prevSep = false
		default:
			return nil, 0, 0, fmt.Errorf("invalid picture character %q", r)
		}
	}

	groups = append(groups, currentGroupSize)

	return groups, minDigits, maxDigits, nil
}

func shouldRepeatGrouping(groups []int) bool {
	if len(groups) < 2 {
		return false
	}

	repeated := groups[1]
	for i := 2; i < len(groups); i++ {
		if groups[i] != repeated {
			return false
		}
	}

	return groups[0] <= repeated
}

func hasInvalidLiteralChars(part []rune, df DecimalFormat) bool {
	for _, r := range part {
		if isPatternDigit(r, df) ||
			r == df.DecimalSeparator ||
			r == df.GroupingSeparator ||
			r == df.PatternSeparator {
			return true
		}
	}

	return false
}

func splitPictureExponent(runes []rune, df DecimalFormat) ([]rune, []rune, bool) {
	if df.ExponentDisabled {
		return runes, nil, false
	}

	separator := df.ExponentSeparator
	if separator == 0 {
		separator = 'e'
	}

	precededByActive := false
	for i, r := range runes {
		if r == separator && precededByActive && i+1 < len(runes) && isPatternDigit(runes[i+1], df) {
			return runes[:i], runes[i+1:], true
		}

		precededByActive = precededByActive || isPatternDigit(r, df) || r == df.DecimalSeparator || r == df.GroupingSeparator
	}

	return runes, nil, false
}

func pictureNumericBounds(runes []rune, df DecimalFormat, pp *ParsedPicture) (int, int) {
	start, end := -1, -1

	for i, r := range runes {
		switch {
		case isPatternDigit(r, df) || r == df.DecimalSeparator || r == df.GroupingSeparator:
			if start < 0 {
				start = i
			}

			end = i + 1
		case r == df.Percent:
			pp.IsPercent = true

			if start >= 0 {
				return start, i
			}
		case r == df.PerMille:
			pp.IsPerMille = true

			if start >= 0 {
				return start, i
			}
		default:
			if start >= 0 {
				return start, i
			}
		}
	}

	return start, end
}

func validatePictureMultipliers(runes []rune, df DecimalFormat) error {
	percent, perMille := 0, 0

	for _, r := range runes {
		switch r {
		case df.Percent:
			percent++
		case df.PerMille:
			perMille++
		}
	}

	if percent > 1 {
		return fmt.Errorf("picture contains more than one percent sign")
	}

	if perMille > 1 {
		return fmt.Errorf("picture contains more than one per-mille sign")
	}

	if percent > 0 && perMille > 0 {
		return fmt.Errorf("picture contains both percent and per-mille signs")
	}

	return nil
}

func parsePictureSuffix(pp *ParsedPicture, mantissaSuffix, exponent []rune, df DecimalFormat) error {
	if !pp.HasExponent {
		pp.Suffix = string(mantissaSuffix)
		if hasInvalidLiteralChars(mantissaSuffix, df) {
			return fmt.Errorf("invalid active character in picture suffix")
		}

		return nil
	}

	end := 0

	for i, r := range exponent {
		if !isPatternDigit(r, df) {
			break
		}

		end = i + 1
	}

	for _, r := range exponent[:end] {
		if isMandatoryDigit(r, df.ZeroDigit) {
			pp.MinExpDigits++
		}
	}

	if pp.MinExpDigits == 0 {
		pp.MinExpDigits = 1
	}

	suffix := exponent[end:]

	pp.Suffix = string(suffix)
	if hasInvalidLiteralChars(suffix, df) {
		return fmt.Errorf("invalid active character in picture suffix")
	}

	for _, r := range suffix {
		if r == df.Percent || r == df.PerMille {
			return fmt.Errorf("percent and per-mille are not allowed in exponent pictures")
		}
	}

	return nil
}

func parsePictureDigits(pp *ParsedPicture, number []rune, df DecimalFormat) error {
	integer, fraction := number, []rune(nil)
	for i, r := range number {
		if r == df.DecimalSeparator {
			pp.HasDecimalPoint = true
			integer, fraction = number[:i], number[i+1:]

			break
		}
	}

	if err := parseIntegerPicture(pp, integer, df); err != nil {
		return err
	}

	if err := parseFractionPicture(pp, fraction, df); err != nil {
		return err
	}

	if pp.MaxIntDigits+pp.MaxFracDigits == 0 {
		return fmt.Errorf("picture requires at least one digit")
	}

	return validateIntegerPictureOrder(integer, df)
}

func parseIntegerPicture(pp *ParsedPicture, integer []rune, df DecimalFormat) error {
	groups, minDigits, maxDigits, err := parseGroupedPart(integer, df.GroupingSeparator, df)
	if err != nil {
		return err
	}

	pp.MinIntDigits = minDigits
	pp.MaxIntDigits = maxDigits

	pp.RepeatGrouping = shouldRepeatGrouping(groups)
	if len(groups) > 1 {
		pp.GroupingSizes = make([]int, len(groups)-1)
		for i := range len(groups) - 1 {
			pp.GroupingSizes[i] = groups[len(groups)-1-i]
		}
	}

	return nil
}

func parseFractionPicture(pp *ParsedPicture, fraction []rune, df DecimalFormat) error {
	groups, minDigits, maxDigits, err := parseGroupedPart(fraction, df.GroupingSeparator, df)
	if err != nil {
		return err
	}

	if len(fraction) > 0 && fraction[0] == df.GroupingSeparator {
		return fmt.Errorf("invalid grouping separator placement")
	}

	optional := false

	for _, r := range fraction {
		switch {
		case r == df.GroupingSeparator:
			continue
		case r == df.Digit:
			optional = true
		case isMandatoryDigit(r, df.ZeroDigit):
			if optional {
				return fmt.Errorf("mandatory fractional digit after optional digit")
			}
		}
	}

	pp.MinFracDigits = minDigits

	pp.MaxFracDigits = maxDigits
	if len(groups) > 1 {
		pp.FracGroupSizes = groups
	}

	return nil
}

func validateIntegerPictureOrder(integer []rune, df DecimalFormat) error {
	mandatory := false

	for _, r := range integer {
		if r == df.GroupingSeparator {
			continue
		}

		if isMandatoryDigit(r, df.ZeroDigit) {
			mandatory = true
		} else if r == df.Digit && mandatory {
			return fmt.Errorf("optional digit after mandatory digit in integer part")
		}
	}

	return nil
}

func formatInfinityPicture(picture string, minus bool, df DecimalFormat) (string, error) {
	pp, err := ParsePicture(picture, df)
	if err != nil {
		return "", err
	}

	prefix := pp.Prefix
	if minus {
		prefix = string(df.MinusSign) + prefix
	}

	return prefix + df.Infinity + pp.Suffix, nil
}

func formatParsedNumber(f float64, precise *big.Rat, pp ParsedPicture, df DecimalFormat) string {
	if pp.HasExponent {
		if precise != nil {
			return formatExponentPrecise(precise, pp, df)
		}

		return formatExponentFloat(f, pp, df)
	}

	if precise != nil {
		return FormatDecimalPrecise(precise, pp, df)
	}

	return FormatFloat(f, pp, df)
}

// exponentScalingFactor computes the number of integer digits in the mantissa
// for scientific notation formatting, per the XPath F&O spec:
//   - MinIntDigits > 0: scaling factor = MinIntDigits
//   - MinIntDigits = 0, MaxIntDigits >= 2: scaling factor = MaxIntDigits
//   - Otherwise: scaling factor = 0 (mantissa in [0.1, 1))
func exponentScalingFactor(pp ParsedPicture) int {
	if pp.MinIntDigits > 0 {
		return pp.MinIntDigits
	}

	if pp.MaxIntDigits >= 2 {
		return pp.MaxIntDigits
	}

	return 0
}

// adjustMantissaPP adjusts the ParsedPicture for mantissa formatting in
// scientific notation. When scaling factor m=0, unused integer digit slots
// effectively become optional fractional digits.
func adjustMantissaPP(pp ParsedPicture, m int) ParsedPicture {
	r := pp
	r.HasExponent = false
	r.IsPercent = false
	r.IsPerMille = false

	if m == 0 {
		// Integer # slots become optional fractional digits
		effMaxFrac := max(pp.MaxFracDigits, pp.MaxIntDigits)

		r.MaxFracDigits = effMaxFrac
		if effMaxFrac > 0 {
			r.HasDecimalPoint = true
		}
		// Show leading zero when pattern had integer digit placeholders
		if pp.MaxIntDigits > 0 {
			r.MinIntDigits = 1
		} else if pp.MaxFracDigits > 0 && r.MinFracDigits == 0 {
			// With pictures like ".#e0", rounding can carry into the integer part;
			// keep one fractional digit in that case.
			r.MinFracDigits = 1
		}
	}

	return r
}

func formatExponentFloat(f float64, pp ParsedPicture, df DecimalFormat) string {
	if f == 0 {
		return formatExponentZero(pp, df)
	}

	m := exponentScalingFactor(pp)

	// Compute exponent: normalize so mantissa has m integer digits
	exp := 0

	abs := math.Abs(f)
	if m == 0 {
		// Normalize so mantissa is in [0.1, 1) — first significant digit
		// is the first fractional digit
		for abs >= 1 {
			abs /= 10
			exp++
		}

		for abs > 0 && abs < 0.1 {
			abs *= 10
			exp--
		}
	} else {
		upperBound := math.Pow(10, float64(m))
		lowerBound := math.Pow(10, float64(m-1))

		for abs >= upperBound {
			abs /= 10
			exp++
		}

		for abs < lowerBound {
			abs *= 10
			exp--
		}
	}

	mantissaPP := adjustMantissaPP(pp, m)
	mantissaStr := FormatFloat(abs, mantissaPP, df)

	return joinExponent(mantissaStr, exp, pp, df)
}

func formatExponentPrecise(r *big.Rat, pp ParsedPicture, df DecimalFormat) string {
	if r.Sign() == 0 {
		return formatExponentZero(pp, df)
	}

	if pp.IsPercent {
		r = new(big.Rat).Mul(r, new(big.Rat).SetInt64(100))
	} else if pp.IsPerMille {
		r = new(big.Rat).Mul(r, new(big.Rat).SetInt64(1000))
	}

	m := exponentScalingFactor(pp)

	// Compute exponent by normalizing the value
	exp := 0
	abs := new(big.Rat).Abs(r)
	ten := new(big.Rat).SetInt64(10)
	one := new(big.Rat).SetInt64(1)

	tenth := new(big.Rat).SetFrac64(1, 10)

	if m == 0 {
		// Normalize so mantissa is in [0.1, 1)
		for abs.Cmp(one) >= 0 {
			abs.Quo(abs, ten)

			exp++
		}

		for abs.Sign() > 0 && abs.Cmp(tenth) < 0 {
			abs.Mul(abs, ten)

			exp--
		}
	} else {
		threshold := new(big.Rat).SetInt(new(big.Int).Exp(big.NewInt(10), big.NewInt(int64(m)), nil))

		lowerBound := new(big.Rat).SetInt(new(big.Int).Exp(big.NewInt(10), big.NewInt(int64(m-1)), nil))
		if m == 1 {
			lowerBound = one
		}

		for abs.Cmp(lowerBound) < 0 {
			abs.Mul(abs, ten)

			exp--
		}

		for abs.Cmp(threshold) >= 0 {
			abs.Quo(abs, ten)

			exp++
		}
	}

	// Format the mantissa
	mantissaPP := adjustMantissaPP(pp, m)
	mantissaStr := FormatDecimalPrecise(abs, mantissaPP, df)

	return joinExponent(mantissaStr, exp, pp, df)
}

func formatExponentZero(pp ParsedPicture, df DecimalFormat) string {
	mantissaPP := adjustMantissaPP(pp, exponentScalingFactor(pp))
	mantissaStr := FormatFloat(0, mantissaPP, df)

	return joinExponent(mantissaStr, 0, pp, df)
}

func joinExponent(mantissa string, exp int, pp ParsedPicture, df DecimalFormat) string {
	mantissa = strings.TrimSuffix(mantissa, string(df.DecimalSeparator))

	expSep := df.ExponentSeparator
	if expSep == 0 {
		expSep = 'e'
	}

	return mantissa + string(expSep) + formatExponentDigits(exp, pp.MinExpDigits, df)
}

func formatExponentDigits(exp, minDigits int, df DecimalFormat) string {
	neg := exp < 0
	if neg {
		exp = -exp
	}

	s := strings.Builder{}
	if neg {
		s.WriteRune(df.MinusSign)
	}

	digits := big.NewInt(int64(exp)).String()
	if padding := minDigits - len(digits); padding > 0 {
		digits = strings.Repeat("0", padding) + digits
	}

	s.WriteString(localizeDigits(digits, df.ZeroDigit))

	return s.String()
}

func isFinite(f float64) bool {
	return !math.IsNaN(f) && !math.IsInf(f, 0)
}

func localizeDigits(s string, zeroDigit rune) string {
	if s == "" || zeroDigit == '0' {
		return s
	}

	var b strings.Builder
	b.Grow(len(s))

	for _, r := range s {
		if r >= '0' && r <= '9' {
			b.WriteRune(zeroDigit + (r - '0'))
			continue
		}

		b.WriteRune(r)
	}

	return b.String()
}

func applyFractionGrouping(frac string, groups []int, df DecimalFormat) string {
	if len(groups) <= 1 || len(frac) == 0 {
		return frac
	}

	runes := []rune(frac)

	var b strings.Builder

	pos := 0
	for i, groupSize := range groups {
		if pos >= len(runes) {
			break
		}

		end := min(pos+groupSize, len(runes))
		b.WriteString(string(runes[pos:end]))

		pos = end
		if pos < len(runes) && i < len(groups)-1 {
			b.WriteRune(df.GroupingSeparator)
		}
	}

	if pos < len(runes) {
		b.WriteString(string(runes[pos:]))
	}

	return b.String()
}
