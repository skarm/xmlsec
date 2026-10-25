// Derived from lestrrat-go/helium at 7362c0a70122a757780f4d0b545a9b370dead6ab.
// Copyright (c) 2015 lestrrat. MIT License; see licenses/MIT-helium.txt at the repository root.

package xpath

import (
	"context"
	"math"
	"math/big"
	"time"

	"github.com/skarm/xmlsec/internal/lexicon"
	"github.com/skarm/xmlsec/transform/internal/xdm"
)

// Conservative magnitude bounds for time.AddDate operands. time.Time can
// represent years up to roughly ±2.9e11, but time.AddDate adds years, months and
// days as plain ints whose internal normalization silently wraps for magnitudes
// near math.MaxInt (e.g. AddDate(0,0,1<<60) returns the original date
// unchanged). We bound the move to maxSafeAddDateYears' worth of months or days,
// which stays comfortably inside the representable range and well clear of any
// wrap; anything larger is a genuine FODT0001 date/time overflow.
//
// maxSafeAddDateYears is 1e11 where int is 64 bits. Where int is 32 bits,
// time.Time reports its year as an int, so the bound is math.MaxInt/4 (about
// 5.4e8 years): a larger move would produce a year that int cannot hold.
const (
	maxSafeAddDateYears  = min(100_000_000_000, math.MaxInt/4)
	maxSafeAddDateMonths = int64(maxSafeAddDateYears * 12)
	// addDateDayChunk is the largest day count passed to one time.AddDate call.
	// Where int is 64 bits it exceeds maxSafeAddDateDays, so a day move is a
	// single call; where int is 32 bits a larger move takes several calls.
	addDateDayChunk = math.MaxInt / 4
)

// maxSafeAddDateDays is maxSafeAddDateYears in days (365.25 days a year), as a
// *big.Int since the day count is computed in big.Int.
const maxSafeAddDateDays = maxSafeAddDateYears * 36525 / 100

// maxResultYear bounds the year of a date/time ± duration result. Where int is
// 32 bits, time.Time reports the year as an int, so a result past about ±1e9
// years would wrap; each move is at most maxSafeAddDateYears (about 5.4e8
// years there), so a start year within this bound cannot wrap before the check.
// Where int is 64 bits the bound is far beyond any year time.Time holds, so the
// check never fires.
const maxResultYear = math.MaxInt / 2

func isDurationType(typeName string) bool {
	return typeName == xdm.TypeDuration || typeName == xdm.TypeYearMonthDuration || typeName == xdm.TypeDayTimeDuration
}

func isDateTimeType(typeName string) bool {
	return typeName == xdm.TypeDate || typeName == xdm.TypeDateTime || typeName == xdm.TypeTime
}

// arithmeticType returns the built-in type that drives date/time/duration
// arithmetic for an AtomicValue. A schema-derived value (e.g. a restriction of
// xs:dayTimeDuration) carries a custom TypeName whose BaseType names the
// built-in ancestor; arithmetic must treat it as that built-in type.
func arithmeticType(a xdm.AtomicValue) string {
	if a.TypeName == xdm.TypeDateTimeStamp || a.BaseType == xdm.TypeDateTimeStamp {
		return xdm.TypeDateTime
	}

	if isDurationType(a.TypeName) || isDateTimeType(a.TypeName) {
		return a.TypeName
	}

	if isDurationType(a.BaseType) || isDateTimeType(a.BaseType) {
		return a.BaseType
	}

	return a.TypeName
}

// julianDayNumber computes a continuous day count for a Gregorian calendar date,
// using the standard Julian Day Number algorithm. Works for negative years.
func julianDayNumber(year, month, day int) int64 {
	// Algorithm from Meeus, Astronomical Algorithms
	a := int64(14-month) / 12
	y := int64(year) + 4800 - a
	m := int64(month) + 12*a - 3

	return int64(day) + (153*m+2)/5 + 365*y + floorYearDivision(y, 4) - floorYearDivision(y, 100) + floorYearDivision(y, 400) - 32045
}

// Meeus' Gregorian formula uses floor, including for years before -4800.
func floorYearDivision(year, divisor int64) int64 {
	quotient := year / divisor
	if year%divisor < 0 {
		quotient--
	}

	return quotient
}

// evalDateTimeArithmetic handles arithmetic involving durations and date/time values.
// Returns (result, handled, error). If handled is false, the caller should fall through
// to numeric arithmetic.
func evalDateTimeArithmetic(ctx context.Context, ec *evalContext, op TokenType, la, ra xdm.AtomicValue) (xdm.Sequence, bool, error) {
	// Promote schema-derived duration/date/time operands to their built-in base
	// type BEFORE classifying, so a restriction of e.g. xs:dayTimeDuration is
	// recognized as a duration and the result carries the built-in type. The
	// promotion only rewrites TypeName; the backing Go value is unchanged.
	if at := arithmeticType(la); at != la.TypeName {
		la.TypeName = at
	}

	if at := arithmeticType(ra); at != ra.TypeName {
		ra.TypeName = at
	}

	lDur := isDurationType(la.TypeName)
	rDur := isDurationType(ra.TypeName)
	lDT := isDateTimeType(la.TypeName)
	rDT := isDateTimeType(ra.TypeName)

	// duration + duration → duration
	// - duration → duration
	// / duration → decimal
	if lDur && rDur {
		if op == TokenDiv {
			return arithmeticDurationDivDuration(ctx, la, ra)
		}

		return arithmeticDurationDuration(op, la, ra)
	}

	// duration * number → duration
	if lDur && ra.IsNumeric() {
		return arithmeticDurationNumber(ctx, op, la, ra)
	}
	// number * duration → duration
	if la.IsNumeric() && rDur {
		if op == TokenStar {
			return arithmeticDurationNumber(ctx, op, ra, la)
		}

		return nil, false, nil
	}

	// date/dateTime/time + duration → date/dateTime/time
	// - duration → date/dateTime/time
	if lDT && rDur {
		return arithmeticDateTimeDuration(op, la, ra)
	}

	// duration + date/dateTime/time → date/dateTime/time (commutative addition only)
	if lDur && rDT && op == TokenPlus {
		return arithmeticDateTimeDuration(op, ra, la)
	}

	// date - date → dayTimeDuration
	// dateTime - dateTime → dayTimeDuration
	// time - time → dayTimeDuration
	if lDT && rDT && la.TypeName == ra.TypeName && op == TokenMinus {
		return arithmeticDateTimeDatetime(ec, la, ra)
	}

	// Not a date/time/duration operation
	if lDur || rDur || (lDT && !la.IsNumeric()) {
		return nil, true, &xdm.Error{Code: lexicon.ErrXPTY0004, Message: "incompatible types for arithmetic"}
	}

	return nil, false, nil
}

func arithmeticDurationDuration(op TokenType, la, ra xdm.AtomicValue) (xdm.Sequence, bool, error) {
	if op != TokenPlus && op != TokenMinus {
		return nil, true, &xdm.Error{Code: lexicon.ErrXPTY0004, Message: "invalid operator for duration arithmetic"}
	}

	// Only same-kind durations can be added/subtracted:
	// xs:yearMonthDuration ± xs:yearMonthDuration → OK
	// xs:dayTimeDuration ± xs:dayTimeDuration → OK
	// xs:duration ± anything → XPTY0004 (xs:duration is not directly arithmetic)
	// mixing YMD and DTD → XPTY0004
	if la.TypeName == xdm.TypeDuration || ra.TypeName == xdm.TypeDuration {
		return nil, true, &xdm.Error{Code: lexicon.ErrXPTY0004, Message: textXsDurationCannotBeUsedInArithmetic}
	}

	if la.TypeName != ra.TypeName {
		return nil, true, &xdm.Error{Code: lexicon.ErrXPTY0004, Message: "cannot mix xs:yearMonthDuration and xs:dayTimeDuration in arithmetic"}
	}

	ld := la.DurationVal()
	rd := ra.DurationVal()

	// Determine result type
	typeName := resultDurationType(la.TypeName, ra.TypeName)

	// yearMonthDuration ± yearMonthDuration operates purely on the integer
	// month component.
	if typeName == xdm.TypeYearMonthDuration {
		lm := ld.Months
		if ld.Negative {
			lm = -lm
		}

		rm := rd.Months
		if rd.Negative {
			rm = -rm
		}
		// lm/rm are signed month totals. Accumulate via big.Int so a result near
		// the int limit (e.g. summing two large yearMonthDurations) does not wrap
		// to an invalid negative lexical; reject anything that overflows int.
		lBig := big.NewInt(int64(lm))
		rBig := big.NewInt(int64(rm))

		resBig := new(big.Int)
		if op == TokenPlus {
			resBig.Add(lBig, rBig)
		} else {
			resBig.Sub(lBig, rBig)
		}

		negative := resBig.Sign() < 0

		absBig := resBig
		if negative {
			absBig = new(big.Int).Neg(resBig)
		}

		if !absBig.IsInt64() || absBig.Int64() > int64(math.MaxInt) {
			return nil, true, &xdm.Error{Code: errCodeFODT0002, Message: "yearMonthDuration arithmetic overflow"}
		}

		return xdm.SingleAtomic(xdm.AtomicValue{
			TypeName: typeName,
			Value:    xdm.Duration{Months: int(absBig.Int64()), Negative: negative},
		}), true, nil
	}

	// dayTimeDuration ± dayTimeDuration: compute the result in exact rational
	// seconds so that fractional seconds (e.g. PT0.05S + PT0.05S) canonicalize
	// identically to a parsed PT0.1S.
	lRat := xdm.DurationToRat(ld, false)
	rRat := xdm.DurationToRat(rd, false)

	var resRat *big.Rat
	if op == TokenPlus {
		resRat = new(big.Rat).Add(lRat, rRat)
	} else {
		resRat = new(big.Rat).Sub(lRat, rRat)
	}

	negative := resRat.Sign() < 0

	absRat := resRat
	if negative {
		absRat = new(big.Rat).Neg(resRat)
	}

	secs, frac := durationFromRatSeconds(absRat)

	return xdm.SingleAtomic(xdm.AtomicValue{
		TypeName: typeName,
		Value:    xdm.Duration{Seconds: secs, FracSec: frac, SecRat: absRat, Negative: negative},
	}), true, nil
}

func arithmeticDurationNumber(ctx context.Context, op TokenType, dur, num xdm.AtomicValue) (xdm.Sequence, bool, error) {
	if op != TokenStar && op != TokenDiv {
		return nil, true, &xdm.Error{Code: lexicon.ErrXPTY0004, Message: "invalid operator for duration*number"}
	}

	// xs:duration (generic) does not support arithmetic — only YMD and DTD do
	if dur.TypeName == xdm.TypeDuration {
		return nil, true, &xdm.Error{Code: lexicon.ErrXPTY0004, Message: textXsDurationCannotBeUsedInArithmetic}
	}

	// XPath's operator table accepts numeric, retaining integer/decimal
	// arithmetic when the supplied numeric operand is exact. In particular,
	// decimal duration fields must not be rounded through binary64 here.
	num = xdm.PromoteSchemaType(num)
	if xdm.IsIntegerDerived(num.TypeName) || num.TypeName == xdm.TypeDecimal {
		result, err := arithmeticDurationExact(ctx, op, dur.TypeName, dur.DurationVal(), toRat(num))

		return result, true, err
	}

	// A floating operand uses the floating operator semantics before rounding
	// the month count or constructing decimal seconds.
	double, err := CastAtomicContext(ctx, num, xdm.TypeDouble)
	if err != nil {
		return nil, true, err
	}

	result, err := arithmeticDurationFloat(op, dur.TypeName, dur.DurationVal(), double.DoubleVal())

	return result, true, err
}

func arithmeticDurationExact(ctx context.Context, op TokenType, typeName string, d xdm.Duration, number *big.Rat) (xdm.Sequence, error) {
	if number.Sign() == 0 {
		if op == TokenDiv {
			return nil, &xdm.Error{Code: errCodeFODT0002, Message: "division of duration by zero"}
		}

		return xdm.SingleAtomic(xdm.AtomicValue{TypeName: typeName, Value: xdm.Duration{}}), nil
	}

	value := xdm.DurationToRat(d, typeName == xdm.TypeYearMonthDuration)
	if err := preflightDecimal(ctx, op, value, number); err != nil {
		return nil, err
	}

	result := new(big.Rat)
	if op == TokenStar {
		result.Mul(value, number)
	} else {
		result.Quo(value, number)
	}

	if typeName == xdm.TypeYearMonthDuration {
		rounded := ratRound(result)

		return durationFromMonthCount(new(big.Int).Quo(rounded.Num(), rounded.Denom()))
	}

	if op == TokenDiv {
		var err error

		result, err = finiteDecimalValue(ctx, result)
		if err != nil {
			return nil, err
		}
	}

	if err := ChargeNumber(ctx, xdm.AtomicValue{TypeName: xdm.TypeDecimal, Value: result}); err != nil {
		return nil, err
	}

	return durationFromExactSeconds(typeName, result), nil
}

func arithmeticDateTimeDuration(op TokenType, dt, dur xdm.AtomicValue) (xdm.Sequence, bool, error) {
	if op != TokenPlus && op != TokenMinus {
		return nil, true, &xdm.Error{Code: lexicon.ErrXPTY0004, Message: "invalid operator for date/time ± duration"}
	}

	if dur.TypeName == xdm.TypeDuration {
		return nil, true, &xdm.Error{Code: lexicon.ErrXPTY0004, Message: textXsDurationCannotBeUsedInArithmetic}
	}

	// xs:time can only be combined with xs:dayTimeDuration, not xs:yearMonthDuration
	if dt.TypeName == xdm.TypeTime && (dur.TypeName == xdm.TypeYearMonthDuration || dur.TypeName == xdm.TypeDuration) {
		return nil, true, &xdm.Error{Code: lexicon.ErrXPTY0004, Message: "cannot combine xs:time with xs:yearMonthDuration"}
	}

	t := dt.TimeVal()
	d := dur.DurationVal()

	// Normalize duration sign
	months := d.Months
	if d.Negative {
		months = -months
	}

	if op == TokenMinus {
		months = -months
	}

	// secsRat is the EXACT total dayTime seconds to add (signed), read from the
	// SecRat-aware rational so a fraction arbitrarily close to a whole second is
	// not rounded up via float64.
	secsRat := xdm.DurationToRat(d, false)
	if op == TokenMinus {
		secsRat = new(big.Rat).Neg(secsRat)
	}

	if dt.TypeName == xdm.TypeTime {
		// F&O 9.7.13 discards whole days before adding to the reference date.
		// A large valid duration must not overflow a date that is not returned.
		days := new(big.Int).Quo(secsRat.Num(), new(big.Int).Mul(secsRat.Denom(), big.NewInt(86400)))
		wholeDays := new(big.Rat).SetInt(new(big.Int).Mul(days, big.NewInt(86400)))
		secsRat = new(big.Rat).Sub(secsRat, wholeDays)
	}

	if months != 0 {
		// time.AddDate computes the result via int month arithmetic that silently
		// wraps for magnitudes near math.MaxInt, so reject month magnitudes beyond a
		// conservative bound that keeps the result within representable years.
		if int64(months) > maxSafeAddDateMonths || int64(months) < -maxSafeAddDateMonths {
			return nil, true, &xdm.Error{Code: errCodeFODT0001, Message: "date/time arithmetic overflow: month count out of range"}
		}

		if !resultYearFits(t, int64(max(months, -months)/12+1)) {
			return nil, true, &xdm.Error{Code: errCodeFODT0001, Message: "date/time arithmetic overflow: result year out of range"}
		}

		t = addMonths(t, int64(months))
	}

	// Add seconds exactly: split into whole seconds and a sub-second nanosecond
	// remainder. Whole seconds are added as days + sub-day seconds via AddDate so
	// large magnitudes never overflow time.Duration's int64-nanosecond range.
	if secsRat.Sign() != 0 {
		abs := secsRat
		neg := false

		if abs.Sign() < 0 {
			abs = new(big.Rat).Neg(abs)
			neg = true
		}

		whole := new(big.Int).Quo(abs.Num(), abs.Denom())
		frac := new(big.Rat).Sub(abs, new(big.Rat).SetInt(whole))
		// Nanosecond remainder (truncated; sub-nanosecond precision is below the
		// representable resolution of time.Time).
		nanoRat := new(big.Rat).Mul(frac, big.NewRat(1e9, 1))
		nanos := new(big.Int).Quo(nanoRat.Num(), nanoRat.Denom()).Int64()

		days := new(big.Int)
		remSecs := new(big.Int)
		days.QuoRem(whole, big.NewInt(86400), remSecs)
		// The day count can exceed int (e.g. P9223372036854775808D). Even within the
		// int range, time.AddDate computes the result via int day arithmetic that
		// silently wraps for magnitudes near math.MaxInt (e.g. 2^60 days returns the
		// original date unchanged). Reject any day magnitude beyond a conservative
		// bound that keeps the result well within time.Time's representable years.
		if days.CmpAbs(big.NewInt(maxSafeAddDateDays)) > 0 {
			return nil, true, &xdm.Error{Code: errCodeFODT0001, Message: "date/time arithmetic overflow: day count out of range"}
		}

		if !resultYearFits(t, days.Int64()/365+1) {
			return nil, true, &xdm.Error{Code: errCodeFODT0001, Message: "date/time arithmetic overflow: result year out of range"}
		}

		sign := 1
		if neg {
			sign = -1
		}

		t = addDays(t, sign, days.Int64())
		t = t.Add(time.Duration(sign) * time.Duration(remSecs.Int64()) * time.Second)
		t = t.Add(time.Duration(sign) * time.Duration(nanos) * time.Nanosecond)
	}

	// For xs:date results, strip the time component to keep only the date
	if dt.TypeName == xdm.TypeDate {
		t = time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, t.Location())
	}

	return xdm.SingleAtomic(xdm.AtomicValue{
		TypeName: dt.TypeName,
		Value:    t,
	}), true, nil
}

// resultYearFits reports whether moving t by up to moveYears years, in either
// direction, keeps the result year within ±maxResultYear. Callers round the
// move up to whole years, so the check may reject a result within a year of
// the bound. They have bounded the move by maxSafeAddDateYears, so the sums
// below cannot overflow int64.
func resultYearFits(t time.Time, moveYears int64) bool {
	year := int64(t.Year())
	return year+moveYears <= maxResultYear && year-moveYears >= -maxResultYear
}

// addMonths adds months to a time.Time, clamping the day per XSD rules.
// Uses time.AddDate for the heavy lifting; detects day overflow (e.g. Jan 31 + 1 month
// normalizing to Mar 3) and clamps to the last day of the target month. The
// month count is split into whole years and remaining months, so each AddDate
// operand fits in int even where int is 32 bits; AddDate normalizes months
// into years exactly, so the split does not change the result. The caller
// bounds |months| by maxSafeAddDateMonths.
func addMonths(t time.Time, months int64) time.Time {
	years := int(months / 12)
	rem := int(months % 12)

	result := t.AddDate(years, rem, 0)
	if result.Day() != t.Day() {
		// Day overflowed — go back to last day of the intended month
		result = t.AddDate(years, rem+1, -t.Day())
	}

	return result
}

// addDays moves t by sign*days calendar days. Each time.AddDate call takes at
// most addDateDayChunk days, so the day operand fits in int even where int is
// 32 bits. The caller bounds days by maxSafeAddDateDays.
func addDays(t time.Time, sign int, days int64) time.Time {
	for days > addDateDayChunk {
		t = t.AddDate(0, 0, sign*addDateDayChunk)
		days -= addDateDayChunk
	}

	return t.AddDate(0, 0, sign*int(days))
}

// arithmeticDateTimeDatetime handles dateTime - dateTime, date - date, time - time.
// Per XPath spec, if either operand lacks a timezone, the implicit timezone is applied.
func arithmeticDateTimeDatetime(ec *evalContext, la, ra xdm.AtomicValue) (xdm.Sequence, bool, error) {
	ta := la.TimeVal()
	tb := ra.TimeVal()

	// Per XPath spec, apply implicit timezone to operands that lack an explicit timezone.
	// Use attachTimezone (not In) to preserve the local time components.
	implicitTZ := ec.getImplicitTimezone()
	if !xdm.HasTimezone(ta) {
		ta = attachTimezone(ta, implicitTZ)
	}

	if !xdm.HasTimezone(tb) {
		tb = attachTimezone(tb, implicitTZ)
	}

	// Compute the difference as an EXACT rational of total seconds so that two
	// dateTimes one second (or one nanosecond) apart never collapse to the same
	// value via float64 rounding. Build:
	//   dayDelta*86400 + timeDelta − tzDelta  (+ nanoseconds / 1e9)
	// entirely with big.Int / big.Rat.
	aDays := julianDayNumber(ta.Year(), int(ta.Month()), ta.Day())
	bDays := julianDayNumber(tb.Year(), int(tb.Month()), tb.Day())

	aTimeSecs := int64(ta.Hour())*3600 + int64(ta.Minute())*60 + int64(ta.Second())
	bTimeSecs := int64(tb.Hour())*3600 + int64(tb.Minute())*60 + int64(tb.Second())

	_, aOff := ta.Zone()
	_, bOff := tb.Zone()

	// Whole-second magnitude: dayDelta*86400 + timeDelta − tzDelta. Each term is
	// added via big.Int so the day count (which can exceed the int64 second range
	// for very distant dates) never overflows.
	dayDelta := new(big.Int).Sub(big.NewInt(aDays), big.NewInt(bDays))
	wholeSecsInt := new(big.Int).Mul(dayDelta, big.NewInt(86400))
	wholeSecsInt.Add(wholeSecsInt, big.NewInt(aTimeSecs-bTimeSecs))
	wholeSecsInt.Sub(wholeSecsInt, big.NewInt(int64(aOff)-int64(bOff)))

	// Exact total seconds = wholeSecsInt + nanoDelta/1e9.
	nanoDelta := int64(ta.Nanosecond()) - int64(tb.Nanosecond())

	secRat := new(big.Rat).SetInt(wholeSecsInt)
	if nanoDelta != 0 {
		secRat.Add(secRat, new(big.Rat).SetFrac(big.NewInt(nanoDelta), big.NewInt(1e9)))
	}

	negative := secRat.Sign() < 0

	absRat := secRat
	if negative {
		absRat = new(big.Rat).Neg(secRat)
	}

	secs, frac := durationFromRatSeconds(absRat)

	return xdm.SingleAtomic(xdm.AtomicValue{
		TypeName: xdm.TypeDayTimeDuration,
		Value:    xdm.Duration{Seconds: secs, FracSec: frac, SecRat: absRat, Negative: negative},
	}), true, nil
}

func arithmeticDurationDivDuration(ctx context.Context, la, ra xdm.AtomicValue) (xdm.Sequence, bool, error) {
	// xs:duration (generic) does not support arithmetic
	if la.TypeName == xdm.TypeDuration || ra.TypeName == xdm.TypeDuration {
		return nil, true, &xdm.Error{Code: lexicon.ErrXPTY0004, Message: textXsDurationCannotBeUsedInArithmetic}
	}
	// Cannot mix YMD and DTD
	if la.TypeName != ra.TypeName {
		return nil, true, &xdm.Error{Code: lexicon.ErrXPTY0004, Message: "cannot divide different duration subtypes"}
	}

	ld := la.DurationVal()
	rd := ra.DurationVal()

	isYM := la.TypeName == xdm.TypeYearMonthDuration

	// Legacy float-only durations (no SecRat) cannot exactly represent seconds
	// beyond 2^53, so reject them. When SecRat is present the exact magnitude is
	// authoritative and durationToRat reads it directly, so no cap applies.
	if !isYM {
		const maxExactFloat64 = 1 << 53
		if ld.SecRat == nil && ld.Seconds > maxExactFloat64 {
			return nil, true, &xdm.Error{Code: errCodeFODT0002, Message: "dayTimeDuration value too large for exact division"}
		}

		if rd.SecRat == nil && rd.Seconds > maxExactFloat64 {
			return nil, true, &xdm.Error{Code: errCodeFODT0002, Message: "dayTimeDuration value too large for exact division"}
		}
	}

	lRat := xdm.DurationToRat(ld, isYM)
	rRat := xdm.DurationToRat(rd, ra.TypeName == xdm.TypeYearMonthDuration)

	if rRat.Sign() == 0 {
		return nil, true, &xdm.Error{Code: errCodeFOAR0001, Message: "division of duration by zero duration"}
	}

	r := new(big.Rat).Quo(lRat, rRat)

	result, err := decimalQuotient(ctx, r)

	return result, true, err
}

// durationFromRatSeconds splits a non-negative exact total-seconds rational
// into the float64 Seconds field (whole seconds plus fractional part, kept for
// compatibility with the rest of the Duration machinery) and an exact FracSec
// rational holding the fractional part in [0,1). Storing the exact fraction lets
// arithmetic-created durations canonicalize identically to parsed ones.
func durationFromRatSeconds(secsRat *big.Rat) (float64, *big.Rat) {
	// Whole seconds = floor(secsRat) for a non-negative value.
	whole := new(big.Int).Quo(secsRat.Num(), secsRat.Denom())
	frac := new(big.Rat).Sub(secsRat, new(big.Rat).SetInt(whole))

	secs, _ := secsRat.Float64()
	if frac.Sign() == 0 {
		return secs, nil
	}

	return secs, frac
}

// attachTimezone sets the timezone on a time value without converting the local
// time components. This is used when the XPath spec says to "apply" the implicit
// timezone to a timezone-less value: the local time stays the same, only the
// timezone label changes. This differs from time.In() which preserves the UTC
// instant and changes the local representation.
func attachTimezone(t time.Time, loc *time.Location) time.Time {
	return time.Date(t.Year(), t.Month(), t.Day(), t.Hour(), t.Minute(), t.Second(), t.Nanosecond(), loc)
}

func resultDurationType(a, b string) string {
	if a == xdm.TypeYearMonthDuration && b == xdm.TypeYearMonthDuration {
		return xdm.TypeYearMonthDuration
	}

	if a == xdm.TypeDayTimeDuration && b == xdm.TypeDayTimeDuration {
		return xdm.TypeDayTimeDuration
	}

	return xdm.TypeDuration
}

func arithmeticDurationFloat(op TokenType, typeName string, d xdm.Duration, n float64) (xdm.Sequence, error) {
	if math.IsNaN(n) {
		return nil, &xdm.Error{Code: "FOCA0005", Message: "NaN in duration arithmetic"}
	}

	if op == TokenDiv && n == 0 {
		return nil, &xdm.Error{Code: errCodeFODT0002, Message: "division of duration by zero"}
	}

	if op == TokenStar && math.IsInf(n, 0) {
		return nil, &xdm.Error{Code: errCodeFODT0002, Message: textDurationOverflow}
	}

	if op == TokenStar && n == 0 || op == TokenDiv && math.IsInf(n, 0) {
		return xdm.SingleAtomic(xdm.AtomicValue{TypeName: typeName, Value: xdm.Duration{}}), nil
	}

	value := float64(d.Months)
	if typeName == xdm.TypeDayTimeDuration {
		value, _ = xdm.DurationToRat(d, false).Float64()
	} else if d.Negative {
		value = -value
	}

	if op == TokenStar {
		value *= n
	} else {
		value /= n
	}

	if math.IsInf(value, 0) || math.IsNaN(value) {
		return nil, &xdm.Error{Code: errCodeFODT0002, Message: textDurationOverflow}
	}

	if typeName == xdm.TypeYearMonthDuration {
		return durationFromRoundedMonths(value)
	}

	return durationFromExactSeconds(typeName, new(big.Rat).SetFloat64(value)), nil
}

func durationFromExactSeconds(typeName string, seconds *big.Rat) xdm.Sequence {
	negative := seconds.Sign() < 0
	seconds.Abs(seconds)
	whole, fraction := durationFromRatSeconds(seconds)

	return xdm.SingleAtomic(xdm.AtomicValue{
		TypeName: typeName,
		Value:    xdm.Duration{Seconds: whole, FracSec: fraction, SecRat: seconds, Negative: negative},
	})
}

func durationFromRoundedMonths(value float64) (xdm.Sequence, error) {
	rounded, _ := new(big.Float).SetFloat64(roundHalfUpFloat(value, 0)).Int(nil)

	return durationFromMonthCount(rounded)
}

func durationFromMonthCount(rounded *big.Int) (xdm.Sequence, error) {
	negative := rounded.Sign() < 0
	rounded.Abs(rounded)

	if !rounded.IsInt64() || rounded.Int64() > int64(math.MaxInt) {
		return nil, &xdm.Error{Code: errCodeFODT0002, Message: "duration overflow: month count out of int range"}
	}

	return xdm.SingleAtomic(xdm.AtomicValue{
		TypeName: xdm.TypeYearMonthDuration,
		Value:    xdm.Duration{Months: int(rounded.Int64()), Negative: negative},
	}), nil
}
