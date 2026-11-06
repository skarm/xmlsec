// Derived from lestrrat-go/helium at 7362c0a70122a757780f4d0b545a9b370dead6ab.
// Copyright (c) 2015 lestrrat. MIT License; see licenses/MIT-helium.txt at the repository root.

package xpath

import (
	"context"
	"math/big"
	"time"

	"github.com/skarm/xmlsec/internal/lexicon"
	"github.com/skarm/xmlsec/transform/internal/xdm"
)

// Date/time function local names are separate from XSD type names. These
// namespace dispatch values preserve the exact case required by F&O.
const (
	fnNameYearFromDateTime         = "year-from-dateTime"
	fnNameMonthFromDateTime        = "month-from-dateTime"
	fnNameDayFromDateTime          = "day-from-dateTime"
	fnNameHoursFromDateTime        = "hours-from-dateTime"
	fnNameMinutesFromDateTime      = "minutes-from-dateTime"
	fnNameSecondsFromDateTime      = "seconds-from-dateTime"
	fnNameTimezoneFromDateTime     = "timezone-from-dateTime"
	fnNameYearFromDate             = "year-from-date"
	fnNameMonthFromDate            = "month-from-date"
	fnNameDayFromDate              = "day-from-date"
	fnNameTimezoneFromDate         = "timezone-from-date"
	fnNameHoursFromTime            = "hours-from-time"
	fnNameMinutesFromTime          = "minutes-from-time"
	fnNameSecondsFromTime          = "seconds-from-time"
	fnNameTimezoneFromTime         = "timezone-from-time"
	fnNameYearsFromDuration        = "years-from-duration"
	fnNameMonthsFromDuration       = "months-from-duration"
	fnNameDaysFromDuration         = "days-from-duration"
	fnNameHoursFromDuration        = "hours-from-duration"
	fnNameMinutesFromDuration      = "minutes-from-duration"
	fnNameSecondsFromDuration      = "seconds-from-duration"
	fnNameAdjustDateTimeToTimezone = "adjust-dateTime-to-timezone"
	fnNameAdjustDateToTimezone     = "adjust-date-to-timezone"
	fnNameAdjustTimeToTimezone     = "adjust-time-to-timezone"
)

// The timezone ceiling is fourteen hours expressed in seconds. DurationToRat's
// false useMonths selector requests exact seconds rather than calendar months.
const (
	timezoneMaximumOffsetSeconds = maximumTimezoneHours * calendarSecondsPerHour
	durationSecondsComponent     = false
)

func lookupFunctionsDatetime(name string) (*builtinFunc, bool) {
	switch name {
	case lexicon.TypeDateTime:
		return &builtinFunc{name: name, min: builtinArityTwo, max: builtinArityTwo, fn: fnDateTime}, true
	case fnNameYearFromDateTime:
		return &builtinFunc{name: name, min: builtinArityOne, max: builtinArityOne, fn: fnYearFromDateTime}, true
	case fnNameMonthFromDateTime:
		return &builtinFunc{name: name, min: builtinArityOne, max: builtinArityOne, fn: fnMonthFromDateTime}, true
	case fnNameDayFromDateTime:
		return &builtinFunc{name: name, min: builtinArityOne, max: builtinArityOne, fn: fnDayFromDateTime}, true
	case fnNameHoursFromDateTime:
		return &builtinFunc{name: name, min: builtinArityOne, max: builtinArityOne, fn: fnHoursFromDateTime}, true
	case fnNameMinutesFromDateTime:
		return &builtinFunc{name: name, min: builtinArityOne, max: builtinArityOne, fn: fnMinutesFromDateTime}, true
	case fnNameSecondsFromDateTime:
		return &builtinFunc{name: name, min: builtinArityOne, max: builtinArityOne, fn: fnSecondsFromDateTime}, true
	case fnNameTimezoneFromDateTime:
		return &builtinFunc{name: name, min: builtinArityOne, max: builtinArityOne, fn: fnTimezoneFromDateTime}, true
	case fnNameYearFromDate:
		return &builtinFunc{name: name, min: builtinArityOne, max: builtinArityOne, fn: fnYearFromDate}, true
	case fnNameMonthFromDate:
		return &builtinFunc{name: name, min: builtinArityOne, max: builtinArityOne, fn: fnMonthFromDate}, true
	case fnNameDayFromDate:
		return &builtinFunc{name: name, min: builtinArityOne, max: builtinArityOne, fn: fnDayFromDate}, true
	case fnNameTimezoneFromDate:
		return &builtinFunc{name: name, min: builtinArityOne, max: builtinArityOne, fn: fnTimezoneFromDate}, true
	case fnNameHoursFromTime:
		return &builtinFunc{name: name, min: builtinArityOne, max: builtinArityOne, fn: fnHoursFromTime}, true
	case fnNameMinutesFromTime:
		return &builtinFunc{name: name, min: builtinArityOne, max: builtinArityOne, fn: fnMinutesFromTime}, true
	case fnNameSecondsFromTime:
		return &builtinFunc{name: name, min: builtinArityOne, max: builtinArityOne, fn: fnSecondsFromTime}, true
	case fnNameTimezoneFromTime:
		return &builtinFunc{name: name, min: builtinArityOne, max: builtinArityOne, fn: fnTimezoneFromTime}, true
	case fnNameYearsFromDuration:
		return &builtinFunc{name: name, min: builtinArityOne, max: builtinArityOne, fn: fnYearsFromDuration}, true
	case fnNameMonthsFromDuration:
		return &builtinFunc{name: name, min: builtinArityOne, max: builtinArityOne, fn: fnMonthsFromDuration}, true
	case fnNameDaysFromDuration:
		return &builtinFunc{name: name, min: builtinArityOne, max: builtinArityOne, fn: fnDaysFromDuration}, true
	case fnNameHoursFromDuration:
		return &builtinFunc{name: name, min: builtinArityOne, max: builtinArityOne, fn: fnHoursFromDuration}, true
	case fnNameMinutesFromDuration:
		return &builtinFunc{name: name, min: builtinArityOne, max: builtinArityOne, fn: fnMinutesFromDuration}, true
	case fnNameSecondsFromDuration:
		return &builtinFunc{name: name, min: builtinArityOne, max: builtinArityOne, fn: fnSecondsFromDuration}, true
	case fnNameAdjustDateTimeToTimezone:
		return &builtinFunc{name: name, min: builtinArityOne, max: builtinArityTwo, fn: fnAdjustDateTimeToTimezone}, true
	case fnNameAdjustDateToTimezone:
		return &builtinFunc{name: name, min: builtinArityOne, max: builtinArityTwo, fn: fnAdjustDateToTimezone}, true
	case fnNameAdjustTimeToTimezone:
		return &builtinFunc{name: name, min: builtinArityOne, max: builtinArityTwo, fn: fnAdjustTimeToTimezone}, true
	case fnNameFormatDateTime:
		return &builtinFunc{name: name, min: builtinArityTwo, max: builtinArityFive, arities: []int{builtinArityTwo, builtinArityFive}, fn: fnFormatDateTime}, true
	case fnNameFormatDate:
		return &builtinFunc{name: name, min: builtinArityTwo, max: builtinArityFive, arities: []int{builtinArityTwo, builtinArityFive}, fn: fnFormatDate}, true
	case fnNameFormatTime:
		return &builtinFunc{name: name, min: builtinArityTwo, max: builtinArityFive, arities: []int{builtinArityTwo, builtinArityFive}, fn: fnFormatTime}, true
	}

	return nil, false
}

func extractTime(seq xdm.Sequence, allowedTypes ...string) (time.Time, bool, error) {
	if xdm.SequenceLen(seq) == 0 {
		return time.Time{}, false, nil
	}

	a, err := AtomizeItem(seq.Get(0))
	if err != nil {
		return time.Time{}, false, err
	}

	t, ok := a.Value.(time.Time)
	if !ok {
		return time.Time{}, false, &xdm.Error{Code: lexicon.ErrXPTY0004, Message: "expected " + allowedTypes[0] + ", got " + a.TypeName}
	}

	if len(allowedTypes) > 0 {
		matched := false

		for _, at := range allowedTypes {
			if xdm.IsSubtypeOf(a.TypeName, at) {
				matched = true
				break
			}
		}
		// For user-defined types, the Go value is time.Time which we already
		// validated above — accept it without type-name check.
		if !matched && xdm.IsKnownXSDType(a.TypeName) {
			return time.Time{}, false, &xdm.Error{Code: lexicon.ErrXPTY0004, Message: "expected " + allowedTypes[0] + ", got " + a.TypeName}
		}
	}

	return t, true, nil
}

func extractDuration(seq xdm.Sequence, allowedTypes ...string) (xdm.Duration, bool, error) {
	if xdm.SequenceLen(seq) == 0 {
		return xdm.Duration{}, false, nil
	}

	a, err := AtomizeItem(seq.Get(0))
	if err != nil {
		return xdm.Duration{}, false, err
	}

	d, ok := a.Value.(xdm.Duration)
	if !ok {
		return xdm.Duration{}, false, &xdm.Error{Code: lexicon.ErrXPTY0004, Message: "expected duration type, got " + a.TypeName}
	}

	if len(allowedTypes) > 0 {
		matched := false

		for _, at := range allowedTypes {
			// BaseType-aware so a schema-derived duration (whose TypeName is a
			// user-defined type derived by restriction) still satisfies the
			// accessor/timezone consumers via its built-in base type.
			if xdm.IsAtomicSubtypeOf(a, at) {
				matched = true
				break
			}
		}

		if !matched {
			return xdm.Duration{}, false, &xdm.Error{Code: lexicon.ErrXPTY0004, Message: "expected " + allowedTypes[0] + ", got " + a.TypeName}
		}
	}

	return d, true, nil
}

// --- Constructors ---

func fnDateTime(_ context.Context, args []xdm.Sequence) (xdm.Sequence, error) {
	if xdm.SequenceLen(args[0]) == 0 || xdm.SequenceLen(args[1]) == 0 {
		return nil, nil
	}

	dateA, err := AtomizeItem(args[0].Get(0))
	if err != nil {
		return nil, err
	}

	timeA, err := AtomizeItem(args[1].Get(0))
	if err != nil {
		return nil, err
	}
	// Coerce xs:untypedAtomic to xs:date / xs:time.
	if dateA.TypeName == xdm.TypeUntypedAtomic || dateA.TypeName == xdm.TypeString {
		dateA, err = CastAtomic(dateA, xdm.TypeDate)
		if err != nil {
			return nil, err
		}
	}

	if timeA.TypeName == xdm.TypeUntypedAtomic || timeA.TypeName == xdm.TypeString {
		timeA, err = CastAtomic(timeA, xdm.TypeTime)
		if err != nil {
			return nil, err
		}
	}
	// Per XPath F&O fn:dateTime($arg1 as xs:date?, $arg2 as xs:time?): the
	// first argument must be xs:date and the second xs:time. By XSD subtype
	// substitution this also accepts any type derived from xs:date / xs:time.
	// Checking only for a time.Time payload is not enough — xs:dateTime (a
	// sibling of xs:date, not a subtype) also carries one and would be silently
	// reinterpreted; it must still be rejected.
	if !xdm.IsAtomicSubtypeOf(dateA, xdm.TypeDate) {
		return nil, &xdm.Error{Code: lexicon.ErrXPTY0004, Message: "first arg must be xs:date, got " + dateA.TypeName}
	}

	if !xdm.IsAtomicSubtypeOf(timeA, xdm.TypeTime) {
		return nil, &xdm.Error{Code: lexicon.ErrXPTY0004, Message: "second arg must be xs:time, got " + timeA.TypeName}
	}

	d, ok := dateA.Value.(time.Time)
	if !ok {
		return nil, &xdm.Error{Code: lexicon.ErrXPTY0004, Message: "first arg must be xs:date, got " + dateA.TypeName}
	}

	t, ok := timeA.Value.(time.Time)
	if !ok {
		return nil, &xdm.Error{Code: lexicon.ErrXPTY0004, Message: "second arg must be xs:time, got " + timeA.TypeName}
	}

	// Per XPath F&O 3.0 §5.2.1: determine timezone from arguments.
	// If both have timezones, they must be equal. If one has a timezone, use it.
	// If neither has a timezone, the result has none.
	dateHasTZ := xdm.HasTimezone(d)
	timeHasTZ := xdm.HasTimezone(t)

	var loc *time.Location

	switch {
	case dateHasTZ && timeHasTZ:
		_, doff := d.Zone()

		_, toff := t.Zone()
		if doff != toff {
			return nil, &xdm.Error{Code: errCodeFORG0008, Message: "date and time timezone values are not equal"}
		}

		loc = d.Location()
	case dateHasTZ:
		loc = d.Location()
	case timeHasTZ:
		loc = t.Location()
	default:
		loc = xdm.NoTimezone() // no timezone
	}

	combined := time.Date(d.Year(), d.Month(), d.Day(), t.Hour(), t.Minute(), t.Second(), t.Nanosecond(), loc)

	return xdm.SingleAtomic(xdm.AtomicValue{TypeName: xdm.TypeDateTime, Value: combined}), nil
}

// --- dateTime accessors ---

func fnYearFromDateTime(_ context.Context, args []xdm.Sequence) (xdm.Sequence, error) {
	t, ok, err := extractTime(args[0], xdm.TypeDateTime)
	if err != nil {
		return nil, err
	}

	if !ok {
		return nil, nil
	}

	return xdm.SingleInteger(int64(t.Year())), nil
}

func fnMonthFromDateTime(_ context.Context, args []xdm.Sequence) (xdm.Sequence, error) {
	t, ok, err := extractTime(args[0], xdm.TypeDateTime)
	if err != nil {
		return nil, err
	}

	if !ok {
		return nil, nil
	}

	return xdm.SingleInteger(int64(t.Month())), nil
}

func fnDayFromDateTime(_ context.Context, args []xdm.Sequence) (xdm.Sequence, error) {
	t, ok, err := extractTime(args[0], xdm.TypeDateTime)
	if err != nil {
		return nil, err
	}

	if !ok {
		return nil, nil
	}

	return xdm.SingleInteger(int64(t.Day())), nil
}

func fnHoursFromDateTime(_ context.Context, args []xdm.Sequence) (xdm.Sequence, error) {
	t, ok, err := extractTime(args[0], xdm.TypeDateTime)
	if err != nil {
		return nil, err
	}

	if !ok {
		return nil, nil
	}

	return xdm.SingleInteger(int64(t.Hour())), nil
}

func fnMinutesFromDateTime(_ context.Context, args []xdm.Sequence) (xdm.Sequence, error) {
	t, ok, err := extractTime(args[0], xdm.TypeDateTime)
	if err != nil {
		return nil, err
	}

	if !ok {
		return nil, nil
	}

	return xdm.SingleInteger(int64(t.Minute())), nil
}

func fnSecondsFromDateTime(_ context.Context, args []xdm.Sequence) (xdm.Sequence, error) {
	t, ok, err := extractTime(args[0], xdm.TypeDateTime)
	if err != nil {
		return nil, err
	}

	if !ok {
		return nil, nil
	}

	return xdm.SingleDecimal(secondsToRat(t)), nil
}

func fnTimezoneFromDateTime(ctx context.Context, args []xdm.Sequence) (xdm.Sequence, error) {
	return timezoneFromTemporal(ctx, args[0], xdm.TypeDateTime)
}

// --- date accessors ---

func fnYearFromDate(_ context.Context, args []xdm.Sequence) (xdm.Sequence, error) {
	t, ok, err := extractTime(args[0], xdm.TypeDate)
	if err != nil {
		return nil, err
	}

	if !ok {
		return nil, nil
	}

	return xdm.SingleInteger(int64(t.Year())), nil
}

func fnMonthFromDate(_ context.Context, args []xdm.Sequence) (xdm.Sequence, error) {
	t, ok, err := extractTime(args[0], xdm.TypeDate)
	if err != nil {
		return nil, err
	}

	if !ok {
		return nil, nil
	}

	return xdm.SingleInteger(int64(t.Month())), nil
}

func fnDayFromDate(_ context.Context, args []xdm.Sequence) (xdm.Sequence, error) {
	t, ok, err := extractTime(args[0], xdm.TypeDate)
	if err != nil {
		return nil, err
	}

	if !ok {
		return nil, nil
	}

	return xdm.SingleInteger(int64(t.Day())), nil
}

func fnTimezoneFromDate(ctx context.Context, args []xdm.Sequence) (xdm.Sequence, error) {
	return timezoneFromTemporal(ctx, args[0], xdm.TypeDate)
}

// --- time accessors ---

func fnHoursFromTime(_ context.Context, args []xdm.Sequence) (xdm.Sequence, error) {
	t, ok, err := extractTime(args[0], xdm.TypeTime)
	if err != nil {
		return nil, err
	}

	if !ok {
		return nil, nil
	}

	return xdm.SingleInteger(int64(t.Hour())), nil
}

func fnMinutesFromTime(_ context.Context, args []xdm.Sequence) (xdm.Sequence, error) {
	t, ok, err := extractTime(args[0], xdm.TypeTime)
	if err != nil {
		return nil, err
	}

	if !ok {
		return nil, nil
	}

	return xdm.SingleInteger(int64(t.Minute())), nil
}

func fnSecondsFromTime(_ context.Context, args []xdm.Sequence) (xdm.Sequence, error) {
	t, ok, err := extractTime(args[0], xdm.TypeTime)
	if err != nil {
		return nil, err
	}

	if !ok {
		return nil, nil
	}

	return xdm.SingleDecimal(secondsToRat(t)), nil
}

// secondsToRat returns the seconds component (0..59) plus the fractional
// nanoseconds of t as an exact rational, for the xs:decimal-typed
// fn:seconds-from-dateTime / fn:seconds-from-time results (F&O 3.1 §9.5.10/§9.5.14).
func secondsToRat(t time.Time) *big.Rat {
	r := new(big.Rat).SetInt64(int64(t.Second()))
	if ns := t.Nanosecond(); ns != 0 {
		r.Add(r, new(big.Rat).SetFrac(big.NewInt(int64(ns)), big.NewInt(nanosecondsPerSecond)))
	}

	return r
}

func fnTimezoneFromTime(ctx context.Context, args []xdm.Sequence) (xdm.Sequence, error) {
	return timezoneFromTemporal(ctx, args[0], xdm.TypeTime)
}

func timezoneFromTemporal(ctx context.Context, arg xdm.Sequence, typeName string) (xdm.Sequence, error) {
	t, ok, err := extractTime(arg, typeName)
	if err != nil {
		return nil, err
	}

	if !ok {
		return nil, nil
	}

	if !xdm.HasTimezone(t) {
		return nil, nil
	}

	_, offset := t.Zone()
	neg := offset < 0

	absOffset := offset
	if neg {
		absOffset = -absOffset
	}
	// Carry the exact integer-second magnitude in SecRat so the timezone-duration
	// path is exact by construction (sign lives in Negative).
	d := xdm.Duration{Seconds: float64(absOffset), SecRat: big.NewRat(int64(absOffset), 1), Negative: neg}

	return boundedDurationResult(ctx, xdm.AtomicValue{TypeName: xdm.TypeDayTimeDuration, Value: d})
}

// --- duration accessors ---

func fnYearsFromDuration(_ context.Context, args []xdm.Sequence) (xdm.Sequence, error) {
	d, ok, err := extractDuration(args[0], xdm.TypeDuration)
	if err != nil {
		return nil, err
	}

	if !ok {
		return nil, nil
	}

	years := d.Months / calendarMonthsPerYear
	if d.Negative {
		years = -years
	}

	return xdm.SingleInteger(int64(years)), nil
}

func fnMonthsFromDuration(_ context.Context, args []xdm.Sequence) (xdm.Sequence, error) {
	d, ok, err := extractDuration(args[0], xdm.TypeDuration)
	if err != nil {
		return nil, err
	}

	if !ok {
		return nil, nil
	}

	months := d.Months % calendarMonthsPerYear
	if d.Negative {
		months = -months
	}

	return xdm.SingleInteger(int64(months)), nil
}

// dayTimeWholeSeconds returns the floor of the absolute total dayTime seconds
// magnitude as a big.Int, using the exact SecRat-aware durationToRat value so
// components stay correct even for fractions arbitrarily close to a whole
// second (where the float64 Seconds field would round up).
func dayTimeWholeSeconds(d xdm.Duration) *big.Int {
	total := xdm.DurationToRat(d, durationSecondsComponent)

	abs := total
	if abs.Sign() < 0 {
		abs = new(big.Rat).Neg(abs)
	}

	return new(big.Int).Quo(abs.Num(), abs.Denom())
}

func fnDaysFromDuration(_ context.Context, args []xdm.Sequence) (xdm.Sequence, error) {
	d, ok, err := extractDuration(args[0], xdm.TypeDuration)
	if err != nil {
		return nil, err
	}

	if !ok {
		return nil, nil
	}

	days := new(big.Int).Quo(dayTimeWholeSeconds(d), big.NewInt(calendarSecondsPerDay))
	if d.Negative {
		days.Neg(days)
	}
	// The day count can exceed int64 (e.g. P9223372036854775808D), so return the
	// exact big.Int, narrowing through no Int64().
	return xdm.SingleIntegerBig(days), nil
}

func fnHoursFromDuration(_ context.Context, args []xdm.Sequence) (xdm.Sequence, error) {
	d, ok, err := extractDuration(args[0], xdm.TypeDuration)
	if err != nil {
		return nil, err
	}

	if !ok {
		return nil, nil
	}

	withinDay := new(big.Int).Rem(dayTimeWholeSeconds(d), big.NewInt(calendarSecondsPerDay))

	hours := new(big.Int).Quo(withinDay, big.NewInt(calendarSecondsPerHour))
	if d.Negative {
		hours.Neg(hours)
	}

	return xdm.SingleInteger(hours.Int64()), nil
}

func fnMinutesFromDuration(_ context.Context, args []xdm.Sequence) (xdm.Sequence, error) {
	d, ok, err := extractDuration(args[0], xdm.TypeDuration)
	if err != nil {
		return nil, err
	}

	if !ok {
		return nil, nil
	}

	withinHour := new(big.Int).Rem(dayTimeWholeSeconds(d), big.NewInt(calendarSecondsPerHour))

	minutes := new(big.Int).Quo(withinHour, big.NewInt(calendarSecondsPerMinute))
	if d.Negative {
		minutes.Neg(minutes)
	}

	return xdm.SingleInteger(minutes.Int64()), nil
}

func fnSecondsFromDuration(_ context.Context, args []xdm.Sequence) (xdm.Sequence, error) {
	d, ok, err := extractDuration(args[0], xdm.TypeDuration)
	if err != nil {
		return nil, err
	}

	if !ok {
		return nil, nil
	}
	// seconds-from-duration returns an xs:decimal: the exact total seconds mod 60.
	// durationToRat is SecRat-aware, so the fractional part is preserved exactly.
	total := xdm.DurationToRat(d, durationSecondsComponent)

	abs := total
	if abs.Sign() < 0 {
		abs = new(big.Rat).Neg(abs)
	}

	whole := new(big.Int).Quo(abs.Num(), abs.Denom())
	frac := new(big.Rat).Sub(abs, new(big.Rat).SetInt(whole))
	secsInt := new(big.Int).Rem(whole, big.NewInt(calendarSecondsPerMinute))
	result := new(big.Rat).SetInt(secsInt)
	result.Add(result, frac)

	if d.Negative {
		result.Neg(result)
	}

	return xdm.SingleDecimal(result), nil
}

// --- timezone adjustment ---

func fnAdjustDateTimeToTimezone(ctx context.Context, args []xdm.Sequence) (xdm.Sequence, error) {
	return adjustClockTimezone(ctx, args, xdm.TypeDateTime)
}

func fnAdjustDateToTimezone(ctx context.Context, args []xdm.Sequence) (xdm.Sequence, error) {
	t, ok, err := extractTime(args[0], xdm.TypeDate)
	if err != nil {
		return nil, err
	}

	if !ok {
		return nil, nil
	}

	if len(args) > 1 && xdm.SequenceLen(args[1]) == 0 {
		// Remove timezone: keep local date
		t = time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, xdm.NoTimezone())
		return xdm.SingleAtomic(xdm.AtomicValue{TypeName: xdm.TypeDate, Value: t}), nil
	}

	loc, err := getTargetTimezone(ctx, args)
	if err != nil {
		return nil, err
	}

	if !xdm.HasTimezone(t) {
		// No timezone — attach the target timezone (same local date)
		t = time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, loc)
	} else {
		// Has timezone — convert via dateTime (T00:00:00), then extract date
		dt := t.In(loc)
		t = time.Date(dt.Year(), dt.Month(), dt.Day(), 0, 0, 0, 0, loc)
	}

	return xdm.SingleAtomic(xdm.AtomicValue{TypeName: xdm.TypeDate, Value: t}), nil
}

func fnAdjustTimeToTimezone(ctx context.Context, args []xdm.Sequence) (xdm.Sequence, error) {
	return adjustClockTimezone(ctx, args, xdm.TypeTime)
}

// getTargetTimezone extracts the target timezone from the second argument (if provided)
// or falls back to the implicit timezone from the dynamic context.
func getTargetTimezone(ctx context.Context, args []xdm.Sequence) (*time.Location, error) {
	if len(args) > 1 && xdm.SequenceLen(args[1]) > 0 {
		d, ok, err := extractDuration(args[1], xdm.TypeDayTimeDuration)
		if err != nil {
			return nil, err
		}

		if !ok {
			return nil, &xdm.Error{Code: lexicon.ErrXPTY0004, Message: "expected dayTimeDuration"}
		}

		if err := validateTimezoneOffset(d); err != nil {
			return nil, err
		}

		return durationToLocation(d), nil
	}

	if ec := getFnContext(ctx); ec != nil {
		return ec.getImplicitTimezone(), nil
	}

	return time.Local, nil
}

// validateTimezoneOffset checks that a duration used as a timezone offset is
// within the allowed range (-PT14H to PT14H) and represents whole minutes.
// Returns FODT0003 if the constraints are violated.
func validateTimezoneOffset(d xdm.Duration) error {
	// Use the exact SecRat-aware total-seconds rational. An offset whose seconds
	// underflow float64 (e.g. PT0.<many zeros>1S) is still exactly nonzero here,
	// so it is not silently accepted as UTC.
	abs := xdm.DurationToRat(d, durationSecondsComponent)
	if abs.Sign() < 0 {
		abs = new(big.Rat).Neg(abs)
	}

	if abs.Cmp(big.NewRat(timezoneMaximumOffsetSeconds, 1)) > 0 { // 14 * 3600
		return &xdm.Error{Code: errCodeFODT0003, Message: "timezone offset out of range (-PT14H to PT14H)"}
	}
	// Whole number of minutes: the exact seconds rational must be divisible by 60.
	rem := new(big.Rat).Quo(abs, big.NewRat(calendarSecondsPerMinute, 1))
	if !rem.IsInt() {
		return &xdm.Error{Code: errCodeFODT0003, Message: "timezone offset must be a whole number of minutes"}
	}

	return nil
}

func durationToLocation(d xdm.Duration) *time.Location {
	// Bounded by validateTimezoneOffset (|offset| <= 50400, whole minutes), so the
	// exact seconds magnitude fits an int. Read it from the SecRat-aware rational
	// so a sub-float64 offset is not flattened to zero.
	abs := xdm.DurationToRat(d, durationSecondsComponent)
	if abs.Sign() < 0 {
		abs = new(big.Rat).Neg(abs)
	}

	offset := int(new(big.Int).Quo(abs.Num(), abs.Denom()).Int64())
	if d.Negative {
		offset = -offset
	}

	return time.FixedZone("", offset)
}

func adjustClockTimezone(ctx context.Context, args []xdm.Sequence, typeName string) (xdm.Sequence, error) {
	t, ok, err := extractTime(args[0], typeName)
	if err != nil {
		return nil, err
	}

	if !ok {
		return nil, nil
	}

	if len(args) > 1 && xdm.SequenceLen(args[1]) == 0 {
		// Remove timezone: keep local components
		t = time.Date(t.Year(), t.Month(), t.Day(), t.Hour(), t.Minute(), t.Second(), t.Nanosecond(), xdm.NoTimezone())
		return xdm.SingleAtomic(xdm.AtomicValue{TypeName: typeName, Value: t}), nil
	}

	loc, err := getTargetTimezone(ctx, args)
	if err != nil {
		return nil, err
	}

	if !xdm.HasTimezone(t) {
		// No timezone — attach the target timezone (same local time)
		t = time.Date(t.Year(), t.Month(), t.Day(), t.Hour(), t.Minute(), t.Second(), t.Nanosecond(), loc)
	} else {
		// Has timezone — convert
		t = t.In(loc)
	}

	return xdm.SingleAtomic(xdm.AtomicValue{TypeName: typeName, Value: t}), nil
}
