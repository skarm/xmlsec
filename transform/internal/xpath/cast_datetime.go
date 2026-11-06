// Derived from lestrrat-go/helium at 7362c0a70122a757780f4d0b545a9b370dead6ab.
// Copyright (c) 2015 lestrrat. MIT License; see licenses/MIT-helium.txt at the repository root.

package xpath

import (
	"errors"
	"fmt"
	"math"
	"math/big"
	"strconv"
	"strings"
	"time"

	"github.com/skarm/xmlsec/internal/lexicon"
	"github.com/skarm/xmlsec/transform/internal/xdm"
)

// Calendar lexical limits are separate from arithmetic movement limits. The
// year ceiling protects time.Time construction; timezone offsets are six bytes
// and XML Schema allows at most fourteen hours, with zero minutes at that bound.
const (
	minimumYearDigits       = 4
	maxCastCalendarYear     = 999_999_999
	minimumCalendarMonth    = 1
	maximumCalendarMonth    = 12
	minimumCalendarDay      = 1
	maximumClockHour        = 23
	maximumClockMinute      = 59
	maximumClockSecond      = 59
	maximumTimezoneHours    = 14
	timezoneOffsetBytes     = 6
	utcTimezoneLexical      = "Z"
	midnightRolloverDays    = 1
	leapDayOfMonth          = 29
	goParseReferenceYear    = "2006"
	leapDayMonthDay         = "-02-29"
	leapDayParseReplacement = "-02-28"
	endOfDayClock           = "24:00:00"
	startOfDayClock         = "00:00:00"
	endOfDayDateTimeClock   = "T24:00:00"
	startOfDayDateTimeClock = "T00:00:00"
)

// Go parsing layouts and canonical Gregorian printf layouts keep their exact
// reference digits and padding. Their order at each call site is significant.
const (
	gregorianDayFormat            = "---%02d%s"
	gregorianMonthFormat          = "--%02d%s"
	gregorianMonthDayFormat       = "--%02d-%02d%s"
	gregorianYearFormat           = "%s%s"
	gregorianYearMonthFormat      = "%s-%02d%s"
	timezoneOffsetFormat          = "%c%02d:%02d"
	xsdDateZoneLayout             = "2006-01-02Z07:00"
	xsdDateLayout                 = "2006-01-02"
	xsdDateTimeFractionZoneLayout = "2006-01-02T15:04:05.999999999Z07:00"
	xsdDateTimeZoneLayout         = "2006-01-02T15:04:05Z07:00"
	xsdDateTimeFractionLayout     = "2006-01-02T15:04:05.999999999"
	xsdDateTimeLayout             = "2006-01-02T15:04:05"
	xsdTimeFractionZoneLayout     = "15:04:05.999999999Z07:00"
	xsdTimeZoneLayout             = "15:04:05Z07:00"
	xsdTimeFractionLayout         = "15:04:05.999999999"
	xsdTimeLayout                 = "15:04:05"
)

// Component ranks enforce XML Schema duration ordering, independently of unit
// conversion. Legacy float mirrors round to microseconds; exact rationals do not.
const (
	durationMonthParseBits      = 64 // ParseInt month magnitudes, not IEEE storage
	durationYearOrder           = 1
	durationMonthOrder          = 2
	durationDayOrder            = 3
	durationHourOrder           = 4
	durationMinuteOrder         = 5
	durationSecondOrder         = 6
	microsecondsPerSecond       = 1e6
	durationMicrosecondFormat   = "%06d"
	signedInt64DecimalBytes     = 20 // includes a possible minus sign
	zeroYearMonthDurationSuffix = "0M"
	zeroDayTimeDurationSuffix   = "T0S"
)

// errDurationMonthsRange reports a duration outside the supported month range.
// Lexical validation finishes before a cast raises FODT0002.
var errDurationMonthsRange = errors.New("duration month count out of int range")

var errCalendarYearRange = errors.New("calendar year out of representable range")

func castToGType(v xdm.AtomicValue, targetType string) (xdm.AtomicValue, error) {
	switch v.TypeName {
	case xdm.TypeDateTime, xdm.TypeDateTimeStamp, xdm.TypeDate:
		// xs:dateTimeStamp is a subtype of xs:dateTime.
		if err := validateDateTimeStampSource(v); err != nil {
			return xdm.AtomicValue{}, err
		}

		return xdm.AtomicValue{TypeName: targetType, Value: formatGregorianPartial(v.TimeVal(), targetType)}, nil
	case xdm.TypeString, xdm.TypeUntypedAtomic:
		return CastFromString(v.StringVal(), targetType)
	}

	return xdm.AtomicValue{}, &xdm.Error{
		Code:    lexicon.ErrXPTY0004,
		Message: fmt.Sprintf("cannot cast %s to %s", v.TypeName, targetType),
	}
}

func formatGregorianPartial(t time.Time, targetType string) string {
	switch targetType {
	case xdm.TypeGDay:
		return fmt.Sprintf(gregorianDayFormat, t.Day(), formatXSDTimezone(t))
	case xdm.TypeGMonth:
		return fmt.Sprintf(gregorianMonthFormat, t.Month(), formatXSDTimezone(t))
	case xdm.TypeGMonthDay:
		return fmt.Sprintf(gregorianMonthDayFormat, t.Month(), t.Day(), formatXSDTimezone(t))
	case xdm.TypeGYear:
		return fmt.Sprintf(gregorianYearFormat, formatXSDYear(t.Year()), formatXSDTimezone(t))
	default:
		return fmt.Sprintf(gregorianYearMonthFormat, formatXSDYear(t.Year()), t.Month(), formatXSDTimezone(t))
	}
}

func formatXSDTimezone(t time.Time) string {
	if !xdm.HasTimezone(t) {
		return ""
	}

	_, offset := t.Zone()
	if offset == 0 {
		return utcTimezoneLexical
	}

	sign := '+'
	if offset < 0 {
		sign = '-'
		offset = -offset
	}

	h := offset / calendarSecondsPerHour
	m := (offset % calendarSecondsPerHour) / calendarSecondsPerMinute

	return fmt.Sprintf(timezoneOffsetFormat, sign, h, m)
}

// splitXSDYear splits an XSD date/dateTime string into the year (as int) and
// the remainder starting from the first '-' after the year digits.
// It handles optional leading '-' for negative years and years with more than
// 4 digits (e.g., "-0002-06-01" → year=-2, rest="-06-01";
// "654321-01-01" → year=654321, rest="-01-01").
func splitXSDYear(s string) (int, string, error) {
	i := 0

	neg := false
	if i < len(s) && s[i] == '-' {
		neg = true
		i++
	}
	// Consume year digits (at least 4 required by XSD)
	start := i
	for i < len(s) && s[i] >= '0' && s[i] <= '9' {
		i++
	}

	digits := i - start
	if digits < minimumYearDigits {
		return 0, "", fmt.Errorf("year must have at least 4 digits")
	}
	// Per XSD: years with more than 4 digits must not have leading zeros
	if digits > minimumYearDigits && s[start] == '0' {
		return 0, "", fmt.Errorf("year with leading zeros is not valid")
	}

	yearStr := s[start:i]

	year, err := strconv.Atoi(yearStr)
	if err != nil || year > maxCastCalendarYear {
		// Retain the Gregorian leap-year cycle so callers can distinguish a
		// malformed date from a valid value outside the supported year range.
		year = 0
		for _, digit := range yearStr {
			year = (year*numericDecimalRadix + int(digit-'0')) % gregorianCycleYears
		}

		if neg {
			year = -year
		}

		return year, s[i:], errCalendarYearRange
	}

	if neg {
		year = -year
	}
	// XSD 1.1: year 0000 is valid (and is a leap year), so it is accepted here.
	// Reject years outside Go's time.Time representable range.
	// time.Date wraps silently for extreme years; cap at ±999,999,999.
	return year, s[i:], nil
}

// buildTimeFromParts constructs a time.Time from a parsed year and the
// remaining month-day (and optional time/tz) components. It uses time.Parse
// with a reference year of 2006, then replaces the year with the actual value.
func buildTimeFromParts(year int, rest string, layouts []string, original string) (time.Time, bool) {
	month, day, err := extractDateMonthDay(rest)
	if err != nil {
		return time.Time{}, false
	}

	if err := validateDateComponents(month, day, year); err != nil {
		return time.Time{}, false
	}

	// rest starts with "-MM-DD..." — prepend a synthetic 4-digit year for time.Parse.
	// Go's time.Parse reference year (2006) is not a leap year, so Feb 29 fails.
	// Use a leap year (2000) in the value string. Go layout uses "2006" for year,
	// but the value has "2000" — Go only matches positionally for fixed-width
	// components so we must re-format the layout to accept "2000".
	// Alternative approach: if the actual year is a leap year, temporarily
	// parse as Jan 1 to get the timezone, then construct manually.

	synthetic := goParseReferenceYear + rest
	for _, layout := range layouts {
		if t, err := time.Parse(layout, synthetic); err == nil {
			t = time.Date(year, t.Month(), t.Day(), t.Hour(), t.Minute(), t.Second(), t.Nanosecond(), t.Location())
			t = ensureExplicitTZ(t, original)

			return t, true
		}
	}

	// Retry with a leap-year workaround for Feb 29: parse a modified string
	// with day=28, then adjust the day back to the original value.
	if strings.HasPrefix(rest, leapDayMonthDay) {
		modRest := leapDayParseReplacement + rest[len(leapDayMonthDay):]

		synthetic = goParseReferenceYear + modRest
		for _, layout := range layouts {
			if t, err := time.Parse(layout, synthetic); err == nil {
				t = time.Date(year, t.Month(), leapDayOfMonth, t.Hour(), t.Minute(), t.Second(), t.Nanosecond(), t.Location())
				t = ensureExplicitTZ(t, original)

				return t, true
			}
		}
	}

	return time.Time{}, false
}

func extractDateMonthDay(rest string) (int, int, error) {
	if len(rest) < 6 || rest[0] != '-' || rest[3] != '-' {
		return 0, 0, fmt.Errorf("invalid month-day segment %q", rest)
	}

	month, err := strconv.Atoi(rest[1:3])
	if err != nil {
		return 0, 0, fmt.Errorf("invalid month in %q", rest)
	}

	day, err := strconv.Atoi(rest[4:6])
	if err != nil {
		return 0, 0, fmt.Errorf("invalid day in %q", rest)
	}

	return month, day, nil
}

func parseXSDDate(s string) (time.Time, error) {
	year, rest, err := splitXSDYear(s)

	overflow := errors.Is(err, errCalendarYearRange)
	if err != nil && !overflow {
		if xe, ok := errors.AsType[*xdm.Error](err); ok {
			return time.Time{}, xe
		}

		return time.Time{}, fmt.Errorf("invalid xs:date: %q", s)
	}

	if err := validateTimezoneInString(s); err != nil {
		return time.Time{}, fmt.Errorf("invalid xs:date: %q: %w", s, err)
	}

	layouts := []string{
		xsdDateZoneLayout,
		xsdDateLayout,
	}
	if t, ok := buildTimeFromParts(year, rest, layouts, s); ok {
		if err := validateDateComponents(int(t.Month()), t.Day(), year); err != nil {
			return time.Time{}, fmt.Errorf("invalid xs:date: %q: %w", s, err)
		}

		if overflow {
			return time.Time{}, &xdm.Error{Code: errCodeFODT0001, Message: errCalendarYearRange.Error()}
		}

		return t, nil
	}

	return time.Time{}, fmt.Errorf("invalid xs:date: %q", s)
}

func parseXSDDateTime(s string) (time.Time, error) {
	// Handle 24:00:00 (end-of-day midnight) — XSD allows this
	normalized, isMidnight24 := normalizeMidnight24DateTime(s)

	target := s
	if isMidnight24 {
		target = normalized
	}

	if err := validateTimezoneInString(s); err != nil {
		return time.Time{}, fmt.Errorf("invalid xs:dateTime: %q: %w", s, err)
	}

	year, rest, err := splitXSDYear(target)

	overflow := errors.Is(err, errCalendarYearRange)
	if err != nil && !overflow {
		if xe, ok := errors.AsType[*xdm.Error](err); ok {
			return time.Time{}, xe
		}

		return time.Time{}, fmt.Errorf("invalid xs:dateTime: %q", s)
	}

	layouts := []string{
		xsdDateTimeFractionZoneLayout,
		xsdDateTimeZoneLayout,
		xsdDateTimeFractionLayout,
		xsdDateTimeLayout,
	}
	if t, ok := buildTimeFromParts(year, rest, layouts, s); ok {
		if err := validateDateComponents(int(t.Month()), t.Day(), year); err != nil {
			return time.Time{}, fmt.Errorf("invalid xs:dateTime: %q: %w", s, err)
		}

		if !isMidnight24 {
			if err := validateTimeComponents(t.Hour(), t.Minute(), t.Second(), t.Nanosecond()); err != nil {
				return time.Time{}, fmt.Errorf("invalid xs:dateTime: %q: %w", s, err)
			}
		}

		if isMidnight24 {
			t = t.AddDate(0, 0, midnightRolloverDays) // advance to next day
		}

		if overflow || t.Year() > maxCastCalendarYear || t.Year() < -maxCastCalendarYear {
			return time.Time{}, &xdm.Error{Code: errCodeFODT0001, Message: errCalendarYearRange.Error()}
		}

		return t, nil
	}

	return time.Time{}, fmt.Errorf("invalid xs:dateTime: %q", s)
}

func parseXSDTime(s string) (time.Time, error) {
	if err := validateTimezoneInString(s); err != nil {
		return time.Time{}, fmt.Errorf("invalid xs:time: %q: %w", s, err)
	}
	// Handle 24:00:00 — XSD allows this as equivalent to 00:00:00
	normalized, isMidnight24 := normalizeMidnight24Time(s)

	target := s
	if isMidnight24 {
		target = normalized
	}

	for _, layout := range []string{
		xsdTimeFractionZoneLayout,
		xsdTimeZoneLayout,
		xsdTimeFractionLayout,
		xsdTimeLayout,
	} {
		if t, err := time.Parse(layout, target); err == nil {
			if !isMidnight24 {
				if err := validateTimeComponents(t.Hour(), t.Minute(), t.Second(), t.Nanosecond()); err != nil {
					return time.Time{}, fmt.Errorf("invalid xs:time: %q: %w", s, err)
				}
			}

			return ensureExplicitTZ(t, s), nil
		}
	}

	return time.Time{}, fmt.Errorf("invalid xs:time: %q", s)
}

// normalizeMidnight24DateTime checks if a dateTime string has T24:00:00 and
// replaces it with T00:00:00. Returns the normalized string and true if it was
// a midnight-24 value. The caller must advance the date by one day.
// 24:00:00.nnn is valid only when the fractional part is all zeros.
func normalizeMidnight24DateTime(s string) (string, bool) {
	before, rest, found := strings.Cut(s, endOfDayDateTimeClock)
	if !found {
		return s, false
	}
	// Allow fractional seconds only if all digits are zero (e.g. .000)
	if len(rest) > 0 && rest[0] == '.' {
		i := 1
		for i < len(rest) && rest[i] >= '0' && rest[i] <= '9' {
			if rest[i] != '0' {
				return s, false // non-zero fractional part is invalid
			}

			i++
		}

		if i == 1 {
			return s, false // bare "." with no digits is invalid
		}
		// Strip the all-zero fractional part
		rest = rest[i:]
	}

	return before + startOfDayDateTimeClock + rest, true
}

// normalizeMidnight24Time checks if a time string starts with 24:00:00 and
// replaces it with 00:00:00. For xs:time, 24:00:00 equals 00:00:00 (no date rollover).
// 24:00:00.nnn is valid only when the fractional part is all zeros.
func normalizeMidnight24Time(s string) (string, bool) {
	if !strings.HasPrefix(s, endOfDayClock) {
		return s, false
	}

	rest := s[len(endOfDayClock):]
	if len(rest) > 0 && rest[0] == '.' {
		i := 1
		for i < len(rest) && rest[i] >= '0' && rest[i] <= '9' {
			if rest[i] != '0' {
				return s, false // non-zero fractional part is invalid
			}

			i++
		}

		if i == 1 {
			return s, false
		}

		rest = rest[i:]
	}

	return startOfDayClock + rest, true
}

func ensureExplicitTZ(t time.Time, s string) time.Time {
	if t.Location() != time.UTC {
		return t
	}

	if hasExplicitTimezone(s) {
		return t.In(time.FixedZone("", 0))
	}
	// No explicit timezone — use the sentinel location so we can distinguish
	// "12:00:00" (no TZ) from "12:00:00Z" (explicit UTC).
	return t.In(xdm.NoTimezone())
}

func hasExplicitTimezone(s string) bool {
	if len(s) == 0 {
		return false
	}

	if s[len(s)-1] == 'Z' {
		return true
	}

	if len(s) >= timezoneOffsetBytes {
		tail := s[len(s)-timezoneOffsetBytes:]
		if (tail[0] == '+' || tail[0] == '-') &&
			tail[1] >= '0' && tail[1] <= '9' &&
			tail[2] >= '0' && tail[2] <= '9' &&
			tail[3] == ':' &&
			tail[4] >= '0' && tail[4] <= '9' &&
			tail[5] >= '0' && tail[5] <= '9' {
			return true
		}
	}

	return false
}

// validateDateComponents checks that month and day are in valid ranges.
// XSD 1.1: year 0000 is valid.
func validateDateComponents(month, day, year int) error {
	if month < minimumCalendarMonth || month > maximumCalendarMonth {
		return fmt.Errorf("month %d out of range 1-12", month)
	}

	maxDay := daysInMonth(year, month)
	if day < minimumCalendarDay || day > maxDay {
		return fmt.Errorf("day %d out of range for month %d (max %d)", day, month, maxDay)
	}

	return nil
}

// validateTimeComponents checks that hours, minutes, seconds are in valid ranges.
// Note: hour 24 is handled separately (normalizeMidnight24*) before this is called.
func validateTimeComponents(hour, minute, second, nanosecond int) error {
	if hour < 0 || hour > maximumClockHour {
		return fmt.Errorf("hour %d out of range 0-23", hour)
	}

	if minute < 0 || minute > maximumClockMinute {
		return fmt.Errorf("minute %d out of range 0-59", minute)
	}

	if second < 0 || second > maximumClockSecond {
		return fmt.Errorf("second %d out of range 0-59", second)
	}

	_ = nanosecond // fractional seconds are always valid if parsed

	return nil
}

// validateTimezoneInString checks that any timezone offset in the string is
// within the valid XSD range of -14:00 to +14:00.
func validateTimezoneInString(s string) error {
	if len(s) == 0 {
		return nil
	}

	if s[len(s)-1] == 'Z' {
		return nil // Z is always valid
	}

	if len(s) < timezoneOffsetBytes {
		return nil // no timezone present
	}

	tail := s[len(s)-timezoneOffsetBytes:]
	if (tail[0] != '+' && tail[0] != '-') ||
		tail[3] != ':' {
		return nil // no timezone suffix
	}

	hh := (int(tail[1]-'0') * numericDecimalRadix) + int(tail[2]-'0')

	mm := (int(tail[4]-'0') * numericDecimalRadix) + int(tail[5]-'0')
	if hh > maximumTimezoneHours || (hh == maximumTimezoneHours && mm != 0) {
		return fmt.Errorf("timezone offset %s out of range (-14:00 to +14:00)", tail)
	}

	if mm > maximumClockMinute {
		return fmt.Errorf("timezone offset minutes %d out of range 0-59", mm)
	}

	return nil
}

func parseXSDDuration(s string) (xdm.Duration, error) {
	if len(s) == 0 {
		return xdm.Duration{}, fmt.Errorf("empty duration")
	}

	parser := durationParser{lexical: s}
	if s[0] == '-' {
		parser.value.Negative = true
		parser.offset++
	}

	if parser.offset >= len(s) || s[parser.offset] != 'P' {
		return xdm.Duration{}, parser.invalid()
	}

	parser.offset++
	parser.used = make(map[byte]struct{})
	parser.seconds = new(big.Rat)

	for parser.offset < len(s) {
		if s[parser.offset] == 'T' {
			if err := parser.startTime(); err != nil {
				return xdm.Duration{}, err
			}

			continue
		}

		component, err := parser.readComponent()
		if err != nil {
			return xdm.Duration{}, err
		}

		if err := parser.addComponent(component); err != nil {
			return xdm.Duration{}, err
		}
	}

	return parser.result()
}

type durationComponent struct {
	number     string
	designator byte
	fractional bool
}

// durationParser keeps lexical ordering separate from exact accumulation.
// Seconds are authoritative rationals; value.Seconds is a float64 mirror.
type durationParser struct {
	seconds           *big.Rat
	used              map[byte]struct{}
	value             xdm.Duration
	lexical           string
	offset            int
	months            int64
	lastOrder         int
	monthsOverflow    bool
	inTime            bool
	seenComponent     bool
	seenTimeComponent bool
}

func (parser *durationParser) invalid() error {
	return fmt.Errorf("invalid duration: %q", parser.lexical)
}

func (parser *durationParser) startTime() error {
	if parser.inTime || parser.offset == len(parser.lexical)-1 {
		return parser.invalid()
	}

	parser.inTime = true
	parser.offset++

	return nil
}

func (parser *durationParser) readComponent() (durationComponent, error) {
	s := parser.lexical
	start := parser.offset
	dot := -1

	for parser.offset < len(s) && ((s[parser.offset] >= '0' && s[parser.offset] <= '9') || s[parser.offset] == '.') {
		if s[parser.offset] == '.' {
			if dot >= 0 {
				return durationComponent{}, parser.invalid()
			}

			dot = parser.offset
		}

		parser.offset++
	}

	if parser.offset == start || parser.offset >= len(s) {
		return durationComponent{}, parser.invalid()
	}

	if dot == start || dot == parser.offset-1 {
		return durationComponent{}, parser.invalid()
	}

	component := durationComponent{
		number:     s[start:parser.offset],
		designator: s[parser.offset],
		fractional: dot >= 0,
	}
	parser.offset++

	return component, nil
}

func (parser *durationParser) addComponent(component durationComponent) error {
	key := component.designator
	if parser.inTime && key == 'M' {
		key = 'm'
	}

	if _, exists := parser.used[key]; exists {
		return parser.invalid()
	}

	parser.used[key] = struct{}{}

	if parser.inTime {
		if err := parser.addTimeComponent(component); err != nil {
			return err
		}

		parser.seenTimeComponent = true
	} else if err := parser.addDateComponent(component); err != nil {
		return err
	}

	parser.seenComponent = true

	return nil
}

func (parser *durationParser) addDateComponent(component durationComponent) error {
	if component.fractional {
		return parser.invalid()
	}

	switch component.designator {
	case 'Y':
		return parser.addMonthComponent(component, durationYearOrder, calendarMonthsPerYear)
	case 'M':
		return parser.addMonthComponent(component, durationMonthOrder, 1)
	case 'D':
		if err := parser.advanceOrder(durationDayOrder); err != nil {
			return err
		}

		// Day counts can exceed int64; retain their exact value in seconds.
		days, ok := new(big.Int).SetString(component.number, numericDecimalRadix)
		if !ok {
			return fmt.Errorf("invalid duration number: %q", component.number)
		}

		dayFloat, _ := new(big.Float).SetInt(days).Float64()
		parser.value.Seconds += dayFloat * calendarSecondsPerDay
		parser.addSeconds(new(big.Rat).SetInt(days), calendarSecondsPerDay)

		return nil
	default:
		return fmt.Errorf("invalid duration designator: %c", component.designator)
	}
}

func (parser *durationParser) addMonthComponent(component durationComponent, order int, multiplier int64) error {
	if err := parser.advanceOrder(order); err != nil {
		return err
	}

	n, err := strconv.ParseInt(component.number, numericDecimalRadix, durationMonthParseBits)
	if errors.Is(err, strconv.ErrRange) {
		parser.monthsOverflow = true
		return nil
	}

	if err != nil {
		return parser.invalid()
	}

	if n > math.MaxInt64/multiplier {
		parser.monthsOverflow = true
		return nil
	}

	months, ok := addCheckedMonths(parser.months, n*multiplier)
	if !ok {
		parser.monthsOverflow = true
		return nil
	}

	parser.months = months

	return nil
}

func (parser *durationParser) addTimeComponent(component durationComponent) error {
	if component.designator != 'S' && component.fractional {
		return parser.invalid()
	}

	number, ok := new(big.Rat).SetString(component.number)
	if !ok {
		return fmt.Errorf("invalid duration number: %q", component.number)
	}

	// An overflowing float mirror may saturate to infinity; the exact
	// rational remains valid and must not be rejected on that account.
	f, err := strconv.ParseFloat(component.number, doubleFloatBits)
	if err != nil && !errors.Is(err, strconv.ErrRange) {
		return fmt.Errorf("invalid duration number: %q", component.number)
	}

	order, multiplier := durationTimeComponent(component.designator)
	if order == 0 {
		return fmt.Errorf("invalid duration designator: %c", component.designator)
	}

	if err := parser.advanceOrder(order); err != nil {
		return err
	}

	parser.value.Seconds += f * float64(multiplier)
	parser.addSeconds(number, multiplier)

	if component.designator == 'S' && component.fractional {
		whole := new(big.Int).Div(number.Num(), number.Denom())
		parser.value.FracSec = new(big.Rat).Sub(number, new(big.Rat).SetInt(whole))
	}

	return nil
}

func (parser *durationParser) advanceOrder(order int) error {
	if parser.lastOrder >= order {
		return parser.invalid()
	}

	parser.lastOrder = order

	return nil
}

func (parser *durationParser) addSeconds(number *big.Rat, multiplier int64) {
	parser.seconds.Add(parser.seconds, new(big.Rat).Mul(number, big.NewRat(multiplier, 1)))
}

func (parser *durationParser) result() (xdm.Duration, error) {
	if !parser.seenComponent || (parser.inTime && !parser.seenTimeComponent) {
		return xdm.Duration{}, parser.invalid()
	}

	parser.value.Months = int(parser.months)

	parser.value.SecRat = parser.seconds
	if parser.monthsOverflow || int64(parser.value.Months) != parser.months {
		return parser.value, fmt.Errorf("%w: %q", errDurationMonthsRange, parser.lexical)
	}

	return parser.value, nil
}

// addCheckedMonths adds two non-negative month counts, reporting ok=false on
// int64 overflow. A year/month total that exceeds int64 (e.g.
// P768614336404564650Y11M) must be rejected BEFORE it wraps to an invalid
// negative lexical form.
func addCheckedMonths(a, b int64) (int64, bool) {
	if b > math.MaxInt64-a {
		return 0, false
	}

	return a + b, true
}

func durationTimeComponent(designator byte) (int, int64) {
	switch designator {
	case 'H':
		return durationHourOrder, calendarSecondsPerHour
	case 'M':
		return durationMinuteOrder, calendarSecondsPerMinute
	case 'S':
		return durationSecondOrder, 1
	default:
		return 0, 0
	}
}

// exactFractionDigits returns the digits AFTER the decimal point for a
// fractional rational in [0,1), with NO rounding for terminating decimals.
//
// When FloatPrec reports the fraction is EXACT (terminating), the full exact
// precision is used with no cap, so an exact value arbitrarily close to 1 (e.g.
// 0.999...9 with hundreds of nines that is exactly representable) is rendered in
// full, and never rounded UP to "1.0...". Only NON-terminating fractions are
// capped, at which point FloatString may legitimately round; the cap value is
// chosen far beyond any precision a real lexical form carries.
//
// Trailing zeros are trimmed. Callers must never see a carried integer part
// (a leading "1."): with the exact-precision path that cannot occur.
func exactFractionDigits(frac *big.Rat) string {
	prec, exact := frac.FloatPrec()
	if exact {
		s := frac.FloatString(prec)
		s = strings.TrimPrefix(s, "0.")

		return strings.TrimRight(s, "0")
	}

	// Non-terminating fraction: emit a capped number of digits via TRUNCATING
	// long division. FloatString would ROUND, which can carry into the integer
	// part (e.g. 0.999... → 1.0) and corrupt the formatted duration; truncation
	// never carries, so the integer part stays 0 and no stray "." is emitted.
	// Forty decimal digits cap only non-terminating duration fractions.
	const maxDigits = 40

	num := new(big.Int).Set(frac.Num())
	den := frac.Denom()
	ten := big.NewInt(numericDecimalRadix)

	var b strings.Builder

	q := new(big.Int)

	for i := 0; i < maxDigits && num.Sign() != 0; i++ {
		num.Mul(num, ten)
		q.QuoRem(num, den, num)
		b.WriteByte(byte('0' + q.Int64())) // #nosec G115 -- Long division of a fraction in [0,1) produces digits in 0..9.
	}

	return strings.TrimRight(b.String(), "0")
}

// formatDuration formats a Duration as an XSD duration string.
// typeName is used to select the correct zero representation:
// yearMonthDuration → "P0M", dayTimeDuration → "PT0S", duration → "PT0S".
func formatDuration(d xdm.Duration, typeName string) string {
	var b strings.Builder

	secsZero := d.Seconds == 0
	if d.SecRat != nil {
		secsZero = d.SecRat.Sign() == 0
	}

	isZero := d.Months == 0 && secsZero
	if d.Negative && !isZero {
		b.WriteByte('-')
	}

	b.WriteByte('P')
	writeDurationMonths(&b, d)

	whole, micro, fraction := durationSecondParts(d)
	writeDurationDayTime(&b, whole, micro, fraction)

	if b.Len() == 1 || (d.Negative && b.Len() == 2) {
		if typeName == xdm.TypeYearMonthDuration {
			b.WriteString(zeroYearMonthDurationSuffix)
		} else {
			b.WriteString(zeroDayTimeDurationSuffix)
		}
	}

	return b.String()
}

func writeDurationMonths(b *strings.Builder, d xdm.Duration) {
	months := d.Months
	if d.Negative && months < 0 {
		months = -months
	}

	if years := months / calendarMonthsPerYear; years != 0 {
		writeDurationInteger(b, int64(years))
		b.WriteByte('Y')
	}

	if remainder := months % calendarMonthsPerYear; remainder != 0 {
		writeDurationInteger(b, int64(remainder))
		b.WriteByte('M')
	}
}

// durationSecondParts gives exact total seconds priority over the float
// mirror. It never rounds an exact fraction across a whole-second boundary.
func durationSecondParts(d xdm.Duration) (*big.Int, int64, *big.Rat) {
	if d.SecRat == nil {
		return legacyDurationSecondParts(d)
	}

	magnitude := d.SecRat
	if magnitude.Sign() < 0 {
		magnitude = new(big.Rat).Neg(magnitude)
	}

	whole := new(big.Int).Quo(magnitude.Num(), magnitude.Denom())
	remainder := new(big.Rat).Sub(magnitude, new(big.Rat).SetInt(whole))

	if remainder.Sign() == 0 {
		return whole, 0, nil
	}

	return whole, 0, remainder
}

func legacyDurationSecondParts(d xdm.Duration) (*big.Int, int64, *big.Rat) {
	seconds := d.Seconds
	if d.Negative && seconds < 0 {
		seconds = -seconds
	}

	whole := int64(seconds)
	fraction := seconds - float64(whole)
	micro := int64(math.Round(fraction * microsecondsPerSecond))

	if micro >= microsecondsPerSecond {
		whole++
		micro -= microsecondsPerSecond
	}

	if micro < 0 {
		micro = 0
	}

	if d.FracSec != nil && d.FracSec.Sign() != 0 {
		return big.NewInt(whole), 0, d.FracSec
	}

	return big.NewInt(whole), micro, nil
}

func writeDurationDayTime(b *strings.Builder, totalSeconds *big.Int, micro int64, fraction *big.Rat) {
	// The day count may exceed int64; all sub-day parts remain bounded.
	days := new(big.Int)
	remainder := new(big.Int)
	days.QuoRem(totalSeconds, big.NewInt(calendarSecondsPerDay), remainder)
	hours := remainder.Int64() / calendarSecondsPerHour
	subHour := remainder.Int64() - hours*calendarSecondsPerHour
	minutes := subHour / calendarSecondsPerMinute
	seconds := subHour - minutes*calendarSecondsPerMinute

	hasFraction := micro != 0 || (fraction != nil && fraction.Sign() != 0)
	hasSeconds := seconds != 0 || hasFraction

	if days.Sign() != 0 {
		b.WriteString(days.String())
		b.WriteByte('D')
	}

	if hours == 0 && minutes == 0 && !hasSeconds {
		return
	}

	b.WriteByte('T')

	if hours != 0 {
		writeDurationInteger(b, hours)
		b.WriteByte('H')
	}

	if minutes != 0 {
		writeDurationInteger(b, minutes)
		b.WriteByte('M')
	}

	if hasSeconds {
		writeDurationSeconds(b, seconds, micro, fraction)
	}
}

func writeDurationSeconds(b *strings.Builder, whole, micro int64, fraction *big.Rat) {
	writeDurationInteger(b, whole)

	if fraction != nil && fraction.Sign() != 0 {
		digits := exactFractionDigits(fraction)
		if digits != "" {
			b.WriteByte('.')
			b.WriteString(digits)
		}
	} else if micro != 0 {
		digits := strings.TrimRight(fmt.Sprintf(durationMicrosecondFormat, micro), "0")

		b.WriteByte('.')
		b.WriteString(digits)
	}

	b.WriteByte('S')
}

func writeDurationInteger(b *strings.Builder, value int64) {
	var digits [signedInt64DecimalBytes]byte
	b.Write(strconv.AppendInt(digits[:0], value, numericDecimalRadix))
}
