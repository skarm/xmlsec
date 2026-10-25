// Derived from lestrrat-go/helium at 7362c0a70122a757780f4d0b545a9b370dead6ab.
// Copyright (c) 2015 lestrrat. MIT License; see licenses/MIT-helium.txt at the repository root.

package value

import (
	"encoding/base64"
	"fmt"
	"math/big"
	"net/netip"
	"strings"
	"unicode/utf8"

	"github.com/skarm/xmlsec/internal/lexicon"
	"github.com/skarm/xmlsec/internal/xmlchar"
)

// Version selects the XSD specification version for the version-sensitive
// lexical rules. The zero value is Version10 (strict XSD 1.0), so callers that
// have no version concept default to 1.0 behavior.
type Version int

const (
	// Version10 targets XML Schema 1.0 lexical rules: "+INF" is NOT a valid
	// xs:float/xs:double form and year "0000" is NOT a valid date year.
	Version10 Version = iota
	// Version11 targets XML Schema 1.1 lexical rules: "+INF" is a valid
	// xs:float/xs:double form and year "0000" is a valid date year.
	Version11
)

// integerRange defines inclusive min/max bounds for integer subtypes.
type integerRange struct {
	min *big.Int // nil means no lower bound
	max *big.Int // nil means no upper bound
}

// ValidateBuiltin validates a value against a builtin XSD type's lexical space.
// version selects the 1.0-vs-1.1 lexical rules for the version-sensitive types
// (xs:float/xs:double "+INF", and year "0000" on the date types).
func ValidateBuiltin(value, builtinLocal string, version Version) error {
	switch builtinLocal {
	case lexicon.TypeDecimal:
		return validateDecimal(value)
	case lexicon.TypeInteger:
		return validateInteger(value)
	case lexicon.TypeNonPositiveInteger, lexicon.TypeNegativeInteger,
		lexicon.TypeLong, lexicon.TypeInt, lexicon.TypeShort, lexicon.TypeByte,
		lexicon.TypeNonNegativeInteger, lexicon.TypeUnsignedLong, lexicon.TypeUnsignedInt, lexicon.TypeUnsignedShort, lexicon.TypeUnsignedByte,
		lexicon.TypePositiveInteger:
		return validateIntegerWithRange(value, builtinLocal)
	case lexicon.TypeHexBinary:
		return validateHexBinary(value)
	case lexicon.TypeDate:
		return validateDate(value, version)
	case lexicon.TypeBoolean:
		return validateBoolean(value)
	case "language":
		return validateLanguage(value)
	case lexicon.TypeFloat, lexicon.TypeDouble:
		return validateFloat(value, version)
	case lexicon.TypeDateTime:
		return validateDateTime(value, version)
	case lexicon.TypeDateTimeStamp:
		return validateDateTimeStamp(value, version)
	case lexicon.TypeTime:
		return validateTime(value)
	case lexicon.TypeDuration:
		return validateDuration(value)
	case lexicon.TypeDayTimeDuration:
		return validateDayTimeDuration(value)
	case lexicon.TypeYearMonthDuration:
		return validateYearMonthDuration(value)
	case lexicon.TypeAnyAtomicType:
		// xs:anyAtomicType is abstract: it has no direct lexical constraints (its
		// abstractness is enforced where types are used, not here).
		return nil
	case lexicon.TypeError:
		// xs:error has an empty value space: no literal is ever valid.
		return fmt.Errorf("xs:error has an empty value space")
	case lexicon.TypeGYear:
		return validateGYear(value, version)
	case lexicon.TypeGYearMonth:
		return validateGYearMonth(value, version)
	case lexicon.TypeGMonth:
		return validateGMonth(value)
	case lexicon.TypeGDay:
		return validateGDay(value)
	case lexicon.TypeGMonthDay:
		return validateGMonthDay(value)
	default:
		return validateStringBuiltin(value, builtinLocal, version)
	}
}

func validateStringBuiltin(value, builtinLocal string, version Version) error {
	switch builtinLocal {
	case "NCName", "ID", "IDREF", "ENTITY":
		return validateNCName(value)
	case "Name":
		return validateName(value)
	case "NMTOKEN":
		return validateNMTOKEN(value)
	case "QName", "NOTATION":
		return validateQName(value)
	case lexicon.TypeBase64Binary:
		return validateBase64Binary(value)
	case lexicon.TypeNormalizedString:
		return validateNormalizedString(value)
	case "token":
		return validateToken(value)
	case lexicon.TypeIDREFS, lexicon.TypeENTITIES:
		return validateSpaceSeparatedList(value, validateNCName)
	case lexicon.TypeNMTokens:
		return validateSpaceSeparatedList(value, validateNMTOKEN)
	case "anyURI":
		return validateAnyURI(value, version)
	}

	return nil
}

// validateDecimal checks the lexical space of xs:decimal.
// Pattern: optional sign, then digits with optional decimal point.

func validateDecimal(value string) error {
	if !decimalLexical(value) {
		return fmt.Errorf("invalid decimal")
	}

	return nil
}

// validateInteger checks the lexical space of xs:integer.

func validateInteger(value string) error {
	if !digits(unsigned(value)) {
		return fmt.Errorf("invalid integer")
	}

	return nil
}

func lookupintegerRanges(key string) (integerRange, bool) {
	switch key {
	case lexicon.TypeByte:
		return integerRange{big.NewInt(-128), big.NewInt(127)}, true
	case lexicon.TypeShort:
		return integerRange{big.NewInt(-32768), big.NewInt(32767)}, true
	case lexicon.TypeInt:
		return integerRange{big.NewInt(-2147483648), big.NewInt(2147483647)}, true
	case lexicon.TypeLong:
		return integerRange{newBigInt("-9223372036854775808"), newBigInt("9223372036854775807")}, true
	case lexicon.TypeUnsignedByte:
		return integerRange{big.NewInt(0), big.NewInt(255)}, true
	case lexicon.TypeUnsignedShort:
		return integerRange{big.NewInt(0), big.NewInt(65535)}, true
	case lexicon.TypeUnsignedInt:
		return integerRange{big.NewInt(0), newBigInt("4294967295")}, true
	case lexicon.TypeUnsignedLong:
		return integerRange{big.NewInt(0), newBigInt("18446744073709551615")}, true
	case lexicon.TypeNonNegativeInteger:
		return integerRange{big.NewInt(0), nil}, true
	case lexicon.TypeNonPositiveInteger:
		return integerRange{nil, big.NewInt(0)}, true
	case lexicon.TypePositiveInteger:
		return integerRange{big.NewInt(1), nil}, true
	case lexicon.TypeNegativeInteger:
		return integerRange{nil, big.NewInt(-1)}, true
	}

	var zero integerRange

	return zero, false
}

func newBigInt(s string) *big.Int {
	n, _ := new(big.Int).SetString(s, 10)
	return n
}

func validateIntegerWithRange(value, typeName string) error {
	if err := validateInteger(value); err != nil {
		return err
	}

	r, ok := lookupintegerRanges(typeName)
	if !ok {
		return nil
	}

	n, ok := new(big.Int).SetString(value, 10)
	if !ok {
		return fmt.Errorf("invalid integer")
	}

	if r.min != nil && n.Cmp(r.min) < 0 {
		return fmt.Errorf("value %s is out of range for %s", value, typeName)
	}

	if r.max != nil && n.Cmp(r.max) > 0 {
		return fmt.Errorf("value %s is out of range for %s", value, typeName)
	}

	return nil
}

// validateHexBinary checks the lexical space of xs:hexBinary.
// Must be even number of hex digits, or empty.

func validateHexBinary(value string) error {
	if !hexLexical(value) {
		return fmt.Errorf("invalid hexBinary")
	}

	return nil
}

// validateDate checks for xs:date: YYYY-MM-DD with optional timezone.

func validateDate(value string, version Version) error {
	if !calendarLexical(value, lexicon.TypeDate, false) {
		return fmt.Errorf("invalid date")
	}

	if tz, ok := splitTimezone(value); ok {
		if err := validateTimezone(tz); err != nil {
			return err
		}
	}

	return validateDateComponents(value, version)
}

// validateLanguage checks the lexical space of xs:language (RFC 3066).

func validateLanguage(value string) error {
	if !ValidLanguage(value) {
		return fmt.Errorf("invalid language")
	}

	return nil
}

func validateBoolean(value string) error {
	switch value {
	case lexicon.ValueTrue, "false", "1", "0":
		return nil
	}

	return fmt.Errorf("invalid boolean")
}

// Numeric scanning checks xs:float and xs:double under XSD 1.1. The optional sign
// applies to the numeric forms and INF, but NaN must be bare: the valid special
// lexical forms are INF, +INF, -INF and NaN — +NaN and -NaN are not valid.

// XSD 1.0 accepts xs:float and xs:double under XSD 1.0, which differs from
// 1.1 only in the infinity forms: 1.0 allows INF and -INF but NOT +INF. The
// sign on the numeric forms is unchanged; only the INF alternative drops the
// leading '+'.

func validateFloat(value string, version Version) error {
	if !floatLexical(value, version) {
		return fmt.Errorf("invalid float")
	}

	return nil
}

// validateDateTime checks xs:dateTime.

func validateDateTime(value string, version Version) error {
	if !calendarLexical(value, lexicon.TypeDateTime, false) {
		return fmt.Errorf("invalid dateTime")
	}

	if err := validateDateComponents(value, version); err != nil {
		return err
	}
	// The time portion follows the 'T' separator.
	_, timePart, found := strings.Cut(value, "T")
	if !found {
		return fmt.Errorf("invalid dateTime")
	}

	return validateTimeComponents(timePart)
}

// validateTime checks xs:time.

func validateTime(value string) error {
	if !calendarLexical(value, lexicon.TypeTime, false) {
		return fmt.Errorf("invalid time")
	}

	return validateTimeComponents(value)
}

// validateTimeComponents enforces the value-space ranges of the time portion
// of xs:time / xs:dateTime: hour 00-23 (or exactly 24:00:00 with zero minutes,
// seconds and fractional seconds), minute 00-59, second 00-59 (XSD does not
// allow leap seconds), plus the timezone offset (±14:00, with minutes 00-59).
// The input must already have passed the relevant lexical check.
func validateTimeComponents(value string) error {
	// Split off the timezone designator, if any.
	timeOnly := value
	if tz, ok := splitTimezone(value); ok {
		timeOnly = value[:len(value)-len(tz)]
		if err := validateTimezone(tz); err != nil {
			return err
		}
	}

	// timeOnly is HH:MM:SS or HH:MM:SS.fff (lexical shape guaranteed by lexical scanning).
	hourStr, rest, found := strings.Cut(timeOnly, ":")
	if !found {
		return fmt.Errorf("invalid time")
	}

	minStr, secStr, found := strings.Cut(rest, ":")
	if !found {
		return fmt.Errorf("invalid time")
	}

	var hour, minute, sec int
	if _, err := fmt.Sscanf(hourStr, "%d", &hour); err != nil {
		return fmt.Errorf("invalid time")
	}

	if _, err := fmt.Sscanf(minStr, "%d", &minute); err != nil {
		return fmt.Errorf("invalid time")
	}

	intSecStr, fracStr, _ := strings.Cut(secStr, ".")
	if _, err := fmt.Sscanf(intSecStr, "%d", &sec); err != nil {
		return fmt.Errorf("invalid time")
	}

	if minute < 0 || minute > 59 {
		return fmt.Errorf("invalid time: minute %d out of range", minute)
	}

	if sec < 0 || sec > 59 {
		return fmt.Errorf("invalid time: second %d out of range", sec)
	}

	if hour < 0 || hour > 24 {
		return fmt.Errorf("invalid time: hour %d out of range", hour)
	}
	// 24:00:00 (with zero minutes, seconds, and fractional seconds) is the only
	// permitted use of hour 24; it denotes midnight at the end of the day.
	if hour == 24 && (minute != 0 || sec != 0 || !isZeroFraction(fracStr)) {
		return fmt.Errorf("invalid time: 24:00:00 is the only allowed value with hour 24")
	}

	return nil
}

// isZeroFraction reports whether a fractional-seconds string (the part after
// the '.', without the dot) represents zero. An empty string means no fraction
// was present, which is also zero.
func isZeroFraction(frac string) bool {
	return strings.Trim(frac, "0") == ""
}

// splitTimezone returns the trailing timezone designator (e.g. "Z", "+09:00",
// "-05:00") and true if present, otherwise "" and false.
func splitTimezone(value string) (string, bool) {
	if value == "" {
		return "", false
	}

	last := value[len(value)-1]
	if last == 'Z' {
		return value[len(value)-1:], true
	}
	// A numeric offset is "±HH:MM" — 6 trailing chars whose 6th-from-last is a
	// sign and whose 3rd-from-last is the ':' separator. The colon check is
	// what distinguishes a real offset from the '-' that separates date fields
	// (e.g. the "-05-20" tail of "1996-05-20").
	if len(value) >= 6 {
		if c := value[len(value)-6]; (c == '+' || c == '-') && value[len(value)-3] == ':' {
			return value[len(value)-6:], true
		}
	}

	return "", false
}

// validateTimezone enforces XSD timezone offset ranges: total offset within
// ±14:00, minutes 00-59, and when hours are 14 the minutes must be 00.
func validateTimezone(tz string) error {
	if tz == "Z" {
		return nil
	}
	// tz is "±HH:MM" (lexical shape guaranteed by lexical scanning).
	hhmm := tz[1:]

	hourStr, minStr, found := strings.Cut(hhmm, ":")
	if !found {
		return fmt.Errorf("invalid timezone")
	}

	var hour, minute int
	if _, err := fmt.Sscanf(hourStr, "%d", &hour); err != nil {
		return fmt.Errorf("invalid timezone")
	}

	if _, err := fmt.Sscanf(minStr, "%d", &minute); err != nil {
		return fmt.Errorf("invalid timezone")
	}

	if minute < 0 || minute > 59 {
		return fmt.Errorf("invalid timezone: minute %d out of range", minute)
	}

	if hour < 0 || hour > 14 {
		return fmt.Errorf("invalid timezone: hour %d out of range", hour)
	}

	if hour == 14 && minute != 0 {
		return fmt.Errorf("invalid timezone: offset exceeds 14:00")
	}

	return nil
}

// validateDateComponents parses YYYY-MM-DD from a date/dateTime string and
// checks month (1-12) and day (1-maxDay) ranges. The value must already have
// passed the lexical check.
// yearForbiddenInXSD10 reports whether yearStr (the digits-only year field, sign
// already stripped) is the year "0000". XSD 1.0 has no year zero; XSD 1.1 adds
// it. yearStr is assumed to have passed its lexical check (all digits).
func yearForbiddenInXSD10(yearStr string) bool {
	return strings.Trim(yearStr, "0") == ""
}

func validateDateComponents(value string, version Version) error {
	s := value
	if len(s) > 0 && s[0] == '-' {
		s = s[1:]
	}
	// Find year-month-day fields: YYYY-MM-DD...
	// Year is variable-length (4+ digits), so find second '-' after first.
	yearStr, rest, found := strings.Cut(s, "-")
	if !found {
		return fmt.Errorf("invalid date")
	}

	if version == Version10 && yearForbiddenInXSD10(yearStr) {
		return fmt.Errorf("invalid date: year 0000 is not valid in XSD 1.0")
	}

	monthStr, dayStr, found := strings.Cut(rest, "-")
	if !found {
		return fmt.Errorf("invalid date")
	}
	// dayStr may have trailing 'T...' or timezone; take first 2 chars.
	if len(dayStr) < 2 {
		return fmt.Errorf("invalid date")
	}

	dayStr = dayStr[:2]

	// The year is variable-length and may be an arbitrarily large expanded year
	// (e.g. "999999999999999999999999"), so do not parse it into a fixed-width
	// int; leap-year status is computed from the digit string directly.
	var month, day int
	if _, err := fmt.Sscanf(monthStr, "%d", &month); err != nil {
		return fmt.Errorf("invalid date")
	}

	if _, err := fmt.Sscanf(dayStr, "%d", &day); err != nil {
		return fmt.Errorf("invalid date")
	}

	if month < 1 || month > 12 {
		return fmt.Errorf("invalid date: month %d out of range", month)
	}
	// Maximum days per month. February's length depends on whether the year is
	// a leap year in the proleptic Gregorian calendar.
	maxDays := [13]int{0, 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31}
	if month == 2 && isLeapYearStr(yearStr) {
		maxDays[2] = 29
	}

	if day < 1 || day > maxDays[month] {
		return fmt.Errorf("invalid date: day %d out of range for month %d", day, month)
	}

	return nil
}

// isLeapYearStr reports whether the Gregorian year given as a (sign-stripped)
// decimal digit string is a leap year. The year may be an arbitrarily large
// expanded year, so leap-year status is computed via modulo arithmetic over the
// digit string. Parsing into a fixed-width int would overflow: a year is leap iff divisible by 4 and (not divisible by 100, or
// divisible by 400).
func isLeapYearStr(year string) bool {
	mod := func(s string, n int) int {
		v := 0
		for _, r := range s {
			v = (v*10 + int(r-'0')) % n
		}

		return v
	}
	if mod(year, 4) != 0 {
		return false
	}

	if mod(year, 100) != 0 {
		return true
	}

	return mod(year, 400) == 0
}

// validateDuration checks xs:duration. When the time designator 'T' is present it
// must be followed by at least one of H/M/S; a dangling 'T' (e.g. "P1YT") is
// rejected by requiring at least one time component within the T group.

func validateDuration(value string) error {
	if !durationLexical(value, lexicon.TypeDuration) {
		return fmt.Errorf("invalid duration")
	}
	// At least one component must be present after P.
	s := value
	if len(s) > 0 && s[0] == '-' {
		s = s[1:]
	}

	s = s[1:] // remove 'P'
	if s == "" || s == "T" {
		return fmt.Errorf("invalid duration")
	}
	// A time designator 'T' must be followed by at least one H/M/S component.
	if _, after, ok := strings.Cut(s, "T"); ok {
		if !strings.ContainsAny(after, "HMS") {
			return fmt.Errorf("invalid duration")
		}
	}

	return nil
}

// validateDateTimeStamp checks xs:dateTimeStamp (XSD 1.1): an xs:dateTime whose
// explicitTimezone is "required", i.e. the timezone designator is mandatory
// (the tzSuffix group is not optional).

// validateDateTimeStamp validates xs:dateTimeStamp: an xs:dateTime value that
// must carry a timezone. Year-0000 gating follows the dateTime rules.
func validateDateTimeStamp(value string, version Version) error {
	if !calendarLexical(value, lexicon.TypeDateTime, true) {
		return fmt.Errorf("invalid dateTimeStamp")
	}

	return validateDateTime(value, version)
}

// validateDayTimeDuration checks xs:dayTimeDuration (XSD 1.1): a duration with
// only day and time components (no year or month). At least one component must
// be present.

func validateDayTimeDuration(value string) error {
	if !durationLexical(value, "dayTimeDuration") {
		return fmt.Errorf("invalid dayTimeDuration")
	}
	// Reuse the shared duration body checks (at least one component, no dangling
	// 'T'); they additionally reject "P"/"PT".
	return validateDuration(value)
}

// validateYearMonthDuration checks xs:yearMonthDuration (XSD 1.1): a duration with
// only year and month components (no day or time). At least one component must
// be present.

func validateYearMonthDuration(value string) error {
	if !durationLexical(value, "yearMonthDuration") {
		return fmt.Errorf("invalid yearMonthDuration")
	}
	// "P" with no component is invalid.
	if value == "P" || value == "-P" {
		return fmt.Errorf("invalid yearMonthDuration")
	}

	return validateDuration(value)
}

// validateGYear checks xs:gYear.

func validateGYear(value string, version Version) error {
	if !calendarLexical(value, lexicon.TypeGYear, false) {
		return fmt.Errorf("invalid gYear")
	}

	body, err := stripAndCheckTimezone(value)
	if err != nil {
		return err
	}

	if version == Version10 && yearForbiddenInXSD10(strings.TrimPrefix(body, "-")) {
		return fmt.Errorf("invalid gYear: year 0000 is not valid in XSD 1.0")
	}

	return nil
}

// stripAndCheckTimezone removes any trailing timezone designator from value,
// validating its range, and returns the remaining (timezone-free) body. The
// input is assumed to have already passed its lexical check.
func stripAndCheckTimezone(value string) (string, error) {
	tz, ok := splitTimezone(value)
	if !ok {
		return value, nil
	}

	if err := validateTimezone(tz); err != nil {
		return "", err
	}

	return value[:len(value)-len(tz)], nil
}

func gMonthRange(s, typeName string) error {
	var month int
	if _, err := fmt.Sscanf(s, "%d", &month); err != nil {
		return fmt.Errorf("invalid %s", typeName)
	}

	if month < 1 || month > 12 {
		return fmt.Errorf("invalid %s: month %d out of range", typeName, month)
	}

	return nil
}

func gDayRange(s, typeName string) error {
	var day int
	if _, err := fmt.Sscanf(s, "%d", &day); err != nil {
		return fmt.Errorf("invalid %s", typeName)
	}

	if day < 1 || day > 31 {
		return fmt.Errorf("invalid %s: day %d out of range", typeName, day)
	}

	return nil
}

// validateGYearMonth checks xs:gYearMonth.

func validateGYearMonth(value string, version Version) error {
	if !calendarLexical(value, lexicon.TypeGYearMonth, false) {
		return fmt.Errorf("invalid gYearMonth")
	}

	body, err := stripAndCheckTimezone(value)
	if err != nil {
		return err
	}
	// body is "[-]YYYY...-MM": the year is everything before the final "-MM".
	if version == Version10 {
		yearStr, _, _ := strings.Cut(strings.TrimPrefix(body, "-"), "-")
		if yearForbiddenInXSD10(yearStr) {
			return fmt.Errorf("invalid gYearMonth: year 0000 is not valid in XSD 1.0")
		}
	}
	// the month is the last two characters.
	return gMonthRange(body[len(body)-2:], lexicon.TypeGYearMonth)
}

// validateGMonth checks xs:gMonth.

func validateGMonth(value string) error {
	if !calendarLexical(value, lexicon.TypeGMonth, false) {
		return fmt.Errorf("invalid gMonth")
	}

	body, err := stripAndCheckTimezone(value)
	if err != nil {
		return err
	}
	// body is "--MM".
	return gMonthRange(body[2:4], lexicon.TypeGMonth)
}

// validateGDay checks xs:gDay.

func validateGDay(value string) error {
	if !calendarLexical(value, lexicon.TypeGDay, false) {
		return fmt.Errorf("invalid gDay")
	}

	body, err := stripAndCheckTimezone(value)
	if err != nil {
		return err
	}
	// body is "---DD".
	return gDayRange(body[3:5], lexicon.TypeGDay)
}

// validateGMonthDay checks xs:gMonthDay.

func validateGMonthDay(value string) error {
	if !calendarLexical(value, lexicon.TypeGMonthDay, false) {
		return fmt.Errorf("invalid gMonthDay")
	}

	body, err := stripAndCheckTimezone(value)
	if err != nil {
		return err
	}
	// body is "--MM-DD".
	if err := gMonthRange(body[2:4], lexicon.TypeGMonthDay); err != nil {
		return err
	}

	if err := gDayRange(body[5:7], lexicon.TypeGMonthDay); err != nil {
		return err
	}
	// Reject month/day combinations that never occur (e.g. --02-30, --04-31).
	var month, day int
	if _, err := fmt.Sscanf(body[2:4], "%d", &month); err != nil {
		return fmt.Errorf("invalid gMonthDay")
	}

	if _, err := fmt.Sscanf(body[5:7], "%d", &day); err != nil {
		return fmt.Errorf("invalid gMonthDay")
	}
	// gMonthDay is year-agnostic, so February permits its maximal length (29).
	maxDays := [13]int{0, 31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31}
	if day > maxDays[month] {
		return fmt.Errorf("invalid gMonthDay: day %d out of range for month %d", day, month)
	}

	return nil
}

func validateNCName(value string) error {
	if !xmlchar.IsValidNCName(value) {
		return fmt.Errorf("invalid NCName")
	}

	return nil
}

func validateName(value string) error {
	if !xmlchar.IsValidName(value) {
		return fmt.Errorf("invalid Name")
	}

	return nil
}

// isNMTOKEN reports whether value is a valid XML Nmtoken: one or more NameChar
// (colon allowed).
func isNMTOKEN(value string) bool {
	if value == "" {
		return false
	}

	if !utf8.ValidString(value) {
		return false
	}

	for _, r := range value {
		if r == ':' || xmlchar.IsNCNameChar(r) {
			continue
		}

		return false
	}

	return true
}

func validateNMTOKEN(value string) error {
	if !isNMTOKEN(value) {
		return fmt.Errorf("invalid NMTOKEN")
	}

	return nil
}

func validateNormalizedString(value string) error {
	if strings.ContainsAny(value, "\t\n\r") {
		return fmt.Errorf("invalid normalizedString")
	}

	return nil
}

func validateToken(value string) error {
	if strings.ContainsAny(value, "\t\n\r") {
		return fmt.Errorf("invalid token")
	}

	if value != trimXSDSpace(value) {
		return fmt.Errorf("invalid token")
	}

	if strings.Contains(value, "  ") {
		return fmt.Errorf("invalid token")
	}

	return nil
}

func validateAnyURI(value string, version Version) error {
	if version == Version11 {
		return nil
	}

	if !utf8.ValidString(value) {
		return fmt.Errorf("invalid anyURI")
	}

	// XSD 1.0 §3.2.17 applies XLink escaping before RFC 2396/2732
	// syntax checks. Spaces, controls, non-ASCII and the excluded punctuation
	// become escaped octets, so they cannot be rejected as URI characters.
	// '%' and '#' are deliberately not escaped by that algorithm.
	for i := 0; i < len(value); i++ {
		ch := value[i]
		if ch == '%' {
			if i+2 >= len(value) || !isHexDigit(value[i+1]) || !isHexDigit(value[i+2]) {
				return fmt.Errorf("invalid anyURI")
			}

			i += 2
		}
	}

	uri, fragment, _ := strings.Cut(value, "#")
	if strings.Contains(fragment, "#") || !validXSD10URI(uri) {
		return fmt.Errorf("invalid anyURI")
	}

	return nil
}

func validXSD10URI(uri string) bool {
	if i := strings.IndexAny(uri, ":/?"); i >= 0 && uri[i] == ':' {
		scheme := uri[:i]
		if scheme == "" || !xmlchar.IsASCIILetter(scheme[0]) {
			return false
		}

		for i := 1; i < len(scheme); i++ {
			ch := scheme[i]
			if !xmlchar.IsASCIILetter(ch) && !xmlchar.IsASCIIDigit(ch) && !strings.ContainsRune("+.-", rune(ch)) {
				return false
			}
		}

		uri = uri[i+1:]
		if uri == "" {
			return false
		}

		if uri[0] != '/' {
			// opaque_part starts with uric_no_slash, which excludes brackets.
			return uri[0] != '[' && uri[0] != ']'
		}
	}

	path, _, _ := strings.Cut(uri, "?")
	if strings.HasPrefix(path, "//") {
		authority, rest, _ := strings.Cut(path[2:], "/")
		if !validXSD10Authority(authority) {
			return false
		}

		path = rest
	}

	// Brackets occur in IPv6 hosts and in uric (query/fragment/opaque
	// components), but are not pchar in an RFC 2396 hierarchical path.
	return !strings.ContainsAny(path, "[]")
}

func validXSD10Authority(authority string) bool {
	if !strings.ContainsAny(authority, "[]") {
		// RFC 2396 reg_name also permits ':' and '@'; imposing server/port
		// rules here would reject valid registry-based naming authorities.
		return true
	}

	if i := strings.LastIndexByte(authority, '@'); i >= 0 {
		if strings.ContainsAny(authority[:i], "[]@") {
			return false
		}

		authority = authority[i+1:]
	}

	host, port, ok := strings.Cut(strings.TrimPrefix(authority, "["), "]")
	if !strings.HasPrefix(authority, "[") || !ok {
		return false
	}

	if !validXSD10IPv6(host) {
		return false
	}

	if port != "" {
		if port[0] != ':' {
			return false
		}

		for i := 1; i < len(port); i++ {
			if !xmlchar.IsASCIIDigit(port[i]) {
				return false
			}
		}
	}

	return true
}

func validXSD10IPv6(host string) bool {
	if colon := strings.LastIndexByte(host, ':'); colon >= 0 && strings.ContainsRune(host[colon+1:], '.') {
		// RFC 2732 uses RFC 2373's 1*3DIGIT IPv4 octets. Unlike netip,
		// that grammar permits leading zeroes, interpreted as decimal.
		// Normalize only this validation copy; retain the original anyURI value.
		octets := strings.SplitN(host[colon+1:], ".", 5)
		if len(octets) != 4 {
			return false
		}

		for i, octet := range octets {
			if octet == "" || len(octet) > 3 {
				return false
			}

			for j := range len(octet) {
				if !xmlchar.IsASCIIDigit(octet[j]) {
					return false
				}
			}

			octets[i] = strings.TrimLeft(octet, "0")
			if octets[i] == "" {
				octets[i] = "0"
			}
		}

		host = host[:colon+1] + strings.Join(octets, ".")
	}

	address, err := netip.ParseAddr(host)

	return err == nil && address.Is6() && address.Zone() == ""
}

func isHexDigit(ch byte) bool {
	return ('0' <= ch && ch <= '9') || ('A' <= ch && ch <= 'F') || ('a' <= ch && ch <= 'f')
}

func validateQName(value string) error {
	parts := strings.SplitN(value, ":", 2)
	if len(parts) == 1 {
		return validateNCName(value)
	}

	if err := validateNCName(parts[0]); err != nil {
		return fmt.Errorf("invalid QName")
	}

	if err := validateNCName(parts[1]); err != nil {
		return fmt.Errorf("invalid QName")
	}

	return nil
}

// base64Characters restricts the character repertoire of xs:base64Binary; the
// grammar (correct quad/padding structure) is enforced by attempting a decode.
// XSD whitespace is exactly space, tab, CR, and LF, so the repertoire excludes
// other Unicode whitespace such as form-feed.

func validateBase64Binary(value string) error {
	if !base64Characters(value) {
		return fmt.Errorf("invalid base64Binary")
	}
	// xs:base64Binary has whiteSpace=collapse and permits whitespace between
	// characters; strip all whitespace then enforce the grammar via a strict
	// (length/padding-aware) decode. This rejects malformed input such as
	// "====", a lone "A", or "AAA" that the character scan alone would pass.
	var b strings.Builder

	for _, r := range value {
		if r == ' ' || r == '\t' || r == '\r' || r == '\n' {
			continue
		}

		b.WriteRune(r)
	}
	// Strict() rejects padded forms whose unused trailing bits are non-zero
	// (e.g. "TR==", "AAB="), which are not valid xs:base64Binary lexical forms.
	if _, err := base64.StdEncoding.Strict().DecodeString(b.String()); err != nil {
		return fmt.Errorf("invalid base64Binary")
	}

	return nil
}

func validateSpaceSeparatedList(value string, validateItem func(string) error) error {
	if value == "" {
		return fmt.Errorf("empty list")
	}
	// Split on XSD whitespace only (space, tab, CR, LF). strings.Fields would
	// also split on NBSP and other Unicode whitespace, so a token containing
	// NBSP would be wrongly broken into valid pieces; XSD-only splitting keeps
	// it as one token that per-item validation then rejects.
	items := xsdFields(value)
	if len(items) == 0 {
		return fmt.Errorf("empty list")
	}

	for _, item := range items {
		if err := validateItem(item); err != nil {
			return err
		}
	}

	return nil
}
