// Derived from lestrrat-go/helium at 7362c0a70122a757780f4d0b545a9b370dead6ab.
// Copyright (c) 2015 lestrrat. MIT License; see licenses/MIT-helium.txt at the repository root.

package xpath

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/skarm/xmlsec/internal/xmlchar"
	"github.com/skarm/xmlsec/transform/internal/xdm"
)

func lookupParseIETFDate(name string) (*builtinFunc, bool) {
	switch name {
	case "parse-ietf-date":
		return &builtinFunc{name: name, min: 1, max: 1, fn: fnParseIETFDate}, true
	}

	return nil, false
}

func fnParseIETFDate(ctx context.Context, args []xdm.Sequence) (xdm.Sequence, error) {
	// xs:string? value: an atomized-empty argument (empty array / nilled node)
	// returns the empty sequence, like a syntactically empty one.
	s, empty, err := coerceAtomizedString(ctx, args[0])
	if err != nil {
		return nil, err
	}

	if empty {
		return nil, nil
	}

	t, err := parseIETFDate(s)
	if err != nil {
		return nil, &xdm.Error{
			Code:    "FORG0010",
			Message: fmt.Sprintf("fn:parse-ietf-date: invalid date string: %s", err),
		}
	}

	return xdm.SingleAtomic(xdm.AtomicValue{TypeName: xdm.TypeDateTime, Value: t}), nil
}

// parseIETFDate parses an IETF date string (RFC 2822, RFC 850, asctime, and
// variations) into a time.Time value. This implements the XPath 3.1
// fn:parse-ietf-date function.
//
// Accepted formats (per XPath Functions and Operators 3.1 section 9.9.1):
//   - RFC 2822: "Wed, 06 Jun 1994 07:29:35 GMT"
//   - RFC 850:  "Sunday, 06-Nov-94 08:49:37 GMT"
//   - asctime:  "Wed Jun 06 11:54:45 EST 2013"
//   - Various with optional day-of-week, flexible separators
func parseIETFDate(s string) (time.Time, error) {
	s = strings.Trim(s, " \t\r\n")
	if s == "" {
		return time.Time{}, fmt.Errorf("empty date string")
	}

	p := &ietfDateParser{input: s, pos: 0}

	return p.parse()
}

type ietfDateParser struct {
	input string
	pos   int
}

func (p *ietfDateParser) parse() (time.Time, error) {
	p.skipWS()

	// Try to detect format by looking for comma (RFC 2822 style) or month first (asctime)
	// Optional day-of-week prefix
	saved := p.pos
	if p.tryDayOfWeek() {
		if p.pos < len(p.input) && p.input[p.pos] == ',' {
			p.pos++
		}

		if p.pos >= len(p.input) || !xmlchar.IsSpace(rune(p.input[p.pos])) {
			return time.Time{}, fmt.Errorf("expected whitespace after day name")
		}

		p.skipWS()
	} else {
		p.pos = saved
	}

	// Determine if this is asctime format (month first) or RFC format (day first)
	if p.peekMonth() {
		return p.parseAsctime()
	}

	return p.parseRFC()
}

// parseRFC parses: day [-] month [-] year time [timezone]
func (p *ietfDateParser) parseRFC() (time.Time, error) {
	day, err := p.readIntN(1)
	if err != nil {
		return time.Time{}, fmt.Errorf("expected day (1-2 digits): %w", err)
	}

	if !p.hasSep() {
		return time.Time{}, fmt.Errorf("expected separator after day")
	}

	p.skipSep()

	monthStr, err := p.readAlpha()
	if err != nil {
		return time.Time{}, fmt.Errorf("expected month: %w", err)
	}

	month, err := parseMonth(monthStr)
	if err != nil {
		return time.Time{}, err
	}

	if !p.hasSep() {
		return time.Time{}, fmt.Errorf("expected separator after month")
	}

	p.skipSep()

	year, err := p.readYear()
	if err != nil {
		return time.Time{}, err
	}

	p.skipWS()

	hour, minute, sec, frac, err := p.parseTime()
	if err != nil {
		return time.Time{}, err
	}

	// Timezone may be immediately adjacent to time (no space)
	loc, err := p.parseTZ()
	if err != nil {
		return time.Time{}, err
	}

	p.skipWS()

	if p.pos < len(p.input) {
		return time.Time{}, fmt.Errorf("unexpected trailing content: %q", p.input[p.pos:])
	}

	if err := validateIETFDate(year, month, day, hour, minute, sec); err != nil {
		return time.Time{}, err
	}

	ns := int(frac * 1e9)

	if hour == 24 {
		hour = 0
		// advance to next day
		t := time.Date(year, time.Month(month), day+1, hour, minute, sec, ns, loc)

		return t, nil
	}

	t := time.Date(year, time.Month(month), day, hour, minute, sec, ns, loc)

	return t, nil
}

// parseAsctime parses: month day time year [timezone]
// Also handles: month[-]day time year
func (p *ietfDateParser) parseAsctime() (time.Time, error) {
	monthStr, err := p.readAlpha()
	if err != nil {
		return time.Time{}, fmt.Errorf("expected month: %w", err)
	}

	month, err := parseMonth(monthStr)
	if err != nil {
		return time.Time{}, err
	}
	// Require at least one separator between month and day
	if !p.hasSep() {
		return time.Time{}, fmt.Errorf("expected separator after month")
	}

	p.skipSep()

	day, err := p.readIntN(1)
	if err != nil {
		return time.Time{}, fmt.Errorf("expected day (1-2 digits): %w", err)
	}

	p.skipWS()

	hour, minute, sec, frac, err := p.parseTime()
	if err != nil {
		return time.Time{}, err
	}

	p.skipWS()

	var (
		loc  *time.Location
		year int
	)

	if p.peekTZ() {
		// timezone first, then year
		loc, err = p.parseTZ()
		if err != nil {
			return time.Time{}, err
		}

		p.skipWS()

		year, err = p.readYear()
		if err != nil {
			return time.Time{}, fmt.Errorf("expected year: %w", err)
		}
	} else {
		year, err = p.readYear()
		if err != nil {
			return time.Time{}, fmt.Errorf("expected year: %w", err)
		}

		p.skipWS()

		loc = time.UTC
	}

	p.skipWS()

	if p.pos < len(p.input) {
		return time.Time{}, fmt.Errorf("unexpected trailing content: %q", p.input[p.pos:])
	}

	if err := validateIETFDate(year, month, day, hour, minute, sec); err != nil {
		return time.Time{}, err
	}

	ns := int(frac * 1e9)

	if hour == 24 {
		hour = 0
		t := time.Date(year, time.Month(month), day+1, hour, minute, sec, ns, loc)

		return t, nil
	}

	t := time.Date(year, time.Month(month), day, hour, minute, sec, ns, loc)

	return t, nil
}

func (p *ietfDateParser) parseTime() (hour, minute, sec int, frac float64, err error) {
	hour, err = p.readIntN(1)
	if err != nil {
		return 0, 0, 0, 0, fmt.Errorf("expected hour (1-2 digits): %w", err)
	}

	if p.pos >= len(p.input) || p.input[p.pos] != ':' {
		return 0, 0, 0, 0, fmt.Errorf("expected ':' after hour")
	}

	p.pos++ // skip ':'

	minute, err = p.readIntN(2)
	if err != nil {
		return 0, 0, 0, 0, fmt.Errorf("expected minute (exactly 2 digits): %w", err)
	}

	// Seconds are optional
	if p.pos < len(p.input) && p.input[p.pos] == ':' {
		p.pos++ // skip ':'

		sec, err = p.readIntN(2)
		if err != nil {
			return 0, 0, 0, 0, fmt.Errorf("expected second (exactly 2 digits): %w", err)
		}
		// Fractional seconds
		if p.pos < len(p.input) && p.input[p.pos] == '.' {
			p.pos++ // skip '.'

			fracStart := p.pos
			for p.pos < len(p.input) && p.input[p.pos] >= '0' && p.input[p.pos] <= '9' {
				p.pos++
			}

			if p.pos == fracStart {
				return 0, 0, 0, 0, fmt.Errorf("expected digits after decimal point")
			}

			frac, _ = strconv.ParseFloat("0."+p.input[fracStart:p.pos], 64)
		}
	}

	return hour, minute, sec, frac, nil
}

func (p *ietfDateParser) parseTZ() (*time.Location, error) {
	p.skipWS()

	if p.pos >= len(p.input) {
		return time.UTC, nil
	}

	// Check for +/- offset: +0500, -0530, +05:00, +05, -05, -05:
	if p.input[p.pos] == '+' || p.input[p.pos] == '-' {
		return p.parseNumericTimezone()
	}

	return p.parseNamedTimezone()
}

// skipComment consumes an optional timezone-name suffix after a numeric offset.
// Only names from the XPath grammar, such as "(EST)", are accepted.
func (p *ietfDateParser) skipComment() error {
	p.skipWS()

	if p.pos < len(p.input) && p.input[p.pos] == '(' {
		start := p.pos
		depth := 1
		p.pos++

		contentStart := p.pos
		for p.pos < len(p.input) && depth > 0 {
			switch p.input[p.pos] {
			case '(':
				depth++
			case ')':
				depth--
			}

			p.pos++
		}

		if depth != 0 {
			return fmt.Errorf("unclosed comment at position %d", start)
		}
		// The suffix is a timezone name, not arbitrary comment text.
		content := strings.Trim(p.input[contentStart:p.pos-1], " \t\r\n")
		if _, ok := lookupIETFTimezone(strings.ToUpper(content)); !ok {
			return fmt.Errorf("invalid timezone-name suffix")
		}
	}

	return nil
}

func (p *ietfDateParser) tryDayOfWeek() bool {
	saved := p.pos

	s, err := p.readAlpha()
	if err != nil {
		p.pos = saved
		return false
	}

	ok := dayOfWeekNames(strings.ToLower(s))
	if !ok {
		p.pos = saved
		return false
	}

	return true
}

func dayOfWeekNames(key string) bool {
	switch key {
	case "mon", "monday", "tue", "tuesday", "wed", "wednesday", "thu", "thursday", "fri", "friday", "sat", "saturday", "sun", "sunday":
		return true
	}

	return false
}

func (p *ietfDateParser) peekMonth() bool {
	saved := p.pos
	s, err := p.readAlpha()
	p.pos = saved

	if err != nil {
		return false
	}

	_, ok := lookupMonthNumber(strings.ToLower(s))

	return ok
}

func (p *ietfDateParser) peekAlpha() bool {
	return p.pos < len(p.input) && unicode.IsLetter(rune(p.input[p.pos]))
}

// peekTZ checks if the next token looks like a timezone (+/- offset or alpha tz name)
func (p *ietfDateParser) peekTZ() bool {
	if p.pos >= len(p.input) {
		return false
	}

	if p.input[p.pos] == '+' || p.input[p.pos] == '-' {
		return true
	}

	if p.peekAlpha() {
		saved := p.pos
		name, err := p.readAlpha()
		p.pos = saved

		if err != nil {
			return false
		}

		_, ok := lookupIETFTimezone(strings.ToUpper(name))

		return ok
	}

	return false
}

// readIntN reads an integer of at least minDigits and at most 2 digits.
func (p *ietfDateParser) readIntN(minDigits int) (int, error) {
	const maxDigits = 2

	start := p.pos
	for p.pos < len(p.input) && p.input[p.pos] >= '0' && p.input[p.pos] <= '9' {
		p.pos++
	}

	n := p.pos - start
	if n < minDigits || n > maxDigits {
		return 0, fmt.Errorf("expected %d-%d digits at position %d, got %d", minDigits, maxDigits, start, n)
	}

	return strconv.Atoi(p.input[start:p.pos])
}

func (p *ietfDateParser) readAlpha() (string, error) {
	start := p.pos
	for p.pos < len(p.input) && unicode.IsLetter(rune(p.input[p.pos])) {
		p.pos++
	}

	if p.pos == start {
		return "", fmt.Errorf("expected alphabetic at position %d", p.pos)
	}

	return p.input[start:p.pos], nil
}

func (p *ietfDateParser) skipWS() {
	for p.pos < len(p.input) && xmlchar.IsSpace(rune(p.input[p.pos])) {
		p.pos++
	}
}

func (p *ietfDateParser) hasSep() bool {
	return p.pos < len(p.input) && (xmlchar.IsSpace(rune(p.input[p.pos])) || p.input[p.pos] == '-')
}

// skipSep consumes XML whitespace or one hyphen with optional surrounding whitespace.
func (p *ietfDateParser) skipSep() {
	p.skipWS()

	if p.pos < len(p.input) && p.input[p.pos] == '-' {
		p.pos++
		p.skipWS()
	}
}

// readYear applies the century adjustment only to a two-digit year.
func (p *ietfDateParser) readYear() (int, error) {
	start := p.pos
	for p.pos < len(p.input) && p.input[p.pos] >= '0' && p.input[p.pos] <= '9' {
		p.pos++
	}

	n := p.pos - start
	if n == 0 {
		return 0, fmt.Errorf("expected year at position %d", start)
	}

	if n != 2 && n != 4 {
		return 0, fmt.Errorf("year must have 2 or 4 digits")
	}

	year, err := strconv.Atoi(p.input[start:p.pos])
	if err != nil {
		return 0, err
	}

	if n == 2 {
		year += 1900
	}

	return year, nil
}

func (p *ietfDateParser) parseNamedTimezone() (*time.Location, error) {
	if !p.peekAlpha() {
		return time.UTC, nil
	}

	saved := p.pos
	name, _ := p.readAlpha()

	nameUpper := strings.ToUpper(name)
	if offset, ok := lookupIETFTimezone(nameUpper); ok {
		// Named TZ must not be immediately followed by digits (e.g., "GMT2014")
		if p.pos < len(p.input) && p.input[p.pos] >= '0' && p.input[p.pos] <= '9' {
			p.pos = saved
			return nil, fmt.Errorf("timezone name followed by digits without separator")
		}

		return time.FixedZone("", offset), nil
	}
	// Unknown timezone name — reject
	p.pos = saved

	return nil, fmt.Errorf("unknown timezone: %q", name)
}

func (p *ietfDateParser) parseNumericTimezone() (*time.Location, error) {
	sign := 1
	if p.input[p.pos] == '-' {
		sign = -1
	}

	p.pos++

	numStart := p.pos
	for p.pos < len(p.input) && (p.input[p.pos] >= '0' && p.input[p.pos] <= '9' || p.input[p.pos] == ':') {
		p.pos++
	}

	offsetStr := p.input[numStart:p.pos]
	offsetStr = strings.TrimSuffix(offsetStr, ":")

	var h, m int

	if hPart, mPart, ok := strings.Cut(offsetStr, ":"); ok {
		if len(hPart) < 1 || len(hPart) > 2 {
			return nil, fmt.Errorf("invalid timezone offset hours")
		}

		h, _ = strconv.Atoi(hPart)

		if len(mPart) != 0 && len(mPart) != 2 {
			return nil, fmt.Errorf("timezone offset minutes must be 2 digits, got %d", len(mPart))
		}

		if len(mPart) != 0 {
			m, _ = strconv.Atoi(mPart)
		}
	} else {
		// Compact format without colon: H, HH, HMM, HHMM
		switch len(offsetStr) {
		case 1, 2:
			h, _ = strconv.Atoi(offsetStr)
		case 3:
			h, _ = strconv.Atoi(offsetStr[:1])
			m, _ = strconv.Atoi(offsetStr[1:3])
		case 4:
			h, _ = strconv.Atoi(offsetStr[:2])
			m, _ = strconv.Atoi(offsetStr[2:4])
		default:
			return nil, fmt.Errorf("invalid timezone offset: %q", offsetStr)
		}
	}

	if h > 14 || (h == 14 && m > 0) {
		return nil, fmt.Errorf("timezone offset hours out of range: %d", h)
	}

	if m > 59 {
		return nil, fmt.Errorf("timezone offset minutes out of range: %d", m)
	}

	offset := sign * (h*3600 + m*60)
	// A numeric offset may have an optional timezone-name suffix.
	if err := p.skipComment(); err != nil {
		return nil, err
	}

	return time.FixedZone("", offset), nil
}

func parseMonth(s string) (int, error) {
	if len(s) != 3 {
		return 0, fmt.Errorf("month abbreviation must be exactly 3 letters: %q", s)
	}

	m, ok := lookupMonthNumber(strings.ToLower(s))
	if !ok {
		return 0, fmt.Errorf("unknown month: %q", s)
	}

	return m, nil
}

func validateIETFDate(year, month, day, hour, minute, sec int) error {
	if month < 1 || month > 12 {
		return fmt.Errorf("month %d out of range", month)
	}

	if day < 1 {
		return fmt.Errorf("day %d out of range", day)
	}

	maxDay := daysInMonth(year, month)
	if day > maxDay {
		return fmt.Errorf("day %d out of range for month %d", day, month)
	}

	if hour > 24 || (hour == 24 && (minute != 0 || sec != 0)) {
		return fmt.Errorf("hour %d out of range", hour)
	}

	if minute < 0 || minute > 59 {
		return fmt.Errorf("minute %d out of range", minute)
	}

	if sec < 0 || sec > 60 { // 60 for leap seconds
		return fmt.Errorf("second %d out of range", sec)
	}

	return nil
}

func daysInMonth(year, month int) int {
	switch month {
	case 1, 3, 5, 7, 8, 10, 12:
		return 31
	case 4, 6, 9, 11:
		return 30
	case 2:
		if year%4 == 0 && (year%100 != 0 || year%400 == 0) {
			return 29
		}

		return 28
	}

	return 31
}

func lookupMonthNumber(key string) (int, bool) {
	switch key {
	case "jan":
		return 1, true
	case "feb":
		return 2, true
	case "mar":
		return 3, true
	case "apr":
		return 4, true
	case "may":
		return 5, true
	case "jun":
		return 6, true
	case "jul":
		return 7, true
	case "aug":
		return 8, true
	case "sep":
		return 9, true
	case "oct":
		return 10, true
	case "nov":
		return 11, true
	case "dec":
		return 12, true
	}

	var zero int

	return zero, false
}

// lookupIETFTimezone maps timezone abbreviations to UTC offsets in seconds.
// Per the XPath spec, only the US military-origin abbreviations are recognized.
func lookupIETFTimezone(key string) (int, bool) {
	switch key {
	case "UT", "UTC", "GMT", "Z":
		return 0, true
	case "EST", "CDT":
		return -5 * 3600, true
	case "EDT":
		return -4 * 3600, true
	case "CST", "MDT":
		return -6 * 3600, true
	case "MST", "PDT":
		return -7 * 3600, true
	case "PST":
		return -8 * 3600, true
	}

	var zero int

	return zero, false
}
