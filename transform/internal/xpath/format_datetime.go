// Derived from lestrrat-go/helium at 7362c0a70122a757780f4d0b545a9b370dead6ab.
// Copyright (c) 2015 lestrrat. MIT License; see licenses/MIT-helium.txt at the repository root.

package xpath

import (
	"context"
	"fmt"
	"math"
	"math/big"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/skarm/xmlsec/internal/lexicon"
	"github.com/skarm/xmlsec/internal/xmlchar"
	"github.com/skarm/xmlsec/transform/internal/xdm"
)

// maxInt64Digits is the number of decimal digits in math.MaxInt64.
const maxInt64Digits = 19

func fnFormatDateTime(ctx context.Context, args []xdm.Sequence) (xdm.Sequence, error) {
	return formatDateTimeCommon(ctx, args, xdm.TypeDateTime)
}

func fnFormatDate(ctx context.Context, args []xdm.Sequence) (xdm.Sequence, error) {
	return formatDateTimeCommon(ctx, args, xdm.TypeDate)
}

func fnFormatTime(ctx context.Context, args []xdm.Sequence) (xdm.Sequence, error) {
	return formatDateTimeCommon(ctx, args, xdm.TypeTime)
}

func formatDateTimeCommon(ctx context.Context, args []xdm.Sequence, typeName string) (xdm.Sequence, error) {
	if xdm.SequenceLen(args[0]) == 0 {
		return nil, nil
	}

	valAtom, err := AtomizeItem(args[0].Get(0))
	if err != nil {
		return nil, err
	}

	// Function conversion admits untypedAtomic, not arbitrary string/date casts.
	if valAtom.TypeName != typeName && !(typeName == xdm.TypeDateTime && valAtom.TypeName == xdm.TypeDateTimeStamp) && valAtom.TypeName != xdm.TypeUntypedAtomic {
		return nil, &xdm.Error{Code: lexicon.ErrXPTY0004, Message: "calendar formatting argument has the wrong type"}
	}

	if valAtom.TypeName == xdm.TypeUntypedAtomic {
		valAtom, err = CastAtomic(valAtom, typeName)
		if err != nil {
			return nil, err
		}
	}

	t := valAtom.TimeVal()

	picture, err := coerceArgToStringRequired(ctx, args[1])
	if err != nil {
		return nil, err
	}

	lang := "en"
	if ec := getFnContext(ctx); ec != nil {
		lang = ec.getDefaultLanguage()
	}

	defaultLanguage := lang

	calendar := ""

	if len(args) > 2 && xdm.SequenceLen(args[2]) > 0 {
		lang, err = coerceArgToString(ctx, args[2])
		if err != nil {
			return nil, err
		}
	}

	if len(args) > 3 && xdm.SequenceLen(args[3]) > 0 {
		calendar, err = coerceArgToString(ctx, args[3])
		if err != nil {
			return nil, err
		}

		calendar, err = resolveCalendarName(ctx, calendar)
		if err != nil {
			return nil, err
		}
	}

	t, err = applyFormatPlace(ctx, args, t)
	if err != nil {
		return nil, err
	}

	legacy := false
	if ec := getFnContext(ctx); ec != nil {
		legacy = ec.version == 20 || ec.version == 30
	}

	result, err := formatDateTimePicture(ctx, t, picture, lang, calendar, typeName, defaultLanguage, legacy)
	if err != nil {
		return nil, err
	}

	return xdm.SingleString(result), nil
}

func applyFormatPlace(ctx context.Context, args []xdm.Sequence, t time.Time) (time.Time, error) {
	if len(args) > 4 && xdm.SequenceLen(args[4]) > 0 {
		place, err := coerceArgToString(ctx, args[4])
		if err != nil {
			return t, err
		}

		if place != "" {
			// F&O 9.8.4.8 uses the default place when a country code or
			// timezone is not recognized, including an invalid place form.
			loc, err := time.LoadLocation(place)
			if err == nil {
				if !xdm.HasTimezone(t) {
					t = time.Date(t.Year(), t.Month(), t.Day(), t.Hour(), t.Minute(), t.Second(), t.Nanosecond(), loc)
				} else {
					t = t.In(loc)
				}
			}
		}
	}

	return t, nil
}

func formatDateTimePicture(ctx context.Context, t time.Time, picture, lang, calendar, typeName, defaultLanguage string, legacy bool) (string, error) {
	if err := Charge(ctx, len(picture)); err != nil {
		return "", err
	}

	if err := ChargeString(ctx, len(picture)); err != nil {
		return "", err
	}

	var b strings.Builder

	effectiveLang, effectiveCalendar, prefix := dateFormattingDefaults(lang, calendar, defaultLanguage)
	b.WriteString(prefix)

	i := 0
	runes := []rune(picture)

	for i < len(runes) {
		if runes[i] == '[' {
			if i+1 < len(runes) && runes[i+1] == '[' {
				// Escaped '[['  → literal '['
				b.WriteRune('[')

				i += 2

				continue
			}

			end := -1

			for j := i + 1; j < len(runes); j++ {
				if runes[j] == ']' {
					end = j
					break
				}
			}

			if end < 0 {
				return "", &xdm.Error{Code: errCodeFOFD1340, Message: "unclosed '[' in picture string"}
			}

			component := string(runes[i+1 : end])

			formatted, err := formatComponent(ctx, t, component, effectiveLang, effectiveCalendar, typeName, legacy)
			if err != nil {
				return "", err
			}

			b.WriteString(formatted)

			i = end + 1
		} else if runes[i] == ']' {
			if i+1 < len(runes) && runes[i+1] == ']' {
				b.WriteRune(']')

				i += 2

				continue
			}

			b.WriteRune(runes[i])
			i++
		} else {
			b.WriteRune(runes[i])
			i++
		}
	}

	result := b.String()
	if err := ChargeString(ctx, len(result)); err != nil {
		return "", err
	}

	return result, nil
}

// Unsupported languages and calendars use an identified fallback (F&O 9.8.4.8).
func dateFormattingDefaults(lang, calendar, defaultLanguage string) (string, string, string) {
	effectiveLang := strings.ToLower(lang)
	prefix := ""

	if !isSupportedLanguage(effectiveLang) {
		effectiveLang = strings.ToLower(defaultLanguage)
		if !isSupportedLanguage(effectiveLang) {
			effectiveLang = "en"
		}

		prefix = "[Language: " + effectiveLang + "]"
	}

	effectiveCalendar := calendar
	if effectiveCalendar != "" && !isISOCalendar(effectiveCalendar) {
		prefix += "[Calendar: AD]"
		effectiveCalendar = nameISO
	}

	return effectiveLang, effectiveCalendar, prefix
}

func isSupportedLanguage(lang string) bool {
	switch lang {
	case "en", "de":
		return true
	default:
		return false
	}
}

func formatComponent(ctx context.Context, t time.Time, spec, lang, calendar, typeName string, legacy bool) (string, error) {
	// Strip whitespace within the spec
	spec = stripSpaces(spec)

	if len(spec) == 0 {
		return "", &xdm.Error{Code: errCodeFOFD1340, Message: "empty component specifier"}
	}

	// First character is the component letter
	compChar := spec[0]
	rest := spec[1:]

	// Validate component is applicable for the type (FOFD1350)
	if err := validateComponentForType(compChar, typeName); err != nil {
		return "", err
	}

	presentation, width := parseDatePresentation(rest)

	// Validate format token and width
	if err := validateDateFormatToken(compChar, presentation, width); err != nil {
		return "", err
	}

	if err := chargeDateMinimumWidth(ctx, width.minWidth); err != nil {
		return "", err
	}

	var value int64

	switch compChar {
	case 'Y':
		value = int64(t.Year())
	case 'M':
		value = int64(t.Month())
	case 'D':
		value = int64(t.Day())
	case 'd':
		value = int64(t.YearDay())
	case 'F':
		return formatDayOfWeek(t, presentation, width, lang), nil
	case 'H':
		value = int64(t.Hour())
	case 'h':
		h := t.Hour() % 12
		if h == 0 {
			h = 12
		}

		value = int64(h)
	case 'P':
		return formatAMPM(t, presentation, width), nil
	case 'm':
		value = int64(t.Minute())
	case 's':
		value = int64(t.Second())
	case 'f':
		return formatFractionalSeconds(t, presentation, width, legacy), nil
	case 'Z', 'z':
		return formatTimezone(t, compChar, presentation, width), nil
	case 'W':
		_, w := t.ISOWeek()
		value = int64(w)
	case 'w':
		if isISOCalendar(calendar) {
			value = int64(isoWeekOfMonth(t))
		} else {
			value = int64((t.Day()-1)/7 + 1)
		}
	case 'E':
		return formatEra(t.Year(), presentation), nil
	case 'C':
		return nameISO, nil
	default:
		return "", &xdm.Error{Code: errCodeFOFD1340, Message: fmt.Sprintf("unknown component specifier: %c", compChar)}
	}

	return formatDateTimeValue(value, compChar, presentation, width, lang), nil
}

// The REC puts no fixed upper bound on a positive width. Reserve the possible
// UTF-8 padding before formatting, and keep resource exhaustion a control error.
func chargeDateMinimumWidth(ctx context.Context, width int) error {
	if width <= 0 {
		return ctx.Err()
	}

	if width > math.MaxInt/utf8.UTFMax {
		return ErrBudget
	}

	if err := ChargeString(ctx, width*utf8.UTFMax); err != nil {
		return err
	}

	return Charge(ctx, width)
}

func stripSpaces(s string) string {
	var b strings.Builder

	for _, r := range s {
		if !unicode.IsSpace(r) {
			b.WriteRune(r)
		}
	}

	return b.String()
}

type dtPresentation struct {
	format        string // the format token (e.g., "01", "1", "Nn", "n", "N", "I", etc.)
	ordinal       bool
	isTraditional bool
	implicit      bool
}

// dtWidth is a parsed width modifier (F&O 3.1 §9.8.4.2). A max-width the
// modifier omits means `*`, so maxWidth is -1 both for an explicit `*` and
// for an omitted maximum; maxOmitted tells the two apart for fractional
// seconds (see formatFractionalSeconds).
type dtWidth struct {
	minWidth   int  // -1 = no explicit minimum
	maxWidth   int  // -1 = unlimited
	maxOmitted bool // the modifier has no "-" max-width part
	present    bool // a width modifier was explicitly supplied
	invalid    bool // malformed width grammar
}

func parseDatePresentation(rest string) (dtPresentation, dtWidth) {
	presentation := dtPresentation{format: "1", implicit: true}

	width := dtWidth{minWidth: -1, maxWidth: -1}
	if rest == "" {
		return presentation, width
	}

	formatPart, widthPart := rest, ""
	if comma := strings.LastIndex(rest, ","); comma >= 0 {
		formatPart, widthPart = rest[:comma], rest[comma+1:]
	}

	format, modifiers := splitDatePresentationModifiers(formatPart)
	presentation.ordinal = strings.ContainsRune(modifiers, 'o')

	presentation.isTraditional = strings.ContainsRune(modifiers, 't')
	if format != "" {
		presentation.format, presentation.implicit = format, false
	}

	width = parseDateWidth(widthPart)
	if strings.Contains(rest, ",") && widthPart == "" {
		width.present, width.invalid = true, true
	}

	return presentation, width
}

func splitDatePresentationModifiers(format string) (string, string) {
	// Only the final semicolon can introduce a modifier. An invalid modifier
	// leaves that semicolon and all preceding text in the decimal picture.
	if semi := strings.LastIndex(format, ";"); semi >= 0 {
		if isDatePresentationModifier(format[semi+1:]) {
			return format[:semi], format[semi+1:]
		}

		return format, ""
	}

	base := strings.TrimRight(format, "otc")
	if base != "" && len(base) < len(format) {
		return base, format[len(base):]
	}

	return format, ""
}

func parseDateWidth(value string) dtWidth {
	width := dtWidth{minWidth: -1, maxWidth: -1}
	if value == "" {
		return width
	}

	width.present = true

	parts := strings.Split(value, "-")
	if len(parts) > 2 {
		width.invalid = true
		return width
	}

	for _, part := range parts {
		if part == "*" {
			continue
		}

		if part == "" {
			width.invalid = true
			return width
		}

		for _, digit := range part {
			if digit < '0' || digit > '9' {
				width.invalid = true
				return width
			}
		}
	}

	if parts[0] != "*" {
		width.minWidth = parseSimpleInt(parts[0])
	}

	width.maxOmitted = len(parts) == 1
	if len(parts) == 2 && parts[1] != "*" {
		width.maxWidth = parseSimpleInt(parts[1])
	}

	return width
}

func isDatePresentationModifier(mod string) bool {
	if mod == "" {
		return false
	}

	for _, r := range mod {
		switch r {
		case 'o', 't', 'c':
		default:
			return false
		}
	}

	return true
}

// parseSimpleInt parses the leading decimal digits of s. A value above
// math.MaxInt (2^31-1 where int is 32 bits) saturates at math.MaxInt instead of
// wrapping to a small or negative width.
func parseSimpleInt(s string) int {
	n := 0

	for _, r := range s {
		if r < '0' || r > '9' {
			break
		}

		d := int(r - '0')
		if n > (math.MaxInt-d)/10 {
			return math.MaxInt
		}

		n = n*10 + d
	}

	return n
}

func formatDateTimeValue(value int64, comp byte, p dtPresentation, w dtWidth, lang string) string {
	format := p.format
	numericValue := normalizeDateNumericValue(value, comp, p, w)

	switch format {
	case "N", "n", "Nn":
		// Named format (for months and days)
		return formatNamedValue(value, comp, format, w, lang)
	case "A":
		return formatAlpha(new(big.Int).SetInt64(numericValue), true)
	case "a":
		return formatAlpha(new(big.Int).SetInt64(numericValue), false)
	case "I", "i":
		// Roman numerals
		n := new(big.Int).SetInt64(numericValue)
		return applyTextWidth(formatRoman(n, format == "I"), w)
	case "W", "w", "Ww":
		n := new(big.Int).SetInt64(numericValue)
		style := nameLower

		switch format {
		case "W":
			style = nameUpper2
		case "w":
			style = nameLower
		case "Ww":
			style = "title"
		}

		result := formatWords(n, lang, style)
		if p.ordinal {
			result = applyOrdinalWords(result, lang, style, "")
		}

		return result
	}

	// Decimal number formatting
	result := formatDateDecimal(numericValue, p, w, comp)

	if p.ordinal {
		n := new(big.Int).SetInt64(value)
		result = applyOrdinalDecimal(result, n, lang, "")
	}

	return result
}

func formatDateDecimal(value int64, p dtPresentation, w dtWidth, comp byte) string {
	format := p.format
	// Determine min digits from format token
	minDigits := 0
	zeroDigit := '0'

	runes := []rune(format)
	for _, r := range runes {
		if unicode.IsDigit(r) {
			zeroDigit = unicodeDigitZero(r)
			minDigits++
		}
	}

	if minDigits == 0 {
		minDigits = 1
	}

	// Apply width constraints. F&O 3.1 §9.8.4.3 ignores the maximum width of
	// a decimal component, so no digit is ever dropped here; the year keeps
	// only its low-order digits through the modulus that
	// normalizeDateNumericValue already applied.
	if p.implicit && (comp == 'm' || comp == 's') && w.minWidth < 0 {
		minDigits = 2
	}

	if w.minWidth > 0 {
		minDigits = w.minWidth
	}

	abs := value
	neg := false

	if abs < 0 {
		abs = -abs
		neg = true
	}

	s := fmt.Sprintf("%d", abs)

	// Pad to minimum digits
	if len(s) < minDigits {
		s = strings.Repeat("0", minDigits-len(s)) + s
	}

	// Apply grouping separators from format pattern
	s = applyDateGrouping(s, runes, zeroDigit)

	// Translate to target digit set
	if zeroDigit != '0' {
		s = translateDigits(s, zeroDigit)
	}

	if neg {
		s = "-" + s
	}

	return s
}

// normalizeDateNumericValue applies the year modulus of F&O 3.1 §9.8.4.4:
// the year is output modulo 10^N, where N is a finite maximum width if the
// width modifier gives one, or else the number of digit signs in a decimal
// digit pattern of two or more digit signs (`[Y01]` keeps two digits). In
// every other case the year is output in full. Other components are
// returned unchanged.
func normalizeDateNumericValue(value int64, comp byte, p dtPresentation, w dtWidth) int64 {
	if comp != 'Y' && comp != 'E' {
		return value
	}

	if value < 0 {
		value = -value
	}

	digits := w.maxWidth
	if digits < 0 {
		digits = 0

		for _, r := range p.format {
			if unicode.IsDigit(r) || r == '#' {
				digits++
			}
		}

		if digits < 2 {
			return value
		}
	}

	// Every int64 has at most maxInt64Digits digits, so a modulus of that
	// many digits or more keeps the whole year and is skipped.
	if digits < maxInt64Digits {
		mod := int64(1)
		for range digits {
			mod *= 10
		}

		value %= mod
	}

	return value
}

func applyTextWidth(s string, w dtWidth) string {
	if w.minWidth <= 0 {
		return s
	}

	if n := utf8.RuneCountInString(s); n < w.minWidth {
		s += strings.Repeat(" ", w.minWidth-n)
	}

	return s
}

func applyDateGrouping(s string, formatRunes []rune, zeroDigit rune) string {
	// Extract grouping separator positions from the format pattern
	var sepPositions []int // positions from the right

	var sepChars []rune

	digitCount := 0

	for _, v := range slices.Backward(formatRunes) {
		r := v
		if r == '#' || isDecimalDigitInRange(r, zeroDigit) {
			digitCount++
		} else {
			if digitCount > 0 {
				sepPositions = append(sepPositions, digitCount)
				sepChars = append(sepChars, r)
			}
		}
	}

	if len(sepPositions) == 0 {
		return s
	}

	// Insert separators
	sRunes := []rune(s)

	sepAt := make(map[int]rune)
	for i, pos := range sepPositions {
		sepAt[pos] = sepChars[i]
	}

	var result []rune

	for i, v := range slices.Backward(sRunes) {
		digitPos := len(sRunes) - 1 - i
		if sep, ok := sepAt[digitPos]; ok {
			result = append(result, sep)
		}

		result = append(result, v)
	}

	for i, j := 0, len(result)-1; i < j; i, j = i+1, j-1 {
		result[i], result[j] = result[j], result[i]
	}

	return string(result)
}

func formatNamedValue(value int64, comp byte, format string, w dtWidth, lang string) string {
	var name string

	switch comp {
	case 'M':
		if value >= 1 && value <= 12 {
			months := monthNamesForLang(lang)
			name = months[value-1]
		}
	case 'F':
		if value >= 0 && value <= 6 {
			days := dayNamesForLang(lang)
			name = days[value]
		}
	default:
		return fmt.Sprintf("%d", value)
	}

	if name == "" {
		return fmt.Sprintf("%d", value)
	}

	name = applyNameWidth(name, comp, w)

	switch format {
	case "N":
		return strings.ToUpper(name)
	case "n":
		return strings.ToLower(name)
	case "Nn":
		r, size := utf8.DecodeRuneInString(name)
		return string(unicode.ToUpper(r)) + strings.ToLower(name[size:])
	}

	return name
}

func monthNamesForLang(lang string) []string {
	switch strings.ToLower(lang) {
	case "de":
		return []string{"Januar", "Februar", "März", "April", "Mai", "Juni", "Juli", "August", "September", "Oktober", "November", "Dezember"}
	default:
		return []string{"January", "February", "March", "April", "May", "June", "July", "August", "September", "October", "November", "December"}
	}
}

func dayNamesForLang(lang string) []string {
	switch strings.ToLower(lang) {
	case "de":
		return []string{"Sonntag", "Montag", "Dienstag", "Mittwoch", "Donnerstag", "Freitag", "Samstag"}
	default:
		return []string{"Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday"}
	}
}

// applyNameWidth fits a full name to the width modifier (F&O 3.1 §9.8.4.3).
// A name longer than the maximum width is abbreviated by removing characters
// from the end, down to the minimum width when one is given (so `[FNn,3-4]`
// yields the conventional "Wed", not "Wedn") or else to the maximum width. A
// name shorter than the minimum width is padded with trailing spaces.
func applyNameWidth(name string, _ byte, w dtWidth) string {
	n := utf8.RuneCountInString(name)
	if w.maxWidth > 0 && n > w.maxWidth {
		target := w.maxWidth
		if w.minWidth > 0 {
			target = w.minWidth
		}

		return string([]rune(name)[:target])
	}

	if w.minWidth > 0 && n < w.minWidth {
		return name + strings.Repeat(" ", w.minWidth-n)
	}

	return name
}

func formatDayOfWeek(t time.Time, p dtPresentation, w dtWidth, lang string) string {
	dow := int64(t.Weekday()) // 0=Sunday, 1=Monday, ..., 6=Saturday
	format := p.format

	switch format {
	case "N", "n", "Nn":
		return formatNamedValue(dow, 'F', format, w, lang)
	default:
		// Numeric day of week: 1=Monday, ..., 7=Sunday per ISO
		isoDow := int64(t.Weekday())
		if isoDow == 0 {
			isoDow = 7
		}

		return formatDateTimeValue(isoDow, 'F', p, w, lang)
	}
}

func formatAMPM(t time.Time, p dtPresentation, w dtWidth) string {
	var s string
	if t.Hour() < 12 {
		s = "am"
	} else {
		s = "pm"
	}

	switch p.format {
	case "N":
		s = strings.ToUpper(s)
	case "n":
		s = strings.ToLower(s)
	case "Nn":
		s = strings.ToUpper(s[:1]) + s[1:]
	}
	// Apply maximum width constraint: truncate to maxWidth characters
	if w.maxWidth > 0 && len(s) > w.maxWidth {
		s = s[:w.maxWidth]
	}

	return s
}

type fractionGroup struct {
	pos int
	sep rune
}

type fractionalPicture struct {
	zeroDigit       rune
	mandatoryDigits int
	optionalDigits  int
	totalDigits     int
	groups          []fractionGroup
}

func formatFractionalSeconds(t time.Time, p dtPresentation, w dtWidth, legacy bool) string {
	picture := parseFractionalPicture(p.format)
	minimum, maximum := fractionalPrecision(picture, w, legacy)

	nanos := t.Nanosecond()

	if legacy && maximum < 9 {
		// XSLT 2.0 §16.5.1 and F&O 3.0 §9.8.4.1 round this component;
		// it does not carry into other displayed date/time components.
		scale := int(math.Pow10(9 - maximum))

		quotient, remainder := nanos/scale, nanos%scale
		if remainder > scale/2 || remainder == scale/2 && quotient%2 != 0 {
			quotient++
		}

		nanos = quotient * scale % 1_000_000_000
	}

	value := fmt.Sprintf("%09d", nanos)[:maximum]
	if len(value) < minimum {
		value += strings.Repeat("0", minimum-len(value))
	}

	for len(value) > minimum && value[len(value)-1] == '0' {
		value = value[:len(value)-1]
	}

	value = applyFractionalGrouping(value, picture)
	if picture.zeroDigit != '0' {
		value = translateDigits(value, picture.zeroDigit)
	}

	return value
}

func parseFractionalPicture(format string) fractionalPicture {
	zeroDigit := pictureZeroDigit(format)
	// Count mandatory digits and optional (#) digits, and find grouping separators
	mandatoryDigits := 0
	optionalDigits := 0
	totalDigits := 0

	var groups []fractionGroup

	for _, r := range format {
		if isDecimalDigitInRange(r, zeroDigit) {
			mandatoryDigits++
			totalDigits++
		} else if r == '#' {
			optionalDigits++
			totalDigits++
		} else {
			if totalDigits > 0 {
				groups = append(groups, fractionGroup{pos: totalDigits, sep: r})
			}
		}
	}

	if mandatoryDigits == 0 && optionalDigits == 0 {
		mandatoryDigits = 1
		totalDigits = 1
	}

	return fractionalPicture{
		zeroDigit: zeroDigit, mandatoryDigits: mandatoryDigits, optionalDigits: optionalDigits,
		totalDigits: totalDigits, groups: groups,
	}
}

func fractionalPrecision(picture fractionalPicture, w dtWidth, legacy bool) (int, int) {
	// For fractional seconds:
	// - Single digit format token ("1") → min=1, max=9 (show all significant)
	// - Multi-digit format token → exact precision (min=max=digitCount)
	// - # digits → optional trailing (increase max)
	// - Width modifier overrides
	minPlaces := picture.mandatoryDigits

	var maxPlaces int
	if picture.mandatoryDigits <= 1 && picture.optionalDigits == 0 {
		// Single-digit or default: unbounded max (show all significant)
		maxPlaces = 9
	} else {
		maxPlaces = picture.totalDigits
	}

	if w.minWidth > 0 && w.minWidth > minPlaces {
		minPlaces = w.minWidth
	}

	if w.maxWidth > 0 {
		maxPlaces = w.maxWidth
	}
	// A width modifier stops the single-digit picture from growing to the
	// value's precision (F&O 3.1 §9.8.4.5), so `[f,3]` keeps exactly three
	// digits. An explicit `*` maximum keeps growing it: the W3C cases
	// format-dateTime-013t and format-time-024t expect `[f,1-*]` to output
	// every significant digit.
	if w.maxOmitted && w.minWidth > 0 {
		maxPlaces = w.minWidth
	}

	if w.present && !w.maxOmitted && w.maxWidth < 0 {
		// An explicit * maximum permits every significant fractional digit.
		maxPlaces = 9
	}

	if legacy && w.present {
		// In XSLT 2.0 and F&O 3.0 an explicit width replaces the picture's widths;
		// an omitted maximum means unbounded, including [f,3].
		minPlaces, maxPlaces = 1, 9
		if w.minWidth > 0 {
			minPlaces = w.minWidth
		}

		if w.maxWidth > 0 {
			maxPlaces = w.maxWidth
		}
	}

	if maxPlaces < minPlaces {
		maxPlaces = minPlaces
	}

	if minPlaces < 1 {
		minPlaces = 1
	}

	if maxPlaces > 9 {
		maxPlaces = 9
	}

	return minPlaces, maxPlaces
}

func applyFractionalGrouping(s string, picture fractionalPicture) string {
	// Apply grouping separators from format token
	if len(picture.groups) > 0 {
		var b strings.Builder

		gi := 0
		for i, r := range s {
			if gi < len(picture.groups) && i == picture.groups[gi].pos {
				b.WriteRune(picture.groups[gi].sep)
				gi++
			}

			b.WriteRune(r)
		}

		s = b.String()
	}

	return s
}

func formatTimezone(t time.Time, comp byte, p dtPresentation, w dtWidth) string {
	if !xdm.HasTimezone(t) {
		if p.format == "Z" && !p.implicit {
			return "J"
		}

		return ""
	}

	_, offset := t.Zone()

	if p.format == "N" || p.format == "n" || p.format == "Nn" {
		if name := formatTimezoneName(t, p.format); name != "" {
			return name
		}
	}

	if p.format == "Z" && !p.implicit {
		if code, ok := militaryTimezoneCode(offset); ok {
			return code
		}
	}

	spec := parseTimezonePicture(comp, p)
	// When a width modifier is present and limits the width to just the hour
	// portion, show minutes only when non-zero (XSLT 2.0 Erratum E29 behavior).
	if w.maxWidth > 0 && p.implicit && w.maxWidth <= spec.hourWidth {
		spec.showMinutes = false
	}

	return renderTimezoneOffset(offset, spec)
}

func isoWeekOfMonth(t time.Time) int {
	loc := t.Location()
	dayStart := time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, loc)
	weekStart := isoWeekStart(dayStart)

	monthWeek1 := isoMonthWeekOneStart(dayStart)
	if weekStart.Before(monthWeek1) {
		prevMonth := time.Date(t.Year(), t.Month(), 0, 0, 0, 0, 0, loc)
		return isoWeekOfMonth(prevMonth)
	}

	return int(weekStart.Sub(monthWeek1)/(7*24*time.Hour)) + 1
}

func formatEra(year int, p dtPresentation) string {
	era := "AD"
	if year < 0 {
		era = "BC"
	}

	switch p.format {
	case "n":
		return strings.ToLower(era)
	case "Nn":
		return strings.ToUpper(era[:1]) + strings.ToLower(era[1:])
	default:
		return era
	}
}

type timezonePicture struct {
	prefix       string
	hourWidth    int
	minuteWidth  int
	separator    string
	showMinutes  bool
	zeroAsZ      bool
	militaryCode bool
	zeroDigit    rune
}

func parseTimezonePicture(comp byte, p dtPresentation) timezonePicture {
	spec := timezonePicture{
		hourWidth:   2,
		minuteWidth: 2,
		separator:   ":",
		showMinutes: true,
		zeroDigit:   '0',
	}
	if comp == 'z' {
		spec.prefix = "GMT"
	}

	if p.implicit {
		return spec
	}

	format := p.format
	if strings.HasSuffix(format, "t") {
		spec.zeroAsZ = true
		format = strings.TrimSuffix(format, "t")
	} else if p.isTraditional {
		spec.zeroAsZ = true
	}

	if format == "Z" {
		spec.militaryCode = true
		return spec
	}

	if format == "N" || format == "n" || format == "Nn" {
		return spec
	}

	formatRunes := []rune(format)

	firstNonDigit := len(formatRunes)
	for i, r := range formatRunes {
		if !unicode.IsDigit(r) {
			firstNonDigit = i
			break
		}

		spec.zeroDigit = unicodeDigitZero(r)
	}

	prefixDigits := formatRunes[:firstNonDigit]
	if len(prefixDigits) > 0 {
		if firstNonDigit == len(formatRunes) && len(prefixDigits) > 2 {
			spec.hourWidth = len(prefixDigits) - 2
			spec.minuteWidth = 2
			spec.separator = ""
			spec.showMinutes = true

			return spec
		}

		spec.hourWidth = len(prefixDigits)
	}

	restRunes := formatRunes[firstNonDigit:]
	if len(restRunes) == 0 {
		spec.showMinutes = false
		return spec
	}

	sepEnd := 0
	for sepEnd < len(restRunes) && !unicode.IsDigit(restRunes[sepEnd]) {
		sepEnd++
	}

	spec.separator = string(restRunes[:sepEnd])

	spec.showMinutes = true
	if sepEnd < len(restRunes) {
		spec.minuteWidth = len(restRunes[sepEnd:])
	}

	if spec.minuteWidth == 0 {
		spec.minuteWidth = 2
	}

	return spec
}

func renderTimezoneOffset(offset int, spec timezonePicture) string {
	if spec.militaryCode {
		if code, ok := militaryTimezoneCode(offset); ok {
			return code
		}
	}

	if spec.zeroAsZ && offset == 0 {
		return "Z"
	}

	sign := "+"
	if offset < 0 {
		sign = "-"
		offset = -offset
	}

	hours := offset / 3600
	minutes := (offset % 3600) / 60

	hourFmt := fmt.Sprintf("%%0%dd", spec.hourWidth)

	body := sign + fmt.Sprintf(hourFmt, hours)
	if spec.showMinutes {
		minuteFmt := fmt.Sprintf("%%0%dd", spec.minuteWidth)
		body += spec.separator + fmt.Sprintf(minuteFmt, minutes)
	} else if minutes != 0 {
		minuteFmt := fmt.Sprintf("%%0%dd", spec.minuteWidth)
		body += ":" + fmt.Sprintf(minuteFmt, minutes)
	}

	if spec.zeroDigit != '0' {
		body = translateDigits(body, spec.zeroDigit)
	}

	return spec.prefix + body
}

func formatTimezoneName(t time.Time, format string) string {
	name, _ := t.Zone()
	if name == "" {
		return ""
	}

	switch format {
	case "N":
		return strings.ToUpper(name)
	case "n":
		return strings.ToLower(name)
	default:
		return name
	}
}

func militaryTimezoneCode(offset int) (string, bool) {
	if offset%3600 != 0 {
		return "", false
	}

	hours := offset / 3600
	switch {
	case hours == 0:
		return "Z", true
	case hours >= 1 && hours <= 12:
		letters := "ABCDEFGHIKLM"
		return string(letters[hours-1]), true
	case hours <= -1 && hours >= -12:
		letters := "NOPQRSTUVWXY"
		return string(letters[-hours-1]), true
	default:
		return "", false
	}
}

func isISOCalendar(calendar string) bool {
	switch calendar {
	case nameISO, "Q{}ISO", "AD", "Q{}AD":
		return true
	default:
		return false
	}
}

func resolveCalendarName(ctx context.Context, calendar string) (string, error) {
	if isKnownCalendarName(calendar) {
		return calendar, nil
	}

	if strings.HasPrefix(calendar, "Q{") {
		if ec := getFnContext(ctx); ec != nil && ec.version == 20 {
			return "", invalidCalendarName(calendar)
		}

		uri, local, ok := parseEQNameToken(calendar)
		if !ok || !xmlchar.IsValidNCName(local) {
			return "", invalidCalendarName(calendar)
		}

		uri = collapseWhitespace(uri)
		if uri == "" && !isKnownCalendarName(local) {
			return "", invalidCalendarName(calendar)
		}

		return "Q{" + uri + "}" + local, nil
	}

	prefix, local, err := parseLexicalQName(calendar)
	if err != nil || prefix == "" {
		return "", invalidCalendarName(calendar)
	}

	uri, ok := FnNamespace(ctx, prefix)
	if !ok || uri == "" {
		return "", invalidCalendarName(calendar)
	}

	return "Q{" + uri + "}" + local, nil
}

func invalidCalendarName(calendar string) error {
	return &xdm.Error{Code: errCodeFOFD1340, Message: fmt.Sprintf("format-dateTime: invalid calendar: %s", calendar)}
}

func isoWeekStart(t time.Time) time.Time {
	weekday := int(t.Weekday())
	if weekday == 0 {
		weekday = 7
	}

	return t.AddDate(0, 0, -(weekday - 1))
}

func isoMonthWeekOneStart(t time.Time) time.Time {
	loc := t.Location()
	first := time.Date(t.Year(), t.Month(), 1, 0, 0, 0, 0, loc)

	firstWeekday := int(first.Weekday())
	if firstWeekday == 0 {
		firstWeekday = 7
	}

	offsetToThursday := (4 - firstWeekday + 7) % 7
	firstThursday := first.AddDate(0, 0, offsetToThursday)

	return isoWeekStart(firstThursday)
}

func isKnownCalendarName(calendar string) bool {
	switch calendar {
	case nameISO, "AD", "AH", "AME", "AM", "AP", "AS", "BE", "CB", "CE", "CL",
		"CS", "EE", "FE", "JE", "KE", "KY", "ME", "MS", "NS",
		"OS", "RS", "SE", "SH", "SS", "TE", "VE", "VS":
		return true
	default:
		return false
	}
}

// validateComponentForType checks that a component specifier is valid for the given type.
// Per XPath F&O §9.8.4: raises FOFD1350 if the component is not available.
func validateComponentForType(comp byte, typeName string) error {
	if !strings.ContainsRune("YMDdFWwHhPmsfZzCE", rune(comp)) {
		return &xdm.Error{Code: errCodeFOFD1340, Message: fmt.Sprintf("unknown component specifier: %c", comp)}
	}

	// Date components: Y, M, D, d, F, W, w, E, C
	// Time components: H, h, P, m, s, f
	// Both: Z, z
	switch typeName {
	case xdm.TypeTime:
		switch comp {
		case 'H', 'h', 'P', 'm', 's', 'f', 'Z', 'z':
			return nil
		default:
			return &xdm.Error{Code: errCodeFOFD1350, Message: fmt.Sprintf("component [%c] is not available for xs:time", comp)}
		}
	case xdm.TypeDate:
		switch comp {
		case 'Y', 'M', 'D', 'd', 'F', 'W', 'w', 'E', 'C', 'Z', 'z':
			return nil
		default:
			return &xdm.Error{Code: errCodeFOFD1350, Message: fmt.Sprintf("component [%c] is not available for xs:date", comp)}
		}
	}
	// xs:dateTime allows all components
	return nil
}

// validateDateFormatToken validates the format token and width for FOFD1340 errors.
func validateDateFormatToken(comp byte, p dtPresentation, w dtWidth) error {
	if w.invalid {
		return &xdm.Error{Code: errCodeFOFD1340, Message: "invalid date/time width modifier"}
	}

	if err := validateDateDigitFamilies(p.format); err != nil {
		return err
	}

	if err := validateDateHashPlacement(comp, p.format); err != nil {
		return err
	}

	// Validate width modifier
	if w.minWidth == 0 {
		return &xdm.Error{Code: errCodeFOFD1340, Message: "minimum width cannot be zero"}
	}

	if w.maxWidth == 0 {
		return &xdm.Error{Code: errCodeFOFD1340, Message: "maximum width cannot be zero"}
	}

	if w.minWidth > 0 && w.maxWidth > 0 && w.minWidth > w.maxWidth {
		return &xdm.Error{Code: errCodeFOFD1340, Message: "minimum width exceeds maximum width"}
	}

	return nil
}

func validateDateDigitFamilies(format string) error {
	// Check for mixed Unicode digit families
	var firstZero rune

	hasDigit := false

	for _, r := range format {
		if unicode.IsDigit(r) {
			z := unicodeDigitZero(r)
			if hasDigit && z != firstZero {
				return &xdm.Error{Code: errCodeFOFD1340, Message: "mixed Unicode digit families in format token"}
			}

			firstZero = z
			hasDigit = true
		}
	}

	return nil
}

func validateDateHashPlacement(comp byte, format string) error {
	// For non-fractional components: '#' after digits is invalid
	// For fractional seconds ('f'): '#' after digits means optional trailing digits
	if comp != 'f' {
		seenDigit := false

		for _, r := range format {
			if unicode.IsDigit(r) {
				seenDigit = true
			} else if r == '#' {
				if seenDigit {
					return &xdm.Error{Code: errCodeFOFD1340, Message: "# after digit in format token"}
				}
			}
		}
	} else {
		// For fractional seconds: '#' BEFORE digits is invalid
		seenHash := false

		for _, r := range format {
			if r == '#' {
				seenHash = true
			} else if unicode.IsDigit(r) {
				if seenHash {
					return &xdm.Error{Code: errCodeFOFD1340, Message: "# before digit in fractional seconds format"}
				}
			}
		}
	}

	return nil
}
