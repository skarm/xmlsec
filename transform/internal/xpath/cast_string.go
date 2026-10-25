// Derived from lestrrat-go/helium at 7362c0a70122a757780f4d0b545a9b370dead6ab.
// Copyright (c) 2015 lestrrat. MIT License; see licenses/MIT-helium.txt at the repository root.

package xpath

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"math/big"
	"strconv"
	"strings"
	"time"

	"github.com/skarm/xmlsec/internal/xmlchar"
	"github.com/skarm/xmlsec/transform/internal/xdm"
	value "github.com/skarm/xmlsec/transform/internal/xdm/lexical"
	"github.com/skarm/xmlsec/transform/internal/xdm/lexicon"
)

// AtomicToString returns the canonical string representation of an atomic value.
func AtomicToString(v xdm.AtomicValue) (string, error) {
	return atomicToString(v)
}

func atomicToString(value xdm.AtomicValue) (string, error) {
	// User annotations format through their known built-in base, retaining Value.
	if value.TypeName != "" && value.BaseType != "" && xdm.IsKnownXSDType(value.BaseType) && !xdm.IsKnownXSDType(value.TypeName) {
		return atomicToString(xdm.AtomicValue{TypeName: value.BaseType, Value: value.Value})
	}

	switch value.TypeName {
	case xdm.TypeString, xdm.TypeAnyURI, xdm.TypeUntypedAtomic,
		xdm.TypeNormalizedString, xdm.TypeToken, xdm.TypeLanguage, xdm.TypeName, xdm.TypeNCName,
		xdm.TypeNMTOKEN, xdm.TypeNMTOKENS, xdm.TypeENTITY, xdm.TypeID, xdm.TypeIDREF, xdm.TypeIDREFS,
		xdm.TypeGDay, xdm.TypeGMonth, xdm.TypeGMonthDay, xdm.TypeGYear, xdm.TypeGYearMonth:
		return formatAtomicString(value)
	case xdm.TypeInteger,
		xdm.TypeLong, xdm.TypeInt, xdm.TypeShort, xdm.TypeByte,
		xdm.TypeUnsignedLong, xdm.TypeUnsignedInt, xdm.TypeUnsignedShort, xdm.TypeUnsignedByte,
		xdm.TypeNonNegativeInteger, xdm.TypeNonPositiveInteger,
		xdm.TypePositiveInteger, xdm.TypeNegativeInteger:
		return formatAtomicInteger(value)
	case xdm.TypeDecimal:
		return formatAtomicDecimal(value)
	case xdm.TypeDouble:
		return formatXPathDouble(value.FloatVal().Float64()), nil
	case xdm.TypeFloat:
		return formatXPathFloat(value.FloatVal().Float64()), nil
	case xdm.TypeBoolean:
		return formatAtomicBoolean(value)
	case xdm.TypeDate, xdm.TypeDateTime, xdm.TypeDateTimeStamp, xdm.TypeTime:
		return formatAtomicTemporal(value)
	case xdm.TypeDuration, xdm.TypeDayTimeDuration, xdm.TypeYearMonthDuration:
		return formatAtomicDuration(value)
	case xdm.TypeBase64Binary, xdm.TypeHexBinary:
		return formatAtomicBinary(value)
	case xdm.TypeQName:
		return formatAtomicQName(value)
	default:
		return formatUserAtomicValue(value.Value), nil
	}
}

func formatAtomicString(value xdm.AtomicValue) (string, error) {
	text, ok := value.Value.(string)
	if !ok {
		return "", fmt.Errorf("xpath: internal error: expected string value for %s", value.TypeName)
	}

	return text, nil
}

func formatAtomicInteger(value xdm.AtomicValue) (string, error) {
	switch number := value.Value.(type) {
	case int64:
		return strconv.FormatInt(number, 10), nil
	case *big.Int:
		return number.String(), nil
	default:
		return "", fmt.Errorf("xpath: internal error: expected integer value for %s, got %T", value.TypeName, value.Value)
	}
}

func formatAtomicDecimal(value xdm.AtomicValue) (string, error) {
	number, ok := value.Value.(*big.Rat)
	if !ok {
		return "", fmt.Errorf("xpath: internal error: expected *big.Rat value for %s", value.TypeName)
	}

	return xdm.DecimalToString(number), nil
}

func formatAtomicBoolean(value xdm.AtomicValue) (string, error) {
	boolean, ok := value.Value.(bool)
	if !ok {
		return "", fmt.Errorf("xpath: internal error: expected bool value for %s", value.TypeName)
	}

	return formatAtomicBooleanValue(boolean), nil
}

func formatAtomicBooleanValue(boolean bool) string {
	if boolean {
		return lexicon.ValueTrue
	}

	return lexicon.ValueFalse
}

func formatAtomicTemporal(value xdm.AtomicValue) (string, error) {
	instant, ok := value.Value.(time.Time)
	if !ok {
		return "", fmt.Errorf("xpath: internal error: expected time.Time value for %s", value.TypeName)
	}

	zone := formatXSDTimezone(instant)
	if value.TypeName == xdm.TypeDate {
		return formatAtomicDate(instant) + zone, nil
	}

	clock := formatAtomicClock(instant)
	if value.TypeName == xdm.TypeTime {
		return clock + zone, nil
	}

	return formatAtomicDate(instant) + "T" + clock + zone, nil
}

func formatAtomicDate(instant time.Time) string {
	return fmt.Sprintf("%s-%02d-%02d", formatXSDYear(instant.Year()), instant.Month(), instant.Day())
}

func formatAtomicClock(instant time.Time) string {
	clock := fmt.Sprintf("%02d:%02d:%02d", instant.Hour(), instant.Minute(), instant.Second())
	if nanos := instant.Nanosecond(); nanos > 0 {
		clock += strings.TrimRight(fmt.Sprintf(".%09d", nanos), "0")
	}

	return clock
}

func formatAtomicDuration(value xdm.AtomicValue) (string, error) {
	duration, ok := value.Value.(xdm.Duration)
	if !ok {
		return "", fmt.Errorf("xpath: internal error: expected Duration value for %s", value.TypeName)
	}

	return formatDuration(duration, value.TypeName), nil
}

func formatAtomicBinary(value xdm.AtomicValue) (string, error) {
	data, ok := value.Value.([]byte)
	if !ok {
		return "", fmt.Errorf("xpath: internal error: expected []byte value for %s", value.TypeName)
	}

	if value.TypeName == xdm.TypeHexBinary {
		return strings.ToUpper(hex.EncodeToString(data)), nil
	}

	return base64.StdEncoding.EncodeToString(data), nil
}

func formatAtomicQName(value xdm.AtomicValue) (string, error) {
	name, ok := value.Value.(xdm.QNameValue)
	if !ok {
		return "", fmt.Errorf("xpath: internal error: expected QNameValue for %s", value.TypeName)
	}

	return formatAtomicQNameValue(name), nil
}

func formatAtomicQNameValue(name xdm.QNameValue) string {
	if name.Prefix != "" {
		return name.Prefix + ":" + name.Local
	}

	return name.Local
}

func formatUserAtomicValue(value any) string {
	switch typed := value.(type) {
	case string:
		return typed
	case int64:
		return strconv.FormatInt(typed, 10)
	case *big.Int:
		return typed.String()
	case *big.Rat:
		return xdm.DecimalToString(typed)
	case *xdm.FloatValue:
		return formatXPathDouble(typed.Float64())
	case float64:
		return formatXPathDouble(typed)
	case bool:
		return formatAtomicBooleanValue(typed)
	case time.Time:
		return fmt.Sprintf("%v", typed)
	case xdm.Duration:
		return formatDuration(typed, xdm.TypeDuration)
	case xdm.QNameValue:
		return formatAtomicQNameValue(typed)
	default:
		return fmt.Sprintf("%v", value)
	}
}

func formatXPathDouble(f float64) string {
	if math.IsNaN(f) {
		return lexicon.FloatNaN
	}

	if math.IsInf(f, 1) {
		return lexicon.FloatINF
	}

	if math.IsInf(f, -1) {
		return lexicon.FloatNegINF
	}

	if f == 0 {
		if math.Signbit(f) {
			return "-0"
		}

		return "0"
	}

	abs := math.Abs(f)
	// XPath F&O: plain decimal for abs in [1e-6, 1e6), scientific notation otherwise.
	if abs >= 0.000001 && abs < 1_000_000 {
		return strconv.FormatFloat(f, 'f', -1, 64)
	}

	s := strconv.FormatFloat(f, 'E', -1, 64)
	if idx := strings.Index(s, "E"); idx >= 0 {
		mantissa := s[:idx]
		expPart := s[idx+1:]

		if !strings.Contains(mantissa, ".") {
			mantissa += ".0"
		}

		expPart = strings.TrimPrefix(expPart, "+")
		if strings.HasPrefix(expPart, "-") {
			inner := strings.TrimLeft(expPart[1:], "0")
			if inner == "" {
				inner = "0"
			}

			expPart = "-" + inner
		} else {
			expPart = strings.TrimLeft(expPart, "0")
			if expPart == "" {
				expPart = "0"
			}
		}

		s = mantissa + "E" + expPart
	}

	return s
}

// formatXPathFloat formats a float64 (representing an xs:float) using
// single-precision XPath canonical representation with 32-bit precision.
func formatXPathFloat(f float64) string {
	f32 := float32(f)
	if math.IsNaN(float64(f32)) {
		return lexicon.FloatNaN
	}

	if math.IsInf(float64(f32), 1) {
		return lexicon.FloatINF
	}

	if math.IsInf(float64(f32), -1) {
		return lexicon.FloatNegINF
	}

	if f32 == 0 {
		if math.Signbit(float64(f32)) {
			return "-0"
		}

		return "0"
	}

	abs := math.Abs(float64(f32))
	if abs >= 0.000001 && abs < 1_000_000 {
		return strconv.FormatFloat(float64(f32), 'f', -1, 32)
	}

	s := strconv.FormatFloat(float64(f32), 'E', -1, 32)
	if idx := strings.Index(s, "E"); idx >= 0 {
		mantissa := s[:idx]
		expPart := s[idx+1:]

		if !strings.Contains(mantissa, ".") {
			mantissa += ".0"
		}

		expPart = strings.TrimPrefix(expPart, "+")
		if strings.HasPrefix(expPart, "-") {
			inner := strings.TrimLeft(expPart[1:], "0")
			if inner == "" {
				inner = "0"
			}

			expPart = "-" + inner
		} else {
			expPart = strings.TrimLeft(expPart, "0")
			if expPart == "" {
				expPart = "0"
			}
		}

		s = mantissa + "E" + expPart
	}

	return s
}

// formatXSDYear formats a year per XSD canonical rules:
// - At least 4 digits, zero-padded
// - Negative years get a leading '-'
// - Years > 9999 use as many digits as needed
func formatXSDYear(year int) string {
	if year < 0 {
		return fmt.Sprintf("-%04d", -year)
	}

	return fmt.Sprintf("%04d", year)
}

func castToString(v xdm.AtomicValue) (xdm.AtomicValue, error) {
	s, err := atomicToString(v)
	if err != nil {
		return xdm.AtomicValue{}, err
	}

	return xdm.AtomicValue{TypeName: xdm.TypeString, Value: s}, nil
}

func isValidDecimalString(s string) bool {
	if s == "" {
		return false
	}

	i := 0
	if s[i] == '+' || s[i] == '-' {
		i++
	}

	if i >= len(s) {
		return false
	}

	hasDigit := false
	for i < len(s) && s[i] >= '0' && s[i] <= '9' {
		hasDigit = true
		i++
	}

	if i < len(s) && s[i] == '.' {
		i++
		for i < len(s) && s[i] >= '0' && s[i] <= '9' {
			hasDigit = true
			i++
		}
	}

	return hasDigit && i == len(s)
}

// normalizeWhitespace replaces #x9, #xA, #xD with #x20 (for xs:normalizedString).
func normalizeWhitespace(s string) string {
	return strings.Map(func(r rune) rune {
		switch r {
		case '\t', '\n', '\r':
			return ' '
		default:
			return r
		}
	}, s)
}

// collapseWhitespace normalizes then collapses whitespace (for xs:token and derived).
// Replaces #x9, #xA, #xD with #x20, then collapses runs of #x20 to a single space,
// and strips leading/trailing spaces.
func collapseWhitespace(s string) string {
	// Preserve lexical casts' rune semantics, including replacement of invalid
	// UTF-8, without normalizing or allocating the complete source first.
	return normalizeWhitespace(collapseXMLWhitespace(s))
}

func collapseXMLWhitespace(s string) string { return xmlchar.CollapseSpace(s) }

// parseXPathDouble parses an XML Schema double, using infinity on overflow.
func parseXPathDouble(s string) (float64, error) {
	return parseXPathFloating(s, 64)
}

func parseXPathFloating(s string, bits int) (float64, error) {
	if err := value.ValidateBuiltin(s, lexicon.TypeDouble, value.Version11); err != nil {
		return 0, err
	}

	switch s {
	case "INF", "+INF":
		return math.Inf(1), nil
	case lexicon.FloatNegINF:
		return math.Inf(-1), nil
	case valueNaN:
		return math.NaN(), nil
	}

	f, err := strconv.ParseFloat(s, bits)
	if errors.Is(err, strconv.ErrRange) && math.IsInf(f, 0) {
		return f, nil
	}

	return f, err
}
