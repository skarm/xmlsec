// Derived from lestrrat-go/helium at 7362c0a70122a757780f4d0b545a9b370dead6ab.
// Copyright (c) 2015 lestrrat. MIT License; see licenses/MIT-helium.txt at the repository root.

package xpath

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"math/big"
	"strings"
	"time"

	"github.com/skarm/xmlsec/internal/xmlchar"
	"github.com/skarm/xmlsec/transform/internal/xdm"
	lexical "github.com/skarm/xmlsec/transform/internal/xdm/lexical"
	"github.com/skarm/xmlsec/transform/internal/xdm/lexicon"
)

func validateVersionedCast(ctx context.Context, source xdm.AtomicValue, target string) error {
	if XMLSchemaVersion(ctx) != 10 {
		return nil
	}

	source = normalizeCastSource(source)
	if source.TypeName != xdm.TypeUntypedAtomic && !xdm.IsStringDerived(source.TypeName) {
		return nil
	}

	switch target {
	case xdm.TypeDouble, xdm.TypeFloat, xdm.TypeDate, xdm.TypeDateTime,
		xdm.TypeDateTimeStamp, xdm.TypeGYear, xdm.TypeGYearMonth, xdm.TypeAnyURI:
		text := collapseXMLWhitespace(source.StringVal())
		if err := lexical.ValidateBuiltin(text, strings.TrimPrefix(target, "xs:"), lexical.Version10); err != nil {
			return castError(text, target)
		}
	}

	return nil
}

// CastFromStringContext applies the invocation's datatype edition and budgets.
func CastFromStringContext(ctx context.Context, source, target string) (xdm.AtomicValue, error) {
	return CastAtomicContext(ctx, xdm.AtomicValue{TypeName: xdm.TypeString, Value: source}, target)
}

// msgDateTimeStampTimezone is the FORG0001 message for an xs:dateTimeStamp
// value that is missing its mandatory timezone.
const msgDateTimeStampTimezone = "xs:dateTimeStamp requires a timezone"

// CastAtomic casts an AtomicValue to the target type.
func CastAtomic(v xdm.AtomicValue, targetType string) (xdm.AtomicValue, error) {
	if targetType == xdm.TypeError {
		return xdm.AtomicValue{}, &xdm.Error{Code: errCodeFORG0001, Message: "xs:error has an empty value space"}
	}

	if isAbstractCastTarget(targetType) {
		return xdm.AtomicValue{}, &xdm.Error{
			Code:    errCodeXPST0080,
			Message: "cannot cast to abstract type " + targetType,
		}
	}

	if v.TypeName == targetType {
		// Public atomic values may be retagged; identity must still enforce
		// the mandatory timezone and time.Time payload of xs:dateTimeStamp.
		if err := validateDateTimeStampSource(v); err != nil {
			return xdm.AtomicValue{}, err
		}

		return v, nil
	}

	v = normalizeCastSource(v)
	if v.TypeName == targetType {
		if err := validateDateTimeStampSource(v); err != nil {
			return xdm.AtomicValue{}, err
		}

		return v, nil
	}

	if xdm.IsIntegerDerived(targetType) && targetType != xdm.TypeInteger {
		return castToIntegerSubtype(v, targetType)
	}

	if xdm.IsIntegerDerived(v.TypeName) && v.TypeName != xdm.TypeInteger {
		v = xdm.AtomicValue{TypeName: xdm.TypeInteger, Value: v.Value}
	}

	if v.TypeName == xdm.TypeUntypedAtomic {
		return CastFromString(v.StringVal(), targetType)
	}

	return castBuiltinAtomic(v, targetType)
}

func isAbstractCastTarget(typeName string) bool {
	return typeName == xdm.TypeAnyAtomicType ||
		typeName == "xs:anySimpleType" ||
		typeName == "xs:anyType" ||
		typeName == xdm.TypeNOTATION
}

// validateDateTimeStampSource enforces the xs:dateTimeStamp invariant on a
// source value before it is cast to a date/time subtype. AtomicValue is public
// and mutable, so a caller can retag a no-timezone or non-time value as
// TypeDateTimeStamp; the subtype cast paths call TimeVal() unconditionally and
// would panic on such a value. Validate the source is a time.Time carrying a
// timezone, rejecting otherwise with a structured FORG0001 error.
func validateDateTimeStampSource(v xdm.AtomicValue) error {
	if v.TypeName != xdm.TypeDateTimeStamp {
		return nil
	}

	t, ok := v.Value.(time.Time)
	if !ok {
		return &xdm.Error{Code: errCodeFORG0001, Message: msgDateTimeStampTimezone}
	}

	if !xdm.HasTimezone(t) {
		return &xdm.Error{Code: errCodeFORG0001, Message: msgDateTimeStampTimezone}
	}

	return nil
}

// normalizeCastSource exposes a schema-derived user type's recorded builtin
// base to the builtin cast helpers. Empty type tags and unrecognized bases stay
// opaque, and existing builtin annotations retain their original dispatch.
func normalizeCastSource(v xdm.AtomicValue) xdm.AtomicValue {
	if v.TypeName != "" && v.BaseType != "" && xdm.IsKnownXSDType(v.BaseType) && !xdm.IsKnownXSDType(v.TypeName) {
		return xdm.AtomicValue{TypeName: v.BaseType, Value: v.Value}
	}

	return v
}

func castToIntegerSubtype(v xdm.AtomicValue, targetType string) (xdm.AtomicValue, error) {
	iv, err := CastAtomic(v, xdm.TypeInteger)
	if err != nil {
		return xdm.AtomicValue{}, err
	}

	n := iv.BigInt()
	minVal, maxVal := integerTypeRange(targetType)

	if err := checkBigIntRange(n, minVal, maxVal, targetType); err != nil {
		return xdm.AtomicValue{}, err
	}

	return xdm.AtomicValue{TypeName: targetType, Value: n}, nil
}

func castBuiltinAtomic(v xdm.AtomicValue, targetType string) (xdm.AtomicValue, error) {
	switch targetType {
	case xdm.TypeString:
		return castToString(v)
	case xdm.TypeDouble:
		return castToDouble(v)
	case xdm.TypeFloat:
		return castToFloat(v)
	case xdm.TypeInteger:
		return castToInteger(v)
	case xdm.TypeDecimal:
		return castToDecimal(v)
	case xdm.TypeBoolean:
		return castToBoolean(v)
	case xdm.TypeAnyURI:
		if v.TypeName == xdm.TypeString {
			return xdm.AtomicValue{TypeName: targetType, Value: collapseWhitespace(v.StringVal())}, nil
		}
	case xdm.TypeBase64Binary:
		return castToBase64Binary(v)
	case xdm.TypeHexBinary:
		return castToHexBinary(v)
	case xdm.TypeDate, xdm.TypeDateTime, xdm.TypeDateTimeStamp, xdm.TypeTime:
		return castCalendarAtomic(v, targetType)
	case xdm.TypeDuration, xdm.TypeDayTimeDuration, xdm.TypeYearMonthDuration:
		return castDurationAtomic(v, targetType)
	case xdm.TypeGDay, xdm.TypeGMonth, xdm.TypeGMonthDay, xdm.TypeGYear, xdm.TypeGYearMonth:
		return castToGType(v, targetType)
	case xdm.TypeUntypedAtomic, xdm.TypeNormalizedString,
		xdm.TypeToken, xdm.TypeLanguage, xdm.TypeName, xdm.TypeNCName,
		xdm.TypeNMTOKEN, xdm.TypeNMTOKENS, xdm.TypeENTITY, xdm.TypeID, xdm.TypeIDREF, xdm.TypeIDREFS:
		s, err := atomicToString(v)
		if err != nil {
			return xdm.AtomicValue{}, err
		}

		return castDerivedString(s, targetType)
	case xdm.TypeQName:
		return castAtomicQName(v)
	}

	return unsupportedAtomicCast(v, targetType)
}

func castCalendarAtomic(v xdm.AtomicValue, targetType string) (xdm.AtomicValue, error) {
	if v.TypeName == xdm.TypeString {
		return CastFromString(v.StringVal(), targetType)
	}

	if targetType == xdm.TypeDateTimeStamp {
		return castToDateTimeStamp(v)
	}

	if err := validateDateTimeStampSource(v); err != nil {
		return xdm.AtomicValue{}, err
	}

	switch targetType {
	case xdm.TypeDate:
		if v.TypeName == xdm.TypeDateTime || v.TypeName == xdm.TypeDateTimeStamp {
			t := v.TimeVal()
			return xdm.AtomicValue{TypeName: targetType, Value: time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, t.Location())}, nil
		}
	case xdm.TypeDateTime:
		if v.TypeName == xdm.TypeDateTimeStamp || v.TypeName == xdm.TypeDate {
			return xdm.AtomicValue{TypeName: targetType, Value: v.TimeVal()}, nil
		}
	case xdm.TypeTime:
		if v.TypeName == xdm.TypeDateTime || v.TypeName == xdm.TypeDateTimeStamp {
			t := v.TimeVal()
			loc := t.Location()

			if !xdm.HasTimezone(t) {
				loc = xdm.NoTimezone()
			}

			return xdm.AtomicValue{TypeName: targetType, Value: time.Date(0, 1, 1, t.Hour(), t.Minute(), t.Second(), t.Nanosecond(), loc)}, nil
		}
	}

	return unsupportedAtomicCast(v, targetType)
}

func castToDateTimeStamp(v xdm.AtomicValue) (xdm.AtomicValue, error) {
	if v.TypeName == xdm.TypeDateTime || v.TypeName == xdm.TypeDate {
		// These public tags do not guarantee a time.Time payload.
		t, ok := v.Value.(time.Time)
		if !ok || !xdm.HasTimezone(t) {
			return xdm.AtomicValue{}, &xdm.Error{Code: errCodeFORG0001, Message: msgDateTimeStampTimezone}
		}

		return xdm.AtomicValue{TypeName: xdm.TypeDateTimeStamp, Value: t}, nil
	}

	// Preserve the xs:dateTime fallback's error for other source types.
	dt, err := CastAtomic(v, xdm.TypeDateTime)
	if err != nil {
		return xdm.AtomicValue{}, err
	}

	if !xdm.HasTimezone(dt.TimeVal()) {
		return xdm.AtomicValue{}, &xdm.Error{Code: errCodeFORG0001, Message: msgDateTimeStampTimezone}
	}

	dt.TypeName = xdm.TypeDateTimeStamp

	return dt, nil
}

func castDurationAtomic(v xdm.AtomicValue, targetType string) (xdm.AtomicValue, error) {
	if v.TypeName == xdm.TypeString {
		return CastFromString(v.StringVal(), targetType)
	}

	switch v.TypeName {
	case xdm.TypeDuration, xdm.TypeDayTimeDuration, xdm.TypeYearMonthDuration:
		return xdm.AtomicValue{TypeName: targetType, Value: durationSubtype(v.DurationVal(), targetType)}, nil
	}

	return unsupportedAtomicCast(v, targetType)
}

func castAtomicQName(v xdm.AtomicValue) (xdm.AtomicValue, error) {
	if v.TypeName == xdm.TypeNOTATION {
		return xdm.AtomicValue{TypeName: xdm.TypeQName, Value: v.Value}, nil
	}

	if _, ok := v.Value.(xdm.QNameValue); ok {
		return xdm.AtomicValue{TypeName: xdm.TypeQName, Value: v.Value}, nil
	}

	// Lexical QName casts require the namespace context provided by the
	// evaluator or constructor; the context-free API cannot resolve them.
	return xdm.AtomicValue{}, &xdm.Error{
		Code:    lexicon.ErrXPTY0004,
		Message: fmt.Sprintf("cannot cast %s to %s (requires namespace context)", v.TypeName, xdm.TypeQName),
	}
}

func unsupportedAtomicCast(v xdm.AtomicValue, targetType string) (xdm.AtomicValue, error) {
	return xdm.AtomicValue{}, &xdm.Error{
		Code:    lexicon.ErrXPTY0004,
		Message: fmt.Sprintf("cannot cast %s to %s", v.TypeName, targetType),
	}
}

func integerTypeRange(typeName string) (minVal *big.Int, maxVal *big.Int) {
	switch typeName {
	case xdm.TypeLong:
		return big.NewInt(math.MinInt64), big.NewInt(math.MaxInt64)
	case xdm.TypeInt:
		return big.NewInt(-2147483648), big.NewInt(2147483647)
	case xdm.TypeShort:
		return big.NewInt(-32768), big.NewInt(32767)
	case xdm.TypeByte:
		return big.NewInt(-128), big.NewInt(127)
	case xdm.TypeUnsignedLong:
		return big.NewInt(0), new(big.Int).SetUint64(math.MaxUint64)
	case xdm.TypeUnsignedInt:
		return big.NewInt(0), big.NewInt(4294967295)
	case xdm.TypeUnsignedShort:
		return big.NewInt(0), big.NewInt(65535)
	case xdm.TypeUnsignedByte:
		return big.NewInt(0), big.NewInt(255)
	case xdm.TypeNonNegativeInteger:
		return big.NewInt(0), nil
	case xdm.TypeNonPositiveInteger:
		return nil, big.NewInt(0)
	case xdm.TypePositiveInteger:
		return big.NewInt(1), nil
	case xdm.TypeNegativeInteger:
		return nil, big.NewInt(-1)
	}

	return nil, nil
}

// checkBigIntRange reports a FORG0001 "out of range" error when n falls below
// minVal or above maxVal (either bound may be nil to mean unbounded). The
// min-then-max check order is significant for which bound a value violates.
func checkBigIntRange(n, minVal, maxVal *big.Int, typeName string) error {
	if minVal != nil && n.Cmp(minVal) < 0 {
		return &xdm.Error{
			Code:    errCodeFORG0001,
			Message: fmt.Sprintf("value %s out of range for %s", n.String(), typeName),
		}
	}

	if maxVal != nil && n.Cmp(maxVal) > 0 {
		return &xdm.Error{
			Code:    errCodeFORG0001,
			Message: fmt.Sprintf("value %s out of range for %s", n.String(), typeName),
		}
	}

	return nil
}

// CastFromString casts a string value to the target atomic type.
func CastFromString(s string, targetType string) (xdm.AtomicValue, error) {
	switch targetType {
	case xdm.TypeString, xdm.TypeUntypedAtomic:
		return xdm.AtomicValue{TypeName: targetType, Value: s}, nil
	case xdm.TypeNormalizedString:
		return castDerivedString(s, targetType)
	case "xs:anyType", "xs:untyped":
		return xdm.AtomicValue{TypeName: xdm.TypeUntypedAtomic, Value: s}, nil
	}

	// XSD whiteSpace applies only to XML S, not all Unicode whitespace.
	trimmed := strings.Trim(s, " \t\r\n")

	switch targetType {
	case xdm.TypeInteger, xdm.TypeDecimal, xdm.TypeDouble, xdm.TypeFloat, xdm.TypeBoolean:
		return castNumericLexical(trimmed, targetType)
	case xdm.TypeDate, xdm.TypeDateTime, xdm.TypeDateTimeStamp, xdm.TypeTime:
		return castCalendarLexical(trimmed, targetType)
	case xdm.TypeDuration, xdm.TypeDayTimeDuration, xdm.TypeYearMonthDuration:
		return castDurationLexical(trimmed, targetType)
	case xdm.TypeBase64Binary, xdm.TypeHexBinary:
		return castBinaryLexical(trimmed, targetType)
	}

	if isIntegerSubtype(targetType) {
		return castIntegerLexical(trimmed, targetType)
	}
	// Only the remaining string-backed values can retain a trimmed source.
	if len(trimmed) != len(s) {
		trimmed = strings.Clone(trimmed)
	}

	s = trimmed

	switch targetType {
	case xdm.TypeAnyURI:
		return xdm.AtomicValue{TypeName: targetType, Value: collapseWhitespace(s)}, nil
	case xdm.TypeGDay:
		return castGregorianLexical(s, targetType, reGDay)
	case xdm.TypeGMonth:
		return castGregorianLexical(s, targetType, reGMonth)
	case xdm.TypeGMonthDay:
		return castGregorianLexical(s, targetType, reGMonthDay)
	case xdm.TypeGYear:
		return castGregorianLexical(s, targetType, reGYear)
	case xdm.TypeGYearMonth:
		return castGregorianLexical(s, targetType, reGYearMonth)
	case xdm.TypeNormalizedString, xdm.TypeToken, xdm.TypeLanguage, xdm.TypeName, xdm.TypeNCName,
		xdm.TypeNMTOKEN, xdm.TypeNMTOKENS, xdm.TypeENTITY, xdm.TypeID, xdm.TypeIDREF, xdm.TypeIDREFS:
		return castDerivedString(s, targetType)
	case xdm.TypeNOTATION:
		return xdm.AtomicValue{TypeName: targetType, Value: s}, nil
	}

	return xdm.AtomicValue{}, &xdm.Error{
		Code:    lexicon.ErrXPTY0004,
		Message: "cannot cast string to " + targetType,
	}
}

func castNumericLexical(s, targetType string) (xdm.AtomicValue, error) {
	switch targetType {
	case xdm.TypeInteger:
		return castIntegerLexical(s, targetType)
	case xdm.TypeDecimal:
		if !isValidDecimalString(s) {
			return xdm.AtomicValue{}, castError(s, targetType)
		}

		r, ok := new(big.Rat).SetString(s)
		if !ok {
			return xdm.AtomicValue{}, castError(s, targetType)
		}

		return xdm.AtomicValue{TypeName: targetType, Value: r}, nil
	case xdm.TypeDouble:
		f, err := parseXPathDouble(s)
		if err != nil {
			return xdm.AtomicValue{}, castError(s, targetType)
		}

		return xdm.AtomicValue{TypeName: targetType, Value: xdm.NewDouble(f)}, nil
	case xdm.TypeFloat:
		return castStringToFloat(s)
	default:
		switch s {
		case lexicon.ValueTrue, "1":
			return xdm.AtomicValue{TypeName: targetType, Value: true}, nil
		case lexicon.ValueFalse, "0":
			return xdm.AtomicValue{TypeName: targetType, Value: false}, nil
		default:
			return xdm.AtomicValue{}, castError(s, targetType)
		}
	}
}

func castIntegerLexical(s, targetType string) (xdm.AtomicValue, error) {
	n, ok := new(big.Int).SetString(s, 10)
	if !ok {
		return xdm.AtomicValue{}, castError(s, targetType)
	}

	if err := validateIntegerRange(n, targetType); err != nil {
		return xdm.AtomicValue{}, err
	}

	return xdm.AtomicValue{TypeName: targetType, Value: n}, nil
}

func castCalendarLexical(s, targetType string) (xdm.AtomicValue, error) {
	var (
		t   time.Time
		err error
	)

	switch targetType {
	case xdm.TypeDate:
		t, err = parseXSDDate(s)
	case xdm.TypeTime:
		t, err = parseXSDTime(s)
	default:
		t, err = parseXSDDateTime(s)
	}

	if err != nil {
		if xe, ok := errors.AsType[*xdm.Error](err); ok {
			return xdm.AtomicValue{}, xe
		}

		return xdm.AtomicValue{}, castError(s, targetType)
	}

	if targetType == xdm.TypeDateTimeStamp && !xdm.HasTimezone(t) {
		return xdm.AtomicValue{}, &xdm.Error{Code: errCodeFORG0001, Message: msgDateTimeStampTimezone}
	}

	return xdm.AtomicValue{TypeName: targetType, Value: t}, nil
}

func castDurationLexical(s, targetType string) (xdm.AtomicValue, error) {
	datePart, _, _ := strings.Cut(s, "T")
	if targetType == xdm.TypeDayTimeDuration && strings.ContainsAny(datePart, "YM") ||
		targetType == xdm.TypeYearMonthDuration && strings.ContainsAny(s, "DT") {
		return xdm.AtomicValue{}, castError(s, targetType)
	}

	d, err := parseXSDDuration(s)
	if err != nil {
		return xdm.AtomicValue{}, durationCastError(err, s, targetType)
	}

	if targetType == xdm.TypeDayTimeDuration && d.Months != 0 {
		return xdm.AtomicValue{}, castError(s, targetType)
	}

	// Exact seconds detect nonzero dayTime components even below float64's
	// representable range, where the mirror d.Seconds can underflow to zero.
	if targetType == xdm.TypeYearMonthDuration && ((d.SecRat != nil && d.SecRat.Sign() != 0) || d.Seconds != 0) {
		return xdm.AtomicValue{}, castError(s, targetType)
	}

	return xdm.AtomicValue{TypeName: targetType, Value: durationSubtype(d, targetType)}, nil
}

func castBinaryLexical(s, targetType string) (xdm.AtomicValue, error) {
	var (
		value []byte
		err   error
	)

	if targetType == xdm.TypeBase64Binary {
		value, err = decodeXSDBase64(s)
	} else {
		value, err = hex.DecodeString(s)
	}

	if err != nil {
		return xdm.AtomicValue{}, castError(s, targetType)
	}

	return xdm.AtomicValue{TypeName: targetType, Value: value}, nil
}

func castGregorianLexical(s, targetType string, matches func(string) bool) (xdm.AtomicValue, error) {
	if targetType == xdm.TypeGYear || targetType == xdm.TypeGYearMonth {
		if _, rest, err := splitXSDYear(s); errors.Is(err, errCalendarYearRange) {
			// Validate complete syntax before classifying representability.
			probe := "2000" + rest
			if matches(probe) && validateGregorianValue(targetType, probe) {
				return xdm.AtomicValue{}, &xdm.Error{Code: errCodeFODT0001, Message: errCalendarYearRange.Error()}
			}
		}
	}

	if !matches(s) || !validateGregorianValue(targetType, s) {
		return xdm.AtomicValue{}, castError(s, targetType)
	}

	if targetType == xdm.TypeGYear || targetType == xdm.TypeGYearMonth {
		s = normalizeNegZeroYear(s)
	}

	s = normalizeZeroTimezoneLexical(s)

	return xdm.AtomicValue{TypeName: targetType, Value: s}, nil
}

func isIntegerSubtype(t string) bool {
	switch t {
	case "xs:long", "xs:int", "xs:short", "xs:byte",
		"xs:unsignedLong", "xs:unsignedInt", "xs:unsignedShort", "xs:unsignedByte",
		"xs:positiveInteger", "xs:nonPositiveInteger",
		"xs:negativeInteger", "xs:nonNegativeInteger":
		return true
	}

	return false
}

func validateIntegerRange(n *big.Int, targetType string) error {
	var minVal, maxVal *big.Int

	switch targetType {
	case "xs:long":
		minVal, maxVal = big.NewInt(math.MinInt64), big.NewInt(math.MaxInt64)
	case "xs:int":
		minVal, maxVal = big.NewInt(math.MinInt32), big.NewInt(math.MaxInt32)
	case "xs:short":
		minVal, maxVal = big.NewInt(math.MinInt16), big.NewInt(math.MaxInt16)
	case "xs:byte":
		minVal, maxVal = big.NewInt(math.MinInt8), big.NewInt(math.MaxInt8)
	case "xs:unsignedLong":
		minVal = big.NewInt(0)
		maxVal = new(big.Int).SetUint64(math.MaxUint64)
	case "xs:unsignedInt":
		minVal, maxVal = big.NewInt(0), big.NewInt(math.MaxUint32)
	case "xs:unsignedShort":
		minVal, maxVal = big.NewInt(0), big.NewInt(math.MaxUint16)
	case "xs:unsignedByte":
		minVal, maxVal = big.NewInt(0), big.NewInt(math.MaxUint8)
	case "xs:positiveInteger":
		minVal = big.NewInt(1)
	case "xs:nonPositiveInteger":
		maxVal = big.NewInt(0)
	case "xs:negativeInteger":
		maxVal = big.NewInt(-1)
	case "xs:nonNegativeInteger":
		minVal = big.NewInt(0)
	default:
		return nil
	}

	if minVal != nil && n.Cmp(minVal) < 0 {
		return castError(n.String(), targetType)
	}

	if maxVal != nil && n.Cmp(maxVal) > 0 {
		return castError(n.String(), targetType)
	}

	return nil
}

// normalizeNegZeroYear strips leading '-' from "-0000" years (e.g. "-0000-05" → "0000-05").
// Per XSD, negative zero is identical to positive zero for year values.
func normalizeNegZeroYear(s string) string {
	if len(s) < 5 || s[0] != '-' {
		return s
	}
	// Check if all year digits are zero: "-0000..." or "-00000..."
	i := 1
	for i < len(s) && s[i] == '0' {
		i++
	}
	// i now points past the zeros; if it hits a non-digit boundary, year is all zeros
	if i < len(s) && s[i] >= '0' && s[i] <= '9' {
		return s // non-zero year digit found
	}

	return s[1:] // strip the '-'
}

func normalizeZeroTimezoneLexical(s string) string {
	switch {
	case strings.HasSuffix(s, "+00:00"), strings.HasSuffix(s, "-00:00"):
		return s[:len(s)-6] + "Z"
	default:
		return s
	}
}

// durationCastError distinguishes duration representability from lexical errors.
func durationCastError(err error, value, targetType string) *xdm.Error {
	if errors.Is(err, errDurationMonthsRange) {
		return &xdm.Error{
			Code:    errCodeFODT0002,
			Message: fmt.Sprintf("cannot cast %q to %s: duration overflow", value, targetType),
		}
	}

	return castError(value, targetType)
}

func isFloatOrDouble(typeName string) bool {
	return typeName == xdm.TypeFloat || typeName == xdm.TypeDouble
}

func durationSubtype(d xdm.Duration, targetType string) xdm.Duration {
	switch targetType {
	case xdm.TypeDayTimeDuration:
		return xdm.Duration{Seconds: d.Seconds, FracSec: d.FracSec, SecRat: d.SecRat, Negative: d.Negative}
	case xdm.TypeYearMonthDuration:
		return xdm.Duration{Months: d.Months, Negative: d.Negative}
	default:
		return d
	}
}

func castDerivedString(s, targetType string) (xdm.AtomicValue, error) {
	switch targetType {
	case xdm.TypeUntypedAtomic:
		// Unlike string-derived types, untypedAtomic preserves whitespace.
	case xdm.TypeNormalizedString:
		s = normalizeWhitespace(s)
	default:
		s = collapseWhitespace(s)
		if err := validateStringDerivedType(s, targetType); err != nil {
			return xdm.AtomicValue{}, err
		}
	}

	return xdm.AtomicValue{TypeName: targetType, Value: s}, nil
}

func validateStringDerivedType(s, targetType string) error {
	switch targetType {
	case xdm.TypeName:
		if !reName(s) {
			return castError(s, targetType)
		}
	case xdm.TypeNCName, xdm.TypeENTITY, xdm.TypeID, xdm.TypeIDREF:
		if !reNCName(s) {
			return castError(s, targetType)
		}
	case xdm.TypeNMTOKEN:
		if !reNMTOKEN(s) {
			return castError(s, targetType)
		}
	case xdm.TypeNMTOKENS:
		// xs:NMTOKENS is a space-separated list of NMTOKEN values; must have at least one
		if s == "" {
			return castError(s, targetType)
		}

		for tok := range strings.FieldsFuncSeq(s, xmlchar.IsSpace) {
			if !reNMTOKEN(tok) {
				return castError(s, targetType)
			}
		}
	case xdm.TypeIDREFS:
		// xs:IDREFS is a space-separated list of IDREF (NCName) values; must have at least one
		if s == "" {
			return castError(s, targetType)
		}

		for tok := range strings.FieldsFuncSeq(s, xmlchar.IsSpace) {
			if !reNCName(tok) {
				return castError(s, targetType)
			}
		}
	case xdm.TypeLanguage:
		if !reLang(s) {
			return castError(s, targetType)
		}
	}

	return nil
}

func castError(value string, targetType string) *xdm.Error {
	return &xdm.Error{
		Code:    errCodeFORG0001,
		Message: fmt.Sprintf("cannot cast %q to %s", value, targetType),
	}
}
