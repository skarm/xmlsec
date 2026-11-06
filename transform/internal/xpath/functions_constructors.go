// Derived from lestrrat-go/helium at 7362c0a70122a757780f4d0b545a9b370dead6ab.
// Copyright (c) 2015 lestrrat. MIT License; see licenses/MIT-helium.txt at the repository root.

package xpath

import (
	"context"
	"fmt"
	"math"
	"math/big"
	"strconv"
	"strings"

	"github.com/skarm/xmlsec/internal/lexicon"
	"github.com/skarm/xmlsec/internal/xmlchar"
	"github.com/skarm/xmlsec/transform/internal/xdm"
	"github.com/skarm/xmlsec/transform/internal/xdm/lexical"
)

// Constructor numeric subtype boundaries are independent of scalar atom
// cardinality. Token capacity is an initial item allocation hint; token work
// counts one logical operation per validated string, with all limits unchanged.
const (
	unsignedConstructorMinimum      = 0
	nonnegativeConstructorMinimum   = 0
	nonpositiveConstructorMaximum   = 0
	positiveConstructorMinimum      = 1
	negativeConstructorMaximum      = -1
	constructorAtomCardinality      = 1
	initialConstructorTokenCapacity = 8
	constructorTokenWork            = 1
)

// ASCII Gregorian lexical field offsets count bytes in ---DD/--MM/--MM-DD.
// Year four is a leap-year reference, not the minimum year lexical digit count.
const (
	constructorMaximumDay        = 31
	gregorianLeapReferenceYear   = 4
	constructorMaximumYearDigits = 9
	gregorianDayFieldStart       = 3
	gregorianDayFieldEnd         = 5
	gregorianMonthFieldStart     = 2
	gregorianMonthFieldEnd       = 4
	gregorianMonthDayFieldStart  = 5
	gregorianMonthDayFieldEnd    = 7
	gregorianYearMonthFieldEnd   = 3 // delimiter byte plus two month digits
)

func lookupConstructor(requestedName string) (*builtinFunc, bool) {
	// Base XSD types — delegate to CastAtomic
	for _, entry := range []struct {
		name       string
		targetType string
	}{
		{lexicon.TypeString, xdm.TypeString},
		{lexicon.TypeBoolean, xdm.TypeBoolean},
		{lexicon.TypeDecimal, xdm.TypeDecimal},
		{lexicon.TypeDouble, xdm.TypeDouble},
		{lexicon.TypeFloat, xdm.TypeFloat},
		{lexicon.TypeInteger, xdm.TypeInteger},
		{lexicon.TypeDate, xdm.TypeDate},
		{lexicon.TypeDateTime, xdm.TypeDateTime},
		{lexicon.TypeTime, xdm.TypeTime},
		{lexicon.TypeDuration, xdm.TypeDuration},
		{lexicon.TypeDayTimeDuration, xdm.TypeDayTimeDuration},
		{lexicon.TypeYearMonthDuration, xdm.TypeYearMonthDuration},
		{lexicon.TypeAnyURI, xdm.TypeAnyURI},
		{lexicon.TypeBase64Binary, xdm.TypeBase64Binary},
		{lexicon.TypeHexBinary, xdm.TypeHexBinary},
		{lexicon.TypeUntypedAtomic, xdm.TypeUntypedAtomic},
	} {
		if requestedName == entry.name {
			return &builtinFunc{name: requestedName, min: builtinArityOne, max: builtinArityOne, fn: makeXSConstructor(entry.targetType)}, true
		}
	}

	// xs:QName constructor needs namespace context to resolve prefixes
	if requestedName == lexicon.TypeQName {
		return &builtinFunc{name: requestedName, min: builtinArityOne, max: builtinArityOne, fn: makeXSQNameConstructor()}, true
	}

	// Derived integer types — cast to integer, then validate range
	for _, entry := range []struct {
		name     string
		typeName string
		min      int64
		max      int64
	}{
		{lexicon.TypeLong, xdm.TypeLong, math.MinInt64, math.MaxInt64},
		{lexicon.TypeInt, xdm.TypeInt, math.MinInt32, math.MaxInt32},
		{lexicon.TypeShort, xdm.TypeShort, math.MinInt16, math.MaxInt16},
		{lexicon.TypeByte, xdm.TypeByte, math.MinInt8, math.MaxInt8},
		{lexicon.TypeUnsignedInt, xdm.TypeUnsignedInt, unsignedConstructorMinimum, math.MaxUint32},
		{lexicon.TypeUnsignedShort, xdm.TypeUnsignedShort, unsignedConstructorMinimum, math.MaxUint16},
		{lexicon.TypeUnsignedByte, xdm.TypeUnsignedByte, unsignedConstructorMinimum, math.MaxUint8},
	} {
		if requestedName == entry.name {
			return &builtinFunc{name: requestedName, min: builtinArityOne, max: builtinArityOne, fn: makeXSIntegerRange(entry.typeName, entry.min, entry.max)}, true
		}
	}
	// Unbounded integer subtypes need big.Int constructor (no fixed max/min)
	if requestedName == lexicon.TypeNonNegativeInteger {
		return &builtinFunc{name: requestedName, min: builtinArityOne, max: builtinArityOne, fn: makeXSIntegerRangeBig(xdm.TypeNonNegativeInteger, big.NewInt(nonnegativeConstructorMinimum), nil)}, true
	}

	if requestedName == lexicon.TypeNonPositiveInteger {
		return &builtinFunc{name: requestedName, min: builtinArityOne, max: builtinArityOne, fn: makeXSIntegerRangeBig(xdm.TypeNonPositiveInteger, nil, big.NewInt(nonpositiveConstructorMaximum))}, true
	}

	if requestedName == lexicon.TypePositiveInteger {
		return &builtinFunc{name: requestedName, min: builtinArityOne, max: builtinArityOne, fn: makeXSIntegerRangeBig(xdm.TypePositiveInteger, big.NewInt(positiveConstructorMinimum), nil)}, true
	}

	if requestedName == lexicon.TypeNegativeInteger {
		return &builtinFunc{name: requestedName, min: builtinArityOne, max: builtinArityOne, fn: makeXSIntegerRangeBig(xdm.TypeNegativeInteger, nil, big.NewInt(negativeConstructorMaximum))}, true
	}

	// xs:unsignedLong needs big.Int max since MaxUint64 exceeds int64
	if requestedName == lexicon.TypeUnsignedLong {
		return &builtinFunc{name: requestedName, min: builtinArityOne, max: builtinArityOne, fn: makeXSIntegerRangeBig(xdm.TypeUnsignedLong, big.NewInt(unsignedConstructorMinimum), new(big.Int).SetUint64(math.MaxUint64))}, true
	}

	// Derived string types — cast to string, validate, store with derived type name
	for _, entry := range []struct {
		name     string
		typeName string
		re       lexicalCheck // nil = no validation, just string cast
	}{
		{lexicon.TypeNormalizedString, xdm.TypeNormalizedString, nil},
		{lexicon.TypeToken, xdm.TypeToken, nil},
		{lexicon.TypeLanguage, xdm.TypeLanguage, reLang},
		{lexicon.TypeName, xdm.TypeName, reName},
		{lexicon.TypeNCName, xdm.TypeNCName, reNCName},
		{lexicon.TypeNMToken, xdm.TypeNMTOKEN, reNMTOKEN},
		{lexicon.TypeENTITY, xdm.TypeENTITY, reNCName},
		{lexicon.TypeID, xdm.TypeID, reNCName},
		{lexicon.TypeIDREF, xdm.TypeIDREF, reNCName},
	} {
		if requestedName == entry.name {
			return &builtinFunc{name: requestedName, min: builtinArityOne, max: builtinArityOne, fn: makeXSStringRestriction(entry.typeName, entry.re)}, true
		}
	}

	// List types — split by whitespace, produce sequence of item type values
	if requestedName == lexicon.TypeNMTokens {
		return &builtinFunc{name: requestedName, min: builtinArityOne, max: builtinArityOne, fn: makeXSTokenList(xdm.TypeNMTOKENS, xdm.TypeNMTOKEN, reNMTOKEN)}, true
	}

	if requestedName == lexicon.TypeIDREFS {
		return &builtinFunc{name: requestedName, min: builtinArityOne, max: builtinArityOne, fn: makeXSTokenList(xdm.TypeIDREFS, xdm.TypeIDREF, reNCName)}, true
	}

	if requestedName == lexicon.TypeENTITIES {
		return &builtinFunc{name: requestedName, min: builtinArityOne, max: builtinArityOne, fn: makeXSTokenList(xdm.TypeENTITIES, xdm.TypeENTITY, reNCName)}, true
	}

	// Gregorian date part types. CastAtomic/CastFromString perform the
	// per-type lexical validation, so these share the generic constructor.
	for _, entry := range []struct {
		name     string
		typeName string
	}{
		{lexicon.TypeGDay, xdm.TypeGDay},
		{lexicon.TypeGMonth, xdm.TypeGMonth},
		{lexicon.TypeGMonthDay, xdm.TypeGMonthDay},
		{lexicon.TypeGYear, xdm.TypeGYear},
		{lexicon.TypeGYearMonth, xdm.TypeGYearMonth},
	} {
		if requestedName == entry.name {
			return &builtinFunc{name: requestedName, min: builtinArityOne, max: builtinArityOne, fn: makeXSConstructor(entry.typeName)}, true
		}
	}

	// xs:dateTimeStamp — dateTime with required timezone. CastAtomic enforces
	// the mandatory-timezone rule, so the generic constructor suffices.
	if requestedName == lexicon.TypeDateTimeStamp {
		return &builtinFunc{name: requestedName, min: builtinArityOne, max: builtinArityOne, fn: makeXSConstructor(xdm.TypeDateTimeStamp)}, true
	}

	// xs:error — always raises an error (used for type checking tests)
	if requestedName == lexicon.TypeError {
		return &builtinFunc{name: requestedName, min: builtinArityOne, max: builtinArityOne, fn: fnXSError}, true
	}

	// xs:numeric preserves numeric members and otherwise selects xs:double.
	if requestedName == lexicon.TypeNumeric {
		return &builtinFunc{name: requestedName, min: builtinArityOne, max: builtinArityOne, fn: makeXSConstructor(xdm.TypeNumeric)}, true
	}

	return nil, false
}

// makeXSConstructor returns a constructor function for a base XSD type.
func makeXSConstructor(targetType string) func(context.Context, []xdm.Sequence) (xdm.Sequence, error) {
	return func(ctx context.Context, args []xdm.Sequence) (xdm.Sequence, error) {
		a, empty, err := atomizeConstructorArg(args[0], targetType)
		if err != nil {
			return nil, err
		}

		if empty {
			return nil, nil
		}

		var result xdm.AtomicValue
		if targetType == xdm.TypeNumeric {
			result, err = castToNumeric(ctx, a)
		} else {
			result, err = CastAtomicContext(ctx, a, targetType)
		}

		if err != nil {
			return nil, err
		}

		return xdm.SingleAtomic(result), nil
	}
}

// makeXSQNameConstructor returns a constructor for xs:QName that resolves
// prefixes using the namespace context from the evaluator.
func makeXSQNameConstructor() func(context.Context, []xdm.Sequence) (xdm.Sequence, error) {
	return func(ctx context.Context, args []xdm.Sequence) (xdm.Sequence, error) {
		a, empty, err := atomizeConstructorArg(args[0], xdm.TypeQName)
		if err != nil {
			return nil, err
		}

		if empty {
			return nil, nil
		}

		result, err := castToQName(a, getFnContext(ctx))
		if err != nil {
			return nil, err
		}

		return xdm.SingleAtomic(result), nil
	}
}

// makeXSIntegerRange returns a constructor for a derived integer type with range validation.
func makeXSIntegerRange(typeName string, minVal, maxVal int64) func(context.Context, []xdm.Sequence) (xdm.Sequence, error) {
	return makeXSIntegerRangeBig(typeName, big.NewInt(minVal), big.NewInt(maxVal))
}

// makeXSIntegerRangeBig returns a constructor for a derived integer type with big.Int range validation.
func makeXSIntegerRangeBig(typeName string, minBig, maxBig *big.Int) func(context.Context, []xdm.Sequence) (xdm.Sequence, error) {
	return func(ctx context.Context, args []xdm.Sequence) (xdm.Sequence, error) {
		a, empty, err := atomizeConstructorArg(args[0], typeName)
		if err != nil {
			return nil, err
		}

		if empty {
			return nil, nil
		}

		iv, err := CastAtomicContext(ctx, a, xdm.TypeInteger)
		if err != nil {
			return nil, err
		}

		n := iv.BigInt()
		if err := checkBigIntRange(n, minBig, maxBig, typeName); err != nil {
			return nil, err
		}

		return xdm.SingleAtomic(xdm.AtomicValue{TypeName: typeName, Value: n}), nil
	}
}

type lexicalCheck func(string) bool

func (f lexicalCheck) MatchString(s string) bool { return f(s) }

func reNCName(s string) bool { return xmlchar.IsValidNCName(s) }
func reName(s string) bool   { return xmlchar.IsValidName(s) }
func reNMTOKEN(s string) bool {
	return lexical.ValidateBuiltin(s, lexicon.TypeNMToken, lexical.Version11) == nil
}
func reLang(s string) bool { return lexical.ValidLanguage(s) }

// makeXSStringRestriction returns a constructor for a derived string type.
func makeXSStringRestriction(typeName string, validate lexicalCheck) func(context.Context, []xdm.Sequence) (xdm.Sequence, error) {
	return func(ctx context.Context, args []xdm.Sequence) (xdm.Sequence, error) {
		a, empty, err := atomizeConstructorArg(args[0], typeName)
		if err != nil {
			return nil, err
		}

		if empty {
			return nil, nil
		}

		s, err := atomicToString(a)
		if err != nil {
			return nil, err
		}

		if typeName == xdm.TypeNormalizedString {
			s = normalizeWhitespace(s)
		} else {
			s = collapseWhitespace(s)
		}

		if validate != nil && !validate.MatchString(s) {
			return nil, &xdm.Error{
				Code:    errCodeFORG0001,
				Message: fmt.Sprintf("cannot cast %q to %s", s, typeName),
			}
		}

		return xdm.SingleAtomic(xdm.AtomicValue{TypeName: typeName, Value: s}), nil
	}
}

// makeXSTokenList returns a constructor for xs:NMTOKENS or xs:IDREFS (whitespace-separated list).
// listType (e.g. xs:NMTOKENS) drives the cardinality/type error message; itemType
// (e.g. xs:NMTOKEN) drives per-token validation and result construction.
func makeXSTokenList(listType, itemType string, tokenRe lexicalCheck) func(context.Context, []xdm.Sequence) (xdm.Sequence, error) {
	return func(ctx context.Context, args []xdm.Sequence) (xdm.Sequence, error) {
		a, empty, err := atomizeConstructorArg(args[0], listType)
		if err != nil {
			return nil, err
		}

		if empty {
			return nil, nil
		}

		source := normalizeCastSource(a)
		if source.TypeName != xdm.TypeUntypedAtomic && !xdm.IsStringDerived(source.TypeName) {
			return nil, &xdm.Error{Code: lexicon.ErrXPTY0004, Message: "cannot cast " + a.TypeName + " to " + listType}
		}

		s := strings.Trim(source.StringVal(), lexicon.XMLWhitespace)
		if s == "" {
			return nil, castError(s, listType)
		}

		ec := getFnContext(ctx)
		limit := NodeLimit(ctx, fnMaxNodes(ec))
		result := make(xdm.ItemSlice, 0, min(limit, initialConstructorTokenCapacity))

		for token := range strings.FieldsFuncSeq(s, xmlchar.IsSpace) {
			if len(result) >= limit {
				return nil, ErrNodeSetLimit
			}

			if ec != nil {
				if err := ec.countOps(ctx, constructorTokenWork); err != nil {
					return nil, err
				}
			} else if err := Charge(ctx, constructorTokenWork); err != nil {
				return nil, err
			}

			if !tokenRe.MatchString(token) {
				return nil, castError(token, listType)
			}

			result = append(result, xdm.AtomicValue{TypeName: itemType, Value: strings.Clone(token)})
		}

		return result, nil
	}
}

func isBuiltinListType(target string) bool {
	return target == xdm.TypeENTITIES || target == xdm.TypeIDREFS || target == xdm.TypeNMTOKENS
}

// Builtin list casts and constructors use one bounded token/member builder.
func castToBuiltinList(ctx context.Context, ec *evalContext, value xdm.AtomicValue, target string) (xdm.Sequence, error) {
	constructor, _ := lookupConstructor(strings.TrimPrefix(target, lexicon.PrefixXS+":"))

	if ec != nil {
		ctx = withFnContext(ctx, ec)
	}

	return constructor.fn(ctx, []xdm.Sequence{xdm.SingleAtomic(value)})
}

func reGDay(s string) bool {
	return lexical.ValidateBuiltin(s, lexicon.TypeGDay, lexical.Version11) == nil
}

func reGMonth(s string) bool {
	return lexical.ValidateBuiltin(s, lexicon.TypeGMonth, lexical.Version11) == nil
}

func reGMonthDay(s string) bool {
	return lexical.ValidateBuiltin(s, lexicon.TypeGMonthDay, lexical.Version11) == nil
}

func reGYear(s string) bool {
	return lexical.ValidateBuiltin(s, lexicon.TypeGYear, lexical.Version11) == nil
}

func reGYearMonth(s string) bool {
	return lexical.ValidateBuiltin(s, lexicon.TypeGYearMonth, lexical.Version11) == nil
}

// validateGregorianValue performs additional validation beyond regex matching.
func validateGregorianValue(typeName, s string) bool {
	// Validate timezone if present
	if validateTimezoneInString(s) != nil {
		return false
	}

	switch typeName {
	case xdm.TypeGDay:
		// ---DD format: day must be 01-31
		day := extractGDayValue(s)
		return day >= minimumCalendarDay && day <= constructorMaximumDay
	case xdm.TypeGMonth:
		// --MM format: month must be 01-12
		month := extractGMonthValue(s)
		return month >= minimumCalendarMonth && month <= maximumCalendarMonth
	case xdm.TypeGMonthDay:
		// --MM-DD format: month 01-12, day valid for month
		month, day := extractGMonthDayValues(s)
		if month < minimumCalendarMonth || month > maximumCalendarMonth {
			return false
		}
		// Use a leap year for gMonthDay since no year is specified;
		// February allows up to 29 because gMonthDay must accommodate leap years.
		maxDay := daysInMonth(gregorianLeapReferenceYear, month) // year 4 is a leap year

		return day >= minimumCalendarDay && day <= maxDay
	case xdm.TypeGYear:
		// XSD 1.1: year 0000 is valid
		y := extractYearDigits(s)
		if !hasValidGregorianYearDigits(y) {
			return false
		}
	case xdm.TypeGYearMonth:
		// XSD 1.1: year 0000 is valid, validate month 01-12
		y := extractYearDigits(s)
		if !hasValidGregorianYearDigits(y) {
			return false
		}

		month := extractGYearMonthMonth(s)

		return month >= minimumCalendarMonth && month <= maximumCalendarMonth
	}

	return true
}

// extractGDayValue extracts the day from a ---DD[tz] string.
func extractGDayValue(s string) int {
	// format: ---DD...
	if len(s) < gregorianDayFieldEnd {
		return 0
	}

	d, err := strconv.Atoi(s[gregorianDayFieldStart:gregorianDayFieldEnd])
	if err != nil {
		return 0
	}

	return d
}

// extractGMonthValue extracts the month from a --MM[tz] string.
func extractGMonthValue(s string) int {
	// format: --MM...
	if len(s) < gregorianMonthFieldEnd {
		return 0
	}

	m, err := strconv.Atoi(s[gregorianMonthFieldStart:gregorianMonthFieldEnd])
	if err != nil {
		return 0
	}

	return m
}

// extractGMonthDayValues extracts month and day from a --MM-DD[tz] string.
func extractGMonthDayValues(s string) (int, int) {
	// format: --MM-DD...
	if len(s) < gregorianMonthDayFieldEnd {
		return 0, 0
	}

	m, err := strconv.Atoi(s[gregorianMonthFieldStart:gregorianMonthFieldEnd])
	if err != nil {
		return 0, 0
	}

	d, err := strconv.Atoi(s[gregorianMonthDayFieldStart:gregorianMonthDayFieldEnd])
	if err != nil {
		return 0, 0
	}

	return m, d
}

// extractGYearMonthMonth extracts the month from a [-]YYYY-MM[tz] string.
func extractGYearMonthMonth(s string) int {
	// Find the last '-' before any timezone
	// The month is right after the year portion: skip optional leading '-', then digits, then '-'
	work := strings.TrimPrefix(s, "-")

	i := 0
	for i < len(work) && work[i] >= '0' && work[i] <= '9' {
		i++
	}

	if i >= len(work) || work[i] != '-' {
		return 0
	}
	// work[i] == '-', month starts at i+1
	if i+gregorianYearMonthFieldEnd > len(work) {
		return 0
	}

	m, err := strconv.Atoi(work[i+1 : i+gregorianYearMonthFieldEnd])
	if err != nil {
		return 0
	}

	return m
}

func extractYearDigits(s string) string {
	y := strings.TrimPrefix(s, "-")
	for i, c := range y {
		if c == '-' || c == 'Z' || c == '+' {
			return y[:i]
		}
	}

	return y
}

func hasValidGregorianYearDigits(y string) bool {
	if len(y) < minimumYearDigits || len(y) > constructorMaximumYearDigits {
		return false
	}

	return len(y) == minimumYearDigits || y[0] != '0'
}

func atomizeConstructorArg(seq xdm.Sequence, typeName string) (xdm.AtomicValue, bool, error) {
	// Atomize the whole argument FIRST, then enforce singleton cardinality on
	// the atomized result. An argument may be an array that flattens to zero,
	// one, or many atomic values; cardinality must be judged on the atomized
	// count, not the raw sequence length. Per function-conversion semantics, an
	// item that cannot be atomized (a map/function → FOTY0013) must surface that
	// error even when it appears after the second atom, so we atomize to
	// completion, short-circuiting nowhere; XPTY0004 cardinality applies only
	// when atomization succeeds and yields more than one atom.
	var (
		first xdm.AtomicValue
		count int
	)

	err := atomizeStream(seq, func(av xdm.AtomicValue) (bool, error) {
		count++
		if count == constructorAtomCardinality {
			first = av
		}

		return true, nil
	})
	if err != nil {
		return xdm.AtomicValue{}, false, err
	}

	if count == 0 {
		return xdm.AtomicValue{}, true, nil
	}

	if count > constructorAtomCardinality {
		return xdm.AtomicValue{}, false, &xdm.Error{
			Code:    lexicon.ErrXPTY0004,
			Message: fmt.Sprintf("%s constructor requires a singleton argument", typeName),
		}
	}

	return first, false, nil
}

func fnXSError(_ context.Context, args []xdm.Sequence) (xdm.Sequence, error) {
	if xdm.SequenceLen(args[0]) == 0 {
		return nil, nil
	}

	return nil, &xdm.Error{
		Code:    errCodeFORG0001,
		Message: "xs:error always fails",
	}
}
