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

	"github.com/skarm/xmlsec/internal/xmlchar"
	"github.com/skarm/xmlsec/transform/internal/xdm"
	valuepkg "github.com/skarm/xmlsec/transform/internal/xdm/lexical"
	"github.com/skarm/xmlsec/transform/internal/xdm/lexicon"
)

func lookupConstructor(requestedName string) (*builtinFunc, bool) {
	// Base XSD types — delegate to CastAtomic
	for _, entry := range []struct {
		name       string
		targetType string
	}{
		{nameString, xdm.TypeString},
		{fnNameBoolean, xdm.TypeBoolean},
		{"decimal", xdm.TypeDecimal},
		{"double", xdm.TypeDouble},
		{"float", xdm.TypeFloat},
		{"integer", xdm.TypeInteger},
		{nameDate, xdm.TypeDate},
		{nameDateTime, xdm.TypeDateTime},
		{nameTime, xdm.TypeTime},
		{nameDuration, xdm.TypeDuration},
		{"dayTimeDuration", xdm.TypeDayTimeDuration},
		{"yearMonthDuration", xdm.TypeYearMonthDuration},
		{"anyURI", xdm.TypeAnyURI},
		{nameBase64Binary, xdm.TypeBase64Binary},
		{nameHexBinary, xdm.TypeHexBinary},
		{"untypedAtomic", xdm.TypeUntypedAtomic},
	} {
		if requestedName == entry.name {
			return &builtinFunc{name: requestedName, min: 1, max: 1, fn: makeXSConstructor(entry.targetType)}, true
		}
	}

	// xs:QName constructor needs namespace context to resolve prefixes
	if requestedName == nameQName {
		return &builtinFunc{name: requestedName, min: 1, max: 1, fn: makeXSQNameConstructor()}, true
	}

	// Derived integer types — cast to integer, then validate range
	for _, entry := range []struct {
		name     string
		typeName string
		min      int64
		max      int64
	}{
		{"long", xdm.TypeLong, math.MinInt64, math.MaxInt64},
		{"int", xdm.TypeInt, -2147483648, 2147483647},
		{"short", xdm.TypeShort, -32768, 32767},
		{"byte", xdm.TypeByte, -128, 127},
		{"unsignedInt", xdm.TypeUnsignedInt, 0, 4294967295},
		{"unsignedShort", xdm.TypeUnsignedShort, 0, 65535},
		{"unsignedByte", xdm.TypeUnsignedByte, 0, 255},
	} {
		if requestedName == entry.name {
			return &builtinFunc{name: requestedName, min: 1, max: 1, fn: makeXSIntegerRange(entry.typeName, entry.min, entry.max)}, true
		}
	}
	// Unbounded integer subtypes need big.Int constructor (no fixed max/min)
	if requestedName == "nonNegativeInteger" {
		return &builtinFunc{name: requestedName, min: 1, max: 1, fn: makeXSIntegerRangeBig(xdm.TypeNonNegativeInteger, big.NewInt(0), nil)}, true
	}

	if requestedName == "nonPositiveInteger" {
		return &builtinFunc{name: requestedName, min: 1, max: 1, fn: makeXSIntegerRangeBig(xdm.TypeNonPositiveInteger, nil, big.NewInt(0))}, true
	}

	if requestedName == "positiveInteger" {
		return &builtinFunc{name: requestedName, min: 1, max: 1, fn: makeXSIntegerRangeBig(xdm.TypePositiveInteger, big.NewInt(1), nil)}, true
	}

	if requestedName == "negativeInteger" {
		return &builtinFunc{name: requestedName, min: 1, max: 1, fn: makeXSIntegerRangeBig(xdm.TypeNegativeInteger, nil, big.NewInt(-1))}, true
	}

	// xs:unsignedLong needs big.Int max since MaxUint64 exceeds int64
	if requestedName == "unsignedLong" {
		return &builtinFunc{name: requestedName, min: 1, max: 1, fn: makeXSIntegerRangeBig(xdm.TypeUnsignedLong, big.NewInt(0), new(big.Int).SetUint64(math.MaxUint64))}, true
	}

	// Derived string types — cast to string, validate, store with derived type name
	for _, entry := range []struct {
		name     string
		typeName string
		re       lexicalCheck // nil = no validation, just string cast
	}{
		{"normalizedString", xdm.TypeNormalizedString, nil},
		{"token", xdm.TypeToken, nil},
		{"language", xdm.TypeLanguage, reLang},
		{nameName, xdm.TypeName, reName},
		{"NCName", xdm.TypeNCName, reNCName},
		{"NMTOKEN", xdm.TypeNMTOKEN, reNMTOKEN},
		{"ENTITY", xdm.TypeENTITY, reNCName},
		{"ID", xdm.TypeID, reNCName},
		{"IDREF", xdm.TypeIDREF, reNCName},
	} {
		if requestedName == entry.name {
			return &builtinFunc{name: requestedName, min: 1, max: 1, fn: makeXSStringRestriction(entry.typeName, entry.re)}, true
		}
	}

	// List types — split by whitespace, produce sequence of item type values
	if requestedName == nameNMTOKENS {
		return &builtinFunc{name: requestedName, min: 1, max: 1, fn: makeXSTokenList(xdm.TypeNMTOKENS, xdm.TypeNMTOKEN, reNMTOKEN)}, true
	}

	if requestedName == nameIDREFS {
		return &builtinFunc{name: requestedName, min: 1, max: 1, fn: makeXSTokenList(xdm.TypeIDREFS, xdm.TypeIDREF, reNCName)}, true
	}

	if requestedName == nameENTITIES {
		return &builtinFunc{name: requestedName, min: 1, max: 1, fn: makeXSTokenList(xdm.TypeENTITIES, xdm.TypeENTITY, reNCName)}, true
	}

	// Gregorian date part types. CastAtomic/CastFromString perform the
	// per-type lexical validation, so these share the generic constructor.
	for _, entry := range []struct {
		name     string
		typeName string
	}{
		{nameGDay, xdm.TypeGDay},
		{nameGMonth, xdm.TypeGMonth},
		{nameGMonthDay, xdm.TypeGMonthDay},
		{nameGYear, xdm.TypeGYear},
		{nameGYearMonth, xdm.TypeGYearMonth},
	} {
		if requestedName == entry.name {
			return &builtinFunc{name: requestedName, min: 1, max: 1, fn: makeXSConstructor(entry.typeName)}, true
		}
	}

	// xs:dateTimeStamp — dateTime with required timezone. CastAtomic enforces
	// the mandatory-timezone rule, so the generic constructor suffices.
	if requestedName == "dateTimeStamp" {
		return &builtinFunc{name: requestedName, min: 1, max: 1, fn: makeXSConstructor(xdm.TypeDateTimeStamp)}, true
	}

	// xs:error — always raises an error (used for type checking tests)
	if requestedName == nameError {
		return &builtinFunc{name: requestedName, min: 1, max: 1, fn: fnXSError}, true
	}

	// xs:numeric — cast to double (xs:numeric is an abstract union type)
	if requestedName == "numeric" {
		return &builtinFunc{name: requestedName, min: 1, max: 1, fn: makeXSConstructor(xdm.TypeDouble)}, true
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

		result, err := CastAtomicContext(ctx, a, targetType)
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
	return valuepkg.ValidateBuiltin(s, "NMTOKEN", valuepkg.Version11) == nil
}
func reLang(s string) bool { return valuepkg.ValidLanguage(s) }

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

		s, err := atomicToString(a)
		if err != nil {
			return nil, err
		}

		s = strings.Trim(s, " \t\r\n")
		if s == "" {
			return nil, &xdm.Error{
				Code:    errCodeFORG0001,
				Message: fmt.Sprintf("cannot cast empty string to %s", listType),
			}
		}

		tokens := splitXMLWhitespace(s)

		result := make(xdm.ItemSlice, len(tokens))
		for i, tok := range tokens {
			if !tokenRe.MatchString(tok) {
				return nil, &xdm.Error{
					Code:    errCodeFORG0001,
					Message: fmt.Sprintf("invalid token %q in %s", tok, listType),
				}
			}

			result[i] = xdm.AtomicValue{TypeName: itemType, Value: strings.Clone(tok)}
		}

		return result, nil
	}
}

func reGDay(s string) bool { return valuepkg.ValidateBuiltin(s, nameGDay, valuepkg.Version11) == nil }

func reGMonth(s string) bool {
	return valuepkg.ValidateBuiltin(s, nameGMonth, valuepkg.Version11) == nil
}

func reGMonthDay(s string) bool {
	return valuepkg.ValidateBuiltin(s, nameGMonthDay, valuepkg.Version11) == nil
}

func reGYear(s string) bool { return valuepkg.ValidateBuiltin(s, nameGYear, valuepkg.Version11) == nil }

func reGYearMonth(s string) bool {
	return valuepkg.ValidateBuiltin(s, nameGYearMonth, valuepkg.Version11) == nil
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
		return day >= 1 && day <= 31
	case xdm.TypeGMonth:
		// --MM format: month must be 01-12
		month := extractGMonthValue(s)
		return month >= 1 && month <= 12
	case xdm.TypeGMonthDay:
		// --MM-DD format: month 01-12, day valid for month
		month, day := extractGMonthDayValues(s)
		if month < 1 || month > 12 {
			return false
		}
		// Use a leap year for gMonthDay since no year is specified;
		// February allows up to 29 because gMonthDay must accommodate leap years.
		maxDay := daysInMonth(4, month) // year 4 is a leap year

		return day >= 1 && day <= maxDay
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

		return month >= 1 && month <= 12
	}

	return true
}

// extractGDayValue extracts the day from a ---DD[tz] string.
func extractGDayValue(s string) int {
	// format: ---DD...
	if len(s) < 5 {
		return 0
	}

	d, err := strconv.Atoi(s[3:5])
	if err != nil {
		return 0
	}

	return d
}

// extractGMonthValue extracts the month from a --MM[tz] string.
func extractGMonthValue(s string) int {
	// format: --MM...
	if len(s) < 4 {
		return 0
	}

	m, err := strconv.Atoi(s[2:4])
	if err != nil {
		return 0
	}

	return m
}

// extractGMonthDayValues extracts month and day from a --MM-DD[tz] string.
func extractGMonthDayValues(s string) (int, int) {
	// format: --MM-DD...
	if len(s) < 7 {
		return 0, 0
	}

	m, err := strconv.Atoi(s[2:4])
	if err != nil {
		return 0, 0
	}

	d, err := strconv.Atoi(s[5:7])
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
	if i+3 > len(work) {
		return 0
	}

	m, err := strconv.Atoi(work[i+1 : i+3])
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
	if len(y) < 4 || len(y) > 9 {
		return false
	}

	return len(y) == 4 || y[0] != '0'
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
		if count == 1 {
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

	if count > 1 {
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
