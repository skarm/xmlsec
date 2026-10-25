// Derived from lestrrat-go/helium at 7362c0a70122a757780f4d0b545a9b370dead6ab.
// Copyright (c) 2015 lestrrat. MIT License; see licenses/MIT-helium.txt at the repository root.

package lexical

import (
	"strings"

	"github.com/skarm/xmlsec/internal/lexicon"
)

// Orderable reports whether range facets apply to builtinLocal's value space.
// Compare also provides deterministic ordering for some unordered types for
// equality checks; that ordering must not be used to enforce range facets.
func Orderable(builtinLocal string) bool {
	if numericComparableTypes(builtinLocal) {
		return true
	}

	switch builtinLocal {
	case lexicon.TypeFloat, lexicon.TypeDouble,
		lexicon.TypeDateTime, lexicon.TypeDateTimeStamp, lexicon.TypeDate, lexicon.TypeTime,
		lexicon.TypeDuration, lexicon.TypeDayTimeDuration, lexicon.TypeYearMonthDuration,
		lexicon.TypeGYear, lexicon.TypeGYearMonth, lexicon.TypeGMonth, lexicon.TypeGDay, lexicon.TypeGMonthDay:
		return true
	}

	return false
}

// LengthApplicable reports whether length facets may be declared for
// builtinLocal. Applicability does not imply that a facet constrains a value:
// XSD leaves the length of QName and NOTATION undefined.
func LengthApplicable(builtinLocal string) bool {
	ok := lengthApplicableTypes(builtinLocal)
	return ok
}

// lengthApplicableTypes lists atomic types with applicable length facets.
// String lengths count characters; binary lengths count octets.
func lengthApplicableTypes(key string) bool {
	switch key {
	case lexicon.TypeString, lexicon.TypeNormalizedString, lexicon.TypeToken, "language", "Name", "NCName", "ID", lexicon.TypeIDREF, lexicon.TypeIDREFS, "ENTITY", lexicon.TypeENTITIES, "NMTOKEN", lexicon.TypeNMTokens, lexicon.TypeAnyURI, lexicon.TypeQName, lexicon.TypeNotation, lexicon.TypeHexBinary, lexicon.TypeBase64Binary:
		return true
	}

	return false
}

// IsDecimalFamily reports whether builtinLocal is in the xs:decimal family
// (xs:decimal and its integer derivations). These are the ONLY types on which the
// digit facets (totalDigits, fractionDigits) are applicable; the facets are
// meaningless on float/double (no decimal digit notion in their value space) and
// on every non-numeric primitive.
func IsDecimalFamily(builtinLocal string) bool {
	ok := numericComparableTypes(builtinLocal)
	return ok
}

// IsIntegerFamily reports whether builtinLocal is xs:integer or one of its
// derivations (long, int, short, byte, nonPositiveInteger, negativeInteger,
// nonNegativeInteger, unsignedLong/Int/Short/Byte, positiveInteger). Every type
// in this family carries the xs:integer built-in fixed facet fractionDigits=0, so
// a restriction may not set fractionDigits to any non-zero value. xs:decimal
// itself is excluded (it does not fix fractionDigits).
func IsIntegerFamily(builtinLocal string) bool {
	return IsDecimalFamily(builtinLocal) && builtinLocal != lexicon.TypeDecimal
}

// CountTotalDigits counts the total number of significant digits in a decimal
// value. Per the XSD datatype spec: strip the sign, then count digits in the
// numeral excluding leading zeros before the integer part and trailing zeros
// after the fraction. Examples: "0.123" → 3, "0.023" → 3, "123" → 3, "12.3" → 3,
// "0.0" → 1.
func CountTotalDigits(value string) int {
	// Strip sign.
	s := value
	if len(s) > 0 && (s[0] == '+' || s[0] == '-') {
		s = s[1:]
	}

	dotIdx := strings.Index(s, ".")
	if dotIdx < 0 {
		// No decimal point — count digits in integer, stripping leading zeros.
		s = strings.TrimLeft(s, "0")
		if s == "" {
			return 1
		}

		return len(s)
	}

	// Has decimal point. Integer part = s[:dotIdx], fraction part = s[dotIdx+1:]
	intPart := strings.TrimLeft(s[:dotIdx], "0")
	fracPart := strings.TrimRight(s[dotIdx+1:], "0")

	total := len(intPart) + len(fracPart)
	if total == 0 {
		return 1 // "0.0" has 1 digit
	}

	return total
}

// CountFractionDigits counts the number of significant digits after the decimal
// point. The fractionDigits facet constrains the value, not the lexical form, so
// trailing zeros are not significant: "1.20" → 1, "2.00" → 0, "1.0" → 0. If there
// is no decimal point, it returns 0.
func CountFractionDigits(value string) int {
	s := value
	if len(s) > 0 && (s[0] == '+' || s[0] == '-') {
		s = s[1:]
	}

	_, frac, found := strings.Cut(s, ".")
	if !found {
		return 0
	}

	return len(strings.TrimRight(frac, "0"))
}
