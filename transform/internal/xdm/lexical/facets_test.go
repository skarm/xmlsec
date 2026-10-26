package lexical_test

import (
	"testing"

	lexicalpkg "github.com/skarm/xmlsec/transform/internal/xdm/lexical"
)

func TestDatatypeFacetApplicability(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		kind                               string
		ordered, length, decimal, integral bool
	}{
		{"decimal", true, false, true, false},
		{"integer", true, false, true, true},
		{"unsignedLong", true, false, true, true},
		{"negativeInteger", true, false, true, true},
		{"float", true, false, false, false},
		{"double", true, false, false, false},
		{"duration", true, false, false, false},
		{"dayTimeDuration", true, false, false, false},
		{"yearMonthDuration", true, false, false, false},
		{"dateTime", true, false, false, false},
		{"dateTimeStamp", true, false, false, false},
		{"date", true, false, false, false},
		{"time", true, false, false, false},
		{"gYear", true, false, false, false},
		{"gMonth", true, false, false, false},
		{"gDay", true, false, false, false},
		{"gYearMonth", true, false, false, false},
		{"gMonthDay", true, false, false, false},
		{"boolean", false, false, false, false},
		{"string", false, true, false, false},
		{"normalizedString", false, true, false, false},
		{"token", false, true, false, false},
		{"QName", false, true, false, false},
		{"NOTATION", false, true, false, false},
		{"base64Binary", false, true, false, false},
		{"hexBinary", false, true, false, false},
		{"NMTOKENS", false, true, false, false},
		{"IDREFS", false, true, false, false},
		{"ENTITIES", false, true, false, false},
		{"unknown", false, false, false, false},
	} {
		t.Run(test.kind, func(t *testing.T) {
			t.Parallel()

			if got := lexicalpkg.Orderable(test.kind); got != test.ordered {
				t.Fatalf("Orderable = %v; want %v", got, test.ordered)
			}
			if got := lexicalpkg.LengthApplicable(test.kind); got != test.length {
				t.Fatalf("LengthApplicable = %v; want %v", got, test.length)
			}
			if got := lexicalpkg.IsDecimalFamily(test.kind); got != test.decimal {
				t.Fatalf("IsDecimalFamily = %v; want %v", got, test.decimal)
			}
			if got := lexicalpkg.IsIntegerFamily(test.kind); got != test.integral {
				t.Fatalf("IsIntegerFamily = %v; want %v", got, test.integral)
			}
		})
	}
}

func TestDecimalDigitFacetsKeepFractionalLeadingZeros(t *testing.T) {
	t.Parallel()

	// XSD 1.1 §4.3.11 constrains both the coefficient and decimal scale.
	for _, test := range []struct {
		value           string
		total, fraction int
	}{
		{"0.02300", 3, 3},
		{"-0.0000100", 5, 5},
		{"+100.000", 3, 0},
		{"-.000", 1, 0},
		{"12345678901234567890.0001", 24, 4},
	} {
		if got := lexicalpkg.CountTotalDigits(test.value); got != test.total {
			t.Fatalf("totalDigits(%q)=%d; want %d", test.value, got, test.total)
		}
		if got := lexicalpkg.CountFractionDigits(test.value); got != test.fraction {
			t.Fatalf("fractionDigits(%q)=%d; want %d", test.value, got, test.fraction)
		}
	}
}

func TestFloatFacetBoundsDistinguishNaNAndValueComparison(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		left, right, kind string
		want              int
		valid             bool
	}{
		{"NaN", "NaN", "double", 0, true},
		{"NaN", "INF", "float", 1, true},
		{"-INF", "NaN", "double", -1, true},
		{"1", "2", "double", -1, true},
		{"16777216", "16777217", "float", 0, true},
		{"16777216", "16777217", "double", -1, true},
		{"1", "NaN", "decimal", 0, false},
		{"nan", "1", "double", 0, false},
		{"1", "+NaN", "float", 0, false},
	} {
		if got, valid := lexicalpkg.CompareFloatFacetBound(test.left, test.right, test.kind); valid != test.valid || valid && got != test.want {
			t.Fatalf("facet bounds %q/%q/%s = %d,%v; want %d,%v", test.left, test.right, test.kind, got, valid, test.want, test.valid)
		}
	}
	for _, value := range []string{"NaN", "+NaN", "-NaN", "nan", "INF", "1"} {
		if got := lexicalpkg.IsFloatNaN(value); got != (value == "NaN") {
			t.Fatalf("IsFloatNaN(%q) = %v", value, got)
		}
	}
}
