package xpath //nolint:testpackage // Exercises general and value comparisons through both evaluation paths.

import (
	"errors"
	"testing"
	"time"

	"github.com/skarm/xmlsec/transform/internal/xdm"
)

func TestGeneralComparisonWithRangeBoundsASTAndVM(t *testing.T) {
	t.Parallel()

	assertFunctionResults(t, []functionResultCase{
		{"inclusive_endpoints", `(2 = (2 to 4), 4 = (2 to 4), 1 = (2 to 4), 5 = (2 to 4))`, "true|true|false|false"},
		{"existential_inequality", `(2 != (2 to 4), (2 to 2) != 2, 2 != (3 to 3), 2 != (4 to 2))`, "true|false|true|false"},
		{"range_on_right", `(4 < (2 to 4), 4 <= (2 to 4), 2 > (2 to 4), 2 >= (2 to 4), 3 < (2 to 4), 3 > (2 to 4))`, "false|true|false|true|true|true"},
		{"range_on_left", `((2 to 4) < 2, (2 to 4) <= 2, (2 to 4) > 4, (2 to 4) >= 4, (2 to 4) < 3, (2 to 4) > 3)`, "false|true|false|true|true|true"},
		{"empty_operands", `(() = (2 to 4), 3 = (() to 4), (2 to ()) < 3)`, "false|false|false"},
		{"decimal_and_sequence_operands", `(2.5 < (2 to 3), (0,5) = (2 to 4), (0,3) = (2 to 4), parse-xml('<n>03</n>')/n = (2 to 4))`, "true|false|true|true"},
		{"large_integer_endpoints", `(9223372036854775809 = (9223372036854775808 to 9223372036854775810), 9223372036854775811 = (9223372036854775808 to 9223372036854775810), 9223372036854775808 != (9223372036854775808 to 9223372036854775808))`, "true|false|false"},
		{"large_integer_range_on_right", `(9223372036854775810 < (9223372036854775808 to 9223372036854775810), 9223372036854775810 <= (9223372036854775808 to 9223372036854775810), 9223372036854775808 > (9223372036854775808 to 9223372036854775810), 9223372036854775808 >= (9223372036854775808 to 9223372036854775810))`, "false|true|false|true"},
		{"large_integer_range_on_left", `((9223372036854775808 to 9223372036854775810) < 9223372036854775808, (9223372036854775808 to 9223372036854775810) <= 9223372036854775808, (9223372036854775808 to 9223372036854775810) > 9223372036854775810, (9223372036854775808 to 9223372036854775810) >= 9223372036854775810)`, "false|true|false|true"},
	})
}

func TestGeneralCompareStopsBeforeUnusedOperands(t *testing.T) {
	t.Parallel()

	one := xdm.AtomicValue{TypeName: xdm.TypeInteger, Value: int64(1)}
	two := xdm.AtomicValue{TypeName: xdm.TypeInteger, Value: int64(2)}
	invalid := xdm.NewMap(nil)
	for _, tc := range []struct {
		name        string
		left, right xdm.Sequence
		want        bool
		wantErr     error
	}{
		{"matching_pair_precedes_invalid_items", xdm.ItemSlice{one, invalid}, xdm.ItemSlice{one, invalid}, true, nil},
		{"right_atomization_error_is_returned", xdm.ItemSlice{two}, xdm.ItemSlice{one, invalid}, false, &xdm.Error{Code: "FOTY0013"}},
		{"left_atomization_error_is_returned", xdm.ItemSlice{two, invalid}, xdm.ItemSlice{one}, false, &xdm.Error{Code: "FOTY0013"}},
		{"empty_left_operand_does_not_atomize_right", nil, xdm.ItemSlice{invalid}, false, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, err := GeneralCompare(TokenEquals, tc.left, tc.right)
			if got != tc.want || !errors.Is(err, tc.wantErr) {
				t.Errorf("GeneralCompare = (%t, %v), want (%t, %v)", got, err, tc.want, tc.wantErr)
			}
		})
	}
}

func TestGregorianToReferenceDateTime(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name     string
		value    xdm.AtomicValue
		year     int
		month    time.Month
		day      int
		offset   int
		explicit bool
	}{
		{"month_day_on_leap_reference_year", xdm.AtomicValue{TypeName: xdm.TypeGMonthDay, Value: "--02-29+05:30"}, 1972, time.February, 29, 19800, true},
		{"month_without_timezone", xdm.AtomicValue{TypeName: xdm.TypeGMonth, Value: "--03"}, 1972, time.March, 1, 0, false},
		{"day_with_negative_offset", xdm.AtomicValue{TypeName: xdm.TypeGDay, Value: "---17-04:00"}, 1972, time.December, 17, -14400, true},
		{"year_with_explicit_utc", xdm.AtomicValue{TypeName: xdm.TypeGYear, Value: "2024Z"}, 2024, time.January, 1, 0, true},
		{"year_month", xdm.AtomicValue{TypeName: xdm.TypeGYearMonth, Value: "2024-09"}, 2024, time.September, 1, 0, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, ok := GregorianToReferenceDateTime(tc.value)
			year, month, day := got.Date()
			_, offset := got.Zone()
			if !ok || year != tc.year || month != tc.month || day != tc.day || offset != tc.offset || xdm.HasTimezone(got) != tc.explicit || got.Hour() != 0 || got.Minute() != 0 || got.Second() != 0 {
				t.Errorf("GregorianToReferenceDateTime(%v) = (%v, %t) with explicit timezone %t, want date %04d-%02d-%02d at midnight and offset %d (explicit=%t)", tc.value, got, ok, xdm.HasTimezone(got), tc.year, tc.month, tc.day, tc.offset, tc.explicit)
			}
		})
	}

	for _, value := range []xdm.AtomicValue{
		{TypeName: xdm.TypeString, Value: "2024Z"},
		{TypeName: xdm.TypeGYear, Value: int64(2024)},
		{TypeName: xdm.TypeGMonthDay, Value: "--02-30Z"},
	} {
		if got, ok := GregorianToReferenceDateTime(value); ok || !got.IsZero() {
			t.Errorf("GregorianToReferenceDateTime(%v) = (%v, %t), want no date", value, got, ok)
		}
	}
}

func TestComparisonSemanticsASTAndVM(t *testing.T) {
	t.Parallel()
	assertFunctionResults(t, []functionResultCase{
		{"general_comparisons_are_existential", `((1,2)=(2,3),(1,2)!=(2,3),not((2,2)!=(2,2)),not(()=(2,3)),empty(() eq 1))`, "true|true|true|true|true"},
		{"general_comparison_atomizes_array_members", `([(),(1,2),[3]] = 3,[(),(1,2),[3]] > 3,[(),(1,2),[3]] < 2)`, "true|false|true"},
		{"untyped_comparison_is_contextual", `let $n := parse-xml('<r>02</r>')/r return ($n = 2,$n eq '02',$n = '2',$n eq '2')`, "true|true|false|false"},
		{"precise_comparison_keeps_big_integer_and_decimal", `(9223372036854775808 gt 9223372036854775807,9223372036854775808.01 gt 9223372036854775808,xs:double('NaN') ne xs:double('NaN'),xs:double('-0') eq 0)`, "true|true|true|true"},
		{"timezones_participate_in_comparison", `(xs:dateTime('2024-01-02T00:00:00+02:00') eq xs:dateTime('2024-01-01T22:00:00Z'),xs:date('2024-01-02+02:00') lt xs:date('2024-01-02Z'),xs:time('12:30:00+02:00') eq xs:time('10:30:00Z'))`, "true|true|true"},
		{"partial_dates_normalize_calendar_fields", `(xs:gYear('2024Z') eq xs:gYear('2024+00:00'),xs:gMonth('--02Z') eq xs:gMonth('--03Z'),xs:gMonthDay('--02-29Z') ne xs:gMonthDay('--02-28Z'),xs:gYearMonth('2024-02Z') eq xs:gYearMonth('2024-02+00:00'),xs:gDay('---01Z') ne xs:gDay('---02Z'))`, "true|false|true|true|true"},
		{"duration_comparisons_use_months_and_seconds", `(xs:yearMonthDuration('P1Y') eq xs:yearMonthDuration('P12M'),xs:dayTimeDuration('PT90M') gt xs:dayTimeDuration('PT1H'),xs:duration('P1M') eq xs:duration('P30D'),xs:duration('PT1H') eq xs:duration('PT60M'))`, "true|true|false|true"},
		{"equality_uses_bytes_and_expanded_qname", `(xs:hexBinary('00fF') eq xs:hexBinary('00FF'),xs:base64Binary('AP8=') ne xs:base64Binary('AAE='),QName('urn:one','p:n') eq QName('urn:one','q:n'),QName('urn:one','p:n') ne QName('urn:two','p:n'))`, "true|true|true|true"},
	})
}

func TestComparisonTypeErrorsASTAndVM(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct{ name, expression, code string }{
		{"untyped_value_is_not_a_number", `parse-xml('<r>02</r>')/r eq 2`, "XPTY0004"},
		{"general_comparison_converts_untyped_number", `parse-xml('<r>text</r>')/r = 2`, "FORG0001"},
		{"qnames_have_no_order", `QName('urn:one','p:a') lt QName('urn:one','p:b')`, "XPTY0004"},
		{"generic_durations_have_no_order", `xs:duration('P1M') lt xs:duration('P2M')`, "XPTY0004"},
		{"value_comparison_requires_singletons", `(1,2) eq 1`, "XPTY0004"},
	} {
		for _, mode := range []string{runtimeASTMode, "VM"} {
			t.Run(tc.name+"/"+mode, func(t *testing.T) {
				t.Parallel()
				seq, err := evaluateFunctionExpression(t, tc.expression, mode)
				if xdm.SequenceLen(seq) != 0 || !errors.Is(err, &xdm.Error{Code: tc.code}) {
					t.Errorf("%s = %v, %v, want no result and %s", tc.expression, seq, err, tc.code)
				}
			})
		}
	}
}
