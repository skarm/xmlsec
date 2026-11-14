package xpath //nolint:testpackage // Exercises general and value comparisons through both evaluation paths.

import (
	"errors"
	"testing"

	"github.com/skarm/xmlsec/transform/internal/xdm"
)

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
