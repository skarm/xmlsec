package xpath //nolint:testpackage // Exercises date and duration arithmetic on both evaluation paths.

import (
	"errors"
	"testing"

	"github.com/skarm/xmlsec/transform/internal/xdm"
)

func TestEvalDateTimeArithmeticASTAndVM(t *testing.T) {
	t.Parallel()
	assertFunctionResults(t, []functionResultCase{
		{"day addition crosses leap day", `(xs:date('2024-02-28Z') + xs:dayTimeDuration('P2D'),xs:date('2024-03-01Z') - xs:dayTimeDuration('P1D'))`, "2024-03-01Z|2024-02-29Z"},
		{"date time subtraction normalizes zones and preserves fractions", `xs:dateTime('2024-03-01T01:00:00.250+02:00') - xs:dateTime('2024-02-29T22:59:59.750Z')`, "PT0.5S"},
		{"time addition wraps at midnight", `xs:time('23:59:50Z') + xs:dayTimeDuration('PT20S')`, "00:00:10Z"},
		{"scaling year-month duration rounds ties", `(xs:yearMonthDuration('P3M') * 0.5, xs:yearMonthDuration('P3M') * -0.5, xs:yearMonthDuration('P1Y') div 4)`, "P2M|-P1M|P3M"},
		{"duration scaling preserves exact decimal", `(xs:dayTimeDuration('PT0.6S') * 1.5,xs:dayTimeDuration('PT1.25S') div 2)`, "PT0.9S|PT0.625S"},
		{"duration division uses the same unit", `(xs:dayTimeDuration('PT1.5S') div xs:dayTimeDuration('PT0.5S'),xs:yearMonthDuration('P1Y') div xs:yearMonthDuration('P8M'))`, "3|1.5"},
	})
}

func TestEvalDateTimeArithmeticErrorsASTAndVM(t *testing.T) {
	t.Parallel()
	for _, test := range []struct{ name, expression, code string }{
		{"empty divisor duration", `xs:yearMonthDuration('P1M') div xs:yearMonthDuration('P0M')`, "FOAR0001"},
	} {
		for _, mode := range []string{runtimeASTMode, "VM"} {
			t.Run(test.name+"/"+mode, func(t *testing.T) {
				t.Parallel()
				seq, err := evaluateFunctionExpression(t, test.expression, mode)
				if xdm.SequenceLen(seq) != 0 || !errors.Is(err, &xdm.Error{Code: test.code}) {
					t.Fatalf("%s = %v, %v; want no result and %s", test.expression, seq, err, test.code)
				}
			})
		}
	}
}
