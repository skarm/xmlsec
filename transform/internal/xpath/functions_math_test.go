package xpath //nolint:testpackage // Exercises math functions on both evaluation paths.

import (
	"errors"
	"testing"

	"github.com/skarm/xmlsec/transform/internal/xdm"
)

func TestMathFunctionsASTAndVM(t *testing.T) {
	t.Parallel()
	assertFunctionResults(t, []functionResultCase{
		{"exponents and logs", `(math:exp(0),math:exp10(2),math:log(1),math:log10(1000))`, "1|100|0|3"},
		{"integer and fractional exponents", `(math:pow(-2,3),math:pow(-2,-2),math:pow(4,0.5),math:pow(-1,17),math:pow(0,0))`, "-8|0.25|2|-1|1"},
		{"trigonometric identities", `(math:sin(0),math:cos(0),math:tan(0),math:asin(0),math:acos(1),math:atan(0),math:atan2(0,1),abs(math:pi()-3.141592653589793) lt 0.000000000001)`, "0|1|0|0|0|0|0|true"},
		{"square root, NaN and empty propagation", `(math:sqrt(9),math:sqrt(-1),math:log(0),count(math:sqrt(())),count(math:pow((),2)))`, "3|NaN|-INF|0|0"},
	})
}

func TestFnMathPowErrorsASTAndVM(t *testing.T) {
	t.Parallel()
	for _, test := range []struct{ name, expression, code string }{
		{"math exponent required even for empty base", `math:pow((),())`, "XPTY0004"},
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
