package xpath //nolint:testpackage // Exercises picture formatting on both evaluation paths.

import (
	"errors"
	"testing"

	"github.com/skarm/xmlsec/transform/internal/xdm"
)

func TestFnFormatNumberPicturesASTAndVM(t *testing.T) {
	t.Parallel()
	assertFunctionResults(t, []functionResultCase{
		{"decimal grouping and rounding", `(format-number(12345.675,'#,##0.00'),format-number(0.125,'0.0%'),format-number(-12.5,'0.00;(0.00)'))`, "12,345.68|12.5%|(12.50)"},
		{"scaled exponent picture", `(format-number(1234.56,'0.00e00'),format-number(0.01234,'0.0e0'))`, "1.23e03|1.2e-2"},
		{"non-finite decimal formatting", `(format-number(xs:double('NaN'),'0.00'),format-number(xs:double('INF'),'0.00'),format-number(xs:double('-INF'),'0.00'))`, "NaN|Infinity|-Infinity"},
	})
}

func TestFnFormatNumberErrorsASTAndVM(t *testing.T) {
	t.Parallel()
	for _, test := range []struct{ name, expression, code string }{
		{"invalid decimal picture", `format-number(1,'000.##0')`, "FODF1310"},
		{"unknown decimal format", `format-number(1,'0','missing')`, "FODF1280"},
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
