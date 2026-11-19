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
		{"overflow in the scaled primitive type", `(format-number(xs:float('3.4e38'),'0%'),format-number(xs:float('-3.4e38'),'0‰;(0‰)'),format-number(xs:double('1e308'),'0%'),format-number(xs:float('INF'),'0%'))`, "Infinity%|(Infinity‰)|Infinity%|Infinity%"},
		{"finite typed floats keep rounding", `(format-number(xs:float('0.125'),'0.0%'),format-number(xs:double('1.015'),'0.00'))`, "12.5%|1.02"},
	})
}

func TestFnFormatNumberErrorsASTAndVM(t *testing.T) {
	t.Parallel()
	for _, test := range []struct{ name, expression, code string }{
		{"invalid decimal picture", `format-number(1,'000.##0')`, "FODF1310"},
		{"invalid unused negative picture", `format-number(1,'0;0.0.0')`, "FODF1310"},
		{"invalid unused positive picture", `format-number(-1,'0.0.0;0')`, "FODF1310"},
		{"invalid picture for NaN", `format-number(xs:double('NaN'),'plain text')`, "FODF1310"},
		{"invalid unused picture for infinity", `format-number(xs:double('INF'),'0;0.0.0')`, "FODF1310"},
		{"empty negative picture", `format-number(1,'0;')`, "FODF1310"},
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
