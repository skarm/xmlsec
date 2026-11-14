package xpath //nolint:testpackage // Checks numeric conversion on the AST and VM.

import (
	"errors"
	"math"
	"testing"

	"github.com/skarm/xmlsec/transform/internal/xdm"
)

func TestFnNumber(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name, query string
		want        float64
		code        string
	}{
		{"absent_context", `number()`, 0, "XPDY0002"},
		{"empty_sequence", `number(())`, math.NaN(), ""},
		{"invalid_lexical_number", `number('two')`, math.NaN(), ""},
		{"boolean_conversion", `number(true())`, 1, ""},
		{"node_context", `parse-xml('<n> 12.5 </n>')/n ! number()`, 12.5, ""},
		{"explicit_attribute", `number(parse-xml('<n x=" 2.5 "/>')/n/@x)`, 2.5, ""},
		{"infinity", `number('INF')`, math.Inf(1), ""},
		{"cannot_atomize_a_map", `number(map{})`, 0, "FOTY0013"},
	} {
		for _, mode := range []string{runtimeASTMode, "VM"} {
			t.Run(tc.name+"/"+mode, func(t *testing.T) {
				t.Parallel()
				seq, err := evaluateFunctionExpression(t, tc.query, mode)
				if tc.code != "" {
					if xdm.SequenceLen(seq) != 0 || !errors.Is(err, &xdm.Error{Code: tc.code}) {
						t.Fatalf("%s returned %v, %v; want no result and %s", tc.query, seq, err, tc.code)
					}
					return
				}
				if err != nil || xdm.SequenceLen(seq) != 1 {
					t.Fatalf("%s returned %v, %v; want one xs:double", tc.query, seq, err)
				}
				item, ok := seq.Get(0).(xdm.AtomicValue)
				if !ok || item.TypeName != xdm.TypeDouble {
					t.Fatalf("%s returned %v; want xs:double", tc.query, seq.Get(0))
				}
				got := item.DoubleVal()
				if got != tc.want && !(math.IsNaN(got) && math.IsNaN(tc.want)) {
					t.Errorf("%s = %g, want %g", tc.query, got, tc.want)
				}
			})
		}
	}
}
