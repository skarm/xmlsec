package xpath //nolint:testpackage // Exercises aggregate functions on both evaluation paths.

import (
	"errors"
	"testing"

	"github.com/skarm/xmlsec/transform/internal/xdm"
)

func TestAggregateTypeAndOrderASTAndVM(t *testing.T) {
	t.Parallel()
	assertFunctionResults(t, []functionResultCase{
		{"integer aggregation crosses int64 exactly", `(sum((9223372036854775807,2)),avg((9223372036854775807,9223372036854775808)))`, "9223372036854775809|9223372036854775807.5"},
		{"sum atomizes XML and nested arrays", `let $d := parse-xml('<r><n>1.25</n><n>2.75</n></r>') return (sum($d/r/n),sum([1,[2,3]]),sum($d/r/n) instance of xs:double)`, "4|6|true"},
		{"duration sums and averages retain subtype", `(sum((xs:yearMonthDuration('P10M'),xs:yearMonthDuration('P3M'))),avg((xs:yearMonthDuration('P2M'),xs:yearMonthDuration('P3M'))),sum((xs:dayTimeDuration('PT1.2S'),xs:dayTimeDuration('-PT0.7S'))),avg((xs:dayTimeDuration('PT1.2S'),xs:dayTimeDuration('PT2.1S'))))`, "P1Y1M|P3M|PT0.5S|PT1.65S"},
		{"numeric extrema promote to the widest argument type", `(min((2,xs:float('3'))) instance of xs:float,max((xs:decimal('2.5'),xs:double('2'))) instance of xs:double,min((1,xs:double('NaN'))),max(xs:byte(7)) instance of xs:byte)`, "true|true|NaN|true"},
		{"non-numeric extrema compare actual values", `(min((true(),false())),max(('a','b')),min((xs:date('2024-03-01Z'),xs:date('2024-02-29Z'))),max((xs:dayTimeDuration('PT20S'),xs:dayTimeDuration('PT3S'))))`, "false|b|2024-02-29Z|PT20S"},
		{"distinct-values coalesces NaNs and equivalent numeric types", `(count(distinct-values((xs:float('NaN'),xs:double('NaN')))),count(distinct-values((1,1.0,xs:double(1)))),count(distinct-values((0,xs:double('-0')))))`, "1|1|1"},
	})
}

func TestAggregateErrorsASTAndVM(t *testing.T) {
	t.Parallel()
	for _, test := range []struct{ name, expression, code string }{
		{"mixed numeric and duration sum", `sum((1,xs:dayTimeDuration('P1D')))`, "FORG0006"},
		{"incomparable extrema", `max((1,'two'))`, "FORG0006"},
		{"average rejects generic duration", `avg((xs:duration('P1Y'),xs:duration('P1M')))`, "FORG0006"},
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
