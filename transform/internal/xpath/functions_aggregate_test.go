package xpath //nolint:testpackage // Exercises aggregate functions on both evaluation paths.

import (
	"context"
	"errors"
	"testing"

	"github.com/skarm/xmlsec/transform/internal/xdm"
)

func TestAggregateTypeAndOrderASTAndVM(t *testing.T) {
	t.Parallel()
	assertFunctionResults(t, []functionResultCase{
		{"integer aggregation crosses int64 exactly", `(sum((9223372036854775807,2)),avg((9223372036854775807,9223372036854775808)))`, "9223372036854775809|9223372036854775807.5"},
		{"sum atomizes XML and nested arrays", `let $d := parse-xml('<r><n>1.25</n><n>2.75</n></r>') return (sum($d/r/n),sum([1,[2,3]]),sum($d/r/n) instance of xs:double)`, "4|6|true"},
		{"sum preserves IEEE zero signs", `(1 div sum((xs:double('-0'),xs:double('-0'))),1 div sum((xs:float('-0'),xs:float('-0'))),1 div sum((xs:double('0'),xs:double('0'))),1 div sum((xs:double('-0'),0)))`, "-INF|-INF|INF|INF"},
		{"average preserves IEEE zero signs", `(1 div avg(xs:double('-0')),1 div avg((xs:untypedAtomic('-0'),xs:untypedAtomic('-0'))),1 div avg((xs:float('-0'),xs:float('-0'))),1 div avg((xs:float('0'),xs:float('0'))),1 div avg((0,xs:float('-0'))))`, "-INF|-INF|-INF|INF|INF"},
		{"duration sums and averages retain subtype", `(sum((xs:yearMonthDuration('P10M'),xs:yearMonthDuration('P3M'))),avg((xs:yearMonthDuration('P2M'),xs:yearMonthDuration('P3M'))),sum((xs:dayTimeDuration('PT1.2S'),xs:dayTimeDuration('-PT0.7S'))),avg((xs:dayTimeDuration('PT1.2S'),xs:dayTimeDuration('PT2.1S'))))`, "P1Y1M|P3M|PT0.5S|PT1.65S"},
		{"numeric extrema promote to the widest argument type", `(min((2,xs:float('3'))) instance of xs:float,max((xs:decimal('2.5'),xs:double('2'))) instance of xs:double,min((1,xs:double('NaN'))),max(xs:byte(7)) instance of xs:byte)`, "true|true|NaN|true"},
		{"minimum compares at common precision", `let $result := min((16777217,xs:float('16777216'),xs:double('16777218'))) return ($result eq xs:double('16777216'),$result instance of xs:double)`, "true|true"},
		{"maximum compares at common precision", `let $result := max((xs:float('16777216'),16777217,xs:double('0'))) return ($result eq xs:double('16777217'),$result instance of xs:double)`, "true|true"},
		{"untyped atomic input sets common precision", `min((16777217,xs:float('16777216'),xs:untypedAtomic('16777218'))) eq xs:double('16777216')`, "true"},
		{"extrema retain NaN at common precision", `(min((xs:float('NaN'),xs:double('0'))) instance of xs:double,max((16777217,xs:float('NaN'))) instance of xs:float)`, "true|true"},
		{"non-numeric extrema compare actual values", `(min((true(),false())),max(('a','b')),min((xs:date('2024-03-01Z'),xs:date('2024-02-29Z'))),max((xs:dayTimeDuration('PT20S'),xs:dayTimeDuration('PT3S'))))`, "false|b|2024-02-29Z|PT20S"},
		{"distinct-values coalesces NaNs and equivalent numeric types", `(count(distinct-values((xs:float('NaN'),xs:double('NaN')))),count(distinct-values((1,1.0,xs:double(1)))),count(distinct-values((0,xs:double('-0')))))`, "1|1|1"},
		{"distinct-values retains selected untyped values", `let $values := distinct-values((xs:untypedAtomic('cherry'),xs:untypedAtomic('plum'),xs:untypedAtomic('plum'))) return ($values instance of xs:untypedAtomic+,sort($values))`, "true|cherry|plum"},
		{"distinct-values compares untyped values as strings", `let $c := 'http://www.w3.org/2005/xpath-functions/collation/html-ascii-case-insensitive', $folded := distinct-values((xs:untypedAtomic('A'),xs:untypedAtomic('a')),$c) return ($folded instance of xs:untypedAtomic,count(distinct-values((xs:untypedAtomic('A'),'a'),$c)),count(distinct-values((xs:untypedAtomic('1'),1))))`, "true|1|2"},
	})
}

func TestAggregateErrorsASTAndVM(t *testing.T) {
	t.Parallel()
	for _, test := range []struct{ name, expression, code string }{
		{"mixed numeric and duration sum", `sum((1,xs:dayTimeDuration('P1D')))`, "FORG0006"},
		{"incomparable extrema", `max((1,'two'))`, "FORG0006"},
		{"NaN does not hide incomparable extrema", `max((xs:float('NaN'),'two'))`, "FORG0006"},
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

func TestDistinctValuesComparisonBudget(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name  string
		input string
		work  int
	}{
		{"numeric promotion", `(1, xs:decimal('2'), xs:float('3'))`, 5},
		{"calendar comparison", `(xs:date('2024-01-01Z'), xs:date('2024-01-02Z'), xs:date('2024-01-03Z'))`, 6},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			input, err := evaluateFunctionExpression(t, tc.input, runtimeASTMode)
			if err != nil || xdm.SequenceLen(input) != 3 {
				t.Fatalf("input = %v (%v), want three atomic values", input, err)
			}

			atLimit := WithBudget(t.Context(), tc.work, 8, 1024, 8)
			result, err := fnDistinctValues(atLimit, []xdm.Sequence{input})
			if err != nil || xdm.SequenceLen(result) != 3 {
				t.Fatalf("result = %v (%v) at the comparison budget, want three distinct values", result, err)
			}

			belowLimit := WithBudget(t.Context(), tc.work-1, 8, 1024, 8)
			result, err = fnDistinctValues(belowLimit, []xdm.Sequence{input})
			if !errors.Is(err, ErrBudget) || xdm.SequenceLen(result) != 0 {
				t.Fatalf("result = %v (%v) below the comparison budget, want ErrBudget and no result", result, err)
			}

			canceled, cancel := context.WithCancel(t.Context())
			cancel()
			result, err = fnDistinctValues(canceled, []xdm.Sequence{input})
			if !errors.Is(err, context.Canceled) || xdm.SequenceLen(result) != 0 {
				t.Fatalf("canceled result = %v (%v), want context.Canceled and no result", result, err)
			}
		})
	}
}
