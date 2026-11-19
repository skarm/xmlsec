package xpath //nolint:testpackage // Exercises date and duration arithmetic on both evaluation paths.

import (
	"errors"
	"testing"
	"time"

	"github.com/skarm/xmlsec/transform/internal/xdm"
)

func TestEvalDateTimeArithmeticASTAndVM(t *testing.T) {
	t.Parallel()
	assertFunctionResults(t, []functionResultCase{
		{"day addition crosses leap day", `(xs:date('2024-02-28Z') + xs:dayTimeDuration('P2D'),xs:date('2024-03-01Z') - xs:dayTimeDuration('P1D'))`, "2024-03-01Z|2024-02-29Z"},
		{"date time subtraction normalizes zones and preserves fractions", `xs:dateTime('2024-03-01T01:00:00.250+02:00') - xs:dateTime('2024-02-29T22:59:59.750Z')`, "PT0.5S"},
		{"time addition wraps at midnight", `xs:time('23:59:50Z') + xs:dayTimeDuration('PT20S')`, "00:00:10Z"},
		{"time subtraction discards dates from midnight carry", `((xs:time('23:59:50Z') + xs:dayTimeDuration('PT20S')) - xs:time('00:00:10Z'), (xs:time('00:00:00Z') - xs:dayTimeDuration('PT1S')) - xs:time('23:59:59Z'))`, "PT0S|PT0S"},
		{"time subtraction preserves offset-induced day difference", `xs:time('17:00:00-06:00') - xs:time('08:00:00+09:00')`, "P1D"},
		{"date time subtraction preserves actual dates", `xs:dateTime('2024-03-01T00:00:00Z') - xs:dateTime('2024-02-29T00:00:00Z')`, "P1D"},
		{"scaling year-month duration rounds ties", `(xs:yearMonthDuration('P3M') * 0.5, xs:yearMonthDuration('P3M') * -0.5, xs:yearMonthDuration('P1Y') div 4)`, "P2M|-P1M|P3M"},
		{"duration scaling preserves exact decimal", `(xs:dayTimeDuration('PT0.6S') * 1.5,xs:dayTimeDuration('PT1.25S') div 2)`, "PT0.9S|PT0.625S"},
		{"untyped numeric operand is converted before duration dispatch", `(xs:yearMonthDuration('P2M') * xs:untypedAtomic('3'), xs:untypedAtomic('3') * xs:yearMonthDuration('P2M'), xs:dayTimeDuration('P6D') div xs:untypedAtomic('3'))`, "P6M|P6M|P2D"},
		{"duration division uses the same unit", `(xs:dayTimeDuration('PT1.5S') div xs:dayTimeDuration('PT0.5S'),xs:yearMonthDuration('P1Y') div xs:yearMonthDuration('P8M'))`, "3|1.5"},
	})
}

func TestTimeSubtractionWithImplicitTimezoneASTAndVM(t *testing.T) {
	t.Parallel()

	const source = `string((xs:time('23:59:50') + xs:dayTimeDuration('PT20S')) - xs:time('00:00:10+02:00'))`
	for _, mode := range []string{runtimeASTMode, "VM"} {
		t.Run(mode, func(t *testing.T) {
			t.Parallel()

			ast, err := Parse(source)
			if err != nil {
				t.Fatal(err)
			}

			evaluator := NewEvaluator(DefaultEvaluatorOptions).ImplicitTimezone(time.FixedZone("test", 2*60*60))

			var seq xdm.Sequence
			if mode == runtimeASTMode {
				ec := evaluator.newEvalCtx(nil)
				ec.version = xpathVersion31
				seq, err = evaluateRuntimeAST(t.Context(), ec, ast)
			} else {
				expr, compileErr := NewCompiler().Language(xpathVersion31, nil).CompileExpr(ast)
				if compileErr != nil {
					t.Fatal(compileErr)
				}

				var result *Result
				result, err = evaluator.Evaluate(t.Context(), expr, nil)
				if err == nil {
					seq = result.Sequence()
				}
			}

			if err != nil {
				t.Fatal(err)
			}
			assertAtomicSequence(t, seq, []xdm.AtomicValue{{TypeName: xdm.TypeString, Value: "PT0S"}})
		})
	}
}

func TestEvalDateTimeArithmeticErrorsASTAndVM(t *testing.T) {
	t.Parallel()
	for _, test := range []struct{ name, expression, code string }{
		{"empty divisor duration", `xs:yearMonthDuration('P1M') div xs:yearMonthDuration('P0M')`, "FOAR0001"},
		{"invalid untyped duration operand", `xs:dayTimeDuration('P6D') div xs:untypedAtomic('invalid')`, "FORG0001"},
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
