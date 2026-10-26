package xpath //nolint:testpackage // Exercises evaluator snapshots and reusable result ownership at their package boundary.

import (
	"context"
	"errors"
	"math/big"
	"slices"
	"testing"
	"time"

	"github.com/skarm/xmlsec/transform/internal/xdm"
)

func compileEvaluatorExpression(t *testing.T, source string) *Expression {
	t.Helper()
	expression, err := NewCompiler().Language(31, nil).Compile(source)
	if err != nil {
		t.Fatal(err)
	}
	return expression
}

func assertEvaluatorString(t *testing.T, evaluator Evaluator, expression *Expression, want string) {
	t.Helper()
	result, err := evaluator.Evaluate(t.Context(), expression, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got, ok := result.IsString(); !ok || got != want {
		t.Fatalf("result = %v; want string %q", result.Sequence(), want)
	}
}

func TestEvaluatorVariableSnapshot(t *testing.T) {
	t.Parallel()
	number := big.NewInt(123)
	sequence := xdm.ItemSlice{xdm.AtomicValue{TypeName: "xs:integer", Value: number}}
	bindings := map[string]xdm.Sequence{"v": sequence}
	base := NewEvaluator(DefaultEvaluatorOptions).Variables(bindings)
	number.SetInt64(999)
	sequence[0] = xdm.AtomicValue{TypeName: "xs:integer", Value: int64(888)}
	bindings["v"] = xdm.SingleInteger(777)
	branch := base.Variables(map[string]xdm.Sequence{"v": xdm.SingleInteger(456)})
	expression := compileEvaluatorExpression(t, `string($v)`)
	assertEvaluatorString(t, base, expression, "123")
	assertEvaluatorString(t, branch, expression, "456")
	assertEvaluatorString(t, base, expression, "123")
}

func TestEvaluatorFocusAndClockIsolation(t *testing.T) {
	t.Parallel()
	at := time.Date(2024, time.February, 29, 23, 45, 6, 0, time.UTC)
	base := NewEvaluator(DefaultEvaluatorOptions).CurrentTime(at).ImplicitTimezone(time.FixedZone("unit", -5*60*60)).Focus(xdm.AtomicValue{TypeName: "xs:string", Value: "base"}, 2, 7)
	focus := compileEvaluatorExpression(t, `string-join((string(.),string(position()),string(last())), '|')`)
	branch := base.Focus(xdm.AtomicValue{TypeName: "xs:string", Value: "branch"}, 3, 9)
	assertEvaluatorString(t, base, focus, "base|2|7")
	assertEvaluatorString(t, branch, focus, "branch|3|9")
	assertEvaluatorString(t, base, focus, "base|2|7")
	clock := compileEvaluatorExpression(t, `string-join((string(current-dateTime()),string(current-date()),string(current-time()),string(implicit-timezone())), '|')`)
	assertEvaluatorString(t, base, clock, "2024-02-29T18:45:06-05:00|2024-02-29-05:00|18:45:06-05:00|-PT5H")
	assertEvaluatorString(t, base.CurrentTime(at.Add(6*time.Hour)), clock, "2024-03-01T00:45:06-05:00|2024-03-01-05:00|00:45:06-05:00|-PT5H")
	assertEvaluatorString(t, base, clock, "2024-02-29T18:45:06-05:00|2024-02-29-05:00|18:45:06-05:00|-PT5H")
}

type evaluatorFunction struct {
	value string
	err   error
}

func (evaluatorFunction) MinArity() int { return 0 }
func (evaluatorFunction) MaxArity() int { return 0 }
func (f evaluatorFunction) Call(context.Context, []xdm.Sequence) (xdm.Sequence, error) {
	if f.err != nil {
		return nil, f.err
	}
	return xdm.SingleString(f.value), nil
}

func TestEvaluatorFunctionSnapshotAndCause(t *testing.T) {
	t.Parallel()
	functions := map[string]Function{"probe": evaluatorFunction{value: "original"}}
	base := NewEvaluator(DefaultEvaluatorOptions).Functions(functions, nil)
	sentinel := errors.New("host function failed")
	functions["probe"] = evaluatorFunction{err: sentinel}
	expression := compileEvaluatorExpression(t, `probe()`)
	assertEvaluatorString(t, base, expression, "original")
	branch := base.Functions(functions, nil)
	result, err := branch.Evaluate(t.Context(), expression, nil)
	if result != nil || !errors.Is(err, sentinel) {
		t.Fatalf("host function failure = %v, %v", result, err)
	}
	assertEvaluatorString(t, base, expression, "original")
}

func TestResultCopyPreservesNodesAfterEvalStateReuse(t *testing.T) {
	t.Parallel()
	doc, err := (xdm.ParseOptions{}).ParseText(t.Context(), `<r><n/><n/><n/></r>`)
	if err != nil {
		t.Fatal(err)
	}
	evaluator := NewEvaluator(DefaultEvaluatorOptions)
	state := evaluator.NewEvalState(doc)
	all := compileEvaluatorExpression(t, `r/n`)
	one := compileEvaluatorExpression(t, `r/n[1]`)
	first, err := all.EvaluateReuse(t.Context(), state, doc)
	if err != nil {
		t.Fatal(err)
	}
	owned := first.Copy()
	firstNode := doc.DocumentElement().FirstChild()
	want := []xdm.Node{firstNode, firstNode.NextSibling(), firstNode.NextSibling().NextSibling()}
	if nodes, nodesErr := owned.Nodes(); nodesErr != nil || !slices.Equal(nodes, want) {
		t.Fatalf("initial nodes = %v, %v; want %v", nodes, nodesErr, want)
	}
	extracted, err := first.Nodes()
	if err != nil {
		t.Fatal(err)
	}
	extracted[0] = nil
	if nodes, nodesErr := first.Nodes(); nodesErr != nil || !slices.Equal(nodes, want) {
		t.Fatal("Nodes exposed retained result storage", nodes, nodesErr)
	}
	second, err := one.EvaluateReuse(t.Context(), state, doc)
	if err != nil {
		t.Fatal(err)
	}
	if nodes, nodesErr := second.Nodes(); nodesErr != nil || len(nodes) != 1 || nodes[0] != want[0] {
		t.Fatal("second evaluation", nodes, nodesErr)
	}
	if nodes, nodesErr := owned.Nodes(); nodesErr != nil || !slices.Equal(nodes, want) {
		t.Fatal("Copy changed after state reuse", nodes, nodesErr)
	}
}
