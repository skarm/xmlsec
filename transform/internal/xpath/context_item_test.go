package xpath //nolint:testpackage // Compares the context-item shortcut with VM evaluation.

import (
	"context"
	"errors"
	"math/big"
	"reflect"
	"testing"

	"github.com/skarm/xmlsec/transform/internal/xdm"
)

func TestContextItemMatchesVM(t *testing.T) {
	doc, err := (xdm.ParseOptions{}).ParseText(t.Context(), `<r>text</r>`)
	if err != nil {
		t.Fatal(err)
	}
	root := doc.DocumentElement()
	expr := compileEvaluatorExpression(t, `.`)
	if expr == nil || expr.program == nil {
		t.Fatal("context-item expression has no compiled program")
	}
	vmExpression := *expr
	program := *expr.program
	program.stream.isContextItem = false
	vmExpression.program = &program
	base := NewEvaluator(DefaultEvaluatorOptions)
	for _, evaluator := range []Evaluator{
		base,
		base.ContextItem(xdm.AtomicValue{TypeName: xdm.TypeString, Value: "atomic"}),
		base.ContextItem(xdm.AtomicValue{TypeName: xdm.TypeInteger, Value: new(big.Int).Lsh(big.NewInt(1), 4096)}),
		base.ContextItem(xdm.NodeItem{Node: root, TypeAnnotation: "xs:untyped"}),
		base.ContextItem(xdm.NodeItem{}),
		base.ContextItem(xdm.NewArray([]xdm.Sequence{xdm.SingleInteger(1)})),
		base.TypeAnnotations(map[xdm.Node]string{root: "xs:untyped"}),
	} {
		for _, node := range []xdm.Node{nil, doc, root} {
			for _, canceled := range []bool{false, true} {
				for _, byteLimit := range []int{1, 8192} {
					ctx, cancel := context.WithCancel(t.Context())
					if canceled {
						cancel()
					}
					fastCtx := WithBudget(ctx, 100, 100, byteLimit, 10)
					vmCtx := WithBudget(ctx, 100, 100, byteLimit, 10)
					fast, fastErr := evaluator.Evaluate(fastCtx, expr, node)
					slow, slowErr := evaluator.Evaluate(vmCtx, &vmExpression, node)
					cancel()
					if (fastErr == nil) != (slowErr == nil) {
						t.Fatalf("error mismatch: %v / %v", fastErr, slowErr)
					}
					if fastErr != nil && slowErr != nil && (reflect.TypeOf(fastErr) != reflect.TypeOf(slowErr) || fastErr.Error() != slowErr.Error() || errors.Is(fastErr, context.Canceled) != errors.Is(slowErr, context.Canceled)) {
						t.Fatalf("error mismatch: %v / %v", fastErr, slowErr)
					}
					if !reflect.DeepEqual(fast, slow) || !reflect.DeepEqual(getBudget(fastCtx), getBudget(vmCtx)) {
						t.Fatalf("result or budget mismatch: %+v / %+v", fast, slow)
					}
				}
			}
		}
	}
}
