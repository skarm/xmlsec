package xpath //nolint:testpackage // Checks static analysis using the internal compiler.

import (
	"context"
	"errors"
	"slices"
	"testing"
)

func TestExpressionAnalysisCollectsSyntaxWithoutEvaluation(t *testing.T) {
	t.Parallel()
	expression, err := NewCompiler().Language(31, nil).Compile(`(count(/catalog/item[position()=1]), count(/catalog/item), (string#1)(.), math:pow(2,3))`)
	if err != nil {
		t.Fatal(err)
	}
	got, err := expression.Analyze(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	want := []FunctionReference{
		{Name: QualifiedName{URI: "http://www.w3.org/2005/xpath-functions", Name: "count"}, Arity: 1},
		{Name: QualifiedName{URI: "http://www.w3.org/2005/xpath-functions", Name: "position"}, Arity: 0},
		{Name: QualifiedName{URI: "http://www.w3.org/2005/xpath-functions", Name: "string"}, Arity: 1},
		{Name: QualifiedName{URI: "http://www.w3.org/2005/xpath-functions/math", Name: "pow"}, Arity: 2},
	}
	if !slices.Equal(got.Functions, want) {
		t.Errorf("function references = %+v, want %+v", got.Functions, want)
	}
	if !got.DynamicCalls || !got.ContextItem || !got.NonMotionlessPredicates || got.DownwardSelections != 2 {
		t.Errorf("analysis = %+v, want dynamic call, focus-sensitive predicate and two downward selections", got)
	}

	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if got, err := expression.Analyze(ctx, nil); len(got.Functions) != 0 || !errors.Is(err, context.Canceled) {
		t.Errorf("canceled analysis = %+v, %v, want no references and context.Canceled", got, err)
	}
}
