package xpath

import (
	"cmp"
	"context"
	"slices"
	"strings"
)

type FunctionReference struct {
	Name  QualifiedName
	Arity int
}
type ExpressionAnalysis struct {
	Functions                                          []FunctionReference
	DynamicCalls, ContextItem, NonMotionlessPredicates bool
	DownwardSelections                                 int
}

// Analyze computes optional diagnostic properties on demand. It neither
// evaluates the expression nor promises streamability or absence of effects.
func (e *Expression) Analyze(ctx context.Context, namespaces map[string]string) (ExpressionAnalysis, error) {
	a := expressionAnalyzer{ctx: ctx, namespaces: namespaces, seen: make(map[FunctionReference]bool)}
	walkExpr(e.astExpr(), a.visit)

	if a.err != nil {
		return ExpressionAnalysis{}, a.err
	}

	slices.SortFunc(a.result.Functions, func(a, b FunctionReference) int {
		if c := strings.Compare(a.Name.URI, b.Name.URI); c != 0 {
			return c
		}

		if c := strings.Compare(a.Name.Name, b.Name.Name); c != 0 {
			return c
		}

		return cmp.Compare(a.Arity, b.Arity)
	})

	return a.result, ctx.Err()
}

type expressionAnalyzer struct {
	ctx        context.Context
	namespaces map[string]string
	seen       map[FunctionReference]bool
	result     ExpressionAnalysis
	err        error
}

func (a *expressionAnalyzer) visit(expr Expr) bool {
	if a.err != nil {
		return false
	}

	if a.err = Charge(a.ctx, 1); a.err != nil {
		return false
	}

	switch v := expr.(type) {
	case FunctionCall:
		a.function(v.Prefix, v.Name, len(v.Args))
	case NamedFunctionRef:
		a.function(v.Prefix, v.Name, v.Arity)
	case DynamicFunctionCall:
		a.result.DynamicCalls = true
	case ContextItemExpr, RootExpr:
		a.result.ContextItem = true
	case LocationPath:
		a.result.ContextItem = true

		downward := false
		for _, step := range v.Steps {
			downward = downward || downwardAxis(step.Axis)
			a.predicates(step.Predicates)
		}

		if downward {
			a.result.DownwardSelections++
		}
	case vmLocationPathExpr:
		a.result.ContextItem = true

		downward := false
		for _, step := range v.Steps {
			downward = downward || downwardAxis(step.Axis)
			a.predicates(step.Predicates)
		}

		if downward {
			a.result.DownwardSelections++
		}
	case FilterExpr:
		a.predicates(v.Predicates)
	}

	return a.err == nil
}

func downwardAxis(axis AxisType) bool {
	return axis == AxisChild || axis == AxisDescendant || axis == AxisDescendantOrSelf
}

func (a *expressionAnalyzer) predicates(predicates []Expr) {
	for _, predicate := range predicates {
		if a.result.NonMotionlessPredicates || a.err != nil {
			return
		}

		walkExpr(predicate, func(expr Expr) bool {
			if a.err != nil || a.result.NonMotionlessPredicates {
				return false
			}

			if a.err = Charge(a.ctx, 1); a.err != nil {
				return false
			}

			var descend bool

			a.result.NonMotionlessPredicates, descend = inspectPredicateMotion(expr, predicate, nil)

			return descend
		})
	}
}

func (a *expressionAnalyzer) function(prefix, name string, arity int) {
	uri := NSFn
	if prefix != "" {
		uri = a.namespaces[prefix]
		if uri == "" {
			uri, _ = PredeclaredNamespace(prefix)
		}
	}

	if strings.HasPrefix(name, "Q{") {
		if end := strings.IndexByte(name, '}'); end >= 0 {
			uri, name = name[2:end], name[end+1:]
		}
	}

	reference := FunctionReference{Name: QualifiedName{URI: uri, Name: name}, Arity: arity}
	if !a.seen[reference] {
		a.seen[reference] = true
		a.result.Functions = append(a.result.Functions, reference)
	}
}
