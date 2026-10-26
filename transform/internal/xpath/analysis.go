package xpath

import (
	"cmp"
	"context"
	"slices"
	"strings"
)

// FunctionReference identifies a statically named function and its argument count.
type FunctionReference struct {
	// Name is the resolved namespace URI and local function name.
	Name QualifiedName
	// Arity is the call or reference argument count.
	Arity int
}

// ExpressionAnalysis reports syntactic properties without authorizing execution or
// establishing W3C streamability.
type ExpressionAnalysis struct {
	// Functions lists unique statically named functions sorted by expanded name and
	// arity.
	Functions []FunctionReference
	// DynamicCalls reports calls through computed function items.
	DynamicCalls bool
	// ContextItem reports focus-sensitive syntax, not proof that the initial focus is
	// required.
	ContextItem bool
	// NonMotionlessPredicates reports predicates with navigation or focus-sensitive
	// syntax.
	NonMotionlessPredicates bool
	// DownwardSelections counts syntactic paths that use child or descendant navigation.
	DownwardSelections int
}

// Analyze computes optional diagnostic properties on demand. It neither
// evaluates the expression nor promises streamability or absence of effects.
func (e *Expression) Analyze(ctx context.Context, namespaces map[string]string) (ExpressionAnalysis, error) {
	a := expressionAnalyzer{ctx: ctx, namespaces: namespaces, seen: make(map[FunctionReference]struct{})}
	WalkExpr(e.astExpr(), a.visit)

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
	seen       map[FunctionReference]struct{}
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

func (a *expressionAnalyzer) predicates(predicates []Expr) {
	for _, predicate := range predicates {
		if a.result.NonMotionlessPredicates || a.err != nil {
			return
		}

		WalkExpr(predicate, func(expr Expr) bool {
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
	if _, present := a.seen[reference]; !present {
		a.seen[reference] = struct{}{}
		a.result.Functions = append(a.result.Functions, reference)
	}
}

func downwardAxis(axis AxisType) bool {
	return axis == AxisChild || axis == AxisDescendant || axis == AxisDescendantOrSelf
}
