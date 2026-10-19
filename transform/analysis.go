package transform

import "context"

// FunctionReference identifies a statically named function and its arity.
type FunctionReference struct {
	Name  Name
	Arity int
}

// Analysis describes syntax and navigation in a compiled XPath expression.
// Dynamic calls can invoke additional functions. This report is diagnostic;
// it is not an authorization policy or a guarantee of streaming execution.
type Analysis struct {
	// Functions lists unique statically named calls/references, sorted by name and arity.
	Functions []FunctionReference
	// DownwardSelections counts syntactic paths using child/descendant axes.
	DownwardSelections int
	// DynamicCalls reports calls through a computed function item.
	DynamicCalls bool
	// ContextItem reports focus-sensitive syntax, including paths and predicates.
	// It does not prove that an initial context item is required.
	ContextItem bool
	// NonMotionlessPredicates reports navigation or focus-sensitive predicates.
	// This is a conservative diagnostic, not an XSLT streamability judgment.
	NonMotionlessPredicates bool
}

// Analyze computes optional properties with the engine's execution budget.
func (q *XPath) Analyze(ctx context.Context) (Analysis, error) {
	if q == nil || q.expression == nil {
		return Analysis{}, wrap("analyze XPath", ErrInput)
	}

	ctx, cancel, err := q.engine.invocation(ctx)
	if err != nil {
		return Analysis{}, wrap("analyze XPath", err)
	}
	defer cancel()

	native, err := q.expression.Analyze(ctx, q.namespaces)
	if err != nil {
		return Analysis{}, wrap("analyze XPath", err)
	}

	result := Analysis{DynamicCalls: native.DynamicCalls, ContextItem: native.ContextItem, DownwardSelections: native.DownwardSelections, NonMotionlessPredicates: native.NonMotionlessPredicates}
	for _, fn := range native.Functions {
		result.Functions = append(result.Functions, FunctionReference{Name: Name{Space: fn.Name.URI, Local: fn.Name.Name}, Arity: fn.Arity})
	}

	return result, nil
}
