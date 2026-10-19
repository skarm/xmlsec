package transform

import (
	"context"
	"fmt"
	"io"
	"time"

	"github.com/skarm/xmlsec/transform/internal/xdm"
	"github.com/skarm/xmlsec/transform/internal/xpath"
)

// Function registers an application-owned function with fixed arity. Use an
// application namespace; standard XPath, XML and XSLT namespaces are reserved.
type Function struct {
	Name  Name
	Arity int
	// Call receives immutable arguments and may run concurrently. It must honor
	// cancellation; returned errors propagate to XPath or XSLT execution.
	Call func(context.Context, []Sequence) (Sequence, error)
}

func (e *Engine) registerFunctions(functions []Function) error {
	e.functions = make(map[xpath.QualifiedName]xpath.Function, len(functions))

	e.functionNames = make(map[string]xpath.Function, len(functions))
	for _, fn := range functions {
		if !xpath.ValidNCName(fn.Name.Local) || reservedFunctionNamespace(fn.Name.Space) || fn.Arity < 0 || fn.Arity > e.limits.MaxNodes || fn.Call == nil {
			return fmt.Errorf("%w: invalid application function", ErrInput)
		}

		name := xpath.QualifiedName{URI: fn.Name.Space, Name: fn.Name.Local}
		if _, exists := e.functions[name]; exists {
			return fmt.Errorf("%w: duplicate application function", ErrInput)
		}

		native := &applicationFunction{definition: fn, limits: e.limits}
		e.functions[name], e.functionNames[expandedName(fn.Name)] = native, native
	}

	return nil
}

func reservedFunctionNamespace(uri string) bool {
	switch uri {
	case "", documentXMLNamespace, "http://www.w3.org/2000/xmlns/", "http://www.w3.org/1999/XSL/Transform",
		xpath.NSFn, xpath.NSMath, xpath.NSMap, xpath.NSArray, xpath.NSErr, xpath.NSXS, "http://www.w3.org/2001/XMLSchema-instance":
		return true
	default:
		return false
	}
}

func (e *Engine) languageContext(ctx context.Context) context.Context {
	// Compilation may evaluate static expressions. Give them the same explicit
	// collection policy and deterministic diagnostic defaults as runtime calls.
	ctx = xpath.WithEvaluationContext(ctx, xpath.EvaluationContext{CurrentTime: time.Now().UTC(), Timezone: time.UTC, Trace: io.Discard, Collections: e.collectionResolver()})
	return xpath.WithFunctions(ctx, e.functions)
}

type applicationFunction struct {
	definition Function
	limits     Limits
}

func (f *applicationFunction) MinArity() int { return f.definition.Arity }

func (f *applicationFunction) MaxArity() int { return f.definition.Arity }

func (f *applicationFunction) Call(ctx context.Context, arguments []xdm.Sequence) (xdm.Sequence, error) {
	if err := xpath.Charge(ctx, len(arguments)+1); err != nil {
		return nil, err
	}

	checker := sequenceChecker{ctx: ctx, limits: f.limits, input: true}

	args := make([]Sequence, len(arguments))
	for i, arg := range arguments {
		if err := checker.walk(arg, 0); err != nil {
			return nil, err
		}

		args[i] = ownSequence(arg)
	}

	result, err := f.definition.Call(ctx, args)
	if err != nil {
		return nil, err
	}

	checker = sequenceChecker{ctx: ctx, limits: f.limits, input: true}
	if err := checker.walk(result.items, 0); err != nil {
		return nil, err
	}

	if err := xpath.Charge(ctx, checker.count); err != nil {
		return nil, err
	}

	if err := xpath.ChargeString(ctx, checker.size); err != nil {
		return nil, err
	}

	return xdm.CloneSequence(result.items), nil
}
