package transform

import (
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/skarm/xmlsec/transform/internal/xdm"
	"github.com/skarm/xmlsec/transform/internal/xpath"
	"github.com/skarm/xmlsec/transform/internal/xslt"
)

// Function registers an application-owned function with fixed arity. Use an
// application namespace; standard XPath, XML and XSLT namespaces are reserved.
// Its parameters and result have the generic XPath type item()*.
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

		native := &applicationFunction{definition: fn, limits: e.limits, resultType: xdm.SequenceType{ItemTest: xdm.AnyItemTest{}, Occurrence: xdm.OccurrenceZeroOrMore}}
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
	ctx = xpath.WithXMLSchemaVersion(ctx, int(e.xmlSchemaVersion))

	ctx = xslt.WithAssertions(ctx, e.xsltAssertions)
	if e.xsltDynamicEvaluationDisabled {
		ctx = xslt.WithDynamicEvaluationDisabled(ctx)
	}
	// Compilation may evaluate static expressions. Give them the same explicit
	// collection policy and deterministic diagnostic defaults as runtime calls.
	ctx = xpath.WithEvaluationContext(ctx, xpath.EvaluationContext{CurrentTime: time.Now().UTC(), Timezone: time.UTC, Trace: io.Discard, Collections: e.collectionResolver()})
	ctx = xslt.WithTransformProgramLimit(ctx, e.limits.MaxProgramBytes)

	return xpath.WithFunctions(ctx, e.functions)
}

func (e *Engine) transformFunction(baseURI string) xpath.Function {
	options := []xslt.TransformOption{
		xslt.WithTransformBaseURI(baseURI), xslt.WithTransformParseOptions(e.parseOptions()),
		xslt.WithTransformMaxResourceBytes(int64(e.limits.MaxInputBytes)),
		xslt.WithTransformCollectionResolver(e.collectionResolver()),
	}
	if e.resolver != nil {
		options = append(options, xslt.WithTransformURIResolver(resourceAdapter{engine: e}))
	}

	if e.packages != nil {
		options = append(options, xslt.WithTransformPackageResolver(packageAdapter{engine: e}))
	}

	return xpathTransformFunction{TypedFunctionByArity: xslt.TransformFunction(options...)}
}

type xpathTransformFunction struct{ xpath.TypedFunctionByArity }

func (f xpathTransformFunction) Call(ctx context.Context, arguments []xdm.Sequence) (xdm.Sequence, error) {
	result, err := f.TypedFunctionByArity.Call(ctx, arguments)
	if err == nil {
		return result, nil
	}

	wrapped := xsltError("fn:transform", err)
	if detail, ok := errors.AsType[*xslt.XSLTError](err); ok && detail.Code != "" {
		return nil, &xdm.Error{Code: detail.CodeQName().Local, QualifiedCode: detail.CodeQName(), Message: detail.Message, Cause: wrapped}
	}

	return nil, wrapped
}

type applicationFunction struct {
	definition Function
	limits     Limits
	resultType xdm.SequenceType
}

func (f *applicationFunction) MinArity() int { return f.definition.Arity }

func (f *applicationFunction) MaxArity() int { return f.definition.Arity }

// Generic item()* parameters need no conversion or arity-sized metadata slice.
func (f *applicationFunction) FuncParamTypes() []xdm.SequenceType { return nil }

func (f *applicationFunction) FuncReturnType() *xdm.SequenceType { return &f.resultType }

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
