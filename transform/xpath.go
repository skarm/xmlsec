package transform

import (
	"context"
	"errors"
	"fmt"
	"io"
	"maps"

	"github.com/skarm/xmlsec/transform/internal/xdm"
	"github.com/skarm/xmlsec/transform/internal/xpath"
)

const documentXMLNamespace = "http://www.w3.org/XML/1998/namespace"

// XPathVersion selects a grammar and function library, not a compatibility hint.
type XPathVersion uint8

const (
	// XPath10 selects XPath 1.0 grammar, functions and IEEE 754 semantics.
	XPath10 XPathVersion = 10
	// XPath20 selects XPath 2.0.
	XPath20 XPathVersion = 20
	// XPath30 selects XPath 3.0.
	XPath30 XPathVersion = 30
	// XPath31 selects XPath 3.1.
	XPath31 XPathVersion = 31
)

// XPathOptions specifies the static context used to compile an expression.
// XPath 1.0 does not support a default element namespace.
type XPathOptions struct {
	// DefaultCollation selects a supported collation; empty uses Unicode codepoint order.
	DefaultCollation string
	// Version defaults to XPath31.
	Version XPathVersion
	// Namespaces maps prefixes to namespace URIs and is copied during compilation.
	// The empty prefix sets the default element namespace in XPath 2.0 and newer.
	Namespaces map[string]string
	// BaseURI resolves relative URI references. Empty leaves the static base URI absent.
	BaseURI string
	// DecimalFormats supplies static fn:format-number formats in XPath 3.0/3.1.
	// A zero Name selects the unnamed format. Property names follow the standard
	// decimal-format declaration (for example "decimal-separator" and "NaN").
	// Omitted properties use standard defaults. Maps are copied at compilation;
	// invalid names or properties report ErrInput. XPath 1.0/2.0 reject this option.
	DecimalFormats map[Name]map[string]string
}

// XPathContext supplies invocation-local variables and focus. In XPath 2.0 and
// later, every free variable must be present in Variables, even in an unselected
// branch. Expressions that need no context item accept a nil document and an
// absent ContextItem.
type XPathContext struct {
	Context   DynamicContext
	Variables Bindings
	// ContextItem overrides the document argument. A zero Value leaves it unspecified.
	ContextItem Value
	// Position and Size set the initial focus. Each zero value selects one;
	// negative values and an effective position greater than size are rejected.
	Position, Size int
}

// XPath is an immutable compiled expression associated with its engine policy.
type XPath struct {
	namespaces    map[string]string
	freeVariables []string
	engine        *Engine
	expression    *xpath.Expression
	evaluator     xpath.Evaluator
	version       XPathVersion
}

// Version reports the compiled language version.
func (q *XPath) Version() XPathVersion {
	if q == nil {
		return 0
	}

	return q.version
}

// Evaluate evaluates the reusable program with an independent dynamic context.
// The returned sequence owns its values and never exposes mutable XML nodes.
func (q *XPath) Evaluate(ctx context.Context, d *Document, options XPathContext) (Sequence, error) {
	if q == nil || q.expression == nil {
		return Sequence{}, wrap("evaluate XPath", ErrInput)
	}

	ctx, cancel, err := q.engine.invocation(ctx)
	if err != nil {
		return Sequence{}, wrapXPath("evaluate XPath", err, q.version)
	}
	defer cancel()

	ctx = q.engine.languageContext(ctx)

	ctx, err = q.engine.dynamicContext(ctx, options.Context)
	if err != nil {
		return Sequence{}, wrapXPath("evaluate XPath", err, q.version)
	}

	variables, err := nativeBindings(ctx, options.Variables, q.engine.limits)
	if err != nil {
		return Sequence{}, wrapXPath("evaluate XPath", err, q.version)
	}

	for _, name := range q.freeVariables {
		if _, present := variables[name]; !present {
			return Sequence{}, wrapXPath("evaluate XPath", xpath.UndefinedVariableError(name, int(q.version)), q.version)
		}
	}

	if returned1, matched := evaluateVersion(ctx, q, variables, &options); matched {
		return Sequence{}, returned1
	}

	position, size := options.Position, options.Size
	if position < 0 || size < 0 {
		return Sequence{}, wrap("evaluate XPath", ErrInput)
	}

	if position == 0 {
		position = 1
	}

	if size == 0 {
		size = 1
	}

	if position > size {
		return Sequence{}, wrap("evaluate XPath", ErrInput)
	}

	evaluator := q.evaluator.Variables(variables).Position(position).Size(size).TraceWriter(io.Discard)
	if q.engine.resolver != nil {
		evaluator = evaluator.URIResolver(resourceAdapter{engine: q.engine})
	}

	var node xdm.Node

	if options.ContextItem.item != nil {
		if err := checkSequence(ctx, xdm.ItemSlice{options.ContextItem.item}, q.engine.limits, true); err != nil {
			return Sequence{}, wrapXPath("evaluate XPath", err, q.version)
		}

		evaluator = evaluator.ContextItem(options.ContextItem.item)
	} else if d != nil {
		if d.native == nil {
			return Sequence{}, wrap("evaluate XPath", ErrInput)
		}

		if err := checkInputDocument(ctx, d.native, q.engine.limits); err != nil {
			return Sequence{}, wrapXPath("evaluate XPath", err, q.version)
		}

		node = d.native
	}

	result, err := evaluator.Evaluate(ctx, q.expression, node)
	if err != nil {
		return Sequence{}, wrapXPath("evaluate XPath", errors.Join(err, ctx.Err()), q.version)
	}

	if err := checkSequence(ctx, result.Sequence(), q.engine.limits, false); err != nil {
		return Sequence{}, wrapXPath("evaluate XPath", err, q.version)
	}

	return ownSequence(result.Sequence()), nil
}

func nativeBindings(ctx context.Context, bindings Bindings, limits Limits) (map[string]xdm.Sequence, error) {
	values := make(map[string]xdm.Sequence, len(bindings))
	checker := sequenceChecker{ctx: ctx, limits: limits, input: true}

	for name, value := range bindings {
		if !xpath.ValidNCName(name.Local) {
			return nil, fmt.Errorf("%w: invalid expanded name", ErrInput)
		}

		if err := checker.walk(value.items, 0); err != nil {
			return nil, err
		}

		values[expandedName(name)] = value.items
	}

	if err := xpath.ChargeString(ctx, checker.size); err != nil {
		return nil, err
	}

	return values, nil
}

func evaluateVersion(ctx context.Context, q *XPath, variables map[string]xdm.Sequence, options *XPathContext) (returned1 error, matched bool) {
	if q.version == XPath10 {
		for name, value := range variables {
			normalized, err := xpath.XPath10Value(ctx, value)
			if err != nil {
				return wrap("evaluate XPath", err), true
			}

			variables[name] = normalized
		}

		if options.ContextItem.item != nil {
			if _, ok := options.ContextItem.item.(xdm.NodeItem); !ok {
				return wrap("evaluate XPath", ErrInput), true
			}
		}
	}

	return
}

// CompileXPath compiles and validates an expression's static language context.
func (e *Engine) CompileXPath(ctx context.Context, source string, options XPathOptions) (*XPath, error) {
	ctx, cancel, err := e.invocation(ctx)
	if err != nil {
		return nil, wrapXPath("compile XPath", err, options.Version)
	}
	defer cancel()

	ctx = e.languageContext(ctx)

	if len(source) > e.limits.MaxProgramBytes {
		return nil, wrapXPath("compile XPath", ErrLimit, options.Version)
	}

	version := options.Version
	if version == 0 {
		version = XPath31
	}

	if version != XPath10 && version != XPath20 && version != XPath30 && version != XPath31 {
		return nil, wrapXPath("compile XPath", ErrUnsupported, options.Version)
	}

	namespaces := maps.Clone(options.Namespaces)
	if namespaces == nil {
		namespaces = make(map[string]string)
	}

	if version != XPath10 {
		if err := xpath.CheckStaticNamespaces(namespaces); err != nil {
			return nil, wrapXPath("compile XPath", err, version)
		}
	}

	namespaces["xml"] = documentXMLNamespace
	if version == XPath10 && namespaces[""] != "" {
		return nil, wrapXPath("compile XPath", fmt.Errorf("%w: XPath 1.0 has no default element namespace", ErrInput), options.Version)
	}

	expression, err := xpath.NewCompiler().Context(ctx).Language(int(version), namespaces).Compile(source)
	if err != nil {
		return nil, wrapXPath("compile XPath", err, options.Version)
	}

	if err := expression.Validate(namespaces); err != nil {
		return nil, wrapXPath("compile XPath", err, options.Version)
	}

	if err := xpath.CheckStandaloneFunctions(expression, namespaces, e.functionNames); err != nil {
		return nil, wrapXPath("compile XPath", err, options.Version)
	}

	if err := ctx.Err(); err != nil {
		return nil, wrapXPath("compile XPath", err, options.Version)
	}

	if options.DefaultCollation != "" && !xpath.IsCollationSupported(options.DefaultCollation) {
		return nil, wrapXPath("compile XPath", ErrUnsupported, options.Version)
	}

	evaluator := xpath.NewEvaluator(xpath.DefaultEvaluatorOptions).Namespaces(namespaces).DefaultCollation(options.DefaultCollation).BaseURI(options.BaseURI).ParseOptions(e.parseOptions()).MaxResourceBytes(int64(e.limits.MaxInputBytes)).OpLimit(e.limits.MaxOperations)

	evaluator, err = e.xpathDecimalFormats(ctx, evaluator, options.DecimalFormats, version)
	if err != nil {
		return nil, wrapXPath("compile XPath", err, version)
	}

	if version == XPath31 {
		evaluator = evaluator.Functions(nil, map[xpath.QualifiedName]xpath.Function{
			{URI: xpath.NSFn, Name: "transform"}: e.transformFunction(options.BaseURI),
		})
	}

	var freeVariables []string

	if version != XPath10 {
		for _, name := range expression.StaticReferences(namespaces).FreeVariables {
			freeVariables = append(freeVariables, xpath.VariableKey(name, namespaces))
		}
	}

	if err := ctx.Err(); err != nil {
		return nil, wrapXPath("compile XPath", err, version)
	}

	return &XPath{engine: e, expression: expression, evaluator: evaluator, version: version, namespaces: namespaces, freeVariables: freeVariables}, nil
}

// XPath 3.0/3.1 §2.3 requires XPDY0130 when an implementation limit is
// exceeded. Preserve more specific standard codes and the public ErrLimit cause.
func wrapXPath(operation string, err error, version XPathVersion) error {
	wrapped := wrap(operation, err)
	if version == 0 || version == XPath30 || version == XPath31 {
		if detail, ok := errors.AsType[*Error](wrapped); ok && detail.Code == "" && errors.Is(detail, ErrLimit) {
			detail.Code = "XPDY0130"
		}
	}

	return wrapped
}
