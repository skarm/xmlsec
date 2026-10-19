package transform

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strings"
	"time"

	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/internal/tree"
	"github.com/skarm/xmlsec/reference"
	"github.com/skarm/xmlsec/transform/internal/xdm"
	"github.com/skarm/xmlsec/transform/internal/xpath"
	"github.com/skarm/xmlsec/transform/internal/xslt"
)

var _ reference.ExtensionProcessor = (*Engine)(nil)

// Fingerprint identifies the exact approved program, excluding runtime Here handles.
func Fingerprint(t reference.Transform) (string, error) { return reference.ProgramFingerprint(t) }

// Validate preflights an approved XMLDSig 1.0 program before reference I/O.
// Config{} enables no such programs.
func (e *Engine) Validate(ctx context.Context, tr reference.Transform) error {
	if e == nil {
		return reference.ErrPolicy
	}

	return e.v1.Validate(ctx, tr)
}

// Apply implements reference.ExtensionProcessor while preserving v1 semantics
// and original document node identity. It uses the engine's shared limit policy.
func (e *Engine) Apply(ctx context.Context, tr reference.Transform, in reference.Data, options reference.ExtensionContext) (reference.Data, error) {
	if e == nil {
		return reference.Data{}, reference.ErrPolicy
	}

	return e.v1.Apply(ctx, tr, in, options)
}

// WriteTransform implements reference.ReaderExtensionProcessor for approved XSLT
// transforms. It parses src incrementally, retains the input/result trees and
// serializes into dst with the same incremental or buffered paths as Result.WriterTo.
// Streams remain caller-owned and errors may leave partial output.
func (e *Engine) WriteTransform(ctx context.Context, dst io.Writer, src io.Reader, tr reference.Transform, _ reference.ExtensionContext) error {
	if e == nil {
		return reference.ErrPolicy
	}

	if _, err := e.v1.approved(ctx, tr); err != nil {
		return err
	}

	if tr.Algorithm != reference.XSLT {
		return reference.ErrUnsupported
	}

	ctx, cancel, err := e.invocation(ctx)
	if err != nil {
		return v1Error(err)
	}
	defer cancel()

	options := e.parseOptions()
	options.Limits.MaxBytes = min(options.Limits.MaxBytes, e.v1.input)

	native, err := options.ParseReader(ctx, src)
	if err != nil {
		return v1Error(err)
	}

	key, err := Fingerprint(tr)
	if err != nil {
		return err
	}

	sheet := Stylesheet{engine: e, native: e.v1.stylesheets[key]}
	_, err = sheet.Write(ctx, dst, &Document{native: native}, XSLTContext{})

	return v1Error(err)
}

type compiled struct {
	expression *xpath.Expression
	evaluator  xpath.Evaluator
}

// v1Processor retains XMLDSig 1.0 semantics for explicitly approved programs.
type v1Processor struct {
	engine                            *Engine
	programs                          map[string][]compiled
	stylesheets                       map[string]*xslt.Stylesheet
	timeout                           time.Duration
	input, nodes, operations, strings int
}

// newV1Processor compiles the approved XMLDSig compatibility programs.
func newV1Processor(e *Engine, programs []reference.Transform) (*v1Processor, error) {
	if len(programs) == 0 || len(programs) > 64 {
		return nil, fmt.Errorf("%w: 1..64 approved programs required", reference.ErrPolicy)
	}

	limits := e.limits
	p := &v1Processor{programs: make(map[string][]compiled), stylesheets: make(map[string]*xslt.Stylesheet), timeout: limits.Timeout, input: limits.MaxInputBytes, nodes: limits.MaxNodes, operations: limits.MaxOperations, strings: limits.MaxOutputBytes, engine: e}

	for _, t := range reference.CloneTransforms(programs) {
		if !reference.IsExtension(t.Algorithm) {
			return nil, reference.ErrUnsupported
		}

		key, err := reference.ProgramFingerprint(t)
		if err != nil {
			return nil, err
		}

		if t.Algorithm == reference.XSLT {
			sheet, err := compileV1Stylesheet(e, t.Stylesheet)
			if err != nil {
				return nil, err
			}

			p.stylesheets[key] = sheet

			continue
		}

		var expressions []compiled

		for _, x := range t.XPath {
			ns := x.Namespaces
			if ns == nil {
				ns = make(map[string]string)
			}

			ns["xml"] = document.XMLNamespace
			functions := map[string]xpath.Function{"here": hereFunction(document.Element{}, nil)}

			expr, err := xpath.NewCompiler().Language(10, ns).Compile(x.Expression)
			if err == nil {
				err = expr.Validate(ns)
			}

			if err == nil {
				err = xpath.CheckStandaloneFunctions(expr, ns, functions)
			}

			if err == nil && len(expr.StaticReferences(ns).FreeVariables) > 0 {
				err = fmt.Errorf("%w: XMLDSig XPath has no variable bindings", reference.ErrInput)
			}

			if err != nil {
				return nil, executionError(err)
			}

			ev := xpath.NewEvaluator(xpath.DefaultEvaluatorOptions).Namespaces(ns).Functions(functions, nil).OpLimit(p.operations)

			expressions = append(expressions, compiled{expr, ev})
		}

		p.programs[key] = expressions
	}

	return p, nil
}

// Validate preflights the compiled allowed transform before reference I/O.
func (p *v1Processor) Validate(ctx context.Context, t reference.Transform) error {
	_, err := p.approved(ctx, t)
	return err
}

// Apply evaluates an allowed transform with shared operation, string and node budgets.
func (p *v1Processor) Apply(ctx context.Context, t reference.Transform, in reference.Data, ec reference.ExtensionContext) (reference.Data, error) {
	program, err := p.approved(ctx, t)
	if err != nil {
		return reference.Data{}, err
	}

	if t.Algorithm == reference.XSLT {
		return p.applyStylesheet(ctx, t, in)
	}

	set, ok := in.Nodes()
	if !ok {
		return reference.Data{}, reference.ErrInput
	}

	if set.Len() > p.nodes {
		return reference.Data{}, reference.ErrLimit
	}

	doc := set.Document()

	ctx, cancel, err := p.engine.invocation(ctx)
	if err != nil {
		return reference.Data{}, executionError(err)
	}
	defer cancel()

	limits := document.DefaultLimits()
	limits.MaxBytes = p.input
	limits.MaxNodes = p.nodes

	limits.MaxDepth = p.engine.limits.MaxDepth
	if err = tree.CheckSnapshotLimits(ctx, doc, limits); err != nil {
		return reference.Data{}, executionError(err)
	}

	if err = xpath.Charge(ctx, set.Len()+1); err != nil {
		return reference.Data{}, executionError(err)
	}

	view, err := xdm.FromDocument(ctx, doc)
	if err != nil {
		return reference.Data{}, executionError(err)
	}

	ids, err := reference.NewSameDocumentResolverWithRules(ctx, doc, ec.IDRules)
	if err != nil {
		return reference.Data{}, err
	}

	resolve := func(id string) xdm.Node {
		e, _, err := ids.Target(ctx, "#"+url.PathEscape(id))
		if err != nil {
			return nil
		}

		return view.NodeView(e.Node())
	}
	evaluators := make([]xpath.Evaluator, len(program))
	order := xpath.NewDocOrderCache()

	for i := range program {
		functions := map[string]xpath.Function{"here": hereFunction(t.XPath[i].Here, view), "id": idFunction(resolve, min(p.nodes, 65536))}
		evaluators[i] = program[i].evaluator.Functions(functions, nil).DocOrderCache(order)
	}

	var kept []document.Node

	if t.Algorithm == reference.XPath {
		kept, err = applyXPathNodes(ctx, set.Nodes(), program[0].expression, evaluators[0], view)
	} else {
		kept, err = applyFilter2Nodes(ctx, t.XPath, program, evaluators, view, set)
	}

	if err != nil {
		return reference.Data{}, err
	}

	if err = ctx.Err(); err != nil {
		return reference.Data{}, err
	}

	out, err := document.NewNodeSet(doc, kept...)
	if err != nil {
		return reference.Data{}, err
	}

	return reference.Nodes(out)
}

func idFunction(resolve func(string) xdm.Node, maxTokens int) xpath.Function {
	return v1Function{1, 1, func(ctx context.Context, args []xdm.Sequence) (xdm.Sequence, error) {
		values, err := idArgumentValues(ctx, args[0])
		if err != nil {
			return nil, err
		}

		return resolveIDValues(ctx, values, resolve, maxTokens)
	}}
}

func idArgumentValues(ctx context.Context, argument xdm.Sequence) ([]string, error) {
	if argument == nil {
		return nil, nil
	}

	var values []string

	for item := range argument.Items() {
		if err := xpath.Charge(ctx, 1); err != nil {
			return nil, err
		}

		node, isNode := item.(xdm.NodeItem)

		var value string

		if isNode {
			value = xdm.CharacterData(node.Node)
		} else {
			var err error

			value, err = xpath.XPath10String(xdm.ItemSlice{item})
			if err != nil {
				return nil, err
			}
		}

		if err := xpath.ChargeString(ctx, len(value)); err != nil {
			return nil, err
		}

		values = append(values, value)

		if !isNode {
			break
		}
	}

	return values, nil
}

func resolveIDValues(ctx context.Context, values []string, resolve func(string) xdm.Node, maxTokens int) (xdm.Sequence, error) {
	seen := map[xdm.Node]bool{}

	var out xdm.ItemSlice

	tokens := 0

	for _, value := range values {
		for id := range strings.FieldsFuncSeq(value, func(r rune) bool { return r == ' ' || r == '\t' || r == '\r' || r == '\n' }) {
			tokens++
			if tokens > maxTokens {
				return nil, reference.ErrLimit
			}

			if err := xpath.Charge(ctx, 1); err != nil {
				return nil, err
			}

			n := resolve(id)
			if n != nil && !seen[n] {
				seen[n] = true
				out = append(out, xdm.NodeItem{Node: n})
			}
		}
	}

	return xpath.XPath10Value(ctx, out)
}

func applyXPathNodes(ctx context.Context, nodes []document.Node, expression *xpath.Expression, evaluator xpath.Evaluator, view *xdm.Document) ([]document.Node, error) {
	// XPath 1.0 cannot return closures or retain evaluation state. Each
	// boolean is consumed before the next node, within this invocation.
	state := evaluator.NewEvalState(nil)

	var kept []document.Node

	for _, node := range nodes {
		result, err := expression.EvaluateReuse(ctx, state, view.NodeView(node))
		if err != nil {
			return nil, executionError(err)
		}

		keep, err := result.EBV()
		if err != nil {
			return nil, executionError(err)
		}

		if keep {
			kept = append(kept, node)
		}
	}

	return kept, nil
}

func applyFilter2Nodes(ctx context.Context, expressions []reference.XPathExpression, program []compiled, evaluators []xpath.Evaluator, view *xdm.Document, set document.NodeSet) ([]document.Node, error) {
	filters := make([]filterSelection, len(program))

	for i := range program {
		result, err := evaluators[i].Evaluate(ctx, program[i].expression, view.NodeView(set.Document().Node()))
		if err != nil {
			return nil, executionError(err)
		}

		if !result.IsNodeSet() {
			return nil, fmt.Errorf("%w: Filter2 requires a node-set", reference.ErrInput)
		}

		selected, err := result.Nodes()
		if err != nil {
			return nil, executionError(err)
		}

		roots := make(map[document.Node]bool, len(selected))
		for _, node := range selected {
			roots[node.Reference()] = true
		}

		filters[i] = filterSelection{expressions[i].Filter, roots}
	}

	kept, err := filterNodes(ctx, set.Nodes(), filters)
	if err != nil {
		return nil, executionError(err)
	}

	return kept, nil
}

func (p *v1Processor) approved(ctx context.Context, t reference.Transform) ([]compiled, error) {
	if ctx == nil {
		return nil, reference.ErrInput
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	if !reference.IsExtension(t.Algorithm) {
		return nil, reference.ErrUnsupported
	}

	if p == nil || len(p.programs)+len(p.stylesheets) == 0 {
		return nil, reference.ErrPolicy
	}

	key, err := reference.ProgramFingerprint(t)
	if err != nil {
		return nil, err
	}

	if t.Algorithm == reference.XSLT {
		if _, ok := p.stylesheets[key]; !ok {
			return nil, fmt.Errorf("%w: stylesheet is not approved", reference.ErrPolicy)
		}

		return nil, nil
	}

	program, ok := p.programs[key]
	if !ok {
		return nil, fmt.Errorf("%w: transform program is not approved", reference.ErrPolicy)
	}

	return program, nil
}

func hereFunction(here document.Element, doc *xdm.Document) xpath.Function {
	return v1Function{0, 0, func(ctx context.Context, args []xdm.Sequence) (xdm.Sequence, error) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		if doc == nil || !here.Valid() || here.Node().Document() != doc.Snapshot() {
			return nil, fmt.Errorf("%w: here() requires its original expression element", reference.ErrInput)
		}

		return xdm.ItemSlice{xdm.NodeItem{Node: doc.NodeView(here.Node())}}, nil
	}}
}

func executionError(err error) error {
	if err == nil {
		return nil
	}

	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) || errors.Is(err, reference.ErrPolicy) || errors.Is(err, reference.ErrInput) {
		return err
	}

	if errors.Is(err, xpath.ErrBudget) || errors.Is(err, xpath.ErrNodeSetLimit) || errors.Is(err, xpath.ErrOpLimit) || errors.Is(err, xpath.ErrRecursionLimit) || errors.Is(err, document.ErrLimit) {
		return fmt.Errorf("%w: %w", reference.ErrLimit, err)
	}

	return fmt.Errorf("%w: XPath: %w", reference.ErrInput, err)
}

type v1Function struct {
	min, max int
	call     func(context.Context, []xdm.Sequence) (xdm.Sequence, error)
}

func (f v1Function) MinArity() int { return f.min }

func (f v1Function) MaxArity() int { return f.max }

func (f v1Function) Call(ctx context.Context, args []xdm.Sequence) (xdm.Sequence, error) {
	return f.call(ctx, args)
}
