package transform

import (
	"context"
	"errors"
	"io"
	"maps"
	"slices"

	"github.com/skarm/xmlsec/internal/nilcheck"
	"github.com/skarm/xmlsec/internal/streamio"
	"github.com/skarm/xmlsec/transform/internal/xdm"
	"github.com/skarm/xmlsec/transform/internal/xslt"
)

// Result is a complete immutable XSLT result before serialization. It supports
// concurrent reads and reuse as XPath/XSLT input without an XML round trip.
type Result struct {
	engine    *Engine
	native    *xslt.Execution
	primary   Sequence
	secondary map[string]Sequence
	messages  []Message
}

// Primary returns the primary XDM sequence, preserving order and atomic types.
func (r *Result) Primary() Sequence {
	if r == nil {
		return Sequence{}
	}

	return r.primary
}

// Secondary returns an owned map of immutable secondary result sequences.
func (r *Result) Secondary() map[string]Sequence {
	out := make(map[string]Sequence)
	if r != nil {
		maps.Copy(out, r.secondary)
	}

	return out
}

// Messages returns an owned copy of xsl:message diagnostics.
func (r *Result) Messages() []Message {
	if r == nil {
		return nil
	}

	return slices.Clone(r.messages)
}

// OutputEncoding returns the effective encoding name for the primary result
// (empty uri) or a named secondary result. An omitted encoding defaults to UTF-8.
// Adaptive output ignores the encoding parameter and uses UTF-8.
// It reads the completed output definition without serializing or validating it.
func (r *Result) OutputEncoding(uri string) (string, error) {
	if r == nil || r.native == nil {
		return "", wrap("output encoding", ErrInput)
	}

	value := r.native.Primary

	if uri != "" {
		var ok bool

		value, ok = r.native.Secondary[uri]
		if !ok {
			return "", wrap("output encoding", ErrInput)
		}
	}

	if value.Output == nil || value.Output.Encoding == "" || value.Output.Method == "adaptive" {
		return "UTF-8", nil
	}

	return value.Output.Encoding, nil
}

// Serialize applies the stylesheet's output definitions to a successful result.
// Serialization has its own invocation budget and collects primary/secondary
// bytes. Message and serialized bytes share MaxOutputBytes. It produces no
// partial Output on error; the Result and collected output coexist in memory.
func (r *Result) Serialize(ctx context.Context) (*Output, error) {
	if r == nil || r.native == nil {
		return nil, wrap("serialize XSLT", ErrInput)
	}

	ctx, cancel, err := r.engine.invocation(ctx)
	if err != nil {
		return nil, wrap("serialize XSLT", err)
	}
	defer cancel()

	out := &Output{Secondary: make(map[string][]byte), Messages: r.Messages()}

	used := 0
	for _, msg := range out.Messages {
		used += len(msg.Text)
	}

	serialize := func(v xslt.ValueResult) ([]byte, error) {
		writer := boundedBuffer{ctx: ctx, limit: r.engine.limits.MaxOutputBytes - used}
		if err := xslt.SerializeValue(ctx, &writer, v); err != nil {
			return nil, xsltError("serialize XSLT", err)
		}

		used += writer.Len()

		return writer.Bytes(), nil
	}
	if out.Primary, err = serialize(r.native.Primary); err != nil {
		return nil, err
	}

	for uri, value := range r.native.Secondary {
		if out.Secondary[uri], err = serialize(value); err != nil {
			return nil, err
		}
	}

	return out, nil
}

// WriterTo returns an io.WriterTo that serializes the primary result under ctx.
// Each WriteTo call uses a fresh serialization budget and returns the byte count,
// including partial output on error. Common XML, HTML, text and JSON output paths
// write incrementally, including stateful encoding conversion. Ordinary XML
// nodes embedded in JSON and large unmapped adaptive strings without quote
// characters avoid complete serialized copies. XHTML, other JSON node methods, mapped/normalized adaptive
// values, disable-output-escaping and FULLY-NORMALIZED may build an extra tree
// or a buffer as large as the result. These paths are selected automatically.
// The complete Result remains in memory; collecting destinations retain output too.
// The destination remains caller-owned; ctx must be non-nil and cannot interrupt
// an arbitrary blocked Write.
func (r *Result) WriterTo(ctx context.Context) io.WriterTo {
	return resultWriterTo{result: r, ctx: ctx}
}

// WriteSecondary serializes one named secondary result with the same storage
// and partial-output behavior as WriterTo. The destination remains caller-owned.
func (r *Result) WriteSecondary(ctx context.Context, uri string, dst io.Writer) (int64, error) {
	if r == nil || r.native == nil {
		return 0, wrap("write secondary XSLT", ErrInput)
	}

	value, ok := r.native.Secondary[uri]
	if !ok {
		return 0, wrap("write secondary XSLT", ErrInput)
	}

	return r.writeValue(ctx, dst, value)
}

// Document converts a single document or element result to a complete XML
// snapshot. An element is copied with its in-scope namespaces; unrelated nodes
// in its owner document are excluded. No XML is serialized or reparsed.
func (r *Result) Document(ctx context.Context) (*Document, error) {
	if r == nil || r.engine == nil {
		return nil, wrap("result document", ErrInput)
	}

	ctx, cancel, err := r.engine.invocation(ctx)
	if err != nil {
		return nil, wrap("result document", err)
	}
	defer cancel()

	value, err := r.Primary().Single()
	if err != nil {
		return nil, err
	}

	node, ok := value.Node()
	if !ok || node.native.Type() != xdm.DocumentNode && node.native.Type() != xdm.ElementNode {
		return nil, wrap("result document", ErrInput)
	}

	doc := node.Document()
	if element, ok := node.native.(*xdm.Element); ok {
		native, err := xdm.ElementDocument(ctx, element)
		if err != nil {
			return nil, wrap("result document", err)
		}

		doc = &Document{native: native}
	}

	if _, err := r.engine.Export(ctx, doc); err != nil {
		return nil, err
	}

	return doc, nil
}

func (r *Result) writeValue(ctx context.Context, dst io.Writer, value xslt.ValueResult) (int64, error) {
	if nilcheck.IsNil(dst) {
		return 0, wrap("write XSLT", ErrInput)
	}

	ctx, cancel, err := r.engine.invocation(ctx)
	if err != nil {
		return 0, err
	}
	defer cancel()

	writer := streamio.Writer{Context: ctx, Target: dst, Limit: int64(r.engine.limits.MaxOutputBytes), LimitError: ErrLimit}

	err = xslt.SerializeValue(ctx, &writer, value)
	if err == nil {
		err = ctx.Err()
	}

	return writer.Written, xsltError("write XSLT", err)
}

// Execute runs the selected template or mode and returns typed XDM results.
func (s *Stylesheet) Execute(ctx context.Context, d *Document, options XSLTContext) (_ *Result, returnedErr error) {
	ctx, cancel, invocation, collector, err := s.prepare(ctx, d, options)
	if err != nil {
		return nil, err
	}
	defer cancel()
	defer func() {
		if failure, ok := errors.AsType[*Error](returnedErr); ok {
			failure.messages = slices.Clone(collector.output.Messages)
		}
	}()

	execution, err := invocation.Execute(ctx)
	if err != nil {
		return nil, xsltError("execute XSLT", err)
	}

	if options.ResultMode != ResultRaw {
		var forceTree *bool

		if options.ResultMode == ResultDocument {
			value := true
			forceTree = &value
		}

		execution, err = xslt.NormalizeExecution(ctx, execution, forceTree, options.BaseOutputURI)
		if err != nil {
			return nil, xsltError("normalize XSLT", err)
		}
	}

	publication := nodePublication{ctx: ctx, limits: s.engine.limits}
	if err := publication.visit(execution.Primary.Items, 0); err != nil {
		return nil, wrap("execute XSLT", err)
	}

	for _, output := range execution.Secondary {
		if err := publication.visit(output.Items, 0); err != nil {
			return nil, wrap("execute XSLT", err)
		}
	}

	for _, node := range publication.nodes {
		xdm.PublishNode(node)
	}

	checker := sequenceChecker{ctx: ctx, limits: s.engine.limits}
	if err := checker.walk(execution.Primary.Items, 0); err != nil {
		return nil, wrap("execute XSLT", err)
	}

	result := &Result{engine: s.engine, native: execution, primary: ownSequence(execution.Primary.Items), secondary: make(map[string]Sequence), messages: slices.Clone(collector.output.Messages)}
	for uri, output := range execution.Secondary {
		if err := checker.walk(output.Items, 0); err != nil {
			return nil, wrap("execute XSLT", err)
		}

		result.secondary[uri] = ownSequence(output.Items)
	}

	return result, nil
}

// ApplyTemplates applies the initial mode to an explicit selection. An empty
// sequence selects no items, rather than falling back to the source document.
func (s *Stylesheet) ApplyTemplates(ctx context.Context, d *Document, selection Sequence, options XSLTContext) (*Result, error) {
	options.selection = &selection
	return s.Execute(ctx, d, options)
}

// CallTemplate invokes a named template with global, initial and tunnel parameters.
func (s *Stylesheet) CallTemplate(ctx context.Context, d *Document, name Name, options XSLTContext) (*Result, error) {
	if name.Local == "" || options.Template.Local != "" || options.Mode.Local != "" {
		return nil, wrap("call template", ErrInput)
	}

	options.Template = name

	return s.Execute(ctx, d, options)
}

// CallFunction invokes a public stylesheet function with typed arguments.
func (s *Stylesheet) CallFunction(ctx context.Context, d *Document, name Name, arguments []Sequence, options XSLTContext) (*Result, error) {
	if name.Local == "" {
		return nil, wrap("call function", ErrInput)
	}

	options.function, options.arguments = name, arguments

	return s.Execute(ctx, d, options)
}

type resultWriterTo struct {
	result *Result
	ctx    context.Context
}

func (w resultWriterTo) WriteTo(dst io.Writer) (int64, error) {
	r := w.result
	if r == nil || r.native == nil {
		return 0, wrap("write XSLT", ErrInput)
	}

	return r.writeValue(w.ctx, dst, r.native.Primary)
}

type nodePublication struct {
	ctx    context.Context
	limits Limits
	count  int
	nodes  []xdm.Node
	seen   map[xdm.Node]struct{}
}

func (p *nodePublication) visit(items xdm.Sequence, depth int) error {
	if err := p.ctx.Err(); err != nil {
		return err
	}

	if depth > p.limits.MaxDepth || xdm.SequenceLen(items) > p.limits.MaxNodes-p.count {
		return ErrLimit
	}

	p.count += xdm.SequenceLen(items)
	for item := range xdm.SequenceItems(items) {
		switch v := item.(type) {
		case xdm.NodeItem:
			if p.seen == nil {
				p.seen = make(map[xdm.Node]struct{})
			}

			if _, published := p.seen[v.Node]; !published {
				p.seen[v.Node] = struct{}{}
				p.nodes = append(p.nodes, v.Node)
			}
		case xdm.MapItem:
			if err := v.ForEachView(func(_ xdm.AtomicValue, value xdm.Sequence) error { return p.visit(value, depth+1) }); err != nil {
				return err
			}
		case xdm.ArrayItem:
			for _, value := range v.MembersView() {
				if err := p.visit(value, depth+1); err != nil {
					return err
				}
			}
		}
	}

	return nil
}
