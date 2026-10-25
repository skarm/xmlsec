package reference

import (
	"bytes"
	"context"
	"fmt"
	"io"

	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/internal/lexicon"
	"github.com/skarm/xmlsec/internal/nilcheck"
	"github.com/skarm/xmlsec/internal/tree"
)

// Process validates and approves the complete transform chain before executing it.
// It never returns a partial Output on error or mutates its inputs. Built-ins
// do not fetch resources; an ExtensionProcessor is a trusted execution boundary.
// Calls may run concurrently if the extension supports it. Callers must not
// mutate input options or transform slices concurrently with the call.
func Process(ctx context.Context, input Data, transforms []Transform, opt Options) (*Output, error) {
	var buffer bytes.Buffer

	report, err := Write(ctx, &buffer, input, transforms, opt)
	if err != nil {
		return nil, err
	}

	return &Output{report: report, bytes: buffer.Bytes()}, nil
}

// Write processes a transform chain into dst. The final canonicalization streams
// directly to dst, including a hash.Hash, without retaining canonical bytes.
// Base64 chains and intermediate canonical bytes are passed incrementally. XML
// processing retains trees; extensions without ReaderExtensionProcessor require
// complete intermediate octets. On error dst may contain a prefix; no successful
// report is returned.
func Write(ctx context.Context, dst io.Writer, input Data, transforms []Transform, opt Options) (*Report, error) {
	if nilcheck.IsNil(dst) {
		return nil, ErrInput
	}

	if ctx == nil {
		return nil, fmt.Errorf("%w: nil context", ErrInput)
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	var err error

	opt, err = normalize(opt)
	if err != nil {
		return nil, err
	}

	transforms, err = snapshotTransforms(ctx, transforms, opt)
	if err != nil {
		return nil, err
	}

	if input.kind != OctetStream && (input.kind != NodeSet || !input.nodes.Valid()) {
		return nil, ErrInput
	}

	if input.kind == OctetStream && len(input.octets) > opt.MaxInputBytes {
		return nil, fmt.Errorf("%w: input bytes", ErrLimit)
	}

	state := processor{opt: opt, out: Report{input: input.kind}}
	if err := state.visit(input); err != nil {
		return nil, err
	}

	return state.run(ctx, dst, input, transforms)
}

type processor struct {
	opt Options
	out Report
}

func (p *processor) run(ctx context.Context, dst io.Writer, input Data, transforms []Transform) (*Report, error) {
	pipeline := transformPipeline{processor: p, ctx: ctx, value: input}
	if input.kind == OctetStream {
		pipeline.reader = pipeline.input(bytes.NewReader(input.octets), p.opt.MaxInputBytes)
	}

	return pipeline.run(dst, transforms)
}

func (p *processor) visit(d Data) error {
	if d.kind == NodeSet {
		n := d.nodes.Len()
		if n > p.opt.MaxNodeVisits-p.out.visits {
			return fmt.Errorf("%w: node visits", ErrLimit)
		}

		p.out.visits += n
	}

	return nil
}

func (p *processor) capacity() int {
	return min(p.opt.MaxOutputBytes, p.opt.MaxProducedBytes-p.out.produced)
}

func (p *processor) produce(n int) error {
	if n > p.capacity() {
		return fmt.Errorf("%w: produced bytes", ErrLimit)
	}

	p.out.produced += n

	return nil
}

func (p *processor) apply(ctx context.Context, in Data, tr Transform) (Data, error) {
	if err := ctx.Err(); err != nil {
		return Data{}, err
	}

	if err := p.visit(in); err != nil {
		return Data{}, err
	}

	var (
		out Data
		err error
	)

	switch tr.Algorithm {
	case XPath, XPathFilter2, XSLT:
		out, err = p.opt.Extension.Apply(ctx, tr, in, ExtensionContext{Signature: p.opt.Signature, IDRules: cloneRules(p.opt.IDRules)})
		if err != nil {
			return Data{}, err
		}

		if err = ctx.Err(); err != nil {
			return Data{}, err
		}

		if err := p.validateExtensionOutput(ctx, tr.Algorithm, in, out); err != nil {
			return Data{}, err
		}

		p.out.canonicalization = ""
	case EnvelopedSignature:
		signature := p.opt.Signature
		if !signature.Valid() || signature.Name() != (document.Name{Space: lexicon.NamespaceDSig, Local: "Signature"}) || signature.Node().Document() != in.nodes.Document() {
			return Data{}, fmt.Errorf("%w: enveloped transform requires its containing Signature in the SAME snapshot", ErrInput)
		}

		set, err := tree.FilterNodeSet(ctx, in.nodes, func(n document.Node) bool { return !tree.NodeWithin(n, signature) })
		if err != nil {
			return Data{}, err
		}

		out, _ = Nodes(set)
		p.out.canonicalization = ""
	default:
		return Data{}, ErrUnsupported
	}

	p.out.steps = append(p.out.steps, Step{Algorithm: tr.Algorithm, InputKind: in.kind, OutputKind: out.kind, InputSize: in.Size(), OutputSize: out.Size()})

	return out, nil
}

func (p *processor) validateExtensionOutput(ctx context.Context, algorithm string, in, out Data) error {
	if algorithm == XSLT {
		if out.kind != OctetStream {
			return fmt.Errorf("%w: XSLT output kind", ErrInput)
		}

		return p.produce(out.Size())
	}

	if out.kind != NodeSet || !out.nodes.Valid() || out.nodes.Document() != in.nodes.Document() {
		return fmt.Errorf("%w: foreign XPath output", ErrInput)
	}

	subset, err := tree.IsNodeSetSubset(ctx, out.nodes, in.nodes)
	if err != nil {
		return err
	}

	if !subset {
		return fmt.Errorf("%w: XPath added input-excluded node", ErrInput)
	}

	return p.visit(out)
}
