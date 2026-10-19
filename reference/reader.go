package reference

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"

	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/internal/nilcheck"
	"github.com/skarm/xmlsec/internal/streamio"
	"github.com/skarm/xmlsec/internal/tree"
)

// WriteReader processes octets from src and writes the transformed bytes to dst.
// Raw and compound Base64 chains use bounded working buffers. Canonicalization
// passes its bytes directly to subsequent stages. XML transforms retain a tree;
// extensions without ReaderExtensionProcessor require complete intermediate octets.
// The entire chain is approved before reading. src and dst remain caller-owned;
// on error dst may contain a prefix and no successful report is returned.
// ReaderExtensionProcessor does not itself guarantee bounded working memory:
// extension implementations control their own buffering and execution storage.
func WriteReader(ctx context.Context, dst io.Writer, src io.Reader, transforms []Transform, opt Options) (*Report, error) {
	if ctx == nil || nilcheck.IsNil(dst) || nilcheck.IsNil(src) {
		return nil, ErrInput
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	opt, err := normalize(opt)
	if err != nil {
		return nil, err
	}

	transforms, err = snapshotTransforms(ctx, transforms, opt)
	if err != nil {
		return nil, err
	}

	state := processor{opt: opt, out: Report{input: OctetStream}}
	pipeline := transformPipeline{processor: &state, ctx: ctx, value: Data{kind: OctetStream}}
	pipeline.reader = pipeline.input(src, opt.MaxInputBytes)

	return pipeline.run(dst, transforms)
}

func (p *processor) parseReader(ctx context.Context, src *streamio.Reader) (Data, error) {
	limits := p.opt.XMLLimits
	limits.MaxBytes = min(limits.MaxBytes, p.opt.MaxInputBytes)

	doc, err := document.ParseReader(ctx, src, limits)
	if err != nil {
		return Data{}, fmt.Errorf("%w: XML conversion: %w", ErrInput, err)
	}

	nodes, err := doc.AllNodes(ctx)
	if err != nil {
		return Data{}, err
	}

	data, err := Nodes(nodes)
	if err != nil {
		return Data{}, err
	}

	if err := p.visit(data); err != nil {
		return Data{}, err
	}

	p.out.steps = append(p.out.steps, Step{Algorithm: ParseXML, InputKind: OctetStream, OutputKind: NodeSet, InputSize: int(src.ReadBytes), OutputSize: nodes.Len(), Implicit: true})

	return data, nil
}

func (p *processor) completed(ctx context.Context) (*Report, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	return &p.out, nil
}

type base64Reader struct {
	source io.Reader
	buffer [4096]byte
}

func (r *base64Reader) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}

	for {
		n, err := r.source.Read(r.buffer[:min(len(p), len(r.buffer))])
		out := 0

		for _, c := range r.buffer[:n] {
			if c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '+' || c == '/' || c == '=' {
				p[out] = c
				out++
			}
		}

		if out > 0 || err != nil {
			return out, err
		}
	}
}

type decodedBase64 struct{ io.Reader }

func (r decodedBase64) Read(p []byte) (int, error) {
	n, err := r.Reader.Read(p)
	if err == nil || errors.Is(err, io.EOF) {
		return n, err
	}

	var corrupt base64.CorruptInputError
	if errors.Is(err, io.ErrUnexpectedEOF) || errors.As(err, &corrupt) {
		err = fmt.Errorf("%w: base64: %w", ErrInput, err)
	}

	return n, err
}

// nodeTextReader supplies the XMLDSig Base64 node-set input in document order.
// It borrows each text node instead of concatenating the complete selection.
type nodeTextReader struct {
	ctx     context.Context
	nodes   document.NodeSet
	pending [][]*tree.Node
	text    string
}

func (r *nodeTextReader) Read(dst []byte) (int, error) {
	if len(dst) == 0 {
		return 0, nil
	}

	for len(r.text) == 0 {
		if err := r.ctx.Err(); err != nil {
			return 0, err
		}

		if len(r.pending) == 0 {
			return 0, io.EOF
		}

		last := len(r.pending) - 1
		if len(r.pending[last]) == 0 {
			r.pending = r.pending[:last]
			continue
		}

		node := r.pending[last][0]

		r.pending[last] = r.pending[last][1:]
		if node.Kind == tree.ElementNode && len(node.Children) != 0 {
			r.pending = append(r.pending, node.Children)
		}

		if node.Kind == tree.TextNode && r.nodes.Contains(tree.WrapNode(r.nodes.Document(), node)) {
			r.text = node.Data
		}
	}

	n := copy(dst, r.text)
	r.text = r.text[n:]

	return n, nil
}
