package reference

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"io"
	"iter"
	"slices"

	"github.com/skarm/xmlsec/c14n"
	"github.com/skarm/xmlsec/internal/streamio"
	"github.com/skarm/xmlsec/internal/tree"
)

type transformPipeline struct {
	processor *processor
	ctx       context.Context
	value     Data
	reader    *streamio.Reader
	closers   []io.Closer
	finalize  []func()
}

func (p *transformPipeline) input(src io.Reader, limit int) *streamio.Reader {
	return &streamio.Reader{Context: p.ctx, Source: src, Limit: int64(limit), LimitError: ErrLimit}
}

func (p *transformPipeline) run(dst io.Writer, transforms []Transform) (*Report, error) {
	defer func() {
		for _, v := range slices.Backward(p.closers) {
			_ = v.Close()
		}
	}()

	for i, tr := range transforms {
		var err error

		switch {
		case tr.Algorithm == Base64:
			err = p.base64(tr, i)
		case isC14N(tr.Algorithm):
			err = p.nodes(i, tr.Algorithm)
			if err == nil {
				err = p.canonical(tr, false, i)
			}
		case tr.Algorithm == XSLT:
			err = p.xslt(tr, i)
		default:
			err = p.nodes(i, tr.Algorithm)
			if err == nil {
				p.value, err = p.processor.apply(p.ctx, p.value, tr)
			}
		}

		if err != nil {
			return nil, pipelineError(i, tr.Algorithm, err)
		}
	}

	if p.value.kind == NodeSet {
		if !allowed(p.processor.opt, c14n.Canonical10) {
			return nil, &StepError{-1, c14n.Canonical10, ErrPolicy}
		}

		if err := p.canonical(Transform{Algorithm: c14n.Canonical10}, true, -1); err != nil {
			return nil, err
		}
	}

	target := dst
	if len(transforms) == 0 && len(p.processor.out.steps) == 0 {
		target = &producedWriter{processor: p.processor, dst: dst}
	}

	writer := streamio.Writer{Context: p.ctx, Target: target, Limit: int64(p.processor.opt.MaxOutputBytes), LimitError: ErrLimit}

	if _, err := io.Copy(&writer, p.reader); err != nil {
		index, algorithm := -1, "digest-input"
		if len(transforms) > 0 {
			index = len(transforms) - 1
			algorithm = transforms[index].Algorithm
		}

		return nil, pipelineError(index, algorithm, err)
	}

	p.finishSteps()
	p.processor.out.size = int(writer.Written)

	return p.processor.completed(p.ctx)
}

func (p *transformPipeline) finishSteps() {
	for _, finish := range p.finalize {
		finish()
	}

	p.finalize = nil
}

func (p *transformPipeline) nodes(index int, algorithm string) error {
	if p.value.kind == NodeSet {
		return nil
	}

	value, err := p.processor.parseReader(p.ctx, p.reader)
	if err != nil {
		return pipelineError(index, algorithm, err)
	}

	p.finishSteps()
	p.value = value
	p.reader = nil

	return nil
}

func (p *transformPipeline) step(tr Transform, inputKind Kind, inputSize func() int, output *streamio.Reader, implicit bool) {
	state := p.processor
	slot := len(state.out.steps)
	state.out.steps = append(state.out.steps, Step{Algorithm: tr.Algorithm, InputKind: inputKind, OutputKind: OctetStream, Implicit: implicit})
	p.finalize = append(p.finalize, func() {
		state.out.steps[slot].InputSize = inputSize()
		state.out.steps[slot].OutputSize = int(output.ReadBytes)
	})
}

func (p *transformPipeline) base64(tr Transform, index int) error {
	kind := p.value.kind

	var size func() int

	if kind == NodeSet {
		data := p.value

		inputSize := data.Size()
		if err := p.processor.visit(data); err != nil {
			return err
		}

		size = func() int { return inputSize }
		p.reader = p.input(&nodeTextReader{ctx: p.ctx, nodes: data.nodes, pending: [][]*tree.Node{tree.Children(data.nodes.Document())}}, p.processor.opt.MaxInputBytes)
	} else {
		input := p.reader
		size = func() int { return int(input.ReadBytes) }
	}

	decoded := decodedBase64{base64.NewDecoder(base64.StdEncoding, &base64Reader{source: p.reader})}
	output := p.input(&producedInput{processor: p.processor, src: decoded, index: index, algorithm: Base64}, p.processor.opt.MaxOutputBytes)
	output.LimitError = &StepError{index, Base64, ErrLimit}
	p.step(tr, kind, size, output, false)
	p.value = Data{kind: OctetStream}
	p.reader = output
	p.processor.out.canonicalization = ""

	return nil
}

func (p *transformPipeline) generated(produce func(io.Writer) error) *streamio.Reader {
	source := readTransform(p.ctx, func(dst io.Writer) error {
		writer := streamio.Writer{Context: p.ctx, Target: &producedWriter{processor: p.processor, dst: dst}, Limit: int64(p.processor.opt.MaxOutputBytes), LimitError: ErrLimit}
		return produce(&writer)
	})
	p.closers = append(p.closers, source)

	return p.input(source, p.processor.opt.MaxOutputBytes)
}

// readTransform connects a writer-based transform to the next stage's reader.
// Each pull resumes production only until the next borrowed chunk. Close unwinds
// a suspended transform and its deferred cleanup without concurrent execution.
func readTransform(ctx context.Context, produce func(io.Writer) error) io.ReadCloser {
	sequence := func(yield func([]byte, error) bool) {
		writer := yieldWriter{ctx: ctx, yield: yield}
		if err := produce(&writer); err != nil && !writer.stopped {
			yield(nil, err)
		}
	}
	next, stop := iter.Pull2(sequence)

	return &producedReader{ctx: ctx, next: next, stop: stop}
}

func (p *transformPipeline) canonical(tr Transform, implicit bool, index int) error {
	data := p.value

	inputSize := data.Size()
	if err := p.processor.visit(data); err != nil {
		return err
	}

	output := p.generated(func(dst io.Writer) error {
		err := c14n.WriteNodeSet(p.ctx, dst, data.nodes, c14n.Options{Algorithm: tr.Algorithm, InclusivePrefixes: tr.InclusivePrefixes, MaxOutputBytes: p.processor.opt.MaxOutputBytes})
		if err != nil {
			return pipelineError(index, tr.Algorithm, err)
		}

		return nil
	})
	p.step(tr, NodeSet, func() int { return inputSize }, output, implicit)
	p.value = Data{kind: OctetStream}
	p.reader = output
	p.processor.out.canonicalization = tr.Algorithm

	return nil
}

func (p *transformPipeline) xslt(tr Transform, index int) error {
	if p.value.kind == NodeSet {
		if !allowed(p.processor.opt, c14n.Canonical10) {
			return ErrPolicy
		}

		if err := p.canonical(Transform{Algorithm: c14n.Canonical10}, true, index); err != nil {
			return err
		}
	}

	input := p.reader

	extension, ok := p.processor.opt.Extension.(ReaderExtensionProcessor)
	if !ok {
		// Extensions without reader support receive a bounded complete input.
		var buffer bytes.Buffer
		if _, err := io.Copy(&buffer, input); err != nil {
			return err
		}

		p.finishSteps()

		value, err := p.processor.apply(p.ctx, Data{kind: OctetStream, octets: buffer.Bytes()}, tr)
		if err != nil {
			return err
		}

		p.value = value
		p.reader = p.input(bytes.NewReader(p.value.octets), p.processor.opt.MaxOutputBytes)

		return nil
	}

	output := p.generated(func(dst io.Writer) error {
		err := extension.WriteTransform(p.ctx, dst, input, tr, ExtensionContext{Signature: p.processor.opt.Signature, IDRules: cloneRules(p.processor.opt.IDRules)})
		if err == nil {
			_, err = io.Copy(io.Discard, input)
		}

		if err != nil {
			return pipelineError(index, tr.Algorithm, err)
		}

		return nil
	})
	p.step(tr, OctetStream, func() int { return int(input.ReadBytes) }, output, false)
	p.value = Data{kind: OctetStream}
	p.reader = output
	p.processor.out.canonicalization = ""

	return nil
}

func pipelineError(index int, algorithm string, err error) error {
	if _, ok := errors.AsType[*StepError](err); ok {
		return err
	}

	return &StepError{index, algorithm, err}
}

type producedInput struct {
	processor *processor
	src       io.Reader
	index     int
	algorithm string
}

func (r *producedInput) Read(dst []byte) (int, error) {
	n, err := r.src.Read(dst)
	if n > 0 {
		if budgetErr := r.processor.produce(n); budgetErr != nil {
			return 0, pipelineError(r.index, r.algorithm, budgetErr)
		}
	}

	if err != nil && !errors.Is(err, io.EOF) {
		err = pipelineError(r.index, r.algorithm, err)
	}

	return n, err
}

type producedWriter struct {
	processor *processor
	dst       io.Writer
}

func (w *producedWriter) Write(p []byte) (int, error) {
	if err := w.processor.produce(len(p)); err != nil {
		return 0, err
	}

	return w.dst.Write(p)
}

type yieldWriter struct {
	ctx     context.Context
	yield   func([]byte, error) bool
	stopped bool
}

func (w *yieldWriter) Write(p []byte) (int, error) {
	if err := w.ctx.Err(); err != nil {
		return 0, err
	}

	if len(p) == 0 {
		return 0, nil
	}

	if !w.yield(p, nil) {
		w.stopped = true
		return 0, io.ErrClosedPipe
	}

	return len(p), nil
}

type producedReader struct {
	ctx     context.Context
	next    func() ([]byte, error, bool)
	stop    func()
	pending []byte
	closed  bool
}

func (r *producedReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}

	if len(p) == 0 {
		return 0, nil
	}

	if r.closed {
		return 0, io.EOF
	}

	if len(r.pending) == 0 {
		chunk, err, ok := r.next()
		if err != nil || !ok {
			_ = r.Close()

			if err != nil {
				return 0, err
			}

			return 0, io.EOF
		}

		r.pending = chunk
	}

	n := copy(p, r.pending)
	r.pending = r.pending[n:]

	return n, nil
}

func (r *producedReader) Close() error {
	if !r.closed {
		r.closed = true
		r.pending = nil
		stop := r.stop
		r.stop = nil
		r.next = nil

		stop()
	}

	return nil
}
