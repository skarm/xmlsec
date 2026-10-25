package transform

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"sync"

	"github.com/skarm/xmlsec/internal/nilcheck"
	"github.com/skarm/xmlsec/resource"
	"github.com/skarm/xmlsec/transform/internal/xdm"
	"github.com/skarm/xmlsec/transform/internal/xpath"
)

type boundedBuffer struct {
	bytes.Buffer
	ctx   context.Context
	limit int
}

func (b *boundedBuffer) Write(p []byte) (int, error) {
	if err := b.ctx.Err(); err != nil {
		return 0, err
	}

	if len(p) > b.limit-b.Len() {
		return 0, ErrLimit
	}

	return b.Buffer.Write(p)
}

// WriteString enforces the byte bound when writing a string, overriding
// bytes.Buffer.WriteString.
func (b *boundedBuffer) WriteString(s string) (int, error) {
	if err := b.ctx.Err(); err != nil {
		return 0, err
	}

	if len(s) > b.limit-b.Len() {
		return 0, ErrLimit
	}

	return b.Buffer.WriteString(s)
}

type resourceAdapter struct {
	engine *Engine
}

func (a resourceAdapter) Resolve(ctx context.Context, uri string) (io.ReadCloser, error) {
	if a.engine.resolver == nil {
		return nil, fmt.Errorf("%w: %s", ErrResource, uri)
	}

	return a.engine.openResource(ctx, a.engine.limits.MaxInputBytes, func() (io.ReadCloser, error) { return a.engine.resolver.Resolve(ctx, uri) })
}

type (
	resourceBudgetKey struct{}
	resourceBudget    struct {
		mu    sync.Mutex
		bytes int
		loads int
	}
)

func (e *Engine) openResource(ctx context.Context, limit int, open func() (io.ReadCloser, error)) (io.ReadCloser, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	budget, _ := ctx.Value(resourceBudgetKey{}).(*resourceBudget)
	if budget != nil {
		budget.mu.Lock()
		if budget.loads <= 0 {
			budget.mu.Unlock()
			return nil, executionControlCause(ErrLimit)
		}

		budget.loads--
		budget.mu.Unlock()
	}

	r, err := open()
	if err != nil {
		if !nilcheck.IsNil(r) {
			err = errors.Join(err, r.Close())
		}

		return nil, executionControlCause(errors.Join(ErrResource, err))
	}

	if nilcheck.IsNil(r) {
		return nil, ErrResource
	}

	return &resourceStream{ctx: ctx, reader: r, remaining: limit, budget: budget}, nil
}

// resourceStream charges actual reads, rather than buffering or reserving an
// entire resource. EOF closes the underlying stream and preserves Close errors.
type resourceStream struct {
	ctx       context.Context
	reader    io.ReadCloser
	budget    *resourceBudget
	remaining int
	closed    bool
	closeErr  error
	stalled   int
}

func (r *resourceStream) MediaType() string {
	if typed, ok := r.reader.(resource.TypedReader); ok {
		return typed.MediaType()
	}

	return ""
}

func (r *resourceStream) Read(p []byte) (int, error) {
	if r.closed {
		if r.closeErr != nil {
			return 0, r.closeErr
		}

		return 0, io.EOF
	}

	if err := r.ctx.Err(); err != nil {
		return 0, errors.Join(err, r.Close())
	}

	if len(p) == 0 {
		return 0, nil
	}

	allowed := min(len(p), r.remaining)
	if r.budget != nil {
		r.budget.mu.Lock()
		allowed = min(allowed, r.budget.bytes)
		r.budget.bytes -= allowed
		r.budget.mu.Unlock()
	}

	var (
		n   int
		err error
	)

	if allowed == 0 {
		var probe [1]byte

		n, err = r.reader.Read(probe[:])
		if n < 0 || n > 1 {
			n, err = 0, errors.Join(ErrResource, io.ErrShortBuffer)
		}

		if n > 0 {
			n, err = 0, ErrLimit
		}
	} else {
		n, err = r.reader.Read(p[:allowed])
		if n < 0 || n > allowed {
			n, err = 0, errors.Join(ErrResource, io.ErrShortBuffer)
		}

		r.remaining -= n
		if r.budget != nil {
			r.budget.mu.Lock()
			r.budget.bytes += allowed - n
			r.budget.mu.Unlock()
		}
	}

	if n > 0 {
		r.stalled = 0
	} else if err == nil {
		r.stalled++
		if r.stalled >= 100 {
			err = io.ErrNoProgress
		}
	}

	if err != nil {
		closeErr := r.Close()
		if closeErr != nil {
			return n, executionControlCause(errors.Join(ErrResource, err, closeErr))
		}

		if !errors.Is(err, io.EOF) {
			return n, executionControlCause(errors.Join(ErrResource, err))
		}
	}

	return n, executionControlCause(err)
}

func (r *resourceStream) Close() error {
	if !r.closed {
		r.closed = true
		r.closeErr = executionControlCause(r.reader.Close())
	}

	return r.closeErr
}

// checkSequence validates nested XDM values as well as the outer sequence,
// before cloning caller bindings or publishing results.
func checkSequence(ctx context.Context, seq xdm.Sequence, limits Limits, input bool) error {
	checker := sequenceChecker{ctx: ctx, limits: limits, input: input}
	if err := checker.walk(seq, 0); err != nil {
		return err
	}

	if input {
		return xpath.ChargeString(ctx, checker.size)
	}

	return nil
}

type sequenceChecker struct {
	ctx    context.Context
	limits Limits
	input  bool
	count  int
	size   int
}

func (c *sequenceChecker) walk(s xdm.Sequence, depth int) error {
	if err := c.ctx.Err(); err != nil {
		return err
	}

	if depth > c.limits.MaxDepth {
		return ErrLimit
	}

	if s == nil {
		return nil
	}

	if s.Len() > c.limits.MaxNodes-c.count {
		return ErrLimit
	}

	c.count += s.Len()
	for item := range s.Items() {
		if err := c.item(item, depth); err != nil {
			return err
		}
	}

	return nil
}

func (c *sequenceChecker) item(item xdm.Item, depth int) error {
	switch v := item.(type) {
	case xdm.NodeItem:
		if v.Node != nil {
			if owner := v.Node.OwnerDocument(); owner != nil {
				owner.Freeze()

				if c.input {
					return checkInputDocument(c.ctx, owner, c.limits)
				}
			}
		}
	case xdm.AtomicValue:
		if size, numeric := xpath.NumericSize(v); numeric {
			if size > c.limits.MaxOutputBytes-c.size {
				return ErrLimit
			}

			c.size += size

			return nil
		}

		text, err := lexical(v)
		if err != nil {
			return err
		}

		if len(text) > c.limits.MaxOutputBytes-c.size {
			return ErrLimit
		}

		c.size += len(text)
	case xdm.MapItem:
		if v.Size() > c.limits.MaxNodes-c.count {
			return ErrLimit
		}

		c.count += v.Size()

		return v.ForEachView(func(key xdm.AtomicValue, member xdm.Sequence) error {
			return c.mapMember(key, member, depth)
		})
	case xdm.ArrayItem:
		if v.Size() > c.limits.MaxNodes-c.count {
			return ErrLimit
		}

		c.count += v.Size()
		for _, member := range v.MembersView() {
			if err := c.walk(member, depth+1); err != nil {
				return err
			}
		}
	}

	return nil
}

func (c *sequenceChecker) mapMember(key xdm.AtomicValue, member xdm.Sequence, depth int) error {
	if err := c.item(key, depth); err != nil {
		return err
	}

	return c.walk(member, depth+1)
}
