package transform

import (
	"context"
	"io"
	"slices"
	"time"

	"github.com/skarm/xmlsec/transform/internal/xdm"
	"github.com/skarm/xmlsec/transform/internal/xpath"
)

// DynamicContext supplies shared XPath and XSLT execution settings.
// The current time and implicit timezone are fixed for each invocation.
type DynamicContext struct {
	// CurrentTime is shared by all current-date/time calls in one invocation.
	// Zero samples the clock once at invocation start, in UTC.
	CurrentTime time.Time
	// ImplicitTimezone defaults to CurrentTime.Location(). Its offset at the
	// invocation time must be a whole minute within -14 to +14 hours.
	ImplicitTimezone *time.Location
	DefaultLanguage  string
	// TraceWriter receives XPath trace and XSLT trace output. Nil discards it.
	// The caller owns the writer and synchronizes concurrent invocations.
	TraceWriter io.Writer
}

// CollectionResolver supplies immutable collections and their member URIs.
// Callbacks must honor context and support concurrent use. Empty URI identifies
// the default collection; no implicit collection is provided by the engine.
type CollectionResolver interface {
	// ResolveCollection returns the members of collection(uri).
	// An empty URI requests the default collection.
	ResolveCollection(context.Context, string) (Sequence, error)
	// ResolveURICollection returns the member URIs of uri-collection(uri).
	// An empty URI requests the default URI collection.
	ResolveURICollection(context.Context, string) ([]string, error)
}

func (e *Engine) dynamicContext(ctx context.Context, options DynamicContext) (context.Context, error) {
	now := options.CurrentTime
	if now.IsZero() {
		now = time.Now().UTC()
	}

	zone := options.ImplicitTimezone
	if zone == nil {
		zone = now.Location()
	}

	_, offset := now.In(zone).Zone()
	if offset%60 != 0 || offset < -14*60*60 || offset > 14*60*60 {
		return nil, ErrInput
	}

	zone = time.FixedZone("", offset)
	now = now.In(zone)

	return xpath.WithEvaluationContext(ctx, xpath.EvaluationContext{CurrentTime: now, Timezone: zone, Language: options.DefaultLanguage, Trace: checkedTrace{ctx: ctx, writer: traceWriter(options.TraceWriter)}, Collections: e.collectionResolver()}), nil
}

func (e *Engine) collectionResolver() xpath.CollectionResolver {
	if e.collections == nil {
		return nil
	}

	return collectionAdapter{engine: e}
}

type checkedTrace struct {
	ctx    context.Context
	writer io.Writer
}

func (w checkedTrace) Write(p []byte) (int, error) {
	if err := xpath.ChargeString(w.ctx, len(p)); err != nil {
		return 0, err
	}

	n, err := w.writer.Write(p)
	if err == nil && n != len(p) {
		err = io.ErrShortWrite
	}

	return n, err
}

type collectionAdapter struct{ engine *Engine }

func (a collectionAdapter) ResolveCollection(ctx context.Context, uri string) (xdm.Sequence, error) {
	if err := xpath.Charge(ctx, 1); err != nil {
		return nil, err
	}

	seq, err := a.engine.collections.ResolveCollection(ctx, uri)
	if err != nil {
		return nil, err
	}

	if err := checkSequence(ctx, seq.items, a.engine.limits, true); err != nil {
		return nil, err
	}

	if err := xpath.Charge(ctx, seq.Len()); err != nil {
		return nil, err
	}

	return xdm.CloneSequence(seq.items), nil
}

func (a collectionAdapter) ResolveURICollection(ctx context.Context, uri string) ([]string, error) {
	if err := xpath.Charge(ctx, 1); err != nil {
		return nil, err
	}

	values, err := a.engine.collections.ResolveURICollection(ctx, uri)
	if err != nil {
		return nil, err
	}

	if len(values) > a.engine.limits.MaxNodes {
		return nil, ErrLimit
	}

	for _, value := range values {
		if err := xpath.ChargeString(ctx, len(value)); err != nil {
			return nil, err
		}
	}

	return slices.Clone(values), ctx.Err()
}
