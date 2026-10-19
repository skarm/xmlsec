package xpath

import (
	"context"
	"io"
	"time"
)

// EvaluationContext is invocation-local configuration shared by both languages.
type EvaluationContext struct {
	CurrentTime time.Time
	Timezone    *time.Location
	Language    string
	Trace       io.Writer
	Collections CollectionResolver
}

// WithEvaluationContext stores an owned configuration shared by nested evaluations.
func WithEvaluationContext(ctx context.Context, value EvaluationContext) context.Context {
	return context.WithValue(ctx, evaluationContextKey{}, &value)
}

// CurrentTime returns a stable invocation time, or the supplied fallback.
func CurrentTime(ctx context.Context, fallback time.Time) time.Time {
	if value, ok := evaluationContextFrom(ctx); ok {
		return value.CurrentTime
	}

	return fallback
}

func evaluationContextFrom(ctx context.Context) (*EvaluationContext, bool) {
	value, ok := ctx.Value(evaluationContextKey{}).(*EvaluationContext)
	return value, ok
}

type evaluationContextKey struct{}
