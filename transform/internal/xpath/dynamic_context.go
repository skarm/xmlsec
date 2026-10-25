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

// DynamicProperties retains value semantics without retaining output handlers
// or resource capabilities from the producing invocation.
type DynamicProperties struct {
	CurrentTime time.Time
	Timezone    *time.Location
	Language    string
}

func CaptureDynamicProperties(ctx context.Context, fallback time.Time) DynamicProperties {
	properties := DynamicProperties{CurrentTime: fallback, Timezone: fallback.Location(), Language: "en"}
	if value, ok := evaluationContextFrom(ctx); ok {
		if !value.CurrentTime.IsZero() {
			properties.CurrentTime = value.CurrentTime
		}

		if value.Timezone != nil {
			properties.Timezone = value.Timezone
		}

		if value.Language != "" {
			properties.Language = value.Language
		}
	}

	return properties
}

// WithDynamicProperties preserves live tracing, collection policy, cancellation
// and the invocation's existing shared budget.
func WithDynamicProperties(ctx context.Context, properties DynamicProperties) context.Context {
	var configuration EvaluationContext
	if current, ok := evaluationContextFrom(ctx); ok {
		configuration = *current
	}

	configuration.CurrentTime, configuration.Timezone, configuration.Language = properties.CurrentTime, properties.Timezone, properties.Language

	return WithEvaluationContext(ctx, configuration)
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

// EvaluationCollections returns the collection policy of the enclosing public
// invocation. A nested transform creates its own caches and whitespace view.
func EvaluationCollections(ctx context.Context) CollectionResolver {
	if value, ok := evaluationContextFrom(ctx); ok {
		return value.Collections
	}

	return nil
}

func evaluationContextFrom(ctx context.Context) (*EvaluationContext, bool) {
	value, ok := ctx.Value(evaluationContextKey{}).(*EvaluationContext)
	return value, ok
}

type evaluationContextKey struct{}
