package xdm

import (
	"context"
	"io"
)

// URIResolver retrieves a resource explicitly authorized by the application.
// Callers enforce cancellation and byte limits while consuming the returned stream.
type URIResolver interface {
	Resolve(context.Context, string) (io.ReadCloser, error)
}

// ResourceReadPolicy observes URI access in one host invocation, independently
// of the application resolver's authorization and transport policy.
type ResourceReadPolicy interface {
	CheckRead(context.Context, string) error
	RecordRead(context.Context, string) error
}

// ResourceAccessError preserves a host error across retrieval wrappers and
// availability functions, which otherwise suppress ordinary retrieval failures.
type ResourceAccessError struct{ Cause error }

func (e *ResourceAccessError) Error() string { return e.Cause.Error() }

func (e *ResourceAccessError) Unwrap() error { return e.Cause }
