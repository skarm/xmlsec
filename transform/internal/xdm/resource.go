package xdm

import (
	"context"
	"io"
)

// URIResolver retrieves a resource explicitly authorized by the application.
// Callers enforce cancellation and byte limits while consuming the returned stream.
type URIResolver interface {
	// Resolve opens an authorized resource. The consumer closes the returned stream;
	// resolving and reading must honor cancellation.
	Resolve(context.Context, string) (io.ReadCloser, error)
}

// ResourceReadPolicy observes URI access in one host invocation, independently
// of the application resolver's authorization and transport policy.
type ResourceReadPolicy interface {
	// CheckRead verifies that reading the resolved URI is permitted before resource
	// access.
	CheckRead(context.Context, string) error
	// RecordRead records a successful resource open in the current invocation's read
	// policy.
	RecordRead(context.Context, string) error
}

// ResourceAccessError preserves a host error across retrieval wrappers and
// availability functions, which otherwise suppress ordinary retrieval failures.
type ResourceAccessError struct {
	// Cause is the host policy or resource-control failure that wrappers must preserve.
	Cause error
}

// Error returns the preserved cause's message.
func (e *ResourceAccessError) Error() string { return e.Cause.Error() }

// Unwrap returns the host failure for errors.Is and errors.As.
func (e *ResourceAccessError) Unwrap() error { return e.Cause }
