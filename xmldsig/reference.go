package xmldsig

import (
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/skarm/xmlsec/c14n"
	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/reference"
)

// ReferenceError describes the first unsuccessful mandatory reference operation.
// A successful/partially populated Result is never returned alongside this error.
// Index is zero-based. Stage is resolve, transform, read, or digest.
type ReferenceError struct {
	Index int
	URI   string
	Stage string
	Err   error
}

// Error returns the diagnostic error message.
func (e *ReferenceError) Error() string {
	return fmt.Sprintf("reference %d (%s), %s: %v", e.Index, e.URI, e.Stage, e.Err)
}

// Unwrap returns the underlying error for errors.Is and errors.As.
func (e *ReferenceError) Unwrap() error { return e.Err }

func processingError(err error) error {
	switch {
	case errors.Is(err, reference.ErrLimit), errors.Is(err, reference.ErrPolicy):
		return fmt.Errorf("%w: %w", ErrPolicy, err)
	case errors.Is(err, reference.ErrUnsupported):
		return fmt.Errorf("%w: %w", ErrAlgorithm, err)
	default:
		return err
	}
}

// processTo shares aggregate octet-production budgets without retaining output.
func processTo(ctx context.Context, dst io.Writer, data reference.Data, ts []reference.Transform, opt reference.Options, remaining *int) (*reference.Report, error) {
	if *remaining <= 0 {
		return nil, fmt.Errorf("%w: processing byte budget", ErrPolicy)
	}

	if opt.MaxProducedBytes == 0 || opt.MaxProducedBytes > *remaining {
		opt.MaxProducedBytes = *remaining
	}

	out, err := reference.Write(ctx, dst, data, ts, opt)
	if err != nil {
		return nil, processingError(err)
	}

	*remaining -= out.ProducedBytes()

	return out, nil
}

// processData shares an aggregate octet-production budget across SignedInfo and
// every reference. Intermediate outputs count, not only the last representation.
func writeCanonicalElement(ctx context.Context, dst io.Writer, e document.Element, method reference.Transform, remaining *int) error {
	set, err := e.Subtree(ctx)
	if err != nil {
		return err
	}

	data, err := reference.Nodes(set)
	if err != nil {
		return err
	}

	_, err = processTo(ctx, dst, data, []reference.Transform{method}, reference.Options{AllowedTransforms: []string{method.Algorithm}}, remaining)

	return err
}

func strictReferenceTransforms(root bool, prefixes []string) []reference.Transform {
	var ts []reference.Transform
	if root {
		ts = append(ts, reference.Transform{Algorithm: EnvelopedSignature})
	}

	return append(ts, reference.Transform{Algorithm: c14n.Exclusive, InclusivePrefixes: append([]string(nil), prefixes...)})
}
