package timestamp

import (
	"context"
	"errors"
	"io"
	"time"

	"github.com/skarm/xmlsec/internal/nilcheck"
	"github.com/skarm/xmlsec/pki"
)

// Transport owns endpoint policy and cancellation of blocking reads. The library
// never follows a TSA URL from XML and never opens network connections itself.
type Transport interface {
	// RoundTrip sends DER request bytes to an application-selected TSA and returns the
	// response stream. Fetch closes every non-nil returned stream, including on error.
	// The transport and its reader must honor cancellation.
	RoundTrip(context.Context, []byte) (io.ReadCloser, error)
}

// TransportFunc adapts a context-aware, application-owned TSA transport.
// It does not add network access or cancellation to a blocking reader.
type TransportFunc func(context.Context, []byte) (io.ReadCloser, error)

// RoundTrip calls the underlying transport function.
func (f TransportFunc) RoundTrip(ctx context.Context, request []byte) (io.ReadCloser, error) {
	if f == nil {
		return nil, ErrPolicy
	}

	return f(ctx, request)
}

// Fetch sends q through the application-owned transport, reads a bounded response
// and verifies it against q at the explicit time with the supplied evidence.
// It validates local arguments before calling the transport and closes the response
// stream on every path. It cannot interrupt a transport or reader that ignores ctx.
func (v *Verifier) Fetch(ctx context.Context, t Transport, q *Request, at time.Time, e pki.Evidence) (*Result, error) {
	if v == nil || v.trust == nil || ctx == nil || nilcheck.IsNil(t) || q == nil || len(q.raw) == 0 || at.IsZero() {
		return nil, ErrPolicy
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	body, err := t.RoundTrip(ctx, q.DER())
	if err != nil {
		if !nilcheck.IsNil(body) {
			err = errors.Join(err, body.Close())
		}

		return nil, err
	}

	if nilcheck.IsNil(body) {
		return nil, ErrFormat
	}

	result, re := v.VerifyResponseReader(ctx, body, q, at, e)
	if err := errors.Join(re, body.Close(), ctx.Err()); err != nil {
		return nil, err
	}

	return result, nil
}
