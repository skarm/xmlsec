package xslt //nolint:testpackage // Provides shared helpers for internal compiler and invocation tests.

import (
	"context"
	"errors"
	"io"
	"testing"
)

func requireSerialization(t *testing.T, got string, err error, want, code string) {
	t.Helper()
	if code == "" {
		if err != nil || got != want {
			t.Fatalf("serialized output = %q, error = %v; want %q", got, err, want)
		}
		return
	}

	var detail *XSLTError
	if got != "" || !errors.As(err, &detail) || detail.Code != code {
		t.Fatalf("serialized output = %q, error = %v; want no output and %s", got, err, code)
	}
}

type contractURIResolver func(context.Context, string) (io.ReadCloser, error)

func (r contractURIResolver) Resolve(ctx context.Context, uri string) (io.ReadCloser, error) {
	return r(ctx, uri)
}
