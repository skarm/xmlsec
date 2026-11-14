package xpath //nolint:testpackage // Shared fixtures for internal evaluator tests.

import (
	"context"
	"io"
	"testing"

	"github.com/skarm/xmlsec/transform/internal/xdm"
)

type documentResolverFunc func(context.Context, string) (io.ReadCloser, error)

func (f documentResolverFunc) Resolve(ctx context.Context, uri string) (io.ReadCloser, error) {
	return f(ctx, uri)
}

type documentTestReader struct {
	io.Reader
	closed int
	err    error
}

func (r *documentTestReader) Close() error {
	r.closed++
	return r.err
}

func assertAtomicSequence(t *testing.T, got xdm.Sequence, want []xdm.AtomicValue) {
	t.Helper()
	if xdm.SequenceLen(got) != len(want) {
		t.Fatalf("result length = %d, want %d", xdm.SequenceLen(got), len(want))
	}
	for i, expected := range want {
		actual, ok := got.Get(i).(xdm.AtomicValue)
		if !ok || actual.TypeName != expected.TypeName || actual.Value != expected.Value {
			t.Errorf("result item %d = %+v, want %+v", i+1, got.Get(i), expected)
		}
	}
}
