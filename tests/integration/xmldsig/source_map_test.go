package xmldsig_test

import (
	"context"
	"errors"
	"io"
	"testing"
)

func TestSourceMapResolvesOnlyConfiguredResources(t *testing.T) {
	const uri, content = "urn:test:fixture", "fixture data"
	resolver := sourceMap(map[string][]byte{uri: []byte(content)})

	for i := range 2 {
		reader, err := resolver.Resolve(t.Context(), uri)
		if err != nil || reader == nil {
			t.Fatalf("Resolve %q (attempt %d) returned reader=%v, error=%v", uri, i+1, reader, err)
		}
		data, readErr := io.ReadAll(reader)
		closeErr := reader.Close()
		if readErr != nil || closeErr != nil || string(data) != content {
			t.Fatalf("read %q (attempt %d) returned %q, read error=%v, close error=%v, want %q", uri, i+1, data, readErr, closeErr, content)
		}
	}

	if reader, err := resolver.Resolve(t.Context(), "urn:test:missing"); reader != nil || err == nil {
		t.Errorf("Resolve missing fixture returned reader=%v, error=%v, want a denial and no reader", reader, err)
	}

	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if reader, err := resolver.Resolve(ctx, uri); reader != nil || !errors.Is(err, context.Canceled) {
		t.Errorf("Resolve after cancellation returned reader=%v, error=%v, want nil and context.Canceled", reader, err)
	}
}
