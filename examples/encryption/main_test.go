package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"testing"
)

func TestStoredCiphertextBindsURIAndByteLimit(t *testing.T) {
	const uri = "urn:example:stored-ciphertext"
	want := []byte{0, 255, 3, 8}
	ref := storedCiphertext(uri, []byte{0, 255, 3, 8})
	if ref.URI != uri || ref.MaxBytes != len(want) {
		t.Errorf("external resource URI = %q, MaxBytes = %d, want %q and %d", ref.URI, ref.MaxBytes, uri, len(want))
	}

	reader, err := ref.Resolver.Resolve(t.Context(), uri)
	if err != nil || reader == nil {
		t.Fatalf("resolve stored ciphertext returned (%v, %v), want a reader", reader, err)
	}
	t.Cleanup(func() {
		if err := reader.Close(); err != nil {
			t.Error(err)
		}
	})

	got, err := io.ReadAll(reader)
	if err != nil || !bytes.Equal(got, want) {
		t.Errorf("ciphertext bytes = %x, error = %v, want %x", got, err, want)
	}

	unexpected, err := ref.Resolver.Resolve(t.Context(), uri+":other")
	if unexpected != nil {
		_ = unexpected.Close()
		t.Error("unexpected URI returned a reader")
	}
	if err == nil {
		t.Error("unexpected URI was accepted")
	}

	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	canceled, err := ref.Resolver.Resolve(ctx, uri)
	if canceled != nil {
		_ = canceled.Close()
		t.Error("canceled lookup returned a reader")
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("canceled lookup error = %v, want %v", err, context.Canceled)
	}
}

func Example() {
	if err := run(); err != nil {
		panic(err)
	}
	// Output:
	// Restored Payload in Envelope; restored payload is private; header is visible
	// Restored content of Payload: private; header is visible
	// Authenticated direct-key ciphertext from the exact external resource
}
