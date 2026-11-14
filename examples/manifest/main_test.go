package main

import (
	"context"
	"errors"
	"io"
	"testing"
)

func TestExample(t *testing.T) {
	if err := run(); err != nil {
		t.Fatal(err)
	}
}

func TestOpenAttachment(t *testing.T) {
	t.Run("allowlisted_uri", func(t *testing.T) {
		reader, err := openAttachment(t.Context(), uriUrnExampleAttachment)
		if err != nil || reader == nil {
			t.Fatalf("openAttachment returned reader=%v, error=%v", reader, err)
		}
		defer func() {
			if err := reader.Close(); err != nil {
				t.Errorf("close attachment: %v", err)
			}
		}()
		data, err := io.ReadAll(reader)
		if err != nil || string(data) != "external binary-safe data" {
			t.Errorf("attachment bytes=%q, error=%v, want %q and nil", data, err, "external binary-safe data")
		}
	})

	t.Run("unknown_uri", func(t *testing.T) {
		reader, err := openAttachment(t.Context(), "urn:example:unknown")
		if err == nil || reader != nil {
			t.Errorf("openAttachment returned reader=%v, error=%v, want nil reader and an error", reader, err)
		}
	})

	t.Run("canceled_context", func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		reader, err := openAttachment(ctx, uriUrnExampleAttachment)
		if reader != nil || !errors.Is(err, context.Canceled) {
			t.Errorf("openAttachment returned reader=%v, error=%v, want nil reader and context.Canceled", reader, err)
		}
	})
}
