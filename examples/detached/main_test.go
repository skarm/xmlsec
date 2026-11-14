package main

import (
	"bytes"
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

func TestPayloadResolverReadsExactResourcesIndependently(t *testing.T) {
	want := []byte{0, 1, 2, 255}
	resolve := payloadResolver(map[string][]byte{
		uriUrnExampleBinary:  {0, 1, 2, 255},
		uriUrnExampleInvoice: []byte("invoice"),
	})
	first, err := resolve.Resolve(t.Context(), uriUrnExampleBinary)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := first.Close(); err != nil {
			t.Error(err)
		}
	})

	var prefix [1]byte
	if _, err := io.ReadFull(first, prefix[:]); err != nil || prefix[0] != want[0] {
		t.Fatalf("first byte = %d, error = %v, want %d", prefix[0], err, want[0])
	}

	for _, tc := range []struct {
		uri  string
		want []byte
	}{
		{uri: uriUrnExampleBinary, want: want},
		{uri: uriUrnExampleInvoice, want: []byte("invoice")},
	} {
		t.Run(tc.uri, func(t *testing.T) {
			reader, err := resolve.Resolve(t.Context(), tc.uri)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := reader.Close(); err != nil {
					t.Error(err)
				}
			})

			got, err := io.ReadAll(reader)
			if err != nil || !bytes.Equal(got, tc.want) {
				t.Errorf("resource bytes = %x, error = %v, want %x", got, err, tc.want)
			}
		})
	}
}

func TestPayloadResolverRejectsUnknownURIAndCancellation(t *testing.T) {
	resolve := payloadResolver(map[string][]byte{uriUrnExampleInvoice: []byte("invoice")})
	reader, err := resolve.Resolve(t.Context(), uriUrnExampleInvoice+"?view=print")
	if reader != nil {
		_ = reader.Close()
		t.Error("unknown URI returned a reader")
	}
	if err == nil {
		t.Error("unknown URI was accepted")
	}

	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	reader, err = resolve.Resolve(ctx, uriUrnExampleInvoice)
	if reader != nil {
		_ = reader.Close()
		t.Error("canceled lookup returned a reader")
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("canceled lookup error = %v, want %v", err, context.Canceled)
	}
}
