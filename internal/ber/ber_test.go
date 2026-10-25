package ber_test

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/skarm/xmlsec/internal/ber"
)

func TestConstructedOctets(t *testing.T) {
	// An indefinite OCTET STRING contains a primitive and a nested definite one.
	raw := []byte{0x24, 0x80, 4, 2, 'a', 'b', 0x24, 3, 4, 1, 'c', 0, 0}
	limits := ber.Limits{MaxBytes: len(raw), MaxDepth: 3, MaxNodes: 4}
	value, err := ber.Read(t.Context(), raw, limits)
	if err != nil || len(value.Children) != 2 || !bytes.Equal(value.Full, raw) || !bytes.Equal(value.Body, raw[2:11]) {
		t.Fatalf("original BER view: %+v, %v", value, err)
	}

	length, err := ber.OctetLength(t.Context(), value, 3)
	if err != nil || length != 3 {
		t.Fatalf("flattened length = %d, %v", length, err)
	}

	var output bytes.Buffer
	if err := ber.AppendOctets(t.Context(), value, &output, 3); err != nil || output.String() != "abc" {
		t.Fatalf("flattened value = %q, %v", output.String(), err)
	}

	output.Reset()
	if err := ber.AppendOctets(t.Context(), value, &output, 2); !errors.Is(err, ber.ErrLimit) || output.String() != "ab" {
		t.Fatalf("partial result at limit = %q, %v", output.String(), err)
	}

	if _, err := ber.OctetLength(t.Context(), value, 2); !errors.Is(err, ber.ErrLimit) {
		t.Fatal("flattened length limit:", err)
	}

	raw[4] = 'z'
	if value.Children[0].Body[0] != 'z' {
		t.Fatal("BER view stopped borrowing its original input")
	}

	for _, limited := range []ber.Limits{{MaxBytes: len(raw) - 1, MaxDepth: 3, MaxNodes: 4}, {MaxBytes: len(raw), MaxDepth: 2, MaxNodes: 4}, {MaxBytes: len(raw), MaxDepth: 3, MaxNodes: 3}} {
		if _, err := ber.Read(t.Context(), raw, limited); !errors.Is(err, ber.ErrLimit) {
			t.Errorf("budget %+v: %v", limited, err)
		}
	}
}

func TestMalformedAndCancelled(t *testing.T) {
	limits := ber.Limits{MaxBytes: 100, MaxDepth: 8, MaxNodes: 32}
	for _, raw := range [][]byte{nil, {0, 0}, {4, 0x80, 0, 0}, {0x24, 0x80, 4, 0}, {4, 1}, {4, 0, 4, 0}, {0x1f, 0, 0}, {4, 0x89}, {4, 0x89, 0, 0, 0, 0, 0, 0, 0, 0, 0}, {0x30, 2, 0, 0}} {
		if _, err := ber.Read(t.Context(), raw, limits); !errors.Is(err, ber.ErrSyntax) {
			t.Errorf("Read(%x) = %v", raw, err)
		}
	}

	value, err := ber.Read(t.Context(), []byte{4, 0x81, 1, 'x'}, limits)
	if err != nil || string(value.Body) != "x" {
		t.Fatalf("BER nonminimal length rejected: %+v, %v", value, err)
	}

	if _, err := ber.Read(nil, []byte{4, 0}, limits); !errors.Is(err, ber.ErrSyntax) {
		t.Fatal("nil context:", err)
	}

	for _, invalid := range []ber.Limits{{MaxDepth: 1, MaxNodes: 1}, {MaxBytes: 2, MaxNodes: 1}, {MaxBytes: 2, MaxDepth: 1}} {
		if _, err := ber.Read(t.Context(), []byte{4, 0}, invalid); !errors.Is(err, ber.ErrSyntax) {
			t.Errorf("nonpositive budget %+v: %v", invalid, err)
		}
	}

	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := ber.Read(ctx, []byte{4, 0}, limits); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled scan:", err)
	}

	var output bytes.Buffer
	if err := ber.AppendOctets(ctx, value, &output, 10); !errors.Is(err, context.Canceled) || output.Len() != 0 {
		t.Fatal("cancelled flatten:", err, output.String())
	}

	if _, err := ber.OctetLength(ctx, value, 10); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled length:", err)
	}

	if err := ber.AppendOctets(t.Context(), ber.Value{Tag: 2}, &output, 10); !errors.Is(err, ber.ErrSyntax) {
		t.Fatal("non-octet value:", err)
	}

	if _, err := ber.OctetLength(t.Context(), ber.Value{Tag: 2}, 10); !errors.Is(err, ber.ErrSyntax) {
		t.Fatal("non-octet length:", err)
	}
}
