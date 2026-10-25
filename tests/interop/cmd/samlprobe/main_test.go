package main

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/skarm/xmlsec/internal/testutil/testcert"
)

func TestSAMLFixtureModesAndTrustedKeyBinding(t *testing.T) {
	chain := testcert.New(t)
	for _, kind := range []string{"request", "response", "metadata"} {
		t.Run(kind, func(t *testing.T) {
			signed, err := process(t.Context(), "sign-"+kind, nil, chain.Leaf, chain.LeafKey, testcert.Now())
			if err != nil || signed == nil {
				t.Fatalf("sign %s: %v", kind, err)
			}
			raw, err := signed.XML(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Contains(raw, []byte("SignatureValue")) {
				t.Fatal("unsigned fixture generated")
			}
			if _, err := process(t.Context(), "verify-"+kind, raw, chain.Leaf, nil, testcert.Now()); err != nil {
				t.Fatalf("verification: %v", err)
			}
			if _, err := process(t.Context(), "verify-"+kind, raw, chain.TSA, nil, testcert.Now()); err == nil {
				t.Fatal("verification ignored trusted key")
			}
			if kind != "metadata" {
				if _, err := process(t.Context(), "verify-"+kind, raw, chain.Leaf, nil, testcert.Now().Add(10*time.Minute)); err == nil {
					t.Fatal("verification ignored supplied clock")
				}
			}
		})
	}
}

func TestSAMLAdapterFailures(t *testing.T) {
	chain := testcert.New(t)
	for _, mode := range []string{"verify-request", "verify-response", "verify-metadata"} {
		if _, err := process(t.Context(), mode, []byte(`<broken`), chain.Leaf, nil, testcert.Now()); err == nil {
			t.Fatal("invalid XML accepted", mode)
		}
	}
	if _, err := process(t.Context(), "unknown", nil, chain.Leaf, nil, testcert.Now()); err == nil {
		t.Fatal("unknown mode accepted")
	}
	if _, err := process(t.Context(), "sign-request", nil, nil, chain.LeafKey, testcert.Now()); err == nil {
		t.Fatal("missing certificate accepted")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := process(ctx, "sign-request", nil, chain.Leaf, chain.LeafKey, testcert.Now()); !errors.Is(err, context.Canceled) {
		t.Fatal("ignored cancellation", err)
	}
}
