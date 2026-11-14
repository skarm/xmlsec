package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"testing"

	"github.com/skarm/xmlsec/keyinfo"
)

func TestTrustedKeySelectorUsesConfiguredPin(t *testing.T) {
	var scalar [32]byte
	scalar[len(scalar)-1] = 1
	first, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), scalar[:])
	if err != nil {
		t.Fatal(err)
	}

	scalar[len(scalar)-1] = 2
	second, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), scalar[:])
	if err != nil {
		t.Fatal(err)
	}

	doc, err := keyinfo.Build(t.Context(), keyinfo.Template{Keys: []keyinfo.PublicKeyValue{{Key: first.Public()}, {Key: second.Public()}}})
	if err != nil {
		t.Fatal(err)
	}

	info, err := keyinfo.Parse(t.Context(), doc, doc.Root(), keyinfo.Options{})
	if err != nil {
		t.Fatal(err)
	}

	spki, err := x509.MarshalPKIXPublicKey(second.Public())
	if err != nil {
		t.Fatal(err)
	}

	selectPinned := trustedKeySelector(sha256.Sum256(spki))
	if got, err := selectPinned(t.Context(), info); got != 1 || err != nil {
		t.Errorf("key index = %d, error = %v, want second candidate", got, err)
	}
	if got, err := trustedKeySelector([sha256.Size]byte{})(t.Context(), info); got != -1 || err == nil {
		t.Errorf("unknown pin selected key index = %d, error = %v, want -1 and rejection", got, err)
	}

	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if got, err := selectPinned(ctx, info); got != -1 || !errors.Is(err, context.Canceled) {
		t.Errorf("canceled selection returned (%d, %v), want (-1, %v)", got, err, context.Canceled)
	}
}

func Example() {
	if err := run(); err != nil {
		panic(err)
	}
	// Output:
	// references=1 payload-covered=true signature-container-covered=false
	// verified payload: message whose exact Object must be signed
}
