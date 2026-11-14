package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"errors"
	"testing"

	"github.com/skarm/xmlsec/keys"
)

func TestVerifyRestoredKeyChecksExpectedIdentity(t *testing.T) {
	var scalar [32]byte
	scalar[len(scalar)-1] = 1
	key, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), scalar[:])
	if err != nil {
		t.Fatal(err)
	}

	scalar[len(scalar)-1] = 2
	other, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), scalar[:])
	if err != nil {
		t.Fatal(err)
	}

	password := []byte("public fixture пароль 😀")
	private, err := keys.MarshalEncryptedPrivate(t.Context(), key, password, keys.EncryptionOptions{Iterations: 1000}, keys.Limits{})
	if err != nil {
		t.Fatal(err)
	}

	if err := verifyRestoredKey(t.Context(), private, password, &key.PublicKey); err != nil {
		t.Errorf("matching key returned error %v", err)
	}
	if err := verifyRestoredKey(t.Context(), private, password, &other.PublicKey); err == nil {
		t.Error("different key was accepted")
	}
	if err := verifyRestoredKey(t.Context(), private, []byte("different password"), &key.PublicKey); !errors.Is(err, keys.ErrDecrypt) {
		t.Errorf("wrong password error = %v, want %v", err, keys.ErrDecrypt)
	}

	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := verifyRestoredKey(ctx, private, password, &key.PublicKey); !errors.Is(err, context.Canceled) {
		t.Errorf("canceled key check error = %v, want %v", err, context.Canceled)
	}
}

func Example() {
	if err := run(); err != nil {
		panic(err)
	}
	// Output:
	// PKCS#8 key restored; PKCS#12 certificate "example document signer", 1 extra certificate
}
