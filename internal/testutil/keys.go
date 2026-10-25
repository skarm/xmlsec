package testutil

import (
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"os"
	"testing"
)

// WritePrivateKey writes a disposable test key as PKCS#8 PEM.
func WritePrivateKey(t testing.TB, dir, name string, key crypto.Signer) string {
	t.Helper()

	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}

	return WriteFile(t, dir, name, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
}

// WritePublicKey writes a disposable test public key as PKIX PEM.
func WritePublicKey(t testing.TB, dir, name string, key crypto.PublicKey) string {
	t.Helper()

	der, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		t.Fatal(err)
	}

	return WriteFile(t, dir, name, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

// ReadPublicKey reads a PKIX public key from a PEM fixture.
func ReadPublicKey(t testing.TB, path string) crypto.PublicKey {
	t.Helper()

	raw, err := os.ReadFile(path) // #nosec G304 -- The test supplies its fixture path.
	if err != nil {
		t.Fatal(err)
	}

	block, _ := pem.Decode(raw)
	if block == nil {
		t.Fatalf("public key fixture %s: invalid PEM", path)
	}

	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		t.Fatalf("public key fixture %s: %v", path, err)
	}

	return key
}
