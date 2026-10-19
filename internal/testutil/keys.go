package testutil

import (
	"crypto"
	"crypto/x509"
	"encoding/pem"
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
