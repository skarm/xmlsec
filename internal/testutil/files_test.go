package testutil_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/skarm/xmlsec/internal/testutil"
)

func TestFixtureFiles(t *testing.T) {
	dir := t.TempDir()
	path := testutil.WriteJSON(t, dir, "data.json", map[string]string{"value": "<é>"})
	raw, err := os.ReadFile(path)
	if err != nil || string(raw) != `{"value":"\u003cé\u003e"}` || filepath.Dir(path) != dir {
		t.Fatalf("JSON fixture = %q, %v", raw, err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}

	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		t.Fatalf("fixture permissions = %o", info.Mode().Perm())
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	privatePath := testutil.WritePrivateKey(t, dir, "private.pem", key)
	private, err := os.ReadFile(privatePath)
	if err != nil {
		t.Fatal(err)
	}

	block, rest := pem.Decode(private)
	if block == nil || block.Type != "PRIVATE KEY" || len(bytes.TrimSpace(rest)) != 0 {
		t.Fatal("private fixture is not one PKCS#8 PEM block")
	}

	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}

	if restored, ok := parsed.(*ecdsa.PrivateKey); !ok || !restored.Equal(key) {
		t.Fatal("private fixture changed key material")
	}

	publicPath := testutil.WritePublicKey(t, dir, "public.pem", &key.PublicKey)
	public, err := os.ReadFile(publicPath)
	if err != nil {
		t.Fatal(err)
	}

	block, rest = pem.Decode(public)
	if block == nil || block.Type != "PUBLIC KEY" || len(bytes.TrimSpace(rest)) != 0 {
		t.Fatal("public fixture is not one PKIX PEM block")
	}

	parsed, err = x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}

	if restored, ok := parsed.(*ecdsa.PublicKey); !ok || !restored.Equal(&key.PublicKey) {
		t.Fatal("public fixture changed the public key")
	}
}
