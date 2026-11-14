package testutil_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/skarm/xmlsec/internal/testutil"
)

func TestReadPublicKeyRoundTrip(t *testing.T) {
	t.Parallel()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	path := testutil.WritePublicKey(t, t.TempDir(), "public.pem", key.Public())
	block := readKeyBlock(t, path, "PUBLIC KEY")
	if _, err := x509.ParsePKIXPublicKey(block.Bytes); err != nil {
		t.Fatalf("public key fixture must contain PKIX DER: %v", err)
	}

	parsed := testutil.ReadPublicKey(t, path)
	got, ok := parsed.(*ecdsa.PublicKey)
	if !ok || !got.Equal(key.Public()) {
		t.Fatalf("read public key from %q: got %T, want the written P-256 public key", path, parsed)
	}
}

func TestWritePrivateKeyWritesPKCS8PEM(t *testing.T) {
	t.Parallel()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	path := testutil.WritePrivateKey(t, t.TempDir(), "private.pem", key)
	block := readKeyBlock(t, path, "PRIVATE KEY")
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if restored, ok := parsed.(*ecdsa.PrivateKey); !ok || !restored.Equal(key) {
		t.Fatalf("private key fixture %q restored %T, want the written P-256 private key", path, parsed)
	}
}

func readKeyBlock(t *testing.T, path, wantType string) *pem.Block {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	block, rest := pem.Decode(raw)
	if block == nil || block.Type != wantType || len(bytes.TrimSpace(rest)) != 0 {
		t.Fatalf("key fixture %q must contain exactly one %s PEM block", path, wantType)
	}
	return block
}

func TestReadPublicKeyReportsMissingFixture(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "missing.pem")
	err := captureFixtureFatal(t, func(tb testing.TB) { testutil.ReadPublicKey(tb, path) })
	var pathErr *os.PathError
	if !errors.As(err, &pathErr) || !errors.Is(err, os.ErrNotExist) || pathErr.Path != path {
		t.Errorf("ReadPublicKey(%q) failed with %v, want missing file error for that path", path, err)
	}
}

func TestReadPublicKeyReportsInvalidFixtureFormat(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name, contents, wantDiagnostic string
	}{
		{"not_pem", "key fixture contents", "invalid PEM"},
		{"not_pkix", string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: []byte{0x05, 0x00}})), "asn1:"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			path := testutil.WriteFile(t, t.TempDir(), "bad.pem", []byte(tc.contents))
			err := captureFixtureFatal(t, func(tb testing.TB) { testutil.ReadPublicKey(tb, path) })
			if got := err.Error(); !strings.Contains(got, path) || !strings.Contains(got, tc.wantDiagnostic) {
				t.Errorf("ReadPublicKey failed with %q, want fixture path %q and %q diagnostic", got, path, tc.wantDiagnostic)
			}
		})
	}
}
