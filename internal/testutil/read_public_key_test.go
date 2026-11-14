package testutil_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
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
	parsed := testutil.ReadPublicKey(t, path)
	got, ok := parsed.(*ecdsa.PublicKey)
	if !ok || !got.Equal(key.Public()) {
		t.Fatalf("read public key from %q: got %T, want the written P-256 public key", path, parsed)
	}
}
