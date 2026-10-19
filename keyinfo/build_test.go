package keyinfo_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"errors"
	"math/big"
	"testing"

	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/keyinfo"
)

func TestBuildPolicyAndZeroValues(t *testing.T) {
	k := ec(t, elliptic.P256())
	for _, test := range []struct {
		name string
		spec keyinfo.Template
		want error
	}{
		{"empty", keyinfo.Template{}, keyinfo.ErrInput},
		{"bad-ID", keyinfo.Template{ID: "bad id", Names: []string{"x"}}, keyinfo.ErrInput},
		{"too-many", keyinfo.Template{Names: make([]string, 33)}, keyinfo.ErrLimit},
		{"nil-key", keyinfo.Template{Keys: []keyinfo.PublicKeyValue{{Key: (*rsa.PublicKey)(nil)}}}, keyinfo.ErrKey},
		{"incomplete-EC", keyinfo.Template{Keys: []keyinfo.PublicKeyValue{{Key: &ecdsa.PublicKey{Curve: elliptic.P256()}}}}, keyinfo.ErrKey},
		{"bad-format", keyinfo.Template{Keys: []keyinfo.PublicKeyValue{{Key: &k.PublicKey, Format: "unexpected"}}}, keyinfo.ErrPolicy},
		{"invalid-cert", keyinfo.Template{Certificates: [][]byte{{1, 2, 3}}}, keyinfo.ErrInput},
		{"invalid-reference", keyinfo.Template{KeyInfoReferences: []string{"relative/path"}}, keyinfo.ErrInput},
		{"invalid-point", keyinfo.Template{Keys: []keyinfo.PublicKeyValue{{Key: &ecdsa.PublicKey{Curve: elliptic.P256(), X: big.NewInt(0), Y: big.NewInt(0)}}}}, keyinfo.ErrKey}, //nolint:staticcheck // Deliberately mutate legacy coordinates to test malformed keys and snapshot ownership.
	} {
		t.Run(test.name, func(t *testing.T) {
			d, e := keyinfo.Build(context.Background(), test.spec)
			if d != nil || !errors.Is(e, test.want) {
				t.Fatalf("got %v, want %v", e, test.want)
			}
		})
	}

	if _, e := keyinfo.Build(nil, keyinfo.Template{}); !errors.Is(e, keyinfo.ErrInput) {
		t.Fatal(e)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if _, e := keyinfo.Build(ctx, keyinfo.Template{Names: []string{"x"}}); !errors.Is(e, context.Canceled) {
		t.Fatal(e)
	}

	var candidate keyinfo.Candidate
	if candidate.Valid() || candidate.Kind() != (document.Name{}) || candidate.FingerprintSHA256() != "" {
		t.Fatal("valid zero candidate")
	}

	if _, e := candidate.PublicKey(); !errors.Is(e, keyinfo.ErrKey) {
		t.Fatal(e)
	}

	if _, e := candidate.Certificate(); !errors.Is(e, keyinfo.ErrKey) {
		t.Fatal(e)
	}

	var r *keyinfo.Result
	if r.Candidates() != nil || r.KeyNames() != nil || r.X509Groups() != nil || r.ExternalURIs() != nil {
		t.Fatal("nil result")
	}
}
