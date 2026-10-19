package signature_test

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"encoding/asn1"
	"errors"
	"io"
	"testing"

	"github.com/skarm/xmlsec/internal/signature"
	"github.com/skarm/xmlsec/internal/testutil/testcert"
)

func TestSignAndVerify(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name string
		key  crypto.Signer
		pss  bool
	}{
		{"ECDSA", testcert.Key(t), false}, {"RSA", rsaKey, false}, {"RSA-PSS", rsaKey, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			algorithm, err := signature.Select(tc.key.Public(), crypto.SHA256, tc.pss)
			if err != nil {
				t.Fatal(err)
			}

			value, err := signature.Sign(t.Context(), tc.key, algorithm, []byte("signed message"))
			if err != nil {
				t.Fatal(err)
			}

			if err := signature.Verify(tc.key.Public(), algorithm, []byte("signed message"), value); err != nil {
				t.Fatal(err)
			}

			if err := signature.Verify(tc.key.Public(), algorithm, []byte("modified message"), value); err == nil {
				t.Fatal("modified message accepted")
			}
		})
	}
}

func TestSignRejectsProviderOutputAndCancellation(t *testing.T) {
	provider := &invalidSigner{Signer: testcert.Key(t)}

	algorithm, err := signature.Select(provider.Public(), crypto.SHA256, false)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	if value, err := signature.Sign(ctx, provider, algorithm, []byte("message")); !errors.Is(err, context.Canceled) || value != nil || provider.calls != 0 {
		t.Fatalf("canceled signing = %x, %v, calls=%d", value, err, provider.calls)
	}

	if value, err := signature.Sign(t.Context(), provider, algorithm, []byte("message")); !errors.Is(err, signature.Err) || value != nil || provider.calls != 1 {
		t.Fatalf("invalid provider output = %x, %v, calls=%d", value, err, provider.calls)
	}
}

func TestHashRequiresExplicitLegacyPolicy(t *testing.T) {
	aid, err := signature.DigestAlgorithm(crypto.SHA1)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := signature.Hash(aid, false); !errors.Is(err, signature.Err) {
		t.Fatalf("SHA-1 enabled implicitly: %v", err)
	}

	if got, err := signature.Hash(aid, true); err != nil || got != crypto.SHA1 {
		t.Fatalf("explicit identifier policy: %v, %v", got, err)
	}

	aid.Parameters = asn1.RawValue{Tag: asn1.TagOctetString, Bytes: []byte("invalid parameters")}
	if _, err := signature.Hash(aid, true); !errors.Is(err, signature.Err) {
		t.Fatalf("unexpected digest parameters accepted: %v", err)
	}
}

func BenchmarkVerify(b *testing.B) {
	c := testcert.New(b)

	a, err := signature.Select(c.LeafKey.Public(), crypto.SHA256, false)
	if err != nil {
		b.Fatal(err)
	}

	m := make([]byte, 4096)

	s, err := signature.Sign(context.Background(), c.LeafKey, a, m)
	if err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()

	for b.Loop() {
		if err := signature.Verify(c.LeafKey.Public(), a, m, s); err != nil {
			b.Fatal(err)
		}
	}
}

type invalidSigner struct {
	crypto.Signer
	calls int
}

func (s *invalidSigner) Sign(io.Reader, []byte, crypto.SignerOpts) ([]byte, error) {
	s.calls++
	return []byte("invalid provider output"), nil
}
