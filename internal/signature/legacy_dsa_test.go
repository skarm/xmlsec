package signature_test

import (
	"bytes"

	// #nosec G406 -- Tests the explicitly bounded public-only legacy verification profile.
	"crypto/dsa" //nolint:staticcheck // Generation and signing with DSA remain disabled.
	"crypto/x509"
	"errors"
	"math/big"
	"testing"

	"github.com/skarm/xmlsec/internal/signature"
	"github.com/skarm/xmlsec/internal/testutil"
	"github.com/skarm/xmlsec/internal/testutil/testcert"
)

func TestLegacyDSAKeyValidationAndSPKIEncoding(t *testing.T) {
	t.Parallel()

	// This existing fixed public fixture is shared with the XMLDSig legacy vectors.
	key, ok := testutil.ReadPublicKey(t, "../../testdata/legacy-dsig/dsa-public.pem").(*dsa.PublicKey)
	if !ok {
		t.Fatal("legacy fixture is not a DSA public key")
	}
	if err := signature.LegacyDSAKey(key); err != nil {
		t.Fatal("valid bounded legacy key rejected", err)
	}
	encoded, err := signature.MarshalPublicKey(key)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := x509.ParsePKIXPublicKey(encoded)
	if err != nil {
		t.Fatal("independent standard parser rejected SPKI", err)
	}
	got, ok := decoded.(*dsa.PublicKey)
	if !ok || got.P.Cmp(key.P) != 0 || got.Q.Cmp(key.Q) != 0 || got.G.Cmp(key.G) != 0 || got.Y.Cmp(key.Y) != 0 {
		t.Fatal("SPKI changed DSA domain parameters or public element")
	}
	for _, test := range []struct {
		name   string
		mutate func(*dsa.PublicKey)
	}{
		{"missing modulus", func(k *dsa.PublicKey) { k.P = nil }},
		{"missing subgroup order", func(k *dsa.PublicKey) { k.Q = nil }},
		{"missing generator", func(k *dsa.PublicKey) { k.G = nil }},
		{"missing public element", func(k *dsa.PublicKey) { k.Y = nil }},
		{"negative modulus", func(k *dsa.PublicKey) { k.P = new(big.Int).Neg(k.P) }},
		{"oversized subgroup order", func(k *dsa.PublicKey) { k.Q = new(big.Int).Lsh(big.NewInt(1), 160) }},
		{"generator below range", func(k *dsa.PublicKey) { k.G = big.NewInt(1) }},
		{"generator at modulus", func(k *dsa.PublicKey) { k.G = new(big.Int).Set(k.P) }},
		{"public element below range", func(k *dsa.PublicKey) { k.Y = big.NewInt(1) }},
		{"public element at modulus", func(k *dsa.PublicKey) { k.Y = new(big.Int).Set(k.P) }},
		{"composite modulus", func(k *dsa.PublicKey) { k.P = new(big.Int).Sub(k.P, big.NewInt(1)) }},
		{"composite subgroup order", func(k *dsa.PublicKey) { k.Q = new(big.Int).Sub(k.Q, big.NewInt(1)) }},
		{"public element outside subgroup", func(k *dsa.PublicKey) { k.Y = new(big.Int).Sub(k.P, big.NewInt(1)) }},
		{"generator outside subgroup", func(k *dsa.PublicKey) { k.G = new(big.Int).Sub(k.P, big.NewInt(1)) }},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			bad := *key
			test.mutate(&bad)
			if err := signature.LegacyDSAKey(&bad); !errors.Is(err, signature.Err) {
				t.Fatal("invalid legacy key accepted", err)
			}
			if value, err := signature.MarshalPublicKey(&bad); value != nil || !errors.Is(err, signature.Err) {
				t.Fatal("invalid legacy key encoded", value, err)
			}
		})
	}
	if err := signature.LegacyDSAKey(nil); !errors.Is(err, signature.Err) {
		t.Fatal("nil legacy key accepted", err)
	}
	modern := testcert.Key(t).Public()
	want, err := x509.MarshalPKIXPublicKey(modern)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := signature.MarshalPublicKey(modern); err != nil || !bytes.Equal(got, want) {
		t.Fatal("modern encoding differs from crypto/x509", err)
	}
}
