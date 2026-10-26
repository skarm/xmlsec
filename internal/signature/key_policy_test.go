package signature_test

import (
	"bytes"
	"crypto"

	// #nosec G406 -- Tests the explicitly bounded public-only legacy verification profile.
	"crypto/dsa" //nolint:staticcheck // Generation and signing with DSA remain disabled.
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"io"
	"math/big"
	"testing"

	"github.com/skarm/xmlsec/internal/signature"
	"github.com/skarm/xmlsec/internal/testutil"
	"github.com/skarm/xmlsec/internal/testutil/testcert"
)

func TestKeyChecksStrengthAndMalformedPublicRepresentations(t *testing.T) {
	t.Parallel()

	rsaPublic := func(bits, exponent int) *rsa.PublicKey {
		return &rsa.PublicKey{N: new(big.Int).Add(new(big.Int).Lsh(big.NewInt(1), uint(bits-1)), big.NewInt(1)), E: exponent}
	}
	for _, test := range []struct {
		name string
		key  crypto.PublicKey
		want bool
	}{
		{"nil", nil, false},
		{"typed RSA nil", (*rsa.PublicKey)(nil), false},
		{"RSA missing modulus", &rsa.PublicKey{E: 65537}, false},
		{"RSA below minimum", rsaPublic(2047, 65537), false},
		{"RSA exact minimum", rsaPublic(2048, 3), true},
		{"RSA exact maximum", rsaPublic(16384, 65537), true},
		{"RSA over maximum", rsaPublic(16385, 65537), false},
		{"RSA negative modulus", &rsa.PublicKey{N: new(big.Int).Neg(rsaPublic(2048, 3).N), E: 3}, false},
		{"RSA even exponent", rsaPublic(2048, 4), false},
		{"RSA small exponent", rsaPublic(2048, 1), false},
		{"typed EC nil", (*ecdsa.PublicKey)(nil), false},
		{"EC missing curve", &ecdsa.PublicKey{}, false},
		{"EC missing coordinates", &ecdsa.PublicKey{Curve: elliptic.P256()}, false},
		{"EC off curve", &ecdsa.PublicKey{Curve: elliptic.P256(), X: big.NewInt(1), Y: big.NewInt(1)}, false}, //nolint:staticcheck // Intentionally constructs an invalid legacy public representation.
		{"Ed25519 exact length", ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize)).Public(), true},
		{"Ed25519 short", make(ed25519.PublicKey, 31), false},
		{"Ed25519 long", make(ed25519.PublicKey, 33), false},
		{"unknown key", struct{}{}, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			if err := signature.Key(test.key); test.want && err != nil || !test.want && !errors.Is(err, signature.Err) {
				t.Fatal("public key profile", err)
			}
		})
	}
	for _, curve := range []elliptic.Curve{elliptic.P224(), elliptic.P256(), elliptic.P384(), elliptic.P521()} {
		key, err := ecdsa.GenerateKey(curve, rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		err = signature.Key(key.Public())
		if curve == elliptic.P224() && !errors.Is(err, signature.Err) || curve != elliptic.P224() && err != nil {
			t.Fatal("curve profile", curve.Params().Name, err)
		}
	}
}

func TestMatchCertificateBindsExactSignerSPKI(t *testing.T) {
	t.Parallel()

	chain := testcert.New(t)
	if err := signature.MatchCertificate(chain.LeafKey, chain.Leaf); err != nil {
		t.Fatal("matching certificate rejected", err)
	}
	for _, test := range []struct {
		name string
		key  crypto.Signer
		cert *x509.Certificate
	}{
		{"nil signer", nil, chain.Leaf},
		{"typed nil signer", (*ecdsa.PrivateKey)(nil), chain.Leaf},
		{"nil certificate", chain.LeafKey, nil},
		{"different signer", chain.TSAKey, chain.Leaf},
		{"empty certificate", chain.LeafKey, &x509.Certificate{}},
		{"invalid public key", publicSigner{public: &ecdsa.PublicKey{}}, chain.Leaf},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			if err := signature.MatchCertificate(test.key, test.cert); !errors.Is(err, signature.Err) {
				t.Fatal("unbound certificate or malformed signer accepted", err)
			}
		})
	}
}

type publicSigner struct{ public crypto.PublicKey }

func (s publicSigner) Public() crypto.PublicKey { return s.public }
func (publicSigner) Sign(_ io.Reader, _ []byte, _ crypto.SignerOpts) ([]byte, error) {
	return nil, errors.New("public-only fixture must not sign")
}

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
