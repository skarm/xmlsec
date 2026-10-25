package ecdsakey_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	"github.com/skarm/xmlsec/internal/ecdsakey"
)

func TestBytesRoundTrip(t *testing.T) {
	for _, curve := range []elliptic.Curve{elliptic.P224(), elliptic.P256(), elliptic.P384(), elliptic.P521()} {
		t.Run(curve.Params().Name, func(t *testing.T) {
			key, err := ecdsa.GenerateKey(curve, rand.Reader)
			if err != nil {
				t.Fatal(err)
			}

			public, err := ecdsakey.PublicBytes(&key.PublicKey)
			if err != nil {
				t.Fatal(err)
			}

			parsedPublic, err := ecdsa.ParseUncompressedPublicKey(curve, public)
			if err != nil || !parsedPublic.Equal(key.Public()) {
				t.Fatal("public encoding changed the key", err)
			}

			private, err := ecdsakey.PrivateBytes(key)
			if err != nil {
				t.Fatal(err)
			}
			defer clear(private)

			parsedPrivate, err := ecdsa.ParseRawPrivateKey(curve, private)
			if err != nil || !parsedPrivate.Equal(key) {
				t.Fatal("private encoding changed the key", err)
			}
		})
	}
}

func TestBytesRejectMalformedKeys(t *testing.T) {
	scalar := make([]byte, 32)
	scalar[len(scalar)-1] = 1

	key, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), scalar)
	if err != nil {
		t.Fatal(err)
	}

	wrongCurve := key.PublicKey
	wrongCurve.Curve = elliptic.P384()

	for _, key := range []*ecdsa.PublicKey{
		nil, {}, {Curve: elliptic.P256()}, &wrongCurve,
	} {
		if raw, err := ecdsakey.PublicBytes(key); raw != nil || err == nil {
			t.Fatalf("malformed public key accepted: %x, %v", raw, err)
		}
	}

	missingCoordinates := *key
	missingCoordinates.PublicKey = ecdsa.PublicKey{Curve: elliptic.P256()}

	for _, key := range []*ecdsa.PrivateKey{
		nil,
		{},
		{Curve: elliptic.P256()},
		{PublicKey: key.PublicKey},
		&missingCoordinates,
	} {
		if raw, err := ecdsakey.PrivateBytes(key); raw != nil || err == nil {
			t.Fatalf("malformed private key accepted: %x, %v", raw, err)
		}
	}
}

// Private encodings are caller-owned secrets and may be cleared after use.
func TestPrivateBytesOwnStorage(t *testing.T) {
	for _, curve := range []elliptic.Curve{elliptic.P224(), elliptic.P256(), elliptic.P384(), elliptic.P521()} {
		t.Run(curve.Params().Name, func(t *testing.T) {
			key, err := ecdsa.GenerateKey(curve, rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			first, err := ecdsakey.PrivateBytes(key)
			if err != nil {
				t.Fatal(err)
			}
			second, err := ecdsakey.PrivateBytes(key)
			if err != nil {
				t.Fatal(err)
			}
			defer clear(second)
			want := bytes.Clone(second)
			defer clear(want)
			clear(first)
			if !bytes.Equal(second, want) {
				t.Fatal("clearing one private encoding changed another caller's encoding")
			}
		})
	}
}
