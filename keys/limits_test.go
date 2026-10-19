package keys_test

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"testing"

	"github.com/skarm/xmlsec/internal/testutil/testcert"
	"github.com/skarm/xmlsec/keys"
)

func TestEncodedAndDecodedKeyLimits(t *testing.T) {
	key := testcert.Key(t)

	raw, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}

	encoded := pem.EncodeToMemory(&pem.Block{Type: privateKeyPEMType, Bytes: raw})

	limits := keys.Limits{MaxInputBytes: len(encoded), MaxKeyBytes: len(raw)}
	if _, err := keys.ParsePrivate(encoded, limits); err != nil {
		t.Fatal("PEM overhead counted as decoded key bytes", err)
	}

	for _, small := range []keys.Limits{{MaxInputBytes: len(encoded) - 1}, {MaxKeyBytes: len(raw) - 1}, {MaxASN1Depth: 1}, {MaxASN1Nodes: 1}} {
		if got, err := keys.ParsePrivate(encoded, small); got != nil || !errors.Is(err, keys.ErrLimit) {
			t.Fatalf("limits %+v: key=%v, error=%v", small, got, err)
		}
	}

	c := testcert.New(t)
	if _, err := keys.ParsePublic(c.Leaf.Raw, keys.Limits{MaxKeyBytes: 1, MaxCertificateBytes: len(c.Leaf.Raw)}); err != nil {
		t.Fatal("certificate incorrectly limited as SPKI", err)
	}

	if got, err := keys.ParseCertificate(c.Leaf.Raw, keys.Limits{MaxCertificateBytes: len(c.Leaf.Raw) - 1}); got != nil || !errors.Is(err, keys.ErrLimit) {
		t.Fatalf("certificate budget: %v", err)
	}
}

func TestRSAResourceLimits(t *testing.T) {
	key, err := rsa.GenerateMultiPrimeKey(rand.Reader, 3, 2048) //nolint:staticcheck // Exercise multi-prime import limits with disposable test material.
	if err != nil {
		t.Fatal(err)
	}

	raw, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}

	for _, limits := range []keys.Limits{{MaxRSABits: 2047}, {MaxRSAPrimes: 2}} {
		if got, err := keys.ParsePrivate(raw, limits); got != nil || !errors.Is(err, keys.ErrLimit) {
			t.Fatalf("private limits %+v: %v", limits, err)
		}

		if got, err := keys.MarshalEncryptedPrivate(t.Context(), key, []byte("password"), keys.EncryptionOptions{Iterations: 1000}, limits); got != nil || !errors.Is(err, keys.ErrLimit) {
			t.Fatalf("export limits %+v: %v", limits, err)
		}
	}

	if _, err := keys.ParsePrivate(raw, keys.Limits{MaxRSABits: 2048, MaxRSAPrimes: 3}); err != nil {
		t.Fatal(err)
	}

	public, err := x509.MarshalPKIXPublicKey(key.Public())
	if err != nil {
		t.Fatal(err)
	}

	if got, err := keys.ParsePublic(public, keys.Limits{MaxRSABits: 2047}); got != nil || !errors.Is(err, keys.ErrLimit) {
		t.Fatalf("public modulus budget: %v", err)
	}
}

func TestLimitsValidationAndDefaults(t *testing.T) {
	raw, err := x509.MarshalPKCS8PrivateKey(testcert.Key(t))
	if err != nil {
		t.Fatal(err)
	}

	invalid := []keys.Limits{
		{MaxInputBytes: -1},
		{MaxKeyBytes: -1},
		{MaxCertificateBytes: -1},
		{MaxCRLBytes: -1},
		{MaxContainerBytes: -1},
		{MaxASN1Depth: -1},
		{MaxASN1Nodes: -1},
		{MaxRSABits: -1},
		{MaxRSAPrimes: 1},
		{MaxCertificates: -1},
		{MaxBags: -1},
		{MaxContentInfos: -1},
		{MaxCRLEntries: -1},
		{MaxPasswordBytes: -1},
		{MinIterations: -1},
		{MaxIterations: -1},
		{MaxKDFWork: -1},
		{MinIterations: 2000, MaxIterations: 1000},
	}
	for _, limits := range invalid {
		if got, err := keys.ParsePrivate(raw, limits); got != nil || !errors.Is(err, keys.ErrPolicy) {
			t.Fatalf("invalid limits %+v: %v", limits, err)
		}
	}

	first := keys.DefaultLimits()

	first.MaxKeyBytes = 1
	if _, err := keys.ParsePrivate(raw, first); !errors.Is(err, keys.ErrLimit) {
		t.Fatal("custom default copy not enforced", err)
	}

	if _, err := keys.ParsePrivate(raw, keys.DefaultLimits()); err != nil {
		t.Fatal("default limits shared mutable state", err)
	}
}

func TestProtectedKeyLimits(t *testing.T) {
	key := testcert.Key(t)
	password := bytes.Repeat([]byte{'p'}, 1500)
	limits := keys.Limits{MaxPasswordBytes: len(password), MaxIterations: 4000001, MaxKDFWork: 12000001}

	options := keys.EncryptionOptions{Iterations: 1000, Hash: crypto.SHA256}
	if _, err := keys.MarshalEncryptedPrivate(t.Context(), key, []byte("short"), options, keys.Limits{MaxInputBytes: 1}); err != nil {
		t.Fatal("encoded-input limit incorrectly applied to export", err)
	}

	if got, err := keys.MarshalEncryptedPrivate(t.Context(), key, password, options, keys.Limits{}); got != nil || !errors.Is(err, keys.ErrLimit) {
		t.Fatalf("default password budget: %v", err)
	}

	raw, err := keys.MarshalEncryptedPrivate(t.Context(), key, password, options, limits)
	if err != nil {
		t.Fatal("explicit budgets rejected", err)
	}

	if _, err := keys.ParseEncryptedPrivate(t.Context(), raw, password, limits); err != nil {
		t.Fatal(err)
	}

	for _, small := range []keys.Limits{
		{MaxPasswordBytes: len(password), MaxContainerBytes: len(raw) - 1},
		{MaxPasswordBytes: len(password), MaxKeyBytes: 1},
		{MaxPasswordBytes: len(password), MaxKDFWork: 999},
	} {
		if got, err := keys.ParseEncryptedPrivate(t.Context(), raw, password, small); got != nil || !errors.Is(err, keys.ErrLimit) {
			t.Fatalf("parse limits %+v: %v", small, err)
		}

		if got, err := keys.MarshalEncryptedPrivate(t.Context(), key, password, options, small); got != nil || !errors.Is(err, keys.ErrLimit) {
			t.Fatalf("export limits %+v: %v", small, err)
		}
	}
}
