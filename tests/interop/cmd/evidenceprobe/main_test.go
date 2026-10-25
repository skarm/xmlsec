package main

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"github.com/skarm/xmlsec/internal/testutil/testcert"
)

func TestHashSelectorsAndSignerLoading(t *testing.T) {
	for _, test := range []struct {
		bits int
		want crypto.Hash
	}{{1, crypto.SHA1}, {256, crypto.SHA256}, {384, crypto.SHA384}, {512, crypto.SHA512}} {
		got, err := hashFromBits(test.bits)
		if err != nil || got != test.want {
			t.Fatalf("hash %d=%v %v", test.bits, got, err)
		}
	}
	for _, bits := range []int{0, 224, -1} {
		if _, err := hashFromBits(bits); err == nil {
			t.Fatalf("unsupported hash %d accepted", bits)
		}
	}
	if key, err := loadSigner(""); key != nil || err != nil {
		t.Fatalf("verification unexpectedly required a signer: %v", err)
	}
	chain := testcert.New(t)
	raw, err := x509.MarshalPKCS8PrivateKey(chain.LeafKey)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(raw)
	directory := t.TempDir()
	path := filepath.Join(directory, "signer.pem")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	signer, err := loadSigner(path)
	if err != nil || signer == nil || !chain.LeafKey.PublicKey.Equal(signer.Public()) {
		t.Fatalf("loaded a different signer: %v", err)
	}
	for _, data := range [][]byte{[]byte("not PEM"), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("invalid DER")})} {
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
		if key, err := loadSigner(path); key != nil || err == nil {
			t.Fatal("malformed signer accepted")
		}
	}
	// Construct the RFC8410 fixture directly: the parser must reject a key
	// agreement credential as a signer, including when X25519 is unavailable.
	seed, err := asn1.Marshal(bytes.Repeat([]byte{0x51}, 32))
	if err != nil {
		t.Fatal(err)
	}
	agreementDER, err := asn1.Marshal(struct {
		Version    int
		Algorithm  pkix.AlgorithmIdentifier
		PrivateKey []byte
	}{0, pkix.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{1, 3, 101, 110}}, seed})
	if err != nil {
		t.Fatal(err)
	}
	defer clear(agreementDER)
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: agreementDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	if signer, err := loadSigner(path); signer != nil || err == nil {
		t.Fatal("key agreement credential accepted as signer")
	}
	if _, err := loadSigner(filepath.Join(directory, "missing")); err == nil {
		t.Fatal("missing signer ignored")
	}
}
