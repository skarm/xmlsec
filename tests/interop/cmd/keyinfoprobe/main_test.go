package main

import (
	"bytes"
	"crypto/x509"
	"testing"

	"github.com/skarm/xmlsec/internal/testutil/testcert"
	"github.com/skarm/xmlsec/keyinfo"
	"github.com/skarm/xmlsec/xmldsig"
)

func TestKeyInfoBuildParseAndPinnedVerification(t *testing.T) {
	chain := testcert.New(t)
	spki, err := x509.MarshalPKIXPublicKey(chain.LeafKey.Public())
	if err != nil {
		t.Fatal(err)
	}
	private, err := x509.MarshalPKCS8PrivateKey(chain.LeafKey)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(private)
	built, err := run(task{Mode: "build", SPKI: spki, Format: string(keyinfo.DERKeyValue)})
	if err != nil || !bytes.Contains(built.Data, []byte("  exact key name  ")) {
		t.Fatalf("build lost exact name: %q %v", built.Data, err)
	}
	parsed, err := run(task{Mode: "parse", Input: built.Data})
	if err != nil || len(parsed.Keys) != 1 || !bytes.Equal(parsed.Keys[0], spki) {
		t.Fatalf("parsed key: %+v %v", parsed, err)
	}
	parsed.Keys[0][0] ^= 1
	fresh, err := run(task{Mode: "parse", Input: built.Data})
	if err != nil || len(fresh.Keys) != 1 || !bytes.Equal(fresh.Keys[0], spki) {
		t.Fatal("caller modified later candidate bytes", err)
	}
	signed, err := run(task{Mode: "sign", SPKI: spki, Private: private, Method: xmldsig.ECDSASHA256, Format: string(keyinfo.DERKeyValue)})
	if err != nil || len(signed.Data) == 0 {
		t.Fatalf("sign: %v", err)
	}
	verified, err := run(task{Mode: "verify", Input: signed.Data, SPKI: spki})
	if err != nil || !verified.Valid {
		t.Fatalf("pinned verification: %+v %v", verified, err)
	}
	certificateInfo, err := run(task{Mode: "build", SPKI: spki, Certificate: chain.Leaf.Raw})
	if err != nil || !bytes.Contains(certificateInfo.Data, []byte("X509Certificate")) || bytes.Contains(certificateInfo.Data, []byte("DEREncodedKeyValue")) {
		t.Fatalf("certificate projection lost its shape: %q %v", certificateInfo.Data, err)
	}
	certificateKeys, err := run(task{Mode: "parse", Input: certificateInfo.Data})
	if err != nil || len(certificateKeys.Keys) != 1 || !bytes.Equal(certificateKeys.Keys[0], spki) {
		t.Fatalf("certificate key mismatch: %+v %v", certificateKeys, err)
	}
	other, err := x509.MarshalPKIXPublicKey(chain.TSAKey.Public())
	if err != nil {
		t.Fatal(err)
	}
	rejected, err := run(task{Mode: "verify", Input: signed.Data, SPKI: other})
	if err == nil || rejected.Valid {
		t.Fatal("untrusted KeyInfo candidate accepted")
	}
	for _, request := range []task{{Mode: "unknown"}, {Mode: "parse", Input: []byte(`<broken`)}, {Mode: "verify", Input: []byte(`<r/>`), SPKI: spki}, {Mode: "build", SPKI: []byte("invalid")}} {
		answer, err := run(request)
		if err == nil || answer.Valid || len(answer.Data) != 0 {
			t.Fatalf("invalid request leaked a success: %+v %v", request, err)
		}
	}
}
