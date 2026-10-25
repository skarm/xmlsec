package main

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"github.com/skarm/xmlsec/internal/testutil/testcert"
	"github.com/skarm/xmlsec/keys"
)

func TestKeyFingerprintAndExportCertificateOrder(t *testing.T) {
	if got := digest([]byte("abc")); got != "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" {
		t.Fatal("fingerprint is not SHA256 hexadecimal", got)
	}
	chain := testcert.New(t)
	directory := t.TempDir()
	write := func(name string, data []byte) string {
		path := filepath.Join(directory, name)
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	certificate := write("leaf.der", chain.Leaf.Raw)
	root := write("root.der", chain.Root.Raw)
	tsa := write("tsa.der", chain.TSA.Raw)
	identity, err := identityForExport(task{Certificate: certificate, Extras: []string{root, tsa}}, chain.LeafKey)
	if err != nil || identity.PrivateKey != chain.LeafKey || !bytes.Equal(identity.Certificate.Raw, chain.Leaf.Raw) || len(identity.ExtraCertificates) != 2 || !bytes.Equal(identity.ExtraCertificates[0].Raw, chain.Root.Raw) || !bytes.Equal(identity.ExtraCertificates[1].Raw, chain.TSA.Raw) {
		t.Fatalf("export identity lost key/certificate/order: %+v %v", identity, err)
	}
	invalid := write("broken.der", []byte("not a certificate"))
	if _, err := identityForExport(task{Certificate: invalid}, chain.LeafKey); err == nil {
		t.Fatal("invalid certificate accepted")
	}
	if err := appendIdentityCertificates(&keys.PKCS12Identity{}, []string{filepath.Join(directory, "missing")}); err == nil {
		t.Fatal("missing extra certificate ignored")
	}
	private, err := x509.MarshalPKCS8PrivateKey(chain.LeafKey)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(private)
	key := write("key.pem", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private}))
	password := []byte("unit fixture password")
	encrypted, err := process(t.Context(), task{Mode: "marshal-pkcs8", Key: key, Password: password})
	if err != nil || len(encrypted.Data) == 0 {
		t.Fatalf("encrypted key output: %q %v", encrypted.Data, err)
	}
	var envelope struct {
		Algorithm  pkix.AlgorithmIdentifier
		Ciphertext []byte
	}
	rest, parseErr := asn1.Unmarshal(encrypted.Data, &envelope)
	if parseErr != nil || len(rest) != 0 || !envelope.Algorithm.Algorithm.Equal(asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 13}) || len(envelope.Ciphertext) == 0 {
		t.Fatalf("not an encrypted PBES2 container: %+v %v", envelope.Algorithm, parseErr)
	}
	protected := write("protected.pem", encrypted.Data)
	imported, err := process(t.Context(), task{Mode: "parse-pkcs8", Input: protected, Password: password})
	spki, marshalErr := x509.MarshalPKIXPublicKey(chain.LeafKey.Public())
	if marshalErr != nil {
		t.Fatal(marshalErr)
	}
	expected := sha256.Sum256(spki)
	if err != nil || imported.Fingerprint != hex.EncodeToString(expected[:]) {
		t.Fatalf("key import fingerprint: %+v %v", imported, err)
	}
	rejected, err := process(t.Context(), task{Mode: "parse-pkcs8", Input: protected, Password: []byte("wrong password")})
	if err == nil || rejected.Fingerprint != "" || len(rejected.Data) != 0 {
		t.Fatal("wrong password released key metadata")
	}
	for _, request := range []task{{Mode: "unknown", Key: key}, {Mode: "marshal-pkcs8", Key: key, Hash: 224, Password: password}, {Mode: "parse-pkcs8", Input: invalid}, {Mode: "parse-pkcs12", Input: invalid}} {
		output, err := process(t.Context(), request)
		if err == nil || len(output.Data) != 0 || output.Fingerprint != "" {
			t.Fatalf("invalid key request produced success: %+v %v", request, err)
		}
	}
}
