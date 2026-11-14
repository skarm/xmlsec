//go:build interop

package interop_test

import (
	"crypto/x509"
	"encoding/pem"
	"path/filepath"
	"testing"
	"time"

	"github.com/skarm/xmlsec/internal/tree"
)

func TestSAMLProfiles(t *testing.T) {
	fixture := newInteropFixture(t)

	selected(t, "portable")
	dir := t.TempDir()
	at := time.Now().UTC().Truncate(time.Second).Format(time.RFC3339)

	p := binary(t, fixture, "samlprobe")
	for _, name := range []string{nameRSASHA256, nameECDSASHA256} {
		key := generateKey(t, dir, name)

		cert := write(t, filepath.Join(dir, "cert.der"), key.cert.Raw)
		for _, kind := range []string{"metadata", "request", "response"} {
			path := filepath.Join(dir, "signed.xml")
			command(t, fixture, true, nil, p, "-mode", "sign-"+kind, flagKey, key.private, flagCert, cert, "-at", at, flagOut, path)

			d := xmlDoc(t, read(t, path))
			for _, sig := range nodes(tree.Root(d), ds, "Signature") {
				verifySignatureValue(t, fixture, d, sig, key.public)

				if !checkReferences(t, fixture, d, sig) {
					t.Fatal("Go SAML Reference differs from independent canonicalization")
				}
			}
		}
	}

	base := filepath.Join(fixture.root, "testdata/saml-interop")

	var cases []struct {
		Name        string
		Kind        string
		Certificate string
		At          string
		Valid       bool
	}
	decode(t, read(t, filepath.Join(base, "manifest.json")), &cases)
	if len(cases) != 16 {
		t.Fatalf("independent SAML fixture count = %d, want 16", len(cases))
	}

	for _, tc := range cases {
		t.Run(tc.Name, func(t *testing.T) {
			certificate := filepath.Join(base, tc.Certificate)

			cert, err := x509.ParseCertificate(read(t, certificate))
			if err != nil {
				t.Fatal(err)
			}

			spki, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
			if err != nil {
				t.Fatal(err)
			}

			public := write(t, filepath.Join(dir, "fixture-public.pem"), pem.EncodeToMemory(&pem.Block{Type: publicKeyPEMType, Bytes: spki}))
			path := filepath.Join(base, tc.Name+".xml")

			d := xmlDoc(t, read(t, path))
			for _, sig := range nodes(tree.Root(d), ds, "Signature") {
				verifySignatureValue(t, fixture, d, sig, public)

				if !checkReferences(t, fixture, d, sig) {
					t.Fatal("semantic negative must retain valid XML signature")
				}
			}

			command(t, fixture, tc.Valid, nil, p, "-mode", "verify-"+tc.Kind, flagIn, path, flagCert, certificate, "-at", tc.At)
		})
	}

	t.Logf("6 generated SAML documents and %d independently signed public fixtures, including semantic negatives", len(cases))
}
