package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/skarm/xmlsec/c14n"
	"github.com/skarm/xmlsec/internal/testutil/testcert"
	"github.com/skarm/xmlsec/keys"
	"github.com/skarm/xmlsec/xmldsig"
)

func TestCLIKeyFormats(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	_, edKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	for algorithm, signer := range map[string]crypto.Signer{nameRSA: rsaKey, "ecdsa": ecKey, "ed25519": edKey} {
		pkcs8, err := x509.MarshalPKCS8PrivateKey(signer)
		if err != nil {
			t.Fatal(err)
		}

		spki, err := x509.MarshalPKIXPublicKey(signer.Public())
		if err != nil {
			t.Fatal(err)
		}

		private := map[string][]byte{"pkcs8.der": pkcs8, "pkcs8.pem": pem.EncodeToMemory(&pem.Block{Type: privateKeyPEMType, Bytes: pkcs8})}
		public := map[string][]byte{"spki.der": spki, "spki.pem": pem.EncodeToMemory(&pem.Block{Type: publicKeyPEMType, Bytes: spki})}

		switch key := signer.(type) {
		case *rsa.PrivateKey:
			der := x509.MarshalPKCS1PrivateKey(key)
			private["pkcs1.der"], private["pkcs1.pem"] = der, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: der})
			der = x509.MarshalPKCS1PublicKey(&key.PublicKey)
			public["pkcs1.der"], public["pkcs1.pem"] = der, pem.EncodeToMemory(&pem.Block{Type: "RSA PUBLIC KEY", Bytes: der})
		case *ecdsa.PrivateKey:
			der, err := x509.MarshalECPrivateKey(key)
			if err != nil {
				t.Fatal(err)
			}

			private["sec1.der"], private["sec1.pem"] = der, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
		}

		now := time.Date(2026, 10, 9, 0, 0, 0, 0, time.UTC)
		cert := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test pin"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour)}

		certificate, err := x509.CreateCertificate(rand.Reader, cert, cert, signer.Public(), signer)
		if err != nil {
			t.Fatal(err)
		}

		public["certificate.der"], public["certificate.pem"] = certificate, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate})

		dir := t.TempDir()
		for name, encoded := range private {
			t.Run(algorithm+"/"+name, func(t *testing.T) { testCLIKeyFormatsCase(t, &dir, &name, &encoded, &public) })
		}
	}
}

func testCLIKeyFormatsCase(t *testing.T, dir *string, name *string, encoded *[]byte, public *map[string][]byte) {
	path := filepath.Join(*dir, *name)
	if err := os.WriteFile(path, *encoded, 0o600); err != nil {
		t.Fatal(err)
	}

	var signed, stderr bytes.Buffer
	if err := run(context.Background(), []string{nameSign, flagKey, path, "-modern-algorithms"}, strings.NewReader(`<r ID="root"><v>protected</v></r>`), &signed, &stderr); err != nil {
		t.Fatal(err)
	}

	for publicName, encodedPublic := range *public {
		publicPath := filepath.Join(*dir, publicName)
		if err := os.WriteFile(publicPath, encodedPublic, 0o600); err != nil {
			t.Fatal(err)
		}

		var output bytes.Buffer
		if err := run(context.Background(), []string{nameVerify, flagKey, publicPath, "-modern-algorithms"}, bytes.NewReader(signed.Bytes()), &output, &stderr); err != nil {
			t.Fatalf("%s: %v", publicName, err)
		}
	}
}

func TestCLIProtectedKeys(t *testing.T) {
	c := testcert.New(t)
	ctx := context.Background()
	password := []byte("public пароль ü")
	options := keys.EncryptionOptions{Iterations: 1000}

	pkcs8, err := keys.MarshalEncryptedPrivate(ctx, c.LeafKey, password, options, keys.Limits{})
	if err != nil {
		t.Fatal(err)
	}

	pfx, err := keys.MarshalPKCS12(ctx, keys.PKCS12Identity{PrivateKey: c.LeafKey, Certificate: c.Leaf, ExtraCertificates: []*x509.Certificate{c.Root}}, password, keys.PKCS12Options{Encryption: options}, keys.Limits{})
	if err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	write := func(name string, contents []byte) string {
		t.Helper()

		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, contents, 0o600); err != nil {
			t.Fatal(err)
		}

		return path
	}
	public := write("certificate.der", c.Leaf.Raw)
	pwd := write("password.txt", append(bytes.Clone(password), '\r', '\n'))
	write("payload.xml", []byte("authenticated bytes"))
	resources := write("resources.json", []byte(`[{"uri":"urn:test:data","path":"payload.xml"}]`))
	template := fmt.Sprintf(`<root><item ID="data">payload</item><ds:Signature xmlns:ds="%s"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="%s"/><ds:SignatureMethod Algorithm="%s"/><ds:Reference URI="#data"><ds:Transforms><ds:Transform Algorithm="%s"/></ds:Transforms><ds:DigestMethod Algorithm="%s"/><ds:DigestValue/></ds:Reference></ds:SignedInfo><ds:SignatureValue/></ds:Signature></root>`, xmldsig.Namespace, c14n.Exclusive, xmldsig.ECDSASHA256, c14n.Exclusive, xmldsig.SHA256)

	for format, raw := range map[string][]byte{namePkcs8: pkcs8, namePKCS12: pfx} {
		private := write(format, raw)
		for _, mode := range []string{nameSign, nameSignTemplate, nameSignDetached} {
			t.Run(format+"/"+mode, func(t *testing.T) {
				testCLIProtectedKeysCase(t, &mode, &private, &format, &pwd, &public, &template, &resources, &ctx, &write)
			})
		}
	}

	private := write("encrypted.der", pkcs8)
	for _, content := range [][]byte{[]byte("one\ntwo\n"), []byte("one\x00two"), []byte("one\r"), bytes.Repeat([]byte{'x'}, 1025)} {
		bad := write("invalid-password.txt", content)
		if key, err := loadPrivateConfigured(ctx, private, &privateKeyFlags{format: namePkcs8, passwordFile: bad, maxKDFWork: 3000000}); key != nil || err == nil {
			t.Fatal("invalid password file accepted")
		}
	}

	for _, flags := range []*privateKeyFlags{
		{format: namePlain, passwordFile: pwd},
		{format: nameUnknown},
		{format: namePkcs8},
		{format: namePkcs8, passwordFile: "-"},
		{format: namePkcs8, passwordFile: dir},
		{format: namePkcs8, passwordFile: filepath.Join(dir, "missing")},
		{format: namePkcs8, passwordFile: pwd, maxKDFWork: 999},
	} {
		if key, err := loadPrivateConfigured(ctx, private, flags); key != nil || err == nil {
			t.Fatal("invalid key-loading options accepted")
		}
	}
}

func testCLIProtectedKeysCase(t *testing.T, mode *string, private *string, format *string, pwd *string, public *string, template *string, resources *string, ctx *context.Context, write *func(name string, contents []byte) string) {
	args := []string{*mode, flagKey, *private, "-key-format", *format, "-password-file", *pwd}
	verify := []string{nameVerify, flagKey, *public}
	input := `<r ID="root"><v>protected</v></r>`

	switch *mode {
	case nameSignTemplate:
		input = *template

		args = append(args, flagSignatureIndex, "0")
		verify = []string{nameVerifyCore, flagKey, *public, flagSignatureIndex, "0"}
	case nameSignDetached:
		args = append(args, flagResources, *resources)
		verify = []string{nameVerifyDetached, flagKey, *public, flagResources, *resources}
	}

	var signed, stderr bytes.Buffer
	if err := run(*ctx, args, strings.NewReader(input), &signed, &stderr); err != nil {
		t.Fatal(err, stderr.String())
	}

	var report bytes.Buffer
	if err := run(*ctx, verify, bytes.NewReader(signed.Bytes()), &report, &stderr); err != nil {
		t.Fatal(err, report.String())
	}

	wrong := (*write)("wrong.txt", []byte("wrong password\n"))
	out := (*write)("untouched.xml", []byte("existing output"))
	args[6] = wrong // -password-file value.
	args = append(args, "-out", out)

	signed.Reset()

	if err := run(*ctx, args, strings.NewReader(input), &signed, &stderr); err == nil || signed.Len() != 0 {
		t.Fatal("wrong password returned signature output")
	}

	content, err := os.ReadFile(out)
	if err != nil || string(content) != "existing output" {
		t.Fatal("failed key loading modified output file", err)
	}
}

func TestCLIKeyMaterialRejectsAmbiguity(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	private, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}

	public, err := x509.MarshalPKIXPublicKey(key.Public())
	if err != nil {
		t.Fatal(err)
	}

	encoded := pem.EncodeToMemory(&pem.Block{Type: privateKeyPEMType, Bytes: private})
	for _, bad := range [][]byte{
		append(bytes.Clone(private), 0), append(bytes.Clone(private), private...),
		append(bytes.Clone(public), 0), append(bytes.Clone(public), public...),
		append(bytes.Clone(encoded), encoded...), append([]byte("garbage"), encoded...),
		pem.EncodeToMemory(&pem.Block{Type: privateKeyPEMType, Bytes: append(bytes.Clone(private), 0)}),
		pem.EncodeToMemory(&pem.Block{Type: privateKeyPEMType, Bytes: private, Headers: map[string]string{"Proc-Type": "4,ENCRYPTED"}}),
		pem.EncodeToMemory(&pem.Block{Type: "ENCRYPTED PRIVATE KEY", Bytes: private}),
		bytes.Repeat([]byte{0}, keys.DefaultLimits().MaxInputBytes+1),
	} {
		path := filepath.Join(t.TempDir(), "bad.key")
		if err := os.WriteFile(path, bad, 0o600); err != nil {
			t.Fatal(err)
		}

		if key, err := loadPrivateContext(context.Background(), path); err == nil || key != nil {
			t.Fatal("ambiguous private key accepted")
		}

		if key, err := loadPublicContext(context.Background(), path); err == nil || key != nil {
			t.Fatal("ambiguous public key accepted")
		}
	}
	// PEM labels cannot be changed to enable a different parser.
	path := filepath.Join(t.TempDir(), "wrong-label.pem")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: private}), 0o600); err != nil {
		t.Fatal(err)
	}

	if key, err := loadPrivateContext(context.Background(), path); err == nil || key != nil {
		t.Fatal("mismatched PEM label accepted")
	}
}
