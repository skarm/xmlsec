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
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/skarm/xmlsec/c14n"
	"github.com/skarm/xmlsec/internal/testutil"
	"github.com/skarm/xmlsec/internal/testutil/testcert"
	"github.com/skarm/xmlsec/keyinfo"
	"github.com/skarm/xmlsec/keys"
	"github.com/skarm/xmlsec/reference"
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
	if err := run(t.Context(), []string{nameSign, flagKey, path, "-modern-algorithms"}, strings.NewReader(`<r ID="root"><v>protected</v></r>`), &signed, &stderr); err != nil {
		t.Fatal(err)
	}

	for publicName, encodedPublic := range *public {
		publicPath := filepath.Join(*dir, publicName)
		if err := os.WriteFile(publicPath, encodedPublic, 0o600); err != nil {
			t.Fatal(err)
		}

		var output bytes.Buffer
		if err := run(t.Context(), []string{nameVerify, flagKey, publicPath, "-modern-algorithms"}, bytes.NewReader(signed.Bytes()), &output, &stderr); err != nil {
			t.Fatalf("%s: %v", publicName, err)
		}
	}
}

func TestCLIProtectedKeys(t *testing.T) {
	c := testcert.New(t)
	ctx := t.Context()
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

	for format, raw := range map[string][]byte{namePKCS8: pkcs8, namePKCS12: pfx} {
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
		if key, err := loadPrivateConfigured(ctx, private, &privateKeyFlags{format: namePKCS8, passwordFile: bad, maxKDFWork: 3000000}); key != nil || err == nil {
			t.Fatal("invalid password file accepted")
		}
	}

	for _, flags := range []*privateKeyFlags{
		{format: namePlain, passwordFile: pwd},
		{format: nameUnknown},
		{format: namePKCS8},
		{format: namePKCS8, passwordFile: "-"},
		{format: namePKCS8, passwordFile: dir},
		{format: namePKCS8, passwordFile: filepath.Join(dir, "missing")},
		{format: namePKCS8, passwordFile: pwd, maxKDFWork: 999},
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

		if key, err := loadPrivateContext(t.Context(), path); err == nil || key != nil {
			t.Fatal("ambiguous private key accepted")
		}

		if key, err := loadPublicContext(t.Context(), path); err == nil || key != nil {
			t.Fatal("ambiguous public key accepted")
		}
	}
	// PEM labels cannot be changed to enable a different parser.
	path := filepath.Join(t.TempDir(), "wrong-label.pem")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: private}), 0o600); err != nil {
		t.Fatal(err)
	}

	if key, err := loadPrivateContext(t.Context(), path); err == nil || key != nil {
		t.Fatal("mismatched PEM label accepted")
	}
}

func TestKeyInfoInspectionApprovedPrograms(t *testing.T) {
	var corpus struct {
		PublicKey string `json:"public_key_pem"`
		Cases     []stage4CLICase
	}

	raw, err := os.ReadFile(filepath.Join("..", "..", "testdata", "next", "dsig-stage4-vectors.json"))
	if err != nil {
		t.Fatal(err)
	}

	if err := json.Unmarshal(raw, &corpus); err != nil {
		t.Fatal(err)
	}

	block, rest := pem.Decode([]byte(corpus.PublicKey))
	if block == nil || block.Type != "PUBLIC KEY" || len(bytes.TrimSpace(rest)) != 0 {
		t.Fatal("missing independent SPKI pin")
	}

	digest := sha256.Sum256(block.Bytes)
	wantFingerprint := hex.EncodeToString(digest[:])
	fixtures := make(map[string]stage4CLICase, len(corpus.Cases))
	for _, fixture := range corpus.Cases {
		fixtures[fixture.Name] = fixture
	}

	for _, name := range []string{"retrieval-xpath", "retrieval-filter2", "retrieval-xslt", "retrieval-prefixlist"} {
		fixture, ok := fixtures[name]
		if !ok {
			t.Fatalf("missing independent fixture %s", name)
		}

		t.Run(name, func(t *testing.T) {
			testKeyInfoInspectionProgram(t, fixture, wantFingerprint)
		})
	}

	dir := t.TempDir()
	public := testutil.WriteFile(t, dir, "public.pem", []byte(corpus.PublicKey))
	programs := testutil.WriteJSON(t, dir, "programs.json", []reference.Transform{{Algorithm: reference.XPath, XPath: []reference.XPathExpression{{Expression: "false()"}}}})
	var output bytes.Buffer
	if err := run(t.Context(), []string{"keyinfo", "build", "-key", public, "-allowed-programs", programs}, nil, &output, io.Discard); err == nil || output.Len() != 0 {
		t.Fatal("inspection-only option accepted for build", err)
	}
}

func testKeyInfoInspectionProgram(t *testing.T, fixture stage4CLICase, wantFingerprint string) {
	t.Helper()
	dir := t.TempDir()
	entries := make([]resourceEntry, 0, len(fixture.Resources))
	for uri, data := range fixture.Resources {
		path := testutil.WriteFile(t, dir, fmt.Sprintf("resource-%d.xml", len(entries)), data)
		entries = append(entries, resourceEntry{URI: uri, Path: path})
	}

	resources := testutil.WriteJSON(t, dir, "resources.json", entries)
	processing := reference.DefaultOptions()
	for _, program := range fixture.Programs {
		processing.AllowedTransforms = append(processing.AllowedTransforms, program.Algorithm)
	}

	config := testutil.WriteJSON(t, dir, "keyinfo.json", keyinfo.Options{RetrievalProcessing: &processing})
	args := []string{"keyinfo", nameInspect, "-index", "0", "-config", config, "-resources", resources}
	t.Run("approved", func(t *testing.T) {
		approved := append([]string(nil), args...)
		if len(fixture.Programs) != 0 {
			programs := testutil.WriteJSON(t, dir, "programs.json", fixture.Programs)
			approved = append(approved, "-allowed-programs", programs)
		}

		var output bytes.Buffer
		if err := run(t.Context(), approved, strings.NewReader(fixture.XML), &output, io.Discard); err != nil {
			t.Fatal(err)
		}

		var report struct {
			Status     string
			Candidates []struct {
				Fingerprint string `json:"spki_sha256"`
			}
		}

		if err := json.Unmarshal(output.Bytes(), &report); err != nil {
			t.Fatal(err)
		}

		if report.Status != statusUnverified || len(report.Candidates) != 1 || report.Candidates[0].Fingerprint != wantFingerprint {
			t.Fatal("inspection changed untrusted candidate", output.String())
		}
	})
	if len(fixture.Programs) == 0 {
		return
	}

	for _, changed := range []bool{false, true} {
		t.Run(fmt.Sprintf("changed-approval=%t", changed), func(t *testing.T) {
			denied := append([]string(nil), args...)
			if changed {
				programs := testutil.WriteJSON(t, dir, "different.json", []reference.Transform{{Algorithm: reference.XPath, XPath: []reference.XPathExpression{{Expression: "false()"}}}})
				denied = append(denied, "-allowed-programs", programs)
			}

			var output bytes.Buffer
			err := run(t.Context(), denied, strings.NewReader(fixture.XML), &output, io.Discard)
			if !errors.Is(err, keyinfo.ErrPolicy) || output.Len() != 0 {
				t.Fatal("unapproved retrieval program accepted or lost policy error", err, output.String())
			}
		})
	}
}
