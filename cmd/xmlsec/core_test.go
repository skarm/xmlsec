package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/skarm/xmlsec/c14n"
	"github.com/skarm/xmlsec/internal/testutil"
	"github.com/skarm/xmlsec/keyinfo"
	"github.com/skarm/xmlsec/reference"
	"github.com/skarm/xmlsec/xmldsig"
)

const (
	nameSignatureGroup = "signature"
	flagPreserve       = "-preserve"
	flagExpectURI      = "-expect-uri"
)

type stage4CLICase struct {
	Name      string
	Kind      string
	XML       string
	Resources map[string][]byte
	Programs  []reference.Transform
}

func TestStage4CLI(t *testing.T) {
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

	public := testutil.WriteFile(t, t.TempDir(), "public.pem", []byte(corpus.PublicKey))
	for _, test := range corpus.Cases {
		t.Run(test.Name, func(t *testing.T) { testStage4CLI(t, test, public) })
	}

	for _, args := range [][]string{
		{nameVerifyCore, flagKey, public, flagSignatureIndex, "0", "-manifest-transforms"},
		{nameSignatureGroup, nameVerifyKeyInfo, flagKey, public, flagSignatureIndex, "0", "-keyinfo-base-uri", "https://example.test/signature.xml"},
	} {
		var output, stderr bytes.Buffer
		if err := run(t.Context(), args, strings.NewReader(corpus.Cases[0].XML), &output, &stderr); err == nil {
			t.Fatal("incomplete opt-in flags accepted")
		}
	}
}

func testStage4CLI(t *testing.T, test stage4CLICase, public string) {
	t.Helper()
	dir := t.TempDir()

	entries := make([]resourceEntry, 0, len(test.Resources))
	for uri, data := range test.Resources {
		entries = append(entries, resourceEntry{URI: uri, Path: testutil.WriteFile(t, dir, fmt.Sprintf("resource-%d.bin", len(entries)), data)})
	}

	resources := testutil.WriteJSON(t, dir, "resources.json", entries)

	args := []string{nameSignatureGroup, nameVerifyKeyInfo, flagKey, public, flagSignatureIndex, "0", flagExpectURI, "#payload"}
	if test.Kind == "manifest" {
		args = []string{nameVerifyCore, flagKey, public, flagSignatureIndex, "0", flagExpectURI, "urn:manifest", "-resources", resources, "-manifests", nameRecursiveExternal, "-manifest-transforms"}
	}

	if len(test.Programs) != 0 {
		args = append(args, "-allowed-programs", testutil.WriteJSON(t, dir, "programs.json", test.Programs))
	}

	if test.Kind != "manifest" {
		if len(entries) != 0 {
			args = append(args, "-keyinfo-resources", resources)
		}

		processing := reference.DefaultOptions()
		for _, program := range test.Programs {
			processing.AllowedTransforms = append(processing.AllowedTransforms, program.Algorithm)
		}

		args = append(args, "-keyinfo-config", testutil.WriteJSON(t, dir, "keyinfo.json", keyinfo.Options{RetrievalProcessing: &processing}))
	}

	var output, stderr bytes.Buffer
	if err := run(t.Context(), args, strings.NewReader(test.XML), &output, &stderr); err != nil {
		t.Fatal(err, stderr.String())
	}

	if test.Kind == "keyinfo" {
		// Unsigned key discovery has its own base and exact resolved allowlist.
		// The signed #payload reference stays in the signature document.
		relative := strings.Replace(test.XML, `URI="urn:keys#stored"`, `URI="keys.xml#stored"`, 1)
		entries[0].URI = "https://example.test/keys.xml#stored"
		testutil.WriteJSON(t, dir, "resources.json", entries)
		output.Reset()

		if err := run(t.Context(), append(args, "-keyinfo-base-uri", "https://example.test/signature.xml"), strings.NewReader(relative), &output, &stderr); err != nil {
			t.Fatal("separate KeyInfo URI context", err)
		}

		output.Reset()

		if err := run(t.Context(), args, strings.NewReader(relative), &output, &stderr); err == nil {
			t.Fatal("relative KeyInfo URI accepted without a base")
		}
	}
}

func TestCoreCLI(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()

	key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}

	private, public := filepath.Join(dir, "private.pem"), filepath.Join(dir, "public.pem")

	der, e := x509.MarshalPKCS8PrivateKey(key)
	if e != nil {
		t.Fatal(e)
	}

	if e = os.WriteFile(private, pem.EncodeToMemory(&pem.Block{Type: privateKeyPEMType, Bytes: der}), 0o600); e != nil {
		t.Fatal(e)
	}

	der, e = x509.MarshalPKIXPublicKey(key.Public())
	if e != nil {
		t.Fatal(e)
	}

	if e = os.WriteFile(public, pem.EncodeToMemory(&pem.Block{Type: publicKeyPEMType, Bytes: der}), 0o600); e != nil {
		t.Fatal(e)
	}

	sig := fmt.Sprintf(`<ds:Signature xmlns:ds="%s" Id="s0"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="%s"/><ds:SignatureMethod Algorithm="%s"/><ds:Reference URI="#data"><ds:Transforms><ds:Transform Algorithm="%s"/></ds:Transforms><ds:DigestMethod Algorithm="%s"/><ds:DigestValue/></ds:Reference></ds:SignedInfo><ds:SignatureValue/></ds:Signature>`, xmldsig.Namespace, c14n.Exclusive, xmldsig.ECDSASHA256, c14n.Exclusive, xmldsig.SHA256)
	raw := `<root><item ID="data">payload</item>` + sig + strings.Replace(sig, `Id="s0"`, `Id="s1"`, 1) + `</root>`

	var signed, stderr bytes.Buffer
	if e := run(ctx, []string{nameSignTemplate, flagKey, private, flagSignatureIndex, "0", flagExpectURI, "#data"}, strings.NewReader(raw), &signed, &stderr); e != nil {
		t.Fatal(e)
	}

	first := signed.String()
	signed.Reset()

	if e := run(ctx, []string{nameSignTemplate, flagKey, private, flagSignatureIndex, "1", flagPreserve, "0=" + public}, strings.NewReader(first), &signed, &stderr); e != nil {
		t.Fatal(e)
	}

	both := signed.String()

	for _, i := range []string{"0", "1"} {
		var out bytes.Buffer
		if e := run(ctx, []string{nameVerifyCore, flagKey, public, flagSignatureIndex, i, flagExpectURI, "#data"}, strings.NewReader(both), &out, &stderr); e != nil {
			t.Fatal(e)
		}

		var report xmldsig.VerificationReport
		if e := json.Unmarshal(coreVerificationChecks(t, out.Bytes()), &report); e != nil {
			t.Fatal(e)
		}

		if report.Status != xmldsig.Valid || report.SignatureValue != xmldsig.Valid {
			t.Fatal(out.String())
		}
	}

	t.Run("failure-has-json", func(t *testing.T) {
		var out bytes.Buffer

		e := run(ctx, []string{nameVerifyCore, flagKey, public, flagSignatureIndex, "0", "-require-root"}, strings.NewReader(both), &out, &stderr)
		if e == nil {
			t.Fatal("unsigned root accepted")
		}

		var report xmldsig.VerificationReport
		if e := json.Unmarshal(coreVerificationChecks(t, out.Bytes()), &report); e != nil {
			t.Fatal(e)
		}

		if report.Status != xmldsig.Disallowed || report.SignatureValue != xmldsig.Valid || report.FailureStage != "coverage" {
			t.Fatal(report)
		}
	})

	t.Run("external-uri-context", func(t *testing.T) {
		testCoreExternalURIContext(t, dir, private, public, sig)
	})

	for _, args := range [][]string{
		{nameVerifyCore},
		{nameVerifyCore, flagKey, public},
		{nameVerifyCore, flagKey, public, flagSignatureIndex, "99"},
		{nameSignTemplate, flagKey, private, flagSignatureIndex, "1"},
		{nameSignTemplate, flagKey, private, flagSignatureIndex, "1", flagPreserve, "bad"},
		{nameSignTemplate, flagKey, private, flagSignatureIndex, "1", flagPreserve, "9=" + public},
		{nameSignTemplate, flagKey, private, flagSignatureIndex, "1", flagPreserve, "0=missing-file"},
		{nameVerifyCore, flagKey, public, flagSignatureIndex, "0", nameExtra},
	} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			var out bytes.Buffer
			if e := run(ctx, args, strings.NewReader(first), &out, &stderr); e == nil {
				t.Fatal("invalid arguments accepted")
			}
		})
	}

	for _, cmd := range []string{nameSignTemplate, nameVerifyCore} {
		if e := run(ctx, []string{cmd, "-h"}, nil, &signed, &stderr); e != nil {
			t.Fatal(e)
		}
	}
}

func testCoreExternalURIContext(t *testing.T, dir, private, public, sig string) {
	t.Helper()

	const (
		base = "https://example.test/signature.xml"
		uri  = "https://example.test/list.xml#part"
	)

	payload := []byte("external CLI payload")
	digest := sha256.Sum256(payload)

	manifest := `<ds:Manifest xmlns:ds="` + xmldsig.Namespace + `" Id="part"><ds:Reference URI="payload.bin"><ds:DigestMethod Algorithm="` + xmldsig.SHA256 + `"/><ds:DigestValue>` + base64.StdEncoding.EncodeToString(digest[:]) + `</ds:DigestValue></ds:Reference></ds:Manifest>`
	for name, contents := range map[string][]byte{"selected-manifest.xml": []byte(manifest), "payload.bin": payload} {
		if err := os.WriteFile(filepath.Join(dir, name), contents, 0o600); err != nil {
			t.Fatal(err)
		}
	}

	entries := []resourceEntry{{URI: uri, Path: "selected-manifest.xml"}, {URI: "https://example.test/payload.bin", Path: "payload.bin"}}

	encoded, err := json.Marshal(entries)
	if err != nil {
		t.Fatal(err)
	}

	resources := filepath.Join(dir, "uri-resources.json")
	if err := os.WriteFile(resources, encoded, 0o600); err != nil {
		t.Fatal(err)
	}

	draft := []byte(strings.Replace(sig, `URI="#data"`, `URI="list.xml#part" Type="`+xmldsig.ManifestType+`"`, 1))
	args := []string{flagSignatureIndex, "0", "-resources", resources, "-base-uri", base, "-manifests", nameRecursiveExternal, flagExpectURI, "list.xml#part"}
	signed := cli(t, draft, append([]string{nameSignTemplate, flagKey, private}, args...)...)
	out := cli(t, signed, append([]string{nameVerifyCore, flagKey, public}, args...)...)

	var report xmldsig.VerificationReport
	if err := json.Unmarshal(coreVerificationChecks(t, out), &report); err != nil {
		t.Fatal(err)
	}

	if report.Status != xmldsig.Valid || report.ManifestValidation != xmldsig.Valid || report.References[0].URI != "list.xml#part" || report.References[0].ResourceURI != uri || report.Manifests[0].References[0].ResourceURI != "https://example.test/payload.bin" {
		t.Fatal(report)
	}

	if err := os.WriteFile(filepath.Join(dir, "payload.bin"), []byte("changed CLI payload"), 0o600); err != nil {
		t.Fatal(err)
	}

	var diagnostics, stderr bytes.Buffer
	if err := run(t.Context(), append([]string{nameVerifyCore, flagKey, public}, args...), bytes.NewReader(signed), &diagnostics, &stderr); err == nil {
		t.Fatal("changed nested resource accepted")
	}

	if err := json.Unmarshal(coreVerificationChecks(t, diagnostics.Bytes()), &report); err != nil {
		t.Fatal(err)
	}

	if report.References[0].Status != xmldsig.Valid || report.ManifestValidation != xmldsig.Invalid {
		t.Fatal(report)
	}

	rejectCLI(t, draft, nameSignTemplate, flagKey, private, flagSignatureIndex, "0", "-base-uri", base)
	rejectCLI(t, draft, nameSignTemplate, flagKey, private, flagSignatureIndex, "0", "-resources", resources)
}
