package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/fips140"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/skarm/xmlsec/c14n"
	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/internal/testutil"
	"github.com/skarm/xmlsec/internal/testutil/testcert"
	"github.com/skarm/xmlsec/reference"
	"github.com/skarm/xmlsec/xmldsig"
	"github.com/skarm/xmlsec/xmlenc"
)

const (
	testObjectURI = "#object"
	testObjectID  = "object"
)

func TestApplicationHelpAndUsage(t *testing.T) {
	for _, args := range [][]string{nil, {"--help"}, {nameHelp}, {"signature"}, {nameHelp, nameEncryption}, {"key", "-h"}, {jsonErrorsFlag, nameHelp}} {
		if len(cli(t, nil, args...)) == 0 {
			t.Fatalf("empty help %v", args)
		}
	}

	for _, c := range commands() {
		t.Run(c.name, func(t *testing.T) {
			args := append(strings.Fields(c.name), "-h")

			var out, stderr bytes.Buffer
			if err := run(context.Background(), args, nil, &out, &stderr); err != nil {
				t.Fatal(err)
			}

			if !strings.Contains(stderr.String(), "-timeout") {
				t.Fatal("missing execution help", stderr.String())
			}
		})
	}

	for _, args := range [][]string{{nameBogus}, {nameHelp, nameBogus}, {"version", nameExtra}, {"algorithms", nameExtra}, {nameC14n, "-unknown"}, {nameC14n, "-max-input-bytes", "0"}, {nameC14n, "-timeout", "-1s"}} {
		var out bytes.Buffer

		err := run(context.Background(), args, strings.NewReader(`<r/>`), &out, io.Discard)
		if err == nil || exitCode(err) != 2 {
			t.Fatal(args, err, exitCode(err))
		}
	}

	if !json.Valid(cli(t, nil, "version")) || !json.Valid(cli(t, nil, "algorithms")) {
		t.Fatal("invalid metadata JSON")
	}

	if exitCode(context.Canceled) != 130 || exitCode(context.DeadlineExceeded) != 124 || exitCode(errors.New("failed")) != 1 {
		t.Fatal("bad exit code")
	}
}

func TestCanceledStreamsAndDeadline(t *testing.T) {
	for _, deadline := range []bool{false, true} {
		t.Run(map[bool]string{false: "cancel", true: "deadline"}[deadline], func(t *testing.T) {
			r, w := io.Pipe()
			defer w.Close()

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			args := []string{nameC14n}
			if deadline {
				args = append(args, "-timeout", "25ms")
			}

			done := make(chan error, 1)
			go func() { done <- run(ctx, args, r, io.Discard, io.Discard) }()

			if !deadline {
				cancel()
			}

			select {
			case err := <-done:
				expected := context.Canceled
				if deadline {
					expected = context.DeadlineExceeded
				}

				if !errors.Is(err, expected) {
					t.Fatal(err)
				}
			case <-time.After(2 * time.Second):
				_ = r.Close()

				t.Fatal("canceled pipe read did not return")
			}
		})
	}

	r, w := io.Pipe()
	defer r.Close()

	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan error, 1)
	go func() { done <- writeOutputContext(ctx, "-", w, []byte("blocked")) }()

	cancel()

	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		_ = w.Close()

		t.Fatal("blocked write did not cancel")
	}

	dir := t.TempDir()
	out := testutil.WriteFile(t, dir, "keep.xml", []byte("original"))
	rejectCLI(t, []byte(`<root/>`), nameC14n, "-out", out, "-max-output-bytes", "1")

	b, err := os.ReadFile(out)
	if err != nil || string(b) != "original" {
		t.Fatal("failed operation modified output", err)
	}
}

func TestStrictConfigurationAndManifestPolicy(t *testing.T) {
	dir := t.TempDir()
	for _, raw := range []string{`{"roots":[],"roots":["x"]}`, `{"unknown":1}`, `{} {}`, `null []`} {
		path := testutil.WriteFile(t, dir, "invalid.json", []byte(raw))

		var c trustConfig
		if err := readJSONFile(context.Background(), path, &c); err == nil {
			t.Fatal("accepted invalid config", raw)
		}
	}

	for _, field := range []string{`"type":""`, `"digest_method":"urn:unsupported"`, `"transforms":[]`, `"transforms":null`} {
		path := testutil.WriteFile(t, dir, "resources.json", []byte(`[{"uri":"urn:data","path":"data",`+field+`}]`))

		entries, _, err := loadResourcesContext(context.Background(), path)
		if err != nil {
			t.Fatal(err)
		}

		if err := validateResourceAllowlist(entries); err == nil {
			t.Fatal("accepted recipe in verification allowlist", field)
		}
	}
}

func TestDetachedRaisedResourceLimit(t *testing.T) {
	c := testcert.New(t)
	dir := t.TempDir()
	key := testutil.WritePrivateKey(t, dir, "private.pem", c.LeafKey)
	public := testutil.WritePublicKey(t, dir, "public.pem", c.LeafKey.Public())
	payload := bytes.Repeat([]byte{'a'}, (8<<20)+1)
	testutil.WriteFile(t, dir, "data", payload)
	resources := testutil.WriteFile(t, dir, "resources.json", []byte(`[{"uri":"urn:data","path":"data"}]`))
	rejectCLI(t, nil, "signature", "sign-detached", flagKey, key, "-resources", resources)
	signed := cli(t, nil, "signature", "sign-detached", flagKey, key, "-resources", resources, "-max-resource-bytes", "9437184")

	report := cli(t, signed, "signature", "verify-detached", flagKey, public, "-resources", resources, "-max-resource-bytes", "9437184")
	if !bytes.Contains(report, []byte(`"status": "valid"`)) {
		t.Fatal(string(report))
	}
	// Core external references must honor the same raised input budget.
	spec := templateConfig{Method: xmldsig.ECDSASHA256, References: []xmldsig.ReferenceTemplate{{URI: "urn:data"}}}
	config := testutil.WriteJSON(t, dir, "template.json", spec)
	draft := cli(t, nil, "signature", "build", "-config", config)
	signed = cli(t, draft, "signature", "sign-template", flagKey, key, "-signature-index", "0", "-resources", resources, "-max-resource-bytes", "9437184")
	cli(t, signed, "signature", "verify-core", flagKey, public, "-signature-index", "0", "-resources", resources, "-max-resource-bytes", "9437184", "-expect-uri", "urn:data")
}

func TestTemplateAlgorithmsAndApprovedPrograms(t *testing.T) {
	c := testcert.New(t)
	dir := t.TempDir()
	key := testutil.WritePrivateKey(t, dir, "key.pem", c.LeafKey)
	pub := testutil.WritePublicKey(t, dir, "pub.pem", c.LeafKey.Public())
	secret := testutil.WriteFile(t, dir, "secret", bytes.Repeat([]byte{7}, 32))
	text := "authenticated"
	build := func(method string, parameters xmldsig.SignatureParameters, transforms []reference.Transform) []byte {
		params := templateParameters{HMACOutputLength: parameters.HMACOutputLength}
		if parameters.PSS != nil {
			params.PSS = &templatePSS{Hash: parameters.PSS.Hash.String(), MGFHash: parameters.PSS.MGFHash.String(), SaltLength: parameters.PSS.SaltLength}
		}

		cfg := templateConfig{Method: method, Parameters: params, References: []xmldsig.ReferenceTemplate{{URI: testObjectURI, Transforms: transforms}}, Objects: []templateObject{{ID: testObjectID, Text: &text}}}
		path := testutil.WriteJSON(t, dir, "template.json", cfg)

		return cli(t, nil, "signature", "build", "-config", path)
	}
	hmac := build(xmldsig.HMACSHA256, xmldsig.SignatureParameters{}, []reference.Transform{{Algorithm: c14n.Exclusive}})
	signed := cli(t, hmac, "signature", "sign-template", "-signature-index", "0", "-secret-file", secret, "-policy", nameHMAC)
	cli(t, signed, "signature", "verify-core", "-signature-index", "0", "-secret-file", secret, "-policy", nameHMAC, "-expect-uri", testObjectURI)
	rejectCLI(t, signed, "signature", "verify-core", "-signature-index", "0", "-secret-file", secret)

	program := reference.Transform{Algorithm: reference.XPath, XPath: []reference.XPathExpression{{Expression: "true()", Namespaces: map[string]string{"ds": xmldsig.Namespace}}}}
	programs := testutil.WriteJSON(t, dir, "programs.json", []reference.Transform{program})
	draft := build(xmldsig.ECDSASHA256, xmldsig.SignatureParameters{}, []reference.Transform{program, {Algorithm: c14n.Exclusive}})
	rejectCLI(t, draft, "signature", "sign-template", "-signature-index", "0", flagKey, key)
	signed = cli(t, draft, "signature", "sign-template", "-signature-index", "0", flagKey, key, "-allowed-programs", programs)
	cli(t, signed, "signature", "verify-core", "-signature-index", "0", flagKey, pub, "-allowed-programs", programs)
	other := testutil.WriteJSON(t, dir, "different-program.json", []reference.Transform{{Algorithm: reference.XPath, XPath: []reference.XPathExpression{{Expression: "false()"}}}})
	rejectCLI(t, signed, "signature", "verify-core", "-signature-index", "0", flagKey, pub, "-allowed-programs", other)

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	rsaPrivate := testutil.WritePrivateKey(t, dir, "rsa.pem", rsaKey)
	rsaPublic := testutil.WritePublicKey(t, dir, "rsa.pub", rsaKey.Public())
	draft = build(xmldsig.RSAPSS, xmldsig.SignatureParameters{PSS: &xmldsig.PSSParameters{Hash: crypto.SHA384, MGFHash: crypto.SHA384, SaltLength: 24}}, []reference.Transform{{Algorithm: c14n.Exclusive}})
	rejectCLI(t, draft, "signature", "sign-template", "-signature-index", "0", flagKey, rsaPrivate, "-policy", "modern")
	signed = cli(t, draft, "signature", "sign-template", "-signature-index", "0", flagKey, rsaPrivate, "-policy", "pss")
	cli(t, signed, "signature", "verify-core", "-signature-index", "0", flagKey, rsaPublic, "-policy", "pss")

	inspect := cli(t, signed, "signature", nameInspect)
	if !bytes.Contains(inspect, []byte(xmldsig.RSAPSS)) {
		t.Fatal(string(inspect))
	}
}

func TestEncryptionScopesAndTransports(t *testing.T) {
	dir := t.TempDir()

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	private := testutil.WritePrivateKey(t, dir, nameRSA, rsaKey)
	public := testutil.WritePublicKey(t, dir, "rsa.pub", rsaKey.Public())
	secret := testutil.WriteFile(t, dir, "aes", bytes.Repeat([]byte{9}, 32))
	source := []byte(`<root xmlns:p="urn:p"><p:item ID="payload">secret<child/>tail</p:item><other>keep</other></root>`)

	for _, transport := range []string{nameRSA, "wrap", transportDirect} {
		for _, scope := range []string{scopeBytes, "document", scopeElement, "content"} {
			t.Run(transport+"/"+scope, func(t *testing.T) { testEncryptionRoundtrip(t, dir, source, transport, scope, private, public, secret) })
		}
	}

	encrypted := cli(t, source, nameEncrypt, flagKey, secret, "-transport", transportDirect, "-scope", scopeElement, "-id", "payload")
	cipherPath := filepath.Join(dir, "cipher.bin")
	external := cli(t, encrypted, nameEncryption, "externalize", "-uri", "urn:cipher", "-cipher-out", cipherPath)
	resources := testutil.WriteFile(t, dir, "cipher.json", []byte(`[{"uri":"urn:cipher","path":"cipher.bin"}]`))

	restored := cli(t, external, nameDecrypt, flagKey, secret, "-transport", transportDirect, "-scope", scopeElement, "-resources", resources)
	if xmlCanonical(t, source) != xmlCanonical(t, restored) {
		t.Fatal("external CipherReference roundtrip failed")
	}

	for _, algorithm := range []struct {
		uri   string
		bytes int
	}{{xmlenc.AES128GCM, 16}, {xmlenc.AES192GCM, 24}, {xmlenc.AES256GCM, 32}} {
		key := testutil.WriteFile(t, dir, "symmetric", bytes.Repeat([]byte{3}, algorithm.bytes))
		encrypted := cli(t, source, nameEncrypt, "-transport", transportDirect, flagKey, key, "-algorithm", algorithm.uri, "-key-name", "test")
		cli(t, encrypted, nameDecrypt, "-transport", transportDirect, flagKey, key, "-algorithm", algorithm.uri, "-key-name", "test")
		rejectCLI(t, encrypted, nameDecrypt, "-transport", transportDirect, flagKey, key, "-algorithm", algorithm.uri, "-key-name", "wrong")
	}
}

func xmlCanonical(t *testing.T, raw []byte) string { t.Helper(); return string(cli(t, raw, nameC14n)) }

func testEncryptionRoundtrip(t *testing.T, dir string, source []byte, transport, scope, private, public, secret string) {
	encKey, decKey := secret, secret
	if transport == nameRSA {
		encKey, decKey = public, private
	}

	args := []string{nameEncryption, nameEncrypt, flagKey, encKey, "-transport", transport, "-scope", scope}
	if scope == scopeElement || scope == "content" {
		args = append(args, "-id", "payload")
	}

	signed := cli(t, source, args...)

	restored := cli(t, signed, nameEncryption, nameDecrypt, flagKey, decKey, "-transport", transport, "-scope", scope)
	if scope == scopeBytes {
		if !bytes.Equal(source, restored) {
			t.Fatal("raw bytes changed")
		}
	} else if xmlCanonical(t, source) != xmlCanonical(t, restored) {
		t.Fatal("XML changed", string(restored))
	}

	tampered := append([]byte(nil), signed...)

	i := bytes.Index(tampered, []byte("CipherValue>"))
	if i < 0 {
		t.Fatal("no CipherValue")
	}

	i += len("CipherValue>")
	if tampered[i] == 'A' {
		tampered[i] = 'B'
	} else {
		tampered[i] = 'A'
	}

	out := testutil.WriteFile(t, dir, "unchanged", []byte("keep"))
	rejectCLI(t, tampered, nameEncryption, nameDecrypt, flagKey, decKey, "-transport", transport, "-scope", scope, "-out", out)

	value, err := os.ReadFile(out)
	if err != nil || string(value) != "keep" {
		t.Fatal("unauthenticated plaintext replaced output", err)
	}
}

func TestKeyKeyInfoAndTransformCommands(t *testing.T) {
	dir := t.TempDir()
	password := testutil.WriteFile(t, dir, "password", []byte("secret\n"))
	private := testutil.WriteFile(t, dir, "private", cli(t, nil, "key", "generate", "-algorithm", "p256"))
	public := cli(t, nil, "key", namePublic, "-in", private)
	publicFile := testutil.WriteFile(t, dir, namePublic, public)
	encrypted := cli(t, nil, "key", "convert", "-in", private, "-output-format", "pkcs8", "-output-password-file", password, "-iterations", "1000")
	encryptedFile := testutil.WriteFile(t, dir, "encrypted", encrypted)

	restoredPublic := cli(t, nil, "key", namePublic, "-in", encryptedFile, "-key-format", "pkcs8", "-password-file", password)
	if !bytes.Equal(public, restoredPublic) {
		t.Fatal("encrypted conversion changed key")
	}

	report := cli(t, nil, "key", nameInspect, "-in", private, "-kind", "private")
	if bytes.Contains(report, []byte("PRIVATE KEY")) || !bytes.Contains(report, []byte("spki_sha256")) {
		t.Fatal(string(report))
	}

	for _, format := range []string{"der", "xml"} {
		ki := cli(t, nil, "keyinfo", "build", flagKey, publicFile, "-name", "hint", "-format", format)

		report := cli(t, ki, "keyinfo", nameInspect)
		if !bytes.Contains(report, []byte(`"status": "unverified"`)) || !bytes.Contains(report, []byte("spki_sha256")) {
			t.Fatal(string(report))
		}
	}

	bindings := testutil.WriteFile(t, dir, "bindings.json", []byte(`[{"name":{"Local":"extra"},"type":"decimal","value":"2.5"}]`))

	source := []byte(`<r><v>1</v><v>2</v></r>`)
	if got := string(cli(t, source, nameXPath, "-expression", "sum(/r/v ! xs:decimal(.)) + $extra", "-bindings", bindings)); got != "5.5\n" {
		t.Fatal(got)
	}

	if !json.Valid(cli(t, source, nameXPath, "-expression", `map{'sum':sum(/r/v),'values':array{/r/v/string()}}`, "-format", "json")) {
		t.Fatal("invalid XPath result")
	}

	for _, version := range []string{version10, version20, version30} {
		sheet := testutil.WriteFile(t, dir, "sheet.xsl", []byte(`<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="`+version+`"><xsl:output method="text"/><xsl:template match="/"><xsl:value-of select="sum(/r/v)"/></xsl:template></xsl:stylesheet>`))
		if got := string(cli(t, source, nameXSLT, "-stylesheet", sheet, "-version", version)); got != "3" {
			t.Fatal(got)
		}
	}

	filtered := cli(t, []byte(`<r><keep>yes</keep><omit>no</omit></r>`), nameC14n, "-xpath", "not(ancestor-or-self::omit)")
	if string(filtered) != `<r><keep>yes</keep></r>` {
		t.Fatal(string(filtered))
	}
	// An unknown URI must never trigger filesystem or network access.
	rejectCLI(t, source, nameXPath, "-expression", `doc('file:///etc/passwd')`)
}

func TestKeyInfoSelectionAndRequiredIDRules(t *testing.T) {
	c := testcert.New(t)
	dir := t.TempDir()
	private := testutil.WritePrivateKey(t, dir, "key", c.LeafKey)
	public := testutil.WritePublicKey(t, dir, "pub", c.LeafKey.Public())
	keyInfo := testutil.WriteFile(t, dir, "keyinfo.xml", cli(t, nil, "keyinfo", "build", flagKey, public))
	text := "signed"
	config := testutil.WriteJSON(t, dir, "template.json", templateConfig{Method: xmldsig.ECDSASHA256, KeyInfoFile: keyInfo, References: []xmldsig.ReferenceTemplate{{URI: testObjectURI, Transforms: []reference.Transform{{Algorithm: c14n.Exclusive}}}}, Objects: []templateObject{{ID: testObjectID, Text: &text}}})
	draft := cli(t, nil, "signature", "build", "-config", config)
	signed := cli(t, draft, "signature", "sign-template", flagKey, private, "-signature-index", "0", "-require-id", testObjectID)
	cli(t, signed, "signature", nameVerifyKeyInfo, flagKey, public, "-signature-index", "0", "-expect-uri", testObjectURI, "-require-id", testObjectID)
	wrong := testutil.WritePublicKey(t, dir, "wrong.pub", c.TSAKey.Public())
	rejectCLI(t, signed, "signature", nameVerifyKeyInfo, flagKey, wrong, "-signature-index", "0")
	rules := testutil.WriteJSON(t, dir, "rules.json", []reference.IDAttributeRule{{Attribute: document.Name{Space: "urn:ids", Local: "custom"}}})
	source := []byte(`<root xmlns:i="urn:ids"><data i:custom="payload">signed</data></root>`)
	config = testutil.WriteJSON(t, dir, "template.json", templateConfig{Method: xmldsig.ECDSASHA256, References: []xmldsig.ReferenceTemplate{{URI: "#payload", Transforms: []reference.Transform{{Algorithm: c14n.Exclusive}}}}})
	sourceFile := testutil.WriteFile(t, dir, "source.xml", source)
	draft = cli(t, nil, "signature", "build", "-config", config, "-in", sourceFile)
	signed = cli(t, draft, "signature", "sign-template", flagKey, private, "-signature-index", "0", "-id-rules", rules, "-require-id", "payload")
	cli(t, signed, "signature", "verify-core", flagKey, public, "-signature-index", "0", "-id-rules", rules, "-require-id", "payload")
	rejectCLI(t, signed, "signature", "verify-core", flagKey, public, "-signature-index", "0", "-id-rules", rules, "-require-root")
}

func TestFilter2XSLTAndTruncatedHMAC(t *testing.T) {
	c := testcert.New(t)
	dir := t.TempDir()
	private := testutil.WritePrivateKey(t, dir, "key", c.LeafKey)
	public := testutil.WritePublicKey(t, dir, "pub", c.LeafKey.Public())
	secret := testutil.WriteFile(t, dir, "secret", bytes.Repeat([]byte{4}, 32))
	text := "payload"

	programs := []reference.Transform{{Algorithm: reference.XPathFilter2, XPath: []reference.XPathExpression{{Expression: "//ds:Object", Filter: "intersect", Namespaces: map[string]string{"ds": xmldsig.Namespace, "xf": reference.XPathFilter2}}}}, {Algorithm: reference.XSLT, Stylesheet: []byte(`<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:ds="` + xmldsig.Namespace + `" version="1.0"><xsl:output method="text"/><xsl:template match="/"><xsl:value-of select="//ds:Object"/></xsl:template></xsl:stylesheet>`)}}
	for _, program := range programs {
		t.Run(program.Algorithm, func(t *testing.T) {
			transforms := []reference.Transform{program}
			if program.Algorithm != reference.XSLT {
				transforms = append(transforms, reference.Transform{Algorithm: c14n.Exclusive})
			}

			cfg := templateConfig{Method: xmldsig.ECDSASHA256, References: []xmldsig.ReferenceTemplate{{URI: testObjectURI, Transforms: transforms}}, Objects: []templateObject{{ID: testObjectID, Text: &text}}}
			config := testutil.WriteJSON(t, dir, "template.json", cfg)
			allowed := testutil.WriteJSON(t, dir, "allowed.json", []reference.Transform{program})
			draft := cli(t, nil, "signature", "build", "-config", config)
			signed := cli(t, draft, "signature", "sign-template", flagKey, private, "-signature-index", "0", "-allowed-programs", allowed)
			cli(t, signed, "signature", "verify-core", flagKey, public, "-signature-index", "0", "-allowed-programs", allowed)
		})
	}

	cfg := templateConfig{Method: xmldsig.HMACSHA256, Parameters: templateParameters{HMACOutputLength: 128}, References: []xmldsig.ReferenceTemplate{{URI: testObjectURI, Transforms: []reference.Transform{{Algorithm: c14n.Exclusive}}}}, Objects: []templateObject{{ID: testObjectID, Text: &text}}}
	config := testutil.WriteJSON(t, dir, "hmac.json", cfg)
	draft := cli(t, nil, "signature", "build", "-config", config)
	rejectCLI(t, draft, "signature", "sign-template", "-secret-file", secret, "-signature-index", "0", "-policy", nameHMAC)
	signed := cli(t, draft, "signature", "sign-template", "-secret-file", secret, "-signature-index", "0", "-policy", nameHMAC, "-allow-hmac-truncation")
	cli(t, signed, "signature", "verify-core", "-secret-file", secret, "-signature-index", "0", "-policy", nameHMAC, "-allow-hmac-truncation")
	rejectCLI(t, signed, "signature", "verify-core", "-secret-file", secret, "-signature-index", "0", "-policy", nameHMAC)
}

func TestRejectedOptionsDoNotPublishOutput(t *testing.T) {
	dir := t.TempDir()
	private := testutil.WriteFile(t, dir, "key", cli(t, nil, "key", "generate", "-algorithm", "p256"))
	password := testutil.WriteFile(t, dir, "password", []byte("password"))
	secret := testutil.WriteFile(t, dir, "aes", bytes.Repeat([]byte{5}, 32))
	output := testutil.WriteFile(t, dir, "keep", []byte("original"))
	rejectCLI(t, nil, "key", "convert", "-in", private, "-output-format", namePkcs8, "-output-password-file", password, "-encryption-bits", "129", "-out", output)
	rejectCLI(t, []byte("secret"), nameEncrypt, "-transport", transportDirect, flagKey, secret, "-algorithm", "urn:unsupported", "-out", output)

	for _, args := range [][]string{{nameCMS, nameVerify, flagKey, private}, {"timestamp", nameInspect, "-nonce-file", password}, {"key", nameInspect, "-output-password-file", password}, {nameEncryption, nameDecrypt, "-cipher-out", output}} {
		rejectCLI(t, nil, args...)
	}

	raw, err := os.ReadFile(output)
	if err != nil || string(raw) != "original" {
		t.Fatal("failure replaced output", err, string(raw))
	}
}

func verificationDetails(t *testing.T, raw []byte) json.RawMessage {
	t.Helper()

	var report struct {
		Status  string          `json:"status"`
		Version int             `json:"schema_version"`
		Details json.RawMessage `json:"details"`
	}
	if err := json.Unmarshal(raw, &report); err != nil {
		t.Fatal(err, string(raw))
	}

	if report.Version != 1 || report.Status == "" {
		t.Fatal("missing report envelope", string(raw))
	}

	return report.Details
}

func coreVerificationChecks(t *testing.T, raw []byte) json.RawMessage {
	t.Helper()

	var detail struct {
		Checks json.RawMessage `json:"checks"`
	}
	if err := json.Unmarshal(verificationDetails(t, raw), &detail); err != nil {
		t.Fatal(err)
	}

	return detail.Checks
}

func cli(t *testing.T, input []byte, args ...string) []byte {
	t.Helper()

	var out, stderr bytes.Buffer
	if err := run(context.Background(), args, bytes.NewReader(input), &out, &stderr); err != nil {
		t.Fatalf("%v: %v\nstderr: %s\nstdout: %s", args, err, stderr.String(), out.String())
	}

	return out.Bytes()
}

func rejectCLI(t *testing.T, input []byte, args ...string) []byte {
	t.Helper()

	var out, stderr bytes.Buffer
	if err := run(context.Background(), args, bytes.NewReader(input), &out, &stderr); err == nil {
		t.Fatalf("accepted invalid invocation %v", args)
	}

	return out.Bytes()
}

func TestEncryptionLegacyCBCPolicy(t *testing.T) {
	dir := t.TempDir()
	secret := testutil.WriteFile(t, dir, "cbc-key", bytes.Repeat([]byte{7}, 32))
	args := []string{nameEncrypt, "-transport", transportDirect, flagKey, secret, "-algorithm", xmlenc.AES256CBC}
	rejectCLI(t, []byte("legacy CBC plaintext"), args...)
	if fips140.Enabled() {
		rejectCLI(t, []byte("legacy CBC plaintext"), append(args, "-allow-legacy-data")...)
		return
	}
	encrypted := cli(t, []byte("legacy CBC plaintext"), append(args, "-allow-legacy-data")...)
	args[0] = nameDecrypt
	rejectCLI(t, encrypted, args...)
	plain := cli(t, encrypted, append(args, "-allow-legacy-data")...)
	if string(plain) != "legacy CBC plaintext" {
		t.Fatal(string(plain))
	}
}

func TestStreamingOutputPublication(t *testing.T) {
	failure := errors.New("late producer failure")
	for _, mode := range []string{"file", "stdout"} {
		for _, reason := range []string{"producer", "limit", "cancel"} {
			t.Run(mode+"/"+reason, func(t *testing.T) {
				dir := t.TempDir()
				path := filepath.Join(dir, "out")
				if err := os.WriteFile(path, []byte("original"), 0o600); err != nil {
					t.Fatal(err)
				}
				if mode == "stdout" {
					path = "-"
				}
				ctx, cancel := context.WithCancel(context.WithValue(t.Context(), executionKey{}, &executionFlags{output: 4}))
				defer cancel()
				var stdout bytes.Buffer
				err := produceOutput(ctx, path, &stdout, func(w io.Writer) error {
					if _, err := io.WriteString(w, "part"); err != nil {
						return err
					}
					switch reason {
					case "producer":
						return failure
					case "limit":
						_, err := io.WriteString(w, "x")
						return err
					default:
						cancel()
						return nil
					}
				})
				if err == nil || reason == "producer" && !errors.Is(err, failure) || reason == "cancel" && !errors.Is(err, context.Canceled) {
					t.Fatal(err)
				}
				if stdout.Len() != 0 {
					t.Fatal("failed serialization published stdout")
				}
				if mode == "file" {
					raw, err := os.ReadFile(path)
					if err != nil || string(raw) != "original" {
						t.Fatal("failed serialization replaced file", err)
					}
				}
				temps, err := filepath.Glob(filepath.Join(dir, ".xmlsec-*"))
				if err != nil || len(temps) != 0 {
					t.Fatal("temporary output leaked", temps, err)
				}
			})
		}
	}
}
