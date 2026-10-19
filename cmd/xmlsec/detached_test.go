package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/skarm/xmlsec/c14n"
	"github.com/skarm/xmlsec/reference"
)

const flagC14n = "-c14n"

func TestDetachedCLI(t *testing.T) {
	dir := t.TempDir()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	private, public := filepath.Join(dir, "private.pem"), filepath.Join(dir, "public.pem")

	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(private, pem.EncodeToMemory(&pem.Block{Type: privateKeyPEMType, Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}

	der, err = x509.MarshalPKIXPublicKey(key.Public())
	if err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(public, pem.EncodeToMemory(&pem.Block{Type: publicKeyPEMType, Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}

	payload := filepath.Join(dir, "payload.xml")
	if err := os.WriteFile(payload, []byte(`<r z="2" a="1"/>`), 0o600); err != nil {
		t.Fatal(err)
	}

	entries := []resourceEntry{{URI: "urn:test:payload", Path: "payload.xml", Transforms: []reference.Transform{{Algorithm: c14n.Canonical11}}}}
	manifest := filepath.Join(dir, "resources.json")

	data, err := json.Marshal(entries)
	if err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(manifest, data, 0o600); err != nil {
		t.Fatal(err)
	}

	verifyManifest := filepath.Join(dir, "verify-resources.json")
	if err := os.WriteFile(verifyManifest, []byte(`[{"uri":"urn:test:payload","path":"payload.xml"}]`), 0o600); err != nil {
		t.Fatal(err)
	}

	var sig, report, stderr bytes.Buffer
	if err := run(context.Background(), []string{nameSignDetached, flagKey, private, flagResources, manifest, flagC14n, c14n.Canonical11}, nil, &sig, &stderr); err != nil {
		t.Fatal(err, stderr.String())
	}

	if !strings.Contains(sig.String(), `<ds:Signature`) {
		t.Fatal(sig.String())
	}

	if err := run(context.Background(), []string{nameVerifyDetached, flagKey, public, flagResources, verifyManifest, flagC14n, c14n.Canonical11}, bytes.NewReader(sig.Bytes()), &report, &stderr); err != nil {
		t.Fatal(err, stderr.String())
	}

	var verified struct {
		Status     string `json:"status"`
		References []struct {
			Steps []struct {
				InputKind string `json:"input_kind"`
			} `json:"steps"`
		} `json:"references"`
	}
	if err := json.Unmarshal(verificationDetails(t, report.Bytes()), &verified); err != nil {
		t.Fatal(err)
	}

	if verified.Status != statusValid || len(verified.References) != 1 || verified.References[0].Steps[0].InputKind != "octet-stream" {
		t.Fatal(report.String())
	}
	// If the signature is invalid, a missing local resource must NOT be opened.
	if err := os.Remove(payload); err != nil {
		t.Fatal(err)
	}

	tampered := strings.Replace(sig.String(), "<ds:SignatureValue>", "<ds:SignatureValue>A", 1)

	err = run(context.Background(), []string{nameVerifyDetached, flagKey, public, flagResources, verifyManifest, flagC14n, c14n.Canonical11}, strings.NewReader(tampered), &report, &stderr)
	if err == nil || strings.Contains(err.Error(), "no such file") {
		t.Fatal("resource read before authentication", err)
	}
}

func TestResourceManifestRejects(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "resources.json")

	cases := []string{`[]`, `{}`, `null`, `[{"uri":"u","path":"x","unknown":1}]`, `[{"uri":"u","path":"x"}] {}`, `[{"uri":"u","path":"x"},{"uri":"u","path":"y"}]`, `[{"uri":"u"}]`}
	for _, input := range cases {
		t.Run(input, func(t *testing.T) {
			if err := os.WriteFile(file, []byte(input), 0o600); err != nil {
				t.Fatal(err)
			}

			if _, _, err := loadResourcesContext(context.Background(), file); err == nil {
				t.Fatal("invalid manifest accepted")
			}
		})
	}

	for _, args := range [][]string{{nameSignDetached}, {nameVerifyDetached}, {nameSignDetached, flagResources, "-", flagKey, "x"}, {nameVerifyDetached, nameExtra}} {
		var out, stderr bytes.Buffer
		if err := run(context.Background(), args, nil, &out, &stderr); err == nil {
			t.Fatal(args)
		}
	}

	for _, cmd := range []string{nameSignDetached, nameVerifyDetached} {
		var out, stderr bytes.Buffer
		if err := run(context.Background(), []string{cmd, "-h"}, nil, &out, &stderr); err != nil {
			t.Fatal(err)
		}
	}
}
