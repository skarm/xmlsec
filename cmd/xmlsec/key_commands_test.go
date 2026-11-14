package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/skarm/xmlsec/internal/testutil"
	"github.com/skarm/xmlsec/internal/testutil/testcert"
)

func TestKeyGenerateWritesRawSymmetricKeys(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		algorithm string
		bytes     int
	}{
		{"aes128", 16}, {"aes192", 24}, {"aes256", 32}, {"hmac256", 32}, {"hmac384", 48}, {"hmac512", 64},
	} {
		t.Run(tc.algorithm, func(t *testing.T) {
			t.Parallel()

			got := cli(t, nil, "key", "generate", "-algorithm", tc.algorithm)
			if len(got) != tc.bytes {
				t.Errorf("key generate %s wrote %d bytes, want %d raw bytes", tc.algorithm, len(got), tc.bytes)
			}
		})
	}
}

func TestKeyGenerateWritesSelectedPrivateKeyType(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct{ algorithm, curve string }{
		{"p384", "P-384"}, {"p521", "P-521"}, {"ed25519", ""},
	} {
		t.Run(tc.algorithm, func(t *testing.T) {
			t.Parallel()

			got := cli(t, nil, "key", "generate", "-algorithm", tc.algorithm, "-pem=false")
			key, err := x509.ParsePKCS8PrivateKey(got)
			if err != nil {
				t.Fatalf("parse generated PKCS#8 DER: %v", err)
			}
			if tc.curve == "" {
				if _, ok := key.(ed25519.PrivateKey); !ok {
					t.Errorf("key type = %T, want Ed25519", key)
				}
				return
			}
			if ec, ok := key.(*ecdsa.PrivateKey); !ok || ec.Curve.Params().Name != tc.curve {
				t.Errorf("generated key = %T, want ECDSA on %s", key, tc.curve)
			}
		})
	}
}

func TestKeyGenerateRejectsIncompatibleOptionsBeforeReplacingOutput(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name string
		args []string
	}{
		{"symmetric_encrypted_output", []string{"-algorithm", "aes128", "-output-format", "pkcs8"}},
		{"symmetric_password", []string{"-algorithm", "hmac512", "-output-password-file", "unused"}},
		{"rsa_below_minimum", []string{"-algorithm", "rsa", "-bits", "1792"}},
		{"rsa_above_maximum", []string{"-algorithm", "rsa", "-bits", "8448"}},
		{"rsa_misaligned_size", []string{"-algorithm", "rsa", "-bits", "2056"}},
		{"unknown_algorithm", []string{"-algorithm", "unknown"}},
		{"plain_output_with_password", []string{"-output-password-file", "unused"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			const original = "existing file"
			out := testutil.WriteFile(t, t.TempDir(), "output", []byte(original))
			args := append([]string{"key", "generate", "-out", out}, tc.args...)
			var stdout bytes.Buffer
			if err := run(t.Context(), args, nil, &stdout, io.Discard); exitCode(err) != cliExitUsage || stdout.Len() != 0 {
				t.Errorf("run(%v) = exit %d (%v), output %q; want usage error and no output", args, exitCode(err), err, &stdout)
			}
			got, err := os.ReadFile(out)
			if err != nil || string(got) != original {
				t.Errorf("output file = (%q, %v), want %q unchanged", got, err, original)
			}
		})
	}
}

func TestKeyInspectReportsCertificateAndCRLMetadata(t *testing.T) {
	t.Parallel()

	chain := testcert.New(t)
	dir := t.TempDir()
	certPath := testutil.WriteFile(t, dir, "leaf.der", chain.Leaf.Raw)
	crlPath := testutil.WriteFile(t, dir, "list.der", testcert.CRL(t, chain, chain.Leaf, chain.TSA))

	certJSON := cli(t, nil, "key", "inspect", "-kind", "certificate", "-in", certPath)
	var cert struct {
		Status    string
		Subject   string
		Issuer    string
		Serial    string
		NotBefore time.Time `json:"not_before"`
		PublicKey struct {
			Algorithm string
			Curve     string
		} `json:"public_key"`
	}
	if err := json.Unmarshal(certJSON, &cert); err != nil {
		t.Fatalf("parse certificate inspection JSON: %v", err)
	}
	if cert.Status != "unverified" || cert.Subject != chain.Leaf.Subject.String() || cert.Issuer != chain.Root.Subject.String() ||
		cert.Serial != chain.Leaf.SerialNumber.String() || !cert.NotBefore.Equal(chain.Leaf.NotBefore) || cert.PublicKey.Algorithm != "ecdsa" || cert.PublicKey.Curve != "P-256" {
		t.Errorf("certificate inspection = %s, want unverified leaf metadata and P-256 public key", certJSON)
	}

	crlJSON := cli(t, nil, "key", "inspect", "-kind", "crl", "-in", crlPath)
	var crl struct {
		Status         string
		Issuer         string
		Number         int
		ThisUpdate     time.Time `json:"this_update"`
		NextUpdate     time.Time `json:"next_update"`
		RevokedEntries int       `json:"revoked_entries"`
	}
	if err := json.Unmarshal(crlJSON, &crl); err != nil {
		t.Fatalf("parse CRL inspection JSON: %v", err)
	}
	at := testcert.Now()
	if crl.Status != "unverified" || crl.Issuer != chain.Root.Subject.String() || crl.Number != 1 || crl.RevokedEntries != 2 ||
		!crl.ThisUpdate.Equal(at.Add(-time.Minute)) || !crl.NextUpdate.Equal(at.Add(time.Hour)) {
		t.Errorf("CRL inspection = %s, want unverified issuer CRL with two entries and the fixture's update times", crlJSON)
	}
}

func TestKeyConvertRequiresReadableExtraCertificate(t *testing.T) {
	t.Parallel()

	chain := testcert.New(t)
	dir := t.TempDir()
	keyPath := testutil.WritePrivateKey(t, dir, "leaf.pem", chain.LeafKey)
	certPath := testutil.WriteFile(t, dir, "leaf.der", chain.Leaf.Raw)
	passwordPath := testutil.WriteFile(t, dir, "password", []byte("fixture password\n"))
	missing := filepath.Join(dir, "missing.der")
	args := []string{"key", "convert", "-in", keyPath, "-output-format", "pkcs12", "-certificate", certPath, "-extra-certificate", missing, "-output-password-file", passwordPath}
	var stdout bytes.Buffer
	err := run(t.Context(), args, nil, &stdout, io.Discard)
	if !errors.Is(err, os.ErrNotExist) || stdout.Len() != 0 {
		t.Errorf("convert with missing extra certificate = %v, wrote %d bytes; want missing-file error and no output", err, stdout.Len())
	}
}
