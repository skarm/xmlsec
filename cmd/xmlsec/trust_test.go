package main

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/skarm/xmlsec/internal/testutil"
	"github.com/skarm/xmlsec/internal/testutil/testcert"
	"github.com/skarm/xmlsec/pki"
)

func TestLoadTrustPreservesUsageAndNormalizesLocalEvidence(t *testing.T) {
	t.Parallel()

	chain := testcert.New(t)
	dir := t.TempDir()
	testutil.WriteFile(t, dir, "root.der", chain.Root.Raw)
	testutil.WriteFile(t, dir, "intermediate.der", chain.Leaf.Raw)
	crl := testcert.CRL(t, chain)
	testutil.WriteFile(t, dir, "list.pem", pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: crl}))
	config := testutil.WriteFile(t, dir, "trust.json", []byte(`{
		"roots":["root.der"], "intermediates":["intermediate.der"],
		"usages":["any","serverAuth","clientAuth","codeSigning","emailProtection","timeStamping","ocspSigning"],
		"revocation":"require-crl", "ocsp_max_age":"1m", "ocsp_clock_skew":"2s",
		"evidence":{"crls":["list.pem"]}
	}`))
	got, evidence, err := loadTrust(t.Context(), config)
	if err != nil {
		t.Fatal(err)
	}
	wantUsages := []x509.ExtKeyUsage{x509.ExtKeyUsageAny, x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageCodeSigning, x509.ExtKeyUsageEmailProtection, x509.ExtKeyUsageTimeStamping, x509.ExtKeyUsageOCSPSigning}
	if !slices.Equal(got.KeyUsages, wantUsages) || got.Revocation != pki.RequireCRL || got.OCSPMaxAge != time.Minute || got.OCSPClockSkew != 2*time.Second {
		t.Errorf("loaded trust policy = usages %v, revocation %q, age %v, skew %v", got.KeyUsages, got.Revocation, got.OCSPMaxAge, got.OCSPClockSkew)
	}
	if !slices.EqualFunc(got.Roots, [][]byte{chain.Root.Raw}, bytes.Equal) || !slices.EqualFunc(got.Intermediates, [][]byte{chain.Leaf.Raw}, bytes.Equal) {
		t.Error("loaded roots or intermediates differ from the local files")
	}
	if !slices.EqualFunc(evidence.CRLs, [][]byte{crl}, bytes.Equal) || len(evidence.OCSPResponses) != 0 {
		t.Errorf("loaded evidence = %d CRLs, %d OCSP responses; want original DER CRL only", len(evidence.CRLs), len(evidence.OCSPResponses))
	}
}

func TestLoadTrustRejectsInvalidUsageAndDuration(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct{ name, config, message string }{
		{"unknown_usage", `{"usages":["unsupported"]}`, "unknown EKU"},
		{"negative_max_age", `{"ocsp_max_age":"-1s"}`, "invalid duration"},
		{"malformed_clock_skew", `{"ocsp_clock_skew":"tomorrow"}`, "invalid duration"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			path := testutil.WriteFile(t, t.TempDir(), "trust.json", []byte(tc.config))
			_, evidence, err := loadTrust(t.Context(), path)
			if exitCode(err) != cliExitUsage || !strings.Contains(err.Error(), tc.message) || len(evidence.CRLs)+len(evidence.OCSPResponses) != 0 {
				t.Errorf("loadTrust = %v and %v; want usage error containing %q and no revocation evidence", evidence, err, tc.message)
			}
		})
	}
}

func TestEvidenceFilesEnforceCountBeforeReadingRevocationFiles(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	for _, tc := range []struct {
		name  string
		files evidenceFiles
	}{
		{"CRL", evidenceFiles{CRLs: make([]string, 257)}},
		{"OCSP", evidenceFiles{OCSP: make([]string, 257)}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, err := tc.files.load(t.Context(), dir)
			if exitCode(err) != cliExitUsage || len(got.CRLs)+len(got.OCSPResponses) != 0 {
				t.Errorf("evidence load = %v, %v; want usage error before reading revocation files", got, err)
			}
		})
	}
}

func TestLoadTrustReportsMissingRelativeEvidenceFile(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := testutil.WriteFile(t, dir, "trust.json", []byte(`{"evidence":{"ocsp":["missing.der"]}}`))
	_, evidence, err := loadTrust(t.Context(), path)
	var pathErr *os.PathError
	if !errors.Is(err, os.ErrNotExist) || !errors.As(err, &pathErr) || pathErr.Path != filepath.Join(dir, "missing.der") || len(evidence.OCSPResponses) != 0 {
		t.Errorf("loadTrust = %v, %v; want missing OCSP file resolved relative to trust.json", evidence, err)
	}
}
