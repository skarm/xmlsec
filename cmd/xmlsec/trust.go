package main

import (
	"context"
	"crypto/x509"
	"encoding/asn1"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/skarm/xmlsec/keys"
	"github.com/skarm/xmlsec/pki"
	"github.com/skarm/xmlsec/timestamp"
)

type evidenceFiles struct {
	Intermediates []string `json:"intermediates,omitempty"`
	CRLs          []string `json:"crls,omitempty"`
	OCSP          []string `json:"ocsp,omitempty"`
}

func (c evidenceFiles) load(ctx context.Context, base string) (pki.Evidence, error) {
	e := pki.Evidence{}

	var err error

	e.Intermediates, err = readCertificates(ctx, base, c.Intermediates)
	if err != nil {
		return e, err
	}

	if len(c.CRLs) > 256 || len(c.OCSP) > 256 {
		return e, usageError("too many revocation evidence files")
	}

	total := 0

	for _, path := range c.CRLs {
		raw, err := readInputContext(ctx, localPath(base, path), nil, keys.DefaultLimits().MaxInputBytes)
		if err != nil {
			return e, err
		}

		crl, err := keys.ParseCRL(raw, keys.Limits{})
		if err != nil {
			return e, err
		}

		total += len(crl.Raw)
		if total > 64<<20 {
			return e, usageError("evidence exceeds 64 MiB")
		}

		e.CRLs = append(e.CRLs, crl.Raw)
	}

	for _, path := range c.OCSP {
		raw, err := readInputContext(ctx, localPath(base, path), nil, 4<<20)
		if err != nil {
			return e, err
		}

		total += len(raw)
		if total > 64<<20 {
			return e, usageError("evidence exceeds 64 MiB")
		}

		e.OCSPResponses = append(e.OCSPResponses, raw)
	}

	return e, nil
}

type trustConfig struct {
	Roots            []string           `json:"roots"`
	Intermediates    []string           `json:"intermediates,omitempty"`
	Usages           []string           `json:"usages,omitempty"`
	RequiredKeyUsage x509.KeyUsage      `json:"required_key_usage,omitempty"`
	AllowCALeaf      bool               `json:"allow_ca_leaf,omitempty"`
	Revocation       pki.RevocationMode `json:"revocation,omitempty"`
	MaxChainDepth    int                `json:"max_chain_depth,omitempty"`
	MaxEvidenceBytes int                `json:"max_evidence_bytes,omitempty"`
	MaxCRLs          int                `json:"max_crls,omitempty"`
	MaxOCSPResponses int                `json:"max_ocsp_responses,omitempty"`
	OCSPMaxAge       string             `json:"ocsp_max_age,omitempty"`
	OCSPClockSkew    string             `json:"ocsp_clock_skew,omitempty"`
	Evidence         evidenceFiles      `json:"evidence"`
}

func (c trustConfig) load(ctx context.Context, base string) (pki.Config, pki.Evidence, error) {
	opt := pki.Config{
		Revocation:       c.Revocation,
		RequiredKeyUsage: c.RequiredKeyUsage,
		AllowCALeaf:      c.AllowCALeaf,
		MaxChainDepth:    c.MaxChainDepth,
		MaxEvidenceBytes: c.MaxEvidenceBytes,
		MaxCRLs:          c.MaxCRLs,
		MaxOCSPResponses: c.MaxOCSPResponses,
	}

	var err error

	opt.Roots, err = readCertificates(ctx, base, c.Roots)
	if err != nil {
		return opt, pki.Evidence{}, err
	}

	opt.Intermediates, err = readCertificates(ctx, base, c.Intermediates)
	if err != nil {
		return opt, pki.Evidence{}, err
	}

	for _, u := range c.Usages {
		var usage x509.ExtKeyUsage

		switch u {
		case "any":
			usage = x509.ExtKeyUsageAny
		case "serverAuth":
			usage = x509.ExtKeyUsageServerAuth
		case "clientAuth":
			usage = x509.ExtKeyUsageClientAuth
		case "codeSigning":
			usage = x509.ExtKeyUsageCodeSigning
		case "emailProtection":
			usage = x509.ExtKeyUsageEmailProtection
		case "timeStamping":
			usage = x509.ExtKeyUsageTimeStamping
		case "ocspSigning":
			usage = x509.ExtKeyUsageOCSPSigning
		default:
			return opt, pki.Evidence{}, usageError("unknown EKU %q", u)
		}

		opt.KeyUsages = append(opt.KeyUsages, usage)
	}

	opt.OCSPMaxAge, err = durationOption(c.OCSPMaxAge)
	if err != nil {
		return opt, pki.Evidence{}, err
	}

	opt.OCSPClockSkew, err = durationOption(c.OCSPClockSkew)
	if err != nil {
		return opt, pki.Evidence{}, err
	}

	evidence, err := c.Evidence.load(ctx, base)

	return opt, evidence, err
}

func durationOption(s string) (time.Duration, error) {
	if s == "" {
		return 0, nil
	}

	d, err := time.ParseDuration(s)
	if err != nil || d < 0 {
		return 0, usageError("invalid duration %q", s)
	}

	return d, nil
}

func loadTrust(ctx context.Context, path string) (pki.Config, pki.Evidence, error) {
	var c trustConfig
	if err := readJSONFile(ctx, path, &c); err != nil {
		return pki.Config{}, pki.Evidence{}, err
	}

	return c.load(ctx, filepath.Dir(path))
}

func parseTime(value string) (time.Time, error) {
	if value == "" {
		return time.Time{}, usageError("an explicit RFC3339 time is required (-at)")
	}

	t, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		return t, usageError("invalid RFC3339 time: %v", err)
	}

	return t, nil
}

func parseOID(s string) (asn1.ObjectIdentifier, error) {
	parts := strings.Split(s, ".")
	if len(parts) < 2 {
		return nil, usageError("invalid OID %q", s)
	}

	out := make(asn1.ObjectIdentifier, len(parts))
	for i, p := range parts {
		if p == "" || len(p) > 1 && p[0] == '0' {
			return nil, usageError("invalid OID %q", s)
		}

		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return nil, usageError("invalid OID %q", s)
		}

		out[i] = n
	}

	if out[0] > 2 || out[0] < 2 && out[1] > 39 {
		return nil, usageError("invalid OID %q", s)
	}

	return out, nil
}

type tsaConfig struct {
	Trust                    trustConfig `json:"trust"`
	Policies                 []string    `json:"policies"`
	Certificates             []string    `json:"certificates,omitempty"`
	AllowUncheckedRevocation bool        `json:"allow_unchecked_revocation,omitempty"`
	AllowLegacyESS           bool        `json:"allow_legacy_ess,omitempty"`
	ClockSkew                string      `json:"clock_skew,omitempty"`
	MaxAge                   string      `json:"max_age,omitempty"`
	MaxAccuracy              string      `json:"max_accuracy,omitempty"`
	RequireAccuracy          bool        `json:"require_accuracy,omitempty"`
	MaxBytes                 int         `json:"max_bytes,omitempty"`
}

func loadTSA(ctx context.Context, path string) (*timestamp.Verifier, pki.Evidence, error) {
	var c tsaConfig
	if err := readJSONFile(ctx, path, &c); err != nil {
		return nil, pki.Evidence{}, err
	}

	base := filepath.Dir(path)

	trust, evidence, err := c.Trust.load(ctx, base)
	if err != nil {
		return nil, evidence, err
	}

	opt := timestamp.Config{
		PKI:                      trust,
		AllowUncheckedRevocation: c.AllowUncheckedRevocation,
		AllowLegacyESSCertID:     c.AllowLegacyESS,
		RequireAccuracy:          c.RequireAccuracy,
		MaxBytes:                 c.MaxBytes,
	}

	for _, s := range c.Policies {
		oid, err := parseOID(s)
		if err != nil {
			return nil, evidence, err
		}

		opt.AllowedPolicies = append(opt.AllowedPolicies, oid)
	}

	opt.Certificates, err = readCertificates(ctx, base, c.Certificates)
	if err != nil {
		return nil, evidence, err
	}

	opt.ClockSkew, err = durationOption(c.ClockSkew)
	if err != nil {
		return nil, evidence, err
	}

	opt.MaxAge, err = durationOption(c.MaxAge)
	if err != nil {
		return nil, evidence, err
	}

	opt.MaxAccuracy, err = durationOption(c.MaxAccuracy)
	if err != nil {
		return nil, evidence, err
	}

	verifier, err := timestamp.NewVerifier(opt)

	return verifier, evidence, err
}
