package main

import (
	"crypto/x509"
	"slices"
	"testing"
	"time"
)

func TestExample(t *testing.T) {
	if err := run(); err != nil {
		t.Fatal(err)
	}
}

func TestCertificateTemplatesSeparateTrustRoles(t *testing.T) {
	now := time.Date(2026, time.January, 2, 3, 0, 0, 0, time.UTC)
	ca, signer := certificateTemplates(now)
	for _, tc := range []struct {
		name    string
		cert    *x509.Certificate
		isCA    bool
		usage   x509.KeyUsage
		purpose []x509.ExtKeyUsage
		expires time.Time
	}{
		{
			name: "root_can_sign_certificates_and_crls", cert: ca, isCA: true,
			usage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign, expires: time.Date(2026, time.January, 3, 3, 0, 0, 0, time.UTC),
		},
		{
			name: "leaf_can_only_sign_code", cert: signer, usage: x509.KeyUsageDigitalSignature,
			purpose: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning}, expires: time.Date(2026, time.January, 2, 4, 0, 0, 0, time.UTC),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cert := tc.cert
			if cert == nil {
				t.Fatal("certificate template is nil")
			}
			if !cert.BasicConstraintsValid || cert.IsCA != tc.isCA || cert.KeyUsage != tc.usage || !slices.Equal(cert.ExtKeyUsage, tc.purpose) {
				t.Errorf("constraints valid=%t, CA=%t, usages=%v/%v, want valid constraints, CA=%t, usages=%v/%v", cert.BasicConstraintsValid, cert.IsCA, cert.KeyUsage, cert.ExtKeyUsage, tc.isCA, tc.usage, tc.purpose)
			}
			starts := time.Date(2026, time.January, 2, 2, 0, 0, 0, time.UTC)
			if !cert.NotBefore.Equal(starts) || !cert.NotAfter.Equal(tc.expires) {
				t.Errorf("validity=%v–%v, want %v–%v", cert.NotBefore, cert.NotAfter, starts, tc.expires)
			}
		})
	}
}
