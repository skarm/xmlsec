package pki

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
)

// WithIntermediateCertificates retains roots, usage, algorithm and revocation
// rules, replacing ONLY untrusted path-building certificates. It is useful for
// checking that a document supplies its own validation material.
func (v *Verifier) WithIntermediateCertificates(raw [][]byte) (*Verifier, error) {
	if v == nil || len(raw) > 64 {
		return nil, ErrPolicy
	}

	out := *v
	out.intermediates = x509.NewCertPool()

	out.issuerCertificates = append([][]byte(nil), v.anchorCertificates...)
	out.originalCertificates = make(map[[32]byte]*x509.Certificate, len(v.anchorCertificates)+len(raw))

	for _, source := range v.anchorCertificates {
		digest := sha256.Sum256(source)
		out.originalCertificates[digest] = v.originalCertificates[digest]
	}

	remaining := v.maxBytes
	for _, b := range raw {
		if len(b) > remaining {
			return nil, ErrPolicy
		}

		remaining -= len(b)

		c, e := parseCertificate(b)
		if e != nil {
			return nil, e
		}

		if e = allowedPublicKey(c.PublicKey); e != nil {
			return nil, e
		}

		view, err := normalizedCertificate(context.Background(), c)
		if err != nil {
			return nil, err
		}

		out.intermediates.AddCert(view)
		out.originalCertificates[sha256.Sum256(c.Raw)] = c
		out.issuerCertificates = append(out.issuerCertificates, c.Raw)
	}

	return &out, nil
}

// RevocationMode describes configured policy, not the outcome of any check.
func (v *Verifier) RevocationMode() RevocationMode {
	if v == nil {
		return NoRevocation
	}

	return v.revocation
}
