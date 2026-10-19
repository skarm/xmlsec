package pki

import (
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

		out.intermediates.AddCert(c)
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
