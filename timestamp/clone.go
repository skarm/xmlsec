package timestamp

import (
	"bytes"
	"crypto/x509"

	"github.com/skarm/xmlsec/pki"
)

// WithEvidenceCertificates replaces UNTRUSTED certificate lookup/path material,
// keeping roots, algorithm policy, TSA policy identifiers and time constraints.
func (v *Verifier) WithEvidenceCertificates(raw [][]byte) (*Verifier, error) {
	if v == nil || len(raw) > 32 {
		return nil, ErrPolicy
	}

	out := *v
	out.certificates = nil

	total := 0
	for _, b := range raw {
		total += len(b)
		if len(b) > 1<<20 || total > v.maxBytes {
			return nil, ErrPolicy
		}

		if _, e := x509.ParseCertificate(b); e != nil {
			return nil, e
		}

		out.certificates = append(out.certificates, bytes.Clone(b))
	}

	trust, e := v.trust.WithIntermediateCertificates(out.certificates)
	if e != nil {
		return nil, e
	}

	out.trust = trust

	return &out, nil
}

// RevocationMode returns the configured offline revocation policy.
func (v *Verifier) RevocationMode() pki.RevocationMode {
	if v == nil {
		return pki.NoRevocation
	}

	return v.trust.RevocationMode()
}
