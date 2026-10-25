package pki

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
)

// normalizedCertificate is private lookup metadata for crypto/x509's exact-name
// indexes. Signatures still cover original RawTBSCertificate. Returned chains
// are restored to original parsed certificates before any CertID or CRL work.
func normalizedCertificate(ctx context.Context, original *x509.Certificate) (*x509.Certificate, error) {
	subject, err := canonicalNameKey(ctx, original.RawSubject)
	if err != nil {
		return nil, err
	}

	issuer, err := canonicalNameKey(ctx, original.RawIssuer)
	if err != nil {
		return nil, err
	}

	view := *original
	view.RawSubject = []byte(subject)
	view.RawIssuer = []byte(issuer)

	return &view, nil
}

func originalCertificateChains(ctx context.Context, chains [][]*x509.Certificate, originals map[[32]byte]*x509.Certificate) ([][]*x509.Certificate, error) {
	out := make([][]*x509.Certificate, 0, len(chains))
	for _, chain := range chains {
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		restored := make([]*x509.Certificate, 0, len(chain))
		for _, view := range chain {
			original := originals[sha256.Sum256(view.Raw)]
			if original == nil {
				return nil, ErrCertificate
			}

			restored = append(restored, original)
		}

		out = append(out, restored)
	}

	return out, nil
}
