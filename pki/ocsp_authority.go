package pki

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"fmt"

	"github.com/skarm/xmlsec/internal/x509cert"
)

// OCSPAuthority explicitly pins a locally trusted OCSP signing certificate for
// one exact issuer certificate. Received names/certificates never create this
// grant. The application establishes the pin's trust out of band; certificate
// validity and signing usage are still checked, but no issuer/delegation path
// or automatic revocation exemption is inferred from received metadata.
type OCSPAuthority struct {
	ResponderCertificateDER []byte
	IssuerCertificateDER    []byte
}

func normalizeOCSPAuthorities(input []OCSPAuthority) ([]OCSPAuthority, error) {
	if len(input) > 8 {
		return nil, ErrPolicy
	}

	remaining := 8 << 20
	seen := make(map[[2][sha256.Size]byte]bool)

	output := make([]OCSPAuthority, 0, len(input))
	for _, authority := range input {
		for _, raw := range [][]byte{authority.ResponderCertificateDER, authority.IssuerCertificateDER} {
			if len(raw) < 1 || len(raw) > 1<<20 || len(raw) > remaining {
				return nil, ErrPolicy
			}

			remaining -= len(raw)
		}

		identity := [2][sha256.Size]byte{sha256.Sum256(authority.ResponderCertificateDER), sha256.Sum256(authority.IssuerCertificateDER)}
		if seen[identity] {
			return nil, ErrPolicy
		}

		seen[identity] = true

		responder, err := x509cert.ParseDefault(authority.ResponderCertificateDER)
		if err != nil || allowedPublicKey(responder.PublicKey) != nil || len(responder.UnhandledCriticalExtensions) != 0 || responder.KeyUsage != 0 && responder.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
			return nil, fmt.Errorf("%w: OCSP authority certificate", ErrPolicy)
		}

		issuer, err := x509cert.ParseDefault(authority.IssuerCertificateDER)
		if err != nil || !issuer.IsCA || !issuer.BasicConstraintsValid || issuer.KeyUsage&x509.KeyUsageCertSign == 0 || allowedPublicKey(issuer.PublicKey) != nil {
			return nil, fmt.Errorf("%w: OCSP authority issuer scope", ErrPolicy)
		}

		authority.ResponderCertificateDER = bytes.Clone(authority.ResponderCertificateDER)
		authority.IssuerCertificateDER = bytes.Clone(authority.IssuerCertificateDER)
		output = append(output, authority)
	}

	return output, nil
}

func configuredOCSPAuthority(authorities []OCSPAuthority, responder, issuer *x509.Certificate) bool {
	for _, authority := range authorities {
		if bytes.Equal(authority.ResponderCertificateDER, responder.Raw) && bytes.Equal(authority.IssuerCertificateDER, issuer.Raw) {
			return true
		}
	}

	return false
}
