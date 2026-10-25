package xades

import (
	"bytes"
	"context"
	"crypto/x509"
	"fmt"
	"time"

	"github.com/skarm/xmlsec/pki"
)

// The general PKI verifier evaluates direct CRLs at its supplied time. This
// narrower with-time profile additionally refuses recovery of a chain named in
// ANY supplied, authenticated issuer CRL, even one issued after the proof. That
// requires general revocation/compromise-time handling outside this B-T profile.
// Run only after pki.Verify has enforced DER size, count and structure limits.
func refuseCRLRecovery(ctx context.Context, trust *pki.Result, raw [][]byte, at time.Time) error {
	chain := trust.ChainDER()
	for i := 0; i+1 < len(chain); i++ {
		cert, e := x509.ParseCertificate(chain[i])
		if e != nil {
			return e
		}

		issuer, e := x509.ParseCertificate(chain[i+1])
		if e != nil {
			return e
		}

		if returned0, matchedBranch := refuseCRLRecoveryRaw(ctx, raw, &e, issuer, &at, cert); matchedBranch {
			return returned0
		}
	}

	return nil
}

func refuseCRLRecoveryRaw(ctx context.Context, raw [][]byte, e *error, issuer *x509.Certificate, at *time.Time, cert *x509.Certificate) (returned0 error, matchedBranch bool) {
	for _, der := range raw {
		if *e = ctx.Err(); (*e) != nil {
			return *e, true
		}

		list, e := x509.ParseRevocationList(der)
		if e != nil {
			return pki.ErrEvidence, true
		}

		if !bytes.Equal(list.RawIssuer, issuer.RawSubject) || len(list.AuthorityKeyId) > 0 && !bytes.Equal(list.AuthorityKeyId, issuer.SubjectKeyId) {
			continue
		}

		switch list.SignatureAlgorithm {
		case x509.SHA256WithRSA, x509.SHA384WithRSA, x509.SHA512WithRSA, x509.SHA256WithRSAPSS, x509.SHA384WithRSAPSS, x509.SHA512WithRSAPSS, x509.ECDSAWithSHA256, x509.ECDSAWithSHA384, x509.ECDSAWithSHA512, x509.PureEd25519:
		default:
			continue
		}

		if list.CheckSignatureFrom(issuer) != nil {
			continue
		}

		if list.ThisUpdate.After(*at) {
			return fmt.Errorf("%w: issuer CRL from the future", pki.ErrEvidence), true
		}

		for _, entry := range list.RevokedCertificateEntries {
			if entry.SerialNumber.Cmp(cert.SerialNumber) == 0 {
				return fmt.Errorf("%w: recovery of a revoked chain is outside the with-time profile", ErrLevel), true
			}
		}
	}

	return returned0, matchedBranch
}
