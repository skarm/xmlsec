package xades

import (
	"bytes"
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"time"

	"github.com/skarm/xmlsec/internal/x509cert"
	"github.com/skarm/xmlsec/internal/x509crl"
	"github.com/skarm/xmlsec/internal/x509name"
	"github.com/skarm/xmlsec/pki"
)

// The general PKI verifier evaluates its broader CRL algorithm at the supplied
// time. This closed with-time profile only accepts direct complete signer CRLs
// and refuses recovery of a chain named in any authenticated issuer CRL, even
// one issued after the proof. Indirect/delta/scoped historical evaluation belongs
// to a separate evidence engine. Run after PKI has bounded the supplied input.
func refuseCRLRecovery(ctx context.Context, trust *pki.Result, raw [][]byte, at time.Time) error {
	lists, err := recoveryCRLs(ctx, raw)
	if err != nil {
		return err
	}

	chain := trust.ChainDER()
	for i := 0; i+1 < len(chain); i++ {
		cert, err := x509cert.ParseWithMaxBytes(chain[i], len(chain[i]))
		if err != nil {
			return err
		}

		issuer, err := x509cert.ParseWithMaxBytes(chain[i+1], len(chain[i+1]))
		if err != nil {
			return err
		}

		if err := refuseCRLRecoveryLists(ctx, lists, issuer, cert, at); err != nil {
			return err
		}
	}

	return nil
}

func recoveryCRLs(ctx context.Context, raw [][]byte) ([]*x509.RevocationList, error) {
	lists := make([]*x509.RevocationList, 0, len(raw))
	for _, encoded := range raw {
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		view, err := x509crl.ParseEvidence(encoded, len(encoded))
		if err != nil {
			return nil, recoveryEvidenceError(err)
		}

		if err := recoveryCRLScope(ctx, view.CRL); err != nil {
			return nil, err
		}

		lists = append(lists, view.CRL)
	}

	return lists, nil
}

func recoveryCRLScope(ctx context.Context, list *x509.RevocationList) error {
	for _, extension := range list.Extensions {
		switch extension.Id.String() {
		case "2.5.29.27", "2.5.29.28": // Delta indicator and issuing distribution point.
			return fmt.Errorf("%w: with-time requires direct complete CRLs", ErrProfile)
		}
	}

	for _, entry := range list.RevokedCertificateEntries {
		if err := ctx.Err(); err != nil {
			return err
		}

		for _, extension := range entry.Extensions {
			if extension.Id.String() == "2.5.29.29" { // certificateIssuer.
				return fmt.Errorf("%w: with-time requires direct CRL entries", ErrProfile)
			}
		}
	}

	return nil
}

func refuseCRLRecoveryLists(ctx context.Context, lists []*x509.RevocationList, issuer, cert *x509.Certificate, at time.Time) error {
	for _, list := range lists {
		if err := ctx.Err(); err != nil {
			return err
		}

		matches, err := x509name.EqualOrExact(ctx, list.RawIssuer, issuer.RawSubject)
		if err != nil {
			return recoveryEvidenceError(err)
		}

		if !matches || len(list.AuthorityKeyId) > 0 && !bytes.Equal(list.AuthorityKeyId, issuer.SubjectKeyId) {
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

		if list.ThisUpdate.After(at) {
			return fmt.Errorf("%w: issuer CRL from the future", pki.ErrEvidence)
		}

		for _, entry := range list.RevokedCertificateEntries {
			if entry.SerialNumber.Cmp(cert.SerialNumber) == 0 {
				return fmt.Errorf("%w: recovery of a revoked chain is outside the with-time profile", ErrLevel)
			}
		}
	}

	return nil
}

func recoveryEvidenceError(err error) error {
	if errors.Is(err, x509crl.ErrLimit) || errors.Is(err, x509name.ErrLimit) {
		return errors.Join(pki.ErrEvidence, pki.ErrLimit, err)
	}

	return errors.Join(pki.ErrEvidence, err)
}
