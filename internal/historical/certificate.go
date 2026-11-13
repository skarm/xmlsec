package historical

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"time"

	"github.com/skarm/xmlsec/internal/pkipast"
	"github.com/skarm/xmlsec/pki"
	"github.com/skarm/xmlsec/timestamp"
)

// ObjectTimestamp identifies an RFC 3161 token and the exact supplied object
// whose bytes were hashed into its imprint.
type ObjectTimestamp struct {
	TokenDER     []byte
	ObjectSHA256 [sha256.Size]byte
}

// ValidateCertificate authenticates archive timestamps and then checks the
// target certificate at the requested past time.
func ValidateCertificate(ctx context.Context, config Config, certificate []byte, at, now time.Time, archive []ObjectTimestamp, evidence, tsaEvidence pki.Evidence) (*pki.PastCertificateResult, *pki.PastCertificateReport, []Stamp, error) {
	if ctx == nil || at.IsZero() || now.IsZero() || !at.Before(now) || len(certificate) == 0 || len(archive) == 0 {
		return nil, nil, nil, ErrInput
	}

	w := validationWorkflow{ctx: ctx, config: config, now: now, report: &Report{At: now}, signerEvidence: evidence, tsaEvidence: tsaEvidence}
	w.input.Certificate = certificate

	if err := w.checkEvidenceLimits(); err != nil {
		return nil, nil, nil, err
	}

	if err := w.bindObjectTimestamps(archive); err != nil {
		return nil, nil, nil, err
	}

	w.input.Signature = sha256.Sum256(certificate)

	if err := w.proveObjects(); err != nil {
		return nil, nil, w.report.Stamps, err
	}

	result, report, err := pkipast.ValidateArchive(ctx, w.signerSession, certificate, w.report.Proofs, at)

	return result, report, w.report.Stamps, err
}

func (w *validationWorkflow) bindObjectTimestamps(archive []ObjectTimestamp) error {
	remaining := w.config.MaxBytes
	objects := make(map[[sha256.Size]byte][]byte)
	admit := func(raw []byte) error {
		if err := w.ctx.Err(); err != nil {
			return err
		}

		if len(raw) > remaining {
			return ErrLimit
		}

		remaining -= len(raw)
		objects[sha256.Sum256(raw)] = raw

		return nil
	}

	if err := admit(w.input.Certificate); err != nil {
		return err
	}

	for _, ev := range []pki.Evidence{w.signerEvidence, w.tsaEvidence} {
		for _, group := range [][][]byte{ev.Intermediates, ev.CRLs, ev.OCSPResponses} {
			for _, raw := range group {
				if err := admit(raw); err != nil {
					return err
				}
			}
		}
	}

	for _, stamp := range archive {
		if err := admit(stamp.TokenDER); err != nil {
			return err
		}
	}

	for i, stamp := range archive {
		raw := objects[stamp.ObjectSHA256]
		if len(raw) == 0 {
			return fmt.Errorf("%w: timestamp %d has no matching object", ErrInput, i)
		}

		token, err := timestamp.ParseToken(w.ctx, stamp.TokenDER)
		if err != nil {
			return fmt.Errorf("timestamp %d: %w", i, errors.Join(ErrValidation, err))
		}

		imprint, err := timestamp.ImprintFor(w.ctx, raw, token.UnverifiedInfo().Imprint().Hash)
		if err != nil {
			return fmt.Errorf("timestamp %d: %w", i, errors.Join(ErrValidation, err))
		}

		w.input.Timestamps = append(w.input.Timestamps, Candidate{Token: token, Imprint: imprint, Covered: [][sha256.Size]byte{stamp.ObjectSHA256}, Archive: true})
	}

	return nil
}
