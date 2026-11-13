// Package history validates certificates against timestamped archival evidence.
package history

import (
	"context"
	"crypto/sha256"
	"time"

	"github.com/skarm/xmlsec/internal/historical"
	"github.com/skarm/xmlsec/pki"
	"github.com/skarm/xmlsec/timestamp"
)

var (
	// ErrInput reports an invalid request, policy or timestamp-to-object selection.
	ErrInput = historical.ErrInput
	// ErrLimit reports exhaustion of a validation budget.
	ErrLimit = historical.ErrLimit
	// ErrTimestamp reports a timestamp that could not establish a proof of existence.
	ErrTimestamp = historical.ErrValidation
)

// Config selects offline trust and budgets for the target certificate and TSAs.
type Config struct {
	// CertificatePKI supplies target certificate trust, revocation and historical policy.
	CertificatePKI pki.HistoricalConfig
	// TSA is the required timestamp verifier. Both trust policies must check revocation.
	TSA *timestamp.Verifier
	// TSAHistory controls temporal constraints and recovery for archived TSA paths.
	TSAHistory pki.HistoricalOptions
	// MissingTSAAccuracy supplies a trusted upper bound for tokens omitting accuracy.
	// Nil rejects those tokens. The value must be between zero and 24 hours.
	MissingTSAAccuracy *time.Duration
	// MaxBytes bounds the submitted DER and the evidence graph separately.
	// Zero selects 16 MiB. The maximum is 64 MiB.
	MaxBytes int
	// MaxTimestamps bounds submitted tokens. Zero selects 16. The maximum is 64.
	MaxTimestamps int
}

// Validator retains offline trust policy and can be used concurrently.
type Validator struct {
	config historical.Config
}

// NewValidator snapshots trust and policy. The validator uses only explicit
// roots and supplied evidence.
func NewValidator(config Config) (*Validator, error) {
	certificate, err := pki.NewVerifier(config.CertificatePKI.PKI)
	if err != nil {
		return nil, err
	}

	workflow, err := historical.Normalize(historical.Config{
		Signer: certificate, SignerHistory: config.CertificatePKI.HistoricalOptions,
		TSA: config.TSA, TSAHistory: config.TSAHistory, MissingAccuracy: config.MissingTSAAccuracy,
		MaxBytes: config.MaxBytes, MaxTimestamps: config.MaxTimestamps, RequireAllTimestamps: true,
	})
	if err != nil {
		return nil, err
	}

	return &Validator{config: workflow}, nil
}

// ObjectTimestamp supplies a DER RFC 3161 token and identifies its input by
// SHA-256. The token's imprint must cover the original DER bytes of that object,
// using the hash algorithm encoded in the token. The selector is never the
// timestamp input. It can select the target certificate, a supplied certificate,
// CRL or OCSP response, or another supplied token for archive renewal.
type ObjectTimestamp struct {
	// TokenDER contains the original CMS token, extracted from a response if needed.
	TokenDER []byte
	// ObjectSHA256 selects the exact submitted encoding.
	ObjectSHA256 [sha256.Size]byte
}

// Evidence contains offline path-building and revocation material and the
// timestamps that bind the exact encodings. Keep the input unchanged until
// Validate returns. Evidence acquisition times never grant historical trust.
type Evidence struct {
	// Certificate holds the target chain's intermediates and revocation data.
	Certificate pki.Evidence
	// TSA holds the TSA chains' intermediates and revocation data.
	TSA pki.Evidence
	// Timestamps holds the tokens and the objects whose encodings they cover.
	Timestamps []ObjectTimestamp
}

// Report retains certificate and timestamp diagnostics on success or failure.
type Report struct {
	// Certificate is available once the target certificate check is reached.
	Certificate *pki.PastCertificateReport
	// Timestamps contains checks completed before the operation returned.
	Timestamps []TimestampReport
}

// TimestampReport records a token's outcome. A nonempty sub-indication
// identifies a failed or indeterminate check. Only Accepted tokens grant proof.
type TimestampReport struct {
	TokenSHA256   [sha256.Size]byte
	GenTime       time.Time
	UpperBound    time.Time
	Accepted      bool
	SubIndication string
}

// Validate verifies the exact certificate, its path and archival revocation
// evidence at at, which must precede the explicit observation time now. Every
// supplied timestamp must pass binding and trust checks. The target certificate
// and the path and status objects required by policy must have been proven to
// exist by at. This operation checks the status supported by the submitted
// archive at that time; it does not prove when an application signature existed.
// The report may be inspected on error.
func (v *Validator) Validate(ctx context.Context, certificateDER []byte, at, now time.Time, input Evidence) (*pki.PastCertificateResult, *Report, error) {
	report := &Report{}
	if v == nil || v.config.Signer == nil {
		return nil, report, ErrInput
	}

	if len(input.Timestamps) > v.config.MaxTimestamps {
		return nil, report, ErrLimit
	}

	archive := make([]historical.ObjectTimestamp, len(input.Timestamps))
	for i, stamp := range input.Timestamps {
		archive[i] = historical.ObjectTimestamp(stamp)
	}

	result, certificate, stamps, err := historical.ValidateCertificate(ctx, v.config, certificateDER, at, now, archive, input.Certificate, input.TSA)
	report.Certificate = certificate

	for _, stamp := range stamps {
		report.Timestamps = append(report.Timestamps, TimestampReport{
			TokenSHA256: stamp.Token, GenTime: stamp.Generation, UpperBound: stamp.Upper,
			Accepted: stamp.Indication == historical.Passed, SubIndication: stamp.SubIndication,
		})
	}

	return result, report, err
}
