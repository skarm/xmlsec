package xades

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/internal/x509cert"
	"github.com/skarm/xmlsec/pki"
	"github.com/skarm/xmlsec/timestamp"
	"github.com/skarm/xmlsec/xmldsig"
)

// WithTimeConfig enables a separate B-T profile: current-time TSA trust and
// signer PKIX/revocation at the earliest proven existence of SignatureValue.
// It does not recover expired TSA chains, archive evidence or obsolete crypto.
// Signer evidence must be fresh at the proof time; TSA evidence at verification.
type WithTimeConfig struct {
	// SignerPKI sets explicit document signer trust and offline revocation policy.
	// Only direct complete signer CRLs are supported. Delta, scoped and indirect
	// CRLs remain outside this B-T profile even when accepted by general PKI.
	SignerPKI pki.Config
	// TSA supplies a trusted timestamp verifier with revocation checks enabled.
	TSA   *timestamp.Verifier
	Basic VerifyOptions
	// MaxTimestamps bounds timestamp tokens; zero selects 8, with a maximum of 32.
	MaxTimestamps int
	// MaxTokenBytes bounds each timestamp token; zero selects 4 MiB, with a 16 MiB maximum.
	MaxTokenBytes int
}

// WithTimeValidator validates the closed XAdES B-T profile using authenticated time
// evidence for the signer.
type WithTimeValidator struct {
	signer                       *pki.Verifier
	tsa                          *timestamp.Verifier
	basic                        VerifyOptions
	maxTimestamps, maxTokenBytes int
}

// NewWithTimeValidator validates and snapshots the closed with-time XAdES policy and
// trusted TSA verifier.
func NewWithTimeValidator(c WithTimeConfig) (*WithTimeValidator, error) {
	if c.SignerPKI.Revocation == pki.NoRevocation || c.TSA == nil || c.TSA.RevocationMode() == pki.NoRevocation {
		return nil, fmt.Errorf("%w: checked signer and TSA revocation required", ErrProfile)
	}

	o, e := normalizeTimedLimits(TimedOptions{MaxTimestamps: c.MaxTimestamps, MaxTokenBytes: c.MaxTokenBytes})
	if e != nil {
		return nil, e
	}

	v, e := pki.NewVerifier(c.SignerPKI)
	if e != nil {
		return nil, e
	}

	c.Basic.Policy.AllowedSignatureMethods = append([]string(nil), c.Basic.Policy.AllowedSignatureMethods...)
	c.Basic.Policy.AllowedDigestMethods = append([]string(nil), c.Basic.Policy.AllowedDigestMethods...)

	return &WithTimeValidator{v, c.TSA, c.Basic, o.MaxTimestamps, o.MaxTokenBytes}, nil
}

// ValidateEnveloped independently verifies SignatureValue, all References and
// the basic certificate binding before considering timestamps. ALL present
// SignatureTimeStamp tokens must verify with TSA trust at at. SigningTime is
// never a proof. Signer trust then uses the earliest verified upper-bound time.
// This closed B-T profile rejects preservation properties and provides no
// general historical EN 319 102-1, control-time sliding or archive recovery.
// Any error returns no result, including an Indeterminate diagnostic report.
func (v *WithTimeValidator) ValidateEnveloped(ctx context.Context, doc *document.Document, selected document.Element, certificateDER []byte, at time.Time, evidence ValidationEvidence) (*WithTimeResult, *WithTimeReport, error) {
	report := &WithTimeReport{at: at}

	reject := func(err error) (*WithTimeResult, *WithTimeReport, error) { report.cause = err; return nil, report, err }
	if v == nil || v.signer == nil || v.tsa == nil || ctx == nil || at.IsZero() {
		return reject(ErrProfile)
	}

	if err := ctx.Err(); err != nil {
		return reject(err)
	}

	basic, err := verifyBasicEnveloped(ctx, doc, selected, certificateDER, v.basic, true)
	if err != nil {
		if errors.Is(err, xmldsig.ErrDigest) || errors.Is(err, xmldsig.ErrSignature) {
			report.indication = Failed
		}

		return reject(err)
	}

	o, err := normalizeTimed(TimedOptions{Basic: v.basic, TSA: v.tsa, At: at, Evidence: evidence.TSA, MaxTimestamps: v.maxTimestamps, MaxTokenBytes: v.maxTokenBytes})
	if err != nil {
		return reject(err)
	}

	tokens, err := verifySignatureTimestamps(ctx, selected, o, false)
	if err != nil {
		return reject(err)
	}

	var proof signatureProof

	for _, token := range tokens {
		if token.Trust().RevocationStatus() != pki.Valid {
			return reject(ErrProfile)
		}

		info := token.Info()

		upper := info.GenTime()
		if accuracy, ok := info.Accuracy(); ok {
			upper = upper.Add(accuracy)
		}

		if upper.After(at) {
			return reject(fmt.Errorf("%w: proof upper bound is in the future", ErrTimestamp))
		}

		proof.add(upper)
	}

	if !proof.present {
		return reject(ErrTimestamp)
	}

	report.proof = proof.at

	originalCertificate := basic.CertificateDER()

	certificate, err := x509cert.ParseWithMaxBytes(originalCertificate, len(originalCertificate))
	if err != nil {
		return reject(ErrCertificate)
	}

	if proof.at.Before(certificate.NotBefore) || !proof.at.Before(certificate.NotAfter) {
		return reject(fmt.Errorf("%w: proof outside signer certificate validity", ErrLevel))
	}

	trust, _, err := v.signer.Verify(ctx, certificateDER, proof.at, evidence.Signer)
	if err != nil {
		if errors.Is(err, pki.ErrRevoked) {
			report.indication = Failed
		}

		return reject(err)
	}

	if err = refuseCRLRecovery(ctx, trust, evidence.Signer.CRLs, at); err != nil {
		return reject(err)
	}

	if trust.RevocationStatus() != pki.Valid {
		return reject(ErrProfile)
	}

	if err = ctx.Err(); err != nil {
		return reject(err)
	}

	report.indication = Passed

	return &WithTimeResult{basic, trust, tokens, at, proof.at}, report, nil
}

// WithTimeReport is diagnostic; a result is returned only when all checks pass.
// Failed denotes proven cryptographic failure or revocation at the proof time.
// Unsupported/missing/untrusted evidence is Indeterminate, never success.
type WithTimeReport struct {
	indication Indication
	at, proof  time.Time
	cause      error
}

// Indication returns the validation indication.
func (r *WithTimeReport) Indication() Indication {
	if r == nil {
		return Indeterminate
	}

	return r.indication
}

// VerificationTime returns the explicit time used for verification.
func (r *WithTimeReport) VerificationTime() time.Time {
	if r == nil {
		return time.Time{}
	}

	return r.at
}

// ProofTime is the earliest verified GenTime plus its declared Accuracy. A
// token without Accuracy uses its asserted GenTime under the trusted TSA policy.
func (r *WithTimeReport) ProofTime() time.Time {
	if r == nil {
		return time.Time{}
	}

	return r.proof
}

// Cause returns the underlying validation failure, if any.
func (r *WithTimeReport) Cause() error {
	if r == nil {
		return nil
	}

	return r.cause
}

// Profile returns the closed validation profile identifier.
func (r *WithTimeReport) Profile() string {
	if r == nil {
		return ""
	}

	return "xmlsec-enveloped-with-time-v1"
}

// WithTimeResult is an immutable signature accepted under the closed with-time profile.
type WithTimeResult struct {
	basic      *BasicResult
	trust      *pki.Result
	timestamps []*timestamp.Result
	at, proof  time.Time
}

// Basic returns the immutable basic XAdES result.
func (r *WithTimeResult) Basic() *BasicResult {
	if r == nil {
		return nil
	}

	return r.basic
}

// SignerTrust returns the immutable document signer trust result.
func (r *WithTimeResult) SignerTrust() *pki.Result {
	if r == nil {
		return nil
	}

	return r.trust
}

// Timestamps returns an owned slice of immutable verified timestamp results.
func (r *WithTimeResult) Timestamps() []*timestamp.Result {
	if r == nil {
		return nil
	}

	return append([]*timestamp.Result(nil), r.timestamps...)
}

// VerificationTime returns the explicit time used for verification.
func (r *WithTimeResult) VerificationTime() time.Time {
	if r == nil {
		return time.Time{}
	}

	return r.at
}

// ProofTime returns the authenticated time used as signature-existence evidence.
func (r *WithTimeResult) ProofTime() time.Time {
	if r == nil {
		return time.Time{}
	}

	return r.proof
}

// Profile returns the closed validation profile identifier.
func (r *WithTimeResult) Profile() string {
	if r == nil {
		return ""
	}

	return "xmlsec-enveloped-with-time-v1"
}
