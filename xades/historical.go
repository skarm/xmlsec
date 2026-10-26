package xades

import (
	"context"
	"encoding/hex"
	"errors"
	"time"

	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/internal/historical"
	"github.com/skarm/xmlsec/pki"
	"github.com/skarm/xmlsec/timestamp"
	"github.com/skarm/xmlsec/xmldsig"
)

// ErrHistorical reports a non-passing historical workflow. Missing evidence is
// an indeterminate outcome; only demonstrated invalidity is a failed outcome.
var ErrHistorical = historical.ErrValidation

// HistoricalConfig selects the separate EN 319 102-1 V1.4.1 workflow.
// It does not alter Validator or WithTimeValidator policy or establish legal
// qualification.
type HistoricalConfig struct {
	// SignerPKI supplies explicit signer trust, revocation checks and historical
	// constraints.
	SignerPKI pki.HistoricalConfig
	// TSA is the required immutable timestamp verifier with revocation checks enabled.
	TSA *timestamp.Verifier
	// TSAHistory selects separate historical certificate and algorithm constraints for
	// timestamp authorities.
	TSAHistory pki.HistoricalOptions
	// Baseline sets signature coverage, external resources and baseline property checks.
	Baseline BaselineVerifyOptions
	// MissingTSAAccuracy is an explicit TSA-policy assumption only when the
	// token omits accuracy. Nil refuses to manufacture a precision for its PoE.
	MissingTSAAccuracy *time.Duration
	// TimestampDelay optionally constrains the interval after claimed SigningTime.
	// It does not turn that signer claim into a proof of existence.
	TimestampDelay *time.Duration
	// RequireAllTimestamps rejects the operation if any present timestamp fails validation.
	RequireAllTimestamps bool
	// MaxObjects bounds exact objects in the evidence graph. Zero selects 512. The maximum
	// is 2048.
	MaxObjects int
	// MaxEdges bounds evidence graph relationships. Zero selects 4096. It must be at least
	// MaxObjects and at most 8192.
	MaxEdges int
	// MaxBytes bounds aggregate exact object bytes. Zero selects 16 MiB. The maximum is 64
	// MiB.
	MaxBytes int
	// MaxTimestamps bounds timestamp candidates. Zero selects 16. The maximum is 64.
	MaxTimestamps int
}

// HistoricalValidator retains immutable offline trust, coverage and time policy.
// Concurrent operations use separate bounded evidence graphs.
type HistoricalValidator struct {
	workflow historical.Config
	baseline BaselineVerifyOptions
}

// NewHistoricalValidator snapshots explicit policy; no system roots or network
// collection are used. Signer and timestamp policies must require revocation checking.
func NewHistoricalValidator(config HistoricalConfig) (*HistoricalValidator, error) {
	signer, err := pki.NewVerifier(config.SignerPKI.PKI)
	if err != nil {
		return nil, err
	}

	workflow, err := historical.Normalize(historical.Config{
		Signer: signer, SignerHistory: config.SignerPKI.HistoricalOptions,
		TSA: config.TSA, TSAHistory: config.TSAHistory,
		MissingAccuracy: config.MissingTSAAccuracy, TimestampDelay: config.TimestampDelay,
		RequireAllTimestamps: config.RequireAllTimestamps,
		MaxObjects:           config.MaxObjects, MaxEdges: config.MaxEdges, MaxBytes: config.MaxBytes, MaxTimestamps: config.MaxTimestamps,
	})
	if err != nil {
		return nil, err
	}

	baseline, err := normalizeBaselineVerifyOptions(config.Baseline)
	if err != nil {
		return nil, err
	}

	return &HistoricalValidator{workflow: workflow, baseline: baseline}, nil
}

// Validate first authenticates the selected baseline XML signature and every
// Reference. It then constructs exact archive/signature timestamp coverage and
// runs the independent historical workflow. A result is returned only on Passed;
// every other outcome retains a diagnostic report and an error.
func (v *HistoricalValidator) Validate(ctx context.Context, doc *document.Document, selected document.Element, certificateDER []byte, at time.Time, input ValidationEvidence) (*HistoricalResult, *HistoricalReport, error) {
	report := &HistoricalReport{state: &historical.Report{At: at}}
	if v == nil || ctx == nil || at.IsZero() {
		report.state.Cause = ErrProfile
		return nil, report, ErrProfile
	}

	if err := ctx.Err(); err != nil {
		report.state.Cause = err
		return nil, report, err
	}

	baseline, err := VerifyBaseline(ctx, doc, selected, certificateDER, v.baseline)
	if err != nil {
		report.state.Cause = err

		report.state.SubIndication = "FORMAT_FAILURE"
		if errors.Is(err, xmldsig.ErrDigest) || errors.Is(err, xmldsig.ErrSignature) {
			report.state.Indication = historical.Failed
			report.state.SubIndication = "SIG_CRYPTO_FAILURE"
		}

		return nil, report, err
	}

	model, evidence, err := historicalInput(ctx, baseline, v.baseline, v.workflow, input)
	if err != nil {
		report.state.Cause = err
		report.state.SubIndication = "FORMAT_FAILURE"

		return nil, report, err
	}

	state, err := historical.Validate(ctx, v.workflow, model, at, evidence.Signer, evidence.TSA)

	report.state = state
	if err != nil || state.Indication != historical.Passed {
		return nil, report, errors.Join(ErrHistorical, err)
	}

	return &HistoricalResult{baseline: baseline, report: report}, report, nil
}

// HistoricalReport records workflow diagnostics without granting acceptance.
// After Validate returns, accessors copy their values and support concurrent use.
type HistoricalReport struct{ state *historical.Report }

// Indication is Passed, Failed or Indeterminate. A nil/zero report is indeterminate.
func (r *HistoricalReport) Indication() Indication {
	if r == nil || r.state == nil {
		return Indeterminate
	}

	return Indication(r.state.Indication)
}

// SubIndication identifies the normative reason for a non-passing result.
func (r *HistoricalReport) SubIndication() string {
	if r == nil || r.state == nil {
		return ""
	}

	return r.state.SubIndication
}

// VerificationTime is the explicit present time of this operation.
func (r *HistoricalReport) VerificationTime() time.Time {
	if r == nil || r.state == nil {
		return time.Time{}
	}

	return r.state.At
}

// BestSignatureTime is the earliest authenticated existence upper bound.
func (r *HistoricalReport) BestSignatureTime() time.Time {
	if r == nil || r.state == nil {
		return time.Time{}
	}

	return r.state.Best
}

// ValidationTime is the calculated validation time, never SigningTime substitution.
func (r *HistoricalReport) ValidationTime() time.Time {
	if r == nil || r.state == nil {
		return time.Time{}
	}

	return r.state.Validation
}

// Cause retains the underlying failure without creating a partially trusted result.
func (r *HistoricalReport) Cause() error {
	if r == nil || r.state == nil {
		return nil
	}

	return r.state.Cause
}

// Standard names the published process edition used by this workflow.
func (r *HistoricalReport) Standard() string { return "ETSI EN 319 102-1 V1.4.1 (2024-06)" }

// Proofs returns owned diagnostic records from the completed graph.
func (r *HistoricalReport) Proofs() []HistoricalProof {
	if r == nil || r.state == nil || r.state.Proofs == nil {
		return nil
	}

	facts := r.state.Proofs.Facts()

	out := make([]HistoricalProof, 0, len(facts))
	for _, fact := range facts {
		source := ""
		if fact.Source != ([32]byte{}) {
			source = hex.EncodeToString(fact.Source[:])
		}

		out = append(out, HistoricalProof{ObjectSHA256: hex.EncodeToString(fact.Digest[:]), SourceSHA256: source, Kind: string(fact.Kind), At: fact.At})
	}

	return out
}

// Steps returns an owned, reproducible explanation of proof extraction/sliding.
func (r *HistoricalReport) Steps() []HistoricalStep {
	if r == nil || r.state == nil {
		return nil
	}

	out := make([]HistoricalStep, 0, len(r.state.Steps))
	for _, step := range r.state.Steps {
		out = append(out, HistoricalStep{Clause: step.Clause, Action: step.Action, SubIndication: step.SubIndication, ObjectSHA256: hex.EncodeToString(step.Object[:]), SourceSHA256: hex.EncodeToString(step.Source[:]), Before: step.Before, After: step.After})
	}

	return out
}

// Timestamps returns owned outcomes, including unusable optional attributes.
func (r *HistoricalReport) Timestamps() []HistoricalTimestamp {
	if r == nil || r.state == nil {
		return nil
	}

	out := make([]HistoricalTimestamp, 0, len(r.state.Stamps))
	for _, stamp := range r.state.Stamps {
		out = append(out, HistoricalTimestamp{TokenSHA256: hex.EncodeToString(stamp.Token[:]), CertificateSHA256: hex.EncodeToString(stamp.Certificate[:]), SubIndication: stamp.SubIndication, Generation: stamp.Generation, Upper: stamp.Upper, BestSignatureTime: stamp.Best, ValidationTime: stamp.Validation, Indication: Indication(stamp.Indication), Archive: stamp.Archive, Content: stamp.Content, Ordering: stamp.Ordering})
	}

	return out
}

// HistoricalProof records existence of an exact object by a specified time.
// SourceSHA256 is empty only for present-time observation. Acquisition provenance
// cannot establish this proof.
type HistoricalProof struct {
	// ObjectSHA256 is the hexadecimal SHA-256 digest of the exact object whose existence
	// was established.
	ObjectSHA256 string
	// SourceSHA256 identifies the protecting source. Empty denotes present-time
	// observation.
	SourceSHA256 string
	// Kind identifies the proof's role in the validation workflow.
	Kind string
	// At is the time by which the exact object is known to have existed.
	At time.Time
}

// HistoricalStep identifies one applied validation rule and its exact object and
// evidence sources.
type HistoricalStep struct {
	// Clause identifies the validation clause applied by this step.
	Clause string
	// Action describes the operation performed by this step.
	Action string
	// SubIndication records the detailed validation outcome associated with this step.
	SubIndication string
	// ObjectSHA256 identifies the exact object affected by this step.
	ObjectSHA256 string
	// SourceSHA256 identifies the evidence source used by this step, when present.
	SourceSHA256 string
	// Before is the relevant control time before this step, when applicable.
	Before time.Time
	// After is the relevant control time after this step, when applicable.
	After time.Time
}

// HistoricalTimestamp records a timestamp token's exact identity, time bounds and
// validation outcome.
type HistoricalTimestamp struct {
	// TokenSHA256 identifies the exact timestamp token by its hexadecimal SHA-256 digest.
	TokenSHA256 string
	// CertificateSHA256 identifies the timestamp signing certificate, when available.
	CertificateSHA256 string
	// SubIndication records the timestamp's detailed validation outcome.
	SubIndication string
	// Generation is the token's asserted generation time.
	Generation time.Time
	// Upper is the upper time bound used for proof extraction after accounting for
	// accuracy.
	Upper time.Time
	// BestSignatureTime is the workflow's best signature time for this timestamp token.
	BestSignatureTime time.Time
	// ValidationTime is the time used for the timestamp's certificate validation.
	ValidationTime time.Time
	// Indication records the timestamp validation outcome.
	Indication Indication
	// Archive reports whether this is an archive timestamp.
	Archive bool
	// Content reports whether this is a content timestamp.
	Content bool
	// Ordering records the token's signed ordering assertion.
	Ordering bool
}

// HistoricalResult records acceptance after every configured historical validation
// requirement passes.
type HistoricalResult struct {
	baseline *BaselineResult
	report   *HistoricalReport
}

// Baseline returns the immutable authenticated XML signature and signed claims.
func (r *HistoricalResult) Baseline() *BaselineResult {
	if r == nil {
		return nil
	}

	return r.baseline
}

// Report returns the immutable complete historical explanation.
func (r *HistoricalResult) Report() *HistoricalReport {
	if r == nil {
		return nil
	}

	return r.report
}

// CurrentSignerTrust is nonnil only when the current-time PKI path passed.
func (r *HistoricalResult) CurrentSignerTrust() *pki.Result {
	if r == nil || r.report == nil || r.report.state == nil {
		return nil
	}

	return r.report.state.Current
}

// PastSignerTrust is nonnil only when the separate past-certificate process passed.
func (r *HistoricalResult) PastSignerTrust() *pki.PastCertificateResult {
	if r == nil || r.report == nil || r.report.state == nil {
		return nil
	}

	return r.report.state.Past
}
