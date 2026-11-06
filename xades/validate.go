package xades

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/pki"
	"github.com/skarm/xmlsec/timestamp"
)

const (
	profileEnvelopedCurrentTime = "xmlsec-enveloped-current-time-v1"
	defaultArchiveBytes         = 16 << 20
	defaultArchiveTimestamps    = 8
	maximumArchiveBytes         = 64 << 20
	maximumArchiveTimestamps    = 16
)

// ErrLevel reports missing evidence or an unavailable required XAdES profile level.
var ErrLevel = errors.New("required XAdES profile level or evidence unavailable")

// Level identifies a validation level within the closed XAdES profile. It does not
// establish full ETSI conformance or legal qualification.
type Level string

const (
	// LevelBB requires basic XAdES validation.
	LevelBB Level = "B-B"
	// LevelBT requires a validated SignatureTimeStamp in the closed XAdES profile.
	LevelBT Level = "B-T"
	// LevelLT requires authenticated embedded validation material in the closed profile.
	LevelLT Level = "B-LT"
	// LevelLTA requires authenticated archive timestamps in the closed profile.
	LevelLTA Level = "B-LTA"
)

// ValidatorConfig supplies signer and TSA trust, the required validation level and
// evidence budgets.
type ValidatorConfig struct {
	// SignerPKI sets explicit document signer trust and offline revocation policy.
	SignerPKI pki.Config
	// TSA supplies the immutable trusted timestamp verifier and is required
	// for every MinimumLevel except LevelBB.
	TSA *timestamp.Verifier
	// MinimumLevel is required and prevents implicit validation downgrades.
	MinimumLevel Level
	// AllowUncheckedSignerRevocation explicitly permits signer verification without
	// revocation evidence.
	AllowUncheckedSignerRevocation bool
	// Basic sets the closed basic signature profile's ID and algorithm policy.
	Basic VerifyOptions
	// MaxTimestamps bounds timestamp tokens; zero selects 8, with a maximum of 32.
	MaxTimestamps int
	// MaxTokenBytes bounds each timestamp token; zero selects 4 MiB, with a 16 MiB maximum.
	MaxTokenBytes int
	// MaxArchiveTimestamps bounds archive timestamps; zero selects 8, with a maximum of 16.
	MaxArchiveTimestamps int
	// MaxArchiveBytes bounds archive input; zero selects 16 MiB, with a 64 MiB maximum.
	MaxArchiveBytes int
}

// Validator retains immutable policy for closed-profile XAdES signatures and offline
// evidence validation.
type Validator struct {
	// signer retains explicit signer certificate and revocation policy.
	signer *pki.Verifier
	// tsa retains timestamp authority verification policy.
	tsa *timestamp.Verifier
	// minimum is the least XAdES level accepted by this validator.
	minimum Level
	// unchecked explicitly permits signer verification without revocation checking.
	unchecked bool
	// basic retains the closed basic signature profile and algorithm policy.
	basic VerifyOptions
	// maxTimestamps bounds signature timestamp tokens.
	maxTimestamps int
	// maxTokenBytes bounds each encoded timestamp token in bytes.
	maxTokenBytes int
	// maxArchives bounds archive timestamps.
	maxArchives int
	// maxArchiveBytes bounds archive timestamp input in bytes.
	maxArchiveBytes int
}

// NewValidator validates and snapshots the required XAdES level, explicit trust and
// evidence budgets.
func NewValidator(c ValidatorConfig) (*Validator, error) {
	if c.MinimumLevel != LevelBB && c.MinimumLevel != LevelBT && c.MinimumLevel != LevelLT && c.MinimumLevel != LevelLTA {
		return nil, ErrProfile
	}

	if c.MinimumLevel != LevelBB && c.TSA == nil {
		return nil, ErrTimestamp
	}

	if c.SignerPKI.Revocation == pki.NoRevocation && !c.AllowUncheckedSignerRevocation {
		return nil, fmt.Errorf("%w: signer revocation checking required", ErrProfile)
	}

	c.Basic.Policy.AllowedSignatureMethods = append([]string(nil), c.Basic.Policy.AllowedSignatureMethods...)
	c.Basic.Policy.AllowedDigestMethods = append([]string(nil), c.Basic.Policy.AllowedDigestMethods...)

	v, e := pki.NewVerifier(c.SignerPKI)
	if e != nil {
		return nil, e
	}

	if c.MaxArchiveTimestamps == 0 {
		c.MaxArchiveTimestamps = defaultArchiveTimestamps
	}

	if c.MaxArchiveBytes == 0 {
		c.MaxArchiveBytes = defaultArchiveBytes
	}

	if c.MaxArchiveTimestamps < 1 || c.MaxArchiveTimestamps > maximumArchiveTimestamps || c.MaxArchiveBytes < 1 || c.MaxArchiveBytes > maximumArchiveBytes {
		return nil, ErrProfile
	}

	limits, e := normalizeTimedLimits(TimedOptions{MaxTimestamps: c.MaxTimestamps, MaxTokenBytes: c.MaxTokenBytes})
	if e != nil {
		return nil, e
	}

	return &Validator{signer: v, tsa: c.TSA, minimum: c.MinimumLevel, unchecked: c.AllowUncheckedSignerRevocation, basic: c.Basic, maxTimestamps: limits.MaxTimestamps, maxTokenBytes: limits.MaxTokenBytes, maxArchives: c.MaxArchiveTimestamps, maxArchiveBytes: c.MaxArchiveBytes}, nil
}

// ValidateEnveloped checks current-time PKIX; it never uses SigningTime to
// backdate certificate validity. Even when minimum=B-B, present timestamps must
// ALL be understood and verified; an invalid higher property cannot be ignored.
func (v *Validator) ValidateEnveloped(ctx context.Context, doc *document.Document, selected document.Element, certificateDER []byte, at time.Time, evidence ValidationEvidence) (*ValidationResult, error) {
	if v == nil || ctx == nil || at.IsZero() {
		return nil, ErrProfile
	}

	preserved, e := hasPreservation(selected)
	if e != nil {
		return nil, e
	}

	if preserved || v.minimum == LevelLT || v.minimum == LevelLTA {
		return v.validatePreserved(ctx, doc, selected, certificateDER, at)
	}

	basic, e := verifyBasicEnveloped(ctx, doc, selected, certificateDER, v.basic, true)
	if e != nil {
		return nil, e
	}

	trust, _, e := v.signer.Verify(ctx, certificateDER, at, evidence.Signer)
	if e != nil {
		return nil, e
	}

	if !v.unchecked && trust.RevocationStatus() != pki.Valid {
		return nil, ErrProfile
	}

	usp, e := unsignedProperties(selected)
	if e != nil {
		return nil, e
	}

	result := &ValidationResult{basic: basic, trust: trust, level: LevelBB, at: at}
	if usp.Valid() || v.minimum == LevelBT {
		opts, e := normalizeTimed(TimedOptions{Basic: v.basic, TSA: v.tsa, At: at, Evidence: evidence.TSA, MaxTimestamps: v.maxTimestamps, MaxTokenBytes: v.maxTokenBytes})
		if e != nil {
			return nil, e
		}

		result.timestamps, e = verifySignatureTimestamps(ctx, selected, opts, false)
		if e != nil {
			return nil, e
		}

		result.level = LevelBT
	}

	return result, nil
}

// ValidationEvidence supplies separate offline inputs for document signer and TSA
// validation.
type ValidationEvidence struct {
	// Signer supplies untrusted intermediates and revocation data for the document signer.
	Signer pki.Evidence
	// TSA supplies untrusted intermediates and revocation data for timestamp authorities.
	TSA pki.Evidence
}

// ValidationResult retains an immutable accepted XAdES signature, its achieved level,
// trust results and evidence.
type ValidationResult struct {
	// basic retains the accepted basic signature and signed properties.
	basic *BasicResult
	// timestamps retains verified signature timestamp results.
	timestamps []*timestamp.Result
	// trust retains the accepted signer certificate and revocation result.
	trust *pki.Result
	// level records the XAdES level achieved under this validator's policy.
	level Level
	// at is the explicit validation time.
	at time.Time
	// archives retains verified archive timestamp results.
	archives []*timestamp.Result
	// material retains the validation material used by the accepted profile.
	material ValidationMaterial
}

// Basic returns the immutable basic XAdES result.
func (r *ValidationResult) Basic() *BasicResult {
	if r == nil {
		return nil
	}

	return r.basic
}

// Timestamps returns an owned slice of immutable verified timestamp results.
func (r *ValidationResult) Timestamps() []*timestamp.Result {
	if r == nil {
		return nil
	}

	return append([]*timestamp.Result(nil), r.timestamps...)
}

// SignerTrust returns the immutable document signer trust result.
func (r *ValidationResult) SignerTrust() *pki.Result {
	if r == nil {
		return nil
	}

	return r.trust
}

// Level returns the achieved validation level.
func (r *ValidationResult) Level() Level {
	if r == nil {
		return ""
	}

	return r.level
}

// VerificationTime returns the explicit time used for verification.
func (r *ValidationResult) VerificationTime() time.Time {
	if r == nil {
		return time.Time{}
	}

	return r.at
}

// ArchiveTimestamps returns an owned slice of immutable verified archive timestamp
// results.
func (r *ValidationResult) ArchiveTimestamps() []*timestamp.Result {
	if r == nil {
		return nil
	}

	return append([]*timestamp.Result(nil), r.archives...)
}

// EmbeddedMaterial returns owned copies of embedded validation material.
func (r *ValidationResult) EmbeddedMaterial() ValidationMaterial {
	if r == nil {
		return ValidationMaterial{}
	}

	return cloneMaterial(r.material)
}

// Profile makes the restricted validation model explicit alongside Level().
// A B-LTA result under this profile does NOT mean historical EN 319 102-1
// validation, long-term algorithm migration, or legal signature qualification.
func (r *ValidationResult) Profile() string {
	if r == nil {
		return ""
	}

	return profileEnvelopedCurrentTime
}
