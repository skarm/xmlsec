// Package historical implements the format-independent past-validation workflow.
// Only library format adapters can construct its exact-byte coverage inputs.
package historical

import (
	"context"
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"time"

	"github.com/skarm/xmlsec/internal/historicalproof"
	"github.com/skarm/xmlsec/pki"
	"github.com/skarm/xmlsec/timestamp"
)

var (
	// ErrValidation reports a non-passing historical validation outcome.
	ErrValidation = errors.New("historical validation did not pass")
	// ErrInput reports invalid adapter input or immutable policy.
	ErrInput = errors.New("invalid historical validation input")
	// ErrLimit reports exhaustion of an aggregate workflow budget.
	ErrLimit = errors.New("historical validation resource limit exceeded")
)

// Indication is the three-state EN 319 102-1 outcome, with an unsafe zero value.
type Indication uint8

const (
	Indeterminate Indication = iota
	Passed
	Failed
)

// Object is one exact original encoding identified independently of its role.
// Contains is populated only by a format parser, not by application assertions.
type Object struct {
	// Bytes contains the exact original encoding established by the format adapter.
	Bytes []byte
	// Kind identifies the object's role in historical validation.
	Kind historicalproof.Kind
	// Contains lists digests of objects physically contained in Bytes.
	Contains [][sha256.Size]byte
	// Refs lists protected digest references encoded by this object.
	Refs []HashReference
}

// HashReference binds an encoded, protected digest to actual object bytes.
type HashReference struct {
	// Hash identifies the protected digest algorithm.
	Hash crypto.Hash
	// Digest is the protected digest value carried by the containing object.
	Digest []byte
	// Target identifies the referenced object's exact encoding by SHA-256.
	Target [sha256.Size]byte
}

// MaterialUse binds an algorithm to the exact material it protects. Recovery
// cannot borrow a SignatureValue proof for unrelated reference input bytes.
type MaterialUse struct {
	// Object identifies the exact protected material by SHA-256.
	Object [sha256.Size]byte
	// Hash is the algorithm used to protect that material.
	Hash crypto.Hash
}

// Candidate is a timestamp and the exact input established by its format adapter.
// Covered names objects actually present in that input; a reference to an object
// must instead be represented as HashReference on the containing object.
type Candidate struct {
	// Token is the parsed timestamp awaiting independent authentication and trust
	// checks.
	Token *timestamp.Token
	// Imprint is the expected digest of the input established by the format
	// adapter.
	Imprint timestamp.Imprint
	// Covered lists exact-byte object digests present in the timestamp input.
	Covered [][sha256.Size]byte
	// Archive identifies an archive timestamp candidate.
	Archive bool
	// Content identifies a content timestamp candidate.
	Content bool
}

// Input has already passed signature, reference and format-binding checks.
// The workflow independently checks all timestamp bindings and certificate paths.
type Input struct {
	// Signature identifies the exact signature object by SHA-256.
	Signature [sha256.Size]byte
	// Certificate contains the signer certificate's exact DER encoding.
	Certificate []byte
	// SignatureMethod is the verified signature algorithm.
	SignatureMethod x509.SignatureAlgorithm
	// Hashes lists hash algorithms whose historical acceptability must be checked.
	Hashes []crypto.Hash
	// Uses binds each protected object to the hash algorithm applied to it.
	Uses []MaterialUse
	// ClaimedTime is a signed time claim and supplies no independent proof of
	// existence.
	ClaimedTime time.Time
	// ClaimedTimeAfter compares the exact signed UTC dateTime to a finite
	// threshold without truncating arbitrary year/fraction precision.
	// Only an authenticated format adapter supplies this pure comparison.
	ClaimedTimeAfter func(time.Time) (bool, error)
	// Objects contains the format adapter's exact encodings and
	// containment/reference bindings.
	Objects []Object
	// Timestamps contains timestamp candidates whose bindings and trust must still
	// be checked.
	Timestamps []Candidate
}

// Config is immutable after construction of a public format validator.
type Config struct {
	// Signer supplies the signer's current certificate and revocation policy.
	Signer *pki.Verifier
	// SignerHistory supplies the signer's historical certificate policy.
	SignerHistory pki.HistoricalOptions
	// TSA supplies timestamp authentication and trust policy.
	TSA *timestamp.Verifier
	// TSAHistory supplies historical certificate policy for timestamp authorities.
	TSAHistory pki.HistoricalOptions
	// MissingAccuracy is an explicit TSA policy assumption when RFC3161 accuracy
	// is absent. Nil refuses to invent a precision for historical proof extraction.
	MissingAccuracy *time.Duration
	// TimestampDelay optionally bounds the delay between claimed signing time and
	// timestamp evidence.
	TimestampDelay *time.Duration
	// RequireAllTimestamps requires every supplied timestamp candidate to pass.
	RequireAllTimestamps bool
	// MaxObjects bounds distinct objects in the proof graph.
	MaxObjects int
	// MaxEdges bounds containment and digest-reference edges.
	MaxEdges int
	// MaxBytes bounds aggregate object encodings in bytes.
	MaxBytes int
	// MaxTimestamps bounds supplied timestamp candidates.
	MaxTimestamps int
}

// Step records a normative decision without exposing mutable internal state.
type Step struct {
	// Clause identifies the standard clause governing the decision.
	Clause string
	// Action identifies the validation operation recorded by this step.
	Action string
	// SubIndication records the detailed validation outcome.
	SubIndication string
	// Object identifies the affected object by its exact-byte SHA-256 digest.
	Object [sha256.Size]byte
	// Source identifies the evidence object supporting the decision.
	Source [sha256.Size]byte
	// Before records the time bound before this decision.
	Before time.Time
	// After records the time bound after this decision.
	After time.Time
}

// Stamp records a timestamp's outcome and its exact token/binding identity.
type Stamp struct {
	// Generation is the authenticated timestamp generation time.
	Generation time.Time
	// Upper is the generation-time upper bound including the accepted accuracy.
	Upper time.Time
	// Best is the best signature time established for this timestamp.
	Best time.Time
	// Validation is the time selected for historical certificate validation.
	Validation time.Time
	// Path is the selected historical TSA certificate path.
	Path *pki.HistoricalPath
	// SubIndication records the detailed timestamp outcome.
	SubIndication string
	// Token identifies the exact timestamp encoding by SHA-256.
	Token [sha256.Size]byte
	// Certificate identifies the TSA certificate encoding by SHA-256.
	Certificate [sha256.Size]byte
	// Indication records the timestamp's three-state validation outcome.
	Indication Indication
	// Archive identifies an archive timestamp.
	Archive bool
	// Content identifies a content timestamp.
	Content bool
	// Ordering records the TSA's authenticated ordering assertion.
	Ordering bool
}

// Report is an operation-local immutable result after Validate returns.
type Report struct {
	// Indication is the overall three-state historical validation outcome.
	Indication Indication
	// SubIndication is the detailed reason for the outcome.
	SubIndication string
	// At is the explicit current validation time.
	At time.Time
	// Best is the best signature time established by accepted evidence.
	Best time.Time
	// Validation is the time selected for historical certificate validation.
	Validation time.Time
	// Path is the selected historical signer certificate path.
	Path *pki.HistoricalPath
	// Current retains acceptance under the current signer policy, when established.
	Current *pki.Result
	// Past retains successful past certificate validation, when established.
	Past *pki.PastCertificateResult
	// Proofs is the immutable exact-byte proof-of-existence snapshot.
	Proofs *historicalproof.Set
	// Steps records validation decisions in execution order.
	Steps []Step
	// Stamps records the evaluated timestamp candidates and their outcomes.
	Stamps []Stamp
	// Cause retains the error responsible for a non-passing outcome.
	Cause error
}

// Validate performs the separate historical workflow. A successful report is
// returned only after both cryptographic format checks and every required time,
// evidence, certificate and algorithm constraint have passed.
func Validate(ctx context.Context, c Config, input Input, now time.Time, signerEvidence, tsaEvidence pki.Evidence) (*Report, error) {
	return validate(ctx, c, input, now, signerEvidence, tsaEvidence)
}
