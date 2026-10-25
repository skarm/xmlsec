// Package historical implements the format-independent past-validation workflow.
// Only library format adapters can construct its exact-byte coverage inputs.
package historical

import (
	"context"
	"crypto"
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
	Bytes    []byte
	Kind     historicalproof.Kind
	Contains [][32]byte
	Refs     []HashReference
}

// HashReference binds an encoded, protected digest to actual object bytes.
type HashReference struct {
	Hash   crypto.Hash
	Digest []byte
	Target [32]byte
}

// MaterialUse binds an algorithm to the exact material it protects. Recovery
// cannot borrow a SignatureValue proof for unrelated reference input bytes.
type MaterialUse struct {
	Object [32]byte
	Hash   crypto.Hash
}

// Candidate is a timestamp and the exact input established by its format adapter.
// Covered names objects actually present in that input; a reference to an object
// must instead be represented as HashReference on the containing object.
type Candidate struct {
	Token   *timestamp.Token
	Imprint timestamp.Imprint
	Covered [][32]byte
	Archive bool
	Content bool
}

// Input has already passed signature, reference and format-binding checks.
// The workflow independently checks all timestamp bindings and certificate paths.
type Input struct {
	Signature       [32]byte
	Certificate     []byte
	SignatureMethod x509.SignatureAlgorithm
	Hashes          []crypto.Hash
	Uses            []MaterialUse
	ClaimedTime     time.Time
	// ClaimedTimeAfter compares the exact signed UTC dateTime to a finite
	// threshold without truncating arbitrary year/fraction precision.
	// Only an authenticated format adapter supplies this pure comparison.
	ClaimedTimeAfter func(time.Time) (bool, error)
	Objects          []Object
	Timestamps       []Candidate
}

// Config is immutable after construction of a public format validator.
type Config struct {
	Signer        *pki.Verifier
	SignerHistory pki.HistoricalOptions
	TSA           *timestamp.Verifier
	TSAHistory    pki.HistoricalOptions
	// MissingAccuracy is an explicit TSA policy assumption when RFC3161 accuracy
	// is absent. Nil refuses to invent a precision for historical proof extraction.
	MissingAccuracy      *time.Duration
	TimestampDelay       *time.Duration
	RequireAllTimestamps bool
	MaxObjects           int
	MaxEdges             int
	MaxBytes             int
	MaxTimestamps        int
}

// Step records a normative decision without exposing mutable internal state.
type Step struct {
	Clause        string
	Action        string
	SubIndication string
	Object        [32]byte
	Source        [32]byte
	Before        time.Time
	After         time.Time
}

// Stamp records a timestamp's outcome and its exact token/binding identity.
type Stamp struct {
	Generation    time.Time
	Upper         time.Time
	Best          time.Time
	Validation    time.Time
	Path          *pki.HistoricalPath
	SubIndication string
	Token         [32]byte
	Certificate   [32]byte
	Indication    Indication
	Archive       bool
	Content       bool
	Ordering      bool
}

// Report is an operation-local immutable result after Validate returns.
type Report struct {
	Indication    Indication
	SubIndication string
	At            time.Time
	Best          time.Time
	Validation    time.Time
	Path          *pki.HistoricalPath
	Current       *pki.Result
	Past          *pki.PastCertificateResult
	Proofs        *historicalproof.Set
	Steps         []Step
	Stamps        []Stamp
	Cause         error
}

// Validate performs the separate historical workflow. A successful report is
// returned only after both cryptographic format checks and every required time,
// evidence, certificate and algorithm constraint have passed.
func Validate(ctx context.Context, c Config, input Input, now time.Time, signerEvidence, tsaEvidence pki.Evidence) (*Report, error) {
	return validate(ctx, c, input, now, signerEvidence, tsaEvidence)
}
