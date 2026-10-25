package timestamp

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/skarm/xmlsec/evidence"
	"github.com/skarm/xmlsec/pki"
)

// VerifiedAssertion is an immutable authenticated TSA assertion minted only by
// successful token/response verification. A caller-created zero value is invalid.
// It binds the exact token, imprint and asserted GenTime to the TSA and explicit
// verification policy/time. It does not itself prove historical validity after
// TSA expiration/revocation or authenticate an arbitrary caller-supplied time.
// Trust retains whether revocation was required or explicitly left unchecked.
type VerifiedAssertion struct {
	generation       time.Time
	validation       time.Time
	trust            *pki.Result
	tokenFingerprint string
	tsaFingerprint   string
	imprint          Imprint
	sources          []*evidence.Observation
	policy           asn1.ObjectIdentifier
	accuracy         time.Duration
	authenticated    bool
	hasAccuracy      bool
	ordering         bool
}

func verifiedAssertion(ctx context.Context, token *Token, info Info, tsa []byte, trust *pki.Result) (*VerifiedAssertion, error) {
	if token == nil || trust == nil {
		return nil, ErrTrust
	}

	digest := sha256.New()
	if _, err := token.WriterTo(ctx).WriteTo(digest); err != nil {
		return nil, err
	}

	signer := sha256.Sum256(tsa)

	return &VerifiedAssertion{authenticated: true, accuracy: info.accuracy, hasAccuracy: info.hasAccuracy, ordering: info.ordering, tokenFingerprint: hex.EncodeToString(digest.Sum(nil)), tsaFingerprint: hex.EncodeToString(signer[:]), imprint: Imprint{Hash: info.imprint.Hash, Digest: bytes.Clone(info.imprint.Digest)}, generation: info.at, validation: trust.VerificationTime(), policy: append(asn1.ObjectIdentifier(nil), info.policy...), trust: trust}, nil
}

// Valid reports whether this value came from a complete configured-policy check.
func (a *VerifiedAssertion) Valid() bool { return a != nil && a.authenticated && a.trust != nil }

// TokenSHA256 identifies the exact authenticated token container encoding.
func (a *VerifiedAssertion) TokenSHA256() string {
	if !a.Valid() {
		return ""
	}

	return a.tokenFingerprint
}

// TSACertificateSHA256 identifies the authenticated TSA certificate DER.
func (a *VerifiedAssertion) TSACertificateSHA256() string {
	if !a.Valid() {
		return ""
	}

	return a.tsaFingerprint
}

// Imprint returns an owned copy of the digest to which the assertion applies.
func (a *VerifiedAssertion) Imprint() Imprint {
	if !a.Valid() {
		return Imprint{}
	}

	return Imprint{Hash: a.imprint.Hash, Digest: bytes.Clone(a.imprint.Digest)}
}

// GenTime returns the TSA's authenticated time assertion, not a local clock read.
func (a *VerifiedAssertion) GenTime() time.Time {
	if !a.Valid() {
		return time.Time{}
	}

	return a.generation
}

// ValidationTime returns the explicit time at which the TSA trust policy passed.
func (a *VerifiedAssertion) ValidationTime() time.Time {
	if !a.Valid() {
		return time.Time{}
	}

	return a.validation
}

// Policy returns an owned copy of the accepted TSA policy identifier.
func (a *VerifiedAssertion) Policy() asn1.ObjectIdentifier {
	if !a.Valid() {
		return nil
	}

	return append(asn1.ObjectIdentifier(nil), a.policy...)
}

// Trust returns the immutable configured TSA chain/revocation policy result.
func (a *VerifiedAssertion) Trust() *pki.Result {
	if !a.Valid() {
		return nil
	}

	return a.trust
}

// Assertion returns the immutable authenticated TSA assertion of this result.
func (r *Result) Assertion() *VerifiedAssertion {
	if r == nil {
		return nil
	}

	return r.assertion
}

// Evidence returns the distinct authenticated chain/revocation records used by
// this result. These records are separate from the token's time/imprint assertion.
func (r *Result) Evidence() []*pki.VerifiedEvidence {
	if r == nil || r.trust == nil {
		return nil
	}

	return r.trust.Evidence()
}

// Accuracy returns the authenticated uncertainty around GenTime when supplied.
// Its absence does not assert zero uncertainty; TSA policy may define accuracy.
func (a *VerifiedAssertion) Accuracy() (time.Duration, bool) {
	if !a.Valid() {
		return 0, false
	}

	return a.accuracy, a.hasAccuracy
}

// Ordering returns the TSA's authenticated within-TSA ordering assertion.
func (a *VerifiedAssertion) Ordering() bool { return a.Valid() && a.ordering }

// Sources returns immutable acquisition observations matched to the exact token
// or solicited response bytes. URI/retrieval time are untrusted metadata, never
// additional TSA authority, freshness evidence or proof of historical existence.
func (a *VerifiedAssertion) Sources() []*evidence.Observation {
	if !a.Valid() {
		return nil
	}

	return append([]*evidence.Observation(nil), a.sources...)
}

func (v *Verifier) timestampSources(ctx context.Context, token *Token, response []byte, input pki.Evidence) (pki.Evidence, []*evidence.Observation, error) {
	if len(input.Sources) == 0 {
		return input, nil, nil
	}

	if len(input.Sources) > 1024 {
		return pki.Evidence{}, nil, ErrPolicy
	}

	var (
		selected  []*evidence.Observation
		tokenHash [sha256.Size]byte
	)

	remaining := v.maxBytes
	filtered := input
	filtered.Sources = make([]*evidence.Observation, 0, len(input.Sources))
	computed := false
	responseHash := sha256.Sum256(response)

	for _, source := range input.Sources {
		if err := ctx.Err(); err != nil {
			return pki.Evidence{}, nil, err
		}

		if source == nil || !source.Valid() {
			return pki.Evidence{}, nil, fmt.Errorf("%w: invalid source", ErrBinding)
		}

		if source.Size() > remaining {
			return pki.Evidence{}, nil, ErrPolicy
		}

		remaining -= source.Size()
		if source.Kind() != evidence.Timestamp {
			filtered.Sources = append(filtered.Sources, source)
			continue
		}

		if !computed {
			hash := sha256.New()
			if _, err := token.WriterTo(ctx).WriteTo(hash); err != nil {
				return pki.Evidence{}, nil, err
			}

			copy(tokenHash[:], hash.Sum(nil))

			computed = true
		}

		fingerprint := source.DigestSHA256()
		if fingerprint != tokenHash && (len(response) == 0 || fingerprint != responseHash) {
			return pki.Evidence{}, nil, fmt.Errorf("%w: unmatched timestamp source", ErrBinding)
		}

		selected = append(selected, source)
	}

	return filtered, selected, nil
}
