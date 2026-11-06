package pki

import (
	"bytes"
	"context"
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"maps"
	"sync"
	"time"

	"github.com/skarm/xmlsec/evidence"
	"github.com/skarm/xmlsec/internal/historicalproof"
)

const (
	defaultMaxHistoricalPaths = 16
	maxConstraintKeyBits      = 16385
	maxCryptoConstraints      = 128
	maxTrustAnchorSunsets     = 64
	maximumHistoricalPaths    = 256
)

// ValidityModel selects the historical certificate calendar model.
type ValidityModel string

const (
	// ShellModel requires a common certificate validity interval.
	ShellModel ValidityModel = "shell"
	// ChainModel checks CA validity at the certificate generation times defined
	// by EN319102-1 and its selected Common PKI chain-model dependency.
	ChainModel ValidityModel = "chain"
)

// CryptoConstraint sets a reliability cutoff for one algorithm or key-size family.
// Set exactly one selector: SignatureAlgorithm, Hash, or PublicKeyAlgorithm with
// MinimumKeyBits. A key-size rule applies below that minimum. These rules do not
// enable unsupported cryptography or bypass FIPS restrictions.
type CryptoConstraint struct {
	// SignatureAlgorithm selects one certificate or evidence signature algorithm.
	SignatureAlgorithm x509.SignatureAlgorithm
	// Hash selects one digest algorithm, independently of a signature algorithm.
	Hash crypto.Hash
	// PublicKeyAlgorithm selects the key family governed by MinimumKeyBits.
	PublicKeyAlgorithm x509.PublicKeyAlgorithm
	// MinimumKeyBits applies the cutoff to keys smaller than this size in the selected
	// family.
	MinimumKeyBits int
	// ReliableUntil is the required, nonzero algorithm or key-size reliability cutoff.
	ReliableUntil time.Time
}

// HistoricalOptions selects certificate calendar and temporal validation policy.
// It applies to historical sessions separately from current Verify operations.
// Construction copies maps, slices and pointed-to values.
type HistoricalOptions struct {
	// Model selects the certificate validity model. Empty selects ShellModel.
	Model ValidityModel
	// MaxPaths bounds candidate paths per target. Zero selects 16. The maximum is 256.
	MaxPaths int
	// TrustAnchorSunsets maps configured trust anchors' lowercase hexadecimal SHA-256 DER
	// fingerprints to nonzero trust cutoffs.
	TrustAnchorSunsets map[string]time.Time
	// CryptoConstraints supplies at most 128 algorithm or key-size reliability rules.
	CryptoConstraints []CryptoConstraint
	// RevocationFreshness nil derives nextUpdate-thisUpdate. Missing nextUpdate
	// then fails freshness; explicit zero remains a distinct configured value.
	RevocationFreshness *time.Duration
}

// HistoricalConfig supplies explicit trust and historical policy.
type HistoricalConfig struct {
	// PKI supplies explicit trust anchors, certificate usages and offline revocation
	// policy.
	PKI Config
	// HistoricalOptions selects the certificate calendar and temporal constraints.
	HistoricalOptions
}

// HistoricalSession holds the evidence, explicit present time and bounded caches
// for one offline historical operation. Its methods serialize cache access and
// return immutable objects. Source authentication, freshness, proof of existence
// and past acceptance are separate checks.
type HistoricalSession struct {
	// mu serializes operation-local caches and cumulative work counters.
	mu sync.Mutex
	// verifier retains the explicit certificate and revocation policy.
	verifier *Verifier
	// options retains the normalized historical validation policy.
	options HistoricalOptions
	// now fixes the operation's current observation time.
	now time.Time
	// evidence owns the supplied offline evidence snapshot.
	evidence Evidence
	// paths caches prospective paths by exact target certificate digest.
	paths map[[sha256.Size]byte][]*HistoricalPath
	// certificates indexes parsed certificates by exact DER digest.
	certificates map[[sha256.Size]byte]*x509.Certificate
	// targetBytes accounts for target certificate input charged to the session.
	targetBytes int
	// pathWork accounts for cumulative prospective-path search work.
	pathWork int
	// signatureWork accounts for cumulative cryptographic verification work.
	signatureWork int
	// sourcesReady records completion of source evidence preparation.
	sourcesReady bool
	// lists caches parsed CRLs without treating parsing as authentication.
	lists []*parsedCRL
	// responses caches parsed OCSP responses without treating parsing as
	// authentication.
	responses []parsedOCSP
	// claims caches authenticated evidence claims by exact prospective path
	// fingerprint.
	claims map[[sha256.Size]byte][]historicalClaim
}

// NewHistoricalSession snapshots an explicit trust configuration and operation.
func NewHistoricalSession(ctx context.Context, config HistoricalConfig, now time.Time, input Evidence) (*HistoricalSession, error) {
	verifier, err := NewVerifier(config.PKI)
	if err != nil {
		return nil, err
	}

	return verifier.NewHistoricalSession(ctx, config.HistoricalOptions, now, input)
}

// Paths discovers bounded prospective exact paths without rejecting current
// expiration. Discovery is not historical authentication or trust acceptance.
func (s *HistoricalSession) Paths(ctx context.Context, targetDER []byte) ([]*HistoricalPath, error) {
	if err := s.request(ctx); err != nil {
		return nil, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	target, err := s.historicalTarget(ctx, targetDER)
	if err != nil {
		return nil, err
	}

	return s.pathsFor(ctx, target)
}

// CheckPath validates one same-session path under its selected calendar model.
func (s *HistoricalSession) CheckPath(ctx context.Context, path *HistoricalPath) (*HistoricalPathAssessment, error) {
	if err := s.request(ctx); err != nil {
		return nil, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	return s.checkPath(ctx, path)
}

// AuthenticateEvidence authenticates source signatures, issuer authority and
// exact target/scope bindings at issuance. Stale/revoked claims are not Results.
func (s *HistoricalSession) AuthenticateEvidence(ctx context.Context, path *HistoricalPath) ([]*VerifiedEvidence, error) {
	if err := s.request(ctx); err != nil {
		return nil, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if _, err := s.checkPath(ctx, path); err != nil {
		return nil, err
	}

	claims, err := s.authenticate(ctx, path)
	if err != nil {
		return nil, err
	}

	facts := make([]*VerifiedEvidence, 0, len(claims))
	for _, claim := range claims {
		facts = append(facts, claim.fact)
	}

	return canonicalEvidence(facts), nil
}

// VerifyCurrent applies the unchanged current-time verifier to this session's
// fixed present time and owned evidence. Diagnostic authentication remains
// available separately through AuthenticateEvidence when the target is expired.
func (s *HistoricalSession) VerifyCurrent(ctx context.Context, targetDER []byte) (*Result, Report, error) {
	if err := s.request(ctx); err != nil {
		return nil, Report{}, err
	}

	return s.verifier.Verify(ctx, targetDER, s.now, s.evidence)
}

// ValidatePast executes past certificate validation and time sliding. The proof
// set is minted by the library historical workflow, never caller timestamps.
func (s *HistoricalSession) ValidatePast(ctx context.Context, targetDER []byte, proofs *historicalproof.Set) (*PastCertificateResult, *PastCertificateReport, error) {
	if err := s.request(ctx); err != nil {
		return nil, &PastCertificateReport{cause: err}, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	return s.validatePast(ctx, targetDER, proofs)
}

// ValidatePastPath evaluates one prospective path for callers with additional
// signature-specific issuer-PoE guards, without silently selecting another path.
func (s *HistoricalSession) ValidatePastPath(ctx context.Context, path *HistoricalPath, proofs *historicalproof.Set) (*PastCertificateResult, *PastCertificateReport, error) {
	if err := s.request(ctx); err != nil {
		return nil, &PastCertificateReport{cause: err}, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	return s.validatePastPath(ctx, path, proofs)
}

func (s *HistoricalSession) request(ctx context.Context) error {
	if s == nil || s.verifier == nil || ctx == nil || s.now.IsZero() {
		return ErrPolicy
	}

	return ctx.Err()
}

func (s *HistoricalSession) validPath(path *HistoricalPath) error {
	if path == nil || path.session != s || len(path.chain) < 1 {
		return fmt.Errorf("%w: foreign or zero historical path", ErrPolicy)
	}

	return nil
}

// HistoricalPath is a candidate certificate path bound to its producing session.
// Only that session can assess or use it. Constructing a path grants no trust.
type HistoricalPath struct {
	// session binds this path to the policy and evidence operation that discovered
	// it.
	session *HistoricalSession
	// chain retains the exact prospective certificate path.
	chain []*x509.Certificate
	// fingerprint identifies the complete path by SHA-256.
	fingerprint [sha256.Size]byte
}

// ChainDER returns owned copies in target-to-anchor order.
func (p *HistoricalPath) ChainDER() [][]byte {
	if p == nil || p.session == nil {
		return nil
	}

	out := make([][]byte, len(p.chain))
	for index, certificate := range p.chain {
		out[index] = bytes.Clone(certificate.Raw)
	}

	return out
}

// HistoricalPathAssessment records structural and calendar checks for a candidate
// path. It establishes neither historical proof of existence nor document signature
// validity.
type HistoricalPathAssessment struct {
	// path is the prospective path checked by this assessment.
	path *HistoricalPath
	// reference is the calendar model's checking time, not a proven signing time.
	reference time.Time
	// model records the selected certificate validity model.
	model ValidityModel
}

// Model returns the selected calendar model.
func (a *HistoricalPathAssessment) Model() ValidityModel {
	if a == nil {
		return ""
	}

	return a.model
}

// ReferenceTime returns the model-specific path checking time, not a proven signing time.
func (a *HistoricalPathAssessment) ReferenceTime() time.Time {
	if a == nil {
		return time.Time{}
	}

	return a.reference
}

// Path returns the assessed immutable prospective path.
func (a *HistoricalPathAssessment) Path() *HistoricalPath {
	if a == nil {
		return nil
	}

	return a.path
}

// TimeTransition records the authenticated evidence or policy reason for a change
// to historical control time. Accessors return independent slices of transitions.
type TimeTransition struct {
	// CertificateSHA256 identifies the affected certificate by its hexadecimal SHA-256 DER
	// digest.
	CertificateSHA256 string
	// EvidenceSHA256 identifies the revocation evidence associated with the transition.
	EvidenceSHA256 string
	// Clause identifies the validation clause applied by this transition.
	Clause string
	// Reason describes why the control time changed.
	Reason string
	// Before is the control time before applying the transition.
	Before time.Time
	// After is the control time after applying the transition.
	After time.Time
}

// PastCertificateResult records successful past certificate validation under the
// selected policy. Document signature and past-signature validation remain separate.
type PastCertificateResult struct {
	// path is the exact path accepted by past certificate validation.
	path *HistoricalPath
	// at is the calculated historical control time.
	at time.Time
	// evidence retains the authenticated source assertions used in validation.
	evidence []*VerifiedEvidence
}

// Path returns the exact path used by past validation.
func (r *PastCertificateResult) Path() *HistoricalPath {
	if r == nil {
		return nil
	}

	return r.path
}

// ValidationTime returns the calculated historical control bound.
func (r *PastCertificateResult) ValidationTime() time.Time {
	if r == nil {
		return time.Time{}
	}

	return r.at
}

// Evidence returns immutable authenticated source assertions used by the process.
func (r *PastCertificateResult) Evidence() []*VerifiedEvidence {
	if r == nil {
		return nil
	}

	return append([]*VerifiedEvidence(nil), r.evidence...)
}

// PastCertificateReport contains past certificate diagnostics. Acceptance requires
// a non-nil result in addition to the report.
type PastCertificateReport struct {
	// subIndication is the detailed diagnostic code, or empty on success.
	subIndication string
	// transitions records the historical control-time changes.
	transitions []TimeTransition
	// cause retains the failure responsible for the diagnostic outcome.
	cause error
	// path is the prospective path considered by validation.
	path *HistoricalPath
	// evidence retains authenticated source diagnostics independently of
	// acceptance.
	evidence []*VerifiedEvidence
}

// SubIndication returns the precise diagnostic code, or empty on success.
func (r *PastCertificateReport) SubIndication() string {
	if r == nil {
		return ""
	}

	return r.subIndication
}

// Transitions returns an owned copy of internal time transitions.
func (r *PastCertificateReport) Transitions() []TimeTransition {
	if r == nil {
		return nil
	}

	return append([]TimeTransition(nil), r.transitions...)
}

// Cause retains the underlying policy, cryptographic or resource failure.
func (r *PastCertificateReport) Cause() error {
	if r == nil {
		return nil
	}

	return r.cause
}

// Path returns the last examined path for diagnostics, never a successful Result.
func (r *PastCertificateReport) Path() *HistoricalPath {
	if r == nil {
		return nil
	}

	return r.path
}

// Evidence returns authenticated diagnostics without granting past validation.
func (r *PastCertificateReport) Evidence() []*VerifiedEvidence {
	if r == nil {
		return nil
	}

	return append([]*VerifiedEvidence(nil), r.evidence...)
}

// NewHistoricalSession retains existing privately owned trust/usage policy and
// snapshots only the supplied historical options and operation evidence.
func (v *Verifier) NewHistoricalSession(ctx context.Context, options HistoricalOptions, now time.Time, input Evidence) (*HistoricalSession, error) {
	if err := v.validateRequest(ctx, now); err != nil {
		return nil, err
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	if err := v.validateEvidenceBounds(input); err != nil {
		return nil, errors.Join(ErrLimit, err)
	}

	if len(input.Sources) > maxSourceObservations {
		return nil, fmt.Errorf("%w: %w: historical source count", ErrPolicy, ErrLimit)
	}

	options, err := v.historicalOptions(options)
	if err != nil {
		return nil, err
	}

	owned, err := snapshotHistoricalEvidence(ctx, input)
	if err != nil {
		return nil, err
	}

	return &HistoricalSession{verifier: v, options: options, now: now.UTC(), evidence: owned, paths: make(map[[sha256.Size]byte][]*HistoricalPath), claims: make(map[[sha256.Size]byte][]historicalClaim)}, nil
}

func (v *Verifier) historicalOptions(options HistoricalOptions) (HistoricalOptions, error) {
	if options.Model == "" {
		options.Model = ShellModel
	}

	if options.Model != ShellModel && options.Model != ChainModel {
		return options, ErrPolicy
	}

	if options.MaxPaths == 0 {
		options.MaxPaths = defaultMaxHistoricalPaths
	}

	if options.MaxPaths < 1 || options.MaxPaths > maximumHistoricalPaths || len(options.CryptoConstraints) > maxCryptoConstraints || len(options.TrustAnchorSunsets) > maxTrustAnchorSunsets {
		return options, ErrPolicy
	}

	if options.RevocationFreshness != nil {
		value := *options.RevocationFreshness
		if value < 0 {
			return options, ErrPolicy
		}

		options.RevocationFreshness = &value
	}

	roots := make(map[string]struct{}, len(v.anchorCertificates))
	for _, raw := range v.anchorCertificates {
		digest := sha256.Sum256(raw)
		roots[hex.EncodeToString(digest[:])] = struct{}{}
	}

	options.TrustAnchorSunsets = maps.Clone(options.TrustAnchorSunsets)
	for root, at := range options.TrustAnchorSunsets {
		if _, allowed := roots[root]; !allowed || at.IsZero() {
			return options, ErrPolicy
		}

		options.TrustAnchorSunsets[root] = at.UTC()
	}

	options.CryptoConstraints = append([]CryptoConstraint(nil), options.CryptoConstraints...)
	for _, rule := range options.CryptoConstraints {
		if !validHistoricalCryptoRule(rule) {
			return options, ErrPolicy
		}
	}

	return options, nil
}

func validHistoricalCryptoRule(rule CryptoConstraint) bool {
	if rule.ReliableUntil.IsZero() {
		return false
	}

	selectors := 0

	if rule.SignatureAlgorithm != x509.UnknownSignatureAlgorithm {
		if !allowedSignature(rule.SignatureAlgorithm) {
			return false
		}

		selectors++
	}

	if rule.Hash != 0 {
		if !rule.Hash.Available() {
			return false
		}

		selectors++
	}

	if rule.PublicKeyAlgorithm != x509.UnknownPublicKeyAlgorithm {
		if rule.PublicKeyAlgorithm != x509.RSA && rule.PublicKeyAlgorithm != x509.ECDSA && rule.PublicKeyAlgorithm != x509.Ed25519 {
			return false
		}

		if rule.MinimumKeyBits < 1 || rule.MinimumKeyBits > maxConstraintKeyBits {
			return false
		}

		selectors++
	} else if rule.MinimumKeyBits != 0 {
		return false
	}

	return selectors == 1
}

func snapshotHistoricalEvidence(ctx context.Context, input Evidence) (Evidence, error) {
	owned := Evidence{Sources: append([]*evidence.Observation(nil), input.Sources...)}
	for _, group := range []struct {
		raw [][]byte
		dst *[][]byte
	}{{input.Intermediates, &owned.Intermediates}, {input.CRLs, &owned.CRLs}, {input.OCSPResponses, &owned.OCSPResponses}} {
		for _, raw := range group.raw {
			if err := ctx.Err(); err != nil {
				return Evidence{}, err
			}

			*group.dst = append(*group.dst, bytes.Clone(raw))
		}
	}

	return owned, nil
}
