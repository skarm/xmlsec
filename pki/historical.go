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

// ValidityModel selects the historical certificate calendar model.
type ValidityModel string

const (
	// ShellModel requires a common certificate validity interval.
	ShellModel ValidityModel = "shell"
	// ChainModel checks CA validity at the certificate generation times defined
	// by EN319102-1 and its selected Common PKI chain-model dependency.
	ChainModel ValidityModel = "chain"
)

// CryptoConstraint bounds when one selected algorithm or key-size family was
// reliable. Exactly one selector is set: SignatureAlgorithm, Hash, or
// PublicKeyAlgorithm with MinimumKeyBits. Key-size rules concern sizes below
// that minimum. A rule never enables unsupported cryptography or bypasses FIPS.
type CryptoConstraint struct {
	SignatureAlgorithm x509.SignatureAlgorithm
	Hash               crypto.Hash
	PublicKeyAlgorithm x509.PublicKeyAlgorithm
	MinimumKeyBits     int
	ReliableUntil      time.Time
}

// HistoricalOptions selects bounded historical policy, separate from current
// Verify semantics. All maps, slices and pointed values are snapshotted.
type HistoricalOptions struct {
	Model              ValidityModel
	MaxPaths           int
	TrustAnchorSunsets map[string]time.Time
	CryptoConstraints  []CryptoConstraint
	// RevocationFreshness nil derives nextUpdate-thisUpdate. Missing nextUpdate
	// then fails freshness; explicit zero remains a distinct configured value.
	RevocationFreshness *time.Duration
}

// HistoricalConfig supplies explicit trust and historical policy.
type HistoricalConfig struct {
	PKI Config
	HistoricalOptions
}

// HistoricalSession owns one bounded offline operation and its present time.
// It separates source authentication from freshness, PoE and past acceptance.
// Its methods serialize operation-local caches; returned objects are immutable.
type HistoricalSession struct {
	mu                    sync.Mutex
	verifier              *Verifier
	options               HistoricalOptions
	now                   time.Time
	evidence              Evidence
	paths                 map[[32]byte][]*HistoricalPath
	certificates          map[[32]byte]*x509.Certificate
	targetBytes, pathWork int
	signatureWork         int
	sourcesReady          bool
	lists                 []*parsedCRL
	responses             []parsedOCSP
	claims                map[[32]byte][]historicalClaim
}

// HistoricalPath is a prospective exact certificate path, not a trust Result.
// Only its producing session can assess or use it.
type HistoricalPath struct {
	session     *HistoricalSession
	chain       []*x509.Certificate
	fingerprint [32]byte
}

// HistoricalPathAssessment records model-specific structural/path checks. It
// neither grants historical PoE nor asserts a document signature is valid.
type HistoricalPathAssessment struct {
	path      *HistoricalPath
	reference time.Time
	model     ValidityModel
}

// TimeTransition records one authenticated source/policy reason for changing
// the internal historical control time. Accessor slices are independent.
type TimeTransition struct {
	CertificateSHA256 string
	EvidenceSHA256    string
	Clause            string
	Reason            string
	Before            time.Time
	After             time.Time
}

// PastCertificateResult means the selected past certificate process passed.
// It does not decide a document signature or replace past-signature validation.
type PastCertificateResult struct {
	path     *HistoricalPath
	at       time.Time
	evidence []*VerifiedEvidence
}

// PastCertificateReport is diagnostic. Only a nonnil result denotes success.
type PastCertificateReport struct {
	subIndication string
	transitions   []TimeTransition
	cause         error
	path          *HistoricalPath
	evidence      []*VerifiedEvidence
}

// NewHistoricalSession snapshots an explicit trust configuration and operation.
func NewHistoricalSession(ctx context.Context, config HistoricalConfig, now time.Time, input Evidence) (*HistoricalSession, error) {
	verifier, err := NewVerifier(config.PKI)
	if err != nil {
		return nil, err
	}

	return verifier.NewHistoricalSession(ctx, config.HistoricalOptions, now, input)
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

	if len(input.Sources) > 1024 {
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

	return &HistoricalSession{verifier: v, options: options, now: now.UTC(), evidence: owned, paths: make(map[[32]byte][]*HistoricalPath), claims: make(map[[32]byte][]historicalClaim)}, nil
}

func (v *Verifier) historicalOptions(options HistoricalOptions) (HistoricalOptions, error) {
	if options.Model == "" {
		options.Model = ShellModel
	}

	if options.Model != ShellModel && options.Model != ChainModel {
		return options, ErrPolicy
	}

	if options.MaxPaths == 0 {
		options.MaxPaths = 16
	}

	if options.MaxPaths < 1 || options.MaxPaths > 256 || len(options.CryptoConstraints) > 128 || len(options.TrustAnchorSunsets) > 64 {
		return options, ErrPolicy
	}

	if options.RevocationFreshness != nil {
		value := *options.RevocationFreshness
		if value < 0 {
			return options, ErrPolicy
		}

		options.RevocationFreshness = &value
	}

	roots := make(map[string]bool, len(v.anchorCertificates))
	for _, raw := range v.anchorCertificates {
		digest := sha256.Sum256(raw)
		roots[hex.EncodeToString(digest[:])] = true
	}

	options.TrustAnchorSunsets = maps.Clone(options.TrustAnchorSunsets)
	for root, at := range options.TrustAnchorSunsets {
		if !roots[root] || at.IsZero() {
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

		if rule.MinimumKeyBits < 1 || rule.MinimumKeyBits > 16385 {
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
