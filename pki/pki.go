package pki

import (
	"bytes"
	"context"
	"crypto"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"time"
)

var (
	// ErrPolicy reports PKI policy violation.
	ErrPolicy = errors.New("PKI policy violation")
	// ErrCertificate reports invalid or untrusted certificate.
	ErrCertificate = errors.New("invalid or untrusted certificate")
	// ErrEvidence reports invalid revocation evidence.
	ErrEvidence = errors.New("invalid revocation evidence")
	// ErrUnavailable reports sufficient fresh revocation evidence unavailable.
	ErrUnavailable = errors.New("sufficient fresh revocation evidence unavailable")
	// ErrRevoked reports certificate revoked.
	ErrRevoked = errors.New("certificate revoked")
	// ErrUnsupported reports unsupported revocation feature.
	ErrUnsupported = errors.New("unsupported revocation feature")
)

// Status records the outcome of a trust or revocation check.
type Status string

const (
	// NotChecked indicates that a check was not performed.
	NotChecked Status = "not-checked"
	// Valid indicates a successful check.
	Valid Status = "valid"
	// Invalid indicates invalid data or a failed check.
	Invalid Status = "invalid"
	// Indeterminate indicates that validation cannot establish the required result.
	Indeterminate Status = "indeterminate"
)

// RevocationMode selects the required offline revocation evidence. NoRevocation does not
// check revocation.
type RevocationMode string

const (
	// NoRevocation does not check revocation; callers must choose this deliberately.
	NoRevocation RevocationMode = ""
	// RequireCRL requires authenticated complete offline CRLs.
	RequireCRL RevocationMode = "require-crl"
	// RequireOCSP requires authenticated offline OCSP responses.
	RequireOCSP RevocationMode = "require-ocsp"
)

// Config sets explicit trust anchors, required usages and offline revocation policy.
// System roots are never used.
type Config struct {
	// Roots supplies required DER trust anchors. System roots are never used.
	Roots [][]byte
	// Intermediates contains untrusted DER certificates used only to build paths to explicit
	// roots.
	Intermediates [][]byte
	// KeyUsages selects acceptable extended key usages. Empty means ExtKeyUsageAny.
	// Applications requiring an EKU, such as timeStamping or codeSigning, must configure
	// it.
	KeyUsages []x509.ExtKeyUsage
	// RequiredKeyUsage selects bits required on the leaf certificate. Zero defaults to
	// DigitalSignature.
	RequiredKeyUsage x509.KeyUsage
	// AllowCALeaf explicitly permits a CA certificate as the leaf.
	AllowCALeaf bool
	// Revocation selects required offline revocation checks.
	Revocation RevocationMode
	// MaxChainDepth bounds certificate chain depth; default 10, maximum 32.
	MaxChainDepth int
	// MaxEvidenceBytes bounds supplied revocation evidence bytes; default 8 MiB, maximum
	// 64 MiB.
	MaxEvidenceBytes int
	// MaxCRLs bounds supplied CRLs; default 32, maximum 256.
	MaxCRLs int
	// MaxOCSPResponses bounds supplied OCSP responses; default 32, maximum 256.
	MaxOCSPResponses int
	// OCSPMaxAge bounds offline OCSP evidence age; zero selects 24 hours,
	// with a 30-day maximum.
	OCSPMaxAge time.Duration
	// OCSPClockSkew permits OCSP time tolerance; zero permits none,
	// with a ten-minute maximum.
	OCSPClockSkew time.Duration
}

// Evidence supplies untrusted DER intermediates and offline revocation evidence for an
// operation.
type Evidence struct {
	// Intermediates contains untrusted DER certificates used only to build paths to explicit
	// roots.
	Intermediates [][]byte
	// CRLs contains untrusted complete DER CRLs to authenticate and check.
	CRLs [][]byte
	// OCSPResponses contains untrusted DER OCSP responses to authenticate and check.
	OCSPResponses [][]byte
}

// Verifier holds an immutable PKIX and offline revocation policy and supports concurrent
// verification.
type Verifier struct {
	roots, intermediates        *x509.CertPool
	usages                      []x509.ExtKeyUsage
	required                    x509.KeyUsage
	allowCA                     bool
	revocation                  RevocationMode
	maxDepth, maxBytes, maxCRLs int
	maxOCSP                     int
	ocspOptions                 OCSPOptions
}

// NewVerifier validates and snapshots explicit trust and revocation policy for concurrent use.
func NewVerifier(c Config) (*Verifier, error) {
	if err := normalizeVerifierPolicy(&c); err != nil {
		return nil, err
	}

	opts, err := normalizeOCSP(OCSPOptions{MaxAge: c.OCSPMaxAge, ClockSkew: c.OCSPClockSkew})
	if err != nil {
		return nil, err
	}

	usages := append([]x509.ExtKeyUsage(nil), c.KeyUsages...)
	if len(usages) == 0 {
		usages = []x509.ExtKeyUsage{x509.ExtKeyUsageAny}
	}

	if len(usages) > 32 {
		return nil, ErrPolicy
	}

	v := &Verifier{
		roots:         x509.NewCertPool(),
		intermediates: x509.NewCertPool(),
		usages:        usages,
		required:      c.RequiredKeyUsage,
		allowCA:       c.AllowCALeaf,
		revocation:    c.Revocation,
		maxDepth:      c.MaxChainDepth,
		maxBytes:      c.MaxEvidenceBytes,
		maxCRLs:       c.MaxCRLs,
		maxOCSP:       c.MaxOCSPResponses,
		ocspOptions:   opts,
	}

	if err := v.snapshotCertificates(c.Roots, c.Intermediates); err != nil {
		return nil, err
	}

	return v, nil
}

// normalizeVerifierPolicy validates policy fields in their public error order,
// filling defaults only in the caller's local configuration snapshot.
func normalizeVerifierPolicy(c *Config) error {
	if len(c.Roots) < 1 || len(c.Roots) > 64 || len(c.Intermediates) > 64 {
		return fmt.Errorf("%w: explicit bounded root/intermediate sets required", ErrPolicy)
	}

	if c.Revocation != NoRevocation && c.Revocation != RequireCRL && c.Revocation != RequireOCSP {
		return fmt.Errorf("%w: revocation mode", ErrPolicy)
	}

	if c.RequiredKeyUsage == 0 {
		c.RequiredKeyUsage = x509.KeyUsageDigitalSignature
	}

	if c.RequiredKeyUsage < 0 || c.RequiredKeyUsage & ^x509.KeyUsage(511) != 0 {
		return fmt.Errorf("%w: key usage", ErrPolicy)
	}

	if c.MaxChainDepth == 0 {
		c.MaxChainDepth = 10
	}

	if c.MaxEvidenceBytes == 0 {
		c.MaxEvidenceBytes = 8 << 20
	}

	if c.MaxCRLs == 0 {
		c.MaxCRLs = 32
	}

	if c.MaxChainDepth < 2 || c.MaxChainDepth > 32 || c.MaxEvidenceBytes < 1 || c.MaxEvidenceBytes > 64<<20 || c.MaxCRLs < 1 || c.MaxCRLs > 256 {
		return fmt.Errorf("%w: limits", ErrPolicy)
	}

	if c.MaxOCSPResponses == 0 {
		c.MaxOCSPResponses = 32
	}

	if c.MaxOCSPResponses < 1 || c.MaxOCSPResponses > 256 {
		return ErrPolicy
	}

	return nil
}

// Verify requires an explicit time. A caller-chosen past time alone is NOT a
// proof that a signature existed then. Certificates are snapshotted; revocation
// evidence is borrowed during the call and must not be modified concurrently.
// Outputs expose no mutable verifier state. x509 path building has no context API, so
// cancellation is checked around that bounded standard-library operation.
func (v *Verifier) Verify(ctx context.Context, leafDER []byte, at time.Time, e Evidence) (result *Result, report Report, err error) {
	report = Report{Chain: NotChecked, Revocation: NotChecked, VerificationTime: at}

	defer func() {
		if err != nil {
			result = nil
			report.Error = err.Error()
		}
	}()

	if err = v.validateRequest(ctx, at); err != nil {
		return nil, report, err
	}

	if err = ctx.Err(); err != nil {
		return nil, report, err
	}

	if err = v.validateEvidenceBounds(e); err != nil {
		return nil, report, err
	}

	leaf, err := v.validateLeaf(leafDER)
	if err != nil {
		report.Chain = Invalid
		return nil, report, err
	}

	pool, err := v.evidenceIntermediatePool(ctx, e.Intermediates)
	if err != nil {
		return nil, report, err
	}

	chains, err := leaf.Verify(x509.VerifyOptions{Roots: v.roots, Intermediates: pool, CurrentTime: at, KeyUsages: append([]x509.ExtKeyUsage(nil), v.usages...), MaxConstraintComparisions: 100000})
	if err != nil {
		report.Chain = Invalid
		return nil, report, fmt.Errorf("%w: %w", ErrCertificate, err)
	}

	if err = ctx.Err(); err != nil {
		return nil, report, err
	}

	report.Chain = Valid

	var lists []*x509.RevocationList
	if v.revocation == RequireCRL {
		lists, err = parseCRLs(ctx, e.CRLs)
		if err != nil {
			report.Revocation = Indeterminate
			return nil, report, err
		}
	}

	selected, chainErr := v.selectVerifiedChain(ctx, chains, lists, at, e)
	if selected == nil {
		if chainErr == nil {
			chainErr = ErrUnavailable
		}

		if errors.Is(chainErr, ErrPolicy) {
			report.Chain = Invalid
			report.Revocation = NotChecked

			return nil, report, chainErr
		}

		if errors.Is(chainErr, ErrRevoked) {
			report.Revocation = Invalid
		} else {
			report.Revocation = Indeterminate
		}

		return nil, report, chainErr
	}

	if err = ctx.Err(); err != nil {
		return nil, report, err
	}

	if v.revocation == RequireCRL || v.revocation == RequireOCSP {
		report.Revocation = Valid
	}

	report.ChainLength = len(selected)

	// Every certificate was parsed from privately owned storage. Results may
	// share that immutable DER; application-facing accessors still copy it.
	result = &Result{at: at, spki: leaf.RawSubjectPublicKeyInfo, revocation: report.Revocation}
	for _, cert := range selected {
		result.chain = append(result.chain, cert.Raw)
	}

	return result, report, nil
}

// snapshotCertificates parses owned DER copies, charging both configured pools
// to one byte limit. Root constraints precede each anchor's public-key policy.
func (v *Verifier) snapshotCertificates(roots, intermediates [][]byte) error {
	configuredBytes := 0

	for _, group := range []struct {
		ders [][]byte
		pool *x509.CertPool
		root bool
	}{{roots, v.roots, true}, {intermediates, v.intermediates, false}} {
		for _, der := range group.ders {
			if len(der) > v.maxBytes-configuredBytes {
				return fmt.Errorf("%w: configured certificate bytes", ErrPolicy)
			}

			configuredBytes += len(der)

			cert, err := parseCertificate(der)
			if err != nil {
				return err
			}

			if group.root && (!cert.IsCA || !cert.BasicConstraintsValid || cert.KeyUsage&x509.KeyUsageCertSign == 0) {
				return fmt.Errorf("%w: trust anchor must be a CA", ErrPolicy)
			}

			if err := allowedPublicKey(cert.PublicKey); err != nil {
				return err
			}

			group.pool.AddCert(cert)
		}
	}

	return nil
}

func (v *Verifier) validateRequest(ctx context.Context, at time.Time) error {
	if v == nil || v.roots == nil || v.intermediates == nil || ctx == nil || at.IsZero() {
		return fmt.Errorf("%w: verifier, context and explicit time required", ErrPolicy)
	}

	return nil
}

func (v *Verifier) validateEvidenceBounds(e Evidence) error {
	if len(e.Intermediates) > 64 || len(e.CRLs) > v.maxCRLs || len(e.OCSPResponses) > v.maxOCSP {
		return fmt.Errorf("%w: evidence count", ErrPolicy)
	}

	remaining := v.maxBytes

	for _, group := range [][][]byte{e.Intermediates, e.CRLs, e.OCSPResponses} {
		for _, der := range group {
			if len(der) > remaining {
				return fmt.Errorf("%w: evidence size", ErrPolicy)
			}

			remaining -= len(der)
		}
	}

	return nil
}

func (v *Verifier) validateLeaf(der []byte) (*x509.Certificate, error) {
	leaf, err := parseCertificate(der)
	if err != nil {
		return nil, err
	}

	if err := allowedPublicKey(leaf.PublicKey); err != nil {
		return nil, err
	}

	if !allowedSignature(leaf.SignatureAlgorithm) {
		return nil, fmt.Errorf("%w: leaf signature algorithm", ErrPolicy)
	}

	if (!v.allowCA && leaf.IsCA) || leaf.KeyUsage&v.required != v.required {
		return nil, fmt.Errorf("%w: signing certificate usage", ErrCertificate)
	}

	return leaf, nil
}

func (v *Verifier) evidenceIntermediatePool(ctx context.Context, ders [][]byte) (*x509.CertPool, error) {
	if len(ders) == 0 {
		return v.intermediates, nil
	}

	pool := v.intermediates.Clone()

	for _, der := range ders {
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		cert, err := parseCertificate(der)
		if err != nil {
			return nil, err
		}

		if err := allowedPublicKey(cert.PublicKey); err != nil {
			return nil, err
		}

		pool.AddCert(cert)
	}

	return pool, nil
}

// selectVerifiedChain keeps x509's candidate order and the final rejected
// candidate's diagnostic, accepting the first chain that passes every policy.
func (v *Verifier) selectVerifiedChain(ctx context.Context, chains [][]*x509.Certificate, lists []*x509.RevocationList, at time.Time, e Evidence) ([]*x509.Certificate, error) {
	var chainErr error

	ocsp := ocspEvidence{raw: e.OCSPResponses, options: v.ocspOptions}
	ocsp.options.ResponderCRLs = e.CRLs

	for _, chain := range chains {
		chainErr = v.validateChainPolicy(chain)
		if chainErr != nil {
			continue
		}

		if v.revocation == RequireCRL {
			chainErr = checkChainCRLs(ctx, chain, lists, at)
			if chainErr != nil {
				continue
			}
		}

		if v.revocation == RequireOCSP {
			chainErr = ocsp.checkChain(ctx, chain, at)
			if chainErr != nil {
				continue
			}
		}

		return chain, nil
	}

	return nil, chainErr
}

func (v *Verifier) validateChainPolicy(chain []*x509.Certificate) error {
	for i, cert := range chain {
		if err := allowedPublicKey(cert.PublicKey); err != nil {
			return err
		}

		if i+1 < len(chain) && !allowedSignature(cert.SignatureAlgorithm) {
			return fmt.Errorf("%w: chain signature algorithm", ErrPolicy)
		}
	}

	if len(chain) > v.maxDepth {
		return fmt.Errorf("%w: chain depth", ErrPolicy)
	}

	return nil
}

func parseCertificate(der []byte) (*x509.Certificate, error) {
	if len(der) < 1 || len(der) > 1<<20 {
		return nil, fmt.Errorf("%w: certificate size", ErrCertificate)
	}

	return parseBorrowedCertificate(bytes.Clone(der))
}

// Report records diagnostic chain and revocation outcomes; successful verification
// additionally returns a Result.
type Report struct {
	Chain Status `json:"chain"`
	// Revocation records the evidence-check outcome; NoRevocation leaves it NotChecked.
	Revocation       Status    `json:"revocation"`
	VerificationTime time.Time `json:"verification_time"`
	ChainLength      int       `json:"chain_length,omitempty"`
	Error            string    `json:"error,omitempty"`
}

// Result means the configured policy passed, not that every possible trust
// policy or AdES historical-validation requirement has passed.
type Result struct {
	chain      [][]byte
	spki       []byte
	at         time.Time
	revocation Status
}

// ChainDER returns owned copies of the verified certificate chain, starting with the leaf.
func (r *Result) ChainDER() [][]byte {
	if r == nil {
		return nil
	}

	out := make([][]byte, len(r.chain))
	for i, b := range r.chain {
		out[i] = bytes.Clone(b)
	}

	return out
}

// PublicKey returns a newly parsed public key owned by the caller.
func (r *Result) PublicKey() (crypto.PublicKey, error) {
	if r == nil {
		return nil, ErrCertificate
	}

	return x509.ParsePKIXPublicKey(bytes.Clone(r.spki))
}

// VerificationTime returns the explicit time used for verification.
func (r *Result) VerificationTime() time.Time {
	if r == nil {
		return time.Time{}
	}

	return r.at
}

// RevocationStatus returns the verified revocation outcome.
func (r *Result) RevocationStatus() Status {
	if r == nil {
		return NotChecked
	}

	return r.revocation
}

// KeyPin pins only SubjectPublicKeyInfo. MatchCertificate intentionally does NOT
// validate certificate validity dates, CA chains, revocation, or subject names.
// This is a distinct trust primitive suitable for already-trusted metadata keys.
type KeyPin struct {
	spki        []byte
	fingerprint [32]byte
}

// NewKeyPin snapshots a public key as an SPKI pin. Matching a pin does not establish PKIX
// certificate trust.
func NewKeyPin(public crypto.PublicKey) (*KeyPin, error) {
	// Marshal may reject nil/unsupported types; require round-trip parse as well.
	der, err := safeMarshalPublic(public)
	if err != nil {
		return nil, err
	}

	if _, err = x509.ParsePKIXPublicKey(der); err != nil {
		return nil, err
	}

	return &KeyPin{spki: der, fingerprint: sha256.Sum256(der)}, nil
}

// FingerprintSHA256 returns the hexadecimal SHA-256 fingerprint of the pinned SPKI.
func (p *KeyPin) FingerprintSHA256() string {
	if p == nil {
		return ""
	}

	return hex.EncodeToString(p.fingerprint[:])
}

// MatchCertificate matches the certificate SPKI to the pin; it does not check PKIX trust,
// validity or revocation.
func (p *KeyPin) MatchCertificate(der []byte) error {
	if p == nil {
		return ErrPolicy
	}

	c, err := parseBorrowedCertificate(der)
	if err != nil {
		return err
	}

	if subtle.ConstantTimeCompare(p.spki, c.RawSubjectPublicKeyInfo) != 1 {
		return fmt.Errorf("%w: public key does not match pin", ErrCertificate)
	}

	return nil
}

// parseBorrowedCertificate is for temporary use or DER that is already owned.
func parseBorrowedCertificate(der []byte) (*x509.Certificate, error) {
	if len(der) < 1 || len(der) > 1<<20 {
		return nil, fmt.Errorf("%w: certificate size", ErrCertificate)
	}

	c, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrCertificate, err)
	}

	return c, nil
}
