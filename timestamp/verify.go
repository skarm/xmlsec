package timestamp

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"io"
	"math/big"
	"slices"
	"time"

	"github.com/skarm/xmlsec/cms"
	"github.com/skarm/xmlsec/internal/der"
	"github.com/skarm/xmlsec/internal/nilcheck"
	"github.com/skarm/xmlsec/internal/x509cert"
	"github.com/skarm/xmlsec/internal/x509name"
	"github.com/skarm/xmlsec/pki"
)

// Config supplies TSA trust and token validation policy. Construction copies its
// configuration. Embedded certificates are untrusted path candidates and cannot
// expand PKI.Roots. PKI must require revocation checking unless
// AllowUncheckedRevocation explicitly permits leaving it unchecked.
type Config struct {
	// PKI sets explicit TSA trust anchors and offline revocation policy.
	// Verification requires the timeStamping EKU and a non-CA signing leaf.
	PKI pki.Config
	// AllowedPolicies is a required allowlist of 1 to 64 distinct TSA policy OIDs.
	AllowedPolicies []asn1.ObjectIdentifier
	// Certificates supplies untrusted DER lookup and path-building candidates.
	// At most 32 certificates are accepted; they do not become trust anchors.
	Certificates [][]byte
	// AllowUncheckedRevocation permits PKI.NoRevocation. False requires offline
	// revocation checks to be configured.
	AllowUncheckedRevocation bool
	// AllowLegacyESSCertID permits the SHA-1 ESSCertID certificate identifier.
	AllowLegacyESSCertID bool
	// ClockSkew permits time tolerance; zero permits none, and the maximum is ten minutes.
	ClockSkew time.Duration
	// MaxAge bounds token age; zero imposes no age limit.
	MaxAge time.Duration
	// MaxAccuracy bounds a token's asserted accuracy; zero imposes no upper bound.
	// Whether accuracy must be present is controlled separately by RequireAccuracy.
	MaxAccuracy time.Duration
	// MaxBytes bounds token DER; zero selects 16 MiB, also the maximum.
	MaxBytes int
	// RequireAccuracy requires a token accuracy assertion.
	RequireAccuracy bool
}

// Verifier checks RFC 3161 tokens against explicit TSA policy, certificate trust and
// offline revocation evidence.
type Verifier struct {
	trust           *pki.Verifier
	policies        map[string]struct{}
	certificates    [][]byte
	skew            time.Duration
	maxAge          time.Duration
	maxAccuracy     time.Duration
	maxBytes        int
	allowUnchecked  bool
	legacy          bool
	requireAccuracy bool
}

// NewVerifier validates and snapshots explicit TSA policies, trust anchors and evidence
// limits.
func NewVerifier(c Config) (*Verifier, error) {
	if len(c.AllowedPolicies) < 1 || len(c.AllowedPolicies) > 64 || len(c.Certificates) > 32 || c.ClockSkew < 0 || c.ClockSkew > 10*time.Minute || c.MaxAge < 0 || c.MaxAccuracy < 0 || c.MaxAccuracy > 24*time.Hour {
		return nil, ErrPolicy
	}

	if c.MaxBytes == 0 {
		c.MaxBytes = 16 << 20
	}

	if c.MaxBytes < 1 || c.MaxBytes > 16<<20 {
		return nil, ErrPolicy
	}

	if c.PKI.Revocation == pki.NoRevocation && !c.AllowUncheckedRevocation {
		return nil, fmt.Errorf("%w: TSA revocation checking required", ErrPolicy)
	}

	c.PKI.KeyUsages = []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping}
	c.PKI.RequiredKeyUsage = x509.KeyUsageDigitalSignature
	c.PKI.AllowCALeaf = false

	trust, e := pki.NewVerifier(c.PKI)
	if e != nil {
		return nil, e
	}

	v := &Verifier{trust: trust, policies: map[string]struct{}{}, allowUnchecked: c.AllowUncheckedRevocation, legacy: c.AllowLegacyESSCertID, skew: c.ClockSkew, maxAge: c.MaxAge, maxAccuracy: c.MaxAccuracy, requireAccuracy: c.RequireAccuracy, maxBytes: c.MaxBytes}
	for _, o := range c.AllowedPolicies {
		if len(der.OID(o)) == 0 {
			return nil, ErrPolicy
		}

		if _, exists := v.policies[o.String()]; exists {
			return nil, ErrPolicy
		}

		v.policies[o.String()] = struct{}{}
	}

	total := 0
	for _, b := range c.Certificates {
		total += len(b)
		if len(b) > 1<<20 || total > c.MaxBytes {
			return nil, ErrPolicy
		}

		if _, e := x509cert.ParseDefault(b); e != nil {
			return nil, ErrPolicy
		}

		v.certificates = append(v.certificates, bytes.Clone(b))
	}

	return v, nil
}

// VerifyToken checks PKIX at the explicit validation time, never silently at
// the token's claimed genTime. Historical LTA validation is a separate process.
func (v *Verifier) VerifyToken(ctx context.Context, raw []byte, want Expectation, at time.Time, evidence pki.Evidence) (*Result, error) {
	if v == nil || v.trust == nil || ctx == nil || at.IsZero() || !validImprint(want.Imprint) || len(raw) > v.maxBytes {
		return nil, ErrPolicy
	}

	if e := ctx.Err(); e != nil {
		return nil, e
	}

	if want.Nonce != nil && (want.Nonce.Sign() <= 0 || want.Nonce.BitLen() > 256) {
		return nil, ErrPolicy
	}

	token, e := parseTokenReader(ctx, bytes.NewReader(raw), v.maxBytes)
	if e != nil {
		return nil, e
	}

	return v.Verify(ctx, token, want, at, evidence)
}

// Verify authenticates a previously parsed token without copying or reparsing
// its DER. It enforces this verifier's byte budget, bindings and trust policy.
func (v *Verifier) Verify(ctx context.Context, token *Token, want Expectation, at time.Time, evidence pki.Evidence) (*Result, error) {
	result, _, err := v.verify(ctx, token, want, at, evidence, nil)
	return result, err
}

// VerifyResponse authenticates and validates a solicited response and its signed assertion
// under explicit expectations.
func (v *Verifier) VerifyResponse(ctx context.Context, raw []byte, q *Request, at time.Time, evidence pki.Evidence) (*Result, error) {
	return v.VerifyResponseReader(ctx, bytes.NewReader(raw), q, at, evidence)
}

// VerifyResponseReader verifies a DER response read from src. Length framing
// allocates one bounded response buffer; the response/token models remain in
// memory. It leaves src open and returns no result on any processing error.
func (v *Verifier) VerifyResponseReader(ctx context.Context, src io.Reader, q *Request, at time.Time, evidence pki.Evidence) (*Result, error) {
	if v == nil || v.trust == nil || ctx == nil || q == nil || len(q.raw) == 0 || at.IsZero() || nilcheck.IsNil(src) {
		return nil, ErrPolicy
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	value, e := der.ReadSequence(ctx, src, v.maxBytes)
	if e != nil {
		if errors.Is(e, der.ErrLimit) {
			return nil, fmt.Errorf("%w: %w", ErrPolicy, e)
		}

		return nil, fmt.Errorf("%w: %w", ErrFormat, e)
	}

	r, e := parseResponseValue(ctx, value, false)
	if e != nil {
		return nil, e
	}

	token, e := parseTokenReader(ctx, bytes.NewReader(r.token), v.maxBytes)
	if e != nil {
		return nil, e
	}

	out, certs, e := v.verify(ctx, token, Expectation{q.imprint, q.nonce, q.policy}, at, evidence, value.FullBytes)
	if e != nil {
		return nil, e
	}

	if !q.certReq && len(certs) > 0 {
		return nil, fmt.Errorf("%w: certReq=false but certs present", ErrBinding)
	}

	if q.certReq {
		found := false

		for _, c := range certs {
			if bytes.Equal(c, out.tsa) {
				found = true
			}
		}

		if !found {
			return nil, fmt.Errorf("%w: requested TSA cert missing", ErrBinding)
		}
	}

	return out, nil
}

func (v *Verifier) verify(ctx context.Context, token *Token, want Expectation, at time.Time, evidence pki.Evidence, response []byte) (*Result, [][]byte, error) {
	if v == nil || v.trust == nil || ctx == nil || token == nil || token.signed == nil || token.Size() == 0 || token.Size() > v.maxBytes || at.IsZero() || !validImprint(want.Imprint) {
		return nil, nil, ErrPolicy
	}

	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}

	if want.Nonce != nil && (want.Nonce.Sign() <= 0 || want.Nonce.BitLen() > 256) {
		return nil, nil, ErrPolicy
	}

	evidence, sources, err := v.timestampSources(ctx, token, response, evidence)
	if err != nil {
		return nil, nil, err
	}

	s := token.signed
	certificates := s.Certificates()

	chosen, e := v.selectTSASigner(s, certificates)
	if e != nil {
		return nil, nil, e
	}

	cert, e := x509cert.ParseDefault(chosen)
	if e != nil {
		return nil, nil, ErrTrust
	}

	info := token.info

	if e := v.validateTokenInfo(ctx, info, want, cert, at); e != nil {
		return nil, nil, e
	}

	ev := tokenEvidence(evidence, certificates, chosen)

	verified, e := s.VerifyWithTrust(ctx, [][]byte{chosen}, cms.VerifyOptions{ExpectedContentType: tstOID(), RequireCertificateBinding: true, AllowLegacyESSCertID: v.legacy, DiscardContent: true}, cms.TrustOptions{Verifier: v.trust, VerificationTime: at, Evidence: ev})
	if e != nil {
		return nil, nil, fmt.Errorf("%w: %w", ErrTrust, e)
	}

	trust := verified.Signers()[0].Trust()
	if !v.allowUnchecked && trust.RevocationStatus() != pki.Valid {
		return nil, nil, ErrTrust
	}

	if e = ctx.Err(); e != nil {
		return nil, nil, e
	}

	assertion, err := verifiedAssertion(ctx, token, info, chosen, trust)
	if err != nil {
		return nil, nil, err
	}

	assertion.sources = sources

	return &Result{token: token, info: info, tsa: chosen, trust: trust, assertion: assertion}, certificates, nil
}

func (v *Verifier) validateTokenInfo(ctx context.Context, info Info, want Expectation, cert *x509.Certificate, at time.Time) error {
	if err := validateTimestampBinding(info, want); err != nil {
		return err
	}

	if _, exists := v.policies[info.policy.String()]; !exists {
		return fmt.Errorf("%w: policy OID", ErrPolicy)
	}

	if err := v.validateTimestampTime(info, at); err != nil {
		return err
	}

	if v.requireAccuracy && !info.hasAccuracy || v.maxAccuracy > 0 && info.hasAccuracy && info.accuracy > v.maxAccuracy {
		return ErrPolicy
	}

	if e := checkTSACertificate(cert, info.at); e != nil {
		return e
	}

	if e := matchTSAName(ctx, info.tsa, cert); e != nil {
		return e
	}

	return nil
}

func (v *Verifier) selectTSASigner(s *cms.SignedData, certificates [][]byte) ([]byte, error) {
	var chosen []byte

	for _, certificate := range append(certificates, v.certificates...) {
		if !s.MatchesSigner(0, certificate) {
			continue
		}

		if chosen != nil && !bytes.Equal(chosen, certificate) {
			return nil, fmt.Errorf("%w: ambiguous TSA signer", ErrTrust)
		}

		chosen = certificate
	}

	if chosen == nil {
		return nil, ErrTrust
	}

	return chosen, nil
}

func (v *Verifier) validateTimestampTime(info Info, at time.Time) error {
	if info.at.After(at.Add(v.skew)) || v.maxAge > 0 && info.at.Before(at.Add(-v.maxAge).Add(-v.skew)) {
		return fmt.Errorf("%w: timestamp age/future time", ErrPolicy)
	}

	return nil
}

func tokenEvidence(evidence pki.Evidence, certificates [][]byte, chosen []byte) pki.Evidence {
	ev := evidence
	ev.Intermediates = append([][]byte(nil), evidence.Intermediates...)

	for _, c := range certificates {
		if !bytes.Equal(c, chosen) {
			ev.Intermediates = append(ev.Intermediates, c)
		}
	}

	return ev
}

func checkTSACertificate(c *x509.Certificate, at time.Time) error {
	if c == nil || c.IsCA || c.KeyUsage&x509.KeyUsageDigitalSignature == 0 || len(c.ExtKeyUsage) != 1 || c.ExtKeyUsage[0] != x509.ExtKeyUsageTimeStamping || len(c.UnknownExtKeyUsage) > 0 || at.Before(c.NotBefore) || at.After(c.NotAfter) {
		return ErrTrust
	}

	critical := false

	for _, e := range c.Extensions {
		if e.Id.Equal(asn1.ObjectIdentifier{2, 5, 29, 37}) {
			critical = e.Critical
		}
	}

	if !critical {
		return fmt.Errorf("%w: critical timeStamping-only EKU required", ErrTrust)
	}

	return nil
}

func matchTSAName(ctx context.Context, n asn1.RawValue, c *x509.Certificate) error {
	if len(n.FullBytes) == 0 {
		return nil
	}

	if n.Class != 2 {
		return ErrFormat
	}

	switch n.Tag {
	case 4:
		rv, e := der.Explicit(n, 4)
		if e != nil {
			return ErrFormat
		}

		equal, err := x509name.EqualOrExact(ctx, rv.FullBytes, c.RawSubject)
		if err != nil {
			return fmt.Errorf("%w: TSA name: %w", ErrTrust, err)
		}

		if equal {
			return nil
		}
	case 1:
		if n.IsCompound {
			return ErrFormat
		}

		if slices.Contains(c.EmailAddresses, string(n.Bytes)) {
			return nil
		}
	case 2:
		if n.IsCompound {
			return ErrFormat
		}

		if slices.Contains(c.DNSNames, string(n.Bytes)) {
			return nil
		}
	case 6:
		if n.IsCompound {
			return ErrFormat
		}

		if tsaURINameMatches(string(n.Bytes), c) {
			return nil
		}

	case 7:
		if n.IsCompound || (len(n.Bytes) != 4 && len(n.Bytes) != 16) {
			return ErrFormat
		}

		if tsaIPNameMatches(n.Bytes, c) {
			return nil
		}

	default:
		return ErrFormat
	}

	return fmt.Errorf("%w: tsa name", ErrTrust)
}

func tsaURINameMatches(name string, c *x509.Certificate) bool {
	for _, uri := range c.URIs {
		if uri.String() == name {
			return true
		}
	}

	return false
}

func tsaIPNameMatches(name []byte, c *x509.Certificate) bool {
	for _, ip := range c.IPAddresses {
		if ip.Equal(name) {
			return true
		}
	}

	return false
}

func validateTimestampBinding(info Info, want Expectation) error {
	if want.Imprint.Hash != info.imprint.Hash || !bytes.Equal(want.Imprint.Digest, info.imprint.Digest) || len(want.Policy) > 0 && !want.Policy.Equal(info.policy) || want.Nonce != nil && (info.nonce == nil || want.Nonce.Cmp(info.nonce) != 0) {
		return ErrBinding
	}

	return nil
}

// Expectation supplies the required data imprint and optional exact nonce and TSA
// policy bindings.
type Expectation struct {
	// Imprint is the required expected hash algorithm and digest of the timestamped data.
	Imprint Imprint
	// Nonce requires an exact token nonce match when non-nil.
	Nonce *big.Int
	// Policy requires an exact TSA policy OID match when nonempty.
	Policy asn1.ObjectIdentifier
}

// Token retains an immutable parsed RFC 3161 CMS token. Use Verifier.Verify to
// authenticate its information and certificates before accepting its claims.
type Token struct {
	signed *cms.SignedData
	info   Info
}

// ParseToken parses a bounded token into owned storage, without authenticating it.
func ParseToken(ctx context.Context, raw []byte) (*Token, error) {
	return ParseTokenReader(ctx, bytes.NewReader(raw))
}

// ParseTokenReader reads one token, retaining its complete DER and parsed model.
// It limits DER to 16 MiB and TSTInfo to 1 MiB, and leaves src open.
func ParseTokenReader(ctx context.Context, src io.Reader) (*Token, error) {
	return parseTokenReader(ctx, src, 16<<20)
}

// UnverifiedInfo returns parsed timestamp claims, without authenticating them.
func (t *Token) UnverifiedInfo() Info {
	if t == nil {
		return Info{}
	}

	return t.info
}

// DER returns an owned copy of the token encoding.
func (t *Token) DER() []byte {
	if t == nil {
		return nil
	}

	return t.signed.DER()
}

// Size returns the DER token size in bytes.
func (t *Token) Size() int {
	if t == nil {
		return 0
	}

	return t.signed.Size()
}

// Certificates returns owned copies of UNTRUSTED embedded certificates.
func (t *Token) Certificates() [][]byte {
	if t == nil {
		return nil
	}

	return t.signed.Certificates()
}

// WriterTo returns an io.WriterTo that writes token DER without a full copy.
// The writer checks ctx and may leave partial output on destination error.
func (t *Token) WriterTo(ctx context.Context) io.WriterTo {
	var signed *cms.SignedData
	if t != nil {
		signed = t.signed
	}

	return signed.WriterTo(ctx)
}

// Result retains an immutable timestamp token with authenticated TSTInfo and the
// accepted TSA trust result.
type Result struct {
	token     *Token
	info      Info
	tsa       []byte
	trust     *pki.Result
	assertion *VerifiedAssertion
}

// TokenDER returns an owned copy of the timestamp token DER.
func (r *Result) TokenDER() []byte {
	if r == nil {
		return nil
	}

	return r.token.DER()
}

// Token returns the immutable parsed token authenticated by this result.
func (r *Result) Token() *Token {
	if r == nil {
		return nil
	}

	return r.token
}

// Info returns the immutable timestamp information.
func (r *Result) Info() Info {
	if r == nil {
		return Info{}
	}

	return r.info
}

// TSACertificateDER returns an owned copy of the authenticated TSA certificate DER.
func (r *Result) TSACertificateDER() []byte {
	if r == nil {
		return nil
	}

	return bytes.Clone(r.tsa)
}

// Trust returns the immutable TSA trust result.
func (r *Result) Trust() *pki.Result {
	if r == nil {
		return nil
	}

	return r.trust
}

// InspectToken returns unverified data, useful only for diagnostics/algorithm
// selection. VerifyToken must authenticate it before any application decision.
func InspectToken(ctx context.Context, b []byte) (Info, error) {
	token, e := ParseToken(ctx, b)
	if e != nil {
		return Info{}, fmt.Errorf("%w: %w", ErrFormat, e)
	}

	return token.UnverifiedInfo(), nil
}

func parseTokenReader(ctx context.Context, src io.Reader, maximum int) (*Token, error) {
	s, err := cms.ParseReader(ctx, src, cms.Limits{MaxBytes: maximum, MaxContentBytes: min(maximum, 1<<20)})
	if err != nil {
		if errors.Is(err, cms.ErrPolicy) {
			return nil, fmt.Errorf("%w: %w", ErrPolicy, err)
		}

		return nil, fmt.Errorf("%w: %w", ErrFormat, err)
	}

	if s.SignerCount() != 1 || s.Detached() || !s.ContentType().Equal(tstOID()) {
		return nil, ErrFormat
	}

	info, err := parseInfo(s.UnverifiedContent())
	if err != nil {
		return nil, err
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	return &Token{signed: s, info: info}, nil
}
