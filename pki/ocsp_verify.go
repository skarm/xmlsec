package pki

import (
	"bytes"
	"context"
	"crypto"
	"crypto/sha1" // #nosec G505 -- RFC 6960 ResponderID byKey requires SHA-1, independent of the signature algorithm.
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"time"

	"github.com/skarm/xmlsec/evidence"
	"github.com/skarm/xmlsec/internal/der"
	"github.com/skarm/xmlsec/internal/signature"
	"github.com/skarm/xmlsec/internal/x509cert"
	"github.com/skarm/xmlsec/internal/x509name"
)

// VerifyOCSP returns a result only for an authenticated fresh GOOD response.
// The issuer must be trusted separately. Revoked/unknown responses yield an
// authenticated diagnostic report but never a successful result.
func VerifyOCSP(ctx context.Context, response, certificateDER, issuerDER []byte, at time.Time, o OCSPOptions) (result *OCSPResult, report OCSPReport, err error) {
	report.Signature = NotChecked

	defer func() {
		if err != nil {
			result = nil
			report.Error = err.Error()
		}
	}()

	if ctx == nil || at.IsZero() {
		return nil, report, ErrPolicy
	}

	if e := ctx.Err(); e != nil {
		return nil, report, e
	}

	o, err = normalizeOCSP(o)
	if err != nil {
		return nil, report, err
	}

	if len(response) > o.MaxBytes || len(certificateDER) > 1<<20 || len(issuerDER) > 1<<20 {
		return nil, report, ErrEvidence
	}

	sources, err := (&Verifier{maxBytes: 8 << 20}).validatedSources(ctx, certificateDER, Evidence{Intermediates: [][]byte{issuerDER}, OCSPResponses: [][]byte{response}, CRLs: o.ResponderCRLs, Sources: o.Sources})
	if err != nil {
		return nil, report, err
	}

	verification, err := prepareOCSPVerification(response, certificateDER, issuerDER, o)
	if err != nil {
		return nil, report, err
	}

	verification.source.sources = sources[evidenceBinding{kind: evidence.OCSP, hash: sha256.Sum256(response)}]
	verification.authorization = &ocspResponderEvidence{raw: o.ResponderCRLs, sources: sources}

	report, err = verifyOCSPData(ctx, &verification, at, o)
	if err != nil {
		return nil, report, err
	}

	responder := verification.responder.Raw
	if verification.responder == verification.issuer {
		responder = bytes.Clone(responder)
	}

	if err = ctx.Err(); err != nil {
		return nil, report, err
	}

	return &OCSPResult{verification.response, responder, report}, report, nil
}

// prepareOCSPVerification preserves the size, certificate, response and nonce
// checks before selecting a responder or verifying its signature.
func prepareOCSPVerification(response, certificateDER, issuerDER []byte, o OCSPOptions) (ocspVerification, error) {
	if len(response) > o.MaxBytes {
		return ocspVerification{}, ErrEvidence
	}

	certificate, err := parseBorrowedCertificate(certificateDER)
	if err != nil {
		return ocspVerification{}, err
	}

	issuer, err := parseBorrowedCertificate(issuerDER)
	if err != nil {
		return ocspVerification{}, err
	}

	if err := allowedPublicKey(issuer.PublicKey); err != nil {
		return ocspVerification{}, err
	}

	response = bytes.Clone(response)

	parsed, err := parseOCSP(response, o.MaxBytes)
	if err != nil {
		return ocspVerification{}, err
	}

	if len(o.ExpectedNonce) > 0 && subtle.ConstantTimeCompare(o.ExpectedNonce, parsed.nonce) != 1 {
		return ocspVerification{}, fmt.Errorf("%w: OCSP nonce", ErrEvidence)
	}

	return ocspVerification{response: response, source: &ocspSource{owned: response}, parsed: parsed, certificate: certificate, issuer: issuer}, nil
}

func responderMatches(ctx context.Context, rid asn1.RawValue, c *x509.Certificate) (bool, error) {
	v, e := der.Explicit(rid, rid.Tag)
	if e != nil {
		return false, e
	}

	if rid.Tag == 1 {
		return x509name.EqualOrExact(ctx, v.FullBytes, c.RawSubject)
	}

	var expected []byte
	if der.Decode(v, &expected) != nil || len(expected) != sha1.Size {
		return false, ErrEvidence
	}

	bits, e := publicBits(c)
	if e != nil {
		return false, e
	}

	sum := sha1.Sum(bits) // #nosec G401 -- RFC 6960 section 4.2.1 fixes this identifier to SHA-1.

	return subtle.ConstantTimeCompare(expected, sum[:]) == 1, nil
}

func authorizeResponder(ctx context.Context, r, issuer *x509.Certificate, at, produced time.Time, revocation *ocspResponderEvidence) ([]*VerifiedEvidence, error) {
	if e := allowedPublicKey(r.PublicKey); e != nil {
		return nil, e
	}

	if at.Before(r.NotBefore) || at.After(r.NotAfter) || produced.Before(r.NotBefore) || produced.After(r.NotAfter) {
		return nil, fmt.Errorf("%w: responder validity", ErrEvidence)
	}

	if bytes.Equal(r.Raw, issuer.Raw) {
		return nil, nil
	}

	equal, err := x509name.EqualOrExact(ctx, r.RawIssuer, issuer.RawSubject)
	if err != nil {
		return nil, fmt.Errorf("%w: responder issuer name: %w", ErrEvidence, err)
	}

	if r.IsCA || r.CheckSignatureFrom(issuer) != nil || !equal || r.KeyUsage&x509.KeyUsageDigitalSignature == 0 || !allowedSignature(r.SignatureAlgorithm) || len(r.UnhandledCriticalExtensions) > 0 {
		return nil, fmt.Errorf("%w: responder delegation", ErrEvidence)
	}

	eku := false

	for _, u := range r.ExtKeyUsage {
		if u == x509.ExtKeyUsageOCSPSigning {
			eku = true
		}
	}

	if !eku {
		return nil, fmt.Errorf("%w: responder EKU", ErrEvidence)
	}

	for _, ex := range r.Extensions {
		if ex.Id.Equal(oidOCSPNoCheck()) {
			if ex.Critical || !bytes.Equal(ex.Value, []byte{5, 0}) {
				return nil, ErrEvidence
			}

			return nil, nil
		}
	}

	if revocation == nil || len(revocation.raw) == 0 {
		return nil, fmt.Errorf("%w: responder revocation proof", ErrUnavailable)
	}

	lists, err := revocation.parsed(ctx)
	if err != nil {
		return nil, err
	}

	for _, list := range lists {
		list.used = nil
	}

	if err := checkChainCRLs(ctx, []*x509.Certificate{r, issuer}, lists, at); err != nil {
		return nil, err
	}

	var dependencies []*VerifiedEvidence
	for _, list := range lists {
		dependencies = appendOCSPEvidence(dependencies, list.used...)
	}

	return dependencies, nil
}

func normalizeOCSP(o OCSPOptions) (OCSPOptions, error) {
	authorities, err := normalizeOCSPAuthorities(o.Authorities)
	if err != nil {
		return o, err
	}

	o.Authorities = authorities
	o.ExpectedNonce = bytes.Clone(o.ExpectedNonce)

	if o.MaxAge == 0 {
		o.MaxAge = 24 * time.Hour
	}

	if o.MaxBytes == 0 {
		o.MaxBytes = 1 << 20
	}

	if o.MaxAge <= 0 || o.MaxAge > 30*24*time.Hour || o.ClockSkew < 0 || o.ClockSkew > 10*time.Minute || o.MaxBytes < 1 || o.MaxBytes > 8<<20 || len(o.ExpectedNonce) > 128 || len(o.ResponderCRLs) > 32 {
		return o, ErrPolicy
	}

	n := 0
	for _, b := range o.ResponderCRLs {
		n += len(b)
		if n > 8<<20 {
			return o, ErrPolicy
		}
	}

	return o, nil
}

func verifyOCSPData(ctx context.Context, verification *ocspVerification, at time.Time, o OCSPOptions) (OCSPReport, error) {
	report := OCSPReport{Signature: NotChecked}
	p := &verification.parsed

	responder, dependencies, status, err := selectOCSPResponder(ctx, *p, verification.issuer, at, o, verification.authorization)

	report.Signature = status
	if err != nil {
		return report, err
	}

	verification.responder = responder
	verification.dependencies = dependencies

	report.Authorization = OCSPAuthorityIssuer

	if !bytes.Equal(responder.Raw, verification.issuer.Raw) {
		if configuredOCSPAuthority(o.Authorities, responder, verification.issuer) {
			report.Authorization = OCSPAuthorityLocal
		} else {
			report.Authorization = OCSPAuthorityDelegated
			report.Delegated = true
		}
	}

	chosen, err := matchingOCSPEntry(ctx, p.entries, verification.certificate, verification.issuer)
	if err != nil {
		return report, err
	}

	report.recordEntry(p.produced, chosen)

	if verification.source == nil {
		verification.source = &ocspSource{owned: verification.response}
	}

	report.evidence = appendOCSPEvidence(report.evidence, dependencies...)
	report.evidence = appendOCSPEvidence(report.evidence, newOCSPEvidence(verification, chosen, at))

	if err := validateOCSPEntry(p.produced, at, chosen, o); err != nil {
		return report, err
	}

	if err = ctx.Err(); err != nil {
		return report, err
	}

	return report, nil
}

type ocspVerification struct {
	authorization *ocspResponderEvidence
	dependencies  []*VerifiedEvidence
	source        *ocspSource
	response      []byte
	parsed        parsedOCSP
	certificate   *x509.Certificate
	issuer        *x509.Certificate
	responder     *x509.Certificate
}

func selectOCSPResponder(ctx context.Context, p parsedOCSP, issuer *x509.Certificate, at time.Time, options OCSPOptions, revocation *ocspResponderEvidence) (*x509.Certificate, []*VerifiedEvidence, Status, error) {
	var (
		selected     *x509.Certificate
		dependencies []*VerifiedEvidence
	)

	status := NotChecked

	var failure error

	candidates := append([]*x509.Certificate{issuer}, p.certs...)
	for _, authority := range options.Authorities {
		if !bytes.Equal(authority.IssuerCertificateDER, issuer.Raw) {
			continue
		}

		candidate, err := x509cert.ParseDefault(authority.ResponderCertificateDER)
		if err != nil {
			return nil, nil, status, ErrPolicy
		}

		candidates = append(candidates, candidate)
	}

	for _, candidate := range candidates {
		if err := ctx.Err(); err != nil {
			return nil, nil, status, err
		}

		matches, err := responderMatches(ctx, p.rid, candidate)
		if err != nil {
			failure = fmt.Errorf("%w: responder name: %w", ErrEvidence, err)
			continue
		}

		if !matches {
			continue
		}

		if err := signature.Verify(candidate.PublicKey, p.alg, p.tbs, p.sig); err != nil {
			if status == NotChecked {
				status = Invalid
				failure = fmt.Errorf("%w: OCSP signature: %w", ErrEvidence, err)
			}

			continue
		}

		status = Valid

		candidateDependencies, err := authorizeOCSPCandidate(ctx, candidate, issuer, at, p.produced, options, revocation)
		if err != nil {
			failure = err
			continue
		}

		if selected != nil && !bytes.Equal(selected.Raw, candidate.Raw) {
			return nil, nil, status, fmt.Errorf("%w: ambiguous authenticated responder", ErrEvidence)
		}

		selected = candidate
		dependencies = candidateDependencies
	}

	if selected == nil {
		if failure == nil {
			failure = ErrEvidence
		}

		return nil, nil, status, failure
	}

	return selected, dependencies, status, nil
}

func matchingOCSPEntry(ctx context.Context, entries []singleResponse, certificate, issuer *x509.Certificate) (*singleResponse, error) {
	chosen, err := findOCSPEntry(ctx, entries, certificate, issuer)
	if err != nil {
		return nil, err
	}

	if chosen == nil {
		return nil, fmt.Errorf("%w: no matching CertID", ErrEvidence)
	}

	return chosen, nil
}

// findOCSPEntry distinguishes an ordinary miss from malformed or ambiguous
// matching status data. The standalone verifier still requires a matching entry.
func findOCSPEntry(ctx context.Context, entries []singleResponse, certificate, issuer *x509.Certificate) (*singleResponse, error) {
	var chosen *singleResponse
	// CertID algorithms can vary across entries. Cache each expected identifier
	// so a response cannot repeat certificate signature checks for every entry.
	wantedIDs := make(map[crypto.Hash]certID, 4)

	for i := range entries {
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		entry := &entries[i]
		h, _ := signature.Hash(entry.id.alg, true)

		wanted, found := wantedIDs[h]
		if !found {
			var err error

			wanted, err = makeCertID(ctx, certificate, issuer, h)
			if err != nil {
				return nil, err
			}

			wantedIDs[h] = wanted
		}

		if sameCertID(entry.id, wanted) {
			if chosen != nil {
				return nil, fmt.Errorf("%w: duplicate matching CertID", ErrEvidence)
			}

			chosen = entry
		}
	}

	return chosen, nil
}

func (r *OCSPReport) recordEntry(produced time.Time, s *singleResponse) {
	r.Status = s.status
	r.ProducedAt = produced
	r.ThisUpdate = s.this
	r.NextUpdate = s.next
	r.RevokedAt = s.revoked
	r.RevocationReason = s.reason
}

func validateOCSPEntry(produced, at time.Time, s *singleResponse, o OCSPOptions) error {
	if produced.After(at.Add(o.ClockSkew)) || produced.Before(at.Add(-o.MaxAge-o.ClockSkew)) || s.this.After(at.Add(o.ClockSkew)) || s.this.Before(at.Add(-o.MaxAge-o.ClockSkew)) || produced.Before(s.this.Add(-o.ClockSkew)) || !s.next.IsZero() && (!s.next.After(s.this) || !at.Before(s.next.Add(o.ClockSkew)) || produced.After(s.next.Add(o.ClockSkew))) {
		return fmt.Errorf("%w: stale/future OCSP evidence", ErrUnavailable)
	}

	if s.status == OCSPRevoked {
		if s.revoked.After(produced.Add(o.ClockSkew)) {
			return ErrEvidence
		}

		return ErrRevoked
	}

	if s.status != OCSPGood {
		return ErrUnavailable
	}

	return nil
}

// ocspEvidence borrows operation-local evidence and parses each response once,
// including when path building presents several candidate chains.
type ocspEvidence struct {
	authorization       *ocspResponderEvidence
	provenanceSources   map[evidenceBinding][]*evidence.Observation
	authenticated, used []*VerifiedEvidence
	raw                 [][]byte
	options             OCSPOptions
	sources             []*ocspSource
	parsed              []parsedOCSP
	errors              []error
	initialized         bool
	initErr             error
}

func (e *ocspEvidence) parse(ctx context.Context) (err error) {
	if e.initialized {
		return e.initErr
	}
	defer func() {
		e.initialized = true
		e.initErr = err
	}()

	options, err := normalizeOCSP(e.options)
	if err != nil {
		return fmt.Errorf("%w: OCSP evidence options", ErrUnavailable)
	}

	e.options = options

	e.authorization = &ocspResponderEvidence{raw: options.ResponderCRLs, sources: e.provenanceSources}
	for _, raw := range e.raw {
		if err := ctx.Err(); err != nil {
			return err
		}

		parsed, err := parseOCSP(raw, options.MaxBytes)
		e.sources = append(e.sources, &ocspSource{input: raw, sources: e.provenanceSources[evidenceBinding{kind: evidence.OCSP, hash: sha256.Sum256(raw)}]})
		e.parsed = append(e.parsed, parsed)
		e.errors = append(e.errors, err)
	}

	return ctx.Err()
}

func (e *ocspEvidence) checkChain(ctx context.Context, chain []*x509.Certificate, at time.Time) error {
	if len(chain) < 2 {
		return ctx.Err()
	}

	if err := e.parse(ctx); err != nil {
		return err
	}

	for i := 0; i+1 < len(chain); i++ {
		good := false

		for j, parsed := range e.parsed {
			if err := ctx.Err(); err != nil {
				return err
			}

			if e.errors[j] != nil {
				continue
			}

			verification := ocspVerification{authorization: e.authorization, source: e.sources[j], parsed: parsed, certificate: chain[i], issuer: chain[i+1]}
			report, err := verifyOCSPData(ctx, &verification, at, e.options)
			e.authenticated = appendOCSPEvidence(e.authenticated, report.evidence...)

			if errors.Is(err, ErrRevoked) {
				return err
			}

			if err == nil {
				good = true
				e.used = appendOCSPEvidence(e.used, report.evidence...)
			}
		}

		if !good {
			return fmt.Errorf("%w: OCSP chain position %d", ErrUnavailable, i)
		}
	}

	return nil
}

func authorizeOCSPCandidate(ctx context.Context, responder, issuer *x509.Certificate, at, produced time.Time, options OCSPOptions, revocation *ocspResponderEvidence) ([]*VerifiedEvidence, error) {
	if configuredOCSPAuthority(options.Authorities, responder, issuer) {
		if at.Before(responder.NotBefore) || at.After(responder.NotAfter) || produced.Before(responder.NotBefore) || produced.After(responder.NotAfter) {
			return nil, fmt.Errorf("%w: local responder validity", ErrEvidence)
		}

		return nil, ctx.Err()
	}

	return authorizeResponder(ctx, responder, issuer, at, produced, revocation)
}
