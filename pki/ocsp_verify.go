package pki

import (
	"bytes"
	"context"
	"crypto"
	"crypto/sha1" // #nosec G505 -- RFC 6960 ResponderID byKey requires SHA-1, independent of the signature algorithm.
	"crypto/subtle"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"time"

	"github.com/skarm/xmlsec/internal/der"
	"github.com/skarm/xmlsec/internal/signature"
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

	verification, err := prepareOCSPVerification(response, certificateDER, issuerDER, o)
	if err != nil {
		return nil, report, err
	}

	report, err = verifyOCSPData(ctx, verification, at, o)
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

	responder, err := selectOCSPResponder(parsed, issuer)
	if err != nil {
		return ocspVerification{}, err
	}

	return ocspVerification{response: response, parsed: parsed, certificate: certificate, issuer: issuer, responder: responder}, nil
}

func responderMatches(rid asn1.RawValue, c *x509.Certificate) bool {
	v, e := der.Explicit(rid, rid.Tag)
	if e != nil {
		return false
	}

	if rid.Tag == 1 {
		return bytes.Equal(v.FullBytes, c.RawSubject)
	}

	var expected []byte
	if der.Decode(v, &expected) != nil || len(expected) != sha1.Size {
		return false
	}

	bits, e := publicBits(c)
	if e != nil {
		return false
	}

	sum := sha1.Sum(bits) // #nosec G401 -- RFC 6960 section 4.2.1 fixes this identifier to SHA-1.

	return subtle.ConstantTimeCompare(expected, sum[:]) == 1
}

func authorizeResponder(ctx context.Context, r, issuer *x509.Certificate, at, produced time.Time, crls [][]byte) error {
	if e := allowedPublicKey(r.PublicKey); e != nil {
		return e
	}

	if at.Before(r.NotBefore) || at.After(r.NotAfter) || produced.Before(r.NotBefore) || produced.After(r.NotAfter) {
		return fmt.Errorf("%w: responder validity", ErrEvidence)
	}

	if bytes.Equal(r.Raw, issuer.Raw) {
		return nil
	}

	if r.IsCA || r.CheckSignatureFrom(issuer) != nil || !bytes.Equal(r.RawIssuer, issuer.RawSubject) || r.KeyUsage&x509.KeyUsageDigitalSignature == 0 || !allowedSignature(r.SignatureAlgorithm) || len(r.UnhandledCriticalExtensions) > 0 {
		return fmt.Errorf("%w: responder delegation", ErrEvidence)
	}

	eku := false

	for _, u := range r.ExtKeyUsage {
		if u == x509.ExtKeyUsageOCSPSigning {
			eku = true
		}
	}

	if !eku {
		return fmt.Errorf("%w: responder EKU", ErrEvidence)
	}

	for _, ex := range r.Extensions {
		if ex.Id.Equal(oidOCSPNoCheck()) {
			if !bytes.Equal(ex.Value, []byte{5, 0}) {
				return ErrEvidence
			}

			return nil
		}
	}

	if len(crls) == 0 {
		return fmt.Errorf("%w: responder revocation proof", ErrUnavailable)
	}

	lists, e := parseCRLs(ctx, crls)
	if e != nil {
		return e
	}

	return checkChainCRLs(ctx, []*x509.Certificate{r, issuer}, lists, at)
}

func normalizeOCSP(o OCSPOptions) (OCSPOptions, error) {
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

func verifyOCSPData(ctx context.Context, verification ocspVerification, at time.Time, o OCSPOptions) (OCSPReport, error) {
	report := OCSPReport{Signature: NotChecked}
	p := &verification.parsed

	responder := verification.responder
	if err := signature.Verify(responder.PublicKey, p.alg, p.tbs, p.sig); err != nil {
		report.Signature = Invalid
		return report, fmt.Errorf("%w: OCSP signature: %w", ErrEvidence, err)
	}

	report.Signature = Valid
	if err := authorizeResponder(ctx, responder, verification.issuer, at, p.produced, o.ResponderCRLs); err != nil {
		return report, err
	}

	report.Delegated = !bytes.Equal(responder.Raw, verification.issuer.Raw)

	chosen, err := matchingOCSPEntry(ctx, p.entries, verification.certificate, verification.issuer)
	if err != nil {
		return report, err
	}

	report.recordEntry(p.produced, chosen)

	if err := validateOCSPEntry(p.produced, at, chosen, o); err != nil {
		return report, err
	}

	if err = ctx.Err(); err != nil {
		return report, err
	}

	return report, nil
}

type ocspVerification struct {
	response    []byte
	parsed      parsedOCSP
	certificate *x509.Certificate
	issuer      *x509.Certificate
	responder   *x509.Certificate
}

func selectOCSPResponder(p parsedOCSP, issuer *x509.Certificate) (*x509.Certificate, error) {
	var responder *x509.Certificate

	for _, candidate := range append([]*x509.Certificate{issuer}, p.certs...) {
		if !responderMatches(p.rid, candidate) {
			continue
		}

		if responder != nil && !bytes.Equal(responder.Raw, candidate.Raw) {
			return nil, fmt.Errorf("%w: ambiguous responder", ErrEvidence)
		}

		responder = candidate
	}

	if responder == nil {
		return nil, ErrEvidence
	}

	return responder, nil
}

func matchingOCSPEntry(ctx context.Context, entries []singleResponse, certificate, issuer *x509.Certificate) (*singleResponse, error) {
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

			wanted, err = makeCertID(certificate, issuer, h)
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

	if chosen == nil {
		return nil, fmt.Errorf("%w: no matching CertID", ErrEvidence)
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
	raw         [][]byte
	options     OCSPOptions
	parsed      []parsedOCSP
	errors      []error
	initialized bool
	initErr     error
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
	for _, raw := range e.raw {
		if err := ctx.Err(); err != nil {
			return err
		}

		parsed, err := parseOCSP(raw, options.MaxBytes)
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

			responder, err := selectOCSPResponder(parsed, chain[i+1])
			if err != nil {
				continue
			}

			_, err = verifyOCSPData(ctx, ocspVerification{parsed: parsed, certificate: chain[i], issuer: chain[i+1], responder: responder}, at, e.options)
			if errors.Is(err, ErrRevoked) {
				return err
			}

			if err == nil {
				good = true
			}
		}

		if !good {
			return fmt.Errorf("%w: OCSP chain position %d", ErrUnavailable, i)
		}
	}

	return nil
}
