package pki

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/skarm/xmlsec/internal/historicalproof"
)

type historicalStatus struct {
	claims    []historicalClaim
	primary   historicalClaim
	revoked   bool
	revokedAt time.Time
	reason    int
	this      time.Time
	next      time.Time
}

type pastEvaluation struct {
	session *HistoricalSession
	proofs  *historicalproof.Set
	active  map[[32]byte]struct{}
	steps   []TimeTransition
	used    []*VerifiedEvidence
	work    int
}

func (s *HistoricalSession) validatePast(ctx context.Context, targetDER []byte, proofs *historicalproof.Set) (*PastCertificateResult, *PastCertificateReport, error) {
	report := &PastCertificateReport{subIndication: "NO_CERTIFICATE_CHAIN_FOUND"}

	target, err := s.historicalTarget(ctx, targetDER)
	if err != nil {
		report.subIndication = historicalPathFailure(err)
		report.cause = err

		return nil, report, err
	}

	paths, err := s.pathsFor(ctx, target)
	if err != nil {
		report.cause = err
		return nil, report, err
	}

	for _, path := range paths {
		result, candidate, err := s.validatePastPath(ctx, path, proofs)

		report = candidate
		if err == nil {
			return result, report, nil
		}

		if errors.Is(err, ErrLimit) || ctx.Err() != nil {
			return nil, report, err
		}
	}

	if report.cause == nil {
		report.cause = ErrUnavailable
	}

	return nil, report, report.cause
}

func (s *HistoricalSession) validatePastPath(ctx context.Context, path *HistoricalPath, proofs *historicalproof.Set) (*PastCertificateResult, *PastCertificateReport, error) {
	report := &PastCertificateReport{path: path}

	reject := func(sub string, err error) (*PastCertificateResult, *PastCertificateReport, error) {
		report.subIndication = sub
		report.cause = err

		return nil, report, err
	}
	if proofs == nil || !proofs.Valid() || !proofs.Now().Equal(s.now) {
		return reject("NO_POE", ErrPolicy)
	}

	if _, err := s.checkPath(ctx, path); err != nil {
		return reject(historicalPathFailure(err), err)
	}

	evaluator := &pastEvaluation{session: s, proofs: proofs, active: make(map[[32]byte]struct{})}
	bound := s.now

	anchor := sha256.Sum256(path.chain[len(path.chain)-1].Raw)
	if sunset, found := s.options.TrustAnchorSunsets[hex.EncodeToString(anchor[:])]; found && sunset.Before(bound) {
		evaluator.transition(path.chain[len(path.chain)-1], nil, "5.6.2.2.4(1)", "trust-anchor-sunset", bound, sunset)
		bound = sunset
	}

	at, err := evaluator.slide(ctx, path, bound, false, false)
	report.transitions = evaluator.steps
	report.evidence = canonicalEvidence(evaluator.used)

	if err != nil {
		return reject("NO_POE", err)
	}

	if err := ctx.Err(); err != nil {
		return reject("NO_POE", err)
	}

	return &PastCertificateResult{path: path, at: at, evidence: report.evidence}, report, nil
}

func (e *pastEvaluation) slide(ctx context.Context, path *HistoricalPath, control time.Time, skipLeaf, authorizationLeaf bool) (time.Time, error) {
	if err := ctx.Err(); err != nil {
		return time.Time{}, err
	}

	if _, exists := e.active[path.fingerprint]; exists {
		return time.Time{}, fmt.Errorf("%w: historical authorization cycle", ErrUnavailable)
	}

	e.active[path.fingerprint] = struct{}{}
	defer delete(e.active, path.fingerprint)

	if len(e.active) > e.session.verifier.maxDepth {
		return time.Time{}, fmt.Errorf("%w: %w: historical authorization depth", ErrPolicy, ErrLimit)
	}

	claims, err := e.session.authenticate(ctx, path)
	if err != nil {
		return time.Time{}, err
	}

	for index := len(path.chain) - 2; index >= 0; index-- {
		control, err = e.slideCertificate(ctx, path, index, claims, control, skipLeaf, authorizationLeaf)
		if err != nil {
			return time.Time{}, err
		}
	}

	return control, ctx.Err()
}

func (e *pastEvaluation) slideCertificate(ctx context.Context, path *HistoricalPath, index int, claims []historicalClaim, control time.Time, skipLeaf, authorizationLeaf bool) (time.Time, error) {
	e.work++
	if e.work > 4096 {
		return time.Time{}, fmt.Errorf("%w: %w: historical certificate work", ErrPolicy, ErrLimit)
	}

	certificate := path.chain[index]
	if !historicalProofAt(e.proofs, sha256.Sum256(certificate.Raw), historicalproof.Certificate, control) {
		return time.Time{}, ErrUnavailable
	}

	if skipLeaf && index == 0 {
		return e.slideExemptCertificate(certificate, path.chain[index+1], control)
	}

	selected, err := e.session.selectHistoricalStatusFor(ctx, certificate, claims, e.proofs, control, historicalStatusMode(e.session.verifier.revocation, authorizationLeaf && index == 0))
	if err != nil {
		return time.Time{}, err
	}

	if err := e.protectCrypto(certificate, selected); err != nil {
		return time.Time{}, err
	}

	control, err = e.slideSourcePaths(ctx, path, index, selected, control)
	if err != nil {
		return time.Time{}, err
	}

	control, err = e.slideStatus(certificate, selected, control)
	if err != nil {
		return time.Time{}, err
	}

	bound := e.cryptoBound(certificate, selected, control)
	if bound.Before(control) {
		e.transition(certificate, selected.primary.fact, "5.6.2.2.4(2d)", "cryptographic-constraints", control, bound)
		control = bound
	}

	for _, claim := range selected.claims {
		applied := *claim.fact
		applied.coverage = claim.fact.historicalCoverage
		e.used = append(e.used, &applied)
	}

	return control, ctx.Err()
}

func (e *pastEvaluation) slideExemptCertificate(certificate, issuer *x509.Certificate, control time.Time) (time.Time, error) {
	cutoff := e.materialCutoff(certificate.SignatureAlgorithm, issuer)
	if cutoff.IsZero() || e.session.now.Before(cutoff) {
		return control, nil
	}

	proof, found := e.proofs.EarliestKind(sha256.Sum256(certificate.Raw), historicalproof.Certificate)
	if !found || !proof.Before(cutoff) {
		return time.Time{}, ErrUnavailable
	}

	if cutoff.Before(control) {
		e.transition(certificate, nil, "5.6.2.2.4(2d)", "cryptographic-constraints", control, cutoff)
		control = cutoff
	}

	return control, nil
}

func (e *pastEvaluation) slideSourcePaths(ctx context.Context, path *HistoricalPath, index int, status historicalStatus, control time.Time) (time.Time, error) {
	for _, claim := range status.claims {
		if claim.signerPath == nil || sameHistoricalChain(claim.signerPath.chain, path.chain[index+1:]) {
			continue
		}

		bound, err := e.slide(ctx, claim.signerPath, control, !claim.needsSignerStatus, true)
		if err != nil {
			return time.Time{}, err
		}

		if bound.Before(control) {
			e.transition(path.chain[index], claim.fact, "5.6.2.2.note5", "source-signer-path", control, bound)
			control = bound
		}
	}

	return control, nil
}

func (e *pastEvaluation) slideStatus(certificate *x509.Certificate, status historicalStatus, control time.Time) (time.Time, error) {
	if status.revoked {
		if status.revokedAt.After(control) {
			return time.Time{}, ErrEvidence
		}

		if e.session.options.Model == ShellModel || status.reason <= 2 {
			e.transition(certificate, status.primary.fact, "5.6.2.2.4(2b)", "revocation", control, status.revokedAt)
			control = status.revokedAt
		}

		return control, nil
	}

	for _, claim := range status.claims {
		if claim.dependency || historicalFresh(claim.fact.this, claim.fact.next, control, e.session.options.RevocationFreshness) {
			continue
		}

		if bound := claim.fact.this; bound.Before(control) {
			e.transition(certificate, claim.fact, "5.6.2.2.4(2c)", "freshness", control, bound)
			control = bound
		}
	}

	return control, nil
}

func historicalProofAt(proofs *historicalproof.Set, digest [32]byte, kind historicalproof.Kind, at time.Time) bool {
	proof, found := proofs.EarliestKind(digest, kind)
	return found && !proof.After(at)
}

func historicalFresh(issued, next, at time.Time, configured *time.Duration) bool {
	var freshness time.Duration
	if configured != nil {
		freshness = *configured
	} else {
		if next.IsZero() || !next.After(issued) {
			return false
		}

		freshness = next.Sub(issued)
	}

	return issued.After(at.Add(-freshness))
}

func (e *pastEvaluation) transition(certificate *x509.Certificate, fact *VerifiedEvidence, clause, reason string, before, after time.Time) {
	if !after.Before(before) {
		return
	}

	digest := sha256.Sum256(certificate.Raw)

	source := ""
	if fact != nil {
		source = fact.FingerprintSHA256()
	}

	e.steps = append(e.steps, TimeTransition{CertificateSHA256: hex.EncodeToString(digest[:]), EvidenceSHA256: source, Clause: clause, Reason: reason, Before: before, After: after})
}

func historicalStatusMode(main RevocationMode, authorizationLeaf bool) RevocationMode {
	if authorizationLeaf {
		return RequireCRL
	}

	return main
}

func (s *HistoricalSession) selectHistoricalStatusFor(ctx context.Context, certificate *x509.Certificate, claims []historicalClaim, proofs *historicalproof.Set, control time.Time, mode RevocationMode) (historicalStatus, error) {
	eligible, err := eligibleHistoricalClaims(ctx, certificate, claims, proofs, control)
	if err != nil {
		return historicalStatus{}, err
	}

	_, freshest, err := certificateCRLPoints(ctx, certificate)
	if err != nil {
		return historicalStatus{}, err
	}

	selected, err := historicalCRLStatuses(ctx, eligible, s.verifier.crlOptions.DisableDeltaCRLs, freshest)
	if err != nil {
		return historicalStatus{}, err
	}

	latestOCSP, err := latestHistoricalOCSP(eligible)
	if err != nil {
		return historicalStatus{}, err
	}

	var covered crlReasonMask

	for _, status := range selected {
		for _, claim := range status.claims {
			covered |= claim.fact.historicalCoverage
		}
	}

	if mode == RequireCRL && covered != allCRLReasons || mode == RequireOCSP && latestOCSP == nil || mode == NoRevocation {
		return historicalStatus{}, ErrUnavailable
	}

	selected = requiredHistoricalCRLs(selected, mode == RequireCRL)

	if latestOCSP != nil {
		if latestOCSP.fact.status == string(OCSPUnknown) {
			return historicalStatus{}, ErrUnavailable
		}

		if mode == RequireOCSP || latestOCSP.fact.status == string(OCSPRevoked) {
			selected = append(selected, historicalStatus{claims: []historicalClaim{*latestOCSP}, primary: *latestOCSP, revoked: latestOCSP.fact.status == string(OCSPRevoked), revokedAt: latestOCSP.fact.revoked, reason: latestOCSP.fact.reason, this: latestOCSP.fact.this, next: latestOCSP.fact.next})
		}
	}

	return combineHistoricalStatuses(selected)
}

func eligibleHistoricalClaims(ctx context.Context, certificate *x509.Certificate, claims []historicalClaim, proofs *historicalproof.Set, control time.Time) ([]historicalClaim, error) {
	var eligible []historicalClaim

	for _, claim := range claims {
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		if !bytes.Equal(claim.target.Raw, certificate.Raw) || proofs != nil && !claim.fact.this.Before(control) || proofs == nil && claim.fact.this.After(control) {
			continue
		}
		// Authentic late not-listed assertions cannot silently claim that the issuer
		// continues to retain status information for an already expired target.
		if claim.fact.this.After(certificate.NotAfter) && !claim.retainsStatus(certificate.NotAfter) {
			continue
		}

		if proofs != nil && !historicalProofAt(proofs, claim.fact.fingerprint, historicalproof.Kind(claim.fact.kind), control) {
			continue
		}

		eligible = append(eligible, claim)
	}

	return eligible, nil
}

func latestHistoricalOCSP(eligible []historicalClaim) (*historicalClaim, error) {
	var latestOCSP *historicalClaim

	for index := range eligible {
		claim := &eligible[index]
		if claim.ocsp == nil {
			continue
		}

		if latestOCSP == nil || claim.fact.this.After(latestOCSP.fact.this) {
			latestOCSP = claim
			continue
		}

		if claim.fact.this.Equal(latestOCSP.fact.this) && claim.fact.status != latestOCSP.fact.status {
			return nil, ErrEvidence
		}
	}

	return latestOCSP, nil
}

func combineHistoricalStatuses(selected []historicalStatus) (historicalStatus, error) {
	if len(selected) == 0 {
		return historicalStatus{}, ErrUnavailable
	}

	sort.Slice(selected, func(i, j int) bool { return selected[i].this.After(selected[j].this) })
	combined := selected[0]

	combined.claims = nil
	for _, status := range selected {
		combined.claims = append(combined.claims, status.claims...)
		if status.revoked {
			if !combined.revoked || status.this.After(combined.primary.fact.this) {
				combined.primary = status.primary
				combined.revokedAt = status.revokedAt
				combined.reason = status.reason
			}

			combined.revoked = true
		}
	}

	return combined, nil
}

func requiredHistoricalCRLs(statuses []historicalStatus, required bool) []historicalStatus {
	sort.SliceStable(statuses, func(i, j int) bool { return statuses[i].this.After(statuses[j].this) })

	var (
		chosen  []historicalStatus
		covered crlReasonMask
	)

	for _, status := range statuses {
		var reasons crlReasonMask
		for _, claim := range status.claims {
			reasons |= claim.fact.historicalCoverage
		}

		if status.revoked || required && reasons & ^covered != 0 {
			chosen = append(chosen, status)
			covered |= reasons
		}
	}

	return chosen
}

func historicalCRLStatuses(ctx context.Context, claims []historicalClaim, disableDelta bool, freshest bool) ([]historicalStatus, error) {
	groups := make(map[string][]historicalClaim)

	for _, claim := range claims {
		if claim.crl == nil {
			continue
		}

		key := claim.crl.issuerKey + "/" + string(claim.crl.scope.raw) + "/" + claim.fact.SignerCertificateSHA256()
		groups[key] = append(groups[key], claim)
	}

	keys := make([]string, 0, len(groups))
	for key := range groups {
		keys = append(keys, key)
	}

	sort.Strings(keys)

	var statuses []historicalStatus

	for _, key := range keys {
		group := groups[key]
		auth := make([]*authenticatedCRL, 0, len(group))

		byList := make(map[*parsedCRL]historicalClaim, len(group))
		for _, claim := range group {
			auth = append(auth, &authenticatedCRL{list: claim.crl, signer: claim.signerPath.chain[0]})
			byList[claim.crl] = claim
		}

		if err := checkCRLSequence(auth); err != nil {
			return nil, err
		}

		views := historicalViews(auth, disableDelta)
		if err := checkEquivalentCRLViews(ctx, views); err != nil {
			return nil, err
		}

		sort.Slice(views, func(i, j int) bool { return compareCRLOrder(views[i].source(), views[j].source()) > 0 })

		for _, view := range views {
			primary := byList[view.source()]
			if !disableDelta && (freshest || len(view.base.list.freshest) > 0) && view.delta == nil {
				continue
			}

			entry, err := viewCRLEntry(ctx, view, primary.target)
			if err != nil {
				return nil, err
			}

			status := historicalStatus{primary: primary, this: primary.fact.this, next: primary.fact.next, claims: []historicalClaim{byList[view.base.list]}}
			if view.delta != nil {
				status.claims[0].dependency = true
				status.claims = append(status.claims, byList[view.delta.list])
				composite := *status.claims[1].fact
				composite.dependencies = []string{status.claims[0].fact.FingerprintSHA256()}
				status.claims[1].fact = &composite
				status.primary = status.claims[1]
			}

			if entry != nil {
				status.revoked = true
				status.revokedAt = entry.revoked
				status.reason = entry.reason
			}

			statuses = append(statuses, status)

			break
		}
	}

	return statuses, nil
}

func historicalViews(group []*authenticatedCRL, disableDelta bool) []completeCRLView {
	var views []completeCRLView

	for _, base := range group {
		if base.list.base == nil {
			views = append(views, completeCRLView{base: base, this: base.list.this})
		}
	}

	if disableDelta {
		return views
	}

	for _, delta := range group {
		if delta.list.base == nil {
			continue
		}

		var newest *authenticatedCRL
		for _, base := range group {
			if compatibleCRLBase(base.list, delta.list) && (newest == nil || base.list.number.Cmp(newest.list.number) > 0) {
				newest = base
			}
		}

		if newest != nil {
			views = append(views, completeCRLView{base: newest, delta: delta, this: delta.list.this})
		}
	}

	return views
}

func historicalKeyBits(certificate *x509.Certificate) int {
	switch key := certificate.PublicKey.(type) {
	case *rsa.PublicKey:
		return key.N.BitLen()
	case *ecdsa.PublicKey:
		return key.Curve.Params().BitSize
	case ed25519.PublicKey:
		return 256
	}

	return 0
}

func historicalSignatureHash(algorithm x509.SignatureAlgorithm) crypto.Hash {
	switch algorithm {
	case x509.SHA256WithRSA, x509.SHA256WithRSAPSS, x509.ECDSAWithSHA256:
		return crypto.SHA256
	case x509.SHA384WithRSA, x509.SHA384WithRSAPSS, x509.ECDSAWithSHA384:
		return crypto.SHA384
	case x509.SHA512WithRSA, x509.SHA512WithRSAPSS, x509.ECDSAWithSHA512:
		return crypto.SHA512
	case x509.SHA1WithRSA, x509.ECDSAWithSHA1:
		return crypto.SHA1
	}

	return 0
}

func historicalRuleMatches(rule CryptoConstraint, algorithm x509.SignatureAlgorithm, signer *x509.Certificate) bool {
	if rule.SignatureAlgorithm != x509.UnknownSignatureAlgorithm {
		return rule.SignatureAlgorithm == algorithm
	}

	if rule.Hash != 0 {
		return rule.Hash == historicalSignatureHash(algorithm)
	}

	return signer != nil && rule.PublicKeyAlgorithm == signer.PublicKeyAlgorithm && historicalKeyBits(signer) < rule.MinimumKeyBits
}

func (e *pastEvaluation) materialCutoff(algorithm x509.SignatureAlgorithm, signer *x509.Certificate) time.Time {
	var cutoff time.Time
	for _, rule := range e.session.options.CryptoConstraints {
		if historicalRuleMatches(rule, algorithm, signer) && (cutoff.IsZero() || rule.ReliableUntil.Before(cutoff)) {
			cutoff = rule.ReliableUntil
		}
	}

	return cutoff
}

func (e *pastEvaluation) cryptoBoundary(certificate *x509.Certificate, status historicalStatus, at time.Time) bool {
	if cutoff := e.materialCutoff(certificate.SignatureAlgorithm, status.primary.issuer); !cutoff.IsZero() && !at.Before(cutoff) {
		return true
	}

	for _, claim := range status.claims {
		algorithm := claim.ocspSignatureAlgorithm()
		if claim.crl != nil {
			algorithm = claim.crlSignatureAlgorithm()
		}

		if cutoff := e.materialCutoff(algorithm, claim.signer); !cutoff.IsZero() && !at.Before(cutoff) {
			return true
		}
	}

	return false
}

func (e *pastEvaluation) protectCrypto(certificate *x509.Certificate, status historicalStatus) error {
	issuer := status.primary.issuer
	if cutoff := e.materialCutoff(certificate.SignatureAlgorithm, issuer); !cutoff.IsZero() && !e.session.now.Before(cutoff) {
		proof, found := e.proofs.EarliestKind(sha256.Sum256(certificate.Raw), historicalproof.Certificate)
		if !found || !proof.Before(cutoff) {
			return ErrUnavailable
		}
	}

	for _, claim := range status.claims {
		signer := claim.signer

		algorithm := claim.ocspSignatureAlgorithm()
		if claim.crl != nil {
			algorithm = claim.crlSignatureAlgorithm()
		}

		if cutoff := e.materialCutoff(algorithm, signer); !cutoff.IsZero() && !e.session.now.Before(cutoff) {
			proof, found := e.proofs.EarliestKind(claim.fact.fingerprint, historicalproof.Kind(claim.fact.kind))
			if !found || !proof.Before(cutoff) {
				return ErrUnavailable
			}
		}
	}

	return nil
}

func (e *pastEvaluation) cryptoBound(certificate *x509.Certificate, status historicalStatus, control time.Time) time.Time {
	cutoff := e.materialCutoff(certificate.SignatureAlgorithm, status.primary.issuer)
	if !cutoff.IsZero() && cutoff.Before(control) {
		control = cutoff
	}

	for _, claim := range status.claims {
		signer := claim.signer

		algorithm := claim.ocspSignatureAlgorithm()
		if claim.crl != nil {
			algorithm = claim.crlSignatureAlgorithm()
		}

		cutoff = e.materialCutoff(algorithm, signer)
		if !cutoff.IsZero() && cutoff.Before(control) {
			control = cutoff
		}
	}

	return control
}

func (c historicalClaim) crlSignatureAlgorithm() x509.SignatureAlgorithm {
	if c.crl == nil {
		return x509.UnknownSignatureAlgorithm
	}

	return c.crl.signatureAlgorithm
}
func (c historicalClaim) ocspSignatureAlgorithm() x509.SignatureAlgorithm { return c.algorithm }
