package pki

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"
)

const (
	historicalChainFailure     = "CERTIFICATE_CHAIN_GENERAL_FAILURE"
	historicalNoChainPoE       = "NO_CERTIFICATE_CHAIN_FOUND_NO_POE"
	historicalRevocationBounds = "REVOCATION_OUT_OF_BOUNDS_NO_POE"
	historicalTryLater         = "TRY_LATER"
)

// CheckCurrentPolicy applies this session's EN319102-1 calendar, freshness,
// sunset and temporal cryptographic constraints to an already successful
// current-time Result. It does not mint a Result or grant any historical PoE.
// The empty sub-indication and nil error denote success.
func (s *HistoricalSession) CheckCurrentPolicy(ctx context.Context, result *Result) (string, error) {
	if err := s.request(ctx); err != nil {
		return historicalChainFailure, err
	}

	if result == nil || len(result.chain) == 0 || !result.at.Equal(s.now) {
		return historicalChainFailure, ErrPolicy
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	target, err := s.historicalTarget(ctx, result.chain[0])
	if err != nil {
		return historicalPathFailure(err), err
	}

	paths, err := s.pathsFor(ctx, target)
	if err != nil {
		return historicalNoChainPoE, err
	}

	for _, path := range paths {
		if !historicalResultPath(result, path) {
			continue
		}

		return s.checkCurrentPathPolicy(ctx, path)
	}

	return historicalNoChainPoE, ErrCertificate
}

func historicalResultPath(result *Result, path *HistoricalPath) bool {
	if len(result.chain) != len(path.chain) {
		return false
	}

	for index, raw := range result.chain {
		if !bytes.Equal(raw, path.chain[index].Raw) {
			return false
		}
	}

	return true
}

type currentPolicyEvaluation struct {
	session *HistoricalSession
	active  map[[32]byte]bool
}

func (s *HistoricalSession) checkCurrentPathPolicy(ctx context.Context, path *HistoricalPath) (string, error) {
	evaluator := currentPolicyEvaluation{session: s, active: make(map[[32]byte]bool)}
	return evaluator.check(ctx, path, false, false)
}

func (e *currentPolicyEvaluation) check(ctx context.Context, path *HistoricalPath, source, skipLeaf bool) (string, error) {
	s := e.session
	if e.active[path.fingerprint] {
		return historicalRevocationBounds, ErrUnavailable
	}

	if len(e.active) >= s.verifier.maxDepth {
		return historicalRevocationBounds, fmt.Errorf("%w: %w: historical authorization depth", ErrPolicy, ErrLimit)
	}

	e.active[path.fingerprint] = true
	defer delete(e.active, path.fingerprint)

	usages := s.verifier.usages
	if source {
		usages = []x509.ExtKeyUsage{x509.ExtKeyUsageAny}
	}

	if _, err := s.checkPathUsages(ctx, path, usages); err != nil {
		return historicalPathFailure(err), err
	}

	anchor := sha256.Sum256(path.chain[len(path.chain)-1].Raw)
	if sunset, found := s.options.TrustAnchorSunsets[hex.EncodeToString(anchor[:])]; found && !s.now.Before(sunset) {
		return historicalNoChainPoE, ErrUnavailable
	}

	claims, err := s.authenticate(ctx, path)
	if err != nil {
		return historicalChainFailure, err
	}

	evaluator := pastEvaluation{session: s}
	for index := len(path.chain) - 2; index >= 0; index-- {
		if sub, err := e.checkCertificate(ctx, path, index, claims, source, skipLeaf, &evaluator); err != nil {
			return sub, err
		}
	}

	return "", ctx.Err()
}

func (e *currentPolicyEvaluation) checkCertificate(ctx context.Context, path *HistoricalPath, index int, claims []historicalClaim, source, skipLeaf bool, evaluator *pastEvaluation) (string, error) {
	s := e.session

	certificate := path.chain[index]
	if source && (s.now.Before(certificate.NotBefore) || s.now.After(certificate.NotAfter)) {
		return historicalRevocationBounds, ErrUnavailable
	}

	if cutoff := evaluator.materialCutoff(certificate.SignatureAlgorithm, path.chain[index+1]); !cutoff.IsZero() && !s.now.Before(cutoff) {
		return "CRYPTO_CONSTRAINTS_FAILURE_NO_POE", ErrPolicy
	}

	if skipLeaf && index == 0 {
		return "", nil
	}

	selected, err := s.selectHistoricalStatusFor(ctx, certificate, claims, nil, s.now, historicalStatusMode(s.verifier.revocation, source && index == 0))
	if err != nil {
		return historicalTryLater, err
	}

	if selected.revoked {
		if index == 0 && !source {
			if selected.reason == 6 {
				return historicalTryLater, ErrRevoked
			}

			return "REVOKED_NO_POE", ErrRevoked
		}

		return "REVOKED_CA_NO_POE", ErrRevoked
	}

	if evaluator.cryptoBoundary(certificate, selected, s.now) {
		return "CRYPTO_CONSTRAINTS_FAILURE_NO_POE", ErrPolicy
	}

	return e.checkSources(ctx, path, index, selected)
}

func (e *currentPolicyEvaluation) checkSources(ctx context.Context, path *HistoricalPath, index int, status historicalStatus) (string, error) {
	for _, claim := range status.claims {
		if e.session.now.Before(claim.signer.NotBefore) || e.session.now.After(claim.signer.NotAfter) {
			return historicalRevocationBounds, ErrUnavailable
		}

		if !claim.dependency && !historicalFresh(claim.fact.this, claim.fact.next, e.session.now, e.session.options.RevocationFreshness) {
			return historicalTryLater, fmt.Errorf("%w: revocation freshness", ErrUnavailable)
		}

		if claim.signerPath != nil && !sameHistoricalChain(claim.signerPath.chain, path.chain[index+1:]) {
			if sub, err := e.check(ctx, claim.signerPath, true, !claim.needsSignerStatus); err != nil {
				return sub, err
			}
		}
	}

	return "", ctx.Err()
}
