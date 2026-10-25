package pki

import (
	"bytes"
	"context"
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/skarm/xmlsec/evidence"
	"github.com/skarm/xmlsec/internal/signature"
	"github.com/skarm/xmlsec/internal/x509name"
)

type historicalClaim struct {
	fact              *VerifiedEvidence
	target, issuer    *x509.Certificate
	signer            *x509.Certificate
	signerPath        *HistoricalPath
	crl               *parsedCRL
	ocsp              *singleResponse
	algorithm         x509.SignatureAlgorithm
	needsSignerStatus bool
	dependency        bool
}

func (s *HistoricalSession) prepareHistoricalSources(ctx context.Context) error {
	if s.sourcesReady {
		return nil
	}

	lists, err := parseCRLs(ctx, s.evidence.CRLs)
	if err != nil {
		return err
	}

	for _, list := range lists {
		list.ownedRaw = list.raw
	}

	if err := s.initializeCertificates(ctx); err != nil {
		return err
	}

	s.lists = lists
	s.sourcesReady = true

	return nil
}

func (s *HistoricalSession) sourcePath(ctx context.Context, signer *x509.Certificate, anchor *x509.Certificate, issued time.Time) (*HistoricalPath, error) {
	if issued.Before(signer.NotBefore) || issued.After(signer.NotAfter) {
		return nil, ErrEvidence
	}

	digest := sha256.Sum256(signer.Raw)
	if s.certificates[digest] == nil {
		s.certificates[digest] = signer
	}

	paths, err := s.pathsFor(ctx, signer)
	if err != nil {
		return nil, err
	}

	for _, path := range paths {
		if !bytes.Equal(path.chain[len(path.chain)-1].Raw, anchor.Raw) {
			continue
		}

		if _, err := s.checkPathUsages(ctx, path, []x509.ExtKeyUsage{x509.ExtKeyUsageAny}); err == nil {
			return path, nil
		} else if errors.Is(err, ErrLimit) {
			return nil, err
		}

		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
	}

	return nil, ErrUnavailable
}

func (s *HistoricalSession) authenticate(ctx context.Context, path *HistoricalPath) ([]historicalClaim, error) {
	if err := s.validPath(path); err != nil {
		return nil, err
	}

	if cached, found := s.claims[path.fingerprint]; found {
		return cached, ctx.Err()
	}

	if err := s.prepareHistoricalSources(ctx); err != nil {
		return nil, err
	}

	sources, err := s.verifier.validatedSources(ctx, path.chain[0].Raw, s.evidence)
	if err != nil {
		return nil, err
	}

	var claims []historicalClaim

	for index := 0; index+1 < len(path.chain); index++ {
		target, issuer := path.chain[index], path.chain[index+1]

		for _, list := range s.lists {
			list.sources = sources[evidenceBinding{kind: evidence.CRL, hash: sha256.Sum256(list.raw)}]

			claim, err := s.authenticateCRL(ctx, path, list, target, issuer)
			if err != nil {
				return nil, err
			}

			if claim != nil {
				claims = append(claims, *claim)
			}
		}

		for responseIndex := range s.responses {
			claim, err := s.authenticateOCSP(ctx, path, &s.responses[responseIndex], s.evidence.OCSPResponses[responseIndex], sources, target, issuer)
			if err != nil {
				return nil, err
			}

			if claim != nil {
				claims = append(claims, *claim)
			}
		}
	}

	s.claims[path.fingerprint] = claims

	return claims, ctx.Err()
}

func (s *HistoricalSession) authenticateCRL(ctx context.Context, path *HistoricalPath, list *parsedCRL, target, issuer *x509.Certificate) (*historicalClaim, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	if list.this.After(s.now) {
		return nil, nil
	}

	points, _, err := certificateCRLPoints(ctx, target)
	if err != nil {
		return nil, err
	}

	var coverage crlReasonMask

	for _, point := range points {
		mask, err := applicableCRLScope(ctx, target, list, point)
		if err != nil {
			return nil, err
		}

		coverage |= mask
	}

	if coverage == 0 {
		return nil, nil
	}

	candidates := make([]*x509.Certificate, 0, len(s.certificates))
	for _, candidate := range s.certificates {
		candidates = append(candidates, candidate)
	}

	sort.Slice(candidates, func(i, j int) bool { return bytes.Compare(candidates[i].Raw, candidates[j].Raw) < 0 })

	for _, candidate := range candidates {
		matches, err := list.signerMatches(ctx, candidate)
		if err != nil {
			return nil, err
		}

		if !matches {
			continue
		}

		s.signatureWork++
		if s.signatureWork > 4096 {
			return nil, fmt.Errorf("%w: %w: historical signature work", ErrPolicy, ErrLimit)
		}

		if list.verifySignature(candidate.PublicKey) != nil {
			continue
		}

		signerPath, err := s.sourcePath(ctx, candidate, path.chain[len(path.chain)-1], list.this)
		if err != nil {
			if errors.Is(err, ErrLimit) || ctx.Err() != nil {
				return nil, err
			}

			continue
		}

		fact, err := recordCRLAssertion(ctx, &authenticatedCRL{list: list, signer: candidate}, target, issuer, list.this)
		if err != nil {
			return nil, err
		}

		historical := *fact
		historical.historicalCoverage = coverage
		historical.signerChain = historicalChainBytes(signerPath)

		historical.signerAuthority = "issuer"
		if !bytes.Equal(candidate.Raw, issuer.Raw) {
			historical.signerAuthority = "delegated"
		}

		return &historicalClaim{fact: &historical, target: target, issuer: issuer, signer: candidate, signerPath: signerPath, crl: list, needsSignerStatus: !bytes.Equal(candidate.Raw, issuer.Raw)}, nil
	}

	return nil, nil
}

func (s *HistoricalSession) authenticateOCSP(ctx context.Context, path *HistoricalPath, parsed *parsedOCSP, raw []byte, sources map[evidenceBinding][]*evidence.Observation, target, issuer *x509.Certificate) (*historicalClaim, error) {
	if parsed.produced.After(s.now) {
		return nil, nil
	}

	entry, err := findOCSPEntry(ctx, parsed.entries, target, issuer)
	if err != nil {
		return nil, err
	}

	if entry == nil {
		return nil, nil
	}
	// The signed envelope and status times must be internally coherent even when
	// present-time freshness is deliberately left to the historical process.
	if parsed.produced.Before(entry.this) || entry.archiveCutoff.After(parsed.produced) || !entry.next.IsZero() && !entry.next.After(entry.this) || entry.status == OCSPRevoked && entry.revoked.After(parsed.produced) {
		return nil, ErrEvidence
	}

	candidates, err := s.historicalOCSPCandidates(parsed, issuer)
	if err != nil {
		return nil, err
	}

	var selected *historicalClaim

	for _, candidate := range candidates {
		claim, err := s.authenticateOCSPCandidate(ctx, path, parsed, raw, sources, target, issuer, entry, candidate)
		if err != nil {
			return nil, err
		}

		if claim == nil {
			continue
		}

		if selected != nil && selected.fact.signer != claim.fact.signer {
			return nil, fmt.Errorf("%w: ambiguous historical responder", ErrEvidence)
		}

		selected = claim
	}

	return selected, nil
}

func (s *HistoricalSession) historicalOCSPCandidates(parsed *parsedOCSP, issuer *x509.Certificate) ([]*x509.Certificate, error) {
	candidates := append([]*x509.Certificate{issuer}, parsed.certs...)
	for _, authority := range s.verifier.ocspOptions.Authorities {
		if !bytes.Equal(authority.IssuerCertificateDER, issuer.Raw) {
			continue
		}

		candidate, err := parseBorrowedCertificate(authority.ResponderCertificateDER)
		if err != nil {
			return nil, err
		}

		candidates = append(candidates, candidate)
	}

	return candidates, nil
}

func (s *HistoricalSession) authenticateOCSPCandidate(ctx context.Context, path *HistoricalPath, parsed *parsedOCSP, raw []byte, sources map[evidenceBinding][]*evidence.Observation, target, issuer *x509.Certificate, entry *singleResponse, candidate *x509.Certificate) (*historicalClaim, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	matches, err := responderMatches(ctx, parsed.rid, candidate)
	if err != nil {
		return nil, err
	}

	if !matches {
		return nil, nil
	}

	s.signatureWork++
	if s.signatureWork > 4096 {
		return nil, fmt.Errorf("%w: %w: historical signature work", ErrPolicy, ErrLimit)
	}

	validSignature := signature.Verify(candidate.PublicKey, parsed.alg, parsed.tbs, parsed.sig) == nil
	if !validSignature {
		return nil, nil
	}

	local := configuredOCSPAuthority(s.verifier.ocspOptions.Authorities, candidate, issuer)

	noCheck, authorized, err := historicalResponderAuthority(ctx, candidate, issuer, parsed.produced, local)
	if err != nil {
		return nil, err
	}

	if !authorized {
		return nil, nil
	}

	var signerPath *HistoricalPath
	if !local {
		signerPath, err = s.sourcePath(ctx, candidate, path.chain[len(path.chain)-1], parsed.produced)
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, ErrLimit) {
				return nil, err
			}

			return nil, nil
		}
	}

	verification := ocspVerification{source: &ocspSource{owned: raw, sources: sources[evidenceBinding{kind: evidence.OCSP, hash: sha256.Sum256(raw)}]}, parsed: *parsed, certificate: target, issuer: issuer, responder: candidate}
	fact := newOCSPEvidence(&verification, entry, parsed.produced)
	fact.historicalCoverage = allCRLReasons
	fact.signerChain = historicalChainBytes(signerPath)

	fact.signerAuthority = "issuer"
	if local {
		fact.signerAuthority = "local"
		fact.signerChain = [][]byte{candidate.Raw}
	} else if !bytes.Equal(candidate.Raw, issuer.Raw) {
		fact.signerAuthority = "delegated"
	}

	return &historicalClaim{fact: fact, target: target, issuer: issuer, signer: candidate, signerPath: signerPath, ocsp: entry, algorithm: historicalAlgorithm(parsed.alg), needsSignerStatus: !local && !noCheck && !bytes.Equal(candidate.Raw, issuer.Raw)}, nil
}

func historicalResponderAuthority(ctx context.Context, responder, issuer *x509.Certificate, issued time.Time, local bool) (bool, bool, error) {
	validKey := allowedPublicKey(responder.PublicKey) == nil
	if issued.Before(responder.NotBefore) || issued.After(responder.NotAfter) || !validKey {
		return false, false, nil
	}

	if local {
		return true, true, ctx.Err()
	}

	if bytes.Equal(responder.Raw, issuer.Raw) {
		return true, true, ctx.Err()
	}

	equal, err := x509name.EqualOrExact(ctx, responder.RawIssuer, issuer.RawSubject)
	if err != nil {
		return false, false, err
	}

	validCertificateSignature := responder.CheckSignatureFrom(issuer) == nil
	if !equal || responder.IsCA || !validCertificateSignature || responder.KeyUsage&x509.KeyUsageDigitalSignature == 0 || len(responder.UnhandledCriticalExtensions) > 0 || !allowedSignature(responder.SignatureAlgorithm) {
		return false, false, nil
	}

	eku := false
	for _, usage := range responder.ExtKeyUsage {
		eku = eku || usage == x509.ExtKeyUsageOCSPSigning
	}

	if !eku {
		return false, false, nil
	}

	for _, extension := range responder.Extensions {
		if !extension.Id.Equal(oidOCSPNoCheck()) {
			continue
		}

		if extension.Critical || !bytes.Equal(extension.Value, []byte{5, 0}) {
			return false, false, nil
		}

		return true, true, nil
	}

	return false, true, nil
}

func historicalChainBytes(path *HistoricalPath) [][]byte {
	if path == nil {
		return nil
	}

	raw := make([][]byte, len(path.chain))
	for index, certificate := range path.chain {
		raw[index] = certificate.Raw
	}

	return raw
}

// SignerChainDER returns owned original certificates used to authenticate an
// historical assertion. A locally pinned authority can have only its own scoped
// certificate here; SignerAuthority distinguishes that explicit trust model.
func (e *VerifiedEvidence) SignerChainDER() [][]byte {
	if e == nil || !e.authenticated {
		return nil
	}

	raw := make([][]byte, len(e.signerChain))
	for index, source := range e.signerChain {
		raw[index] = bytes.Clone(source)
	}

	return raw
}

// SignerAuthority returns issuer, delegated or locally configured historical
// authorization; it is not a proof-of-existence or freshness indication.
func (e *VerifiedEvidence) SignerAuthority() string {
	if e == nil || !e.authenticated {
		return ""
	}

	return e.signerAuthority
}

func historicalAlgorithm(algorithm pkix.AlgorithmIdentifier) x509.SignatureAlgorithm {
	hash, mode, err := signature.Details(algorithm)
	if err != nil {
		if algorithm.Algorithm.Equal(asn1.ObjectIdentifier{1, 3, 101, 112}) && len(algorithm.Parameters.FullBytes) == 0 {
			return x509.PureEd25519
		}

		return x509.UnknownSignatureAlgorithm
	}

	switch mode {
	case "rsa":
		switch hash {
		case crypto.SHA256:
			return x509.SHA256WithRSA
		case crypto.SHA384:
			return x509.SHA384WithRSA
		case crypto.SHA512:
			return x509.SHA512WithRSA
		}
	case "pss":
		switch hash {
		case crypto.SHA256:
			return x509.SHA256WithRSAPSS
		case crypto.SHA384:
			return x509.SHA384WithRSAPSS
		case crypto.SHA512:
			return x509.SHA512WithRSAPSS
		}
	case "ecdsa":
		switch hash {
		case crypto.SHA256:
			return x509.ECDSAWithSHA256
		case crypto.SHA384:
			return x509.ECDSAWithSHA384
		case crypto.SHA512:
			return x509.ECDSAWithSHA512
		}
	}

	return x509.UnknownSignatureAlgorithm
}

func (c historicalClaim) retainsStatus(expired time.Time) bool {
	if c.crl != nil {
		return !c.crl.retainedFrom.IsZero() && !expired.Before(c.crl.retainedFrom)
	}

	return c.ocsp != nil && !c.ocsp.archiveCutoff.IsZero() && !expired.Before(c.ocsp.archiveCutoff)
}

// InspectOCSPCertificates returns owned copies of certificates actually embedded
// in one bounded OCSP response. They are untrusted input, not authenticated
// signer paths or proof of existence. It shares the response syntax decoder and
// its eight-certificate/64-status limits; the input cannot exceed64MiB.
func InspectOCSPCertificates(ctx context.Context, raw []byte) ([][]byte, error) {
	if ctx == nil {
		return nil, ErrPolicy
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	if len(raw) > 64<<20 {
		return nil, fmt.Errorf("%w: %w: OCSP inspection bytes", ErrPolicy, ErrLimit)
	}

	parsed, err := parseOCSP(raw, 64<<20)
	if err != nil {
		return nil, err
	}

	certificates := make([][]byte, len(parsed.certs))
	for index, certificate := range parsed.certs {
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		certificates[index] = bytes.Clone(certificate.Raw)
	}

	return certificates, ctx.Err()
}
