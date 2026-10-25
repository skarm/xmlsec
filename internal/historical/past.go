package historical

import (
	"context"
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"time"

	"github.com/skarm/xmlsec/internal/historicalproof"
	"github.com/skarm/xmlsec/internal/x509cert"
	"github.com/skarm/xmlsec/pki"
)

const (
	noChain          = "NO_CERTIFICATE_CHAIN_FOUND_NO_POE"
	outOfBounds      = "OUT_OF_BOUNDS_NO_POE"
	outNotRevoked    = "OUT_OF_BOUNDS_NOT_REVOKED"
	revoked          = "REVOKED_NO_POE"
	revokedCA        = "REVOKED_CA_NO_POE"
	revocationBounds = "REVOCATION_OUT_OF_BOUNDS_NO_POE"
	cryptoFailure    = "CRYPTO_CONSTRAINTS_FAILURE_NO_POE"
	tryLater         = "TRY_LATER"
	proofCertificate = historicalproof.Certificate
	assertedRevoked  = "revoked"
)

type signedMaterial struct {
	digest      [32]byte
	certificate []byte
	algorithm   x509.SignatureAlgorithm
	hashes      []crypto.Hash
	uses        []MaterialUse
}

type pastOutcome struct {
	indication Indication
	sub        string
	best       time.Time
	result     *pki.PastCertificateResult
	steps      []Step
	err        error
}

type pastSignatureEvaluation struct {
	material    signedMaterial
	current     string
	proofs      *historicalproof.Set
	options     pki.HistoricalOptions
	certificate *x509.Certificate
}

// pastSignature applies §5.6.2.4 after current-time validation failed with a
// recoverable indication. Exact path alternatives are tried independently.
func pastSignature(ctx context.Context, session *pki.HistoricalSession, material signedMaterial, current string, proofs *historicalproof.Set, options pki.HistoricalOptions) pastOutcome {
	out := pastOutcome{sub: current, err: ErrValidation}
	if proofs == nil || !proofs.Valid() || !recoverable(current) {
		return out
	}

	best, exists := proofs.Earliest(material.digest)
	if !exists {
		return out
	}

	out.best = best

	certificate, err := x509cert.ParseDefault(material.certificate)
	if err != nil {
		out.err = err
		return out
	}

	paths, err := session.Paths(ctx, material.certificate)
	if err != nil {
		out.err = err
		return out
	}

	evaluation := pastSignatureEvaluation{material: material, current: current, proofs: proofs, options: options, certificate: certificate}

	for _, path := range paths {
		if err := ctx.Err(); err != nil {
			out.err = err
			return out
		}

		if evaluation.evaluatePath(ctx, session, path, &out) {
			return out
		}
	}

	return out
}

func (e *pastSignatureEvaluation) evaluatePath(ctx context.Context, session *pki.HistoricalSession, path *pki.HistoricalPath, out *pastOutcome) bool {
	past, report, err := session.ValidatePastPath(ctx, path, e.proofs)
	appendPastTransitions(out, report)

	if err != nil || past == nil {
		out.err = errors.Join(ErrValidation, err)
		return false
	}

	claims := past.Evidence()

	accept, terminal := e.acceptsPast(out, past, claims)
	if terminal {
		return true
	}

	if !accept {
		return false
	}
	// §5.6.2.4(7) retains the separately calculated issuer-certificate PoE
	// outcome. A good signature proof alone cannot repair its absence.
	if !issuerRevocationProof(path, e.material.certificate, claims, e.proofs) {
		out.sub, out.err = revocationBounds, ErrValidation
		return false
	}

	if !historicalMaterialReliable(e.material, e.certificate, e.proofs, e.options.CryptoConstraints) {
		out.sub, out.err = cryptoFailure, ErrValidation
		return false
	}

	out.indication, out.sub, out.result, out.err = Passed, "", past, nil
	out.steps = append(out.steps, Step{Clause: "5.6.2.4(7)", Action: "past-signature-validation", Object: e.material.digest, Before: e.proofs.Now(), After: past.ValidationTime()})

	return true
}

func appendPastTransitions(out *pastOutcome, report *pki.PastCertificateReport) {
	if report == nil {
		return
	}

	for _, transition := range report.Transitions() {
		out.steps = append(out.steps, Step{Clause: transition.Clause, Action: transition.Reason, Object: decodeDigest(transition.CertificateSHA256), Source: decodeDigest(transition.EvidenceSHA256), Before: transition.Before, After: transition.After, SubIndication: report.SubIndication()})
	}
}

func (e *pastSignatureEvaluation) acceptsPast(out *pastOutcome, past *pki.PastCertificateResult, claims []*pki.VerifiedEvidence) (bool, bool) {
	signaturePOE := e.proofs.HasAtOrBefore(e.material.digest, past.ValidationTime())
	accept := false

	if signaturePOE {
		var terminal bool

		accept, terminal = e.signatureProofRecovery(out, claims)
		if terminal {
			return false, true
		}
	}

	if e.current == cryptoFailure {
		accept = historicalMaterialReliable(e.material, e.certificate, e.proofs, e.options.CryptoConstraints)
	}

	if e.current == tryLater && signaturePOE {
		if suspended(e.material.certificate, claims) {
			return knownRevocationRecovery(out, e.certificate)
		}

		accept = freshForSignature(e.material.certificate, claims, out.best, e.options.RevocationFreshness)
	}

	return accept, false
}

func (e *pastSignatureEvaluation) signatureProofRecovery(out *pastOutcome, claims []*pki.VerifiedEvidence) (bool, bool) {
	switch e.current {
	case noChain:
		if rejectBeforeIssuance(out, e.certificate) {
			return false, true
		}

		if out.best.After(e.certificate.NotAfter) {
			out.sub = outOfBounds
			return false, false
		}

		return true, false
	case revoked, revocationBounds:
		return knownRevocationRecovery(out, e.certificate)
	case revokedCA:
		if !hasPreCARevocationProof(e.material.certificate, claims, e.proofs) {
			return false, false
		}

		if withinCertificate(out.best, e.certificate) {
			return true, false
		}

		out.sub = outNotRevoked
	case outOfBounds, outNotRevoked:
		if rejectBeforeIssuance(out, e.certificate) {
			return false, true
		}
		// This specific branch requires strict after/before bounds; the no-chain
		// and known-revocation branches intentionally retain inclusive validity.
		return out.best.After(e.certificate.NotBefore) && out.best.Before(e.certificate.NotAfter), false
	}

	return false, false
}

func rejectBeforeIssuance(out *pastOutcome, certificate *x509.Certificate) bool {
	if !out.best.Before(certificate.NotBefore) {
		return false
	}

	out.indication, out.sub = Failed, "NOT_YET_VALID"

	return true
}

func withinCertificate(at time.Time, certificate *x509.Certificate) bool {
	return !at.Before(certificate.NotBefore) && !at.After(certificate.NotAfter)
}

func knownRevocationRecovery(out *pastOutcome, certificate *x509.Certificate) (bool, bool) {
	if rejectBeforeIssuance(out, certificate) {
		return false, true
	}

	if withinCertificate(out.best, certificate) {
		return true, false
	}

	out.sub = outNotRevoked

	return false, false
}

func historicalMaterialReliable(material signedMaterial, certificate *x509.Certificate, proofs *historicalproof.Set, rules []pki.CryptoConstraint) bool {
	best, ok := proofs.Earliest(material.digest)
	if !ok || !signatureReliable(material.algorithm, 0, certificate, best, rules) {
		return false
	}

	if len(material.uses) == 0 {
		for _, hash := range material.hashes {
			if !hashReliable(hash, best, rules) {
				return false
			}
		}

		return true
	}

	for _, use := range material.uses {
		at, exists := proofs.Earliest(use.Object)
		if !exists || !hashReliable(use.Hash, at, rules) {
			return false
		}
	}

	return true
}

func recoverable(sub string) bool {
	return sub == noChain || sub == outOfBounds || sub == outNotRevoked || sub == revoked || sub == revokedCA || sub == revocationBounds || sub == cryptoFailure || sub == tryLater
}

func materialReliable(material signedMaterial, certificate *x509.Certificate, at time.Time, rules []pki.CryptoConstraint) bool {
	if !signatureReliable(material.algorithm, 0, certificate, at, rules) {
		return false
	}

	for _, hash := range material.hashes {
		if !hashReliable(hash, at, rules) {
			return false
		}
	}

	return true
}

func issuerRevocationProof(path *pki.HistoricalPath, target []byte, claims []*pki.VerifiedEvidence, proofs *historicalproof.Set) bool {
	chain := path.ChainDER()
	if len(chain) < 2 {
		return false
	}

	issuer, err := x509cert.ParseDefault(chain[1])
	if err != nil {
		return false
	}

	digest := sha256.Sum256(chain[1])
	hasIssuer := false

	for _, fact := range proofs.Facts() {
		if fact.Digest == digest && fact.Kind == proofCertificate && fact.At.After(issuer.NotBefore) && fact.At.Before(issuer.NotAfter) {
			hasIssuer = true
			break
		}
	}

	if !hasIssuer {
		return false
	}

	targetHash := sha256.Sum256(target)

	issuerHash := sha256.Sum256(issuer.RawSubjectPublicKeyInfo)
	for _, claim := range claims {
		if claim.AuthenticationStatus() == pki.Valid && decodeDigest(claim.TargetCertificateSHA256()) == targetHash && decodeDigest(claim.IssuerSPKISHA256()) == issuerHash {
			return true
		}
	}

	return false
}

func hasPreCARevocationProof(target []byte, claims []*pki.VerifiedEvidence, proofs *historicalproof.Set) bool {
	targetHash := sha256.Sum256(target)
	for _, ca := range claims {
		if ca.AssertedStatus() != assertedRevoked || decodeDigest(ca.TargetCertificateSHA256()) == targetHash {
			continue
		}

		for _, leaf := range claims {
			if decodeDigest(leaf.TargetCertificateSHA256()) == targetHash && proofs.HasAtOrBefore(decodeDigest(leaf.FingerprintSHA256()), ca.RevokedAt()) {
				return true
			}
		}
	}

	return false
}

func freshForSignature(target []byte, claims []*pki.VerifiedEvidence, at time.Time, maximum *time.Duration) bool {
	targetHash := sha256.Sum256(target)
	dependencies := make(map[string]struct{})

	for _, claim := range claims {
		if decodeDigest(claim.TargetCertificateSHA256()) != targetHash {
			continue
		}

		for _, dependency := range claim.Dependencies() {
			dependencies[dependency] = struct{}{}
		}
	}

	checked := false

	for _, claim := range claims {
		if decodeDigest(claim.TargetCertificateSHA256()) != targetHash {
			continue
		}

		if _, exists := dependencies[claim.FingerprintSHA256()]; exists {
			continue
		}

		checked = true

		var age time.Duration
		if maximum != nil {
			age = *maximum
		} else {
			if claim.NextUpdate().IsZero() {
				return false
			}

			age = claim.NextUpdate().Sub(claim.ThisUpdate())
		}

		if age < 0 || !claim.ThisUpdate().After(at.Add(-age)) {
			return false
		}
	}

	return checked
}

func suspended(target []byte, claims []*pki.VerifiedEvidence) bool {
	targetHash := sha256.Sum256(target)

	for _, claim := range claims {
		reason, ok := claim.RevocationReason()
		if ok && reason == 6 && claim.AssertedStatus() == assertedRevoked && decodeDigest(claim.TargetCertificateSHA256()) == targetHash {
			return true
		}
	}

	return false
}

func decodeDigest(value string) [32]byte {
	var digest [32]byte
	if len(value) == 64 {
		if _, err := hex.Decode(digest[:], []byte(value)); err != nil {
			return [32]byte{}
		}
	}

	return digest
}
