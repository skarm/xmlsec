package historical

import (
	"bytes"
	"context"
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"maps"
	"slices"
	"time"

	"github.com/skarm/xmlsec/cms"
	"github.com/skarm/xmlsec/evidence"
	"github.com/skarm/xmlsec/internal/historicalproof"
	"github.com/skarm/xmlsec/internal/x509cert"
	"github.com/skarm/xmlsec/pki"
	"github.com/skarm/xmlsec/timestamp"
)

const (
	objectData                  = historicalproof.Data
	objectOCSP                  = historicalproof.OCSP
	signatureConstraintsFailure = "SIG_CONSTRAINTS_FAILURE"
	timestampOrderFailure       = "TIMESTAMP_ORDER_FAILURE"
)

// Normalize snapshots policy and checks non-PKIX workflow limits. The PKI
// session factories validate their own immutable historical options.
func Normalize(c Config) (Config, error) {
	if c.Signer == nil || c.TSA == nil || c.Signer.RevocationMode() == pki.NoRevocation || c.TSA.RevocationMode() == pki.NoRevocation {
		return c, ErrInput
	}

	if c.MaxObjects == 0 {
		c.MaxObjects = 512
	}

	if c.MaxEdges == 0 {
		c.MaxEdges = 4096
	}

	if c.MaxBytes == 0 {
		c.MaxBytes = 16 << 20
	}

	if c.MaxTimestamps == 0 {
		c.MaxTimestamps = 16
	}

	if c.MaxObjects < 1 || c.MaxObjects > 2048 || c.MaxEdges < c.MaxObjects || c.MaxEdges > 8192 || c.MaxBytes < 1 || c.MaxBytes > 64<<20 || c.MaxTimestamps < 1 || c.MaxTimestamps > 64 {
		return c, ErrLimit
	}

	for _, pointer := range []**time.Duration{&c.MissingAccuracy, &c.TimestampDelay} {
		if *pointer == nil {
			continue
		}

		value := **pointer
		if value < 0 || value > 365*24*time.Hour {
			return c, ErrInput
		}

		*pointer = &value
	}

	if c.MissingAccuracy != nil && *c.MissingAccuracy > 24*time.Hour {
		return c, ErrInput
	}

	for _, options := range []pki.HistoricalOptions{c.SignerHistory, c.TSAHistory} {
		if len(options.CryptoConstraints) > 128 || len(options.TrustAnchorSunsets) > 64 {
			return c, ErrLimit
		}
	}

	c.SignerHistory = cloneOptions(c.SignerHistory)
	c.TSAHistory = cloneOptions(c.TSAHistory)

	return c, nil
}

func cloneOptions(options pki.HistoricalOptions) pki.HistoricalOptions {
	options.CryptoConstraints = slices.Clone(options.CryptoConstraints)

	options.TrustAnchorSunsets = maps.Clone(options.TrustAnchorSunsets)
	if options.RevocationFreshness != nil {
		value := *options.RevocationFreshness
		options.RevocationFreshness = &value
	}

	return options
}

type preparedStamp struct {
	candidate   Candidate
	assertion   *timestamp.AuthenticatedToken
	upper       time.Time
	certificate *x509.Certificate
}

type validationWorkflow struct {
	ctx            context.Context
	config         Config
	input          Input
	now            time.Time
	report         *Report
	certificate    *x509.Certificate
	signerEvidence pki.Evidence
	tsaEvidence    pki.Evidence
	prepared       []preparedStamp
	signerSession  *pki.HistoricalSession
	tsaSession     *pki.HistoricalSession
	graph          *graph
	material       signedMaterial
}

func validate(ctx context.Context, c Config, input Input, now time.Time, signerEvidence, tsaEvidence pki.Evidence) (_ *Report, resultError error) {
	report := &Report{At: now, Best: now}

	defer func() {
		if resultError != nil {
			report.Cause = resultError
		}
	}()

	workflow := validationWorkflow{
		ctx: ctx, config: c, input: input, now: now, report: report,
		signerEvidence: signerEvidence, tsaEvidence: tsaEvidence,
	}
	if err := workflow.initialize(); err != nil {
		return report, err
	}

	if err := workflow.admitEvidence(); err != nil {
		return report, err
	}

	if err := workflow.prepareTimestamps(); err != nil {
		return report, err
	}

	if err := workflow.preparePaths(); err != nil {
		return report, err
	}

	if err := workflow.prepareGraph(); err != nil {
		return report, err
	}

	if err := workflow.processTimestamps(); err != nil {
		return report, err
	}

	if err := workflow.verifySigner(); err != nil {
		return report, err
	}

	if err := workflow.verifyDelay(); err != nil {
		return report, err
	}

	if err := workflow.finish(); err != nil {
		return report, err
	}

	return report, nil
}

func (w *validationWorkflow) initialize() error {
	if w.ctx == nil || w.now.IsZero() {
		return ErrInput
	}

	if err := w.ctx.Err(); err != nil {
		return err
	}

	config, err := Normalize(w.config)
	if err != nil {
		return err
	}

	w.config = config

	certificate, err := x509cert.ParseDefault(w.input.Certificate)
	if err != nil || w.input.SignatureMethod == x509.UnknownSignatureAlgorithm {
		return ErrInput
	}

	w.certificate = certificate
	if len(w.input.Hashes) > 128 {
		return ErrLimit
	}

	for _, hash := range w.input.Hashes {
		if hash == 0 || !hash.Available() {
			return ErrInput
		}
	}

	if len(w.input.Timestamps) > w.config.MaxTimestamps {
		return ErrLimit
	}

	return nil
}

// admit records an exact object at the explicit present time. Neither source
// provenance times nor SigningTime establish its earlier existence.
func (w *validationWorkflow) admit(raw []byte, kind historicalproof.Kind) {
	digest := sha256.Sum256(raw)
	for index, object := range w.input.Objects {
		if sha256.Sum256(object.Bytes) == digest {
			if object.Kind == objectData {
				w.input.Objects[index].Kind = kind
			}

			return
		}
	}

	w.input.Objects = append(w.input.Objects, Object{Bytes: raw, Kind: kind})
}

func (w *validationWorkflow) containCertificates(parent [32]byte, certificates [][]byte) {
	for _, raw := range certificates {
		w.admit(raw, historicalproof.Certificate)
	}

	for index, object := range w.input.Objects {
		if sha256.Sum256(object.Bytes) != parent {
			continue
		}

		for _, raw := range certificates {
			child := sha256.Sum256(raw)
			if !slices.Contains(w.input.Objects[index].Contains, child) {
				w.input.Objects[index].Contains = append(slices.Clone(w.input.Objects[index].Contains), child)
			}
		}

		break
	}
}

func (w *validationWorkflow) admitEvidence() error {
	w.input.Objects = slices.Clone(w.input.Objects)
	w.admit(w.input.Certificate, historicalproof.Certificate)

	for _, ev := range []pki.Evidence{w.signerEvidence, w.tsaEvidence} {
		for index, group := range [][][]byte{ev.Intermediates, ev.CRLs, ev.OCSPResponses} {
			kind := []historicalproof.Kind{historicalproof.Certificate, historicalproof.CRL, objectOCSP}[index]
			for _, raw := range group {
				w.admit(raw, kind)

				if kind != objectOCSP {
					continue
				}

				certificates, err := pki.InspectOCSPCertificates(w.ctx, raw)
				if err != nil {
					return err
				}

				w.containCertificates(sha256.Sum256(raw), certificates)
			}
		}
	}

	var err error

	w.signerEvidence, w.tsaEvidence, err = removeTimestampSources(w.input, w.signerEvidence, w.tsaEvidence)

	return err
}

func (w *validationWorkflow) prepareTimestamps() error {
	w.prepared = make([]preparedStamp, 0, len(w.input.Timestamps))
	w.tsaEvidence.Intermediates = slices.Clone(w.tsaEvidence.Intermediates)
	coverageEdges := 0

	for _, candidate := range w.input.Timestamps {
		if err := w.ctx.Err(); err != nil {
			return err
		}

		if candidate.Token == nil || len(candidate.Covered) > w.config.MaxEdges-coverageEdges {
			return ErrLimit
		}

		coverageEdges += len(candidate.Covered)
		w.admit(candidate.Token.DER(), historicalproof.Timestamp)
		w.containCertificates(sha256.Sum256(candidate.Token.DER()), candidate.Token.Certificates())

		stamp, err := w.prepareTimestamp(candidate)
		if err != nil {
			return err
		}

		if stamp != nil {
			w.prepared = append(w.prepared, *stamp)
		}
	}

	return nil
}

func (w *validationWorkflow) prepareTimestamp(candidate Candidate) (*preparedStamp, error) {
	assertion, err := w.config.TSA.Authenticate(w.ctx, candidate.Token, timestamp.Expectation{Imprint: candidate.Imprint}, w.now)
	if err != nil {
		return nil, w.rejectTimestampAuthentication(candidate, err)
	}

	w.admit(assertion.CertificateDER(), historicalproof.Certificate)

	for _, raw := range candidate.Token.Certificates() {
		w.admit(raw, historicalproof.Certificate)
		w.tsaEvidence.Intermediates = uniqueDER(w.tsaEvidence.Intermediates, raw)
	}

	cert, err := x509cert.ParseDefault(assertion.CertificateDER())
	if err != nil {
		return nil, err
	}

	accuracy, exists := assertion.Info().Accuracy()
	if !exists {
		if w.config.MissingAccuracy == nil {
			outcome := Stamp{Token: assertion.TokenSHA256(), Generation: assertion.Info().GenTime(), Archive: candidate.Archive, SubIndication: "TIMESTAMP_CONSTRAINTS_FAILURE"}

			return nil, w.rejectTimestampConstraint(outcome)
		}

		accuracy = *w.config.MissingAccuracy
	}

	upper := assertion.Info().GenTime().Add(accuracy)
	if upper.After(w.now) {
		outcome := Stamp{Token: assertion.TokenSHA256(), Generation: assertion.Info().GenTime(), Upper: upper, Archive: candidate.Archive, SubIndication: "TIMESTAMP_CONSTRAINTS_FAILURE"}

		return nil, w.rejectTimestampConstraint(outcome)
	}

	return &preparedStamp{candidate: candidate, assertion: assertion, upper: upper, certificate: cert}, nil
}

func (w *validationWorkflow) rejectTimestampAuthentication(candidate Candidate, err error) error {
	indication, sub := Indeterminate, signatureConstraintsFailure
	if errors.Is(err, cms.ErrSignature) {
		indication, sub = Failed, "SIG_CRYPTO_FAILURE"
	}

	if errors.Is(err, timestamp.ErrBinding) {
		indication, sub = Failed, "HASH_FAILURE"
	}

	w.report.Stamps = append(w.report.Stamps, Stamp{Token: sha256.Sum256(candidate.Token.DER()), Archive: candidate.Archive, Indication: indication, SubIndication: sub})
	if w.ctx.Err() != nil || errors.Is(err, pki.ErrLimit) {
		return err
	}

	if w.config.RequireAllTimestamps {
		w.report.Indication, w.report.SubIndication = indication, sub

		return errors.Join(ErrValidation, err)
	}

	return nil
}

func (w *validationWorkflow) rejectTimestampConstraint(outcome Stamp) error {
	w.report.Stamps = append(w.report.Stamps, outcome)
	if w.config.RequireAllTimestamps {
		w.report.SubIndication = signatureConstraintsFailure

		return ErrValidation
	}

	return nil
}

func (w *validationWorkflow) preparePaths() error {
	var err error

	w.signerSession, err = w.config.Signer.NewHistoricalSession(w.ctx, w.config.SignerHistory, w.now, w.signerEvidence)
	if err != nil {
		return err
	}

	w.tsaSession, err = w.config.TSA.NewHistoricalSession(w.ctx, w.config.TSAHistory, w.now, w.tsaEvidence)
	if err != nil {
		return err
	}

	// Prospective chains remain bounded by session policy. Their exact bytes are
	// observed now; only actual embedded coverage proves earlier existence.
	if err := w.admitPaths(w.signerSession, w.input.Certificate); err != nil {
		return err
	}

	for _, stamp := range w.prepared {
		if err := w.admitPaths(w.tsaSession, stamp.assertion.CertificateDER()); err != nil {
			return err
		}
	}

	return nil
}

func (w *validationWorkflow) admitPaths(session *pki.HistoricalSession, raw []byte) error {
	paths, err := session.Paths(w.ctx, raw)
	if err != nil && (w.ctx.Err() != nil || errors.Is(err, pki.ErrLimit)) {
		return err
	}

	for _, path := range paths {
		for _, certificate := range path.ChainDER() {
			w.admit(certificate, historicalproof.Certificate)
		}
	}

	return nil
}

func (w *validationWorkflow) prepareGraph() error {
	g, err := newGraph(w.ctx, w.config, w.input, w.now)
	if err != nil {
		return err
	}

	if len(w.input.Uses) > w.config.MaxEdges {
		return ErrLimit
	}

	for _, use := range w.input.Uses {
		if _, ok := g.objects[use.Object]; !ok || use.Hash == 0 || !use.Hash.Available() {
			return ErrInput
		}
	}

	w.graph = g
	w.prepared, err = orderStamps(w.ctx, g, w.prepared)

	return err
}

func (w *validationWorkflow) updateProofs() error {
	proofs, err := w.graph.set(w.ctx)
	if err != nil {
		return err
	}

	w.report.Proofs = proofs
	w.report.Best, _ = proofs.Earliest(w.input.Signature)

	return nil
}

func (w *validationWorkflow) processTimestamps() error {
	var accepted []preparedStamp

	for _, stamp := range w.prepared {
		if err := w.updateProofs(); err != nil {
			return err
		}

		passed, err := w.processTimestamp(stamp, accepted)
		if err != nil {
			return err
		}

		if passed {
			accepted = append(accepted, stamp)
		}
	}

	return w.updateProofs()
}

func (w *validationWorkflow) processTimestamp(stamp preparedStamp, accepted []preparedStamp) (bool, error) {
	outcome, err := validateStamp(w.ctx, w.config, stamp, w.now, w.tsaSession, w.report.Proofs)
	w.report.Stamps = append(w.report.Stamps, outcome)

	if err != nil {
		if w.ctx.Err() != nil || errors.Is(err, pki.ErrLimit) || errors.Is(err, ErrLimit) {
			return false, err
		}

		if w.config.RequireAllTimestamps {
			w.report.Indication, w.report.SubIndication = outcome.Indication, outcome.SubIndication

			return false, err
		}

		return false, nil
	}

	if err := checkProtectedChronology(w.ctx, w.graph, stamp, accepted); err != nil {
		w.rejectTimestampChronology()

		if w.config.RequireAllTimestamps {
			w.report.SubIndication = timestampOrderFailure

			return false, err
		}

		return false, nil
	}

	if err := checkContentChronology(stamp, accepted); err != nil {
		w.rejectTimestampChronology()
		w.report.SubIndication = timestampOrderFailure

		return false, err
	}

	if err := w.graph.extract(w.ctx, stamp.candidate, stamp.assertion.TokenSHA256(), stamp.upper); err != nil {
		return false, err
	}

	w.report.Steps = append(w.report.Steps, Step{Clause: "5.6.2.3", Action: "extract-exact-object-poe", Source: stamp.assertion.TokenSHA256(), Before: w.now, After: stamp.upper})

	return true, nil
}

func (w *validationWorkflow) rejectTimestampChronology() {
	w.report.Stamps[len(w.report.Stamps)-1].Indication = Indeterminate
	w.report.Stamps[len(w.report.Stamps)-1].SubIndication = timestampOrderFailure
}

func (w *validationWorkflow) verifySigner() error {
	if w.report.Best.Before(w.certificate.NotBefore) {
		w.report.Indication, w.report.SubIndication = Failed, "NOT_YET_VALID"

		return ErrValidation
	}

	current, currentReport, currentErr := w.config.Signer.Verify(w.ctx, w.input.Certificate, w.now, w.signerEvidence)
	if currentErr != nil && (w.ctx.Err() != nil || errors.Is(currentErr, pki.ErrLimit)) {
		return currentErr
	}

	w.material = signedMaterial{digest: w.input.Signature, certificate: w.input.Certificate, algorithm: w.input.SignatureMethod, hashes: w.input.Hashes, uses: w.input.Uses}
	policySub := ""

	var policyErr error
	if currentErr == nil {
		policySub, policyErr = w.signerSession.CheckCurrentPolicy(w.ctx, current)
	}

	if policyErr != nil && (w.ctx.Err() != nil || errors.Is(policyErr, pki.ErrLimit)) {
		return policyErr
	}

	if currentErr == nil && policyErr == nil && materialReliable(w.material, w.certificate, w.now, w.config.SignerHistory.CryptoConstraints) {
		w.report.Current, w.report.Validation = current, w.now

		return nil
	}

	sub := currentSubIndication(currentErr, currentReport, w.certificate, w.now)
	if currentErr == nil {
		sub = cryptoFailure
		if policySub != "" {
			sub = policySub
		}
	}

	past := pastSignature(w.ctx, w.signerSession, w.material, sub, w.report.Proofs, w.config.SignerHistory)
	w.report.Steps = append(w.report.Steps, past.steps...)

	if past.indication != Passed {
		w.report.Indication, w.report.SubIndication = past.indication, past.sub

		return errors.Join(ErrValidation, past.err)
	}

	w.report.Past, w.report.Path, w.report.Validation = past.result, past.result.Path(), past.result.ValidationTime()

	return nil
}

func (w *validationWorkflow) verifyDelay() error {
	hasSignatureTimestamp := false

	for _, candidate := range w.input.Timestamps {
		if !candidate.Archive && !candidate.Content {
			hasSignatureTimestamp = true
		}
	}

	if w.config.TimestampDelay == nil || !hasSignatureTimestamp {
		return nil
	}

	satisfied := false

	if w.input.ClaimedTimeAfter != nil {
		var err error

		satisfied, err = w.input.ClaimedTimeAfter(w.report.Best.Add(-*w.config.TimestampDelay))
		if err != nil {
			return err
		}
	} else if !w.input.ClaimedTime.IsZero() {
		satisfied = w.input.ClaimedTime.Add(*w.config.TimestampDelay).After(w.report.Best)
	}

	if !satisfied {
		w.report.SubIndication = signatureConstraintsFailure

		return ErrValidation
	}

	return nil
}

func (w *validationWorkflow) finish() error {
	if !historicalMaterialReliable(w.material, w.certificate, w.report.Proofs, w.config.SignerHistory.CryptoConstraints) {
		w.report.SubIndication = cryptoFailure

		return ErrValidation
	}

	if err := w.ctx.Err(); err != nil {
		return err
	}

	w.report.Indication = Passed
	w.report.Steps = append(w.report.Steps, Step{Clause: "5.6.3.4(10)", Action: "return-passed", Object: w.input.Signature, Before: w.now, After: w.report.Validation})

	return nil
}

func validateStamp(ctx context.Context, c Config, stamp preparedStamp, now time.Time, session *pki.HistoricalSession, proofs *historicalproof.Set) (Stamp, error) {
	assertion := stamp.assertion
	info := assertion.Info()
	out := Stamp{Token: assertion.TokenSHA256(), Certificate: sha256.Sum256(assertion.CertificateDER()), Generation: info.GenTime(), Upper: stamp.upper, Archive: stamp.candidate.Archive, Content: stamp.candidate.Content, Ordering: info.Ordering()}
	out.Best, _ = proofs.Earliest(out.Token)

	material := signedMaterial{digest: out.Token, certificate: assertion.CertificateDER(), algorithm: cmsAlgorithm(assertion.SignatureAlgorithmOID(), assertion.SignatureHash()), hashes: []crypto.Hash{assertion.SignatureHash(), info.Imprint().Hash}}
	if material.algorithm == x509.UnknownSignatureAlgorithm {
		out.SubIndication = "SIG_CRYPTO_FAILURE"
		return out, ErrValidation
	}

	trusted, currentReport, err := session.VerifyCurrent(ctx, assertion.CertificateDER())
	policySub := ""

	var policyErr error
	if err == nil {
		policySub, policyErr = session.CheckCurrentPolicy(ctx, trusted)
	}

	if err != nil && (ctx.Err() != nil || errors.Is(err, pki.ErrLimit)) {
		return out, err
	}

	if policyErr != nil && (ctx.Err() != nil || errors.Is(policyErr, pki.ErrLimit)) {
		return out, policyErr
	}

	if err == nil && policyErr == nil && materialReliable(material, stamp.certificate, now, c.TSAHistory.CryptoConstraints) {
		out.Validation = now
	} else {
		sub := currentSubIndication(err, currentReport, stamp.certificate, now)
		if err == nil {
			sub = cryptoFailure
			if policySub != "" {
				sub = policySub
			}
		}

		past := pastSignature(ctx, session, material, sub, proofs, c.TSAHistory)
		if past.indication != Passed {
			out.Indication, out.SubIndication = past.indication, past.sub
			return out, errors.Join(ErrValidation, past.err)
		}

		out.Path, out.Validation = past.result.Path(), past.result.ValidationTime()
	}
	// §5.6.3.4(5b/c): the imprint hash must still be reliable at a separately
	// proven time of the token. GenTime itself cannot prove its own token existed.
	if !hashReliable(info.Imprint().Hash, out.Best, c.TSAHistory.CryptoConstraints) {
		out.SubIndication = cryptoFailure
		return out, ErrValidation
	}

	out.Indication = Passed

	return out, nil
}

func currentSubIndication(err error, report pki.Report, certificate *x509.Certificate, now time.Time) string {
	if certificate != nil && (now.Before(certificate.NotBefore) || now.After(certificate.NotAfter)) {
		return outOfBounds
	}

	if errors.Is(err, pki.ErrRevoked) {
		if certificate != nil && suspended(certificate.Raw, report.Evidence()) {
			return tryLater
		}

		target := sha256.Sum256(certificate.Raw)
		for _, assertion := range report.Evidence() {
			if assertion.AssertedStatus() == "revoked" && decodeDigest(assertion.TargetCertificateSHA256()) != target {
				return revokedCA
			}
		}

		return revoked
	}

	if errors.Is(err, pki.ErrUnavailable) {
		return tryLater
	}

	if errors.Is(err, pki.ErrCertificate) || errors.Is(err, timestamp.ErrTrust) {
		return noChain
	}

	return "CHAIN_CONSTRAINTS_FAILURE"
}

func removeTimestampSources(input Input, groups ...pki.Evidence) (pki.Evidence, pki.Evidence, error) {
	allowed := make(map[[32]byte]struct{}, len(input.Timestamps))
	for _, candidate := range input.Timestamps {
		if candidate.Token != nil {
			allowed[sha256.Sum256(candidate.Token.DER())] = struct{}{}
		}
	}

	for index := range groups {
		var sources []*evidence.Observation

		for _, source := range groups[index].Sources {
			if source == nil || !source.Valid() {
				return pki.Evidence{}, pki.Evidence{}, ErrInput
			}

			if source.Kind() == evidence.Timestamp {
				if _, exists := allowed[source.DigestSHA256()]; !exists {
					return pki.Evidence{}, pki.Evidence{}, ErrInput
				}
			} else {
				sources = append(sources, source)
			}
		}

		groups[index].Sources = sources
	}

	return groups[0], groups[1], nil
}

func uniqueDER(existing [][]byte, raw []byte) [][]byte {
	for _, previous := range existing {
		if bytes.Equal(previous, raw) {
			return existing
		}
	}

	return append(existing, raw)
}
