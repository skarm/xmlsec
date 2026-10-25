package pki

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"fmt"
	"maps"
	"sort"
	"time"

	"github.com/skarm/xmlsec/internal/der"
)

func (s *HistoricalSession) initializeCertificates(ctx context.Context) error {
	if s.certificates != nil {
		return nil
	}

	certificates := make(map[[32]byte]*x509.Certificate, len(s.verifier.originalCertificates)+len(s.evidence.Intermediates))
	maps.Copy(certificates, s.verifier.originalCertificates)

	for _, raw := range s.evidence.Intermediates {
		if err := ctx.Err(); err != nil {
			return err
		}

		digest := sha256.Sum256(raw)
		if certificates[digest] != nil {
			continue
		}

		certificate, err := parseBorrowedCertificate(raw)
		if err != nil {
			return err
		}

		certificates[digest] = certificate
	}

	var responses []parsedOCSP

	for _, raw := range s.evidence.OCSPResponses {
		if err := ctx.Err(); err != nil {
			return err
		}

		parsed, err := parseOCSP(raw, s.verifier.maxBytes)
		if err != nil {
			return err
		}

		responses = append(responses, parsed)
		for _, certificate := range parsed.certs {
			certificates[sha256.Sum256(certificate.Raw)] = certificate
		}
	}

	s.responses = responses
	s.certificates = certificates

	return nil
}

func (s *HistoricalSession) historicalTarget(ctx context.Context, raw []byte) (*x509.Certificate, error) {
	if len(raw) > s.verifier.maxBytes {
		return nil, fmt.Errorf("%w: %w: historical target bytes", ErrPolicy, ErrLimit)
	}

	if err := s.initializeCertificates(ctx); err != nil {
		return nil, err
	}

	digest := sha256.Sum256(raw)
	if certificate := s.certificates[digest]; certificate != nil {
		if err := s.verifier.validateHistoricalLeaf(certificate); err != nil {
			return nil, err
		}

		return certificate, nil
	}

	if len(raw) > s.verifier.maxBytes-s.targetBytes {
		return nil, fmt.Errorf("%w: %w: historical target bytes", ErrPolicy, ErrLimit)
	}

	certificate, err := parseCertificate(raw)
	if err != nil {
		return nil, err
	}

	if err := s.verifier.validateHistoricalLeaf(certificate); err != nil {
		return nil, err
	}

	s.targetBytes += len(raw)
	s.certificates[digest] = certificate

	return certificate, nil
}

func (v *Verifier) validateHistoricalLeaf(certificate *x509.Certificate) error {
	if err := allowedPublicKey(certificate.PublicKey); err != nil {
		return err
	}

	if !allowedSignature(certificate.SignatureAlgorithm) {
		return fmt.Errorf("%w: historical leaf signature algorithm", ErrPolicy)
	}

	if certificate.IsCA && !v.allowCA {
		return historicalConstraintFailure{}
	}

	if certificate.KeyUsage&v.required != v.required {
		return historicalConstraintFailure{}
	}

	return nil
}

type historicalConstraintFailure struct{}

func (historicalConstraintFailure) Error() string {
	return "configured historical certificate usage is not satisfied"
}
func (historicalConstraintFailure) Unwrap() error { return ErrCertificate }
func historicalPathFailure(err error) string {
	var (
		configured  historicalConstraintFailure
		certificate x509.CertificateInvalidError
	)
	if errors.As(err, &configured) || errors.As(err, &certificate) && certificate.Reason == x509.IncompatibleUsage {
		return "CHAIN_CONSTRAINTS_FAILURE"
	}

	return historicalChainFailure
}

func (s *HistoricalSession) pathsFor(ctx context.Context, target *x509.Certificate) ([]*HistoricalPath, error) {
	digest := sha256.Sum256(target.Raw)
	if cached, found := s.paths[digest]; found {
		return append([]*HistoricalPath(nil), cached...), ctx.Err()
	}

	certificates := make([]*x509.Certificate, 0, len(s.certificates))
	for _, certificate := range s.certificates {
		certificates = append(certificates, certificate)
	}

	sort.Slice(certificates, func(i, j int) bool { return bytes.Compare(certificates[i].Raw, certificates[j].Raw) < 0 })

	roots := make(map[[32]byte]bool, len(s.verifier.anchorCertificates))
	for _, raw := range s.verifier.anchorCertificates {
		roots[sha256.Sum256(raw)] = true
	}

	search := historicalPathSearch{session: s, certificates: certificates, roots: roots}
	if err := search.visit(ctx, []*x509.Certificate{target}, map[[32]byte]bool{digest: true}); err != nil {
		return nil, err
	}

	s.paths[digest] = search.paths

	return append([]*HistoricalPath(nil), search.paths...), nil
}

type historicalPathSearch struct {
	session      *HistoricalSession
	certificates []*x509.Certificate
	roots        map[[32]byte]bool
	paths        []*HistoricalPath
}

func (search *historicalPathSearch) visit(ctx context.Context, chain []*x509.Certificate, seen map[[32]byte]bool) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	current := chain[len(chain)-1]
	if search.roots[sha256.Sum256(current.Raw)] {
		if len(search.paths) >= search.session.options.MaxPaths {
			return fmt.Errorf("%w: %w: historical path count", ErrPolicy, ErrLimit)
		}

		hash := sha256.New()

		for _, certificate := range chain {
			digest := sha256.Sum256(certificate.Raw)
			_, _ = hash.Write(digest[:])
		}

		var fingerprint [32]byte
		copy(fingerprint[:], hash.Sum(nil))
		search.paths = append(search.paths, &HistoricalPath{session: search.session, chain: append([]*x509.Certificate(nil), chain...), fingerprint: fingerprint})

		return nil
	}

	issuerName, err := canonicalNameKey(ctx, current.RawIssuer)
	if err != nil {
		return err
	}

	for _, issuer := range search.certificates {
		digest := sha256.Sum256(issuer.Raw)
		if seen[digest] {
			continue
		}

		subject, err := canonicalNameKey(ctx, issuer.RawSubject)
		if err != nil {
			return err
		}

		if subject != issuerName {
			continue
		}

		if len(current.AuthorityKeyId) > 0 && len(issuer.SubjectKeyId) > 0 && !bytes.Equal(current.AuthorityKeyId, issuer.SubjectKeyId) {
			continue
		}

		search.session.pathWork++
		if search.session.pathWork > 8192 {
			return fmt.Errorf("%w: %w: historical path work", ErrPolicy, ErrLimit)
		}

		if len(chain) >= search.session.verifier.maxDepth {
			return fmt.Errorf("%w: %w: historical path depth", ErrPolicy, ErrLimit)
		}

		seen[digest] = true
		if err := search.visit(ctx, append(chain, issuer), seen); err != nil {
			return err
		}

		delete(seen, digest)
	}

	return nil
}

func (s *HistoricalSession) checkPath(ctx context.Context, path *HistoricalPath) (*HistoricalPathAssessment, error) {
	return s.checkPathUsages(ctx, path, s.verifier.usages)
}

func (s *HistoricalSession) checkPathUsages(ctx context.Context, path *HistoricalPath, usages []x509.ExtKeyUsage) (*HistoricalPathAssessment, error) {
	if err := s.validPath(path); err != nil {
		return nil, err
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	if err := s.verifier.validateChainPolicy(path.chain); err != nil {
		return nil, err
	}

	s.signatureWork += len(path.chain)
	if s.signatureWork > 4096 {
		return nil, fmt.Errorf("%w: %w: historical signature work", ErrPolicy, ErrLimit)
	}

	reference, err := historicalReferenceTime(path.chain, s.options.Model)
	if err != nil {
		return nil, err
	}

	views := make([]*x509.Certificate, len(path.chain))
	for index, original := range path.chain {
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		view, err := normalizedCertificate(ctx, original)
		if err != nil {
			return nil, err
		}
		// Calendar rules were checked under the selected model above. These private
		// lookup views adapt crypto/x509's fixed shell calendar without changing the
		// original signed TBS or any returned certificate metadata.
		view.NotBefore = reference.Add(-time.Hour)
		view.NotAfter = reference.Add(time.Hour)
		views[index] = view
	}

	roots, intermediates := x509.NewCertPool(), x509.NewCertPool()
	roots.AddCert(views[len(views)-1])

	for _, view := range historicalIntermediates(views) {
		intermediates.AddCert(view)
	}

	chains, err := views[0].Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates, CurrentTime: reference, KeyUsages: append([]x509.ExtKeyUsage(nil), usages...), MaxConstraintComparisions: 100000})
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrCertificate, err)
	}

	for _, chain := range chains {
		if sameHistoricalChain(chain, path.chain) {
			return &HistoricalPathAssessment{path: path, reference: reference, model: s.options.Model}, ctx.Err()
		}
	}

	return nil, fmt.Errorf("%w: selected historical path was not validated", ErrCertificate)
}

func sameHistoricalChain(a, b []*x509.Certificate) bool {
	if len(a) != len(b) {
		return false
	}

	for index := range a {
		if !bytes.Equal(a[index].Raw, b[index].Raw) {
			return false
		}
	}

	return true
}

func historicalReferenceTime(chain []*x509.Certificate, model ValidityModel) (time.Time, error) {
	reference := chain[0].NotBefore
	if model == ChainModel {
		for index := 0; index+2 < len(chain); index++ {
			issued, err := certificateGenerationTime(chain[index])
			if err != nil {
				return time.Time{}, err
			}

			issuer := chain[index+1]
			if issued.Before(issuer.NotBefore) || issued.After(issuer.NotAfter) {
				return time.Time{}, fmt.Errorf("%w: issuer validity at certificate generation", ErrCertificate)
			}
		}

		return reference, nil
	}

	end := chain[0].NotAfter
	for _, certificate := range historicalIntermediates(chain) {
		if reference.Before(certificate.NotBefore) {
			reference = certificate.NotBefore
		}

		if end.After(certificate.NotAfter) {
			end = certificate.NotAfter
		}
	}

	if reference.After(end) {
		return time.Time{}, fmt.Errorf("%w: no common shell validity interval", ErrCertificate)
	}

	return reference, nil
}

func certificateGenerationTime(certificate *x509.Certificate) (time.Time, error) {
	for _, extension := range certificate.Extensions {
		if !extension.Id.Equal(asn1.ObjectIdentifier{1, 3, 36, 8, 3, 1}) {
			continue
		}

		value, err := der.Read(extension.Value, 64)
		if err != nil {
			return time.Time{}, ErrCertificate
		}

		at, err := generalized(value)
		if err != nil {
			return time.Time{}, errors.Join(ErrCertificate, err)
		}

		return at, nil
	}

	return certificate.NotBefore, nil
}

// FingerprintSHA256 identifies the exact ordered prospective path.
func (p *HistoricalPath) FingerprintSHA256() string {
	if p == nil || p.session == nil {
		return ""
	}

	return hex.EncodeToString(p.fingerprint[:])
}

func historicalIntermediates(chain []*x509.Certificate) []*x509.Certificate {
	if len(chain) < 3 {
		return nil
	}

	return chain[1 : len(chain)-1]
}
