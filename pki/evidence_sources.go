package pki

import (
	"context"
	"crypto/sha256"
	"fmt"

	"github.com/skarm/xmlsec/evidence"
)

type evidenceBinding struct {
	kind evidence.Kind
	hash [32]byte
}

func (v *Verifier) validatedSources(ctx context.Context, leaf []byte, input Evidence) (map[evidenceBinding][]*evidence.Observation, error) {
	if len(input.Sources) > 1024 {
		return nil, ErrPolicy
	}

	allowed := make(map[evidenceBinding]struct{})
	add := func(kind evidence.Kind, values [][]byte) error {
		for _, raw := range values {
			if err := ctx.Err(); err != nil {
				return err
			}

			allowed[evidenceBinding{kind: kind, hash: sha256.Sum256(raw)}] = struct{}{}
		}

		return nil
	}

	if len(input.Sources) == 0 {
		return nil, nil
	}

	for _, group := range []struct {
		kind   evidence.Kind
		values [][]byte
	}{{evidence.Certificate, [][]byte{leaf}}, {evidence.Certificate, v.issuerCertificates}, {evidence.Certificate, input.Intermediates}, {evidence.CRL, input.CRLs}, {evidence.OCSP, input.OCSPResponses}} {
		if err := add(group.kind, group.values); err != nil {
			return nil, err
		}
	}

	for _, authority := range v.ocspOptions.Authorities {
		if err := add(evidence.Certificate, [][]byte{authority.ResponderCertificateDER, authority.IssuerCertificateDER}); err != nil {
			return nil, err
		}
	}

	sources := make(map[evidenceBinding][]*evidence.Observation)
	total := 0

	for _, source := range input.Sources {
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		if source == nil || !source.Valid() {
			return nil, ErrEvidence
		}

		if source.Size() > v.maxBytes-total {
			return nil, fmt.Errorf("%w: source observation bytes", ErrPolicy)
		}

		total += source.Size()

		key := evidenceBinding{kind: source.Kind(), hash: source.DigestSHA256()}
		if _, exists := allowed[key]; !exists {
			return nil, fmt.Errorf("%w: unmatched evidence source kind/digest", ErrEvidence)
		}

		sources[key] = append(sources[key], source)
	}

	return sources, nil
}

func bindVerifiedSources(items []*VerifiedEvidence, sources map[evidenceBinding][]*evidence.Observation) {
	for _, item := range items {
		kind := evidence.Kind(item.kind)
		if matched := sources[evidenceBinding{kind: kind, hash: item.fingerprint}]; len(matched) != 0 {
			item.sources = append([]*evidence.Observation(nil), matched...)
			item.raw = nil
		}
	}
}
