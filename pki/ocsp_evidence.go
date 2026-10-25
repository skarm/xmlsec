package pki

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"time"

	"github.com/skarm/xmlsec/evidence"
)

// A source snapshot is shared by all certificate-bound assertions derived from
// that response. Standalone verification already owns its response buffer.
type ocspSource struct {
	sources      []*evidence.Observation
	input, owned []byte
	fingerprint  [sha256.Size]byte
	captured     bool
}

func (s *ocspSource) capture() ([]byte, [sha256.Size]byte) {
	if !s.captured {
		if len(s.sources) != 0 {
			s.fingerprint = s.sources[0].DigestSHA256()
			s.captured = true

			return nil, s.fingerprint
		}

		if s.owned == nil {
			s.owned = bytes.Clone(s.input)
		}

		s.fingerprint = sha256.Sum256(s.owned)
		s.captured = true
	}

	return s.owned, s.fingerprint
}

func newOCSPEvidence(v *ocspVerification, entry *singleResponse, at time.Time) *VerifiedEvidence {
	raw, fingerprint := v.source.capture()
	scope := sha256.Sum256(encodeCertID(entry.id))

	dependencies := make([]string, 0, len(v.dependencies))
	for _, dependency := range v.dependencies {
		dependencies = append(dependencies, dependency.FingerprintSHA256())
	}

	return &VerifiedEvidence{revoked: entry.revoked, reason: entry.reason, signatureOID: v.parsed.alg.Algorithm.String(), sources: append([]*evidence.Observation(nil), v.source.sources...), dependencies: dependencies, authenticated: true, kind: EvidenceOCSP, raw: raw, fingerprint: fingerprint, target: sha256.Sum256(v.certificate.Raw), issuer: sha256.Sum256(v.issuer.RawSubjectPublicKeyInfo), signer: sha256.Sum256(v.responder.Raw), issued: v.parsed.produced, this: entry.this, next: entry.next, validation: at, status: string(entry.status), scope: hex.EncodeToString(scope[:])}
}

// Evidence returns immutable authenticated assertions, including stale or
// revoked/unknown diagnostic claims. It does not turn an error into success.
func (r OCSPReport) Evidence() []*VerifiedEvidence {
	return append([]*VerifiedEvidence(nil), r.evidence...)
}

// Evidence returns the original authenticated OCSP assertion and any retained
// authorization dependencies. The returned slice is owned by the caller.
func (r *OCSPResult) Evidence() []*VerifiedEvidence {
	if r == nil {
		return nil
	}

	return r.report.Evidence()
}

func appendOCSPEvidence(dst []*VerifiedEvidence, values ...*VerifiedEvidence) []*VerifiedEvidence {
	for _, value := range values {
		duplicate := false

		for _, old := range dst {
			if old.fingerprint == value.fingerprint && old.target == value.target && old.scope == value.scope && old.signer == value.signer && old.issuer == value.issuer && old.validation.Equal(value.validation) {
				duplicate = true
				break
			}
		}

		if !duplicate {
			dst = append(dst, value)
		}
	}

	return dst
}

// Responder CRLs are parsed and snapshotted once across all target certificates
// and candidate paths of one verification operation.
type ocspResponderEvidence struct {
	raw         [][]byte
	sources     map[evidenceBinding][]*evidence.Observation
	lists       []*parsedCRL
	initialized bool
	err         error
}

func (e *ocspResponderEvidence) parsed(ctx context.Context) ([]*parsedCRL, error) {
	if !e.initialized {
		e.initialized = true

		e.lists, e.err = parseCRLs(ctx, e.raw)
		for _, list := range e.lists {
			list.sources = e.sources[evidenceBinding{kind: evidence.CRL, hash: sha256.Sum256(list.raw)}]
		}
	}

	return e.lists, e.err
}
