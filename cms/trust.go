package cms

import (
	"context"
	"crypto/sha256"
	"encoding/asn1"
	"fmt"
	"io"
	"time"

	"github.com/skarm/xmlsec/internal/der"
	"github.com/skarm/xmlsec/pki"
)

// TrustOptions selects an immutable PKIX and offline revocation verifier and an
// explicit validation time. Embedded certificates are untrusted path candidates.
// The caller supplies trust anchors through Verifier; CMS SigningTime cannot
// supply a trusted validation time.
type TrustOptions struct {
	// Verifier supplies the required signer trust and offline revocation policy.
	Verifier *pki.Verifier
	// VerificationTime is the explicit time for certificate validation. It must be nonzero.
	VerificationTime time.Time
	// Evidence supplies untrusted intermediates and offline revocation data for signer
	// validation.
	Evidence pki.Evidence
}

// VerifyWithTrust authenticates all content/signers and then applies the supplied
// trust policy to every exact signer certificate. No Result is returned if any
// signature, binding, chain, usage or required revocation check fails.
// A verifier configured with NoRevocation still reports revocation NotChecked.
func (s *SignedData) VerifyWithTrust(ctx context.Context, expected [][]byte, opt VerifyOptions, trust TrustOptions) (*Result, error) {
	if trust.Verifier == nil || trust.VerificationTime.IsZero() {
		return nil, ErrPolicy
	}

	result, err := s.Verify(ctx, expected, opt)
	if err != nil {
		return nil, err
	}

	return s.applyTrust(ctx, result, trust)
}

// VerifyReaderWithTrust has VerifyWithTrust's all-signer trust semantics while
// consuming detached content once without retaining it. src remains open.
func (s *SignedData) VerifyReaderWithTrust(ctx context.Context, src io.Reader, expected [][]byte, opt VerifyOptions, trust TrustOptions) (*Result, error) {
	if trust.Verifier == nil || trust.VerificationTime.IsZero() {
		return nil, ErrPolicy
	}

	result, err := s.VerifyReader(ctx, src, expected, opt)
	if err != nil {
		return nil, err
	}

	return s.applyTrust(ctx, result, trust)
}

func (s *SignedData) applyTrust(ctx context.Context, result *Result, options TrustOptions) (*Result, error) {
	evidence, err := s.signerTrustEvidence(ctx, options.Evidence)
	if err != nil {
		return nil, err
	}

	for i := range result.signers {
		signer := &result.signers[i]
		if err := unrestrictedESSBinding(signer.signed); err != nil {
			return nil, err
		}

		trusted, _, err := options.Verifier.Verify(ctx, signer.certificate, options.VerificationTime, evidence)
		if err != nil {
			return nil, fmt.Errorf("%w: signer%d: %w", ErrTrust, i, err)
		}

		signer.trust = trusted
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	return result, nil
}

func (s *SignedData) signerTrustEvidence(ctx context.Context, evidence pki.Evidence) (pki.Evidence, error) {
	if len(evidence.Intermediates) > 64 || len(evidence.CRLs) > 256 || len(evidence.OCSPResponses) > 256 {
		return pki.Evidence{}, ErrPolicy
	}

	remaining := 64 << 20

	for _, group := range [][][]byte{evidence.Intermediates, evidence.CRLs, evidence.OCSPResponses} {
		for _, raw := range group {
			if len(raw) > remaining {
				return pki.Evidence{}, ErrPolicy
			}

			remaining -= len(raw)
		}
	}

	merged := evidence
	merged.Intermediates = make([][]byte, 0, min(64, len(evidence.Intermediates)+len(s.certificates)))
	seen := make(map[[sha256.Size]byte]struct{})

	for _, group := range [][][]byte{evidence.Intermediates, s.certificates} {
		for _, candidate := range group {
			if err := ctx.Err(); err != nil {
				return pki.Evidence{}, err
			}

			if len(candidate) > 1<<20 {
				return pki.Evidence{}, ErrPolicy
			}

			digest := sha256.Sum256(candidate)
			if _, exists := seen[digest]; exists {
				continue
			}

			seen[digest] = struct{}{}

			if len(merged.Intermediates) == 64 {
				return pki.Evidence{}, ErrPolicy
			}

			merged.Intermediates = append(merged.Intermediates, candidate)
		}
	}

	return merged, nil
}

// TrustChecked reports whether the configured PKIX/revocation policy passed for
// every signer. It is false for ordinary cryptographic Verify results. Individual
// trust results retain whether revocation was required or deliberately unchecked.
func (r *Result) TrustChecked() bool {
	if r == nil || len(r.signers) == 0 {
		return false
	}

	for _, signer := range r.signers {
		if signer.trust == nil {
			return false
		}
	}

	return true
}

// Evidence returns immutable authenticated revocation assertions retained by the
// successful signer trust checks. Ordinary Verify results return nil. Assertions
// retain certificate/scope bindings; they do not establish trust at other times.
func (r *Result) Evidence() []*pki.VerifiedEvidence {
	if r == nil {
		return nil
	}

	type identity struct {
		fingerprint string
		target      string
		scope       string
		signer      string
		issuer      string
		validation  time.Time
	}

	seen := make(map[identity]struct{})

	var out []*pki.VerifiedEvidence

	for _, signer := range r.signers {
		if signer.trust == nil {
			continue
		}

		for _, assertion := range signer.trust.Evidence() {
			key := identity{assertion.FingerprintSHA256(), assertion.TargetCertificateSHA256(), assertion.IssuerScopeBinding(), assertion.SignerCertificateSHA256(), assertion.IssuerSPKISHA256(), assertion.ValidationTime()}
			if _, exists := seen[key]; exists {
				continue
			}

			seen[key] = struct{}{}

			out = append(out, assertion)
		}
	}

	return out
}

// Trust returns the successfully checked caller-selected PKIX/revocation result,
// or nil for a signer authenticated only by ordinary CMS Verify/VerifyReader.
func (r SignerResult) Trust() *pki.Result { return r.trust }

// The crypto-only API binds the first certificate. A trusted result cannot
// silently ignore signed restrictions on the rest of the certification path.
func unrestrictedESSBinding(attrs []Attribute) error {
	for _, oid := range []asn1.ObjectIdentifier{oidSigningCertificate(), oidSigningCertificateV2()} {
		raw, present, err := attributeValue(attrs, oid)
		if err != nil {
			return err
		}

		if !present {
			continue
		}

		value, err := der.Read(raw, 1<<20)
		if err != nil {
			return ErrSyntax
		}

		fields, err := der.Sequence(value, 1, 2)
		if err != nil {
			return ErrSyntax
		}

		ids, err := der.Sequence(fields[0], 1, 32)
		if err != nil {
			return ErrSyntax
		}

		if len(ids) > 1 {
			return fmt.Errorf("%w: ESS certification-path restrictions", ErrUnsupported)
		}
	}

	return nil
}
