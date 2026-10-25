package pki

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"sort"
	"time"

	"github.com/skarm/xmlsec/evidence"
)

// EvidenceKind identifies the encoding of an authenticated offline assertion.
type EvidenceKind string

const (
	// EvidenceCRL identifies an original signed CertificateList.
	EvidenceCRL EvidenceKind = "crl"
	// EvidenceOCSP identifies an original signed BasicOCSPResponse envelope.
	EvidenceOCSP EvidenceKind = "ocsp"
)

// VerifiedEvidence is an immutable authenticated assertion bound to an exact
// target certificate, issuer and scope. Only package verification creates it.
// Authentication at ValidationTime does not establish freshness at another time,
// certificate issuance, historical proof of existence or general PKIX trust.
// Result includes an assertion only after its required freshness/coverage policy
// passes. Report can also expose authenticated but stale or inapplicable evidence.
type VerifiedEvidence struct {
	revoked, invalidity                 time.Time
	issued, this, next, validation      time.Time
	signatureOID                        string
	kind                                EvidenceKind
	status                              string
	scope                               string
	sources                             []*evidence.Observation
	raw                                 []byte
	dependencies                        []string
	reason                              int
	scopeReasons, coverage              crlReasonMask
	fingerprint, target, issuer, signer [32]byte
	authenticated                       bool
}

// Kind returns the original evidence encoding.
func (e *VerifiedEvidence) Kind() EvidenceKind {
	if e == nil {
		return ""
	}

	return e.kind
}

// DER returns an owned copy of the exact authenticated source bytes.
func (e *VerifiedEvidence) DER() []byte {
	if e == nil {
		return nil
	}

	if len(e.sources) != 0 {
		return e.sources[0].Bytes()
	}

	return bytes.Clone(e.raw)
}

// FingerprintSHA256 identifies the exact original evidence bytes.
func (e *VerifiedEvidence) FingerprintSHA256() string {
	if e == nil {
		return ""
	}

	return hex.EncodeToString(e.fingerprint[:])
}

// TargetCertificateSHA256 binds the assertion to one exact certificate encoding.
func (e *VerifiedEvidence) TargetCertificateSHA256() string {
	if e == nil {
		return ""
	}

	return hex.EncodeToString(e.target[:])
}

// IssuerSPKISHA256 identifies the certificate issuer's public key.
func (e *VerifiedEvidence) IssuerSPKISHA256() string {
	if e == nil {
		return ""
	}

	return hex.EncodeToString(e.issuer[:])
}

// SignerCertificateSHA256 identifies the authenticated evidence signer certificate.
func (e *VerifiedEvidence) SignerCertificateSHA256() string {
	if e == nil {
		return ""
	}

	return hex.EncodeToString(e.signer[:])
}

// IssuedAt returns producedAt for OCSP and thisUpdate for a CRL.
func (e *VerifiedEvidence) IssuedAt() time.Time {
	if e == nil {
		return time.Time{}
	}

	return e.issued
}

// ThisUpdate returns the assertion's original status reference time.
func (e *VerifiedEvidence) ThisUpdate() time.Time {
	if e == nil {
		return time.Time{}
	}

	return e.this
}

// NextUpdate returns the original upper validity hint, or zero when absent.
func (e *VerifiedEvidence) NextUpdate() time.Time {
	if e == nil {
		return time.Time{}
	}

	return e.next
}

// ValidationTime is the explicit time used to authenticate the issuer/path.
func (e *VerifiedEvidence) ValidationTime() time.Time {
	if e == nil {
		return time.Time{}
	}

	return e.validation
}

// AuthenticationStatus reports authentication, not freshness or trust at any time.
func (e *VerifiedEvidence) AuthenticationStatus() Status {
	if e == nil || !e.authenticated {
		return NotChecked
	}

	return Valid
}

// AssertedStatus returns the authenticated assertion, not a certificate trust result.
func (e *VerifiedEvidence) AssertedStatus() string {
	if e == nil {
		return ""
	}

	return e.status
}

// IssuerScopeBinding identifies the exact issuer/scope context used in checking.
func (e *VerifiedEvidence) IssuerScopeBinding() string {
	if e == nil {
		return ""
	}

	return e.scope
}

// Dependencies returns original-source fingerprints used in a composite assertion.
func (e *VerifiedEvidence) Dependencies() []string {
	if e == nil {
		return nil
	}

	return append([]string(nil), e.dependencies...)
}

// Evidence returns immutable authenticated assertions used by the successful
// configured policy. The returned slice can be modified without affecting r.
func (r *Result) Evidence() []*VerifiedEvidence {
	if r == nil {
		return nil
	}

	return append([]*VerifiedEvidence(nil), r.evidence...)
}

// Evidence returns authenticated diagnostics, including stale assertions. It
// does not turn a failed verification report into a successful Result.
func (r Report) Evidence() []*VerifiedEvidence {
	return append([]*VerifiedEvidence(nil), r.evidence...)
}

func newCRLEvidence(list *parsedCRL, target, issuer, signer *x509.Certificate, at time.Time) *VerifiedEvidence {
	if len(list.sources) == 0 && list.ownedRaw == nil {
		list.ownedRaw = bytes.Clone(list.raw)
	}

	scopeData := append([]byte(list.issuerKey), list.scope.raw...)
	scope := sha256.Sum256(scopeData)

	return &VerifiedEvidence{authenticated: true, signatureOID: list.algorithm.Algorithm.String(), scopeReasons: list.scope.reasons, sources: append([]*evidence.Observation(nil), list.sources...), kind: EvidenceCRL, raw: list.ownedRaw, fingerprint: sha256.Sum256(list.raw), target: sha256.Sum256(target.Raw), issuer: sha256.Sum256(issuer.RawSubjectPublicKeyInfo), signer: sha256.Sum256(signer.Raw), issued: list.this, this: list.this, next: list.next, validation: at, status: "not-listed", scope: hex.EncodeToString(scope[:])}
}

func canonicalEvidence(items []*VerifiedEvidence) []*VerifiedEvidence {
	byBinding := make(map[string]*VerifiedEvidence, len(items))

	keys := make([]string, 0, len(items))
	for _, item := range items {
		if item == nil || !item.authenticated {
			continue
		}

		key := item.FingerprintSHA256() + "/" + item.TargetCertificateSHA256() + "/" + item.IssuerScopeBinding() + "/" + item.SignerCertificateSHA256() + "/" + item.IssuerSPKISHA256() + "/" + item.validation.UTC().Format(time.RFC3339Nano)
		if previous := byBinding[key]; previous == nil {
			keys = append(keys, key)
			byBinding[key] = item
		} else {
			merged := *previous
			merged.coverage |= item.coverage

			dependencies := make(map[string]bool, len(previous.dependencies)+len(item.dependencies))
			for _, dependency := range previous.dependencies {
				dependencies[dependency] = true
			}

			for _, dependency := range item.dependencies {
				dependencies[dependency] = true
			}

			merged.dependencies = make([]string, 0, len(dependencies))
			for dependency := range dependencies {
				merged.dependencies = append(merged.dependencies, dependency)
			}

			sort.Strings(merged.dependencies)
			byBinding[key] = &merged
		}
	}

	sort.Strings(keys)

	out := make([]*VerifiedEvidence, 0, len(keys))
	for _, key := range keys {
		out = append(out, byBinding[key])
	}

	return out
}

// Sources returns owned observations as immutable pointers. Their transport
// provenance remains untrusted and is never proof of existence or authority.
func (e *VerifiedEvidence) Sources() []*evidence.Observation {
	if e == nil {
		return nil
	}

	return append([]*evidence.Observation(nil), e.sources...)
}

// RevokedAt returns the signed revocation-time claim, or zero when not asserted.
func (e *VerifiedEvidence) RevokedAt() time.Time {
	if e == nil {
		return time.Time{}
	}

	return e.revoked
}

// InvalidityDate returns the issuer's signed claim. It is not automatically a
// trusted compromise time, proof of existence or historical validation result.
func (e *VerifiedEvidence) InvalidityDate() time.Time {
	if e == nil {
		return time.Time{}
	}

	return e.invalidity
}

// RevocationReason returns the signed status reason when revocation/removal is asserted.
func (e *VerifiedEvidence) RevocationReason() (int, bool) {
	if e == nil || e.status != "revoked" && e.status != "remove-from-crl" {
		return 0, false
	}

	return e.reason, true
}

// SignatureAlgorithmOID returns the exact declared signature algorithm identifier.
func (e *VerifiedEvidence) SignatureAlgorithmOID() string {
	if e == nil {
		return ""
	}

	return e.signatureOID
}

// ScopeReasons returns the signed CRL scope's reasons. Bits0..7 identify
// keyCompromise,cACompromise,affiliationChanged,superseded,cessationOfOperation,
// certificateHold,privilegeWithdrawn,aACompromise. Other formats return zero.
func (e *VerifiedEvidence) ScopeReasons() uint16 {
	if e == nil {
		return 0
	}

	return uint16(e.scopeReasons)
}

// CoveredReasons returns the CRL reasons checked for this exact target/scope
// application at ValidationTime, including required composite dependencies.
// It is not an assertion that this evidence suffices at another time.
func (e *VerifiedEvidence) CoveredReasons() uint16 {
	if e == nil {
		return 0
	}

	return uint16(e.coverage)
}
