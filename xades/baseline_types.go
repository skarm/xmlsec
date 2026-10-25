package xades

import (
	"context"
	"crypto"
	"slices"
	"time"

	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/reference"
	"github.com/skarm/xmlsec/xmldsig"
)

const (
	prefixXades141             = "xades141"
	qualifierOIDAsURI          = "OIDAsURI"
	qualifierOIDAsURN          = "OIDAsURN"
	attributeEncoding          = "Encoding"
	defaultBaselineSignatureID = "signature"
)

// ObjectIdentifier carries a URI or a qualified OID identifier and its signed
// descriptive claims.
type ObjectIdentifier struct {
	// Identifier is the URI identifying the object or specification.
	Identifier string
	// Qualifier optionally selects the identifier interpretation, OIDAsURI or OIDAsURN.
	Qualifier string
	// Description is an optional human-readable description.
	Description string
	// Documentation lists optional documentation reference URIs.
	Documentation []string
}

// DataObjectFormat attaches signed format claims to one exact SignedInfo or
// authenticated Manifest Reference. ObjectReference binds the claim to that
// Reference; it does not select the application's payload.
type DataObjectFormat struct {
	// ObjectReference is the fragment URI of the authenticated Reference being described.
	ObjectReference string
	// Description is the optional signed description of the data object.
	Description string
	// MIMEType is the optional claimed media type of the data object.
	MIMEType string
	// Encoding is the optional claimed encoding URI of the data object.
	Encoding string
	// ObjectIdentifier optionally identifies the data object's format or specification.
	ObjectIdentifier *ObjectIdentifier
}

// ProductionPlace records signed address claims without establishing the signer's
// physical location.
type ProductionPlace struct {
	// City is the claimed city of signature production.
	City string
	// StreetAddress is the claimed street address of signature production.
	StreetAddress string
	// StateOrProvince is the claimed state or province of signature production.
	StateOrProvince string
	// PostalCode is the claimed postal code of signature production.
	PostalCode string
	// CountryName is the claimed country of signature production.
	CountryName string
}

// PropertyValue supplies plain text or a complete qualifying-property element of
// the required name. XML preserves mixed content and namespaced attributes and
// requires Text to be empty. Both inputs remain borrowed until the call returns.
type PropertyValue struct {
	// Text supplies plain property text when XML is absent.
	Text string
	// XML supplies the complete property element. When valid, Text must be empty.
	XML document.Element
}

// CommitmentType attaches a signed commitment to selected authenticated data
// References, or to all signed data when All is true. Qualifiers remain signer
// claims and establish no authority.
type CommitmentType struct {
	// Identifier identifies the claimed commitment type.
	Identifier ObjectIdentifier
	// ObjectReferences lists the exact Reference fragment URIs covered by this commitment.
	ObjectReferences []string
	// All applies the commitment to all signed data and excludes ObjectReferences.
	All bool
	// Qualifiers supplies additional signed commitment claims without establishing their
	// authority.
	Qualifiers []PropertyValue
}

// PolicyNotice records a human-readable signature policy notice. NoticeNumbers uses
// arbitrary-precision xs:integer strings.
type PolicyNotice struct {
	// Organization names the organization associated with NoticeNumbers.
	Organization string
	// NoticeNumbers contains notice identifiers as arbitrary-precision integer strings.
	NoticeNumbers []string
	// ExplicitText contains the optional human-readable policy notice.
	ExplicitText string
}

// PolicyQualifier selects exactly one of XML, URI, Notice or Specification.
type PolicyQualifier struct {
	// XML is an alternative complete AnyType SigPolicyQualifier, preserving
	// attributes, mixed content and domain-specific qualifier syntax.
	XML document.Element
	// URI supplies a policy document location without authorizing retrieval.
	URI string
	// Notice supplies a human-readable policy notice.
	Notice *PolicyNotice
	// Specification identifies the policy document's technical specification.
	Specification *ObjectIdentifier
}

// SignaturePolicy selects an implied policy or identifies an explicit policy document
// supplied offline by the caller. No URI is fetched.
type SignaturePolicy struct {
	// Implied selects SignaturePolicyImplied and excludes explicit policy fields.
	Implied bool
	// Identifier identifies the explicit signature policy.
	Identifier ObjectIdentifier
	// DigestMethod selects the policy digest algorithm URI. Empty selects xmldsig.SHA256 when building.
	DigestMethod string
	// Digest contains the raw digest of the supplied policy document after its transforms.
	// When building, nil computes it. A non-nil value must match the computed digest.
	Digest []byte
	// Transforms lists the explicit policy document transforms in execution order.
	Transforms []reference.Transform
	// Qualifiers contains additional policy references or notice claims.
	Qualifiers []PolicyQualifier
}

// CertificateIdentifier supplies an additional SigningCertificateV2 digest binding
// to untrusted certificate DER. It asserts no path relationship. Baseline generation
// omits Cert.URI as required by EN 319 132-1 clause 6.3(i), and omits IssuerSerialV2
// by default as recommended by clause 6.3(j).
type CertificateIdentifier struct {
	// DER contains the exact untrusted certificate bytes to bind by digest.
	DER []byte
	// DigestMethod selects the certificate digest algorithm URI. Empty selects xmldsig.SHA256 when building.
	DigestMethod string
	// IncludeIssuerSerial emits an IssuerSerialV2 hint in addition to the certificate
	// digest.
	IncludeIssuerSerial bool
}

// BaselineProperties supplies claims for SignBaseline. SigningTime is a required UTC
// signer claim and provides no proof of existence.
type BaselineProperties struct {
	// SigningTime is the required signer-claimed time when SigningTimeLexical is empty.
	SigningTime time.Time
	// SigningTimeLexical is an alternative UTC xs:dateTime claim, preserving
	// years/fractions outside the time.Time convenience profile. Set only one.
	SigningTimeLexical string
	// SigningCertificateDigest selects the signing certificate digest URI.
	// Empty selects xmldsig.SHA256.
	SigningCertificateDigest string
	// AdditionalCertificates adds digest bindings without asserting a certificate path.
	AdditionalCertificates []CertificateIdentifier
	// DataObjects contains signed format claims bound to exact authenticated References.
	DataObjects []DataObjectFormat
	// ProductionPlace optionally supplies signed address claims.
	ProductionPlace *ProductionPlace
	// ClaimedRoles contains signer-asserted role values without third-party authority.
	ClaimedRoles []PropertyValue
	// CertifiedRoles and SignedAssertions are authenticated encapsulations.
	// No third-party validity or authority is established by this API.
	CertifiedRoles []PropertyValue
	// SignedAssertions contains assertion encapsulations whose outer signature does not
	// establish third-party trust.
	SignedAssertions []PropertyValue
	// Commitments contains signed commitment claims and their data Reference bindings.
	Commitments []CommitmentType
	// DataTimestamps supplies content timestamp tokens. TSA trust requires separate
	// verification.
	DataTimestamps []DataTimestampProperty
	// Policy optionally supplies an implied or explicit signature policy claim.
	Policy *SignaturePolicy
}

// PolicySpecificationDigest computes the explicitly selected
// SPDocDigestAsInSpecification policy digest. During verification it is called
// after signature authentication. It must honor ctx and hash the caller-supplied
// policy document according to the named specification.
type PolicySpecificationDigest func(ctx context.Context, specification ObjectIdentifier, document []byte, algorithm crypto.Hash) ([]byte, error)

// BaselineVerifyOptions supplies explicit XMLDSig coverage and resource policy.
// CertificateValues provides untrusted candidates for additional certificate
// references. Each reference must bind actual DER before verification succeeds.
type BaselineVerifyOptions struct {
	// Signature sets XMLDSig algorithms, required coverage and authorized external
	// resources.
	Signature xmldsig.SignatureOptions
	// DataTimestamps bounds content timestamp parsing and input replay.
	DataTimestamps DataTimestampLimits
	// CertificateValues supplies untrusted DER candidates for additional certificate digest
	// references.
	CertificateValues [][]byte
	// PolicyDocument contains the offline document used to check an explicit policy digest.
	PolicyDocument []byte
	// PolicySpecificationDigest implements the explicitly selected technical specification
	// digest operation.
	PolicySpecificationDigest PolicySpecificationDigest
}

// BaselineSignOptions combines an XMLDSig template with signed baseline properties.
// Template selects placement, data References and Objects. SignBaseline adds the
// properties Object and its exact Reference.
type BaselineSignOptions struct {
	// Template supplies signature placement, algorithms, data References and Objects.
	Template xmldsig.SignatureTemplate
	// SignedPropertiesID is the generated SignedProperties Id. Empty selects
	// "signed-properties".
	SignedPropertiesID string
	// Properties supplies the signed baseline claims to generate.
	Properties BaselineProperties
	// Validation supplies coverage, resource and property checks for signature
	// self-verification.
	Validation BaselineVerifyOptions
	// Preserve gives explicit trust requirements for existing nonempty signatures.
	// Handles refer to the original doc snapshot.
	Preserve []xmldsig.SignatureRequirement
}

// CertificateReference binds an authenticated digest to exact certificate DER.
// The binding establishes no certificate path, validity or role.
type CertificateReference struct {
	digestMethod string
	digest       []byte
	certificate  []byte
	issuerSerial []byte
	uri          string
}

// DigestMethod returns the certificate digest algorithm URI.
func (r CertificateReference) DigestMethod() string { return r.digestMethod }

// Digest returns an owned copy of the authenticated certificate digest.
func (r CertificateReference) Digest() []byte { return slices.Clone(r.digest) }

// CertificateDER returns an owned copy of the certificate bound by this reference. It
// does not establish certificate trust.
func (r CertificateReference) CertificateDER() []byte { return slices.Clone(r.certificate) }

// IssuerSerialV2 returns an owned copy of the encoded issuer/serial hint, or nil when
// absent.
func (r CertificateReference) IssuerSerialV2() []byte { return slices.Clone(r.issuerSerial) }

// URI returns the optional certificate reference URI without resolving it.
func (r CertificateReference) URI() string { return r.uri }

// BaselineResult authenticates the selected XML signature, complete SignedProperties
// and explicit certificate bindings. Other signed values remain claims; the result
// grants no PKIX, timestamp, role, policy or legal trust. Closed enveloped APIs
// retain their separate, stricter contracts.
type BaselineResult struct {
	dataTimestamps []DataTimestamp
	basic          *BasicResult
	signingTime    string
	certificates   []CertificateReference
	data           []DataObjectFormat
	place          *ProductionPlace
	roles          []document.Element
	certifiedRoles []document.Element
	assertions     []document.Element
	commitments    []CommitmentType
	policy         *SignaturePolicy
	unsigned       document.Element
}

// Basic returns the authenticated common signature/property/certificate core
// for evidence workflows. MIMEType is empty when there is not exactly one data
// format; callers use DataObjects for all format bindings. ClaimedSigningTime
// is zero outside years 0001..9999 or exact nanosecond precision; use
// SigningTimeLexical and CompareSigningTime for the complete UTC value.
func (r *BaselineResult) Basic() *BasicResult {
	if r == nil {
		return nil
	}

	return r.basic
}

// CertificateReferences returns an independent slice of immutable certificate digest
// bindings. The bindings do not establish PKIX trust.
func (r *BaselineResult) CertificateReferences() []CertificateReference {
	if r == nil {
		return nil
	}

	return slices.Clone(r.certificates)
}

// UnsignedProperties returns an unverified evidence container. Its content does
// not become trusted through the XML signature or this format result.
func (r *BaselineResult) UnsignedProperties() document.Element {
	if r == nil {
		return document.Element{}
	}

	return r.unsigned
}

// UnsignedSignatureProperties returns unverified evidence properties for a
// separate timestamp/material workflow. Their order and original nodes survive.
func (r *BaselineResult) UnsignedSignatureProperties() []document.Element {
	if r == nil || !r.unsigned.Valid() {
		return nil
	}

	for _, child := range r.unsigned.Children() {
		if child.Name() == name("UnsignedSignatureProperties") {
			return child.Children()
		}
	}

	return nil
}

// DataObjects returns authenticated format claims and their exact Reference bindings.
func (r *BaselineResult) DataObjects() []DataObjectFormat {
	if r == nil {
		return nil
	}

	out := slices.Clone(r.data)
	for i := range out {
		if out[i].ObjectIdentifier != nil {
			v := cloneObjectIdentifier(*out[i].ObjectIdentifier)
			out[i].ObjectIdentifier = &v
		}
	}

	return out
}

// ProductionPlace returns signed address claims without establishing location.
func (r *BaselineResult) ProductionPlace() *ProductionPlace {
	if r == nil || r.place == nil {
		return nil
	}

	out := *r.place

	return &out
}

// ClaimedRoles returns authenticated claims, without third-party role authority.
func (r *BaselineResult) ClaimedRoles() []document.Element {
	if r == nil {
		return nil
	}

	return slices.Clone(r.roles)
}

// Commitments returns authenticated commitment claims and Reference bindings.
func (r *BaselineResult) Commitments() []CommitmentType {
	if r == nil {
		return nil
	}

	out := slices.Clone(r.commitments)
	for i := range out {
		out[i].Identifier = cloneObjectIdentifier(out[i].Identifier)
		out[i].ObjectReferences = slices.Clone(out[i].ObjectReferences)
		out[i].Qualifiers = slices.Clone(out[i].Qualifiers)
	}

	return out
}

// SignaturePolicy returns the authenticated policy identifier and checked digest;
// it does not establish acceptance, suitability or legal effect of that policy.
func (r *BaselineResult) SignaturePolicy() *SignaturePolicy {
	if r == nil || r.policy == nil {
		return nil
	}

	out := *r.policy
	out.Identifier = cloneObjectIdentifier(out.Identifier)
	out.Digest = slices.Clone(out.Digest)
	out.Transforms = reference.CloneTransforms(out.Transforms)

	out.Qualifiers = slices.Clone(out.Qualifiers)
	for i := range out.Qualifiers {
		q := &out.Qualifiers[i]
		if q.Notice != nil {
			n := *q.Notice
			n.NoticeNumbers = slices.Clone(n.NoticeNumbers)
			q.Notice = &n
		}

		if q.Specification != nil {
			s := cloneObjectIdentifier(*q.Specification)
			q.Specification = &s
		}
	}

	return &out
}

func cloneObjectIdentifier(value ObjectIdentifier) ObjectIdentifier {
	value.Documentation = slices.Clone(value.Documentation)
	return value
}

// CertifiedRoles returns authenticated third-party attribute-certificate claims.
// Their signature, issuer, holder and authority require a separate policy check.
func (r *BaselineResult) CertifiedRoles() []document.Element {
	if r == nil {
		return nil
	}

	return slices.Clone(r.certifiedRoles)
}

// SignedAssertions returns authenticated encapsulations, not verified assertions.
func (r *BaselineResult) SignedAssertions() []document.Element {
	if r == nil {
		return nil
	}

	return slices.Clone(r.assertions)
}
