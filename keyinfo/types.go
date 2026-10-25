package keyinfo

import (
	"bytes"
	"context"
	"crypto"

	// #nosec G406 -- Public parameter context for explicitly selected legacy verification.
	"crypto/dsa" //nolint:staticcheck // XMLDSig 1.1 DSA verification has a separate compatibility policy.
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io"

	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/internal/lexicon"
	"github.com/skarm/xmlsec/internal/x509cert"
	"github.com/skarm/xmlsec/reference"
)

const (
	// Namespace is the XMLDSig 1.0 namespace URI.
	Namespace = lexicon.NamespaceDSig
	// Namespace11 is the XMLDSig 1.1 namespace URI.
	Namespace11 = lexicon.NamespaceDSig11
	// RawX509Certificate identifies DER certificate octets retrieved by RetrievalMethod.
	RawX509Certificate = Namespace + "rawX509Certificate"
)

var (
	// ErrInput reports invalid KeyInfo structure.
	ErrInput = errors.New("invalid KeyInfo structure")
	// ErrUnsupported reports unsupported KeyInfo feature.
	ErrUnsupported = errors.New("unsupported KeyInfo feature")
	// ErrPolicy reports KeyInfo policy violation.
	ErrPolicy = errors.New("KeyInfo policy violation")
	// ErrLimit reports KeyInfo resource limit exceeded.
	ErrLimit = errors.New("KeyInfo resource limit exceeded")
	// ErrCycle reports cyclic KeyInfo reference.
	ErrCycle = errors.New("cyclic KeyInfo reference")
	// ErrResource reports KeyInfo resource unavailable.
	ErrResource = errors.New("KeyInfo resource unavailable")
	// ErrKey reports invalid KeyInfo public key.
	ErrKey = errors.New("invalid KeyInfo public key")
)

// Limits bounds an entire Parse call, including repeated reference visits.
// Zero fields select defaults. Negative values and values above the documented
// maximum are rejected.
type Limits struct {
	// MaxDepth bounds reference depth. Zero selects 8. The maximum is 32.
	MaxDepth int
	// MaxElements bounds all element visits, including repeated visits. Zero selects 256.
	// The maximum is 4096.
	MaxElements int
	// MaxCandidates bounds decoded candidates, including duplicates. Zero selects 32. The
	// maximum is 256.
	MaxCandidates int
	// MaxBlobBytes bounds each decoded key, certificate or CRL. Zero selects 1 MiB. The
	// maximum is 8 MiB.
	MaxBlobBytes int
	// MaxTotalBytes bounds aggregate decoded blobs and text. Zero selects 4 MiB. The
	// maximum is 64 MiB.
	MaxTotalBytes int
	// MaxExternalResources bounds distinct external reads. Zero selects 8. The maximum is
	// 64.
	MaxExternalResources int
	// MaxExternalBytes bounds aggregate external bytes read. Zero selects 4 MiB. The
	// maximum is 64 MiB.
	MaxExternalBytes int
	// MaxTransformBytes bounds aggregate intermediate and final retrieval output when
	// RetrievalProcessing is enabled. Zero selects 32 MiB. The maximum is 64 MiB. Raw
	// external input has a separate budget.
	MaxTransformBytes int
	// MaxTransformNodes bounds reference-processor visits and result parsing when
	// RetrievalProcessing is enabled. Zero selects 2,000,000. The maximum is 16,000,000.
	MaxTransformNodes int
	// MaxRSABits bounds RSA modulus size. Zero selects 8192. The maximum is 16384. Trust
	// policy sets minimum key strength.
	MaxRSABits int
}

// ResourceResolver opens explicitly authorized KeyInfo resources. Retrieval can
// precede SignatureValue verification. Implementations must honor cancellation
// while resolving and reading, and must restrict attacker-controlled URIs through
// application policy.
type ResourceResolver interface {
	// Resolve receives the complete authorized URI, including a fragment, and
	// returns the identified subresource as octets. XML subresources must be
	// standalone documents; fragment interpretation belongs to this adapter.
	// It and the returned reader must honor cancellation.
	Resolve(context.Context, string) (io.ReadCloser, error)
}

// ExternalResources grants access to exact KeyInfo resource URIs through a trusted
// application resolver.
type ExternalResources struct {
	// Resolver is the trusted application adapter used to read explicitly authorized
	// resources.
	Resolver ResourceResolver
	// AllowedURIs lists exact absolute URI strings without userinfo. Fragments
	// identify distinct resources and are passed unchanged to Resolver. A cached
	// resource is read once per Parse.
	AllowedURIs []string
	// BaseURI opts into relative URI resolution, inherited xml:base on permitted
	// containing elements and retrieval context for nested resources. It must be
	// absolute, hierarchical and fragment-free. Authorization uses the resolved
	// absolute URI. Empty keeps literal URI handling; empty/#fragment references
	// always address their containing document. Redirect metadata is not inferred.
	BaseURI string
}

// Options selects KeyInfo representations, retrieval permissions and parsing budgets.
// Parsing alone establishes no trust.
type Options struct {
	// Limits bounds the complete parse, including retrievals. Zero fields select defaults.
	Limits Limits
	// AdditionalIDRules adds explicit ID attributes to the default KeyInfo resolution rules.
	AdditionalIDRules []reference.IDAttributeRule
	// AllowedKeyData selects representations by expanded name: KeyName, RSAKeyValue,
	// DSAKeyValue, ECKeyValue, DEREncodedKeyValue, X509Data, RetrievalMethod or
	// KeyInfoReference. Nil permits every supported form; an empty slice denies all.
	// KeyValue is a wrapper and cannot select a representation. Raw certificate
	// retrieval requires both RetrievalMethod and X509Data. These parsing permissions
	// grant no trust.
	AllowedKeyData []document.Name
	// External authorizes external KeyInfo resources. Nil denies them. This permission is
	// separate from signed-data resource access.
	External *ExternalResources
	// RetrievalProcessing explicitly permits additional RetrievalMethod chains.
	// Nil preserves raw-certificate retrieval with at most one Base64 step.
	// The shared reference processor enforces the supplied transform allowlist
	// and approves XPath/Filter2/XSLT only through an explicit Extension processor.
	// Signature and IDRules are supplied by KeyInfo parsing and must be zero here.
	// Numeric limits are capped by Limits and shared across the entire Parse.
	RetrievalProcessing *reference.Options
	// DSAParameters supplies application-known P/Q/G when DSAKeyValue omits
	// some of those fields (XMLDSig 1.1 section 4.5.2.1). Nil requires complete
	// parameters in XML. The bounded 1024/160 context is copied before callbacks;
	// it neither authenticates the key nor enables DSA signature verification.
	DSAParameters *dsa.Parameters
}

// Candidate is an immutable, untrusted key description with an invalid zero value.
// Its accessors copy mutable key objects, DER and certificate data. Concurrent
// policy callbacks can read the same Candidate safely.
type Candidate struct {
	spki        []byte
	certificate []byte
	source      document.Element
	resource    string
	kind        document.Name
}

// Valid returns whether this value is initialized.
func (c Candidate) Valid() bool { return len(c.spki) > 0 }

// SPKI returns an owned copy of the SubjectPublicKeyInfo DER.
func (c Candidate) SPKI() []byte { return bytes.Clone(c.spki) }

// CertificateDER returns an owned copy of the certificate DER.
func (c Candidate) CertificateDER() []byte { return bytes.Clone(c.certificate) }

// Source returns the immutable XML source handle.
func (c Candidate) Source() document.Element { return c.source }

// ResourceURI returns the external resource URI, or an empty string for local data.
func (c Candidate) ResourceURI() string { return c.resource }

// Kind returns the expanded QName of the key representation.
func (c Candidate) Kind() document.Name { return c.kind }

// PublicKey returns a newly parsed public key owned by the caller.
func (c Candidate) PublicKey() (crypto.PublicKey, error) {
	if !c.Valid() {
		return nil, ErrKey
	}

	return x509.ParsePKIXPublicKey(bytes.Clone(c.spki))
}

// Certificate returns a newly parsed certificate, or nil when no certificate was supplied;
// this does not establish trust.
func (c Candidate) Certificate() (*x509.Certificate, error) {
	if !c.Valid() {
		return nil, ErrKey
	}

	if len(c.certificate) == 0 {
		return nil, nil
	}

	return x509cert.ParseWithMaxBytes(bytes.Clone(c.certificate), len(c.certificate))
}

// FingerprintSHA256 returns the hexadecimal SHA-256 fingerprint of the candidate SPKI.
func (c Candidate) FingerprintSHA256() string {
	if !c.Valid() {
		return ""
	}

	h := sha256.Sum256(c.spki)

	return hex.EncodeToString(h[:])
}

// X509Group retains certificates and selectors from one X509Data element.
// Names and distinguished-name spellings are untrusted hints. The parser does not
// normalize or compare those strings to establish trust. Application policy must
// resolve selectors and validate certificate relationships.
type X509Group struct {
	source   document.Element
	certs    [][]byte
	crls     [][]byte
	issuers  []IssuerSerial
	subjects []string
	skis     [][]byte
	digests  []CertificateDigest
}

// Source returns the immutable XML source handle.
func (g X509Group) Source() document.Element { return g.source }

// CertificatesDER returns owned copies of untrusted certificate DER values.
func (g X509Group) CertificatesDER() [][]byte { return cloneBlobs(g.certs) }

// CRLsDER returns owned copies of untrusted CRL DER values.
func (g X509Group) CRLsDER() [][]byte { return cloneBlobs(g.crls) }

// IssuerSerials returns an owned copy of untrusted issuer and serial selectors.
func (g X509Group) IssuerSerials() []IssuerSerial { return append([]IssuerSerial(nil), g.issuers...) }

// SubjectNames returns an owned copy of untrusted subject-name selectors.
func (g X509Group) SubjectNames() []string { return append([]string(nil), g.subjects...) }

// SubjectKeyIdentifiers returns owned copies of untrusted subject key identifiers.
func (g X509Group) SubjectKeyIdentifiers() [][]byte { return cloneBlobs(g.skis) }

// CertificateDigests returns owned copies of untrusted certificate digest selectors.
func (g X509Group) CertificateDigests() []CertificateDigest {
	out := make([]CertificateDigest, len(g.digests))
	for i, d := range g.digests {
		out[i] = CertificateDigest{d.Algorithm, bytes.Clone(d.Value)}
	}

	return out
}

func cloneBlobs(a [][]byte) [][]byte {
	out := make([][]byte, len(a))
	for i, b := range a {
		out[i] = bytes.Clone(b)
	}

	return out
}

// IssuerSerial pairs an unverified X.509 issuer distinguished name with a decimal
// certificate serial number.
type IssuerSerial struct {
	// Issuer is the issuer distinguished name in XMLDSig/RFC 4514 spelling.
	Issuer string
	// Serial is the certificate serial number in nonnegative decimal notation.
	Serial string
}

// CertificateDigest pairs unverified digest bytes with a digest algorithm URI.
type CertificateDigest struct {
	// Algorithm is the digest method URI.
	Algorithm string
	// Value contains the raw digest bytes, without Base64 encoding.
	Value []byte
}

// Result contains untrusted decoded key hints. A successful parse provides neither
// a validity flag nor a trust decision. Parse returns no partial Result on error.
type Result struct {
	candidates []Candidate
	names      []string
	groups     []X509Group
	external   []string
}

// Candidates returns an owned slice of immutable untrusted key candidates.
func (r *Result) Candidates() []Candidate {
	if r == nil {
		return nil
	}

	return append([]Candidate(nil), r.candidates...)
}

// KeyNames returns an owned copy of untrusted key-name strings.
func (r *Result) KeyNames() []string {
	if r == nil {
		return nil
	}

	return append([]string(nil), r.names...)
}

// X509Groups returns an owned slice of immutable untrusted X509Data groups.
func (r *Result) X509Groups() []X509Group {
	if r == nil {
		return nil
	}

	return append([]X509Group(nil), r.groups...)
}

// ExternalURIs returns an owned copy of the external URIs read during parsing.
func (r *Result) ExternalURIs() []string {
	if r == nil {
		return nil
	}

	return append([]string(nil), r.external...)
}

// CheckKeyDeclarations rejects conflicting bare KeyValue/DER declarations. It
// does not validate certificate chains, selectors, key names or identities.
func (r *Result) CheckKeyDeclarations(selected int) error {
	if r == nil || selected < 0 || selected >= len(r.candidates) {
		return ErrKey
	}

	chosen := r.candidates[selected]
	for _, c := range r.candidates {
		if len(c.certificate) == 0 && !bytes.Equal(c.spki, chosen.spki) {
			return fmt.Errorf("%w: contradictory bare key declarations", ErrKey)
		}
	}

	return nil
}

func normalizeLimits(l Limits) (Limits, error) {
	fields := []struct {
		p   *int
		def int
		cap int
	}{
		{&l.MaxDepth, 8, 32},
		{&l.MaxElements, 256, 4096},
		{&l.MaxCandidates, 32, 256},
		{&l.MaxBlobBytes, 1 << 20, 8 << 20},
		{&l.MaxTotalBytes, 4 << 20, 64 << 20},
		{&l.MaxExternalResources, 8, 64},
		{&l.MaxExternalBytes, 4 << 20, 64 << 20},
		{&l.MaxTransformBytes, 32 << 20, 64 << 20},
		{&l.MaxTransformNodes, 2_000_000, 16_000_000},
		{&l.MaxRSABits, 8192, 16384},
	}
	for _, f := range fields {
		if *f.p == 0 {
			*f.p = f.def
		}

		if *f.p < 1 || *f.p > f.cap {
			return l, fmt.Errorf("%w: invalid limits", ErrPolicy)
		}
	}

	if l.MaxRSABits < 512 {
		return l, fmt.Errorf("%w: MaxRSABits must be >=512", ErrPolicy)
	}

	return l, nil
}
