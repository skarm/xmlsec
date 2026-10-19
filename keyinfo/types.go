package keyinfo

import (
	"bytes"
	"context"
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io"

	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/reference"
)

const (
	// Namespace is the XMLDSig 1.0 namespace URI.
	Namespace = "http://www.w3.org/2000/09/xmldsig#"
	// Namespace11 is the XMLDSig 1.1 namespace URI.
	Namespace11 = "http://www.w3.org/2009/xmldsig11#"
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

// Limits apply to one entire Parse, including repeated references. Zero fields
// use the defaults. Negative values and values above documented hard caps fail.
type Limits struct {
	// MaxDepth bounds reference depth; default 8, maximum 32.
	MaxDepth int
	// MaxElements bounds visited elements, including duplicates; default 256, maximum
	// 4096.
	MaxElements int
	// MaxCandidates bounds decoded candidates, including duplicates; default 32, maximum
	// 256.
	MaxCandidates int
	// MaxBlobBytes bounds each decoded key, certificate or CRL; default 1 MiB, maximum 8
	// MiB.
	MaxBlobBytes int
	// MaxTotalBytes bounds all decoded blobs and text; default 4 MiB, maximum 64 MiB.
	MaxTotalBytes int
	// MaxExternalResources bounds distinct external resource reads; default 8, maximum 64.
	MaxExternalResources int
	// MaxExternalBytes bounds aggregate external bytes read; default 4 MiB, maximum 64
	// MiB.
	MaxExternalBytes int
	// MaxRSABits bounds RSA modulus size; default 8192, maximum 16384. Minimum key
	// strength belongs to the trust policy.
	MaxRSABits int
}

// ResourceResolver must honor context itself, including during Read. It is
// called BEFORE SignatureValue can be verified. Never use an unrestricted HTTP
// or filesystem resolver for attacker-controlled KeyInfo.
type ResourceResolver interface {
	// Resolve opens the original resource bytes for an authorized URI. It and the returned
	// reader must honor cancellation.
	Resolve(context.Context, string) (io.ReadCloser, error)
}

// ExternalResources authorizes exact external KeyInfo URIs through an application-supplied
// resolver.
type ExternalResources struct {
	// Resolver is the trusted application adapter used to read explicitly authorized
	// resources.
	Resolver ResourceResolver
	// AllowedURIs lists exact absolute URI strings without fragments or userinfo. A cached
	// resource is read once per Parse. Redirects, relative URL resolution and URI
	// rewriting belong to the application resolver.
	AllowedURIs []string
}

// Options controls bounded KeyInfo parsing and authorized key representations. Parsing
// alone never establishes trust.
type Options struct {
	Limits Limits
	// AdditionalIDRules adds explicit ID attributes to the default KeyInfo resolution rules.
	AdditionalIDRules []reference.IDAttributeRule
	// AllowedKeyData restricts representations by expanded QName: KeyName,
	// RSAKeyValue, ECKeyValue, DEREncodedKeyValue, X509Data, RetrievalMethod,
	// KeyInfoReference. Nil preserves all supported forms; empty denies all.
	// KeyValue is a wrapper, not a representation. Raw certificate retrieval
	// requires both RetrievalMethod and X509Data. This controls parsing, not trust.
	AllowedKeyData []document.Name
	// External authorizes external KeyInfo resources. Nil denies all such resources; this
	// policy is separate from signed-data URIs.
	External *ExternalResources
}

// Candidate is an immutable, untrusted key description. All mutable key, DER and
// certificate data returned by methods are fresh copies. It can be read safely
// by concurrent policy callbacks. The zero value is invalid.
type Candidate struct {
	spki, certificate []byte
	source            document.Element
	resource          string
	kind              document.Name
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

	return x509.ParseCertificate(bytes.Clone(c.certificate))
}

// FingerprintSHA256 returns the hexadecimal SHA-256 fingerprint of the candidate SPKI.
func (c Candidate) FingerprintSHA256() string {
	if !c.Valid() {
		return ""
	}

	h := sha256.Sum256(c.spki)

	return hex.EncodeToString(h[:])
}

// X509Group preserves the grouping of certificates and selectors in one
// X509Data. Strings (including DN spellings) are not authenticated identifiers.
// DNs are NOT normalized or compared as strings to decide trust. The caller's
// policy must resolve/check selectors and certificate-chain relationships.
type X509Group struct {
	source      document.Element
	certs, crls [][]byte
	issuers     []IssuerSerial
	subjects    []string
	skis        [][]byte
	digests     []CertificateDigest
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

// IssuerSerial is an unverified X.509 issuer distinguished name and decimal serial number.
type IssuerSerial struct{ Issuer, Serial string }

// CertificateDigest is an unverified certificate digest identified by its algorithm URI.
type CertificateDigest struct {
	Algorithm string
	Value     []byte
}

// Result records decoded hints. It deliberately exposes no Valid/Trusted flag.
// It is never returned partially on an error.
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
		p        *int
		def, cap int
	}{
		{&l.MaxDepth, 8, 32},
		{&l.MaxElements, 256, 4096},
		{&l.MaxCandidates, 32, 256},
		{&l.MaxBlobBytes, 1 << 20, 8 << 20},
		{&l.MaxTotalBytes, 4 << 20, 64 << 20},
		{&l.MaxExternalResources, 8, 64},
		{&l.MaxExternalBytes, 4 << 20, 64 << 20},
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
