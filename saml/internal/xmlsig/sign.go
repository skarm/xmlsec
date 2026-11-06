package xmlsig

import (
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"errors"

	"github.com/skarm/xmlsec/c14n"
	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/internal/lexicon"
	"github.com/skarm/xmlsec/internal/nilcheck"
	"github.com/skarm/xmlsec/internal/signature"
	"github.com/skarm/xmlsec/internal/tree"
	"github.com/skarm/xmlsec/internal/x509cert"
	"github.com/skarm/xmlsec/reference"
	"github.com/skarm/xmlsec/saml/internal/profile"
	"github.com/skarm/xmlsec/saml/internal/xmlutil"
	"github.com/skarm/xmlsec/xmldsig"
)

// Bound explicit public-key candidates before cloning or signature verification; received KeyInfo never adds candidates or trust.
const (
	maximumTrustedKeys = 16
)

// MaxMessageSignatures bounds all XML signatures visible in one SAML message
// snapshot, including an enclosing response and contained assertion signatures.
// Query responses reserve one slot for the response; any nested signatures also
// consume this same budget.
const (
	MaxMessageSignatures = 64
)

// ErrSignature reports SAML signature rejected.
var ErrSignature = errors.New("SAML signature rejected")

// SigningKey supplies the signer, optional matching certificate and explicit signature
// policy.
type SigningKey struct {
	Key               crypto.Signer
	CertificateDER    []byte
	Method            string
	DigestMethod      string
	Canonicalization  string
	InclusivePrefixes []string
	PreserveKeys      func(context.Context, document.Element) ([]crypto.PublicKey, error)
	Secret            *SharedSecret
	Policy            xmldsig.Policy
}

// SharedSecret is an explicitly selected SAML MAC credential. It never comes
// from XML, X509Data or a public-key byte encoding. Holders can all forge MACs.
type SharedSecret struct{ value []byte }

// NewSharedSecret snapshots a 32-byte to 1-MiB shared secret. Signature policy
// can impose a smaller upper bound. No secret is serialized into XML.
func NewSharedSecret(value []byte) (SharedSecret, error) {
	const (
		maximumSecretBytes = 1 << 20
		minimumSecretBytes = 32
	)

	if len(value) < minimumSecretBytes || len(value) > maximumSecretBytes {
		return SharedSecret{}, ErrSignature
	}

	return SharedSecret{value: bytes.Clone(value)}, nil
}

// VerifiedSignature describes authenticated SAML target coverage for either
// explicitly selected public-key or shared-secret credentials.
type VerifiedSignature interface {
	CoversElement(document.Element) bool
}

// ClonePolicy returns an owned copy of the SAML signature algorithm policy.
func ClonePolicy(p xmldsig.Policy) xmldsig.Policy {
	p.AllowedDigestMethods = append([]string(nil), p.AllowedDigestMethods...)
	p.AllowedSignatureMethods = append([]string(nil), p.AllowedSignatureMethods...)

	return p
}

// CloneKeys returns owned parsed copies of supported explicitly supplied public keys.
func CloneKeys(keys []crypto.PublicKey) ([]crypto.PublicKey, error) {
	if len(keys) == 0 || len(keys) > maximumTrustedKeys {
		return nil, ErrSignature
	}

	out := make([]crypto.PublicKey, 0, len(keys))
	for _, k := range keys {
		if secret, ok := k.(SharedSecret); ok {
			snapshot, err := NewSharedSecret(secret.value)
			if err != nil {
				return nil, err
			}

			out = append(out, snapshot)

			continue
		}

		if e := signature.Key(k); e != nil {
			return nil, ErrSignature
		}

		b, e := x509.MarshalPKIXPublicKey(k)
		if e != nil {
			return nil, e
		}

		snapshot, e := x509.ParsePKIXPublicKey(b)
		if e != nil {
			return nil, e
		}

		out = append(out, snapshot)
	}

	return out, nil
}

// Verify verifies the closed SAML signature shape and exact target coverage using an
// explicitly supplied trusted key.
func Verify(ctx context.Context, d *document.Document, target document.Element, keys []crypto.PublicKey, p xmldsig.Policy) (VerifiedSignature, error) {
	const (
		referenceTransformCount = 2
		signedInfoChildCount    = 3
	)

	if ctx == nil || d == nil || !target.Valid() || !profile.ID(xmlutil.Attr(target, lexicon.SAMLAttrID)) || len(keys) == 0 || len(keys) > maximumTrustedKeys {
		return nil, ErrSignature
	}

	scope := d

	owner, _ := tree.Unwrap(target)
	if owner != d {
		return nil, ErrSignature
	}

	target = tree.ContextElement(target)
	d, _ = tree.Unwrap(target)

	sig, e := xmlutil.Direct(target, xmlutil.Name(xmlutil.DS, lexicon.DSigElementSignature))
	if e != nil {
		return nil, e
	}

	si, e := xmlutil.Direct(sig, xmlutil.Name(xmlutil.DS, lexicon.DSigElementSignedInfo))
	if e != nil {
		return nil, e
	}

	cs, e := xmlutil.Children(si)
	if e != nil || len(cs) != signedInfoChildCount || cs[0].Name() != xmlutil.Name(xmlutil.DS, lexicon.DSigElementCanonicalizationMethod) || cs[1].Name() != xmlutil.Name(xmlutil.DS, lexicon.DSigElementSignatureMethod) || cs[2].Name() != xmlutil.Name(xmlutil.DS, lexicon.DSigElementReference) {
		return nil, ErrSignature
	}

	if !simpleCanonicalization(cs[0]) {
		return nil, ErrSignature
	}

	ref := cs[2]
	if xmlutil.Attr(ref, lexicon.SecurityAttrURI) != "#"+xmlutil.Attr(target, lexicon.SAMLAttrID) {
		return nil, ErrSignature
	}

	trs, e := xmlutil.Direct(ref, xmlutil.Name(xmlutil.DS, lexicon.DSigElementTransforms))
	if e != nil {
		return nil, e
	}

	ts := trs.Children()
	if len(ts) != referenceTransformCount || ts[0].Name() != xmlutil.Name(xmlutil.DS, lexicon.DSigElementTransform) || ts[1].Name() != xmlutil.Name(xmlutil.DS, lexicon.DSigElementTransform) || xmlutil.Attr(ts[0], lexicon.SecurityAttrAlgorithm) != xmldsig.EnvelopedSignature || !simpleCanonicalization(ts[1]) || len(ts[0].Children()) != 0 {
		return nil, ErrSignature
	}

	for _, key := range keys {
		opts := xmldsig.SignatureOptions{Policy: p, MaxSignatures: MaxMessageSignatures, AllowedCanonicalizationMethods: []string{c14n.Exclusive, c14n.Canonical10}, ExpectedURIs: []string{"#" + xmlutil.Attr(target, lexicon.SAMLAttrID)}, RequiredElements: []document.Element{target}}

		var (
			r VerifiedSignature
			e error
		)
		if secret, ok := key.(SharedSecret); ok {
			r, e = xmldsig.VerifyHMACSignature(ctx, d, sig, secret.value, opts)
		} else {
			r, e = xmldsig.VerifySignature(ctx, d, sig, key, opts)
		}

		if e == nil {
			if scope != d {
				return scopedSignature{proof: r, scope: scope}, nil
			}

			return r, nil
		}

		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
	}

	return nil, ErrSignature
}

type scopedSignature struct {
	proof VerifiedSignature
	scope *document.Document
}

func (s scopedSignature) CoversElement(e document.Element) bool {
	owner, _ := tree.Unwrap(e)
	return owner == s.scope && s.proof.CoversElement(tree.ContextElement(e))
}

func samlCanonicalization(algorithm string) bool {
	return algorithm == c14n.Exclusive || algorithm == c14n.Canonical10
}

// Sign signs a copied SAML target and places its signature at the schema-required
// position.
func Sign(ctx context.Context, d *document.Document, target document.Element, k SigningKey, afterIssuer bool) (*document.Document, error) {
	const (
		xmlNameIssuer = "Issuer"
	)

	if ctx == nil || d == nil || !target.Valid() || !profile.ID(xmlutil.Attr(target, lexicon.SAMLAttrID)) {
		return nil, ErrSignature
	}

	if err := k.validate(); err != nil {
		return nil, err
	}

	id, e := profile.NewID()
	if e != nil {
		return nil, e
	}

	digest := k.DigestMethod
	if digest == "" {
		digest = xmldsig.SHA256
	}

	canonicalization := k.Canonicalization
	if canonicalization == "" {
		canonicalization = c14n.Exclusive
	}

	if !samlCanonicalization(canonicalization) {
		return nil, ErrSignature
	}

	spec := xmldsig.SignatureTemplate{ID: id, SignatureMethod: k.Method, Canonicalization: reference.Transform{Algorithm: canonicalization, InclusivePrefixes: k.InclusivePrefixes}, References: []xmldsig.ReferenceTemplate{{URI: "#" + xmlutil.Attr(target, lexicon.SAMLAttrID), DigestMethod: digest, Transforms: []reference.Transform{{Algorithm: xmldsig.EnvelopedSignature}, {Algorithm: canonicalization, InclusivePrefixes: k.InclusivePrefixes}}}}}
	if len(k.CertificateDER) > 0 {
		spec.Certificates = [][]byte{k.CertificateDER}
	}

	draft, sig, e := xmldsig.BuildTemplate(ctx, d, target, spec)
	if e != nil {
		return nil, e
	}

	_, node := tree.Unwrap(sig)
	parent := node.Parent

	var others []*tree.Node

	for _, c := range parent.Children {
		if c != node {
			others = append(others, c)
		}
	}

	pos := 0

	if afterIssuer {
		found := false

		for i, c := range others {
			if c.Kind == tree.ElementNode && c.Name == xmlutil.Name(xmlutil.Assertion, xmlNameIssuer) {
				pos = i + 1
				found = true

				break
			}
		}

		if !found {
			return nil, profile.ErrSchema
		}
	}

	children := make([]*tree.Node, 0, len(others)+1)
	children = append(children, others[:pos]...)
	children = append(children, node)
	children = append(children, others[pos:]...)
	parent.Children = children
	// Template signing checks all completed preexisting signatures both before and
	// after serialization. Other assertion issuers need explicitly supplied trust.
	preserve, err := preservedSignatures(ctx, draft, sig, k)
	if err != nil {
		return nil, err
	}

	options := xmldsig.TemplateSignOptions{Validation: xmldsig.SignatureOptions{Policy: k.Policy, MaxSignatures: MaxMessageSignatures, AllowedCanonicalizationMethods: []string{canonicalization}, ExpectedURIs: []string{"#" + xmlutil.Attr(target, lexicon.SAMLAttrID)}}, Preserve: preserve}
	if k.Secret != nil {
		return xmldsig.SignHMACTemplate(ctx, draft, sig, k.Secret.value, options)
	}

	return xmldsig.SignTemplate(ctx, draft, sig, k.Key, options)
}

func preservedSignatures(ctx context.Context, draft *document.Document, sig document.Element, k SigningKey) ([]xmldsig.SignatureRequirement, error) {
	var preserve []xmldsig.SignatureRequirement

	for _, s := range xmldsig.Signatures(draft) {
		if !s.Same(sig) {
			requirement := xmldsig.SignatureRequirement{Signature: s, Options: xmldsig.SignatureOptions{Policy: k.Policy, MaxSignatures: MaxMessageSignatures, AllowedCanonicalizationMethods: []string{c14n.Exclusive, c14n.Canonical10}}}
			if k.PreserveKeys != nil {
				_, node := tree.Unwrap(s)

				keys, err := k.PreserveKeys(ctx, tree.Wrap(draft, node.Parent))
				if err != nil {
					return nil, err
				}

				requirement, err = preservationCredential(ctx, draft, requirement, keys)
				if err != nil {
					return nil, err
				}
			} else if k.Secret != nil {
				requirement.SharedSecret = k.Secret.value
			} else {
				requirement.PublicKey = k.Key.Public()
			}

			preserve = append(preserve, requirement)
		}
	}

	return preserve, nil
}

func preservationCredential(ctx context.Context, d *document.Document, r xmldsig.SignatureRequirement, keys []crypto.PublicKey) (xmldsig.SignatureRequirement, error) {
	if len(keys) == 0 || len(keys) > maximumTrustedKeys {
		return r, ErrSignature
	}

	for _, key := range keys {
		if secret, ok := key.(SharedSecret); ok {
			if _, err := xmldsig.VerifyHMACSignature(ctx, d, r.Signature, secret.value, r.Options); err == nil {
				r.SharedSecret = secret.value
				return r, nil
			}
		} else if _, err := xmldsig.VerifySignature(ctx, d, r.Signature, key, r.Options); err == nil {
			r.PublicKey = key
			return r, nil
		}

		if err := ctx.Err(); err != nil {
			return r, err
		}
	}

	return r, ErrSignature
}

func (k SigningKey) validate() error {
	if nilcheck.IsNil(k.Key) && k.Secret == nil || !nilcheck.IsNil(k.Key) && k.Secret != nil || k.Secret != nil && len(k.CertificateDER) != 0 {
		return ErrSignature
	}

	if len(k.CertificateDER) > 0 {
		c, e := x509cert.ParseWithMaxBytes(k.CertificateDER, len(k.CertificateDER))
		if e != nil {
			return e
		}

		if e = signature.MatchCertificate(k.Key, c); e != nil {
			return e
		}
	}

	return nil
}

func simpleCanonicalization(e document.Element) bool {
	algorithm := xmlutil.Attr(e, lexicon.SecurityAttrAlgorithm)
	if !samlCanonicalization(algorithm) || xmlutil.Attrs(e, []string{lexicon.SecurityAttrAlgorithm}, nil) != nil {
		return false
	}

	children, err := xmlutil.Children(e)
	if err != nil {
		return false
	}

	if len(children) == 0 {
		return true
	}

	if algorithm != c14n.Exclusive || len(children) != 1 {
		return false
	}

	parameters := children[0]

	return parameters.Name() == xmlutil.Name(c14n.Exclusive, lexicon.C14NElementInclusiveNamespaces) && xmlutil.Attrs(parameters, []string{lexicon.C14NAttrPrefixList}, nil) == nil && xmlutil.EmptyContent(parameters)
}
