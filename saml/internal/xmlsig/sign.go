package xmlsig

import (
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
	"github.com/skarm/xmlsec/saml/internal/xmlutil"
	"github.com/skarm/xmlsec/xmldsig"
)

// ErrSignature reports SAML signature rejected.
var ErrSignature = errors.New("SAML signature rejected")

// SigningKey supplies the signer, optional matching certificate and explicit signature
// policy.
type SigningKey struct {
	Key            crypto.Signer
	CertificateDER []byte
	Method         string
	Policy         xmldsig.Policy
}

// ClonePolicy returns an owned copy of the SAML signature algorithm policy.
func ClonePolicy(p xmldsig.Policy) xmldsig.Policy {
	p.AllowedDigestMethods = append([]string(nil), p.AllowedDigestMethods...)
	p.AllowedSignatureMethods = append([]string(nil), p.AllowedSignatureMethods...)

	return p
}

// CloneKeys returns owned parsed copies of supported explicitly supplied public keys.
func CloneKeys(keys []crypto.PublicKey) ([]crypto.PublicKey, error) {
	if len(keys) == 0 || len(keys) > 16 {
		return nil, ErrSignature
	}

	out := make([]crypto.PublicKey, 0, len(keys))
	for _, k := range keys {
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
func Verify(ctx context.Context, d *document.Document, target document.Element, keys []crypto.PublicKey, p xmldsig.Policy) (*xmldsig.SignatureResult, error) {
	if ctx == nil || d == nil || !target.Valid() || !xmlutil.ID(xmlutil.Attr(target, "ID")) || len(keys) == 0 || len(keys) > 16 {
		return nil, ErrSignature
	}

	sig, e := xmlutil.Direct(target, xmlutil.Name(xmlutil.DS, lexicon.DSigElementSignature))
	if e != nil {
		return nil, e
	}

	si, e := xmlutil.Direct(sig, xmlutil.Name(xmlutil.DS, lexicon.DSigElementSignedInfo))
	if e != nil {
		return nil, e
	}

	cs, e := xmlutil.Children(si)
	if e != nil || len(cs) != 3 || cs[0].Name() != xmlutil.Name(xmlutil.DS, lexicon.DSigElementCanonicalizationMethod) || cs[1].Name() != xmlutil.Name(xmlutil.DS, lexicon.DSigElementSignatureMethod) || cs[2].Name() != xmlutil.Name(xmlutil.DS, lexicon.DSigElementReference) {
		return nil, ErrSignature
	}

	if xmlutil.Attr(cs[0], "Algorithm") != c14n.Exclusive || len(cs[0].Children()) != 0 || xmlutil.Attrs(cs[0], []string{"Algorithm"}, nil) != nil {
		return nil, ErrSignature
	}

	ref := cs[2]
	if xmlutil.Attr(ref, "URI") != "#"+xmlutil.Attr(target, "ID") {
		return nil, ErrSignature
	}

	trs, e := xmlutil.Direct(ref, xmlutil.Name(xmlutil.DS, lexicon.DSigElementTransforms))
	if e != nil {
		return nil, e
	}

	ts := trs.Children()
	if len(ts) != 2 || ts[0].Name() != xmlutil.Name(xmlutil.DS, lexicon.DSigElementTransform) || ts[1].Name() != xmlutil.Name(xmlutil.DS, lexicon.DSigElementTransform) || xmlutil.Attr(ts[0], "Algorithm") != xmldsig.EnvelopedSignature || xmlutil.Attr(ts[1], "Algorithm") != c14n.Exclusive || len(ts[0].Children()) != 0 || len(ts[1].Children()) != 0 {
		return nil, ErrSignature
	}

	for _, key := range keys {
		r, e := xmldsig.VerifySignature(ctx, d, sig, key, xmldsig.SignatureOptions{Policy: p, ExpectedURIs: []string{"#" + xmlutil.Attr(target, "ID")}, RequiredElements: []document.Element{target}})
		if e == nil {
			return r, nil
		}

		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
	}

	return nil, ErrSignature
}

// Sign signs a copied SAML target and places its signature at the schema-required
// position.
func Sign(ctx context.Context, d *document.Document, target document.Element, k SigningKey, afterIssuer bool) (*document.Document, error) {
	if ctx == nil || d == nil || !target.Valid() || nilcheck.IsNil(k.Key) || !xmlutil.ID(xmlutil.Attr(target, "ID")) {
		return nil, ErrSignature
	}

	if len(k.CertificateDER) > 0 {
		c, e := x509cert.ParseWithMaxBytes(k.CertificateDER, len(k.CertificateDER))
		if e != nil {
			return nil, e
		}

		if e = signature.MatchCertificate(k.Key, c); e != nil {
			return nil, e
		}
	}

	id, e := xmlutil.NewID()
	if e != nil {
		return nil, e
	}

	spec := xmldsig.SignatureTemplate{ID: id, SignatureMethod: k.Method, Canonicalization: reference.Transform{Algorithm: c14n.Exclusive}, References: []xmldsig.ReferenceTemplate{{URI: "#" + xmlutil.Attr(target, "ID"), DigestMethod: xmldsig.SHA256, Transforms: []reference.Transform{{Algorithm: xmldsig.EnvelopedSignature}, {Algorithm: c14n.Exclusive}}}}}
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
			if c.Kind == tree.ElementNode && c.Name == xmlutil.Name(xmlutil.Assertion, "Issuer") {
				pos = i + 1
				found = true

				break
			}
		}

		if !found {
			return nil, xmlutil.ErrSchema
		}
	}

	children := make([]*tree.Node, 0, len(others)+1)
	children = append(children, others[:pos]...)
	children = append(children, node)
	children = append(children, others[pos:]...)
	parent.Children = children
	// Template signing checks all completed preexisting signatures both before and
	// after serialization. This helper only supports the same authorized key.
	var preserve []xmldsig.SignatureRequirement

	for _, s := range xmldsig.Signatures(draft) {
		if !s.Same(sig) {
			preserve = append(preserve, xmldsig.SignatureRequirement{Signature: s, PublicKey: k.Key.Public(), Options: xmldsig.SignatureOptions{Policy: k.Policy}})
		}
	}

	return xmldsig.SignTemplate(ctx, draft, sig, k.Key, xmldsig.TemplateSignOptions{Validation: xmldsig.SignatureOptions{Policy: k.Policy, ExpectedURIs: []string{"#" + xmlutil.Attr(target, "ID")}}, Preserve: preserve})
}
