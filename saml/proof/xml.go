package proof

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/fips140"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/base64"
	"hash"
	"slices"
	"strings"

	"github.com/skarm/xmlsec/c14n"
	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/internal/lexicon"
	"github.com/skarm/xmlsec/internal/nilcheck"
	"github.com/skarm/xmlsec/internal/transformxml"
	"github.com/skarm/xmlsec/internal/tree"
	"github.com/skarm/xmlsec/reference"
	"github.com/skarm/xmlsec/saml/binding"
	"github.com/skarm/xmlsec/saml/internal/xmlutil"
	"github.com/skarm/xmlsec/xmldsig"
)

// Locate/build the SOAP 1.1 security-header container by expanded name; copying other headers does not authenticate them.
const (
	soapHeaderElement = "Header"
)

// SOAP processing attributes used for the proof security header; the next-actor rule is checked independently of certificate possession.
const (
	soapActorAttribute          = "actor"
	soapMustUnderstandAttribute = "mustUnderstand"
)

const (
	soapPrefix         = "soap"
	algorithmAttribute = lexicon.SecurityAttrAlgorithm
)

// Signing selects the proof key/certificate and independent XMLDSig algorithms.
type Signing struct {
	// Key is the private signing key proving possession of Certificate's public
	// key.
	Key crypto.Signer
	// Certificate contains the exact DER certificate carried by the proof.
	Certificate []byte
	// Method selects the XMLDSig signature algorithm URI.
	Method string
	// Canonicalization selects the SignedInfo canonicalization algorithm URI.
	Canonicalization string
	// Digest selects the reference digest algorithm URI.
	Digest string
	// Policy restricts the algorithms used to create the proof.
	Policy xmldsig.Policy
	// InclusivePrefixes applies only to Exclusive C14N of SignedInfo.
	InclusivePrefixes []string
}

// SignEnvelopedXML signs the complete SOAP message using a declared W3C
// enveloped-signature transform. The scope of CS01 2.3.11's no-Transforms wording
// needs clarification; full ECP conformance is not established by this API.
func SignEnvelopedXML(ctx context.Context, envelope *document.Document, key Signing) (*document.Document, error) {
	return signXML(ctx, envelope, key, true)
}

// SignCS01CompatXML omits Reference transforms under the restrictive reading of
// CS01, applying an ECP-specific self-exclusion rule. This is not ordinary W3C
// XMLDSig reference processing and requires an explicitly agreeing peer.
func SignCS01CompatXML(ctx context.Context, envelope *document.Document, key Signing) (*document.Document, error) {
	return signXML(ctx, envelope, key, false)
}

// signXML preserves existing SAML signatures and their namespace context.
func signXML(ctx context.Context, envelope *document.Document, key Signing, enveloped bool) (*document.Document, error) {
	const (
		soapEnvelopeElement = "Envelope"
	)

	if ctx == nil || envelope == nil || !envelope.Root().Valid() || nilcheck.IsNil(key.Key) {
		return nil, ErrProof
	}

	cert, err := certificate(key.Certificate)
	if err != nil {
		return nil, err
	}

	public, ok := key.Key.Public().(interface{ Equal(crypto.PublicKey) bool })
	if !ok || !public.Equal(cert.PublicKey) {
		return nil, ErrProof
	}

	if key.Method == "" {
		switch key.Key.Public().(type) {
		case *rsa.PublicKey:
			key.Method = xmldsig.RSASHA256
		case *ecdsa.PublicKey:
			key.Method = xmldsig.ECDSASHA256
		default:
			return nil, ErrProof
		}
	}

	if key.Canonicalization == "" {
		key.Canonicalization = c14n.Exclusive
	}

	if key.Digest == "" {
		key.Digest = xmldsig.SHA256
	}

	draft, err := tree.Clone(ctx, envelope)
	if err != nil {
		return nil, err
	}

	root := tree.Root(draft)
	if root.Name != xmlutil.Name(binding.SOAPNamespace, soapEnvelopeElement) {
		return nil, ErrProof
	}

	security, err := addSecurity(root)
	if err != nil {
		return nil, err
	}

	sig := xmlutil.Node(lexicon.PrefixDSig, xmlutil.DS, lexicon.DSigElementSignature)
	sig.NS = []tree.Namespace{{Prefix: lexicon.PrefixDSig, URI: xmlutil.DS}}
	si := xmlutil.Node(lexicon.PrefixDSig, xmlutil.DS, lexicon.DSigElementSignedInfo)
	cm := xmlutil.Node(lexicon.PrefixDSig, xmlutil.DS, lexicon.DSigElementCanonicalizationMethod)
	xmlutil.Set(cm, algorithmAttribute, key.Canonicalization)

	if len(key.InclusivePrefixes) != 0 {
		prefixes := xmlutil.Node(lexicon.PrefixExclusiveC14N, c14n.Exclusive, lexicon.C14NElementInclusiveNamespaces)
		prefixes.NS = []tree.Namespace{{Prefix: lexicon.PrefixExclusiveC14N, URI: c14n.Exclusive}}
		xmlutil.Set(prefixes, lexicon.C14NAttrPrefixList, strings.Join(key.InclusivePrefixes, " "))
		xmlutil.Add(cm, prefixes)
	}

	sm := xmlutil.Node(lexicon.PrefixDSig, xmlutil.DS, lexicon.DSigElementSignatureMethod)
	xmlutil.Set(sm, algorithmAttribute, key.Method)

	ref := xmlutil.Node(lexicon.PrefixDSig, xmlutil.DS, lexicon.DSigElementReference)
	xmlutil.Set(ref, lexicon.SecurityAttrURI, "")

	if enveloped {
		transforms := xmlutil.Node(lexicon.PrefixDSig, xmlutil.DS, lexicon.DSigElementTransforms)
		transform := xmlutil.Node(lexicon.PrefixDSig, xmlutil.DS, lexicon.DSigElementTransform)
		xmlutil.Set(transform, algorithmAttribute, reference.EnvelopedSignature)
		xmlutil.Add(transforms, transform)
		xmlutil.Add(ref, transforms)
	}

	dm := xmlutil.Node(lexicon.PrefixDSig, xmlutil.DS, lexicon.DSigElementDigestMethod)
	xmlutil.Set(dm, algorithmAttribute, key.Digest)

	dv := xmlutil.Node(lexicon.PrefixDSig, xmlutil.DS, lexicon.DSigElementDigestValue)

	xmlutil.Add(ref, dm)
	xmlutil.Add(ref, dv)
	xmlutil.Add(si, cm)
	xmlutil.Add(si, sm)
	xmlutil.Add(si, ref)
	xmlutil.Add(sig, si)
	xmlutil.Add(sig, xmlutil.Node(lexicon.PrefixDSig, xmlutil.DS, lexicon.DSigElementSignatureValue))
	info := xmlutil.Node(lexicon.PrefixDSig, xmlutil.DS, lexicon.DSigElementKeyInfo)
	data := xmlutil.Node(lexicon.PrefixDSig, xmlutil.DS, lexicon.DSigElementX509Data)
	leaf := xmlutil.Node(lexicon.PrefixDSig, xmlutil.DS, lexicon.DSigElementX509Certificate)
	xmlutil.Text(leaf, base64.StdEncoding.EncodeToString(cert.Raw))
	xmlutil.Add(data, leaf)
	xmlutil.Add(info, data)
	xmlutil.Add(sig, info)
	xmlutil.Add(security, sig)

	d, err := tree.Reparse(ctx, draft, document.DefaultLimits())
	if err != nil {
		return nil, err
	}

	selected, err := proofSignature(d)
	if err != nil {
		return nil, err
	}

	digest, consumed, err := referenceDigest(ctx, d, selected, key.Digest, key.Policy)
	if err != nil {
		return nil, err
	}

	_, sn := tree.Unwrap(selected)
	refNode := sn.Children[0].Children[2]
	digestValue := refNode.Children[len(refNode.Children)-1]
	digestValue.Children = nil
	xmlutil.Text(digestValue, base64.StdEncoding.EncodeToString(digest))
	// d is a newly produced private snapshot, never exposed until reparsed.
	d, err = tree.Reparse(ctx, d, document.DefaultLimits())
	if err != nil {
		return nil, err
	}

	selected, err = proofSignature(d)
	if err != nil {
		return nil, err
	}

	canonical, err := signedInfoBytes(ctx, selected.Children()[0], key.Canonicalization, canonicalLimit(key.Policy)-consumed)
	if err != nil {
		return nil, err
	}

	value, err := xmldsig.SignMessageWithParameters(ctx, canonical, key.Key, key.Method, xmldsig.SignatureParameters{}, key.Policy)
	if err != nil {
		return nil, err
	}

	_, sn = tree.Unwrap(selected)
	xmlutil.Text(sn.Children[1], base64.StdEncoding.EncodeToString(value))

	out, err := tree.Reparse(ctx, d, document.DefaultLimits())
	if err != nil {
		return nil, err
	}

	raw, err := out.XML(ctx)
	if err != nil {
		return nil, err
	}

	_, err = verifyXML(ctx, raw, Options{Certificate: cert.Raw, Policy: key.Policy, SOAP: binding.SOAPOptions{Understood: allHeaderNames(out)}}, enveloped)
	if err != nil {
		return nil, err
	}

	return out, nil
}

// VerifyEnvelopedXML verifies the whole SOAP message with exactly one declared
// enveloped-signature transform. It never accepts the CS01 compatibility form.
// Certificate association, SAML validation and replay checks remain separate.
func VerifyEnvelopedXML(ctx context.Context, raw []byte, o Options) (*Verified, error) {
	return verifyXML(ctx, raw, o, true)
}

// VerifyCS01CompatXML verifies only CS01's no-Transforms compatibility form,
// applying the explicitly agreed nonstandard self-exclusion rule. It never
// accepts declared transforms or infers trust from KeyInfo.
func VerifyCS01CompatXML(ctx context.Context, raw []byte, o Options) (*Verified, error) {
	return verifyXML(ctx, raw, o, false)
}

func verifyXML(ctx context.Context, raw []byte, o Options, enveloped bool) (*Verified, error) {
	const (
		maximumDigestBytes       = 128
		maximumSignatureBytes    = 4096
		maximumSignatureChildren = 3
		minimumSignatureChildren = 2
	)

	m, err := decode(ctx, raw, o)
	if err != nil {
		return nil, err
	}

	d := m.Envelope()

	sig, err := proofSignature(d)
	if err != nil {
		return nil, err
	}

	parts, err := xmlutil.Children(sig)
	if err != nil || len(parts) < minimumSignatureChildren || len(parts) > maximumSignatureChildren || xmlutil.Attrs(sig, nil, []string{lexicon.SecurityAttrID}) != nil || parts[0].Name() != xmlutil.Name(xmlutil.DS, lexicon.DSigElementSignedInfo) || parts[1].Name() != xmlutil.Name(xmlutil.DS, lexicon.DSigElementSignatureValue) {
		return nil, ErrProof
	}

	info, err := readSignedInfo(parts[0], enveloped)
	if err != nil {
		return nil, err
	}

	certBytes := bytes.Clone(o.Certificate)

	if len(parts) == maximumSignatureChildren {
		provided, err := readCertificate(parts[2])
		if err != nil || len(certBytes) != 0 && !bytes.Equal(certBytes, provided) {
			return nil, ErrProof
		}

		certBytes = provided
	}

	cert, err := certificate(certBytes)
	if err != nil {
		return nil, err
	}

	digest, consumed, err := referenceDigest(ctx, d, sig, info.digestMethod, o.Policy)
	if err != nil {
		return nil, err
	}

	want, err := binary(info.digestValue, maximumDigestBytes)
	if err != nil || subtle.ConstantTimeCompare(digest, want) != 1 {
		return nil, ErrProof
	}

	canonical, err := signedInfoBytes(ctx, parts[0], info.canonicalization, canonicalLimit(o.Policy)-consumed)
	if err != nil {
		return nil, err
	}

	value, err := binary(parts[1], maximumSignatureBytes)
	if err != nil {
		return nil, err
	}

	if err := xmldsig.VerifyMessageWithParameters(ctx, canonical, value, cert.PublicKey, info.method, xmldsig.SignatureParameters{}, o.Policy); err != nil {
		return nil, err
	}

	return &Verified{message: m, certificate: bytes.Clone(cert.Raw), xml: true}, nil
}

type signedInfo struct {
	canonicalization, method, digestMethod string
	digestValue                            document.Element
}

func readSignedInfo(e document.Element, enveloped bool) (signedInfo, error) {
	const (
		digestReferenceChildCount    = 2
		envelopedReferenceChildCount = 3
		signedInfoChildCount         = 3
	)

	si, err := xmlutil.Children(e)
	if err != nil || len(si) != signedInfoChildCount || xmlutil.Attrs(e, nil, []string{lexicon.SecurityAttrID}) != nil {
		return signedInfo{}, ErrProof
	}

	if si[0].Name() != xmlutil.Name(xmlutil.DS, lexicon.DSigElementCanonicalizationMethod) || si[1].Name() != xmlutil.Name(xmlutil.DS, lexicon.DSigElementSignatureMethod) || si[2].Name() != xmlutil.Name(xmlutil.DS, lexicon.DSigElementReference) {
		return signedInfo{}, ErrProof
	}

	if xmlutil.Attrs(si[1], []string{algorithmAttribute}, nil) != nil || !xmlutil.EmptyContent(si[1]) {
		return signedInfo{}, ErrProof
	}

	_, method := tree.Unwrap(si[0])
	if _, err := transformxml.ParseCanonical(method, lexicon.DSigElementCanonicalizationMethod); err != nil {
		return signedInfo{}, err
	}

	ref, err := xmlutil.Children(si[2])
	if err == nil && enveloped {
		if len(ref) != envelopedReferenceChildCount || standardEnvelopedTransform(ref[0]) != nil {
			return signedInfo{}, ErrProof
		}

		ref = ref[1:]
	}

	if err != nil || xmlutil.Attrs(si[2], []string{lexicon.SecurityAttrURI}, nil) != nil || xmlutil.Attr(si[2], lexicon.SecurityAttrURI) != "" || len(ref) != digestReferenceChildCount || ref[0].Name() != xmlutil.Name(xmlutil.DS, lexicon.DSigElementDigestMethod) || ref[1].Name() != xmlutil.Name(xmlutil.DS, lexicon.DSigElementDigestValue) || xmlutil.Attrs(ref[0], []string{algorithmAttribute}, nil) != nil || !xmlutil.EmptyContent(ref[0]) {
		return signedInfo{}, ErrProof
	}

	return signedInfo{canonicalization: xmlutil.Attr(si[0], algorithmAttribute), method: xmlutil.Attr(si[1], algorithmAttribute), digestMethod: xmlutil.Attr(ref[0], algorithmAttribute), digestValue: ref[1]}, nil
}

func standardEnvelopedTransform(element document.Element) error {
	if element.Name() != xmlutil.Name(xmlutil.DS, lexicon.DSigElementTransforms) || xmlutil.Attrs(element, nil, nil) != nil {
		return ErrProof
	}

	children, err := xmlutil.Children(element)
	if err != nil || len(children) != 1 || children[0].Name() != xmlutil.Name(xmlutil.DS, lexicon.DSigElementTransform) || xmlutil.Attrs(children[0], []string{algorithmAttribute}, nil) != nil || xmlutil.Attr(children[0], algorithmAttribute) != reference.EnvelopedSignature || !xmlutil.EmptyContent(children[0]) {
		return ErrProof
	}

	return nil
}

func referenceDigest(ctx context.Context, d *document.Document, sig document.Element, algorithm string, p xmldsig.Policy) ([]byte, int, error) {
	allowed := p.AllowedDigestMethods
	if len(allowed) == 0 {
		allowed = xmldsig.DefaultPolicy().AllowedDigestMethods
	}

	if !slices.Contains(allowed, algorithm) {
		return nil, 0, ErrProof
	}

	var h hash.Hash

	switch algorithm {
	case xmldsig.SHA1:
		// Only the explicit digest allowlist reaches this compatibility case.
		if fips140.Enabled() || !crypto.SHA1.Available() {
			return nil, 0, ErrProof
		}

		h = crypto.SHA1.New()
	case xmldsig.SHA256:
		h = sha256.New()
	case xmldsig.SHA384:
		h = sha512.New384()
	case xmldsig.SHA512:
		h = sha512.New()
	default:
		return nil, 0, ErrProof
	}

	resolver, err := reference.NewSameDocumentResolver(ctx, d, document.Name{Local: lexicon.SAMLAttrID})
	if err != nil {
		return nil, 0, err
	}

	resolved, err := resolver.Resolve(ctx, "")
	if err != nil {
		return nil, 0, err
	}
	// Both APIs exclude only the proof Signature, retaining nested SAML signatures.
	// The enveloped API declares this transform; CS01 compatibility agrees it out
	// of band. Empty URI still removes comments.
	report, err := reference.Write(ctx, h, resolved.Data(), []reference.Transform{{Algorithm: reference.EnvelopedSignature}}, reference.Options{Signature: sig, MaxOutputBytes: canonicalLimit(p), MaxProducedBytes: canonicalLimit(p)})
	if err != nil {
		return nil, 0, err
	}

	return h.Sum(nil), report.Size(), nil
}

func canonicalLimit(p xmldsig.Policy) int {
	const (
		maximumCanonicalBytes = 32 << 20
	)

	if p.MaxCanonicalBytes > 0 {
		return min(p.MaxCanonicalBytes, maximumCanonicalBytes)
	}

	return maximumCanonicalBytes
}

func signedInfoBytes(ctx context.Context, si document.Element, algorithm string, maximum int) ([]byte, error) {
	if maximum < 1 {
		return nil, ErrProof
	}

	_, cm := tree.Unwrap(si.Children()[0])

	method, err := transformxml.ParseCanonical(cm, lexicon.DSigElementCanonicalizationMethod)
	if err != nil || method.Algorithm != algorithm {
		return nil, ErrProof
	}

	var out bytes.Buffer

	err = c14n.WriteElement(ctx, &out, si, c14n.Options{Algorithm: algorithm, InclusivePrefixes: method.InclusivePrefixes, MaxOutputBytes: maximum})

	return out.Bytes(), err
}

func readCertificate(info document.Element) ([]byte, error) {
	if info.Name() != xmlutil.Name(xmlutil.DS, lexicon.DSigElementKeyInfo) || xmlutil.Attrs(info, nil, []string{lexicon.SecurityAttrID}) != nil {
		return nil, ErrProof
	}

	cs, err := xmlutil.Children(info)
	if err != nil || len(cs) != 1 || cs[0].Name() != xmlutil.Name(xmlutil.DS, lexicon.DSigElementX509Data) || xmlutil.Attrs(cs[0], nil, nil) != nil {
		return nil, ErrProof
	}

	data, err := xmlutil.Children(cs[0])
	if err != nil || len(data) != 1 || data[0].Name() != xmlutil.Name(xmlutil.DS, lexicon.DSigElementX509Certificate) {
		return nil, ErrProof
	}

	return binary(data[0], maximumCertificateBytes)
}

func binary(e document.Element, maximum int) ([]byte, error) {
	text, err := xmlutil.Simple(e, 2*maximum)
	if err != nil {
		return nil, err
	}

	text = strings.Map(func(r rune) rune {
		if r == ' ' || r == '\t' || r == '\r' || r == '\n' {
			return -1
		}

		return r
	}, text)

	value, err := base64.StdEncoding.Strict().DecodeString(text)
	if err != nil || len(value) > maximum {
		return nil, ErrProof
	}

	return value, nil
}

func addSecurity(root *tree.Node) (*tree.Node, error) {
	const (
		prefixWSSE      = "wsse"
		soapBooleanTrue = "1"
	)

	var header *tree.Node

	for _, c := range root.Children {
		if c.Kind == tree.ElementNode && c.Name == xmlutil.Name(binding.SOAPNamespace, soapHeaderElement) {
			header = c
		}
	}

	if header == nil {
		header = xmlutil.Node(root.Prefix, binding.SOAPNamespace, soapHeaderElement)
		header.Parent = root
		root.Children = append([]*tree.Node{header}, root.Children...)
	}

	for _, c := range header.Children {
		if c.Name == xmlutil.Name(SecurityNamespace, xmlNameSecurity) {
			return nil, ErrProof
		}
	}

	security := xmlutil.Node(prefixWSSE, SecurityNamespace, xmlNameSecurity)
	security.NS = []tree.Namespace{{Prefix: prefixWSSE, URI: SecurityNamespace}, {Prefix: soapPrefix, URI: binding.SOAPNamespace}}
	security.Attrs = []tree.Attribute{{Name: xmlutil.Name(binding.SOAPNamespace, soapActorAttribute), Prefix: soapPrefix, Value: binding.SOAPNext}, {Name: xmlutil.Name(binding.SOAPNamespace, soapMustUnderstandAttribute), Prefix: soapPrefix, Value: soapBooleanTrue}}
	xmlutil.Add(header, security)

	return security, nil
}

func proofSignature(d *document.Document) (document.Element, error) {
	var selected document.Element

	for _, header := range d.Root().Children() {
		if header.Name() != xmlutil.Name(binding.SOAPNamespace, soapHeaderElement) {
			continue
		}

		for _, security := range header.Children() {
			if security.Name() != xmlutil.Name(SecurityNamespace, xmlNameSecurity) {
				continue
			}

			if selected.Valid() {
				return document.Element{}, ErrProof
			}

			for _, a := range security.Attributes() {
				if a.Name.Space != binding.SOAPNamespace || a.Name.Local == soapActorAttribute && a.Value != binding.SOAPNext && a.Value != "" || a.Name.Local != soapActorAttribute && a.Name.Local != soapMustUnderstandAttribute {
					return document.Element{}, ErrProof
				}
			}

			cs, err := xmlutil.Children(security)
			if err != nil || len(cs) != 1 || cs[0].Name() != xmlutil.Name(xmlutil.DS, lexicon.DSigElementSignature) {
				return document.Element{}, ErrProof
			}

			selected = cs[0]
		}
	}

	if !selected.Valid() {
		return document.Element{}, ErrProof
	}

	return selected, nil
}

func allHeaderNames(d *document.Document) []document.Name {
	var out []document.Name

	for _, h := range d.Root().Children() {
		if h.Name() == xmlutil.Name(binding.SOAPNamespace, soapHeaderElement) {
			for _, c := range h.Children() {
				out = append(out, c.Name())
			}
		}
	}

	return out
}
