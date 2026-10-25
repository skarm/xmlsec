package xades

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"mime"
	"strings"
	"time"

	"github.com/skarm/xmlsec/internal/lexicon"

	"github.com/skarm/xmlsec/c14n"
	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/internal/nilcheck"
	"github.com/skarm/xmlsec/internal/streamio"
	"github.com/skarm/xmlsec/internal/tree"
	"github.com/skarm/xmlsec/internal/x509cert"
	"github.com/skarm/xmlsec/internal/xmltime"
	"github.com/skarm/xmlsec/pki"
	"github.com/skarm/xmlsec/reference"
	"github.com/skarm/xmlsec/xmldsig"
)

const (
	// Namespace is the XAdES 1.3.2 namespace URI.
	Namespace = "http://uri.etsi.org/01903/v1.3.2#"
	// SignedPropertiesType is the XAdES SignedProperties reference type URI.
	SignedPropertiesType = "http://uri.etsi.org/01903#SignedProperties"
)

var (
	// ErrProfile reports unsupported or invalid basic enveloped XAdES profile.
	ErrProfile = errors.New("unsupported or invalid basic enveloped XAdES profile")
	// ErrCertificate reports XAdES signing certificate binding mismatch.
	ErrCertificate = errors.New("XAdES signing certificate binding mismatch")
)

// SignOptions configures the closed basic enveloped XAdES profile and its claimed signing
// time.
type SignOptions struct {
	SignatureID, SignedPropertiesID, DataReferenceID string
	// SignatureMethod is required, for example xmldsig.ECDSASHA256.
	SignatureMethod string
	// ClaimedSigningTime is required and serialized in UTC. This signer claim is not a
	// trusted timestamp.
	ClaimedSigningTime time.Time
	// MIMEType defaults to application/xml.
	MIMEType string
	// IDAttribute selects the application root attribute; zero uses unqualified ID.
	IDAttribute document.Name
	Policy      xmldsig.Policy
}

// VerifyOptions selects the application ID attribute and XML signature policy for basic
// XAdES.
type VerifyOptions struct {
	// IDAttribute selects the application ID attribute; it is never inferred from a schema.
	IDAttribute document.Name
	Policy      xmldsig.Policy
}

// BasicResult authenticates this profile's properties with the EXPLICITLY
// supplied certificate's key. It does not validate certificate dates, PKIX,
// revocation, claimed time, legal status or any other AdES evidence.
type BasicResult struct {
	signature   *xmldsig.SignatureResult
	properties  document.Element
	certificate []byte
	claimedTime time.Time
	mimeType    string
}

type basicPropertySet struct {
	signed          document.Element
	id              string
	signature, data document.Element
}

// VerifyBasicEnveloped validates the small profile described by this package.
// trustedCertificateDER is an EXTERNAL trust decision, not a candidate selected
// from KeyInfo. Certificate pinning is not PKIX; call pki.Verifier separately when
// a certificate path and revocation policy are required. Unsupported properties
// (including timestamps) are rejected rather than silently ignored/downgraded.
func VerifyBasicEnveloped(ctx context.Context, doc *document.Document, selected document.Element, trustedCertificateDER []byte, o VerifyOptions) (*BasicResult, error) {
	return verifyBasicEnveloped(ctx, doc, selected, trustedCertificateDER, o, false)
}

func localAttribute(e document.Element, k string) string {
	v, _ := e.Attribute(document.Name{Local: k})
	return v
}

// children enforces a fixed, small profile (not a general XAdES schema parser).
// Comments/PIs are ignored; application results never use their values.
func children(e document.Element, names ...document.Name) ([]document.Element, error) {
	_, n := tree.Unwrap(e)
	if n == nil {
		return nil, ErrProfile
	}

	for _, v := range n.Children {
		if v.Kind == tree.TextNode && !xmlSpace(v.Data) {
			return nil, ErrProfile
		}
	}

	a := e.Children()
	if len(a) != len(names) {
		return nil, ErrProfile
	}

	for i, n := range names {
		if a[i].Name() != n {
			return nil, ErrProfile
		}
	}

	return a, nil
}

func attrs(e document.Element, names ...string) error {
	_, n := tree.Unwrap(e)
	if n == nil || len(n.Attrs) != len(names) {
		return ErrProfile
	}

	for _, a := range n.Attrs {
		if a.Name.Space != "" {
			return ErrProfile
		}

		found := false

		for _, name := range names {
			if a.Name.Local == name {
				found = true
			}
		}

		if !found {
			return ErrProfile
		}
	}

	return nil
}

func simple(e document.Element) (string, error) {
	if len(e.Children()) != 0 || attrs(e) != nil {
		return "", ErrProfile
	}

	return e.Text(), nil
}

func decodeElementBase64(ctx context.Context, element document.Element, encodedLimit, decodedLimit int) ([]byte, error) {
	if ctx == nil || !element.Valid() || encodedLimit < 0 || decodedLimit < 0 {
		return nil, ErrProfile
	}

	_, node := tree.Unwrap(element)

	encodedLength, err := base64TextLength(ctx, node.Children, encodedLimit)
	if err != nil {
		return nil, err
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	if encodedLength > base64.StdEncoding.EncodedLen(decodedLimit) {
		return nil, ErrProfile
	}

	decoder := base64.NewDecoder(base64.StdEncoding.Strict(), &base64TextReader{ctx: ctx, nodes: node.Children})
	reader := &streamio.Reader{Context: ctx, Source: decoder, Limit: int64(decodedLimit), LimitError: ErrProfile}
	output := make([]byte, min(base64.StdEncoding.DecodedLen(encodedLength), decodedLimit))
	used := 0

	var probe [1]byte

	for {
		destination := output[used:]
		if len(destination) == 0 {
			destination = probe[:]
		}

		n, err := reader.Read(destination)
		if n > len(output)-used {
			return nil, ErrProfile
		}

		used += n

		if err != nil {
			if errors.Is(err, io.EOF) {
				if err := ctx.Err(); err != nil {
					return nil, err
				}

				return output[:used:used], nil
			}

			return nil, errors.Join(ErrProfile, err)
		}
	}
}

// unsigned=true is only used by higher profiles which MUST validate every
// unsigned property before returning their result. The public basic API stays closed.
func verifyBasicEnveloped(ctx context.Context, doc *document.Document, selected document.Element, trustedCertificateDER []byte, o VerifyOptions, unsigned bool) (*BasicResult, error) {
	if ctx == nil || doc == nil || !selected.Valid() {
		return nil, ErrProfile
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	all := xmldsig.Signatures(doc)
	if len(all) != 1 || !all[0].Same(selected) {
		return nil, ErrProfile
	}

	_, node := tree.Unwrap(selected)
	if node.Parent != tree.Root(doc) {
		return nil, ErrProfile
	}

	certificate, err := cert(trustedCertificateDER)
	if err != nil {
		return nil, err
	}

	if attrs(selected, "Id") != nil {
		return nil, ErrProfile
	}

	sigID := localAttribute(selected, "Id")
	if !tree.NCName(sigID) {
		return nil, ErrProfile
	}

	sc, err := children(selected, ds(lexicon.DSigElementSignedInfo), ds(lexicon.DSigElementSignatureValue), ds(lexicon.DSigElementKeyInfo), ds("Object"))
	if err != nil {
		return nil, err
	}

	if err := verifyEmbeddedCertificate(ctx, sc[2], certificate); err != nil {
		return nil, err
	}

	properties, err := parseBasicProperties(sc[3], sigID, unsigned)
	if err != nil {
		return nil, err
	}

	sp, spID := properties.signed, properties.id

	ssp, err := children(properties.signature, name("SigningTime"), name("SigningCertificateV2"))
	if err != nil {
		return nil, err
	}

	claimed, err := parseClaimedSigningTime(ssp[0])
	if err != nil {
		return nil, err
	}

	if err := verifySigningCertificate(ctx, ssp[1], certificate); err != nil {
		return nil, err
	}

	fmtRef, mimeType, err := parseBasicDataFormat(properties.data)
	if err != nil {
		return nil, err
	}

	siChildren := sc[0].Children()
	if len(siChildren) != 4 {
		return nil, ErrProfile
	}

	rootID, ok := doc.Root().Attribute(normalizeID(o.IDAttribute))
	if !ok || !tree.NCName(rootID) {
		return nil, ErrProfile
	}

	refs := siChildren[2:]

	dataID := localAttribute(refs[0], "Id")
	if !tree.NCName(dataID) || fmtRef != "#"+dataID {
		return nil, ErrProfile
	}

	if localAttribute(refs[0], "URI") != "#"+rootID || localAttribute(refs[0], "Type") != "" || localAttribute(refs[1], "URI") != "#"+spID || localAttribute(refs[1], "Type") != SignedPropertiesType {
		return nil, ErrProfile
	}
	// Exact transforms preserve original-node coverage and exclude only our Signature.
	if err := validateBasicTransforms(refs); err != nil {
		return nil, err
	}

	opt := profileOptions(o.IDAttribute, o.Policy, doc.Root(), sp, rootID, spID)

	verified, err := xmldsig.VerifySignature(ctx, doc, selected, certificate.PublicKey, opt)
	if err != nil {
		return nil, err
	}

	return &BasicResult{signature: verified, properties: sp, certificate: certificate.Raw, claimedTime: claimed, mimeType: mimeType}, nil
}

// XML S is only space, tab, CR and LF, not Unicode's broader whitespace set.
func xmlSpace(s string) bool {
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case ' ', '\t', '\r', '\n':
		default:
			return false
		}
	}

	return true
}

func validateBasicTransforms(refs []tree.Element) error {
	for i, r := range refs {
		a := r.Children()
		if len(a) != 3 || a[0].Name() != ds(lexicon.DSigElementTransforms) {
			return ErrProfile
		}

		trs := a[0].Children()

		want := []string{c14n.Exclusive}
		if i == 0 {
			want = []string{reference.EnvelopedSignature, c14n.Exclusive}
		}

		if len(trs) != len(want) {
			return ErrProfile
		}

		for j, t := range trs {
			if t.Name() != ds(lexicon.DSigElementTransform) || attrs(t, "Algorithm") != nil || len(t.Children()) != 0 || localAttribute(t, "Algorithm") != want[j] {
				return ErrProfile
			}
		}
	}

	return nil
}

func verifyEmbeddedCertificate(ctx context.Context, keyInfo document.Element, certificate *x509.Certificate) error {
	ki, err := children(keyInfo, ds(lexicon.DSigElementX509Data))
	if err != nil || attrs(keyInfo) != nil {
		return ErrProfile
	}

	xc, err := children(ki[0], ds(lexicon.DSigElementX509Certificate))
	if err != nil || attrs(ki[0]) != nil {
		return ErrProfile
	}

	if len(xc[0].Children()) != 0 || attrs(xc[0]) != nil {
		return ErrProfile
	}

	owner, _ := tree.Unwrap(keyInfo)

	embedded, err := decodeElementBase64(ctx, xc[0], tree.Policy(owner).MaxBytes, len(certificate.Raw))
	if err != nil {
		return errors.Join(ErrCertificate, err)
	}

	if !bytes.Equal(embedded, certificate.Raw) {
		return ErrCertificate
	}

	return nil
}

func verifySigningCertificate(ctx context.Context, property document.Element, certificate *x509.Certificate) error {
	cv, err := children(property, name("Cert"))
	if err != nil || attrs(property) != nil {
		return ErrProfile
	}

	cd, err := children(cv[0], name("CertDigest"))
	if err != nil || attrs(cv[0]) != nil {
		return ErrProfile
	}

	cvd, err := children(cd[0], ds(lexicon.DSigElementDigestMethod), ds(lexicon.DSigElementDigestValue))
	if err != nil || attrs(cd[0]) != nil {
		return ErrProfile
	}

	if attrs(cvd[0], "Algorithm") != nil || len(cvd[0].Children()) != 0 || !xmlSpace(cvd[0].Text()) || localAttribute(cvd[0], "Algorithm") != xmldsig.SHA256 {
		return ErrProfile
	}

	if len(cvd[1].Children()) != 0 || attrs(cvd[1]) != nil {
		return ErrProfile
	}

	owner, _ := tree.Unwrap(property)

	digest, err := decodeElementBase64(ctx, cvd[1], tree.Policy(owner).MaxBytes, sha256.Size)
	if err != nil {
		return errors.Join(ErrCertificate, err)
	}

	sum := sha256.Sum256(certificate.Raw)
	if subtle.ConstantTimeCompare(digest, sum[:]) != 1 {
		return ErrCertificate
	}

	return nil
}

func parseClaimedSigningTime(property document.Element) (time.Time, error) {
	ts, err := simple(property)
	if err != nil || !strings.HasSuffix(ts, "Z") {
		return time.Time{}, ErrProfile
	}

	claimed, err := xmltime.ParseUTC(ts)
	if err != nil {
		return time.Time{}, ErrProfile
	}

	return claimed, nil
}

func parseBasicProperties(object document.Element, sigID string, unsigned bool) (basicPropertySet, error) {
	ob, err := children(object, name("QualifyingProperties"))
	if err != nil || attrs(object) != nil {
		return basicPropertySet{}, ErrProfile
	}

	qp := ob[0]
	if attrs(qp, "Target") != nil || localAttribute(qp, "Target") != "#"+sigID {
		return basicPropertySet{}, ErrProfile
	}

	qpNames := []document.Name{name("SignedProperties")}
	if unsigned && len(qp.Children()) == 2 {
		qpNames = append(qpNames, name("UnsignedProperties"))
	}

	qpChildren, err := children(qp, qpNames...)
	if err != nil {
		return basicPropertySet{}, err
	}

	sp := qpChildren[0]
	if attrs(sp, "Id") != nil {
		return basicPropertySet{}, ErrProfile
	}

	spID := localAttribute(sp, "Id")
	if !tree.NCName(spID) {
		return basicPropertySet{}, ErrProfile
	}

	spChildren, err := children(sp, name("SignedSignatureProperties"), name("SignedDataObjectProperties"))
	if err != nil {
		return basicPropertySet{}, err
	}

	if attrs(spChildren[0]) != nil || attrs(spChildren[1]) != nil {
		return basicPropertySet{}, ErrProfile
	}

	return basicPropertySet{signed: sp, id: spID, signature: spChildren[0], data: spChildren[1]}, nil
}

func parseBasicDataFormat(data document.Element) (string, string, error) {
	formats, err := children(data, name("DataObjectFormat"))
	if err != nil {
		return "", "", err
	}

	if attrs(formats[0], "ObjectReference") != nil {
		return "", "", ErrProfile
	}

	fmtRef := localAttribute(formats[0], "ObjectReference")

	mts, err := children(formats[0], name("MimeType"))
	if err != nil {
		return "", "", err
	}

	mimeType, err := simple(mts[0])
	if err != nil || !validMime(mimeType) {
		return "", "", ErrProfile
	}

	return fmtRef, mimeType, nil
}

func base64TextLength(ctx context.Context, nodes []*tree.Node, encodedLimit int) (int, error) {
	remaining, encodedLength := encodedLimit, 0

	for _, child := range nodes {
		if child.Kind == tree.ElementNode {
			return 0, ErrProfile
		}

		if child.Kind != tree.TextNode {
			continue
		}

		if len(child.Data) > remaining {
			return 0, ErrProfile
		}

		remaining -= len(child.Data)
		for i := range len(child.Data) {
			if i&4095 == 0 {
				if err := ctx.Err(); err != nil {
					return 0, err
				}
			}

			if !base64Space(child.Data[i]) {
				encodedLength++
			}
		}
	}

	return encodedLength, nil
}

// Signature returns the underlying verified XML signature result.
func (r *BasicResult) Signature() *xmldsig.SignatureResult {
	if r == nil {
		return nil
	}

	return r.signature
}

// SignedProperties returns the authenticated SignedProperties handle.
func (r *BasicResult) SignedProperties() document.Element {
	if r == nil {
		return document.Element{}
	}

	return r.properties
}

// CertificateDER returns an owned copy of the certificate DER.
func (r *BasicResult) CertificateDER() []byte {
	if r == nil {
		return nil
	}

	return bytes.Clone(r.certificate)
}

// ClaimedSigningTime returns the signed claimed signing time; it is not trusted timestamp
// evidence.
func (r *BasicResult) ClaimedSigningTime() time.Time {
	if r == nil {
		return time.Time{}
	}

	return r.claimedTime
}

// MIMEType returns the signed MIME type claim.
func (r *BasicResult) MIMEType() string {
	if r == nil {
		return ""
	}

	return r.mimeType
}

// SignBasicEnveloped creates and self-verifies a new document. The input must
// have an application ID on its root and no existing Signature. Certificate DER
// is bound by SHA-256, embedded as X509Data, and must match signer's public key.
// No trust chain or revocation status is inferred from the embedded certificate.
func SignBasicEnveloped(ctx context.Context, doc *document.Document, signer crypto.Signer, certificateDER []byte, o SignOptions) (*document.Document, *BasicResult, error) {
	if ctx == nil || doc == nil || !doc.Root().Valid() || nilcheck.IsNil(signer) {
		return nil, nil, ErrProfile
	}

	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}

	c, err := cert(certificateDER)
	if err != nil {
		return nil, nil, err
	}

	if len(xmldsig.Signatures(doc)) != 0 || o.ClaimedSigningTime.IsZero() || o.ClaimedSigningTime.UTC().Year() < 1 || o.ClaimedSigningTime.UTC().Year() > 9999 {
		return nil, nil, ErrProfile
	}
	// Use a DER pin rather than relying on a provider-specific key representation.
	if key, ok := signer.(ed25519.PrivateKey); ok && len(key) != ed25519.PrivateKeySize {
		return nil, nil, ErrCertificate
	}

	pin, err := pki.NewKeyPin(signer.Public())
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %w", ErrCertificate, err)
	}

	if err := pin.MatchCertificate(c.Raw); err != nil {
		return nil, nil, ErrCertificate
	}

	if o.SignatureID == "" {
		o.SignatureID = "signature"
	}

	if o.SignedPropertiesID == "" {
		o.SignedPropertiesID = "signed-properties"
	}

	if o.DataReferenceID == "" {
		o.DataReferenceID = "data-reference"
	}

	for _, id := range []string{o.SignatureID, o.SignedPropertiesID, o.DataReferenceID} {
		if !tree.NCName(id) {
			return nil, nil, ErrProfile
		}
	}

	if o.MIMEType == "" {
		o.MIMEType = "application/xml"
	}

	if !validMime(o.MIMEType) {
		return nil, nil, ErrProfile
	}

	idAttr := normalizeID(o.IDAttribute)

	rootID, ok := doc.Root().Attribute(idAttr)
	if !ok || !tree.NCName(rootID) {
		return nil, nil, ErrProfile
	}

	qp := xnode("QualifyingProperties")
	qp.NS = []tree.Namespace{{Prefix: nameXades, URI: Namespace}, {Prefix: "ds", URI: xmldsig.Namespace}}
	attr(qp, "Target", "#"+o.SignatureID)

	sp := xnode("SignedProperties")
	attr(sp, "Id", o.SignedPropertiesID)
	add(qp, sp)

	ssp := xnode("SignedSignatureProperties")
	add(sp, ssp)

	st := xnode("SigningTime")
	text(st, o.ClaimedSigningTime.UTC().Format(time.RFC3339Nano))
	add(ssp, st)

	sc := xnode("SigningCertificateV2")
	ce := xnode("Cert")
	cd := xnode("CertDigest")
	dm := dsnode(lexicon.DSigElementDigestMethod)
	attr(dm, "Algorithm", xmldsig.SHA256)

	dv := dsnode(lexicon.DSigElementDigestValue)
	sum := sha256.Sum256(c.Raw)
	text(dv, base64.StdEncoding.EncodeToString(sum[:]))
	add(cd, dm)
	add(cd, dv)
	add(ce, cd)
	add(sc, ce)
	add(ssp, sc)

	sdop := xnode("SignedDataObjectProperties")
	dof := xnode("DataObjectFormat")
	attr(dof, "ObjectReference", "#"+o.DataReferenceID)

	mt := xnode("MimeType")
	text(mt, o.MIMEType)
	add(dof, mt)
	add(sdop, dof)
	add(sp, sdop)

	propsDoc := tree.FromNodes([]*tree.Node{qp}, document.DefaultLimits())
	ex := reference.Transform{Algorithm: c14n.Exclusive}

	draft, selected, err := xmldsig.BuildTemplate(ctx, doc, doc.Root(), xmldsig.SignatureTemplate{
		ID: o.SignatureID, SignatureMethod: o.SignatureMethod, Canonicalization: ex, Certificates: [][]byte{c.Raw},
		References: []xmldsig.ReferenceTemplate{
			{ID: o.DataReferenceID, URI: "#" + rootID, Transforms: []reference.Transform{{Algorithm: reference.EnvelopedSignature}, ex}},
			{URI: "#" + o.SignedPropertiesID, Type: SignedPropertiesType, Transforms: []reference.Transform{ex}},
		},
		Objects: []xmldsig.ObjectTemplate{{XML: propsDoc}},
	})
	if err != nil {
		return nil, nil, err
	}

	object, err := childNamed(selected, ds("Object"))
	if err != nil {
		return nil, nil, err
	}

	properties, err := childNamed(object, name("QualifyingProperties"))
	if err != nil {
		return nil, nil, err
	}

	props, err := childNamed(properties, name("SignedProperties"))
	if err != nil {
		return nil, nil, err
	}

	opt := profileOptions(idAttr, o.Policy, draft.Root(), props, rootID, o.SignedPropertiesID)

	signed, err := xmldsig.SignTemplate(ctx, draft, selected, signer, xmldsig.TemplateSignOptions{Validation: opt})
	if err != nil {
		return nil, nil, err
	}

	result, err := VerifyBasicEnveloped(ctx, signed, xmldsig.Signatures(signed)[0], c.Raw, VerifyOptions{IDAttribute: idAttr, Policy: o.Policy})
	if err != nil {
		return nil, nil, err
	}

	return signed, result, nil
}

func xnode(local string) *tree.Node {
	return &tree.Node{Kind: tree.ElementNode, Name: document.Name{Space: Namespace, Local: local}, Prefix: nameXades}
}

func dsnode(local string) *tree.Node {
	return &tree.Node{Kind: tree.ElementNode, Name: document.Name{Space: xmldsig.Namespace, Local: local}, Prefix: "ds"}
}

func add(p, c *tree.Node) { p.Children = append(p.Children, c); c.Parent = p }

func text(n *tree.Node, s string) { add(n, &tree.Node{Kind: tree.TextNode, Data: s}) }

func attr(n *tree.Node, k, v string) {
	n.Attrs = append(n.Attrs, tree.Attribute{Name: document.Name{Local: k}, Value: v})
}

func childNamed(e document.Element, n document.Name) (document.Element, error) {
	var out document.Element

	for _, c := range e.Children() {
		if c.Name() == n {
			if out.Valid() {
				return document.Element{}, ErrProfile
			}

			out = c
		}
	}

	if !out.Valid() {
		return out, ErrProfile
	}

	return out, nil
}

func normalizeID(n document.Name) document.Name {
	if n == (document.Name{}) {
		return document.Name{Local: "ID"}
	}

	return n
}

func cert(der []byte) (*x509.Certificate, error) {
	if len(der) == 0 || len(der) > 1<<20 {
		return nil, ErrCertificate
	}

	c, e := x509cert.ParseWithMaxBytes(bytes.Clone(der), len(der))
	if e != nil {
		return nil, fmt.Errorf("%w: %w", ErrCertificate, e)
	}

	return c, nil
}

func validMime(s string) bool {
	if len(s) == 0 || len(s) > 256 {
		return false
	}

	_, _, err := mime.ParseMediaType(s)

	return err == nil && !strings.ContainsAny(s, "\r\n")
}

func profileOptions(id document.Name, policy xmldsig.Policy, root, props document.Element, rootID, propsID string) xmldsig.SignatureOptions {
	return xmldsig.SignatureOptions{
		IDAttribute: normalizeID(id), Policy: policy,
		AdditionalIDRules: []reference.IDAttributeRule{{Attribute: document.Name{Local: "Id"}, Elements: []document.Name{{Space: Namespace, Local: "SignedProperties"}}}},
		RequiredElements:  []document.Element{root, props}, ExpectedURIs: []string{"#" + rootID, "#" + propsID},
	}
}

func name(l string) document.Name { return document.Name{Space: Namespace, Local: l} }

func ds(l string) document.Name { return document.Name{Space: xmldsig.Namespace, Local: l} }

func base64Space(c byte) bool { return c == ' ' || c == '\n' || c == '\r' || c == '\t' }

// base64TextReader borrows direct text nodes and skips only XML whitespace.
type base64TextReader struct {
	ctx   context.Context
	nodes []*tree.Node
	text  string
}

func (r *base64TextReader) Read(dst []byte) (int, error) {
	if len(dst) == 0 {
		return 0, nil
	}

	used := 0
	for used < len(dst) {
		if err := r.ctx.Err(); err != nil {
			return used, err
		}

		for r.text == "" {
			if len(r.nodes) == 0 {
				if used > 0 {
					return used, nil
				}

				return 0, io.EOF
			}

			node := r.nodes[0]

			r.nodes = r.nodes[1:]
			if node.Kind == tree.TextNode {
				r.text = node.Data
			}
		}

		span := r.text[:min(len(r.text), 4096)]

		taken := 0
		for taken < len(span) && used < len(dst) {
			c := span[taken]
			taken++

			if !base64Space(c) {
				dst[used] = c
				used++
			}
		}

		r.text = r.text[taken:]
	}

	return used, nil
}
