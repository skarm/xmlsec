package keyinfo

import (
	"context"
	"crypto"

	// #nosec G406 -- Explicit bounded legacy compatibility only.
	"crypto/dsa" //nolint:staticcheck // XMLDSig 1.1 requires legacy DSA verification; generation is disabled.
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"
	"math/big"
	"net/url"
	"strings"

	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/internal/ecdsakey"
	"github.com/skarm/xmlsec/internal/lexicon"
	"github.com/skarm/xmlsec/internal/signature"
	"github.com/skarm/xmlsec/internal/tree"
	"github.com/skarm/xmlsec/reference"
)

// Parse reads one explicitly selected ds:KeyInfo in the supplied snapshot.
// Unsupported choices are errors, not silently ignored extensions. KeyName is
// preserved verbatim. KeyInfoReference/typed RetrievalMethod follow bounded
// references. Additional RetrievalMethod chains require explicit processing
// policy; no arbitrary program runs during key discovery by default.
func Parse(ctx context.Context, doc *document.Document, selected document.Element, opt Options) (*Result, error) {
	if ctx == nil || doc == nil {
		return nil, ErrInput
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	d, n := tree.Unwrap(selected)
	if d != doc || n == nil || !is(n, Namespace, lexicon.DSigElementKeyInfo) {
		return nil, ErrInput
	}
	// Freeze nested ID-rule slices before any application resolver can run.
	rules := make([]reference.IDAttributeRule, len(opt.AdditionalIDRules))
	for i, r := range opt.AdditionalIDRules {
		rules[i] = reference.IDAttributeRule{Attribute: r.Attribute, Elements: append([]document.Name(nil), r.Elements...)}
	}

	opt.AdditionalIDRules = rules

	l, err := normalizeLimits(opt.Limits)
	if err != nil {
		return nil, err
	}

	p := &parser{ctx: ctx, limits: l, options: opt, active: make(map[visitKey]struct{}), scopes: make(map[*document.Document]*scope), resources: make(map[string]resourceBlob), parsedResources: make(map[string]*scope), allow: make(map[string]struct{})}
	if err := p.configureKeyData(); err != nil {
		return nil, err
	}

	if err := p.configureExternal(); err != nil {
		return nil, err
	}

	if err := p.configureRetrieval(); err != nil {
		return nil, err
	}

	if err := p.configureDSAParameters(); err != nil {
		return nil, err
	}

	s, err := p.newScope(doc, "")
	if err != nil {
		return nil, err
	}

	if err := p.keyInfo(s, n, 0); err != nil {
		return nil, err
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	return &p.result, nil
}

// DefaultIDRules returns a fresh copy of the supported default ID attribute rules.
func DefaultIDRules() []reference.IDAttributeRule {
	return []reference.IDAttributeRule{{Attribute: document.Name{Local: "Id"}, Elements: []document.Name{
		{Space: Namespace, Local: lexicon.DSigElementKeyInfo},
		{Space: Namespace11, Local: nameECKeyValue},
		{Space: Namespace11, Local: nameDEREncodedKeyValue},
		{Space: Namespace11, Local: nameKeyInfoReference},
	}}}
}

type scope struct {
	doc      *document.Document
	resolver *reference.SameDocumentResolver
	resource string
}

type visitKey struct {
	doc  *document.Document
	node *tree.Node
}

type parser struct {
	ctx               context.Context
	limits            Limits
	options           Options
	result            Result
	elements          int
	total             int
	externalBytes     int
	active            map[visitKey]struct{}
	scopes            map[*document.Document]*scope
	resources         map[string]resourceBlob
	parsedResources   map[string]*scope
	allow             map[string]struct{}
	keyData           map[document.Name]struct{}
	externalReads     int
	transformBytes    int
	transformNodes    int
	retrievalPlans    map[visitKey]retrievalPlan
	rawResources      map[string][]byte
	transformedScopes map[retrievalOutput]*scope
	baseURI           *url.URL
}

func (p *parser) newScope(d *document.Document, resource string) (*scope, error) {
	if old, ok := p.scopes[d]; ok {
		return old, nil
	}

	rules := append(DefaultIDRules(), p.options.AdditionalIDRules...)

	r, err := reference.NewSameDocumentResolverWithRules(p.ctx, d, rules)
	if err != nil {
		return nil, fmt.Errorf("%w: ID index: %w", ErrInput, err)
	}

	s := &scope{doc: d, resolver: r, resource: resource}
	p.scopes[d] = s

	return s, nil
}

func (p *parser) enter(s *scope, n *tree.Node, depth int) (func(), error) {
	if err := p.ctx.Err(); err != nil {
		return nil, err
	}

	if depth > p.limits.MaxDepth {
		return nil, fmt.Errorf("%w: reference depth", ErrLimit)
	}

	p.elements++
	if p.elements > p.limits.MaxElements {
		return nil, fmt.Errorf("%w: visited elements", ErrLimit)
	}

	k := visitKey{s.doc, n}
	if _, exists := p.active[k]; exists {
		return nil, ErrCycle
	}

	p.active[k] = struct{}{}

	return func() { delete(p.active, k) }, nil
}

func (p *parser) keyInfo(s *scope, n *tree.Node, depth int) error {
	leave, err := p.enter(s, n, depth)
	if err != nil {
		return err
	}
	defer leave()

	children, err := structure(n, Namespace, lexicon.DSigElementKeyInfo, "Id")
	if err != nil {
		return err
	}

	if len(children) == 0 {
		return fmt.Errorf("%w: empty KeyInfo", ErrInput)
	}
	// Preflight every direct choice before processing any link in this KeyInfo.
	// A disallowed later sibling must not cause an earlier external read.
	for _, child := range children {
		if err := p.checkKeyData(child); err != nil {
			return err
		}

		if is(child, Namespace, "RetrievalMethod") {
			if _, err := p.prepareRetrieval(s, child); err != nil {
				return err
			}
		}

		if is(child, Namespace11, nameKeyInfoReference) {
			if _, err := p.keyInfoReferenceURI(s, child); err != nil {
				return err
			}
		}
	}

	for _, child := range children {
		if err := p.item(s, child, depth); err != nil {
			return err
		}
	}

	return nil
}

func (p *parser) item(s *scope, n *tree.Node, depth int) error {
	if err := p.checkKeyData(n); err != nil {
		return err
	}

	leave, err := p.enter(s, n, depth)
	if err != nil {
		return err
	}
	defer leave()

	switch n.Name {
	case document.Name{Space: Namespace, Local: lexicon.DSigElementKeyName}:
		value, err := p.stringValue(n)
		if err != nil {
			return err
		}

		p.result.names = append(p.result.names, value)

		return nil
	case document.Name{Space: Namespace, Local: lexicon.DSigElementKeyValue}:
		c, err := structure(n, Namespace, lexicon.DSigElementKeyValue)
		if err != nil {
			return err
		}

		if len(c) != 1 {
			return fmt.Errorf("%w: KeyValue needs one key", ErrInput)
		}

		if is(c[0], Namespace11, nameDEREncodedKeyValue) {
			return fmt.Errorf("%w: DEREncodedKeyValue must not be inside KeyValue", ErrUnsupported)
		}

		return p.bareKey(s, c[0])
	case document.Name{Space: Namespace11, Local: nameDEREncodedKeyValue}:
		return p.bareKey(s, n)
	case document.Name{Space: Namespace, Local: nameX509Data}:
		return p.x509Data(s, n)
	case document.Name{Space: Namespace11, Local: nameKeyInfoReference}:
		if depth >= p.limits.MaxDepth {
			return ErrLimit
		}

		uri, err := p.keyInfoReferenceURI(s, n)
		if err != nil {
			return err
		}

		target, scope, err := p.resolveXML(s, uri)
		if err != nil {
			return err
		}

		if !is(target, Namespace, lexicon.DSigElementKeyInfo) {
			return fmt.Errorf("%w: KeyInfoReference target is not KeyInfo", ErrInput)
		}

		return p.keyInfo(scope, target, depth+1)
	case document.Name{Space: Namespace, Local: "RetrievalMethod"}:
		return p.retrieve(s, n, depth)
	default:
		return fmt.Errorf("%w: {%s}%s", ErrUnsupported, n.Name.Space, n.Name.Local)
	}
}

func (p *parser) charge(n int) error {
	if n > p.limits.MaxBlobBytes || n > p.limits.MaxTotalBytes-p.total {
		return ErrLimit
	}

	p.total += n

	return nil
}

func (p *parser) stringValue(n *tree.Node) (string, error) {
	if err := p.tick(); err != nil {
		return "", err
	}

	if err := attrs(n); err != nil {
		return "", err
	}

	length, segments := 0, 0

	var single string

	for _, child := range n.Children {
		if err := p.ctx.Err(); err != nil {
			return "", err
		}

		switch child.Kind {
		case tree.TextNode:
			if len(child.Data) > min(p.limits.MaxBlobBytes, p.limits.MaxTotalBytes-p.total)-length {
				return "", ErrLimit
			}

			length += len(child.Data)
			single = child.Data
			segments++
		case tree.CommentNode, tree.PINode:
		default:
			return "", fmt.Errorf("%w: nested value", ErrInput)
		}
	}

	if err := p.charge(length); err != nil {
		return "", err
	}

	if segments < 2 {
		return single, nil
	}

	var output strings.Builder
	output.Grow(length)

	for _, child := range n.Children {
		if err := p.ctx.Err(); err != nil {
			return "", err
		}

		if child.Kind == tree.TextNode {
			output.WriteString(child.Data)
		}
	}

	return output.String(), p.ctx.Err()
}

func (p *parser) binary(n *tree.Node, allowed ...string) ([]byte, error) {
	if err := p.tick(); err != nil {
		return nil, err
	}
	// The base64 text itself is input-bounded independently of decoded output.
	if err := attrs(n, allowed...); err != nil {
		return nil, err
	}

	value, err := tree.DecodeBase64(p.ctx, n, 0, min(p.limits.MaxBlobBytes, p.limits.MaxTotalBytes-p.total))
	if errors.Is(err, tree.ErrLimit) {
		return nil, errors.Join(ErrLimit, err)
	}

	if err != nil || len(value) == 0 {
		return nil, errors.Join(ErrInput, err)
	}

	if err := p.charge(len(value)); err != nil {
		return nil, err
	}

	return value, nil
}

func (p *parser) bareKey(s *scope, n *tree.Node) error {
	if err := p.requireKeyData(n.Name); err != nil {
		return err
	}

	if err := p.tick(); err != nil {
		return err
	}

	var (
		key crypto.PublicKey
		err error
	)

	switch n.Name {
	case document.Name{Space: Namespace, Local: nameDSAKeyValue}:
		key, err = p.dsaKeyValue(n)
	case document.Name{Space: Namespace, Local: nameRSAKeyValue}:
		key, err = p.rsaKeyValue(n)
	case document.Name{Space: Namespace11, Local: nameECKeyValue}:
		key, err = p.ecKeyValue(n)
	case document.Name{Space: Namespace11, Local: nameDEREncodedKeyValue}:
		key, err = p.derEncodedKeyValue(n)
	default:
		return fmt.Errorf("%w: key representation", ErrUnsupported)
	}

	if err != nil {
		return err
	}

	return p.addCandidate(s, n, key, nil)
}

func (p *parser) rsaKeyValue(n *tree.Node) (*rsa.PublicKey, error) {
	children, err := structure(n, Namespace, nameRSAKeyValue)
	if err != nil {
		return nil, err
	}

	if len(children) != 2 || !is(children[0], Namespace, "Modulus") || !is(children[1], Namespace, "Exponent") {
		return nil, ErrInput
	}

	modulus, err := p.binary(children[0])
	if err != nil {
		return nil, err
	}

	exponent, err := p.binary(children[1])
	if err != nil {
		return nil, err
	}

	// Read both CryptoBinary values before rejecting nonminimal integers.
	if modulus[0] == 0 || exponent[0] == 0 {
		return nil, fmt.Errorf("%w: nonminimal CryptoBinary integer", ErrInput)
	}

	e := new(big.Int).SetBytes(exponent)
	if !e.IsInt64() || e.Int64() > 2147483647 {
		return nil, ErrKey
	}

	return &rsa.PublicKey{N: new(big.Int).SetBytes(modulus), E: int(e.Int64())}, nil
}

func (p *parser) dsaKeyValue(n *tree.Node) (*dsa.PublicKey, error) {
	children, err := structure(n, Namespace, nameDSAKeyValue)
	if err != nil {
		return nil, err
	}

	if len(children) < 1 || len(children) > 7 {
		return nil, ErrInput
	}

	k, remaining, err := p.dsaPublicFields(children)
	if err != nil {
		return nil, err
	}

	if len(remaining) > 0 && is(remaining[0], Namespace, "J") {
		j, err := p.dsaInteger(remaining[0])
		if err != nil {
			return nil, err
		}

		if k.Q.Sign() == 0 || j.Cmp(new(big.Int).Div(new(big.Int).Sub(k.P, big.NewInt(1)), k.Q)) != 0 {
			return nil, ErrKey
		}

		remaining = remaining[1:]
	}

	if len(remaining) > 0 {
		if len(remaining) != 2 || !is(remaining[0], Namespace, "Seed") || !is(remaining[1], Namespace, "PgenCounter") {
			return nil, ErrInput
		}

		for _, child := range remaining {
			if _, err := p.dsaInteger(child); err != nil {
				return nil, err
			}
		}
	}

	return k, nil
}

func (p *parser) configureDSAParameters() error {
	parameters := p.options.DSAParameters
	if parameters == nil {
		return nil
	}

	if parameters.P == nil || parameters.Q == nil || parameters.G == nil || parameters.P.BitLen() != 1024 || parameters.Q.BitLen() != 160 || parameters.G.BitLen() > 1024 {
		return fmt.Errorf("%w: invalid DSA parameter context", ErrPolicy)
	}

	copyParameters := dsa.Parameters{P: new(big.Int).Set(parameters.P), Q: new(big.Int).Set(parameters.Q), G: new(big.Int).Set(parameters.G)}
	if err := signature.LegacyDSAKey(&dsa.PublicKey{Parameters: copyParameters, Y: copyParameters.G}); err != nil {
		return fmt.Errorf("%w: DSA parameter context: %w", ErrPolicy, err)
	}

	p.options.DSAParameters = &copyParameters

	return p.ctx.Err()
}

func (p *parser) dsaPublicFields(children []*tree.Node) (*dsa.PublicKey, []*tree.Node, error) {
	key := &dsa.PublicKey{}

	remaining := children
	if is(remaining[0], Namespace, "P") {
		if len(remaining) < 2 || !is(remaining[1], Namespace, "Q") {
			return nil, nil, ErrInput
		}

		var err error

		key.P, err = p.dsaInteger(remaining[0])
		if err != nil {
			return nil, nil, err
		}

		key.Q, err = p.dsaInteger(remaining[1])
		if err != nil {
			return nil, nil, err
		}

		remaining = remaining[2:]
	}

	if len(remaining) > 0 && is(remaining[0], Namespace, "G") {
		var err error

		key.G, err = p.dsaInteger(remaining[0])
		if err != nil {
			return nil, nil, err
		}

		remaining = remaining[1:]
	}

	if len(remaining) == 0 || !is(remaining[0], Namespace, "Y") {
		return nil, nil, ErrInput
	}

	var err error

	key.Y, err = p.dsaInteger(remaining[0])
	if err != nil {
		return nil, nil, err
	}

	if key.P == nil || key.G == nil {
		if p.options.DSAParameters == nil {
			return nil, nil, fmt.Errorf("%w: DSA parameter context required", ErrUnsupported)
		}

		if key.P == nil {
			key.P = p.options.DSAParameters.P
			key.Q = p.options.DSAParameters.Q
		}

		if key.G == nil {
			key.G = p.options.DSAParameters.G
		}
	}

	return key, remaining[1:], nil
}

func (p *parser) dsaInteger(n *tree.Node) (*big.Int, error) {
	value, err := p.binary(n)
	if err != nil {
		return nil, err
	}

	if len(value) > 1 && value[0] == 0 {
		return nil, fmt.Errorf("%w: nonminimal DSA CryptoBinary", ErrInput)
	}

	if len(value) > 128 {
		return nil, ErrKey
	}

	return new(big.Int).SetBytes(value), nil
}

func (p *parser) ecKeyValue(n *tree.Node) (*ecdsa.PublicKey, error) {
	children, err := structure(n, Namespace11, nameECKeyValue, "Id")
	if err != nil {
		return nil, err
	}

	if len(children) != 2 {
		return nil, ErrInput
	}

	if !is(children[0], Namespace11, "NamedCurve") {
		return nil, fmt.Errorf("%w: explicit EC parameters", ErrUnsupported)
	}

	curveChildren, err := structure(children[0], Namespace11, "NamedCurve", "URI")
	if err != nil {
		return nil, err
	}

	if len(curveChildren) != 0 || !is(children[1], Namespace11, "PublicKey") {
		return nil, ErrInput
	}

	uri, ok := attr(children[0], "URI")
	if !ok {
		return nil, ErrInput
	}

	curve := curveForURI(uri)
	if curve == nil {
		return nil, fmt.Errorf("%w: named curve", ErrUnsupported)
	}

	encoded, err := p.binary(children[1])
	if err != nil {
		return nil, err
	}

	key, err := ecdsa.ParseUncompressedPublicKey(curve, encoded)
	if err != nil {
		return nil, ErrKey
	}

	return key, nil
}

func (p *parser) derEncodedKeyValue(n *tree.Node) (crypto.PublicKey, error) {
	encoded, err := p.binary(n, "Id")
	if err != nil {
		return nil, err
	}

	key, err := x509.ParsePKIXPublicKey(encoded)
	if err != nil {
		return nil, fmt.Errorf("%w: SubjectPublicKeyInfo: %w", ErrKey, err)
	}

	return key, nil
}

func (p *parser) addCandidate(s *scope, n *tree.Node, key crypto.PublicKey, cert []byte) error {
	if err := validateKey(key, p.limits.MaxRSABits); err != nil {
		return err
	}

	if len(p.result.candidates) >= p.limits.MaxCandidates {
		return fmt.Errorf("%w: candidates", ErrLimit)
	}

	spki, err := signature.MarshalPublicKey(key)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrKey, err)
	}

	// Certificate DER is decoded/cached in privately owned storage; candidates
	// and X509 groups can share it while their accessors still return copies.
	p.result.candidates = append(p.result.candidates, Candidate{spki: spki, certificate: cert, source: tree.Wrap(s.doc, n), resource: s.resource, kind: n.Name})

	return nil
}

func curveForURI(s string) elliptic.Curve {
	switch s {
	case lexicon.CurveP256:
		return elliptic.P256()
	case lexicon.CurveP384:
		return elliptic.P384()
	case lexicon.CurveP521:
		return elliptic.P521()
	}

	return nil
}

func validateKey(key crypto.PublicKey, maxRSA int) error {
	switch k := key.(type) {
	case *dsa.PublicKey:
		if err := signature.LegacyDSAKey(k); err != nil {
			return fmt.Errorf("%w: invalid legacy DSA public key", ErrKey)
		}
	case *rsa.PublicKey:
		if k == nil || k.N == nil || k.N.Sign() <= 0 || k.N.Bit(0) == 0 || k.N.BitLen() > maxRSA || k.E < 3 || k.E%2 == 0 || int64(k.E) > 2147483647 || k.N.Cmp(big.NewInt(int64(k.E))) <= 0 {
			return ErrKey
		}
	case *ecdsa.PublicKey:
		if k == nil || k.Curve == nil {
			return ErrKey
		}

		if k.Curve != elliptic.P256() && k.Curve != elliptic.P384() && k.Curve != elliptic.P521() {
			return ErrUnsupported
		}

		if _, err := ecdsakey.PublicBytes(k); err != nil {
			return ErrKey
		}
	case ed25519.PublicKey:
		if len(k) != ed25519.PublicKeySize {
			return ErrKey
		}
	default:
		return ErrUnsupported
	}

	return nil
}

func attr(n *tree.Node, local string) (string, bool) {
	for _, a := range n.Attrs {
		if a.Name == (document.Name{Local: local}) {
			return a.Value, true
		}
	}

	return "", false
}

func attrs(n *tree.Node, allowed ...string) error {
	for _, a := range n.Attrs {
		ok := false

		for _, v := range allowed {
			if a.Name == (document.Name{Local: v}) {
				ok = true
				break
			}
		}

		if !ok {
			return fmt.Errorf("%w: unexpected attribute {%s}%s", ErrInput, a.Name.Space, a.Name.Local)
		}

		if a.Name.Local == "Id" && !tree.NCName(a.Value) {
			return ErrInput
		}
	}

	return nil
}

func xmlSpace(b byte) bool { return b == ' ' || b == '\t' || b == '\r' || b == '\n' }

func onlySpace(s string) bool {
	for i := 0; i < len(s); i++ {
		if !xmlSpace(s[i]) {
			return false
		}
	}

	return true
}

func structure(n *tree.Node, space, local string, allowed ...string) ([]*tree.Node, error) {
	if !is(n, space, local) {
		return nil, ErrInput
	}

	if err := attrs(n, allowed...); err != nil {
		return nil, err
	}

	var out []*tree.Node

	for _, c := range n.Children {
		switch c.Kind {
		case tree.ElementNode:
			out = append(out, c)
		case tree.TextNode:
			if !onlySpace(c.Data) {
				return nil, ErrInput
			}
		case tree.CommentNode, tree.PINode:
		default:
			return nil, ErrInput
		}
	}

	return out, nil
}

func curveURI(c elliptic.Curve) string {
	switch c {
	case elliptic.P256():
		return lexicon.CurveP256
	case elliptic.P384():
		return lexicon.CurveP384
	case elliptic.P521():
		return lexicon.CurveP521
	}

	return ""
}

func is(n *tree.Node, space, local string) bool {
	return n != nil && n.Kind == tree.ElementNode && n.Name == (document.Name{Space: space, Local: local})
}
