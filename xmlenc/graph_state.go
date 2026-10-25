package xmlenc

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdh"
	"crypto/rsa"
	"errors"
	"net/url"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/internal/lexicon"
	"github.com/skarm/xmlsec/internal/nilcheck"
	"github.com/skarm/xmlsec/internal/streamio"
	"github.com/skarm/xmlsec/internal/tree"
	"github.com/skarm/xmlsec/internal/uriref"
	"github.com/skarm/xmlsec/reference"
	"github.com/skarm/xmlsec/resource"
)

// KeyGraphKey binds application-owned key material to an exact name and algorithm.
// Name is an untrusted XML label matched with whitespace preserved. Algorithm is
// an explicit restriction and is never inferred from key length.
//
// Supply exactly one of Secret, Decrypter, PublicKey, ECDHRecipient or ECDHPublicKey.
// Public keys are accepted only for EncryptKey and cannot decrypt a graph. When
// Algorithm selects ConcatKDF, Secret supplies the master secret.
type KeyGraphKey struct {
	// Name is the exact key label to match in XML, including whitespace.
	Name string
	// Algorithm is the application-selected key algorithm URI.
	Algorithm string
	// Secret supplies a symmetric key or ConcatKDF master secret, as selected by Algorithm.
	Secret []byte
	// Decrypter supplies the private RSA operation for key unwrapping.
	Decrypter crypto.Decrypter
	// PublicKey supplies the RSA recipient key for EncryptKey only.
	PublicKey *rsa.PublicKey
	// ECDHPublicKey is accepted only by EncryptKey for ECDH/AESKW generation.
	ECDHPublicKey *ecdh.PublicKey
	// ECDHRecipient and ECDH select the existing ECDH-ES/AESKW leaf profile.
	// They are exclusive with Secret/Decrypter/PublicKey. ECDH.Data must be zero;
	// graph Data supplies the data/resource policy. Name fixes RecipientKeyName,
	// Algorithm fixes the AES key-wrap method, and KDF remains caller-selected.
	ECDHRecipient ECDHRecipient
	// ECDH optionally selects exact KDF and ECDH leaf parameters. Its Data field must be
	// zero.
	ECDH *ECDHOptions
}

// KeyGraphLimits bounds one operation across loaded documents and key dependencies.
// Zero fields select their documented defaults. MaxDepth bounds key dependencies
// separately from XML parser depth.
type KeyGraphLimits struct {
	// MaxDepth bounds key dependency depth. Zero selects 8.
	MaxDepth int
	// MaxNodes bounds aggregate graph processing nodes. Zero selects 8192.
	MaxNodes int
	// MaxBytes bounds aggregate graph processing bytes. Zero selects 32 MiB.
	MaxBytes int
	// MaxResources bounds external key resources. Zero selects 8.
	MaxResources int
}

// KeyGraphResources authorizes exact absolute URIs for external key documents.
// An optional BaseURI must be absolute and hierarchical, without credentials or a
// fragment. It identifies the principal document for links and backlinks and enables
// relative links and inherited xml:base. Empty preserves literal URI handling.
// BaseURI grants no access by itself. Resolving and reading must honor cancellation.
// The graph closes every returned reader, including readers returned with errors.
type KeyGraphResources struct {
	// BaseURI optionally enables relative key links and inherited xml:base resolution.
	BaseURI string
	// AllowedURIs lists exact absolute key resource URIs authorized for retrieval.
	AllowedURIs []string
	// Resolver supplies authorized key document bytes and must honor cancellation while
	// resolving and reading.
	Resolver resource.Resolver
}

// KeyGraphOptions enables bounded XMLENC key relationships explicitly.
// Strict decryption entry points do not enable this profile. Data fixes the
// expected data cipher and OAEP parameters. KeyAlgorithms permits additional exact
// key-method URIs alongside those bound in Keys. Nil ConcatKDF denies DerivedKey;
// a non-nil context must match the declared algorithm and party bitstrings before
// derivation.
type KeyGraphOptions struct {
	// Data selects the expected data cipher, OAEP parameters and ciphertext resource
	// policy.
	Data Options
	// Keys supplies explicit application-owned key material and exact name and algorithm
	// restrictions.
	Keys []KeyGraphKey
	// KeyAlgorithms permits additional exact key algorithm URIs beyond those bound in Keys.
	KeyAlgorithms []string
	// ConcatKDF supplies the exact expected derivation context. Nil denies DerivedKey
	// processing.
	ConcatKDF *ConcatKDFParameters
	// External optionally authorizes external key documents. Nil denies them.
	External *KeyGraphResources
	// KeyURIs explicitly supplies standalone key candidates, including external
	// keys discoverable through a ReferenceList without an inbound KeyInfo link.
	KeyURIs []string
	// MasterKeyBytes selects 16, 24 or 32 bytes for a graph-resolved DerivedKey
	// master; zero uses 32.
	// Direct ConcatKDF Secret bindings retain their actual 1..1024-byte size.
	// Other sizes of encrypted master material are outside this key-wrap profile.
	MasterKeyBytes int
	// IDRules supplements XMLENC/KeyInfo Id and xml:id typing. There is no
	// local-name guessing, schema loading, or automatic trust in these IDs.
	IDRules []reference.IDAttributeRule
	// CipherTransforms permits only built-in base64/canonicalization transforms.
	// Empty enables Base64 and the mandatory implicit Canonical XML 1.0 conversion.
	// XPath, XSLT, enveloped signatures and application extension programs are denied.
	CipherTransforms []string
	// Limits bounds the complete graph operation. Zero fields select defaults.
	Limits KeyGraphLimits
}

type (
	graphBinding struct {
		name      string
		algorithm string
	}
	graphNode struct {
		document *graphDocument
		node     *tree.Node
	}
)

type graphDocument struct {
	doc      *document.Document
	uri      string
	resolver *reference.SameDocumentResolver
	keys     []graphNode
}
type keyGraph struct {
	ctx        context.Context
	options    KeyGraphOptions
	profile    profile
	limits     KeyGraphLimits
	bindings   map[graphBinding]KeyGraphKey
	methods    map[string]struct{}
	allowed    map[string]struct{}
	documents  map[string]*graphDocument
	ordered    []*graphDocument
	standalone []graphNode
	active     map[graphPlanID]struct{}
	plans      map[graphPlanID]*graphKeyPlan
	baseURI    *url.URL
	remaining  KeyGraphLimits
}

func normalizeGraphLimits(limits KeyGraphLimits) (KeyGraphLimits, error) {
	if limits.MaxDepth == 0 {
		limits.MaxDepth = 8
	}

	if limits.MaxNodes == 0 {
		limits.MaxNodes = 8192
	}

	if limits.MaxBytes == 0 {
		limits.MaxBytes = 32 << 20
	}

	if limits.MaxResources == 0 {
		limits.MaxResources = 8
	}

	if limits.MaxDepth < 1 || limits.MaxDepth > 32 || limits.MaxNodes < 1 || limits.MaxNodes > 100000 || limits.MaxBytes < 1 || limits.MaxBytes > 128<<20 || limits.MaxResources < 1 || limits.MaxResources > 64 {
		return KeyGraphLimits{}, ErrPolicy
	}

	return limits, nil
}

func newKeyGraph(ctx context.Context, doc *document.Document, options KeyGraphOptions) (*keyGraph, *graphDocument, error) {
	p, err := normalize(ctx, options.Data)
	if err != nil {
		return nil, nil, err
	}

	limits, err := normalizeGraphLimits(options.Limits)
	if err != nil || len(options.Keys) > 64 || len(options.KeyAlgorithms) > 32 || len(options.KeyURIs) > 64 || len(options.IDRules) > 28 {
		return nil, nil, ErrPolicy
	}

	options.Data = p.options
	if options.Data.OAEP != nil {
		parameters, err := normalizeOAEP(options.Data.OAEP)
		if err != nil {
			return nil, nil, err
		}

		options.Data.OAEP = &parameters
	}

	options.Keys = append([]KeyGraphKey(nil), options.Keys...)
	options.KeyAlgorithms = append([]string(nil), options.KeyAlgorithms...)
	options.KeyURIs = append([]string(nil), options.KeyURIs...)
	options.CipherTransforms = append([]string(nil), options.CipherTransforms...)

	options.IDRules = append([]reference.IDAttributeRule(nil), options.IDRules...)
	for i := range options.IDRules {
		options.IDRules[i].Elements = append([]document.Name(nil), options.IDRules[i].Elements...)
	}

	if options.ConcatKDF != nil {
		parameters := cloneGraphKDF(*options.ConcatKDF)
		options.ConcatKDF = &parameters
	}

	if options.External != nil {
		external := *options.External
		external.AllowedURIs = append([]string(nil), external.AllowedURIs...)
		options.External = &external
	}

	if options.MasterKeyBytes == 0 {
		options.MasterKeyBytes = 32
	}

	if !sessionKeySize(options.MasterKeyBytes) {
		return nil, nil, ErrPolicy
	}

	g := &keyGraph{
		ctx: ctx, options: options, profile: p, limits: limits, remaining: limits,
		bindings: make(map[graphBinding]KeyGraphKey), methods: make(map[string]struct{}), allowed: make(map[string]struct{}), documents: make(map[string]*graphDocument),
		active: make(map[graphPlanID]struct{}), plans: make(map[graphPlanID]*graphKeyPlan),
	}
	if err := g.configure(); err != nil {
		g.close()
		return nil, nil, err
	}

	base := ""
	if options.External != nil {
		base = options.External.BaseURI
	}

	principal, err := g.addDocument(doc, base)
	if err != nil {
		g.close()
		return nil, nil, err
	}

	return g, principal, nil
}

func (g *keyGraph) configure() error {
	seen := make(map[graphBinding]struct{})

	for _, binding := range g.options.Keys {
		identity := graphBinding{binding.Name, binding.Algorithm}
		if _, exists := seen[identity]; exists {
			return ErrPolicy
		}

		seen[identity] = struct{}{}
	}

	if _, err := g.referenceOptions(1); err != nil {
		return err
	}

	for _, algorithm := range g.options.KeyAlgorithms {
		if _, exists := g.methods[algorithm]; !graphKeyAlgorithm(algorithm) || exists {
			return ErrPolicy
		}

		g.methods[algorithm] = struct{}{}
	}

	for _, binding := range g.options.Keys {
		identity := graphBinding{binding.Name, binding.Algorithm}
		if len(binding.Name) > 1024 || !utf8.ValidString(binding.Name) || binding.Algorithm == "" {
			return ErrPolicy
		}

		if _, duplicate := g.bindings[identity]; duplicate {
			return ErrPolicy
		}

		if err := g.validateBinding(binding); err != nil {
			return err
		}

		binding.Secret = bytes.Clone(binding.Secret)
		if binding.ECDH != nil {
			agreement := *binding.ECDH
			if agreement.KDF != nil {
				parameters := cloneGraphKDF(*agreement.KDF)
				agreement.KDF = &parameters
			}

			binding.ECDH = &agreement
		}

		g.bindings[identity] = binding
		if graphKeyAlgorithm(binding.Algorithm) {
			g.methods[binding.Algorithm] = struct{}{}
		}
	}

	if g.options.ConcatKDF != nil {
		if _, err := encodeConcatKDFParameters(g.ctx, *g.options.ConcatKDF); err != nil {
			return err
		}

		probe, err := DeriveConcatKey(g.ctx, []byte{1}, 8, *g.options.ConcatKDF)
		clear(probe)

		if err != nil {
			return err
		}
	}

	return g.configureExternal()
}

func (g *keyGraph) configureExternal() error {
	external := g.options.External
	if external == nil {
		return nil
	}

	if nilcheck.IsNil(external.Resolver) || len(external.AllowedURIs) > 64 || external.BaseURI != "" && !validCipherURI(external.BaseURI) {
		return ErrPolicy
	}

	base, err := uriref.Base(external.BaseURI)
	if err != nil {
		return errors.Join(ErrPolicy, err)
	}

	g.baseURI = base
	for _, uri := range external.AllowedURIs {
		if _, exists := g.allowed[uri]; !validCipherURI(uri) || exists {
			return ErrPolicy
		}

		g.allowed[uri] = struct{}{}
	}

	return nil
}

func (g *keyGraph) validateBinding(binding KeyGraphKey) error {
	if binding.ECDHPublicKey != nil {
		return ErrPolicy
	}

	if binding.ECDHRecipient != nil || binding.ECDH != nil {
		return g.validateAgreementBinding(binding)
	}

	if binding.PublicKey != nil || binding.Decrypter != nil && nilcheck.IsNil(binding.Decrypter) {
		return ErrPolicy
	}

	if rsaOAEPAlgorithm(binding.Algorithm) {
		if len(binding.Secret) != 0 || nilcheck.IsNil(binding.Decrypter) {
			return ErrPolicy
		}

		public, ok := binding.Decrypter.Public().(*rsa.PublicKey)
		if !ok {
			return ErrPolicy
		}

		return validateRSAKey(public)
	}

	if !nilcheck.IsNil(binding.Decrypter) || len(binding.Secret) == 0 {
		return ErrPolicy
	}

	if binding.Algorithm == ConcatKDF {
		if len(binding.Secret) > 1024 {
			return ErrPolicy
		}

		return nil
	}

	if size := graphWrappingKeyBytes(binding.Algorithm); size != 0 {
		if size != len(binding.Secret) || binding.Algorithm == TripleDESKeyWrap && !g.options.Data.AllowLegacy {
			return ErrPolicy
		}

		return nil
	}

	data, err := dataAlgorithm(binding.Algorithm, g.options.Data.AllowLegacy)
	if err != nil || data.keyBytes != len(binding.Secret) {
		return ErrPolicy
	}

	return nil
}

func graphWrappingKeyBytes(algorithm string) int {
	switch algorithm {
	case AES128KeyWrap:
		return 16
	case AES192KeyWrap, TripleDESKeyWrap:
		return 24
	case AES256KeyWrap:
		return 32
	}

	return 0
}

func graphKeyAlgorithm(algorithm string) bool {
	return rsaOAEPAlgorithm(algorithm) || graphWrappingKeyBytes(algorithm) != 0 || algorithm == ConcatKDF
}

func (g *keyGraph) close() {
	for _, binding := range g.bindings {
		clear(binding.Secret)
	}

	for _, plan := range g.plans {
		clear(plan.value)
	}
}

func graphLimitError() error { return errors.Join(ErrPolicy, document.ErrLimit) }

func (g *keyGraph) charge(nodes, octets int) error {
	if err := g.ctx.Err(); err != nil {
		return err
	}

	if nodes > g.remaining.MaxNodes || octets > g.remaining.MaxBytes {
		return graphLimitError()
	}

	g.remaining.MaxNodes -= nodes
	g.remaining.MaxBytes -= octets

	return nil
}

func graphIDRules(extra []reference.IDAttributeRule) []reference.IDAttributeRule {
	rules := make([]reference.IDAttributeRule, 0, 2+len(extra))
	rules = append(rules, reference.IDAttributeRule{
		Attribute: document.Name{Local: "Id"}, Elements: []document.Name{
			elementName(Namespace, "EncryptedData"), elementName(Namespace, "EncryptedKey"), elementName(Namespace11, "DerivedKey"),
			elementName(Namespace, "EncryptionProperties"), elementName(Namespace, "EncryptionProperty"), elementName(SignatureNamespace, lexicon.DSigElementKeyInfo),
			elementName(Namespace, "OriginatorKeyInfo"), elementName(Namespace, "RecipientKeyInfo"),
		},
	}, reference.IDAttributeRule{Attribute: document.Name{Space: document.XMLNamespace, Local: "id"}})

	return append(rules, extra...)
}

func (g *keyGraph) addDocument(doc *document.Document, uri string) (*graphDocument, error) {
	if doc == nil || !doc.Root().Valid() {
		return nil, ErrFormat
	}

	d := &graphDocument{doc: doc, uri: uri}

	stack := []*tree.Node{tree.Root(doc)}
	for len(stack) != 0 {
		node := stack[len(stack)-1]

		stack = stack[:len(stack)-1]
		if err := g.charge(1, len(node.Data)+len(node.Name.Space)+len(node.Name.Local)); err != nil {
			return nil, err
		}

		for _, ns := range node.NS {
			if err := g.charge(1, len(ns.Prefix)+len(ns.URI)); err != nil {
				return nil, err
			}
		}

		for _, attribute := range node.Attrs {
			if err := g.chargeAttribute(attribute); err != nil {
				return nil, err
			}
		}

		if node.Name == elementName(Namespace, "EncryptedKey") || node.Name == elementName(Namespace11, "DerivedKey") {
			d.keys = append(d.keys, graphNode{d, node})
		}

		stack = append(stack, node.Children...)
	}

	resolver, err := reference.NewSameDocumentResolverWithRules(g.ctx, doc, graphIDRules(g.options.IDRules))
	if err != nil {
		return nil, errors.Join(ErrFormat, err)
	}

	d.resolver = resolver
	g.documents[uri] = d
	g.ordered = append(g.ordered, d)

	return d, nil
}

func (g *keyGraph) externalDocument(uri string) (result *graphDocument, err error) {
	if found := g.documents[uri]; found != nil {
		return found, nil
	}

	if _, exists := g.allowed[uri]; !exists || g.options.External == nil {
		return nil, ErrPolicy
	}

	if g.remaining.MaxResources == 0 || g.remaining.MaxBytes == 0 || g.remaining.MaxNodes == 0 {
		return nil, graphLimitError()
	}

	g.remaining.MaxResources--

	reader, err := g.options.External.Resolver.Resolve(g.ctx, uri)
	if !nilcheck.IsNil(reader) {
		defer func() {
			if closeErr := reader.Close(); closeErr != nil {
				result, err = nil, errors.Join(ErrResource, err, closeErr)
			}
		}()
	}

	if g.ctx.Err() != nil {
		return nil, g.ctx.Err()
	}

	if err != nil || nilcheck.IsNil(reader) {
		return nil, errors.Join(ErrResource, err)
	}

	bounded := &streamio.Reader{Context: g.ctx, Source: reader, Limit: int64(g.remaining.MaxBytes), LimitError: graphLimitError()}
	limits := document.DefaultLimits()
	limits.MaxBytes = g.remaining.MaxBytes
	limits.MaxNodes = min(limits.MaxNodes, g.remaining.MaxNodes)

	doc, err := document.ParseReader(g.ctx, bounded, limits)
	if bounded.ReadBytes > int64(g.remaining.MaxBytes) {
		return nil, graphLimitError()
	}

	g.remaining.MaxBytes -= int(bounded.ReadBytes)
	if err != nil {
		if g.ctx.Err() != nil {
			return nil, g.ctx.Err()
		}

		return nil, errors.Join(ErrResource, err)
	}

	return g.addDocument(doc, uri)
}

func validGraphReference(value string) bool {
	if len(value) > 4096 || !utf8.ValidString(value) || strings.Contains(value, "\\") {
		return false
	}

	for _, r := range value {
		if unicode.IsSpace(r) || unicode.IsControl(r) {
			return false
		}
	}

	return true
}

func (g *keyGraph) referenceTarget(source *graphDocument, element document.Element, raw string) (graphNode, error) {
	if !validGraphReference(raw) {
		return graphNode{}, ErrFormat
	}

	if raw == "" || strings.HasPrefix(raw, "#") {
		return g.localTarget(source, raw)
	}

	uri, err := g.absoluteReference(source, element, raw)
	if err != nil {
		return graphNode{}, err
	}

	fragment := uri.EscapedFragment()
	uri.Fragment, uri.RawFragment = "", ""

	doc, err := g.externalDocument(uri.String())
	if err != nil {
		return graphNode{}, err
	}

	if fragment == "" {
		return graphNode{doc, tree.Root(doc.doc)}, nil
	}

	return g.localTarget(doc, "#"+fragment)
}

func (g *keyGraph) localTarget(doc *graphDocument, uri string) (graphNode, error) {
	target, whole, err := doc.resolver.Target(g.ctx, uri)
	if err != nil {
		return graphNode{}, errors.Join(ErrFormat, err)
	}

	if whole {
		return graphNode{doc, tree.Root(doc.doc)}, nil
	}

	_, node := tree.Unwrap(target)

	return graphNode{doc, node}, nil
}

func (n graphNode) element() document.Element { return tree.Wrap(n.document.doc, n.node) }

func graphNameText(element document.Element) (string, error) {
	if !exactAttributes(element) || len(element.Children()) != 0 {
		return "", ErrFormat
	}

	text := element.Text()
	if len(text) > 1024 {
		return "", graphLimitError()
	}

	return text, nil
}

var errGraphKeyUnavailable = errors.New("no configured key for this graph path")

func cloneGraphKDF(p ConcatKDFParameters) ConcatKDFParameters {
	p.AlgorithmID = bytes.Clone(p.AlgorithmID)
	p.PartyUInfo = bytes.Clone(p.PartyUInfo)
	p.PartyVInfo = bytes.Clone(p.PartyVInfo)
	p.SuppPubInfo = bytes.Clone(p.SuppPubInfo)
	p.SuppPrivInfo = bytes.Clone(p.SuppPrivInfo)

	return p
}

func (g *keyGraph) chargeAttribute(attribute tree.Attribute) error {
	if g.baseURI != nil && attribute.Name == (document.Name{Space: document.XMLNamespace, Local: "base"}) {
		if !validGraphReference(attribute.Value) || uriref.Validate(attribute.Value) != nil || strings.Contains(attribute.Value, "#") {
			return ErrFormat
		}

		part, err := url.Parse(attribute.Value)
		if err != nil || part.User != nil {
			return ErrFormat
		}
	}

	return g.charge(1, len(attribute.Value)+len(attribute.Name.Space)+len(attribute.Name.Local))
}
