package xmldsig

import (
	"context"
	"crypto"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"strings"

	"github.com/skarm/xmlsec/c14n"
	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/internal/nilcheck"
	"github.com/skarm/xmlsec/internal/signature"
	"github.com/skarm/xmlsec/internal/tree"
	"github.com/skarm/xmlsec/internal/uriref"
	"github.com/skarm/xmlsec/reference"
)

// Resolver provides the ORIGINAL octets identified by an explicitly permitted
// URI. No automatic HTTP/file fetching or XML fragment selection occurs in this
// library. ExternalReferences.BaseURI can explicitly resolve relative URI spelling
// in the general Signature API. The returned stream is closed on every path.
// Resolve and the returned reader must honor ctx themselves if blocking: the
// library cannot interrupt an arbitrary blocking Read without leaking a worker.
type Resolver interface {
	// Resolve opens original bytes for an explicitly authorized URI. The caller closes the
	// stream; resolving and reading must honor cancellation.
	Resolve(ctx context.Context, uri string) (io.ReadCloser, error)
}

// ResolverFunc adapts a function to Resolver. It must provide owned readers for explicitly
// authorized URIs.
type ResolverFunc func(context.Context, string) (io.ReadCloser, error)

// Resolve calls the underlying application resolver function.
func (f ResolverFunc) Resolve(ctx context.Context, uri string) (io.ReadCloser, error) {
	return f(ctx, uri)
}

// ResourceLimits bounds each external resource and the total resource bytes read by an
// operation.
type ResourceLimits struct {
	// MaxResourceBytes bounds each resource; zero uses 8 MiB.
	MaxResourceBytes int
	// MaxTotalResourceBytes bounds all resource reads in one operation; zero uses 32 MiB.
	MaxTotalResourceBytes int
}

// DetachedReference is a recipe for signing externally supplied octets. A nil
// Transforms slice means the exact original bytes, not implicit XML parsing.
// Each URI must be nonempty, have no fragment, and occur once in the signature.
// Type is advisory only: Manifest recursion is NOT performed.
type DetachedReference struct {
	URI          string
	Type         string
	DigestMethod string
	Transforms   []reference.Transform
}

// DetachedSignOptions sets explicit detached signature policy, canonicalization and
// processing budgets.
type DetachedSignOptions struct {
	SignatureMethod string
	// Canonicalization defaults to Exclusive C14N without comments. All six implemented
	// C14N URIs are available explicitly, independently of each reference's transforms.
	Canonicalization reference.Transform
	Policy           Policy
	Processing       reference.Options
	Limits           ResourceLimits
	XMLLimits        document.Limits
}

// DetachedVerifyOptions sets the exact expected resource URI set and detached verification
// policy.
type DetachedVerifyOptions struct {
	// ExpectedURIs is required and specifies the exact expected URI set, independent of
	// order. A subset, superset or different resource set is rejected before I/O.
	ExpectedURIs []string
	// AllowedCanonicalizationMethods defaults to Exclusive C14N only.
	AllowedCanonicalizationMethods []string
	Policy                         Policy
	Processing                     reference.Options
	Limits                         ResourceLimits
}

// DetachedResult proves verification of the exact reference set with an
// externally pinned key. It deliberately has NO Root/CoversElement methods:
// neither the signature container nor arbitrary original XML is authenticated
// by a signature over external/transformed octets.
type DetachedResult struct {
	algorithm, fingerprint string
	references             []ReferenceResult
}

// VerifyDetached authenticates SignedInfo BEFORE calling resolver. It checks the
// whole expected reference set and every digest. KeyInfo is ignored for trust.
// Any failure returns nil, never a partially authenticated DetachedResult.
func VerifyDetached(ctx context.Context, doc *document.Document, key crypto.PublicKey, resolver Resolver, opt DetachedVerifyOptions) (*DetachedResult, error) {
	if ctx == nil {
		return nil, fmt.Errorf("%w: nil context", ErrPolicy)
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	if doc == nil || !doc.Root().Valid() {
		return nil, ErrStructure
	}

	if nilcheck.IsNil(resolver) {
		return nil, fmt.Errorf("%w: resolver required", ErrReference)
	}

	p, err := prepareDetachedVerification(ctx, doc, key, opt)
	if err != nil {
		return nil, err
	}

	remaining, resourceRemaining := p.policy.MaxCanonicalBytes, p.limits.MaxTotalResourceBytes

	spec := signatureSpec{algorithm: p.method}
	credential := signatureCredential{public: key}

	canonicalSI, err := credential.prepareInput(ctx, spec, func(dst io.Writer) error {
		return writeCanonicalElement(ctx, dst, tree.Wrap(doc, p.si), p.cm, &remaining)
	})
	if err != nil {
		return nil, err
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	if err := credential.verifyPrepared(spec, canonicalSI, p.value); err != nil {
		return nil, err
	}

	result := &DetachedResult{algorithm: p.method}

	if err := verifyDetachedResources(ctx, resolver, p, &remaining, &resourceRemaining, result); err != nil {
		return nil, err
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	spki, err := signature.MarshalPublicKey(key)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrKey, err)
	}

	fingerprint := sha256.Sum256(spki)
	result.fingerprint = hex.EncodeToString(fingerprint[:])

	return result, nil
}

func prepareDetachedVerification(ctx context.Context, doc *document.Document, key crypto.PublicKey, opt DetachedVerifyOptions) (*detachedVerificationPlan, error) {
	p, err := normalizePolicy(opt.Policy)
	if err != nil {
		return nil, err
	}

	limits, err := normalizeResourceLimits(opt.Limits)
	if err != nil {
		return nil, err
	}

	if err := validateKey(key, p); err != nil {
		return nil, err
	}

	if err := validateDetachedTransforms(nil, opt.Processing); err != nil {
		return nil, err
	}

	methods := append([]string(nil), opt.AllowedCanonicalizationMethods...)
	if len(methods) == 0 {
		methods = []string{c14n.Exclusive}
	}

	for _, method := range methods {
		if !canonicalAlgorithm(method) {
			return nil, fmt.Errorf("%w: allowed canonicalization", ErrAlgorithm)
		}
	}

	expected := make(map[string]bool, len(opt.ExpectedURIs))
	if len(opt.ExpectedURIs) == 0 || len(opt.ExpectedURIs) > p.MaxReferences {
		return nil, fmt.Errorf("%w: exact ExpectedURIs are required", ErrPolicy)
	}

	if err := validateExpectedDetachedURIs(opt.ExpectedURIs, expected); err != nil {
		return nil, err
	}

	plan := &detachedVerificationPlan{policy: p, limits: limits, processing: opt.Processing, methods: methods, expected: expected}
	if err := plan.parseSignature(ctx, doc); err != nil {
		return nil, err
	}

	for i, ref := range plan.refs {
		if err := reference.PrepareTransforms(ctx, ref.Transforms, plan.processing); err != nil {
			return nil, &ReferenceError{i, ref.URI, nameTransform, processingError(err)}
		}
	}

	return plan, nil
}

func verifyDetachedResources(ctx context.Context, resolver Resolver, p *detachedVerificationPlan, remaining, resourceRemaining *int, result *DetachedResult) error {
	for i, ref := range p.refs {
		h, _ := hashForDigest(ref.DigestMethod)
		hash := h.New()
		source := &referenceSource{resolver: resolver, uri: ref.URI, limits: p.limits}

		processed, err := source.write(ctx, hash, ref.Transforms, p.processing, remaining, resourceRemaining)
		if err != nil {
			return &ReferenceError{i, ref.URI, nameTransform, err}
		}

		if subtle.ConstantTimeCompare(hash.Sum(nil), ref.digest) != 1 {
			return &ReferenceError{i, ref.URI, "digest", ErrDigest}
		}

		result.references = append(result.references, ReferenceResult{uri: ref.URI, typeURI: ref.Type, digestMethod: ref.DigestMethod, processed: processed, external: source, processing: p.processing, digest: hash.Sum(nil), transforms: ref.Transforms})
	}

	return nil
}

func validateExpectedDetachedURIs(uris []string, expected map[string]bool) error {
	for _, uri := range uris {
		if err := validExternalURI(uri); err != nil {
			return err
		}

		if expected[uri] {
			return fmt.Errorf("%w: duplicate ExpectedURI", ErrPolicy)
		}

		expected[uri] = true
	}

	return nil
}

// SignatureMethod returns the authenticated signature algorithm URI.
func (r *DetachedResult) SignatureMethod() string {
	if r == nil {
		return ""
	}

	return r.algorithm
}

// KeyFingerprintSHA256 returns the hexadecimal SHA-256 fingerprint of the externally
// trusted verification key.
func (r *DetachedResult) KeyFingerprintSHA256() string {
	if r == nil {
		return ""
	}

	return r.fingerprint
}

// References returns an owned slice of immutable validated reference results.
func (r *DetachedResult) References() []ReferenceResult {
	if r == nil {
		return nil
	}

	return append([]ReferenceResult(nil), r.references...)
}

type detachedSigningPlan struct {
	policy     Policy
	limits     ResourceLimits
	cm         reference.Transform
	xmlLimits  document.Limits
	processing reference.Options
	method     string
	key        crypto.PublicKey
	refs       []DetachedReference
}

type detachedSignatureDraft struct {
	doc         *document.Document
	sig, si     *tree.Node
	digestNodes []*tree.Node
}

// SignDetached produces a standalone ds:Signature, with one or more external
// octet-stream references. ALL recipes are checked before any resolver call.
// The same processing engine is used by SignEnveloped, Verify and VerifyDetached.
func SignDetached(ctx context.Context, refs []DetachedReference, signer crypto.Signer, resolver Resolver, opt DetachedSignOptions) (*document.Document, error) {
	if ctx == nil {
		return nil, fmt.Errorf("%w: nil context", ErrPolicy)
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	if nilcheck.IsNil(signer) {
		return nil, ErrKey
	}

	if nilcheck.IsNil(resolver) {
		return nil, fmt.Errorf("%w: resolver required", ErrReference)
	}

	p, err := prepareDetachedSigning(refs, signer, opt)
	if err != nil {
		return nil, err
	}

	draft, err := buildDetachedSignature(ctx, p)
	if err != nil {
		return nil, err
	}

	remaining := p.policy.MaxCanonicalBytes
	if err := fillDetachedDigests(ctx, draft, p, resolver, &remaining); err != nil {
		return nil, err
	}

	spec := signatureSpec{algorithm: p.method}
	credential := signatureCredential{public: p.key, signer: signer}

	canonicalSI, err := credential.prepareInput(ctx, spec, func(dst io.Writer) error {
		return writeCanonicalElement(ctx, dst, tree.Wrap(draft.doc, draft.si), p.cm, &remaining)
	})
	if err != nil {
		return nil, err
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	value, err := credential.signPrepared(ctx, spec, canonicalSI)
	if err != nil {
		return nil, err
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	sv := newDS("SignatureValue")
	text(sv, base64.StdEncoding.EncodeToString(value))
	add(draft.sig, sv)

	return tree.Reparse(ctx, draft.doc, p.xmlLimits)
}

func normalizeCanonicalization(tr reference.Transform) (reference.Transform, error) {
	if tr.Algorithm == "" {
		tr.Algorithm = c14n.Exclusive
	}

	if !canonicalAlgorithm(tr.Algorithm) {
		return tr, fmt.Errorf("%w: canonicalization method", ErrAlgorithm)
	}

	tr.InclusivePrefixes = append([]string(nil), tr.InclusivePrefixes...)
	if err := reference.ValidateTransforms([]reference.Transform{tr}, reference.Options{}); err != nil {
		return tr, processingError(err)
	}

	return tr, nil
}

func prepareDetachedSigning(refs []DetachedReference, signer crypto.Signer, opt DetachedSignOptions) (*detachedSigningPlan, error) {
	p, err := normalizePolicy(opt.Policy)
	if err != nil {
		return nil, err
	}

	limits, err := normalizeResourceLimits(opt.Limits)
	if err != nil {
		return nil, err
	}

	cm, err := normalizeCanonicalization(opt.Canonicalization)
	if err != nil {
		return nil, err
	}

	if opt.XMLLimits == (document.Limits{}) {
		opt.XMLLimits = document.DefaultLimits()
	}

	if err := opt.XMLLimits.Validate(); err != nil {
		return nil, err
	}

	if err := validateDetachedTransforms(nil, opt.Processing); err != nil {
		return nil, err
	}

	key := signer.Public()
	if err := validateKey(key, p); err != nil {
		return nil, err
	}

	method := opt.SignatureMethod
	if method == "" {
		method = defaultSignature(key)
	}

	if !permits(p.AllowedSignatureMethods, method) {
		return nil, fmt.Errorf("%w: signature method", ErrPolicy)
	}

	if err := matchKeyAlgorithm(method, key); err != nil {
		return nil, err
	}

	if err := validateDetachedReferenceCount(refs, p.MaxReferences); err != nil {
		return nil, err
	}

	refs, err = normalizeDetachedReferences(refs, p, opt.Processing)
	if err != nil {
		return nil, err
	}

	return &detachedSigningPlan{policy: p, limits: limits, cm: cm, xmlLimits: opt.XMLLimits, processing: opt.Processing, method: method, key: key, refs: refs}, nil
}

func normalizeDetachedReferences(refs []DetachedReference, p Policy, processing reference.Options) ([]DetachedReference, error) {
	refs = append([]DetachedReference(nil), refs...)

	seen := make(map[string]bool, len(refs))
	for i := range refs {
		ref := &refs[i]
		if err := validExternalURI(ref.URI); err != nil {
			return nil, &ReferenceError{i, ref.URI, nameResolve, err}
		}

		if seen[ref.URI] {
			return nil, fmt.Errorf("%w: duplicate URI", ErrReference)
		}

		seen[ref.URI] = true

		ref.Transforms = reference.CloneTransforms(ref.Transforms)
		if err := validateDetachedTransforms(ref.Transforms, processing); err != nil {
			return nil, &ReferenceError{i, ref.URI, nameTransform, err}
		}

		if ref.DigestMethod == "" {
			ref.DigestMethod = SHA256
		}

		if !permits(p.AllowedDigestMethods, ref.DigestMethod) {
			return nil, fmt.Errorf("%w: digest method", ErrPolicy)
		}

		if _, err := hashForDigest(ref.DigestMethod); err != nil {
			return nil, err
		}
	}

	return refs, nil
}

// buildDetachedSignature validates all serialized metadata before resource I/O.
func buildDetachedSignature(ctx context.Context, p *detachedSigningPlan) (*detachedSignatureDraft, error) {
	sig := newDS("Signature")
	sig.NS = []tree.Namespace{{Prefix: "ds", URI: Namespace}}
	doc := tree.FromNodes([]*tree.Node{sig}, p.xmlLimits)
	si := newDS("SignedInfo")
	add(sig, si)

	methodNode := newDS("CanonicalizationMethod")
	setAttr(methodNode, "Algorithm", p.cm.Algorithm)
	addInclusive(methodNode, p.cm.InclusivePrefixes)
	add(si, methodNode)

	sm := newDS("SignatureMethod")
	setAttr(sm, "Algorithm", p.method)
	add(si, sm)
	// Build ALL metadata before resolving any data. Reparse the temporary template
	// to catch invalid Type strings, prefixes, and document limits before I/O.
	digestNodes := make([]*tree.Node, len(p.refs))
	if err := signDetachedReferences(ctx, p.refs, digestNodes, si); err != nil {
		return nil, err
	}

	checked, err := tree.Reparse(ctx, doc, p.xmlLimits)
	if err != nil {
		return nil, err
	}
	// Approve the actual serialized namespace context and all recipes before
	// any resource I/O. here() also needs the parsed parameter's real handle.
	sig = tree.Root(checked)
	si = sig.Children[0]
	processing := p.processing
	processing.Signature = tree.Wrap(checked, sig)

	for i, n := range si.Children[2:] {
		if isDS(n.Children[0], "Transforms") {
			transforms, err := parseCoreTransforms(ctx, n.Children[0], processing)
			if err != nil {
				return nil, &ReferenceError{i, p.refs[i].URI, nameTransform, err}
			}

			p.refs[i].Transforms = transforms
		}

		if err := reference.PrepareTransforms(ctx, p.refs[i].Transforms, processing); err != nil {
			return nil, &ReferenceError{i, p.refs[i].URI, nameTransform, processingError(err)}
		}

		digestNodes[i] = n.Children[len(n.Children)-1]
	}

	return &detachedSignatureDraft{doc: checked, sig: sig, si: si, digestNodes: digestNodes}, nil
}

func fillDetachedDigests(ctx context.Context, draft *detachedSignatureDraft, p *detachedSigningPlan, resolver Resolver, remaining *int) error {
	resourceRemaining := p.limits.MaxTotalResourceBytes
	for i, ref := range p.refs {
		h, _ := hashForDigest(ref.DigestMethod)
		hash := h.New()
		source := referenceSource{resolver: resolver, uri: ref.URI, limits: p.limits}

		_, err := source.write(ctx, hash, ref.Transforms, p.processing, remaining, &resourceRemaining)
		if err != nil {
			return &ReferenceError{i, ref.URI, nameTransform, err}
		}

		text(draft.digestNodes[i], base64.StdEncoding.EncodeToString(hash.Sum(nil)))
	}

	return nil
}

func signDetachedReferences(ctx context.Context, refs []DetachedReference, digestNodes []*tree.Node, si *tree.Node) error {
	for i, ref := range refs {
		n, err := referenceTemplateNode(ctx, ReferenceTemplate{URI: ref.URI, Type: ref.Type, DigestMethod: ref.DigestMethod, Transforms: ref.Transforms})
		if err != nil {
			return &ReferenceError{i, ref.URI, nameTransform, err}
		}

		digestNodes[i] = n.Children[len(n.Children)-1]
		add(si, n)
	}

	return nil
}

func validateDetachedReferenceCount(refs []DetachedReference, maximum int) error {
	if len(refs) == 0 || len(refs) > maximum {
		return fmt.Errorf("%w: reference count", ErrPolicy)
	}

	return nil
}

func normalizeResourceLimits(l ResourceLimits) (ResourceLimits, error) {
	if l.MaxResourceBytes == 0 {
		l.MaxResourceBytes = 8 << 20
	}

	if l.MaxTotalResourceBytes == 0 {
		l.MaxTotalResourceBytes = 32 << 20
	}

	if l.MaxResourceBytes < 1 || l.MaxTotalResourceBytes < 1 {
		return l, fmt.Errorf("%w: resource limits", ErrPolicy)
	}

	return l, nil
}

func validExternalURI(uri string) error {
	if strings.Contains(uri, "#") {
		return fmt.Errorf("%w: nonempty external URI without fragment required", ErrReference)
	}

	return validExternalReferenceURI(uri)
}

func validExternalReferenceURI(uri string) error {
	if !externalURI(uri) {
		return fmt.Errorf("%w: nonempty external URI required", ErrReference)
	}

	return validateURIReference(uri)
}

func validateURIReference(uri string) error {
	if err := uriref.Validate(uri); err != nil {
		return fmt.Errorf("%w: %w", ErrReference, err)
	}

	return nil
}

func validateDetachedTransforms(ts []reference.Transform, opt reference.Options) error {
	if err := reference.ValidateTransforms(ts, opt); err != nil {
		return processingError(err)
	}

	for _, tr := range ts {
		if tr.Algorithm == EnvelopedSignature {
			return fmt.Errorf("%w: enveloped transform on external reference", ErrPolicy)
		}
	}

	return nil
}

func canonicalAlgorithm(uri string) bool {
	switch uri {
	case c14n.Exclusive, c14n.ExclusiveWithComments, c14n.Canonical10, c14n.Canonical10WithComments, c14n.Canonical11, c14n.Canonical11WithComments:
		return true
	default:
		return false
	}
}

type parsedDetachedReference struct {
	DetachedReference
	digest []byte
}

type detachedVerificationPlan struct {
	policy     Policy
	limits     ResourceLimits
	processing reference.Options
	methods    []string
	expected   map[string]bool
	si         *tree.Node
	cm         reference.Transform
	method     string
	value      []byte
	refs       []parsedDetachedReference
}

func (p *detachedVerificationPlan) parseSignature(ctx context.Context, doc *document.Document) error {
	sig := tree.Root(doc)
	if !isDS(sig, "Signature") || len(findSignatures(doc)) != 1 {
		return fmt.Errorf("%w: standalone Signature required", ErrStructure)
	}

	children, err := structure(sig, "Signature", "Id")
	if err != nil {
		return err
	}

	if err := validateSimpleSignatureChildren(children); err != nil {
		return err
	}

	si := children[0]

	signed, err := structure(si, "SignedInfo", "Id")
	if err != nil {
		return err
	}

	if err := validateDetachedSignedInfo(signed, p.policy.MaxReferences); err != nil {
		return err
	}

	cm, err := parseCanonicalTransform(signed[0], "CanonicalizationMethod")
	if err != nil {
		return err
	}

	if !permits(p.methods, cm.Algorithm) {
		return fmt.Errorf("%w: SignedInfo canonicalization", ErrPolicy)
	}

	method, err := simpleAlgorithm(signed[1], "SignatureMethod")
	if err != nil {
		return err
	}

	if _, _, err := signatureAlgorithm(method); err != nil {
		return err
	}

	if !permits(p.policy.AllowedSignatureMethods, method) {
		return fmt.Errorf("%w: signature method", ErrPolicy)
	}

	value, err := base64Value(ctx, children[1], "SignatureValue", 2048, "Id")
	if err != nil {
		return err
	}

	if len(signed)-2 != len(p.expected) {
		return fmt.Errorf("%w: expected reference set size", ErrPolicy)
	}

	refs, err := parseDetachedReferenceSet(ctx, doc, signed[2:], p.policy, p.processing, p.expected)
	if err != nil {
		return err
	}

	p.si, p.cm, p.method, p.value, p.refs = si, cm, method, value, refs

	return nil
}

func parseDetachedReference(ctx context.Context, doc *document.Document, n *tree.Node, p Policy, processing reference.Options) (parsedDetachedReference, error) {
	var ref parsedDetachedReference

	children, err := structure(n, "Reference", "URI", "Id", "Type")
	if err != nil {
		return ref, err
	}

	ref.URI, err = requiredAttribute(n, "URI")
	if err != nil {
		return ref, err
	}

	if err := validExternalURI(ref.URI); err != nil {
		return ref, err
	}

	ref.Type, _ = getAttr(n, document.Name{Local: "Type"})

	if len(children) != 0 && isDS(children[0], "Transforms") {
		transforms, err := structure(children[0], "Transforms")
		if err != nil {
			return ref, err
		}
		// Schema requires at least one Transform when Transforms exists.
		if len(transforms) == 0 || len(transforms) > 64 {
			return ref, fmt.Errorf("%w: Transforms count", ErrStructure)
		}

		for _, tr := range transforms {
			method, err := parseTransform(ctx, tr, doc)
			if err != nil {
				return ref, err
			}

			ref.Transforms = append(ref.Transforms, method)
		}

		children = children[1:]
	}

	if len(children) != 2 || !isDS(children[0], "DigestMethod") || !isDS(children[1], "DigestValue") {
		return ref, fmt.Errorf("%w: Reference children", ErrStructure)
	}

	if err := validateDetachedTransforms(ref.Transforms, processing); err != nil {
		return ref, err
	}

	ref.DigestMethod, err = simpleAlgorithm(children[0], "DigestMethod")
	if err != nil {
		return ref, err
	}

	h, err := hashForDigest(ref.DigestMethod)
	if err != nil {
		return ref, err
	}

	if !permits(p.AllowedDigestMethods, ref.DigestMethod) {
		return ref, fmt.Errorf("%w: digest method", ErrPolicy)
	}

	ref.digest, err = base64Value(ctx, children[1], "DigestValue", h.Size())
	if err != nil {
		return ref, err
	}

	if len(ref.digest) != h.Size() {
		return ref, fmt.Errorf("%w: digest size", ErrStructure)
	}

	return ref, nil
}

func parseDetachedReferenceSet(ctx context.Context, doc *document.Document, nodes []*tree.Node, policy Policy, processing reference.Options, expected map[string]bool) ([]parsedDetachedReference, error) {
	refs := make([]parsedDetachedReference, 0, len(expected))
	seen := make(map[string]bool, len(expected))

	for i, n := range nodes {
		ref, err := parseDetachedReference(ctx, doc, n, policy, processing)
		if err != nil {
			return nil, &ReferenceError{i, ref.URI, nameTransform, err}
		}

		if seen[ref.URI] {
			return nil, fmt.Errorf("%w: duplicate URI", ErrReference)
		}

		seen[ref.URI] = true
		if !expected[ref.URI] {
			return nil, fmt.Errorf("%w: unexpected reference URI", ErrPolicy)
		}

		refs = append(refs, ref)
	}

	return refs, nil
}

func validateDetachedSignedInfo(signed []*tree.Node, maximum int) error {
	if len(signed) < 3 || len(signed)-2 > maximum || !isDS(signed[0], "CanonicalizationMethod") || !isDS(signed[1], "SignatureMethod") {
		return fmt.Errorf("%w: SignedInfo children", ErrStructure)
	}

	return nil
}
