package xmldsig

import (
	"bytes"
	"context"
	"crypto"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math"
	"slices"
	"strings"

	"github.com/skarm/xmlsec/c14n"
	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/internal/lexicon"
	"github.com/skarm/xmlsec/internal/nilcheck"
	"github.com/skarm/xmlsec/internal/signature"
	"github.com/skarm/xmlsec/internal/streamio"
	"github.com/skarm/xmlsec/internal/transformxml"
	"github.com/skarm/xmlsec/internal/tree"
	"github.com/skarm/xmlsec/reference"
)

// VerifyOptions sets the expected root name, application ID attribute and algorithms
// for restricted enveloped verification.
type VerifyOptions struct {
	// IDAttribute selects the application ID attribute; it is never inferred from a schema.
	IDAttribute document.Name
	// ExpectedRoot, when nonzero, must equal the document root's expanded name.
	ExpectedRoot document.Name
	// Policy sets permitted signature and digest algorithms and key and processing limits.
	Policy Policy
}

// Result records acceptance after SignatureValue and every Reference pass.
// The caller-supplied key is the entire trust decision for this restricted profile.
// The result does not establish PKIX trust or SAML or XAdES acceptance.
type Result struct {
	doc         *document.Document
	signature   *tree.Node
	algorithm   string
	fingerprint string
	references  []ReferenceResult
}

type parsedReference struct {
	uri          string
	digestMethod string
	target       *tree.Node
	digest       []byte
	prefixes     []string
	transforms   []reference.Transform
	exclude      *tree.Node
}

// Verify checks a single root-enveloped signature with an externally trusted
// key. KeyInfo, if present, is ignored for key selection and trust. No network,
// filesystem, metadata, certificate-chain or revocation lookup is performed.
func Verify(ctx context.Context, d *document.Document, key crypto.PublicKey, opt VerifyOptions) (*Result, error) {
	if ctx == nil {
		return nil, fmt.Errorf("%w: nil context", ErrPolicy)
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	if tree.Root(d) == nil {
		return nil, fmt.Errorf("%w: nil document", ErrStructure)
	}

	p, err := normalizePolicy(opt.Policy)
	if err != nil {
		return nil, err
	}

	if err := validateKey(key, p); err != nil {
		return nil, err
	}

	idAttr, err := normalizeID(opt.IDAttribute)
	if err != nil {
		return nil, err
	}

	sig, err := envelopedSignatureNode(d, opt.ExpectedRoot)
	if err != nil {
		return nil, err
	}

	children, err := structure(sig, lexicon.DSigElementSignature, "Id")
	if err != nil {
		return nil, err
	}

	if err := validateSimpleSignatureChildren(children); err != nil {
		return nil, err
	}

	si, sv := children[0], children[1]

	signed, err := structure(si, lexicon.DSigElementSignedInfo, "Id")
	if err != nil {
		return nil, err
	}

	if err := validateEnvelopedSignedInfo(signed, p.MaxReferences); err != nil {
		return nil, err
	}

	prefixes, err := parseCanonicalization(signed[0], lexicon.DSigElementCanonicalizationMethod)
	if err != nil {
		return nil, err
	}

	algorithm, err := simpleAlgorithm(signed[1], lexicon.DSigElementSignatureMethod)
	if err != nil {
		return nil, err
	}

	if _, _, err := signatureAlgorithm(algorithm); err != nil {
		return nil, err
	}

	if !permits(p.AllowedSignatureMethods, algorithm) {
		return nil, fmt.Errorf("%w: signature algorithm", ErrPolicy)
	}

	signatureValue, err := base64Value(ctx, sv, lexicon.DSigElementSignatureValue, 2048, "Id")
	if err != nil {
		return nil, err
	}

	refs, err := parseEnvelopedReferenceSet(ctx, d, idAttr, signed[2:], sig, p)
	if err != nil {
		return nil, err
	}

	resolver, err := reference.NewSameDocumentResolver(ctx, d, idAttr)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrReference, err)
	}

	remaining := p.MaxCanonicalBytes

	spec := signatureSpec{algorithm: algorithm}
	credential := signatureCredential{public: key}

	canonicalSI, err := credential.prepareInput(ctx, spec, func(dst io.Writer) error {
		return writeCanonicalElement(ctx, dst, tree.Wrap(d, si), reference.Transform{Algorithm: c14n.Exclusive, InclusivePrefixes: prefixes}, &remaining)
	})
	if err != nil {
		return nil, err
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}
	// Authenticating SignedInfo precedes processing Reference transforms.
	if err := credential.verifyPrepared(spec, canonicalSI, signatureValue); err != nil {
		return nil, err
	}

	result := &Result{doc: d, signature: sig, algorithm: algorithm}

	if err := verifyEnvelopedReferences(ctx, refs, resolver, d, sig, &remaining, result); err != nil {
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

// Root returns the immutable document root.
func (r *Result) Root() document.Element {
	if r == nil {
		return document.Element{}
	}

	return r.doc.Root()
}

// SignatureMethod returns the authenticated signature algorithm URI.
func (r *Result) SignatureMethod() string {
	if r == nil {
		return ""
	}

	return r.algorithm
}

// KeyFingerprintSHA256 returns the hexadecimal SHA-256 fingerprint of the externally
// trusted verification key.
func (r *Result) KeyFingerprintSHA256() string {
	if r == nil {
		return ""
	}

	return r.fingerprint
}

// References returns an owned slice of immutable validated reference results.
func (r *Result) References() []ReferenceResult {
	if r == nil {
		return nil
	}

	return append([]ReferenceResult(nil), r.references...)
}

// CoversElement checks element identity in this EXACT snapshot and membership
// in a checked reference subtree, excluding Signature. It does NOT certify
// comments, omitted namespace bindings, inherited context, XPath/QName values,
// schema defaults or application semantics. It is not a generic node-set API.
func (r *Result) CoversElement(e document.Element) bool {
	if r == nil {
		return false
	}

	d, n := tree.Unwrap(e)
	if d != r.doc || n == nil || within(n, r.signature) {
		return false
	}

	for _, ref := range r.references {
		_, target := tree.Unwrap(ref.target)
		if within(n, target) {
			return true
		}
	}

	return false
}

func envelopedSignatureNode(d *document.Document, expected document.Name) (*tree.Node, error) {
	root := tree.Root(d)
	if expected != (document.Name{}) && root.Name != expected {
		return nil, fmt.Errorf("%w: unexpected root QName", ErrPolicy)
	}

	signatures := findSignatures(d)
	if len(signatures) != 1 || signatures[0].Parent != root {
		return nil, fmt.Errorf("%w: exactly one Signature directly under root is required", ErrStructure)
	}

	return signatures[0], nil
}

func parseEnvelopedReferenceSet(ctx context.Context, d *document.Document, idAttr document.Name, nodes []*tree.Node, sig *tree.Node, p Policy) ([]parsedReference, error) {
	root := tree.Root(d)

	ids, err := indexIDs(d, idAttr)
	if err != nil {
		return nil, err
	}

	rootID, ok := getAttr(root, idAttr)
	if !ok {
		return nil, fmt.Errorf("%w: root ID missing", ErrReference)
	}

	refs := make([]parsedReference, 0, len(nodes))
	seen := map[string]struct{}{}
	rootCovered := false

	for _, n := range nodes {
		ref, err := parseReference(ctx, n, ids, root, sig, p)
		if err != nil {
			return nil, err
		}

		if _, exists := seen[ref.uri]; exists {
			return nil, fmt.Errorf("%w: duplicate reference", ErrReference)
		}

		seen[ref.uri] = struct{}{}
		if ref.uri == "#"+rootID && ref.target == root {
			rootCovered = true
		}

		refs = append(refs, ref)
	}

	if !rootCovered {
		return nil, fmt.Errorf("%w: root reference is mandatory", ErrPolicy)
	}

	return refs, nil
}

func isDS(n *tree.Node, local string) bool {
	return n != nil && n.Kind == tree.ElementNode && n.Name == (document.Name{Space: Namespace, Local: local})
}

func attributes(n *tree.Node, allowed ...string) error {
	for _, a := range n.Attrs {
		ok := false

		if a.Name.Space == "" {
			if slices.Contains(allowed, a.Name.Local) {
				ok = true
			}
		}

		if !ok {
			return fmt.Errorf("%w: unexpected attribute on %s", ErrStructure, n.Name.Local)
		}
	}

	return nil
}

func structure(n *tree.Node, local string, allowed ...string) ([]*tree.Node, error) {
	if !isDS(n, local) {
		return nil, fmt.Errorf("%w: expected ds:%s", ErrStructure, local)
	}

	if err := attributes(n, allowed...); err != nil {
		return nil, err
	}

	return elementChildren(n)
}

func elementChildren(n *tree.Node) ([]*tree.Node, error) {
	var children []*tree.Node

	for _, c := range n.Children {
		switch c.Kind {
		case tree.ElementNode:
			children = append(children, c)
		case tree.CommentNode:
		case tree.TextNode:
			if !tree.IsXMLSpace(c.Data) {
				return nil, fmt.Errorf("%w: unexpected text in %s", ErrStructure, n.Name.Local)
			}
		default:
			return nil, fmt.Errorf("%w: processing instruction in signature structure", ErrStructure)
		}
	}

	return children, nil
}

func requiredAttribute(n *tree.Node, name string) (string, error) {
	s, ok := getAttr(n, document.Name{Local: name})
	if !ok {
		return "", fmt.Errorf("%w: missing %s on %s", ErrStructure, name, n.Name.Local)
	}

	return s, nil
}

func simpleAlgorithm(n *tree.Node, local string) (string, error) {
	children, err := structure(n, local, "Algorithm")
	if err != nil {
		return "", err
	}

	if len(children) != 0 {
		return "", fmt.Errorf("%w: algorithm parameters unsupported", ErrAlgorithm)
	}

	return requiredAttribute(n, "Algorithm")
}

func parseCanonicalization(n *tree.Node, local string) ([]string, error) {
	tr, err := parseCanonicalTransform(n, local)
	if err != nil {
		return nil, err
	}

	if tr.Algorithm != c14n.Exclusive {
		return nil, fmt.Errorf("%w: this signature profile requires Exclusive C14N without comments", ErrAlgorithm)
	}

	return tr.InclusivePrefixes, nil
}

func parseCanonicalTransform(n *tree.Node, local string) (reference.Transform, error) {
	t, err := transformxml.ParseCanonical(n, local)
	return t, transformXMLError(err)
}

func base64Value(ctx context.Context, n *tree.Node, local string, maxBytes int, allowed ...string) ([]byte, error) {
	if !isDS(n, local) {
		return nil, fmt.Errorf("%w: expected %s", ErrStructure, local)
	}

	if err := attributes(n, allowed...); err != nil {
		return nil, err
	}

	for _, child := range n.Children {
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		if child.Kind != tree.TextNode && child.Kind != tree.CommentNode {
			return nil, fmt.Errorf("%w: non-text base64", ErrStructure)
		}
	}

	value, err := tree.DecodeBase64(ctx, n, 0, maxBytes)
	if errors.Is(err, tree.ErrLimit) {
		return nil, errors.Join(ErrPolicy, err)
	}

	if err != nil || len(value) == 0 {
		return nil, errors.Join(fmt.Errorf("%w: invalid base64 in %s", ErrStructure, local), err)
	}

	return value, nil
}

func parseReference(ctx context.Context, n *tree.Node, ids map[string]*tree.Node, root, sig *tree.Node, p Policy) (parsedReference, error) {
	var ref parsedReference

	children, err := structure(n, lexicon.DSigElementReference, "URI", "Id")
	if err != nil {
		return ref, err
	}

	if len(children) != 3 || !isDS(children[0], lexicon.DSigElementTransforms) || !isDS(children[1], lexicon.DSigElementDigestMethod) || !isDS(children[2], lexicon.DSigElementDigestValue) {
		return ref, fmt.Errorf("%w: Reference children", ErrStructure)
	}

	uri, err := requiredAttribute(n, "URI")
	if err != nil {
		return ref, err
	}

	if !strings.HasPrefix(uri, "#") || !tree.NCName(strings.TrimPrefix(uri, "#")) {
		return ref, fmt.Errorf("%w: only bare same-document #ID is supported", ErrReference)
	}

	ref.uri = uri

	ref.target = ids[uri[1:]]
	if ref.target == nil || within(ref.target, sig) {
		return ref, fmt.Errorf("%w: unresolved or signature-internal target", ErrReference)
	}

	transforms, err := structure(children[0], lexicon.DSigElementTransforms)
	if err != nil {
		return ref, err
	}

	if ref.target == root {
		if len(transforms) != 2 {
			return ref, fmt.Errorf("%w: root needs exactly enveloped then exclusive transforms", ErrPolicy)
		}

		alg, err := simpleAlgorithm(transforms[0], lexicon.DSigElementTransform)
		if err != nil {
			return ref, err
		}

		if alg != EnvelopedSignature {
			return ref, fmt.Errorf("%w: root enveloped transform missing", ErrPolicy)
		}

		ref.exclude = sig
		transforms = transforms[1:]
	}

	if len(transforms) != 1 {
		return ref, fmt.Errorf("%w: transform count", ErrPolicy)
	}

	ref.prefixes, err = parseCanonicalization(transforms[0], lexicon.DSigElementTransform)
	if err != nil {
		return ref, err
	}

	ref.transforms = strictReferenceTransforms(ref.target == root, ref.prefixes)

	ref.digestMethod, err = simpleAlgorithm(children[1], lexicon.DSigElementDigestMethod)
	if err != nil {
		return ref, err
	}

	h, err := hashForDigest(ref.digestMethod)
	if err != nil {
		return ref, err
	}

	if !permits(p.AllowedDigestMethods, ref.digestMethod) {
		return ref, fmt.Errorf("%w: digest method", ErrPolicy)
	}

	ref.digest, err = base64Value(ctx, children[2], lexicon.DSigElementDigestValue, h.Size())
	if err != nil {
		return ref, err
	}

	if len(ref.digest) != h.Size() {
		return ref, fmt.Errorf("%w: digest size", ErrStructure)
	}

	return ref, nil
}

// validateSimpleSignatureChildren restricts this profile to SignedInfo,
// SignatureValue, and an optional untrusted KeyInfo.
func validateSimpleSignatureChildren(children []*tree.Node) error {
	if len(children) < 2 || len(children) > 3 || !isDS(children[0], lexicon.DSigElementSignedInfo) || !isDS(children[1], lexicon.DSigElementSignatureValue) || len(children) == 3 && !isDS(children[2], lexicon.DSigElementKeyInfo) {
		return fmt.Errorf("%w: Signature children", ErrStructure)
	}

	return nil
}

func verifyEnvelopedReferences(ctx context.Context, refs []parsedReference, resolver *reference.SameDocumentResolver, d *document.Document, sig *tree.Node, remaining *int, result *Result) error {
	for i, ref := range refs {
		if err := ctx.Err(); err != nil {
			return err
		}

		resolved, err := resolver.Resolve(ctx, ref.uri)
		if err != nil {
			return &ReferenceError{i, ref.uri, nameResolve, err}
		}

		h, err := hashForDigest(ref.digestMethod)
		if err != nil {
			return err
		}

		digest := h.New()
		processing := reference.Options{AllowedTransforms: []string{EnvelopedSignature, c14n.Exclusive}, Signature: tree.Wrap(d, sig)}

		processed, err := processTo(ctx, digest, resolved.Data(), ref.transforms,
			processing, remaining)
		if err != nil {
			return &ReferenceError{i, ref.uri, nameTransform, err}
		}

		if subtle.ConstantTimeCompare(digest.Sum(nil), ref.digest) != 1 {
			return &ReferenceError{i, ref.uri, "digest", ErrDigest}
		}

		result.references = append(result.references, ReferenceResult{uri: ref.uri, digestMethod: ref.digestMethod, target: tree.Wrap(d, ref.target), processed: processed, resolver: resolver, processing: processing, digest: digest.Sum(nil), transforms: ref.transforms})
	}

	return nil
}

func validateEnvelopedSignedInfo(signed []*tree.Node, maximum int) error {
	if len(signed) < 3 || len(signed)-2 > maximum || !isDS(signed[0], lexicon.DSigElementCanonicalizationMethod) || !isDS(signed[1], lexicon.DSigElementSignatureMethod) {
		return fmt.Errorf("%w: SignedInfo children or reference count", ErrStructure)
	}

	return nil
}

// ReferenceResult retains an authenticated digest and processing trace without
// canonical bytes. Explicit Manifest traversal also retains bounded original
// subresource bytes. Target is valid only for a same-document element reference;
// it is invalid for whole-document and external octet references.
type ReferenceResult struct {
	uri             string
	digestMethod    string
	typeURI         string
	target          document.Element
	processed       *reference.Report
	resolver        *reference.SameDocumentResolver
	external        *referenceSource
	processing      reference.Options
	digest          []byte
	manifestInput   []byte
	transforms      []reference.Transform
	coverageDoc     *document.Document
	coverageRoot    *tree.Node
	coverageExclude *tree.Node
}

// CoversElement conservatively proves original element/subtree membership for
// results from VerifySignature. It excludes the containing Signature only when
// an enveloped transform actually removed it. Result.CoversElement applies the
// root-enveloped profile's coverage rules; detached results never prove coverage.
// Comments, unused namespace bindings and application-level meaning are outside
// this guarantee. A handle from a different snapshot is never accepted.
func (r ReferenceResult) CoversElement(e document.Element) bool {
	d, n := tree.Unwrap(e)
	return n != nil && d == r.coverageDoc && r.coverageRoot != nil && within(n, r.coverageRoot) && !within(n, r.coverageExclude)
}

// Type returns the Reference Type URI.
func (r ReferenceResult) Type() string { return r.typeURI }

// URI returns the reference URI.
func (r ReferenceResult) URI() string { return r.uri }

// ResourceURI returns the exact URI supplied to the external resolver, including
// any fragment. It is empty for a same-document reference. URI preserves the
// original signed spelling, which can differ when BaseURI resolution is enabled.
func (r ReferenceResult) ResourceURI() string {
	if r.external == nil {
		return ""
	}

	return r.external.uri
}

// DigestMethod returns the reference digest algorithm URI.
func (r ReferenceResult) DigestMethod() string { return r.digestMethod }

// Target returns the same-document element selected by the reference, or an
// invalid handle for whole-document references and external octets.
func (r ReferenceResult) Target() document.Element { return r.target }

// Digest returns an owned copy of the authenticated reference digest.
func (r ReferenceResult) Digest() []byte { return slices.Clone(r.digest) }

// Size returns the number of processed digest-input bytes.
func (r ReferenceResult) Size() int { return r.processed.Size() }

// WriteDigestInput replays the approved transforms into dst, without retaining
// their serialized output. It checks that the replay still matches the verified
// digest. External references reopen the application resolver; it must remain
// usable and honor ctx. On any error dst may contain bytes that must be discarded.
func (r ReferenceResult) WriteDigestInput(ctx context.Context, dst io.Writer) (int64, error) {
	if ctx == nil || nilcheck.IsNil(dst) || r.processed == nil {
		return 0, ErrPolicy
	}

	h, err := hashForDigest(r.digestMethod)
	if err != nil {
		return 0, err
	}

	digest := h.New()
	writer := streamio.Writer{Context: ctx, Target: io.MultiWriter(dst, digest), Limit: math.MaxInt64, LimitError: ErrPolicy}

	if r.external != nil {
		resources := r.external.limits.MaxResourceBytes
		remaining := r.processed.ProducedBytes()
		// Empty streams still need an EOF check.
		remaining = max(1, remaining)
		_, err = r.external.write(ctx, &writer, r.transforms, r.processing, &remaining, &resources)
	} else {
		if r.resolver == nil {
			return 0, ErrPolicy
		}

		resolved, resolveErr := r.resolver.Resolve(ctx, r.uri)
		if resolveErr != nil {
			return 0, resolveErr
		}

		_, err = reference.Write(ctx, &writer, resolved.Data(), r.transforms, r.processing)
	}

	if err != nil {
		return writer.Written, err
	}

	if !bytes.Equal(digest.Sum(nil), r.digest) {
		return writer.Written, ErrDigest
	}

	return writer.Written, nil
}

// IsCanonicalXML returns whether processing ended in a recognized canonicalization step.
func (r ReferenceResult) IsCanonicalXML() bool { return r.processed.Canonicalization() != "" }

// CanonicalizationMethod returns the final canonicalization algorithm URI, or an empty
// string for arbitrary octets.
func (r ReferenceResult) CanonicalizationMethod() string { return r.processed.Canonicalization() }

// InputKind returns the original transform input kind.
func (r ReferenceResult) InputKind() reference.Kind { return r.processed.InputKind() }

// Transforms returns a deep copy of the reference transform parameters.
func (r ReferenceResult) Transforms() []reference.Transform {
	return reference.CloneTransforms(r.transforms)
}

// Steps returns an owned copy of the processing trace.
func (r ReferenceResult) Steps() []reference.Step { return r.processed.Steps() }

// WriteCanonicalizedInput replays the approved transforms once and checks the
// original signed digest while writing a timestamp input. Final octets are
// unchanged; a final node set is serialized with method instead of the implicit
// XMLDSig Canonical XML 1.0 conversion. Resolvers and extension transforms are
// each invoked once. External raw-resource identity, Close and all work bounds
// remain checked. On error dst may contain bytes that must be discarded.
func (r ReferenceResult) WriteCanonicalizedInput(ctx context.Context, dst io.Writer, method reference.Transform) (int64, error) {
	if ctx == nil || nilcheck.IsNil(dst) || r.processed == nil {
		return 0, ErrPolicy
	}

	if err := ctx.Err(); err != nil {
		return 0, err
	}

	h, err := hashForDigest(r.digestMethod)
	if err != nil {
		return 0, err
	}

	digest := h.New()
	writer := streamio.Writer{Context: ctx, Target: dst, Limit: math.MaxInt64, LimitError: ErrPolicy}

	if r.external != nil {
		resources := r.external.limits.MaxResourceBytes

		remaining := r.processing.MaxProducedBytes
		if remaining == 0 {
			remaining = reference.DefaultOptions().MaxProducedBytes
		}

		_, err = r.external.writeOutputs(ctx, digest, &writer, method, r.transforms, r.processing, &remaining, &resources)
	} else {
		if r.resolver == nil {
			return 0, ErrPolicy
		}

		resolved, resolveErr := r.resolver.Resolve(ctx, r.uri)
		if resolveErr != nil {
			return 0, resolveErr
		}

		_, err = reference.WriteAndCanonicalize(ctx, digest, &writer, resolved.Data(), r.transforms, method, r.processing)
	}

	if err != nil {
		return writer.Written, err
	}

	if !bytes.Equal(digest.Sum(nil), r.digest) {
		return writer.Written, ErrDigest
	}

	return writer.Written, nil
}

func within(n, ancestor *tree.Node) bool {
	for ; n != nil; n = n.Parent {
		if n == ancestor {
			return true
		}
	}

	return false
}
