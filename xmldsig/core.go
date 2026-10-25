package xmldsig

import (
	"context"
	"crypto"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"

	"github.com/skarm/xmlsec/c14n"
	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/internal/lexicon"
	"github.com/skarm/xmlsec/internal/signature"
	"github.com/skarm/xmlsec/internal/tree"
	"github.com/skarm/xmlsec/keyinfo"
	"github.com/skarm/xmlsec/reference"
)

// SignatureOptions verifies an explicitly selected signature. Same-document
// references are enabled; external resources and recursive Manifest checks require
// opt-in. Zero options do not require root coverage. Applications should set
// RequiredElements or ExpectedURIs, or both, for their coverage contract.
type SignatureOptions struct {
	// External enables external references with a mandatory allowlist. Nil disables them.
	External *ExternalReferences
	// Manifests selects recursive Manifest validation. Zero retains core XMLDSig behavior
	// without checking Manifest contents.
	Manifests ManifestPolicy
	// IDAttribute selects the application ID attribute; zero uses unqualified ID.
	// Unqualified Id is also indexed on supported XMLDSig elements.
	IDAttribute document.Name
	// AdditionalIDRules adds explicit same-document ID attributes to the application rule.
	AdditionalIDRules []reference.IDAttributeRule
	// Policy sets permitted signature and digest algorithms and key and processing limits.
	Policy Policy
	// AllowedCanonicalizationMethods defaults to Exclusive C14N, independently of
	// Reference transforms.
	AllowedCanonicalizationMethods []string
	// Processing sets reference transform permissions, extensions and execution budgets.
	Processing reference.Options
	// MaxSignatures bounds Signature elements in the document; default 16, maximum 64.
	MaxSignatures int
	// RequiredElements requires conservative coverage of exact snapshot handles. Coverage
	// does not establish the meaning of comments, unused namespaces, QName-valued text or
	// application protocols.
	RequiredElements []document.Element
	// ExpectedURIs requires an exact multiset of direct reference URI spellings,
	// independent of order. Nil disables this check. Repeated URIs with different
	// transforms are permitted.
	ExpectedURIs []string
}

// SignatureResult records acceptance after SignatureValue, every direct Reference
// and requested coverage and Manifest checks pass. Manifest contents are checked
// only in recursive mode. Other signatures, unreferenced Objects and PKIX, SAML
// and XAdES requirements remain separate. The result has no Root convenience
// method because core verification does not imply root coverage.
type SignatureResult struct {
	doc         *document.Document
	signature   document.Element
	algorithm   string
	fingerprint string
	parameters  SignatureParameters
	references  []ReferenceResult
	manifests   []ManifestResult
}

// VerifySignature validates ONLY the explicitly selected signature with the
// caller's trusted key. It does not trust KeyInfo or any other signature.
func VerifySignature(ctx context.Context, doc *document.Document, selected document.Element, key crypto.PublicKey, opt SignatureOptions) (*SignatureResult, error) {
	result, _, err := VerifySignatureDetailed(ctx, doc, selected, key, opt)
	return result, err
}

// VerifySignatureDetailed stops at the first error and leaves unprocessed
// references not-checked. No successful Result accompanies a failure. The report
// contains diagnostic strings/steps only, never partially authenticated payloads.
func VerifySignatureDetailed(ctx context.Context, doc *document.Document, selected document.Element, key crypto.PublicKey, opt SignatureOptions) (*SignatureResult, *VerificationReport, error) {
	return verifySignatureDetailed(ctx, doc, selected, signatureCredential{public: key}, opt)
}

func failureStatus(err error) CheckStatus {
	switch {
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return Indeterminate
	case errors.Is(err, ErrPolicy), errors.Is(err, reference.ErrPolicy), errors.Is(err, reference.ErrLimit), errors.Is(err, document.ErrLimit):
		return Disallowed
	case errors.Is(err, ErrAlgorithm), errors.Is(err, reference.ErrUnsupported), errors.Is(err, document.ErrUnsupported):
		return Unsupported
	default:
		return Invalid
	}
}

func coreOptions(doc *document.Document, opt SignatureOptions) (SignatureOptions, Policy, error) {
	p, err := normalizePolicy(opt.Policy)
	if err != nil {
		return opt, p, err
	}

	opt.IDAttribute, err = normalizeID(opt.IDAttribute)
	if err != nil {
		return opt, p, err
	}

	if opt.MaxSignatures == 0 {
		opt.MaxSignatures = 16
	}

	if opt.MaxSignatures < 1 || opt.MaxSignatures > 64 {
		return opt, p, fmt.Errorf("%w: signature count limit", ErrPolicy)
	}

	opt.AllowedCanonicalizationMethods = append([]string(nil), opt.AllowedCanonicalizationMethods...)
	if len(opt.AllowedCanonicalizationMethods) == 0 {
		opt.AllowedCanonicalizationMethods = []string{c14n.Exclusive}
	}

	for _, method := range opt.AllowedCanonicalizationMethods {
		if !canonicalAlgorithm(method) {
			return opt, p, fmt.Errorf("%w: canonicalization policy", ErrAlgorithm)
		}
	}

	if err := reference.ValidateTransforms(nil, opt.Processing); err != nil {
		return opt, p, processingError(err)
	}

	for _, e := range opt.RequiredElements {
		d, n := tree.Unwrap(e)
		if d != doc || n == nil {
			return opt, p, fmt.Errorf("%w: RequiredElements must belong to the input snapshot", ErrPolicy)
		}
	}

	if opt.ExpectedURIs != nil && (len(opt.ExpectedURIs) == 0 || len(opt.ExpectedURIs) > p.MaxReferences) {
		return opt, p, fmt.Errorf("%w: ExpectedURIs count", ErrPolicy)
	}

	return opt, p, nil
}

func coreIDRules(opt SignatureOptions) []reference.IDAttributeRule {
	names := make([]document.Name, 0, 9)
	for _, local := range []string{lexicon.DSigElementSignature, lexicon.DSigElementSignedInfo, lexicon.DSigElementSignatureValue, lexicon.DSigElementReference, lexicon.DSigElementKeyInfo, "Object", "Manifest", "SignatureProperties", "SignatureProperty"} {
		names = append(names, document.Name{Space: Namespace, Local: local})
	}

	rules := []reference.IDAttributeRule{{Attribute: opt.IDAttribute}, {Attribute: document.Name{Local: "Id"}, Elements: names}}
	rules = append(rules, keyinfo.DefaultIDRules()...)

	return append(rules, opt.AdditionalIDRules...)
}

func signatureParts(sig *tree.Node) (si, sv *tree.Node, err error) {
	children, err := structure(sig, lexicon.DSigElementSignature, "Id")
	if err != nil {
		return nil, nil, err
	}

	if len(children) < 2 || !isDS(children[0], lexicon.DSigElementSignedInfo) || !isDS(children[1], lexicon.DSigElementSignatureValue) {
		return nil, nil, fmt.Errorf("%w: Signature children", ErrStructure)
	}

	rest := children[2:]
	if len(rest) > 0 && isDS(rest[0], lexicon.DSigElementKeyInfo) {
		if err := attributes(rest[0], "Id"); err != nil {
			return nil, nil, err
		}

		rest = rest[1:]
	}

	for _, object := range rest {
		if !isDS(object, "Object") {
			return nil, nil, fmt.Errorf("%w: expected Object after SignatureValue/KeyInfo", ErrStructure)
		}

		if err := attributes(object, "Id", "MimeType", "Encoding"); err != nil {
			return nil, nil, err
		}
		// Object content is arbitrary XML. No XAdES/Manifest interpretation here.
	}

	return children[0], children[1], nil
}

func prepareCore(ctx context.Context, doc *document.Document, selected document.Element, opt SignatureOptions, template bool, report *VerificationReport) (*corePlan, error) {
	if ctx == nil {
		return nil, fmt.Errorf("%w: nil context", ErrPolicy)
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	if tree.Root(doc) == nil {
		return nil, ErrStructure
	}

	sd, sig := tree.Unwrap(selected)
	if sd != doc || sig == nil || !isDS(sig, lexicon.DSigElementSignature) {
		return nil, fmt.Errorf("%w: explicit Signature handle from this snapshot required", ErrPolicy)
	}

	opt, p, err := coreOptions(doc, opt)
	if err != nil {
		return nil, err
	}

	if len(findSignatures(doc)) > opt.MaxSignatures {
		return nil, fmt.Errorf("%w: too many Signature elements", ErrPolicy)
	}

	si, sv, err := signatureParts(sig)
	if err != nil {
		return nil, err
	}

	signed, err := structure(si, lexicon.DSigElementSignedInfo, "Id")
	if err != nil {
		return nil, err
	}

	if len(signed) < 3 || len(signed)-2 > p.MaxReferences || !isDS(signed[0], lexicon.DSigElementCanonicalizationMethod) || !isDS(signed[1], lexicon.DSigElementSignatureMethod) {
		return nil, fmt.Errorf("%w: SignedInfo children/reference count", ErrStructure)
	}

	plan := &corePlan{sig: sig, si: si, sv: sv, policy: p, processing: opt.Processing}
	plan.processing.Signature = selected // caller cannot override the containing Signature
	plan.processing.IDRules = coreIDRules(opt)

	plan.cm, err = parseCanonicalTransform(signed[0], lexicon.DSigElementCanonicalizationMethod)
	if err != nil {
		return nil, err
	}

	if !permits(opt.AllowedCanonicalizationMethods, plan.cm.Algorithm) {
		return nil, fmt.Errorf("%w: SignedInfo canonicalization", ErrPolicy)
	}

	plan.spec, err = parseSignatureMethod(signed[1], p)
	if err != nil {
		return nil, err
	}

	plan.method = plan.spec.algorithm
	report.SignatureMethod = plan.method

	if template {
		err = emptyValue(sv, lexicon.DSigElementSignatureValue, "Id")
	} else {
		plan.value, err = base64Value(ctx, sv, lexicon.DSigElementSignatureValue, 2048, "Id")
	}

	if err != nil {
		return nil, err
	}

	if err := plan.prepareReferences(ctx, signed[2:], opt, template, report); err != nil {
		return nil, err
	}

	plan.resolver, err = reference.NewSameDocumentResolverWithRules(ctx, doc, coreIDRules(opt))
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrReference, err)
	}

	plan.external, err = newResourceSession(opt.External)
	if err != nil {
		return nil, err
	}

	plan.graph, err = prepareManifestGraph(ctx, doc, plan, opt.Manifests, template, report)
	if err != nil {
		return nil, err
	}

	if err := prepareProgramReferences(ctx, plan); err != nil {
		return nil, err
	}

	return plan, nil
}

func verifySignatureDetailed(ctx context.Context, doc *document.Document, selected document.Element, credential signatureCredential, opt SignatureOptions) (result *SignatureResult, report *VerificationReport, resultErr error) {
	report = &VerificationReport{Status: NotChecked, SignatureValue: NotChecked, ManifestValidation: NotChecked}
	stage := "structure"

	defer func() {
		if resultErr != nil {
			result = nil
		}

		finalizeVerificationReport(report, stage, resultErr)
	}()

	plan, err := prepareCore(ctx, doc, selected, opt, false, report)
	if err != nil {
		return nil, report, err
	}

	stage = "key"

	if err := credential.validate(plan.spec, plan.policy); err != nil {
		return nil, report, err
	}

	budget := newCoreBudget(plan)
	stage = "signed-info"

	canonical, err := credential.prepareInput(ctx, plan.spec, func(dst io.Writer) error { return budget.signedInfo(ctx, dst, doc, plan) })
	if err != nil {
		return nil, report, err
	}

	stage = "signature-value"

	if err := ctx.Err(); err != nil {
		return nil, report, err
	}

	if err := credential.verifyPrepared(plan.spec, canonical, plan.value); err != nil {
		return nil, report, err
	}

	report.SignatureValue = Valid
	result = &SignatureResult{doc: doc, signature: selected, algorithm: plan.method, parameters: plan.spec.parameters()}
	stage = "references"

	if err := plan.graph.verify(ctx, doc, plan, budget, result, report); err != nil {
		if _, ok := errors.AsType[*ManifestReferenceError](err); ok {
			stage = "manifests"
		}

		return nil, report, err
	}

	stage = "coverage"

	for _, e := range opt.RequiredElements {
		if !result.CoversElement(e) {
			return nil, report, fmt.Errorf("%w: required element is not covered", ErrPolicy)
		}
	}

	if err := ctx.Err(); err != nil {
		return nil, report, err
	}

	if credential.mac {
		return result, report, nil
	} // no fingerprint of a shared secret

	spki, err := signature.MarshalPublicKey(credential.public)
	if err != nil {
		return nil, report, fmt.Errorf("%w: %w", ErrKey, err)
	}

	fp := sha256.Sum256(spki)
	result.fingerprint = hex.EncodeToString(fp[:])

	return result, report, nil
}

func finalizeVerificationReport(report *VerificationReport, stage string, err error) {
	if err == nil {
		report.Status = Valid
		return
	}

	status := failureStatus(err)
	report.Status = status
	report.FailureStage = stage
	report.Error = err.Error()

	if stage == "signature-value" {
		report.SignatureValue = status
	}

	if me, ok := errors.AsType[*ManifestReferenceError](err); ok {
		report.ManifestValidation = status
		recordManifestReferenceFailure(report, me, status)

		return
	}

	if re, ok := errors.AsType[*ReferenceError](err); ok {
		recordReferenceFailure(report.References, re, status)
	}
}

func recordManifestReferenceFailure(report *VerificationReport, me *ManifestReferenceError, status CheckStatus) {
	if me.Manifest < 0 || me.Manifest >= len(report.Manifests) {
		return
	}

	m := &report.Manifests[me.Manifest]
	m.Status = status

	if me.Reference != nil {
		recordReferenceFailure(m.References, me.Reference, status)
	}
}

func recordReferenceFailure(references []ReferenceReport, re *ReferenceError, status CheckStatus) {
	if re.Index < 0 || re.Index >= len(references) {
		return
	}

	r := &references[re.Index]
	r.Status = status
	r.Stage = re.Stage
	r.Error = re.Err.Error()
}

// Signature returns the validated Signature element in the verified snapshot.
func (r *SignatureResult) Signature() document.Element {
	if r == nil {
		return document.Element{}
	}

	return r.signature
}

// SignatureMethod returns the authenticated signature algorithm URI.
func (r *SignatureResult) SignatureMethod() string {
	if r == nil {
		return ""
	}

	return r.algorithm
}

// Parameters returns a copy of the effective SignatureMethod parameters.
func (r *SignatureResult) Parameters() SignatureParameters {
	if r == nil {
		return SignatureParameters{}
	}

	return copySignatureParameters(r.parameters)
}

// KeyFingerprintSHA256 returns the hexadecimal SHA-256 fingerprint of the externally
// trusted verification key.
func (r *SignatureResult) KeyFingerprintSHA256() string {
	if r == nil {
		return ""
	}

	return r.fingerprint
}

// References returns an owned slice of immutable validated reference results.
func (r *SignatureResult) References() []ReferenceResult {
	if r == nil {
		return nil
	}

	return append([]ReferenceResult(nil), r.references...)
}

// CoversElement reports whether a validated reference authenticates the complete element
// under its coverage rules.
func (r *SignatureResult) CoversElement(e document.Element) bool {
	if r == nil {
		return false
	}

	d, n := tree.Unwrap(e)
	if d != r.doc || n == nil {
		return false
	}

	for _, m := range r.manifests {
		for _, ref := range m.references {
			if ref.CoversElement(e) {
				return true
			}
		}
	}

	for _, ref := range r.references {
		if ref.CoversElement(e) {
			return true
		}
	}

	return false
}

// CheckStatus records a diagnostic outcome. It grants no partial trust in returned
// data.
type CheckStatus string

const (
	// NotChecked indicates that a check was not performed.
	NotChecked CheckStatus = "not-checked"
	// Valid indicates a successful check.
	Valid CheckStatus = "valid"
	// Invalid indicates invalid data or a failed check.
	Invalid CheckStatus = "invalid"
	// Unsupported indicates an unsupported feature.
	Unsupported CheckStatus = "unsupported"
	// Disallowed indicates a policy rejection.
	Disallowed CheckStatus = "disallowed"
	// Indeterminate indicates that validation cannot establish the required result.
	Indeterminate CheckStatus = "indeterminate"
)

// ReferenceReport records one reference digest outcome and its completed transform
// steps.
type ReferenceReport struct {
	// Index is the zero-based reference position within its SignedInfo or Manifest.
	Index int `json:"index"`
	// URI preserves the signed reference URI spelling.
	URI string `json:"uri"`
	// ResourceURI is the authorized resolver URI; URI preserves signed spelling.
	ResourceURI string `json:"resource_uri,omitempty"`
	// Status records the reference digest check outcome.
	Status CheckStatus `json:"status"`
	// Stage identifies the failed reference processing stage, when present.
	Stage string `json:"stage,omitempty"`
	// Error describes the reference failure, or is empty on success.
	Error string `json:"error,omitempty"`
	// Steps records completed transforms and implicit conversions.
	Steps []reference.Step `json:"steps,omitempty"`
}

// VerificationReport contains signature, reference and Manifest diagnostics. Check the
// returned error before accepting any result.
type VerificationReport struct {
	// ManifestValidation records the requested Manifest validation outcome.
	ManifestValidation CheckStatus `json:"manifest_validation"`
	// Manifests contains diagnostics for traversed Manifests in recursive mode.
	Manifests []ManifestReport `json:"manifests,omitempty"`
	// Status records the overall signature verification outcome.
	Status CheckStatus `json:"status"`
	// SignatureValue records the cryptographic signature check outcome.
	SignatureValue CheckStatus `json:"signature_value"`
	// SignatureMethod is the declared XMLDSig signature algorithm URI.
	SignatureMethod string `json:"signature_method,omitempty"`
	// References contains direct SignedInfo reference diagnostics in document order.
	References []ReferenceReport `json:"references,omitempty"`
	// FailureStage identifies the stage at which verification failed, when present.
	FailureStage string `json:"failure_stage,omitempty"`
	// Error describes the verification failure, or is empty on success.
	Error string `json:"error,omitempty"`
}

// Signatures lists UNTRUSTED handles in document order, including nested ones.
// Neither this enumeration nor selecting a handle establishes trust.
func Signatures(doc *document.Document) []document.Element {
	if doc == nil || !doc.Root().Valid() {
		return nil
	}

	found := findSignatures(doc)

	out := make([]document.Element, len(found))
	for i, n := range found {
		out[i] = tree.Wrap(doc, n)
	}

	return out
}

type coreReference struct {
	uri        string
	typeURI    string
	method     string
	digest     []byte
	digestNode *tree.Node
	transforms []reference.Transform
}

type corePlan struct {
	sig        *tree.Node
	si         *tree.Node
	sv         *tree.Node
	method     string
	spec       signatureSpec
	cm         reference.Transform
	value      []byte
	refs       []coreReference
	resolver   *reference.SameDocumentResolver
	policy     Policy
	processing reference.Options
	external   *resourceSession
	graph      *manifestGraph
}

func (plan *corePlan) prepareReferences(ctx context.Context, nodes []*tree.Node, opt SignatureOptions, template bool, report *VerificationReport) error {
	report.References = make([]ReferenceReport, len(nodes))
	for i, n := range nodes {
		uri, _ := getAttr(n, document.Name{Local: "URI"})
		report.References[i] = ReferenceReport{Index: i, URI: uri, Status: NotChecked}
	}

	expected := map[string]int{}
	for _, uri := range opt.ExpectedURIs {
		expected[uri]++
	}

	for i, n := range nodes {
		ref, err := parseCoreReference(ctx, n, plan.policy, plan.processing, template)
		if err != nil {
			return &ReferenceError{i, ref.uri, "structure", err}
		}

		if opt.ExpectedURIs != nil {
			if expected[ref.uri] == 0 {
				return fmt.Errorf("%w: unexpected reference URI/multiplicity", ErrPolicy)
			}

			expected[ref.uri]--
		}

		plan.refs = append(plan.refs, ref)
	}

	if opt.ExpectedURIs != nil && len(opt.ExpectedURIs) != len(plan.refs) {
		return fmt.Errorf("%w: expected reference multiset differs", ErrPolicy)
	}

	return nil
}

func parseCoreReference(ctx context.Context, n *tree.Node, p Policy, opt reference.Options, template bool) (coreReference, error) {
	var ref coreReference

	children, err := structure(n, lexicon.DSigElementReference, "URI", "Id", "Type")
	if err != nil {
		return ref, err
	}

	ref.uri, err = requiredAttribute(n, "URI")
	if err != nil {
		return ref, err
	}

	ref.typeURI, _ = getAttr(n, document.Name{Local: "Type"})

	if len(children) > 0 && isDS(children[0], lexicon.DSigElementTransforms) {
		ref.transforms, err = parseCoreTransforms(ctx, children[0], opt)
		if err != nil {
			return ref, err
		}

		children = children[1:]
	}

	if len(children) != 2 || !isDS(children[0], lexicon.DSigElementDigestMethod) || !isDS(children[1], lexicon.DSigElementDigestValue) {
		return ref, fmt.Errorf("%w: Reference children", ErrStructure)
	}

	if err := reference.ValidateTransforms(ref.transforms, opt); err != nil {
		return ref, processingError(err)
	}

	ref.method, err = simpleAlgorithm(children[0], lexicon.DSigElementDigestMethod)
	if err != nil {
		return ref, err
	}

	h, err := hashForDigest(ref.method)
	if err != nil {
		return ref, err
	}

	if !permits(p.AllowedDigestMethods, ref.method) {
		return ref, fmt.Errorf("%w: digest method", ErrPolicy)
	}

	ref.digestNode = children[1]
	if template {
		return ref, emptyValue(ref.digestNode, lexicon.DSigElementDigestValue)
	}

	ref.digest, err = base64Value(ctx, ref.digestNode, lexicon.DSigElementDigestValue, h.Size())
	if err == nil && len(ref.digest) != h.Size() {
		err = fmt.Errorf("%w: digest size", ErrStructure)
	}

	return ref, err
}

func parseCoreTransforms(ctx context.Context, n *tree.Node, opt reference.Options) ([]reference.Transform, error) {
	ts, err := structure(n, lexicon.DSigElementTransforms)
	if err != nil {
		return nil, err
	}

	if len(ts) == 0 || len(ts) > 64 {
		return nil, fmt.Errorf("%w: Transforms count", ErrStructure)
	}

	var transforms []reference.Transform

	for _, tr := range ts {
		method, err := parseCoreTransform(ctx, tr, opt)
		if err != nil {
			return transforms, err
		}

		transforms = append(transforms, method)
	}

	return transforms, nil
}

func parseCoreTransform(ctx context.Context, tr *tree.Node, opt reference.Options) (reference.Transform, error) {
	return parseTransform(ctx, tr, opt.Signature.Node().Document())
}

func parseTransform(ctx context.Context, tr *tree.Node, doc *document.Document) (reference.Transform, error) {
	algorithm, err := requiredAttribute(tr, "Algorithm")
	if err != nil {
		return reference.Transform{}, err
	}

	if reference.IsExtension(algorithm) {
		return parseProgramTransform(ctx, tr, doc)
	}

	if canonicalAlgorithm(algorithm) {
		return parseCanonicalTransform(tr, lexicon.DSigElementTransform)
	}

	var method reference.Transform

	method.Algorithm, err = simpleAlgorithm(tr, lexicon.DSigElementTransform)

	return method, err
}

// emptyValue accepts whitespace only, without comments or element placeholders.
func emptyValue(n *tree.Node, local string, allowed ...string) error {
	if !isDS(n, local) {
		return fmt.Errorf("%w: expected %s", ErrStructure, local)
	}

	if err := attributes(n, allowed...); err != nil {
		return err
	}

	for _, child := range n.Children {
		if child.Kind != tree.TextNode || !tree.IsXMLSpace(child.Data) {
			return fmt.Errorf("%w: %s must be an empty template placeholder", ErrStructure, local)
		}
	}

	return nil
}

type coreBudget struct {
	bytes  int
	visits int
}

func newCoreBudget(p *corePlan) *coreBudget {
	v := p.processing.MaxNodeVisits
	if v == 0 {
		v = reference.DefaultOptions().MaxNodeVisits
	}

	return &coreBudget{p.policy.MaxCanonicalBytes, v}
}

func (b *coreBudget) write(ctx context.Context, dst io.Writer, data reference.Data, ts []reference.Transform, opt reference.Options) (*reference.Report, error) {
	if b.visits <= 0 {
		return nil, fmt.Errorf("%w: aggregate node visit budget", ErrPolicy)
	}

	opt.MaxNodeVisits = b.visits

	out, err := processTo(ctx, dst, data, ts, opt, &b.bytes)
	if err == nil {
		b.visits -= out.NodeVisits()
	}

	return out, err
}

func (b *coreBudget) signedInfo(ctx context.Context, dst io.Writer, doc *document.Document, p *corePlan) error {
	set, err := tree.Wrap(doc, p.si).Subtree(ctx)
	if err != nil {
		return err
	}

	data, _ := reference.Nodes(set)
	opt := p.processing
	opt.AllowedTransforms = []string{p.cm.Algorithm}

	_, err = b.write(ctx, dst, data, []reference.Transform{p.cm}, opt)
	if err != nil {
		return err
	}

	return nil
}

// Preserve original-node provenance only for one final canonicalization with
// optional enveloped exclusions before it. Base64/reparse/sparse transforms do
// not establish coverage of the original application nodes.
func coreCoverage(doc *document.Document, sig *tree.Node, resolved reference.Resolved, out *reference.Report) (*document.Document, *tree.Node, *tree.Node) {
	_, target := tree.Unwrap(resolved.Target())
	if resolved.WholeDocument() {
		target = tree.Root(doc)
	}

	var exclude *tree.Node

	canonical := false
	for _, step := range out.Steps() {
		if canonical {
			return nil, nil, nil
		}

		if step.Algorithm == EnvelopedSignature {
			exclude = sig
			continue
		}

		if canonicalAlgorithm(step.Algorithm) {
			canonical = true
			continue
		}

		return nil, nil, nil
	}

	if !canonical {
		return nil, nil, nil
	}

	return doc, target, exclude
}
