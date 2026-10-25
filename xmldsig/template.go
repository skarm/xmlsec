package xmldsig

import (
	"context"
	"crypto"
	"encoding/base64"
	"fmt"
	"io"
	"slices"

	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/internal/lexicon"
	"github.com/skarm/xmlsec/internal/nilcheck"
	"github.com/skarm/xmlsec/internal/tree"
)

// SignatureRequirement supplies explicit trust for an existing signature that must
// remain valid during template signing. Signature and Options.RequiredElements
// handles must belong to the original input snapshot.
type SignatureRequirement struct {
	// Signature selects the existing signature in the original input snapshot.
	Signature document.Element
	// PublicKey is the explicitly trusted verification key. It is mutually exclusive with
	// SharedSecret.
	PublicKey crypto.PublicKey
	// Options sets verification policy and required coverage for this existing signature.
	Options SignatureOptions
	// SharedSecret is mutually exclusive with PublicKey. Non-nil selects HMAC.
	// It is copied and wiped for each operation, and is never emitted in XML.
	SharedSecret []byte
}

// TemplateSignOptions sets self-verification policy and explicit trust requirements
// for preserving existing signatures.
type TemplateSignOptions struct {
	// Validation applies during preflight and complete post-serialization
	// self-verification. The template supplies algorithms, References and XML.
	Validation SignatureOptions
	// Preserve supplies trusted verification requirements for every nonempty signature
	// except the selected one. Each is checked before and after signing with its supplied
	// key. Empty templates need no entry. The new signing key grants no trust to existing
	// signatures.
	Preserve []SignatureRequirement
}

// SignTemplate fills empty DigestValue/SignatureValue placeholders in the
// explicitly selected Signature and returns a NEW document snapshot. Algorithms
// and transforms must already be present in the template. It supports enveloped,
// enveloping (Object), same-document detached and independent multiple signatures.
//
// No existing signature is overwritten. References depending on this signature's
// own mutable placeholders are rejected before calling the signer. Existing
// nonempty signatures require Preserve entries; invalidating one aborts the
// operation. Self-verification is performed after serialization and reparsing.
// All byte/node budgets apply per verification/generation pass, not as a single
// budget shared with the extra preservation and self-verification passes.
// Explicit external Manifest graphs are checked before the private signer call,
// using a separate processing budget and the same bounded resource-read cache.
//
// AdaptContextSigner passes context to capable providers; plain crypto.Signer
// has no cancellation parameter and its blocking call cannot be interrupted. Like other
// APIs here, the caller must not mutate the signer/key/options during the call.
func SignTemplate(ctx context.Context, doc *document.Document, selected document.Element, signer crypto.Signer, opt TemplateSignOptions) (*document.Document, error) {
	if ctx == nil {
		return nil, ErrPolicy
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	if nilcheck.IsNil(signer) {
		return nil, ErrKey
	}

	return signTemplate(ctx, doc, selected, signatureCredential{signer: signer, public: signer.Public()}, opt)
}

func signTemplate(ctx context.Context, doc *document.Document, selected document.Element, credential signatureCredential, opt TemplateSignOptions) (*document.Document, error) {
	if ctx == nil {
		return nil, fmt.Errorf("%w: nil context", ErrPolicy)
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	if len(opt.Preserve) > 64 {
		return nil, fmt.Errorf("%w: preservation count", ErrPolicy)
	}

	opt.Validation = cloneSignatureOptions(opt.Validation)

	preserved := make([]SignatureRequirement, len(opt.Preserve))
	defer func() {
		for i := range preserved {
			clear(preserved[i].SharedSecret)
		}
	}()

	for i, req := range opt.Preserve {
		cloned, err := cloneSignatureRequirement(req)
		if err != nil {
			return nil, err
		}

		preserved[i] = cloned
	}

	opt.Preserve = preserved
	report := &VerificationReport{}

	original, err := prepareCore(ctx, doc, selected, opt.Validation, true, report)
	if err != nil {
		return nil, err
	}

	if err := credential.validate(original.spec, original.policy); err != nil {
		return nil, err
	}
	// Validate the method/key match before any expensive provider operation.
	if err := credential.validateSigner(original.spec); err != nil {
		return nil, err
	}

	if _, err := original.graph.signingOrder(ctx, original); err != nil {
		return nil, err
	}

	if err := checkPreservation(ctx, doc, selected, opt.Preserve); err != nil {
		return nil, err
	}

	out, err := tree.Clone(ctx, doc)
	if err != nil {
		return nil, err
	}

	own, err := remapElement(doc, out, selected)
	if err != nil {
		return nil, err
	}

	validation, err := remapOptions(doc, out, opt.Validation)
	if err != nil {
		return nil, err
	}

	plan, err := prepareCore(ctx, out, own, validation, true, &VerificationReport{})
	if err != nil {
		return nil, err
	}

	budget, err := fillTemplateDigests(ctx, out, plan)
	if err != nil {
		return nil, err
	}

	if err := validateGeneratedManifests(ctx, out, plan); err != nil {
		return nil, err
	}

	canonical, err := credential.prepareInput(ctx, plan.spec, func(dst io.Writer) error { return budget.signedInfo(ctx, dst, out, plan) })
	if err != nil {
		return nil, err
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	value, err := credential.signPrepared(ctx, plan.spec, canonical)
	if err != nil {
		return nil, err
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	replaceValue(plan.sv, base64.StdEncoding.EncodeToString(value))

	final, err := tree.Reparse(ctx, out, tree.Policy(doc))
	if err != nil {
		return nil, err
	}

	selectedFinal, err := remapElement(doc, final, selected)
	if err != nil {
		return nil, err
	}

	finalOptions, err := remapOptions(doc, final, opt.Validation)
	if err != nil {
		return nil, err
	}
	// Reuse external processing evidence from this signing operation. The
	// self-check retains independent budgets without fetching resources twice.
	if plan.external != nil {
		finalOptions.External = plan.external.replayOptions()
	}

	if _, _, err := verifySignatureDetailed(ctx, final, selectedFinal, credential, finalOptions); err != nil {
		return nil, fmt.Errorf("template self-verification: %w", err)
	}

	if err := verifyPreservedSignatures(ctx, doc, final, opt.Preserve); err != nil {
		return nil, err
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	return final, nil
}

func checkPreservation(ctx context.Context, doc *document.Document, selected document.Element, requirements []SignatureRequirement) error {
	if len(requirements) > 64 {
		return fmt.Errorf("%w: preservation count", ErrPolicy)
	}

	required := map[*tree.Node]SignatureRequirement{}

	_, own := tree.Unwrap(selected)
	for _, req := range requirements {
		d, n := tree.Unwrap(req.Signature)
		if d != doc || n == nil || n == own || !isDS(n, lexicon.DSigElementSignature) {
			return fmt.Errorf("%w: invalid preservation selection", ErrPolicy)
		}

		if _, ok := required[n]; ok {
			return fmt.Errorf("%w: duplicate preservation selection", ErrPolicy)
		}

		required[n] = req
	}

	for _, n := range findSignatures(doc) {
		if n == own {
			continue
		}

		_, sv, err := signatureParts(n)
		if err != nil {
			return err
		}

		req, hasRequirement := required[n]
		if emptyValue(sv, lexicon.DSigElementSignatureValue, "Id") == nil {
			if hasRequirement {
				return fmt.Errorf("%w: cannot preserve an unsigned template", ErrPolicy)
			}

			continue
		}

		if !hasRequirement {
			return fmt.Errorf("%w: every other nonempty signature needs an explicit Preserve requirement", ErrPolicy)
		}

		if err := verifyRequirement(ctx, doc, req.Signature, req, req.Options); err != nil {
			return fmt.Errorf("preservation precheck: %w", err)
		}
	}

	return nil
}

func replaceValue(n *tree.Node, value string) { n.Children = nil; text(n, value) }

// Template edits change only leaf text. Element positions in the immutable
// input, private clone and serialized output therefore remain stable. Remapping
// is structural, never by a potentially ambiguous ID or global ordinal lookup.
func remapElement(from, to *document.Document, e document.Element) (document.Element, error) {
	d, n := tree.Unwrap(e)
	if d != from || n == nil || tree.Root(to) == nil {
		return document.Element{}, fmt.Errorf("%w: cannot map a foreign element", ErrPolicy)
	}

	var path []int

	for n.Parent != nil {
		parent := n.Parent
		index := -1

		for i, child := range parent.Children {
			if child == n {
				index = i
				break
			}
		}

		if index < 0 {
			return document.Element{}, ErrStructure
		}

		path = append(path, index)
		n = parent
	}

	if n != tree.Root(from) {
		return document.Element{}, ErrStructure
	}

	n = tree.Root(to)
	for _, index := range slices.Backward(path) {
		if index >= len(n.Children) {
			return document.Element{}, ErrStructure
		}

		n = n.Children[index]
	}

	if n.Kind != tree.ElementNode || n.Name != e.Name() {
		return document.Element{}, ErrStructure
	}

	return tree.Wrap(to, n), nil
}

func remapOptions(from, to *document.Document, opt SignatureOptions) (SignatureOptions, error) {
	required := make([]document.Element, len(opt.RequiredElements))
	for i, e := range opt.RequiredElements {
		mapped, err := remapElement(from, to, e)
		if err != nil {
			return opt, err
		}

		required[i] = mapped
	}

	opt.RequiredElements = required

	return opt, nil
}

func fillTemplateDigests(ctx context.Context, out *document.Document, plan *corePlan) (*coreBudget, error) {
	order, err := plan.graph.signingOrder(ctx, plan)
	if err != nil {
		return nil, err
	}

	budget := newCoreBudget(plan)

	for _, task := range order {
		_, checked, err := processCoreTask(ctx, out, plan, budget, task)
		if err != nil {
			return nil, task.wrap("process", err)
		}

		replaceValue(task.ref.digestNode, base64.StdEncoding.EncodeToString(checked.digest))
		task.ref.digest = checked.digest
	}

	return budget, nil
}

func cloneSignatureRequirement(req SignatureRequirement) (SignatureRequirement, error) {
	cloned := req
	cloned.SharedSecret = nil
	cloned.Options = cloneSignatureOptions(req.Options)

	if req.SharedSecret == nil {
		return cloned, nil
	}

	if !nilcheck.IsNil(req.PublicKey) {
		return cloned, fmt.Errorf("%w: preservation has two credential types", ErrPolicy)
	}

	secret, err := copySecret(req.SharedSecret)
	if err != nil {
		return cloned, err
	}

	cloned.SharedSecret = secret

	return cloned, nil
}

func verifyPreservedSignatures(ctx context.Context, doc, final *document.Document, requirements []SignatureRequirement) error {
	for i, req := range requirements {
		handle, err := remapElement(doc, final, req.Signature)
		if err != nil {
			return err
		}

		options, err := remapOptions(doc, final, req.Options)
		if err != nil {
			return err
		}

		if err := verifyRequirement(ctx, final, handle, req, options); err != nil {
			return fmt.Errorf("%w: preserved signature %d would be invalidated: %w", ErrPolicy, i, err)
		}
	}

	return nil
}
