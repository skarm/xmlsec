package xmldsig

import (
	"context"
	"crypto"
	"encoding/base64"
	"fmt"
	"io"
	"strings"

	"github.com/skarm/xmlsec/c14n"
	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/internal/nilcheck"
	"github.com/skarm/xmlsec/internal/tree"
	"github.com/skarm/xmlsec/reference"
)

// SignOptions configures the restricted root-enveloped signing profile and optional
// covered descendants.
type SignOptions struct {
	// IDAttribute defaults to the unqualified attribute ID. It is not guessed.
	IDAttribute document.Name
	// ReferenceIDs defaults to the root ID. When set, it must contain the root
	// ID exactly once. Additional IDs select complete descendant subtrees.
	ReferenceIDs []string
	// SignatureMethod defaults to RSA-SHA256, Ed25519, or ECDSA with SHA-256,
	// SHA-384 or SHA-512 for P-256, P-384 or P-521 respectively, subject to Policy.
	SignatureMethod string
	// DigestMethod defaults to SHA256.
	DigestMethod string
	// InclusivePrefixes applies to SignedInfo and each reference C14N step.
	InclusivePrefixes []string
	Policy            Policy
}

// SignEnveloped returns a new snapshot, leaving d unchanged. It accepts standard
// crypto.Signer implementations, including external signers. Cancellation is
// checked between stages. AdaptContextSigner passes context to capable providers;
// a plain crypto.Signer.Sign cannot be interrupted by the library.
// Existing signatures are rejected rather than modified or silently invalidated.
func SignEnveloped(ctx context.Context, d *document.Document, signer crypto.Signer, opt SignOptions) (*document.Document, error) {
	if ctx == nil {
		return nil, fmt.Errorf("%w: nil context", ErrPolicy)
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	if tree.Root(d) == nil {
		return nil, fmt.Errorf("%w: nil or empty document", ErrStructure)
	}

	if nilcheck.IsNil(signer) {
		return nil, ErrKey
	}

	p, err := normalizePolicy(opt.Policy)
	if err != nil {
		return nil, err
	}

	idAttr, err := normalizeID(opt.IDAttribute)
	if err != nil {
		return nil, err
	}

	pub := signer.Public()
	if err := validateKey(pub, p); err != nil {
		return nil, err
	}

	opt, err = normalizeEnvelopedAlgorithms(pub, opt, p)
	if err != nil {
		return nil, err
	}

	if len(findSignatures(d)) != 0 {
		return nil, fmt.Errorf("%w: existing signatures are not supported", ErrStructure)
	}
	// Resolve and hash the immutable source before constructing the new root.
	out := d

	ids, err := indexIDs(out, idAttr)
	if err != nil {
		return nil, err
	}

	resolver, err := reference.NewSameDocumentResolver(ctx, out, idAttr)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrReference, err)
	}

	root := tree.Root(out)

	rootID, ok := getAttr(root, idAttr)
	if !ok {
		return nil, fmt.Errorf("%w: root needs an explicit ID attribute", ErrReference)
	}

	refs, err := selectEnvelopedReferences(opt.ReferenceIDs, rootID, ids, p.MaxReferences)
	if err != nil {
		return nil, err
	}

	signature := newDS("Signature")
	signature.NS = []tree.Namespace{{Prefix: "ds", URI: Namespace}}
	signature.Parent = root
	si := newDS("SignedInfo")
	add(signature, si)

	cm := newDS("CanonicalizationMethod")
	setAttr(cm, "Algorithm", c14n.Exclusive)
	addInclusive(cm, opt.InclusivePrefixes)
	add(si, cm)

	sm := newDS("SignatureMethod")
	setAttr(sm, "Algorithm", opt.SignatureMethod)
	add(si, sm)

	h, err := hashForDigest(opt.DigestMethod)
	if err != nil {
		return nil, err
	}

	remaining := p.MaxCanonicalBytes

	for i, id := range refs {
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		target := ids[id]

		resolved, err := resolver.Resolve(ctx, "#"+id)
		if err != nil {
			return nil, &ReferenceError{i, "#" + id, nameResolve, err}
		}

		digest := h.New()

		_, err = processTo(ctx, digest, resolved.Data(), strictReferenceTransforms(target == root, opt.InclusivePrefixes),
			reference.Options{AllowedTransforms: []string{EnvelopedSignature, c14n.Exclusive}, Signature: tree.Wrap(out, signature)}, &remaining)
		if err != nil {
			return nil, &ReferenceError{i, "#" + id, nameTransform, err}
		}

		ref := newDS("Reference")
		setAttr(ref, "URI", "#"+id)

		ts := newDS("Transforms")
		if target == root {
			tr := newDS("Transform")
			setAttr(tr, "Algorithm", EnvelopedSignature)
			add(ts, tr)
		}

		tr := newDS("Transform")
		setAttr(tr, "Algorithm", c14n.Exclusive)
		addInclusive(tr, opt.InclusivePrefixes)
		add(ts, tr)
		add(ref, ts)

		dm := newDS("DigestMethod")
		setAttr(dm, "Algorithm", opt.DigestMethod)
		add(ref, dm)

		dv := newDS("DigestValue")
		text(dv, base64.StdEncoding.EncodeToString(digest.Sum(nil)))
		add(ref, dv)
		add(si, ref)
	}
	// Attach before canonicalizing SignedInfo so ancestor context is final.
	newRoot := *root
	newRoot.Children = make([]*tree.Node, len(root.Children), len(root.Children)+1)
	copy(newRoot.Children, root.Children)
	add(&newRoot, signature)

	out, err = tree.ReplaceDraft(ctx, d, root, &newRoot)
	if err != nil {
		return nil, err
	}

	spec := signatureSpec{algorithm: opt.SignatureMethod}
	credential := signatureCredential{public: pub, signer: signer}

	canonical, err := credential.prepareInput(ctx, spec, func(dst io.Writer) error {
		return writeCanonicalElement(ctx, dst, tree.Wrap(out, si), reference.Transform{Algorithm: c14n.Exclusive, InclusivePrefixes: opt.InclusivePrefixes}, &remaining)
	})
	if err != nil {
		return nil, err
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	value, err := credential.signPrepared(ctx, spec, canonical)
	if err != nil {
		return nil, err
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	sv := newDS("SignatureValue")
	text(sv, base64.StdEncoding.EncodeToString(value))
	add(signature, sv)
	// Reparse to enforce the same XML and resource limits as incoming documents.
	return tree.Reparse(ctx, out, tree.Policy(d))
}

func newDS(local string) *tree.Node {
	return &tree.Node{Kind: tree.ElementNode, Name: document.Name{Space: Namespace, Local: local}, Prefix: "ds"}
}

func setAttr(n *tree.Node, name, value string) {
	n.Attrs = append(n.Attrs, tree.Attribute{Name: document.Name{Local: name}, Value: value})
}

func add(parent, child *tree.Node) {
	child.Parent = parent
	parent.Children = append(parent.Children, child)
}
func text(n *tree.Node, s string) { add(n, &tree.Node{Kind: tree.TextNode, Data: s}) }
func addInclusive(parent *tree.Node, prefixes []string) {
	if len(prefixes) == 0 {
		return
	}

	n := &tree.Node{Kind: tree.ElementNode, Name: document.Name{Space: c14n.Exclusive, Local: "InclusiveNamespaces"}, Prefix: "ec", NS: []tree.Namespace{{Prefix: "ec", URI: c14n.Exclusive}}}
	setAttr(n, "PrefixList", strings.Join(prefixes, " "))
	add(parent, n)
}

func selectEnvelopedReferences(requested []string, rootID string, ids map[string]*tree.Node, maximum int) ([]string, error) {
	refs := append([]string(nil), requested...)
	if len(refs) == 0 {
		refs = []string{rootID}
	}

	if len(refs) > maximum {
		return nil, fmt.Errorf("%w: reference count", ErrPolicy)
	}

	seen := map[string]bool{}

	for _, id := range refs {
		if !tree.NCName(id) || ids[id] == nil || seen[id] {
			return nil, fmt.Errorf("%w: missing or repeated ID %q", ErrReference, id)
		}

		seen[id] = true
	}

	if !seen[rootID] {
		return nil, fmt.Errorf("%w: root reference is mandatory", ErrPolicy)
	}

	return refs, nil
}

func normalizeEnvelopedAlgorithms(pub crypto.PublicKey, opt SignOptions, p Policy) (SignOptions, error) {
	if opt.SignatureMethod == "" {
		opt.SignatureMethod = defaultSignature(pub)
	}

	if opt.DigestMethod == "" {
		opt.DigestMethod = SHA256
	}

	if opt.SignatureMethod == DSASHA1 || opt.SignatureMethod == RSASHA1 {
		return opt, fmt.Errorf("%w: legacy signature generation is disabled", ErrPolicy)
	}

	if !permits(p.AllowedSignatureMethods, opt.SignatureMethod) || !permits(p.AllowedDigestMethods, opt.DigestMethod) {
		return opt, fmt.Errorf("%w: signing algorithm", ErrPolicy)
	}

	return opt, nil
}
