package xmldsig

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"fmt"

	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/internal/tree"
	"github.com/skarm/xmlsec/reference"
)

// ReferenceTemplate describes one direct or Manifest reference. URI may be a
// same-document reference or an externally allowlisted URI. An omitted transform
// list does not mean Exclusive C14N: the XMLDSig input-type rules apply.
type ReferenceTemplate struct {
	// ID supplies an optional ds:Reference Id for signed data-object properties.
	ID   string
	URI  string
	Type string
	// DigestMethod defaults to SHA256.
	DigestMethod string
	Transforms   []reference.Transform
}

// ManifestTemplate supplies a local Manifest ID and its reference templates.
type ManifestTemplate struct {
	ID         string
	References []ReferenceTemplate
}

// ObjectTemplate accepts exactly one content variant. XML inserts the complete
// root subtree of a separately parsed document, not arbitrary unparsed markup.
// Binary inserts Base64 text; include a Base64 transform on its Reference to sign
// decoded octets. An empty object is represented by Text pointing to "".
type ObjectTemplate struct {
	ID       string
	MIMEType string
	XML      *document.Document
	Text     *string
	Binary   []byte
	Manifest *ManifestTemplate
}

// SignatureTemplate supplies explicit signature algorithms, references, objects and
// optional untrusted KeyInfo.
type SignatureTemplate struct {
	ID string
	// SignatureMethod is required; templates have no key-dependent default.
	SignatureMethod string
	// SignatureParameters applies only to generic RSA-PSS or HMAC.
	SignatureParameters SignatureParameters
	// Canonicalization defaults to Exclusive C14N without comments.
	Canonicalization reference.Transform
	References       []ReferenceTemplate
	Objects          []ObjectTemplate
	// KeyInfo is an optional immutable ds:KeyInfo document (e.g. keyinfo.Build).
	// Its root is copied. Contents and referenced keys are NOT trusted or resolved.
	// Mutually exclusive with Certificates; signature algorithms/keys are separate.
	KeyInfo *document.Document
	// Certificates supplies optional DER X509Data. Embedded keys are never trusted
	// automatically.
	Certificates [][]byte
	// XMLLimits bounds standalone documents; zero selects document.DefaultLimits.
	// It does not change an existing snapshot.
	XMLLimits document.Limits
}

type signatureTemplateDraft struct {
	doc       *document.Document
	signature document.Element
	limits    document.Limits
}

// BuildTemplate appends a new unsigned ds:Signature to an explicit parent, or
// creates a standalone Signature when doc==nil and parent is invalid. It returns
// a NEW parsed snapshot and the exact new signature handle. No digest, trust or
// validity is established. Existing Signature elements are left untouched; use
// SignTemplate's Preserve requirements when filling the new template.
func BuildTemplate(ctx context.Context, doc *document.Document, parent document.Element, spec SignatureTemplate) (*document.Document, document.Element, error) {
	fail := func(err error) (*document.Document, document.Element, error) { return nil, document.Element{}, err }
	if ctx == nil {
		return fail(fmt.Errorf("%w: nil context", ErrPolicy))
	}

	if err := ctx.Err(); err != nil {
		return fail(err)
	}

	if _, _, err := signatureAlgorithm(spec.SignatureMethod); err != nil {
		return fail(err)
	}

	cm, err := normalizeCanonicalization(spec.Canonicalization)
	if err != nil {
		return fail(err)
	}

	if len(spec.References) < 1 || len(spec.References) > 64 || len(spec.Objects) > 256 {
		return fail(fmt.Errorf("%w: template size", ErrPolicy))
	}

	limits, err := templateLimits(doc, parent, spec.XMLLimits)
	if err != nil {
		return fail(err)
	}

	if err := templateBlobBudget(ctx, spec, limits.MaxBytes); err != nil {
		return fail(err)
	}

	sig, err := signatureTemplateNode(ctx, spec, cm)
	if err != nil {
		return fail(err)
	}

	draft, err := attachTemplateSignature(ctx, doc, parent, sig, limits)
	if err != nil {
		return fail(err)
	}

	return parseTemplateDraft(ctx, draft)
}

// signatureTemplateNode builds in validation order: SignedInfo, KeyInfo, Objects.
func signatureTemplateNode(ctx context.Context, spec SignatureTemplate, cm reference.Transform) (*tree.Node, error) {
	sig := newDS("Signature")

	sig.NS = []tree.Namespace{{Prefix: "ds", URI: Namespace}}
	if err := templateID(sig, spec.ID); err != nil {
		return nil, err
	}

	si := newDS("SignedInfo")
	add(sig, si)

	c := newDS("CanonicalizationMethod")
	setAttr(c, "Algorithm", cm.Algorithm)
	addInclusive(c, cm.InclusivePrefixes)
	add(si, c)

	sm, err := signatureMethodNode(spec.SignatureMethod, spec.SignatureParameters)
	if err != nil {
		return nil, err
	}

	add(si, sm)

	for _, ref := range spec.References {
		n, err := referenceTemplateNode(ctx, ref)
		if err != nil {
			return nil, err
		}

		add(si, n)
	}

	add(sig, newDS("SignatureValue"))

	if err := appendTemplateKeyInfo(ctx, sig, spec); err != nil {
		return nil, err
	}

	for _, object := range spec.Objects {
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		n, err := objectTemplateNode(ctx, object)
		if err != nil {
			return nil, err
		}

		add(sig, n)
	}

	return sig, nil
}

func appendTemplateKeyInfo(ctx context.Context, sig *tree.Node, spec SignatureTemplate) error {
	if spec.KeyInfo != nil {
		if len(spec.Certificates) > 0 {
			return fmt.Errorf("%w: KeyInfo and Certificates are mutually exclusive", ErrPolicy)
		}

		n := tree.Root(spec.KeyInfo)
		if !isDS(n, "KeyInfo") {
			return fmt.Errorf("%w: expected a KeyInfo document", ErrStructure)
		}

		if _, err := structure(n, "KeyInfo", "Id"); err != nil {
			return err
		}

		// Only the root header needs a new parent; retained children are read
		// by serialization before the independent final snapshot is parsed.
		root := *n
		add(sig, &root)
	}

	if len(spec.Certificates) > 16 {
		return fmt.Errorf("%w: too many embedded certificates", ErrPolicy)
	}

	if len(spec.Certificates) == 0 {
		return nil
	}

	ki := newDS("KeyInfo")
	xd := newDS("X509Data")

	total := 0
	for _, der := range spec.Certificates {
		total += len(der)
		if len(der) == 0 || len(der) > 1<<20 || total > 4<<20 {
			return fmt.Errorf("%w: certificate size", ErrPolicy)
		}

		if _, err := x509.ParseCertificate(der); err != nil {
			return fmt.Errorf("%w: invalid embedded certificate: %w", ErrStructure, err)
		}

		xc := newDS("X509Certificate")

		encoded, err := tree.EncodeBase64(ctx, der)
		if err != nil {
			return err
		}

		text(xc, encoded)
		add(xd, xc)
	}

	add(ki, xd)
	add(sig, ki)

	return nil
}

func objectTemplateNode(ctx context.Context, spec ObjectTemplate) (*tree.Node, error) {
	if objectTemplateVariants(spec) != 1 {
		return nil, fmt.Errorf("%w: Object needs exactly one content variant", ErrStructure)
	}

	object := newDS("Object")
	if err := templateID(object, spec.ID); err != nil {
		return nil, err
	}

	if spec.MIMEType != "" {
		setAttr(object, "MimeType", spec.MIMEType)
	}

	switch {
	case spec.XML != nil:
		if !spec.XML.Root().Valid() {
			return nil, ErrStructure
		}

		root := *tree.Root(spec.XML)
		add(object, &root)
	case spec.Text != nil:
		text(object, *spec.Text)
	case spec.Binary != nil:
		encoded, err := tree.EncodeBase64(ctx, spec.Binary)
		if err != nil {
			return nil, err
		}

		text(object, encoded)
	case spec.Manifest != nil:
		manifest, err := manifestTemplateNode(ctx, *spec.Manifest)
		if err != nil {
			return nil, err
		}

		add(object, manifest)
	}

	return object, nil
}

func objectTemplateVariants(spec ObjectTemplate) int {
	variants := 0
	if spec.XML != nil {
		variants++
	}

	if spec.Text != nil {
		variants++
	}

	if spec.Binary != nil {
		variants++
	}

	if spec.Manifest != nil {
		variants++
	}

	return variants
}

func manifestTemplateNode(ctx context.Context, spec ManifestTemplate) (*tree.Node, error) {
	manifest := newDS("Manifest")
	if err := templateID(manifest, spec.ID); err != nil {
		return nil, err
	}

	if len(spec.References) < 1 || len(spec.References) > 64 {
		return nil, fmt.Errorf("%w: Manifest template reference count", ErrPolicy)
	}

	for _, ref := range spec.References {
		n, err := referenceTemplateNode(ctx, ref)
		if err != nil {
			return nil, err
		}

		add(manifest, n)
	}

	return manifest, nil
}

func templateLimits(doc *document.Document, parent document.Element, limits document.Limits) (document.Limits, error) {
	if doc == nil {
		if parent.Valid() {
			return limits, fmt.Errorf("%w: parent supplied without document", ErrPolicy)
		}

		if limits == (document.Limits{}) {
			limits = document.DefaultLimits()
		}
	} else {
		owner, node := tree.Unwrap(parent)
		if owner != doc || node == nil {
			return limits, fmt.Errorf("%w: parent from input document required", ErrPolicy)
		}

		if limits != (document.Limits{}) {
			return limits, fmt.Errorf("%w: existing document retains its XML limits", ErrPolicy)
		}

		limits = tree.Policy(doc)
	}

	return limits, limits.Validate()
}

// Base64 text cannot shrink during XML serialization. Reject an aggregate that
// cannot fit before allocating encoded certificates or binary Object content.
func templateBlobBudget(ctx context.Context, spec SignatureTemplate, maximum int) error {
	remaining := maximum

	charge := func(blob []byte) error {
		if err := ctx.Err(); err != nil {
			return err
		}

		if len(blob) > remaining || base64.StdEncoding.EncodedLen(len(blob)) > remaining {
			return fmt.Errorf("%w: encoded template blobs exceed XML byte budget: %w", ErrPolicy, document.ErrLimit)
		}

		remaining -= base64.StdEncoding.EncodedLen(len(blob))

		return nil
	}
	for _, certificate := range spec.Certificates {
		if err := charge(certificate); err != nil {
			return err
		}
	}

	for _, object := range spec.Objects {
		if err := charge(object.Binary); err != nil {
			return err
		}
	}

	return ctx.Err()
}

func attachTemplateSignature(ctx context.Context, doc *document.Document, parent document.Element, sig *tree.Node, limits document.Limits) (signatureTemplateDraft, error) {
	if doc == nil {
		draft := tree.FromNodes([]*tree.Node{sig}, limits)
		return signatureTemplateDraft{doc: draft, signature: draft.Root(), limits: limits}, nil
	}

	_, n := tree.Unwrap(parent)

	selected := *n
	selected.Children = make([]*tree.Node, len(n.Children), len(n.Children)+1)
	copy(selected.Children, n.Children)
	add(&selected, sig)

	draft, err := tree.ReplaceDraft(ctx, doc, n, &selected)
	if err != nil {
		return signatureTemplateDraft{}, err
	}

	return signatureTemplateDraft{doc: draft, signature: tree.Wrap(draft, sig), limits: limits}, nil
}

func parseTemplateDraft(ctx context.Context, draft signatureTemplateDraft) (*document.Document, document.Element, error) {
	fail := func(err error) (*document.Document, document.Element, error) { return nil, document.Element{}, err }

	final, err := tree.Reparse(ctx, draft.doc, draft.limits)
	if err != nil {
		return fail(err)
	}

	selected, err := remapElement(draft.doc, final, draft.signature)
	if err != nil {
		return fail(err)
	}
	// Detect ds:Id/default ID collisions early. Additional application ID rules
	// are still checked by SignTemplate's validation configuration.
	if _, err := reference.NewSameDocumentResolverWithRules(ctx, final, coreIDRules(SignatureOptions{IDAttribute: document.Name{Local: "ID"}})); err != nil {
		return fail(err)
	}

	return final, selected, nil
}

func templateID(n *tree.Node, id string) error {
	if id == "" {
		return nil
	}

	if !tree.NCName(id) {
		return fmt.Errorf("%w: invalid template ID", ErrReference)
	}

	setAttr(n, "Id", id)

	return nil
}

func referenceTemplateNode(ctx context.Context, r ReferenceTemplate) (*tree.Node, error) {
	if externalURI(r.URI) {
		if err := validExternalURI(r.URI); err != nil {
			return nil, err
		}
	}

	if r.DigestMethod == "" {
		r.DigestMethod = SHA256
	}

	if _, err := hashForDigest(r.DigestMethod); err != nil {
		return nil, err
	}

	for _, tr := range r.Transforms {
		if reference.IsExtension(tr.Algorithm) {
			if err := reference.ValidateTransformParameters(tr); err != nil {
				return nil, err
			}
		} else {
			if err := reference.ValidateTransforms([]reference.Transform{tr}, reference.Options{}); err != nil {
				return nil, err
			}
		}
	}

	n := newDS("Reference")
	if err := templateID(n, r.ID); err != nil {
		return nil, err
	}

	setAttr(n, "URI", r.URI)

	if r.Type != "" {
		setAttr(n, "Type", r.Type)
	}

	if len(r.Transforms) > 0 {
		ts := newDS("Transforms")
		for _, tr := range r.Transforms {
			t := newDS("Transform")
			setAttr(t, "Algorithm", tr.Algorithm)
			addInclusive(t, tr.InclusivePrefixes)

			if reference.IsExtension(tr.Algorithm) {
				if err := appendProgramParameters(ctx, t, tr); err != nil {
					return nil, err
				}
			}

			add(ts, t)
		}

		add(n, ts)
	}

	dm := newDS("DigestMethod")
	setAttr(dm, "Algorithm", r.DigestMethod)
	add(n, dm)
	add(n, newDS("DigestValue"))

	return n, nil
}
