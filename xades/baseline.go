package xades

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/x509"
	"errors"
	"slices"
	"strconv"

	"github.com/skarm/xmlsec/c14n"
	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/internal/lexicon"
	"github.com/skarm/xmlsec/internal/nilcheck"
	"github.com/skarm/xmlsec/internal/tree"
	"github.com/skarm/xmlsec/pki"
	"github.com/skarm/xmlsec/reference"
	"github.com/skarm/xmlsec/xmldsig"
)

type baselineLayout struct {
	qualifying document.Element
	signed     document.Element
	signature  document.Element
	data       document.Element
	unsigned   document.Element
}

// VerifyBaseline authenticates one explicitly selected baseline signature and
// its signed properties. XMLDSig resource/transform/coverage policy is supplied
// explicitly. Unsigned properties are exposed for a separate evidence workflow;
// this operation does not assign a B-T/LT/LTA level or historical trust.
func VerifyBaseline(ctx context.Context, doc *document.Document, selected document.Element, certificateDER []byte, options BaselineVerifyOptions) (*BaselineResult, error) {
	if ctx == nil || doc == nil || !selected.Valid() {
		return nil, ErrProfile
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	owner, _ := tree.Unwrap(selected)
	if owner != doc || selected.Name() != ds(lexicon.DSigElementSignature) {
		return nil, ErrProfile
	}

	options, err := normalizeBaselineVerifyOptions(options)
	if err != nil {
		return nil, err
	}

	certificate, err := cert(certificateDER)
	if err != nil {
		return nil, err
	}

	layout, err := baselineLayoutFor(selected)
	if err != nil {
		return nil, err
	}

	opt := baselineCanonicalizationOptions(options.Signature)
	opt.AdditionalIDRules = append(opt.AdditionalIDRules, reference.IDAttributeRule{Attribute: document.Name{Local: "Id"}, Elements: []document.Name{name("SignedProperties")}})
	opt.RequiredElements = append(opt.RequiredElements, layout.signed)

	verified, err := xmldsig.VerifySignature(ctx, doc, selected, certificate.PublicKey, opt)
	if err != nil {
		return nil, err
	}

	if err := checkBaselineCounterReferences(verified); err != nil {
		return nil, err
	}

	found := false

	for _, result := range verified.References() {
		if result.Type() != SignedPropertiesType {
			continue
		}

		if !result.Target().Same(layout.signed) || !result.CoversElement(layout.signed) {
			return nil, ErrProfile
		}

		found = true
	}

	if !found {
		return nil, ErrProfile
	}

	result, err := parseBaselineSigned(ctx, layout, certificate, options, verified)
	if err != nil {
		return nil, err
	}

	result.basic.signature = verified
	result.basic.properties = layout.signed
	result.basic.certificate = certificate.Raw
	result.unsigned = layout.unsigned

	return result, nil
}

// SignBaseline adds a property-bearing Object to the caller XMLDSig template.
// doc/parent select an arbitrary enveloped or sibling position; nil doc creates
// a standalone enveloping/detached signature. Existing signatures remain present
// and confer no implicit trust. The signer must match the explicit certificate.
func SignBaseline(ctx context.Context, doc *document.Document, parent document.Element, signer crypto.Signer, certificateDER []byte, options BaselineSignOptions) (*document.Document, *BaselineResult, error) {
	certificate, err := baselineSignerCertificate(ctx, signer, certificateDER)
	if err != nil {
		return nil, nil, err
	}

	options.Validation, err = normalizeBaselineVerifyOptions(options.Validation)
	if err != nil {
		return nil, nil, err
	}

	template, verification, err := prepareBaselineTemplate(ctx, certificate, options)
	if err != nil {
		return nil, nil, err
	}

	draft, selected, err := xmldsig.BuildTemplate(ctx, doc, parent, template)
	if err != nil {
		return nil, nil, err
	}

	layout, err := baselineLayoutFor(selected)
	if err != nil {
		return nil, nil, err
	}

	validation, err := remapBaselineSignatureOptions(doc, draft, baselineCanonicalizationOptions(verification.Signature))
	if err != nil {
		return nil, nil, err
	}

	validation.AdditionalIDRules = append(validation.AdditionalIDRules, reference.IDAttributeRule{Attribute: document.Name{Local: "Id"}, Elements: []document.Name{name("SignedProperties")}})
	validation.RequiredElements = append(validation.RequiredElements, layout.signed)

	preserve, err := remapBaselinePreservation(doc, draft, options.Preserve)
	if err != nil {
		return nil, nil, err
	}

	signed, err := xmldsig.SignTemplate(ctx, draft, selected, signer, xmldsig.TemplateSignOptions{Validation: validation, Preserve: preserve})
	if err != nil {
		return nil, nil, err
	}

	chosen, err := signatureByID(signed, template.ID)
	if err != nil {
		return nil, nil, err
	}

	verification.Signature, err = remapBaselineSignatureOptions(doc, signed, verification.Signature)
	if err != nil {
		return nil, nil, err
	}

	result, err := VerifyBaseline(ctx, signed, chosen, certificate.Raw, verification)
	if err != nil {
		return nil, nil, err
	}

	return signed, result, nil
}

func baselineSignerCertificate(ctx context.Context, signer crypto.Signer, certificateDER []byte) (*x509.Certificate, error) {
	if ctx == nil || nilcheck.IsNil(signer) {
		return nil, ErrProfile
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	certificate, err := cert(certificateDER)
	if err != nil {
		return nil, err
	}

	if key, ok := signer.(ed25519.PrivateKey); ok && len(key) != ed25519.PrivateKeySize {
		return nil, ErrCertificate
	}

	pin, err := pki.NewKeyPin(signer.Public())
	if err != nil {
		return nil, errors.Join(ErrCertificate, err)
	}

	if err := pin.MatchCertificate(certificate.Raw); err != nil {
		return nil, ErrCertificate
	}

	return certificate, nil
}

func prepareBaselineTemplate(ctx context.Context, certificate *x509.Certificate, options BaselineSignOptions) (xmldsig.SignatureTemplate, BaselineVerifyOptions, error) {
	template := options.Template
	if len(options.Properties.AdditionalCertificates) > 63 || len(options.Properties.DataObjects) > 256 || len(options.Properties.Commitments) > 64 {
		return template, options.Validation, ErrProfile
	}

	for _, value := range options.Properties.AdditionalCertificates {
		if len(value.DER) == 0 || len(value.DER) > 1<<20 {
			return template, options.Validation, ErrCertificate
		}

		options.Validation.CertificateValues = append(options.Validation.CertificateValues, slices.Clone(value.DER))
	}

	if template.ID == "" {
		template.ID = defaultBaselineSignatureID
	}

	if options.SignedPropertiesID == "" {
		options.SignedPropertiesID = "signed-properties"
	}

	if !tree.NCName(template.ID) || !tree.NCName(options.SignedPropertiesID) {
		return template, options.Validation, ErrProfile
	}

	template.References = slices.Clone(template.References)
	for i := range template.References {
		if template.References[i].Type == SignedPropertiesType {
			return template, options.Validation, ErrProfile
		}

		if template.References[i].ID == "" {
			template.References[i].ID = baselineReferenceID(template.ID, i)
		}
	}

	if len(options.Properties.DataObjects) == 0 {
		for _, ref := range template.References {
			if ref.Type == countersignedSignatureType {
				continue
			}

			options.Properties.DataObjects = append(options.Properties.DataObjects, DataObjectFormat{ObjectReference: "#" + ref.ID, MIMEType: "application/octet-stream"})
		}
	}

	if err := checkBaselineTemplateBindings(template, options.Properties, options.Validation); err != nil {
		return template, options.Validation, err
	}

	properties, err := buildBaselineProperties(ctx, certificate, template.ID, options.SignedPropertiesID, options.Properties, options.Validation)
	if err != nil {
		return template, options.Validation, err
	}

	appendBaselineSignerCertificate(&template, certificate.Raw)

	template.Objects = append(slices.Clone(template.Objects), xmldsig.ObjectTemplate{XML: properties})
	transform := reference.Transform{Algorithm: c14n.Exclusive}
	template.References = append(template.References, xmldsig.ReferenceTemplate{URI: "#" + options.SignedPropertiesID, Type: SignedPropertiesType, Transforms: []reference.Transform{transform}})

	return template, options.Validation, nil
}

func remapBaselinePreservation(from, to *document.Document, requirements []xmldsig.SignatureRequirement) ([]xmldsig.SignatureRequirement, error) {
	if len(requirements) > 64 {
		return nil, ErrProfile
	}

	out := make([]xmldsig.SignatureRequirement, len(requirements))
	for i, req := range requirements {
		var err error

		req.Signature, err = remapBaselineElement(from, to, req.Signature)
		if err != nil {
			return nil, err
		}

		req.Options, err = remapBaselineSignatureOptions(from, to, req.Options)
		if err != nil {
			return nil, err
		}

		out[i] = req
	}

	return out, nil
}

func baselineLayoutFor(selected document.Element) (baselineLayout, error) {
	var out baselineLayout

	id := localAttribute(selected, "Id")
	if !tree.NCName(id) {
		return out, ErrProfile
	}

	var err error

	out.qualifying, err = findBaselineQualifying(selected)
	if err != nil {
		return out, err
	}

	if !out.qualifying.Valid() || baselineAttrs(out.qualifying, []string{"Target"}, "Id") != nil || localAttribute(out.qualifying, "Target") != "#"+id {
		return out, ErrProfile
	}

	children, err := baselineContent(out.qualifying)
	if err != nil {
		return out, err
	}

	if len(children) < 1 || len(children) > 2 || children[0].Name() != name("SignedProperties") {
		return out, ErrProfile
	}

	out.signed = children[0]
	if baselineAttrs(out.signed, []string{"Id"}) != nil || !tree.NCName(localAttribute(out.signed, "Id")) {
		return out, ErrProfile
	}

	if len(children) == 2 {
		if children[1].Name() != name("UnsignedProperties") || baselineAttrs(children[1], nil, "Id") != nil || len(children[1].Children()) == 0 {
			return out, ErrProfile
		}

		if err := checkBaselineUnsigned(children[1]); err != nil {
			return out, err
		}

		out.unsigned = children[1]
	}

	properties, err := baselineContent(out.signed)
	if err != nil {
		return out, err
	}

	if len(properties) < 1 || len(properties) > 2 || properties[0].Name() != name("SignedSignatureProperties") {
		return out, ErrProfile
	}

	out.signature = properties[0]
	if baselineAttrs(out.signature, nil, "Id") != nil || len(out.signature.Children()) == 0 {
		return out, ErrProfile
	}

	if len(properties) == 2 {
		if properties[1].Name() != name("SignedDataObjectProperties") || baselineAttrs(properties[1], nil, "Id") != nil || len(properties[1].Children()) == 0 {
			return out, ErrProfile
		}

		out.data = properties[1]
	}

	return out, nil
}

func baselineAttrs(element document.Element, required []string, optional ...string) error {
	seen := map[string]struct{}{}

	for _, attr := range element.Attributes() {
		if attr.Name.Space != "" || (!slices.Contains(required, attr.Name.Local) && !slices.Contains(optional, attr.Name.Local)) {
			return ErrProfile
		}

		if attr.Name.Local == "Id" && !tree.NCName(attr.Value) {
			return ErrProfile
		}

		seen[attr.Name.Local] = struct{}{}
	}

	for _, name := range required {
		if _, exists := seen[name]; !exists {
			return ErrProfile
		}
	}

	return nil
}

func cloneBaselineOptions(options BaselineVerifyOptions) BaselineVerifyOptions {
	signature := &options.Signature
	signature.Policy.AllowedSignatureMethods = slices.Clone(signature.Policy.AllowedSignatureMethods)
	signature.Policy.AllowedDigestMethods = slices.Clone(signature.Policy.AllowedDigestMethods)
	signature.AllowedCanonicalizationMethods = slices.Clone(signature.AllowedCanonicalizationMethods)
	signature.Processing.AllowedTransforms = slices.Clone(signature.Processing.AllowedTransforms)
	signature.Processing.IDRules = baselineCloneIDRules(signature.Processing.IDRules)
	signature.AdditionalIDRules = baselineCloneIDRules(signature.AdditionalIDRules)
	signature.RequiredElements = slices.Clone(signature.RequiredElements)

	signature.ExpectedURIs = slices.Clone(signature.ExpectedURIs)
	if signature.External != nil {
		snapshot := *signature.External
		snapshot.AllowedURIs = slices.Clone(snapshot.AllowedURIs)
		signature.External = &snapshot
	}

	options.CertificateValues = cloneDERValues(options.CertificateValues)
	options.PolicyDocument = slices.Clone(options.PolicyDocument)

	return options
}

func baselineCloneIDRules(rules []reference.IDAttributeRule) []reference.IDAttributeRule {
	out := slices.Clone(rules)
	for i := range out {
		out[i].Elements = slices.Clone(out[i].Elements)
	}

	return out
}

func cloneDERValues(values [][]byte) [][]byte {
	if values == nil {
		return nil
	}

	out := make([][]byte, len(values))
	for i, value := range values {
		out[i] = slices.Clone(value)
	}

	return out
}

const countersignedSignatureType = "http://uri.etsi.org/01903#CountersignedSignature"

func baselineReferenceID(signatureID string, index int) string {
	return signatureID + "-data-reference-" + strconv.Itoa(index+1)
}

func signatureByID(doc *document.Document, id string) (document.Element, error) {
	var found document.Element

	for _, selected := range xmldsig.Signatures(doc) {
		if localAttribute(selected, "Id") == id {
			if found.Valid() {
				return found, ErrProfile
			}

			found = selected
		}
	}

	if !found.Valid() {
		return found, ErrProfile
	}

	return found, nil
}

func remapBaselineSignatureOptions(from, to *document.Document, options xmldsig.SignatureOptions) (xmldsig.SignatureOptions, error) {
	options = cloneBaselineOptions(BaselineVerifyOptions{Signature: options}).Signature
	for i, element := range options.RequiredElements {
		mapped, err := remapBaselineElement(from, to, element)
		if err != nil {
			return options, err
		}

		options.RequiredElements[i] = mapped
	}

	return options, nil
}

func remapBaselineElement(from, to *document.Document, element document.Element) (document.Element, error) {
	if from == nil || to == nil || !element.Valid() {
		return document.Element{}, ErrProfile
	}

	owner, node := tree.Unwrap(element)
	if owner != from {
		return document.Element{}, ErrProfile
	}

	var path []int

	for node != tree.Root(from) {
		parent := node.Parent
		if parent == nil {
			return document.Element{}, ErrProfile
		}

		index := slices.Index(parent.Children, node)
		if index < 0 {
			return document.Element{}, ErrProfile
		}

		path = append(path, index)
		node = parent
	}

	node = tree.Root(to)
	for _, index := range slices.Backward(path) {
		if index >= len(node.Children) {
			return document.Element{}, ErrProfile
		}

		node = node.Children[index]
	}

	if node.Name != element.Name() {
		return document.Element{}, ErrProfile
	}

	return tree.Wrap(to, node), nil
}

func checkBaselineUnsigned(element document.Element) error {
	values, err := baselineContent(element)
	if err != nil || len(values) == 0 || len(values) > 2 {
		return ErrProfile
	}

	previous := -1

	for _, child := range values {
		index := slices.Index([]document.Name{name("UnsignedSignatureProperties"), name("UnsignedDataObjectProperties")}, child.Name())
		if index < 0 || index <= previous || baselineAttrs(child, nil, "Id") != nil {
			return ErrProfile
		}

		previous = index

		entries, err := baselineContent(child)
		if err != nil || len(entries) == 0 {
			return ErrProfile
		}

		for _, entry := range entries {
			if entry.Name() == name("CounterSignature") {
				if err := checkCounterContainer(entry); err != nil {
					return err
				}
			}
		}
	}

	return nil
}

func baselineCanonicalizationOptions(options xmldsig.SignatureOptions) xmldsig.SignatureOptions {
	if len(options.AllowedCanonicalizationMethods) == 0 {
		options.AllowedCanonicalizationMethods = []string{c14n.Exclusive, c14n.ExclusiveWithComments, c14n.Canonical10, c14n.Canonical10WithComments, c14n.Canonical11, c14n.Canonical11WithComments}
	}

	return options
}

func appendBaselineSignerCertificate(template *xmldsig.SignatureTemplate, signerDER []byte) {
	if template.KeyInfo == nil { // The template has no alternate KeyInfo source.
		if len(template.Certificates) == 0 {
			template.Certificates = [][]byte{signerDER}
		} else {
			present := false
			for _, raw := range template.Certificates {
				present = present || bytes.Equal(raw, signerDER)
			}

			if !present {
				template.Certificates = append([][]byte{signerDER}, template.Certificates...)
			}
		}
	}
}

func findBaselineQualifying(selected document.Element) (document.Element, error) {
	var qualifying document.Element

	for _, object := range selected.Children() {
		if object.Name() != ds("Object") {
			continue
		}

		for _, child := range object.Children() {
			if child.Name() == name("QualifyingPropertiesReference") {
				return document.Element{}, ErrProfile
			}

			if child.Name() != name("QualifyingProperties") {
				continue
			}

			if qualifying.Valid() {
				return document.Element{}, ErrProfile
			}

			qualifying = child
		}
	}

	return qualifying, nil
}

func normalizeBaselineVerifyOptions(options BaselineVerifyOptions) (BaselineVerifyOptions, error) {
	if len(options.CertificateValues) > 64 || len(options.PolicyDocument) > 8<<20 {
		return options, ErrProfile
	}

	for _, value := range options.CertificateValues {
		if len(value) == 0 || len(value) > 1<<20 {
			return options, ErrCertificate
		}
	}

	limits, err := normalizeDataTimestampLimits(options.DataTimestamps)
	if err != nil {
		return options, err
	}

	options.DataTimestamps = limits

	return cloneBaselineOptions(options), nil
}
