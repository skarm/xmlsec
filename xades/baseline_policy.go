package xades

import (
	"bytes"
	"context"
	"crypto"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"math/big"
	"slices"
	"strings"

	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/internal/lexicon"
	"github.com/skarm/xmlsec/internal/transformxml"
	"github.com/skarm/xmlsec/internal/tree"
	"github.com/skarm/xmlsec/reference"
	"github.com/skarm/xmlsec/xmldsig"
)

const (
	nameExplicitText           = "ExplicitText"
	nameNoticeNumber           = "int"
	nameNoticeNumbers          = "NoticeNumbers"
	nameNoticeRef              = "NoticeRef"
	nameOrganization           = "Organization"
	nameSPDocSpecification     = "SPDocSpecification"
	nameSPURI                  = "SPURI"
	nameSPUserNotice           = "SPUserNotice"
	nameSigPolicyHash          = "SigPolicyHash"
	nameSigPolicyID            = "SigPolicyId"
	nameSigPolicyQualifier     = "SigPolicyQualifier"
	nameSigPolicyQualifiers    = "SigPolicyQualifiers"
	nameSignaturePolicyID      = "SignaturePolicyId"
	nameSignaturePolicyImplied = "SignaturePolicyImplied"
	// Base used for exact decimal integer parsing of signed property values.
	decimalRadix             = 10
	maximumNoticeNumberBytes = 8192
	maximumPolicyTransforms  = 16
	maximumSignaturePolicies = 16
)

// PolicyDocumentDigestAsSpecified is confined to SignaturePolicyId; it is never
// registered as a general XMLDSig transform.
const PolicyDocumentDigestAsSpecified = "http://uri.etsi.org/01903/v1.3.2/SignaturePolicy/SPDocDigestAsInSpecification"

func parseBaselinePolicy(ctx context.Context, element document.Element, options BaselineVerifyOptions) (*SignaturePolicy, error) {
	// SigPolicyId and SigPolicyHash are required; Transforms and qualifiers are optional.
	const (
		minimumSignaturePolicyChildren = 2
		maximumSignaturePolicyChildren = 4
	)

	if attrs(element) != nil {
		return nil, ErrProfile
	}

	values, err := baselineContent(element)
	if err != nil || len(values) != 1 {
		return nil, ErrProfile
	}

	if values[0].Name() == name(nameSignaturePolicyImplied) {
		if _, err := children(values[0]); err != nil || attrs(values[0]) != nil {
			return nil, ErrProfile
		}

		return &SignaturePolicy{Implied: true}, nil
	}

	if values[0].Name() != name(nameSignaturePolicyID) || attrs(values[0]) != nil {
		return nil, ErrProfile
	}

	values, err = baselineContent(values[0])
	if err != nil || len(values) < minimumSignaturePolicyChildren || len(values) > maximumSignaturePolicyChildren || values[0].Name() != name(nameSigPolicyID) {
		return nil, ErrProfile
	}

	policy := &SignaturePolicy{}

	policy.Identifier, err = parseObjectIdentifier(values[0])
	if err != nil {
		return nil, err
	}

	at := 1
	if values[at].Name() == ds(lexicon.DSigElementTransforms) {
		policy.Transforms, err = parsePolicyTransforms(ctx, values[at])
		if err != nil {
			return nil, err
		}

		at++
	}

	if at >= len(values) || values[at].Name() != name(nameSigPolicyHash) {
		return nil, ErrProfile
	}

	policy.DigestMethod, policy.Digest, err = parseBaselineDigest(ctx, values[at], options)
	if err != nil {
		return nil, err
	}

	at++
	if at < len(values) && values[at].Name() == name(nameSigPolicyQualifiers) {
		policy.Qualifiers, err = parsePolicyQualifiers(values[at])
		if err != nil {
			return nil, err
		}

		at++
	}

	if at != len(values) {
		return nil, ErrProfile
	}

	sum, err := baselinePolicyDigest(ctx, *policy, options)
	if err != nil {
		return nil, err
	}

	if subtle.ConstantTimeCompare(sum, policy.Digest) != 1 {
		return nil, ErrProfile
	}

	return policy, nil
}

func buildBaselinePolicy(ctx context.Context, policy SignaturePolicy, options BaselineVerifyOptions) (*tree.Node, error) {
	out := xnode(nameSignaturePolicyIdentifier)

	if policy.Implied {
		if (policy.Identifier.Identifier != "" || policy.Identifier.Qualifier != "" || policy.Identifier.Description != "" || len(policy.Identifier.Documentation) != 0) || policy.DigestMethod != "" || len(policy.Digest) != 0 || len(policy.Transforms) != 0 || len(policy.Qualifiers) != 0 {
			return nil, ErrProfile
		}

		add(out, xnode(nameSignaturePolicyImplied))

		return out, nil
	}

	if policy.DigestMethod == "" {
		policy.DigestMethod = xmldsig.SHA256
	}

	sum, err := baselinePolicyDigest(ctx, policy, options)
	if err != nil {
		return nil, err
	}

	if policy.Digest != nil && subtle.ConstantTimeCompare(policy.Digest, sum) != 1 {
		return nil, ErrProfile
	}

	explicit := xnode(nameSignaturePolicyID)
	add(out, explicit)

	identifier, err := buildObjectIdentifier(nameSigPolicyID, policy.Identifier)
	if err != nil {
		return nil, err
	}

	add(explicit, identifier)

	if len(policy.Transforms) > 0 {
		transforms := dsnode(lexicon.DSigElementTransforms)
		for _, tr := range policy.Transforms {
			n := dsnode(lexicon.DSigElementTransform)
			attr(n, lexicon.SecurityAttrAlgorithm, tr.Algorithm)

			if tr.Algorithm == PolicyDocumentDigestAsSpecified {
				if len(tr.XPath) != 0 || len(tr.InclusivePrefixes) != 0 || len(tr.Stylesheet) != 0 {
					return nil, ErrProfile
				}
			} else if err := transformxml.AppendParameters(ctx, n, tr); err != nil {
				return nil, err
			}

			add(transforms, n)
		}

		add(explicit, transforms)
	}

	hash := xnode(nameSigPolicyHash)
	method := dsnode(lexicon.DSigElementDigestMethod)
	attr(method, lexicon.SecurityAttrAlgorithm, policy.DigestMethod)
	add(hash, method)

	dv := dsnode(lexicon.DSigElementDigestValue)
	text(dv, base64.StdEncoding.EncodeToString(sum))
	add(hash, dv)
	add(explicit, hash)

	if len(policy.Qualifiers) > 0 {
		qualifiers := xnode(nameSigPolicyQualifiers)

		for _, qualifier := range policy.Qualifiers {
			value, err := buildPolicyQualifier(qualifier)
			if err != nil {
				return nil, err
			}

			add(qualifiers, value)
		}

		add(explicit, qualifiers)
	}

	return out, nil
}

func baselinePolicyDigest(ctx context.Context, policy SignaturePolicy, options BaselineVerifyOptions) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	if options.PolicyDocument == nil || len(options.PolicyDocument) > maximumPolicyDocumentBytes || len(policy.Transforms) > maximumPolicyTransforms {
		return nil, ErrProfile
	}

	h, err := baselineHash(policy.DigestMethod, options)
	if err != nil {
		return nil, err
	}

	transforms := reference.CloneTransforms(policy.Transforms)
	special := -1

	for i, tr := range transforms {
		if tr.Algorithm == PolicyDocumentDigestAsSpecified {
			if special >= 0 || i != len(transforms)-1 || len(tr.InclusivePrefixes) != 0 || len(tr.XPath) != 0 || len(tr.Stylesheet) != 0 {
				return nil, ErrProfile
			}

			special = i
		}
	}

	processing := options.Signature.Processing
	processing.Signature = document.Element{}

	if special >= 0 {
		return baselineSpecifiedPolicyDigest(ctx, policy, options, h, transforms, special, processing)
	}

	hash := h.New()
	if _, err := reference.WriteReader(ctx, hash, bytes.NewReader(options.PolicyDocument), transforms, processing); err != nil {
		return nil, err
	}

	return hash.Sum(nil), nil
}

func parsePolicyQualifier(element document.Element) (PolicyQualifier, error) {
	var out PolicyQualifier
	if element.Name() != name(nameSigPolicyQualifier) {
		return out, ErrProfile
	}

	values := element.Children()
	// AnyType permits attributes, mixed content and application-domain qualifiers.
	// These remain authenticated claims, never permission to fetch or trust them.
	if len(element.Attributes()) != 0 || len(values) != 1 {
		out.XML = element
		return out, nil
	}

	if baselineQualifierMixed(element) {
		out.XML = element
		return out, nil
	}

	child := values[0]
	switch child.Name() {
	case name(nameSPURI):
		value, err := simple(child)
		if err != nil || !baselineURI(value) {
			return out, ErrProfile
		}

		if value == "" {
			out.XML = element
		} else {
			out.URI = value
		}
	case name(nameSPUserNotice):
		var err error

		out.Notice, err = parsePolicyNotice(child)

		return out, err
	case name141(nameSPDocSpecification):
		value, err := parseObjectIdentifier(child)
		if err != nil || value.Qualifier == qualifierOIDAsURI {
			return out, ErrProfile
		}

		out.Specification = &value
	default:
		out.XML = element
	}

	return out, nil
}

func buildPolicyQualifier(value PolicyQualifier) (*tree.Node, error) {
	if value.XML.Valid() {
		if value.URI != "" || value.Notice != nil || value.Specification != nil || value.XML.Name() != name(nameSigPolicyQualifier) {
			return nil, ErrProfile
		}

		_, node := tree.Unwrap(value.XML)

		return tree.ImportSubtree(node), nil
	}

	choices := 0
	if value.URI != "" {
		choices++
	}

	if value.Notice != nil {
		choices++
	}

	if value.Specification != nil {
		choices++
	}

	if choices != 1 {
		return nil, ErrProfile
	}

	out := xnode(nameSigPolicyQualifier)

	if value.URI != "" {
		if !baselineURI(value.URI) {
			return nil, ErrProfile
		}

		leaf(out, nameSPURI, value.URI)
	}

	if value.Specification != nil {
		if value.Specification.Qualifier == qualifierOIDAsURI {
			return nil, ErrProfile
		}

		n, err := buildObjectIdentifier(nameSPDocSpecification, *value.Specification)
		if err != nil {
			return nil, err
		}

		n.Name = name141(nameSPDocSpecification)
		n.Prefix = prefixXAdES141
		add(out, n)
	}

	if value.Notice != nil {
		n, err := buildPolicyNotice(*value.Notice)
		if err != nil {
			return nil, err
		}

		add(out, n)
	}

	return out, nil
}

func parsePolicyNotice(element document.Element) (*PolicyNotice, error) {
	if attrs(element) != nil {
		return nil, ErrProfile
	}

	values, err := baselineContent(element)
	if err != nil || len(values) > 2 {
		return nil, ErrProfile
	}

	out := &PolicyNotice{}

	at := 0
	if at < len(values) && values[at].Name() == name(nameNoticeRef) {
		if attrs(values[at]) != nil {
			return nil, ErrProfile
		}

		fields, err := children(values[at], name(nameOrganization), name(nameNoticeNumbers))
		if err != nil {
			return nil, err
		}

		out.Organization, err = simple(fields[0])
		if err != nil || attrs(fields[1]) != nil {
			return nil, ErrProfile
		}

		out.NoticeNumbers = []string{}

		numbers, err := baselineContent(fields[1])
		if err != nil {
			return nil, err
		}

		for _, number := range numbers {
			if number.Name() != name(nameNoticeNumber) {
				return nil, ErrProfile
			}

			value, err := simple(number)
			if err != nil || !baselineInteger(value) {
				return nil, ErrProfile
			}

			out.NoticeNumbers = append(out.NoticeNumbers, value)
		}

		at++
	}

	if at < len(values) && values[at].Name() == name(nameExplicitText) {
		out.ExplicitText, err = simple(values[at])
		if err != nil {
			return nil, err
		}

		at++
	}

	if at != len(values) {
		return nil, ErrProfile
	}

	return out, nil
}

func buildPolicyNotice(value PolicyNotice) (*tree.Node, error) {
	out := xnode(nameSPUserNotice)
	if value.Organization != "" || value.NoticeNumbers != nil {
		ref := xnode(nameNoticeRef)
		leaf(ref, nameOrganization, value.Organization)

		numbers := xnode(nameNoticeNumbers)

		for _, number := range value.NoticeNumbers {
			if !baselineInteger(number) {
				return nil, ErrProfile
			}

			leaf(numbers, nameNoticeNumber, number)
		}

		add(ref, numbers)
		add(out, ref)
	}

	if value.ExplicitText != "" {
		leaf(out, nameExplicitText, value.ExplicitText)
	}

	return out, nil
}

func baselineInteger(value string) bool {
	value = strings.Trim(value, lexicon.XMLWhitespace)
	if value == "" || len(value) > maximumNoticeNumberBytes {
		return false
	}

	_, ok := new(big.Int).SetString(value, decimalRadix)

	return ok
}

func parsePolicyTransforms(ctx context.Context, element document.Element) ([]reference.Transform, error) {
	if attrs(element) != nil {
		return nil, ErrProfile
	}

	entries, err := baselineContent(element)
	if err != nil || len(entries) == 0 || len(entries) > maximumSignaturePolicies {
		return nil, ErrProfile
	}

	out := make([]reference.Transform, 0, len(entries))
	for _, entry := range entries {
		if entry.Name() != ds(lexicon.DSigElementTransform) {
			return nil, ErrProfile
		}

		owner, node := tree.Unwrap(entry)

		tr, err := transformxml.Parse(ctx, owner, node)
		if err != nil {
			return nil, errors.Join(ErrProfile, err)
		}

		out = append(out, tr)
	}

	return out, nil
}

func parsePolicyQualifiers(element document.Element) ([]PolicyQualifier, error) {
	if attrs(element) != nil {
		return nil, ErrProfile
	}

	entries, err := baselineContent(element)
	if err != nil || len(entries) == 0 {
		return nil, ErrProfile
	}

	out := make([]PolicyQualifier, 0, len(entries))
	for _, entry := range entries {
		value, err := parsePolicyQualifier(entry)
		if err != nil {
			return nil, err
		}

		out = append(out, value)
	}

	return out, nil
}

func baselineSpecifiedPolicyDigest(ctx context.Context, policy SignaturePolicy, options BaselineVerifyOptions, h crypto.Hash, transforms []reference.Transform, special int, processing reference.Options) ([]byte, error) {
	specifications, err := baselinePolicySpecifications(policy.Qualifiers)
	if err != nil {
		return nil, err
	}

	if len(specifications) == 0 || options.PolicySpecificationDigest == nil {
		return nil, ErrProfile
	}

	source := options.PolicyDocument

	if special > 0 {
		var transformed bytes.Buffer
		if _, err := reference.WriteReader(ctx, &transformed, bytes.NewReader(source), transforms[:special], processing); err != nil {
			return nil, err
		}

		source = transformed.Bytes()
	}

	var result []byte

	for _, specification := range specifications {
		sum, err := options.PolicySpecificationDigest(ctx, specification, slices.Clone(source), h)
		if err != nil {
			return nil, err
		}

		if err := ctx.Err(); err != nil {
			return nil, err
		}

		if len(sum) != h.Size() {
			return nil, ErrProfile
		}

		if result != nil && subtle.ConstantTimeCompare(result, sum) != 1 {
			return nil, ErrProfile
		}

		result = slices.Clone(sum)
	}

	return result, nil
}

func baselinePolicySpecifications(qualifiers []PolicyQualifier) ([]ObjectIdentifier, error) {
	var out []ObjectIdentifier

	for _, qualifier := range qualifiers {
		if qualifier.Specification != nil {
			out = append(out, *qualifier.Specification)
		}

		if !qualifier.XML.Valid() {
			continue
		}

		for _, child := range qualifier.XML.Children() {
			if child.Name() != name141(nameSPDocSpecification) {
				continue
			}

			value, err := parseObjectIdentifier(child)
			if err != nil || value.Qualifier == qualifierOIDAsURI {
				return nil, ErrProfile
			}

			out = append(out, value)
		}
	}

	return out, nil
}

func baselineQualifierMixed(element document.Element) bool {
	_, node := tree.Unwrap(element)
	for _, child := range node.Children {
		if child.Kind == tree.TextNode && !tree.IsXMLSpace(child.Data) {
			return true
		}
	}

	return false
}
