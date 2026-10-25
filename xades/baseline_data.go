package xades

import (
	"context"
	"net/url"
	"slices"
	"strings"

	"github.com/skarm/xmlsec/internal/lexicon"

	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/internal/tree"
	"github.com/skarm/xmlsec/xmldsig"
)

func parseObjectIdentifier(element document.Element) (ObjectIdentifier, error) {
	var out ObjectIdentifier
	if attrs(element) != nil {
		return out, ErrProfile
	}

	values, err := baselineContent(element)
	if err != nil || len(values) == 0 || len(values) > 3 || values[0].Name() != name("Identifier") {
		return out, ErrProfile
	}

	identifier := values[0]
	if baselineAttrs(identifier, nil, "Qualifier") != nil || len(identifier.Children()) != 0 {
		return out, ErrProfile
	}

	out.Identifier = identifier.Text()
	out.Qualifier = localAttribute(identifier, "Qualifier")

	at := 1
	if at < len(values) && values[at].Name() == name("Description") {
		out.Description, err = simple(values[at])
		if err != nil {
			return out, err
		}

		at++
	}

	if at < len(values) && values[at].Name() == name("DocumentationReferences") {
		docs := values[at]
		if attrs(docs) != nil {
			return out, ErrProfile
		}

		entries, err := baselineContent(docs)
		if err != nil || len(entries) == 0 {
			return out, ErrProfile
		}

		for _, entry := range entries {
			if entry.Name() != name("DocumentationReference") {
				return out, ErrProfile
			}

			value, err := simple(entry)
			if err != nil || !baselineURI(value) {
				return out, ErrProfile
			}

			out.Documentation = append(out.Documentation, value)
		}

		at++
	}

	if at != len(values) || checkObjectIdentifier(out) != nil {
		return out, ErrProfile
	}

	return out, nil
}

func checkObjectIdentifier(value ObjectIdentifier) error {
	if len(value.Documentation) > 64 || !baselineURI(value.Identifier) {
		return ErrProfile
	}

	switch value.Qualifier {
	case "":
		if strings.HasPrefix(strings.ToLower(value.Identifier), "urn:oid:") {
			return ErrProfile
		}
	case qualifierOIDAsURN:
		if !strings.HasPrefix(value.Identifier, "urn:oid:") || !baselineOID(value.Identifier[len("urn:oid:"):]) {
			return ErrProfile
		}
	case qualifierOIDAsURI:
		uri, err := url.Parse(value.Identifier)
		if err != nil || !uri.IsAbs() || strings.EqualFold(uri.Scheme, "urn") {
			return ErrProfile
		}
	default:
		return ErrProfile
	}

	for _, doc := range value.Documentation {
		if !baselineURI(doc) {
			return ErrProfile
		}
	}

	return nil
}

func baselineOID(value string) bool {
	arcs := strings.Split(value, ".")
	if len(arcs) < 2 {
		return false
	}

	for _, arc := range arcs {
		if arc == "" || len(arc) > 1 && arc[0] == '0' {
			return false
		}

		for _, c := range arc {
			if c < '0' || c > '9' {
				return false
			}
		}
	}

	if len(arcs[0]) != 1 || arcs[0][0] > '2' {
		return false
	}

	if arcs[0] != "2" && (len(arcs[1]) > 2 || len(arcs[1]) == 2 && arcs[1] > "39") {
		return false
	}

	return true
}

func buildObjectIdentifier(local string, value ObjectIdentifier) (*tree.Node, error) {
	if err := checkObjectIdentifier(value); err != nil {
		return nil, err
	}

	out := xnode(local)

	identifier := leaf(out, "Identifier", value.Identifier)
	if value.Qualifier != "" {
		attr(identifier, "Qualifier", value.Qualifier)
	}

	if value.Description != "" {
		leaf(out, "Description", value.Description)
	}

	if len(value.Documentation) > 0 {
		docs := xnode("DocumentationReferences")
		for _, value := range value.Documentation {
			leaf(docs, "DocumentationReference", value)
		}

		add(out, docs)
	}

	return out, nil
}

func parseDataObjectFormat(element document.Element) (DataObjectFormat, error) {
	out := DataObjectFormat{ObjectReference: localAttribute(element, "ObjectReference")}
	if baselineAttrs(element, []string{"ObjectReference"}) != nil {
		return out, ErrProfile
	}

	values, err := baselineContent(element)
	if err != nil {
		return out, err
	}

	previous := -1

	for _, child := range values {
		index := slices.Index([]document.Name{name("Description"), name("ObjectIdentifier"), name("MimeType"), name(attributeEncoding)}, child.Name())
		if index < 0 || index <= previous {
			return out, ErrProfile
		}

		previous = index
		switch index {
		case 0:
			out.Description, err = simple(child)
		case 1:
			var identifier ObjectIdentifier

			identifier, err = parseObjectIdentifier(child)
			out.ObjectIdentifier = &identifier
		case 2:
			out.MIMEType, err = simple(child)
		case 3:
			out.Encoding, err = simple(child)
		}

		if err != nil {
			return out, err
		}
	}

	hasDescription := slices.ContainsFunc(values, func(child document.Element) bool { return child.Name() == name("Description") })
	if !hasDescription && out.ObjectIdentifier == nil && out.MIMEType == "" {
		return out, ErrProfile
	}

	if out.MIMEType != "" && !validMime(out.MIMEType) || !baselineURI(out.Encoding) || out.ObjectReference == "" || !baselineURI(out.ObjectReference) {
		return out, ErrProfile
	}

	return out, nil
}

func checkDataObjectFormat(value DataObjectFormat) error {
	if !baselineURI(value.ObjectReference) || value.ObjectReference == "" || value.Description == "" && value.ObjectIdentifier == nil && value.MIMEType == "" {
		return ErrProfile
	}

	if value.MIMEType != "" && !validMime(value.MIMEType) {
		return ErrProfile
	}

	if value.Encoding != "" && !baselineURI(value.Encoding) {
		return ErrProfile
	}

	if value.ObjectIdentifier != nil {
		return checkObjectIdentifier(*value.ObjectIdentifier)
	}

	return nil
}

func buildDataObjectFormat(value DataObjectFormat) (*tree.Node, error) {
	if err := checkDataObjectFormat(value); err != nil {
		return nil, err
	}

	node := xnode("DataObjectFormat")
	attr(node, "ObjectReference", value.ObjectReference)

	if value.Description != "" {
		leaf(node, "Description", value.Description)
	}

	if value.ObjectIdentifier != nil {
		identifier, err := buildObjectIdentifier("ObjectIdentifier", *value.ObjectIdentifier)
		if err != nil {
			return nil, err
		}

		add(node, identifier)
	}

	if value.MIMEType != "" {
		leaf(node, "MimeType", value.MIMEType)
	}

	if value.Encoding != "" {
		leaf(node, attributeEncoding, value.Encoding)
	}

	return node, nil
}

func parseCommitment(element document.Element) (CommitmentType, error) {
	var out CommitmentType
	if attrs(element) != nil {
		return out, ErrProfile
	}

	values, err := baselineContent(element)
	if err != nil || len(values) < 2 || values[0].Name() != name("CommitmentTypeId") {
		return out, ErrProfile
	}

	out.Identifier, err = parseObjectIdentifier(values[0])
	if err != nil || out.Identifier.Qualifier != "" {
		return out, ErrProfile
	}

	at := 1
	if values[at].Name() == name("AllSignedDataObjects") {
		if _, err := children(values[at]); err != nil || attrs(values[at]) != nil {
			return out, ErrProfile
		}

		out.All = true
		at++
	} else {
		for at < len(values) && values[at].Name() == name("ObjectReference") {
			value, err := simple(values[at])
			if err != nil || value == "" || !baselineURI(value) {
				return out, ErrProfile
			}

			out.ObjectReferences = append(out.ObjectReferences, value)
			at++
		}

		if len(out.ObjectReferences) == 0 {
			return out, ErrProfile
		}
	}

	if at < len(values) && values[at].Name() == name("CommitmentTypeQualifiers") {
		out.Qualifiers, err = parseCommitmentQualifiers(values[at])
		if err != nil {
			return out, err
		}

		at++
	}

	if at != len(values) {
		return out, ErrProfile
	}

	return out, nil
}

func buildCommitment(ctx context.Context, value CommitmentType) (*tree.Node, error) {
	if value.Identifier.Qualifier != "" || value.All == (len(value.ObjectReferences) > 0) {
		return nil, ErrProfile
	}

	node := xnode("CommitmentTypeIndication")

	identifier, err := buildObjectIdentifier("CommitmentTypeId", value.Identifier)
	if err != nil {
		return nil, err
	}

	add(node, identifier)

	if value.All {
		add(node, xnode("AllSignedDataObjects"))
	} else {
		for _, uri := range value.ObjectReferences {
			if uri == "" || !baselineURI(uri) {
				return nil, ErrProfile
			}

			leaf(node, "ObjectReference", uri)
		}
	}

	if len(value.Qualifiers) > 0 {
		qualifiers := xnode("CommitmentTypeQualifiers")

		for _, qualifier := range value.Qualifiers {
			n, err := baselinePropertyValue(ctx, qualifier, name("CommitmentTypeQualifier"))
			if err != nil {
				return nil, err
			}

			add(qualifiers, n)
		}

		add(node, qualifiers)
	}

	return node, nil
}

type baselineDataReference struct {
	element document.Element
	result  xmldsig.ReferenceResult
}

func baselineDataReferences(verified *xmldsig.SignatureResult) (map[string]baselineDataReference, error) {
	out := make(map[string]baselineDataReference)

	si, err := childNamed(verified.Signature(), ds(lexicon.DSigElementSignedInfo))
	if err != nil {
		return nil, err
	}

	appendReferences := func(parent document.Element, results []xmldsig.ReferenceResult, resource string) error {
		index := 0

		for _, element := range parent.Children() {
			if element.Name() != ds(lexicon.DSigElementReference) {
				continue
			}

			if index >= len(results) {
				return ErrProfile
			}

			result := results[index]
			index++

			id := localAttribute(element, "Id")
			if id == "" {
				continue
			}

			key := baselineReferenceResource(resource) + "#" + id
			if _, exists := out[key]; exists {
				return ErrProfile
			}

			out[key] = baselineDataReference{element, result}
		}

		if index != len(results) {
			return ErrProfile
		}

		return nil
	}
	if err := appendReferences(si, verified.References(), ""); err != nil {
		return nil, err
	}

	for _, manifest := range verified.Manifests() {
		if err := appendReferences(manifest.Target(), manifest.References(), manifest.ResourceURI()); err != nil {
			return nil, err
		}
	}

	return out, nil
}

func checkBaselineDataBindings(layout baselineLayout, verified *xmldsig.SignatureResult, result *BaselineResult, options BaselineVerifyOptions) error {
	refs, err := baselineDataReferences(verified)
	if err != nil {
		return err
	}

	covered := map[string]bool{}

	for _, format := range result.data {
		key, err := baselineReferenceKey(format.ObjectReference, layout.data, options)
		if err != nil {
			return err
		}

		ref, found := refs[key]
		if !found || ref.result.Type() == SignedPropertiesType || ref.result.Type() == countersignedSignatureType {
			return ErrProfile
		}

		if covered[key] {
			return ErrProfile
		}

		covered[key] = true

		if err := checkBaselineObjectFormat(ref.result.Target(), format); err != nil {
			return err
		}
	}
	// EN319132-1 6.3(k) requires a DataObjectFormat for every directly signed
	// data Reference, excluding properties and the special countersignature target.

	si, err := childNamed(verified.Signature(), ds(lexicon.DSigElementSignedInfo))
	if err != nil {
		return err
	}

	for _, element := range si.Children() {
		if element.Name() != ds(lexicon.DSigElementReference) {
			continue
		}

		typ := localAttribute(element, "Type")
		if typ == SignedPropertiesType || typ == countersignedSignatureType {
			continue
		}

		if !covered["#"+localAttribute(element, "Id")] {
			return ErrProfile
		}
	}

	for _, commitment := range result.commitments {
		for _, uri := range commitment.ObjectReferences {
			key, err := baselineReferenceKey(uri, layout.data, options)
			if err != nil {
				return err
			}

			ref, found := refs[key]
			if !found || ref.result.Type() == SignedPropertiesType || ref.result.Type() == countersignedSignatureType {
				return ErrProfile
			}
		}
	}

	return nil
}

func checkBaselineTemplateBindings(template xmldsig.SignatureTemplate, properties BaselineProperties, options BaselineVerifyOptions) error {
	refs, err := collectBaselineTemplateReferences(template)
	if err != nil {
		return err
	}

	covered := map[string]bool{}

	for _, format := range properties.DataObjects {
		ref, found := refs[format.ObjectReference]
		if !found && options.Signature.Manifests.AllowExternal && !strings.HasPrefix(format.ObjectReference, "#") {
			continue
		}

		if !found || ref.Type == SignedPropertiesType || ref.Type == countersignedSignatureType || covered[format.ObjectReference] {
			return ErrProfile
		}

		covered[format.ObjectReference] = true
	}

	for _, ref := range template.References {
		if ref.Type != SignedPropertiesType && ref.Type != countersignedSignatureType && !covered["#"+ref.ID] {
			return ErrProfile
		}
	}

	for _, commitment := range properties.Commitments {
		for _, uri := range commitment.ObjectReferences {
			ref, found := refs[uri]
			if !found || ref.Type == SignedPropertiesType || ref.Type == countersignedSignatureType {
				return ErrProfile
			}
		}
	}

	return nil
}

func parseCommitmentQualifiers(element document.Element) ([]PropertyValue, error) {
	if attrs(element) != nil {
		return nil, ErrProfile
	}

	values, err := baselineContent(element)
	if err != nil {
		return nil, err
	}

	out := make([]PropertyValue, 0, len(values))
	for _, value := range values {
		if value.Name() != name("CommitmentTypeQualifier") {
			return nil, ErrProfile
		}

		out = append(out, PropertyValue{XML: value})
	}

	return out, nil
}

func checkBaselineObjectFormat(target document.Element, format DataObjectFormat) error {
	if target.Name() != ds("Object") {
		return nil
	}

	for _, pair := range [][2]string{{"MimeType", format.MIMEType}, {attributeEncoding, format.Encoding}} {
		value, exists := target.Attribute(document.Name{Local: pair[0]})
		if exists && pair[1] != "" && value != pair[1] {
			return ErrProfile
		}
	}

	return nil
}

func baselineReferenceResource(value string) string {
	uri, err := url.Parse(value)
	if err != nil {
		return value
	}

	uri.Fragment = ""

	return uri.String()
}

func baselineReferenceKey(value string, element document.Element, options BaselineVerifyOptions) (string, error) {
	uri, err := url.Parse(value)
	if err != nil || !tree.NCName(uri.Fragment) {
		return "", ErrProfile
	}

	fragment := uri.Fragment

	uri.Fragment = ""
	if uri.String() == "" {
		return "#" + fragment, nil
	}

	if !uri.IsAbs() && options.Signature.External != nil && options.Signature.External.BaseURI != "" {
		base, err := url.Parse(options.Signature.External.BaseURI)
		if err != nil {
			return "", ErrProfile
		}

		_, node := tree.Unwrap(element)

		var path []*tree.Node
		for n := node; n != nil; n = n.Parent {
			path = append(path, n)
		}

		for _, n := range slices.Backward(path) {
			for _, attribute := range n.Attrs {
				if attribute.Name == (document.Name{Space: document.XMLNamespace, Local: "base"}) {
					part, err := url.Parse(attribute.Value)
					if err != nil {
						return "", ErrProfile
					}

					base = base.ResolveReference(part)
				}
			}
		}

		uri = base.ResolveReference(uri)
	}

	return uri.String() + "#" + fragment, nil
}

func collectBaselineTemplateReferences(template xmldsig.SignatureTemplate) (map[string]xmldsig.ReferenceTemplate, error) {
	refs := make(map[string]xmldsig.ReferenceTemplate)

	add := func(values []xmldsig.ReferenceTemplate) error {
		for _, value := range values {
			if value.ID == "" {
				continue
			}

			uri := "#" + value.ID
			if _, exists := refs[uri]; exists {
				return ErrProfile
			}

			refs[uri] = value
		}

		return nil
	}
	if err := add(template.References); err != nil {
		return nil, err
	}

	for _, object := range template.Objects {
		if object.Manifest != nil {
			if err := add(object.Manifest.References); err != nil {
				return nil, err
			}
		}
	}

	return refs, nil
}
