package xades

import (
	"bytes"
	"context"
	"encoding/asn1"
	"errors"
	"math/big"
	"slices"

	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/internal/der"
	"github.com/skarm/xmlsec/internal/lexicon"
	"github.com/skarm/xmlsec/internal/tree"
)

const (
	nameCertifiedRole                     = "CertifiedRole"
	nameCertifiedRolesV2                  = "CertifiedRolesV2"
	nameClaimedRole                       = "ClaimedRole"
	nameClaimedRoles                      = "ClaimedRoles"
	nameOtherAttributeCertificate         = "OtherAttributeCertificate"
	nameSignedAssertion                   = "SignedAssertion"
	nameSignedAssertions                  = "SignedAssertions"
	nameX509AttributeCertificate          = "X509AttributeCertificate"
	maximumAttributeCertificateAttributes = 256
	maximumAttributeCertificateExtensions = 256
	maximumAttributeCertificateValues     = 256
	maximumRoleValues                     = 64
)

func parseBaselineRoles(ctx context.Context, element document.Element, result *BaselineResult) error {
	if attrs(element) != nil {
		return ErrProfile
	}

	groups, err := baselineContent(element)
	if err != nil || len(groups) == 0 {
		return ErrProfile
	}

	previous := -1

	for _, group := range groups {
		index := slices.Index([]document.Name{name(nameClaimedRoles), name(nameCertifiedRolesV2), name(nameSignedAssertions)}, group.Name())
		if index < 0 || index <= previous || attrs(group) != nil {
			return ErrProfile
		}

		previous = index

		values, err := baselineContent(group)
		if err != nil || len(values) == 0 {
			return ErrProfile
		}

		for _, value := range values {
			switch index {
			case 0:
				if value.Name() != name(nameClaimedRole) {
					return ErrProfile
				}

				result.roles = append(result.roles, value)
			case 1:
				if err := checkCertifiedRole(ctx, value); err != nil {
					return err
				}

				result.certifiedRoles = append(result.certifiedRoles, value)
			case 2:
				if value.Name() != name(nameSignedAssertion) {
					return ErrProfile
				}

				result.assertions = append(result.assertions, value)
			}
		}
	}

	return nil
}

func buildBaselineRoles(ctx context.Context, properties BaselineProperties) (*tree.Node, error) {
	out := xnode(nameSignerRoleV2)

	groups := []struct {
		local  string
		child  string
		values []PropertyValue
	}{
		{nameClaimedRoles, nameClaimedRole, properties.ClaimedRoles},
		{nameCertifiedRolesV2, nameCertifiedRole, properties.CertifiedRoles},
		{nameSignedAssertions, nameSignedAssertion, properties.SignedAssertions},
	}

	for _, group := range groups {
		if len(group.values) == 0 {
			continue
		}

		if len(group.values) > maximumRoleValues {
			return nil, ErrProfile
		}

		container := xnode(group.local)
		for _, value := range group.values {
			n, err := baselinePropertyValue(ctx, value, name(group.child))
			if err != nil {
				return nil, err
			}

			if group.child == nameCertifiedRole {
				doc := tree.FromNodes([]*tree.Node{n}, document.DefaultLimits())
				if err := checkCertifiedRole(ctx, doc.Root()); err != nil {
					return nil, err
				}
			}

			add(container, n)
		}

		add(out, container)
	}

	if len(out.Children) == 0 {
		return nil, ErrProfile
	}

	return out, nil
}

func checkCertifiedRole(ctx context.Context, element document.Element) error {
	if element.Name() != name(nameCertifiedRole) || attrs(element) != nil {
		return ErrProfile
	}

	values, err := baselineContent(element)
	if err != nil || len(values) != 1 {
		return ErrProfile
	}

	switch values[0].Name() {
	case name(nameOtherAttributeCertificate):
		return nil // Domain syntax and authority remain explicitly external.
	case name(nameX509AttributeCertificate):
		value := values[0]
		if baselineAttrs(value, nil, lexicon.SecurityAttrID, attributeEncoding) != nil {
			return ErrProfile
		}

		encoding := localAttribute(value, attributeEncoding)
		if encoding != "" && encoding != encodingDER {
			return ErrProfile
		}

		raw, err := decodeElementBase64(ctx, value, maximumRoleCertificateLexicalBytes, maximumCertificateBytes)
		if err != nil {
			return err
		}

		return checkAttributeCertificate(raw)
	default:
		return ErrProfile
	}
}

// checkAttributeCertificate validates the bounded RFC5755 v2 envelope and
// signed-field structure. Issuer trust, holder matching, signatures and
// attribute-specific authorization are separate caller policy decisions.
func checkAttributeCertificate(raw []byte) error {
	// RFC 5755's v2 envelope has three fields. Its signed info has seven
	// mandatory fields and optional issuerUniqueID/extensions; v2 is encoded as 1.
	const (
		attributeCertificateFields         = 3
		attributeCertificateRequiredFields = 7
		attributeCertificateMaximumFields  = 9
		attributeCertificateVersion2       = 1
		attributeCertificateValidityFields = 2
	)

	value, err := der.Read(raw, maximumCertificateBytes)
	if err != nil {
		return errors.Join(ErrProfile, err)
	}

	fields, err := der.Sequence(value, attributeCertificateFields, attributeCertificateFields)
	if err != nil {
		return ErrProfile
	}

	info, err := der.Sequence(fields[0], attributeCertificateRequiredFields, attributeCertificateMaximumFields)
	if err != nil {
		return ErrProfile
	}

	var version int
	if der.Decode(info[0], &version) != nil || version != attributeCertificateVersion2 {
		return ErrProfile
	}

	if err := checkAttributeHolder(info[1]); err != nil {
		return err
	}

	if !(der.Is(info[2], asn1.ClassUniversal, asn1.TagSequence, true) || der.Is(info[2], asn1.ClassContextSpecific, 0, true)) || len(info[2].Bytes) == 0 {
		return ErrProfile
	}

	if err := baselineAlgorithmIdentifier(info[3]); err != nil {
		return err
	}

	if err := baselineAlgorithmIdentifier(fields[1]); err != nil || !bytes.Equal(info[3].FullBytes, fields[1].FullBytes) {
		return ErrProfile
	}

	var serial *big.Int
	if der.Decode(info[4], &serial) != nil || serial == nil || serial.Sign() <= 0 {
		return ErrProfile
	}

	validity, err := der.Sequence(info[5], attributeCertificateValidityFields, attributeCertificateValidityFields)
	if err != nil || !der.Is(validity[0], asn1.ClassUniversal, asn1.TagGeneralizedTime, false) || !der.Is(validity[1], asn1.ClassUniversal, asn1.TagGeneralizedTime, false) {
		return ErrProfile
	}

	if err := checkAttributeValues(info[6]); err != nil {
		return err
	}

	at := attributeCertificateRequiredFields
	if at < len(info) && der.Is(info[at], asn1.ClassUniversal, asn1.TagBitString, false) {
		at++
	}

	if at < len(info) {
		if _, err := der.Sequence(info[at], 1, maximumAttributeCertificateExtensions); err != nil {
			return ErrProfile
		}

		at++
	}

	if at != len(info) || !der.Is(fields[2], asn1.ClassUniversal, asn1.TagBitString, false) || len(fields[2].Bytes) < 2 || fields[2].Bytes[0] != 0 {
		return ErrProfile
	}

	return nil
}

func baselineAlgorithmIdentifier(value asn1.RawValue) error {
	// AlgorithmIdentifier has a required OID and optional parameters.
	const (
		algorithmIdentifierMinimumFields = 1
		algorithmIdentifierMaximumFields = 2
	)

	fields, err := der.Sequence(value, algorithmIdentifierMinimumFields, algorithmIdentifierMaximumFields)
	if err != nil || !der.Is(fields[0], asn1.ClassUniversal, asn1.TagOID, false) {
		return ErrProfile
	}

	return nil
}

func checkAttributeValues(value asn1.RawValue) error {
	const attributeFields = 2 // type OID and SET OF values

	attributes, err := der.Sequence(value, 1, maximumAttributeCertificateAttributes)
	if err != nil {
		return ErrProfile
	}

	for _, attribute := range attributes {
		pair, err := der.Sequence(attribute, attributeFields, attributeFields)
		if err != nil || !der.Is(pair[0], asn1.ClassUniversal, asn1.TagOID, false) {
			return ErrProfile
		}

		if _, err := der.SetFields(pair[1], asn1.ClassUniversal, asn1.TagSet, maximumAttributeCertificateValues); err != nil || len(pair[1].Bytes) == 0 {
			return ErrProfile
		}
	}

	return nil
}

func checkAttributeHolder(value asn1.RawValue) error {
	// Holder permits nonempty selections of its three context-specific fields.
	const (
		holderMinimumFields = 1
		holderMaximumFields = 3
		holderFirstFieldTag = 0
		holderLastFieldTag  = 2
	)

	holder, err := der.Sequence(value, holderMinimumFields, holderMaximumFields)
	if err != nil {
		return ErrProfile
	}

	previous := -1
	for _, field := range holder {
		if field.Class != asn1.ClassContextSpecific || !field.IsCompound || field.Tag < holderFirstFieldTag || field.Tag > holderLastFieldTag || field.Tag <= previous || len(field.Bytes) == 0 {
			return ErrProfile
		}

		previous = field.Tag
	}

	return nil
}
