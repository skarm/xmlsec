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
	"github.com/skarm/xmlsec/internal/tree"
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
		index := slices.Index([]document.Name{name("ClaimedRoles"), name("CertifiedRolesV2"), name("SignedAssertions")}, group.Name())
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
				if value.Name() != name("ClaimedRole") {
					return ErrProfile
				}

				result.roles = append(result.roles, value)
			case 1:
				if err := checkCertifiedRole(ctx, value); err != nil {
					return err
				}

				result.certifiedRoles = append(result.certifiedRoles, value)
			case 2:
				if value.Name() != name("SignedAssertion") {
					return ErrProfile
				}

				result.assertions = append(result.assertions, value)
			}
		}
	}

	return nil
}

func buildBaselineRoles(ctx context.Context, properties BaselineProperties) (*tree.Node, error) {
	out := xnode("SignerRoleV2")

	groups := []struct {
		local, child string
		values       []PropertyValue
	}{{"ClaimedRoles", "ClaimedRole", properties.ClaimedRoles}, {"CertifiedRolesV2", "CertifiedRole", properties.CertifiedRoles}, {"SignedAssertions", "SignedAssertion", properties.SignedAssertions}}
	for _, group := range groups {
		if len(group.values) == 0 {
			continue
		}

		if len(group.values) > 64 {
			return nil, ErrProfile
		}

		container := xnode(group.local)
		for _, value := range group.values {
			n, err := baselinePropertyValue(ctx, value, name(group.child))
			if err != nil {
				return nil, err
			}

			if group.child == "CertifiedRole" {
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
	if element.Name() != name("CertifiedRole") || attrs(element) != nil {
		return ErrProfile
	}

	values, err := baselineContent(element)
	if err != nil || len(values) != 1 {
		return ErrProfile
	}

	switch values[0].Name() {
	case name("OtherAttributeCertificate"):
		return nil // Domain syntax and authority remain explicitly external.
	case name("X509AttributeCertificate"):
		value := values[0]
		if baselineAttrs(value, nil, "Id", attributeEncoding) != nil {
			return ErrProfile
		}

		encoding := localAttribute(value, attributeEncoding)
		if encoding != "" && encoding != encodingDER {
			return ErrProfile
		}

		raw, err := decodeElementBase64(ctx, value, 2<<20, 1<<20)
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
	value, err := der.Read(raw, 1<<20)
	if err != nil {
		return errors.Join(ErrProfile, err)
	}

	fields, err := der.Sequence(value, 3, 3)
	if err != nil {
		return ErrProfile
	}

	info, err := der.Sequence(fields[0], 7, 9)
	if err != nil {
		return ErrProfile
	}

	var version int
	if der.Decode(info[0], &version) != nil || version != 1 {
		return ErrProfile
	}

	if err := checkAttributeHolder(info[1]); err != nil {
		return err
	}

	if !(der.Is(info[2], 0, asn1.TagSequence, true) || der.Is(info[2], 2, 0, true)) || len(info[2].Bytes) == 0 {
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

	validity, err := der.Sequence(info[5], 2, 2)
	if err != nil || !der.Is(validity[0], 0, asn1.TagGeneralizedTime, false) || !der.Is(validity[1], 0, asn1.TagGeneralizedTime, false) {
		return ErrProfile
	}

	if err := checkAttributeValues(info[6]); err != nil {
		return err
	}

	at := 7
	if at < len(info) && der.Is(info[at], 0, asn1.TagBitString, false) {
		at++
	}

	if at < len(info) {
		if _, err := der.Sequence(info[at], 1, 256); err != nil {
			return ErrProfile
		}

		at++
	}

	if at != len(info) || !der.Is(fields[2], 0, asn1.TagBitString, false) || len(fields[2].Bytes) < 2 || fields[2].Bytes[0] != 0 {
		return ErrProfile
	}

	return nil
}

func baselineAlgorithmIdentifier(value asn1.RawValue) error {
	fields, err := der.Sequence(value, 1, 2)
	if err != nil || !der.Is(fields[0], 0, asn1.TagOID, false) {
		return ErrProfile
	}

	return nil
}

func checkAttributeValues(value asn1.RawValue) error {
	attributes, err := der.Sequence(value, 1, 256)
	if err != nil {
		return ErrProfile
	}

	for _, attribute := range attributes {
		pair, err := der.Sequence(attribute, 2, 2)
		if err != nil || !der.Is(pair[0], 0, asn1.TagOID, false) {
			return ErrProfile
		}

		if _, err := der.SetFields(pair[1], 0, asn1.TagSet, 256); err != nil || len(pair[1].Bytes) == 0 {
			return ErrProfile
		}
	}

	return nil
}

func checkAttributeHolder(value asn1.RawValue) error {
	holder, err := der.Sequence(value, 1, 3)
	if err != nil {
		return ErrProfile
	}

	previous := -1
	for _, field := range holder {
		if field.Class != 2 || !field.IsCompound || field.Tag < 0 || field.Tag > 2 || field.Tag <= previous || len(field.Bytes) == 0 {
			return ErrProfile
		}

		previous = field.Tag
	}

	return nil
}
