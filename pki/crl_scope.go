package pki

import (
	"bytes"
	"context"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"net"
	"strings"

	"github.com/skarm/xmlsec/internal/der"
	"github.com/skarm/xmlsec/internal/lexicon"
	"github.com/skarm/xmlsec/internal/x509name"
)

const (
	// Bounds individual CRL scope/name extension encodings, in bytes.
	maxCRLExtensionBytes       = 1 << 20
	maxDistributionPointFields = 256
	maxDistributionPointNames  = 256
	maxRDNAttributes           = 256
)

type crlReasonMask uint16

// CRL ReasonFlags positions 1..8 map to bits 0..7 in the internal coverage mask.
// This mask is separate from the CRLReason ENUMERATED values in signed entries.
const (
	crlReasonFlagBitLength               = 9
	allCRLReasons          crlReasonMask = 1<<(crlReasonFlagBitLength-1) - 1
)

// DistributionPoint and IssuingDistributionPoint have distinct tagged schemas.
const (
	crlPointNameTag       = 0
	crlPointReasonsTag    = 1
	crlPointIssuerTag     = 2
	crlPointMaximumFields = 3
	crlScopeNameTag       = 0
	crlScopeOnlyUserTag   = 1
	crlScopeOnlyCATag     = 2
	crlScopeReasonsTag    = 3
	crlScopeIndirectTag   = 4
	crlScopeOnlyAttrTag   = 5
	crlScopeMaximumFields = 6
)

type crlGeneralName struct {
	tag   int
	value []byte
	key   string
}
type crlDistributionPoint struct {
	names          []crlGeneralName
	relative       []byte
	issuer         []crlGeneralName
	reasons        crlReasonMask
	reasonsPresent bool
}
type crlScope struct {
	crlDistributionPoint
	indirect      bool
	onlyUser      bool
	onlyCA        bool
	onlyAttribute bool
	raw           []byte
}

func parseDistinguishedName(raw []byte) (pkix.RDNSequence, error) {
	var name pkix.RDNSequence
	if len(raw) > maxCRLExtensionBytes || der.Unmarshal(raw, &name) != nil {
		return nil, ErrEvidence
	}

	return name, nil
}

// Canonical names are lookup keys only; original Name DER remains untouched.
func canonicalNameKey(ctx context.Context, raw []byte) (string, error) {
	key, err := x509name.Key(ctx, raw)
	if errors.Is(err, x509name.ErrUnsupported) {
		return "DN-opaque\x00" + string(raw), nil
	}

	if errors.Is(err, x509name.ErrLimit) {
		return "", fmt.Errorf("%w: %w: %w", ErrPolicy, ErrLimit, err)
	}

	if err != nil {
		return "", err
	}

	return key, nil
}

func crlDirectoryName(ctx context.Context, raw []byte) (crlGeneralName, error) {
	key, err := canonicalNameKey(ctx, raw)
	return crlGeneralName{tag: lexicon.GeneralNameDirectory, value: raw, key: key}, err
}

func parseGeneralNames(ctx context.Context, value asn1.RawValue, implicit bool) ([]crlGeneralName, error) {
	if !value.IsCompound || !implicit && !der.Is(value, asn1.ClassUniversal, asn1.TagSequence, true) || implicit && value.Class != asn1.ClassContextSpecific {
		return nil, ErrEvidence
	}

	fields, err := der.ChildrenLimit(value, maxDistributionPointFields)
	if errors.Is(err, der.ErrLimit) {
		return nil, fmt.Errorf("%w: %w: CRL GeneralNames count", ErrPolicy, ErrLimit)
	}

	if err != nil || len(fields) < 1 {
		return nil, ErrEvidence
	}

	out := make([]crlGeneralName, 0, len(fields))
	for _, field := range fields {
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		name, err := parseCRLGeneralName(ctx, field)
		if err != nil {
			return nil, err
		}

		out = append(out, name)
	}

	return out, nil
}

func parseCRLReasonMask(value asn1.RawValue) (crlReasonMask, error) {
	if value.IsCompound {
		return 0, ErrEvidence
	}

	var bits asn1.BitString
	if der.Unmarshal(der.Wrap(asn1.ClassUniversal, asn1.TagBitString, false, value.Bytes), &bits) != nil || bits.BitLength > crlReasonFlagBitLength || bits.At(0) != 0 {
		return 0, ErrEvidence
	}

	var mask crlReasonMask

	for i := 1; i < bits.BitLength; i++ {
		if bits.At(i) != 0 {
			mask |= 1 << (i - 1)
		}
	}

	return mask, nil
}

func parseCRLPointName(ctx context.Context, value asn1.RawValue) ([]crlGeneralName, []byte, error) {
	name, err := der.Explicit(value, 0)
	if err != nil || name.Class != asn1.ClassContextSpecific || !name.IsCompound {
		return nil, nil, ErrEvidence
	}

	switch name.Tag {
	case 0:
		names, err := parseGeneralNames(ctx, name, true)
		return names, nil, err
	case 1:
		raw := der.Wrap(asn1.ClassUniversal, asn1.TagSet, true, name.Bytes)
		if _, err := der.Read(raw, maxCRLExtensionBytes); err != nil {
			return nil, nil, ErrEvidence
		}

		var rdn pkix.RelativeDistinguishedNameSET
		if der.Unmarshal(raw, &rdn) != nil || len(rdn) == 0 || len(rdn) > maxRDNAttributes {
			return nil, nil, ErrEvidence
		}

		return nil, raw, nil
	default:
		return nil, nil, ErrEvidence
	}
}

func parseCRLDistributionPoints(ctx context.Context, raw []byte) ([]crlDistributionPoint, error) {
	value, err := der.Read(raw, maxCRLExtensionBytes)
	if err != nil {
		return nil, ErrEvidence
	}

	fields, err := der.Sequence(value, 1, maxDistributionPointNames)
	if err != nil {
		return nil, ErrEvidence
	}

	out := make([]crlDistributionPoint, 0, len(fields))
	for _, value := range fields {
		fields, err := der.Sequence(value, 1, crlPointMaximumFields)
		if err != nil {
			return nil, ErrEvidence
		}

		point := crlDistributionPoint{reasons: allCRLReasons}

		previous := -1
		for _, field := range fields {
			if field.Class != asn1.ClassContextSpecific || field.Tag <= previous {
				return nil, ErrEvidence
			}

			previous = field.Tag
			switch field.Tag {
			case crlPointNameTag:
				point.names, point.relative, err = parseCRLPointName(ctx, field)
			case crlPointReasonsTag:
				point.reasonsPresent = true
				point.reasons, err = parseCRLReasonMask(field)
			case crlPointIssuerTag:
				point.issuer, err = parseGeneralNames(ctx, field, true)
			default:
				return nil, ErrEvidence
			}

			if err != nil {
				return nil, err
			}
		}

		if len(point.names) == 0 && len(point.relative) == 0 && len(point.issuer) == 0 {
			return nil, ErrEvidence
		}

		if len(point.relative) != 0 && len(point.issuer) > 1 {
			return nil, ErrEvidence
		}

		for _, name := range point.issuer {
			if name.tag != lexicon.GeneralNameDirectory {
				return nil, ErrEvidence
			}
		}

		out = append(out, point)
	}

	return out, nil
}

func parseCRLScope(ctx context.Context, raw []byte) (crlScope, error) {
	// DER TRUE is encoded as a single all-one octet.
	const crlDERTrue = 0xff

	scope := crlScope{reasons: allCRLReasons, raw: raw}

	value, err := der.Read(raw, maxCRLExtensionBytes)
	if err != nil {
		return scope, ErrEvidence
	}

	fields, err := der.Sequence(value, 1, crlScopeMaximumFields)
	if err != nil {
		return scope, ErrEvidence
	}

	previous := -1
	for _, field := range fields {
		if field.Class != asn1.ClassContextSpecific || field.Tag <= previous {
			return scope, ErrEvidence
		}

		previous = field.Tag
		switch field.Tag {
		case crlScopeNameTag:
			scope.names, scope.relative, err = parseCRLPointName(ctx, field)
		case crlScopeReasonsTag:
			scope.reasons, err = parseCRLReasonMask(field)
		case crlScopeOnlyUserTag, crlScopeOnlyCATag, crlScopeIndirectTag, crlScopeOnlyAttrTag:
			if field.IsCompound || len(field.Bytes) != 1 || field.Bytes[0] != crlDERTrue {
				return scope, ErrEvidence
			}

			switch field.Tag {
			case crlScopeOnlyUserTag:
				scope.onlyUser = true
			case crlScopeOnlyCATag:
				scope.onlyCA = true
			case crlScopeIndirectTag:
				scope.indirect = true
			case crlScopeOnlyAttrTag:
				scope.onlyAttribute = true
			}
		default:
			return scope, ErrEvidence
		}

		if err != nil {
			return scope, err
		}
	}

	count := 0

	for _, v := range []bool{scope.onlyUser, scope.onlyCA, scope.onlyAttribute} {
		if v {
			count++
		}
	}

	if count > 1 {
		return scope, ErrEvidence
	}

	return scope, nil
}

func crlPointNames(ctx context.Context, point crlDistributionPoint, issuer []byte) ([]crlGeneralName, error) {
	if len(point.relative) == 0 {
		return point.names, nil
	}

	if len(point.issuer) != 0 {
		if len(point.issuer) != 1 || point.issuer[0].tag != lexicon.GeneralNameDirectory {
			return nil, ErrEvidence
		}

		issuer = point.issuer[0].value
	}

	name, err := parseDistinguishedName(issuer)
	if err != nil {
		return nil, err
	}

	var rdn pkix.RelativeDistinguishedNameSET
	if der.Unmarshal(point.relative, &rdn) != nil {
		return nil, ErrEvidence
	}

	name = append(name, rdn)

	raw, err := asn1.Marshal(name)
	if err != nil {
		return nil, ErrEvidence
	}

	resolved, err := crlDirectoryName(ctx, raw)

	return []crlGeneralName{resolved}, err
}

func equalCRLGeneralName(a, b crlGeneralName) bool {
	if a.tag != b.tag {
		return false
	}

	switch a.tag {
	case lexicon.GeneralNameDirectory:
		return a.key != "" && a.key == b.key
	case lexicon.GeneralNameRFC822:
		return equalCRLMailbox(string(a.value), string(b.value))
	case lexicon.GeneralNameURI:
		return crlURIKey(string(a.value)) == crlURIKey(string(b.value))
	case lexicon.GeneralNameDNS:
		return strings.EqualFold(string(a.value), string(b.value))
	}

	return bytes.Equal(a.value, b.value)
}

func intersectCRLNames(a, b []crlGeneralName) bool {
	for _, left := range a {
		for _, right := range b {
			if equalCRLGeneralName(left, right) {
				return true
			}
		}
	}

	return false
}

func parseCRLGeneralName(ctx context.Context, field asn1.RawValue) (crlGeneralName, error) {
	if field.Class != asn1.ClassContextSpecific || field.Tag < lexicon.GeneralNameOtherName || field.Tag > lexicon.GeneralNameRegisteredID {
		return crlGeneralName{}, ErrEvidence
	}

	name := crlGeneralName{tag: field.Tag, value: field.Bytes}

	var err error

	switch field.Tag {
	case lexicon.GeneralNameDirectory:
		if !field.IsCompound {
			return crlGeneralName{}, ErrEvidence
		}

		name, err = crlDirectoryName(ctx, field.Bytes)
		if err != nil {
			return crlGeneralName{}, err
		}
	case lexicon.GeneralNameRFC822, lexicon.GeneralNameDNS, lexicon.GeneralNameURI:
		if err := validateCRLIA5Name(field); err != nil {
			return crlGeneralName{}, err
		}

	case lexicon.GeneralNameIP:
		if field.IsCompound || len(field.Bytes) != net.IPv4len && len(field.Bytes) != net.IPv6len {
			return crlGeneralName{}, ErrEvidence
		}
	case lexicon.GeneralNameRegisteredID:
		if field.IsCompound {
			return crlGeneralName{}, ErrEvidence
		}

		var oid asn1.ObjectIdentifier
		if der.Unmarshal(der.Wrap(asn1.ClassUniversal, asn1.TagOID, false, field.Bytes), &oid) != nil {
			return crlGeneralName{}, ErrEvidence
		}
	case lexicon.GeneralNameOtherName:
		if !field.IsCompound {
			return crlGeneralName{}, ErrEvidence
		}

		fields, err := der.Children(field)
		if err != nil || len(fields) != 2 {
			return crlGeneralName{}, ErrEvidence
		}

		var oid asn1.ObjectIdentifier
		if der.Decode(fields[0], &oid) != nil {
			return crlGeneralName{}, ErrEvidence
		}

		if _, err := der.Explicit(fields[1], 0); err != nil {
			return crlGeneralName{}, ErrEvidence
		}
	default:
		if !field.IsCompound {
			return crlGeneralName{}, ErrEvidence
		}
	}

	return name, nil
}

func validateCRLIA5Name(field asn1.RawValue) error {
	// GeneralName IA5 spellings here exclude space/control bytes and DEL.
	const (
		ia5SpaceByte  = 32
		ia5DeleteByte = 127
	)

	if field.IsCompound || len(field.Bytes) == 0 {
		return ErrEvidence
	}

	for _, b := range field.Bytes {
		if b <= ia5SpaceByte || b >= ia5DeleteByte {
			return ErrEvidence
		}
	}

	if field.Tag == lexicon.GeneralNameURI {
		if !validCRLURI(string(field.Bytes)) {
			return ErrEvidence
		}
	}

	return nil
}
