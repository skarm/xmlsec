package pki

import (
	"bytes"
	"context"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"strings"

	"github.com/skarm/xmlsec/internal/der"
	"github.com/skarm/xmlsec/internal/x509name"
)

type crlReasonMask uint16

const allCRLReasons crlReasonMask = 255

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
	indirect, onlyUser, onlyCA, onlyAttribute bool
	raw                                       []byte
}

func parseDistinguishedName(raw []byte) (pkix.RDNSequence, error) {
	var name pkix.RDNSequence
	if len(raw) > 1<<20 || der.Unmarshal(raw, &name) != nil {
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
	return crlGeneralName{tag: 4, value: raw, key: key}, err
}

func parseGeneralNames(ctx context.Context, value asn1.RawValue, implicit bool) ([]crlGeneralName, error) {
	if !value.IsCompound || !implicit && !der.Is(value, 0, asn1.TagSequence, true) || implicit && value.Class != 2 {
		return nil, ErrEvidence
	}

	fields, err := der.ChildrenLimit(value, 256)
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
	if der.Unmarshal(der.Wrap(0, asn1.TagBitString, false, value.Bytes), &bits) != nil || bits.BitLength > 9 || bits.At(0) != 0 {
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
	if err != nil || name.Class != 2 || !name.IsCompound {
		return nil, nil, ErrEvidence
	}

	switch name.Tag {
	case 0:
		names, err := parseGeneralNames(ctx, name, true)
		return names, nil, err
	case 1:
		raw := der.Wrap(0, asn1.TagSet, true, name.Bytes)
		if _, err := der.Read(raw, 1<<20); err != nil {
			return nil, nil, ErrEvidence
		}

		var rdn pkix.RelativeDistinguishedNameSET
		if der.Unmarshal(raw, &rdn) != nil || len(rdn) == 0 || len(rdn) > 256 {
			return nil, nil, ErrEvidence
		}

		return nil, raw, nil
	default:
		return nil, nil, ErrEvidence
	}
}

func parseCRLDistributionPoints(ctx context.Context, raw []byte) ([]crlDistributionPoint, error) {
	value, err := der.Read(raw, 1<<20)
	if err != nil {
		return nil, ErrEvidence
	}

	fields, err := der.Sequence(value, 1, 256)
	if err != nil {
		return nil, ErrEvidence
	}

	out := make([]crlDistributionPoint, 0, len(fields))
	for _, value := range fields {
		fields, err := der.Sequence(value, 1, 3)
		if err != nil {
			return nil, ErrEvidence
		}

		point := crlDistributionPoint{reasons: allCRLReasons}

		previous := -1
		for _, field := range fields {
			if field.Class != 2 || field.Tag <= previous {
				return nil, ErrEvidence
			}

			previous = field.Tag
			switch field.Tag {
			case 0:
				point.names, point.relative, err = parseCRLPointName(ctx, field)
			case 1:
				point.reasonsPresent = true
				point.reasons, err = parseCRLReasonMask(field)
			case 2:
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
			if name.tag != 4 {
				return nil, ErrEvidence
			}
		}

		out = append(out, point)
	}

	return out, nil
}

func parseCRLScope(ctx context.Context, raw []byte) (crlScope, error) {
	scope := crlScope{reasons: allCRLReasons, raw: raw}

	value, err := der.Read(raw, 1<<20)
	if err != nil {
		return scope, ErrEvidence
	}

	fields, err := der.Sequence(value, 1, 6)
	if err != nil {
		return scope, ErrEvidence
	}

	previous := -1
	for _, field := range fields {
		if field.Class != 2 || field.Tag <= previous {
			return scope, ErrEvidence
		}

		previous = field.Tag
		switch field.Tag {
		case 0:
			scope.names, scope.relative, err = parseCRLPointName(ctx, field)
		case 3:
			scope.reasons, err = parseCRLReasonMask(field)
		case 1, 2, 4, 5:
			if field.IsCompound || len(field.Bytes) != 1 || field.Bytes[0] != 255 {
				return scope, ErrEvidence
			}

			switch field.Tag {
			case 1:
				scope.onlyUser = true
			case 2:
				scope.onlyCA = true
			case 4:
				scope.indirect = true
			case 5:
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
		if len(point.issuer) != 1 || point.issuer[0].tag != 4 {
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
	case 4:
		return a.key != "" && a.key == b.key
	case 1:
		return equalCRLMailbox(string(a.value), string(b.value))
	case 6:
		return crlURIKey(string(a.value)) == crlURIKey(string(b.value))
	case 2:
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
	if field.Class != 2 || field.Tag < 0 || field.Tag > 8 {
		return crlGeneralName{}, ErrEvidence
	}

	name := crlGeneralName{tag: field.Tag, value: field.Bytes}

	var err error

	switch field.Tag {
	case 4:
		if !field.IsCompound {
			return crlGeneralName{}, ErrEvidence
		}

		name, err = crlDirectoryName(ctx, field.Bytes)
		if err != nil {
			return crlGeneralName{}, err
		}
	case 1, 2, 6:
		if err := validateCRLIA5Name(field); err != nil {
			return crlGeneralName{}, err
		}

	case 7:
		if field.IsCompound || len(field.Bytes) != 4 && len(field.Bytes) != 16 {
			return crlGeneralName{}, ErrEvidence
		}
	case 8:
		if field.IsCompound {
			return crlGeneralName{}, ErrEvidence
		}

		var oid asn1.ObjectIdentifier
		if der.Unmarshal(der.Wrap(0, asn1.TagOID, false, field.Bytes), &oid) != nil {
			return crlGeneralName{}, ErrEvidence
		}
	case 0:
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
	if field.IsCompound || len(field.Bytes) == 0 {
		return ErrEvidence
	}

	for _, b := range field.Bytes {
		if b <= 32 || b >= 127 {
			return ErrEvidence
		}
	}

	if field.Tag == 6 {
		if !validCRLURI(string(field.Bytes)) {
			return ErrEvidence
		}
	}

	return nil
}
