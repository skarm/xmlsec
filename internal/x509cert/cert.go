// Package x509cert provides bounded parsing of original certificate encodings.
// It performs no trust, signature, validity or revocation checks.
package x509cert

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"

	"github.com/skarm/xmlsec/internal/der"
)

// Limits bounds the private relative-distribution-point parsing view.
type Limits struct{ Bytes, Depth, Nodes int }

// ParseDefault uses the package's bounded 1MiB, 33-level and 100000-value profile.
// It borrows raw and performs no authentication or trust decision.
func ParseDefault(raw []byte) (*x509.Certificate, error) {
	return Parse(raw, Limits{Bytes: 1 << 20, Depth: 33, Nodes: 100000})
}

// ParseWithMaxBytes preserves the caller byte bound with shared depth/value caps.
// It borrows raw and performs no authentication or trust decision.
func ParseWithMaxBytes(raw []byte, maximum int) (*x509.Certificate, error) {
	return Parse(raw, Limits{Bytes: maximum, Depth: 33, Nodes: 100000})
}

// Parse returns a certificate borrowing raw. It preserves every signed byte.
// The standard parser only accepts fullName CRL distribution points. For valid
// nameRelativeToCRLIssuer points, a private parse view supplies a fullName and
// the original Raw/TBS/extensions are restored before the result can be used.
func Parse(raw []byte, limits Limits) (*x509.Certificate, error) {
	if len(raw) > limits.Bytes {
		return nil, der.ErrLimit
	}

	value, err := der.ReadLimits(raw, limits.Bytes, limits.Depth, limits.Nodes)
	if err != nil {
		return nil, err
	}

	var outerFields [3]asn1.RawValue

	outer, err := checkedSequence(value, 3, outerFields[:])
	if err != nil {
		return nil, err
	}

	var bodyFields [10]asn1.RawValue

	body, err := checkedSequence(outer[0], 6, bodyFields[:])
	if err != nil {
		return nil, err
	}

	if err := validateCertificateDefaults(body); err != nil {
		return nil, err
	}

	certificate, originalError := x509.ParseCertificate(raw)
	if originalError == nil {
		return certificate, nil
	}

	var (
		original []pkix.Extension
		changed  bool
	)

	parts := make([][]byte, len(body))
	for index, field := range body {
		parts[index] = field.FullBytes
		if field.Class != 2 || field.Tag != 3 {
			continue
		}

		original, parts[index], changed, err = relativeExtensions(field)
		if err != nil {
			return nil, err
		}
	}

	if !changed {
		return nil, originalError
	}

	certificate, err = x509.ParseCertificate(der.Seq(der.Seq(parts...), outer[1].FullBytes, outer[2].FullBytes))
	if err != nil {
		return nil, err
	}

	offset := 0
	if body[0].Class == 2 {
		offset++
	}

	if len(body) < offset+6 {
		return nil, der.ErrInvalidDER
	}

	certificate.Raw, certificate.RawTBSCertificate = raw, outer[0].FullBytes
	certificate.RawIssuer, certificate.RawSubject = body[offset+2].FullBytes, body[offset+4].FullBytes
	certificate.RawSubjectPublicKeyInfo = body[offset+5].FullBytes
	certificate.RawSignatureAlgorithm, certificate.Extensions = body[offset+1].FullBytes, original

	certificate.CRLDistributionPoints, err = originalCRLURIs(original)
	if err != nil {
		return nil, err
	}

	return certificate, nil
}

func validateCertificateDefaults(body []asn1.RawValue) error {
	version, offset := 0, 0

	if body[0].Class == 2 && body[0].Tag == 0 {
		value, err := checkedExplicit(body[0], 0)
		if err != nil || !der.Is(value, 0, asn1.TagInteger, false) || len(value.Bytes) != 1 || value.Bytes[0] < 1 || value.Bytes[0] > 2 {
			return der.ErrInvalidDER
		}

		version = int(value.Bytes[0])
		offset++
	}

	if len(body) < offset+6 {
		return der.ErrInvalidDER
	}

	previous := 0
	for _, field := range body[offset+6:] {
		if field.Class != 2 || field.Tag <= previous || field.Tag > 3 || version == 0 || field.Tag == 3 && version != 2 {
			return der.ErrInvalidDER
		}

		previous = field.Tag
		if field.Tag == 3 {
			value, err := checkedExplicit(field, 3)
			if err != nil || !der.Is(value, 0, asn1.TagSequence, true) || len(value.Bytes) == 0 {
				return der.ErrInvalidDER
			}

			count := 0
			for content := value.Bytes; len(content) > 0; count++ {
				if count == 256 {
					return errors.Join(der.ErrInvalidDER, der.ErrLimit)
				}

				extension, rest := checkedValue(content)
				if err := validateExtensionDefault(extension); err != nil {
					return err
				}

				content = rest
			}
		}
	}

	return nil
}

func relativeExtensions(wrapper asn1.RawValue) ([]pkix.Extension, []byte, bool, error) {
	value, err := der.Explicit(wrapper, 3)
	if err != nil {
		return nil, nil, false, err
	}

	fields, err := der.Sequence(value, 1, 256)
	if err != nil {
		return nil, nil, false, err
	}

	originals := make([]pkix.Extension, 0, len(fields))
	parts := make([][]byte, len(fields))
	changed := false

	seen := make(map[string]bool, len(fields))
	for index, field := range fields {
		var extension pkix.Extension

		components, err := der.Sequence(field, 2, 3)
		if err != nil || der.Decode(field, &extension) != nil || seen[extension.Id.String()] {
			return nil, nil, false, der.ErrInvalidDER
		}

		if len(components) == 3 && !extension.Critical {
			return nil, nil, false, der.ErrInvalidDER
		}

		seen[extension.Id.String()] = true
		originals = append(originals, extension)
		parts[index] = field.FullBytes

		if !extension.Id.Equal(asn1.ObjectIdentifier{2, 5, 29, 31}) {
			continue
		}

		patched, relative, err := relativePoints(extension.Value)
		if err != nil {
			return nil, nil, false, err
		}

		if !relative {
			continue
		}

		extension.Value = patched

		parts[index], err = asn1.Marshal(extension)
		if err != nil {
			return nil, nil, false, err
		}

		changed = true
	}

	return originals, der.Ctx(3, der.Seq(parts...)), changed, nil
}

func relativePoints(raw []byte) ([]byte, bool, error) {
	value, err := der.Read(raw, 1<<20)
	if err != nil {
		return nil, false, err
	}

	points, err := der.Sequence(value, 1, 256)
	if err != nil {
		return nil, false, err
	}

	changed := false

	parts := make([][]byte, len(points))
	for index, point := range points {
		encoded, relative, err := relativePoint(point)
		if err != nil {
			return nil, false, err
		}

		changed = changed || relative

		parts[index] = encoded
	}

	return der.Seq(parts...), changed, nil
}

func generalNames(value asn1.RawValue) error {
	if !value.IsCompound {
		return der.ErrInvalidDER
	}

	names, err := der.ChildrenLimit(value, 256)
	if err != nil || len(names) == 0 {
		return errors.Join(der.ErrInvalidDER, err)
	}

	for _, name := range names {
		if err := generalName(name); err != nil {
			return err
		}
	}

	return nil
}

func validateExtensionDefault(extension asn1.RawValue) error {
	var scratch [3]asn1.RawValue

	fields, err := checkedSequence(extension, 2, scratch[:])
	if err != nil {
		return err
	}

	if len(fields) == 3 {
		if !der.Is(fields[1], 0, asn1.TagBoolean, false) || len(fields[1].Bytes) != 1 || fields[1].Bytes[0] != 255 {
			return der.ErrInvalidDER
		}
	}

	return nil
}

func relativePoint(point asn1.RawValue) ([]byte, bool, error) {
	changed := false

	fields, err := der.Sequence(point, 1, 3)
	if err != nil {
		return nil, false, err
	}

	encoded := make([][]byte, len(fields))
	previous := -1
	named := false

	for position, field := range fields {
		if field.Class != 2 || field.Tag <= previous || field.Tag > 2 {
			return nil, false, der.ErrInvalidDER
		}

		previous = field.Tag

		encoded[position] = field.FullBytes
		switch field.Tag {
		case 0:
			named = true

			encoded[position], changed, err = relativePointName(field)
			if err != nil {
				return nil, false, err
			}

		case 1:
			var bits asn1.BitString
			if field.IsCompound || der.Unmarshal(der.Wrap(0, asn1.TagBitString, false, field.Bytes), &bits) != nil || bits.BitLength > 9 || bits.At(0) != 0 {
				return nil, false, der.ErrInvalidDER
			}
		case 2:
			named = true

			if err := generalNames(field); err != nil {
				return nil, false, err
			}
		}
	}

	if !named {
		return nil, false, der.ErrInvalidDER
	}

	return der.Seq(encoded...), changed, nil
}

func generalName(name asn1.RawValue) error {
	if name.Class != 2 || name.Tag < 0 || name.Tag > 8 {
		return der.ErrInvalidDER
	}

	switch name.Tag {
	case 0:
		fields, err := der.Children(name)
		if err != nil || len(fields) != 2 {
			return der.ErrInvalidDER
		}

		var oid asn1.ObjectIdentifier
		if der.Decode(fields[0], &oid) != nil {
			return der.ErrInvalidDER
		}

		if _, err := der.Explicit(fields[1], 0); err != nil {
			return err
		}
	case 4:
		var dn pkix.RDNSequence
		if !name.IsCompound || der.Unmarshal(name.Bytes, &dn) != nil {
			return der.ErrInvalidDER
		}
	case 3, 5:
		if !name.IsCompound {
			return der.ErrInvalidDER
		}
	case 1, 2, 6:
		return asciiGeneralName(name)

	case 7:
		if name.IsCompound || len(name.Bytes) != 4 && len(name.Bytes) != 16 {
			return der.ErrInvalidDER
		}
	case 8:
		var oid asn1.ObjectIdentifier
		if name.IsCompound || der.Unmarshal(der.Wrap(0, asn1.TagOID, false, name.Bytes), &oid) != nil {
			return der.ErrInvalidDER
		}
	}

	return nil
}

func originalCRLURIs(extensions []pkix.Extension) ([]string, error) {
	var uris []string

	for _, extension := range extensions {
		if !extension.Id.Equal(asn1.ObjectIdentifier{2, 5, 29, 31}) {
			continue
		}

		value, err := der.Read(extension.Value, 1<<20)
		if err != nil {
			return nil, err
		}

		points, err := der.Sequence(value, 1, 256)
		if err != nil {
			return nil, err
		}

		for _, point := range points {
			names, err := fullCRLPointURIs(point)
			if err != nil {
				return nil, err
			}

			uris = append(uris, names...)
		}
	}

	return uris, nil
}

func fullCRLPointURIs(point asn1.RawValue) ([]string, error) {
	fields, err := der.Sequence(point, 1, 3)
	if err != nil {
		return nil, err
	}

	for _, field := range fields {
		if field.Class != 2 || field.Tag != 0 {
			continue
		}

		choice, err := der.Explicit(field, 0)
		if err != nil {
			return nil, err
		}

		if choice.Tag != 0 {
			return nil, nil
		}

		names, err := der.ChildrenLimit(choice, 256)
		if err != nil {
			return nil, err
		}

		var uris []string

		for _, name := range names {
			if name.Class == 2 && name.Tag == 6 {
				uris = append(uris, string(name.Bytes))
			}
		}

		return uris, nil
	}

	return nil, nil
}

func relativePointName(field asn1.RawValue) ([]byte, bool, error) {
	name, err := der.Explicit(field, 0)
	if err != nil || name.Class != 2 || !name.IsCompound {
		return nil, false, der.ErrInvalidDER
	}

	if name.Tag == 0 {
		if err := generalNames(name); err != nil {
			return nil, false, err
		}

		return field.FullBytes, false, nil
	}

	if name.Tag != 1 {
		return nil, false, der.ErrInvalidDER
	}

	var rdn pkix.RelativeDistinguishedNameSET
	if der.Unmarshal(der.Wrap(0, asn1.TagSet, true, name.Bytes), &rdn) != nil || len(rdn) == 0 {
		return nil, false, der.ErrInvalidDER
	}

	return der.Ctx(0, der.Wrap(2, 0, true, der.Wrap(2, 6, false, []byte("urn:xmlsec:private-relative-dp-view")))), true, nil
}

func asciiGeneralName(name asn1.RawValue) error {
	if name.IsCompound || len(name.Bytes) == 0 {
		return der.ErrInvalidDER
	}

	for _, b := range name.Bytes {
		if b < 32 || b >= 127 {
			return der.ErrInvalidDER
		}
	}

	return nil
}
