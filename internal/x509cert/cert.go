// Package x509cert provides bounded parsing of original certificate encodings.
// It performs no trust, signature, validity or revocation checks.
package x509cert

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"net"

	"github.com/skarm/xmlsec/internal/der"
	"github.com/skarm/xmlsec/internal/lexicon"
)

const (
	defaultASN1Depth                 = 33
	defaultASN1Nodes                 = 100000
	defaultCertificateBytes          = 1 << 20
	maximumDistributionPoints        = 256
	maximumExtensionBytes            = 1 << 20
	maximumExtensions                = 256
	maximumGeneralNames              = 256
	relativeDistributionPointViewURI = "urn:xmlsec:private-relative-dp-view"
)

// X.509 schema bounds and context-specific tags, independent of the parser's
// byte, nesting and node budgets. Version values are the encoded integers.
const (
	certificateFields        = 3
	tbsMinimumFields         = 6
	tbsMaximumFields         = 10
	certificateVersionTag    = 0
	certificateExtensionsTag = 3
	certificateVersion1      = 0
	certificateVersion2      = 1
	certificateVersion3      = 2
	extensionMinimumFields   = 2
	extensionMaximumFields   = 3
)

// DistributionPoint and DistributionPointName use separate tagged schemas.
const (
	distributionPointNameTag    = 0
	distributionPointReasonsTag = 1
	distributionPointIssuerTag  = 2
	distributionPointMaxFields  = 3
	pointNameFullTag            = 0
	pointNameRelativeTag        = 1
)

// Limits bounds the private relative-distribution-point parsing view.
type Limits struct {
	// Bytes bounds the complete certificate DER encoding in bytes.
	Bytes int
	// Depth bounds ASN.1 nesting during structural validation.
	Depth int
	// Nodes bounds the number of ASN.1 values visited before certificate parsing.
	Nodes int
}

// ParseDefault uses the package's bounded 1MiB, 33-level and 100000-value profile.
// It borrows raw and performs no authentication or trust decision.
func ParseDefault(raw []byte) (*x509.Certificate, error) {
	return Parse(raw, Limits{Bytes: defaultCertificateBytes, Depth: defaultASN1Depth, Nodes: defaultASN1Nodes})
}

// ParseWithMaxBytes preserves the caller byte bound with shared depth/value caps.
// It borrows raw and performs no authentication or trust decision.
func ParseWithMaxBytes(raw []byte, maximum int) (*x509.Certificate, error) {
	return Parse(raw, Limits{Bytes: maximum, Depth: defaultASN1Depth, Nodes: defaultASN1Nodes})
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

	var outerFields [certificateFields]asn1.RawValue

	outer, err := checkedSequence(value, certificateFields, outerFields[:])
	if err != nil {
		return nil, err
	}

	var bodyFields [tbsMaximumFields]asn1.RawValue

	body, err := checkedSequence(outer[0], tbsMinimumFields, bodyFields[:])
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
		if field.Class != asn1.ClassContextSpecific || field.Tag != certificateExtensionsTag {
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
	if body[0].Class == asn1.ClassContextSpecific {
		offset++
	}

	if len(body) < offset+tbsMinimumFields {
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
	version, offset := certificateVersion1, 0

	if body[0].Class == asn1.ClassContextSpecific && body[0].Tag == certificateVersionTag {
		value, err := checkedExplicit(body[0], certificateVersionTag)
		if err != nil || !der.Is(value, asn1.ClassUniversal, asn1.TagInteger, false) || len(value.Bytes) != 1 || value.Bytes[0] < certificateVersion2 || value.Bytes[0] > certificateVersion3 {
			return der.ErrInvalidDER
		}

		version = int(value.Bytes[0])
		offset++
	}

	if len(body) < offset+tbsMinimumFields {
		return der.ErrInvalidDER
	}

	previous := 0
	for _, field := range body[offset+tbsMinimumFields:] {
		if field.Class != asn1.ClassContextSpecific || field.Tag <= previous || field.Tag > certificateExtensionsTag || version == certificateVersion1 || field.Tag == certificateExtensionsTag && version != certificateVersion3 {
			return der.ErrInvalidDER
		}

		previous = field.Tag
		if field.Tag == certificateExtensionsTag {
			value, err := checkedExplicit(field, certificateExtensionsTag)
			if err != nil || !der.Is(value, asn1.ClassUniversal, asn1.TagSequence, true) || len(value.Bytes) == 0 {
				return der.ErrInvalidDER
			}

			count := 0
			for content := value.Bytes; len(content) > 0; count++ {
				if count == maximumExtensions {
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
	value, err := der.Explicit(wrapper, certificateExtensionsTag)
	if err != nil {
		return nil, nil, false, err
	}

	fields, err := der.Sequence(value, 1, maximumExtensions)
	if err != nil {
		return nil, nil, false, err
	}

	originals := make([]pkix.Extension, 0, len(fields))
	parts := make([][]byte, len(fields))
	changed := false

	seen := make(map[string]struct{}, len(fields))
	for index, field := range fields {
		var extension pkix.Extension

		components, err := der.Sequence(field, extensionMinimumFields, extensionMaximumFields)
		if err != nil || der.Decode(field, &extension) != nil {
			return nil, nil, false, der.ErrInvalidDER
		}

		if _, exists := seen[extension.Id.String()]; exists {
			return nil, nil, false, der.ErrInvalidDER
		}

		if len(components) == extensionMaximumFields && !extension.Critical {
			return nil, nil, false, der.ErrInvalidDER
		}

		seen[extension.Id.String()] = struct{}{}
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

	return originals, der.Ctx(certificateExtensionsTag, der.Seq(parts...)), changed, nil
}

func relativePoints(raw []byte) ([]byte, bool, error) {
	value, err := der.Read(raw, maximumExtensionBytes)
	if err != nil {
		return nil, false, err
	}

	points, err := der.Sequence(value, 1, maximumDistributionPoints)
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

	names, err := der.ChildrenLimit(value, maximumGeneralNames)
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
	const derTrue = 0xff

	var scratch [extensionMaximumFields]asn1.RawValue

	fields, err := checkedSequence(extension, extensionMinimumFields, scratch[:])
	if err != nil {
		return err
	}

	if len(fields) == extensionMaximumFields {
		if !der.Is(fields[1], asn1.ClassUniversal, asn1.TagBoolean, false) || len(fields[1].Bytes) != 1 || fields[1].Bytes[0] != derTrue {
			return der.ErrInvalidDER
		}
	}

	return nil
}

func relativePoint(point asn1.RawValue) ([]byte, bool, error) {
	const reasonFlagCount = 9

	changed := false

	fields, err := der.Sequence(point, 1, distributionPointMaxFields)
	if err != nil {
		return nil, false, err
	}

	encoded := make([][]byte, len(fields))
	previous := -1
	named := false

	for position, field := range fields {
		if field.Class != asn1.ClassContextSpecific || field.Tag <= previous || field.Tag > distributionPointIssuerTag {
			return nil, false, der.ErrInvalidDER
		}

		previous = field.Tag

		encoded[position] = field.FullBytes
		switch field.Tag {
		case distributionPointNameTag:
			named = true

			encoded[position], changed, err = relativePointName(field)
			if err != nil {
				return nil, false, err
			}

		case distributionPointReasonsTag:
			var bits asn1.BitString
			if field.IsCompound || der.Unmarshal(der.Wrap(asn1.ClassUniversal, asn1.TagBitString, false, field.Bytes), &bits) != nil || bits.BitLength > reasonFlagCount || bits.At(0) != 0 {
				return nil, false, der.ErrInvalidDER
			}
		case distributionPointIssuerTag:
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
	if name.Class != asn1.ClassContextSpecific || name.Tag < lexicon.GeneralNameOtherName || name.Tag > lexicon.GeneralNameRegisteredID {
		return der.ErrInvalidDER
	}

	switch name.Tag {
	case lexicon.GeneralNameOtherName:
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
	case lexicon.GeneralNameDirectory:
		var dn pkix.RDNSequence
		if !name.IsCompound || der.Unmarshal(name.Bytes, &dn) != nil {
			return der.ErrInvalidDER
		}
	case lexicon.GeneralNameX400, lexicon.GeneralNameEDI:
		if !name.IsCompound {
			return der.ErrInvalidDER
		}
	case lexicon.GeneralNameRFC822, lexicon.GeneralNameDNS, lexicon.GeneralNameURI:
		return asciiGeneralName(name)

	case lexicon.GeneralNameIP:
		if name.IsCompound || len(name.Bytes) != net.IPv4len && len(name.Bytes) != net.IPv6len {
			return der.ErrInvalidDER
		}
	case lexicon.GeneralNameRegisteredID:
		var oid asn1.ObjectIdentifier
		if name.IsCompound || der.Unmarshal(der.Wrap(asn1.ClassUniversal, asn1.TagOID, false, name.Bytes), &oid) != nil {
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

		value, err := der.Read(extension.Value, maximumExtensionBytes)
		if err != nil {
			return nil, err
		}

		points, err := der.Sequence(value, 1, maximumDistributionPoints)
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
	fields, err := der.Sequence(point, 1, distributionPointMaxFields)
	if err != nil {
		return nil, err
	}

	for _, field := range fields {
		if field.Class != asn1.ClassContextSpecific || field.Tag != distributionPointNameTag {
			continue
		}

		choice, err := der.Explicit(field, distributionPointNameTag)
		if err != nil {
			return nil, err
		}

		if choice.Tag != pointNameFullTag {
			return nil, nil
		}

		names, err := der.ChildrenLimit(choice, maximumGeneralNames)
		if err != nil {
			return nil, err
		}

		var uris []string

		for _, name := range names {
			if name.Class == asn1.ClassContextSpecific && name.Tag == lexicon.GeneralNameURI {
				uris = append(uris, string(name.Bytes))
			}
		}

		return uris, nil
	}

	return nil, nil
}

func relativePointName(field asn1.RawValue) ([]byte, bool, error) {
	name, err := der.Explicit(field, distributionPointNameTag)
	if err != nil || name.Class != asn1.ClassContextSpecific || !name.IsCompound {
		return nil, false, der.ErrInvalidDER
	}

	if name.Tag == pointNameFullTag {
		if err := generalNames(name); err != nil {
			return nil, false, err
		}

		return field.FullBytes, false, nil
	}

	if name.Tag != pointNameRelativeTag {
		return nil, false, der.ErrInvalidDER
	}

	var rdn pkix.RelativeDistinguishedNameSET
	if der.Unmarshal(der.Wrap(asn1.ClassUniversal, asn1.TagSet, true, name.Bytes), &rdn) != nil || len(rdn) == 0 {
		return nil, false, der.ErrInvalidDER
	}

	return der.Ctx(distributionPointNameTag, der.Wrap(asn1.ClassContextSpecific, pointNameFullTag, true, der.Wrap(asn1.ClassContextSpecific, lexicon.GeneralNameURI, false, []byte(relativeDistributionPointViewURI)))), true, nil
}

func asciiGeneralName(name asn1.RawValue) error {
	const (
		firstPrintableASCII = 0x20
		asciiDelete         = 0x7f
	)

	if name.IsCompound || len(name.Bytes) == 0 {
		return der.ErrInvalidDER
	}

	for _, b := range name.Bytes {
		if b < firstPrintableASCII || b >= asciiDelete {
			return der.ErrInvalidDER
		}
	}

	return nil
}
