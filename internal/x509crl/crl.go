// Package x509crl decodes bounded original X.509 CertificateList bytes. It
// performs no issuer authorization, signature verification or revocation policy.
package x509crl

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/skarm/xmlsec/internal/der"
	"github.com/skarm/xmlsec/internal/lexicon"
	"github.com/skarm/xmlsec/internal/signature"
)

// CRL versions are encoded ASN.1 integers. Every revoked entry starts with a
// serial number and revocation date; v2 may add entry extensions.
const (
	encodedCRLVersion1         = 0
	encodedCRLVersion2         = 1
	revokedEntryRequiredFields = 2
)

const (
	evidenceASN1Depth      = 33
	evidenceASN1Nodes      = 1000000
	evidenceMaxEntries     = 100000
	generalizedTimeBytes   = 15
	maximumEntryExtensions = 32
	utcTimeBytes           = 13
	utcTimePivotYear       = 2050
	yearsPerCentury        = 100
)

const (
	oidDSAWithSHA1   = "1.2.840.10040.4.3"
	oidDSAWithSHA256 = "2.16.840.1.101.3.4.3.2"
	oidECDSAWithSHA1 = "1.2.840.10045.4.1"
	oidMD5WithRSA    = "1.2.840.113549.1.1.4"
	oidSHA1WithRSA   = "1.2.840.113549.1.1.5"
)

// ErrLimit identifies a configured byte/depth/node/entry budget, not malformed syntax.
var ErrLimit = errors.New("CRL decoder resource limit exceeded")

// Limits bounds decoding before the standard-library v2 allocation.
type Limits struct {
	// Bytes bounds the complete CRL DER encoding in bytes.
	Bytes int
	// Depth bounds ASN.1 nesting during structural validation.
	Depth int
	// Nodes bounds the number of ASN.1 values visited.
	Nodes int
	// Entries bounds revoked certificate entries before standard-library
	// allocation.
	Entries int
}

// View preserves the exact signed header while providing the standard X.509 view.
// Returned byte slices borrow the input; callers that retain them must own input.
type View struct {
	// CRL is the parsed, unauthenticated standard-library view.
	CRL *x509.RevocationList
	// Version is the encoded ASN.1 version value; an absent version is zero.
	Version int
	// Algorithm preserves the signed header's signature algorithm identifier.
	Algorithm pkix.AlgorithmIdentifier
}

type listDecoder struct {
	body      []asn1.RawValue
	index     int
	version   int
	list      *x509.RevocationList
	algorithm pkix.AlgorithmIdentifier
}

// ParseEvidence applies the shared PKIX evidence structural bounds with an
// explicit caller byte cap. It preserves original bytes and performs no trust
// checks. Keys callers with configured ASN.1/entry budgets use Parse directly.
func ParseEvidence(raw []byte, maximum int) (*View, error) {
	return Parse(raw, Limits{Bytes: maximum, Depth: evidenceASN1Depth, Nodes: evidenceASN1Nodes, Entries: evidenceMaxEntries})
}

// Parse decodes one complete DER v1/v2 list. It never authenticates the result.
func Parse(raw []byte, limits Limits) (*View, error) {
	// CertificateList contains TBSCertList, signatureAlgorithm and signatureValue.
	const certificateListFields = 3

	value, err := der.ReadLimits(raw, limits.Bytes, limits.Depth, limits.Nodes)
	if err != nil {
		if errors.Is(err, der.ErrLimit) {
			return nil, fmt.Errorf("%w: %w", ErrLimit, err)
		}

		return nil, err
	}

	outer, err := der.Sequence(value, certificateListFields, certificateListFields)
	if err != nil {
		return nil, err
	}

	decoder, err := parseHeader(raw, outer)
	if err != nil {
		return nil, err
	}

	entries, err := decoder.entries(limits.Entries)
	if err != nil {
		return nil, err
	}

	if decoder.version == encodedCRLVersion1 {
		err = decoder.decodeV1Entries(entries)
	} else {
		decoder.list, err = x509.ParseRevocationList(raw)
	}

	if err != nil {
		return nil, err
	}

	return &View{CRL: decoder.list, Version: decoder.version, Algorithm: decoder.algorithm}, nil
}

func parseHeader(raw []byte, outer []asn1.RawValue) (*listDecoder, error) {
	// Signature, issuer and thisUpdate are mandatory. Version, nextUpdate,
	// revokedCertificates and extensions account for the optional fields.
	const (
		tbsRequiredFields  = 3
		tbsMaximumFields   = 7
		signatureOctetBits = 8
	)

	body, err := der.Sequence(outer[0], tbsRequiredFields, tbsMaximumFields)
	if err != nil {
		return nil, err
	}

	decoder := &listDecoder{body: body}
	if der.Is(body[0], asn1.ClassUniversal, asn1.TagInteger, false) {
		if der.Decode(body[0], &decoder.version) != nil || decoder.version != encodedCRLVersion2 {
			return nil, der.ErrInvalidDER
		}

		decoder.index++
	}

	index := decoder.index
	if len(body) < index+tbsRequiredFields || !bytes.Equal(body[index].FullBytes, outer[1].FullBytes) {
		return nil, der.ErrInvalidDER
	}

	decoder.algorithm, err = signature.Algorithm(outer[1])
	if err != nil {
		return nil, err
	}

	var bits asn1.BitString
	if der.Decode(outer[2], &bits) != nil || bits.BitLength%signatureOctetBits != 0 || len(bits.Bytes) == 0 {
		return nil, der.ErrInvalidDER
	}

	list := &x509.RevocationList{Raw: raw, RawTBSRevocationList: outer[0].FullBytes, RawIssuer: body[index+1].FullBytes, RawSignatureAlgorithm: outer[1].FullBytes, Signature: bits.Bytes}

	var issuer pkix.RDNSequence
	if der.Decode(body[index+1], &issuer) != nil || len(issuer) == 0 {
		return nil, der.ErrInvalidDER
	}

	list.Issuer.FillFromRDNSequence(&issuer)

	list.ThisUpdate, err = parseTime(body[index+2])
	if err != nil {
		return nil, err
	}

	decoder.index += tbsRequiredFields

	index = decoder.index
	if index < len(body) && body[index].Class == asn1.ClassUniversal && (body[index].Tag == asn1.TagUTCTime || body[index].Tag == asn1.TagGeneralizedTime) {
		list.NextUpdate, err = parseTime(body[index])
		if err != nil {
			return nil, err
		}

		decoder.index++
	}

	decoder.list = list

	return decoder, nil
}

func (d *listDecoder) entries(maximum int) ([]asn1.RawValue, error) {
	var entries []asn1.RawValue

	if d.index < len(d.body) && der.Is(d.body[d.index], asn1.ClassUniversal, asn1.TagSequence, true) {
		sequence := d.body[d.index]
		count := 0
		// Count before schema checks, preserving entry-budget precedence.
		// Full DER validation has already checked every header and value.
		for range der.ValidatedChildren(sequence) {
			if count >= maximum {
				return nil, errors.Join(ErrLimit, der.ErrInvalidDER, der.ErrLimit)
			}

			count++
		}

		if count == 0 {
			return nil, der.ErrInvalidDER
		}

		if d.version == encodedCRLVersion1 {
			entries = make([]asn1.RawValue, 0, count)
		}

		for entry := range der.ValidatedChildren(sequence) {
			if err := validateEntry(entry, d.version); err != nil {
				return nil, err
			}
			// v2 is decoded by crypto/x509 below. Only v1 needs these views.
			if d.version == encodedCRLVersion1 {
				entries = append(entries, entry)
			}
		}

		d.index++
	}

	if d.version == encodedCRLVersion2 && d.index < len(d.body) {
		extension, err := der.Explicit(d.body[d.index], 0)
		if err != nil {
			return nil, err
		}

		if err := validateExtensions(extension); err != nil {
			return nil, err
		}

		d.index++
	}

	if d.index != len(d.body) {
		return nil, der.ErrInvalidDER
	}

	return entries, nil
}

func (d *listDecoder) decodeV1Entries(entries []asn1.RawValue) error {
	for _, entry := range entries {
		var scratch [revokedEntryRequiredFields]asn1.RawValue

		fields, err := der.ValidatedSequence(entry, revokedEntryRequiredFields, scratch[:])
		if err != nil {
			return err
		}

		var serial *big.Int
		if der.Decode(fields[0], &serial) != nil || serial == nil {
			return der.ErrInvalidDER
		}

		revoked, err := parseTime(fields[1])
		if err != nil {
			return err
		}

		d.list.RevokedCertificateEntries = append(d.list.RevokedCertificateEntries, x509.RevocationListEntry{Raw: entry.FullBytes, SerialNumber: serial, RevocationTime: revoked})
	}

	d.list.SignatureAlgorithm = signatureAlgorithm(d.algorithm)

	return nil
}

func validateEntry(entry asn1.RawValue, version int) error {
	// Entry extensions are the third, optional field permitted only in v2.
	const maximumRevokedEntryFields = 3

	var scratch [maximumRevokedEntryFields]asn1.RawValue

	fields, err := der.ValidatedSequence(entry, revokedEntryRequiredFields, scratch[:])
	if err != nil {
		return err
	}

	if _, err := parseTime(fields[1]); err != nil {
		return err
	}

	if len(fields) == maximumRevokedEntryFields {
		if version == encodedCRLVersion1 {
			return der.ErrInvalidDER
		}

		return validateExtensions(fields[2])
	}

	return nil
}

// validateExtensions checks schema-level constraints not covered by generic DER:
// the DEFAULT FALSE critical flag must be omitted, and extension IDs are unique.
func validateExtensions(value asn1.RawValue) error {
	// Extension contains extnID, optional critical, and extnValue.
	const (
		extensionMinimumFields = 2
		extensionMaximumFields = 3
	)

	fields, err := der.Sequence(value, 1, maximumEntryExtensions)
	if err != nil {
		return err
	}

	seen := make(map[string]struct{}, len(fields))
	for _, field := range fields {
		parts, err := der.Sequence(field, extensionMinimumFields, extensionMaximumFields)
		if err != nil {
			return err
		}

		var oid asn1.ObjectIdentifier
		if der.Decode(parts[0], &oid) != nil {
			return der.ErrInvalidDER
		}

		if _, exists := seen[oid.String()]; exists {
			return der.ErrInvalidDER
		}

		seen[oid.String()] = struct{}{}

		if len(parts) == extensionMaximumFields {
			var critical bool
			if der.Decode(parts[1], &critical) != nil || !critical {
				return der.ErrInvalidDER
			}
		}

		if !der.Is(parts[len(parts)-1], asn1.ClassUniversal, asn1.TagOctetString, false) {
			return der.ErrInvalidDER
		}
	}

	return nil
}

func parseTime(value asn1.RawValue) (time.Time, error) {
	if value.Class != asn1.ClassUniversal || value.IsCompound {
		return time.Time{}, der.ErrInvalidDER
	}
	// PKIX requires seconds and a literal Z. Decoding that exact form avoids
	// encoding/asn1's failed minute-only parse and a redundant format pass.
	var layout string

	switch value.Tag {
	case asn1.TagUTCTime:
		if len(value.Bytes) != utcTimeBytes {
			return time.Time{}, der.ErrInvalidDER
		}

		layout = lexicon.ASN1UTCTimeLayout
	case asn1.TagGeneralizedTime:
		if len(value.Bytes) != generalizedTimeBytes {
			return time.Time{}, der.ErrInvalidDER
		}

		layout = lexicon.ASN1GeneralizedTimeLayout
	default:
		return time.Time{}, der.ErrInvalidDER
	}

	at, err := time.Parse(layout, string(value.Bytes))
	if err != nil || at.Year() < 1 {
		return time.Time{}, der.ErrInvalidDER
	}

	// ASN.1 uses a 1950 century pivot; time.Parse uses 1969.
	if value.Tag == asn1.TagUTCTime && at.Year() >= utcTimePivotYear {
		at = at.AddDate(-yearsPerCentury, 0, 0)
	}

	return at, nil
}

func signatureAlgorithm(algorithm pkix.AlgorithmIdentifier) x509.SignatureAlgorithm {
	if algorithm.Algorithm.Equal(asn1.ObjectIdentifier{1, 3, 101, 112}) && len(algorithm.Parameters.FullBytes) == 0 {
		return x509.PureEd25519
	}

	hash, mode, err := signature.Details(algorithm)
	if err == nil {
		switch mode {
		case lexicon.SignatureFamilyRSA:
			switch hash {
			case crypto.SHA256:
				return x509.SHA256WithRSA
			case crypto.SHA384:
				return x509.SHA384WithRSA
			case crypto.SHA512:
				return x509.SHA512WithRSA
			}
		case lexicon.SignatureFamilyRSAPSS:
			switch hash {
			case crypto.SHA256:
				return x509.SHA256WithRSAPSS
			case crypto.SHA384:
				return x509.SHA384WithRSAPSS
			case crypto.SHA512:
				return x509.SHA512WithRSAPSS
			}
		case lexicon.SignatureFamilyECDSA:
			switch hash {
			case crypto.SHA256:
				return x509.ECDSAWithSHA256
			case crypto.SHA384:
				return x509.ECDSAWithSHA384
			case crypto.SHA512:
				return x509.ECDSAWithSHA512
			}
		}
	}

	if signature.NullOrAbsent(algorithm.Parameters) {
		switch algorithm.Algorithm.String() {
		case oidSHA1WithRSA:
			return x509.SHA1WithRSA
		case oidMD5WithRSA:
			return x509.MD5WithRSA
		}
	}

	if len(algorithm.Parameters.FullBytes) == 0 {
		switch algorithm.Algorithm.String() {
		case oidECDSAWithSHA1:
			return x509.ECDSAWithSHA1
		case oidDSAWithSHA1:
			return x509.DSAWithSHA1
		case oidDSAWithSHA256:
			return x509.DSAWithSHA256
		}
	}

	return x509.UnknownSignatureAlgorithm
}
