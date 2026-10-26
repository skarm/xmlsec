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
	"github.com/skarm/xmlsec/internal/signature"
)

// ErrLimit identifies a configured byte/depth/node/entry budget, not malformed syntax.
var ErrLimit = errors.New("CRL decoder resource limit exceeded")

// Limits bounds decoding before the standard-library v2 allocation.
type Limits struct {
	Bytes   int
	Depth   int
	Nodes   int
	Entries int
}

// View preserves the exact signed header while providing the standard X.509 view.
// Returned byte slices borrow the input; callers that retain them must own input.
type View struct {
	CRL       *x509.RevocationList
	Version   int
	Algorithm pkix.AlgorithmIdentifier
}

// ParseEvidence applies the shared PKIX evidence structural bounds with an
// explicit caller byte cap. It preserves original bytes and performs no trust
// checks. Keys callers with configured ASN.1/entry budgets use Parse directly.
func ParseEvidence(raw []byte, maximum int) (*View, error) {
	return Parse(raw, Limits{Bytes: maximum, Depth: 33, Nodes: 1000000, Entries: 100000})
}

// Parse decodes one complete DER v1/v2 list. It never authenticates the result.
func Parse(raw []byte, limits Limits) (*View, error) {
	value, err := der.ReadLimits(raw, limits.Bytes, limits.Depth, limits.Nodes)
	if err != nil {
		if errors.Is(err, der.ErrLimit) {
			return nil, fmt.Errorf("%w: %w", ErrLimit, err)
		}

		return nil, err
	}

	outer, err := der.Sequence(value, 3, 3)
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

	if decoder.version == 0 {
		err = decoder.decodeV1Entries(entries)
	} else {
		decoder.list, err = x509.ParseRevocationList(raw)
	}

	if err != nil {
		return nil, err
	}

	return &View{CRL: decoder.list, Version: decoder.version, Algorithm: decoder.algorithm}, nil
}

type listDecoder struct {
	body      []asn1.RawValue
	index     int
	version   int
	list      *x509.RevocationList
	algorithm pkix.AlgorithmIdentifier
}

func (d *listDecoder) entries(maximum int) ([]asn1.RawValue, error) {
	var entries []asn1.RawValue

	if d.index < len(d.body) && der.Is(d.body[d.index], 0, asn1.TagSequence, true) {
		var err error

		entries, err = der.Sequence(d.body[d.index], 1, maximum)
		if err != nil {
			if errors.Is(err, der.ErrLimit) {
				return nil, fmt.Errorf("%w: %w", ErrLimit, err)
			}

			return nil, err
		}

		d.index++
	}

	for _, entry := range entries {
		if err := validateEntry(entry, d.version); err != nil {
			return nil, err
		}
	}

	if d.version == 1 && d.index < len(d.body) {
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
		fields, err := der.Sequence(entry, 2, 2)
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

func parseHeader(raw []byte, outer []asn1.RawValue) (*listDecoder, error) {
	body, err := der.Sequence(outer[0], 3, 7)
	if err != nil {
		return nil, err
	}

	decoder := &listDecoder{body: body}
	if der.Is(body[0], 0, asn1.TagInteger, false) {
		if der.Decode(body[0], &decoder.version) != nil || decoder.version != 1 {
			return nil, der.ErrInvalidDER
		}

		decoder.index++
	}

	index := decoder.index
	if len(body) < index+3 || !bytes.Equal(body[index].FullBytes, outer[1].FullBytes) {
		return nil, der.ErrInvalidDER
	}

	decoder.algorithm, err = signature.Algorithm(outer[1])
	if err != nil {
		return nil, err
	}

	var bits asn1.BitString
	if der.Decode(outer[2], &bits) != nil || bits.BitLength%8 != 0 || len(bits.Bytes) == 0 {
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

	decoder.index += 3

	index = decoder.index
	if index < len(body) && body[index].Class == 0 && (body[index].Tag == asn1.TagUTCTime || body[index].Tag == asn1.TagGeneralizedTime) {
		list.NextUpdate, err = parseTime(body[index])
		if err != nil {
			return nil, err
		}

		decoder.index++
	}

	decoder.list = list

	return decoder, nil
}

func validateEntry(entry asn1.RawValue, version int) error {
	fields, err := der.Sequence(entry, 2, 3)
	if err != nil {
		return err
	}

	if _, err := parseTime(fields[1]); err != nil {
		return err
	}

	if len(fields) == 3 {
		if version == 0 {
			return der.ErrInvalidDER
		}

		return validateExtensions(fields[2])
	}

	return nil
}

// validateExtensions checks schema-level constraints not covered by generic DER:
// the DEFAULT FALSE critical flag must be omitted, and extension IDs are unique.
func validateExtensions(value asn1.RawValue) error {
	fields, err := der.Sequence(value, 1, 32)
	if err != nil {
		return err
	}

	seen := make(map[string]struct{}, len(fields))
	for _, field := range fields {
		parts, err := der.Sequence(field, 2, 3)
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

		if len(parts) == 3 {
			var critical bool
			if der.Decode(parts[1], &critical) != nil || !critical {
				return der.ErrInvalidDER
			}
		}

		if !der.Is(parts[len(parts)-1], 0, asn1.TagOctetString, false) {
			return der.ErrInvalidDER
		}
	}

	return nil
}

func parseTime(value asn1.RawValue) (time.Time, error) {
	var at time.Time
	if value.Class != 0 || value.IsCompound || der.Decode(value, &at) != nil {
		return at, der.ErrInvalidDER
	}

	switch value.Tag {
	case asn1.TagUTCTime:
		if len(value.Bytes) != 13 || string(value.Bytes) != at.UTC().Format("060102150405Z") {
			return at, der.ErrInvalidDER
		}
	case asn1.TagGeneralizedTime:
		if len(value.Bytes) != 15 || at.Year() < 1 || string(value.Bytes) != at.UTC().Format("20060102150405Z") {
			return at, der.ErrInvalidDER
		}
	default:
		return at, der.ErrInvalidDER
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
		case "rsa":
			switch hash {
			case crypto.SHA256:
				return x509.SHA256WithRSA
			case crypto.SHA384:
				return x509.SHA384WithRSA
			case crypto.SHA512:
				return x509.SHA512WithRSA
			}
		case "pss":
			switch hash {
			case crypto.SHA256:
				return x509.SHA256WithRSAPSS
			case crypto.SHA384:
				return x509.SHA384WithRSAPSS
			case crypto.SHA512:
				return x509.SHA512WithRSAPSS
			}
		case "ecdsa":
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
		case "1.2.840.113549.1.1.5":
			return x509.SHA1WithRSA
		case "1.2.840.113549.1.1.4":
			return x509.MD5WithRSA
		}
	}

	if len(algorithm.Parameters.FullBytes) == 0 {
		switch algorithm.Algorithm.String() {
		case "1.2.840.10045.4.1":
			return x509.ECDSAWithSHA1
		case "1.2.840.10040.4.3":
			return x509.DSAWithSHA1
		case "2.16.840.1.101.3.4.3.2":
			return x509.DSAWithSHA256
		}
	}

	return x509.UnknownSignatureAlgorithm
}
