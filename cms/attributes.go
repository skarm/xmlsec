package cms

import (
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"math/big"
	"time"

	"github.com/skarm/xmlsec/internal/der"
	"github.com/skarm/xmlsec/internal/lexicon"
	"github.com/skarm/xmlsec/internal/signature"
	"github.com/skarm/xmlsec/internal/x509cert"
	"github.com/skarm/xmlsec/internal/x509name"
)

// SigningCertificate and SigningCertificateV2 contain required certificate IDs
// and optional policies; binding and trust paths validate this same envelope.
const (
	signingCertificateMinimumFields = 1
	signingCertificateMaximumFields = 2
)

const (
	maximumAlgorithmIdentifierBytes = 8192
	// Bounds DER for CMS attribute values and their aggregate encoding, in bytes.
	maximumAttributeBytes  = 1 << 20
	maximumAttributeValues = 64
	maximumIssuerNames     = 32
	// Caps certificate references in a CMS signing-certificate attribute.
	maximumSigningCertificateIDs = 32
	maximumSigningPolicies       = 32
	maximumSigningTimeBytes      = 32
	maximumUTCTimeYear           = 2049
	minimumUTCTimeYear           = 1950
)

// Context-specific tags in distinct CMS attribute schemas. An unsigned-attribute
// section and an algorithm-protection signature field happen to both use [1].
const (
	signedAttributesTag             = 0
	unsignedAttributesTag           = 1
	algorithmProtectionSignatureTag = 1
)

// Attribute contains an attribute type OID and complete DER-encoded values.
// Result accessors copy the attribute and its mutable values. Authenticating an
// attribute does not establish its meaning for the application.
type Attribute struct {
	// OID identifies the attribute type.
	OID asn1.ObjectIdentifier
	// ValuesDER contains the complete DER encoding of each attribute value.
	ValuesDER [][]byte
}

// CertificateBindingAttribute encodes ESSCertIDv2 using default SHA-256 and an
// issuerSerial identifying the exact certificate (RFC 5035 / RFC 5816).
func CertificateBindingAttribute(b []byte) (Attribute, error) {
	if len(b) > maximumCertificateBytes {
		return Attribute{}, ErrPolicy
	}

	cert, err := x509cert.ParseDefault(b)
	if err != nil || cert.SerialNumber == nil {
		return Attribute{}, ErrCertificate
	}

	sum, _ := signature.Sum(crypto.SHA256, cert.Raw)
	serial, _ := asn1.Marshal(cert.SerialNumber)
	issuer := der.Seq(der.Seq(der.Ctx(lexicon.GeneralNameDirectory, cert.RawIssuer)), serial)
	id := der.Seq(der.Octets(sum), issuer)

	return Attribute{
		OID:       append(asn1.ObjectIdentifier(nil), oidSigningCertificateV2()...),
		ValuesDER: [][]byte{der.Seq(der.Seq(id))},
	}, nil
}

func verifyESS(ctx context.Context, attrs []Attribute, cert *x509.Certificate, legacy bool) (bool, error) {
	bound := false

	for _, v2 := range []bool{false, true} {
		oid := oidSigningCertificate()
		if v2 {
			oid = oidSigningCertificateV2()
		}

		raw, ok, err := attributeValue(attrs, oid)
		if err != nil {
			return false, err
		}

		if !ok {
			continue
		}

		if !v2 && !legacy {
			return false, ErrPolicy
		}

		if err := verifyESSAttribute(ctx, raw, cert, v2); err != nil {
			return false, err
		}

		bound = true
	}

	return bound, nil
}

func verifyESSAttribute(ctx context.Context, raw []byte, cert *x509.Certificate, v2 bool) error {
	v, err := der.Read(raw, maximumAttributeBytes)
	if err != nil {
		return ErrSyntax
	}

	top, err := der.Sequence(v, signingCertificateMinimumFields, signingCertificateMaximumFields)
	if err != nil {
		return ErrSyntax
	}

	ids, err := der.Sequence(top[0], 1, maximumSigningCertificateIDs)
	if err != nil {
		return ErrSyntax
	}

	for i, id := range ids {
		if err := verifyESSCertID(ctx, id, cert, v2, i == 0); err != nil {
			return err
		}
	}

	if len(top) == signingCertificateMaximumFields {
		if err := validateESSPolicies(ctx, top[1]); err != nil {
			return err
		}
	}

	return nil
}

// RFC 5035 policies are advisory and do not select the verifier's trust policy.
// Their PolicyInformation and PolicyQualifierInfo containers still require the
// declared ASN.1 structure. Qualifier meanings remain application-owned.
func validateESSPolicies(ctx context.Context, value asn1.RawValue) error {
	// PolicyInformation has an OID and optional qualifiers. A qualifier
	// itself contains its type OID and one encoded value.
	const (
		policyInformationMinimumFields = 1
		policyInformationMaximumFields = 2
		policyQualifierFields          = 2
	)

	policies, err := der.Sequence(value, 1, maximumSigningPolicies)
	if err != nil {
		return ErrSyntax
	}

	for _, policy := range policies {
		if err := ctx.Err(); err != nil {
			return err
		}

		fields, err := der.Sequence(policy, policyInformationMinimumFields, policyInformationMaximumFields)
		if err != nil || !der.Is(fields[0], asn1.ClassUniversal, asn1.TagOID, false) {
			return ErrSyntax
		}

		if len(fields) == policyInformationMinimumFields {
			continue
		}

		qualifiers := fields[1]
		if !der.Is(qualifiers, asn1.ClassUniversal, asn1.TagSequence, true) || len(qualifiers.Bytes) == 0 {
			return ErrSyntax
		}

		// The enclosing ESS value has passed der.Read, including the shared
		// node budget. Iterate without materializing another qualifier slice.
		for qualifier := range der.ValidatedChildren(qualifiers) {
			if err := ctx.Err(); err != nil {
				return err
			}

			parts, err := der.Sequence(qualifier, policyQualifierFields, policyQualifierFields)
			if err != nil || !der.Is(parts[0], asn1.ClassUniversal, asn1.TagOID, false) {
				return ErrSyntax
			}
		}
	}

	return nil
}

func verifyESSCertID(ctx context.Context, v asn1.RawValue, cert *x509.Certificate, v2, signer bool) error {
	// ESSCertIDv2 has a required hash plus optional hashAlgorithm and issuerSerial.
	const (
		minimumESSCertIDFields = 1
		maximumESSCertIDFields = 3
	)

	fields, err := der.Sequence(v, minimumESSCertIDFields, maximumESSCertIDFields)
	if err != nil {
		return ErrSyntax
	}

	h, sum, index, err := parseESSCertHash(fields, v2)
	if err != nil {
		return err
	}

	if signer {
		want, _ := signature.Sum(h, cert.Raw)
		if !bytes.Equal(sum, want) {
			return ErrCertificate
		}
	}

	if index < len(fields) {
		names, serial, err := parseESSIssuer(fields[index])
		if err != nil {
			return err
		}

		if signer {
			if err := verifyESSIssuer(ctx, names, serial, cert); err != nil {
				return err
			}
		}

		index++
	}

	if index != len(fields) {
		return ErrSyntax
	}

	return nil
}

func parseESSCertHash(fields []asn1.RawValue, v2 bool) (crypto.Hash, []byte, int, error) {
	h := crypto.SHA1
	index := 0

	if v2 {
		h = crypto.SHA256

		if der.Is(fields[0], asn1.ClassUniversal, asn1.TagSequence, true) {
			algorithm, err := signature.Algorithm(fields[0])
			if err != nil {
				return 0, nil, 0, ErrSyntax
			}

			h, err = signature.Hash(algorithm, false)
			if err != nil {
				return 0, nil, 0, ErrPolicy
			}

			if h == crypto.SHA256 {
				return 0, nil, 0, ErrSyntax
			}

			index++
		}
	}

	if index >= len(fields) {
		return 0, nil, 0, ErrSyntax
	}

	var sum []byte
	if der.Decode(fields[index], &sum) != nil || len(sum) != h.Size() {
		return 0, nil, 0, ErrSyntax
	}

	return h, sum, index + 1, nil
}

func parseESSIssuer(v asn1.RawValue) ([]asn1.RawValue, *big.Int, error) {
	const issuerSerialFields = 2 // GeneralNames and certificate serial number

	issuer, err := der.Sequence(v, issuerSerialFields, issuerSerialFields)
	if err != nil {
		return nil, nil, ErrSyntax
	}

	names, err := der.Sequence(issuer[0], 1, maximumIssuerNames)
	if err != nil {
		return nil, nil, ErrSyntax
	}

	var serial *big.Int
	if der.Decode(issuer[1], &serial) != nil || serial == nil || serial.Sign() <= 0 {
		return nil, nil, ErrSyntax
	}

	return names, serial, nil
}

func verifyESSIssuer(ctx context.Context, names []asn1.RawValue, serial *big.Int, cert *x509.Certificate) error {
	// RFC5035 section4: a public-key certificate's issuerSerial contains only
	// its issuer's directoryName, not a matching name among unrelated aliases.
	if len(names) != 1 || !der.Is(names[0], asn1.ClassContextSpecific, lexicon.GeneralNameDirectory, true) {
		return ErrCertificate
	}

	directory, err := der.Explicit(names[0], lexicon.GeneralNameDirectory)
	if err != nil {
		return ErrSyntax
	}

	equal, err := x509name.EqualOrExact(ctx, directory.FullBytes, cert.RawIssuer)
	if err != nil {
		return fmt.Errorf("%w: ESS issuer name: %w", ErrCertificate, err)
	}

	if !equal || serial.Cmp(cert.SerialNumber) != 0 {
		return ErrCertificate
	}

	return nil
}

func verifyProtection(attrs []Attribute, alg pkix.AlgorithmIdentifier, h crypto.Hash) error {
	// The supported algorithm-protection form binds digest and signature algorithms.
	const algorithmProtectionFields = 2

	raw, ok, e := attributeValue(attrs, oidAlgorithmProtect())
	if e != nil {
		return e
	}

	if !ok {
		return nil
	}

	v, e := der.Read(raw, maximumAlgorithmIdentifierBytes)
	if e != nil {
		return ErrSyntax
	}

	f, e := der.Sequence(v, algorithmProtectionFields, algorithmProtectionFields)
	if e != nil {
		return ErrSyntax
	}

	a, e := signature.Algorithm(f[0])
	if e != nil {
		return ErrSyntax
	}

	ah, e := signature.Hash(a, false)
	if e != nil || ah != h {
		return ErrSignature
	}

	if !der.Is(f[1], asn1.ClassContextSpecific, algorithmProtectionSignatureTag, true) {
		return ErrSyntax
	}

	s := asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true, Bytes: f[1].Bytes}

	sa, e := signature.Algorithm(s)
	if e != nil {
		return ErrSyntax
	}
	// RFC 6211 section 3.1 protects the identifier itself. rsaEncryption and
	// sha256WithRSAEncryption describe compatible operations in CMS, but they
	// are distinct OIDs and must not be normalized into an apparent match.
	if !alg.Algorithm.Equal(sa.Algorithm) {
		return ErrSignature
	}

	actual, e := normalizeSignature(alg, h)
	if e != nil {
		return e
	}

	protected, e := normalizeSignature(sa, h)
	if e != nil {
		return e
	}

	ha, ma, ea := signature.Details(actual)
	hb, mb, eb := signature.Details(protected)

	if ea != nil || eb != nil || ha != hb || ma != mb {
		return ErrSignature
	}

	return nil
}

func cloneAttributes(attrs []Attribute) []Attribute {
	o := make([]Attribute, len(attrs))
	for i, v := range attrs {
		o[i].OID = append(asn1.ObjectIdentifier(nil), v.OID...)
		for _, b := range v.ValuesDER {
			o[i].ValuesDER = append(o[i].ValuesDER, bytes.Clone(b))
		}
	}

	return o
}

func parseAttributes(v asn1.RawValue, tag, maximum int) ([]Attribute, error) {
	const attributeFields = 2 // attribute type OID and SET OF values

	f, e := der.SetFields(v, asn1.ClassContextSpecific, tag, maximum)
	if e != nil || len(f) == 0 {
		return nil, ErrSyntax
	}

	out := make([]Attribute, 0, len(f))
	seen := map[string]struct{}{}

	for _, field := range f {
		a, e := der.Sequence(field, attributeFields, attributeFields)
		if e != nil {
			return nil, ErrSyntax
		}

		var o asn1.ObjectIdentifier
		if der.Decode(a[0], &o) != nil {
			return nil, ErrSyntax
		}

		key := o.String()

		if _, exists := seen[key]; exists || !attributePlacement(o, tag) {
			return nil, ErrSyntax
		}

		seen[key] = struct{}{}

		vals, e := der.SetFields(a[1], asn1.ClassUniversal, asn1.TagSet, maximumAttributeValues)
		if e != nil || len(vals) == 0 {
			return nil, ErrSyntax
		}

		x := Attribute{OID: o}
		for _, v := range vals {
			x.ValuesDER = append(x.ValuesDER, v.FullBytes)
		}

		if tag == signedAttributesTag {
			if err := validateSigningTime(x); err != nil {
				return nil, ErrSyntax
			}
		}

		out = append(out, x)
	}

	return out, nil
}

func attributeValue(attrs []Attribute, oid asn1.ObjectIdentifier) ([]byte, bool, error) {
	for _, x := range attrs {
		if x.OID.Equal(oid) {
			if len(x.ValuesDER) != 1 {
				return nil, true, ErrSyntax
			}

			return x.ValuesDER[0], true, nil
		}
	}

	return nil, false, nil
}

func encodeAttributes(attrs []Attribute, maximum int) ([]byte, error) {
	if len(attrs) < minimumAttributes || len(attrs) > maximum {
		return nil, ErrPolicy
	}

	seen := map[string]struct{}{}

	var parts [][]byte

	total := 0

	for _, x := range attrs {
		key := x.OID.String()
		if _, exists := seen[key]; exists || len(x.ValuesDER) < 1 || len(x.ValuesDER) > maximumAttributeValues || !attributePlacement(x.OID, signedAttributesTag) {
			return nil, ErrPolicy
		}

		if err := validateSigningTime(x); err != nil {
			return nil, ErrPolicy
		}

		seen[key] = struct{}{}

		oid := der.OID(x.OID)
		if len(oid) == 0 {
			return nil, ErrPolicy
		}

		for _, b := range x.ValuesDER {
			total += len(b)
			if total > maximumAttributeBytes {
				return nil, ErrPolicy
			}

			if _, e := der.Read(b, maximumAttributeBytes); e != nil {
				return nil, fmt.Errorf("%w: attribute value: %w", ErrPolicy, e)
			}
		}

		parts = append(parts, der.Seq(oid, der.Set(x.ValuesDER...)))
	}

	return der.Set(parts...), nil
}

// attributePlacement enforces the section constraints of RFC 5652 sections
// 11.1--11.4, RFC 6211 section 2, and RFC 5035 section 3 / RFC 2634 section 5.
// Unknown attributes retain the caller's responsibility for their semantics.
func attributePlacement(oid asn1.ObjectIdentifier, tag int) bool {
	if tag == signedAttributesTag {
		return !oid.Equal(oidCountersignature())
	}

	return !oid.Equal(oidContentType()) && !oid.Equal(oidMessageDigest()) &&
		!oid.Equal(oidSigningTime()) && !oid.Equal(oidAlgorithmProtect()) &&
		!oid.Equal(oidSigningCertificate()) && !oid.Equal(oidSigningCertificateV2())
}

// SigningTime is only an untrusted assertion of time even when signed. Validate
// its required syntax (RFC 5652 section 11.3), never use it as a trust clock.
func validateSigningTime(attr Attribute) error {
	if !attr.OID.Equal(oidSigningTime()) {
		return nil
	}

	if len(attr.ValuesDER) != 1 {
		return ErrSyntax
	}

	v, err := der.Read(attr.ValuesDER[0], maximumSigningTimeBytes)
	if err != nil {
		return ErrSyntax
	}

	var instant time.Time
	if der.Decode(v, &instant) != nil {
		return ErrSyntax
	}

	var text string

	switch {
	case der.Is(v, asn1.ClassUniversal, asn1.TagUTCTime, false):
		text = instant.UTC().Format(lexicon.ASN1UTCTimeLayout)
	case der.Is(v, asn1.ClassUniversal, asn1.TagGeneralizedTime, false):
		if instant.Year() >= minimumUTCTimeYear && instant.Year() <= maximumUTCTimeYear || instant.Year() < 1 {
			return ErrSyntax
		}

		text = instant.UTC().Format(lexicon.ASN1GeneralizedTimeLayout)
	default:
		return ErrSyntax
	}

	if !bytes.Equal(v.Bytes, []byte(text)) {
		return fmt.Errorf("%w: signingTime encoding", ErrSyntax)
	}

	return nil
}
