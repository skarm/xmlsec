package cms

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"math/big"
	"time"

	"github.com/skarm/xmlsec/internal/der"
	"github.com/skarm/xmlsec/internal/signature"
)

// Attribute pairs an OID with complete DER-encoded values. A signature over an
// attribute does not establish its application semantics. Result accessors return
// owned copies of attributes and their value slices.
type Attribute struct {
	OID       asn1.ObjectIdentifier
	ValuesDER [][]byte
}

// CertificateBindingAttribute encodes ESSCertIDv2 using default SHA-256 and an
// issuerSerial identifying the exact certificate (RFC 5035 / RFC 5816).
func CertificateBindingAttribute(b []byte) (Attribute, error) {
	if len(b) > 1<<20 {
		return Attribute{}, ErrPolicy
	}

	cert, err := x509.ParseCertificate(b)
	if err != nil || cert.SerialNumber == nil {
		return Attribute{}, ErrCertificate
	}

	sum, _ := signature.Sum(crypto.SHA256, cert.Raw)
	serial, _ := asn1.Marshal(cert.SerialNumber)
	issuer := der.Seq(der.Seq(der.Ctx(4, cert.RawIssuer)), serial)
	id := der.Seq(der.Octets(sum), issuer)

	return Attribute{append(asn1.ObjectIdentifier(nil), oidSigningCertificateV2()...), [][]byte{der.Seq(der.Seq(id))}}, nil
}

func verifyESS(attrs []Attribute, cert *x509.Certificate, legacy bool) (bool, error) {
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

		if err := verifyESSAttribute(raw, cert, v2); err != nil {
			return false, err
		}

		bound = true
	}

	return bound, nil
}

func verifyESSAttribute(raw []byte, cert *x509.Certificate, v2 bool) error {
	v, err := der.Read(raw, 1<<20)
	if err != nil {
		return ErrSyntax
	}

	top, err := der.Sequence(v, 1, 2)
	if err != nil {
		return ErrSyntax
	}

	ids, err := der.Sequence(top[0], 1, 32)
	if err != nil {
		return ErrSyntax
	}

	for i, id := range ids {
		if err := verifyESSCertID(id, cert, v2, i == 0); err != nil {
			return err
		}
	}

	if len(top) == 2 {
		if _, err := der.Sequence(top[1], 1, 32); err != nil {
			return ErrSyntax
		}
	}

	return nil
}

func verifyESSCertID(v asn1.RawValue, cert *x509.Certificate, v2, signer bool) error {
	fields, err := der.Sequence(v, 1, 3)
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
			if err := verifyESSIssuer(names, serial, cert); err != nil {
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

		if der.Is(fields[0], 0, asn1.TagSequence, true) {
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
	issuer, err := der.Sequence(v, 2, 2)
	if err != nil {
		return nil, nil, ErrSyntax
	}

	names, err := der.Sequence(issuer[0], 1, 32)
	if err != nil {
		return nil, nil, ErrSyntax
	}

	var serial *big.Int
	if der.Decode(issuer[1], &serial) != nil || serial == nil || serial.Sign() <= 0 {
		return nil, nil, ErrSyntax
	}

	return names, serial, nil
}

func verifyESSIssuer(names []asn1.RawValue, serial *big.Int, cert *x509.Certificate) error {
	match := false

	for _, name := range names {
		if !der.Is(name, 2, 4, true) {
			continue
		}

		directory, err := der.Explicit(name, 4)
		if err != nil {
			return ErrSyntax
		}

		if bytes.Equal(directory.FullBytes, cert.RawIssuer) {
			match = true
		}
	}

	if !match || serial.Cmp(cert.SerialNumber) != 0 {
		return ErrCertificate
	}

	return nil
}

func verifyProtection(attrs []Attribute, alg pkix.AlgorithmIdentifier, h crypto.Hash) error {
	raw, ok, e := attributeValue(attrs, oidAlgorithmProtect())
	if e != nil {
		return e
	}

	if !ok {
		return nil
	}

	v, e := der.Read(raw, 8192)
	if e != nil {
		return ErrSyntax
	}

	f, e := der.Sequence(v, 2, 2)
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

	if !der.Is(f[1], 2, 1, true) {
		return ErrSyntax
	}

	s := asn1.RawValue{Class: 0, Tag: asn1.TagSequence, IsCompound: true, Bytes: f[1].Bytes}

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
	f, e := der.SetFields(v, 2, tag, maximum)
	if e != nil || len(f) == 0 {
		return nil, ErrSyntax
	}

	out := make([]Attribute, 0, len(f))
	seen := map[string]bool{}

	for _, field := range f {
		a, e := der.Sequence(field, 2, 2)
		if e != nil {
			return nil, ErrSyntax
		}

		var o asn1.ObjectIdentifier
		if der.Decode(a[0], &o) != nil || seen[o.String()] || !attributePlacement(o, tag) {
			return nil, ErrSyntax
		}

		seen[o.String()] = true

		vals, e := der.SetFields(a[1], 0, asn1.TagSet, 64)
		if e != nil || len(vals) == 0 {
			return nil, ErrSyntax
		}

		x := Attribute{OID: o}
		for _, v := range vals {
			x.ValuesDER = append(x.ValuesDER, v.FullBytes)
		}

		if tag == 0 {
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
	if len(attrs) < 2 || len(attrs) > maximum {
		return nil, ErrPolicy
	}

	seen := map[string]bool{}

	var parts [][]byte

	total := 0

	for _, x := range attrs {
		if seen[x.OID.String()] || len(x.ValuesDER) < 1 || len(x.ValuesDER) > 64 || !attributePlacement(x.OID, 0) {
			return nil, ErrPolicy
		}

		if err := validateSigningTime(x); err != nil {
			return nil, ErrPolicy
		}

		seen[x.OID.String()] = true

		oid := der.OID(x.OID)
		if len(oid) == 0 {
			return nil, ErrPolicy
		}

		for _, b := range x.ValuesDER {
			total += len(b)
			if total > 1<<20 {
				return nil, ErrPolicy
			}

			if _, e := der.Read(b, 1<<20); e != nil {
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
	if tag == 0 {
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

	v, err := der.Read(attr.ValuesDER[0], 32)
	if err != nil {
		return ErrSyntax
	}

	var instant time.Time
	if der.Decode(v, &instant) != nil {
		return ErrSyntax
	}

	var text string

	switch {
	case der.Is(v, 0, asn1.TagUTCTime, false):
		text = instant.UTC().Format("060102150405Z")
	case der.Is(v, 0, asn1.TagGeneralizedTime, false):
		if instant.Year() >= 1950 && instant.Year() <= 2049 || instant.Year() < 1 {
			return ErrSyntax
		}

		text = instant.UTC().Format("20060102150405Z")
	default:
		return ErrSyntax
	}

	if !bytes.Equal(v.Bytes, []byte(text)) {
		return fmt.Errorf("%w: signingTime encoding", ErrSyntax)
	}

	return nil
}
