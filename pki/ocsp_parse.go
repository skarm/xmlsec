package pki

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"time"

	"github.com/skarm/xmlsec/internal/der"
	"github.com/skarm/xmlsec/internal/signature"
)

type singleResponse struct {
	id                  certID
	status              OCSPStatus
	this, next, revoked time.Time
	reason              int
}

func (s *singleResponse) parseStatus(v asn1.RawValue) error {
	switch {
	case der.Is(v, 2, 0, false) && len(v.Bytes) == 0:
		s.status = OCSPGood
	case der.Is(v, 2, 2, false) && len(v.Bytes) == 0:
		s.status = OCSPUnknown
	case der.Is(v, 2, 1, true):
		s.status = OCSPRevoked

		return s.parseRevokedInfo(v)
	default:
		return ErrEvidence
	}

	return nil
}

func (s *singleResponse) parseRevokedInfo(v asn1.RawValue) error {
	fields, err := der.Children(v)
	if err != nil || len(fields) < 1 || len(fields) > 2 {
		return ErrEvidence
	}

	s.revoked, err = generalized(fields[0])
	if err != nil {
		return err
	}

	if len(fields) == 1 {
		return nil
	}

	reason, err := der.Explicit(fields[1], 0)

	var code asn1.Enumerated
	if err != nil || der.Decode(reason, &code) != nil || !validReason(int(code)) {
		return ErrEvidence
	}

	s.reason = int(code)

	return nil
}

func validReason(r int) bool { return r >= 0 && r <= 10 && r != 7 }

func (s *singleResponse) parseOptionalFields(fields []asn1.RawValue) error {
	i := 0
	if i < len(fields) && der.Is(fields[i], 2, 0, true) {
		next, err := der.Explicit(fields[i], 0)
		if err != nil {
			return err
		}

		s.next, err = generalized(next)
		if err != nil {
			return err
		}

		i++
	}

	if i < len(fields) {
		x, err := der.Explicit(fields[i], 1)
		if err != nil {
			return err
		}

		ext, err := extensions(x)
		if err != nil {
			return err
		}

		if _, err := nonceFrom(ext, false); err != nil {
			return err
		}

		i++
	}

	if i != len(fields) {
		return ErrEvidence
	}

	return nil
}

func generalized(v asn1.RawValue) (time.Time, error) {
	var t time.Time
	// RFC 6960 section 4.2.2.1 applies RFC 5280 section 4.1.2.5.2:
	// UTC, seconds present, and no fractional seconds. encoding/asn1 also
	// accepts BER time forms; successful decoding alone is insufficient.
	if !der.Is(v, 0, asn1.TagGeneralizedTime, false) || len(v.Bytes) != 15 || der.Decode(v, &t) != nil || t.Year() < 1 || string(v.Bytes) != t.UTC().Format("20060102150405Z") {
		return t, ErrEvidence
	}

	return t, nil
}

type parsedOCSP struct {
	tbs      []byte
	alg      pkix.AlgorithmIdentifier
	sig      []byte
	rid      asn1.RawValue
	produced time.Time
	entries  []singleResponse
	certs    []*x509.Certificate
	nonce    []byte
}

func (p *parsedOCSP) parseCertificates(v asn1.RawValue) error {
	x, err := der.Explicit(v, 0)
	if err != nil {
		return ErrEvidence
	}

	certificates, err := der.Sequence(x, 1, 8)
	if err != nil {
		return ErrEvidence
	}

	for _, certificate := range certificates {
		c, err := parseBorrowedCertificate(certificate.FullBytes)
		if err != nil {
			return err
		}

		p.certs = append(p.certs, c)
	}

	return nil
}

func (p *parsedOCSP) parseResponseData(v asn1.RawValue) error {
	fields, err := der.Sequence(v, 3, 4)
	if err != nil {
		return ErrEvidence
	}

	p.rid = fields[0]
	if !der.Is(p.rid, 2, 1, true) && !der.Is(p.rid, 2, 2, true) {
		return ErrUnsupported
	}

	p.produced, err = generalized(fields[1])
	if err != nil {
		return err
	}

	if err := p.parseEntries(fields[2]); err != nil {
		return err
	}

	if len(fields) == 4 {
		return p.parseResponseExtensions(fields[3])
	}

	return nil
}

func (p *parsedOCSP) parseEntries(v asn1.RawValue) error {
	entries, err := der.Sequence(v, 1, 64)
	if err != nil {
		return ErrEvidence
	}

	for _, entry := range entries {
		s, err := parseSingle(entry)
		if err != nil {
			return err
		}

		p.entries = append(p.entries, s)
	}

	return nil
}

func parseSingle(v asn1.RawValue) (singleResponse, error) {
	fields, err := der.Sequence(v, 3, 5)
	if err != nil {
		return singleResponse{}, ErrEvidence
	}

	id, err := parseCertID(fields[0])
	if err != nil {
		return singleResponse{}, err
	}

	s := singleResponse{id: id}
	if err := s.parseStatus(fields[1]); err != nil {
		return s, err
	}

	s.this, err = generalized(fields[2])
	if err != nil {
		return s, err
	}

	if err := s.parseOptionalFields(fields[3:]); err != nil {
		return s, err
	}

	return s, nil
}

func (p *parsedOCSP) parseResponseExtensions(v asn1.RawValue) error {
	x, err := der.Explicit(v, 1)
	if err != nil {
		return ErrEvidence
	}

	ext, err := extensions(x)
	if err != nil {
		return err
	}

	p.nonce, err = nonceFrom(ext, true)

	return err
}

func parseOCSP(b []byte, maximum int) (parsedOCSP, error) {
	data, err := ocspResponseBytes(b, maximum)
	if err != nil {
		return parsedOCSP{}, err
	}

	p, responseData, err := parseBasicOCSP(data, maximum)
	if err != nil {
		return p, err
	}

	if err := p.parseResponseData(responseData); err != nil {
		return p, err
	}

	return p, nil
}

// ocspResponseBytes validates the outer status before decoding BasicOCSPResponse.
func ocspResponseBytes(b []byte, maximum int) ([]byte, error) {
	v, err := der.Read(b, maximum)
	if err != nil {
		return nil, ErrEvidence
	}

	fields, err := der.Sequence(v, 1, 2)
	if err != nil {
		return nil, ErrEvidence
	}

	var status asn1.Enumerated
	if der.Decode(fields[0], &status) != nil || status < 0 || status > 6 || status == 4 {
		return nil, ErrEvidence
	}

	if status != 0 {
		if len(fields) != 1 {
			return nil, ErrEvidence
		}

		return nil, fmt.Errorf("%w: OCSP response status %d", ErrUnavailable, status)
	}

	if len(fields) != 2 {
		return nil, ErrEvidence
	}

	x, err := der.Explicit(fields[1], 0)
	if err != nil {
		return nil, ErrEvidence
	}

	response, err := der.Sequence(x, 2, 2)
	if err != nil || !der.OIDEqual(response[0], oidOCSPBasic()) {
		return nil, ErrUnsupported
	}

	if !der.Is(response[1], 0, asn1.TagOctetString, false) {
		return nil, ErrEvidence
	}

	return response[1].Bytes, nil
}

func parseBasicOCSP(data []byte, maximum int) (parsedOCSP, asn1.RawValue, error) {
	v, err := der.Read(data, maximum)
	if err != nil {
		return parsedOCSP{}, asn1.RawValue{}, ErrEvidence
	}

	fields, err := der.Sequence(v, 3, 4)
	if err != nil {
		return parsedOCSP{}, asn1.RawValue{}, ErrEvidence
	}

	algorithm, err := signature.Algorithm(fields[1])
	if err != nil {
		return parsedOCSP{}, asn1.RawValue{}, err
	}

	var bits asn1.BitString
	if der.Decode(fields[2], &bits) != nil || bits.BitLength%8 != 0 || len(bits.Bytes) == 0 {
		return parsedOCSP{}, asn1.RawValue{}, ErrEvidence
	}

	p := parsedOCSP{tbs: fields[0].FullBytes, alg: algorithm, sig: bits.Bytes}
	if len(fields) == 4 {
		if err := p.parseCertificates(fields[3]); err != nil {
			return p, asn1.RawValue{}, err
		}
	}

	return p, fields[0], nil
}
