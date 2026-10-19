package pki

import (
	"bytes"
	"context"
	"crypto"
	"encoding/asn1"
	"errors"
	"io"
	"time"

	"github.com/skarm/xmlsec/internal/der"
	"github.com/skarm/xmlsec/internal/nilcheck"
	"github.com/skarm/xmlsec/internal/signature"
	"github.com/skarm/xmlsec/internal/streamio"
)

// OCSPResponseTemplate contains caller-asserted status and UTC instants.
// The encoder does not determine revocation status.
type OCSPResponseTemplate struct {
	Status                 OCSPStatus
	ProducedAt, ThisUpdate time.Time
	// NextUpdate is omitted when zero, subject to the verifier's freshness policy.
	NextUpdate time.Time
	// RevokedAt is required when Status is OCSPRevoked.
	RevokedAt time.Time
	// RevocationReason applies only to OCSPRevoked; zero omits the reason.
	RevocationReason int
	// Hash defaults to SHA-256.
	Hash crypto.Hash
	// RSAPSS selects fixed-parameter RSA-PSS for an RSA key.
	RSAPSS bool
}

// CreateOCSPResponse is an encoder, not a CA: the caller supplies status/time.
func CreateOCSPResponse(ctx context.Context, requestDER, certificateDER, issuerDER, responderDER []byte, signer crypto.Signer, t OCSPResponseTemplate) ([]byte, error) {
	parts, err := prepareOCSPResponse(ctx, requestDER, certificateDER, issuerDER, responderDER, signer, t)
	if err != nil {
		return nil, err
	}

	size, err := ocspResponseSize(parts)
	if err != nil {
		return nil, err
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	output := bytes.NewBuffer(make([]byte, 0, size))
	if _, err := writeOCSPResponse(ctx, output, parts, size); err != nil {
		return nil, err
	}

	return output.Bytes(), nil
}

// WriteOCSPResponse signs caller-supplied status/time and emits DER directly to
// dst without copying an embedded responder certificate into nested encodings.
// Input certificates are limited to 1 MiB each and response DER to 8 MiB.
// Signature/provider checks precede output. The caller owns dst; a write or
// cancellation error may leave partial output and returns its actual byte count.
func WriteOCSPResponse(ctx context.Context, dst io.Writer, requestDER, certificateDER, issuerDER, responderDER []byte, signer crypto.Signer, t OCSPResponseTemplate) (int64, error) {
	if nilcheck.IsNil(dst) {
		return 0, ErrPolicy
	}

	parts, err := prepareOCSPResponse(ctx, requestDER, certificateDER, issuerDER, responderDER, signer, t)
	if err != nil {
		return 0, err
	}

	size, err := ocspResponseSize(parts)
	if err != nil {
		return 0, err
	}

	return writeOCSPResponse(ctx, dst, parts, size)
}

func genTime(t time.Time) ([]byte, error) {
	if t.IsZero() || t.Year() < 1 || t.Year() > 9999 {
		return nil, ErrPolicy
	}

	return asn1.MarshalWithParams(t.UTC(), "generalized")
}

func ocspResponseSize(parts [][]byte) (int, error) {
	size := 0
	for _, part := range parts {
		if len(part) > 8<<20-size {
			return 0, ErrPolicy
		}

		size += len(part)
	}

	return size, nil
}

func writeOCSPResponse(ctx context.Context, dst io.Writer, parts [][]byte, size int) (int64, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}

	if buffer, ok := dst.(*bytes.Buffer); ok {
		buffer.Grow(size)
	}

	writer := &streamio.Writer{Context: ctx, Target: dst, Limit: int64(size), LimitError: ErrPolicy}

	for _, part := range parts {
		for len(part) > 0 {
			chunk := part[:min(len(part), 32<<10)]
			if _, err := writer.Write(chunk); err != nil {
				return writer.Written, errors.Join(err, ctx.Err())
			}

			part = part[len(chunk):]
		}
	}

	return writer.Written, ctx.Err()
}

func prepareOCSPResponse(ctx context.Context, requestDER, certificateDER, issuerDER, responderDER []byte, signer crypto.Signer, t OCSPResponseTemplate) ([][]byte, error) {
	if ctx == nil {
		return nil, ErrPolicy
	}

	if e := ctx.Err(); e != nil {
		return nil, e
	}

	r, e := ParseOCSPRequest(requestDER)
	if e != nil {
		return nil, e
	}

	c, e := parseBorrowedCertificate(certificateDER)
	if e != nil {
		return nil, e
	}

	issuer, e := parseBorrowedCertificate(issuerDER)
	if e != nil {
		return nil, e
	}

	responder, e := parseCertificate(responderDER)
	if e != nil {
		return nil, e
	}

	if e = signature.MatchCertificate(signer, responder); e != nil {
		return nil, e
	}

	h, _ := signature.Hash(r.id.alg, true)

	want, e := makeCertID(c, issuer, h)
	if e != nil || !sameCertID(r.id, want) {
		return nil, ErrCertificate
	}

	if t.Hash == 0 {
		t.Hash = crypto.SHA256
	}

	if returned1, matched := createOCSPResponseIsZero(&t); matched {
		return nil, returned1
	}

	var st []byte

	switch t.Status {
	case OCSPGood:
		st = der.Wrap(2, 0, false, nil)
	case OCSPUnknown:
		st = der.Wrap(2, 2, false, nil)
	case OCSPRevoked:
		if !validReason(t.RevocationReason) || t.RevokedAt.IsZero() || t.RevokedAt.After(t.ProducedAt) {
			return nil, ErrPolicy
		}

		rt, e := genTime(t.RevokedAt)
		if e != nil {
			return nil, e
		}

		f := [][]byte{rt}

		if t.RevocationReason != 0 {
			rr, _ := asn1.Marshal(asn1.Enumerated(t.RevocationReason))
			f = append(f, der.Ctx(0, rr))
		}

		st = der.Wrap(2, 1, true, bytes.Join(f, nil))
	default:
		return nil, ErrPolicy
	}

	tu, e := genTime(t.ThisUpdate)
	if e != nil {
		return nil, e
	}

	f := [][]byte{encodeCertID(r.id), st, tu}

	if !t.NextUpdate.IsZero() {
		nt, e := genTime(t.NextUpdate)
		if e != nil {
			return nil, e
		}

		f = append(f, der.Ctx(0, nt))
	}

	pa, e := genTime(t.ProducedAt)
	if e != nil {
		return nil, e
	}

	rd := [][]byte{der.Ctx(1, responder.RawSubject), pa, der.Seq(der.Seq(f...))}
	if len(r.nonce) > 0 {
		rd = append(rd, der.Ctx(1, nonceExtensions(r.nonce)))
	}

	tbs := der.Seq(rd...)

	alg, e := signature.Select(responder.PublicKey, t.Hash, t.RSAPSS)
	if e != nil {
		return nil, e
	}

	value, e := signature.Sign(ctx, signer, alg, tbs)
	if e != nil {
		return nil, e
	}

	bv, _ := asn1.Marshal(asn1.BitString{Bytes: value, BitLength: len(value) * 8})

	bs := [][]byte{tbs, signature.EncAlgorithm(alg), bv}
	if !bytes.Equal(responder.Raw, issuer.Raw) {
		bs = append(bs, frameOCSP(0xa0, frameOCSP(0x30, [][]byte{responder.Raw}))...)
	}

	success, _ := asn1.Marshal(asn1.Enumerated(0))

	response := frameOCSP(0x30, append([][]byte{der.OID(oidOCSPBasic())}, frameOCSP(4, frameOCSP(0x30, bs))...))

	return frameOCSP(0x30, append([][]byte{success}, frameOCSP(0xa0, response)...)), nil
}

func frameOCSP(tag byte, parts [][]byte) [][]byte {
	size := 0
	for _, part := range parts {
		size += len(part)
	}

	return append([][]byte{der.Header(tag, size)}, parts...)
}

func createOCSPResponseIsZero(t *OCSPResponseTemplate) (returned1 error, matched bool) {
	if t.ProducedAt.IsZero() || t.ThisUpdate.IsZero() || t.ProducedAt.Before(t.ThisUpdate) || !t.NextUpdate.IsZero() && (!t.NextUpdate.After(t.ThisUpdate) || t.ProducedAt.After(t.NextUpdate)) {
		return ErrPolicy, true
	}

	return
}
