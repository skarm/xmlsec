package timestamp

import (
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"io"
	"math/big"
	"time"

	"github.com/skarm/xmlsec/cms"
	"github.com/skarm/xmlsec/internal/der"
	"github.com/skarm/xmlsec/internal/nilcheck"
	"github.com/skarm/xmlsec/internal/streamio"
)

// IssueOptions uses a caller-supplied clock/serial. A real TSA must independently
// guarantee trusted time, serial uniqueness and any Ordering claim.
type IssueOptions struct {
	// GenTime is the explicit trusted issuance time; the clock is not read implicitly.
	GenTime time.Time
	// SerialNumber is required, positive and at most 160 bits. The caller guarantees uniqueness.
	SerialNumber *big.Int
	// Accuracy is omitted when nil. Otherwise it must be a nonnegative whole
	// number of microseconds, at most 24 hours.
	Accuracy *time.Duration
	// Policy is the required issuance policy OID and must satisfy the request's policy.
	Policy asn1.ObjectIdentifier
	// ExtraCertificates embeds untrusted path-building candidates.
	ExtraCertificates [][]byte
	// Hash selects the CMS signing hash; zero selects SHA-256.
	Hash crypto.Hash
	// Ordering asserts that this TSA's tokens can be ordered by GenTime.
	Ordering bool
	// OmitTSAName omits the TSTInfo tsa name derived from the signer's certificate.
	OmitTSAName bool
	// RSAPSS selects fixed-parameter RSA-PSS for an RSA key.
	RSAPSS bool
}

// IssueResponse issues a signed RFC 3161 response bound to the supplied request. The
// caller supplies trusted time and serial allocation.
func IssueResponse(ctx context.Context, requestDER []byte, signer crypto.Signer, tsaCertificateDER []byte, o IssueOptions) ([]byte, error) {
	var output bytes.Buffer
	if _, err := WriteResponse(ctx, &output, requestDER, signer, tsaCertificateDER, o); err != nil {
		return nil, err
	}

	return output.Bytes(), nil
}

// WriteResponse issues an RFC 3161 response directly to dst. CMS signed metadata
// is validated before output; token/certificate bytes are not collected into a
// complete response first. The destination stays open and may contain partial
// output after an error. Requests are bounded to 64 KiB and responses to 16 MiB.
func WriteResponse(ctx context.Context, dst io.Writer, requestDER []byte, signer crypto.Signer, tsaCertificateDER []byte, o IssueOptions) (int64, error) {
	if nilcheck.IsNil(dst) {
		return 0, ErrPolicy
	}

	if ctx == nil || o.SerialNumber == nil || o.SerialNumber.Sign() <= 0 || o.SerialNumber.BitLen() > 160 || len(der.OID(o.Policy)) == 0 || len(tsaCertificateDER) > 1<<20 {
		return 0, ErrPolicy
	}

	if e := ctx.Err(); e != nil {
		return 0, e
	}

	q, e := ParseRequest(requestDER)
	if e != nil {
		return 0, e
	}

	if len(q.policy) > 0 && !q.policy.Equal(o.Policy) {
		return 0, ErrBinding
	}

	c, e := x509.ParseCertificate(tsaCertificateDER)
	if e != nil {
		return 0, ErrTrust
	}

	if e = checkTSACertificate(c, o.GenTime); e != nil {
		return 0, e
	}

	if o.Hash == 0 {
		o.Hash = crypto.SHA256
	}

	serial, _ := asn1.Marshal(new(big.Int).Set(o.SerialNumber))

	gen, e := encodeTime(o.GenTime)
	if e != nil {
		return 0, e
	}

	f := [][]byte{der.Int(1), der.OID(o.Policy), encodeImprint(q.imprint), serial, gen}
	if o.Accuracy != nil {
		a, e := encodeAccuracy(*o.Accuracy)
		if e != nil {
			return 0, e
		}

		f = append(f, a)
	}

	if o.Ordering {
		b, _ := asn1.Marshal(true)
		f = append(f, b)
	}

	if q.nonce != nil {
		b, _ := asn1.Marshal(q.nonce)
		f = append(f, b)
	}

	if !o.OmitTSAName {
		f = append(f, der.Ctx(0, der.Ctx(4, c.RawSubject)))
	}

	opt := cms.SignOptions{ContentType: TSTInfoOID(), OmitCertificates: !q.certReq}
	if q.certReq {
		opt.ExtraCertificates = o.ExtraCertificates
	}

	writer := &streamio.Writer{Context: ctx, Target: dst, Limit: 16 << 20, LimitError: ErrPolicy}
	envelope := responseWriter{target: writer}

	_, e = cms.SignReader(ctx, &envelope, bytes.NewBuffer(der.Seq(f...)), []cms.Signer{{Key: signer, CertificateDER: c.Raw, Hash: o.Hash, RSAPSS: o.RSAPSS}}, opt)
	if e == nil && writer.Written != envelope.expected {
		e = ErrFormat
	}

	return writer.Written, errors.Join(e, ctx.Err())
}

func encodeAccuracy(d time.Duration) ([]byte, error) {
	if d < 0 || d > 24*time.Hour || d%time.Microsecond != 0 {
		return nil, ErrPolicy
	}

	var f [][]byte
	if s := d / time.Second; s > 0 {
		f = append(f, der.Int(int(s)))
	}

	if ms := d % time.Second / time.Millisecond; ms > 0 {
		x, _ := der.Read(der.Int(int(ms)), 16)
		f = append(f, der.Wrap(2, 0, false, x.Bytes))
	}

	if us := d % time.Millisecond / time.Microsecond; us > 0 {
		x, _ := der.Read(der.Int(int(us)), 16)
		f = append(f, der.Wrap(2, 1, false, x.Bytes))
	}

	return der.Seq(f...), nil
}

// responseWriter frames an RFC 3161 response after the CMS length becomes known.
// Only the small DER SEQUENCE header is buffered, regardless of Write boundaries.
type responseWriter struct {
	target   *streamio.Writer
	header   [10]byte
	used     int
	started  bool
	expected int64
}

func (w *responseWriter) Write(p []byte) (int, error) {
	if w.started {
		return w.target.Write(p)
	}

	consumed := 0
	for consumed < len(p) {
		if w.used == len(w.header) {
			return consumed, ErrFormat
		}

		w.header[w.used] = p[consumed]
		w.used++
		consumed++

		if w.used < 2 {
			continue
		}

		if w.header[0] != 0x30 {
			return consumed, ErrFormat
		}

		need := 2

		if w.header[1]&0x80 != 0 {
			count := int(w.header[1] & 0x7f)
			if count == 0 || count > len(w.header)-2 {
				return consumed, ErrFormat
			}

			need += count
		}

		if w.used < need {
			continue
		}

		if err := w.start(); err != nil {
			return consumed, err
		}

		n, err := w.target.Write(p[consumed:])

		return consumed + n, err
	}

	return consumed, nil
}

func (w *responseWriter) start() error {
	length := int(w.header[1])
	if length >= 128 {
		if w.header[2] == 0 {
			return ErrFormat
		}

		length = 0
		for _, b := range w.header[2:w.used] {
			if length > (16<<20)/256 {
				return ErrPolicy
			}

			length = length*256 + int(b)
		}

		if length < 128 {
			return ErrFormat
		}
	}

	status := der.Seq(der.Int(0))
	body := len(status) + w.used + length

	header := der.Header(0x30, body)
	if body > 16<<20-len(header) {
		return ErrPolicy
	}

	w.expected = int64(len(header) + body)
	for _, part := range [][]byte{header, status, w.header[:w.used]} {
		if _, err := w.target.Write(part); err != nil {
			return err
		}
	}

	w.started = true

	return nil
}
