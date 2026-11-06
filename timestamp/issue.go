package timestamp

import (
	"bytes"
	"context"
	"crypto"
	"encoding/asn1"
	"errors"
	"io"
	"math/big"
	"time"

	"github.com/skarm/xmlsec/cms"
	"github.com/skarm/xmlsec/internal/der"
	"github.com/skarm/xmlsec/internal/lexicon"
	"github.com/skarm/xmlsec/internal/nilcheck"
	"github.com/skarm/xmlsec/internal/streamio"
	"github.com/skarm/xmlsec/internal/x509cert"
)

const (
	// Caps issued accuracy and the configurable verifier accuracy bound. Received
	// TSTInfo components have separate parsing bounds; MaxAccuracy zero is unlimited.
	maximumAccuracy = 24 * time.Hour
)

// DER framing of the streamed CMS token and its response SEQUENCE. These wire
// widths do not change the separate maximumResponseBytes policy.
const (
	responseSequenceTag         = 0x30
	responseLongLengthFlag      = 0x80
	responseLengthCountMask     = 0x7f
	responseMinimumHeaderBytes  = 2
	responseMaximumLengthOctets = 8
	responseLengthRadix         = 256
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

	if ctx == nil || o.SerialNumber == nil || o.SerialNumber.Sign() <= 0 || o.SerialNumber.BitLen() > maximumSerialBits || len(der.OID(o.Policy)) == 0 || len(tsaCertificateDER) > maximumCertificateBytes {
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

	c, e := x509cert.ParseDefault(tsaCertificateDER)
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

	f := [][]byte{der.Int(timestampVersion), der.OID(o.Policy), encodeImprint(q.imprint), serial, gen}
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
		f = append(f, der.Ctx(infoTSANameTag, der.Ctx(lexicon.GeneralNameDirectory, c.RawSubject)))
	}

	opt := cms.SignOptions{ContentType: TSTInfoOID(), OmitCertificates: !q.certReq}
	if q.certReq {
		opt.ExtraCertificates = o.ExtraCertificates
	}

	writer := &streamio.Writer{Context: ctx, Target: dst, Limit: maximumResponseBytes, LimitError: ErrPolicy}
	envelope := responseWriter{target: writer}

	_, e = cms.SignReader(ctx, &envelope, bytes.NewBuffer(der.Seq(f...)), []cms.Signer{{Key: signer, CertificateDER: c.Raw, Hash: o.Hash, RSAPSS: o.RSAPSS}}, opt)
	if e == nil && writer.Written != envelope.expected {
		e = ErrFormat
	}

	return writer.Written, errors.Join(e, ctx.Err())
}

func encodeAccuracy(d time.Duration) ([]byte, error) {
	const maximumEncodedAccuracyIntegerBytes = 16

	if d < 0 || d > maximumAccuracy || d%time.Microsecond != 0 {
		return nil, ErrPolicy
	}

	var f [][]byte
	if s := d / time.Second; s > 0 {
		f = append(f, der.Int(int(s)))
	}

	if ms := d % time.Second / time.Millisecond; ms > 0 {
		x, _ := der.Read(der.Int(int(ms)), maximumEncodedAccuracyIntegerBytes)
		f = append(f, der.Wrap(asn1.ClassContextSpecific, accuracyMillisTag, false, x.Bytes))
	}

	if us := d % time.Millisecond / time.Microsecond; us > 0 {
		x, _ := der.Read(der.Int(int(us)), maximumEncodedAccuracyIntegerBytes)
		f = append(f, der.Wrap(asn1.ClassContextSpecific, accuracyMicrosTag, false, x.Bytes))
	}

	return der.Seq(f...), nil
}

// responseWriter frames an RFC 3161 response after the CMS length becomes known.
// Only the small DER SEQUENCE header is buffered, regardless of Write boundaries.
type responseWriter struct {
	target   *streamio.Writer
	used     int
	expected int64
	header   [responseMinimumHeaderBytes + responseMaximumLengthOctets]byte
	started  bool
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

		if w.used < responseMinimumHeaderBytes {
			continue
		}

		if w.header[0] != responseSequenceTag {
			return consumed, ErrFormat
		}

		need := responseMinimumHeaderBytes

		if w.header[1]&responseLongLengthFlag != 0 {
			count := int(w.header[1] & responseLengthCountMask)
			if count == 0 || count > len(w.header)-responseMinimumHeaderBytes {
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
	if length >= responseLongLengthFlag {
		if w.header[responseMinimumHeaderBytes] == 0 {
			return ErrFormat
		}

		length = 0
		for _, b := range w.header[responseMinimumHeaderBytes:w.used] {
			if length > maximumResponseBytes/responseLengthRadix {
				return ErrPolicy
			}

			length = length*responseLengthRadix + int(b)
		}

		if length < responseLongLengthFlag {
			return ErrFormat
		}
	}

	status := der.Seq(der.Int(statusGranted))
	body := len(status) + w.used + length

	header := der.Header(responseSequenceTag, body)
	if body > maximumResponseBytes-len(header) {
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
