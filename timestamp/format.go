package timestamp

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"encoding/asn1"
	"errors"
	"fmt"
	"io"
	"math"
	"math/big"
	"strings"
	"time"

	"github.com/skarm/xmlsec/cms"
	"github.com/skarm/xmlsec/internal/der"
	"github.com/skarm/xmlsec/internal/nilcheck"
	"github.com/skarm/xmlsec/internal/signature"
	"github.com/skarm/xmlsec/internal/streamio"
)

var (
	// ErrFormat reports invalid or unsupported timestamp format.
	ErrFormat = errors.New("invalid or unsupported timestamp format")
	// ErrPolicy reports timestamp policy violation.
	ErrPolicy = errors.New("timestamp policy violation")
	// ErrBinding reports timestamp imprint, policy or nonce mismatch.
	ErrBinding = errors.New("timestamp imprint, policy or nonce mismatch")
	// ErrTrust reports timestamp TSA trust/usage check failed.
	ErrTrust = errors.New("timestamp TSA trust/usage check failed")
)

// Imprint identifies timestamped data by its hash algorithm and raw digest.
type Imprint struct {
	// Hash identifies the algorithm that produced Digest.
	Hash crypto.Hash
	// Digest contains the raw message digest bytes, with the length required by Hash.
	Digest []byte
}

// ImprintFor hashes data with a supported SHA-2 algorithm to create a message imprint.
func ImprintFor(ctx context.Context, data []byte, h crypto.Hash) (Imprint, error) {
	return ImprintReader(ctx, bytes.NewReader(data), h)
}

// ImprintReader hashes src incrementally with SHA-256, SHA-384 or SHA-512.
// A zero hash selects SHA-256. It leaves src open and retains no message bytes.
// Blocking readers must honor cancellation themselves.
func ImprintReader(ctx context.Context, src io.Reader, h crypto.Hash) (Imprint, error) {
	if ctx == nil || nilcheck.IsNil(src) {
		return Imprint{}, ErrPolicy
	}

	if h == 0 {
		h = crypto.SHA256
	}

	a, e := signature.DigestAlgorithm(h)
	if e != nil {
		return Imprint{}, ErrPolicy
	}

	if _, e = signature.Hash(a, false); e != nil {
		return Imprint{}, ErrPolicy
	}

	digest := h.New()

	_, e = io.Copy(digest, &streamio.Reader{Context: ctx, Source: src, Limit: math.MaxInt64, LimitError: ErrPolicy})
	if e != nil {
		return Imprint{}, e
	}

	return Imprint{h, digest.Sum(nil)}, ctx.Err()
}

// RequestOptions selects the imprint hash, TSA policy, nonce and certificate request
// for an RFC 3161 request.
type RequestOptions struct {
	// Hash selects the imprint hash for CreateRequest; zero selects SHA-256.
	// CreateImprintRequest uses its supplied imprint instead.
	Hash crypto.Hash
	// Policy requests an exact TSA policy OID; empty leaves it unspecified.
	Policy asn1.ObjectIdentifier
	// Nonce supplies a positive, big-endian integer in 16 to 32 bytes.
	// Nil generates a random 256-bit nonce unless OmitNonce is set.
	Nonce []byte
	// OmitNonce omits the nonce and cannot be combined with a supplied Nonce.
	OmitNonce bool
	// OmitCertificates clears the request's certReq flag.
	OmitCertificates bool
}

// Request retains an immutable parsed RFC 3161 request. Parsing establishes no sender
// authenticity.
type Request struct {
	raw     []byte
	imprint Imprint
	policy  asn1.ObjectIdentifier
	nonce   *big.Int
	certReq bool
}

// CreateRequest hashes data and builds an RFC 3161 request. A nil nonce generates
// 256 random bits; omitting it requires OmitNonce.
func CreateRequest(ctx context.Context, data []byte, o RequestOptions) (*Request, error) {
	return CreateRequestReader(ctx, bytes.NewReader(data), o)
}

// CreateRequestReader hashes src incrementally and builds an RFC 3161 request.
// It leaves src open; request storage is independent of the message length.
func CreateRequestReader(ctx context.Context, src io.Reader, o RequestOptions) (*Request, error) {
	m, e := ImprintReader(ctx, src, o.Hash)
	if e != nil {
		return nil, e
	}

	return CreateImprintRequest(m, o)
}

// CreateImprintRequest builds an RFC 3161 request from an explicit message imprint and
// request options.
func CreateImprintRequest(m Imprint, o RequestOptions) (*Request, error) {
	if !validImprint(m) || o.OmitNonce && len(o.Nonce) > 0 {
		return nil, ErrPolicy
	}

	f := [][]byte{der.Int(1), encodeImprint(m)}

	if len(o.Policy) > 0 {
		b := der.OID(o.Policy)
		if len(b) == 0 {
			return nil, ErrPolicy
		}

		f = append(f, b)
	}

	if !o.OmitNonce {
		n := bytes.Clone(o.Nonce)
		if n == nil {
			n = make([]byte, 32)
			if _, e := rand.Read(n); e != nil {
				return nil, e
			}

			n[0] |= 128
		}

		if len(n) < 16 || len(n) > 32 {
			return nil, ErrPolicy
		}

		v := new(big.Int).SetBytes(n)
		if v.Sign() <= 0 {
			return nil, ErrPolicy
		}

		b, _ := asn1.Marshal(v)
		f = append(f, b)
	}

	if !o.OmitCertificates {
		b, _ := asn1.Marshal(true)
		f = append(f, b)
	}

	return parseOwnedRequest(der.Seq(f...))
}

// ParseRequest parses one complete bounded RFC 3161 request without authenticating its
// origin.
func ParseRequest(b []byte) (*Request, error) {
	if len(b) > 1<<16 {
		return nil, ErrPolicy
	}

	return parseOwnedRequest(bytes.Clone(b))
}

// DER returns an owned copy of the original DER encoding.
func (r *Request) DER() []byte {
	if r == nil {
		return nil
	}

	return bytes.Clone(r.raw)
}

// Imprint returns an owned copy of the message imprint.
func (r *Request) Imprint() Imprint {
	if r == nil {
		return Imprint{}
	}

	return Imprint{r.imprint.Hash, bytes.Clone(r.imprint.Digest)}
}

// Nonce returns an owned copy of the nonce, or nil when absent.
func (r *Request) Nonce() *big.Int {
	if r == nil || r.nonce == nil {
		return nil
	}

	return new(big.Int).Set(r.nonce)
}

// Policy returns an owned copy of the timestamp policy OID.
func (r *Request) Policy() asn1.ObjectIdentifier {
	if r == nil {
		return nil
	}

	return append(asn1.ObjectIdentifier(nil), r.policy...)
}

// CertificatesRequested returns whether the timestamp request asks the TSA to include
// certificates.
func (r *Request) CertificatesRequested() bool { return r != nil && r.certReq }

func validImprint(m Imprint) bool {
	return (m.Hash == crypto.SHA256 || m.Hash == crypto.SHA384 || m.Hash == crypto.SHA512) && len(m.Digest) == m.Hash.Size()
}

func encodeImprint(m Imprint) []byte {
	a, _ := signature.DigestAlgorithm(m.Hash)
	return der.Seq(signature.EncAlgorithm(a), der.Octets(m.Digest))
}

func parseOwnedRequest(b []byte) (*Request, error) {
	if len(b) > 1<<16 {
		return nil, ErrPolicy
	}

	v, e := der.Read(b, 1<<16)
	if e != nil {
		return nil, ErrFormat
	}

	f, e := der.Sequence(v, 2, 5)
	if e != nil {
		return nil, ErrFormat
	}

	var ver int
	if der.Decode(f[0], &ver) != nil || ver != 1 {
		return nil, ErrFormat
	}

	m, e := parseImprint(f[1])
	if e != nil {
		return nil, e
	}

	r := &Request{raw: b, imprint: m}

	i := 2
	if i < len(f) && der.Is(f[i], 0, asn1.TagOID, false) {
		if der.Decode(f[i], &r.policy) != nil {
			return nil, ErrFormat
		}

		i++
	}

	if i < len(f) && der.Is(f[i], 0, asn1.TagInteger, false) {
		if der.Decode(f[i], &r.nonce) != nil || r.nonce == nil || r.nonce.Sign() <= 0 || r.nonce.BitLen() > 256 {
			return nil, ErrFormat
		}

		i++
	}

	if i < len(f) && der.Is(f[i], 0, asn1.TagBoolean, false) {
		if der.Decode(f[i], &r.certReq) != nil || !r.certReq {
			return nil, ErrFormat
		}

		i++
	}

	if i != len(f) {
		return nil, ErrFormat
	}

	return r, nil
}

// Info retains parsed TSTInfo. Accept its time claims only after successful token
// verification.
type Info struct {
	policy      asn1.ObjectIdentifier
	imprint     Imprint
	serial      *big.Int
	nonce       *big.Int
	at          time.Time
	accuracy    time.Duration
	hasAccuracy bool
	ordering    bool
	tsa         asn1.RawValue
}

// Policy returns an owned copy of the timestamp policy OID.
func (i Info) Policy() asn1.ObjectIdentifier { return append(asn1.ObjectIdentifier(nil), i.policy...) }

// Imprint returns an owned copy of the message imprint.
func (i Info) Imprint() Imprint { return Imprint{i.imprint.Hash, bytes.Clone(i.imprint.Digest)} }

// SerialNumber returns an owned copy of the token serial number.
func (i Info) SerialNumber() *big.Int {
	if i.serial == nil {
		return nil
	}

	return new(big.Int).Set(i.serial)
}

// Nonce returns an owned copy of the nonce, or nil when absent.
func (i Info) Nonce() *big.Int {
	if i.nonce == nil {
		return nil
	}

	return new(big.Int).Set(i.nonce)
}

// GenTime returns the asserted token generation time.
func (i Info) GenTime() time.Time { return i.at }

// Accuracy returns the asserted time accuracy and whether it was supplied.
func (i Info) Accuracy() (time.Duration, bool) { return i.accuracy, i.hasAccuracy }

// Ordering returns the asserted token ordering flag.
func (i Info) Ordering() bool { return i.ordering }

func (i *Info) parseRequiredFields(fields []asn1.RawValue) error {
	if der.Decode(fields[1], &i.policy) != nil {
		return ErrFormat
	}

	var e error

	i.imprint, e = parseImprint(fields[2])
	if e != nil {
		return e
	}

	if der.Decode(fields[3], &i.serial) != nil || i.serial == nil || i.serial.Sign() <= 0 || i.serial.BitLen() > 160 {
		return ErrFormat
	}

	i.at, e = parseTime(fields[4])
	if e != nil {
		return e
	}

	return nil
}

func (i *Info) parseOptionalFields(fields []asn1.RawValue) error {
	index := 0
	if index < len(fields) && der.Is(fields[index], 0, asn1.TagSequence, true) {
		var e error

		i.accuracy, e = parseAccuracy(fields[index])
		if e != nil {
			return e
		}

		i.hasAccuracy = true
		index++
	}

	if index < len(fields) && der.Is(fields[index], 0, asn1.TagBoolean, false) {
		if der.Decode(fields[index], &i.ordering) != nil || !i.ordering {
			return ErrFormat
		}

		index++
	}

	if index < len(fields) && der.Is(fields[index], 0, asn1.TagInteger, false) {
		if der.Decode(fields[index], &i.nonce) != nil || i.nonce == nil || i.nonce.Sign() <= 0 || i.nonce.BitLen() > 256 {
			return ErrFormat
		}

		index++
	}

	if index < len(fields) && der.Is(fields[index], 2, 0, true) {
		var e error

		i.tsa, e = der.Explicit(fields[index], 0)
		if e != nil || i.tsa.Class != 2 {
			return ErrFormat
		}

		index++
	}

	if index < len(fields) && der.Is(fields[index], 2, 1, true) {
		if err := validateInfoExtensions(fields[index]); err != nil {
			return err
		}

		index++
	}

	if index != len(fields) {
		return ErrFormat
	}

	return nil
}

func encodeTime(t time.Time) ([]byte, error) {
	if t.IsZero() || t.Year() < 1 || t.Year() > 9999 {
		return nil, ErrPolicy
	}

	s := t.UTC().Format("20060102150405")
	if t.Nanosecond() != 0 {
		s += "." + strings.TrimRight(fmt.Sprintf("%09d", t.Nanosecond()), "0")
	}

	return der.Wrap(0, asn1.TagGeneralizedTime, false, []byte(s+"Z")), nil
}

func parseTime(v asn1.RawValue) (time.Time, error) {
	if !der.Is(v, 0, asn1.TagGeneralizedTime, false) {
		return time.Time{}, ErrFormat
	}

	s := string(v.Bytes)
	if len(s) < 15 || !strings.HasSuffix(s, "Z") {
		return time.Time{}, ErrFormat
	}

	if len(s) > 15 && (s[14] != '.' || len(s) < 17 || len(s) > 25 || s[len(s)-2] == '0') {
		return time.Time{}, ErrFormat
	}

	var t time.Time
	if der.Decode(v, &t) != nil || t.Year() < 1 {
		return time.Time{}, ErrFormat
	}

	b, e := encodeTime(t)
	if e != nil || !bytes.Equal(b, v.FullBytes) {
		return time.Time{}, ErrFormat
	}

	return t, nil
}

func parseAccuracy(v asn1.RawValue) (time.Duration, error) {
	f, e := der.Sequence(v, 0, 3)
	if e != nil {
		return 0, ErrFormat
	}

	last := -1

	var total time.Duration

	for _, x := range f {
		var kind int

		unit := time.Second

		b := x.FullBytes
		switch {
		case der.Is(x, 0, asn1.TagInteger, false):
			kind = 0
		case der.Is(x, 2, 0, false):
			kind = 1
			unit = time.Millisecond
			b = der.Wrap(0, asn1.TagInteger, false, x.Bytes)
		case der.Is(x, 2, 1, false):
			kind = 2
			unit = time.Microsecond
			b = der.Wrap(0, asn1.TagInteger, false, x.Bytes)
		default:
			return 0, ErrFormat
		}

		if kind <= last {
			return 0, ErrFormat
		}

		last = kind

		var n int
		if der.Unmarshal(b, &n) != nil || n < 0 || kind > 0 && (n < 1 || n > 999) || kind == 0 && n > 86400 {
			return 0, ErrFormat
		}

		total += time.Duration(n) * unit
	}

	return total, nil
}

func validateInfoExtensions(v asn1.RawValue) error {
	xs, err := der.Children(v)
	if err != nil || len(xs) < 1 || len(xs) > 32 {
		return ErrFormat
	}

	seen := make(map[string]struct{}, len(xs))

	for _, x := range xs {
		fields, e := der.Sequence(x, 2, 3)
		if e != nil {
			return ErrFormat
		}

		var oid asn1.ObjectIdentifier
		if der.Decode(fields[0], &oid) != nil {
			return ErrFormat
		}

		if _, exists := seen[oid.String()]; exists {
			return ErrFormat
		}

		seen[oid.String()] = struct{}{}

		if len(fields) == 3 {
			var critical bool
			if der.Decode(fields[1], &critical) != nil || !critical {
				return ErrFormat
			}

			return ErrPolicy
		}

		if !der.Is(fields[1], 0, asn1.TagOctetString, false) {
			return ErrFormat
		}
	}

	return nil
}

// Response retains an immutable parsed RFC 3161 response. Parsing does not
// authenticate its token.
type Response struct {
	raw    []byte
	token  []byte
	status int
	text   []string
	fail   asn1.BitString
}

// ParseResponse parses one complete bounded RFC 3161 response and rejects unsuccessful
// status values.
func ParseResponse(ctx context.Context, b []byte) (*Response, error) {
	return ParseResponseReader(ctx, bytes.NewReader(b))
}

// ParseResponseReader reads one bounded DER response into owned storage. The
// full response and token remain materialized; src remains caller-owned.
func ParseResponseReader(ctx context.Context, src io.Reader) (*Response, error) {
	if ctx == nil || nilcheck.IsNil(src) {
		return nil, ErrPolicy
	}

	value, err := der.ReadSequence(ctx, src, 16<<20)
	if err != nil {
		if errors.Is(err, der.ErrLimit) {
			return nil, fmt.Errorf("%w: %w", ErrPolicy, err)
		}

		return nil, fmt.Errorf("%w: %w", ErrFormat, err)
	}

	return parseResponseValue(ctx, value, true)
}

// DER returns an owned copy of the original DER encoding.
func (r *Response) DER() []byte {
	if r == nil {
		return nil
	}

	return bytes.Clone(r.raw)
}

// TokenDER returns an owned copy of the timestamp token DER.
func (r *Response) TokenDER() []byte {
	if r == nil {
		return nil
	}

	return bytes.Clone(r.token)
}

// Status returns the RFC 3161 response status code.
func (r *Response) Status() int {
	if r == nil {
		return -1
	}

	return r.status
}

// bindToken checks whether the response status permits an attached CMS token.
func (r *Response) bindToken(ctx context.Context, f []asn1.RawValue, validateToken bool) (*Response, error) {
	if r.status == 0 || r.status == 1 {
		if len(f) != 2 || r.fail.BitLength != 0 {
			return nil, ErrFormat
		}

		r.token = f[1].FullBytes
		if validateToken {
			if _, e := cms.Parse(ctx, r.token, cms.DefaultLimits()); e != nil {
				return nil, fmt.Errorf("%w: %w", ErrFormat, e)
			}
		}
	} else {
		if len(f) != 1 {
			return nil, ErrFormat
		}

		err := &ResponseError{Status: r.status, Text: append([]string(nil), r.text...)}
		for n := 0; n < r.fail.BitLength; n++ {
			if r.fail.At(n) != 0 {
				err.FailureBits = append(err.FailureBits, n)
			}
		}

		return r, err
	}

	return r, nil
}

func parseResponseValue(ctx context.Context, v asn1.RawValue, validateToken bool) (*Response, error) {
	b := v.FullBytes

	f, e := der.Sequence(v, 1, 2)
	if e != nil {
		return nil, ErrFormat
	}

	sf, e := der.Sequence(f[0], 1, 3)
	if e != nil {
		return nil, ErrFormat
	}

	r := &Response{raw: b}
	if der.Decode(sf[0], &r.status) != nil || r.status < 0 || r.status > 5 {
		return nil, ErrFormat
	}

	i := 1
	if i < len(sf) && der.Is(sf[i], 0, asn1.TagSequence, true) {
		texts, e := der.Sequence(sf[i], 1, 16)
		if e != nil {
			return nil, ErrFormat
		}

		for _, s := range texts {
			var msg string
			if !der.Is(s, 0, asn1.TagUTF8String, false) || der.Decode(s, &msg) != nil || len(msg) > 4096 {
				return nil, ErrFormat
			}

			r.text = append(r.text, msg)
		}

		i++
	}

	if i < len(sf) {
		if der.Decode(sf[i], &r.fail) != nil || r.fail.BitLength > 26 {
			return nil, ErrFormat
		}

		i++

		for n := 0; n < r.fail.BitLength; n++ {
			if r.fail.At(n) != 0 && n != 0 && n != 2 && n != 5 && n != 14 && n != 15 && n != 16 && n != 17 && n != 25 {
				return nil, ErrFormat
			}
		}
	}

	if i != len(sf) {
		return nil, ErrFormat
	}

	return r.bindToken(ctx, f, validateToken)
}

// ResponseError reports a TSA failure status, untrusted status text and failure bit
// positions.
type ResponseError struct {
	// Status is the RFC 3161 PKIStatus value returned by the TSA.
	Status int
	// Text contains the TSA's untrusted status strings.
	Text []string
	// FailureBits lists the set bit positions in the response's PKIFailureInfo.
	FailureBits []int
}

// Error returns the diagnostic error message.
func (e *ResponseError) Error() string {
	return fmt.Sprintf("TSA response status %d (failure bits %v)", e.Status, e.FailureBits)
}

// TSTInfoOID returns an owned copy of the RFC 3161 id-ct-TSTInfo object identifier.
func TSTInfoOID() asn1.ObjectIdentifier { return append(asn1.ObjectIdentifier(nil), tstOID()...) }

func tstOID() asn1.ObjectIdentifier { return asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 1, 4} }

func parseImprint(v asn1.RawValue) (Imprint, error) {
	f, e := der.Sequence(v, 2, 2)
	if e != nil {
		return Imprint{}, ErrFormat
	}

	a, e := signature.Algorithm(f[0])
	if e != nil {
		return Imprint{}, ErrFormat
	}

	h, e := signature.Hash(a, false)
	if e != nil {
		return Imprint{}, ErrPolicy
	}

	var d []byte
	if der.Decode(f[1], &d) != nil || len(d) != h.Size() {
		return Imprint{}, ErrFormat
	}

	return Imprint{h, d}, nil
}

func parseInfo(b []byte) (Info, error) {
	v, e := der.Read(b, 1<<20)
	if e != nil {
		return Info{}, ErrFormat
	}

	f, e := der.Sequence(v, 5, 10)
	if e != nil {
		return Info{}, ErrFormat
	}

	var version int
	if der.Decode(f[0], &version) != nil || version != 1 {
		return Info{}, ErrFormat
	}

	info := Info{}
	if err := info.parseRequiredFields(f); err != nil {
		return info, err
	}

	if err := info.parseOptionalFields(f[5:]); err != nil {
		return info, err
	}
	// Only the GeneralName borrows TSTInfo bytes. Detach that small value so
	// Info does not keep discarded extensions or a complete content copy alive.
	if len(info.tsa.FullBytes) > 0 {
		encoded := bytes.Clone(info.tsa.FullBytes)
		info.tsa.Bytes = encoded[len(encoded)-len(info.tsa.Bytes):]
		info.tsa.FullBytes = encoded
	}

	return info, nil
}
