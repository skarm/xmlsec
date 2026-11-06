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

const (
	// Hard byte ceiling shared by timestamp response/token parsing and issuance.
	maximumResponseBytes = 16 << 20
)

const (
	// GeneralizedTime uses whole UTC seconds plus an optional canonical fraction.
	generalizedTimeSecondsLayout = "20060102150405"
	// Locally generated nonces have a fixed byte width; parsing separately caps bit length.
	generatedNonceBytes = 32
	// Accuracy components are bounded independently when parsing received TSTInfo.
	maximumAccuracyFraction = 999
	maximumAccuracySeconds  = 86400
	// Caps the TSTInfo DER payload separately from its enclosing CMS token, in bytes.
	maximumInfoBytes = 1 << 20
	// Caps distinct optional extension records in received TSTInfo.
	maximumInfoExtensions = 32
	// Upper bound on a positive RFC 3161 nonce, in bits.
	maximumNonceBits = 256
	// Maximum width of locally supplied nonces; received nonces use the bit cap.
	maximumNonceBytes = 32
	// Caps the complete encoded request, independently of response/token limits.
	maximumRequestBytes = 1 << 16
	// Upper bound on the timestamp serial number, in bits.
	maximumSerialBits = 160
	// Status text is untrusted: cap each UTF-8 value and the number of values.
	maximumStatusTextBytes = 4096
	maximumStatusTexts     = 16
	// Canonical GeneralizedTime represents years with exactly four digits.
	maximumTimeYear = 9999
	// Minimum width of locally supplied nonces; generated nonces use their fixed width.
	minimumNonceBytes = 16
	// RFC 3161 version value emitted by issuers and required by request/TSTInfo parsing.
	timestampVersion = 1
	// PKIFailureInfo uses bit positions, independently of the PKIStatus enumeration.
	failureAdditionalInfoNotAvailable = 17
	failureBadAlgorithm               = 0
	failureBadDataFormat              = 5
	failureBadRequest                 = 2
	failureSystem                     = 25
	failureTimeNotAvailable           = 14
	failureUnacceptedExtension        = 16
	failureUnacceptedPolicy           = 15
	// Widths include the UTC designator; fractional forms also contain the decimal point.
	generalizedTimeBaseBytes            = 15
	generalizedTimeMaximumFractionBytes = generalizedTimeBaseBytes + 10
	generalizedTimeMinimumFractionBytes = generalizedTimeBaseBytes + 2
	// Bounds the encoded failure bitmap through its highest recognized bit.
	maximumFailureInfoBits = failureSystem + 1
	// These two success statuses require an attached timestamp token.
	statusGranted         = 0
	statusGrantedWithMods = 1
	// Highest recognized PKIStatus; unsuccessful statuses return ResponseError.
	statusRevocationNotification = 5
)

// TSTInfo context tags and Accuracy component tags belong to different ASN.1
// structures. Their equal numeric values do not make them interchangeable.
const (
	infoTSANameTag          = 0
	infoExtensionsTag       = 1
	accuracyMillisTag       = 0
	accuracyMicrosTag       = 1
	infoRequiredFields      = 5
	infoMaximumFields       = 10
	responseStatusFields    = 1
	responseWithTokenFields = 2
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
	// raw owns the complete encoded timestamp request.
	raw []byte
	// imprint retains the requested message digest and algorithm.
	imprint Imprint
	// policy is the requested TSA policy OID, if supplied.
	policy asn1.ObjectIdentifier
	// nonce binds a response to this request; nil records an omitted nonce.
	nonce *big.Int
	// certReq requests inclusion of the TSA certificate in the response token.
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
	const nonceTopBit = 0x80 // Generated positive integers retain the full nonce bit width.

	if !validImprint(m) || o.OmitNonce && len(o.Nonce) > 0 {
		return nil, ErrPolicy
	}

	f := [][]byte{der.Int(timestampVersion), encodeImprint(m)}

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
			n = make([]byte, generatedNonceBytes)
			if _, e := rand.Read(n); e != nil {
				return nil, e
			}

			n[0] |= nonceTopBit
		}

		if len(n) < minimumNonceBytes || len(n) > maximumNonceBytes {
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
	if len(b) > maximumRequestBytes {
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

// Info retains parsed TSTInfo. Accept its time claims only after successful token
// verification.
type Info struct {
	// policy is the claimed TSA policy OID.
	policy asn1.ObjectIdentifier
	// imprint is the claimed message digest and algorithm.
	imprint Imprint
	// serial is the TSA-assigned token serial number.
	serial *big.Int
	// nonce is the echoed request nonce, if present.
	nonce *big.Int
	// at is the claimed timestamp generation time.
	at time.Time
	// accuracy is the claimed uncertainty around at when hasAccuracy is true.
	accuracy time.Duration
	// hasAccuracy distinguishes absent accuracy from an explicit zero value.
	hasAccuracy bool
	// ordering is the claimed within-TSA ordering guarantee.
	ordering bool
	// tsa retains the optional encoded TSA name.
	tsa asn1.RawValue
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

	if der.Decode(fields[3], &i.serial) != nil || i.serial == nil || i.serial.Sign() <= 0 || i.serial.BitLen() > maximumSerialBits {
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
	if index < len(fields) && der.Is(fields[index], asn1.ClassUniversal, asn1.TagSequence, true) {
		var e error

		i.accuracy, e = parseAccuracy(fields[index])
		if e != nil {
			return e
		}

		i.hasAccuracy = true
		index++
	}

	if index < len(fields) && der.Is(fields[index], asn1.ClassUniversal, asn1.TagBoolean, false) {
		if der.Decode(fields[index], &i.ordering) != nil || !i.ordering {
			return ErrFormat
		}

		index++
	}

	if index < len(fields) && der.Is(fields[index], asn1.ClassUniversal, asn1.TagInteger, false) {
		if der.Decode(fields[index], &i.nonce) != nil || i.nonce == nil || i.nonce.Sign() <= 0 || i.nonce.BitLen() > maximumNonceBits {
			return ErrFormat
		}

		index++
	}

	if index < len(fields) && der.Is(fields[index], asn1.ClassContextSpecific, infoTSANameTag, true) {
		var e error

		i.tsa, e = der.Explicit(fields[index], infoTSANameTag)
		if e != nil || i.tsa.Class != asn1.ClassContextSpecific {
			return ErrFormat
		}

		index++
	}

	if index < len(fields) && der.Is(fields[index], asn1.ClassContextSpecific, infoExtensionsTag, true) {
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

// Response retains an immutable parsed RFC 3161 response. Parsing does not
// authenticate its token.
type Response struct {
	// raw owns the complete encoded timestamp response.
	raw []byte
	// token retains the attached CMS token only for a successful status.
	token []byte
	// status is the parsed RFC 3161 PKIStatus value.
	status int
	// text contains untrusted TSA diagnostic strings.
	text []string
	// fail retains the PKIFailureInfo bitmap without interpreting it as trust.
	fail asn1.BitString
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

	value, err := der.ReadSequence(ctx, src, maximumResponseBytes)
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
	if r.status == statusGranted || r.status == statusGrantedWithMods {
		if len(f) != responseWithTokenFields || r.fail.BitLength != 0 {
			return nil, ErrFormat
		}

		r.token = f[1].FullBytes
		if validateToken {
			if _, e := cms.Parse(ctx, r.token, cms.DefaultLimits()); e != nil {
				return nil, fmt.Errorf("%w: %w", ErrFormat, e)
			}
		}
	} else {
		if len(f) != responseStatusFields {
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

func validImprint(m Imprint) bool {
	return (m.Hash == crypto.SHA256 || m.Hash == crypto.SHA384 || m.Hash == crypto.SHA512) && len(m.Digest) == m.Hash.Size()
}

func encodeImprint(m Imprint) []byte {
	a, _ := signature.DigestAlgorithm(m.Hash)
	return der.Seq(signature.EncAlgorithm(a), der.Octets(m.Digest))
}

func parseOwnedRequest(b []byte) (*Request, error) {
	const (
		requestRequiredFields = 2
		requestMaximumFields  = 5
	)

	if len(b) > maximumRequestBytes {
		return nil, ErrPolicy
	}

	v, e := der.Read(b, maximumRequestBytes)
	if e != nil {
		return nil, ErrFormat
	}

	f, e := der.Sequence(v, requestRequiredFields, requestMaximumFields)
	if e != nil {
		return nil, ErrFormat
	}

	var ver int
	if der.Decode(f[0], &ver) != nil || ver != timestampVersion {
		return nil, ErrFormat
	}

	m, e := parseImprint(f[1])
	if e != nil {
		return nil, e
	}

	r := &Request{raw: b, imprint: m}

	i := requestRequiredFields
	if i < len(f) && der.Is(f[i], asn1.ClassUniversal, asn1.TagOID, false) {
		if der.Decode(f[i], &r.policy) != nil {
			return nil, ErrFormat
		}

		i++
	}

	if i < len(f) && der.Is(f[i], asn1.ClassUniversal, asn1.TagInteger, false) {
		if der.Decode(f[i], &r.nonce) != nil || r.nonce == nil || r.nonce.Sign() <= 0 || r.nonce.BitLen() > maximumNonceBits {
			return nil, ErrFormat
		}

		i++
	}

	if i < len(f) && der.Is(f[i], asn1.ClassUniversal, asn1.TagBoolean, false) {
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

func encodeTime(t time.Time) ([]byte, error) {
	const nanosecondDigitsFormat = "%09d"

	if t.IsZero() || t.Year() < 1 || t.Year() > maximumTimeYear {
		return nil, ErrPolicy
	}

	s := t.UTC().Format(generalizedTimeSecondsLayout)
	if t.Nanosecond() != 0 {
		s += "." + strings.TrimRight(fmt.Sprintf(nanosecondDigitsFormat, t.Nanosecond()), "0")
	}

	return der.Wrap(asn1.ClassUniversal, asn1.TagGeneralizedTime, false, []byte(s+"Z")), nil
}

func parseTime(v asn1.RawValue) (time.Time, error) {
	if !der.Is(v, asn1.ClassUniversal, asn1.TagGeneralizedTime, false) {
		return time.Time{}, ErrFormat
	}

	s := string(v.Bytes)
	if len(s) < generalizedTimeBaseBytes || !strings.HasSuffix(s, "Z") {
		return time.Time{}, ErrFormat
	}

	if len(s) > generalizedTimeBaseBytes && (s[len(generalizedTimeSecondsLayout)] != '.' || len(s) < generalizedTimeMinimumFractionBytes || len(s) > generalizedTimeMaximumFractionBytes || s[len(s)-2] == '0') {
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
	const (
		accuracySeconds = iota
		accuracyMillis
		accuracyMicros
		accuracyComponentCount
	)

	f, e := der.Sequence(v, 0, accuracyComponentCount)
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
		case der.Is(x, asn1.ClassUniversal, asn1.TagInteger, false):
			kind = accuracySeconds
		case der.Is(x, asn1.ClassContextSpecific, accuracyMillisTag, false):
			kind = accuracyMillis
			unit = time.Millisecond
			b = der.Wrap(asn1.ClassUniversal, asn1.TagInteger, false, x.Bytes)
		case der.Is(x, asn1.ClassContextSpecific, accuracyMicrosTag, false):
			kind = accuracyMicros
			unit = time.Microsecond
			b = der.Wrap(asn1.ClassUniversal, asn1.TagInteger, false, x.Bytes)
		default:
			return 0, ErrFormat
		}

		if kind <= last {
			return 0, ErrFormat
		}

		last = kind

		var n int
		if der.Unmarshal(b, &n) != nil || n < 0 || kind > accuracySeconds && (n < 1 || n > maximumAccuracyFraction) || kind == accuracySeconds && n > maximumAccuracySeconds {
			return 0, ErrFormat
		}

		total += time.Duration(n) * unit
	}

	return total, nil
}

func validateInfoExtensions(v asn1.RawValue) error {
	const (
		extensionRequiredFields = 2
		extensionWithCritical   = 3
	)

	xs, err := der.Children(v)
	if err != nil || len(xs) < 1 || len(xs) > maximumInfoExtensions {
		return ErrFormat
	}

	seen := make(map[string]struct{}, len(xs))

	for _, x := range xs {
		fields, e := der.Sequence(x, extensionRequiredFields, extensionWithCritical)
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

		if len(fields) == extensionWithCritical {
			var critical bool
			if der.Decode(fields[1], &critical) != nil || !critical {
				return ErrFormat
			}

			return ErrPolicy
		}

		if !der.Is(fields[1], asn1.ClassUniversal, asn1.TagOctetString, false) {
			return ErrFormat
		}
	}

	return nil
}

func parseResponseValue(ctx context.Context, v asn1.RawValue, validateToken bool) (*Response, error) {
	const (
		statusRequiredFields = 1
		statusMaximumFields  = 3
	)

	b := v.FullBytes

	f, e := der.Sequence(v, responseStatusFields, responseWithTokenFields)
	if e != nil {
		return nil, ErrFormat
	}

	sf, e := der.Sequence(f[0], statusRequiredFields, statusMaximumFields)
	if e != nil {
		return nil, ErrFormat
	}

	r := &Response{raw: b}
	if der.Decode(sf[0], &r.status) != nil || r.status < statusGranted || r.status > statusRevocationNotification {
		return nil, ErrFormat
	}

	i := 1
	if i < len(sf) && der.Is(sf[i], asn1.ClassUniversal, asn1.TagSequence, true) {
		texts, e := der.Sequence(sf[i], 1, maximumStatusTexts)
		if e != nil {
			return nil, ErrFormat
		}

		for _, s := range texts {
			var msg string
			if !der.Is(s, asn1.ClassUniversal, asn1.TagUTF8String, false) || der.Decode(s, &msg) != nil || len(msg) > maximumStatusTextBytes {
				return nil, ErrFormat
			}

			r.text = append(r.text, msg)
		}

		i++
	}

	if i < len(sf) {
		if der.Decode(sf[i], &r.fail) != nil || r.fail.BitLength > maximumFailureInfoBits {
			return nil, ErrFormat
		}

		i++

		for n := 0; n < r.fail.BitLength; n++ {
			if r.fail.At(n) != 0 && n != failureBadAlgorithm && n != failureBadRequest && n != failureBadDataFormat && n != failureTimeNotAvailable && n != failureUnacceptedPolicy && n != failureUnacceptedExtension && n != failureAdditionalInfoNotAvailable && n != failureSystem {
				return nil, ErrFormat
			}
		}
	}

	if i != len(sf) {
		return nil, ErrFormat
	}

	return r.bindToken(ctx, f, validateToken)
}

func tstOID() asn1.ObjectIdentifier { return asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 1, 4} }

func parseImprint(v asn1.RawValue) (Imprint, error) {
	const imprintFields = 2

	f, e := der.Sequence(v, imprintFields, imprintFields)
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
	v, e := der.Read(b, maximumInfoBytes)
	if e != nil {
		return Info{}, ErrFormat
	}

	f, e := der.Sequence(v, infoRequiredFields, infoMaximumFields)
	if e != nil {
		return Info{}, ErrFormat
	}

	var version int
	if der.Decode(f[0], &version) != nil || version != timestampVersion {
		return Info{}, ErrFormat
	}

	info := Info{}
	if err := info.parseRequiredFields(f); err != nil {
		return info, err
	}

	if err := info.parseOptionalFields(f[infoRequiredFields:]); err != nil {
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
