package der

import (
	"bytes"
	"context"
	"encoding/asn1"
	"errors"
	"fmt"
	"io"
	"math"
	"slices"
	"time"
	"unicode/utf8"

	"github.com/skarm/xmlsec/internal/nilcheck"
	"github.com/skarm/xmlsec/internal/streamio"
)

const (
	defaultMaxNodes              = 100000
	defaultReadDepth             = 33
	generalizedTimeDigits        = 14
	generalizedTimeSecondsLayout = "20060102150405"
	utcTimeDigits                = 12
	utcTimeSecondsLayout         = "060102150405"
)

// ASN.1 identifier and length parameters shared by the DER encoder and the
// borrowed views. The views use them only after complete DER validation.
const (
	identifierClassShift = 6
	identifierClassMask  = 3
	highTagNumber        = 0x1f
	constructedBit       = 0x20
	base128Bits          = 7
	base128PayloadMask   = 0x7f
	base128Continuation  = 0x80
	longLengthFlag       = 0x80
	longLengthCountMask  = 0x7f
	maximumLengthOctets  = 8
	octetBits            = 8
	octetRadix           = 256
	minimumHeaderBytes   = 2
	sequenceTag          = constructedBit | asn1.TagSequence
	setTag               = constructedBit | asn1.TagSet
	contextConstructed   = asn1.ClassContextSpecific<<identifierClassShift | constructedBit
)

// ErrInvalidDER reports invalid or unsupported DER.
var ErrInvalidDER = errors.New("invalid or unsupported DER")

// ErrLimit reports an exhausted DER byte, nesting or value-count budget.
var ErrLimit = errors.New("DER resource limit exceeded")

// Read validates schema-independent DER constraints on one complete value,
// with at most 32 levels below the root and 100000 values. Implicit types,
// DEFAULT omission and open-type semantics require schema-specific validation.
func Read(b []byte, maximum int) (asn1.RawValue, error) {
	return ReadLimits(b, maximum, defaultReadDepth, defaultMaxNodes)
}

// ReadLimits validates complete DER with explicit byte, depth and value-count budgets.
// The root is at depth one. Limits must be positive.
func ReadLimits(b []byte, maximum, maxDepth, maxNodes int) (asn1.RawValue, error) {
	if len(b) == 0 || maximum < 1 || maxDepth < 1 || maxNodes < 1 {
		return asn1.RawValue{}, ErrInvalidDER
	}

	if len(b) > maximum {
		return asn1.RawValue{}, fmt.Errorf("%w: %w", ErrInvalidDER, ErrLimit)
	}

	count := 0

	v, r, e := read(b, 1, &count, maxDepth, maxNodes)
	if e != nil || len(r) != 0 {
		return asn1.RawValue{}, fmt.Errorf("%w: complete value: %w", ErrInvalidDER, e)
	}

	return v, nil
}

// Children decodes the direct components of a constructed DER value.
func Children(v asn1.RawValue) ([]asn1.RawValue, error) {
	return ChildrenLimit(v, defaultMaxNodes)
}

// ChildrenLimit decodes at most maximum direct components without allocating an oversized slice.
func ChildrenLimit(v asn1.RawValue, maximum int) ([]asn1.RawValue, error) {
	if !v.IsCompound {
		return nil, ErrInvalidDER
	}

	var out []asn1.RawValue

	b := v.Bytes
	for len(b) > 0 {
		if len(out) >= maximum {
			return nil, fmt.Errorf("%w: %w", ErrInvalidDER, ErrLimit)
		}

		var x asn1.RawValue

		r, e := asn1.Unmarshal(b, &x)
		if e != nil {
			return nil, ErrInvalidDER
		}

		out = append(out, x)
		b = r
	}

	return out, nil
}

// Is compares a DER value with the required class, tag and construction flag.
func Is(v asn1.RawValue, c, t int, compound bool) bool {
	return v.Class == c && v.Tag == t && v.IsCompound == compound
}

// Sequence decodes a DER SEQUENCE with the required component-count range.
func Sequence(v asn1.RawValue, minimum, maximum int) ([]asn1.RawValue, error) {
	if !Is(v, asn1.ClassUniversal, asn1.TagSequence, true) {
		return nil, ErrInvalidDER
	}

	f, e := ChildrenLimit(v, maximum)
	if e != nil {
		return nil, e
	}

	if len(f) < minimum || len(f) > maximum {
		return nil, ErrInvalidDER
	}

	return f, nil
}

// Decode decodes a complete DER value into out and rejects trailing bytes.
func Decode(v asn1.RawValue, out any) error {
	r, e := asn1.Unmarshal(v.FullBytes, out)
	if e != nil || len(r) != 0 {
		return fmt.Errorf("%w: %w", ErrInvalidDER, e)
	}

	return nil
}

// Unmarshal validates a complete DER structure before decoding it into out.
func Unmarshal(b []byte, out any) error {
	v, e := Read(b, len(b))
	if e != nil {
		return e
	}

	return Decode(v, out)
}

// Explicit unwraps one explicitly tagged context-specific value.
func Explicit(v asn1.RawValue, tag int) (asn1.RawValue, error) {
	if !Is(v, asn1.ClassContextSpecific, tag, true) {
		return asn1.RawValue{}, ErrInvalidDER
	}

	f, e := ChildrenLimit(v, 1)
	if e != nil || len(f) != 1 {
		return asn1.RawValue{}, ErrInvalidDER
	}

	return f[0], nil
}

// Wrap encodes a DER tag and definite length around the supplied content.
func Wrap(class, tag int, compound bool, b []byte) []byte {
	if class >= 0 && class <= asn1.ClassPrivate && tag >= 0 && tag < highTagNumber {
		tagByte := byte(class&identifierClassMask)<<identifierClassShift | byte(tag&highTagNumber)
		if compound {
			tagByte |= constructedBit
		}

		return wrapParts(tagByte, b)
	}

	out, e := asn1.Marshal(asn1.RawValue{Class: class, Tag: tag, IsCompound: compound, Bytes: b})
	if e != nil {
		panic("der.Wrap: invalid internal tag")
	}

	return out
}

// Seq encodes a DER SEQUENCE from encoded components.
func Seq(parts ...[]byte) []byte { return wrapParts(sequenceTag, parts...) }

// Set encodes a DER SET OF with lexicographically sorted encoded components.
func Set(parts ...[]byte) []byte {
	parts = append([][]byte(nil), parts...)
	slices.SortFunc(parts, bytes.Compare)

	return wrapParts(setTag, parts...)
}

// Ctx encodes a constructed context-specific value from encoded components.
func Ctx(tag int, parts ...[]byte) []byte {
	if tag >= 0 && tag < highTagNumber {
		return wrapParts(contextConstructed|byte(tag), parts...)
	}

	return Wrap(asn1.ClassContextSpecific, tag, true, bytes.Join(parts, nil))
}

// OID encodes an object identifier, returning nil for an invalid value.
func OID(o asn1.ObjectIdentifier) []byte {
	b, e := asn1.Marshal(o)
	if e != nil {
		return nil
	}

	return b
}

// Octets encodes a DER OCTET STRING.
func Octets(b []byte) []byte { return Wrap(asn1.ClassUniversal, asn1.TagOctetString, false, b) }

// Int encodes a DER INTEGER.
func Int(n int) []byte { b, _ := asn1.Marshal(n); return b }

// OIDEqual reports whether a complete DER object identifier equals o.
func OIDEqual(v asn1.RawValue, o asn1.ObjectIdentifier) bool {
	var got asn1.ObjectIdentifier
	return Decode(v, &got) == nil && got.Equal(o)
}

// SetFields validates a bounded SET OF, including ordering for implicitly tagged values.
func SetFields(v asn1.RawValue, c, t, maximum int) ([]asn1.RawValue, error) {
	if !Is(v, c, t, true) {
		return nil, ErrInvalidDER
	}

	f, e := ChildrenLimit(v, maximum)
	if e != nil {
		return nil, e
	}

	if len(f) > maximum {
		return nil, ErrInvalidDER
	}

	for i := 1; i < len(f); i++ {
		if bytes.Compare(f[i-1].FullBytes, f[i].FullBytes) > 0 {
			return nil, fmt.Errorf("%w: implicit SET order", ErrInvalidDER)
		}
	}

	return f, nil
}

// ReadSequence reads one complete definite-length DER SEQUENCE into owned
// storage. Its length is checked before allocating the body; trailing data is
// rejected. The parsed model and this encoding remain materialized.
func ReadSequence(ctx context.Context, src io.Reader, maximum int) (asn1.RawValue, error) {
	if ctx == nil || nilcheck.IsNil(src) || maximum < minimumHeaderBytes {
		return asn1.RawValue{}, ErrInvalidDER
	}

	source := &streamio.Reader{Context: ctx, Source: src, Limit: int64(maximum), LimitError: ErrLimit}

	var header [minimumHeaderBytes + maximumLengthOctets]byte
	if _, err := io.ReadFull(source, header[:minimumHeaderBytes]); err != nil {
		return asn1.RawValue{}, err
	}

	if header[0] != sequenceTag {
		return asn1.RawValue{}, ErrInvalidDER
	}

	length, used := int(header[1]), minimumHeaderBytes
	if length >= longLengthFlag {
		count := length & longLengthCountMask
		if count == 0 || count > maximumLengthOctets {
			return asn1.RawValue{}, ErrInvalidDER
		}

		if _, err := io.ReadFull(source, header[minimumHeaderBytes:minimumHeaderBytes+count]); err != nil {
			return asn1.RawValue{}, err
		}

		if header[minimumHeaderBytes] == 0 {
			return asn1.RawValue{}, ErrInvalidDER
		}

		length = 0
		for _, c := range header[minimumHeaderBytes : minimumHeaderBytes+count] {
			if length > (maximum-int(c))/octetRadix {
				return asn1.RawValue{}, ErrLimit
			}

			length = length*octetRadix + int(c)
		}

		if length < longLengthFlag {
			return asn1.RawValue{}, ErrInvalidDER
		}

		used += count
	}

	if length > maximum-used {
		return asn1.RawValue{}, ErrLimit
	}

	raw := make([]byte, used+length)
	copy(raw, header[:used])

	if _, err := io.ReadFull(source, raw[used:]); err != nil {
		return asn1.RawValue{}, err
	}

	var extra [1]byte
	// Only bare EOF proves that no trailing value or source failure remains.
	if n, err := io.ReadFull(source, extra[:]); n != 0 || err != io.EOF {
		if err == nil || n > 0 {
			err = ErrInvalidDER
		}

		return asn1.RawValue{}, err
	}

	return Read(raw, maximum)
}

// Header encodes a short-tag DER header without allocating its payload.
// tag includes class/construction bits; length must be nonnegative.
func Header(tag byte, length int) []byte {
	if length < 0 || tag&highTagNumber == highTagNumber {
		panic("der.Header: invalid internal tag or length")
	}

	if length < longLengthFlag {
		return []byte{tag, byte(length & longLengthCountMask)}
	}

	var encoded [maximumLengthOctets]byte

	used := len(encoded)
	for length > 0 {
		used--
		encoded[used] = byte(length & math.MaxUint8)
		length >>= octetBits
	}

	result := make([]byte, minimumHeaderBytes, minimumHeaderBytes+len(encoded)-used)
	result[0], result[1] = tag, longLengthFlag|byte(len(encoded)-used)

	return append(result, encoded[used:]...)
}

func read(b []byte, depth int, count *int, maxDepth, maxNodes int) (asn1.RawValue, []byte, error) {
	*count++
	if depth > maxDepth || *count > maxNodes {
		return asn1.RawValue{}, nil, fmt.Errorf("%w: %w", ErrInvalidDER, ErrLimit)
	}

	if len(b) < minimumHeaderBytes {
		return asn1.RawValue{}, nil, ErrInvalidDER
	}

	var v asn1.RawValue

	r, e := asn1.Unmarshal(b, &v)
	if e != nil {
		return v, nil, fmt.Errorf("%w: %w", ErrInvalidDER, e)
	}

	if err := validateUniversalDER(v); err != nil {
		return v, nil, err
	}

	if err := validateConstructedDER(v, depth, count, maxDepth, maxNodes); err != nil {
		return v, nil, err
	}

	return v, r, nil
}

func validateConstructedDER(v asn1.RawValue, depth int, count *int, maxDepth, maxNodes int) error {
	if !v.IsCompound {
		return nil
	}

	content := v.Bytes

	var previous asn1.RawValue

	lexicalOrder, tagOrder := true, true

	for len(content) > 0 {
		child, rest, err := read(content, depth+1, count, maxDepth, maxNodes)
		if err != nil {
			return err
		}

		if v.Class == asn1.ClassUniversal && v.Tag == asn1.TagSet && previous.FullBytes != nil {
			lexicalOrder = lexicalOrder && bytes.Compare(previous.FullBytes, child.FullBytes) <= 0
			tagOrder = tagOrder && (previous.Class < child.Class || previous.Class == child.Class && previous.Tag < child.Tag)
		}

		previous = child
		content = rest
	}

	// SET and SET OF share a tag. Without a schema, either canonical order is
	// possible (X.690 10.3 / 11.6). Known SET OF fields use SetFields to enforce
	// their schema's lexical ordering, including implicitly tagged sets.
	if v.Class == asn1.ClassUniversal && v.Tag == asn1.TagSet && !lexicalOrder && !tagOrder {
		return fmt.Errorf("%w: SET order", ErrInvalidDER)
	}

	return nil
}

func validateUniversalDER(v asn1.RawValue) error {
	if v.Class != asn1.ClassUniversal {
		return nil
	}

	switch v.Tag {
	case asn1.TagSequence, asn1.TagSet:
		if !v.IsCompound {
			return ErrInvalidDER
		}
	case asn1.TagBoolean:
		const derTrue = 0xff
		if v.IsCompound || len(v.Bytes) != 1 || (v.Bytes[0] != 0 && v.Bytes[0] != derTrue) {
			return ErrInvalidDER
		}
	case asn1.TagInteger, asn1.TagEnum:
		if !validDERInteger(v) {
			return ErrInvalidDER
		}
	case asn1.TagBitString:
		if !validDERBitString(v) {
			return ErrInvalidDER
		}
	case asn1.TagNull:
		if v.IsCompound || len(v.Bytes) != 0 {
			return ErrInvalidDER
		}
	case asn1.TagOID:
		if v.IsCompound || !validDEROID(v.Bytes) {
			return ErrInvalidDER
		}
	case asn1.TagOctetString, asn1.TagUTF8String, asn1.TagPrintableString, asn1.TagT61String, asn1.TagIA5String, asn1.TagUTCTime, asn1.TagGeneralizedTime, asn1.TagGeneralString, asn1.TagBMPString, asn1.TagNumericString:
		if v.IsCompound || !validDERContent(v.Tag, v.Bytes) {
			return ErrInvalidDER
		}
	default:
		return fmt.Errorf("%w: universal tag %d", ErrInvalidDER, v.Tag)
	}

	return nil
}

// Match encoding/asn1's canonical base-128, signed32-bit subidentifier profile
// without allocating an OID slice and re-marshaling an already validated header.
func validDEROID(content []byte) bool {
	if len(content) == 0 {
		return false
	}

	for at := 0; at < len(content); {
		if content[at] == base128Continuation { // Leading zero base-128 group is nonminimal.
			return false
		}

		var value int64

		for {
			if at == len(content) {
				return false
			}

			octet := content[at]
			at++

			value = value<<base128Bits | int64(octet&base128PayloadMask)
			if value > math.MaxInt32 {
				return false
			}

			if octet&base128Continuation == 0 {
				break
			}
		}
	}

	return true
}

func validDERContent(tag int, b []byte) bool {
	switch tag {
	case asn1.TagUTF8String:
		return utf8.Valid(b)
	case asn1.TagPrintableString, asn1.TagIA5String, asn1.TagNumericString:
		for _, c := range b {
			if !validDERCharacter(tag, c) {
				return false
			}
		}
	case asn1.TagBMPString:
		const (
			codeUnitBytes  = 2
			firstSurrogate = 0xd800
			lastSurrogate  = 0xdfff
			firstNonchar   = 0xfffe
		)
		if len(b)%codeUnitBytes != 0 {
			return false
		}

		for i := 0; i < len(b); i += codeUnitBytes {
			c := uint16(b[i])<<octetBits | uint16(b[i+1])
			if c >= firstSurrogate && c <= lastSurrogate || c >= firstNonchar {
				return false
			}
		}
	case asn1.TagUTCTime, asn1.TagGeneralizedTime:
		return validDERTime(tag, b)
	}

	return true
}

func validDERCharacter(tag int, c byte) bool {
	switch tag {
	case asn1.TagIA5String:
		return c < utf8.RuneSelf
	case asn1.TagNumericString:
		return c == ' ' || c >= '0' && c <= '9'
	default: // X.680 Table 10, without Go's legacy '*' and '&' exceptions.
		const printablePunctuation = " '()+,-./:=?"
		return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || bytes.IndexByte([]byte(printablePunctuation), c) >= 0
	}
}

func validDERTime(tag int, b []byte) bool {
	// Fractional GeneralizedTime needs a dot, at least one digit and final Z.
	const minimumFractionSuffixBytes = 3

	const (
		generalizedClockOffset = 8
		leapSecondClock        = "235960"
		ordinaryLastSecond     = "59"
		secondDigits           = 2
	)

	width, layout := utcTimeDigits, utcTimeSecondsLayout
	if tag == asn1.TagGeneralizedTime {
		width, layout = generalizedTimeDigits, generalizedTimeSecondsLayout
	}

	if len(b) < width+1 || b[len(b)-1] != 'Z' {
		return false
	}

	for _, c := range b[:width] {
		if c < '0' || c > '9' {
			return false
		}
	}

	if len(b) != width+1 {
		if tag != asn1.TagGeneralizedTime || len(b) < width+minimumFractionSuffixBytes || b[width] != '.' || b[len(b)-2] == '0' {
			return false
		}

		// DER allows arbitrary fractional precision; do not round it through time.Time.
		for _, c := range b[width+1 : len(b)-1] {
			if c < '0' || c > '9' {
				return false
			}
		}
	}

	calendar := string(b[:width])
	if tag == asn1.TagGeneralizedTime && calendar[generalizedClockOffset:] == leapSecondClock {
		// GeneralizedTime follows ISO 8601, including the leap-second notation.
		calendar = calendar[:width-secondDigits] + ordinaryLastSecond
	}

	_, err := time.Parse(layout, calendar)

	return err == nil
}

func validDERInteger(v asn1.RawValue) bool {
	const (
		signBit        = 0x80
		negativePrefix = 0xff
	)

	return !(v.IsCompound || len(v.Bytes) == 0 || len(v.Bytes) > 1 && ((v.Bytes[0] == 0 && v.Bytes[1]&signBit == 0) || (v.Bytes[0] == negativePrefix && v.Bytes[1]&signBit != 0)))
}

func validDERBitString(v asn1.RawValue) bool {
	const maximumUnusedBits = octetBits - 1
	return !(v.IsCompound || len(v.Bytes) == 0 || v.Bytes[0] > maximumUnusedBits || len(v.Bytes) == 1 && v.Bytes[0] != 0 || len(v.Bytes) > 1 && v.Bytes[len(v.Bytes)-1]&byte((1<<v.Bytes[0])-1) != 0)
}

// wrapParts copies encoded components directly into the owned final value.
func wrapParts(tag byte, parts ...[]byte) []byte {
	size := 0
	for _, part := range parts {
		if len(part) > math.MaxInt-size {
			panic("der: encoded value too large")
		}

		size += len(part)
	}

	header := Header(tag, size)
	if size > math.MaxInt-len(header) {
		panic("der: encoded value too large")
	}

	out := make([]byte, len(header)+size)

	at := copy(out, header)
	for _, part := range parts {
		at += copy(out[at:], part)
	}

	return out
}
