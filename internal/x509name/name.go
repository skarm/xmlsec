// Package x509name compares bounded X.509 distinguished names without changing
// their original DER, which remains the input to signatures and identifier hashes.
package x509name

import (
	"bytes"
	"context"
	"encoding/asn1"
	"encoding/binary"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/skarm/xmlsec/internal/der"
)

var (
	// ErrInvalid reports malformed DER or a prohibited stored string.
	ErrInvalid = errors.New("invalid distinguished name")
	// ErrUnsupported reports an attribute encoding outside the selected matching profile.
	ErrUnsupported = errors.New("unsupported distinguished name encoding")
	// ErrLimit reports the fixed byte, RDN, AVA or prepared-key budget.
	ErrLimit = errors.New("distinguished name resource limit exceeded")
)

const (
	maxNameBytes = 64 << 10
	maxRDNs      = 256
	maxAVAs      = 1024
	maxKeyBytes  = 1 << 20
)

// Key returns an unambiguous comparison key under RFC5280 section7.1.
// UTF8String and PrintableString use RFC4518 caseIgnoreMatch/Unicode3.2;
// domainComponent IA5String uses the exact ASCII case-insensitive rule in7.3.
// Other attribute encodings return ErrUnsupported. Empty RDNSequence is allowed;
// each present RDN must contain at least one AVA. The input is never modified.
// Limits are64KiB DER,256 RDNs,1024 AVAs and1MiB prepared key.
func Key(ctx context.Context, rawDER []byte) (string, error) {
	if ctx == nil {
		return "", ErrInvalid
	}

	if err := ctx.Err(); err != nil {
		return "", err
	}

	if len(rawDER) > maxNameBytes {
		return "", ErrLimit
	}

	raw := string(rawDER)
	if key, ok := nameCacheGet(raw); ok {
		if err := ctx.Err(); err != nil {
			return "", err
		}

		return key, nil
	}

	key, err := key(ctx, rawDER)
	if err != nil {
		return "", err
	}

	if err := ctx.Err(); err != nil {
		return "", err
	}

	nameCachePut(raw, key)

	return key, nil
}

// Equal performs semantic name comparison. Invalid/unsupported input or exhausted
// limits return false with an error; even identical malformed DER is rejected.
func Equal(ctx context.Context, a, b []byte) (bool, error) {
	left, err := Key(ctx, a)
	if err != nil {
		return false, err
	}

	right, err := Key(ctx, b)
	if err != nil {
		return false, err
	}

	if err := ctx.Err(); err != nil {
		return false, err
	}

	return left == right, nil
}

// EqualOrExact uses strict semantic comparison where supported. Only identical,
// completely validated DER may fall back when an optional value encoding is
// unsupported. Invalid/prohibited names, limits and cancellation never fall back.
func EqualOrExact(ctx context.Context, a, b []byte) (bool, error) {
	same, err := Equal(ctx, a, b)
	if err == nil || !errors.Is(err, ErrUnsupported) {
		return same, err
	}

	if ctx == nil {
		return false, ErrInvalid
	}

	if control := ctx.Err(); control != nil {
		return false, control
	}

	if bytes.Equal(a, b) {
		return true, nil
	}

	return false, err
}

func key(ctx context.Context, raw []byte) (string, error) {
	root, err := der.ReadLimits(raw, maxNameBytes, 6, 1+maxRDNs+5*maxAVAs)
	if err != nil {
		return "", nameDERError(err)
	}

	if root.Class != 0 || root.Tag != asn1.TagSequence || !root.IsCompound {
		return "", ErrInvalid
	}

	rdns, err := der.ChildrenLimit(root, maxRDNs)
	if err != nil {
		return "", nameDERError(err)
	}

	out := binary.AppendUvarint([]byte("DN4518\x00"), uint64(len(rdns)))
	count := 0
	unsupported := false

	for _, rdn := range rdns {
		if err := ctx.Err(); err != nil {
			return "", err
		}

		if rdn.Class != 0 || rdn.Tag != asn1.TagSet || !rdn.IsCompound {
			return "", ErrInvalid
		}

		avas, err := der.ChildrenLimit(rdn, maxAVAs-count)
		if err != nil {
			return "", nameDERError(err)
		}

		if len(avas) == 0 {
			return "", ErrInvalid
		}

		count += len(avas)

		keys := make([]string, 0, len(avas))
		for _, ava := range avas {
			k, err := avaKey(ctx, ava)
			if errors.Is(err, ErrUnsupported) {
				unsupported = true
				continue
			}

			if err != nil {
				return "", err
			}

			keys = append(keys, k)
		}

		slices.Sort(keys)

		out = binary.AppendUvarint(out, uint64(len(keys)))
		for _, k := range keys {
			if len(k) > maxKeyBytes-len(out)-10 {
				return "", ErrLimit
			}

			out = binary.AppendUvarint(out, uint64(len(k)))
			out = append(out, k...)
		}
	}

	if unsupported {
		return "", ErrUnsupported
	}

	return string(out), ctx.Err()
}

func avaKey(ctx context.Context, ava asn1.RawValue) (string, error) {
	if ava.Class != 0 || ava.Tag != asn1.TagSequence || !ava.IsCompound {
		return "", ErrInvalid
	}

	fields, err := der.ChildrenLimit(ava, 2)
	if err != nil || len(fields) != 2 {
		return "", ErrInvalid
	}

	typ, value := fields[0], fields[1]

	if typ.Class != 0 || typ.Tag != asn1.TagOID || typ.IsCompound {
		return "", ErrInvalid
	}

	if len(typ.Bytes) > 128 {
		return "", ErrLimit
	}

	var oid asn1.ObjectIdentifier
	if der.Unmarshal(typ.FullBytes, &oid) != nil {
		return "", ErrInvalid
	}

	if value.Class != 0 || value.IsCompound {
		return "", ErrUnsupported
	}

	var prepared string

	kind := byte(1)

	if oid.Equal(asn1.ObjectIdentifier{0, 9, 2342, 19200300, 100, 1, 25}) {
		if value.Tag != asn1.TagIA5String {
			return "", ErrUnsupported
		}

		prepared = strings.ToLower(string(value.Bytes)) // DER scanner already enforces ASCII.
		kind = 2
	} else {
		if value.Tag != asn1.TagUTF8String && value.Tag != asn1.TagPrintableString {
			return "", ErrUnsupported
		}

		prepared, err = prepare(ctx, string(value.Bytes))
		if err != nil {
			return "", err
		}
	}

	out := binary.AppendUvarint(nil, uint64(len(typ.Bytes)))
	out = append(out, typ.Bytes...)
	out = append(out, kind)
	out = append(out, prepared...)

	return string(out), nil
}

func nameDERError(err error) error {
	if errors.Is(err, der.ErrLimit) {
		return fmt.Errorf("%w: %w", ErrLimit, err)
	}

	return fmt.Errorf("%w: %w", ErrInvalid, err)
}
