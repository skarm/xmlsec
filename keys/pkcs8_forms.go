package keys

import (
	"bytes"
	"context"

	"github.com/skarm/xmlsec/internal/ber"
	"github.com/skarm/xmlsec/internal/der"
)

// Normalize only the explicitly selected PKCS#8 wrappers. No ASN.1 inside the
// privateKey OCTET STRING is rewritten, and algorithms/attributes retain their
// original strict DER encodings. The original input is never changed.
func normalizePrivateBER(ctx context.Context, input []byte, maximum int, limits Limits, encrypted bool) ([]byte, error) {
	root, err := ber.Read(ctx, input, ber.Limits{MaxBytes: maximum, MaxDepth: limits.MaxASN1Depth, MaxNodes: limits.MaxASN1Nodes})
	if err != nil {
		return nil, pkcs12BERError(err)
	}

	if root.Tag != 0x30 {
		return nil, ErrFormat
	}

	// Preserve strict DER PKCS#1/SEC1 inputs on the unencrypted API. A BER
	// traditional key remains invalid; compatibility is confined to PKCS#8.
	if !encrypted && len(root.Children) >= 2 && root.Children[1].Tag != 0x30 {
		if _, err := readDER(input, maximum, limits); err != nil {
			return nil, err
		}

		return bytes.Clone(input), nil
	}

	at := 2

	if encrypted {
		if len(root.Children) != 2 {
			return nil, ErrFormat
		}

		at = 1
	} else if len(root.Children) < 3 || len(root.Children) > 4 {
		return nil, ErrFormat
	}

	var octets bytes.Buffer
	defer func() { clear(octets.Bytes()) }()

	if err := ber.AppendOctets(ctx, root.Children[at], &octets, maximum); err != nil {
		return nil, pkcs12BERError(err)
	}

	parts := make([][]byte, 0, len(root.Children))
	for i, child := range root.Children {
		if i == at {
			parts = append(parts, der.Octets(octets.Bytes()))
		} else {
			parts = append(parts, child.Full)
		}
	}

	defer clear(parts[at])

	out := der.Seq(parts...)
	if len(out) > maximum {
		clear(out)
		return nil, ErrLimit
	}

	if _, err := readDER(out, maximum, limits); err != nil {
		clear(out)
		return nil, err
	}

	if err := ctx.Err(); err != nil {
		clear(out)
		return nil, err
	}

	return out, nil
}
