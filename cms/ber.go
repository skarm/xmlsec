package cms

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/skarm/xmlsec/internal/ber"
	"github.com/skarm/xmlsec/internal/der"
	"github.com/skarm/xmlsec/internal/nilcheck"
	"github.com/skarm/xmlsec/internal/streamio"
)

// ParseBER accepts the selected BER forms documented by [ParseBERReader].
// Input must remain unchanged during the call; the result owns its normalized
// encoding. It does not authenticate content or embedded certificates.
func ParseBER(ctx context.Context, b []byte, l Limits) (*SignedData, error) {
	if ctx == nil {
		return nil, ErrPolicy
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	l, err := normalize(l)
	if err != nil {
		return nil, err
	}

	return parseBER(ctx, b, l)
}

// ParseBERReader accepts definite or indefinite ContentInfo, SignedData and
// encapContentInfo wrappers, and recursively constructed eContent OCTET STRINGs.
// Other fields, including SignerInfos and signed attributes, retain the strict
// encoding rules of ParseReader. Signed attribute bytes are never repaired,
// reordered or re-encoded. There is no implicit BER support in Parse/ParseReader.
//
// Both source and normalized encodings obey MaxBytes; flattened content obeys
// MaxContentBytes. Structural parsing permits at most 33 levels (root depth one)
// and 100000 values. The complete source and normalized encoding
// coexist temporarily; this is a bounded materializing parser, not a streaming
// verifier. The caller must supply a reader that honors cancellation; src is
// left open. DER/Size/WriterTo refer to the normalized definite encoding, not
// the original BER representation. Verification and trust policies are unchanged.
func ParseBERReader(ctx context.Context, src io.Reader, l Limits) (*SignedData, error) {
	if ctx == nil || nilcheck.IsNil(src) {
		return nil, ErrPolicy
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	l, err := normalize(l)
	if err != nil {
		return nil, err
	}

	input, err := io.ReadAll(&streamio.Reader{Context: ctx, Source: src, Limit: int64(l.MaxBytes), LimitError: ErrPolicy})
	if err != nil {
		if errors.Is(err, ErrPolicy) {
			return nil, err
		}

		return nil, fmt.Errorf("%w: %w", ErrSyntax, err)
	}

	return parseBER(ctx, input, l)
}

// parseBER borrows input only during normalization; the result owns its DER.
func parseBER(ctx context.Context, input []byte, l Limits) (*SignedData, error) {
	root, err := ber.Read(ctx, input, ber.Limits{MaxBytes: l.MaxBytes, MaxDepth: 33, MaxNodes: 100000})
	if err != nil {
		return nil, cmsBERError(err)
	}

	normalized, err := normalizeCMSBER(ctx, root, l)
	if err != nil {
		return nil, err
	}

	v, err := der.Read(normalized, l.MaxBytes)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrSyntax, err)
	}

	return parseOwned(ctx, v, l)
}

func normalizeCMSBER(ctx context.Context, root ber.Value, limits Limits) ([]byte, error) {
	if root.Tag != 0x30 || len(root.Children) != 2 {
		return nil, ErrSyntax
	}

	explicit := root.Children[1]
	if explicit.Tag != 0xa0 || len(explicit.Children) != 1 {
		return nil, ErrSyntax
	}

	sd := explicit.Children[0]
	if sd.Tag != 0x30 || len(sd.Children) < 4 || len(sd.Children) > 6 {
		return nil, ErrSyntax
	}

	ec := sd.Children[2]
	if ec.Tag != 0x30 || len(ec.Children) < 1 || len(ec.Children) > 2 {
		return nil, ErrSyntax
	}

	// Measure the selected BER octets before allocating the final DER buffer.
	// Opaque signed fields are copied verbatim; only envelope headers change.
	var octets ber.Value

	contentSize := 0
	encapSize := len(ec.Children[0].Full)

	var octetHeader, contentHeader []byte

	if len(ec.Children) == 2 {
		content := ec.Children[1]
		if content.Tag != 0xa0 || len(content.Children) != 1 {
			return nil, ErrSyntax
		}

		octets = content.Children[0]

		var err error

		contentSize, err = ber.OctetLength(ctx, octets, limits.MaxContentBytes)
		if err != nil {
			return nil, cmsBERError(err)
		}

		octetHeader = der.Header(4, contentSize)
		contentHeader = der.Header(0xa0, len(octetHeader)+contentSize)
		encapSize += len(contentHeader) + len(octetHeader) + contentSize
	}

	encapHeader := der.Header(0x30, encapSize)
	signedSize := len(encapHeader) + encapSize

	for i, field := range sd.Children {
		if i != 2 {
			signedSize += len(field.Full)
		}
	}

	signedHeader := der.Header(0x30, signedSize)
	explicitHeader := der.Header(0xa0, len(signedHeader)+signedSize)
	rootSize := len(root.Children[0].Full) + len(explicitHeader) + len(signedHeader) + signedSize

	rootHeader := der.Header(0x30, rootSize)
	if len(rootHeader)+rootSize > limits.MaxBytes {
		return nil, ErrPolicy
	}

	var output bytes.Buffer
	output.Grow(len(rootHeader) + rootSize)
	output.Write(rootHeader)
	output.Write(root.Children[0].Full)
	output.Write(explicitHeader)
	output.Write(signedHeader)

	for i, field := range sd.Children {
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		if i != 2 {
			output.Write(field.Full)
			continue
		}

		output.Write(encapHeader)
		output.Write(ec.Children[0].Full)

		if len(ec.Children) == 2 {
			output.Write(contentHeader)
			output.Write(octetHeader)

			if err := ber.AppendOctets(ctx, octets, &output, output.Len()+contentSize); err != nil {
				return nil, cmsBERError(err)
			}
		}
	}

	return output.Bytes(), nil
}

func cmsBERError(err error) error {
	if errors.Is(err, ber.ErrLimit) {
		return errors.Join(ErrPolicy, err)
	}

	if errors.Is(err, ber.ErrSyntax) {
		return errors.Join(ErrSyntax, err)
	}

	return err
}
