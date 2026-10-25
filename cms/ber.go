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
// It does not authenticate content or embedded certificates.
func ParseBER(ctx context.Context, b []byte, l Limits) (*SignedData, error) {
	return ParseBERReader(ctx, bytes.NewReader(b), l)
}

// ParseBERReader accepts definite or indefinite ContentInfo, SignedData and
// encapContentInfo wrappers, and recursively constructed eContent OCTET STRINGs.
// Other fields, including SignerInfos and signed attributes, retain the strict
// encoding rules of ParseReader. Signed attribute bytes are never repaired,
// reordered or re-encoded. There is no implicit BER support in Parse/ParseReader.
//
// Both source and normalized encodings obey MaxBytes; flattened content obeys
// MaxContentBytes. Structural parsing permits at most 33 levels (root depth one)
// and 100000 values. The complete source, intermediate encoding and parsed model
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

	root, err := ber.Read(ctx, input, ber.Limits{MaxBytes: l.MaxBytes, MaxDepth: 33, MaxNodes: 100000})
	if err != nil {
		return nil, cmsBERError(err)
	}

	normalized, err := normalizeCMSBER(ctx, root, l.MaxContentBytes)
	if err != nil {
		return nil, err
	}

	if len(normalized) > l.MaxBytes {
		return nil, ErrPolicy
	}

	return Parse(ctx, normalized, l)
}

func normalizeCMSBER(ctx context.Context, root ber.Value, maxContent int) ([]byte, error) {
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

	encap := ec.Children[0].Full
	if len(ec.Children) == 2 {
		content := ec.Children[1]
		if content.Tag != 0xa0 || len(content.Children) != 1 {
			return nil, ErrSyntax
		}

		var output bytes.Buffer
		if err := ber.AppendOctets(ctx, content.Children[0], &output, maxContent); err != nil {
			return nil, cmsBERError(err)
		}

		encap = append(bytes.Clone(encap), der.Ctx(0, der.Octets(output.Bytes()))...)
	}

	parts := make([][]byte, len(sd.Children))
	for i, field := range sd.Children {
		parts[i] = field.Full
	}

	parts[2] = der.Seq(encap)

	return der.Seq(root.Children[0].Full, der.Ctx(0, der.Seq(parts...))), nil
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
