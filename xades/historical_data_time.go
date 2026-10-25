package xades

import (
	"bytes"
	"context"
	"crypto/sha256"
	"io"
	"slices"

	"github.com/skarm/xmlsec/c14n"
	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/internal/historical"
	"github.com/skarm/xmlsec/internal/streamio"
	"github.com/skarm/xmlsec/timestamp"
)

func appendHistoricalDataTimestamps(ctx context.Context, baseline *BaselineResult, objects *historicalObjects, input *historical.Input) error {
	for _, value := range baseline.DataTimestamps() {
		hash := value.Token().UnverifiedInfo().Imprint().Hash
		if hash == 0 || !hash.Available() {
			return ErrTimestamp
		}

		state := hash.New()
		candidate := historical.Candidate{Content: true, Token: value.Token()}

		remaining := value.maximum
		for _, ref := range value.references {
			raw, err := objects.write(func(dst io.Writer) error {
				writer := streamio.Writer{Context: ctx, Target: io.MultiWriter(dst, state), Limit: int64(remaining), LimitError: historical.ErrLimit}
				_, err := ref.WriteCanonicalizedInput(ctx, &writer, value.method)

				return err
			})
			if err != nil {
				return err
			}

			remaining -= len(raw)

			children, err := objects.contained(raw)
			if err != nil {
				return err
			}

			key, err := objects.add(raw, "data", children)
			if err != nil {
				return err
			}

			steps := ref.Steps()
			if len(steps) > 0 && steps[len(steps)-1].Implicit {
				if err := linkDataTimestampCanonicalEncoding(ctx, objects, key, raw, value.maximum); err != nil {
					return err
				}
			}

			candidate.Covered = append(candidate.Covered, key)
		}

		candidate.Imprint = timestamp.Imprint{Hash: hash, Digest: state.Sum(nil)}
		input.Timestamps = append(input.Timestamps, candidate)
	}

	return ctx.Err()
}

// An alternative timestamp canonicalization proves an original reference input
// only when canonicalizing those actual protected bytes reproduces a known
// original encoding exactly. No original ancestor or unprotected namespace is
// borrowed to manufacture the link.
func linkDataTimestampCanonicalEncoding(ctx context.Context, objects *historicalObjects, parent [32]byte, raw []byte, maximum int) error {
	doc, err := document.Parse(ctx, raw, document.DefaultLimits())
	if err != nil {
		return ctx.Err()
	}

	var canonical bytes.Buffer

	writer := streamio.Writer{Context: ctx, Target: &canonical, Limit: int64(maximum), LimitError: historical.ErrLimit}
	if err := c14n.WriteDocument(ctx, &writer, doc, c14n.Options{Algorithm: c14n.Canonical10, MaxOutputBytes: maximum}); err != nil {
		return err
	}

	key := sha256.Sum256(canonical.Bytes())
	if key == parent {
		return nil
	}

	index, exists := objects.index[key]
	if !exists || !slices.Contains(objects.references, key) || !bytes.Equal(objects.objects[index].Bytes, canonical.Bytes()) {
		return nil
	}

	container := &objects.objects[objects.index[parent]]
	if !slices.Contains(container.Contains, key) {
		container.Contains = append(container.Contains, key)
	}

	return nil
}
