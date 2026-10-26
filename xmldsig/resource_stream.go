package xmldsig

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"

	"github.com/skarm/xmlsec/internal/nilcheck"
	"github.com/skarm/xmlsec/internal/streamio"
	"github.com/skarm/xmlsec/reference"
)

// referenceSource can reopen explicitly authorized application resources for
// WriteDigestInput. Ordinary verification retains only digests and reports.
// Explicit external Manifest traversal also retains its bounded original bytes
// until they can be authenticated and parsed in their own document scope.
type referenceSource struct {
	resolver        Resolver
	uri             string
	limits          ResourceLimits
	rawDigest       []byte
	captureManifest bool
	rawManifest     []byte
}

func (s *referenceSource) write(ctx context.Context, dst io.Writer, ts []reference.Transform, opt reference.Options, remaining, resources *int) (*reference.Report, error) {
	return s.writeOutputs(ctx, dst, nil, reference.Transform{}, ts, opt, remaining, resources)
}

func (s *referenceSource) writeOutputs(ctx context.Context, dst, canonical io.Writer, method reference.Transform, ts []reference.Transform, opt reference.Options, remaining, resources *int) (out *reference.Report, resultErr error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	if *resources <= 0 || *remaining <= 0 {
		return nil, fmt.Errorf("%w: resource byte budget", ErrPolicy)
	}

	reader, err := s.resolver.Resolve(ctx, s.uri)
	if !nilcheck.IsNil(reader) {
		defer func() {
			if closeErr := reader.Close(); closeErr != nil {
				out = nil
				resultErr = errors.Join(resultErr, fmt.Errorf("close resource: %w", closeErr))
			}

			if err := ctx.Err(); err != nil {
				out = nil
				resultErr = errors.Join(resultErr, err)
			}
		}()
	}

	if err != nil {
		return nil, err
	}

	if nilcheck.IsNil(reader) {
		return nil, fmt.Errorf("%w: nil resource reader", ErrReference)
	}

	bounded := &streamio.Reader{Context: ctx, Source: reader, Limit: int64(min(s.limits.MaxResourceBytes, *resources)), LimitError: ErrPolicy}

	if opt.MaxProducedBytes == 0 || opt.MaxProducedBytes > *remaining {
		opt.MaxProducedBytes = *remaining
	}

	rawHash := sha256.New()

	var (
		captured  bytes.Buffer
		rawWriter io.Writer = rawHash
	)
	if s.captureManifest && s.rawManifest == nil {
		rawWriter = io.MultiWriter(rawHash, &captured)
	}

	source := io.TeeReader(bounded, rawWriter)
	if canonical == nil {
		out, err = reference.WriteReader(ctx, dst, source, ts, opt)
	} else {
		out, err = reference.WriteReaderAndCanonicalize(ctx, dst, canonical, source, ts, method, opt)
	}

	*resources -= int(bounded.ReadBytes)

	if err != nil {
		if errors.Is(err, io.ErrShortBuffer) {
			return nil, fmt.Errorf("%w: invalid reader count: %w", ErrReference, err)
		}

		return nil, processingError(err)
	}

	if s.rawDigest != nil && !bytes.Equal(s.rawDigest, rawHash.Sum(nil)) {
		return nil, ErrDigest
	}

	if s.rawDigest == nil {
		s.rawDigest = rawHash.Sum(nil)
	}

	if s.captureManifest && s.rawManifest == nil {
		s.rawManifest = bytes.Clone(captured.Bytes())
	}

	*remaining -= out.ProducedBytes()

	return out, nil
}

func manifestOutputWriter(dst io.Writer, capture bool) (io.Writer, *bytes.Buffer) {
	if !capture {
		return dst, nil
	}

	output := new(bytes.Buffer)

	return io.MultiWriter(dst, output), output
}
