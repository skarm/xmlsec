package cms

import (
	"context"
	"crypto"
	"hash"
	"io"

	"github.com/skarm/xmlsec/internal/streamio"
)

// hashContent consumes each source octet once for every distinct signer hash.
// retain is used only when the caller explicitly needs embedded content.
func hashContent(ctx context.Context, src io.Reader, algorithms []crypto.Hash, maximum int, retain io.Writer) (map[crypto.Hash][]byte, int64, error) {
	states := make(map[crypto.Hash]hash.Hash, len(algorithms))

	writers := make([]io.Writer, 0, len(algorithms)+1)
	for _, algorithm := range algorithms {
		if _, ok := states[algorithm]; ok {
			continue
		}

		state := algorithm.New()
		states[algorithm] = state
		writers = append(writers, state)
	}

	if retain != nil {
		writers = append(writers, retain)
	}

	n, err := io.Copy(io.MultiWriter(writers...), &streamio.Reader{Context: ctx, Source: src, Limit: int64(maximum), LimitError: ErrPolicy})
	if err != nil {
		return nil, 0, err
	}

	if err := ctx.Err(); err != nil {
		return nil, 0, err
	}

	result := make(map[crypto.Hash][]byte, len(states))
	for algorithm, state := range states {
		result[algorithm] = state.Sum(nil)
	}

	return result, n, nil
}
