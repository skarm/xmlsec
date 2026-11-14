package tree_test

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/skarm/xmlsec/internal/tree"
)

func TestWriteXMLFragmentCountsOnlyDeliveredBytes(t *testing.T) {
	t.Parallel()

	failure := errors.New("destination failure")
	for _, tc := range []struct {
		name      string
		limit     int
		failWrite bool
		cancel    bool
		writeErr  error
		want      string
		wantErr   error
	}{
		{name: "exact_byte_limit", limit: 5, want: "éend"},
		{name: "limit_rejects_next_chunk", limit: 4, want: "é", wantErr: tree.ErrLimit},
		{name: "short_write", limit: 10, failWrite: true, want: "ée", wantErr: io.ErrShortWrite},
		{name: "partial_failure", limit: 10, failWrite: true, writeErr: failure, want: "ée", wantErr: failure},
		{name: "cancellation_from_writer", limit: 10, cancel: true, want: "é", wantErr: context.Canceled},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			var output strings.Builder
			calls := 0
			writer := fragmentWriteFunc(func(p []byte) (int, error) {
				calls++
				if tc.failWrite && calls == 2 {
					n, _ := output.Write(p[:1])
					return n, tc.writeErr
				}
				n, err := output.Write(p)
				if tc.cancel {
					cancel()
				}
				return n, err
			})
			nodes := []*tree.Node{{Kind: tree.TextNode, Data: "é"}, {Kind: tree.TextNode, Data: "end"}}
			n, err := tree.WriteXMLFragment(ctx, writer, nodes, tc.limit)
			if !errors.Is(err, tc.wantErr) || n != int64(len(tc.want)) || output.String() != tc.want {
				t.Fatalf("WriteXMLFragment = (%q, %d, %v), want (%q, %d, %v)", output.String(), n, err, tc.want, len(tc.want), tc.wantErr)
			}
		})
	}
}

type fragmentWriteFunc func([]byte) (int, error)

func (f fragmentWriteFunc) Write(p []byte) (int, error) { return f(p) }
