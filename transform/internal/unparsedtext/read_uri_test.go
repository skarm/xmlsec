package unparsedtext_test

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"
	"testing/iotest"

	"github.com/skarm/xmlsec/transform/internal/unparsedtext"
)

func TestReadURIDiscardsPartialResultOnFailure(t *testing.T) {
	readFailure := errors.New("read failed")
	closeErr := errors.New("close failed")
	for _, tc := range []struct {
		name      string
		reader    io.Reader
		closeErr  error
		want      string
		wantError error
	}{
		{name: "reads_unmodified_bytes", reader: strings.NewReader("a\x00\xff"), want: "a\x00\xff"},
		{name: "preserves_read_failure_joined_with_eof", reader: io.MultiReader(strings.NewReader("prefix"), iotest.ErrReader(errors.Join(io.EOF, readFailure))), wantError: readFailure},
		{name: "discards_text_after_close_failure", reader: strings.NewReader("complete"), closeErr: closeErr, wantError: closeErr},
	} {
		t.Run(tc.name, func(t *testing.T) {
			closes := 0
			cfg := &unparsedtext.Config{URIResolver: resolverFunc(func(context.Context, string) (io.ReadCloser, error) {
				return closeFailure{Reader: tc.reader, err: tc.closeErr, onClose: func() { closes++ }}, nil
			})}
			got, err := unparsedtext.ReadURI(t.Context(), cfg, textResourceURI)
			if got != tc.want || !errors.Is(err, tc.wantError) || closes != 1 {
				t.Errorf("ReadURI = (%q, %v), close count=%d, want (%q, %v) and one close", got, err, closes, tc.want, tc.wantError)
			}
		})
	}
}
