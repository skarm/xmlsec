package xslt //nolint:testpackage // Checks ownership and errors at the shared resource parsing boundary.

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/skarm/xmlsec/internal/tree"
	"github.com/skarm/xmlsec/transform/internal/xdm"
	"github.com/skarm/xmlsec/transform/internal/xpath"
)

type closeTrackingReader struct {
	reader   io.Reader
	closeErr error
	closed   int
}

func (r *closeTrackingReader) Read(p []byte) (int, error) { return r.reader.Read(p) }
func (r *closeTrackingReader) Close() error {
	r.closed++
	return r.closeErr
}

type failingReader struct{ err error }

func (r failingReader) Read([]byte) (int, error) { return 0, r.err }

func TestParseXMLResourceHonorsByteLimitAndRetrievalBase(t *testing.T) {
	t.Parallel()
	const source = `<r/>`
	for _, test := range []struct {
		name    string
		limit   int64
		wantErr error
	}{
		{"exact cap", int64(len(source)), nil},
		{"one byte over cap", int64(len(source) - 1), ErrResourceTooLarge},
		{"unbounded", -1, nil},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			resource := &closeTrackingReader{reader: strings.NewReader(source)}
			options := xdm.ParseOptions{BaseURI: "https://configured.example/base"}
			doc, err := parseXMLResource(t.Context(), &options, resource, "https://retrieved.example/document", test.limit)
			if resource.closed != 1 || options.BaseURI != "https://configured.example/base" || options.Limits.MaxBytes != 0 {
				t.Fatalf("resource closes=%d, caller options=%+v", resource.closed, options)
			}
			if test.wantErr != nil {
				if doc != nil || !errors.Is(err, test.wantErr) {
					t.Fatalf("over cap = %v, %v", doc, err)
				}
				return
			}
			if err != nil || doc == nil {
				t.Fatalf("within cap: %v, %v", doc, err)
			}
			if base := xpath.NodeBaseURI(doc); base != "https://retrieved.example/document" {
				t.Fatalf("retrieval base = %q", base)
			}
		})
	}
}

func TestParseXMLResourcePreservesFailures(t *testing.T) {
	t.Parallel()
	readErr := errors.New("source read failed")
	closeErr := errors.New("source close failed")
	for _, test := range []struct {
		name     string
		reader   io.Reader
		closeErr error
		causes   []error
	}{
		{"read and close", failingReader{readErr}, closeErr, []error{readErr, closeErr}},
		{"well formed but close fails", strings.NewReader(`<r/>`), closeErr, []error{closeErr}},
		{"EOF joined with source failure", failingReader{errors.Join(io.EOF, readErr)}, nil, []error{readErr}},
		{"malformed", strings.NewReader(`<r>`), nil, []error{tree.ErrMalformed}},
		{"malformed and close fails", strings.NewReader(`<r>`), closeErr, []error{tree.ErrMalformed, closeErr}},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			resource := &closeTrackingReader{reader: test.reader, closeErr: test.closeErr}
			doc, err := parseXMLResource(t.Context(), nil, resource, "", 0)
			if doc != nil || err == nil || resource.closed != 1 {
				t.Fatalf("failed resource = %v, %v, closes=%d", doc, err, resource.closed)
			}
			for _, cause := range test.causes {
				if !errors.Is(err, cause) {
					t.Fatalf("lost cause %v in %v", cause, err)
				}
			}
		})
	}
}

func TestParseXMLResourceCancellationStillCloses(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	closeErr := errors.New("close failed")
	resource := &closeTrackingReader{reader: strings.NewReader(`<r/>`), closeErr: closeErr}
	doc, err := parseXMLResource(ctx, nil, resource, "", 0)
	if doc != nil || resource.closed != 1 || !errors.Is(err, context.Canceled) || !errors.Is(err, closeErr) {
		t.Fatalf("canceled resource = %v, %v, closes=%d", doc, err, resource.closed)
	}
}
