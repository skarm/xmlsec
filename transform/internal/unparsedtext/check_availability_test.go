package unparsedtext_test

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"slices"
	"strings"
	"testing"

	"github.com/skarm/xmlsec/internal/tree"
	"github.com/skarm/xmlsec/transform/internal/unparsedtext"
	"github.com/skarm/xmlsec/transform/internal/xdm"
)

func TestCheckAvailabilityDistinguishesRetrievalAndControlFailures(t *testing.T) {
	hostFailure := errors.New("invocation canceled by host")
	for _, tc := range []struct {
		name, body string
		resolveErr error
		controlErr error
		maxBytes   int64
		available  bool
		wantErr    error
	}{
		{name: "valid_resource", body: "abc", available: true},
		{name: "missing_resource", resolveErr: fs.ErrNotExist},
		{name: "invalid_encoding", body: "\xff"},
		{name: "byte_limit", body: "abcd", maxBytes: 3, wantErr: tree.ErrLimit},
		{name: "host_control_failure", body: "abc", controlErr: hostFailure, wantErr: hostFailure},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := &trackedReader{Reader: strings.NewReader(tc.body)}
			cfg := &unparsedtext.Config{
				MaxBytes: tc.maxBytes,
				URIResolver: resolverFunc(func(context.Context, string) (io.ReadCloser, error) {
					if tc.resolveErr != nil {
						return nil, tc.resolveErr
					}
					return body, nil
				}),
				CheckBytes: func(n int) error {
					t.Errorf("availability charged %d bytes of retained output", n)
					return nil
				},
				ControlFailure: func(context.Context, error) error { return tc.controlErr },
			}
			got, err := unparsedtext.CheckAvailability(t.Context(), cfg, textResourceURI, "")
			if got != tc.available || !errors.Is(err, tc.wantErr) || body.closed != (tc.resolveErr == nil) {
				t.Errorf("CheckAvailability = (%t, %v), closed=%t, want (%t, %v), closed=%t", got, err, body.closed, tc.available, tc.wantErr, tc.resolveErr == nil)
			}
		})
	}
}

type resourceReadPolicy struct {
	check  func(string) error
	record func(string) error
}

func (p resourceReadPolicy) CheckRead(_ context.Context, uri string) error  { return p.check(uri) }
func (p resourceReadPolicy) RecordRead(_ context.Context, uri string) error { return p.record(uri) }

func TestCheckAvailabilityPreservesReadPolicyFailure(t *testing.T) {
	policyFailure := errors.New("read policy rejected the resource")
	for _, rejectAt := range []string{"check", "record"} {
		t.Run(rejectAt, func(t *testing.T) {
			body := &trackedReader{Reader: strings.NewReader("test")}
			var calls []string
			observe := func(stage, uri string) error {
				calls = append(calls, stage)
				if uri != textResourceURI {
					t.Errorf("%s saw URI %q, want %q", stage, uri, textResourceURI)
				}
				if stage == rejectAt {
					return policyFailure
				}
				return nil
			}
			cfg := &unparsedtext.Config{
				ReadPolicy: resourceReadPolicy{
					check:  func(uri string) error { return observe("check", uri) },
					record: func(uri string) error { return observe("record", uri) },
				},
				URIResolver: resolverFunc(func(_ context.Context, uri string) (io.ReadCloser, error) {
					return body, observe("resolve", uri)
				}),
			}
			available, err := unparsedtext.CheckAvailability(t.Context(), cfg, textResourceURI, "")
			var detail *xdm.ResourceAccessError
			if available || !errors.As(err, &detail) || !errors.Is(err, policyFailure) {
				t.Errorf("CheckAvailability = (%t, %v), want false and the original policy failure", available, err)
			}
			wantCalls := []string{"check"}
			wantClosed := rejectAt == "record"
			if wantClosed {
				wantCalls = append(wantCalls, "resolve", "record")
			}
			if !slices.Equal(calls, wantCalls) || body.closed != wantClosed {
				t.Errorf("calls=%q, closed=%t, want %q and closed=%t", calls, body.closed, wantCalls, wantClosed)
			}
		})
	}
}
