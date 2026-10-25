package collect_test

import (
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/skarm/xmlsec/evidence"
	"github.com/skarm/xmlsec/evidence/collect"
)

type transportFunc func(*http.Request) (*http.Response, error)

func (f transportFunc) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

type trackedBody struct {
	io.Reader
	closed     *int
	closeError error
}

func (r *trackedBody) Close() error { *r.closed++; return r.closeError }

func TestCollectorSnapshotsRequestAndSourcePolicy(t *testing.T) {
	allowed := []string{"https://evidence.test/status"}
	body := []byte("request nonce")
	original := string(body)
	closed := 0
	client := &http.Client{Transport: transportFunc(func(req *http.Request) (*http.Response, error) {
		defer req.Body.Close()
		clear(body)
		got, err := io.ReadAll(req.Body)
		if err != nil || string(got) != original || req.Header.Get("Content-Type") != "application/ocsp-request" {
			t.Fatal("mutable request snapshot", string(got), err)
		}
		return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: &trackedBody{Reader: strings.NewReader("opaque response"), closed: &closed}, Request: req}, nil
	})}
	collector, err := collect.NewHTTP(collect.Config{Client: client, AllowedURIs: allowed})
	if err != nil {
		t.Fatal(err)
	}
	allowed[0] = "https://unapproved.test/"
	items, err := collector.Collect(t.Context(), []collect.Request{{Kind: evidence.OCSP, URI: "https://evidence.test/status", Method: http.MethodPost, Body: body}})
	if err != nil || len(items) != 1 || closed != 1 || string(items[0].Bytes()) != "opaque response" || items[0].Provenance().RequestSHA256 != sha256.Sum256([]byte(original)) {
		t.Fatal("acquisition binding", items, closed, err)
	}
	if got, err := collector.Collect(t.Context(), []collect.Request{{Kind: evidence.OCSP, URI: allowed[0]}}); got != nil || !errors.Is(err, evidence.ErrPolicy) {
		t.Fatal("mutated allowlist was accepted", got, err)
	}
}

func TestCollectorRollsBackStoredResultsAfterLateCloseError(t *testing.T) {
	store, err := evidence.NewStore(t.TempDir(), 8)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	closed := 0
	failure := errors.New("late close")
	client := &http.Client{Transport: transportFunc(func(req *http.Request) (*http.Response, error) {
		var closeErr error
		if closed == 1 {
			closeErr = failure
		}
		return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: &trackedBody{Reader: strings.NewReader("abc"), closed: &closed, closeError: closeErr}, Request: req}, nil
	})}
	collector, err := collect.NewHTTP(collect.Config{Client: client, AllowedURIs: []string{"https://evidence.test/status"}, Limits: collect.Limits{MaxBytes: 4, MaxTotalBytes: 8}})
	if err != nil {
		t.Fatal(err)
	}
	requests := []collect.Request{{Kind: evidence.CRL, URI: "https://evidence.test/status"}, {Kind: evidence.CRL, URI: "https://evidence.test/status"}}
	if records, err := collector.CollectTo(t.Context(), store, requests); records != nil || !errors.Is(err, failure) || closed != 2 {
		t.Fatal("partial result/hidden Close failure", records, closed, err)
	}
	record, err := store.PutReader(t.Context(), evidence.CRL, strings.NewReader("12345678"), evidence.Provenance{}, 8)
	if err != nil {
		t.Fatal("rollback leaked a reservation", err)
	}
	if err := record.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestCollectorPreservesCancellationAndBudgetErrors(t *testing.T) {
	for _, cancelRead := range []bool{false, true} {
		ctx, cancel := context.WithCancel(t.Context())
		closed := 0
		client := &http.Client{Transport: transportFunc(func(req *http.Request) (*http.Response, error) {
			if cancelRead {
				cancel()
			}
			return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: &trackedBody{Reader: strings.NewReader("12345"), closed: &closed}, Request: req}, nil
		})}
		collector, err := collect.NewHTTP(collect.Config{Client: client, AllowedURIs: []string{"https://evidence.test/status"}, Limits: collect.Limits{MaxBytes: 4}})
		if err != nil {
			t.Fatal(err)
		}
		want := evidence.ErrLimit
		if cancelRead {
			want = context.Canceled
		}
		items, err := collector.Collect(ctx, []collect.Request{{Kind: evidence.CRL, URI: "https://evidence.test/status"}})
		cancel()
		if items != nil || !errors.Is(err, want) || closed != 1 {
			t.Fatal("acquisition error/ownership", items, closed, err)
		}
	}
}

func BenchmarkHTTPCollect(b *testing.B) {
	raw := strings.Repeat("x", 4096)
	client := &http.Client{Transport: transportFunc(func(req *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(raw)), Request: req}, nil
	})}
	collector, err := collect.NewHTTP(collect.Config{Client: client, AllowedURIs: []string{"https://evidence.test/status"}})
	if err != nil {
		b.Fatal(err)
	}
	requests := []collect.Request{{Kind: evidence.CRL, URI: "https://evidence.test/status"}}
	b.SetBytes(int64(len(raw)))
	b.ReportAllocs()
	for b.Loop() {
		items, err := collector.Collect(b.Context(), requests)
		if err != nil || len(items) != 1 || items[0].Size() != len(raw) {
			b.Fatal(err)
		}
	}
}
