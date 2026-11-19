package collect_test

import (
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"net/http"
	"net/http/cookiejar"
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

func TestCollectorValidatesCookieJarAtConstruction(t *testing.T) {
	t.Parallel()

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}

	var typedNil *cookiejar.Jar
	for _, tc := range []struct {
		name string
		jar  http.CookieJar
		want error
	}{
		{name: "absent"},
		{name: "present", jar: jar},
		{name: "typed nil", jar: typedNil, want: evidence.ErrInput},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			client := &http.Client{Jar: tc.jar, Transport: transportFunc(func(*http.Request) (*http.Response, error) {
				t.Error("constructing a collector invoked the transport")
				return nil, evidence.ErrResource
			})}
			collector, err := collect.NewHTTP(collect.Config{Client: client, AllowedURIs: []string{"https://evidence.test/status"}})
			if !errors.Is(err, tc.want) || (collector != nil) != (tc.want == nil) {
				t.Errorf("NewHTTP() = (collector present: %t, %v), want error %v", collector != nil, err, tc.want)
			}
		})
	}
}

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

func TestCollectorLeavesRequestBytesAvailableUntilTransportClosesBody(t *testing.T) {
	t.Parallel()

	const uri = "https://evidence.test/status"
	const original = "request nonce"
	var requestBody io.ReadCloser
	client := &http.Client{Transport: transportFunc(func(req *http.Request) (*http.Response, error) {
		requestBody = req.Body
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader("opaque response")), Request: req}, nil
	})}
	collector, err := collect.NewHTTP(collect.Config{Client: client, AllowedURIs: []string{uri}})
	if err != nil {
		t.Fatal(err)
	}
	items, err := collector.Collect(t.Context(), []collect.Request{{Kind: evidence.OCSP, URI: uri, Method: http.MethodPost, Body: []byte(original)}})
	if err != nil || len(items) != 1 || requestBody == nil {
		t.Fatalf("Collect returned (%v, %v), want one observation and an open transport request body", items, err)
	}
	// RoundTripper owns the request body and may finish with it after returning.
	got, err := io.ReadAll(requestBody)
	if err := errors.Join(err, requestBody.Close()); err != nil || string(got) != original {
		t.Errorf("request body = (%q, %v), want %q", got, err, original)
	}
}

func TestCollectorClosesUnsentRequestBodyAfterRedirectCloseFailure(t *testing.T) {
	t.Parallel()

	const uri = "https://evidence.test/status"
	const next = "https://evidence.test/next"
	failure := errors.New("redirect response close failed")
	var sent, responseClosed, unsentClosed int
	client := &http.Client{
		CheckRedirect: func(req *http.Request, _ []*http.Request) error {
			if err := req.Body.Close(); err != nil {
				return err
			}
			req.Body = &trackedBody{Reader: strings.NewReader("request"), closed: &unsentClosed}
			return nil
		},
		Transport: transportFunc(func(req *http.Request) (*http.Response, error) {
			sent++
			if err := req.Body.Close(); err != nil {
				return nil, err
			}
			return &http.Response{
				StatusCode: http.StatusTemporaryRedirect,
				Header:     http.Header{"Location": {next}},
				Body:       &trackedBody{Reader: strings.NewReader(""), closed: &responseClosed, closeError: failure},
				Request:    req,
			}, nil
		}),
	}
	collector, err := collect.NewHTTP(collect.Config{
		Client: client, AllowedURIs: []string{uri, next}, Limits: collect.Limits{MaxRedirects: 1},
	})
	if err != nil {
		t.Fatal(err)
	}
	items, err := collector.Collect(t.Context(), []collect.Request{{Kind: evidence.OCSP, URI: uri, Method: http.MethodPost, Body: []byte("request")}})
	if items != nil || !errors.Is(err, failure) || sent != 1 || responseClosed != 1 || unsentClosed != 1 {
		t.Fatalf("Collect = (%v, %v), sent=%d, response closed=%d, unsent request closed=%d", items, err, sent, responseClosed, unsentClosed)
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

func TestCollectorRejectsMalformedQueries(t *testing.T) {
	calls := 0
	wantURI := "https://evidence.test/status?x=%23%2f%25+value;other=yes"
	client := &http.Client{Transport: transportFunc(func(req *http.Request) (*http.Response, error) {
		calls++
		if req.URL.String() != wantURI {
			t.Errorf("URI changed: %q", req.URL.String())
		}

		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader("body")), Request: req}, nil
	})}
	for _, query := range []string{"x=%zz", "x=%", "x=%0", "x=two words", `x=one\two`} {
		collector, err := collect.NewHTTP(collect.Config{Client: client, AllowedURIs: []string{"https://evidence.test/status?" + query}})
		if collector != nil || !errors.Is(err, evidence.ErrInput) || calls != 0 {
			t.Errorf("malformed query %q: collector=%v, err=%v, calls=%d", query, collector, err, calls)
		}
	}

	collector, err := collect.NewHTTP(collect.Config{Client: client, AllowedURIs: []string{wantURI}})
	if err != nil {
		t.Fatal(err)
	}

	items, err := collector.Collect(t.Context(), []collect.Request{{Kind: evidence.CRL, URI: wantURI}})
	if err != nil || len(items) != 1 || string(items[0].Bytes()) != "body" || calls != 1 {
		t.Fatalf("valid encoded query rejected: %v, calls=%d", err, calls)
	}
}
