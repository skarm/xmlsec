package resource_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"io/fs"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/skarm/xmlsec/evidence"
	"github.com/skarm/xmlsec/evidence/collect"
	"github.com/skarm/xmlsec/resource"
)

const fsBaseURI = "embed:/"

func TestHTTPResolverRechecksCallerRedirectChanges(t *testing.T) {
	calls, closed := 0, 0
	resolver, err := resource.NewHTTPResolver(resource.HTTPConfig{
		AllowedOrigins: []string{"https://resource.test"},
		Client: &http.Client{
			CheckRedirect: func(req *http.Request, _ []*http.Request) error {
				req.URL, _ = url.Parse("https://attacker.test/changed")
				return nil
			},
			Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				calls++
				if calls > 1 {
					return evidenceResponse(req, http.StatusOK, io.NopCloser(strings.NewReader("opaque"))), nil
				}
				response := evidenceResponse(req, http.StatusFound, &callbackBody{read: func([]byte) (int, error) { return 0, io.EOF }, close: func() error { closed++; return nil }})
				response.Header.Set("Location", "https://resource.test/final")
				return response, nil
			}),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	stream, err := resolver.Resolve(t.Context(), "https://resource.test/initial")
	if stream != nil || !errors.Is(err, resource.ErrPolicy) || calls != 1 || closed != 1 {
		t.Fatal(stream, err, calls, closed)
	}
}

func TestEvidenceObservationOwnership(t *testing.T) {
	input := []byte("unverified certificate")
	want := bytes.Clone(input)
	redirects := []string{"https://evidence.test/final"}
	when := time.Date(2026, 10, 1, 12, 0, 0, 0, time.FixedZone("host", 7200))
	item, err := evidence.NewObservation(t.Context(), evidence.Certificate, input, evidence.Provenance{URI: "https://evidence.test/cert", Redirects: redirects, RetrievedAt: when})
	if err != nil {
		t.Fatal(err)
	}
	clear(input)
	redirects[0] = "https://attacker.test/"
	clear(item.Bytes())
	item.Provenance().Redirects[0] = "https://attacker.test/"
	if !item.Valid() || item.Size() != len(want) || item.Kind() != evidence.Certificate || !bytes.Equal(item.Bytes(), want) || item.DigestSHA256() != sha256.Sum256(want) || item.Provenance().Redirects[0] != "https://evidence.test/final" || !item.Provenance().RetrievedAt.Equal(when) || item.Provenance().RetrievedAt.Location() != time.UTC {
		t.Fatal("observation did not preserve its owned bytes and metadata")
	}
	for _, zero := range []*evidence.Observation{nil, {}} {
		if zero.Valid() || zero.Size() != 0 || zero.Kind() != "" || zero.Bytes() != nil || zero.DigestSHA256() != [32]byte{} || zero.FingerprintSHA256() != "" || zero.Provenance().URI != "" {
			t.Fatal("zero observation is usable")
		}
	}
	for _, raw := range []string{"relative", "https://user:password@evidence.test/", "https://evidence.test/\x01"} {
		if _, err := evidence.NewObservation(t.Context(), evidence.CRL, want, evidence.Provenance{URI: raw}); !errors.Is(err, evidence.ErrInput) {
			t.Fatal(raw, err)
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := evidence.NewObservation(ctx, evidence.CRL, want, evidence.Provenance{}); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

func evidenceCollector(t *testing.T, transport http.RoundTripper, limits collect.Limits, hook func(*http.Request, []*http.Request) error) *collect.HTTP {
	t.Helper()
	c, err := collect.NewHTTP(collect.Config{Client: &http.Client{Transport: transport, CheckRedirect: hook}, AllowedURIs: []string{"https://evidence.test/first", "https://evidence.test/final"}, Limits: limits, Now: func() time.Time { return time.Unix(42, 0) }})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func evidenceResponse(req *http.Request, status int, body io.ReadCloser) *http.Response {
	return &http.Response{StatusCode: status, Header: make(http.Header), Body: body, Request: req}
}

func TestEvidenceCollectorSuccessAndConcurrentCalls(t *testing.T) {
	request := []byte("OCSP request binding")
	c := evidenceCollector(t, roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.Method == http.MethodPost {
			data, err := io.ReadAll(req.Body)
			if err != nil || !bytes.Equal(data, request) || req.Header.Get("Content-Type") != "application/ocsp-request" {
				t.Error(data, err, req.Header)
			}
		}
		return evidenceResponse(req, http.StatusOK, io.NopCloser(strings.NewReader("opaque"))), nil
	}), collect.Limits{MaxResources: 1, MaxTotalBytes: 6}, nil)
	var workers sync.WaitGroup
	for range 8 {
		workers.Go(func() {
			items, err := c.Collect(t.Context(), []collect.Request{{Kind: evidence.OCSP, URI: "https://evidence.test/first", Method: http.MethodPost, Body: request}})
			if err != nil || len(items) != 1 {
				t.Error(items, err)
				return
			}
			p := items[0].Provenance()
			if string(items[0].Bytes()) != "opaque" || p.URI != "https://evidence.test/first" || p.RequestSHA256 != sha256.Sum256(request) || !p.RetrievedAt.Equal(time.Unix(42, 0)) || len(p.Redirects) != 0 {
				t.Error("incorrect observation", p)
			}
		})
	}
	workers.Wait()
}

func TestEvidenceCollectorPrevalidatesAllRequests(t *testing.T) {
	calls := 0
	c := evidenceCollector(t, roundTripFunc(func(req *http.Request) (*http.Response, error) {
		calls++
		return evidenceResponse(req, http.StatusOK, io.NopCloser(strings.NewReader("opaque"))), nil
	}), collect.Limits{MaxRequestBytes: 4}, nil)
	first := collect.Request{Kind: evidence.CRL, URI: "https://evidence.test/first"}
	for _, bad := range []collect.Request{
		{Kind: evidence.CRL, URI: "https://attacker.test/"},
		{Kind: "unknown", URI: first.URI},
		{Kind: evidence.CRL, URI: first.URI, Method: http.MethodPost, Body: []byte("x")},
		{Kind: evidence.OCSP, URI: first.URI, Method: http.MethodPost},
		{Kind: evidence.OCSP, URI: first.URI, Method: http.MethodPost, Body: []byte("large")},
		{Kind: evidence.CRL, URI: first.URI, Method: http.MethodGet, Body: []byte("x")},
		{Kind: evidence.CRL, URI: first.URI, Method: http.MethodPut},
	} {
		items, err := c.Collect(t.Context(), []collect.Request{first, bad})
		if items != nil || err == nil || calls != 0 {
			t.Fatal(items, err, calls)
		}
	}
}

func TestEvidenceCollectorRedirectPolicy(t *testing.T) {
	for _, tc := range []struct {
		name, target, method         string
		status, resources, redirects int
		hook                         func(*http.Request, []*http.Request) error
		want                         error
	}{
		{name: "default-deny", target: "https://evidence.test/final", status: 302, resources: 2, want: evidence.ErrLimit},
		{name: "exact-allowlist", target: "https://attacker.test/final", status: 302, resources: 2, redirects: 1, want: evidence.ErrPolicy},
		{name: "request-budget", target: "https://evidence.test/final", status: 302, resources: 1, redirects: 1, want: evidence.ErrLimit},
		{name: "explicit", target: "https://evidence.test/final", status: 302, resources: 2, redirects: 1},
		{name: "post-preserved", target: "https://evidence.test/final", method: http.MethodPost, status: 307, resources: 2, redirects: 1},
		{name: "post-rewritten", target: "https://evidence.test/final", method: http.MethodPost, status: 302, resources: 2, redirects: 1, want: evidence.ErrPolicy},
		{name: "caller-deny", target: "https://evidence.test/final", status: 302, resources: 2, redirects: 1, hook: func(*http.Request, []*http.Request) error { return fs.ErrPermission }, want: fs.ErrPermission},
		{name: "caller-rewrites-target", target: "https://evidence.test/final", status: 302, resources: 2, redirects: 1, hook: func(req *http.Request, _ []*http.Request) error {
			req.URL, _ = url.Parse("https://attacker.test/")
			return nil
		}, want: evidence.ErrPolicy},
		{name: "caller-removes-target", target: "https://evidence.test/final", status: 302, resources: 2, redirects: 1, hook: func(req *http.Request, _ []*http.Request) error {
			req.URL = nil
			return nil
		}, want: evidence.ErrPolicy},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls, closed := 0, 0
			c := evidenceCollector(t, roundTripFunc(func(req *http.Request) (*http.Response, error) {
				calls++
				if calls == 1 {
					response := evidenceResponse(req, tc.status, &callbackBody{read: func([]byte) (int, error) { return 0, io.EOF }, close: func() error { closed++; return nil }})
					response.Header.Set("Location", tc.target)
					return response, nil
				}
				return evidenceResponse(req, http.StatusOK, io.NopCloser(strings.NewReader("opaque"))), nil
			}), collect.Limits{MaxResources: tc.resources, MaxRedirects: tc.redirects}, tc.hook)
			request := collect.Request{Kind: evidence.OCSP, URI: "https://evidence.test/first", Method: tc.method}
			if tc.method == http.MethodPost {
				request.Body = []byte("request")
			}
			items, err := c.Collect(t.Context(), []collect.Request{request})
			if tc.want != nil {
				if items != nil || !errors.Is(err, tc.want) || calls != 1 || closed != 1 {
					t.Fatal(items, err, calls, closed)
				}
			} else if err != nil || len(items) != 1 || !slices.Equal(items[0].Provenance().Redirects, []string{tc.target}) || calls != 2 || closed != 1 {
				t.Fatal(items, err, calls, closed)
			}
		})
	}
}

func TestEvidenceCollectorFailureLifecycle(t *testing.T) {
	readErr, closeErr := errors.New("reader failed"), errors.New("close failed")
	for _, tc := range []struct {
		name, data              string
		status, perBody, total  int
		readErr, closeErr, want error
		cancel                  bool
	}{
		{name: "body-limit", data: "12345", status: 200, perBody: 4, want: evidence.ErrLimit},
		{name: "aggregate-limit", data: "123", status: 200, total: 5, want: evidence.ErrLimit},
		{name: "empty", status: 200, want: evidence.ErrResource},
		{name: "status", data: "ignored", status: 404, want: evidence.ErrResource},
		{name: "read", status: 200, readErr: readErr, want: readErr},
		{name: "close", data: "123", status: 200, closeErr: closeErr, want: closeErr},
		{name: "last-read-cancel", data: "123", status: 200, cancel: true, closeErr: closeErr, want: context.Canceled},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			calls, closed := 0, 0
			c := evidenceCollector(t, roundTripFunc(func(req *http.Request) (*http.Response, error) {
				calls++
				reader := strings.NewReader(tc.data)
				body := &callbackBody{read: func(p []byte) (int, error) {
					if tc.cancel {
						cancel()
					}
					if tc.readErr != nil {
						return 0, tc.readErr
					}
					return reader.Read(p)
				}, close: func() error { closed++; return tc.closeErr }}
				return evidenceResponse(req, tc.status, body), nil
			}), collect.Limits{MaxBytes: tc.perBody, MaxTotalBytes: tc.total}, nil)
			requests := []collect.Request{{Kind: evidence.CRL, URI: "https://evidence.test/first"}}
			if tc.name == "aggregate-limit" {
				requests = append(requests, requests[0])
			}
			items, err := c.Collect(ctx, requests)
			if items != nil || !errors.Is(err, tc.want) || closed != calls || tc.closeErr != nil && !errors.Is(err, tc.closeErr) {
				t.Fatal(items, err, calls, closed)
			}
		})
	}
}

func TestEvidenceCollectorCancellationAndConfiguration(t *testing.T) {
	calls := 0
	c := evidenceCollector(t, roundTripFunc(func(req *http.Request) (*http.Response, error) {
		calls++
		<-req.Context().Done()
		return nil, req.Context().Err()
	}), collect.Limits{Timeout: time.Millisecond}, nil)
	request := []collect.Request{{Kind: evidence.CRL, URI: "https://evidence.test/first"}}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if items, err := c.Collect(ctx, request); items != nil || !errors.Is(err, context.Canceled) || calls != 0 {
		t.Fatal(items, err, calls)
	}
	if items, err := c.Collect(t.Context(), request); items != nil || !errors.Is(err, context.DeadlineExceeded) || calls != 1 {
		t.Fatal(items, err, calls)
	}
	for _, uri := range []string{"relative", "http://evidence.test/", "https://user@evidence.test/", "https://evidence.test/#fragment", "ftp://evidence.test/", "https://evidence.test/\\file", "https://evidence.test/\nfile"} {
		if collector, err := collect.NewHTTP(collect.Config{Client: &http.Client{}, AllowedURIs: []string{uri}}); collector != nil || !errors.Is(err, evidence.ErrInput) {
			t.Fatal(uri, collector, err)
		}
	}
	if collector, err := collect.NewHTTP(collect.Config{Client: &http.Client{}, AllowedURIs: []string{"http://evidence.test/"}, AllowHTTP: true}); collector == nil || err != nil {
		t.Fatal(collector, err)
	}
}

func TestFSResolverRejectsNilFiles(t *testing.T) {
	var typedNil *testFile
	for _, file := range []fs.File{nil, typedNil} {
		resolver, err := resource.NewFSResolver(resource.FSConfig{BaseURI: fsBaseURI, FS: openFunc(func(string) (fs.File, error) { return file, nil })})
		if err != nil {
			t.Fatal(err)
		}

		stream, err := resolver.Resolve(t.Context(), "embed:/file")
		if stream != nil || !errors.Is(err, resource.ErrResource) {
			t.Fatal(stream, err)
		}
	}
}

func TestFSResolverClosesFileReturnedWithError(t *testing.T) {
	openErr, closeErr := errors.New("open failed"), errors.New("close failed")
	file := &testFile{closeErr: closeErr}

	resolver, err := resource.NewFSResolver(resource.FSConfig{BaseURI: fsBaseURI, FS: openFunc(func(string) (fs.File, error) { return file, openErr })})
	if err != nil {
		t.Fatal(err)
	}

	stream, err := resolver.Resolve(t.Context(), "embed:/file")
	if stream != nil || !errors.Is(err, resource.ErrResource) || !errors.Is(err, openErr) || !errors.Is(err, closeErr) || file.closes != 1 {
		t.Fatal(stream, err, file.closes)
	}
}

func TestFSResolverClosesAfterCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	closeErr := errors.New("close failed")
	file := &testFile{closeErr: closeErr}

	resolver, err := resource.NewFSResolver(resource.FSConfig{BaseURI: fsBaseURI, FS: openFunc(func(string) (fs.File, error) { cancel(); return file, nil })})
	if err != nil {
		t.Fatal(err)
	}

	stream, err := resolver.Resolve(ctx, "embed:/file")
	if stream != nil || !errors.Is(err, context.Canceled) || !errors.Is(err, closeErr) || file.closes != 1 {
		t.Fatal(stream, err, file.closes)
	}
}

func TestHTTPStatusFailureClosesBodyAndPreservesCloseError(t *testing.T) {
	closeErr := errors.New("close failed")
	file := &testFile{closeErr: closeErr}

	resolver, err := resource.NewHTTPResolver(resource.HTTPConfig{AllowedOrigins: []string{"https://resource.test"}, Client: &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusNotFound, Body: file, Header: make(http.Header), Request: req}, nil
	})}})
	if err != nil {
		t.Fatal(err)
	}

	stream, err := resolver.Resolve(t.Context(), "https://resource.test/missing")
	if stream != nil || !errors.Is(err, resource.ErrResource) || !errors.Is(err, closeErr) || file.closes != 1 {
		t.Fatal(stream, err, file.closes)
	}
}

func TestFSResolverRejectsTypedNilFilesystem(t *testing.T) {
	var filesystem openFunc
	if resolver, err := resource.NewFSResolver(resource.FSConfig{BaseURI: fsBaseURI, FS: filesystem}); resolver != nil || !errors.Is(err, resource.ErrInput) {
		t.Fatal(resolver, err)
	}
}

func TestHTTPResolverCancellationAtOpenAndFinalRead(t *testing.T) {
	for _, duringOpen := range []bool{false, true} {
		t.Run(strconv.FormatBool(duringOpen), func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()

			closes := 0
			body := &callbackBody{read: func(p []byte) (int, error) {
				cancel()
				return copy(p, "complete"), io.EOF
			}, close: func() error { closes++; return nil }}

			resolver, err := resource.NewHTTPResolver(resource.HTTPConfig{AllowedOrigins: []string{"https://resource.test"}, Client: &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				if duringOpen {
					cancel()
				}

				return &http.Response{StatusCode: http.StatusOK, Body: body, Header: make(http.Header), Request: req}, nil
			})}})
			if err != nil {
				t.Fatal(err)
			}

			reader, err := resolver.Resolve(ctx, "https://resource.test/value")
			if duringOpen {
				if reader != nil || !errors.Is(err, context.Canceled) || closes != 1 {
					t.Fatal(reader, err, closes)
				}

				return
			}

			if err != nil {
				t.Fatal(err)
			}

			data, err := io.ReadAll(reader)

			closeErr := reader.Close()
			if string(data) != "complete" || !errors.Is(err, context.Canceled) || closeErr != nil || closes != 1 {
				t.Fatal(string(data), err, closeErr, closes)
			}
		})
	}
}

type openFunc func(string) (fs.File, error)

func (f openFunc) Open(name string) (fs.File, error) { return f(name) }

type testFile struct {
	closes   int
	closeErr error
}

func (f *testFile) Read([]byte) (int, error) { panic("unexpected read") }

func (f *testFile) Stat() (fs.FileInfo, error) { panic("unexpected stat") }

func (f *testFile) Close() error { f.closes++; return f.closeErr }

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

type callbackBody struct {
	read  func([]byte) (int, error)
	close func() error
}

func (r *callbackBody) Read(p []byte) (int, error) { return r.read(p) }

func (r *callbackBody) Close() error { return r.close() }

func TestEvidenceCollectorPreservesRedirectCloseError(t *testing.T) {
	closeErr := errors.New("redirect close failed")
	calls, closed := 0, 0
	collector := evidenceCollector(t, roundTripFunc(func(request *http.Request) (*http.Response, error) {
		calls++
		body := &callbackBody{read: func([]byte) (int, error) { return 0, io.EOF }, close: func() error { closed++; return closeErr }}
		response := evidenceResponse(request, http.StatusFound, body)
		response.Header.Set("Location", "https://evidence.test/final")
		return response, nil
	}), collect.Limits{MaxResources: 2, MaxRedirects: 1}, nil)
	observations, err := collector.Collect(t.Context(), []collect.Request{{Kind: evidence.CRL, URI: "https://evidence.test/first"}})
	if observations != nil || !errors.Is(err, closeErr) || !errors.Is(err, evidence.ErrResource) || calls != 1 || closed != 1 {
		t.Fatal(observations, err, calls, closed)
	}
}

func TestEvidenceCollectorClosesTransportErrorResponse(t *testing.T) {
	transportErr, closeErr := errors.New("transport failed"), errors.New("error body close failed")
	closed := 0
	collector := evidenceCollector(t, roundTripFunc(func(request *http.Request) (*http.Response, error) {
		body := &callbackBody{read: func([]byte) (int, error) { t.Fatal("failed transport body read"); return 0, io.EOF }, close: func() error { closed++; return closeErr }}
		return evidenceResponse(request, http.StatusOK, body), transportErr
	}), collect.Limits{}, nil)
	observations, err := collector.Collect(t.Context(), []collect.Request{{Kind: evidence.CRL, URI: "https://evidence.test/first"}})
	if observations != nil || !errors.Is(err, transportErr) || !errors.Is(err, closeErr) || closed != 1 {
		t.Fatal(observations, err, closed)
	}
}

func TestEvidenceCollectorPreservesRedirectReadFailures(t *testing.T) {
	readErr := errors.New("redirect body read failed")
	for _, name := range []string{"error", "joined-eof", "no-progress", "invalid-count"} {
		t.Run(name, func(t *testing.T) {
			calls, closed, reads := 0, 0, 0
			want := readErr
			switch name {
			case "no-progress":
				want = io.ErrNoProgress
			case "invalid-count":
				want = io.ErrShortBuffer
			}
			collector := evidenceCollector(t, roundTripFunc(func(request *http.Request) (*http.Response, error) {
				calls++
				body := &callbackBody{read: func(dst []byte) (int, error) {
					reads++
					switch name {
					case "error":
						return 0, readErr
					case "joined-eof":
						return 0, errors.Join(io.EOF, readErr)
					case "invalid-count":
						return len(dst) + 1, nil
					default:
						return 0, nil
					}
				}, close: func() error { closed++; return nil }}
				response := evidenceResponse(request, http.StatusFound, body)
				response.Header.Set("Location", "https://evidence.test/final")
				return response, nil
			}), collect.Limits{MaxResources: 2, MaxRedirects: 1}, nil)
			observations, err := collector.Collect(t.Context(), []collect.Request{{Kind: evidence.CRL, URI: "https://evidence.test/first"}})
			if observations != nil || !errors.Is(err, want) || calls != 1 || closed != 1 || reads < 1 || reads > 100 {
				t.Fatal(observations, err, calls, closed, reads)
			}
		})
	}
}

func TestHTTPAdaptersRejectTypedNilTransport(t *testing.T) {
	var transport *http.Transport
	client := &http.Client{Transport: transport}
	if adapter, err := resource.NewHTTPResolver(resource.HTTPConfig{Client: client, AllowedOrigins: []string{"https://evidence.test"}}); adapter != nil || !errors.Is(err, resource.ErrInput) {
		t.Fatal(adapter, err)
	}
	if collector, err := collect.NewHTTP(collect.Config{Client: client, AllowedURIs: []string{"https://evidence.test/first"}}); collector != nil || !errors.Is(err, evidence.ErrInput) {
		t.Fatal(collector, err)
	}
	client.Transport = nil
	if adapter, err := resource.NewHTTPResolver(resource.HTTPConfig{Client: client, AllowedOrigins: []string{"https://evidence.test"}}); adapter == nil || err != nil {
		t.Fatal("ordinary nil transport lost standard-client semantics", err)
	}
	if collector, err := collect.NewHTTP(collect.Config{Client: client, AllowedURIs: []string{"https://evidence.test/first"}}); collector == nil || err != nil {
		t.Fatal("ordinary nil transport lost standard-client semantics", err)
	}
}
