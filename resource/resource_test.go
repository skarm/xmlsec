package resource_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
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

func evidenceCollector(t testing.TB, transport http.RoundTripper, limits collect.Limits, hook func(*http.Request, []*http.Request) error) *collect.HTTP {
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
	server := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Method == http.MethodPost {
			defer req.Body.Close()
			data, err := io.ReadAll(req.Body)
			if err != nil || !bytes.Equal(data, request) || req.Header.Get("Content-Type") != "application/ocsp-request" {
				t.Error(data, err, req.Header)
			}
		}
		_, _ = io.WriteString(w, "opaque")
	}))
	c := evidenceCollector(t, server.Client().Transport, collect.Limits{MaxResources: 1, MaxTotalBytes: 6}, nil)
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
		name      string
		target    string
		method    string
		status    int
		resources int
		redirects int
		hook      func(*http.Request, []*http.Request) error
		want      error
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
		name     string
		data     string
		status   int
		perBody  int
		total    int
		readErr  error
		closeErr error
		want     error
		cancel   bool
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

func BenchmarkEvidenceCollect(b *testing.B) {
	for _, size := range []int{256, 16 << 10, 1 << 20} {
		b.Run(strconv.Itoa(size), func(b *testing.B) {
			raw := bytes.Repeat([]byte("a"), size)
			digest := sha256.Sum256(raw)
			c := evidenceCollector(b, roundTripFunc(func(req *http.Request) (*http.Response, error) {
				return evidenceResponse(req, http.StatusOK, io.NopCloser(bytes.NewReader(raw))), nil
			}), collect.Limits{}, nil)
			requests := []collect.Request{{Kind: evidence.CRL, URI: "https://evidence.test/first"}}
			b.ReportAllocs()
			b.SetBytes(int64(size))
			for b.Loop() {
				items, err := c.Collect(b.Context(), requests)
				if err != nil || len(items) != 1 || items[0].Size() != size || items[0].DigestSHA256() != digest {
					b.Fatal(err)
				}
			}
		})
	}
}

func TestReadObservation(t *testing.T) {
	input := []byte("unverified")
	want := bytes.Clone(input)
	redirects := []string{"https://evidence.test/final"}
	source := bytes.NewReader(input)
	closed := false
	reader := &callbackBody{read: func(p []byte) (int, error) {
		redirects[0] = "https://attacker.test/"
		return source.Read(p)
	}, close: func() error { closed = true; return nil }}
	item, err := evidence.ReadObservation(t.Context(), evidence.CRL, reader, evidence.Provenance{Redirects: redirects}, len(input))
	if err != nil {
		t.Fatal(err)
	}
	clear(input)
	clear(item.Bytes())
	if closed || !bytes.Equal(item.Bytes(), want) || item.DigestSHA256() != sha256.Sum256(want) || item.Provenance().Redirects[0] != "https://evidence.test/final" {
		t.Fatal("reader observation lost ownership")
	}
	failure := errors.New("source failed")
	for _, tc := range []struct {
		name  string
		src   io.Reader
		limit int
		want  error
	}{
		{"empty", strings.NewReader(""), 1, evidence.ErrInput},
		{"overflow", strings.NewReader("ab"), 1, evidence.ErrLimit},
		{"zero limit", strings.NewReader("a"), 0, evidence.ErrLimit},
		{"large limit", strings.NewReader("a"), 64<<20 + 1, evidence.ErrLimit},
		{"nil", nil, 1, evidence.ErrInput},
		{"typed nil", (*bytes.Reader)(nil), 1, evidence.ErrInput},
		{"terminal failure", &callbackBody{read: func(p []byte) (int, error) { p[0] = 'a'; return 1, failure }}, 1, failure},
		{"joined EOF", &callbackBody{read: func(p []byte) (int, error) { p[0] = 'a'; return 1, errors.Join(io.EOF, failure) }}, 1, failure},
		{"invalid count", &callbackBody{read: func(p []byte) (int, error) { return len(p) + 1, nil }}, 1, io.ErrShortBuffer},
		{"stalled", &callbackBody{read: func([]byte) (int, error) { return 0, nil }}, 1, io.ErrNoProgress},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got, err := evidence.ReadObservation(t.Context(), evidence.CRL, tc.src, evidence.Provenance{}, tc.limit); got != nil || !errors.Is(err, tc.want) {
				t.Fatal(got, err)
			}
		})
	}
	ctx, cancel := context.WithCancel(t.Context())
	reader.read = func(p []byte) (int, error) { cancel(); p[0] = 'a'; return 1, io.EOF }
	if got, err := evidence.ReadObservation(ctx, evidence.CRL, reader, evidence.Provenance{}, 1); got != nil || !errors.Is(err, context.Canceled) || closed {
		t.Fatal(got, err, closed)
	}
	reader.read = func([]byte) (int, error) { t.Fatal("invalid metadata consumed source"); return 0, nil }
	for _, p := range []evidence.Provenance{{URI: "relative"}, {Redirects: []string{"relative"}}, {Redirects: make([]string, 11)}} {
		if got, err := evidence.ReadObservation(t.Context(), evidence.CRL, reader, p, 1); got != nil || err == nil {
			t.Fatal(got, err)
		}
	}
	if got, err := evidence.ReadObservation(nil, evidence.CRL, reader, evidence.Provenance{}, 1); got != nil || !errors.Is(err, evidence.ErrInput) {
		t.Fatal(got, err)
	}
	if got, err := evidence.ReadObservation(t.Context(), "invalid", reader, evidence.Provenance{}, 1); got != nil || !errors.Is(err, evidence.ErrInput) {
		t.Fatal(got, err)
	}
}

func TestEvidenceStore(t *testing.T) {
	parent := t.TempDir()
	store, err := evidence.NewStore(parent, 2<<20)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := store.Close(); err != nil {
			t.Error(err)
		}
	})
	raw := bytes.Repeat([]byte("exact signed bytes"), 1024)
	provenance := evidence.Provenance{URI: "https://evidence.test/crl", Redirects: []string{"https://evidence.test/final"}}
	item, err := store.PutReader(t.Context(), evidence.CRL, bytes.NewReader(raw), provenance, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	provenance.Redirects[0] = "changed"
	if item.Size() != len(raw) || item.Kind() != evidence.CRL || item.DigestSHA256() != sha256.Sum256(raw) || item.Provenance().Redirects[0] != "https://evidence.test/final" {
		t.Fatal("metadata ownership")
	}
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			reader, err := item.Open(t.Context())
			if err != nil {
				t.Error(err)
				return
			}
			got, err := io.ReadAll(reader)
			err = errors.Join(err, reader.Close())
			if err != nil || !bytes.Equal(got, raw) {
				t.Errorf("repeatable read: %v", err)
			}
		})
	}
	wg.Wait()
	canceled, cancel := context.WithCancel(t.Context())
	reader, err := item.Open(canceled)
	if err != nil {
		t.Fatal(err)
	}
	cancel()
	if _, err := reader.Read(make([]byte, 1)); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if err := reader.Close(); err != nil {
		t.Fatal(err)
	}
	if err := item.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := item.Open(t.Context()); !errors.Is(err, os.ErrClosed) {
		t.Fatal(err)
	}
	if err := item.Close(); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := store.PutReader(t.Context(), evidence.CRL, strings.NewReader("x"), evidence.Provenance{}, 1); !errors.Is(err, os.ErrClosed) {
		t.Fatal(err)
	}
	files, err := os.ReadDir(parent)
	if err != nil || len(files) != 0 {
		t.Fatal("store retained files", err)
	}
}

func TestEvidenceStoreFailures(t *testing.T) {
	store, err := evidence.NewStore(t.TempDir(), 4)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	late := errors.New("late source error")
	for _, tc := range []struct {
		name    string
		reader  io.Reader
		maximum int
		want    error
	}{
		{"empty", strings.NewReader(""), 4, evidence.ErrInput},
		{"overflow", strings.NewReader("12345"), 4, evidence.ErrLimit},
		{"late", &callbackBody{read: func(p []byte) (int, error) { return copy(p, "1234"), late }}, 4, late},
		{"no progress", &callbackBody{read: func([]byte) (int, error) { return 0, nil }}, 4, io.ErrNoProgress},
		{"invalid count", &callbackBody{read: func(p []byte) (int, error) { return len(p) + 1, nil }}, 4, io.ErrShortBuffer},
		{"budget", strings.NewReader("a"), 5, evidence.ErrLimit},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := store.PutReader(t.Context(), evidence.CRL, tc.reader, evidence.Provenance{}, tc.maximum)
			if got != nil || !errors.Is(err, tc.want) {
				t.Fatal(got, err)
			}
			// Every failed write must release its reservation and file.
			good, err := store.PutReader(t.Context(), evidence.CRL, strings.NewReader("1234"), evidence.Provenance{}, 4)
			if err != nil {
				t.Fatal(err)
			}
			if err := good.Close(); err != nil {
				t.Fatal(err)
			}
		})
	}
	first, err := store.PutReader(t.Context(), evidence.CRL, strings.NewReader("1234"), evidence.Provenance{}, 4)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := store.PutReader(t.Context(), evidence.CRL, strings.NewReader("a"), evidence.Provenance{}, 1); got != nil || !errors.Is(err, evidence.ErrLimit) {
		t.Fatal(got, err)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestEvidenceCollectTo(t *testing.T) {
	for _, failClose := range []bool{false, true} {
		t.Run(strconv.FormatBool(failClose), func(t *testing.T) {
			parent := t.TempDir()
			store, err := evidence.NewStore(parent, 32)
			if err != nil {
				t.Fatal(err)
			}
			defer store.Close()
			calls, closed := 0, 0
			late := errors.New("body close")
			collector := evidenceCollector(t, roundTripFunc(func(req *http.Request) (*http.Response, error) {
				calls++
				return evidenceResponse(req, http.StatusOK, &callbackBody{read: strings.NewReader("opaque").Read, close: func() error {
					closed++
					if failClose && closed == 2 {
						return late
					}
					return nil
				}}), nil
			}), collect.Limits{MaxBytes: 8, MaxTotalBytes: 16}, nil)
			items, err := collector.CollectTo(t.Context(), store, []collect.Request{{Kind: evidence.CRL, URI: "https://evidence.test/first"}, {Kind: evidence.CRL, URI: "https://evidence.test/first"}})
			if calls != 2 || closed != 2 {
				t.Fatal(calls, closed)
			}
			if failClose {
				if items != nil || !errors.Is(err, late) {
					t.Fatal(items, err)
				}
				// Rollback must release both stored resources and the failed final one.
				item, err := store.PutReader(t.Context(), evidence.CRL, strings.NewReader(strings.Repeat("x", 32)), evidence.Provenance{}, 32)
				if err != nil {
					t.Fatal(err)
				}
				if err := item.Close(); err != nil {
					t.Fatal(err)
				}
			} else {
				if err != nil || len(items) != 2 {
					t.Fatal(items, err)
				}
				for _, item := range items {
					reader, err := item.Open(t.Context())
					if err != nil {
						t.Fatal(err)
					}
					got, err := io.ReadAll(reader)
					err = errors.Join(err, reader.Close(), item.Close())
					if err != nil || string(got) != "opaque" {
						t.Fatal(string(got), err)
					}
				}
			}
		})
	}
}

func BenchmarkEvidenceStorage(b *testing.B) {
	for _, size := range []int{256, 16 << 10, 8 << 20} {
		b.Run(strconv.Itoa(size), func(b *testing.B) {
			raw := bytes.Repeat([]byte("x"), size)
			store, err := evidence.NewStore(b.TempDir(), 64<<20)
			if err != nil {
				b.Fatal(err)
			}
			defer store.Close()
			for _, mode := range []string{"memory", "file", "memory_then_file"} {
				b.Run(mode, func(b *testing.B) {
					b.ReportAllocs()
					b.SetBytes(int64(size))
					for b.Loop() {
						var source io.Reader = struct{ io.Reader }{bytes.NewReader(raw)}
						if mode == "memory" {
							item, err := evidence.ReadObservation(b.Context(), evidence.CRL, source, evidence.Provenance{}, size)
							if err != nil || item.Size() != size {
								b.Fatal(err)
							}
							continue
						}
						if mode == "memory_then_file" {
							item, err := evidence.ReadObservation(b.Context(), evidence.CRL, source, evidence.Provenance{}, size)
							if err != nil {
								b.Fatal(err)
							}
							source = bytes.NewReader(item.Bytes())
						}
						record, err := store.PutReader(b.Context(), evidence.CRL, source, evidence.Provenance{}, size)
						if err != nil || record.Size() != size {
							b.Fatal(err)
						}
						if err := record.Close(); err != nil {
							b.Fatal(err)
						}
					}
				})
			}
		})
	}
}

func TestEvidenceStoreShutdownDuringWrite(t *testing.T) {
	parent := t.TempDir()
	store, err := evidence.NewStore(parent, 8)
	if err != nil {
		t.Fatal(err)
	}
	first := true
	var shutdownError error
	input := &callbackBody{read: func(p []byte) (int, error) {
		if first {
			first = false
			shutdownError = store.Close()
			return copy(p, "bytes"), nil
		}
		return 0, io.EOF
	}}
	if got, err := store.PutReader(t.Context(), evidence.CRL, input, evidence.Provenance{}, 8); got != nil || !errors.Is(err, os.ErrClosed) {
		t.Fatal(got, err)
	}
	if shutdownError != nil && !errors.Is(shutdownError, evidence.ErrResource) {
		t.Fatal(shutdownError)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	files, err := os.ReadDir(parent)
	if err != nil || len(files) != 0 {
		t.Fatal(files, err)
	}
}

func TestEvidenceStoreConcurrentLifecycle(t *testing.T) {
	store, err := evidence.NewStore(t.TempDir(), 64<<20)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	var wg sync.WaitGroup
	for worker := range 16 {
		wg.Go(func() {
			raw := strings.Repeat(strconv.Itoa(worker)+"bytes", 256)
			for range 8 {
				item, err := store.PutReader(t.Context(), evidence.CRL, strings.NewReader(raw), evidence.Provenance{}, 8<<10)
				if err != nil {
					t.Error(err)
					return
				}
				reader, err := item.Open(t.Context())
				if err != nil {
					t.Error(err)
					return
				}
				data, err := io.ReadAll(reader)
				err = errors.Join(err, reader.Close(), item.Close())
				if err != nil || string(data) != raw {
					t.Errorf("concurrent replay %v", err)
					return
				}
			}
		})
	}
	wg.Wait()
	// A full-budget reservation is possible after all workers release records.
	item, err := store.PutReader(t.Context(), evidence.CRL, strings.NewReader("x"), evidence.Provenance{}, 64<<20)
	if err != nil {
		t.Fatal("reservation leak", err)
	}
	if err := item.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestEvidenceStoreRecordLimitAndCancellation(t *testing.T) {
	store, err := evidence.NewStore(t.TempDir(), 64<<20)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	items := make([]*evidence.Record, 0, 64)
	for range 64 {
		item, err := store.PutReader(t.Context(), evidence.CRL, strings.NewReader("x"), evidence.Provenance{}, 1)
		if err != nil {
			t.Fatal(err)
		}
		items = append(items, item)
	}
	if item, err := store.PutReader(t.Context(), evidence.CRL, strings.NewReader("x"), evidence.Provenance{}, 1); item != nil || !errors.Is(err, evidence.ErrLimit) {
		t.Fatal(item, err)
	}
	for _, item := range items {
		if err := item.Close(); err != nil {
			t.Fatal(err)
		}
	}
	for _, terminal := range []error{nil, io.EOF} {
		ctx, cancel := context.WithCancel(t.Context())
		input := &callbackBody{read: func(p []byte) (int, error) { cancel(); return copy(p, "x"), terminal }}
		if item, err := store.PutReader(ctx, evidence.CRL, input, evidence.Provenance{}, 1); item != nil || !errors.Is(err, context.Canceled) {
			t.Fatal(item, err)
		}
	}
}

func TestEvidenceStoreFailedCleanupStopsAcquisition(t *testing.T) {
	parent := t.TempDir()
	store, err := evidence.NewStore(parent, 4)
	if err != nil {
		t.Fatal(err)
	}
	directories, err := os.ReadDir(parent)
	if err != nil || len(directories) != 1 {
		t.Fatal(err)
	}
	directory := filepath.Join(parent, directories[0].Name())
	t.Cleanup(func() {
		if err := store.Close(); err != nil {
			t.Error(err)
		}
	})
	late := errors.New("read failed")
	var blocker *os.File
	t.Cleanup(func() {
		if blocker != nil {
			if err := blocker.Close(); err != nil {
				t.Error(err)
			}
		}
	})
	input := &callbackBody{read: func(p []byte) (int, error) {
		files, err := os.ReadDir(directory)
		if err != nil || len(files) != 1 {
			t.Fatal(err)
		}
		path := filepath.Join(directory, files[0].Name())
		// Force a real cleanup failure under each platform's file semantics.
		if runtime.GOOS == "windows" {
			blocker, err = os.Open(path) // An additional Windows handle denies deletion.
			if err != nil {
				t.Fatal(err)
			}
		} else {
			// A nonempty directory cannot be unlinked even by privileged test users.
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(path, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(path, "occupied"), []byte("x"), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		return copy(p, "x"), late
	}}
	item, err := store.PutReader(t.Context(), evidence.CRL, input, evidence.Provenance{}, 4)
	var cleanup *os.PathError
	if item != nil || !errors.Is(err, late) || !errors.As(err, &cleanup) || cleanup.Op != "remove" {
		t.Fatal(item, err)
	}
	if item, err := store.PutReader(t.Context(), evidence.CRL, strings.NewReader("x"), evidence.Provenance{}, 1); item != nil || !errors.Is(err, os.ErrClosed) {
		t.Fatal("failed cleanup permitted another acquisition", item, err)
	}
	if blocker != nil {
		if err := blocker.Close(); err != nil {
			t.Fatal(err)
		}
		blocker = nil
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	directories, err = os.ReadDir(parent)
	if err != nil || len(directories) != 0 {
		t.Fatal("close did not retry cleanup", directories, err)
	}
}
