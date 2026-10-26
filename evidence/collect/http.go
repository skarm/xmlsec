// Package collect supplies opt-in network collection of untrusted evidence.
// Its results require separate offline authentication, object binding and
// freshness checks. Importing this package never initiates network access.
package collect

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/skarm/xmlsec/evidence"
	"github.com/skarm/xmlsec/internal/nilcheck"
	"github.com/skarm/xmlsec/internal/streamio"
)

// Limits bounds one complete collection call. Zero fields select their documented
// defaults, except MaxRedirects: zero denies redirects.
type Limits struct {
	// MaxResources bounds all HTTP requests, including redirects. Zero selects 8.
	// The maximum is 64.
	MaxResources int
	// MaxBytes bounds each delivered evidence body. Zero selects 4 MiB.
	// The maximum is 64 MiB.
	MaxBytes int
	// MaxTotalBytes bounds all delivered evidence bodies. Zero selects 16 MiB.
	// The maximum is 64 MiB.
	// HTTP framing/headers and redirect bodies belong to the supplied transport;
	// their work is separately bounded by MaxResources, MaxRedirects and Timeout.
	MaxTotalBytes int
	// MaxRequestBytes bounds each OCSP POST body. Zero selects 64 KiB, also the maximum.
	MaxRequestBytes int
	// MaxTotalRequestBytes bounds snapshotted POST bodies. Zero selects 512 KiB.
	// The maximum is 4 MiB.
	MaxTotalRequestBytes int
	// MaxRedirects bounds redirects per resource. Zero denies redirects. The maximum is 10.
	MaxRedirects int
	// Timeout bounds the complete call, including response reads. Zero selects ten seconds.
	// The maximum is two minutes.
	Timeout time.Duration
}

// Config authorizes exact resource URIs through an application-owned HTTP client.
// Construction copies the client value. Its transport and cookie jar remain shared
// and must support concurrent use and cancellation. The application configures DNS,
// IP and proxy access, TLS roots and credentials. Collection requires this explicit
// client and does not follow certificate AIA or revocation links automatically.
type Config struct {
	// Client is required. Its transport and jar remain owned by the application.
	Client *http.Client
	// AllowedURIs contains 1 to 256 exact absolute HTTP(S) URI strings, without fragments
	// or userinfo. Every followed redirect must also be explicitly listed.
	AllowedURIs []string
	// AllowHTTP explicitly permits HTTP; HTTPS remains the default scheme policy.
	// Transport protection never authenticates the contained evidence assertions.
	AllowHTTP bool
	// Limits bounds requests, bodies, redirects and the duration of one collection call.
	Limits Limits
	// Now supplies an untrusted observation clock; nil uses time.Now.
	Now func() time.Time
}

// Request identifies an untrusted evidence body to retrieve. Method defaults to GET.
// POST requires OCSP kind and a nonempty bounded request body. Other methods are
// rejected. Inputs must remain unchanged during collection. The caller separately
// supplies expected OCSP request, nonce and CertID bindings for offline verification.
type Request struct {
	// Kind selects the intended offline parser without asserting that the response is
	// valid.
	Kind evidence.Kind
	// URI is the exact authorized absolute HTTP(S) resource URI.
	URI string
	// Method selects GET or OCSP POST. Empty selects GET.
	Method string
	// Body contains the OCSP request bytes for POST. GET requires an empty body.
	Body []byte
}

// HTTP collects untrusted evidence under immutable resource policy. Construct it
// with NewHTTP. Concurrent calls use separate counters and redirect state; the
// shared transport, cookie jar and optional clock must also support concurrent use.
type HTTP struct {
	client  http.Client
	allowed map[string]struct{}
	limits  Limits
	now     func() time.Time
}

// NewHTTP snapshots a bounded exact URI policy without performing I/O.
func NewHTTP(config Config) (*HTTP, error) {
	if config.Client == nil || config.Client.Transport != nil && nilcheck.IsNil(config.Client.Transport) || len(config.AllowedURIs) == 0 || len(config.AllowedURIs) > 256 {
		return nil, evidence.ErrInput
	}

	limits, err := normalizeLimits(config.Limits)
	if err != nil {
		return nil, err
	}

	c := &HTTP{client: *config.Client, allowed: make(map[string]struct{}, len(config.AllowedURIs)), limits: limits, now: config.Now}
	if c.now == nil {
		c.now = time.Now
	}

	for _, raw := range config.AllowedURIs {
		u, err := collectionURI(raw)
		if err != nil || u.Scheme != "https" && !(config.AllowHTTP && u.Scheme == "http") {
			return nil, evidence.ErrInput
		}

		if _, exists := c.allowed[raw]; exists {
			return nil, evidence.ErrInput
		}

		c.allowed[raw] = struct{}{}
	}

	return c, nil
}

// Collect returns observations only when every requested retrieval succeeds.
// On any HTTP, redirect, reader, close, budget or cancellation error it returns
// no partial result. Returned bytes remain untrusted, including over HTTPS.
func (c *HTTP) Collect(ctx context.Context, requests []Request) ([]*evidence.Observation, error) {
	return collect(c, ctx, requests, evidence.ReadObservation)
}

// CollectTo stores exact response bytes in store, retaining only metadata in
// heap. The caller owns store and each returned record. All records created by
// this call are removed on any retrieval, close, cancellation or budget error.
// The returned records remain untrusted and require offline authentication.
func (c *HTTP) CollectTo(ctx context.Context, store *evidence.Store, requests []Request) ([]*evidence.Record, error) {
	if store == nil {
		return nil, evidence.ErrInput
	}

	return collect(c, ctx, requests, store.PutReader)
}

func normalizeLimits(limits Limits) (Limits, error) {
	for _, field := range []struct {
		value    *int
		fallback int
		maximum  int
	}{
		{value: &limits.MaxResources, fallback: 8, maximum: 64},
		{value: &limits.MaxBytes, fallback: 4 << 20, maximum: 64 << 20},
		{value: &limits.MaxTotalBytes, fallback: 16 << 20, maximum: 64 << 20},
		{value: &limits.MaxRequestBytes, fallback: 64 << 10, maximum: 64 << 10},
		{value: &limits.MaxTotalRequestBytes, fallback: 512 << 10, maximum: 4 << 20},
	} {
		if *field.value == 0 {
			*field.value = field.fallback
		}

		if *field.value < 1 || *field.value > field.maximum {
			return Limits{}, evidence.ErrInput
		}
	}

	if limits.MaxRedirects < 0 || limits.MaxRedirects > 10 {
		return Limits{}, evidence.ErrInput
	}

	if limits.Timeout == 0 {
		limits.Timeout = 10 * time.Second
	}

	if limits.Timeout < time.Millisecond || limits.Timeout > 2*time.Minute {
		return Limits{}, evidence.ErrInput
	}

	return limits, nil
}

func collectionURI(raw string) (*url.URL, error) {
	if len(raw) > 8192 || !utf8.ValidString(raw) || strings.ContainsAny(raw, "\x00\r\n") {
		return nil, evidence.ErrPolicy
	}

	u, err := url.Parse(raw)
	if err != nil || u.Opaque != "" || u.Hostname() == "" || u.User != nil || u.Fragment != "" || strings.ContainsRune(u.Path, '\\') || u.String() != raw {
		return nil, evidence.ErrPolicy
	}

	return u, nil
}

type collection struct {
	collector *HTTP
	requests  int
	octets    int
}

type (
	collected                      interface{ Size() int }
	observationReader[T collected] func(context.Context, evidence.Kind, io.Reader, evidence.Provenance, int) (T, error)
)

func release[T collected](item T) error {
	if closer, ok := any(item).(io.Closer); ok {
		return closer.Close()
	}

	return nil
}

func collect[T collected](c *HTTP, ctx context.Context, requests []Request, read observationReader[T]) ([]T, error) {
	if ctx == nil || c == nil || c.allowed == nil || len(requests) == 0 {
		return nil, evidence.ErrInput
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	if len(requests) > c.limits.MaxResources {
		return nil, evidence.ErrLimit
	}

	plans := make([]Request, len(requests))
	defer func() {
		for _, plan := range plans {
			clear(plan.Body)
		}
	}()

	remaining := c.limits.MaxTotalRequestBytes

	for i, request := range requests {
		if !evidence.ValidKind(request.Kind) {
			return nil, evidence.ErrPolicy
		}

		if _, allowed := c.allowed[request.URI]; !allowed {
			return nil, evidence.ErrPolicy
		}

		if request.Method == "" {
			request.Method = http.MethodGet
		}

		if request.Method != http.MethodGet && request.Method != http.MethodPost || request.Method == http.MethodGet && len(request.Body) != 0 || request.Method == http.MethodPost && (request.Kind != evidence.OCSP || len(request.Body) == 0) {
			return nil, evidence.ErrPolicy
		}

		if len(request.Body) > c.limits.MaxRequestBytes || len(request.Body) > remaining {
			return nil, evidence.ErrLimit
		}

		remaining -= len(request.Body)
		request.Body = bytes.Clone(request.Body)
		plans[i] = request
	}

	ctx, cancel := context.WithTimeout(ctx, c.limits.Timeout)
	defer cancel()

	state := collection{collector: c, requests: c.limits.MaxResources, octets: c.limits.MaxTotalBytes}

	observations := make([]T, 0, len(plans))
	for _, request := range plans {
		observation, err := fetch(&state, ctx, request, read)
		if err != nil {
			for _, item := range observations {
				err = errors.Join(err, release(item))
			}

			return nil, err
		}

		observations = append(observations, observation)
	}

	return observations, nil
}

func fetch[T collected](s *collection, ctx context.Context, input Request, read observationReader[T]) (T, error) {
	var zero T
	if s.requests == 0 || s.octets == 0 {
		return zero, evidence.ErrLimit
	}

	if err := ctx.Err(); err != nil {
		return zero, err
	}

	s.requests--

	var redirects []string

	client := s.collector.client

	transport := &responseTransport{base: client.Transport}
	if transport.base == nil {
		transport.base = http.DefaultTransport
	}

	client.Transport = transport
	check := client.CheckRedirect
	client.CheckRedirect = func(request *http.Request, via []*http.Request) error {
		if len(via) > s.collector.limits.MaxRedirects || s.requests == 0 {
			return evidence.ErrLimit
		}

		if check != nil {
			if err := check(request, via); err != nil {
				return err
			}
		}

		if request.URL == nil {
			return evidence.ErrPolicy
		}

		if _, allowed := s.collector.allowed[request.URL.String()]; !allowed || request.Method != input.Method {
			return evidence.ErrPolicy
		}

		s.requests--

		redirects = append(redirects, request.URL.String())

		return nil
	}

	request, err := http.NewRequestWithContext(ctx, input.Method, input.URI, bytes.NewReader(input.Body))
	if err != nil {
		return zero, errors.Join(evidence.ErrResource, err)
	}

	if input.Method == http.MethodPost {
		request.Header.Set("Content-Type", "application/ocsp-request")
	}

	response, err := client.Do(request)
	if err != nil {
		return zero, errors.Join(evidence.ErrResource, err, transport.failure())
	}

	provenance := evidence.Provenance{URI: input.URI, Redirects: redirects, RetrievedAt: s.collector.now()}
	if len(input.Body) != 0 {
		provenance.RequestSHA256 = sha256.Sum256(input.Body)
	}

	var observation T

	if response.StatusCode != http.StatusOK {
		err = fmt.Errorf("%w: HTTP status %d", evidence.ErrResource, response.StatusCode)
	} else {
		observation, err = read(ctx, input.Kind, response.Body, provenance, min(s.collector.limits.MaxBytes, s.octets))
	}

	if err := errors.Join(err, response.Body.Close(), transport.failure(), ctx.Err()); err != nil {
		if observation.Size() != 0 {
			err = errors.Join(err, release(observation))
		}

		return zero, errors.Join(evidence.ErrResource, err)
	}

	s.octets -= observation.Size()

	return observation, nil
}

// net/http closes intermediate redirect bodies itself and discards their Close
// errors. Keep those failures operation-local, including asynchronous cleanup.
// The wrapper retains only Reader/Closer behavior: collectors do not consume
// optional body interfaces. It never mutates the caller's shared transport.
type responseTransport struct {
	base         http.RoundTripper
	mutex        sync.Mutex
	failureError error
}

func (t *responseTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	if err := t.failure(); err != nil {
		return nil, err
	}

	response, err := t.base.RoundTrip(request)
	if response == nil || response.Body == nil {
		return response, err
	}

	if nilcheck.IsNil(response.Body) {
		return nil, errors.Join(err, evidence.ErrResource)
	}

	response.Body = &responseBody{ReadCloser: response.Body, reader: streamio.Reader{Context: request.Context(), Source: response.Body, Limit: math.MaxInt64, LimitError: evidence.ErrLimit}, transport: t}
	if err != nil {
		// A custom transport can return both a response and an error. Client.Do
		// discards that response, so close its body here rather than losing ownership.
		return nil, errors.Join(err, response.Body.Close())
	}

	return response, nil
}

func (t *responseTransport) failure() error {
	t.mutex.Lock()
	defer t.mutex.Unlock()

	return t.failureError
}

func (t *responseTransport) record(err error) {
	if err == nil {
		return
	}

	t.mutex.Lock()
	defer t.mutex.Unlock()

	t.failureError = errors.Join(t.failureError, err)
}

type responseBody struct {
	io.ReadCloser
	reader     streamio.Reader
	transport  *responseTransport
	once       sync.Once
	closeError error
}

// Redirect drains are transport work, not delivered evidence bytes. Still
// preserve their non-EOF failures and bound stalled/invalid reader behavior.
func (b *responseBody) Read(dst []byte) (int, error) {
	n, err := b.reader.Read(dst)
	// A joined EOF may also carry a real read/cancellation failure. Only the
	// Reader contract's exact terminal sentinel is an ordinary end of stream.
	if err != nil && err != io.EOF { //nolint:errorlint // Only exact EOF is benign; wrapped/joined failures must be retained.
		b.transport.record(err)
	}

	return n, err
}

func (b *responseBody) Close() error {
	b.once.Do(func() { b.closeError = b.ReadCloser.Close(); b.transport.record(b.closeError) })
	return b.closeError
}
