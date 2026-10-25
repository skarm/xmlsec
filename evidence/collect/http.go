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

// Limits bounds a complete Collect call. Zero selects the documented default,
// except MaxRedirects: zero denies redirects; a positive value opts into them.
type Limits struct {
	// MaxResources bounds all HTTP requests, including redirects; default8, max64.
	MaxResources int
	// MaxBytes bounds each delivered evidence body; default4MiB, maximum64MiB.
	MaxBytes int
	// MaxTotalBytes bounds all delivered evidence bodies; default16MiB, max64MiB.
	// HTTP framing/headers and redirect bodies belong to the supplied transport;
	// their work is separately bounded by MaxResources, MaxRedirects and Timeout.
	MaxTotalBytes int
	// MaxRequestBytes bounds each OCSP POST body; default/max64KiB.
	MaxRequestBytes int
	// MaxTotalRequestBytes bounds snapshotted POST bodies; default512KiB, max4MiB.
	MaxTotalRequestBytes int
	// MaxRedirects is the maximum per resource; zero denies, maximum10.
	MaxRedirects int
	// Timeout bounds the complete call, including response reads; default10s, max2m.
	Timeout time.Duration
}

// Config requires an application-owned client and exact authorized URIs.
// The client value is copied; Transport/Jar stay application-owned and must
// support concurrency and cancellation. The application controls DNS, IP/proxy
// access, TLS roots and credentials through that transport. No implicit client,
// system fetch, certificate AIA traversal or revocation fallback is supplied.
type Config struct {
	Client *http.Client
	// AllowedURIs contains1..256 exact absolute HTTP(S) URI strings, no fragments
	// or userinfo. Every followed redirect must also be explicitly listed.
	AllowedURIs []string
	// AllowHTTP explicitly permits HTTP; HTTPS remains the default scheme policy.
	// Transport protection never authenticates the contained evidence assertions.
	AllowHTTP bool
	Limits    Limits
	// Now supplies an untrusted observation clock; nil uses time.Now.
	Now func() time.Time
}

// Request selects one opaque body. An empty Method means GET. POST is permitted
// only for OCSP with a nonempty bounded request body; no other methods are used.
// The caller independently carries expected OCSP request/nonce/CertID bindings
// into offline verification. Inputs must stay unchanged during Collect.
type Request struct {
	Kind   evidence.Kind
	URI    string
	Method string
	Body   []byte
}

// HTTP is immutable after construction. Its client transport, jar and optional
// clock must support concurrent calls. Per-call counters and redirects are local.
type HTTP struct {
	client  http.Client
	allowed map[string]bool
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

	c := &HTTP{client: *config.Client, allowed: make(map[string]bool, len(config.AllowedURIs)), limits: limits, now: config.Now}
	if c.now == nil {
		c.now = time.Now
	}

	for _, raw := range config.AllowedURIs {
		u, err := collectionURI(raw)
		if err != nil || u.Scheme != "https" && !(config.AllowHTTP && u.Scheme == "http") || c.allowed[raw] {
			return nil, evidence.ErrInput
		}

		c.allowed[raw] = true
	}

	return c, nil
}

func normalizeLimits(limits Limits) (Limits, error) {
	for _, field := range []struct {
		value             *int
		fallback, maximum int
	}{
		{&limits.MaxResources, 8, 64},
		{&limits.MaxBytes, 4 << 20, 64 << 20},
		{&limits.MaxTotalBytes, 16 << 20, 64 << 20},
		{&limits.MaxRequestBytes, 64 << 10, 64 << 10},
		{&limits.MaxTotalRequestBytes, 512 << 10, 4 << 20},
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
	collector        *HTTP
	requests, octets int
}

// Collect returns observations only when every requested retrieval succeeds.
// On any HTTP, redirect, reader, close, budget or cancellation error it returns
// no partial result. Returned bytes remain untrusted, including over HTTPS.
func (c *HTTP) Collect(ctx context.Context, requests []Request) ([]*evidence.Observation, error) {
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
		if !evidence.ValidKind(request.Kind) || !c.allowed[request.URI] {
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

	observations := make([]*evidence.Observation, 0, len(plans))
	for _, request := range plans {
		observation, err := state.fetch(ctx, request)
		if err != nil {
			return nil, err
		}

		observations = append(observations, observation)
	}

	return observations, nil
}

func (s *collection) fetch(ctx context.Context, input Request) (*evidence.Observation, error) {
	if s.requests == 0 || s.octets == 0 {
		return nil, evidence.ErrLimit
	}

	if err := ctx.Err(); err != nil {
		return nil, err
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

		if request.URL == nil || !s.collector.allowed[request.URL.String()] || request.Method != input.Method {
			return evidence.ErrPolicy
		}

		s.requests--

		redirects = append(redirects, request.URL.String())

		return nil
	}

	request, err := http.NewRequestWithContext(ctx, input.Method, input.URI, bytes.NewReader(input.Body))
	if err != nil {
		return nil, errors.Join(evidence.ErrResource, err)
	}

	if input.Method == http.MethodPost {
		request.Header.Set("Content-Type", "application/ocsp-request")
	}

	response, err := client.Do(request)
	if err != nil {
		return nil, errors.Join(evidence.ErrResource, err, transport.failure())
	}

	data, err := s.read(ctx, response)
	if closeErr := transport.failure(); err != nil || closeErr != nil {
		clear(data)
		return nil, errors.Join(evidence.ErrResource, err, closeErr)
	}

	s.octets -= len(data)

	provenance := evidence.Provenance{URI: input.URI, Redirects: redirects, RetrievedAt: s.collector.now()}
	if len(input.Body) != 0 {
		provenance.RequestSHA256 = sha256.Sum256(input.Body)
	}

	observation, err := evidence.NewObservation(ctx, input.Kind, data, provenance)
	clear(data)

	return observation, err
}

func (s *collection) read(ctx context.Context, response *http.Response) ([]byte, error) {
	var (
		data []byte
		err  error
	)
	if response.StatusCode != http.StatusOK {
		err = fmt.Errorf("%w: HTTP status %d", evidence.ErrResource, response.StatusCode)
	} else {
		reader := &streamio.Reader{Context: ctx, Source: response.Body, Limit: int64(min(s.collector.limits.MaxBytes, s.octets)), LimitError: evidence.ErrLimit}

		data, err = io.ReadAll(reader)
		if err == nil && len(data) == 0 {
			err = fmt.Errorf("%w: empty body", evidence.ErrResource)
		}
	}

	err = errors.Join(err, response.Body.Close(), ctx.Err())
	if err != nil {
		clear(data)
		return nil, errors.Join(evidence.ErrResource, err)
	}

	return data, nil
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
