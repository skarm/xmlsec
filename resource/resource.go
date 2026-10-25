// Package resource supplies explicitly configured resource adapters shared by
// transform and xmlenc. Adapters perform no I/O until Resolve is called; the
// consuming library package owns byte limits and closes the returned stream.
package resource

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/url"
	"strings"

	"github.com/skarm/xmlsec/internal/nilcheck"
)

var (
	// ErrInput reports invalid adapter configuration.
	ErrInput = errors.New("resource: invalid input")
	// ErrPolicy reports a URI outside the configured resource scope.
	ErrPolicy = errors.New("resource: disallowed URI")
	// ErrResource reports an unavailable resource, preserving its underlying error.
	ErrResource = errors.New("resource: unavailable resource")
)

// Resolver opens exact resources approved by application policy. Implementations
// must support concurrent use and honor context, including during reads.
type Resolver interface {
	// Resolve opens an authorized URI. The consumer owns the returned reader
	// and closes every non-nil reader, including when resolution fails.
	Resolve(context.Context, string) (io.ReadCloser, error)
}

// TypedReader optionally supplies the resource's MIME Content-Type, including
// parameters such as charset. Empty means no transport metadata is available.
// The value must remain stable for the lifetime of the stream. Consumers still
// own byte limits and Close; metadata does not authorize additional retrievals.
type TypedReader interface {
	io.ReadCloser
	MediaType() string
}

// ResolverFunc adapts an application function to the shared resource contract.
type ResolverFunc func(context.Context, string) (io.ReadCloser, error)

// Resolve calls f. A nil function reports ErrResource.
func (f ResolverFunc) Resolve(ctx context.Context, uri string) (io.ReadCloser, error) {
	if f == nil {
		return nil, ErrResource
	}

	return f(ctx, uri)
}

// FSConfig maps an absolute directory URI to an explicitly supplied filesystem.
// Use embed.FS for embedded resources or os.Root.FS for confined disk access.
type FSConfig struct {
	// FS is required and remains application-owned. Its symlink and blocking-I/O
	// behavior is the application's responsibility.
	FS fs.FS
	// BaseURI is an absolute directory URI ending in a slash. Resource paths
	// below it are resolved relative to FS, not the process working directory.
	BaseURI string
}

// FSResolver is immutable after construction. Its FS must support concurrent reads.
type FSResolver struct {
	fs   fs.FS
	base *url.URL
}

// NewFSResolver constructs a filesystem adapter. BaseURI must end in a slash.
func NewFSResolver(config FSConfig) (*FSResolver, error) {
	base, err := parseURI(config.BaseURI)
	if err != nil || nilcheck.IsNil(config.FS) || !strings.HasSuffix(base.Path, "/") {
		return nil, ErrInput
	}

	return &FSResolver{fs: config.FS, base: base}, nil
}

// Resolve opens the relative FS path under BaseURI. It refuses traversal,
// fragments, queries, authorities outside the base and ambiguous backslashes.
func (r *FSResolver) Resolve(ctx context.Context, uri string) (io.ReadCloser, error) {
	if ctx == nil {
		return nil, ErrInput
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	if r == nil || r.base == nil {
		return nil, ErrInput
	}

	u, err := parseURI(uri)
	if err != nil || u.Scheme != r.base.Scheme || u.Host != r.base.Host || !strings.HasPrefix(u.Path, r.base.Path) {
		return nil, ErrPolicy
	}

	name := strings.TrimPrefix(u.Path, r.base.Path)
	if !fs.ValidPath(name) || strings.ContainsRune(name, '\\') {
		return nil, ErrPolicy
	}

	f, err := r.fs.Open(name)
	if err != nil {
		if !nilcheck.IsNil(f) {
			err = errors.Join(err, f.Close())
		}

		return nil, errors.Join(ErrResource, err)
	}

	if nilcheck.IsNil(f) {
		return nil, fmt.Errorf("%w: filesystem returned a nil file", ErrResource)
	}

	if err := ctx.Err(); err != nil {
		return nil, errors.Join(err, f.Close())
	}

	return &contextReader{ctx: ctx, ReadCloser: f}, nil
}

// HTTPConfig configures an HTTP client and an explicit origin allowlist.
type HTTPConfig struct {
	// Client is required. Its value is copied to enforce redirect checks;
	// Transport and Jar remain shared with the caller.
	Client *http.Client
	// AllowedOrigins is a required allowlist of exact HTTP(S) scheme and host
	// pairs, including any port. It is checked again on every redirect.
	AllowedOrigins []string
}

// HTTPResolver enforces the origin policy on the initial request and redirects.
type HTTPResolver struct {
	client  *http.Client
	origins map[string]bool
}

// NewHTTPResolver requires an explicit client and at least one allowed origin.
func NewHTTPResolver(config HTTPConfig) (*HTTPResolver, error) {
	if config.Client == nil || config.Client.Transport != nil && nilcheck.IsNil(config.Client.Transport) || len(config.AllowedOrigins) == 0 {
		return nil, ErrInput
	}

	r := &HTTPResolver{origins: make(map[string]bool, len(config.AllowedOrigins))}
	for _, origin := range config.AllowedOrigins {
		u, err := parseURI(origin)
		if err != nil || u.Scheme != "http" && u.Scheme != "https" || u.Host == "" || u.Path != "" && u.Path != "/" {
			return nil, ErrInput
		}

		r.origins[u.Scheme+"://"+u.Host] = true
	}

	client := *config.Client
	redirect := client.CheckRedirect
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if !r.allowed(req.URL) {
			return ErrPolicy
		}

		if redirect != nil {
			if err := redirect(req, via); err != nil {
				return err
			}

			if !r.allowed(req.URL) {
				return ErrPolicy
			}

			return nil
		}

		if len(via) >= 10 {
			return fmt.Errorf("%w: too many redirects", ErrPolicy)
		}

		return nil
	}
	r.client = &client

	return r, nil
}

// Resolve retrieves one HTTP resource with request and body cancellation.
func (r *HTTPResolver) Resolve(ctx context.Context, uri string) (io.ReadCloser, error) {
	if ctx == nil || r == nil || r.client == nil {
		return nil, ErrInput
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	u, err := url.Parse(uri)
	if err != nil || !r.allowed(u) || u.Fragment != "" {
		return nil, ErrPolicy
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, errors.Join(ErrResource, err)
	}

	response, err := r.client.Do(req)
	if err != nil {
		return nil, errors.Join(ErrResource, err)
	}

	if err := ctx.Err(); err != nil {
		return nil, errors.Join(err, response.Body.Close())
	}

	if response.StatusCode != http.StatusOK {
		return nil, errors.Join(fmt.Errorf("%w: HTTP status %d", ErrResource, response.StatusCode), response.Body.Close())
	}

	return &contextReader{ctx: ctx, ReadCloser: response.Body, mediaType: response.Header.Get("Content-Type")}, nil
}

func (r *HTTPResolver) allowed(u *url.URL) bool {
	return u != nil && u.User == nil && (u.Scheme == "http" || u.Scheme == "https") && r.origins[u.Scheme+"://"+u.Host]
}

func parseURI(value string) (*url.URL, error) {
	u, err := url.Parse(value)
	if err != nil || !u.IsAbs() || u.Opaque != "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || strings.ContainsRune(u.Path, '\\') {
		return nil, ErrPolicy
	}

	return u, nil
}

type contextReader struct {
	ctx context.Context
	io.ReadCloser
	mediaType string
}

func (r *contextReader) MediaType() string { return r.mediaType }

func (r *contextReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}

	n, err := r.ReadCloser.Read(p)
	if n < 0 || n > len(p) {
		return 0, errors.Join(ErrResource, io.ErrShortBuffer)
	}

	if canceled := r.ctx.Err(); canceled != nil {
		return n, errors.Join(err, canceled)
	}

	return n, err
}
