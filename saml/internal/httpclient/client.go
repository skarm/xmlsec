// Package httpclient supplies the redirect-free HTTP client used by SAML bindings.
package httpclient

import (
	"errors"
	"net/http"
	"time"

	"github.com/skarm/xmlsec/internal/nilcheck"
)

func WithoutRedirects(source *http.Client, invalid error) (*http.Client, error) {
	const defaultTimeout = 30 * time.Second

	client := http.Client{Timeout: defaultTimeout}
	if source != nil {
		client = *source
	}

	transport := client.Transport
	if transport == nil {
		transport = http.DefaultTransport
	}

	if nilcheck.IsNil(transport) || client.Jar != nil && nilcheck.IsNil(client.Jar) {
		return nil, invalid
	}

	client.Transport = responseTransport{base: transport, invalid: invalid}
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

	return &client, nil
}

type responseTransport struct {
	base    http.RoundTripper
	invalid error
}

func (t responseTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	response, err := t.base.RoundTrip(req)
	if response == nil || response.Body == nil {
		return response, err
	}

	if nilcheck.IsNil(response.Body) {
		return nil, errors.Join(t.invalid, err)
	}

	if err != nil {
		return nil, errors.Join(err, response.Body.Close())
	}

	return response, nil
}

func (t responseTransport) CancelRequest(req *http.Request) {
	if legacy, ok := t.base.(interface{ CancelRequest(*http.Request) }); ok {
		legacy.CancelRequest(req)
	}
}
