package httpclient_test

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"testing/synctest"
	"time"

	"github.com/skarm/xmlsec/saml/internal/httpclient"
)

// Some caller-owned transports implement the pre-context CancelRequest API.
type legacyTransport struct {
	canceled chan *http.Request
}

func (l legacyTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	select {
	case canceled := <-l.canceled:
		if canceled != req {
			return nil, errors.New("canceled a different request")
		}
		return nil, context.Canceled
	case <-time.After(2 * time.Second):
		return nil, errors.New("transport did not receive cancellation")
	}
}

func (l legacyTransport) CancelRequest(req *http.Request) {
	l.canceled <- req
}

func TestTimeoutCancelsLegacyTransport(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		source := &http.Client{Transport: legacyTransport{canceled: make(chan *http.Request, 1)}, Timeout: time.Second}
		client, err := httpclient.WithoutRedirects(source, errors.New("invalid HTTP configuration"))
		if err != nil {
			t.Fatal(err)
		}
		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "https://example.test/", nil)
		if err != nil {
			t.Fatal(err)
		}
		started := time.Now()
		resp, err := client.Do(req)
		if resp != nil {
			resp.Body.Close()
			t.Fatal("transport returned an unexpected response")
		}
		if !errors.Is(err, context.DeadlineExceeded) || time.Since(started) != source.Timeout {
			t.Fatalf("request finished after %s with %v", time.Since(started), err)
		}
	})
}
