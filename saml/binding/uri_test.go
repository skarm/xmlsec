package binding_test

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"testing/iotest"

	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/saml/binding"
)

func TestAssertionURIBinding(t *testing.T) {
	for _, endpoint := range []string{"https://authority.test/assertion?other=x", "https://authority.test/assertion?", "https://authority.test/assertion#fragment"} {
		if _, err := binding.AssertionURL(endpoint, "_held", false); err == nil {
			t.Fatalf("invalid endpoint accepted: %s", endpoint)
		}
	}
	for _, query := range []string{"ID=_held&ID=_other", "ID=_held&extra=value", "id=_held", "ID=*", "ID=%ZZ"} {
		r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "https://authority.test/assertion?"+query, nil)
		if _, err := binding.ReadAssertionID(r); err == nil {
			t.Fatalf("invalid query accepted: %s", query)
		}
	}
	d, err := document.Parse(t.Context(), []byte(`<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_held"/>`), document.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	if err = binding.WriteAssertion(t.Context(), response, d); err != nil {
		t.Fatal(err)
	}
	if response.Header().Get("Content-Type") != binding.AssertionMediaType || response.Header().Get("Cache-Control") != "no-cache, no-store" || response.Header().Get("Pragma") != "no-cache" {
		t.Fatal("URI media/cache contract")
	}
	for _, mode := range []string{"good", "wrong-id", "redirect", "oversize"} {
		t.Run(mode, func(t *testing.T) {
			var requests, targetHits atomic.Int32
			server := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/elsewhere" {
					targetHits.Add(1)
					http.Error(w, "unexpected redirect", http.StatusForbidden)
					return
				}
				requests.Add(1)
				if r.Method != http.MethodGet || r.URL.RawQuery != "ID=_held" {
					t.Errorf("assertion request method=%q, query=%q; want GET, ID=_held", r.Method, r.URL.RawQuery)
					http.Error(w, "invalid test request", http.StatusBadRequest)
					return
				}
				if mode == "redirect" {
					http.Redirect(w, r, "/elsewhere", http.StatusFound)
					return
				}
				w.Header().Set("Content-Type", binding.AssertionMediaType)
				id := "_held"
				if mode == "wrong-id" {
					id = "_other"
				}
				if _, err := io.WriteString(w, `<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="`+id+`"/>`); err != nil {
					t.Errorf("write test assertion: %v", err)
				}
			}))
			client := binding.URIClient{Client: server.Client(), AllowHTTP: true}
			if mode == "oversize" {
				client.MaxBytes = 16
			}
			got, err := client.Resolve(t.Context(), server.URL, "_held")
			if count, followed := requests.Load(), targetHits.Load(); count != 1 || followed != 0 {
				t.Errorf("assertion endpoint and redirect target received %d and %d requests, want 1 and 0", count, followed)
			}
			if mode != "good" {
				if got != nil || !errors.Is(err, binding.ErrBinding) {
					t.Fatalf("Resolve returned assertion=%p, err=%v; want nil, %v", got, err, binding.ErrBinding)
				}
				return
			}
			if err != nil || got == nil {
				t.Fatalf("Resolve returned assertion=%p, err=%v; want an assertion and nil error", got, err)
			}
			if id, _ := got.Root().Attribute(document.Name{Local: "ID"}); id != "_held" {
				t.Fatalf("resolved assertion ID = %q, want _held", id)
			}
		})
	}
}

func TestURIClientResponseCloseContract(t *testing.T) {
	const valid = `<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_held"/>`
	closeFailure := errors.New("URI response close failed")
	readFailure := errors.New("URI response read failed")
	for _, tc := range []struct {
		name   string
		status int
		reader func() io.Reader
		cause  error
	}{
		{"valid assertion", http.StatusOK, func() io.Reader { return strings.NewReader(valid) }, nil},
		{"malformed XML", http.StatusOK, func() io.Reader { return strings.NewReader("<broken") }, document.ErrMalformed},
		{"HTTP failure", http.StatusForbidden, func() io.Reader { return strings.NewReader("denied") }, binding.ErrBinding},
		{"read failure", http.StatusOK, func() io.Reader { return iotest.ErrReader(readFailure) }, readFailure},
	} {
		for _, failClose := range []bool{false, true} {
			name := tc.name + "/close-ok"
			if failClose {
				name = tc.name + "/close-failed"
			}
			t.Run(name, func(t *testing.T) {
				body := &soapClosingBody{Reader: tc.reader()}
				if failClose {
					body.err = closeFailure
				}
				client := binding.URIClient{Client: &http.Client{Transport: soapRoundTripperFunc(func(*http.Request) (*http.Response, error) {
					return &http.Response{StatusCode: tc.status, Header: http.Header{"Content-Type": {binding.AssertionMediaType}}, Body: body}, nil
				})}}
				result, err := client.Resolve(t.Context(), "https://authority.test/assertion", "_held")
				if body.closed != 1 {
					t.Errorf("response closed %d times; want once", body.closed)
				}
				if failClose {
					if result != nil || !errors.Is(err, closeFailure) {
						t.Errorf("close failure lost or result released: result=%v error=%v", result, err)
					}
				} else if tc.cause == nil {
					if err != nil || result == nil {
						t.Fatalf("valid response lost: result=%v error=%v", result, err)
					}
					id, _ := result.Root().Attribute(document.Name{Local: "ID"})
					if id != "_held" {
						t.Fatal("wrong assertion", id)
					}
				}
				if tc.cause != nil && (result != nil || !errors.Is(err, tc.cause)) {
					t.Errorf("original failure lost: result=%v error=%v; want %v", result, err, tc.cause)
				}
			})
		}
	}
}
