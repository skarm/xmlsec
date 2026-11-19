package binding_test

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/saml/binding"
)

func TestWrapSOAPRejectsEmptyDocument(t *testing.T) {
	for _, payload := range []*document.Document{nil, {}} {
		envelope, err := binding.WrapSOAP(t.Context(), payload)
		if !errors.Is(err, binding.ErrBinding) || envelope != nil {
			t.Fatal("invalid payload must be rejected without an envelope", err)
		}
	}
}

func TestWriteSOAPFaultRequiresValidatedEnvelope(t *testing.T) {
	const headerNamespace = "urn:mandatory-header"
	raw := soapPrefix + `<s:Header><h:route xmlns:h="` + headerNamespace + `" s:mustUnderstand="1"/></s:Header><s:Body><s:Fault><faultcode>s:Client</faultcode><faultstring>bad request</faultstring></s:Fault></s:Body></s:Envelope>`
	envelope, err := document.Parse(t.Context(), []byte(raw), document.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	for _, understood := range []bool{false, true} {
		options := binding.SOAPOptions{}
		if understood {
			options.Understood = []document.Name{{Space: headerNamespace, Local: "route"}}
		}
		writer := httptest.NewRecorder()
		err := binding.WriteSOAPResponseWithOptions(t.Context(), writer, envelope, options)
		if understood {
			if err != nil || writer.Code != http.StatusInternalServerError || writer.Body.Len() == 0 {
				t.Fatal("valid remote fault was not forwarded", err)
			}
		} else {
			var fault *binding.SOAPFault
			if !errors.As(err, &fault) || fault.Code.Local != "MustUnderstand" || writer.Body.Len() != 0 || len(writer.Header()) != 0 {
				t.Fatal("invalid envelope was transmitted as a valid SOAP fault", err)
			}
		}
	}
}

type soapRoundTripperFunc func(*http.Request) (*http.Response, error)

func (f soapRoundTripperFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type soapClosingBody struct {
	io.Reader
	err     error
	onClose func()
	closed  int
}

func (b *soapClosingBody) Close() error {
	b.closed++
	if b.onClose != nil {
		b.onClose()
	}
	return b.err
}

func TestBindingClientsObserveCancellationDuringResponseClose(t *testing.T) {
	const soap = soapPrefix + `<s:Body><p:LogoutResponse/></s:Body></s:Envelope>`
	const assertion = `<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_held"/>`
	envelope, err := document.Parse(t.Context(), []byte(soap), document.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}

	for _, test := range []struct {
		name string
		raw  string
		call func(context.Context, *http.Client) (bool, error)
	}{
		{"SOAP", soap, func(ctx context.Context, client *http.Client) (bool, error) {
			got, err := (binding.SOAPClient{Client: client}).RoundTrip(ctx, "https://peer.test/soap", envelope)
			return got != nil, err
		}},
		{"URI", assertion, func(ctx context.Context, client *http.Client) (bool, error) {
			got, err := (binding.URIClient{Client: client}).Resolve(ctx, "https://peer.test/assertion", "_held")
			return got != nil, err
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			body := &soapClosingBody{Reader: strings.NewReader(test.raw), onClose: cancel}
			client := &http.Client{Transport: soapRoundTripperFunc(func(*http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": {"text/xml"}}, Body: body}, nil
			})}
			if got, err := test.call(ctx, client); got || !errors.Is(err, context.Canceled) || body.closed != 1 {
				t.Fatalf("got result=%t, err=%v, closes=%d; want no result, cancellation, and one close", got, err, body.closed)
			}
		})
	}
}

func TestBindingClientsCloseResponseReturnedWithTransportError(t *testing.T) {
	const valid = soapPrefix + `<s:Body><p:LogoutResponse/></s:Body></s:Envelope>`
	envelope, err := document.Parse(t.Context(), []byte(valid), document.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	transportFailure := errors.New("transport failed with response")
	closeFailure := errors.New("closing unused response failed")
	for _, mode := range []string{"SOAP", "URI"} {
		t.Run(mode, func(t *testing.T) {
			body := &soapClosingBody{Reader: strings.NewReader("unused"), err: closeFailure}
			client := &http.Client{Transport: soapRoundTripperFunc(func(*http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: http.StatusOK, Body: body}, transportFailure
			})}
			var err error
			if mode == "SOAP" {
				result, callErr := (binding.SOAPClient{Client: client}).RoundTrip(t.Context(), "https://peer.test/soap", envelope)
				if result != nil {
					t.Fatal("SOAPClient returned a message on transport failure")
				}
				err = callErr
			} else {
				result, callErr := (binding.URIClient{Client: client}).Resolve(t.Context(), "https://peer.test/assertion", "_held")
				if result != nil {
					t.Fatal("URIClient returned an assertion on transport failure")
				}
				err = callErr
			}
			if body.closed != 1 || !errors.Is(err, transportFailure) || !errors.Is(err, closeFailure) {
				t.Fatalf("body closed %d times, error = %v; want one close and both failures", body.closed, err)
			}
		})
	}
}

func TestURIClientRejectsTypedNilTransportResponseBody(t *testing.T) {
	var body *soapClosingBody
	custom := soapRoundTripperFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Body: body}, nil
	})
	standard := &http.Transport{}
	standard.RegisterProtocol("http", custom)
	for _, test := range []struct {
		name      string
		transport http.RoundTripper
	}{
		{"direct transport", custom},
		{"registered protocol", standard},
	} {
		t.Run(test.name, func(t *testing.T) {
			client := binding.URIClient{Client: &http.Client{Transport: test.transport}, AllowHTTP: true}
			result, err := client.Resolve(t.Context(), "http://peer.test/assertion", "_held")
			if result != nil || !errors.Is(err, binding.ErrBinding) {
				t.Fatalf("Resolve = (%v, %v), want nil document and ErrBinding", result, err)
			}
		})
	}
}

func TestSOAPClientPreservesResponseCloseErrors(t *testing.T) {
	const valid = soapPrefix + `<s:Body><p:LogoutResponse/></s:Body></s:Envelope>`
	envelope, err := document.Parse(t.Context(), []byte(valid), document.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	failure := errors.New("response close failed")
	for _, tc := range []struct {
		name   string
		status int
		body   string
	}{
		{"valid response", http.StatusOK, valid},
		{"invalid XML", http.StatusOK, "<broken"},
		{"HTTP failure", http.StatusForbidden, "denied"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := &soapClosingBody{Reader: strings.NewReader(tc.body), err: failure}
			client := binding.SOAPClient{Client: &http.Client{Transport: soapRoundTripperFunc(func(*http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: tc.status, Header: http.Header{"Content-Type": {"text/xml"}}, Body: body}, nil
			})}}
			response, err := client.RoundTrip(t.Context(), "https://peer.test/soap", envelope)
			if !errors.Is(err, failure) || response != nil || body.closed != 1 {
				t.Fatal("response close failure or ownership was lost", err, body.closed)
			}
			if tc.status == http.StatusForbidden && !errors.Is(err, binding.ErrBinding) {
				t.Fatal("HTTP status failure was lost", err)
			}
		})
	}
}
