package binding_test

import (
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
	err    error
	closed int
}

func (b *soapClosingBody) Close() error {
	b.closed++
	return b.err
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
