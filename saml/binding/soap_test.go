package binding_test

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/saml/binding"
)

const soapPrefix = `<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" xmlns:p="urn:oasis:names:tc:SAML:2.0:protocol">`

func TestSOAPIndependentEnvelopes(t *testing.T) {
	for _, tc := range []struct {
		name, xml string
		wantError bool
		code      string
	}{
		{"minimal", soapPrefix + `<s:Body><p:LogoutResponse/></s:Body></s:Envelope>`, false, ""},
		{"optional header", soapPrefix + `<s:Header><routing xmlns="urn:routing"/></s:Header><s:Body><p:LogoutResponse/></s:Body></s:Envelope>`, false, ""},
		{"mandatory unknown", soapPrefix + `<s:Header><routing xmlns="urn:routing" s:mustUnderstand="1"/></s:Header><s:Body><p:LogoutResponse/></s:Body></s:Envelope>`, true, "MustUnderstand"},
		{"different actor", soapPrefix + `<s:Header><routing xmlns="urn:routing" s:mustUnderstand="1" s:actor="urn:other"/></s:Header><s:Body><p:LogoutResponse/></s:Body></s:Envelope>`, false, ""},
		{"two payloads", soapPrefix + `<s:Body><p:LogoutResponse/><p:LogoutResponse/></s:Body></s:Envelope>`, true, "Client"},
		{"header after body", soapPrefix + `<s:Body><p:LogoutResponse/></s:Body><s:Header/></s:Envelope>`, true, "Client"},
		{"invalid mustUnderstand", soapPrefix + `<s:Header><routing xmlns="urn:routing" s:mustUnderstand="true"/></s:Header><s:Body><p:LogoutResponse/></s:Body></s:Envelope>`, true, "Client"},
		{"SOAP12", `<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Body/></s:Envelope>`, true, "VersionMismatch"},
		{"fault", soapPrefix + `<s:Body><s:Fault><faultcode>s:Client</faultcode><faultstring>bad request</faultstring></s:Fault></s:Body></s:Envelope>`, true, "Client"},
		{"malformed fault QName", soapPrefix + `<s:Body><s:Fault><faultcode>s:Client:bad</faultcode><faultstring>bad request</faultstring></s:Fault></s:Body></s:Envelope>`, true, ""},
		{"duplicate fault field", soapPrefix + `<s:Body><s:Fault><faultcode>s:Client</faultcode><faultstring>bad request</faultstring><faultstring>duplicate</faultstring></s:Fault></s:Body></s:Envelope>`, true, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := binding.DecodeSOAP(t.Context(), []byte(tc.xml), binding.SOAPOptions{})
			if (err != nil) != tc.wantError {
				t.Fatalf("DecodeSOAP: %v", err)
			}
			if tc.code != "" {
				var fault *binding.SOAPFault
				if !errors.As(err, &fault) || fault.Code.Local != tc.code {
					t.Fatalf("fault: %v", err)
				}
			}
		})
	}
	if _, err := binding.DecodeSOAP(t.Context(), []byte(soapPrefix+`<s:Body><p:LogoutResponse/></s:Body></s:Envelope>`), binding.SOAPOptions{MaxBytes: 20}); err == nil {
		t.Fatal("byte bound ignored")
	}
}

func TestSOAPHTTPStatusAndRedirects(t *testing.T) {
	payload, err := document.Parse(t.Context(), []byte(`<p:LogoutResponse xmlns:p="urn:oasis:names:tc:SAML:2.0:protocol"/>`), document.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	request, err := document.Parse(t.Context(), []byte(soapPrefix+`<s:Body><p:LogoutRequest/></s:Body></s:Envelope>`), document.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := binding.WrapSOAP(t.Context(), payload)
	if err != nil {
		t.Fatal(err)
	}
	var redirectHits, targetHits atomic.Int32
	server := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/redirect":
			redirectHits.Add(1)
			http.Redirect(w, r, "/target", http.StatusFound)
			return
		case "/target":
			targetHits.Add(1)
			http.Error(w, "unexpected redirect", http.StatusForbidden)
			return
		}
		if r.Header.Get("SoapAction") == "" {
			t.Error("SOAP request has an empty SOAPAction header")
		}
		if _, err := binding.ReadSOAPRequest(r.Context(), r, binding.SOAPOptions{}); err != nil {
			t.Error(err)
			return
		}
		if err := binding.WriteSOAPResponse(r.Context(), w, envelope); err != nil {
			t.Error(err)
		}
	}))
	client := binding.SOAPClient{Client: server.Client(), AllowHTTP: true}
	message, err := client.RoundTrip(t.Context(), server.URL, request)
	if err != nil {
		t.Fatalf("SOAP exchange: %v", err)
	}
	got, err := message.Payload(t.Context())
	if err != nil {
		t.Fatalf("extract SOAP response payload: %v", err)
	}
	if want := (document.Name{Space: binding.ProtocolNamespace, Local: "LogoutResponse"}); got.Root().Name() != want {
		t.Fatalf("SOAP response payload name = %v, want %v", got.Root().Name(), want)
	}
	fault, err := binding.FaultSOAP(t.Context(), binding.SOAPFault{Code: document.Name{Space: binding.SOAPNamespace, Local: "Client"}, Message: "invalid"})
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	if err := binding.WriteSOAPResponse(t.Context(), w, fault); err != nil {
		t.Fatal(err)
	}
	if w.Code != 500 || w.Header().Get("Content-Type") != "text/xml; charset=utf-8" || !strings.Contains(w.Body.String(), "faultcode") {
		t.Fatal("SOAP fault HTTP mapping")
	}
	w = httptest.NewRecorder()
	if err := binding.WriteSOAPResponse(t.Context(), w, envelope); err != nil || w.Code != 200 {
		t.Fatal("SAML response must retain HTTP 200")
	}
	if message, err := client.RoundTrip(t.Context(), server.URL+"/redirect", request); message != nil || !errors.Is(err, binding.ErrBinding) {
		t.Fatalf("SOAP redirect returned message=%p, err=%v; want nil, %v", message, err, binding.ErrBinding)
	}
	if redirects, targets := redirectHits.Load(), targetHits.Load(); redirects != 1 || targets != 0 {
		t.Fatalf("SOAP redirect and target received %d and %d requests, want 1 and 0", redirects, targets)
	}
	if message, err := (binding.SOAPClient{Client: server.Client()}).RoundTrip(t.Context(), server.URL, request); message != nil || !errors.Is(err, binding.ErrBinding) {
		t.Fatalf("SOAP over HTTP without permission returned message=%p, err=%v; want nil, %v", message, err, binding.ErrBinding)
	}
}

func FuzzSOAPEnvelope(f *testing.F) {
	f.Add([]byte(soapPrefix + `<s:Body><p:LogoutRequest/></s:Body></s:Envelope>`))
	f.Add([]byte(soapPrefix + `<s:Body><p:LogoutRequest/><p:LogoutResponse/></s:Body></s:Envelope>`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		m, err := binding.DecodeSOAP(t.Context(), raw, binding.SOAPOptions{MaxBytes: 4096, XMLLimits: document.Limits{MaxBytes: 4096, MaxDepth: 16, MaxNodes: 128, MaxAttributesPerElement: 16, MaxInScopeNamespaces: 32, MaxNodeSetNodes: 512}})
		if err != nil {
			return
		}
		payload, err := m.Payload(t.Context())
		if err != nil || payload.Root().Name().Space != "urn:oasis:names:tc:SAML:2.0:protocol" {
			t.Fatalf("invalid accepted SOAP payload: %v", err)
		}
	})
}

type shortResponseWriter struct{ *httptest.ResponseRecorder }

func (w shortResponseWriter) Write(p []byte) (int, error) {
	return w.ResponseRecorder.Write(p[:len(p)-1])
}

func TestWriteSOAPResponseRejectsShortWrite(t *testing.T) {
	t.Parallel()
	for _, fault := range []bool{false, true} {
		var envelope *document.Document
		var err error
		if fault {
			envelope, err = binding.FaultSOAP(t.Context(), binding.SOAPFault{
				Code: document.Name{Space: binding.SOAPNamespace, Local: "Server"}, Message: "unavailable",
			})
		} else {
			envelope, err = document.Parse(t.Context(), []byte(soapPrefix+`<s:Body><p:LogoutResponse/></s:Body></s:Envelope>`), document.DefaultLimits())
		}
		if err != nil {
			t.Fatal(err)
		}
		writer := shortResponseWriter{httptest.NewRecorder()}
		if err := binding.WriteSOAPResponse(t.Context(), writer, envelope); !errors.Is(err, io.ErrShortWrite) {
			t.Fatalf("short SOAP write returned %v; want io.ErrShortWrite", err)
		}
		wantStatus := http.StatusOK
		if fault {
			wantStatus = http.StatusInternalServerError
		}
		if writer.Code != wantStatus {
			t.Fatalf("status = %d; want %d", writer.Code, wantStatus)
		}
	}
}

func TestWriteAssertionRejectsTypedNilWriter(t *testing.T) {
	t.Parallel()
	d, err := document.Parse(t.Context(), []byte(`<s:Assertion xmlns:s="urn:oasis:names:tc:SAML:2.0:assertion" ID="_assertion"/>`), document.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	var writer *httptest.ResponseRecorder
	if err := binding.WriteAssertion(t.Context(), writer, d); !errors.Is(err, binding.ErrBinding) {
		t.Fatalf("typed-nil writer returned %v; want ErrBinding", err)
	}
}
