package ecp_test

import (
	"bytes"
	"crypto"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/skarm/xmlsec/c14n"
	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/internal/testutil/testcert"
	"github.com/skarm/xmlsec/saml/binding"
	"github.com/skarm/xmlsec/saml/ecp"
	"github.com/skarm/xmlsec/saml/metadata"
	"github.com/skarm/xmlsec/saml/protocol"
)

func TestPAOSNegotiation(t *testing.T) {
	h := http.Header{}
	ecp.Advertise(h)
	if !ecp.Negotiated(h) || strings.Contains(h.Get("Paos"), "'") {
		t.Fatal("Errata E21/E54 negotiation")
	}
	for _, accept := range []string{"application/vnd.paos+xml;q=0", "application/vnd.paos+xml;q=0, */*;q=1", "text/html", "application/vnd.paos+xml;q=bogus"} {
		bad := h.Clone()
		bad.Set("Accept", accept)
		if ecp.Negotiated(bad) {
			t.Fatalf("accepted %q", accept)
		}
	}
	bad := h.Clone()
	bad.Set("Paos", `ver="urn:wrong"; "`+ecp.Namespace+`"`)
	if ecp.Negotiated(bad) {
		t.Fatal("wrong version")
	}
}

func TestECPRoutingAndSignedBodies(t *testing.T) {
	cert := testcert.New(t)
	at := testcert.Now()
	const spID = "https://sp.test/entity"
	const idpID = "https://idp.test/entity"
	const acs = "https://sp.test/acs"
	const sso = "https://idp.test/soap"
	for _, algorithm := range []string{c14n.Exclusive, c14n.Canonical10} {
		t.Run(algorithm, func(t *testing.T) {
			spKey := protocol.SigningKey{Key: cert.LeafKey, CertificateDER: cert.Leaf.Raw, Canonicalization: algorithm}
			idpKey := protocol.SigningKey{Key: cert.TSAKey, CertificateDER: cert.TSA.Raw, Canonicalization: algorithm}
			relay := "state from SP"
			challenge, err := ecp.Challenge(t.Context(), protocol.AuthnRequest{ID: "_ecp", Issuer: spID, Destination: sso, ACS: acs, IssueInstant: at}, spKey, &relay, "paos-correlation")
			if err != nil {
				t.Fatal(err)
			}
			raw, _ := challenge.XML(t.Context())
			exchange, err := ecp.ParseChallenge(t.Context(), raw, "https://sp.test/resource", binding.SOAPOptions{})
			if err != nil || exchange.Endpoint() != acs || exchange.IsPassive() {
				t.Fatalf("challenge: %v", err)
			}
			forward, err := exchange.ToIDP(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			forwardRaw, _ := forward.XML(t.Context())
			if bytes.Contains(forwardRaw, []byte("<ecp:Request")) || bytes.Contains(forwardRaw, []byte("RelayState")) || bytes.Contains(forwardRaw, []byte("<paos:Request")) {
				t.Fatal("ECP-targeted headers forwarded to IdP")
			}
			m, err := binding.DecodeSOAP(t.Context(), forwardRaw, binding.SOAPOptions{})
			if err != nil {
				t.Fatal(err)
			}
			payload, err := m.Payload(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			request, err := protocol.VerifyAuthnRequest(t.Context(), payload, []crypto.PublicKey{cert.LeafKey.Public()}, protocol.RequestOptions{Issuer: spID, Destination: sso, At: at, ResponseBinding: metadata.PAOS, ACS: []metadata.Endpoint{{Binding: metadata.PAOS, Location: acs}}})
			if err != nil || request.ResponseBinding() != metadata.PAOS {
				t.Fatalf("IdP verify: %v", err)
			}
			response, err := protocol.SignResponse(t.Context(), protocol.Response{ID: "_response", Issuer: idpID, Audience: spID, Destination: acs, InResponseTo: "_ecp", IssueInstant: at, SOAPContext: true, Assertion: protocol.AssertionData{ID: "_assertion", NameID: "alice", NameIDFormat: protocol.NameIDPersistent, NotBefore: at, NotOnOrAfter: at.Add(time.Minute), AuthnInstant: at, AuthnContext: "urn:test:password"}}, idpKey)
			if err != nil {
				t.Fatal(err)
			}
			idpEnvelope, err := ecp.Response(t.Context(), response, request.ACS())
			if err != nil {
				t.Fatal(err)
			}
			idpRaw, _ := idpEnvelope.XML(t.Context())
			returned, err := exchange.Finish(t.Context(), idpRaw, binding.SOAPOptions{})
			if err != nil {
				t.Fatal(err)
			}
			returnedRaw, _ := returned.XML(t.Context())
			decoded, state, err := ecp.DecodeResponse(t.Context(), returnedRaw, "paos-correlation", binding.SOAPOptions{})
			if err != nil || state == nil || *state != relay {
				t.Fatalf("return routing: %v", err)
			}
			assertion, err := protocol.VerifyResponse(t.Context(), decoded, []crypto.PublicKey{cert.TSAKey.Public()}, protocol.ResponseOptions{Issuer: idpID, Audience: spID, Destination: acs, ExpectedRequestID: "_ecp", At: at})
			if err != nil || assertion.NameID() != "alice" {
				t.Fatalf("SP assertion verification: %v", err)
			}
			// Replace only the unsigned header, not signed Destination/Recipient.
			mismatch := bytes.Replace(idpRaw, []byte(`AssertionConsumerServiceURL="`+acs+`"`), []byte(`AssertionConsumerServiceURL="https://attacker.test/collect"`), 1)
			fault, err := exchange.Finish(t.Context(), mismatch, binding.SOAPOptions{})
			var routingFault *binding.SOAPFault
			if !errors.As(err, &routingFault) || fault == nil {
				t.Fatalf("mismatch must produce SOAP fault: %v", err)
			}
			faultRaw, _ := fault.XML(t.Context())
			if bytes.Contains(faultRaw, []byte("alice")) || bytes.Contains(faultRaw, []byte("<samlp:Response")) {
				t.Fatal("SAML response disclosed on routing fault")
			}
			if _, _, err := ecp.DecodeResponse(t.Context(), returnedRaw, "wrong-message-id", binding.SOAPOptions{}); err == nil {
				t.Fatal("PAOS correlation ignored")
			}
			remoteFault, err := binding.FaultSOAP(t.Context(), binding.SOAPFault{Code: document.Name{Space: binding.SOAPNamespace, Local: "Server"}, Message: "authentication unavailable"})
			if err != nil {
				t.Fatal(err)
			}
			faultInput, _ := remoteFault.XML(t.Context())
			forwardedFault, err := exchange.Finish(t.Context(), faultInput, binding.SOAPOptions{})
			if !errors.As(err, &routingFault) || forwardedFault == nil {
				t.Fatalf("IdP SOAP fault was not made deliverable to the SP: %v", err)
			}
			applicationFault := `<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Header><private xmlns="urn:private">do not forward</private></s:Header><s:Body><s:Fault><faultcode xmlns:app="urn:application">app:AuthenticationFailed</faultcode><faultstring>denied</faultstring><detail><reason xmlns="urn:application">account disabled</reason></detail></s:Fault></s:Body></s:Envelope>`
			forwardedFault, err = exchange.Finish(t.Context(), []byte(applicationFault), binding.SOAPOptions{})
			if !errors.As(err, &routingFault) || forwardedFault == nil || routingFault.Code.Space != "urn:application" {
				t.Fatalf("application fault code lost: %v", err)
			}
			faultBytes, _ := forwardedFault.XML(t.Context())
			if !bytes.Contains(faultBytes, []byte("account disabled")) || bytes.Contains(faultBytes, []byte("do not forward")) {
				t.Fatal("SOAP fault detail or hop-header processing changed")
			}
			// Relative consumer URL is allowed; resolve against the originating SP.
			relative := bytes.Replace(raw, []byte(`responseConsumerURL="`+acs+`"`), []byte(`responseConsumerURL="/acs"`), 1)
			if x, err := ecp.ParseChallenge(t.Context(), relative, "https://sp.test/resource", binding.SOAPOptions{}); err != nil || x.Endpoint() != acs {
				t.Fatalf("relative URL: %v", err)
			}
		})
	}
}

// A wire fixture independent of the generator checks the ECP-specific passive
// default (true), required actors and unknown mandatory header behavior.
func TestECPIndependentHeaders(t *testing.T) {
	raw := `<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" xmlns:p="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:a="urn:oasis:names:tc:SAML:2.0:assertion"><s:Header><paos:Request xmlns:paos="urn:liberty:paos:2003-08" s:mustUnderstand="1" s:actor="http://schemas.xmlsoap.org/soap/actor/next" responseConsumerURL="/acs" service="urn:oasis:names:tc:SAML:2.0:profiles:SSO:ecp"/><e:Request xmlns:e="urn:oasis:names:tc:SAML:2.0:profiles:SSO:ecp" s:mustUnderstand="1" s:actor="http://schemas.xmlsoap.org/soap/actor/next"><a:Issuer>https://sp.test/entity</a:Issuer></e:Request></s:Header><s:Body><p:AuthnRequest ID="_ecp" AssertionConsumerServiceURL="https://sp.test/acs"><a:Issuer>https://sp.test/entity</a:Issuer></p:AuthnRequest></s:Body></s:Envelope>`
	x, err := ecp.ParseChallenge(t.Context(), []byte(raw), "https://sp.test/resource", binding.SOAPOptions{})
	if err != nil || !x.IsPassive() {
		t.Fatalf("passive default: %v", err)
	}
	for _, bad := range []string{strings.Replace(raw, `s:mustUnderstand="1"`, `s:mustUnderstand="0"`, 1), strings.Replace(raw, `s:actor="http://schemas.xmlsoap.org/soap/actor/next"`, `s:actor="urn:other"`, 1), strings.Replace(raw, "</s:Header>", `<x:unknown xmlns:x="urn:unknown" s:mustUnderstand="1"/></s:Header>`, 1)} {
		if _, err := ecp.ParseChallenge(t.Context(), []byte(bad), "https://sp.test/resource", binding.SOAPOptions{}); err == nil {
			t.Fatal("invalid header accepted")
		}
	}
	if _, err := document.Parse(t.Context(), []byte(raw), document.DefaultLimits()); err != nil {
		t.Fatal(err)
	}
}

type shortChallengeWriter struct{ *httptest.ResponseRecorder }

func (w shortChallengeWriter) Write(p []byte) (int, error) {
	return w.ResponseRecorder.Write(p[:len(p)-1])
}

func challengeHTTPFixture(t *testing.T) (*http.Request, *document.Document) {
	t.Helper()
	r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "https://sp.test/resource", nil)
	ecp.Advertise(r.Header)
	d, err := document.Parse(t.Context(), []byte(`<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body><p:AuthnRequest xmlns:p="urn:oasis:names:tc:SAML:2.0:protocol"/></s:Body></s:Envelope>`), document.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	return r, d
}

func TestWriteChallengeRejectsShortWrite(t *testing.T) {
	t.Parallel()
	r, d := challengeHTTPFixture(t)
	writer := shortChallengeWriter{httptest.NewRecorder()}
	if err := ecp.WriteChallenge(t.Context(), writer, r, d); !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("short challenge write returned %v; want io.ErrShortWrite", err)
	}
	if writer.Code != http.StatusOK || writer.Header().Get("Content-Type") != ecp.MediaType+"; charset=utf-8" {
		t.Fatal("challenge HTTP status or media type changed")
	}
}

func TestWriteChallengeRejectsTypedNilWriter(t *testing.T) {
	t.Parallel()
	r, d := challengeHTTPFixture(t)
	var writer *httptest.ResponseRecorder
	if err := ecp.WriteChallenge(t.Context(), writer, r, d); !errors.Is(err, ecp.ErrECP) {
		t.Fatalf("typed-nil challenge writer returned %v; want ErrECP", err)
	}
}
