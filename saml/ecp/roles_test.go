package ecp_test

import (
	"bytes"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	"github.com/skarm/xmlsec/c14n"
	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/internal/testutil/testcert"
	"github.com/skarm/xmlsec/saml/binding"
	"github.com/skarm/xmlsec/saml/ecp"
	"github.com/skarm/xmlsec/saml/idp"
	"github.com/skarm/xmlsec/saml/metadata"
	"github.com/skarm/xmlsec/saml/protocol"
	"github.com/skarm/xmlsec/saml/replay"
	"github.com/skarm/xmlsec/saml/sp"
	"github.com/skarm/xmlsec/saml/state"
)

// Both high-level roles participate: current metadata, PAOS ACS selection,
// application authentication, complete assertion verification and atomic replay.
func TestECPServiceProviderIdentityProvider(t *testing.T) {
	for _, bound := range []bool{false, true} {
		name := "bearer"
		if bound {
			name = "channel-bound"
		}

		t.Run(name, func(t *testing.T) { runECPRoles(t, bound) })
	}
}

func runECPRoles(t *testing.T, bound bool) {
	t.Helper()
	const spID = "https://sp.test/entity"
	const idpID = "https://idp.test/entity"
	const acs = "https://sp.test/acs"
	const sso = "https://idp.test/soap"
	at := testcert.Now()
	cert := testcert.New(t)
	spKey := protocol.SigningKey{Key: cert.LeafKey, CertificateDER: cert.Leaf.Raw, Canonicalization: c14n.Canonical10}
	idpKey := protocol.SigningKey{Key: cert.TSAKey, CertificateDER: cert.TSA.Raw, Canonicalization: c14n.Canonical10}
	specs := []metadata.EntityDescriptor{
		{ID: "_sp", EntityID: spID, ValidUntil: at.Add(time.Hour), SP: &metadata.RoleDescriptor{Keys: []metadata.KeyDescriptor{{Use: "signing", CertificateDER: spKey.CertificateDER}}, Endpoints: map[string][]metadata.Endpoint{metadata.AssertionConsumerService: {{Binding: metadata.PAOS, Location: acs, Indexed: true, Index: 3, Default: true}}}, NameIDFormats: []string{protocol.NameIDPersistent}}},
		{ID: "_idp", EntityID: idpID, ValidUntil: at.Add(time.Hour), IDP: &metadata.RoleDescriptor{Keys: []metadata.KeyDescriptor{{Use: "signing", CertificateDER: idpKey.CertificateDER}}, Endpoints: map[string][]metadata.Endpoint{metadata.SingleSignOnService: {{Binding: metadata.SOAP, Location: sso}}}, NameIDFormats: []string{protocol.NameIDPersistent}}},
	}
	specs[1].IDP.Endpoints[metadata.SingleLogoutService] = []metadata.Endpoint{{Binding: metadata.SOAP, Location: "https://idp.test/slo"}}
	var raw bytes.Buffer
	raw.WriteString(`<md:EntitiesDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata">`)
	for _, spec := range specs {
		d, err := metadata.Build(t.Context(), spec, at, metadata.Options{})
		if err != nil {
			t.Fatal(err)
		}
		b, err := d.XML(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		raw.Write(b)
	}
	raw.WriteString(`</md:EntitiesDescriptor>`)
	partners, err := metadata.ParseTrusted(t.Context(), raw.Bytes(), at, metadata.Options{})
	if err != nil {
		t.Fatal(err)
	}
	requests, err := state.NewMemoryStore(state.Config{})
	if err != nil {
		t.Fatal(err)
	}
	spReplay, err := replay.NewMemoryStore(replay.Config{})
	if err != nil {
		t.Fatal(err)
	}
	idpReplay, err := replay.NewMemoryStore(replay.Config{})
	if err != nil {
		t.Fatal(err)
	}
	service, err := sp.NewServiceProvider(sp.Config{EntityID: spID, Metadata: partners, Signing: spKey, Requests: requests, Replay: spReplay})
	if err != nil {
		t.Fatal(err)
	}
	identity, err := idp.NewIdentityProvider(idp.Config{EntityID: idpID, Metadata: partners, Signing: idpKey, Replay: idpReplay})
	if err != nil {
		t.Fatal(err)
	}
	browser := bytes.Repeat([]byte{42}, 32)
	var channels []protocol.ChannelBinding
	if bound {
		channel, err := ecp.ServerCertificateBinding(cert.Leaf)
		if err != nil {
			t.Fatal(err)
		}
		channels = []protocol.ChannelBinding{channel}
	}

	out, err := service.Begin(t.Context(), sp.BeginOptions{IDP: idpID, Binding: metadata.PAOS, BrowserBinding: browser, At: at, NameIDFormat: protocol.NameIDPersistent, ChannelBindings: channels})
	if err != nil {
		t.Fatal(err)
	}
	challenge, err := out.PAOS()
	if err != nil {
		t.Fatal(err)
	}
	b, _ := challenge.XML(t.Context())
	x := parseRolesChallenge(t, b, channels)
	if bound {
		if _, err := ecp.ParseChallenge(t.Context(), b, "https://sp.test/resource", binding.SOAPOptions{}); err == nil {
			t.Fatal("channel request accepted without trusted transport data")
		}
	}

	forward, err := x.ToIDP(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	b, _ = forward.XML(t.Context())
	if bound {
		// Changing the client's channel header leaves the signed request valid.
		// The IdP must nevertheless reject the authentication, not downgrade it.
		bad := bytes.Replace(b, []byte(base64.StdEncoding.EncodeToString(channels[0].Data)), []byte(base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{91}, len(channels[0].Data)))), 1)
		rejected, err := identity.AcceptSOAP(t.Context(), bad, spID, sso, at)
		if err == nil || rejected == nil {
			t.Fatalf("authenticated mismatched channel: request=%v error=%v", rejected, err)
		}
		if _, err := identity.Issue(t.Context(), rejected, idp.Authentication{NameID: "alice", AuthnInstant: at, AuthnContext: "urn:test:password", SessionIndex: "device-1"}, at); err == nil {
			t.Fatal("mismatched channel issued a successful assertion")
		}
	}
	r, err := identity.AcceptSOAP(t.Context(), b, spID, sso, at)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := identity.Issue(t.Context(), r, idp.Authentication{NameID: "alice", NameIDFormat: protocol.NameIDPersistent, AuthnInstant: at, AuthnContext: "urn:test:password"}, at); err == nil {
		t.Fatal("SLO-capable IdP issued an assertion without SessionIndex")
	}
	badResponse, err := protocol.SignResponse(t.Context(), protocol.Response{ID: "_missing_session", Issuer: idpID, Audience: spID, Destination: acs, InResponseTo: out.RequestID(), IssueInstant: at, SOAPContext: true, Assertion: protocol.AssertionData{ID: "_missing_session_assertion", NameID: "alice", NameIDFormat: protocol.NameIDPersistent, NotBefore: at, NotOnOrAfter: at.Add(time.Minute), AuthnInstant: at, AuthnContext: "urn:test:password"}}, idpKey)
	if err != nil {
		t.Fatal(err)
	}
	badEnvelope, err := ecp.ResponseWithBindings(t.Context(), badResponse, acs, channels)
	if err != nil {
		t.Fatal(err)
	}
	badRaw, _ := badEnvelope.XML(t.Context())
	badReturn, err := x.Finish(t.Context(), badRaw, binding.SOAPOptions{})
	if err != nil {
		t.Fatal(err)
	}
	badRaw, _ = badReturn.XML(t.Context())
	if _, err := service.ConsumePAOS(t.Context(), badRaw, sp.ConsumeOptions{At: at, BrowserBinding: browser}); err == nil {
		t.Fatal("SP accepted an SLO-capable peer's assertion without SessionIndex")
	}
	issued, err := identity.Issue(t.Context(), r, idp.Authentication{NameID: "current-primary-id", NameIDFormat: protocol.NameIDPersistent, NameQualifier: idpID, SPNameQualifier: spID, SPProvidedID: "current-sp-alias", AuthnInstant: at, AuthnContext: "urn:test:password", SessionIndex: "device-1"}, at)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := identity.Issue(t.Context(), r, idp.Authentication{NameID: "alice", AuthnInstant: at, AuthnContext: "urn:test:password"}, at); err == nil {
		t.Fatal("IdP request reused")
	}
	envelope, err := issued.ECP(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	b, _ = envelope.XML(t.Context())
	if !bound {
		// A 2005 ECP does not know RequestAuthenticated. The IdP must not
		// make understanding this new CS01 signal mandatory for that client.
		legacyHeaders := []document.Name{{Space: ecp.Namespace, Local: "Response"}, {Space: ecp.Namespace, Local: "RelayState"}}
		if _, err := binding.DecodeSOAP(t.Context(), b, binding.SOAPOptions{Understood: legacyHeaders}); err != nil {
			t.Fatalf("2013 extension broke a legacy bearer ECP: %v", err)
		}
	}
	if bound {
		without, err := ecp.Response(t.Context(), issued.Document(), acs)
		if err != nil {
			t.Fatal(err)
		}
		withoutRaw, _ := without.XML(t.Context())
		fault, err := x.Finish(t.Context(), withoutRaw, binding.SOAPOptions{})
		var soapFault *binding.SOAPFault
		if !errors.As(err, &soapFault) || fault == nil {
			t.Fatalf("missing IdP channel signal: %v", err)
		}
		faultRaw, _ := fault.XML(t.Context())
		if bytes.Contains(faultRaw, []byte("current-primary-id")) {
			t.Fatal("fault disclosed the SAML assertion")
		}
	}
	returned, err := x.Finish(t.Context(), b, binding.SOAPOptions{})
	if err != nil {
		t.Fatal(err)
	}
	b, _ = returned.XML(t.Context())
	wrong := sp.ConsumeOptions{At: at, BrowserBinding: bytes.Repeat([]byte{43}, 32)}
	if _, err := service.ConsumePAOS(t.Context(), b, wrong); err == nil {
		t.Fatal("wrong browser accepted")
	}
	assertion, err := service.ConsumePAOS(t.Context(), b, sp.ConsumeOptions{At: at, BrowserBinding: browser})
	if err != nil {
		t.Fatal(err)
	}
	if assertion.NameID() != "current-primary-id" || assertion.Identifier().SPProvidedID != "current-sp-alias" || assertion.SessionIndex() != "device-1" {
		t.Fatal("managed NameID lost between IdP and SP")
	}
	if _, err := service.ConsumePAOS(t.Context(), b, sp.ConsumeOptions{At: at, BrowserBinding: browser}); err == nil {
		t.Fatal("SP response reused")
	}
	// An IdP may return an authentication failure instead of an assertion. Its
	// nested status remains authenticated and correlated all the way to the SP.
	out, err = service.Begin(t.Context(), sp.BeginOptions{IDP: idpID, Binding: metadata.PAOS, BrowserBinding: browser, At: at, ChannelBindings: channels})
	if err != nil {
		t.Fatal(err)
	}
	challenge, err = out.PAOS()
	if err != nil {
		t.Fatal(err)
	}
	b, _ = challenge.XML(t.Context())
	x = parseRolesChallenge(t, b, channels)
	forward, err = x.ToIDP(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	b, _ = forward.XML(t.Context())
	r, err = identity.AcceptSOAP(t.Context(), b, spID, sso, at)
	if err != nil {
		t.Fatal(err)
	}
	denied, err := identity.Reject(t.Context(), r, protocol.Status{Code: protocol.Responder, Subcodes: []string{"urn:oasis:names:tc:SAML:2.0:status:AuthnFailed"}, Message: "authentication failed"}, at)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err = denied.ECP(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	b, _ = envelope.XML(t.Context())
	returned, err = x.Finish(t.Context(), b, binding.SOAPOptions{})
	if err != nil {
		t.Fatal(err)
	}
	b, _ = returned.XML(t.Context())
	_, err = service.ConsumePAOS(t.Context(), b, sp.ConsumeOptions{At: at, BrowserBinding: browser})
	var failure *protocol.StatusError
	if !errors.As(err, &failure) || failure.Code != protocol.Responder || len(failure.Subcodes) != 1 || failure.Subcodes[0] != "urn:oasis:names:tc:SAML:2.0:status:AuthnFailed" {
		t.Fatalf("authenticated error response: %v", err)
	}
}

func parseRolesChallenge(t *testing.T, raw []byte, channels []protocol.ChannelBinding) *ecp.Exchange {
	t.Helper()
	var (
		x   *ecp.Exchange
		err error
	)
	if len(channels) == 0 {
		x, err = ecp.ParseChallenge(t.Context(), raw, "https://sp.test/resource", binding.SOAPOptions{})
	} else {
		x, err = ecp.ParseChallengeWithBindings(t.Context(), raw, "https://sp.test/resource", channels, binding.SOAPOptions{})
	}
	if err != nil {
		t.Fatal(err)
	}
	return x
}
