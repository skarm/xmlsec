package sp_test

import (
	"bytes"
	"crypto"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/skarm/xmlsec/c14n"
	"github.com/skarm/xmlsec/internal/testutil/testcert"
	"github.com/skarm/xmlsec/saml/artifact"
	"github.com/skarm/xmlsec/saml/binding"
	"github.com/skarm/xmlsec/saml/idp"
	"github.com/skarm/xmlsec/saml/metadata"
	"github.com/skarm/xmlsec/saml/protocol"
	"github.com/skarm/xmlsec/saml/replay"
	"github.com/skarm/xmlsec/saml/sp"
	"github.com/skarm/xmlsec/saml/state"
)

// Resolve both halves over real SOAP HTTP exchanges and keep the nested
// AuthnRequest/Response correlation separate from ArtifactResolve correlation.
func TestArtifactWebSSOBothRoles(t *testing.T) {
	const spID = "https://sp.test/entity"
	const idpID = "https://idp.test/entity"
	const acs = "https://sp.test/acs"
	const sso = "https://idp.test/sso"
	at := testcert.Now()
	c := testcert.New(t)
	spKey := protocol.SigningKey{Key: c.LeafKey, CertificateDER: c.Leaf.Raw, Canonicalization: c14n.Canonical10}
	idpKey := protocol.SigningKey{Key: c.TSAKey, CertificateDER: c.TSA.Raw, Canonicalization: c14n.Canonical10}
	spStore, _ := artifact.NewMemoryStore(10)
	idpStore, _ := artifact.NewMemoryStore(10)
	spIssuer := artifact.Issuer{EntityID: spID, ReturnEndpoint: sso, Signing: spKey, Store: spStore}
	idpIssuer := artifact.Issuer{EntityID: idpID, ReturnEndpoint: acs, Signing: idpKey, Store: idpStore}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		issuer, peer, keys := idpIssuer, spID, []crypto.PublicKey{c.LeafKey.Public()}
		if r.URL.Path == "/sp-ars" {
			issuer, peer, keys = spIssuer, idpID, []crypto.PublicKey{c.TSAKey.Public()}
		}
		m, err := binding.ReadSOAPRequest(r.Context(), r, binding.SOAPOptions{})
		if err != nil {
			t.Error(err)
			return
		}
		d, err := m.Payload(r.Context())
		if err != nil {
			t.Error(err)
			return
		}
		request, err := protocol.VerifyArtifactResolve(r.Context(), d, keys, protocol.ExchangeOptions{Issuer: peer, Destination: issuer.Endpoint, At: at, Binding: metadata.SOAP})
		if err != nil {
			t.Error(err)
			return
		}
		response, err := issuer.Respond(r.Context(), request, at)
		if err != nil {
			t.Error(err)
			return
		}
		envelope, err := protocol.SignSOAP(r.Context(), response, issuer.Signing)
		if err != nil {
			t.Error(err)
			return
		}
		if err := binding.WriteSOAPResponse(r.Context(), w, envelope); err != nil {
			t.Error(err)
		}
	}))
	defer server.Close()
	spIssuer.Endpoint = server.URL + "/sp-ars"
	idpIssuer.Endpoint = server.URL + "/idp-ars"
	specs := []metadata.EntityDescriptor{
		{ID: "_sp", EntityID: spID, ValidUntil: at.Add(time.Hour), SP: &metadata.RoleDescriptor{Keys: []metadata.KeyDescriptor{{Use: "signing", CertificateDER: spKey.CertificateDER}}, Endpoints: map[string][]metadata.Endpoint{metadata.AssertionConsumerService: {{Binding: metadata.HTTPArtifact, Location: acs, Indexed: true}}, metadata.ArtifactResolutionService: {{Binding: metadata.SOAP, Location: spIssuer.Endpoint, Indexed: true}}}}},
		{ID: "_idp", EntityID: idpID, ValidUntil: at.Add(time.Hour), IDP: &metadata.RoleDescriptor{Keys: []metadata.KeyDescriptor{{Use: "signing", CertificateDER: idpKey.CertificateDER}}, Endpoints: map[string][]metadata.Endpoint{metadata.SingleSignOnService: {{Binding: metadata.HTTPArtifact, Location: sso}}, metadata.ArtifactResolutionService: {{Binding: metadata.SOAP, Location: idpIssuer.Endpoint, Indexed: true}}}}},
	}
	var raw bytes.Buffer
	raw.WriteString(`<md:EntitiesDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata">`)
	for _, spec := range specs {
		d, err := metadata.Build(t.Context(), spec, at, metadata.Options{AllowHTTP: true})
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
	partners, err := metadata.ParseTrusted(t.Context(), raw.Bytes(), at, metadata.Options{AllowHTTP: true})
	if err != nil {
		t.Fatal(err)
	}
	requests, _ := state.NewMemoryStore(state.Config{})
	spReplay, _ := replay.NewMemoryStore(replay.Config{})
	idpReplay, _ := replay.NewMemoryStore(replay.Config{})
	service, err := sp.NewServiceProvider(sp.Config{EntityID: spID, Metadata: partners, Signing: spKey, Requests: requests, Replay: spReplay})
	if err != nil {
		t.Fatal(err)
	}
	identity, err := idp.NewIdentityProvider(idp.Config{EntityID: idpID, Metadata: partners, Signing: idpKey, Replay: idpReplay})
	if err != nil {
		t.Fatal(err)
	}
	browser := bytes.Repeat([]byte{71}, 32)
	out, err := service.Begin(t.Context(), sp.BeginOptions{IDP: idpID, Binding: metadata.HTTPArtifact, ResponseBinding: metadata.HTTPArtifact, BrowserBinding: browser, At: at})
	if err != nil {
		t.Fatal(err)
	}
	a, err := out.IssueArtifact(t.Context(), spIssuer, at, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	resolve := artifact.Resolver{EntityID: idpID, PeerEntityID: spID, ReturnEndpoint: sso, Signing: idpKey, Keys: []crypto.PublicKey{c.LeafKey.Public()}, Endpoints: []metadata.Endpoint{{Binding: metadata.SOAP, Location: spIssuer.Endpoint, Indexed: true}}, SOAP: binding.SOAPClient{AllowHTTP: true}}
	requestDoc, err := resolve.Resolve(t.Context(), a, at)
	if err != nil {
		t.Fatal(err)
	}
	relay := out.RelayState()
	request, err := identity.AcceptArtifact(t.Context(), requestDoc, &relay, spID, sso, at)
	if err != nil {
		t.Fatal(err)
	}
	issued, err := identity.Issue(t.Context(), request, idp.Authentication{NameID: "alice", AuthnInstant: at, AuthnContext: "urn:test:password", SessionIndex: "device"}, at)
	if err != nil {
		t.Fatal(err)
	}
	responseArtifact, err := issued.IssueArtifact(t.Context(), idpIssuer, at, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	resolve = artifact.Resolver{EntityID: spID, PeerEntityID: idpID, ReturnEndpoint: acs, Signing: spKey, Keys: []crypto.PublicKey{c.TSAKey.Public()}, Endpoints: []metadata.Endpoint{{Binding: metadata.SOAP, Location: idpIssuer.Endpoint, Indexed: true}}, SOAP: binding.SOAPClient{AllowHTTP: true}}
	responseDoc, err := resolve.Resolve(t.Context(), responseArtifact, at)
	if err != nil {
		t.Fatal(err)
	}
	assertion, err := service.ConsumeArtifact(t.Context(), responseDoc, relay, sp.ConsumeOptions{At: at, BrowserBinding: browser})
	if err != nil || assertion.NameID() != "alice" {
		t.Fatalf("artifact SSO: %v", err)
	}
	if _, err := service.ConsumeArtifact(t.Context(), responseDoc, relay, sp.ConsumeOptions{At: at, BrowserBinding: browser}); err == nil {
		t.Fatal("nested response replay accepted")
	}
}
