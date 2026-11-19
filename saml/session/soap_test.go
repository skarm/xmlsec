package session_test

import (
	"bytes"
	"crypto"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/skarm/xmlsec/internal/testutil/testcert"
	"github.com/skarm/xmlsec/saml/binding"
	"github.com/skarm/xmlsec/saml/metadata"
	"github.com/skarm/xmlsec/saml/protocol"
	"github.com/skarm/xmlsec/saml/session"
)

func TestSOAPBackChannelRejectsTypedNilMetadata(t *testing.T) {
	t.Parallel()

	var snapshot *metadata.Snapshot
	back := session.BackChannel{EntityID: idpID, Role: metadata.IdentityProvider, Metadata: snapshot}
	status, err := back.Logout(t.Context(), session.Participant{Peer: spID}, testcert.Now())
	if status.Code != "" || !errors.Is(err, session.ErrState) {
		t.Errorf("BackChannel.Logout without metadata = %+v, %v, want ErrState", status, err)
	}
}

func TestSOAPBackChannelManagementAndLogout(t *testing.T) {
	at := testcert.Now()
	c := testcert.New(t)
	spKey := protocol.SigningKey{Key: c.LeafKey, CertificateDER: c.Leaf.Raw}
	idpKey := protocol.SigningKey{Key: c.TSAKey, CertificateDER: c.TSA.Raw}
	spStore, _ := session.NewMemoryStore(session.Config{EntityID: spID, Role: metadata.ServiceProvider, Capacity: 100})
	idpStore, _ := session.NewMemoryStore(session.Config{EntityID: idpID, Role: metadata.IdentityProvider, Capacity: 100})
	register(t, spStore, idpID, "local-account", "group", "index", "sp-session")
	register(t, idpStore, spID, "local-account", "group", "index", "idp-session")
	spService := session.Service{EntityID: spID, Role: metadata.ServiceProvider, Store: spStore, Signing: spKey, ResponseEndpoint: "https://sp.test/manage-result"}
	idpService := session.Service{EntityID: idpID, Role: metadata.IdentityProvider, Store: idpStore, Signing: idpKey}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
		if r.URL.Path == "/idp-manage" {
			request, err := protocol.VerifyManageNameIDRequest(r.Context(), d, []crypto.PublicKey{c.LeafKey.Public()}, protocol.ExchangeOptions{Issuer: spID, Destination: idpService.Endpoint, At: at, Binding: metadata.SOAP})
			if err != nil {
				t.Error(err)
				return
			}
			response, err := idpService.Manage(r.Context(), request, "https://sp.test/manage-result", at)
			if err != nil {
				t.Error(err)
				return
			}
			envelope, err := protocol.SignSOAP(r.Context(), response, idpKey)
			if err != nil {
				t.Error(err)
				return
			}
			if err := binding.WriteSOAPResponse(r.Context(), w, envelope); err != nil {
				t.Error(err)
			}
			return
		}
		service := spService
		service.Endpoint = serverURL(r) + "/sp-slo"
		request, err := protocol.VerifyLogoutRequest(r.Context(), d, []crypto.PublicKey{c.TSAKey.Public()}, protocol.ExchangeOptions{Issuer: idpID, Destination: service.Endpoint, At: at, Binding: metadata.SOAP})
		if err != nil {
			t.Error(err)
			return
		}
		response, _, err := service.Logout(r.Context(), request, "https://idp.test/slo-result", at)
		if err != nil {
			t.Error(err)
			return
		}
		envelope, err := protocol.SignSOAP(r.Context(), response, spKey)
		if err != nil {
			t.Error(err)
			return
		}
		if err := binding.WriteSOAPResponse(r.Context(), w, envelope); err != nil {
			t.Error(err)
		}
	}))
	defer server.Close()
	spService.Endpoint = server.URL + "/sp-manage"
	idpService.Endpoint = server.URL + "/idp-manage"
	specs := []metadata.EntityDescriptor{
		{ID: "_sp", EntityID: spID, ValidUntil: at.Add(time.Hour), SP: &metadata.RoleDescriptor{Keys: []metadata.KeyDescriptor{{Use: "signing", CertificateDER: spKey.CertificateDER}}, Endpoints: map[string][]metadata.Endpoint{metadata.AssertionConsumerService: {{Binding: metadata.HTTPPost, Location: "https://sp.test/acs", Indexed: true}}, metadata.ManageNameIDService: {{Binding: metadata.SOAP, Location: spService.Endpoint, ResponseLocation: spService.ResponseEndpoint}}, metadata.SingleLogoutService: {{Binding: metadata.SOAP, Location: server.URL + "/sp-slo", ResponseLocation: "https://sp.test/slo-result"}}}}},
		{ID: "_idp", EntityID: idpID, ValidUntil: at.Add(time.Hour), IDP: &metadata.RoleDescriptor{Keys: []metadata.KeyDescriptor{{Use: "signing", CertificateDER: idpKey.CertificateDER}}, Endpoints: map[string][]metadata.Endpoint{metadata.SingleSignOnService: {{Binding: metadata.HTTPPost, Location: "https://idp.test/sso"}}, metadata.ManageNameIDService: {{Binding: metadata.SOAP, Location: idpService.Endpoint}}, metadata.SingleLogoutService: {{Binding: metadata.SOAP, Location: server.URL + "/idp-slo", ResponseLocation: "https://idp.test/slo-result"}}}}},
	}
	partners := soapMetadata(t, specs, at)
	channel := session.BackChannel{EntityID: spID, Role: metadata.ServiceProvider, Metadata: partners, Signing: spKey, SOAP: binding.SOAPClient{AllowHTTP: true}}
	old, _ := spStore.Lookup(t.Context(), "local-account", idpID, at)
	request, err := spService.BeginManage(t.Context(), idpID, protocol.ManageNameIDRequest{ID: "_soap_alias", Issuer: spID, Destination: idpService.Endpoint, IssueInstant: at, NameID: old.NameID, NewID: "soap-alias"}, at)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("preflight", func(t *testing.T) {
		withoutKeys := *specs[1].IDP
		withoutKeys.Keys = nil
		peer := specs[1]
		peer.IDP = &withoutKeys
		for _, tc := range []struct {
			name     string
			metadata *metadata.Snapshot
			limits   protocol.Limits
			want     error
		}{
			{"invalid limits", partners, protocol.Limits{MaxMessageAge: -time.Second}, protocol.ErrProfile},
			{"no peer signing keys", soapMetadata(t, []metadata.EntityDescriptor{specs[0], peer}, at), protocol.Limits{}, protocol.ErrSignature},
		} {
			t.Run(tc.name, func(t *testing.T) {
				invalid := channel
				invalid.Metadata = tc.metadata
				invalid.Options.Limits = tc.limits
				invalid.Signing.Key = failingSigner{spKey.Key}
				if got, err := invalid.Exchange(t.Context(), idpID, request, at); got != nil || !errors.Is(err, tc.want) {
					t.Errorf("Exchange = %v, %v; want nil, %v", got, err, tc.want)
				}
			})
		}
	})

	response, err := channel.Exchange(t.Context(), idpID, request, at)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := spService.Complete(t.Context(), response, at); err != nil {
		t.Fatal(err)
	}
	current, _ := idpStore.Lookup(t.Context(), "local-account", spID, at)
	if current.NameID.Value != "alice" || current.NameID.SPProvidedID != "soap-alias" {
		t.Fatal("SOAP alias management")
	}
	channel = session.BackChannel{EntityID: idpID, Role: metadata.IdentityProvider, Metadata: partners, Signing: idpKey, SOAP: binding.SOAPClient{AllowHTTP: true}}
	status, err := channel.Logout(t.Context(), session.Participant{Peer: spID, NameID: current.NameID, SessionIndexes: []string{"index"}}, at)
	if err != nil || status.Code != protocol.Success || spStore.Active(t.Context(), "sp-session", at) {
		t.Fatalf("SOAP SLO: %v", err)
	}
}

func soapMetadata(t *testing.T, specs []metadata.EntityDescriptor, at time.Time) *metadata.Snapshot {
	t.Helper()
	var raw bytes.Buffer
	raw.WriteString(`<md:EntitiesDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata">`)
	options := metadata.Options{AllowHTTP: true}
	for _, spec := range specs {
		d, err := metadata.Build(t.Context(), spec, at, options)
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
	partners, err := metadata.ParseTrusted(t.Context(), raw.Bytes(), at, options)
	if err != nil {
		t.Fatal(err)
	}
	return partners
}

func serverURL(r *http.Request) string { return "http://" + r.Host }
