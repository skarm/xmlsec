package session_test

import (
	"crypto"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/skarm/xmlsec/internal/testutil/testcert"
	"github.com/skarm/xmlsec/saml/binding"
	"github.com/skarm/xmlsec/saml/metadata"
	"github.com/skarm/xmlsec/saml/protocol"
	"github.com/skarm/xmlsec/saml/session"
	"github.com/skarm/xmlsec/xmldsig"
)

// Each provider initiates a change, the other applies it, and only a correlated
// authenticated response commits the initiator's matching local change.
func TestManageNameIDBothDirectionsAndBindings(t *testing.T) {
	c := testcert.New(t)
	at := testcert.Now()
	spKey := protocol.SigningKey{Key: c.LeafKey, CertificateDER: c.Leaf.Raw}
	idpKey := protocol.SigningKey{Key: c.TSAKey, CertificateDER: c.TSA.Raw}
	spStore, _ := session.NewMemoryStore(session.Config{EntityID: spID, Role: metadata.ServiceProvider, Capacity: 100})
	idpStore, _ := session.NewMemoryStore(session.Config{EntityID: idpID, Role: metadata.IdentityProvider, Capacity: 100})
	register(t, spStore, idpID, "local-account", "group", "index", "sp-session")
	register(t, idpStore, spID, "local-account", "group", "index", "idp-session")
	spService := session.Service{EntityID: spID, Endpoint: "https://sp.test/manage", Role: metadata.ServiceProvider, Store: spStore, Signing: spKey}
	idpService := session.Service{EntityID: idpID, Endpoint: mgmt, Role: metadata.IdentityProvider, Store: idpStore, Signing: idpKey}
	for i, step := range []struct {
		sender, receiver            session.Service
		store, remote               *session.MemoryStore
		senderID, receiverID, value string
		redirect                    bool
	}{
		{spService, idpService, spStore, idpStore, spID, idpID, "new-sp-alias", true},
		{idpService, spService, idpStore, spStore, idpID, spID, "new-primary", false},
	} {
		old, ok := step.store.Lookup(t.Context(), "local-account", step.receiverID, at)
		if !ok {
			t.Fatal("missing original binding")
		}
		id := "_sp_change"
		if i == 1 {
			id = "_idp_change"
		}
		d, err := step.sender.BeginManage(t.Context(), step.receiverID, protocol.ManageNameIDRequest{ID: id, Issuer: step.senderID, Destination: step.receiver.Endpoint, IssueInstant: at, NameID: old.NameID, NewID: step.value}, at)
		if err != nil {
			t.Fatal(err)
		}
		o := protocol.ExchangeOptions{Issuer: step.senderID, Destination: step.receiver.Endpoint, At: at}
		var request *protocol.VerifiedManageNameIDRequest
		if step.redirect {
			query, err := binding.SignRedirect(t.Context(), d, binding.Request, nil, step.sender.Signing.Key, binding.Options{SignatureMethod: xmldsig.ECDSASHA256})
			if err != nil {
				t.Fatal(err)
			}
			request, _, err = protocol.VerifyRedirectManageNameIDRequest(t.Context(), query, []crypto.PublicKey{step.sender.Signing.Key.Public()}, o, binding.Options{})
			if err != nil {
				t.Fatal(err)
			}
		} else {
			request, err = protocol.VerifyManageNameIDRequest(t.Context(), d, []crypto.PublicKey{step.sender.Signing.Key.Public()}, o)
			if err != nil {
				t.Fatal(err)
			}
		}
		response, err := step.receiver.Manage(t.Context(), request, step.sender.Endpoint, at)
		if err != nil {
			t.Fatal(err)
		}
		o = protocol.ExchangeOptions{Issuer: step.receiverID, Destination: step.sender.Endpoint, ExpectedRequestID: id, At: at}
		var verified *protocol.VerifiedStatusResponse
		if step.redirect {
			query, err := binding.SignRedirect(t.Context(), response, binding.Response, nil, step.receiver.Signing.Key, binding.Options{SignatureMethod: xmldsig.ECDSASHA256})
			if err != nil {
				t.Fatal(err)
			}
			verified, _, err = protocol.VerifyRedirectStatusResponse(t.Context(), query, []crypto.PublicKey{step.receiver.Signing.Key.Public()}, o, binding.Options{})
			if err != nil {
				t.Fatal(err)
			}
		} else {
			verified, err = protocol.VerifyStatusResponse(t.Context(), response, []crypto.PublicKey{step.receiver.Signing.Key.Public()}, o)
			if err != nil {
				t.Fatal(err)
			}
		}
		before, _ := step.store.Lookup(t.Context(), "local-account", step.receiverID, at)
		if before.NameID != old.NameID {
			t.Fatal("outgoing change applied before reply")
		}
		step.sender.Limits.MaxMessageAge = time.Second
		if _, err := step.sender.Complete(t.Context(), verified, at.Add(2*time.Second)); err == nil {
			t.Fatal("held response bypassed the service freshness policy")
		}
		if _, err := step.sender.Complete(t.Context(), verified, at); err != nil {
			t.Fatal(err)
		}
		if _, err := step.sender.Complete(t.Context(), verified, at); err == nil {
			t.Fatal("response replay")
		}
		local, _ := step.store.Lookup(t.Context(), "local-account", step.receiverID, at)
		remote, _ := step.remote.Lookup(t.Context(), "local-account", step.senderID, at)
		if local.NameID != remote.NameID || local.NameID.Format != protocol.NameIDPersistent {
			t.Fatal("providers diverged")
		}
		if i == 0 && (local.NameID.Value != "alice" || local.NameID.SPProvidedID != step.value) {
			t.Fatal("SP alias change affected primary ID")
		}
		if i == 1 && (local.NameID.Value != step.value || local.NameID.SPProvidedID != "new-sp-alias") {
			t.Fatal("IdP change lost current SP alias")
		}
	}
	old, _ := spStore.Lookup(t.Context(), "local-account", idpID, at)
	_, err := spService.BeginManage(t.Context(), idpID, protocol.ManageNameIDRequest{ID: "_termination", Issuer: spID, Destination: mgmt, IssueInstant: at, NameID: old.NameID, Terminate: true}, at)
	if err != nil {
		t.Fatal(err)
	}
	_, err = spService.BeginLogout(t.Context(), idpID, protocol.LogoutRequest{ID: "_late_logout", Issuer: spID, Destination: "https://idp.test/slo", IssueInstant: at, NameID: old.NameID, SessionIndexes: []string{"index"}}, at)
	if err == nil {
		t.Fatal("Errata E8: SLO sent after sending Terminate")
	}
	if !spStore.Active(t.Context(), "sp-session", at) || !idpStore.Active(t.Context(), "idp-session", at) {
		t.Fatal("name management invalidated active sessions")
	}
	// The remote reply may never arrive. Expiring correlation state must not
	// undo a termination already sent, or allow late assertions under its name.
	later := at.Add(6 * time.Minute)
	if _, ok := spStore.Lookup(t.Context(), "local-account", idpID, later); ok {
		t.Fatal("termination timed out back into an active relationship")
	}
	if err := spStore.Add(t.Context(), session.Session{ID: "late", Principal: "local-account", Peer: idpID, NameID: old.NameID, Index: "index", ExpiresAt: later.Add(time.Minute)}, later); err == nil {
		t.Fatal("late assertion accepted after sending Terminate")
	}
	if err := spStore.Register(t.Context(), session.Relationship{Principal: "local-account", Peer: idpID, NameID: old.NameID, ExpiresAt: later.Add(time.Hour)}, later); err == nil {
		t.Fatal("terminated identifier immediately reactivated")
	}
	_, err = spService.BeginLogout(t.Context(), idpID, protocol.LogoutRequest{ID: "_after_timeout", Issuer: spID, Destination: "https://idp.test/slo", IssueInstant: later, NameID: old.NameID, SessionIndexes: []string{"index"}}, later)
	if err == nil || !spStore.Active(t.Context(), "sp-session", later) {
		t.Fatal("E8 termination lifetime or preservation of active sessions violated")
	}
}

type failingSigner struct{ crypto.Signer }

func (f failingSigner) Sign(io.Reader, []byte, crypto.SignerOpts) ([]byte, error) {
	return nil, errors.New("signing device unavailable")
}

func TestControlSigningFailureDoesNotCommitState(t *testing.T) {
	c := testcert.New(t)
	at := testcert.Now()
	key := protocol.SigningKey{Key: c.LeafKey, CertificateDER: c.Leaf.Raw}
	store, _ := session.NewMemoryStore(session.Config{EntityID: idpID, Role: metadata.IdentityProvider, Capacity: 100})
	register(t, store, spID, "local-account", "group", "index", "active")
	service := session.Service{EntityID: idpID, Endpoint: mgmt, Role: metadata.IdentityProvider, Store: store, Signing: key}
	service.Signing.Key = failingSigner{Signer: c.LeafKey}
	r := managementRequest(t, key, "_sign_failure", name(spID), "new-alias", false)
	if _, err := service.Manage(t.Context(), r, "https://sp.test/manage", at); err == nil {
		t.Fatal("signer failure ignored")
	}
	before, _ := store.Lookup(t.Context(), "local-account", spID, at)
	if before.NameID.SPProvidedID != "original-alias" {
		t.Fatal("failed reply changed identifier")
	}
	service.Signing = key
	if _, err := service.Manage(t.Context(), r, "https://sp.test/manage", at); err != nil {
		t.Fatalf("failed signing consumed request: %v", err)
	}
}

func TestIdPInitiatedRedirectLogout(t *testing.T) {
	at := testcert.Now()
	c := testcert.New(t)
	key := protocol.SigningKey{Key: c.LeafKey, CertificateDER: c.Leaf.Raw}
	spStore, _ := session.NewMemoryStore(session.Config{EntityID: spID, Role: metadata.ServiceProvider, Capacity: 100})
	idpStore, _ := session.NewMemoryStore(session.Config{EntityID: idpID, Role: metadata.IdentityProvider, Capacity: 100})
	register(t, spStore, idpID, "local-account", "group", "index", "sp-session")
	register(t, idpStore, spID, "local-account", "group", "index", "idp-session")
	sender := session.Service{EntityID: idpID, Endpoint: "https://idp.test/slo", Role: metadata.IdentityProvider, Store: idpStore, Signing: key}
	receiver := session.Service{EntityID: spID, Endpoint: slo, Role: metadata.ServiceProvider, Store: spStore, Signing: key}
	d, err := sender.BeginLogout(t.Context(), spID, protocol.LogoutRequest{ID: "_idp_logout", Issuer: idpID, Destination: slo, IssueInstant: at, NameID: name(spID), NotOnOrAfter: at.Add(time.Minute)}, at)
	if err != nil {
		t.Fatal(err)
	}
	query, err := binding.SignRedirect(t.Context(), d, binding.Request, nil, key.Key, binding.Options{SignatureMethod: xmldsig.ECDSASHA256})
	if err != nil {
		t.Fatal(err)
	}
	r, _, err := protocol.VerifyRedirectLogoutRequest(t.Context(), query, []crypto.PublicKey{key.Key.Public()}, protocol.ExchangeOptions{Issuer: idpID, Destination: slo, At: at}, binding.Options{})
	if err != nil {
		t.Fatal(err)
	}
	reply, _, err := receiver.Logout(t.Context(), r, sender.Endpoint, at)
	if err != nil {
		t.Fatal(err)
	}
	query, err = binding.SignRedirect(t.Context(), reply, binding.Response, nil, key.Key, binding.Options{SignatureMethod: xmldsig.ECDSASHA256})
	if err != nil {
		t.Fatal(err)
	}
	response, _, err := protocol.VerifyRedirectStatusResponse(t.Context(), query, []crypto.PublicKey{key.Key.Public()}, protocol.ExchangeOptions{Issuer: spID, Destination: sender.Endpoint, ExpectedRequestID: "_idp_logout", At: at}, binding.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sender.Complete(t.Context(), response, at); err != nil {
		t.Fatal(err)
	}
	if spStore.Active(t.Context(), "sp-session", at) || idpStore.Active(t.Context(), "idp-session", at) {
		t.Fatal("IdP-initiated Redirect logout did not terminate both sides")
	}
}
