package session_test

import (
	"context"
	"crypto"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/skarm/xmlsec/internal/testutil/testcert"
	"github.com/skarm/xmlsec/saml/metadata"
	"github.com/skarm/xmlsec/saml/protocol"
	"github.com/skarm/xmlsec/saml/session"
)

const (
	spID  = "https://sp.test/entity"
	idpID = "https://idp.test/entity"
	slo   = "https://sp.test/slo"
	mgmt  = "https://idp.test/manage"
)

func name(peer string) protocol.NameIdentifier {
	return protocol.NameIdentifier{Value: "alice", Format: protocol.NameIDPersistent, NameQualifier: idpID, SPNameQualifier: peer, SPProvidedID: "original-alias"}
}

func register(t *testing.T, store *session.MemoryStore, peer, principal, group, index, id string) {
	t.Helper()
	at := testcert.Now()
	if _, ok := store.Lookup(t.Context(), principal, peer, at); !ok {
		n := name(peer)
		if peer == idpID {
			n = name(spID)
		}
		if principal != "local-account" {
			n.Value = principal
		}
		if err := store.Register(t.Context(), session.Relationship{Principal: principal, Peer: peer, NameID: n, ExpiresAt: at.Add(time.Hour)}, at); err != nil {
			t.Fatal(err)
		}
	}
	rel, _ := store.Lookup(t.Context(), principal, peer, at)
	if err := store.Add(t.Context(), session.Session{ID: id, Principal: principal, Peer: peer, NameID: rel.NameID, AuthoritySession: group, Index: index, ExpiresAt: at.Add(30 * time.Minute)}, at); err != nil {
		t.Fatal(err)
	}
}

func logoutRequest(t *testing.T, key protocol.SigningKey, issuer, destination, id string, n protocol.NameIdentifier, indices ...string) *protocol.VerifiedLogoutRequest {
	t.Helper()
	at := testcert.Now()
	d, err := protocol.SignLogoutRequest(t.Context(), protocol.LogoutRequest{ID: id, Issuer: issuer, Destination: destination, IssueInstant: at, NameID: n, SessionIndexes: indices, NotOnOrAfter: at.Add(10 * time.Minute)}, key)
	if err != nil {
		t.Fatal(err)
	}
	r, err := protocol.VerifyLogoutRequest(t.Context(), d, []crypto.PublicKey{key.Key.Public()}, protocol.ExchangeOptions{Issuer: issuer, Destination: destination, At: at})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func managementRequest(t *testing.T, key protocol.SigningKey, id string, n protocol.NameIdentifier, value string, terminate bool) *protocol.VerifiedManageNameIDRequest {
	t.Helper()
	at := testcert.Now()
	d, err := protocol.SignManageNameIDRequest(t.Context(), protocol.ManageNameIDRequest{ID: id, Issuer: spID, Destination: mgmt, IssueInstant: at, NameID: n, NewID: value, Terminate: terminate}, key)
	if err != nil {
		t.Fatal(err)
	}
	r, err := protocol.VerifyManageNameIDRequest(t.Context(), d, []crypto.PublicKey{key.Key.Public()}, protocol.ExchangeOptions{Issuer: spID, Destination: mgmt, At: at})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// Core 3.7.3.1 requires logout to cover valid assertions arriving later, while
// preserving different SessionIndex values and unrelated principals.
func TestParticipantLogoutAndLateAssertions(t *testing.T) {
	c := testcert.New(t)
	key := protocol.SigningKey{Key: c.LeafKey, CertificateDER: c.Leaf.Raw}
	at := testcert.Now()
	store, err := session.NewMemoryStore(session.Config{EntityID: spID, Role: metadata.ServiceProvider, Capacity: 100})
	if err != nil {
		t.Fatal(err)
	}
	register(t, store, idpID, "local-account", "authority", "index-a", "session-a")
	register(t, store, idpID, "local-account", "authority", "index-b", "session-b")
	register(t, store, idpID, "bob", "other", "index-a", "bob-session")
	n := name(spID)
	r := logoutRequest(t, key, idpID, slo, "_logout", n, "index-a")
	service := session.Service{EntityID: spID, Endpoint: slo, Role: metadata.ServiceProvider, Store: store, Signing: key}
	if _, _, err := service.Logout(t.Context(), r, "https://idp.test/slo", at.Add(6*time.Minute)); err == nil {
		t.Fatal("held verified request bypassed freshness")
	}
	d, result, err := service.Logout(t.Context(), r, "https://idp.test/slo", at)
	if err != nil || d == nil || len(result.SessionIDs) != 1 || result.SessionIDs[0] != "session-a" {
		t.Fatalf("logout: %+v %v", result, err)
	}
	if store.Active(t.Context(), "session-a", at) || !store.Active(t.Context(), "session-b", at) || !store.Active(t.Context(), "bob-session", at) {
		t.Fatal("wrong session scope")
	}
	late := session.Session{ID: "late", Principal: "local-account", Peer: idpID, NameID: n, Index: "index-a", ExpiresAt: at.Add(30 * time.Minute)}
	if err := store.Add(t.Context(), late, at.Add(time.Minute)); err == nil {
		t.Fatal("late assertion resurrected logged-out index")
	}
	if _, _, err := service.Logout(t.Context(), r, "https://idp.test/slo", at); !errors.Is(err, session.ErrReplay) {
		t.Fatalf("replay: %v", err)
	}
	if err := store.Add(t.Context(), late, at.Add(10*time.Minute)); err != nil {
		t.Fatalf("expired logout still blocks session: %v", err)
	}
	all := logoutRequest(t, key, idpID, slo, "_all", n)
	if _, _, err := service.Logout(t.Context(), all, "https://idp.test/slo", at); err != nil {
		t.Fatal(err)
	}
	if store.Active(t.Context(), "session-b", at) {
		t.Fatal("omitted indices did not select all")
	}
}

func TestAuthorityFanoutPartialAndInitiation(t *testing.T) {
	c := testcert.New(t)
	key := protocol.SigningKey{Key: c.LeafKey, CertificateDER: c.Leaf.Raw}
	at := testcert.Now()
	store, err := session.NewMemoryStore(session.Config{EntityID: idpID, Role: metadata.IdentityProvider, Capacity: 100})
	if err != nil {
		t.Fatal(err)
	}
	register(t, store, spID, "local-account", "group-1", "one", "session-1")
	register(t, store, "https://sp2.test/entity", "local-account", "group-1", "two", "session-2")
	register(t, store, "https://sp3.test/entity", "local-account", "group-2", "three", "session-3")
	var notified []string
	service := session.Service{EntityID: idpID, Endpoint: mgmt, Role: metadata.IdentityProvider, Store: store, Signing: key, Notify: func(_ context.Context, p session.Participant) (protocol.Status, error) {
		notified = append(notified, p.Peer)
		return protocol.Status{}, errors.New("unreachable")
	}}
	r := logoutRequest(t, key, spID, mgmt, "_fanout", name(spID), "one")
	d, result, err := service.Logout(t.Context(), r, "https://sp.test/slo", at)
	if err != nil || len(notified) != 1 || notified[0] != "https://sp2.test/entity" || len(result.Status.Subcodes) != 1 || result.Status.Subcodes[0] != protocol.PartialLogout {
		t.Fatalf("fanout: %+v %v", result, err)
	}
	if store.Active(t.Context(), "session-1", at) || store.Active(t.Context(), "session-2", at) || !store.Active(t.Context(), "session-3", at) {
		t.Fatal("authority session isolation")
	}
	v, err := protocol.VerifyStatusResponse(t.Context(), d, []crypto.PublicKey{c.LeafKey.Public()}, protocol.ExchangeOptions{Issuer: idpID, Destination: "https://sp.test/slo", ExpectedRequestID: "_fanout", At: at})
	if err != nil || v.Status().Code != protocol.Success || v.Status().Subcodes[0] != protocol.PartialLogout {
		t.Fatal("partial logout status mapping")
	}
	result, err = service.InitiateLogout(t.Context(), "local-account", "group-2", at)
	if err != nil || store.Active(t.Context(), "session-3", at) || len(result.Participants) != 1 {
		t.Fatal("IdP-initiated logout")
	}
}

// Errata E8/E12/E55: an SP changes its alias, retains primary identity and active
// sessions, and termination removes the binding without forcing SLO.
func TestManageAliasTerminationAndAtomicReplay(t *testing.T) {
	c := testcert.New(t)
	key := protocol.SigningKey{Key: c.LeafKey, CertificateDER: c.Leaf.Raw}
	at := testcert.Now()
	store, err := session.NewMemoryStore(session.Config{EntityID: idpID, Role: metadata.IdentityProvider, Capacity: 100})
	if err != nil {
		t.Fatal(err)
	}
	register(t, store, spID, "local-account", "group", "index", "active")
	r := managementRequest(t, key, "_alias", name(spID), "new-alias", false)
	var applied atomic.Int32
	var replayed atomic.Int32
	var wg sync.WaitGroup
	for range 24 {
		wg.Go(func() {
			status, err := store.Manage(t.Context(), r, false, at, at.Add(time.Hour))
			if err == nil && status.Code == protocol.Success {
				applied.Add(1)
			} else if errors.Is(err, session.ErrReplay) {
				replayed.Add(1)
			} else {
				t.Errorf("unexpected result: %+v %v", status, err)
			}
		})
	}
	wg.Wait()
	if applied.Load() != 1 || replayed.Load() != 23 {
		t.Fatal("non-atomic NameID/replay transaction")
	}
	rel, ok := store.Lookup(t.Context(), "local-account", spID, at)
	if !ok || rel.NameID.Value != "alice" || rel.NameID.SPProvidedID != "new-alias" || !store.Active(t.Context(), "active", at) {
		t.Fatal("SPProvidedID semantics")
	}
	stale := managementRequest(t, key, "_stale", name(spID), "bad", false)
	status, err := store.Manage(t.Context(), stale, false, at, at.Add(time.Hour))
	if err != nil || status.Code != protocol.Requester || status.Subcodes[0] != protocol.UnknownPrincipal {
		t.Fatal("stale identifier must fail")
	}
	termination := managementRequest(t, key, "_terminate", rel.NameID, "", true)
	status, err = store.Manage(t.Context(), termination, false, at, at.Add(time.Hour))
	if err != nil || status.Code != protocol.Success {
		t.Fatal(err)
	}
	if _, ok := store.Lookup(t.Context(), "local-account", spID, at); ok || !store.Active(t.Context(), "active", at) {
		t.Fatal("termination must remove binding and preserve active sessions")
	}
}

func TestLogoutMarkersSurviveIdentifierChange(t *testing.T) {
	at := testcert.Now()
	c := testcert.New(t)
	key := protocol.SigningKey{Key: c.LeafKey, CertificateDER: c.Leaf.Raw}
	store, _ := session.NewMemoryStore(session.Config{EntityID: spID, Role: metadata.ServiceProvider, Capacity: 100})
	register(t, store, idpID, "local-account", "group", "index-a", "session-a")
	old := name(spID)
	r := logoutRequest(t, key, idpID, slo, "_before_rename", old, "index-a")
	if _, err := store.Logout(t.Context(), r, false, at, at.Add(time.Hour), 0); err != nil {
		t.Fatal(err)
	}
	d, err := protocol.SignManageNameIDRequest(t.Context(), protocol.ManageNameIDRequest{ID: "_rename", Issuer: idpID, Destination: slo, IssueInstant: at, NameID: old, NewID: "new-primary"}, key)
	if err != nil {
		t.Fatal(err)
	}
	change, err := protocol.VerifyManageNameIDRequest(t.Context(), d, []crypto.PublicKey{key.Key.Public()}, protocol.ExchangeOptions{Issuer: idpID, Destination: slo, At: at})
	if err != nil {
		t.Fatal(err)
	}
	status, err := store.Manage(t.Context(), change, true, at, at.Add(time.Hour))
	if err != nil || status.Code != protocol.Success {
		t.Fatal(err)
	}
	late := session.Session{ID: "late", Principal: "local-account", Peer: idpID, NameID: old, Index: "index-a", ExpiresAt: at.Add(time.Minute)}
	if err := store.Add(t.Context(), late, at); err == nil {
		t.Fatal("stale signed identifier accepted after rename")
	}
	current, _ := store.Lookup(t.Context(), "local-account", idpID, at)
	late.NameID = current.NameID
	if err := store.Add(t.Context(), late, at); err == nil {
		t.Fatal("rename bypassed a live logout marker")
	}
	late.Index = "fresh-index"
	if err := store.Add(t.Context(), late, at); err != nil {
		t.Fatalf("unrelated fresh session blocked: %v", err)
	}
}

func TestTerminatedBindingDoesNotWidenLogout(t *testing.T) {
	at := testcert.Now()
	c := testcert.New(t)
	key := protocol.SigningKey{Key: c.LeafKey, CertificateDER: c.Leaf.Raw}
	store, _ := session.NewMemoryStore(session.Config{EntityID: spID, Role: metadata.ServiceProvider, Capacity: 100})
	register(t, store, idpID, "local-account", "old-group", "shared-index", "old-session")
	old := name(spID)
	d, err := protocol.SignManageNameIDRequest(t.Context(), protocol.ManageNameIDRequest{ID: "_end_old", Issuer: idpID, Destination: slo, IssueInstant: at, NameID: old, Terminate: true}, key)
	if err != nil {
		t.Fatal(err)
	}
	r, err := protocol.VerifyManageNameIDRequest(t.Context(), d, []crypto.PublicKey{key.Key.Public()}, protocol.ExchangeOptions{Issuer: idpID, Destination: slo, At: at})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Manage(t.Context(), r, true, at, at.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	current := old
	current.Value = "second-primary"
	if err := store.Register(t.Context(), session.Relationship{Principal: "local-account", Peer: idpID, NameID: current, ExpiresAt: at.Add(time.Hour)}, at); err != nil {
		t.Fatal(err)
	}
	if err := store.Add(t.Context(), session.Session{ID: "new-session", Principal: "local-account", Peer: idpID, NameID: current, AuthoritySession: "new-group", Index: "shared-index", ExpiresAt: at.Add(time.Minute)}, at); err != nil {
		t.Fatal(err)
	}
	logout := logoutRequest(t, key, idpID, slo, "_end_new", current)
	if _, err := store.Logout(t.Context(), logout, false, at, at.Add(time.Hour), 0); err != nil {
		t.Fatal(err)
	}
	if !store.Active(t.Context(), "old-session", at) || store.Active(t.Context(), "new-session", at) {
		t.Fatal("logout crossed a terminated identifier relationship")
	}
}

func TestPersistentImplicitQualifiersAndStoreOwner(t *testing.T) {
	at := testcert.Now()
	c := testcert.New(t)
	key := protocol.SigningKey{Key: c.LeafKey, CertificateDER: c.Leaf.Raw}
	store, _ := session.NewMemoryStore(session.Config{EntityID: spID, Role: metadata.ServiceProvider, Capacity: 100})
	minimal := protocol.NameIdentifier{Value: "opaque", Format: protocol.NameIDPersistent}
	if err := store.Register(t.Context(), session.Relationship{Principal: "account", Peer: idpID, NameID: minimal, ExpiresAt: at.Add(time.Hour)}, at); err != nil {
		t.Fatal(err)
	}
	if err := store.Add(t.Context(), session.Session{ID: "session", Principal: "account", Peer: idpID, NameID: minimal, Index: "index", ExpiresAt: at.Add(time.Minute)}, at); err != nil {
		t.Fatal(err)
	}
	request := logoutRequest(t, key, idpID, slo, "_implicit", minimal, "index")
	wrong := session.Service{EntityID: "https://other-sp.test/entity", Role: metadata.ServiceProvider, Endpoint: slo, Store: store, Signing: key}
	if _, _, err := wrong.Logout(t.Context(), request, "https://idp.test/return", at); err == nil || !store.Active(t.Context(), "session", at) {
		t.Fatal("cross-provider store reuse")
	}
	service := session.Service{EntityID: spID, Role: metadata.ServiceProvider, Endpoint: slo, Store: store, Signing: key}
	if _, _, err := service.Logout(t.Context(), request, "https://idp.test/return", at); err != nil || store.Active(t.Context(), "session", at) {
		t.Fatalf("implicit qualifiers: %v", err)
	}
}
