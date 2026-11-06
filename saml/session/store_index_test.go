package session_test

import (
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/skarm/xmlsec/internal/testutil/testcert"
	"github.com/skarm/xmlsec/saml/metadata"
	"github.com/skarm/xmlsec/saml/protocol"
	"github.com/skarm/xmlsec/saml/session"
)

func TestStoreExpiryReleasesNamesAndCapacity(t *testing.T) {
	at := testcert.Now()
	store, err := session.NewMemoryStore(session.Config{EntityID: spID, Role: metadata.ServiceProvider, Capacity: 1})
	if err != nil {
		t.Fatal(err)
	}
	r := session.Relationship{Principal: "alice", Peer: idpID, NameID: protocol.NameIdentifier{Value: "federated"}, ExpiresAt: at.Add(2 * time.Minute)}
	if err := store.Register(t.Context(), r, at); err != nil {
		t.Fatal(err)
	}
	duplicate := r
	duplicate.Principal = "bob"
	duplicate.NameID.Format = protocol.NameIDUnspecified
	if err := store.Register(t.Context(), duplicate, at); err == nil {
		t.Fatal("equivalent unspecified formats admitted the same identifier twice")
	}
	s := session.Session{ID: "session", Principal: r.Principal, Peer: r.Peer, NameID: r.NameID, ExpiresAt: at.Add(time.Minute)}
	if err := store.Add(t.Context(), s, at); err != nil {
		t.Fatal(err)
	}
	s.ExpiresAt = r.ExpiresAt
	if err := store.Add(t.Context(), s, at.Add(time.Minute)); err != nil || !store.Active(t.Context(), s.ID, at.Add(time.Minute)) {
		t.Fatal("expired session blocked reuse at its exact deadline", err)
	}
	duplicate.ExpiresAt = at.Add(3 * time.Minute)
	if err := store.Register(t.Context(), duplicate, r.ExpiresAt); err != nil {
		t.Fatal("expired relationship retained its identifier or capacity", err)
	}
	if _, ok := store.Lookup(t.Context(), r.Principal, r.Peer, r.ExpiresAt); ok || store.Active(t.Context(), s.ID, r.ExpiresAt) {
		t.Fatal("expired relationship or session remained active")
	}
	if _, ok := store.Lookup(t.Context(), duplicate.Principal, duplicate.Peer, r.ExpiresAt); !ok {
		t.Fatal("replacement relationship was lost")
	}
}

func TestStoreConcurrentPopulationAndExpiry(t *testing.T) {
	at := testcert.Now()
	store, err := session.NewMemoryStore(session.Config{EntityID: spID, Role: metadata.ServiceProvider, Capacity: 1024})
	if err != nil {
		t.Fatal(err)
	}
	for round := range 2 {
		now := at.Add(time.Duration(round) * time.Hour)
		var wg sync.WaitGroup
		for worker := range 8 {
			wg.Go(func() {
				for i := worker; i < 1024; i += 8 {
					id := "user-" + strconv.Itoa(i)
					r := session.Relationship{Principal: id, Peer: idpID, NameID: protocol.NameIdentifier{Value: id}, ExpiresAt: now.Add(time.Hour)}
					if err := store.Register(t.Context(), r, now); err != nil {
						t.Error(err)
						return
					}
					if err := store.Add(t.Context(), session.Session{ID: id, Principal: id, Peer: r.Peer, NameID: r.NameID, ExpiresAt: now.Add(10 * time.Minute)}, now); err != nil {
						t.Error(err)
						return
					}
				}
			})
		}
		wg.Wait()
		for i := range 1024 {
			id := "user-" + strconv.Itoa(i)
			if _, ok := store.Lookup(t.Context(), id, idpID, now); !ok || !store.Active(t.Context(), id, now) {
				t.Fatal("concurrent insertion or prior expiry lost an active user", id)
			}
		}
	}
}
