package session //nolint:testpackage // Holds the transaction mutex to reproduce cancellation while queued.

import (
	"context"
	"crypto"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/skarm/xmlsec/internal/testutil/testcert"
	"github.com/skarm/xmlsec/saml/metadata"
	"github.com/skarm/xmlsec/saml/protocol"
)

type observedContext struct {
	context.Context
	checked chan struct{}
	once    sync.Once
}

func (c *observedContext) Err() error {
	err := c.Context.Err()
	c.once.Do(func() { close(c.checked) })
	return err
}

func TestCanceledSessionTransactionDoesNotCommit(t *testing.T) {
	for _, operation := range []string{"Register", "Add", "Active", "Lookup", "Logout", "Manage", "Start", "Finish", "Withdraw"} {
		t.Run(operation, func(t *testing.T) {
			const local, peer, endpoint = "https://idp.test/entity", "https://sp.test/entity", "https://idp.test/control"
			at := testcert.Now()
			cert := testcert.New(t)
			key := protocol.SigningKey{Key: cert.LeafKey, CertificateDER: cert.Leaf.Raw}
			keys := []crypto.PublicKey{key.Key.Public()}
			options := protocol.ExchangeOptions{Issuer: peer, Destination: endpoint, At: at, ExpectedRequestID: "_pending"}
			store, err := NewMemoryStore(Config{EntityID: local, Role: metadata.IdentityProvider})
			if err != nil {
				t.Fatal(err)
			}
			name := protocol.NameIdentifier{Value: "alice"}
			relationship := Relationship{Principal: "alice", Peer: peer, NameID: name, ExpiresAt: at.Add(time.Hour)}
			if err := store.Register(t.Context(), relationship, at); err != nil {
				t.Fatal(err)
			}
			session := Session{ID: "active", Principal: "alice", Peer: peer, NameID: name, AuthoritySession: "group", Index: "index", ExpiresAt: at.Add(time.Minute)}
			if err := store.Add(t.Context(), session, at); err != nil {
				t.Fatal(err)
			}
			pending := Pending{ID: "_pending", Peer: peer, Kind: protocol.ManageNameIDResponse, NameID: name, NewID: "replacement", LocalIsIDP: true, ExpiresAt: at.Add(time.Minute)}
			if err := store.Start(t.Context(), pending, at); err != nil {
				t.Fatal(err)
			}
			header := protocol.MessageHeader{Issuer: peer, Destination: endpoint, IssueInstant: at}
			logoutXML, err := protocol.SignLogoutRequest(t.Context(), protocol.LogoutRequest{MessageHeader: header, NameID: name, SessionIndexes: []string{"index"}, NotOnOrAfter: at.Add(time.Minute)}, key)
			if err != nil {
				t.Fatal(err)
			}
			logout, err := protocol.VerifyLogoutRequest(t.Context(), logoutXML, keys, options)
			if err != nil {
				t.Fatal(err)
			}
			manageXML, err := protocol.SignManageNameIDRequest(t.Context(), protocol.ManageNameIDRequest{MessageHeader: header, NameID: name, NewID: "new-alias"}, key)
			if err != nil {
				t.Fatal(err)
			}
			manage, err := protocol.VerifyManageNameIDRequest(t.Context(), manageXML, keys, options)
			if err != nil {
				t.Fatal(err)
			}
			responseXML, err := protocol.SignStatusResponse(t.Context(), protocol.StatusResponse{MessageHeader: header, Kind: protocol.ManageNameIDResponse, InResponseTo: pending.ID, Status: protocol.Status{Code: protocol.Success}}, key)
			if err != nil {
				t.Fatal(err)
			}
			response, err := protocol.VerifyStatusResponse(t.Context(), responseXML, keys, options)
			if err != nil {
				t.Fatal(err)
			}
			call := func(ctx context.Context) error {
				switch operation {
				case "Register":
					r := relationship
					r.Principal, r.NameID.Value = "bob", "bob"
					return store.Register(ctx, r, at)
				case "Add":
					s := session
					s.ID = "new-session"
					return store.Add(ctx, s, at)
				case "Active":
					if store.Active(ctx, session.ID, at) {
						return errors.New("canceled read returned an active session")
					}
					return ctx.Err()
				case "Lookup":
					if _, ok := store.Lookup(ctx, "alice", peer, at); ok {
						return errors.New("canceled read returned a relationship")
					}
					return ctx.Err()
				case "Logout":
					_, err := store.Logout(ctx, logout, true, at, at.Add(time.Hour), 0)
					return err
				case "Manage":
					_, err := store.Manage(ctx, manage, false, at, at.Add(time.Hour))
					return err
				case "Start":
					p := pending
					p.ID = "_newPending"
					return store.Start(ctx, p, at)
				case "Finish":
					_, err := store.Finish(ctx, response, at)
					return err
				case "Withdraw":
					_, err := store.Withdraw(ctx, "alice", "group", at)
					return err
				}
				return nil
			}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			observed := &observedContext{Context: ctx, checked: make(chan struct{})}
			finished := make(chan error, 1)
			store.mu.Lock()
			go func() { finished <- call(observed) }()
			<-observed.checked
			cancel()
			store.mu.Unlock()
			if err := <-finished; !errors.Is(err, context.Canceled) {
				t.Error("canceled transaction was not rejected", err)
			}
			if !store.Active(t.Context(), session.ID, at) || store.Active(t.Context(), "new-session", at) {
				t.Error("canceled transaction changed sessions")
			}
			if r, ok := store.Lookup(t.Context(), "alice", peer, at); !ok || r.NameID != name {
				t.Error("canceled transaction changed the identifier")
			}
			if _, ok := store.Lookup(t.Context(), "bob", peer, at); ok {
				t.Error("canceled transaction inserted a relationship")
			}
		})
	}
}
