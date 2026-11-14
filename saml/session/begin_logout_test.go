package session_test

import (
	"crypto"
	"errors"
	"testing"
	"time"

	"github.com/skarm/xmlsec/internal/testutil/testcert"
	"github.com/skarm/xmlsec/saml/metadata"
	"github.com/skarm/xmlsec/saml/protocol"
	"github.com/skarm/xmlsec/saml/session"
)

func TestOutgoingLogoutBlockSurvivesCorrelation(t *testing.T) {
	at := testcert.Now()
	cert := testcert.New(t)
	key := protocol.SigningKey{Key: cert.LeafKey, CertificateDER: cert.Leaf.Raw}
	for _, tc := range []struct {
		name, status string
		deadline     time.Time
	}{
		{"pending expiry", "", at.Add(10 * time.Minute)},
		{"success response", protocol.Success, at.Add(10 * time.Minute)},
		{"failure response", protocol.Responder, at.Add(10 * time.Minute)},
		{"no deadline", "", time.Time{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store, err := session.NewMemoryStore(session.Config{EntityID: spID, Role: metadata.ServiceProvider})
			if err != nil {
				t.Fatal(err)
			}
			identifier := name(spID)
			if err := store.Register(t.Context(), session.Relationship{
				Principal: "local-account", Peer: idpID, NameID: identifier, ExpiresAt: at.Add(3 * time.Hour),
			}, at); err != nil {
				t.Fatal(err)
			}
			active := session.Session{
				ID: "active", Principal: "local-account", Peer: idpID, NameID: identifier,
				Index: "index", ExpiresAt: at.Add(150 * time.Minute),
			}
			if err := store.Add(t.Context(), active, at); err != nil {
				t.Fatal(err)
			}
			service := session.Service{
				EntityID: spID, Endpoint: slo, Role: metadata.ServiceProvider, Store: store, Signing: key,
				Limits: protocol.Limits{ClockSkew: 5 * time.Second},
			}
			request := protocol.LogoutRequest{
				ID: "_outgoing", Issuer: spID, Destination: "https://idp.test/slo", IssueInstant: at,
				NameID: identifier, SessionIndexes: []string{"index"}, NotOnOrAfter: tc.deadline,
			}
			if _, err := service.BeginLogout(t.Context(), idpID, request, at); err != nil {
				t.Fatal(err)
			}
			if store.Active(t.Context(), active.ID, at) {
				t.Fatal("outgoing logout retained the original session")
			}
			if tc.status != "" {
				now := at.Add(time.Minute)
				doc, err := protocol.SignStatusResponse(t.Context(), protocol.StatusResponse{
					ID: "_logoutReply", Issuer: idpID, Destination: slo, IssueInstant: now,
					Kind: protocol.LogoutResponse, InResponseTo: request.ID, Status: protocol.Status{Code: tc.status},
				}, key)
				if err != nil {
					t.Fatal(err)
				}
				response, err := protocol.VerifyStatusResponse(t.Context(), doc, []crypto.PublicKey{key.Key.Public()}, protocol.ExchangeOptions{
					Issuer: idpID, Destination: slo, At: now, ExpectedRequestID: request.ID,
				})
				if err != nil {
					t.Fatal(err)
				}
				if _, err := service.Complete(t.Context(), response, now); err != nil {
					t.Fatal(err)
				}
			}

			later := at.Add(6 * time.Minute)
			late := active
			late.ID = "late"
			if err := store.Add(t.Context(), late, later); !errors.Is(err, session.ErrState) {
				t.Fatal("correlation completion or expiry removed the logout block", err)
			}
			other := late
			other.ID, other.Index = "other-session", "other-index"
			if err := store.Add(t.Context(), other, later); err != nil {
				t.Fatal("outgoing logout blocked an unrelated SessionIndex", err)
			}
			// Reusing an expired pending ID must not overwrite a live block
			// with a shorter deadline or different SessionIndex.
			request.IssueInstant = later
			request.NotOnOrAfter = later.Add(time.Minute)
			request.SessionIndexes = []string{other.Index}
			if _, err := service.BeginLogout(t.Context(), idpID, request, later); !errors.Is(err, session.ErrState) {
				t.Fatal("live logout block overwritten by a reused request ID", err)
			}
			if !store.Active(t.Context(), other.ID, later) {
				t.Fatal("rejected ID reuse invalidated an unrelated session")
			}
			end := at.Add(2 * time.Hour)
			if !tc.deadline.IsZero() {
				end = tc.deadline.Add(service.Limits.ClockSkew)
			}
			if err := store.Add(t.Context(), late, end); err != nil {
				t.Fatal("outgoing logout block did not expire at its deadline", err)
			}
		})
	}
}

func TestOutgoingLogoutCapacityFailurePreservesSession(t *testing.T) {
	at := testcert.Now()
	cert := testcert.New(t)
	key := protocol.SigningKey{Key: cert.LeafKey, CertificateDER: cert.Leaf.Raw}
	store, err := session.NewMemoryStore(session.Config{EntityID: spID, Role: metadata.ServiceProvider, Capacity: 1})
	if err != nil {
		t.Fatal(err)
	}
	register(t, store, idpID, "local-account", "authority", "first-index", "first")
	service := session.Service{EntityID: spID, Endpoint: slo, Role: metadata.ServiceProvider, Store: store, Signing: key}
	request := protocol.LogoutRequest{
		ID: "_firstLogout", Issuer: spID, Destination: "https://idp.test/slo", IssueInstant: at,
		NameID: name(spID), SessionIndexes: []string{"first-index"}, NotOnOrAfter: at.Add(10 * time.Minute),
	}
	if _, err := service.BeginLogout(t.Context(), idpID, request, at); err != nil {
		t.Fatal(err)
	}
	later := at.Add(6 * time.Minute)
	active := session.Session{
		ID: "second", Principal: "local-account", Peer: idpID, NameID: name(spID),
		Index: "second-index", ExpiresAt: at.Add(30 * time.Minute),
	}
	if err := store.Add(t.Context(), active, later); err != nil {
		t.Fatal(err)
	}
	request.ID, request.IssueInstant = "_secondLogout", later
	request.SessionIndexes = []string{active.Index}
	if _, err := service.BeginLogout(t.Context(), idpID, request, later); !errors.Is(err, session.ErrState) {
		t.Fatal("outgoing logout exceeded block capacity", err)
	}
	if !store.Active(t.Context(), active.ID, later) {
		t.Fatal("capacity failure invalidated a session without retaining its block")
	}
}
