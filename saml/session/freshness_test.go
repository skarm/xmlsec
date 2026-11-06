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

func TestLogoutRechecksExpirationAtApplication(t *testing.T) {
	for _, tc := range []struct {
		name string
		at   time.Duration
		skew time.Duration
		want bool
	}{
		{"before deadline", 0, 0, true},
		{"at deadline", time.Second, 0, false},
		{"after deadline", 2 * time.Second, 0, false},
		{"within skew", 2 * time.Second, 2 * time.Second, true},
		{"at skew boundary", 3 * time.Second, 2 * time.Second, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			at := testcert.Now()
			cert := testcert.New(t)
			key := protocol.SigningKey{Key: cert.LeafKey, CertificateDER: cert.Leaf.Raw}
			store, err := session.NewMemoryStore(session.Config{EntityID: spID, Role: metadata.ServiceProvider})
			if err != nil {
				t.Fatal(err)
			}
			register(t, store, idpID, "local-account", "authority", "index", "active")
			request := protocol.LogoutRequest{ID: "_expiringLogout", Issuer: idpID, Destination: slo, IssueInstant: at, NameID: name(spID), SessionIndexes: []string{"index"}, NotOnOrAfter: at.Add(time.Second)}
			doc, err := protocol.SignLogoutRequest(t.Context(), request, key)
			if err != nil {
				t.Fatal(err)
			}
			limits := protocol.Limits{ClockSkew: tc.skew}
			verified, err := protocol.VerifyLogoutRequest(t.Context(), doc, []crypto.PublicKey{key.Key.Public()}, protocol.ExchangeOptions{Issuer: idpID, Destination: slo, At: at, Limits: limits})
			if err != nil {
				t.Fatal(err)
			}
			service := session.Service{EntityID: spID, Endpoint: slo, Role: metadata.ServiceProvider, Store: store, Signing: key, Limits: limits}
			response, _, err := service.Logout(t.Context(), verified, "https://idp.test/slo", at.Add(tc.at))
			if tc.want {
				if err != nil || response == nil || store.Active(t.Context(), "active", at.Add(tc.at)) {
					t.Fatal("fresh logout did not terminate the session", err)
				}
			} else if !errors.Is(err, session.ErrState) || response != nil || !store.Active(t.Context(), "active", at.Add(tc.at)) {
				t.Fatal("expired authenticated logout changed session state", err)
			}
		})
	}
}

func TestBeginLogoutRejectsExpiredRequest(t *testing.T) {
	at := testcert.Now()
	cert := testcert.New(t)
	store, err := session.NewMemoryStore(session.Config{EntityID: idpID, Role: metadata.IdentityProvider})
	if err != nil {
		t.Fatal(err)
	}
	register(t, store, spID, "local-account", "authority", "index", "active")
	service := session.Service{EntityID: idpID, Endpoint: mgmt, Role: metadata.IdentityProvider, Store: store, Signing: protocol.SigningKey{Key: cert.LeafKey, CertificateDER: cert.Leaf.Raw}}
	request := protocol.LogoutRequest{ID: "_expiredOutgoing", Issuer: idpID, Destination: slo, IssueInstant: at, NameID: name(spID), SessionIndexes: []string{"index"}, NotOnOrAfter: at.Add(time.Second)}
	response, err := service.BeginLogout(t.Context(), spID, request, at.Add(2*time.Second))
	if !errors.Is(err, session.ErrState) || response != nil || !store.Active(t.Context(), "active", at.Add(2*time.Second)) {
		t.Fatal("expired outgoing request was published or changed state", err)
	}
}

func TestLogoutBlocksDelayedAssertionThroughClockSkew(t *testing.T) {
	at := testcert.Now()
	cert := testcert.New(t)
	key := protocol.SigningKey{Key: cert.LeafKey, CertificateDER: cert.Leaf.Raw}
	keys := []crypto.PublicKey{key.Key.Public()}
	limits := protocol.Limits{ClockSkew: 2 * time.Second}
	identifier := name(spID)
	deadline := at.Add(time.Second)
	response, err := protocol.SignResponse(t.Context(), protocol.Response{
		ID: "_delayedResponse", Issuer: idpID, Audience: spID,
		Destination: "https://sp.test/acs", InResponseTo: "_pending", IssueInstant: at,
		Limits: limits,
		Assertion: protocol.AssertionData{
			ID: "_delayedAssertion", NameID: identifier.Value, NameIDFormat: identifier.Format,
			NameQualifier: identifier.NameQualifier, SPNameQualifier: identifier.SPNameQualifier,
			SPProvidedID: identifier.SPProvidedID, NotBefore: at, NotOnOrAfter: deadline,
			AuthnInstant: at, AuthnContext: "urn:test:password", SessionIndex: "index",
			SessionNotOnOrAfter: at.Add(30 * time.Minute),
		},
	}, key)
	if err != nil {
		t.Fatal(err)
	}

	logout, err := protocol.SignLogoutRequest(t.Context(), protocol.LogoutRequest{
		ID: "_logoutSkew", Issuer: idpID, Destination: slo, IssueInstant: at,
		NameID: identifier, SessionIndexes: []string{"index"}, NotOnOrAfter: deadline,
	}, key)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := protocol.VerifyLogoutRequest(t.Context(), logout, keys, protocol.ExchangeOptions{
		Issuer: idpID, Destination: slo, At: at, Limits: limits,
	})
	if err != nil {
		t.Fatal(err)
	}

	later := at.Add(2 * time.Second)
	options := protocol.ResponseOptions{
		Issuer: idpID, Audience: spID, Destination: "https://sp.test/acs",
		ExpectedRequestID: "_pending", At: later, Limits: limits,
	}
	assertion, err := protocol.VerifyResponse(t.Context(), response, keys, options)
	if err != nil {
		t.Fatal("signed delayed assertion must remain valid within clock skew", err)
	}
	late := session.Session{
		ID: "late", Principal: "local-account", Peer: idpID, NameID: assertion.Identifier(),
		Index: assertion.SessionIndex(), ExpiresAt: assertion.SessionNotOnOrAfter(),
	}

	for _, tc := range []struct {
		name     string
		at       time.Time
		outgoing bool
	}{
		{"applied before deadline", at, false},
		{"applied within clock skew", later, false},
		{"initiated before deadline", at, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store, err := session.NewMemoryStore(session.Config{EntityID: spID, Role: metadata.ServiceProvider})
			if err != nil {
				t.Fatal(err)
			}
			register(t, store, idpID, "local-account", "authority", "index", "active")
			service := session.Service{
				EntityID: spID, Endpoint: slo, Role: metadata.ServiceProvider,
				Store: store, Signing: key, Limits: limits,
			}
			if tc.outgoing {
				_, err = service.BeginLogout(t.Context(), idpID, protocol.LogoutRequest{
					ID: "_outgoingSkew", Issuer: spID, Destination: "https://idp.test/slo", IssueInstant: at,
					NameID: identifier, SessionIndexes: []string{"index"}, NotOnOrAfter: deadline,
				}, tc.at)
			} else {
				_, _, err = service.Logout(t.Context(), verified, "https://idp.test/slo", tc.at)
			}
			if err != nil {
				t.Fatal(err)
			}
			if store.Active(t.Context(), "active", tc.at) {
				t.Fatal("logout did not invalidate the existing session")
			}
			if err := store.Add(t.Context(), late, later); !errors.Is(err, session.ErrState) {
				t.Fatal("delayed assertion recreated a logged-out SessionIndex", err)
			}
			end := deadline.Add(limits.ClockSkew)
			if err := store.Add(t.Context(), late, end.Add(-time.Nanosecond)); !errors.Is(err, session.ErrState) {
				t.Fatal("logout block expired before the full acceptance window", err)
			}
			if err := store.Add(t.Context(), late, end); err != nil {
				t.Fatal("expired logout block still prevents a new session", err)
			}
		})
	}

	options.At = deadline.Add(limits.ClockSkew)
	if _, err := protocol.VerifyResponse(t.Context(), response, keys, options); !errors.Is(err, protocol.ErrConditions) {
		t.Fatal("assertion accepted at the exclusive skew boundary", err)
	}
}

func TestLogoutRejectsInvalidClockSkewWithoutChangingState(t *testing.T) {
	at := testcert.Now()
	cert := testcert.New(t)
	key := protocol.SigningKey{Key: cert.LeafKey, CertificateDER: cert.Leaf.Raw}
	verified := logoutRequest(t, key, idpID, slo, "_invalidSkew", name(spID), "index")

	for _, skew := range []time.Duration{-time.Nanosecond, 5*time.Minute + time.Nanosecond} {
		t.Run(skew.String(), func(t *testing.T) {
			store, err := session.NewMemoryStore(session.Config{EntityID: spID, Role: metadata.ServiceProvider})
			if err != nil {
				t.Fatal(err)
			}
			register(t, store, idpID, "local-account", "authority", "index", "active")
			if _, err := store.Logout(t.Context(), verified, false, at, at.Add(time.Hour), skew); !errors.Is(err, session.ErrState) {
				t.Fatal("invalid clock skew accepted", err)
			}
			if !store.Active(t.Context(), "active", at) {
				t.Fatal("invalid clock skew invalidated the session")
			}
			if _, err := store.Logout(t.Context(), verified, false, at, at.Add(time.Hour), 0); err != nil {
				t.Fatal("invalid clock skew consumed replay state", err)
			}
		})
	}
}
