package idp //nolint:testpackage // Exercises response orchestration with isolated metadata and replay adapters.

import (
	"bytes"
	"context"
	"crypto"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/skarm/xmlsec/internal/testutil/testcert"
	"github.com/skarm/xmlsec/saml/binding"
	"github.com/skarm/xmlsec/saml/metadata"
	"github.com/skarm/xmlsec/saml/protocol"
	"github.com/skarm/xmlsec/saml/replay"
	"github.com/skarm/xmlsec/xmldsig"
)

type issuanceReplayStore struct {
	entries []replay.Entry
	at      time.Time
	calls   int
	err     error
}

func (store *issuanceReplayStore) Consume(_ context.Context, entries []replay.Entry, at time.Time) error {
	store.calls++
	store.at = at
	store.entries = slices.Clone(entries)
	return store.err
}

func issuanceConfig(t *testing.T, responseBinding string, idpExpiry, spExpiry time.Time) (Config, protocol.SigningKey) {
	t.Helper()
	chain := testcert.New(t)
	idpSigner := protocol.SigningKey{Key: chain.LeafKey, CertificateDER: chain.Leaf.Raw}
	spSigner := protocol.SigningKey{Key: chain.ResponderKey, CertificateDER: chain.Responder.Raw}
	entities := make(map[string]*metadata.Entity)
	for _, spec := range []metadata.EntityDescriptor{
		{
			ID: "_idp", EntityID: idpEntityID, ValidUntil: idpExpiry,
			IDP: &metadata.RoleDescriptor{
				Keys: []metadata.KeyDescriptor{{Use: "signing", CertificateDER: idpSigner.CertificateDER}},
				Endpoints: map[string][]metadata.Endpoint{
					metadata.SingleSignOnService: {
						{Binding: metadata.HTTPPost, Location: singleSignOnURL},
						{Binding: metadata.HTTPRedirect, Location: singleSignOnURL},
						{Binding: metadata.HTTPArtifact, Location: singleSignOnURL},
						{Binding: metadata.SOAP, Location: singleSignOnURL},
					},
				},
			},
		},
		{
			ID: "_sp", EntityID: spEntityID, ValidUntil: spExpiry,
			SP: &metadata.RoleDescriptor{
				Keys: []metadata.KeyDescriptor{{Use: "signing", CertificateDER: spSigner.CertificateDER}},
				Endpoints: map[string][]metadata.Endpoint{
					metadata.AssertionConsumerService: {{Binding: responseBinding, Location: assertionConsumerURL, Indexed: true}},
				},
			},
		},
	} {
		doc, err := metadata.Build(t.Context(), spec, testcert.Now(), metadata.Options{})
		if err != nil {
			t.Fatal(err)
		}
		raw, err := doc.XML(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		snapshot, err := metadata.ParseTrusted(t.Context(), raw, testcert.Now(), metadata.Options{})
		if err != nil {
			t.Fatal(err)
		}
		entity, err := snapshot.Find(spec.EntityID, testcert.Now())
		if err != nil {
			t.Fatal(err)
		}
		entities[spec.EntityID] = entity
	}
	return Config{
		EntityID:       idpEntityID,
		Metadata:       &metadataResolverSpy{entities: entities},
		Signing:        idpSigner,
		Limits:         protocol.Limits{MaxMessageAge: 30 * time.Second, ClockSkew: time.Second},
		RedirectLimits: binding.Options{SignatureMethod: xmldsig.ECDSASHA256},
	}, spSigner
}

func TestAcceptBindingPreservesAuthenticatedRequest(t *testing.T) {
	t.Parallel()
	const requestID = "_binding_request"
	relay := "state +/"
	at := testcert.Now()
	for _, tc := range []struct {
		name, responseBinding string
		accept                func(*testing.T, *IdentityProvider, protocol.AuthnRequest, protocol.SigningKey) (*Request, error)
		wantRelay             *string
	}{
		{"post", metadata.HTTPPost, func(t *testing.T, provider *IdentityProvider, spec protocol.AuthnRequest, key protocol.SigningKey) (*Request, error) {
			t.Helper()
			doc, err := protocol.SignAuthnRequest(t.Context(), spec, key)
			if err != nil {
				t.Fatal(err)
			}
			form, err := binding.EncodePOST(t.Context(), doc, binding.Request, &relay, binding.POSTLimits{})
			if err != nil {
				t.Fatal(err)
			}
			return provider.AcceptPOST(t.Context(), form, spEntityID, singleSignOnURL, at)
		}, &relay},
		{"redirect", metadata.HTTPPost, func(t *testing.T, provider *IdentityProvider, spec protocol.AuthnRequest, key protocol.SigningKey) (*Request, error) {
			t.Helper()
			doc, err := protocol.BuildAuthnRequest(t.Context(), spec)
			if err != nil {
				t.Fatal(err)
			}
			query, err := binding.SignRedirect(t.Context(), doc, binding.Request, &relay, key.Key, binding.Options{SignatureMethod: xmldsig.ECDSASHA256})
			if err != nil {
				t.Fatal(err)
			}
			return provider.AcceptRedirect(t.Context(), query, spEntityID, singleSignOnURL, at)
		}, &relay},
		{"artifact", metadata.HTTPArtifact, func(t *testing.T, provider *IdentityProvider, spec protocol.AuthnRequest, key protocol.SigningKey) (*Request, error) {
			t.Helper()
			doc, err := protocol.SignAuthnRequest(t.Context(), spec, key)
			if err != nil {
				t.Fatal(err)
			}
			return provider.AcceptArtifact(t.Context(), doc, &relay, spEntityID, singleSignOnURL, at)
		}, &relay},
		{"soap", metadata.PAOS, func(t *testing.T, provider *IdentityProvider, spec protocol.AuthnRequest, key protocol.SigningKey) (*Request, error) {
			t.Helper()
			doc, err := protocol.SignAuthnRequest(t.Context(), spec, key)
			if err != nil {
				t.Fatal(err)
			}
			envelope, err := binding.WrapSOAP(t.Context(), doc)
			if err != nil {
				t.Fatal(err)
			}
			raw, err := envelope.XML(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			return provider.AcceptSOAP(t.Context(), raw, spEntityID, singleSignOnURL, at)
		}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			config, signer := issuanceConfig(t, tc.responseBinding, at.Add(time.Hour), at.Add(time.Hour))
			store := &issuanceReplayStore{}
			config.Replay = store
			provider, err := NewIdentityProvider(config)
			if err != nil {
				t.Fatal(err)
			}
			spec := protocol.AuthnRequest{ID: requestID, Issuer: spEntityID, Destination: singleSignOnURL, ACS: assertionConsumerURL, IssueInstant: at, ResponseBinding: tc.responseBinding, NameIDFormat: protocol.NameIDTransient, SOAPContext: tc.responseBinding != metadata.HTTPPost}
			request, err := tc.accept(t, provider, spec, signer)
			if err != nil || request == nil {
				t.Fatalf("accept request: got %v, %v, want an authenticated request", request, err)
			}
			if request.ID() != requestID || request.SP() != spEntityID || request.ACS() != assertionConsumerURL || request.RequestedNameIDFormat() != protocol.NameIDTransient || !request.ExpiresAt().Equal(at.Add(31*time.Second)) {
				t.Errorf("accepted ID=%q, SP=%q, ACS=%q, format=%q, expiry=%v", request.ID(), request.SP(), request.ACS(), request.RequestedNameIDFormat(), request.ExpiresAt())
			}
			if tc.wantRelay == nil && request.relayPresent || tc.wantRelay != nil && (!request.relayPresent || request.relay != *tc.wantRelay) {
				t.Errorf("accepted RelayState=%q, present=%t, want %v", request.relay, request.relayPresent, tc.wantRelay)
			}
			if store.calls != 0 {
				t.Errorf("accept called replay adapter %d times before issuing a response", store.calls)
			}
		})
	}
}

func TestIssueLimitsAssertionLifetimeAndCommitsReplay(t *testing.T) {
	t.Parallel()
	at := testcert.Now()
	for _, tc := range []struct {
		name                 string
		lifetime, idp, sp    time.Duration
		assertion, retention time.Duration
	}{
		{"configured_lifetime", 90 * time.Second, time.Hour, time.Hour, 90 * time.Second, 91 * time.Second},
		{"idp_metadata_expires_first", 90 * time.Second, 20 * time.Second, time.Hour, 20 * time.Second, 31 * time.Second},
		{"sp_metadata_expires_first", 90 * time.Second, time.Hour, 25 * time.Second, 25 * time.Second, 31 * time.Second},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			config, _ := issuanceConfig(t, metadata.HTTPPost, at.Add(tc.idp), at.Add(tc.sp))
			store := &issuanceReplayStore{}
			config.Replay = store
			config.AssertionLifetime = tc.lifetime
			provider, err := NewIdentityProvider(config)
			if err != nil {
				t.Fatal(err)
			}
			request, err := provider.wrap(signedAndVerifiedRequest(t, false, false, false), "opaque", true, at)
			if err != nil {
				t.Fatal(err)
			}
			auth := Authentication{NameID: "alice", AuthnInstant: at, AuthnContext: authenticationContext, SessionIndex: "session-one"}
			issued, err := provider.Issue(t.Context(), request, auth, at)
			if err != nil || issued == nil {
				t.Fatalf("Issue = %v, %v", issued, err)
			}
			if issued.Destination() != assertionConsumerURL || issued.Document() == nil {
				t.Fatalf("issued response destination=%q, document present=%t", issued.Destination(), issued.Document() != nil)
			}
			var form bytes.Buffer
			if n, err := issued.WritePOST(t.Context(), &form); err != nil || n != int64(form.Len()) {
				t.Fatalf("WritePOST wrote %d bytes, buffer contains %d, error=%v", n, form.Len(), err)
			}
			message, err := binding.DecodePOST(t.Context(), form.Bytes(), binding.Response, binding.POSTLimits{})
			if err != nil {
				t.Fatal(err)
			}
			if got, present := message.RelayState(); got != "opaque" || !present {
				t.Errorf("response RelayState=%q, present=%t, want opaque", got, present)
			}
			verified, err := protocol.VerifyResponse(t.Context(), message.UnverifiedDocument(), []crypto.PublicKey{config.Signing.Key.Public()}, issuanceResponseOptions(request.ID(), at))
			if err != nil {
				t.Fatal(err)
			}
			if verified.NameID() != "alice" || verified.SessionIndex() != "session-one" || verified.AuthnContext() != authenticationContext || verified.NameIDFormat() != protocol.NameIDUnspecified || !verified.NotOnOrAfter().Equal(at.Add(tc.assertion)) {
				t.Errorf("signed assertion subject=%q, session=%q, context=%q, format=%q, expiry=%v (want %v)", verified.NameID(), verified.SessionIndex(), verified.AuthnContext(), verified.NameIDFormat(), verified.NotOnOrAfter(), at.Add(tc.assertion))
			}
			if store.calls != 1 || !store.at.Equal(at) || len(store.entries) != 1 || store.entries[0].ID != request.ID() || store.entries[0].Scope == "" || !store.entries[0].ExpiresAt.Equal(at.Add(tc.retention)) {
				t.Errorf("replay calls=%d at %v, entries=%+v, want one entry for %q expiring at %v", store.calls, store.at, store.entries, request.ID(), at.Add(tc.retention))
			}
			store.err = replay.ErrReplay
			if again, err := provider.Issue(t.Context(), request, auth, at); again != nil || !errors.Is(err, replay.ErrReplay) {
				t.Errorf("Issue after replay adapter rejection = %v, %v, want nil, %v", again, err, replay.ErrReplay)
			}
		})
	}
}

func TestRejectSignsFailureBeforeConsumingRequest(t *testing.T) {
	t.Parallel()
	at := testcert.Now()
	config, _ := issuanceConfig(t, metadata.HTTPPost, at.Add(time.Hour), at.Add(time.Hour))
	store := &issuanceReplayStore{}
	config.Replay = store
	provider, err := NewIdentityProvider(config)
	if err != nil {
		t.Fatal(err)
	}
	request, err := provider.wrap(signedAndVerifiedRequest(t, false, false, false), "", false, at)
	if err != nil {
		t.Fatal(err)
	}
	if issued, err := provider.Reject(t.Context(), request, protocol.Status{Code: protocol.Success}, at); issued != nil || !errors.Is(err, ErrPolicy) || store.calls != 0 {
		t.Fatalf("Reject with success status returned %v, %v and made %d replay calls", issued, err, store.calls)
	}
	const failure = "urn:oasis:names:tc:SAML:2.0:status:AuthnFailed"
	status := protocol.Status{Code: protocol.Responder, Subcodes: []string{failure}, Message: "authentication failed"}
	provider.c.POSTLimits.MaxFormBytes = 16
	if issued, err := provider.Reject(t.Context(), request, status, at); issued != nil || !errors.Is(err, binding.ErrBinding) || store.calls != 0 {
		t.Fatalf("Reject with insufficient POST budget returned %v, %v and made %d replay calls", issued, err, store.calls)
	}
	provider.c.POSTLimits = binding.POSTLimits{}
	issued, err := provider.Reject(t.Context(), request, status, at)
	if err != nil || issued == nil || store.calls != 1 {
		t.Fatalf("Reject returned %v, %v and made %d replay calls, want one signed failure", issued, err, store.calls)
	}
	verified, err := protocol.VerifyResponse(t.Context(), issued.Document(), []crypto.PublicKey{config.Signing.Key.Public()}, issuanceResponseOptions(request.ID(), at))
	var statusErr *protocol.StatusError
	if verified != nil || !errors.As(err, &statusErr) || statusErr.Code != protocol.Responder || !slices.Equal(statusErr.Subcodes, []string{failure}) || statusErr.Message != "authentication failed" {
		t.Errorf("signed rejection produced assertion=%v, status error=%+v, error=%v", verified, statusErr, err)
	}
}

func issuanceResponseOptions(id string, at time.Time) protocol.ResponseOptions {
	return protocol.ResponseOptions{Issuer: idpEntityID, Audience: spEntityID, Destination: assertionConsumerURL, ExpectedRequestID: id, At: at}
}
