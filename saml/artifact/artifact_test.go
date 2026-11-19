package artifact_test

import (
	"context"
	"crypto"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/internal/testutil/testcert"
	"github.com/skarm/xmlsec/saml/artifact"
	"github.com/skarm/xmlsec/saml/binding"
	"github.com/skarm/xmlsec/saml/metadata"
	"github.com/skarm/xmlsec/saml/protocol"
)

// issueStore exposes just the operations required by Issuer.
type issueStore struct {
	PutFunc     func(context.Context, artifact.Entry, time.Time) error
	ResolveFunc func(context.Context, binding.Artifact, string, time.Time, func(*document.Document) (*document.Document, error)) (*document.Document, error)
}

func (s issueStore) Put(ctx context.Context, e artifact.Entry, at time.Time) error {
	return s.PutFunc(ctx, e, at)
}

func (s issueStore) Resolve(ctx context.Context, a binding.Artifact, recipient string, at time.Time, reply func(*document.Document) (*document.Document, error)) (*document.Document, error) {
	return s.ResolveFunc(ctx, a, recipient, at, reply)
}

type artifactTransportFunc func(*http.Request) (*http.Response, error)

func (f artifactTransportFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type artifactCountingSigner struct {
	crypto.Signer
	calls int
}

func (s *artifactCountingSigner) Sign(random io.Reader, digest []byte, options crypto.SignerOpts) ([]byte, error) {
	s.calls++
	return s.Signer.Sign(random, digest, options)
}

func TestResolverValidatesResponseConfigurationBeforeContactingPeer(t *testing.T) {
	t.Parallel()
	const peer = "urn:example:artifact-provider"
	const recipient = "urn:example:recipient"
	a, err := binding.NewArtifact(peer, 7)
	if err != nil {
		t.Fatal(err)
	}
	transportReached := errors.New("test transport reached")
	for _, tc := range []struct {
		name, returnEndpoint string
		keyCount             int
		limits               protocol.Limits
		wantErr              error
	}{
		{name: "missing peer keys", wantErr: protocol.ErrSignature},
		{name: "too many peer keys", keyCount: 17, wantErr: protocol.ErrSignature},
		{name: "invalid response limits", keyCount: 1, limits: protocol.Limits{MaxMessageAge: -time.Second}, wantErr: protocol.ErrProfile},
		{name: "relative response endpoint", keyCount: 1, returnEndpoint: "artifact/return", wantErr: protocol.ErrProfile},
		{name: "default response endpoint", keyCount: 1, wantErr: transportReached},
		{name: "maximum key count and HTTP response endpoint", keyCount: 16, returnEndpoint: "http://recipient.example.test/artifact", wantErr: transportReached},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			key := testcert.Key(t)
			signer := &artifactCountingSigner{Signer: key}
			var crossings int
			keys := make([]crypto.PublicKey, tc.keyCount)
			for i := range keys {
				keys[i] = key.Public()
			}
			resolver := artifact.Resolver{
				EntityID: recipient, PeerEntityID: peer, ReturnEndpoint: tc.returnEndpoint, Signing: protocol.SigningKey{Key: signer},
				Endpoints: []metadata.Endpoint{{Binding: metadata.SOAP, Location: "https://provider.example.test/artifact", Index: 7, Indexed: true}},
				Keys:      keys, Options: protocol.ExchangeOptions{Limits: tc.limits},
				SOAP: binding.SOAPClient{Client: &http.Client{Transport: artifactTransportFunc(func(*http.Request) (*http.Response, error) {
					crossings++
					return nil, transportReached
				})}},
			}
			result, err := resolver.Resolve(t.Context(), a, testcert.Now())
			if result != nil || !errors.Is(err, tc.wantErr) {
				t.Errorf("Resolve = %p, %v; want nil, %v", result, err, tc.wantErr)
			}
			if errors.Is(tc.wantErr, transportReached) {
				if crossings != 1 || signer.calls == 0 {
					t.Errorf("valid configuration reached signer %d times and transport %d times", signer.calls, crossings)
				}
			} else if crossings != 0 || signer.calls != 0 {
				t.Errorf("invalid configuration reached signer %d times and transport %d times", signer.calls, crossings)
			}
		})
	}
}

func TestAuthenticatedArtifactSOAP(t *testing.T) {
	at := testcert.Now()
	cert := testcert.New(t)
	const issuerID = "https://idp.test/entity"
	const recipientID = "https://sp.test/entity"
	const destination = "https://sp.test/acs"
	key := protocol.SigningKey{Key: cert.LeafKey, CertificateDER: cert.Leaf.Raw}
	peerKey := protocol.SigningKey{Key: cert.TSAKey, CertificateDER: cert.TSA.Raw}
	store, err := artifact.NewMemoryStore(10)
	if err != nil {
		t.Fatal(err)
	}
	issuer := artifact.Issuer{EntityID: issuerID, ReturnEndpoint: destination, EndpointIndex: 7, Signing: key, Store: issueStore{PutFunc: store.Put, ResolveFunc: store.Resolve}}
	opaqueSource := [20]byte{0x81, 0x23, 0x47}
	issuer.SourceID = &opaqueSource
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
		verified, err := protocol.VerifyArtifactResolve(r.Context(), d, []crypto.PublicKey{cert.TSAKey.Public()}, protocol.ExchangeOptions{Issuer: recipientID, Destination: issuer.Endpoint, At: at})
		if err != nil {
			t.Error(err)
			return
		}
		strict := issuer
		strict.Limits.MaxMessageAge = time.Second
		if _, err := strict.Respond(r.Context(), verified, at.Add(2*time.Second)); !errors.Is(err, artifact.ErrArtifact) {
			t.Errorf("stale ArtifactResolve returned %v, want %v", err, artifact.ErrArtifact)
			return
		}
		response, err := issuer.Respond(r.Context(), verified, at.Add(time.Millisecond))
		if err != nil {
			t.Error(err)
			return
		}
		envelope, err := protocol.SignSOAP(r.Context(), response, key)
		if err != nil {
			t.Error(err)
			return
		}
		if err := binding.WriteSOAPResponse(r.Context(), w, envelope); err != nil {
			t.Error(err)
		}
	}))
	defer server.Close()
	issuer.Endpoint = server.URL
	message, err := protocol.SignLogoutRequest(t.Context(), protocol.LogoutRequest{ID: "_embedded", Issuer: issuerID, Destination: destination, IssueInstant: at, NameID: protocol.NameIdentifier{Value: "alice"}, NotOnOrAfter: at.Add(time.Minute)}, key)
	if err != nil {
		t.Fatal(err)
	}
	a, err := issuer.Issue(t.Context(), message, recipientID, at, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	resolver := artifact.Resolver{EntityID: recipientID, PeerEntityID: issuerID, ReturnEndpoint: destination, Endpoints: []metadata.Endpoint{{Binding: metadata.SOAP, Location: server.URL, Index: 7, Indexed: true}}, Signing: peerKey, Keys: []crypto.PublicKey{cert.LeafKey.Public()}, SOAP: binding.SOAPClient{AllowHTTP: true}}
	resolver.SourceID = &opaqueSource
	resolved, err := resolver.Resolve(t.Context(), a, at)
	if err != nil || resolved == nil {
		t.Fatalf("resolve: %v", err)
	}
	logout, err := protocol.VerifyLogoutRequest(t.Context(), resolved, resolver.Keys, protocol.ExchangeOptions{Issuer: issuerID, Destination: destination, At: at})
	if err != nil || logout.Request().ID != "_embedded" || logout.Request().NameID.Value != "alice" {
		t.Fatalf("embedded protocol lost: %v", err)
	}
	empty, err := resolver.Resolve(t.Context(), a, at)
	if err != nil || empty != nil {
		t.Fatalf("reused artifact must yield empty Success: %v", err)
	}
	a.EndpointIndex = 9
	if _, err := resolver.Resolve(t.Context(), a, at); err == nil {
		t.Fatal("unknown index")
	}
	a.EndpointIndex = 7
	a.SourceID[0] ^= 1
	if _, err := resolver.Resolve(t.Context(), a, at); err == nil {
		t.Fatal("untrusted source")
	}
}

func TestArtifactAtomicRecipientAndExpiry(t *testing.T) {
	at := testcert.Now()
	c := testcert.New(t)
	d, err := protocol.SignArtifactResolve(t.Context(), protocol.ArtifactResolve{Issuer: "https://issuer.test", Destination: "https://peer.test/ars", IssueInstant: at, Artifact: "opaque"}, protocol.SigningKey{Key: c.LeafKey, CertificateDER: c.Leaf.Raw})
	if err != nil {
		t.Fatal(err)
	}
	store, err := artifact.NewMemoryStore(1)
	if err != nil {
		t.Fatal(err)
	}
	a, err := binding.NewArtifact("https://issuer.test", 0)
	if err != nil {
		t.Fatal(err)
	}
	entry := artifact.Entry{Artifact: a, Recipient: "https://peer.test", Message: d, ExpiresAt: at.Add(time.Minute)}
	if err := store.Put(t.Context(), entry, at); err != nil {
		t.Fatal(err)
	}
	if m, err := store.Take(t.Context(), a, "https://attacker.test", at); err != nil || m != nil {
		t.Fatalf("Take for wrong recipient returned message=%p, err=%v; want nil, nil", m, err)
	}
	signingFailure := errors.New("signing failed")
	response, err := store.Resolve(t.Context(), a, entry.Recipient, at, func(message *document.Document) (*document.Document, error) {
		if message != d {
			t.Errorf("Resolve callback received message=%p, want %p", message, d)
		}
		return nil, signingFailure
	})
	if response != nil || !errors.Is(err, signingFailure) {
		t.Fatalf("Resolve after signing failure returned response=%p, err=%v; want nil, %v", response, err, signingFailure)
	}
	var successes atomic.Int32
	var wg sync.WaitGroup
	for range 32 {
		wg.Go(func() {
			m, err := store.Take(t.Context(), a, entry.Recipient, at)
			if err != nil {
				t.Error(err)
			}
			if m != nil {
				if m != d {
					t.Errorf("Take returned message=%p, want %p", m, d)
				}
				successes.Add(1)
			}
		})
	}
	wg.Wait()
	if got := successes.Load(); got != 1 {
		t.Fatalf("successful Take calls = %d, want 1", got)
	}
	if err := store.Put(t.Context(), entry, at); err == nil {
		t.Fatal("consumed handle was reinserted")
	}
	for _, tc := range []struct {
		name      string
		checkTime time.Time
		want      *document.Document
	}{
		{"before_expiry", entry.ExpiresAt.Add(-time.Nanosecond), d},
		{"at_expiry", entry.ExpiresAt, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store, err := artifact.NewMemoryStore(1)
			if err != nil {
				t.Fatal(err)
			}
			if err := store.Put(t.Context(), entry, at); err != nil {
				t.Fatal(err)
			}
			m, err := store.Take(t.Context(), a, entry.Recipient, tc.checkTime)
			if err != nil || m != tc.want {
				t.Fatalf("Take returned message=%p, err=%v; want %p, nil", m, err, tc.want)
			}
		})
	}
}

func TestInvalidArtifactReturnsEmptySuccess(t *testing.T) {
	at := testcert.Now()
	c := testcert.New(t)
	key := protocol.SigningKey{Key: c.LeafKey, CertificateDER: c.Leaf.Raw}
	store, err := artifact.NewMemoryStore(10)
	if err != nil {
		t.Fatal(err)
	}
	issuer := artifact.Issuer{EntityID: "https://idp.test/entity", Endpoint: "https://idp.test/ars", ReturnEndpoint: "https://sp.test/return", Store: store, Signing: key}
	for _, value := range []string{"", "unrecognized-artifact"} {
		d, err := protocol.SignArtifactResolve(t.Context(), protocol.ArtifactResolve{ID: "_resolve_invalid", Issuer: "https://sp.test/entity", Destination: issuer.Endpoint, IssueInstant: at, Artifact: value}, key)
		if err != nil {
			t.Fatal(err)
		}
		r, err := protocol.VerifyArtifactResolve(t.Context(), d, []crypto.PublicKey{key.Key.Public()}, protocol.ExchangeOptions{Issuer: "https://sp.test/entity", Destination: issuer.Endpoint, At: at})
		if err != nil {
			t.Fatal(err)
		}
		reply, err := issuer.Respond(t.Context(), r, at)
		if err != nil {
			t.Fatal(err)
		}
		verified, err := protocol.VerifyStatusResponse(t.Context(), reply, []crypto.PublicKey{key.Key.Public()}, protocol.ExchangeOptions{Issuer: issuer.EntityID, Destination: issuer.ReturnEndpoint, ExpectedRequestID: "_resolve_invalid", At: at})
		if err != nil || verified.Status().Code != protocol.Success || verified.Message() != nil {
			t.Fatalf("unknown artifact: %v", err)
		}
	}
}
