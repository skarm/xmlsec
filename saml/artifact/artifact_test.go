package artifact_test

import (
	"crypto"
	"errors"
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
	issuer := artifact.Issuer{EntityID: issuerID, ReturnEndpoint: destination, EndpointIndex: 7, Signing: key, Store: store}
	opaqueSource := [20]byte{0x81, 0x23, 0x47}
	issuer.SourceID = &opaqueSource
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(2 * time.Millisecond)
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
		if _, err := strict.Respond(r.Context(), verified, at.Add(2*time.Second)); err == nil {
			t.Error("held ArtifactResolve bypassed the responder's freshness policy")
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
		t.Fatal("wrong-recipient disclosure")
	}
	if _, err := store.Resolve(t.Context(), a, entry.Recipient, at, func(*document.Document) (*document.Document, error) { return nil, errors.New("signing failed") }); err == nil {
		t.Fatal("callback failure ignored")
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
				successes.Add(1)
			}
		})
	}
	wg.Wait()
	if successes.Load() != 1 {
		t.Fatal("artifact not single-use")
	}
	if err := store.Put(t.Context(), entry, at); err == nil {
		t.Fatal("consumed handle was reinserted")
	}
	if m, err := store.Take(t.Context(), a, entry.Recipient, entry.ExpiresAt); err != nil || m != nil {
		t.Fatal("expired artifact")
	}
}

func TestInvalidArtifactReturnsEmptySuccess(t *testing.T) {
	at := testcert.Now()
	c := testcert.New(t)
	key := protocol.SigningKey{Key: c.LeafKey, CertificateDER: c.Leaf.Raw}
	store, _ := artifact.NewMemoryStore(10)
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
