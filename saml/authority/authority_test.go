package authority //nolint:testpackage // This suite also checks cancellation while holding the private store lock.

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/internal/testutil/testcert"
	"github.com/skarm/xmlsec/saml/binding"
	"github.com/skarm/xmlsec/saml/metadata"
	"github.com/skarm/xmlsec/saml/protocol"
	"github.com/skarm/xmlsec/saml/replay"
)

const (
	requester = "https://requester.test/entity"
	issuer    = "https://authority.test/entity"
)

func parsed(t *testing.T, s string) *document.Document {
	t.Helper()
	d, err := document.Parse(t.Context(), []byte(s), document.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func replayStore(t *testing.T) replay.Store {
	t.Helper()
	s, err := replay.NewMemoryStore(replay.Config{})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// An actual HTTPS SOAP exchange exercises trusted metadata, all three authority
// roles, AssertionIDRequest, opaque target mapping, URI retrieval and replay.
func TestAuthoritySOAPAndURI(t *testing.T) {
	c, caller := testcert.New(t), testcert.New(t)
	at := testcert.Now()
	key := protocol.SigningKey{Key: c.LeafKey}
	callerKey := protocol.SigningKey{Key: caller.LeafKey}
	target, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	sub, _ := protocol.NewSubject(t.Context(), protocol.NameIdentifier{Value: "alice"})
	statement := parsed(t, `<saml:AttributeStatement xmlns:saml="`+protocol.AssertionNamespace+`"><saml:Attribute Name="role"><saml:AttributeValue>reader</saml:AttributeValue></saml:Attribute></saml:AttributeStatement>`)
	assertion, err := protocol.SignAuthorityAssertion(t.Context(), protocol.AuthorityAssertion{ID: "_held", Issuer: issuer, IssueInstant: at, Subject: sub, Statements: []*document.Document{statement}}, key)
	if err != nil {
		t.Fatal(err)
	}
	bulk := make([]*document.Document, 0, 20)
	conditions := parsed(t, `<saml:Conditions xmlns:saml="`+protocol.AssertionNamespace+`" NotOnOrAfter="`+at.Add(time.Minute).Format(time.RFC3339)+`"><saml:OneTimeUse/></saml:Conditions>`)
	for i := range 20 {
		a, err := protocol.SignAuthorityAssertion(t.Context(), protocol.AuthorityAssertion{ID: "_bulk_assertion_" + strconv.Itoa(i), Issuer: issuer, IssueInstant: at, Subject: sub, Statements: []*document.Document{statement}, Conditions: conditions}, key)
		if err != nil {
			t.Fatal(err)
		}
		bulk = append(bulk, a)
	}
	store, _ := NewMemoryAssertions(4)
	if err = store.Add(t.Context(), assertion); err != nil {
		t.Fatal(err)
	}
	var service *Service
	var calls atomic.Int32
	mux := http.NewServeMux()
	mux.HandleFunc("/soap", func(w http.ResponseWriter, r *http.Request) {
		m, err := binding.ReadSOAPRequest(r.Context(), r, binding.SOAPOptions{})
		if err != nil {
			http.Error(w, "SOAP", 400)
			return
		}
		d, _ := m.Payload(r.Context())
		out, err := service.Respond(r.Context(), d, requester, at)
		if err != nil {
			http.Error(w, "denied", http.StatusForbidden)
			return
		}
		if err = binding.WriteSOAPResponse(r.Context(), w, out); err != nil {
			t.Error(err)
		}
	})
	mux.Handle("/assertion", URIHandler{Authenticate: func(r *http.Request) (string, error) {
		u, p, ok := r.BasicAuth()
		if !ok || u != "alice" || p != "secret" {
			return "", ErrDenied
		}
		return requester, nil
	}, Lookup: func(ctx context.Context, peer, id string) (*document.Document, error) {
		if peer != requester {
			return nil, ErrDenied
		}
		return store.Get(ctx, id)
	}})
	server := httptest.NewTLSServer(mux)
	defer server.Close()
	trust := func(_ context.Context, peer string, _ time.Time) ([]crypto.PublicKey, error) {
		switch peer {
		case requester:
			return []crypto.PublicKey{caller.LeafKey.Public()}, nil
		case issuer:
			return []crypto.PublicKey{c.LeafKey.Public()}, nil
		default:
			return nil, ErrDenied
		}
	}
	service, err = NewService(Config{EntityID: issuer, Endpoint: server.URL + "/soap", Signing: key, Trust: trust, Replay: replayStore(t), Kinds: []protocol.QueryKind{protocol.AttributeQuery, protocol.AuthenticationQuery, protocol.AuthorizationQuery, protocol.AssertionRequest}, Query: func(ctx context.Context, v *protocol.VerifiedQuery) ([]*document.Document, error) {
		calls.Add(1)
		q := v.Query()
		if q.ID == "_bulk" || q.ID == "_bulk_again" {
			return bulk, nil
		}
		if q.Kind == protocol.AttributeQuery || q.Kind == protocol.AssertionRequest {
			return []*document.Document{assertion}, nil
		}
		return nil, nil
	}, Mapping: func(ctx context.Context, v *protocol.VerifiedNameIDMappingRequest) (*document.Document, error) {
		calls.Add(1)
		q := v.Request()
		id, err := protocol.NameIDDocument(ctx, protocol.NameIdentifier{Value: "target-alice", Format: q.Policy.Format, SPNameQualifier: q.Policy.SPNameQualifier})
		if err != nil {
			return nil, err
		}
		return protocol.EncryptMappedIdentifier(ctx, id, &protocol.EncryptionOptions{Targets: protocol.EncryptNameID, Recipient: &target.PublicKey})
	}})
	if err != nil {
		t.Fatal(err)
	}
	roles := func(service string) *metadata.RoleDescriptor {
		return &metadata.RoleDescriptor{Keys: []metadata.KeyDescriptor{{CertificateDER: c.Leaf.Raw}}, Endpoints: map[string][]metadata.Endpoint{service: {{Binding: metadata.SOAP, Location: server.URL + "/soap"}}, metadata.AssertionIDRequestService: {{Binding: metadata.SOAP, Location: server.URL + "/soap"}, {Binding: metadata.URI, Location: server.URL + "/assertion"}}}}
	}
	spec := metadata.EntityDescriptor{EntityID: issuer, ValidUntil: at.Add(time.Hour), AuthnAuthority: roles(metadata.AuthnQueryService), AttributeAuthority: roles(metadata.AttributeService), PDP: roles(metadata.AuthzService), IDP: &metadata.RoleDescriptor{Keys: []metadata.KeyDescriptor{{CertificateDER: c.Leaf.Raw}}, Endpoints: map[string][]metadata.Endpoint{metadata.SingleSignOnService: {{Binding: metadata.SOAP, Location: server.URL + "/soap"}}, metadata.NameIDMappingService: {{Binding: metadata.SOAP, Location: server.URL + "/soap"}}}}}
	md, err := metadata.Build(t.Context(), spec, at, metadata.Options{})
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := md.XML(t.Context())
	snapshot, err := metadata.ParseTrusted(t.Context(), raw, at, metadata.Options{})
	if err != nil {
		t.Fatal(err)
	}
	client := Client{EntityID: requester, Peer: issuer, Role: metadata.AttributeAuthority, Metadata: snapshot, Signing: callerKey, Replay: replayStore(t), SOAP: binding.SOAPClient{Client: server.Client()}}
	q := protocol.Query{ID: "_call", Kind: protocol.AttributeQuery, Subject: sub}
	r, err := client.Query(t.Context(), q, at)
	if err != nil || len(r.Assertions()) != 1 {
		t.Fatalf("attribute SOAP: %v", err)
	}
	if _, err = client.Query(t.Context(), q, at); err == nil {
		t.Fatal("same signed request executed twice")
	}
	if calls.Load() != 1 {
		t.Fatalf("backend replayed: %d", calls.Load())
	}
	q.ID = "_by_id"
	q.Kind = protocol.AssertionRequest
	q.Subject = nil
	q.AssertionIDs = []string{"_held"}
	if r, err = client.Query(t.Context(), q, at); err != nil || r.Assertions()[0].ID() != "_held" {
		t.Fatalf("assertion ID SOAP: %v", err)
	}
	for _, test := range []struct {
		kind protocol.QueryKind
		role metadata.RoleType
	}{{protocol.AuthenticationQuery, metadata.AuthenticationAuthority}, {protocol.AuthorizationQuery, metadata.PolicyDecisionPoint}} {
		client.Role = test.role
		q = protocol.Query{Kind: test.kind, Subject: sub}
		if test.kind == protocol.AuthorizationQuery {
			q.Resource = "urn:test:resource"
			q.Actions = []protocol.Action{{Value: "Read"}}
		}
		if r, err = client.Query(t.Context(), q, at); err != nil || len(r.Assertions()) != 0 || r.Status().Code != protocol.Success {
			t.Fatalf("empty %s: %v", test.kind, err)
		}
	}
	client.Role = metadata.IdentityProvider
	mapped, err := client.Map(t.Context(), protocol.NameIDMappingRequest{NameID: protocol.NameIdentifier{Value: "alice"}, Policy: protocol.NameIDPolicy{Format: protocol.NameIDPersistent, SPNameQualifier: "https://target.test/entity", AllowCreate: true}}, at)
	if err != nil {
		t.Fatal(err)
	}
	id, err := protocol.DecryptMappedNameID(t.Context(), mapped.Identifier(), &protocol.DecryptionOptions{Keys: []crypto.Decrypter{target}})
	if err != nil || id.Value != "target-alice" {
		t.Fatalf("mapped target: %v", err)
	}
	client.Role = metadata.AttributeAuthority
	client.URI = binding.URIClient{Client: &http.Client{Transport: basicTransport{base: server.Client().Transport}}}
	a, err := client.Assertion(t.Context(), "_held", at)
	if err != nil || a.ID() != "_held" {
		t.Fatalf("URI assertion: %v", err)
	}
	if _, err = client.Assertion(t.Context(), "_absent", at); err == nil {
		t.Fatal("unknown URI assertion accepted")
	}
	client.URI.Client = server.Client()
	if _, err = client.Assertion(t.Context(), "_held", at); err == nil {
		t.Fatal("unauthenticated URI disclosure")
	}
	if err = store.Add(t.Context(), assertion); err != nil {
		t.Fatal(err)
	}
	other, _ := protocol.SignAuthorityAssertion(t.Context(), protocol.AuthorityAssertion{ID: "_held", Issuer: issuer, IssueInstant: at, Subject: sub}, key)
	if err = store.Add(t.Context(), other); !errors.Is(err, ErrDenied) {
		t.Fatal("URI rebound to different assertion")
	}
	q = protocol.Query{ID: "_bulk", Kind: protocol.AttributeQuery, Subject: sub}
	if r, err = client.Query(t.Context(), q, at); err != nil || len(r.Assertions()) != len(bulk) {
		t.Fatalf("large OneTimeUse response: %v", err)
	}
	q.ID = "_bulk_again"
	if _, err = client.Query(t.Context(), q, at); !errors.Is(err, replay.ErrReplay) {
		t.Fatalf("OneTimeUse assertion reused in a new response: %v", err)
	}
}

type basicTransport struct{ base http.RoundTripper }

func (b basicTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.SetBasicAuth("alice", "secret")
	return b.base.RoundTrip(r)
}

func TestAuthorityBackendFailures(t *testing.T) {
	c := testcert.New(t)
	key := protocol.SigningKey{Key: c.LeafKey}
	keys := []crypto.PublicKey{c.LeafKey.Public()}
	at := testcert.Now()
	const endpoint = "https://authority.test/soap"
	for _, test := range []struct {
		name, code, subcode string
		mapping             bool
		failure             error
	}{
		{name: "denied-mapping", mapping: true, failure: ErrDenied, code: protocol.Requester, subcode: "urn:oasis:names:tc:SAML:2.0:status:RequestDenied"},
		{name: "unknown-principal", mapping: true, failure: &protocol.StatusError{Code: protocol.Requester, Subcodes: []string{protocol.UnknownPrincipal}}, code: protocol.Requester, subcode: protocol.UnknownPrincipal},
		{name: "internal-query-error", failure: errors.New("private backend detail"), code: protocol.Responder},
		{name: "no-context", failure: &protocol.StatusError{Code: protocol.Responder, Subcodes: []string{protocol.NoAuthnContext}}, code: protocol.Responder, subcode: protocol.NoAuthnContext},
		{name: "canceled", failure: context.Canceled},
	} {
		t.Run(test.name, func(t *testing.T) {
			calls := 0
			service, err := NewService(Config{EntityID: issuer, Endpoint: endpoint, Signing: key, Replay: replayStore(t), Trust: func(context.Context, string, time.Time) ([]crypto.PublicKey, error) { return keys, nil }, Kinds: []protocol.QueryKind{protocol.AuthenticationQuery}, Query: func(context.Context, *protocol.VerifiedQuery) ([]*document.Document, error) {
				calls++
				return nil, test.failure
			}, Mapping: func(context.Context, *protocol.VerifiedNameIDMappingRequest) (*document.Document, error) {
				calls++
				return nil, test.failure
			}})
			if err != nil {
				t.Fatal(err)
			}
			header := protocol.MessageHeader{ID: "_failure", Issuer: requester, Destination: endpoint, IssueInstant: at}
			sub, _ := protocol.NewSubject(t.Context(), protocol.NameIdentifier{Value: "alice"})
			q := protocol.Query{MessageHeader: header, Kind: protocol.AuthenticationQuery, Subject: sub}
			request, err := protocol.SignQuery(t.Context(), q, key)
			if test.mapping {
				request, err = protocol.SignNameIDMappingRequest(t.Context(), protocol.NameIDMappingRequest{MessageHeader: header, NameID: protocol.NameIdentifier{Value: "alice"}}, key)
			}
			if err != nil {
				t.Fatal(err)
			}
			out, err := service.Respond(t.Context(), request, requester, at)
			if errors.Is(test.failure, context.Canceled) {
				if !errors.Is(err, context.Canceled) || out != nil {
					t.Fatalf("cancellation hidden: %v", err)
				}
			} else {
				if err != nil {
					t.Fatal(err)
				}
				raw, _ := out.XML(t.Context())
				message, err := binding.DecodeSOAP(t.Context(), raw, binding.SOAPOptions{})
				if err != nil {
					t.Fatal(err)
				}
				payload, _ := message.Payload(t.Context())
				o := protocol.ExchangeOptions{Issuer: issuer, ExpectedRequestID: header.ID, At: at, Binding: metadata.SOAP}
				var status protocol.Status
				if test.mapping {
					r, err := protocol.VerifyNameIDMappingResponse(t.Context(), payload, keys, o)
					if err != nil || r.Identifier() != nil {
						t.Fatalf("mapping failure exposed identity: %v", err)
					}
					status = r.Status()
				} else {
					r, err := protocol.VerifyQueryResponse(t.Context(), payload, keys, q, protocol.QueryResponseOptions{ExchangeOptions: o})
					if err != nil || len(r.Assertions()) != 0 {
						t.Fatalf("query failure exposed assertions: %v", err)
					}
					status = r.Status()
				}
				if status.Code != test.code || status.Message != "" || test.subcode != "" && (len(status.Subcodes) != 1 || status.Subcodes[0] != test.subcode) {
					t.Fatalf("wrong failure status: %+v", status)
				}
			}
			if _, err = service.Respond(t.Context(), request, requester, at); !errors.Is(err, replay.ErrReplay) || calls != 1 {
				t.Fatalf("failed backend request executed again (%d): %v", calls, err)
			}
		})
	}
}

type observedReadContext struct {
	context.Context
	checked chan struct{}
	once    sync.Once
}

func (c *observedReadContext) Err() error {
	err := c.Context.Err()
	c.once.Do(func() { close(c.checked) })
	return err
}

func TestMemoryAssertionsGetRechecksCancellation(t *testing.T) {
	t.Parallel()
	store, err := NewMemoryAssertions(1)
	if err != nil {
		t.Fatal(err)
	}
	doc, err := document.Parse(t.Context(), []byte(`<s:Assertion xmlns:s="urn:oasis:names:tc:SAML:2.0:assertion" ID="_held"/>`), document.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Add(t.Context(), doc); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	observed := &observedReadContext{Context: ctx, checked: make(chan struct{})}
	finished := make(chan error, 1)
	store.mu.Lock()
	go func() {
		got, err := store.Get(observed, "_held")
		if got != nil {
			finished <- errors.New("canceled lookup returned an assertion")
			return
		}
		finished <- err
	}()
	<-observed.checked
	cancel()
	store.mu.Unlock()
	if err := <-finished; !errors.Is(err, context.Canceled) {
		t.Fatalf("queued lookup returned %v; want context.Canceled", err)
	}
	if got, err := store.Get(t.Context(), "_held"); err != nil || got != doc {
		t.Fatal("canceled lookup changed immutable assertion storage", got, err)
	}
}
