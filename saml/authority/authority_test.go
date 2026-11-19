package authority //nolint:testpackage // This suite also checks cancellation while holding the private store lock.

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
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
	"github.com/skarm/xmlsec/xmldsig"
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

func authorityMetadata(t *testing.T, at time.Time, certificate []byte, soapURL, assertionURL string) *metadata.Snapshot {
	t.Helper()
	var keys []metadata.KeyDescriptor
	if len(certificate) != 0 {
		keys = []metadata.KeyDescriptor{{CertificateDER: certificate}}
	}
	roles := func(service string) *metadata.RoleDescriptor {
		return &metadata.RoleDescriptor{Keys: keys, Endpoints: map[string][]metadata.Endpoint{service: {{Binding: metadata.SOAP, Location: soapURL}}, metadata.AssertionIDRequestService: {{Binding: metadata.SOAP, Location: soapURL}, {Binding: metadata.URI, Location: assertionURL}}}}
	}
	spec := metadata.EntityDescriptor{EntityID: issuer, ValidUntil: at.Add(time.Hour), AuthnAuthority: roles(metadata.AuthnQueryService), AttributeAuthority: roles(metadata.AttributeService), PDP: roles(metadata.AuthzService), IDP: &metadata.RoleDescriptor{Keys: keys, Endpoints: map[string][]metadata.Endpoint{metadata.SingleSignOnService: {{Binding: metadata.SOAP, Location: soapURL}}, metadata.NameIDMappingService: {{Binding: metadata.SOAP, Location: soapURL}}}}}
	md, err := metadata.Build(t.Context(), spec, at, metadata.Options{})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := md.XML(t.Context())
	if err != nil {
		t.Fatalf("serialize authority metadata: %v", err)
	}
	snapshot, err := metadata.ParseTrusted(t.Context(), raw, at, metadata.Options{})
	if err != nil {
		t.Fatal(err)
	}
	return snapshot
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
	sub, err := protocol.NewSubject(t.Context(), protocol.NameIdentifier{Value: "alice"})
	if err != nil {
		t.Fatalf("build authority subject: %v", err)
	}
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
	store, err := NewMemoryAssertions(4)
	if err != nil {
		t.Fatalf("create assertion store: %v", err)
	}
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
		d, err := m.Payload(r.Context())
		if err != nil {
			t.Errorf("extract authority SOAP request: %v", err)
			http.Error(w, "SOAP payload", http.StatusBadRequest)
			return
		}
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
	snapshot := authorityMetadata(t, at, c.Leaf.Raw, server.URL+"/soap", server.URL+"/assertion")
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
	if r, err = client.Query(t.Context(), q, at); err != nil {
		t.Fatalf("assertion ID SOAP: %v", err)
	}
	if assertions := r.Assertions(); len(assertions) != 1 || assertions[0].ID() != "_held" {
		t.Fatalf("assertion ID SOAP returned %v, want one assertion with ID _held", assertions)
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
	client.Role = metadata.AuthenticationAuthority
	q = protocol.Query{Kind: protocol.AuthenticationQuery, Subject: sub, Context: &protocol.RequestedContext{Classes: []string{"urn:example:strong"}}}
	r, err = client.Query(t.Context(), q, at)
	if err != nil || len(r.Assertions()) != 0 {
		t.Fatalf("empty AuthnQuery with requested context: %v", err)
	}
	if status := r.Status(); status.Code != protocol.Responder || len(status.Subcodes) != 1 || status.Subcodes[0] != protocol.NoAuthnContext {
		t.Fatalf("empty AuthnQuery status = %+v, want NoAuthnContext", status)
	}

	client.Role = metadata.IdentityProvider
	mapping := protocol.NameIDMappingRequest{NameID: protocol.NameIdentifier{Value: "alice"}, Policy: protocol.NameIDPolicy{Format: protocol.NameIDPersistent, SPNameQualifier: "https://target.test/entity", AllowCreate: true}}
	mapped, err := client.Map(t.Context(), mapping, at)
	if err != nil {
		t.Fatal(err)
	}
	id, err := protocol.DecryptMappedNameID(t.Context(), mapped.Identifier(), &protocol.DecryptionOptions{Keys: []crypto.Decrypter{target}})
	if err != nil || id.Value != "target-alice" {
		t.Fatalf("mapped target: %v", err)
	}
	t.Run("no mapping result when storage fails", func(t *testing.T) {
		unavailable := errors.New("state storage unavailable")
		unavailableClient := client
		unavailableClient.Replay = failingReplayStore{err: unavailable}
		result, err := unavailableClient.Map(t.Context(), mapping, at)
		if result != nil || !errors.Is(err, unavailable) {
			t.Fatalf("Map returned a result: %t, error: %v; want no result and storage error", result != nil, err)
		}
	})

	client.Role = metadata.AttributeAuthority
	client.URI = binding.URIClient{Client: &http.Client{Transport: basicTransport{base: server.Client().Transport}}}
	uriOnlyClient := client
	uriOnlyClient.Replay = nil
	a, err := uriOnlyClient.Assertion(t.Context(), "_held", at)
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
	other, err := protocol.SignAuthorityAssertion(t.Context(), protocol.AuthorityAssertion{ID: "_held", Issuer: issuer, IssueInstant: at, Subject: sub}, key)
	if err != nil {
		t.Fatalf("sign replacement assertion with ID _held: %v", err)
	}
	if err = store.Add(t.Context(), other); !errors.Is(err, ErrDenied) {
		t.Fatalf("Add replacement assertion returned %v, want %v", err, ErrDenied)
	}
	if got, err := store.Get(t.Context(), "_held"); err != nil || got != assertion {
		t.Fatalf("Get after rejected replacement returned assertion=%p, err=%v; want %p, nil", got, err, assertion)
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

func TestClientRejectsInvalidSOAPConfigurationBeforeSigningOrSending(t *testing.T) {
	t.Parallel()
	chain := testcert.New(t)
	at := testcert.Now()
	const soapURL = "https://authority.test/soap"
	const assertionURL = "https://authority.test/assertion"
	snapshot := authorityMetadata(t, at, chain.Leaf.Raw, soapURL, assertionURL)
	withoutKeys := authorityMetadata(t, at, nil, soapURL, assertionURL)
	sub, err := protocol.NewSubject(t.Context(), protocol.NameIdentifier{Value: "alice"})
	if err != nil {
		t.Fatal(err)
	}

	var typedNil *replay.MemoryStore
	for _, test := range []struct {
		name     string
		store    replay.Store
		metadata *metadata.Snapshot
		limits   protocol.Limits
		want     error
	}{
		{name: "nil replay store", metadata: snapshot, want: ErrDenied},
		{name: "typed nil replay store", store: typedNil, metadata: snapshot, want: ErrDenied},
		{name: "invalid limits", store: replayStore(t), metadata: snapshot, limits: protocol.Limits{MaxMessageAge: -time.Second}, want: protocol.ErrProfile},
		{name: "no peer signing keys", store: replayStore(t), metadata: withoutKeys, want: protocol.ErrSignature},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			signer := &recordingSigner{Signer: chain.LeafKey}
			transport := &recordingTransport{}
			client := Client{EntityID: requester, Peer: issuer, Role: metadata.AttributeAuthority, Metadata: test.metadata, Signing: protocol.SigningKey{Key: signer}, Replay: test.store, SOAP: binding.SOAPClient{Client: &http.Client{Transport: transport}}}
			client.Options.Limits = test.limits
			if result, err := client.Query(t.Context(), protocol.Query{Kind: protocol.AttributeQuery, Subject: sub}, at); result != nil || !errors.Is(err, test.want) {
				t.Errorf("Query = %v, %v; want nil, %v", result, err, test.want)
			}

			client.Role = metadata.IdentityProvider
			if result, err := client.Map(t.Context(), protocol.NameIDMappingRequest{NameID: protocol.NameIdentifier{Value: "alice"}}, at); result != nil || !errors.Is(err, test.want) {
				t.Errorf("Map = %v, %v; want nil, %v", result, err, test.want)
			}

			if signer.calls != 0 || transport.calls != 0 {
				t.Errorf("signer calls = %d, transport calls = %d; want zero of each", signer.calls, transport.calls)
			}
		})
	}
}

type recordingSigner struct {
	crypto.Signer
	calls int
}

func (s *recordingSigner) Sign(r io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	s.calls++
	return s.Signer.Sign(r, digest, opts)
}

type recordingTransport struct{ calls int }

func (t *recordingTransport) RoundTrip(*http.Request) (*http.Response, error) {
	t.calls++
	return nil, errors.New("unexpected outbound request")
}

type failingReplayStore struct{ err error }

func (s failingReplayStore) Consume(context.Context, []replay.Entry, time.Time) error {
	return s.err
}

type basicTransport struct{ base http.RoundTripper }

func (b basicTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.SetBasicAuth("alice", "secret")
	return b.base.RoundTrip(r)
}

func TestURIHandlerReportsInvalidBackendDocument(t *testing.T) {
	t.Parallel()

	const assertionStart = `<s:Assertion xmlns:s="` + protocol.AssertionNamespace + `" ID="_held">`
	const assertionEnd = `</s:Assertion>`

	for _, test := range []struct {
		name, xml string
		status    int
	}{
		{"assertion", assertionStart + "payload" + assertionEnd, http.StatusOK},
		{"wrong root", `<Other ID="_held"/>`, http.StatusInternalServerError},
		{"oversized assertion", assertionStart + strings.Repeat("a", 2<<20) + assertionEnd, http.StatusInternalServerError},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			doc := parsed(t, test.xml)
			handler := URIHandler{
				Authenticate: func(*http.Request) (string, error) { return requester, nil },
				Lookup:       func(context.Context, string, string) (*document.Document, error) { return doc, nil },
			}
			request := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/assertion?ID=_held", nil)
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)

			if response.Code != test.status {
				t.Fatalf("status = %d, want %d", response.Code, test.status)
			}
			if test.status == http.StatusOK {
				if got := response.Header().Get("Content-Type"); got != binding.AssertionMediaType || response.Body.String() != test.xml {
					t.Fatalf("content type = %q, body = %q", got, response.Body.String())
				}
			} else if got := response.Body.String(); got != "assertion unavailable\n" {
				t.Fatalf("error response = %q", got)
			}
		})
	}
}

type shortAssertionWriter struct{ *httptest.ResponseRecorder }

func (w shortAssertionWriter) Write(p []byte) (int, error) {
	return w.ResponseRecorder.Write(p[:len(p)/2])
}

func TestURIHandlerLeavesCommittedResponseAlone(t *testing.T) {
	t.Parallel()

	const assertion = `<s:Assertion xmlns:s="` + protocol.AssertionNamespace + `" ID="_held">payload</s:Assertion>`
	doc := parsed(t, assertion)
	handler := URIHandler{
		Authenticate: func(*http.Request) (string, error) { return requester, nil },
		Lookup:       func(context.Context, string, string) (*document.Document, error) { return doc, nil },
	}
	request := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/assertion?ID=_held", nil)
	response := shortAssertionWriter{httptest.NewRecorder()}
	handler.ServeHTTP(response, request)

	if response.Code != http.StatusOK || response.Body.String() != assertion[:len(assertion)/2] {
		t.Fatalf("committed assertion response = %d %q", response.Code, response.Body.String())
	}
}

func TestBackendStatusRejectsTypedNil(t *testing.T) {
	t.Parallel()

	var status *protocol.StatusError
	for _, input := range []error{status, errors.Join(status, ErrDenied)} {
		if got, err := backendStatus(input); !errors.Is(err, ErrDenied) || got.Code != "" {
			t.Fatalf("status = %q, error = %v; want empty status and ErrDenied", got.Code, err)
		}
	}
}

func TestServiceValidatesAndOwnsSigningAndReplayConfiguration(t *testing.T) {
	t.Parallel()

	secret, err := protocol.NewSharedSecret(bytes.Repeat([]byte{1}, 32))
	if err != nil {
		t.Fatal(err)
	}

	key := testcert.Key(t)
	base := Config{
		EntityID: issuer, Endpoint: "https://authority.test/soap", Signing: protocol.SigningKey{Key: key},
		Replay: replayStore(t), Trust: func(context.Context, string, time.Time) ([]crypto.PublicKey, error) {
			return []crypto.PublicKey{key.Public()}, nil
		},
		Mapping: func(context.Context, *protocol.VerifiedNameIDMappingRequest) (*document.Document, error) {
			return nil, ErrDenied
		},
	}
	for _, test := range []struct {
		name   string
		change func(*Config)
	}{
		{"missing signer", func(c *Config) { c.Signing.Key = nil }},
		{"typed nil signer", func(c *Config) { c.Signing.Key = (*recordingSigner)(nil) }},
		{"both credentials", func(c *Config) { c.Signing.Secret = &secret }},
		{"typed nil replay", func(c *Config) { c.Replay = (*replay.MemoryStore)(nil) }},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			config := base
			test.change(&config)
			if service, err := NewService(config); service != nil || !errors.Is(err, ErrDenied) {
				t.Fatalf("NewService = %v, %v; want nil, ErrDenied", service, err)
			}
		})
	}

	config := base
	config.Signing = protocol.SigningKey{Secret: &secret, Policy: xmldsig.HMACPolicy()}
	service, err := NewService(config)
	if err != nil {
		t.Fatal(err)
	}
	if service.c.Signing.Secret == &secret {
		t.Fatal("service retained the caller's assignable secret pointer")
	}

	var uninitialized Service
	if out, err := uninitialized.Respond(t.Context(), parsed(t, `<Request/>`), requester, testcert.Now()); out != nil || !errors.Is(err, ErrDenied) {
		t.Fatalf("zero Service.Respond = %v, %v; want nil, ErrDenied", out, err)
	}
}

func TestAuthorityQueryRejectsOversizedResultBeforeResolvingAssertionKeys(t *testing.T) {
	t.Parallel()

	at := testcert.Now()
	key := protocol.SigningKey{Key: testcert.Key(t)}
	const endpoint = "https://authority.test/soap"
	q := protocol.Query{ID: "_query", Issuer: requester, Destination: endpoint, IssueInstant: at, Kind: protocol.AssertionRequest, AssertionIDs: []string{"_result"}}
	request, err := protocol.SignQuery(t.Context(), q, key)
	if err != nil {
		t.Fatal(err)
	}
	assertion, err := protocol.SignAuthorityAssertion(t.Context(), protocol.AuthorityAssertion{ID: "_result", Issuer: issuer, IssueInstant: at}, key)
	if err != nil {
		t.Fatal(err)
	}

	keyLookups := 0
	service, err := NewService(Config{
		EntityID: issuer, Endpoint: endpoint, Signing: key, Replay: replayStore(t), Kinds: []protocol.QueryKind{protocol.AssertionRequest},
		Trust: func(context.Context, string, time.Time) ([]crypto.PublicKey, error) {
			return []crypto.PublicKey{key.Key.Public()}, nil
		},
		AssertionTrust: func(context.Context, string, time.Time) ([]crypto.PublicKey, error) {
			keyLookups++
			return []crypto.PublicKey{key.Key.Public()}, nil
		},
		Query: func(context.Context, *protocol.VerifiedQuery) ([]*document.Document, error) {
			results := make([]*document.Document, protocol.MaxQueryAssertions+1)
			results[0] = assertion
			return results, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result, err := service.Respond(t.Context(), request, requester, at); result != nil || !errors.Is(err, protocol.ErrProfile) || keyLookups != 0 {
		t.Fatalf("oversized query response result=%v err=%v assertion-key lookups=%d", result, err, keyLookups)
	}
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
