package sp //nolint:testpackage // Checks constructor snapshots and orchestration before trust/store boundaries.

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/url"
	"testing"
	"time"

	"github.com/skarm/xmlsec/internal/testutil/testcert"
	"github.com/skarm/xmlsec/saml/binding"
	"github.com/skarm/xmlsec/saml/metadata"
	"github.com/skarm/xmlsec/saml/protocol"
	"github.com/skarm/xmlsec/saml/replay"
	"github.com/skarm/xmlsec/saml/state"
	"github.com/skarm/xmlsec/xmldsig"
)

const (
	spEntityID           = "https://sp.example.test/entity"
	idpEntityID          = "https://idp.example.test/entity"
	assertionConsumerURL = "https://sp.example.test/acs"
	singleSignOnURL      = "https://idp.example.test/sso?tenant=blue"
)

type requestContextKey struct{}

type resolverCall struct {
	id  string
	at  time.Time
	ctx context.Context
}

type resolverSpy struct {
	entities map[string]*metadata.Entity
	calls    []resolverCall
	err      error
	failAt   int
}

func (r *resolverSpy) Lookup(ctx context.Context, id string, at time.Time) (*metadata.Entity, error) {
	r.calls = append(r.calls, resolverCall{id, at, ctx})
	if len(r.calls) == r.failAt {
		return nil, r.err
	}
	return r.entities[id], nil
}

type requestStoreSpy struct {
	puts       int
	gets       int
	pending    state.Pending
	putErr     error
	getErr     error
	getSP      string
	getRelay   string
	getAt      time.Time
	getContext context.Context
}

func (s *requestStoreSpy) Put(_ context.Context, p state.Pending, _ time.Time) error {
	s.puts++
	s.pending = p
	return s.putErr
}

func (s *requestStoreSpy) Get(ctx context.Context, sp, relay string, at time.Time) (state.Pending, error) {
	s.gets++
	s.getContext, s.getSP, s.getRelay, s.getAt = ctx, sp, relay, at
	return s.pending, s.getErr
}

type replayStoreSpy struct{ calls int }

func (s *replayStoreSpy) Consume(context.Context, []replay.Entry, time.Time) error {
	s.calls++
	return nil
}

func serviceProviderConfig(t *testing.T) (Config, *resolverSpy, *requestStoreSpy, *replayStoreSpy) {
	t.Helper()
	chain := testcert.New(t)
	resolver, requests, consumed := &resolverSpy{}, &requestStoreSpy{}, &replayStoreSpy{}
	return Config{EntityID: spEntityID, Metadata: resolver, Signing: protocol.SigningKey{Key: chain.LeafKey, CertificateDER: chain.Leaf.Raw}, Requests: requests, Replay: consumed}, resolver, requests, consumed
}

func trustedMetadataEntities(t *testing.T, c Config, ownTTL, peerTTL time.Duration, endpoint string) map[string]*metadata.Entity {
	t.Helper()
	entities := make(map[string]*metadata.Entity)
	for _, spec := range []metadata.EntityDescriptor{
		{ID: "_sp", EntityID: spEntityID, ValidUntil: testcert.Now().Add(ownTTL), SP: &metadata.RoleDescriptor{Keys: []metadata.KeyDescriptor{{Use: "signing", CertificateDER: c.Signing.CertificateDER}}, Endpoints: map[string][]metadata.Endpoint{metadata.AssertionConsumerService: {{Binding: metadata.HTTPPost, Location: assertionConsumerURL, Indexed: true, Default: true}}}, NameIDFormats: []string{protocol.NameIDPersistent}}},
		{ID: "_idp", EntityID: idpEntityID, ValidUntil: testcert.Now().Add(peerTTL), IDP: &metadata.RoleDescriptor{Keys: []metadata.KeyDescriptor{{Use: "signing", CertificateDER: c.Signing.CertificateDER}}, Endpoints: map[string][]metadata.Endpoint{metadata.SingleSignOnService: {{Binding: metadata.HTTPRedirect, Location: endpoint}}}, NameIDFormats: []string{protocol.NameIDPersistent}}},
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
		entities[spec.EntityID], err = snapshot.Find(spec.EntityID, testcert.Now())
		if err != nil {
			t.Fatal(err)
		}
	}
	return entities
}

func TestNewServiceProviderRequestLifetime(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name     string
		lifetime time.Duration
		want     time.Duration
		valid    bool
	}{
		{"default", 0, 5 * time.Minute, true},
		{"minimum", time.Second, time.Second, true},
		{"maximum", 10 * time.Minute, 10 * time.Minute, true},
		{"below minimum", time.Second - time.Nanosecond, 0, false},
		{"above maximum", 10*time.Minute + time.Nanosecond, 0, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			c, resolver, requests, consumed := serviceProviderConfig(t)
			c.RequestLifetime = tc.lifetime
			service, err := NewServiceProvider(c)
			if !tc.valid {
				if service != nil || !errors.Is(err, ErrPolicy) {
					t.Fatalf("NewServiceProvider = %v, %v", service, err)
				}
			} else if err != nil || service.c.RequestLifetime != tc.want || service.c.Signing.SignatureMethod != xmldsig.ECDSASHA256 {
				t.Fatalf("constructor defaults/bounds: %v, %v", service, err)
			}
			if len(resolver.calls) != 0 || requests.puts != 0 || requests.gets != 0 || consumed.calls != 0 {
				t.Fatal("constructor called adapters")
			}
		})
	}
}

func TestNewServiceProviderRejectsInvalidConfig(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name   string
		mutate func(*Config)
	}{
		{"metadata", func(c *Config) { c.Metadata = (*resolverSpy)(nil) }},
		{"requests", func(c *Config) { c.Requests = (*requestStoreSpy)(nil) }},
		{"replay", func(c *Config) { c.Replay = (*replayStoreSpy)(nil) }},
		{"signer", func(c *Config) { c.Signing.Key = (*ecdsa.PrivateKey)(nil) }},
		{"entity", func(c *Config) { c.EntityID = "relative" }},
		{"limits", func(c *Config) { c.Limits.ClockSkew = -time.Nanosecond }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			c, _, _, _ := serviceProviderConfig(t)
			tc.mutate(&c)
			if service, err := NewServiceProvider(c); service != nil || !errors.Is(err, ErrPolicy) {
				t.Fatalf("invalid config accepted: %v, %v", service, err)
			}
		})
	}
}

func TestNewServiceProviderSnapshotsTrustInputs(t *testing.T) {
	t.Parallel()

	c, resolver, requests, consumed := serviceProviderConfig(t)
	c.Signing.Policy.AllowedSignatureMethods = []string{xmldsig.ECDSASHA256}
	c.Signing.Policy.AllowedDigestMethods = []string{xmldsig.SHA256}
	c.VerificationPolicy.AllowedSignatureMethods = []string{xmldsig.ECDSASHA384}
	c.VerificationPolicy.AllowedDigestMethods = []string{xmldsig.SHA384}
	wantCertificate := bytes.Clone(c.Signing.CertificateDER)
	service, err := NewServiceProvider(c)
	if err != nil {
		t.Fatal(err)
	}
	c.Signing.CertificateDER[0] ^= 0xff
	c.Signing.Policy.AllowedSignatureMethods[0] = xmldsig.RSASHA256
	c.Signing.Policy.AllowedDigestMethods[0] = xmldsig.SHA512
	c.VerificationPolicy.AllowedSignatureMethods[0] = xmldsig.RSASHA384
	c.VerificationPolicy.AllowedDigestMethods[0] = xmldsig.SHA512
	if !bytes.Equal(service.c.Signing.CertificateDER, wantCertificate) || service.c.Signing.Policy.AllowedSignatureMethods[0] != xmldsig.ECDSASHA256 || service.c.Signing.Policy.AllowedDigestMethods[0] != xmldsig.SHA256 || service.c.VerificationPolicy.AllowedSignatureMethods[0] != xmldsig.ECDSASHA384 || service.c.VerificationPolicy.AllowedDigestMethods[0] != xmldsig.SHA384 {
		t.Fatal("caller mutation changed the provider's trust snapshot")
	}
	if len(resolver.calls) != 0 || requests.puts != 0 || requests.gets != 0 || consumed.calls != 0 {
		t.Fatal("constructing the trust snapshot called adapters")
	}
}

func TestNewServiceProviderSelectsRSAMethod(t *testing.T) {
	t.Parallel()

	c, resolver, requests, consumed := serviceProviderConfig(t)
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	c.Signing = protocol.SigningKey{Key: rsaKey}
	rsaService, err := NewServiceProvider(c)
	if err != nil || rsaService.c.Signing.SignatureMethod != xmldsig.RSASHA256 {
		t.Fatalf("RSA method selection: %v, %v", rsaService, err)
	}
	if len(resolver.calls) != 0 || requests.puts != 0 || requests.gets != 0 || consumed.calls != 0 {
		t.Fatal("selecting the signing method called adapters")
	}
}

func TestBeginDoesNotSaveWhenSigningFails(t *testing.T) {
	t.Parallel()

	c, resolver, requests, consumed := serviceProviderConfig(t)
	resolver.entities = trustedMetadataEntities(t, c, time.Minute, time.Minute, singleSignOnURL)
	c.Signing.Policy.AllowedSignatureMethods = []string{xmldsig.ECDSASHA384}
	service, err := NewServiceProvider(c)
	if err != nil {
		t.Fatal(err)
	}
	if result, err := service.Begin(t.Context(), BeginOptions{IDP: idpEntityID, At: testcert.Now(), BrowserBinding: bytes.Repeat([]byte{7}, 32)}); result != nil || !errors.Is(err, xmldsig.ErrPolicy) {
		t.Fatal("signing policy failure lost", result, err)
	}
	if len(resolver.calls) != 2 || requests.puts != 0 || consumed.calls != 0 {
		t.Fatal("failed signing persisted or consumed state")
	}
}

func TestBeginRejectsInvalidInputBeforeAdapters(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name   string
		change func(*ServiceProvider, *context.Context, *BeginOptions)
		want   error
	}{
		{"nil context", func(_ *ServiceProvider, ctx *context.Context, _ *BeginOptions) { *ctx = nil }, ErrPolicy},
		{"cancelled", func(_ *ServiceProvider, ctx *context.Context, _ *BeginOptions) {
			cancelled, cancel := context.WithCancel(*ctx)
			cancel()
			*ctx = cancelled
		}, context.Canceled},
		{"zero time", func(_ *ServiceProvider, _ *context.Context, o *BeginOptions) { o.At = time.Time{} }, ErrPolicy},
		{"relative IdP", func(_ *ServiceProvider, _ *context.Context, o *BeginOptions) { o.IDP = "/idp" }, ErrPolicy},
		{"short browser secret", func(_ *ServiceProvider, _ *context.Context, o *BeginOptions) { o.BrowserBinding = make([]byte, 15) }, state.ErrPolicy},
		{"unsupported binding", func(_ *ServiceProvider, _ *context.Context, o *BeginOptions) { o.Binding = metadata.SOAP }, ErrPolicy},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			c, resolver, requests, consumed := serviceProviderConfig(t)
			service, err := NewServiceProvider(c)
			if err != nil {
				t.Fatal(err)
			}
			ctx := t.Context()
			o := BeginOptions{IDP: idpEntityID, At: testcert.Now(), BrowserBinding: bytes.Repeat([]byte{7}, 32)}
			tc.change(service, &ctx, &o)
			if result, err := service.Begin(ctx, o); result != nil || !errors.Is(err, tc.want) {
				t.Fatalf("Begin = %v, %v; want %v", result, err, tc.want)
			}
			if len(resolver.calls) != 0 || requests.puts != 0 || requests.gets != 0 || consumed.calls != 0 {
				t.Fatal("invalid request reached adapters")
			}
		})
	}
}

func TestBeginPreservesMetadataAndStoreFailures(t *testing.T) {
	t.Parallel()

	failure := errors.New("adapter unavailable")
	for _, failAt := range []int{1, 2, 3} {
		t.Run([]string{"own metadata", "peer metadata", "put"}[failAt-1], func(t *testing.T) {
			t.Parallel()

			c, resolver, requests, consumed := serviceProviderConfig(t)
			resolver.entities = trustedMetadataEntities(t, c, time.Minute, time.Minute, singleSignOnURL)
			if failAt < 3 {
				resolver.err, resolver.failAt = failure, failAt
			} else {
				requests.putErr = failure
			}
			service, err := NewServiceProvider(c)
			if err != nil {
				t.Fatal(err)
			}
			ctx := context.WithValue(t.Context(), requestContextKey{}, "begin marker")
			if result, err := service.Begin(ctx, BeginOptions{IDP: idpEntityID, At: testcert.Now(), BrowserBinding: bytes.Repeat([]byte{7}, 32)}); result != nil || !errors.Is(err, failure) {
				t.Fatalf("adapter error lost: %v, %v", result, err)
			}
			wantLookups, wantPuts := failAt, 0
			if failAt == 3 {
				wantLookups, wantPuts = 2, 1
			}
			if len(resolver.calls) != wantLookups || requests.puts != wantPuts || consumed.calls != 0 {
				t.Fatal("unexpected adapter call order/count", resolver.calls, requests.puts, consumed.calls)
			}
			for n, call := range resolver.calls {
				if call.id != []string{spEntityID, idpEntityID}[n] || call.at != testcert.Now() || call.ctx == nil || call.ctx.Value(requestContextKey{}) != "begin marker" {
					t.Fatal("lookup lost trusted identity, time or context", call)
				}
			}
		})
	}
}

func TestBeginBindsPendingStateAndExpiration(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name            string
		own, peer, want time.Duration
	}{
		{"request lifetime", 4 * time.Minute, 3 * time.Minute, 2 * time.Minute},
		{"own metadata", 30 * time.Second, time.Minute, 30 * time.Second},
		{"peer metadata", time.Minute, 20 * time.Second, 20 * time.Second},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			c, resolver, requests, consumed := serviceProviderConfig(t)
			c.RequestLifetime = 2 * time.Minute
			resolver.entities = trustedMetadataEntities(t, c, tc.own, tc.peer, singleSignOnURL)
			service, err := NewServiceProvider(c)
			if err != nil {
				t.Fatal(err)
			}
			browser := bytes.Repeat([]byte{7}, 32)
			contexts := []string{"urn:example:password"}
			out, err := service.Begin(t.Context(), BeginOptions{IDP: idpEntityID, At: testcert.Now(), BrowserBinding: browser, NameIDFormat: protocol.NameIDPersistent, RequestedContexts: contexts, ForceAuthn: true})
			if err != nil {
				t.Fatal(err)
			}
			contexts[0] = "urn:example:changed"
			p := requests.pending
			if requests.puts != 1 || consumed.calls != 0 || p.SP != spEntityID || p.IDP != idpEntityID || p.ACS != assertionConsumerURL || p.RequestID != out.RequestID() || p.RequestID == "" || p.RelayState != out.RelayState() || len(p.RelayState) < 16 || p.BrowserSHA256 != sha256.Sum256(browser) || p.IssuedAt != testcert.Now() || p.ExpiresAt != testcert.Now().Add(tc.want) || out.ExpiresAt() != p.ExpiresAt || p.NameIDFormat != protocol.NameIDPersistent || !p.ForceAuthn || len(p.RequestedContexts) != 1 || p.RequestedContexts[0] != "urn:example:password" {
				t.Fatalf("pending request lost browser/policy binding: %+v", p)
			}
			redirect, err := out.RedirectURL()
			if err != nil {
				t.Fatal(err)
			}
			u, err := url.Parse(redirect)
			if err != nil || out.Binding() != metadata.HTTPRedirect || u.Query().Get("tenant") != "blue" || u.Query().Get("SAMLRequest") == "" {
				t.Fatal("Redirect lost metadata query or signed request", redirect, err)
			}
			verified, err := protocol.VerifyRedirectRequest(t.Context(), out.RawQuery(), []crypto.PublicKey{c.Signing.Key.Public()}, protocol.RequestOptions{Issuer: spEntityID, Destination: singleSignOnURL, ACS: []metadata.Endpoint{{Binding: metadata.HTTPPost, Location: assertionConsumerURL}}, At: testcert.Now()}, binding.Options{})
			if err != nil || verified.ID() != p.RequestID || verified.ACS() != p.ACS || verified.NameIDFormat() != protocol.NameIDPersistent || !verified.ForceAuthn() {
				t.Fatal("stored state differs from the authenticated request", verified, err)
			}
			if contexts := verified.RequestedContexts(); len(contexts) != 1 || contexts[0] != "urn:example:password" {
				t.Fatal("signed request lost the requested authentication contexts", contexts)
			}
		})
	}
}

func TestConsumePOSTRejectsCorrelationBeforeTrustAndReplay(t *testing.T) {
	t.Parallel()

	const relay = "registered-relay-value"
	browser := bytes.Repeat([]byte{7}, 32)
	for _, tc := range []struct {
		name   string
		mutate func(*state.Pending)
	}{
		{"SP", func(p *state.Pending) { p.SP = "https://other.test/entity" }},
		{"relay", func(p *state.Pending) { p.RelayState = "different-relay-value" }},
		{"expiration equality", func(p *state.Pending) { p.ExpiresAt = testcert.Now() }},
		{"future issuance", func(p *state.Pending) { p.IssuedAt = testcert.Now().Add(time.Nanosecond) }},
		{"browser", func(p *state.Pending) { p.BrowserSHA256[31] ^= 1 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			c, resolver, requests, consumed := serviceProviderConfig(t)
			requests.pending = state.Pending{SP: spEntityID, IDP: idpEntityID, RelayState: relay, IssuedAt: testcert.Now(), ExpiresAt: testcert.Now().Add(time.Minute), BrowserSHA256: sha256.Sum256(browser)}
			tc.mutate(&requests.pending)
			service, err := NewServiceProvider(c)
			if err != nil {
				t.Fatal(err)
			}
			form := []byte(url.Values{"SAMLResponse": {base64.StdEncoding.EncodeToString([]byte(`<r/>`))}, "RelayState": {relay}}.Encode())
			if result, err := service.ConsumePOST(t.Context(), form, ConsumeOptions{At: testcert.Now(), BrowserBinding: browser}); result != nil || !errors.Is(err, ErrCorrelation) {
				t.Fatal("uncorrelated response accepted", result, err)
			}
			if requests.gets != 1 || requests.puts != 0 || len(resolver.calls) != 0 || consumed.calls != 0 {
				t.Fatal("uncorrelated response reached trust or replay adapters")
			}
		})
	}
}

func TestConsumePOSTPreservesStateLookupFailure(t *testing.T) {
	t.Parallel()

	c, resolver, requests, consumed := serviceProviderConfig(t)
	requests.getErr = errors.New("state backend unavailable")
	service, err := NewServiceProvider(c)
	if err != nil {
		t.Fatal(err)
	}
	form := []byte(url.Values{"SAMLResponse": {base64.StdEncoding.EncodeToString([]byte(`<r/>`))}, "RelayState": {"registered-relay-value"}}.Encode())
	if result, err := service.ConsumePOST(t.Context(), form, ConsumeOptions{At: testcert.Now(), BrowserBinding: bytes.Repeat([]byte{7}, 32)}); result != nil || !errors.Is(err, requests.getErr) {
		t.Fatal("state lookup failure lost", result, err)
	}
	if requests.gets != 1 || len(resolver.calls) != 0 || consumed.calls != 0 {
		t.Fatal("failed state lookup reached trust or replay adapters")
	}
}

func TestConsumePOSTMatchedCorrelationReachesTrustedMetadata(t *testing.T) {
	t.Parallel()

	c, resolver, requests, consumed := serviceProviderConfig(t)
	const relay = "registered-relay-value"
	browser := bytes.Repeat([]byte{7}, 32)
	requests.pending = state.Pending{SP: spEntityID, IDP: idpEntityID, RelayState: relay, IssuedAt: testcert.Now(), ExpiresAt: testcert.Now().Add(time.Nanosecond), BrowserSHA256: sha256.Sum256(browser)}
	resolver.err, resolver.failAt = errors.New("metadata backend unavailable"), 1
	service, err := NewServiceProvider(c)
	if err != nil {
		t.Fatal(err)
	}
	form := []byte(url.Values{"SAMLResponse": {base64.StdEncoding.EncodeToString([]byte(`<r/>`))}, "RelayState": {relay}}.Encode())
	ctx := context.WithValue(t.Context(), requestContextKey{}, "consume marker")
	if result, err := service.ConsumePOST(ctx, form, ConsumeOptions{At: testcert.Now(), BrowserBinding: browser}); result != nil || !errors.Is(err, resolver.err) {
		t.Fatal("matching correlation did not reach metadata", result, err)
	}
	if requests.gets != 1 || requests.getSP != spEntityID || requests.getRelay != relay || requests.getAt != testcert.Now() || requests.getContext == nil || requests.getContext.Value(requestContextKey{}) != "consume marker" || len(resolver.calls) != 1 || resolver.calls[0].id != spEntityID || consumed.calls != 0 {
		t.Fatal("trusted lookup arguments or ordering changed", requests, resolver.calls, consumed.calls)
	}
}

func TestConsumePOSTStopsBeforeAdapters(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name    string
		context func(*testing.T) context.Context
		at      time.Time
		browser []byte
		form    string
		want    error
	}{
		{"nil context", func(*testing.T) context.Context { return nil }, testcert.Now(), bytes.Repeat([]byte{7}, 32), "", ErrPolicy},
		{"cancelled context", func(t *testing.T) context.Context {
			ctx, cancel := context.WithCancel(t.Context())
			cancel()
			return ctx
		}, testcert.Now(), bytes.Repeat([]byte{7}, 32), "", context.Canceled},
		{"zero time", func(t *testing.T) context.Context { return t.Context() }, time.Time{}, bytes.Repeat([]byte{7}, 32), "", ErrPolicy},
		{"short secret", func(t *testing.T) context.Context { return t.Context() }, testcert.Now(), make([]byte, 15), "", state.ErrPolicy},
		{"missing relay", func(t *testing.T) context.Context { return t.Context() }, testcert.Now(), bytes.Repeat([]byte{7}, 32), "SAMLResponse=PHIvPg%3D%3D", ErrCorrelation},
		{"short relay", func(t *testing.T) context.Context { return t.Context() }, testcert.Now(), bytes.Repeat([]byte{7}, 32), "SAMLResponse=PHIvPg%3D%3D&RelayState=123456789012345", ErrCorrelation},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			c, resolver, requests, consumed := serviceProviderConfig(t)
			service, err := NewServiceProvider(c)
			if err != nil {
				t.Fatal(err)
			}
			if result, err := service.ConsumePOST(tc.context(t), []byte(tc.form), ConsumeOptions{At: tc.at, BrowserBinding: tc.browser}); result != nil || !errors.Is(err, tc.want) {
				t.Fatalf("ConsumePOST = %v, %v; want %v", result, err, tc.want)
			}
			if requests.gets != 0 || requests.puts != 0 || len(resolver.calls) != 0 || consumed.calls != 0 {
				t.Fatal("invalid response reached adapters")
			}
		})
	}
}

func TestBeginRejectsMetadataPolicyBeforeSaving(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name                      string
		endpoint, binding, format string
		replaceKey                bool
	}{
		{"unsupported NameID", singleSignOnURL, "", "urn:example:unsupported", false},
		{"no matching endpoint", singleSignOnURL, metadata.HTTPPost, "", false},
		{"reserved query field", singleSignOnURL + "&SAMLRequest=injected", "", "", false},
		{"unpublished signing key", singleSignOnURL, "", "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			c, resolver, requests, consumed := serviceProviderConfig(t)
			resolver.entities = trustedMetadataEntities(t, c, time.Minute, time.Minute, tc.endpoint)
			if tc.replaceKey {
				c.Signing.Key = testcert.Key(t)
			}
			service, err := NewServiceProvider(c)
			if err != nil {
				t.Fatal(err)
			}
			if result, err := service.Begin(t.Context(), BeginOptions{IDP: idpEntityID, At: testcert.Now(), BrowserBinding: bytes.Repeat([]byte{7}, 32), Binding: tc.binding, NameIDFormat: tc.format}); result != nil || !errors.Is(err, ErrPolicy) {
				t.Fatal("metadata policy bypassed", result, err)
			}
			if requests.puts != 0 || consumed.calls != 0 {
				t.Fatal("policy rejection persisted or consumed state")
			}
		})
	}
}
