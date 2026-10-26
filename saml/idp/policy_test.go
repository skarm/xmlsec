package idp //nolint:testpackage // Exercises private policy boundaries without a complete SSO workflow.

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"encoding/base64"
	"errors"
	"io"
	"slices"
	"testing"
	"time"

	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/internal/signature"
	"github.com/skarm/xmlsec/internal/testutil/testcert"
	"github.com/skarm/xmlsec/saml/metadata"
	"github.com/skarm/xmlsec/saml/protocol"
	"github.com/skarm/xmlsec/saml/replay"
	"github.com/skarm/xmlsec/xmldsig"
)

const (
	idpEntityID           = "https://idp.example.test/entity"
	spEntityID            = "https://sp.example.test/entity"
	singleSignOnURL       = "https://idp.example.test/sso"
	assertionConsumerURL  = "https://sp.example.test/acs"
	authenticationContext = "urn:test:authentication"
)

type metadataLookupCall struct {
	id string
	at time.Time
}

type metadataResolverSpy struct {
	entities map[string]*metadata.Entity
	calls    []metadataLookupCall
	failAt   int
	err      error
}

func (r *metadataResolverSpy) Lookup(ctx context.Context, id string, at time.Time) (*metadata.Entity, error) {
	r.calls = append(r.calls, metadataLookupCall{id, at})
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if len(r.calls) == r.failAt {
		return nil, r.err
	}
	return r.entities[id], nil
}

type replayStoreSpy struct{ calls int }

func (r *replayStoreSpy) Consume(context.Context, []replay.Entry, time.Time) error {
	r.calls++
	return nil
}

func identityProviderConfig(t *testing.T) Config {
	t.Helper()
	return Config{EntityID: idpEntityID, Metadata: &metadataResolverSpy{}, Replay: &replayStoreSpy{}, Signing: protocol.SigningKey{Key: testcert.Key(t)}}
}

func TestIdentityProviderPolicyBoundariesAndSnapshots(t *testing.T) {
	t.Parallel()

	base := identityProviderConfig(t)
	invalid := base
	invalid.Signing.Key = &ecdsa.PrivateKey{}
	if provider, err := NewIdentityProvider(invalid); provider != nil || !errors.Is(err, signature.Err) {
		t.Fatal("invalid key error was replaced", provider, err)
	}
	for _, test := range []struct {
		name   string
		change func(*Config)
		want   time.Duration
	}{
		{"default lifetime", func(*Config) {}, 5 * time.Minute},
		{"minimum lifetime", func(c *Config) { c.AssertionLifetime = time.Second }, time.Second},
		{"maximum lifetime", func(c *Config) { c.AssertionLifetime = 10 * time.Minute }, 10 * time.Minute},
		{"custom maximum", func(c *Config) {
			c.AssertionLifetime = 2 * time.Minute
			c.Limits.MaxAssertionLifetime = 2 * time.Minute
		}, 2 * time.Minute},
		{"below minimum", func(c *Config) { c.AssertionLifetime = time.Second - time.Nanosecond }, 0},
		{"above maximum", func(c *Config) { c.AssertionLifetime = 10*time.Minute + time.Nanosecond }, 0},
		{"default exceeds custom maximum", func(c *Config) { c.Limits.MaxAssertionLifetime = time.Minute }, 0},
		{"invalid limits", func(c *Config) { c.Limits.ClockSkew = -time.Nanosecond }, 0},
		{"invalid entity", func(c *Config) { c.EntityID = "relative" }, 0},
		{"nil resolver", func(c *Config) { c.Metadata = nil }, 0},
		{"typed nil resolver", func(c *Config) { c.Metadata = (*metadataResolverSpy)(nil) }, 0},
		{"nil replay", func(c *Config) { c.Replay = nil }, 0},
		{"typed nil replay", func(c *Config) { c.Replay = (*replayStoreSpy)(nil) }, 0},
		{"nil signer", func(c *Config) { c.Signing.Key = nil }, 0},
		{"typed nil signer", func(c *Config) { c.Signing.Key = (*ecdsa.PrivateKey)(nil) }, 0},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			config := base
			test.change(&config)
			provider, err := NewIdentityProvider(config)
			if test.want == 0 {
				if provider != nil || !errors.Is(err, ErrPolicy) {
					t.Fatalf("NewIdentityProvider = %v, %v", provider, err)
				}
				return
			}
			if err != nil || provider.c.AssertionLifetime != test.want {
				t.Fatalf("lifetime = %v, %v; want %v", provider, err, test.want)
			}
		})
	}
	config := base
	certificate := testcert.New(t)
	config.Signing.Key = certificate.LeafKey
	config.Signing.CertificateDER = bytes.Clone(certificate.Leaf.Raw)
	wantDER := bytes.Clone(config.Signing.CertificateDER)
	config.Signing.Policy.AllowedDigestMethods = []string{xmldsig.SHA256}
	config.Signing.Policy.AllowedSignatureMethods = []string{xmldsig.ECDSASHA256}
	config.VerificationPolicy.AllowedDigestMethods = []string{xmldsig.SHA384}
	config.VerificationPolicy.AllowedSignatureMethods = []string{xmldsig.ECDSASHA384}
	provider, err := NewIdentityProvider(config)
	if err != nil {
		t.Fatal(err)
	}
	config.Signing.CertificateDER[0] = 9
	config.Signing.Policy.AllowedDigestMethods[0] = "changed"
	config.Signing.Policy.AllowedSignatureMethods[0] = "changed"
	config.VerificationPolicy.AllowedDigestMethods[0] = "changed"
	config.VerificationPolicy.AllowedSignatureMethods[0] = "changed"
	if !bytes.Equal(provider.c.Signing.CertificateDER, wantDER) || !slices.Equal(provider.c.Signing.Policy.AllowedDigestMethods, []string{xmldsig.SHA256}) || !slices.Equal(provider.c.Signing.Policy.AllowedSignatureMethods, []string{xmldsig.ECDSASHA256}) || !slices.Equal(provider.c.VerificationPolicy.AllowedDigestMethods, []string{xmldsig.SHA384}) || !slices.Equal(provider.c.VerificationPolicy.AllowedSignatureMethods, []string{xmldsig.ECDSASHA384}) {
		t.Fatal("caller mutation changed the provider's captured trust policy")
	}
}

func trustedRoleEntity(t *testing.T, id string, kind metadata.RoleType) *metadata.Entity {
	t.Helper()
	role := &metadata.RoleDescriptor{Keys: []metadata.KeyDescriptor{{CertificateDER: testcert.New(t).Leaf.Raw}}}
	spec := metadata.EntityDescriptor{ID: "_metadata", EntityID: id, ValidUntil: testcert.Now().Add(time.Hour)}
	if kind == metadata.IdentityProvider {
		role.Endpoints = map[string][]metadata.Endpoint{metadata.SingleSignOnService: {{Binding: metadata.HTTPPost, Location: singleSignOnURL}, {Binding: metadata.HTTPRedirect, Location: singleSignOnURL}}}
		spec.IDP = role
	} else {
		role.Endpoints = map[string][]metadata.Endpoint{metadata.AssertionConsumerService: {{Binding: metadata.HTTPPost, Location: assertionConsumerURL, Index: 7}}}
		spec.SP = role
	}
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
	entity, err := snapshot.Find(id, testcert.Now())
	if err != nil {
		t.Fatal(err)
	}
	return entity
}

func TestRequestPolicyTrustLookupAndBinding(t *testing.T) {
	t.Parallel()

	own := trustedRoleEntity(t, idpEntityID, metadata.IdentityProvider)
	other := trustedRoleEntity(t, spEntityID, metadata.ServiceProvider)
	resolver := &metadataResolverSpy{entities: map[string]*metadata.Entity{idpEntityID: own, spEntityID: other}}
	store := &replayStoreSpy{}
	provider := &IdentityProvider{c: Config{EntityID: idpEntityID, Metadata: resolver, Replay: store, Limits: protocol.Limits{ClockSkew: time.Second}}}
	for _, test := range []struct {
		owner *IdentityProvider
		ctx   context.Context
		sp    string
		at    time.Time
	}{{nil, t.Context(), spEntityID, testcert.Now()}, {provider, nil, spEntityID, testcert.Now()}, {provider, t.Context(), "relative", testcert.Now()}, {provider, t.Context(), spEntityID, time.Time{}}} {
		_, role, err := test.owner.requestPolicy(test.ctx, test.sp, singleSignOnURL, metadata.HTTPPost, test.at)
		if role != nil || !errors.Is(err, ErrPolicy) || len(resolver.calls) != 0 {
			t.Fatal("invalid request policy reached metadata", role, err, resolver.calls)
		}
	}
	for _, transport := range []string{metadata.HTTPPost, metadata.HTTPRedirect} {
		resolver.calls = nil
		options, role, err := provider.requestPolicy(t.Context(), spEntityID, singleSignOnURL, transport, testcert.Now())
		if err != nil {
			t.Fatal(err)
		}
		if role == nil || options.Issuer != spEntityID || options.Destination != singleSignOnURL || options.At != testcert.Now() || options.Limits.ClockSkew != time.Second || len(options.ACS) != 1 || options.ACS[0].Location != assertionConsumerURL || options.ACS[0].Index != 7 {
			t.Fatalf("wrong request policy: %+v", options)
		}
		if !slices.Equal(resolver.calls, []metadataLookupCall{{idpEntityID, testcert.Now()}, {spEntityID, testcert.Now()}}) || store.calls != 0 {
			t.Fatal("unexpected trust lookup order or early replay consumption", resolver.calls, store.calls)
		}
	}
	for _, test := range []struct{ destination, binding string }{{singleSignOnURL + "/other", metadata.HTTPPost}, {singleSignOnURL, "urn:test:unsupported-binding"}} {
		options, role, err := provider.requestPolicy(t.Context(), spEntityID, test.destination, test.binding, testcert.Now())
		if !errors.Is(err, ErrPolicy) || role != nil || options.Issuer != "" {
			t.Fatal("unadvertised endpoint accepted", options, role, err)
		}
	}
	sentinel := errors.New("metadata unavailable")
	for _, position := range []int{1, 2} {
		resolver.calls = nil
		resolver.failAt = position
		resolver.err = sentinel
		for _, accept := range []func() (*Request, error){func() (*Request, error) {
			return provider.AcceptPOST(t.Context(), nil, spEntityID, singleSignOnURL, testcert.Now())
		}, func() (*Request, error) {
			return provider.AcceptRedirect(t.Context(), "", spEntityID, singleSignOnURL, testcert.Now())
		}} {
			resolver.calls = nil
			if request, err := accept(); request != nil || !errors.Is(err, sentinel) || len(resolver.calls) != position || store.calls != 0 {
				t.Fatal("adapter error was replaced or processing continued", request, err, resolver.calls, store.calls)
			}
		}
	}
	resolver.failAt = 0
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	for _, accept := range []func() (*Request, error){func() (*Request, error) {
		return provider.AcceptPOST(ctx, nil, spEntityID, singleSignOnURL, testcert.Now())
	}, func() (*Request, error) {
		return provider.AcceptRedirect(ctx, "", spEntityID, singleSignOnURL, testcert.Now())
	}} {
		resolver.calls = nil
		if request, err := accept(); request != nil || !errors.Is(err, context.Canceled) || len(resolver.calls) != 1 || store.calls != 0 {
			t.Fatal("canceled metadata lookup continued or lost its error", request, err, resolver.calls, store.calls)
		}
	}
	for _, replace := range []string{idpEntityID, spEntityID} {
		resolver.entities = map[string]*metadata.Entity{idpEntityID: own, spEntityID: other}
		kind := metadata.IdentityProvider
		if replace == idpEntityID {
			kind = metadata.ServiceProvider
		}
		resolver.entities[replace] = trustedRoleEntity(t, replace, kind)
		_, role, err := provider.requestPolicy(t.Context(), spEntityID, singleSignOnURL, metadata.HTTPPost, testcert.Now())
		if role != nil || !errors.Is(err, metadata.ErrMetadata) {
			t.Fatal("wrong metadata role accepted", replace, err)
		}
	}
}

func signedAndVerifiedRequest(t *testing.T, force, passive, create bool) *protocol.VerifiedRequest {
	t.Helper()
	key := testcert.Key(t)
	doc, err := protocol.SignAuthnRequest(t.Context(), protocol.AuthnRequest{ID: "_policy", Issuer: spEntityID, Destination: singleSignOnURL, ACS: assertionConsumerURL, IssueInstant: testcert.Now(), ForceAuthn: force, IsPassive: passive, AllowCreateNameID: create, RequestedContexts: []string{authenticationContext}}, protocol.SigningKey{Key: key})
	if err != nil {
		t.Fatal(err)
	}
	request, err := protocol.VerifyAuthnRequest(t.Context(), doc, []crypto.PublicKey{key.Public()}, protocol.RequestOptions{Issuer: spEntityID, Destination: singleSignOnURL, ACS: []metadata.Endpoint{{Binding: metadata.HTTPPost, Location: assertionConsumerURL}}, At: testcert.Now()})
	if err != nil {
		t.Fatal(err)
	}
	return request
}

func TestAuthenticationPolicyIndependentConditions(t *testing.T) {
	t.Parallel()

	normal := signedAndVerifiedRequest(t, false, false, false)
	force := signedAndVerifiedRequest(t, true, false, false)
	passive := signedAndVerifiedRequest(t, false, true, true)
	creation := signedAndVerifiedRequest(t, true, false, true)
	at, skew := testcert.Now(), 2*time.Second
	for _, test := range []struct {
		name    string
		request *protocol.VerifiedRequest
		change  func(*Authentication)
		want    bool
	}{
		{"ordinary", normal, func(*Authentication) {}, true},
		{"future skew inclusive", normal, func(a *Authentication) { a.AuthnInstant = at.Add(skew) }, true},
		{"future beyond skew", normal, func(a *Authentication) { a.AuthnInstant = at.Add(skew + time.Nanosecond) }, false},
		{"zero instant", normal, func(a *Authentication) { a.AuthnInstant = time.Time{} }, false},
		{"invalid context", normal, func(a *Authentication) { a.AuthnContext = "relative" }, false},
		{"force fresh", force, func(a *Authentication) { a.FreshAuthentication = true }, true},
		{"force freshness required", force, func(*Authentication) {}, false},
		{"force lower skew inclusive", force, func(a *Authentication) { a.FreshAuthentication = true; a.AuthnInstant = at.Add(-skew) }, true},
		{"force before lower skew", force, func(a *Authentication) {
			a.FreshAuthentication = true
			a.AuthnInstant = at.Add(-skew - time.Nanosecond)
		}, false},
		{"passive without interaction", passive, func(*Authentication) {}, true},
		{"passive with interaction", passive, func(a *Authentication) { a.InteractionUsed = true }, false},
		{"creation forbidden", normal, func(a *Authentication) { a.CreatedNameID = true }, false},
		{"passive and creation allowed", passive, func(a *Authentication) { a.CreatedNameID = true }, true},
		{"force and creation allowed", creation, func(a *Authentication) { a.FreshAuthentication = true; a.CreatedNameID = true }, true},
		{"creation does not bypass freshness", creation, func(a *Authentication) { a.CreatedNameID = true }, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			a := Authentication{AuthnInstant: at, AuthnContext: authenticationContext}
			test.change(&a)
			if got := authenticationAllowed(a, at, skew, test.request); got != test.want {
				t.Fatalf("authenticationAllowed = %v; want %v", got, test.want)
			}
		})
	}
}

func TestRequestWrappingExclusiveExpiryAndCopies(t *testing.T) {
	t.Parallel()

	verified := signedAndVerifiedRequest(t, true, false, true)
	provider := &IdentityProvider{c: Config{Limits: protocol.Limits{MaxMessageAge: 30 * time.Second, ClockSkew: 2 * time.Second}}}
	expires := testcert.Now().Add(32 * time.Second)
	request, err := provider.wrap(verified, "", true, expires.Add(-time.Nanosecond))
	if err != nil {
		t.Fatal(err)
	}
	if request.owner != provider || request.ExpiresAt() != expires || request.ID() != "_policy" || request.SP() != spEntityID || request.ACS() != assertionConsumerURL || !request.ForceAuthn() || request.IsPassive() || !request.AllowCreateNameID() || !request.relayPresent || request.relay != "" {
		t.Fatal("wrapper lost authenticated request state", request)
	}
	contexts := request.RequestedContexts()
	contexts[0] = "urn:changed"
	if !slices.Equal(request.RequestedContexts(), []string{authenticationContext}) {
		t.Fatal("returned context list changed the authenticated request")
	}
	for _, at := range []time.Time{expires, expires.Add(time.Nanosecond)} {
		if request, err := provider.wrap(verified, "opaque", false, at); request != nil || !errors.Is(err, ErrPolicy) {
			t.Fatal("exclusive expiry accepted", at, request, err)
		}
	}
	provider.c.Limits.MaxMessageAge = -time.Second
	if request, err := provider.wrap(verified, "", false, testcert.Now()); request != nil || !errors.Is(err, protocol.ErrProfile) {
		t.Fatal("invalid acceptance policy accepted", request, err)
	}
}

func TestIssueRejectsUnownedExpiredAndCanceledRequestsBeforeAdapters(t *testing.T) { //nolint:tparallel // Subtests share adapter spies checked after the table.
	t.Parallel()

	config := identityProviderConfig(t)
	provider, err := NewIdentityProvider(config)
	if err != nil {
		t.Fatal(err)
	}
	verified := signedAndVerifiedRequest(t, false, false, false)
	valid, err := provider.wrap(verified, "", false, testcert.Now())
	if err != nil {
		t.Fatal("valid authenticated request fixture", err)
	}
	for _, test := range []struct {
		name    string
		owner   *IdentityProvider
		ctx     context.Context
		request *Request
		at      time.Time
	}{
		{"nil provider", nil, t.Context(), valid, testcert.Now()},
		{"nil context", provider, nil, valid, testcert.Now()},
		{"nil request", provider, t.Context(), nil, testcert.Now()},
		{"another owner", &IdentityProvider{}, t.Context(), valid, testcert.Now()},
		{"unverified request", provider, t.Context(), &Request{owner: provider, expires: valid.expires}, testcert.Now()},
		{"missing time", provider, t.Context(), valid, time.Time{}},
		{"expiry equality", provider, t.Context(), valid, valid.expires},
		{"after expiry", provider, t.Context(), valid, valid.expires.Add(time.Nanosecond)},
	} {
		t.Run(test.name, func(t *testing.T) {
			if result, err := test.owner.Issue(test.ctx, test.request, Authentication{}, test.at); result != nil || !errors.Is(err, ErrPolicy) {
				t.Fatal("invalid proof reached issuance", result, err)
			}
		})
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if result, err := provider.Issue(ctx, valid, Authentication{}, testcert.Now()); result != nil || !errors.Is(err, context.Canceled) {
		t.Fatal("cancellation was replaced", result, err)
	}
	if len(config.Metadata.(*metadataResolverSpy).calls) != 0 || config.Replay.(*replayStoreSpy).calls != 0 {
		t.Fatal("invalid/canceled request reached external adapters")
	}
}

func TestBindingFailuresPreserveErrorsWithoutReplay(t *testing.T) {
	t.Parallel()

	resolver := &metadataResolverSpy{entities: map[string]*metadata.Entity{idpEntityID: trustedRoleEntity(t, idpEntityID, metadata.IdentityProvider), spEntityID: trustedRoleEntity(t, spEntityID, metadata.ServiceProvider)}}
	store := &replayStoreSpy{}
	provider := &IdentityProvider{c: Config{EntityID: idpEntityID, Metadata: resolver, Replay: store}}
	var corrupt base64.CorruptInputError
	if request, err := provider.AcceptPOST(t.Context(), []byte("SAMLRequest=invalid-base64"), spEntityID, singleSignOnURL, testcert.Now()); request != nil || !errors.As(err, &corrupt) || corrupt != 7 {
		t.Fatal("POST decoder error lost", request, err)
	}
	if request, err := provider.AcceptRedirect(t.Context(), "SAMLRequest=bad", spEntityID, singleSignOnURL, testcert.Now()); request != nil || !errors.Is(err, protocol.ErrSignature) {
		t.Fatal("Redirect decoder error lost", request, err)
	}
	if store.calls != 0 {
		t.Fatal("malformed binding consumed replay state", store.calls)
	}
}

func TestSigningKeyMatchesTrustedRoleOnly(t *testing.T) {
	t.Parallel()

	entity := trustedRoleEntity(t, idpEntityID, metadata.IdentityProvider)
	role, err := entity.Role(metadata.IdentityProvider, testcert.Now())
	if err != nil {
		t.Fatal(err)
	}
	if !keyAllowed(role.SigningKeys()[0], role) {
		t.Fatal("trusted parsed key did not match its metadata role")
	}
	if keyAllowed(testcert.Key(t).Public(), role) {
		t.Fatal("unadvertised signing key was accepted")
	}
	if keyAllowed(struct{}{}, role) {
		t.Fatal("unsupported public key was accepted")
	}
}

type partialBindingWriter struct {
	remaining int
	written   int
}

func (w *partialBindingWriter) Write(p []byte) (int, error) {
	n := min(len(p), w.remaining)
	w.remaining -= n
	w.written += n
	if n < len(p) {
		return n, io.ErrClosedPipe
	}
	return n, nil
}

func TestIssuedBindingWritersPropagatePartialFailures(t *testing.T) {
	t.Parallel()

	doc, err := document.Parse(t.Context(), []byte(`<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"/>`), document.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	for _, present := range []bool{false, true} {
		issued := &Issued{doc: doc, destination: assertionConsumerURL, relayPresent: present}
		var output bytes.Buffer
		n, err := issued.WritePOST(t.Context(), &output)
		if err != nil || n != int64(output.Len()) || !bytes.Contains(output.Bytes(), []byte("SAMLResponse=")) || bytes.Contains(output.Bytes(), []byte("RelayState=")) != present {
			t.Fatal("POST writer lost relay presence or byte count", output.String(), n, err)
		}
		for _, write := range []func(context.Context, io.Writer) (int64, error){issued.WritePOST, issued.WritePOSTForm} {
			writer := &partialBindingWriter{remaining: 11}
			if n, err := write(t.Context(), writer); n != 11 || writer.written != 11 || !errors.Is(err, io.ErrClosedPipe) {
				t.Fatal("partial writer failure was lost", n, writer.written, err)
			}
		}
	}
}
