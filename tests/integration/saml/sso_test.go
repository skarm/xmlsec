package saml_test

import (
	"bytes"
	"context"
	"crypto"
	"errors"
	"io"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/skarm/xmlsec/internal/testutil/testcert"
	"github.com/skarm/xmlsec/saml/binding"
	"github.com/skarm/xmlsec/saml/idp"
	"github.com/skarm/xmlsec/saml/metadata"
	"github.com/skarm/xmlsec/saml/protocol"
	"github.com/skarm/xmlsec/saml/replay"
	"github.com/skarm/xmlsec/saml/sp"
	"github.com/skarm/xmlsec/saml/state"
	"github.com/skarm/xmlsec/xmldsig"
)

const (
	spID        = "https://sp.test/entity"
	idpID       = "https://idp.test/entity"
	acs         = "https://sp.test/acs"
	ssoRedirect = "https://idp.test/sso/redirect"
	ssoPost     = "https://idp.test/sso/post"
	authClass   = "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"
)

func TestEndToEndSolicitedLogin(t *testing.T) {
	for _, kind := range []string{metadata.HTTPRedirect, metadata.HTTPPost} {
		t.Run(kind, func(t *testing.T) { testEndToEndSolicitedLoginCase(t, &kind) })
	}
}

func testEndToEndSolicitedLoginCase(t *testing.T, kind *string) {
	s := setup(t)
	out, req, browser := begin(t, s, *kind)
	a := auth()
	bad := a

	bad.FreshAuthentication = false
	if r, e := s.idp.Issue(t.Context(), req, bad, testcert.Now().Add(2*time.Second)); r != nil || e == nil {
		t.Fatal("ForceAuthn weakened")
	}

	other, e := idp.NewIdentityProvider(s.idpConfig)
	if e != nil {
		t.Fatal(e)
	}

	if r, e := other.Issue(t.Context(), req, a, testcert.Now().Add(2*time.Second)); r != nil || e == nil {
		t.Fatal("request proof from other provider accepted")
	}

	issued, e := s.idp.Issue(t.Context(), req, a, testcert.Now().Add(2*time.Second))
	if e != nil {
		t.Fatal(e)
	}

	if issued.Destination() != acs {
		t.Fatal("ACS")
	}

	if r, e := s.idp.Issue(t.Context(), req, a, testcert.Now().Add(2*time.Second)); r != nil || !errors.Is(e, replay.ErrReplay) {
		t.Fatal("IdP repeated issuance", e)
	}

	at := testcert.Now().Add(3 * time.Second)

	wrongBrowser := bytes.Repeat([]byte{1}, 32)
	if r, e := s.sp.ConsumePOST(t.Context(), postBody(t, issued), sp.ConsumeOptions{At: at, BrowserBinding: wrongBrowser}); r != nil || !errors.Is(e, sp.ErrCorrelation) {
		t.Fatal("browser not bound", e)
	}

	changed := bytes.Replace(postBody(t, issued), []byte(out.RelayState()), []byte("different-unregistered-relay-value"), 1)
	if r, e := s.sp.ConsumePOST(t.Context(), changed, sp.ConsumeOptions{At: at, BrowserBinding: browser}); r != nil || e == nil {
		t.Fatal("unknown request accepted")
	}

	r, e := s.sp.ConsumePOST(t.Context(), postBody(t, issued), sp.ConsumeOptions{At: at, BrowserBinding: browser})
	if e != nil {
		t.Fatal(e)
	}

	if r.NameID() != "alice" || r.AuthnContext() != authClass || r.InResponseTo() != out.RequestID() || !r.ResponseAuthenticated() {
		t.Fatal("session result")
	}

	if r, e := s.sp.ConsumePOST(t.Context(), postBody(t, issued), sp.ConsumeOptions{At: at, BrowserBinding: browser}); r != nil || !errors.Is(e, replay.ErrReplay) {
		t.Fatal("SP replay", e)
	}
}

func TestConcurrentSPOneWinner(t *testing.T) {
	s := setup(t)
	_, req, browser := begin(t, s, metadata.HTTPPost)

	issued, e := s.idp.Issue(t.Context(), req, auth(), testcert.Now().Add(2*time.Second))
	if e != nil {
		t.Fatal(e)
	}

	form := postBody(t, issued)

	var (
		wins atomic.Int32
		wg   sync.WaitGroup
	)
	for range 32 {
		wg.Go(func() {
			r, e := s.sp.ConsumePOST(t.Context(), form, sp.ConsumeOptions{At: testcert.Now().Add(3 * time.Second), BrowserBinding: browser})
			if e == nil && r != nil {
				wins.Add(1)
			} else if !errors.Is(e, replay.ErrReplay) {
				t.Errorf("unexpected %v", e)
			}
		})
	}

	wg.Wait()

	if wins.Load() != 1 {
		t.Fatal("non-atomic login", wins.Load())
	}
}

func TestSignedArbitraryACSRejected(t *testing.T) {
	s := setup(t)

	d, e := protocol.SignAuthnRequest(t.Context(), protocol.AuthnRequest{ID: "_wrongacs", Issuer: spID, Destination: ssoPost, ACS: "https://evil.test/receive", IssueInstant: testcert.Now()}, protocol.SigningKey{Key: s.cert.LeafKey, CertificateDER: s.cert.Leaf.Raw})
	if e != nil {
		t.Fatal(e)
	}

	relay := "opaque-relay-value"

	body, e := binding.EncodePOST(t.Context(), d, binding.Request, &relay, binding.POSTLimits{})
	if e != nil {
		t.Fatal(e)
	}

	if r, e := s.idp.AcceptPOST(t.Context(), body, spID, ssoPost, testcert.Now()); r != nil || e == nil {
		t.Fatal("signed ACS injection")
	}

	_, req, _ := begin(t, s, metadata.HTTPPost)
	if r, e := s.idp.Issue(t.Context(), req, auth(), testcert.Now().Add(6*time.Minute)); r != nil || e == nil {
		t.Fatal("expired request")
	}
}

func TestUnspecifiedNameIDDoesNotRequireLiteralUnspecifiedFormat(t *testing.T) {
	f := setup(t)
	ctx := t.Context()
	browser := bytes.Repeat([]byte{9}, 32)

	outbound, e := f.sp.Begin(ctx, sp.BeginOptions{IDP: idpID, BrowserBinding: browser, At: testcert.Now(), NameIDFormat: protocol.NameIDUnspecified, AllowCreateNameID: true})
	if e != nil {
		t.Fatal(e)
	}

	request, e := f.idp.AcceptRedirect(ctx, outbound.RawQuery(), spID, ssoRedirect, testcert.Now())
	if e != nil {
		t.Fatal(e)
	}

	answer, e := f.idp.Issue(ctx, request, auth(), testcert.Now().Add(time.Second))
	if e != nil {
		t.Fatal(e)
	}

	grant, e := f.sp.ConsumePOST(ctx, postBody(t, answer), sp.ConsumeOptions{At: testcert.Now().Add(2 * time.Second), BrowserBinding: browser})
	if e != nil || grant.NameIDFormat() != protocol.NameIDPersistent {
		t.Fatal(e)
	}
}

type registry map[string]*metadata.Snapshot

func (r registry) Lookup(ctx context.Context, id string, at time.Time) (*metadata.Entity, error) {
	s, ok := r[id]
	if !ok {
		return nil, metadata.ErrMetadata
	}

	return s.Lookup(ctx, id, at)
}

type system struct {
	sp        *sp.ServiceProvider
	idp       *idp.IdentityProvider
	registry  registry
	cert      testcert.Chain
	idpConfig idp.Config
}

func setup(t testing.TB) system {
	t.Helper()

	ctx := t.Context()
	c := testcert.New(t)
	reg := registry{}
	specs := []metadata.EntityDescriptor{
		{ID: "_spmeta", EntityID: spID, ValidUntil: testcert.Now().Add(time.Hour), SP: &metadata.RoleDescriptor{Keys: []metadata.KeyDescriptor{{Use: "signing", CertificateDER: c.Leaf.Raw}}, Endpoints: map[string][]metadata.Endpoint{"AssertionConsumerService": {{Binding: metadata.HTTPPost, Location: acs, Indexed: true, Index: 0, Default: true, DefaultSet: true}}}, NameIDFormats: []string{protocol.NameIDPersistent}, AuthnRequestsSigned: true, WantAssertionsSigned: true}},
		{ID: "_idpmeta", EntityID: idpID, ValidUntil: testcert.Now().Add(time.Hour), IDP: &metadata.RoleDescriptor{Keys: []metadata.KeyDescriptor{{Use: "signing", CertificateDER: c.TSA.Raw}}, Endpoints: map[string][]metadata.Endpoint{"SingleSignOnService": {{Binding: metadata.HTTPRedirect, Location: ssoRedirect}, {Binding: metadata.HTTPPost, Location: ssoPost}}}, NameIDFormats: []string{protocol.NameIDPersistent}, WantAuthnRequestsSigned: true}},
	}

	mv, e := metadata.NewVerifier(metadata.Config{TrustedKeys: []crypto.PublicKey{c.RootKey.Public()}, Options: metadata.Options{}})
	if e != nil {
		t.Fatal(e)
	}

	for _, spec := range specs {
		d, e := metadata.Build(ctx, spec, testcert.Now(), metadata.Options{})
		if e != nil {
			t.Fatal(e)
		}

		d, e = metadata.Sign(ctx, d, c.RootKey, c.Root.Raw, xmldsig.ECDSASHA256, testcert.Now(), metadata.Options{})
		if e != nil {
			t.Fatal(e)
		}

		raw, e := d.XML(ctx)
		if e != nil {
			t.Fatal(e)
		}

		snapshot, e := mv.Verify(ctx, raw, testcert.Now())
		if e != nil {
			t.Fatal(e)
		}

		reg[spec.EntityID] = snapshot
	}

	requests, e := state.NewMemoryStore(state.Config{})
	if e != nil {
		t.Fatal(e)
	}

	sr, e := replay.NewMemoryStore(replay.Config{})
	if e != nil {
		t.Fatal(e)
	}

	ir, e := replay.NewMemoryStore(replay.Config{})
	if e != nil {
		t.Fatal(e)
	}

	service, e := sp.NewServiceProvider(sp.Config{EntityID: spID, Metadata: reg, Signing: protocol.SigningKey{Key: c.LeafKey, CertificateDER: c.Leaf.Raw}, Requests: requests, Replay: sr})
	if e != nil {
		t.Fatal(e)
	}

	ic := idp.Config{EntityID: idpID, Metadata: reg, Signing: protocol.SigningKey{Key: c.TSAKey, CertificateDER: c.TSA.Raw}, Replay: ir, AssertionLifetime: 3 * time.Minute}

	identity, e := idp.NewIdentityProvider(ic)
	if e != nil {
		t.Fatal(e)
	}

	return system{service, identity, reg, c, ic}
}

func begin(t testing.TB, s system, kind string) (*sp.Outbound, *idp.Request, []byte) {
	t.Helper()

	browser := bytes.Repeat([]byte{0xa7}, 32)

	o, e := s.sp.Begin(t.Context(), sp.BeginOptions{IDP: idpID, Binding: kind, BrowserBinding: browser, At: testcert.Now(), NameIDFormat: protocol.NameIDPersistent, RequestedContexts: []string{authClass}, ForceAuthn: true, AllowCreateNameID: true})
	if e != nil {
		t.Fatal(e)
	}

	var r *idp.Request
	if kind == metadata.HTTPRedirect {
		r, e = s.idp.AcceptRedirect(t.Context(), o.RawQuery(), spID, ssoRedirect, testcert.Now())
		if u, err := o.RedirectURL(); err != nil || u == "" {
			t.Fatal(err)
		}
	} else {
		r, e = s.idp.AcceptPOST(t.Context(), postBody(t, o), spID, ssoPost, testcert.Now())
	}

	if e != nil {
		t.Fatal(e)
	}

	if r.ID() != o.RequestID() || r.ACS() != acs || !r.ForceAuthn() {
		t.Fatal("request")
	}

	return o, r, browser
}

func auth() idp.Authentication {
	return idp.Authentication{NameID: "alice", NameIDFormat: protocol.NameIDPersistent, AuthnInstant: testcert.Now().Add(time.Second), AuthnContext: authClass, FreshAuthentication: true, InteractionUsed: true, CreatedNameID: true, SessionIndex: "_session", Attributes: []protocol.Attribute{{Name: "email", Values: []string{"alice@example.test"}}}}
}

type postSerializer interface {
	WritePOST(context.Context, io.Writer) (int64, error)
}

func postBody(t testing.TB, message postSerializer) []byte {
	t.Helper()
	var body bytes.Buffer
	if _, err := message.WritePOST(t.Context(), &body); err != nil {
		t.Fatal(err)
	}
	return body.Bytes()
}

func TestOutboundPOSTSerialization(t *testing.T) {
	s := setup(t)
	out, request, _ := begin(t, s, metadata.HTTPPost)
	issued, err := s.idp.Issue(t.Context(), request, auth(), testcert.Now().Add(2*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	sentinel := errors.New("late sink failure")
	for name, write := range map[string]func(context.Context, io.Writer) (int64, error){
		"request": out.WritePOST, "response": issued.WritePOST,
		"requestHTML": out.WritePOSTForm, "responseHTML": issued.WritePOSTForm,
	} {
		t.Run(name, func(t *testing.T) {
			var expected bytes.Buffer
			count, err := write(t.Context(), &expected)
			if err != nil || count != int64(expected.Len()) || expected.Len() == 0 {
				t.Fatalf("output: %d %v", count, err)
			}
			var repeated bytes.Buffer
			if _, err := write(t.Context(), &repeated); err != nil || !bytes.Equal(expected.Bytes(), repeated.Bytes()) {
				t.Fatalf("repeatability: %v", err)
			}
			ctx, cancel := context.WithCancel(t.Context())
			cancel()
			var untouched bytes.Buffer
			if n, err := write(ctx, &untouched); n != 0 || untouched.Len() != 0 || !errors.Is(err, context.Canceled) {
				t.Fatalf("canceled: %d %v", n, err)
			}
			if _, err := write(t.Context(), &postFailureWriter{}); !errors.Is(err, io.ErrShortWrite) {
				t.Fatalf("short write: %v", err)
			}
			if n, err := write(t.Context(), &postFailureWriter{remaining: 512, err: sentinel}); n == 0 || !errors.Is(err, sentinel) {
				t.Fatalf("late failure: %d %v", n, err)
			}
			repeated.Reset()
			if _, err := write(t.Context(), &repeated); err != nil || !bytes.Equal(expected.Bytes(), repeated.Bytes()) {
				t.Fatalf("failed writer mutated message: %v", err)
			}

			var workers sync.WaitGroup
			for range 8 {
				workers.Go(func() {
					var concurrent bytes.Buffer
					if _, err := write(t.Context(), &concurrent); err != nil || !bytes.Equal(expected.Bytes(), concurrent.Bytes()) {
						t.Errorf("concurrent serialization: %v", err)
					}
				})
			}
			workers.Wait()
		})
	}
	redirect, _, _ := begin(t, s, metadata.HTTPRedirect)
	if _, err := redirect.WritePOST(t.Context(), io.Discard); !errors.Is(err, sp.ErrPolicy) {
		t.Fatal(err)
	}
	if _, err := redirect.WritePOSTForm(t.Context(), io.Discard); !errors.Is(err, sp.ErrPolicy) {
		t.Fatal(err)
	}
}

type postFailureWriter struct {
	remaining int
	err       error
}

func (w *postFailureWriter) Write(p []byte) (int, error) {
	if w.remaining <= 0 {
		return 0, w.err
	}
	n := min(w.remaining, len(p))
	w.remaining -= n
	if n < len(p) {
		return n, w.err
	}
	return n, nil
}

func TestPOSTLimitPrecedesStoreCommit(t *testing.T) {
	s := setup(t)
	requests, err := state.NewMemoryStore(state.Config{})
	if err != nil {
		t.Fatal(err)
	}
	sr, err := replay.NewMemoryStore(replay.Config{})
	if err != nil {
		t.Fatal(err)
	}
	service, err := sp.NewServiceProvider(sp.Config{EntityID: spID, Metadata: s.registry, Signing: protocol.SigningKey{Key: s.cert.LeafKey, CertificateDER: s.cert.Leaf.Raw}, Requests: requests, Replay: sr, POSTLimits: binding.POSTLimits{MaxFormBytes: 1}})
	if err != nil {
		t.Fatal(err)
	}
	if out, err := service.Begin(t.Context(), sp.BeginOptions{IDP: idpID, Binding: metadata.HTTPPost, At: testcert.Now(), BrowserBinding: bytes.Repeat([]byte{7}, 32)}); out != nil || !errors.Is(err, binding.ErrBinding) || requests.Len() != 0 {
		t.Fatalf("pending commit: %v %d", err, requests.Len())
	}
	config := s.idpConfig
	replayStore := &countReplayStore{Store: config.Replay}
	config.Replay = replayStore
	config.POSTLimits.MaxFormBytes = 1
	identity, err := idp.NewIdentityProvider(config)
	if err != nil {
		t.Fatal(err)
	}
	out, _, _ := begin(t, s, metadata.HTTPRedirect)
	request, err := identity.AcceptRedirect(t.Context(), out.RawQuery(), spID, ssoRedirect, testcert.Now())
	if err != nil {
		t.Fatal(err)
	}
	if issued, err := identity.Issue(t.Context(), request, auth(), testcert.Now().Add(2*time.Second)); issued != nil || !errors.Is(err, binding.ErrBinding) || replayStore.calls != 0 {
		t.Fatalf("replay commit: %v %d", err, replayStore.calls)
	}
}

type countReplayStore struct {
	replay.Store
	calls int
}

func (s *countReplayStore) Consume(ctx context.Context, entries []replay.Entry, at time.Time) error {
	s.calls++
	return s.Store.Consume(ctx, entries, at)
}
