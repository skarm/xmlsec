// Command sso demonstrates the corresponding XML security API.
// This example exchanges messages locally. An application must provide its own
// HTTP handlers, real user authentication, browser cookies and shared stores.

package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/skarm/xmlsec/examples/internal/democert"
	"github.com/skarm/xmlsec/saml/idp"
	"github.com/skarm/xmlsec/saml/metadata"
	"github.com/skarm/xmlsec/saml/protocol"
	"github.com/skarm/xmlsec/saml/replay"
	"github.com/skarm/xmlsec/saml/sp"
	"github.com/skarm/xmlsec/saml/state"
	"github.com/skarm/xmlsec/xmldsig"
)

const (
	spEntity  = "https://sp.example.test/entity"
	idpEntity = "https://idp.example.test/entity"
	acs       = "https://sp.example.test/acs"
	sso       = "https://idp.example.test/sso"
	authClass = "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"
)

func main() {
	if e := run(); e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
}

func run() error {
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)

	c, e := democert.New(now)
	if e != nil {
		return e
	}

	reg := registry{}

	metadataVerifier, e := metadata.NewVerifier(metadata.Config{TrustedKeys: []crypto.PublicKey{c.RootKey.Public()}, Options: metadata.Options{}})
	if e != nil {
		return e
	}

	specs := []metadata.EntityDescriptor{
		{ID: "_spmetadata", EntityID: spEntity, ValidUntil: now.Add(time.Hour), SP: &metadata.RoleDescriptor{Keys: []metadata.KeyDescriptor{{Use: "signing", CertificateDER: c.Signer.Raw}}, Endpoints: map[string][]metadata.Endpoint{metadata.AssertionConsumerService: {{Binding: metadata.HTTPPost, Location: acs, Indexed: true, Default: true}}}, NameIDFormats: []string{protocol.NameIDPersistent}, AuthnRequestsSigned: true, WantAssertionsSigned: true}},
		{ID: "_idpmetadata", EntityID: idpEntity, ValidUntil: now.Add(time.Hour), IDP: &metadata.RoleDescriptor{Keys: []metadata.KeyDescriptor{{Use: "signing", CertificateDER: c.Peer.Raw}}, Endpoints: map[string][]metadata.Endpoint{metadata.SingleSignOnService: {{Binding: metadata.HTTPRedirect, Location: sso}}}, NameIDFormats: []string{protocol.NameIDPersistent}, WantAuthnRequestsSigned: true}},
	}
	for _, spec := range specs {
		doc, e := metadata.Build(ctx, spec, now, metadata.Options{})
		if e != nil {
			return e
		}

		doc, e = metadata.Sign(ctx, doc, c.RootKey, c.Root.Raw, xmldsig.ECDSASHA256, now, metadata.Options{})
		if e != nil {
			return e
		}

		raw, e := doc.XML(ctx)
		if e != nil {
			return e
		}

		snapshot, e := metadataVerifier.Verify(ctx, raw, now)
		if e != nil {
			return e
		}

		reg[spec.EntityID] = snapshot
	}

	requests, e := state.NewMemoryStore(state.Config{})
	if e != nil {
		return e
	}

	spReplay, e := replay.NewMemoryStore(replay.Config{})
	if e != nil {
		return e
	}

	idpReplay, e := replay.NewMemoryStore(replay.Config{})
	if e != nil {
		return e
	}

	service, e := sp.NewServiceProvider(sp.Config{EntityID: spEntity, Metadata: reg, Signing: protocol.SigningKey{Key: c.SignerKey, CertificateDER: c.Signer.Raw}, Requests: requests, Replay: spReplay})
	if e != nil {
		return e
	}

	identity, e := idp.NewIdentityProvider(idp.Config{EntityID: idpEntity, Metadata: reg, Signing: protocol.SigningKey{Key: c.PeerKey, CertificateDER: c.Peer.Raw}, Replay: idpReplay})
	if e != nil {
		return e
	}

	browserSecret := make([]byte, 32)
	if _, e = rand.Read(browserSecret); e != nil {
		return e
	}

	request, e := service.Begin(ctx, sp.BeginOptions{IDP: idpEntity, BrowserBinding: browserSecret, At: now, NameIDFormat: protocol.NameIDPersistent, RequestedContexts: []string{authClass}, ForceAuthn: true})
	if e != nil {
		return e
	}

	accepted, e := identity.AcceptRedirect(ctx, request.RawQuery(), spEntity, sso, now)
	if e != nil {
		return e
	}
	// In a real IdP these values come from the application's completed, verified
	// authentication, never from untrusted request fields or this sample alone.
	authenticated := idp.Authentication{NameID: "alice", NameIDFormat: protocol.NameIDPersistent, AuthnInstant: now.Add(time.Second), AuthnContext: authClass, FreshAuthentication: true, InteractionUsed: true, SessionIndex: "_session", Attributes: []protocol.Attribute{{Name: "email", Values: []string{"alice@example.test"}}}}

	response, e := identity.Issue(ctx, accepted, authenticated, now.Add(2*time.Second))
	if e != nil {
		return e
	}

	var form bytes.Buffer
	if _, e := response.WritePOST(ctx, &form); e != nil {
		return e
	}

	grant, e := service.ConsumePOST(ctx, form.Bytes(), sp.ConsumeOptions{At: now.Add(3 * time.Second), BrowserBinding: browserSecret})
	if e != nil {
		return e
	}

	fmt.Printf("subject=%s response-authenticated=%t request-correlated=%t\n", grant.NameID(), grant.ResponseAuthenticated(), grant.InResponseTo() == request.RequestID())

	_, e = service.ConsumePOST(ctx, form.Bytes(), sp.ConsumeOptions{At: now.Add(3 * time.Second), BrowserBinding: browserSecret})
	if !errors.Is(e, replay.ErrReplay) {
		if e == nil {
			return errors.New("replay unexpectedly accepted")
		}

		return fmt.Errorf("replay unexpectedly accepted: %w", e)
	}

	fmt.Println("replay=rejected; transport=local-demo; stores=single-process")

	return nil
}

type registry map[string]*metadata.Snapshot

func (r registry) Lookup(ctx context.Context, id string, at time.Time) (*metadata.Entity, error) {
	s, ok := r[id]
	if !ok {
		return nil, metadata.ErrMetadata
	}

	return s.Lookup(ctx, id, at)
}
