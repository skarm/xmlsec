package sp_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/skarm/xmlsec/saml/idp"
	"github.com/skarm/xmlsec/saml/metadata"
	"github.com/skarm/xmlsec/saml/protocol"
	"github.com/skarm/xmlsec/saml/replay"
	"github.com/skarm/xmlsec/saml/sp"
	"github.com/skarm/xmlsec/saml/state"
)

func ExampleServiceProvider_ConsumePOST() {
	ctx := context.Background()
	at := time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC)

	const (
		spID      = "https://sp.example.test/entity"
		idpID     = "https://idp.example.test/entity"
		acs       = "https://sp.example.test/acs"
		sso       = "https://idp.example.test/sso"
		authClass = "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"
	)

	// Create disposable partner identities, not a PKIX trust infrastructure.
	makeIdentity := func(serial int64) protocol.SigningKey {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			panic(err)
		}

		template := &x509.Certificate{
			SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: "example SAML partner"},
			NotBefore: at.Add(-time.Hour), NotAfter: at.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature,
		}

		der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
		if err != nil {
			panic(err)
		}

		return protocol.SigningKey{Key: key, CertificateDER: der}
	}
	spKey, idpKey := makeIdentity(1), makeIdentity(2)
	specs := []metadata.EntityDescriptor{
		{ID: "_sp", EntityID: spID, ValidUntil: at.Add(time.Hour), SP: &metadata.RoleDescriptor{
			Keys:          []metadata.KeyDescriptor{{Use: "signing", CertificateDER: spKey.CertificateDER}},
			Endpoints:     map[string][]metadata.Endpoint{"AssertionConsumerService": {{Binding: metadata.HTTPPost, Location: acs, Indexed: true, Default: true}}},
			NameIDFormats: []string{protocol.NameIDPersistent}, AuthnRequestsSigned: true, WantAssertionsSigned: true,
		}},
		{ID: "_idp", EntityID: idpID, ValidUntil: at.Add(time.Hour), IDP: &metadata.RoleDescriptor{
			Keys:          []metadata.KeyDescriptor{{Use: "signing", CertificateDER: idpKey.CertificateDER}},
			Endpoints:     map[string][]metadata.Endpoint{"SingleSignOnService": {{Binding: metadata.HTTPRedirect, Location: sso}}},
			NameIDFormats: []string{protocol.NameIDPersistent}, WantAuthnRequestsSigned: true,
		}},
	}

	var aggregate bytes.Buffer
	aggregate.WriteString(`<md:EntitiesDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" validUntil="2026-10-19T13:00:00Z">`)

	for _, spec := range specs {
		doc, err := metadata.Build(ctx, spec, at, metadata.Options{})
		if err != nil {
			panic(err)
		}

		raw, err := doc.XML(ctx)
		if err != nil {
			panic(err)
		}

		aggregate.Write(raw)
	}

	aggregate.WriteString(`</md:EntitiesDescriptor>`)
	// These bytes were provisioned locally. Use metadata.Verifier.Verify for
	// signed metadata received from a partner; ParseTrusted does not authenticate it.
	partners, err := metadata.ParseTrusted(ctx, aggregate.Bytes(), at, metadata.Options{})
	if err != nil {
		panic(err)
	}

	requests, err := state.NewMemoryStore(state.Config{})
	if err != nil {
		panic(err)
	}

	spReplay, err := replay.NewMemoryStore(replay.Config{})
	if err != nil {
		panic(err)
	}

	idpReplay, err := replay.NewMemoryStore(replay.Config{})
	if err != nil {
		panic(err)
	}

	service, err := sp.NewServiceProvider(sp.Config{
		EntityID: spID, Metadata: partners, Signing: spKey, Requests: requests, Replay: spReplay,
	})
	if err != nil {
		panic(err)
	}

	identity, err := idp.NewIdentityProvider(idp.Config{EntityID: idpID, Metadata: partners, Signing: idpKey, Replay: idpReplay})
	if err != nil {
		panic(err)
	}

	browserSecret := make([]byte, 32)
	if _, err := rand.Read(browserSecret); err != nil {
		panic(err)
	}
	defer clear(browserSecret)

	outbound, err := service.Begin(ctx, sp.BeginOptions{
		IDP: idpID, At: at, BrowserBinding: browserSecret,
		NameIDFormat: protocol.NameIDPersistent, RequestedContexts: []string{authClass}, ForceAuthn: true,
	})
	if err != nil {
		panic(err)
	}

	request, err := identity.AcceptRedirect(ctx, outbound.RawQuery(), spID, sso, at)
	if err != nil {
		panic(err)
	}
	// A real IdP supplies these statements only after authenticating the user.
	response, err := identity.Issue(ctx, request, idp.Authentication{
		NameID: "alice", NameIDFormat: protocol.NameIDPersistent,
		AuthnInstant: at.Add(time.Second), AuthnContext: authClass,
		FreshAuthentication: true, InteractionUsed: true,
	}, at.Add(2*time.Second))
	if err != nil {
		panic(err)
	}

	var form bytes.Buffer
	if _, err := response.WritePOST(ctx, &form); err != nil {
		panic(err)
	}

	// A response from another browser must not consume the legitimate request.
	wrongBrowser := append([]byte(nil), browserSecret...)
	wrongBrowser[0] ^= 1

	_, err = service.ConsumePOST(ctx, form.Bytes(), sp.ConsumeOptions{
		At: at.Add(3 * time.Second), BrowserBinding: wrongBrowser,
	})
	clear(wrongBrowser)
	fmt.Println("browser mismatch:", errors.Is(err, sp.ErrCorrelation))

	grant, err := service.ConsumePOST(ctx, form.Bytes(), sp.ConsumeOptions{
		At: at.Add(3 * time.Second), BrowserBinding: browserSecret,
	})
	if err != nil {
		panic(err)
	}

	// Only now may the application create a session. Memory stores coordinate
	// this one process; multiple instances require shared state and replay storage.
	fmt.Println(grant.NameID(), grant.InResponseTo() == outbound.RequestID())

	_, err = service.ConsumePOST(ctx, form.Bytes(), sp.ConsumeOptions{
		At: at.Add(3 * time.Second), BrowserBinding: browserSecret,
	})
	fmt.Println(errors.Is(err, replay.ErrReplay))
	// Output:
	// browser mismatch: true
	// alice true
	// true
}
