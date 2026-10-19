package protocol_test

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"time"

	"github.com/skarm/xmlsec/saml/metadata"
	"github.com/skarm/xmlsec/saml/protocol"
)

func ExampleSignAuthnRequest() {
	const (
		requestID   = "_request"
		consumerURL = "https://sp.example.test/acs"
		spEntity    = "https://sp.example.test/entity"
		idpEntity   = "https://idp.example.test/entity"
	)

	ctx := context.Background()
	at := time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC)

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}

	signed, err := protocol.SignAuthnRequest(ctx, protocol.AuthnRequest{
		ID: requestID, Issuer: spEntity, IssueInstant: at,
		Destination: "https://idp.example.test/sso", ACS: consumerURL,
		NameIDFormat: protocol.NameIDPersistent, ForceAuthn: true,
	}, protocol.SigningKey{Key: key})
	if err != nil {
		panic(err)
	}
	// Keys and endpoint expectations come from trusted partner configuration.
	accepted, err := protocol.VerifyAuthnRequest(ctx, signed, []crypto.PublicKey{key.Public()}, protocol.RequestOptions{
		Issuer: spEntity, Destination: "https://idp.example.test/sso", At: at,
		ACS: []metadata.Endpoint{{Binding: metadata.HTTPPost, Location: consumerURL}},
	})
	if err != nil {
		panic(err)
	}

	fmt.Println(accepted.ID(), accepted.ForceAuthn())
	// Output: _request true
}

func ExampleSignResponse() {
	const (
		subject     = "alice"
		requestID   = "_request"
		consumerURL = "https://sp.example.test/acs"
		spEntity    = "https://sp.example.test/entity"
		idpEntity   = "https://idp.example.test/entity"
	)

	ctx := context.Background()
	at := time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC)

	idpKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	// Assertion data represents a completed application authentication decision.
	signed, err := protocol.SignResponse(ctx, protocol.Response{
		ID: "_response", Issuer: idpEntity, Audience: spEntity,
		Destination: consumerURL, InResponseTo: requestID, IssueInstant: at,
		Assertion: protocol.AssertionData{
			ID: "_example_assertion", NameID: subject, NameIDFormat: protocol.NameIDPersistent,
			NotBefore: at, NotOnOrAfter: at.Add(time.Minute), AuthnInstant: at,
			AuthnContext: "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport",
		},
	}, protocol.SigningKey{Key: idpKey})
	if err != nil {
		panic(err)
	}

	accepted, err := protocol.VerifyResponse(ctx, signed, []crypto.PublicKey{idpKey.Public()}, protocol.ResponseOptions{
		Issuer: idpEntity, Audience: spEntity,
		Destination: consumerURL, ExpectedRequestID: requestID,
		At: at, RequestIssueInstant: at,
		AllowedNameIDFormats: []string{protocol.NameIDPersistent},
	})
	if err != nil {
		panic(err)
	}

	// Browser correlation, replay consumption and session creation are separate.
	fmt.Println(accepted.NameID(), accepted.InResponseTo(), accepted.ResponseAuthenticated())
	// Output: alice _request true
}
