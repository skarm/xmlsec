package idp_test

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/skarm/xmlsec/saml/binding"
	"github.com/skarm/xmlsec/saml/idp"
	"github.com/skarm/xmlsec/saml/metadata"
	"github.com/skarm/xmlsec/saml/protocol"
	"github.com/skarm/xmlsec/saml/replay"
)

func ExampleIdentityProvider_Issue() {
	ctx := context.Background()
	at := time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC)

	const (
		spID  = "https://sp.example.test/entity"
		idpID = "https://idp.example.test/entity"
		acs   = "https://sp.example.test/acs"
		sso   = "https://idp.example.test/sso"
	)

	spKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}

	idpKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}

	certificates := make([]string, 0, 2)

	for index, key := range []*ecdsa.PrivateKey{spKey, idpKey} {
		cert := &x509.Certificate{
			SerialNumber: big.NewInt(int64(index + 1)), Subject: pkix.Name{CommonName: "local SAML example"},
			NotBefore: at.Add(-time.Hour), NotAfter: at.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature,
		}

		raw, err := x509.CreateCertificate(rand.Reader, cert, cert, key.Public(), key)
		if err != nil {
			panic(err)
		}

		certificates = append(certificates, base64.StdEncoding.EncodeToString(raw))
	}
	// An operator-provisioned aggregate binds partner keys and exact endpoints.
	// ParseTrusted is only for already-trusted bytes, not arbitrary downloaded XML.
	rawMetadata := fmt.Sprintf(`<md:EntitiesDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" validUntil="2026-10-19T13:00:00Z">
 <md:EntityDescriptor entityID="%s">
  <md:SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol" AuthnRequestsSigned="true" WantAssertionsSigned="true">
   <md:KeyDescriptor use="signing"><ds:KeyInfo><ds:X509Data><ds:X509Certificate>%s</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>
   <md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="%s" index="0"/>
  </md:SPSSODescriptor>
 </md:EntityDescriptor>
 <md:EntityDescriptor entityID="%s">
  <md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol" WantAuthnRequestsSigned="true">
   <md:KeyDescriptor use="signing"><ds:KeyInfo><ds:X509Data><ds:X509Certificate>%s</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>
   <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="%s"/>
  </md:IDPSSODescriptor>
 </md:EntityDescriptor>
 </md:EntitiesDescriptor>`, spID, certificates[0], acs, idpID, certificates[1], sso)

	partners, err := metadata.ParseTrusted(ctx, []byte(rawMetadata), at, metadata.Options{})
	if err != nil {
		panic(err)
	}

	store, err := replay.NewMemoryStore(replay.Config{})
	if err != nil {
		panic(err)
	}

	identity, err := idp.NewIdentityProvider(idp.Config{
		EntityID: idpID, Metadata: partners, Signing: protocol.SigningKey{Key: idpKey}, Replay: store,
	})
	if err != nil {
		panic(err)
	}

	signed, err := protocol.SignAuthnRequest(ctx, protocol.AuthnRequest{
		ID: "_request", Issuer: spID, Destination: sso, ACS: acs, IssueInstant: at, ForceAuthn: true,
	}, protocol.SigningKey{Key: spKey})
	if err != nil {
		panic(err)
	}

	form, err := binding.EncodePOST(ctx, signed, binding.Request, nil, binding.POSTLimits{})
	if err != nil {
		panic(err)
	}

	request, err := identity.AcceptPOST(ctx, form, spID, sso, at)
	if err != nil {
		panic(err)
	}
	// These facts come from completed application authentication, not request XML.
	authentication := idp.Authentication{
		NameID: "alice", AuthnInstant: at, FreshAuthentication: true, InteractionUsed: true,
		AuthnContext: "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport",
	}

	response, err := identity.Issue(ctx, request, authentication, at)
	if err != nil {
		panic(err)
	}

	accepted, err := protocol.VerifyResponse(ctx, response.Document(), []crypto.PublicKey{idpKey.Public()}, protocol.ResponseOptions{
		Issuer: idpID, Audience: spID, Destination: acs, ExpectedRequestID: "_request", At: at,
	})
	if err != nil {
		panic(err)
	}

	fmt.Println(response.Destination(), accepted.NameID())

	_, err = identity.Issue(ctx, request, authentication, at)
	fmt.Println(errors.Is(err, replay.ErrReplay))
	// Output:
	// https://sp.example.test/acs alice
	// true
}
