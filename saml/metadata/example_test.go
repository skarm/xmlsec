package metadata_test

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"time"

	"github.com/skarm/xmlsec/saml/metadata"
	"github.com/skarm/xmlsec/xmldsig"
)

func ExampleBuild() {
	const acsElement = "AssertionConsumerService"

	ctx := context.Background()
	at := time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC)

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}

	doc, err := metadata.Build(ctx, metadata.EntityDescriptor{
		ID: "_metadata", EntityID: "https://sp.example.test/entity", ValidUntil: at.Add(time.Hour),
		SP: &metadata.RoleDescriptor{
			Endpoints: map[string][]metadata.Endpoint{
				acsElement: {{Binding: metadata.HTTPPost, Location: "https://sp.example.test/acs", Indexed: true, Default: true}},
			},
		},
	}, at, metadata.Options{})
	if err != nil {
		panic(err)
	}

	signed, err := metadata.Sign(ctx, doc, key, nil, xmldsig.ECDSASHA256, at, metadata.Options{})
	if err != nil {
		panic(err)
	}

	raw, err := signed.XML(ctx)
	if err != nil {
		panic(err)
	}
	// Provision the metadata authority's key independently of the received XML.
	verifier, err := metadata.NewVerifier(metadata.Config{TrustedKeys: []crypto.PublicKey{key.Public()}, Options: metadata.Options{}})
	if err != nil {
		panic(err)
	}

	trusted, err := verifier.Verify(ctx, raw, at)
	if err != nil {
		panic(err)
	}

	entity, err := trusted.Lookup(ctx, "https://sp.example.test/entity", at)
	if err != nil {
		panic(err)
	}

	role, err := entity.Role(metadata.ServiceProvider, at)
	if err != nil {
		panic(err)
	}

	endpoint, err := role.ACS(metadata.HTTPPost, nil)
	if err != nil {
		panic(err)
	}

	fmt.Println(trusted.AuthenticatedSignature(), endpoint.Location)
	// Output: true https://sp.example.test/acs
}
