package binding_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"

	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/saml/binding"
	"github.com/skarm/xmlsec/xmldsig"
)

func ExampleSignRedirect() {
	ctx := context.Background()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}

	doc, err := document.Parse(ctx, []byte(`<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_request"/>`), document.DefaultLimits())
	if err != nil {
		panic(err)
	}

	relay := "opaque-login-handle"
	options := binding.Options{SignatureMethod: xmldsig.ECDSASHA256}

	rawQuery, err := binding.SignRedirect(ctx, doc, binding.Request, &relay, key, options)
	if err != nil {
		panic(err)
	}
	// Use the received raw query: parsing and re-encoding changes signed bytes.
	verified, err := binding.VerifyRedirect(ctx, rawQuery, key.Public(), options)
	if err != nil {
		panic(err)
	}

	// Only binding integrity was checked. Protocol and replay checks are separate.
	fmt.Println(verified.Kind())
	// Output: SAMLRequest
}

func ExampleDecodePOST() {
	doc, err := document.Parse(context.Background(), []byte(`<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"/>`), document.DefaultLimits())
	if err != nil {
		panic(err)
	}

	form, err := binding.EncodePOST(context.Background(), doc, binding.Response, nil, binding.POSTLimits{})
	if err != nil {
		panic(err)
	}

	message, err := binding.DecodePOST(context.Background(), form, binding.Response, binding.POSTLimits{})
	if err != nil {
		panic(err)
	}

	// Decoding is unauthenticated; verify XML signatures and protocol expectations.
	fmt.Println(message.Parameter(), message.UnverifiedDocument().Root().Name().Local)
	// Output: SAMLResponse Response
}
