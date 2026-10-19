package xmldsig_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"log"

	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/xmldsig"
)

func ExampleSignEnveloped() {
	ctx := context.Background()
	// This example generates a key for one round trip. A receiver must obtain
	// its trusted verification key from application configuration.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatal(err)
	}

	doc, err := document.Parse(ctx, []byte(`<invoice ID="invoice-1"><amount>42</amount></invoice>`), document.DefaultLimits())
	if err != nil {
		log.Fatal(err)
	}

	signed, err := xmldsig.SignEnveloped(ctx, doc, key, xmldsig.SignOptions{})
	if err != nil {
		log.Fatal(err)
	}

	result, err := xmldsig.Verify(ctx, signed, &key.PublicKey, xmldsig.VerifyOptions{
		ExpectedRoot: document.Name{Local: "invoice"},
	})
	if err != nil {
		log.Fatal(err)
	}

	// Consume the verified snapshot returned by the verifier.
	fmt.Println(result.Root().Name().Local)
	// Output: invoice
}
