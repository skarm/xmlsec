// Command basic demonstrates the corresponding XML security API.
// An executable example with an ephemeral key. Production key management is
// outside this example; the public key must come from a trusted configuration.

package main

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

func main() {
	ctx := context.Background()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatal(err)
	}

	original, err := document.Parse(ctx, []byte(`<Invoice xmlns="urn:example:invoice" ID="invoice-1"><Amount currency="EUR">125.00</Amount></Invoice>`), document.DefaultLimits())
	if err != nil {
		log.Fatal(err)
	}

	signed, err := xmldsig.SignEnveloped(ctx, original, key, xmldsig.SignOptions{})
	if err != nil {
		log.Fatal(err)
	}

	wire, err := signed.XML(ctx)
	if err != nil {
		log.Fatal(err)
	}

	received, err := document.Parse(ctx, wire, document.DefaultLimits())
	if err != nil {
		log.Fatal(err)
	}

	checked, err := xmldsig.Verify(ctx, received, key.Public(), xmldsig.VerifyOptions{ExpectedRoot: document.Name{Space: "urn:example:invoice", Local: "Invoice"}})
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Verified %d reference(s), method %s\n", len(checked.References()), checked.SignatureMethod())

	for _, ref := range checked.References() {
		fmt.Printf("%s: digest=%x, bytes=%d\n", ref.URI(), ref.Digest(), ref.Size())
	}
}
