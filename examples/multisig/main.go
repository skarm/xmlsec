// Command multisig demonstrates the corresponding XML security API.
// This executable example uses two independent temporary keys. Both signatures
// cover the item, NOT the unsigned root envelope. No private keys are written.

package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"log"

	"github.com/skarm/xmlsec/c14n"
	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/xmldsig"
)

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func signature(id string) string {
	return fmt.Sprintf(`<ds:Signature xmlns:ds="%s" Id="%s"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="%s"/><ds:SignatureMethod Algorithm="%s"/><ds:Reference URI="#payload"><ds:Transforms><ds:Transform Algorithm="%s"/></ds:Transforms><ds:DigestMethod Algorithm="%s"/><ds:DigestValue/></ds:Reference></ds:SignedInfo><ds:SignatureValue/></ds:Signature>`, xmldsig.Namespace, id, c14n.Exclusive, xmldsig.ECDSASHA256, c14n.Exclusive, xmldsig.SHA256)
}

func run() error {
	ctx := context.Background()

	first, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}

	second, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}

	doc, err := document.Parse(ctx, []byte(`<envelope><item ID="payload">signed data</item>`+signature("first")+signature("second")+`<note>unsigned</note></envelope>`), document.DefaultLimits())
	if err != nil {
		return err
	}

	opt := xmldsig.SignatureOptions{ExpectedURIs: []string{"#payload"}, RequiredElements: []document.Element{doc.Root().Children()[0]}}

	one, err := xmldsig.SignTemplate(ctx, doc, xmldsig.Signatures(doc)[0], first, xmldsig.TemplateSignOptions{Validation: opt})
	if err != nil {
		return err
	}
	// Handles must be renewed for the newly returned snapshot.
	opt.RequiredElements = []document.Element{one.Root().Children()[0]}
	selections := xmldsig.Signatures(one)

	both, err := xmldsig.SignTemplate(ctx, one, selections[1], second, xmldsig.TemplateSignOptions{
		Validation: opt,
		Preserve:   []xmldsig.SignatureRequirement{{Signature: selections[0], PublicKey: &first.PublicKey, Options: opt}},
	})
	if err != nil {
		return err
	}

	raw, err := both.XML(ctx)
	if err != nil {
		return err
	}

	received, err := document.Parse(ctx, raw, document.DefaultLimits())
	if err != nil {
		return err
	}

	opt.RequiredElements = []document.Element{received.Root().Children()[0]}
	for i, key := range []*ecdsa.PrivateKey{first, second} {
		result, err := xmldsig.VerifySignature(ctx, received, xmldsig.Signatures(received)[i], &key.PublicKey, opt)
		if err != nil {
			return err
		}

		fmt.Printf("signature=%d references=%d payload-covered=%t root-covered=%t\n", i, len(result.References()), result.CoversElement(received.Root().Children()[0]), result.CoversElement(received.Root()))
	}

	return nil
}
