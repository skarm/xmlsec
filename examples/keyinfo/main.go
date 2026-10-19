// Command keyinfo demonstrates the corresponding XML security API.
// A complete local example with an explicit public-key pin. The embedded key is
// never itself the source of trust. The demo key is temporary and not persisted.

package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"fmt"
	"os"

	"github.com/skarm/xmlsec/c14n"
	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/keyinfo"
	"github.com/skarm/xmlsec/reference"
	"github.com/skarm/xmlsec/xmldsig"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	ctx := context.Background()

	signer, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	// In a service this pin comes from trusted configuration for the expected
	// partner, NOT from the incoming signature or its KeyName/X509Certificate.
	trustedSPKI, err := x509.MarshalPKIXPublicKey(&signer.PublicKey)
	if err != nil {
		return err
	}

	expectedPin := sha256.Sum256(trustedSPKI)

	info, err := keyinfo.Build(ctx, keyinfo.Template{ID: "signer-key", Keys: []keyinfo.PublicKeyValue{{Key: &signer.PublicKey, Format: keyinfo.XMLKeyValue}}})
	if err != nil {
		return err
	}

	text := "message whose exact Object must be signed"

	template, signature, err := xmldsig.BuildTemplate(ctx, nil, document.Element{}, xmldsig.SignatureTemplate{SignatureMethod: xmldsig.ECDSASHA256, KeyInfo: info, References: []xmldsig.ReferenceTemplate{{URI: "#payload", Transforms: []reference.Transform{{Algorithm: c14n.Exclusive}}}}, Objects: []xmldsig.ObjectTemplate{{ID: "payload", Text: &text}}})
	if err != nil {
		return err
	}

	signed, err := xmldsig.SignTemplate(ctx, template, signature, signer, xmldsig.TemplateSignOptions{})
	if err != nil {
		return err
	}

	wire, err := signed.XML(ctx)
	if err != nil {
		return err
	}

	received, err := document.Parse(ctx, wire, document.DefaultLimits())
	if err != nil {
		return err
	}

	signatures := xmldsig.Signatures(received)
	if len(signatures) != 1 {
		return errors.New("expected one signature")
	}

	var payload document.Element

	for _, e := range received.Root().Children() {
		id, _ := e.Attribute(document.Name{Local: "Id"})
		if e.Name() == (document.Name{Space: xmldsig.Namespace, Local: "Object"}) && id == "payload" {
			payload = e
		}
	}

	if !payload.Valid() {
		return errors.New("expected Object missing")
	}

	result, err := xmldsig.VerifySignatureWithKeyInfo(ctx, received, signatures[0], xmldsig.KeyInfoVerifyOptions{
		Signature: xmldsig.SignatureOptions{RequiredElements: []document.Element{payload}, ExpectedURIs: []string{"#payload"}},
		KeyInfo:   keyinfo.Options{AllowedKeyData: []document.Name{{Space: keyinfo.Namespace11, Local: "ECKeyValue"}}},
		SelectTrustedKey: func(ctx context.Context, untrusted *keyinfo.Result) (int, error) {
			if err := ctx.Err(); err != nil {
				return -1, err
			}

			for i, c := range untrusted.Candidates() {
				if sha256.Sum256(c.SPKI()) == expectedPin {
					return i, nil
				}
			}

			return -1, errors.New("no key authorized for the expected partner")
		},
	})
	if err != nil {
		return err
	}

	fmt.Printf("references=%d payload-covered=%t signature-container-covered=%t\n", len(result.References()), result.CoversElement(payload), result.CoversElement(received.Root()))
	fmt.Printf("verified payload: %s\n", payload.Text())

	return nil
}
