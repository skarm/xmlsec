// Command manifest demonstrates the corresponding XML security API.
// This example signs a Manifest graph and one application-allowlisted attachment.
// No network access or private-key files are used.

package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"io"
	"log"
	"strings"

	"github.com/skarm/xmlsec/c14n"
	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/reference"
	"github.com/skarm/xmlsec/xmldsig"
)

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	ctx := context.Background()

	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}

	payload := "a signed XML object"
	canonical := []reference.Transform{{Algorithm: c14n.Exclusive}}

	template, selected, err := xmldsig.BuildTemplate(ctx, nil, document.Element{}, xmldsig.SignatureTemplate{
		ID: "signature", SignatureMethod: xmldsig.Ed25519,
		References: []xmldsig.ReferenceTemplate{{URI: "#manifest", Type: xmldsig.ManifestType, Transforms: canonical}},
		Objects: []xmldsig.ObjectTemplate{
			{Manifest: &xmldsig.ManifestTemplate{ID: "manifest", References: []xmldsig.ReferenceTemplate{
				{URI: "#payload", Transforms: canonical}, {URI: uriUrnExampleAttachment},
			}}},
			{ID: "payload", Text: &payload},
		},
	})
	if err != nil {
		return err
	}

	fetches := 0
	opt := xmldsig.SignatureOptions{
		Policy: xmldsig.ModernPolicy(), ExpectedURIs: []string{"#manifest"},
		Manifests: xmldsig.ManifestPolicy{Mode: xmldsig.ManifestRecursive, MaxDepth: 4, MaxManifests: 8, MaxReferences: 16},
		External: &xmldsig.ExternalReferences{
			AllowedURIs: []string{uriUrnExampleAttachment},
			Resolver: xmldsig.ResolverFunc(func(ctx context.Context, uri string) (io.ReadCloser, error) {
				if err := ctx.Err(); err != nil {
					return nil, err
				}

				if uri != uriUrnExampleAttachment {
					return nil, fmt.Errorf("unexpected resource %q", uri)
				}

				fetches++

				return io.NopCloser(strings.NewReader("external binary-safe data")), nil
			}),
		},
	}

	signed, err := xmldsig.SignTemplate(ctx, template, selected, key, xmldsig.TemplateSignOptions{Validation: opt})
	if err != nil {
		return err
	}

	if fetches != 1 {
		return fmt.Errorf("signing/self-check fetched %d times", fetches)
	}

	raw, err := signed.XML(ctx)
	if err != nil {
		return err
	}

	received, err := document.Parse(ctx, raw, document.DefaultLimits())
	if err != nil {
		return err
	}
	// A standalone Signature is the exact selected root; no first-signature guess.
	result, report, err := xmldsig.VerifySignatureDetailed(ctx, received, received.Root(), key.Public(), opt)
	if err != nil {
		return err
	}

	fmt.Printf("signature=%s manifests=%s direct=%d manifest-count=%d fetches=%d\n", report.SignatureValue, report.ManifestValidation, len(result.References()), len(result.Manifests()), fetches)

	for _, m := range result.Manifests() {
		for _, ref := range m.References() {
			fmt.Printf("uri=%s digest-input-bytes=%d xml-source-covered=%t\n", ref.URI(), ref.Size(), result.CoversElement(ref.Target()))
		}
	}

	return nil
}
