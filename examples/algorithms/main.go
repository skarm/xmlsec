// Command algorithms demonstrates the corresponding XML security API.
// Example: exact RSA-PSS parameters and a separate HMAC trust model.

package main

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"os"

	"github.com/skarm/xmlsec/c14n"
	"github.com/skarm/xmlsec/document"
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

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}

	message := "this Object, not the entire Signature container, is protected"
	spec := xmldsig.SignatureTemplate{
		SignatureMethod:     xmldsig.RSAPSS,
		SignatureParameters: xmldsig.SignatureParameters{PSS: &xmldsig.PSSParameters{Hash: crypto.SHA384, MGFHash: crypto.SHA384, SaltLength: 24}},
		References:          []xmldsig.ReferenceTemplate{{URI: "#payload", Transforms: []reference.Transform{{Algorithm: c14n.Exclusive}}}},
		Objects:             []xmldsig.ObjectTemplate{{ID: "payload", Text: &message}},
	}

	draft, selected, err := xmldsig.BuildTemplate(ctx, nil, document.Element{}, spec)
	if err != nil {
		return err
	}

	opt := xmldsig.SignatureOptions{Policy: xmldsig.ParameterizedPolicy(), ExpectedURIs: []string{"#payload"}}

	signed, err := xmldsig.SignTemplate(ctx, draft, selected, key, xmldsig.TemplateSignOptions{Validation: opt})
	if err != nil {
		return err
	}

	raw, err := signed.XML(ctx)
	if err != nil {
		return err
	}

	signed, err = document.Parse(ctx, raw, document.DefaultLimits())
	if err != nil {
		return err
	}

	result, err := xmldsig.VerifySignature(ctx, signed, signed.Root(), key.Public(), opt)
	if err != nil {
		return err
	}

	p := result.Parameters().PSS
	fmt.Printf("RSA-PSS: hash=%v mgf=%v salt=%d references=%d container-covered=%v\n", p.Hash, p.MGFHash, p.SaltLength, len(result.References()), result.CoversElement(signed.Root()))

	// This secret is local to the demo, never printed or written to disk.
	secret := make([]byte, 32)
	if _, err = rand.Read(secret); err != nil {
		return err
	}
	defer clear(secret)

	spec.SignatureMethod = xmldsig.HMACSHA256
	spec.SignatureParameters = xmldsig.SignatureParameters{}

	draft, selected, err = xmldsig.BuildTemplate(ctx, nil, document.Element{}, spec)
	if err != nil {
		return err
	}

	opt.Policy = xmldsig.HMACPolicy()

	authenticated, err := xmldsig.SignHMACTemplate(ctx, draft, selected, secret, xmldsig.TemplateSignOptions{Validation: opt})
	if err != nil {
		return err
	}

	raw, err = authenticated.XML(ctx)
	if err != nil {
		return err
	}

	authenticated, err = document.Parse(ctx, raw, document.DefaultLimits())
	if err != nil {
		return err
	}

	macResult, err := xmldsig.VerifyHMACSignature(ctx, authenticated, authenticated.Root(), secret, opt)
	if err != nil {
		return err
	}

	fmt.Printf("HMAC: output-bits=%d references=%d container-covered=%v\n", macResult.OutputLength(), len(macResult.References()), macResult.CoversElement(authenticated.Root()))

	return nil
}
