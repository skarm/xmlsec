// Command detached demonstrates the corresponding XML security API.
// Example: a standalone XMLDSig over binary data and a canonicalized XML file.
// The in-memory resolver is an exact allowlist, not an HTTP or filesystem client.

package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"io"
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

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}

	payloads := map[string][]byte{
		uriUrnExampleBinary:  {0, 1, 2, 255},
		uriUrnExampleInvoice: []byte(`<Invoice currency="EUR" number="42"><Amount>10.00</Amount></Invoice>`),
	}
	resolver := xmldsig.ResolverFunc(func(ctx context.Context, uri string) (io.ReadCloser, error) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		payload, ok := payloads[uri]
		if !ok {
			return nil, fmt.Errorf("unapproved URI %q", uri)
		}

		return io.NopCloser(bytes.NewReader(payload)), nil
	})
	recipes := []xmldsig.DetachedReference{
		{URI: uriUrnExampleBinary}, // Exact binary bytes, no automatic XML parsing.
		{URI: uriUrnExampleInvoice, Transforms: []reference.Transform{{Algorithm: c14n.Canonical11}}},
	}

	signed, err := xmldsig.SignDetached(ctx, recipes, key, resolver, xmldsig.DetachedSignOptions{})
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

	result, err := xmldsig.VerifyDetached(ctx, received, key.Public(), resolver, xmldsig.DetachedVerifyOptions{
		ExpectedURIs: []string{uriUrnExampleBinary, uriUrnExampleInvoice},
		Processing:   reference.Options{AllowedTransforms: []string{c14n.Canonical11}},
	})
	if err != nil {
		return err
	}

	fmt.Printf("Verified %d resources with %s\n", len(result.References()), result.SignatureMethod())

	for _, ref := range result.References() {
		fmt.Printf("%s: %d digest-input bytes, %d processing steps\n", ref.URI(), ref.Size(), len(ref.Steps()))
	}

	return nil
}
