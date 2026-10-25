# xmlsec

A Go library for signing, verifying and encrypting XML. It also provides XML
canonicalization, XPath/XSLT, offline certificate and signature evidence
verification, and supported SAML WebSSO flows. Builds without CGO.

## What you can do

- **Sign and verify XML documents** with XMLDSig, including enveloped, enveloping
  and detached signatures.
- **Encrypt and decrypt XML or bytes** with AES-GCM, using direct keys, RSA-OAEP
  or AES Key Wrap.
- **Select, transform and canonicalize XML** with XPath, XSLT and canonicalization
  APIs for documents, subtrees and node sets.
- **Work with keys, certificates and signature evidence** using PEM/DER,
  protected PKCS#8/PKCS#12 containers, offline PKIX validation, CMS, timestamps
  and supported XAdES profiles.
- **Build solicited SAML WebSSO flows** for service providers and identity
  providers, with signed metadata, POST/Redirect bindings and state/replay stores.

The optional [CLI](docs/cli.md) exposes operations through the same public APIs.

## Quick start

Requires **Go 1.27.3 or later**, including the `crypto/x509` security fixes in
[Go 1.27.3](https://go.dev/doc/devel/release#go1.27.3).
To try the library in a new project:

```sh
mkdir invoice-demo
cd invoice-demo
go mod init example.com/invoice-demo
go get github.com/skarm/xmlsec
```

Save the following as `main.go`. It generates a temporary ECDSA key, signs an
invoice, serializes and reparses the signed XML, then verifies the signature
against that key and the expected root element.

```go
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

	doc, err := document.Parse(ctx, []byte(
		`<Invoice xmlns="urn:example:invoice" ID="invoice-1"><Amount currency="EUR">125.00</Amount></Invoice>`,
	), document.DefaultLimits())
	if err != nil {
		log.Fatal(err)
	}

	signed, err := xmldsig.SignEnveloped(ctx, doc, key, xmldsig.SignOptions{})
	if err != nil {
		log.Fatal(err)
	}

	xml, err := signed.XML(ctx)
	if err != nil {
		log.Fatal(err)
	}

	received, err := document.Parse(ctx, xml, document.DefaultLimits())
	if err != nil {
		log.Fatal(err)
	}

	verified, err := xmldsig.Verify(ctx, received, key.Public(), xmldsig.VerifyOptions{
		ExpectedRoot: document.Name{Space: "urn:example:invoice", Local: "Invoice"},
	})
	if err != nil {
		log.Fatal(err)
	}

	// Read application data from the verified snapshot.
	fmt.Println("Verified:", verified.Root().Name().Local)
}
```

Run it with `go run .`. Expected output:

```text
Verified: Invoice
```

The generated key is only for this example. In an application, use your own
signing key and obtain the verification key from a trusted configuration.
Keys and certificates embedded in XML do not establish trust.

Public APIs live in packages such as `document`, `xmldsig`, `xmlenc` and
`transform` under `github.com/skarm/xmlsec`; the module root has no Go package.
If you already have this repository checked out, run `go run ./examples/basic`
for a similar signing and verification example.

## API principles

- **Immutable XML snapshots.** Signing, decrypting and replacing XML return new
  documents. Use element and node handles from the relevant snapshot; after
  verification, read the authenticated content from the verified result.
- **Explicit trust and coverage.** The application supplies trusted keys and
  identifies the content it expects to be signed. Certificate trust and protocol
  validation are separate from XML signature verification.
- **Controlled resource access.** Parsers and operations expose limits; external
  resources require explicit resolvers and policies. Offline trust verification
  does not automatically fetch certificates or revocation data.
- **Context-aware operations.** Operations accept `context.Context` for
  cancellation. See the [API guide](docs/usage.md) for ownership, concurrency and
  I/O contracts, and [streaming and memory](docs/streaming.md) for storage behavior
  and record processing.

## Status and compatibility

The API is **experimental**. The library implements specific profiles of the
listed standards; full standards conformance and an independent security audit
have not been established.

For example, DTDs, external entities and XSD validation are unsupported. The
XPath/XSLT engine implements selected XPath 1.0/2.0/3.0/3.1 and XSLT
1.0/2.0/3.0 features. Complete Basic XSLT conformance remains open;
[suite results](docs/language-baseline.md) record the current failures. Schema
awareness and W3C streamable execution are unsupported. SAML support covers
solicited WebSSO; it does not include SLO, Artifact/ECP or encrypted assertions.

Check [supported profiles and compatibility](docs/compatibility.md) for the full
scope, exclusions and known interoperability differences. The
[conformance register](docs/conformance.json) separates supported capabilities,
normative obligations, policy and remaining gaps. Each declared profile has a
pinned document/role/mode matrix, selected correction IDs and a named clause/contract
inventory. Missing implementation, local tests and independent evidence remain
explicit; inventory completion does not grant a full standards claim;
see [normative traceability](docs/conformance.md) and the pinned
[standards](docs/standards.md).

## Documentation and examples

- **XML signatures:** [basic signing](examples/basic),
  [detached signatures](examples/detached), [multiple signatures](examples/multisig)
  and [KeyInfo](examples/keyinfo).
- **Encryption and trust:** [encryption](examples/encryption),
  [key formats](examples/keys) and [certificate and evidence verification](examples/trust).
- **XML processing:** [XPath/XSLT guide](docs/transforms.md),
  [transform examples](examples/transforms) and [streaming and memory](docs/streaming.md).
- **SAML:** [WebSSO example](examples/sso) and [Redirect binding](examples/redirect).
- **Reference:** [API guide](docs/usage.md), [all examples](examples),
  [CLI](docs/cli.md), [package architecture](docs/architecture.md) and
  [security policy](SECURITY.md).

### Development

From the repository root, with Go, make and a POSIX shell:

```sh
make check race examples
```

See [testing and profiling](docs/testing.md) for lint, fuzzing and optional native
interoperability checks. Build the CLI with `make build` (`bin/xmlsec`), or run
`go run ./cmd/xmlsec --help`.

### License

[MIT](LICENSE). Third-party notices are retained in adapted sources and
[licenses](licenses). See [XPath/XSLT source provenance](docs/engine-origin.md)
for origins and local modifications.
