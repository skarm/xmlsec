# xmlsec

Go toolkit for XML signatures, encryption, XPath/XSLT, offline trust and evidence,
and solicited SAML WebSSO. Requires Go 1.27.0 or later; builds without CGO.
License: [MIT](LICENSE).

The API is experimental. See [supported profiles and compatibility](docs/compatibility.md)
for scope, exclusions and known differences. Full standards conformance and an
independent security audit have not been established.

## Use

```sh
go get github.com/skarm/xmlsec
```

Import public packages such as `github.com/skarm/xmlsec/document` and
`github.com/skarm/xmlsec/xmldsig`; the module root has no Go package.
This example signs and verifies a root-enveloped document:

```go
doc, err := document.Parse(ctx, []byte(`<invoice ID="invoice-1"><amount>123</amount></invoice>`), document.DefaultLimits())
if err != nil {
    return err
}
signed, err := xmldsig.SignEnveloped(ctx, doc, signer, xmldsig.SignOptions{})
if err != nil {
    return err
}
result, err := xmldsig.Verify(ctx, signed, trustedPublicKey, xmldsig.VerifyOptions{
    ExpectedRoot: document.Name{Local: "invoice"},
})
if err != nil {
    return err
}
// Consume result.Root() from this verified snapshot.
fmt.Println("Verified:", result.Root().Name().Local)
```

Supply a `context.Context` as `ctx`, an application-managed `crypto.Signer` as
`signer`, and an externally trusted `crypto.PublicKey` as `trustedPublicKey`.
The fragment uses `fmt`, `document` and `xmldsig`. Embedded keys and certificates
do not establish trust. XML signature verification does not perform PKIX or protocol
validation. Run the complete example with `go run ./examples/basic`.

## Packages

- `document`, `c14n`: immutable XML, node sets and canonicalization.
- `reference`, `xmldsig`, `keyinfo`: signatures, references and untrusted key descriptions.
- `xmlenc`: AES-GCM with direct keys, RSA-OAEP SHA-2 or AES Key Wrap.
- `keys`: PEM/DER keys, certificates, CRLs and protected PKCS#8/PKCS#12 containers.
- `pki`, `cms`, `timestamp`, `xades`: offline trust and evidence profiles.
- `saml/...`: authenticated metadata, bindings and solicited WebSSO with state/replay stores.
- `resource`: explicit filesystem and HTTP adapters shared by library consumers.
- `transform`: XPath 1.0/2.0/3.0/3.1, XSLT 1.0 and Basic XSLT 2.0/3.0.

The optional [CLI](docs/cli.md) uses the same public APIs. Run
`go run ./cmd/xmlsec --help` or build it with `make build` (`bin/xmlsec`).

## Streaming and memory

`document.ParseReader` reads incrementally but retains the complete XML tree and
the current lexical token. `Document.WriteXML`, C14N writers and digest-based
message signing avoid collecting a complete serialized message. A `[]byte`
result or a caller-owned `bytes.Buffer` still retains the complete output.

XSLT computes a complete result before serialization. `Result.WriterTo(ctx)`
returns an `io.WriterTo`; it reduces serialization buffering for common output
options. `document.ReadRecords` and `Stylesheet.WriteRecords` process independent
subtrees without retaining the enclosing tree. Memory includes the current
record and result, parser tokens, stylesheet, parameters and loaded resources.
W3C streamable XSLT execution is unsupported.

Pure Ed25519 and AES-GCM need complete messages; CMS and timestamp parsing retain
complete bounded DER containers. Limits bound data and work, not exact heap usage
or RSS. See [streaming and memory](docs/streaming.md) for per-API storage behavior,
buffered serialization options, cancellation and partial-output contracts.

## Development

```sh
make check race examples
```

Run from the module root with Go, make and a POSIX shell. See [testing](docs/testing.md)
for lint, fuzzing and optional native interoperability checks.

## Documentation

- [API guide](docs/usage.md) and runnable [examples](examples)
- [XPath/XSLT](docs/transforms.md) and [streaming/memory](docs/streaming.md)
- [Supported profiles](docs/compatibility.md), [standards](docs/standards.md)
  and [conformance register](docs/conformance.json)
- [CLI](docs/cli.md), [testing and profiling](docs/testing.md)
- [Security policy](SECURITY.md)

Third-party notices remain in adapted sources and [licenses](licenses).
See [XPath/XSLT source provenance](docs/engine-origin.md) for origins and local modifications.
