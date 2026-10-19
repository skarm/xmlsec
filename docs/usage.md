# API guide

Import packages under `github.com/skarm/xmlsec`; the module root has no Go package.
Use `go doc ./<package>` for signatures, defaults and complete option contracts.
The runnable [examples](../examples) show compositions with disposable keys.
The optional [CLI](cli.md) calls the same public APIs.

## Common contracts

- Cancellation-aware operations take a non-nil `context.Context` first.
  Constructors use `Config`; individual calls use their domain options.
- Document and CMS parsers take explicit limits. Key parsers and exports accept
  `keys.Limits`; zero fields select defaults. Engines retain configured limits.
- Published XML snapshots and compiled programs support concurrent reuse.
  Handles belong to one snapshot. Mutable data returned by accessors is owned
  as documented; adapters remain application-owned.
- Caller-supplied readers and writers remain open. The library closes streams
  acquired from resolvers/transports. Context checks cannot interrupt an arbitrary
  blocked `Read` or `Write`; transports and caller-owned streams must arrange that.
- Writers may leave partial output on error. Byte-returning operations return
  no partial result. `result.WriterTo(ctx)` returns a standard `io.WriterTo`;
  invoke `WriteTo(dst)` to serialize under that context.
- Use `errors.Is` for package errors and cancellation, and `errors.As` for
  structured diagnostics. A diagnostic report is not a verified result.

`document.Name{Space, Local}` is the shared expanded-name type; `Space` is a
namespace URI, not a prefix. `transform.Name` aliases it. Resource adapters
`resource.NewFSResolver` and `NewHTTPResolver` require explicit filesystem/base-URI
or HTTP-client/origin configuration. Consumers enforce budgets; resolution does
not establish trust.

Context-aware cryptographic providers use `ContextSigner` or `ContextDecrypter`
through `AdaptContextSigner` / `AdaptContextDecrypter`. Direct calls through the
standard `crypto.Signer` / `crypto.Decrypter` interfaces have no context parameter.
Providers and application callbacks must satisfy their concurrency contracts.

## XML and canonicalization

`document.Parse(ctx, data, document.DefaultLimits())` and `ParseReader` produce
immutable XML snapshots. `XML(ctx)` returns ordinary UTF-8 XML; `WriteXML(ctx,
dst, maxBytes)` writes it with an output budget. These are not canonicalization.

`c14n.WriteDocument`, `WriteElement` and `WriteNodeSet` write canonical bytes.
The default algorithm is Exclusive C14N. Explicit node sets select individual
nodes, attributes and namespaces; use `Subtree` or `AllNodes` for full selections.
`InclusivePrefixes` applies only to Exclusive C14N. Discard partial output and any
hash state fed by it on error. `XML` collects a complete byte slice; use `WriteXML`
with an explicit output budget when collecting it is unnecessary.
See [streaming](streaming.md) for tree storage and independent-record processing.

## Signatures and coverage

`xmldsig.SignEnveloped` and `Verify` implement the restricted root-enveloped
profile. Supply an externally trusted key and an expected expanded root name.
General XMLDSig requires explicit signature selection and application coverage:

```go
signatures := xmldsig.Signatures(doc)
if signatureIndex < 0 || signatureIndex >= len(signatures) {
    return xmldsig.ErrStructure
}
result, report, err := xmldsig.VerifySignatureDetailed(ctx, doc,
    signatures[signatureIndex], trustedKey, xmldsig.SignatureOptions{
        RequiredElements: []document.Element{payload},
        ExpectedURIs: []string{"#payload"},
    })
if err != nil {
    return err // report describes failure; it is not authenticated content.
}
// Consume the covered payload from this snapshot under application schema rules.
_ = result
_ = report
```

`ExpectedURIs` checks the exact multiset; `RequiredElements` uses handles from
this document. General verification does not require root coverage by default.
`CoversElement` does not establish protocol validity or coverage of comments,
unused namespaces or QName-valued strings. Reparsing or replacing XML creates
another snapshot whose coverage must be established separately.

`BuildTemplate` and `SignTemplate` support explicit references and objects.
Preserving existing signatures requires trusted keys in `Preserve`. Local
Manifest recursion is opt-in and bounded; authenticating Manifest XML alone
does not verify its listed content.

Detached verification requires the exact expected URI set and a resolver.
SignatureValue is authenticated before signed external resources are read.
KeyInfo retrieval is authorized separately and may occur earlier.
`ReferenceResult.WriteDigestInput` explicitly replays approved transforms and
rejects changed external data; keep the resolver usable for that replay.

The default policy permits RSA/ECDSA with SHA-2. `ModernPolicy` adds fixed PSS,
Ed25519 and Ed25519ph; the prehash variant must be selected explicitly and is
not interchangeable with pure Ed25519. `ParameterizedPolicy` enables generic
PSS. HMAC has separate secret APIs and `HMACPolicy`; truncation requires explicit
permission. A MAC does not establish a public-key identity.

## Keys, trust and evidence

`keys.ParsePrivate` and `ParsePublic` accept the supported PEM/DER formats.
`ParseCertificate` and `ParseCRL` return owned X.509 objects. Parsing is bounded
by encoded/decoded sizes, collection counts and key parameters; it performs no
file/network access or trust validation. Ambiguous PEM and trailing DER fail.

`ParseEncryptedPrivate` / `MarshalEncryptedPrivate` use PBES2/PBKDF2 and AES-CBC.
Encrypted PKCS#8 has no integrity tag; use it for key storage, not authenticated
transport. `ParsePKCS12` requires a MAC, one private key and a matching
certificate; extra certificates remain untrusted evidence. `MarshalPKCS12`
defaults to PBMAC1 with UTF-8 passwords. `ClassicMAC` selects classic SHA-2
integrity and BMP-only passwords. Exports require a nonempty password; imports
accept an explicit empty password. Passwords are not normalized. KDF work and
collection limits apply across the operation. Writer variants are described in
[streaming](streaming.md).

`keyinfo.Parse` returns untrusted candidates. `AllowedKeyData: nil` allows
supported forms; an empty list denies all. Retrieval needs an exact URI allowlist
and bounded resolver. `VerifyWithKeyInfo` requires an application trust selector;
an embedded key or certificate is not trust.

`pki.NewVerifier` snapshots explicit roots and policy; it never uses system roots.
Verification requires an explicit time, application EKUs and chosen offline
revocation policy. `KeyPin` checks SPKI identity, not lifetime or revocation.
CMS `Parse` is unauthenticated; `SignedData.Verify` checks the required signers
against supplied certificates. Compose PKIX separately when needed.

Timestamp verification binds a token to an expected imprint and a response to
its original request. Configure TSA trust, allowed policies and revocation.
`Token.UnverifiedInfo()` only selects processing parameters. Claimed signing time
is not trusted time evidence. XAdES validates the closed current-time/with-time
profiles described in [compatibility](compatibility.md).

## XML Encryption

AES-GCM uses an explicit RSA-OAEP SHA-2, AES Key Wrap or direct AES-key suite.
Bytes accept arbitrary plaintext; XML Element/Content operations require UTF-8/NFC.
Decryption authenticates before XML parsing and returns no plaintext on failure.
Element replacement changes the selected element; Content replacement changes
its children. Both return a new snapshot and preserve unrelated content.
Decryption does not authenticate a sender or establish signature coverage.

`Options.OAEP` selects matching SHA-256/384/512 digest and MGF1 with an optional
label. Decryption requires the caller-selected parameters. Direct-key variants
require a matching AES key size and exact configured KeyName hint. Limit a data
key to at most 2^32 encryptions with the randomly generated 96-bit nonces.

`ExternalizeCiphertext` returns XML and owned ciphertext without I/O.
CipherReference decryption requires `Options.External` with one exact absolute
URI and a bounded resolver. Raw ciphertext or one base64 transform is supported;
resource, close, budget and authentication failures return no plaintext.

## SAML and transformations

Compose `saml/sp` and `saml/idp` with authenticated or explicitly trusted metadata.
POST decoding is unauthenticated. Redirect verification authenticates the raw
query before inflation; protocol checks still establish issuer, audience,
destination, correlation, time and authentication conditions.

SP requests bind to unpredictable browser/session secrets. Acceptance atomically
consumes request/assertion IDs after validation. IdP authentication, HTTP handlers,
cookies and endpoints belong to the application. Multiple instances need shared
atomic request/replay stores; memory stores coordinate one process.

The [XPath/XSLT guide](transforms.md) covers typed bindings, reusable programs,
resource policy and [approved XMLDSig programs](transforms.md#xmldsig-v1-compatibility).
