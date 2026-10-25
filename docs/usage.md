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

Resolver streams may implement `resource.TypedReader` to expose a stable MIME
`MediaType()` value, including `charset`. `NewHTTPResolver` preserves the
response Content-Type. Text functions use this transport metadata through the
same bounded read/close path; it does not authorize another resource access.

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

Set `ManifestPolicy.AllowTransformed` explicitly to recurse into a typed
`Type=ManifestType` reference whose approved transforms produce standalone
Manifest XML. This works with local Base64 objects and external Base64,
XPath/Filter2/XSLT pipelines. The same processing pass captures the exact final
digest input; only a matching incoming digest permits parsing and following its
children. Derived scopes share graph, node and byte budgets and use the containing
retrieval URI plus output digest as their identity. `ManifestResult.Transformed()`
and report `transformed` identify these scopes. Their IDs refer to derived XML;
original-node coverage is never inferred from a transformed Manifest. References
that preserve complete original XML retain the existing provenance checks.

For an external Manifest subresource such as `https://example.test/list.xml#part`,
allowlist the complete URI. The resolver receives that complete string and must
return the selected Manifest as standalone XML octets, including the context
needed for its nested references. Returning the whole containing XML file while
silently ignoring `#part` violates this adapter contract. The library does not
fetch that file and guess its ID typing or fragment serialization.

`ExternalReferences.BaseURI` explicitly enables relative URI resolution. Set it
to the trusted absolute, hierarchical URI of the signature document and put
resolved absolute URIs in `AllowedURIs`. References in an external Manifest use
that resource's resolved URI as their retrieval base. Inherited `xml:base` on
permitted application containers participates; empty `xml:base` inherits the
current base. XMLDSig's existing attribute grammar is unchanged. No redirect or
MIME metadata is inferred from a plain reader. An adapter that redirects or
selects from another containing document must preserve the intended context in
the supplied octets or use application-selected absolute nested references.

`ReferenceResult.URI()` and report `uri` preserve the signed spelling;
`ResourceURI()` and report `resource_uri` expose the actual authorized resolver
URI. Replay uses that retained URI. `ExpectedURIs` still checks signed spelling.
Empty and fragment-only references always address their containing document.
These options apply to the general Signature API; the narrow detached API
retains its literal-URI contract. KeyInfo has its own separately authorized
`ExternalResources.BaseURI` option, described below.
Core CLI signing and verification expose the same opt-in as `-base-uri`, together
with the existing trusted `-resources` file.
Approved extension transforms execute separately for each Reference, preserving
their original expression context. Their resource bytes can be read again under
the aggregate byte limit; a repeated URI does not bypass the processor's runtime
checks. Built-in transform results can share processing evidence.

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
and bounded resolver. rawX509Certificate retrieval accepts raw certificate bytes
or one Base64 transform by default. Build additional descriptions with
`Template.RetrievalMethods`; set `Options.RetrievalProcessing` explicitly to use
the shared reference transform allowlist and budgets. XPath/Filter2/XSLT also
require an exact approved program and a trusted extension processor. The complete
chain is preflighted before resource access. Type describes its final result:
one XML element/document, or DER octets for rawX509Certificate. Aggregate
`MaxTransformBytes`/`MaxTransformNodes` bound intermediate work across links.
Omitted DSAKeyValue P/Q/G can come from `Options.DSAParameters`; that context
is copied before callbacks, requires the bounded 1024/160 profile, and supplies
no trust or algorithm permission. Builders emit complete DSA descriptions.
`VerifySignatureWithKeyInfo` requires an application trust selector;
an embedded key or certificate is not trust.

For external KeyInfoReference/RetrievalMethod links, authorize complete absolute
URIs, including any fragment. The trusted resolver supplies the identified octets
or standalone XML. `keyinfo.ExternalResources.BaseURI` explicitly enables relative
URI and inherited `xml:base` resolution before the exact allowlist check. Nested
links use the containing resource URI; empty and fragment-only links stay local.
Base/allowlist options are copied before callbacks. Candidate `ResourceURI()` and
`ExternalURIs()` retain the resolved identity. KeyInfo permissions never grant
signed-data resource access, or the reverse. No automatic network or fragment
selector is added.

`keyinfo.Template.X509Data` builds separate groups of certificates, v2 CRLs,
issuer/serial pairs, subject names, plain SKI values and certificate digests.
`Template.Certificates` still supplies the first separate certificate group.
Builders preserve original DER and caller-supplied XMLDSig/RFC 4514 DN spelling;
issuer serial numbers use the parser's nonnegative decimal normalization.
All group sources are budgeted before DER parsing and Base64 allocation.
The builder checks representation syntax; certificate/selector matching, chain
relationships and revocation remain application policy. A selector-only group
contains no candidate and triggers no certificate lookup. Sign a reference to the
KeyInfo when those metadata must be authenticated, and require that coverage when
verifying. Authenticating a selector still requires an application trust decision.

`pki.NewVerifier` snapshots explicit roots and policy; it never uses system roots.
Verification requires an explicit time, application EKUs and chosen offline
revocation policy. `KeyPin` checks SPKI identity, not lifetime or revocation.
CMS `Parse` is unauthenticated; `SignedData.Verify` checks the required signers
against supplied certificates. Compose PKIX separately when needed.
For selected BER input, explicitly use `cms.ParseBER` or `cms.ParseBERReader`.
They coalesce constructed content and normalize the permitted wrappers within
byte/content/depth/value limits. They preserve signed-attribute bytes and reject
non-DER attributes. `DER`, `Size` and `WriterTo` expose the normalized encoding;
they do not replay the original BER. Parsing still establishes no authenticity.

Timestamp verification binds a token to an expected imprint and a response to
its original request. Configure TSA trust, allowed policies and revocation.
`Token.UnverifiedInfo()` only selects processing parameters. Claimed signing time
is not trusted time evidence. XAdES validates the closed current-time/with-time
profiles described in [compatibility](compatibility.md).

## XML Encryption

AES-GCM uses an explicit RSA-OAEP SHA-2, AES Key Wrap or direct AES-key suite.
Bytes accept arbitrary plaintext; XML Element/Content operations require UTF-8/NFC.
GCM decryption authenticates before XML parsing and returns no plaintext on failure.
Element replacement changes the selected element; Content replacement changes
its children. Both return a new snapshot and preserve unrelated content.
Decryption does not authenticate a sender or establish signature coverage.

`Options.OAEP` selects independent SHA-224/256/384/512 digest and MGF1 hashes
with an optional label. A zero `MGFHash` uses `Hash` for `RSAOAEP` and SHA-1 for
`RSAOAEP10`. SHA-1 and `RSAOAEP10` require explicit `AllowLegacy: true` and are
disabled with crypto/fips140 enabled. XMLENC's omitted digest/MGF parameters
mean SHA-1; they never select SHA-256 or expand the caller's accepted parameters.
Decryption requires the caller-selected parameters. Direct-key variants
require a matching AES key size and exact configured KeyName hint. Limit a data
key to at most 2^32 encryptions with the randomly generated 96-bit nonces.

AES-CBC 128/192/256 and TripleDES-CBC require an exact `DataAlgorithm` and
`Options.AllowLegacy: true`. TripleDES Key Wrap requires the same permission
and a TripleDES data key. Selected legacy algorithms are disabled in FIPS mode.
CBC uses XMLENC padding, whose preceding padding bytes may have arbitrary values;
it does not use PKCS#7 padding. Successful CBC decryption does not authenticate
plaintext. The application must establish ciphertext integrity before decryption
and keep legacy keys separate from GCM keys. Uniform errors and dummy-key
processing do not establish resistance to padding oracles.

`DeriveConcatKey` implements ConcatKDF with SHA-256 or explicitly permitted
legacy SHA-1. The five `ConcatKDFParameters` fields use XMLENC's padding-count
octet followed by the original bit string, before hex encoding. Padding is
removed before the fields are concatenated. Fields, secrets, derived key lengths
and work are bounded. Non-octet OtherInfo is supported outside FIPS mode; FIPS mode
requires byte-aligned OtherInfo supported by Go's validated hash backend.

The Go `Encrypt*WithECDH` / `Decrypt*WithECDH` APIs use an explicit static
recipient and a fresh ephemeral key for each encryption. They support P-256,
P-384 and P-521 with ConcatKDF and AES Key Wrap. A nil `ECDHOptions.KDF` selects
SHA-256 and binds the wrap algorithm URI and recipient public point in OtherInfo;
explicit parameters must match exactly. `RecipientKeyName` is an optional exact
hint; received key descriptions never choose a recipient or establish sender
identity. `AdaptContextECDHRecipient` passes cancellation to an application key
provider. Byte, document, selected-element and content operations retain their
existing snapshot, namespace and plaintext-limit contracts.

`Decrypt*WithKeyGraph` explicitly enables inline, sibling and authorized external
EncryptedKey/DerivedKey relationships, RetrievalMethod, ReferenceList and exact
key-name associations. Select the EncryptedData handle and application-owned
material explicitly. Algorithms, KDF context, IDs, graph depth, nodes, bytes and
resources remain bounded; conflicting authorized key paths fail rather than
selecting whichever decrypts. Key XML resources use `KeyGraphOptions.External`;
external ciphertext uses the separate `Data.External` policy. Same-document
cipher references permit the selected built-in base64/canonicalization transforms.
Byte decryption treats Type/MimeType/Encoding as advisory metadata; XML restoration
requires the appropriate Element/Content type. `EncryptKey` emits a standalone
wrapped key; `BuildDerivedKey` emits derivation metadata without publishing a secret.

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
