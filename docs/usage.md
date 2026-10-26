# API guide

Import packages under `github.com/skarm/xmlsec`; the module root has no Go package.
Use `go doc ./<package>` for full signatures/options and the runnable
[examples](../examples) for complete applications. The [CLI](cli.md) uses the same APIs.

## Common contracts

- Pass a non-nil context. Configure policy and resource limits explicitly;
  zero option fields select the documented defaults.
- Published XML snapshots and compiled programs support concurrent reuse.
  Handles belong to one snapshot; mutable accessors return owned copies where
  documented. Application adapters must satisfy their concurrency contracts.
- Caller-owned streams stay open. Resolver/transport streams are closed by the
  library. A context cannot interrupt an arbitrary blocked `Read`, `Write` or
  provider call; the adapter must support cancellation.
- Writers may leave a prefix on failure; discard or stage it. Byte-returning
  operations return no partial result. `result.WriterTo(ctx)` supplies `io.WriterTo`.
- Use `errors.Is` for package/cancellation errors and `errors.As` for structured
  diagnostics. A diagnostic report is not a verified result.

`document.Name{Space, Local}` uses namespace URIs, not prefixes. `transform.Name`
aliases it. Filesystem/HTTP access requires configured `resource` adapters and
allowlists; resolution grants no trust. `resource.TypedReader` can provide MIME
and charset metadata. Context-aware key providers use `AdaptContextSigner`,
`AdaptContextDecrypter` or `AdaptContextECDHRecipient`.

## XML and canonicalization

`document.Parse` / `ParseReader` create immutable XML snapshots. `XML` and
`WriteXML` serialize ordinary XML; `c14n.WriteDocument`, `WriteElement` and
`WriteNodeSet` produce canonical bytes. Exclusive C14N is the default;
`InclusivePrefixes` applies only to that algorithm. Use `Subtree` / `AllNodes`
for full selections; sparse node sets may produce fragments.

The security parser rejects DTDs and external entities. Language input has a
separate [DTD profile](transforms.md#xml-input-profiles). See [streaming](streaming.md)
for retained trees, independent records and partial output.

## Signatures and coverage

`xmldsig.SignEnveloped` / `Verify` implement the restricted root-enveloped profile.
Verification needs an externally trusted key and expected expanded root name.
General signatures require explicit selection and application coverage:

```go
result, report, err := xmldsig.VerifySignatureDetailed(ctx, doc, signature, trustedKey,
    xmldsig.SignatureOptions{
        RequiredElements: []document.Element{payload},
        ExpectedURIs: []string{"#payload"},
    })
if err != nil { return err } // report alone is not authenticated content.
_ = result
_ = report
```

`ExpectedURIs` checks the exact reference multiset. General verification does not
require root coverage by default. Consume authenticated data from the verified
snapshot; coverage does not establish application schema or protocol validity.

`BuildTemplate` / `SignTemplate` support references and objects. `Preserve`
requires trusted keys for existing signatures. Manifest recursion is opt-in:
authenticating the Manifest does not alone verify its children.
`AllowTransformed` follows approved, authenticated output as derived XML; its
coverage never establishes coverage of original nodes.

External resources use complete allowlisted URIs, including fragments. A resolver
must return the identified octets or selected standalone XML, not silently ignore
a fragment. `ExternalReferences.BaseURI` enables relative URI/XML Base resolution;
allowlists then contain resolved absolute URIs. `URI()` retains signed spelling;
`ResourceURI()` identifies retrieval. Same-document references retain local scope.

Detached verification requires the exact expected URI set and authenticates
SignatureValue before reading signed resources. KeyInfo retrieval has separate
permissions and may occur earlier. `WriteDigestInput` replays approved transforms
and rejects changed external data; keep its resolver available.

Default signatures use RSA/ECDSA with SHA-2. `ModernPolicy` adds fixed PSS and
Ed25519/Ed25519ph; these two Ed25519 methods are not interchangeable.
`ParameterizedPolicy` enables generic PSS. HMAC uses separate secret APIs/policy;
truncation needs explicit permission. See [compatibility](compatibility.md) for legacy modes.

## Keys, trust and evidence

`keys` parses supported PEM/DER keys, certificates and CRLs under size, count and
key/KDF-work limits. Parsing does not establish trust. Protected PKCS#8 uses
PBES2/PBKDF2/AES-CBC without an integrity tag. PKCS#12 requires a MAC and matching
key/certificate; additional certificates remain untrusted. Export needs a nonempty
password. Optional BER, nested containers and multiple-identity selection require
explicit import options; output remains one DER identity.

`keyinfo.Parse` returns untrusted candidates. `AllowedKeyData: nil` allows supported
forms; an empty list denies them. Retrieval requires its own URI allowlist and
resolver. `RetrievalProcessing` enables separately approved transform chains;
`ExternalResources.BaseURI` enables relative resolution. These permissions do not
grant access to signed-data resources. Embedded keys, X509Data selectors and
signed KeyInfo metadata still require an application trust decision.

`pki.NewVerifier` snapshots explicit roots and policy, never system roots.
Verification uses an explicit time, EKUs and offline revocation evidence.
`KeyPin` checks SPKI identity, not lifetime/revocation. Missing required CRL/OCSP
material fails without a network fallback. Evidence results retain authenticated
object, signer/issuer, status, scope and time bindings.

`evidence.NewObservation` owns untrusted bytes and acquisition metadata.
`evidence/collect.NewHTTP` requires an explicit client and exact URI policy;
redirects require separately authorized targets and a positive limit. Collection
failure returns no partial collection. The application owns DNS/IP/proxy/TLS
policy. Retrieval time and HTTPS do not establish historical existence.

CMS `Parse` is unauthenticated. `Verify` checks supplied signer certificates;
`VerifyWithTrust` also applies explicit PKIX/revocation policy to every signer.
Selected BER wrappers require `ParseBER` / `ParseBERReader`; signed attributes
remain strict DER. Normalized output does not replay the original BER.

Timestamp verification binds a response to its request or a token to its expected
imprint, with configured TSA trust, policies and revocation. `UnverifiedInfo`
authenticates nothing. Verified assertions retain the signed time/accuracy and
exact token binding; they do not alone establish validity after TSA expiry.
OCSP verification selects an exact CertID and authorized responder. Only fresh,
authenticated GOOD is success; stale/revoked diagnostics are not successful results.

XAdES has separate current/with-time, baseline-format and bounded historical APIs.
`SignBaseline` / `VerifyBaseline` authenticate selected signatures and properties;
application coverage and trust remain explicit. `NewHistoricalValidator` additionally
requires signer/TSA revocation policies, present time, offline evidence and
historical constraints. Missing timestamp accuracy needs a trusted policy bound
for old-time proof. Consume results only when the error is nil. Supported levels
and remaining ETSI gaps are in [compatibility](compatibility.md).

## XML Encryption

AES-GCM accepts a configured RSA-OAEP, AES Key Wrap, ECDH-ES or direct-key path.
Decryption authenticates before parsing/restoring XML and releases no plaintext
on failure. Element/Content replacement returns a new snapshot. Encryption does
not authenticate the sender or establish signature coverage.

OAEP digest, MGF1 hash, label and key hints must match application policy.
Omitted XMLENC digest/MGF parameters mean SHA-1, not SHA-256; accepting them
requires explicit legacy permission. Limit a GCM data key to at most 2^32
uses with generated 96-bit nonces.

CBC/TripleDES require exact algorithms and `AllowLegacy`; they are disabled by
default and in FIPS mode. CBC plaintext is unauthenticated: establish ciphertext
integrity before decryption and keep legacy keys separate from GCM keys.

ConcatKDF and ECDH-ES use explicit parameters and bounded work; ECDH supports
P-256/P-384/P-521 and fresh ephemeral keys. Explicit key-graph APIs resolve
bounded nested/retrieved/derived keys. Key-document access and external ciphertext
have separate policies. Labels and received key descriptions confer no trust.
`ExternalizeCiphertext` returns XML and ciphertext without I/O.

## SAML and transformations

Compose `saml/sp` / `saml/idp` with authenticated or explicitly trusted metadata.
POST decoding is unverified. Redirect verification authenticates the query before
inflation; protocol checks still validate issuer, audience, destination,
correlation, time and authentication conditions.

Bind SP requests to unpredictable browser/session secrets. Acceptance atomically
consumes request/assertion IDs after validation. Multiple instances need shared
atomic state/replay stores. Authentication, cookies, sessions and HTTP endpoints
belong to the application. See the [SSO example](../examples/sso).

The [XPath/XSLT guide](transforms.md) covers language contexts and
[approved XMLDSig programs](transforms.md#xmldsig-v1-compatibility).
