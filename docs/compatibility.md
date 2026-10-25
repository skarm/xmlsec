# Supported profiles and compatibility

The library implements bounded profiles. Full standards conformance and an
independent security audit have not been established. The [conformance register](conformance.json)
separates capabilities from a partial normative clause matrix, tracking implementation,
policy and applicability independently. Every declared profile has a pinned
document/role/mode matrix with its assessed obligations and remaining clause
regions; missing mandatory behavior remains applicable. See [normative traceability](conformance.md)
for review rules and remaining gaps; [standards](standards.md) lists primary sources.

## Supported scope

- XML 1.0 Fifth Edition in UTF-8/UTF-16, immutable namespace-aware content and
  seven XPath node kinds. ID typing is explicit. DTDs, external entities,
  XML 1.1, UTF-32, schema defaults and XSD validation are unsupported.
- Exclusive C14N and Canonical XML 1.0/1.1, with or without comments, over full
  documents, subtrees and explicit node sets. Sparse sets may produce fragments.
- XMLDSig enveloped/enveloping/detached references, Objects, multiple signatures
  and bounded Manifest graphs. Typed external Manifest roots require recursive
  mode, `AllowExternal`, a resolver and exact URI allowlist. Their incoming digest
  is authenticated before nested discovery. The resolver receives complete
  allowlisted URIs, including fragments, and supplies the identified subresource
  as octets; automatic ID selection from a fetched external XML document is not
  provided. Explicit `ExternalReferences.BaseURI` enables relative URI resolution
  against the signature document or external Manifest retrieval URI and inherited
  `xml:base` on permitted containers. The allowlist must then contain resolved
  absolute URIs. Same-document references keep their own document scope. Existing
  XMLDSig attribute grammar and the URI character profile still apply; arbitrary
  LEIRIs and redirect metadata remain outside this profile. `AllowTransformed`
  separately follows explicitly typed, authenticated transform outputs as bounded
  standalone Manifest snapshots. Their coverage concerns the derived XML;
  `Transformed()` and report `transformed` distinguish it from original XML.
  RSA/ECDSA SHA-2, RSA-PSS, Ed25519/Ed25519ph and
  separate HMAC profiles are supported. `LegacyVerificationPolicy` additionally
  permits SHA-1 reference digests and RSA-SHA1/1024-bit DSA-SHA1 verification;
  legacy public-key signature generation is disabled. `LegacyHMACPolicy`
  separately opts into HMAC-SHA1 with the existing secret/tag limits. Both
  compatibility policies are disabled in FIPS mode. DSAKeyValue and DER key
  descriptions remain untrusted until an application selects a trusted key.
  Omitted DSA P/Q/G require an explicit 1024/160 application parameter context;
  they are never inferred from another candidate. Retrieval of rawX509Certificate
  permits one optional Base64 transform by default. Explicit
  `keyinfo.Options.RetrievalProcessing` additionally permits allowlisted chains
  of Base64, C14N, enveloped and approved XPath/Filter2/XSLT. Type is checked after
  processing, external resources use one immutable source per URI, and shared
  byte/node/depth limits and cycle detection apply. KeyInfo separately supports
  exact complete fragment URIs and opt-in `ExternalResources.BaseURI`, using the
  same URI-valued inherited `xml:base` rules. The resolver supplies the identified
  octets; automatic external XML fragment selection is unsupported.
  `Template.X509Data` constructs the same certificate/CRL and selector forms read
  by the parser, with separate groups and preserved DER/DN spellings. CRLs use the
  existing v2 parser profile. Selector-only groups are untrusted descriptions and
  perform no lookup; grouping and selector/chain consistency remain the caller's
  responsibility. Signing a KeyInfo reference authenticates its metadata without
  establishing certificate or CRL trust.
- Selected features of XPath 1.0/2.0/3.0/3.1 and XSLT 1.0/2.0/3.0. Complete
  Basic XSLT conformance remains open; [suite results](language-baseline.md)
  record the current failures. Package/collection resolvers and application
  functions are explicit. XMLDSig XPath 1.0, Filter2
  and restricted XSLT 1.0 need approved programs. Schema awareness and normative
  W3C streaming are unsupported. Streaming annotations use materialized trees;
  independent-record processing is available separately.
  XPath 3.0/3.1 resource limits preserve `transform.ErrLimit` and report
  `XPDY0130` when no more specific standard code applies. Pinned
  [suite diagnostics](language-suites.md) retain mandatory and harness failures.
  See [transforms](transforms.md) and [streaming](streaming.md).
  Explicit `transform.Config.AllowSingleByteEncodings` additionally permits
  ASCII-compatible IANA single-byte XML encodings under the same raw/decoded
  input limits. Default XML byte parsing remains UTF-8/UTF-16 and DTD-free.
  Language input accepts deprecated Namespaces 1.0 relative namespace names and
  preserves their literal values. The document security parser requires absolute
  names; C14N rejects relative names even outside the selected nodes.
  `XSLTOptions.ProcessorVersion` selects a modern processor independently of lower
  stylesheet declarations, preserving local backwards-compatible behavior and
  module semantics. Higher/future declarations enable fallback and deferred-error
  behavior, including a 3.0 principal declaration with a 2.0 processor. Complete
  forwards-compatible processing remains open. `Config.XMLSchemaVersion` selects
  builtin datatype/regex rules (default 1.1), independently of schema awareness.
  Recurring decimal results use at least twenty fractional places/significant
  digits; terminating decimals remain exact.
- PKIX with explicit roots/time, direct complete offline CRLs and restricted
  OCSP; definite-length CMS SignedData and RFC 3161/5816 timestamps. Explicit
  CMS `ParseBER`/`ParseBERReader` also accept indefinite envelope/SignedData/
  encapsulated-content wrappers and constructed content OCTET STRINGs. Signed
  attributes retain their original strict DER encoding. Other BER fields remain
  restricted; timestamp APIs retain their existing input profile. There is no
  automatic network fetching, indirect/delta CRL processing or unrestricted BER.
- Closed XAdES basic/T/LT/LTA current-time and separate with-time B-T profiles.
  A complete historical EN 319 102-1 evidence engine is unsupported.
- Signed SAML metadata, POST/Redirect and solicited WebSSO. SLO, Artifact/ECP,
  queries, unsolicited SSO and encrypted Assertion/NameID/Attribute profiles are unsupported.
  SAML/XAdES dateTime values use UTC, positive four-digit years and at most nine
  fractional digits; `24:00:00` is normalized. Metadata cache durations use a
  positive day/time profile, capped at 365 days and nine fractional digits.
- PEM/DER PKCS#8, RSA PKCS#1, EC SEC1, SPKI, X.509 certificates and CRLs.
  Encrypted PKCS#8 uses PBES2/PBKDF2 with SHA-2 and AES-CBC. DER PKCS#12 requires
  a SHA-2 classic MAC or PBMAC1, one private key and matching certificate, with
  optional extra certificates. KDF work and collections are bounded. Legacy
  RC2/3DES/SHA-1, scrypt, BER, nested bags and multiple identities are unsupported.
  Private DER versions/components are checked; EC scalar size, curve and optional
  public key must agree. Schema-dependent DER rules for custom attributes remain
  the application's responsibility.
- XML Encryption AES-GCM 128/192/256 with direct keys, independently selected
  SHA-224/256/384/512 OAEP/MGF1 hashes or AES Key Wrap. The strict entry points
  require one inline EncryptedKey or a direct application key.
  Explicit `OAEPParameters.AllowLegacy` permits SHA-1 and `RSAOAEP10` with fixed
  MGF1-SHA1; the exact application-selected parameters still have to match.
  Default RSA-OAEP remains SHA-256/MGF1-SHA256. Bytes, root, Element and Content
  are supported. CipherReference permits one exact absolute URI with raw bytes
  or one base64 transform. Explicit `Options.AllowLegacy` additionally permits
  AES-CBC 128/192/256 and TripleDES-CBC, including RFC 3217 TripleDES key wrap
  for TripleDES data keys. CBC plaintext is unauthenticated; legacy algorithms
  remain disabled by default and in FIPS mode. CLI opt-in is `-allow-legacy-data`.
  Optional EncryptionMethod/KeySize is accepted only when it agrees with the
  selected data key, KEK or RSA modulus. The bounded ConcatKDF API supports
  XMLENC bitstring parameters and SHA-1/SHA-256; SHA-1 requires explicit legacy
  permission, and non-octet input is denied in FIPS mode.
  Explicit ECDH-ES APIs support P-256, P-384 and P-521, ConcatKDF and AES Key
  Wrap. Agreement does not authenticate the sender. Explicit key-graph APIs
  resolve bounded nested/retrieved/derived keys, ReferenceList and CarriedKeyName
  relationships; external key documents require an exact application allowlist.
  Key labels, recipients and references confer no trust. Cipher-reference
  transformations are separately selected; base64 and built-in canonicalization
  are supported by the graph API, including implicit Canonical XML 1.0 conversion.
  RSA PKCS#1 v1.5, finite-field DH, PBKDF2, EXI and padded AES key wrap remain
  unsupported optional features.

General key-manager persistence, HSM management, XMLDSig decryption transforms,
CipherReference XPath/XSLT pipelines and arbitrary XPointer are unsupported.
The bounded URI profile accepts `#xpointer(/)` and `#xpointer(id(...))`.

JSON serialization uses XML as the default output method for node values;
applications that need node string values can select `json-node-output-method="text"`.
Use explicit arrays for multiple JSON values. A sequence of multiple items at the
result, map-value or array-member level raises `SERE0023`. See the shared
[serialization contract](transforms.md#xslt-results-and-xml-identity).

## Unicode normalization

NFC/NFD/NFKC/NFKD use Unicode 17.0 tables from `x/text`, with exact ordering and
composition for long sequences, preserving original CGJ without inserting one.
XPath, XSLT serialization and XML Encryption NFC checks share the normalizer.
XML Encryption checks plaintext without rewriting it; ordinary XML output and
C14N do not normalize Unicode. An unfinished combining sequence may require
storage proportional to its length; [operation budgets](streaming.md) still apply.

The official [NormalizationTest](https://www.unicode.org/Public/17.0.0/ucd/NormalizationTest.txt)
is tested locally. Its notice is retained in the fixture and
[Unicode license](../licenses/Unicode-3.0.txt).

## Known oracle differences

[Native comparisons](testing.md#xmlsec1-comparisons) cover overlapping profiles
and assert these differences separately:

- Sparse C14N: an omitted own `xml:lang` blocks inheritance. The result differs
  from libxml2/JDK for the diagnostic case; see
  [C14N 1.0 §2.4](https://www.w3.org/TR/2001/REC-xml-c14n-20010315#DocSubsets).
- Document-level comments/PI follow original order when the root is omitted.
  libxml2 adds a terminal LF in the diagnostic case; see
  [C14N 1.1 §2.3](https://www.w3.org/TR/xml-c14n11/#ProcessingModel).
- C14N 1.1 base-URI joining preserves `../../` and omits an empty result from
  `abc/` plus `../`. libxml2 differs in diagnostic cases; see
  [§2.4](https://www.w3.org/TR/xml-c14n11/#DocSubsets) and
  [errata](https://www.w3.org/2008/05/xml-c14n11-errata).
- The fixed corpus also distinguishes JDK subtree inheritance from the nearest
  omitted ancestor, selected attribute/namespace identity from DOM declaration
  ownership, and empty node sets. libxml2 can reintroduce an omitted attribute's
  namespace and retain a fragment during C14N 1.1 base joining. Per-case
  diagnostic reasons cite the processing rule; such cases are excluded from
  independent-engine agreement, while their normative bytes remain required.
- xmlsec1's CLI validates the incoming external Manifest reference in the tested
  fragment exchange, but does not recursively check its children. It also opens
  the literal relative URI in the tested inherited `xml:base` case. Native/Go
  signature exchanges use explicit native URI mappings; they do not establish
  native recursive traversal or matching XML Base semantics.
- xmlsec1 XML replacement rejects empty plaintext, while its `DecryptToBuffer`
  API authenticates empty GCM input and returns size zero. Empty Go byte/Content
  plaintext is supported. Empty native XML replacements are diagnostic cases,
  excluded from successful exchanges.
- Saxon HE 12.10 accepts a malformed encoding name in `fn:parse-xml` after
  removing the encoding pseudo-attribute. The native character-input parser
  retains XML 1.0 production [81] validation and reports `FODC0006`. This case is
  a separate diagnostic, excluded from successful query agreement counts.
- Saxon HE 12.10 and two QT3 case-conversion expectations retain older Greek
  U+037F/U+03F3 mappings. The native Unicode 17.0 mappings agree with the
  Unicode 7.0 data selected by those catalog cases. The corrected catalog dependency matcher treats a Unicode edition as exact:
  those 7.0-only cases are inapplicable to the selected 17.0 data. Their historical
  failures remain in the earlier baseline; the Saxon diagnostic still runs.
  No publisher fixture is rewritten.

The libxml2 adapter translates empty default-namespace markers without changing
Go selections or expected output. JDK arbitrary DOM namespace-axis selections
are not a general oracle.

## Trust and operations

Cryptographic validity alone does not establish PKIX trust, SAML acceptance,
trusted time or historical evidence validity. Configure coverage, trust and
resource access, then consume verified handles. Transform execution has
cooperative in-process limits rather than OS isolation. Memory state/replay
stores coordinate one process. Native libraries are optional test dependencies.

## Assertion and compatibility controls

`Config.EnableXSLTAssertions` now selects assertion checking explicitly. The
default disables `xsl:assert`, as XSLT 3.0 requires. Applications that relied on
the earlier unconditional checking must enable it for direct invocations.
Nested `fn:transform` calls independently use `enable-assertions`, defaulting to
false as required by F&O 3.1. Disabled assertions do not evaluate their test/message.
Application error namespaces survive public error reporting and `xsl:catch`.

`Config.DisableXSLTDynamicEvaluation` selects static disabling of `xsl:evaluate`.
It defaults to false. The setting applies to direct and nested compilation and
package loading; availability queries report false/no, and `xsl:fallback` runs.
An invoked disabled instruction without fallback reports `XTDE3175`.


`Execute` still defaults to raw XDM values. `XSLTContext.ResultMode` additionally
offers explicit document normalization or stylesheet-directed `build-tree`.
`fn:transform` now retains mixed item order and raw secondary values, constructs
normalized documents on request, and includes an empty principal result map
entry under the published F&O 3.1 contract. Callers that tested map-key absence
to detect empty output should inspect its value instead.

`XPathOptions.XPath10Compatibility` selects the compatibility property without
changing the modern grammar. Function values retain their originating static
context across invocations. Native Greek alphabetic numbering consistently uses
24 letters in XPath and XSLT; the publisher's older lowercase 25-letter choice
is an implementation-defined difference, retained in suite diagnostics.
