# Supported profiles and compatibility

The API is experimental. Full standards conformance and an independent security
audit have not been established. [standards](standards.md) lists primary sources;
[conformance](conformance.md) explains the development requirement/evidence register.

## Supported scope

- XML 1.0 Fifth Edition, UTF-8/UTF-16, immutable namespace-aware snapshots and
  explicit ID typing. The security parser rejects DTDs/entities. XML 1.1,
  UTF-32, schema defaults and XSD validation are unsupported.
- Exclusive C14N and Canonical XML 1.0/1.1, with/without comments, over documents,
  subtrees and node sets. Sparse selections can produce fragments.
- XMLDSig enveloped/enveloping/detached signatures, Objects, multiple signatures
  and bounded Manifest graphs. External/transformed Manifests require explicit
  policy; derived-node coverage does not establish original-node coverage.
  Complete fragment URIs are allowlisted and resolvers supply identified octets.
  Base-URI resolution is opt-in; arbitrary LEIRI/fragment selection is unsupported.
- RSA/ECDSA SHA-2, RSA-PSS, Ed25519/Ed25519ph and separate HMAC profiles.
  Legacy verification/HMAC policies explicitly permit SHA-1; legacy public-key
  signing remains disabled. Compatibility algorithms are disabled in FIPS mode.
- KeyInfo candidates, X509Data groups/selectors and explicitly authorized
  retrieval/processing. KeyInfo has its own resources/base URI. Omitted DSA
  parameters need an explicit bounded application context. Descriptions and
  selectors never grant trust or automatic certificate lookup.
- Selected XPath 1.0/2.0/3.0/3.1 and XSLT 1.0/2.0/3.0 features. Schema awareness
  and W3C streamable execution are unsupported. Streaming annotations operate on
  trees; independent-record processing is separate. Complete Basic XSLT remains
  open; see [validation profiles](language-baseline.md).
- Language XML supports bounded nonvalidating DTD processing and explicitly
  enabled single-byte encodings. External entities require configured resources.
  Language input preserves relative namespace names; the security parser and
  C14N reject them. See [input profiles](transforms.md#xml-input-profiles).
- PKIX with explicit roots/time and offline complete/scoped/indirect/base-delta
  CRLs. OCSP selects an exact CertID and authorized responder. Required missing
  evidence fails without fetching. Acquisition metadata grants no trust or PoE.
- CMS SignedData and RFC 3161/5816 timestamps. Trusted CMS operations check all
  signer policies. Optional ESS multi-certificate path restrictions are rejected.
  Selected BER envelopes/content are opt-in; signed attributes remain DER.
  General BER and other CMS content types are unsupported.
- Closed XAdES current-time basic/T/LT/LTA and separate with-time B-T profiles;
  the latter uses direct complete signer CRLs without historical recovery.
  Baseline-format APIs cover additional topologies/properties without granting
  trust or a validation level. `NewHistoricalValidator` implements a bounded
  EN 319 102-1 V1.4.1 workflow, not full historical validation. Evidence records,
  historical countersignature/attribute-authority workflows and remaining
  indication branches are outside that subset. Unknown unsigned properties fail.
- Signed SAML metadata, POST/Redirect and solicited WebSSO. SLO, Artifact/ECP,
  queries, unsolicited SSO and encrypted assertions/names/attributes are unsupported.
  SAML/closed XAdES use positive four-digit UTC years and up to nine fractional
  digits. The separate baseline API retains extended dateTime lexical values;
  use `CompareSigningTime` when `time.Time` cannot represent them.
- PEM/DER PKCS#8, PKCS#1, SEC1, SPKI, certificates and CRLs. Protected PKCS#8
  uses PBES2/PBKDF2/SHA-2/AES-CBC. PKCS#12 requires a MAC and matching key/certificate;
  selected BER/nested/multiple-identity imports require explicit options.
  All identities are validated before selection; output is one DER identity.
  Legacy password RC2/3DES and scrypt are unsupported. SHA-1 import needs explicit
  permission and is disabled in FIPS mode. RFC 9879 vectors' explicit outer
  iteration DEFAULT1 is a narrow PBMAC1 placeholder tolerance.
- XML Encryption AES-GCM with direct AES, RSA-OAEP, AES Key Wrap or explicit
  P-256/P-384/P-521 ECDH-ES/ConcatKDF paths. Bytes, documents, Element and Content
  replacement are supported. OAEP hashes/label/key hints must match caller policy;
  SHA-1/RSAOAEP10 require separate permission.
- CBC/TripleDES data encryption and TripleDES Key Wrap are explicit legacy modes,
  disabled by default and in FIPS mode. CBC plaintext is unauthenticated.
  Bounded key graphs can resolve nested/retrieved/derived keys; key-document and
  ciphertext resources have separate policies. RSA PKCS#1 v1.5, finite-field DH,
  XMLENC PBKDF2, EXI and padded AES key wrap remain unsupported.

General key-manager/HSM management, XMLDSig decryption transforms, arbitrary
XPointer and CipherReference XPath/XSLT pipelines are unsupported. The URI profile
accepts `#xpointer(/)` and `#xpointer(id(...))`. See the [API guide](usage.md) for
trust, coverage and resource configuration.

## Unicode normalization

NFC/NFD/NFKC/NFKD use Unicode 17.0 `x/text` tables, preserving existing CGJ without
inserting one. XML Encryption checks NFC without rewriting plaintext; ordinary
XML output and C14N do not normalize Unicode. Unfinished combining sequences may
retain proportional storage within [operation budgets](streaming.md).

The official [NormalizationTest](https://www.unicode.org/Public/17.0.0/ucd/NormalizationTest.txt)
is tested locally; its fixture retains the [Unicode notice](../licenses/Unicode-3.0.txt).

## Known oracle differences

Archive timestamp input canonicalizes SignedInfo, SignatureValue and KeyInfo
with the archive's selected algorithm (EN319132-1 §5.5.2.3). An imprint computed
with a different SignedInfo method is rejected.

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
  Unicode 7.0 data selected by those catalog cases. Catalog Unicode dependencies
  require an exact edition:
  those 7.0-only cases are inapplicable to the selected 17.0 data. The Saxon
  diagnostic records the processor difference.
  No publisher fixture is rewritten.

The libxml2 adapter translates empty default-namespace markers without changing
Go selections or expected output. JDK arbitrary DOM namespace-axis selections
are not a general oracle.

## Trust and operations

Cryptographic validity does not establish certificate trust, SAML acceptance,
trusted time or historical validity. Consume verified handles under configured
coverage/trust/resource policy. Transform limits are cooperative, not OS isolation.
Memory state/replay stores coordinate one process. Native libraries are test-only.

## Assertion and compatibility controls

`EnableXSLTAssertions` controls direct `xsl:assert`; nested `fn:transform` uses
its own `enable-assertions`. Both default off. `DisableXSLTDynamicEvaluation`
disables `xsl:evaluate`, default false. `XPath10Compatibility` changes conversions
without changing the modern grammar. See [contexts](transforms.md#contexts-and-values).

`Execute` defaults to raw XDM values; document/default delivery is explicit.
`fn:transform` retains the published F&O 3.1 empty principal-result entry.
Greek alphabetic numbering uses 24 letters; publisher cases assuming 25 retain
a documented implementation-defined difference.
