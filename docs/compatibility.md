# Supported profiles and compatibility

The library implements bounded profiles. Full standards conformance and an
independent security audit have not been established. The [conformance register](conformance.json)
maps supported requirements to tests; [standards](standards.md) lists primary sources.

## Supported scope

- XML 1.0 Fifth Edition in UTF-8/UTF-16, immutable namespace-aware content and
  seven XPath node kinds. ID typing is explicit. DTDs, external entities,
  XML 1.1, UTF-32, schema defaults and XSD validation are unsupported.
- Exclusive C14N and Canonical XML 1.0/1.1, with or without comments, over full
  documents, subtrees and explicit node sets. Sparse sets may produce fragments.
- XMLDSig enveloped/enveloping/detached references, Objects, multiple signatures
  and bounded local Manifests. RSA/ECDSA SHA-2, RSA-PSS, Ed25519/Ed25519ph and
  separate HMAC profiles are supported. External Manifests, unrestricted KeyInfo
  selection and RetrievalMethod transforms are unsupported.
- XPath 1.0/2.0/3.0/3.1, XSLT 1.0 and Basic XSLT 2.0/3.0. Package/collection
  resolvers and application functions are explicit. XMLDSig XPath 1.0, Filter2
  and restricted XSLT 1.0 need approved programs. Schema awareness and W3C
  streamable modes are unsupported; independent-record processing is available.
  See [transforms](transforms.md) and [streaming](streaming.md).
- PKIX with explicit roots/time, direct complete offline CRLs and restricted
  OCSP; definite-length CMS SignedData and RFC 3161/5816 timestamps. There is no
  automatic network fetching, indirect/delta CRL processing or unrestricted BER.
- Closed XAdES basic/T/LT/LTA current-time and separate with-time B-T profiles.
  A complete historical EN 319 102-1 evidence engine is unsupported.
- Signed SAML metadata, POST/Redirect and solicited WebSSO. SLO, Artifact/ECP,
  queries, unsolicited SSO and encrypted Assertion/NameID profiles are unsupported.
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
- XML Encryption AES-GCM 128/192/256 with direct keys, matching SHA-2 OAEP/MGF1
  or AES Key Wrap and one inline EncryptedKey. Bytes, root, Element and Content
  are supported. CipherReference permits one exact absolute URI with raw bytes
  or one base64 transform. CBC, RSA PKCS#1 v1.5, mixed-hash OAEP, key agreement,
  KDF/DerivedKey/ReferenceList and external EncryptedKey processing are unsupported.

General key-manager persistence, HSM management, XMLDSig decryption transforms,
CipherReference XPath/XSLT pipelines and arbitrary XPointer are unsupported.
The bounded URI profile accepts `#xpointer(/)` and `#xpointer(id(...))`.

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
- xmlsec1 XML replacement rejects empty plaintext, while its `DecryptToBuffer`
  API authenticates empty GCM input and returns size zero. Empty Go byte/Content
  plaintext is supported. Empty native XML replacements are diagnostic cases,
  excluded from successful exchanges.

The libxml2 adapter translates empty default-namespace markers without changing
Go selections or expected output. JDK arbitrary DOM namespace-axis selections
are not a general oracle.

## Trust and operations

Cryptographic validity alone does not establish PKIX trust, SAML acceptance,
trusted time or historical evidence validity. Configure coverage, trust and
resource access, then consume verified handles. Transform execution has
cooperative in-process limits rather than OS isolation. Memory state/replay
stores coordinate one process. Native libraries are optional test dependencies.
