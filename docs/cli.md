# Command-line application

Build with `make build`; run `bin/xmlsec --help`. Examples assume `bin` is on PATH.
Use `xmlsec help <group>` or a command's `-h` for flags/defaults;
`xmlsec algorithms` lists supported algorithm URIs and policies.

## I/O and policy

`-in -` / `-out -` select stdin/stdout. Binary results are bytes; reports are JSON.
Key, password, configuration and resource inputs must be regular files.
Configuration JSON rejects unknown/duplicate keys and trailing values; referenced
paths are relative to that file. Processing commands expose limits and `-timeout`.
Boolean false values use `-flag=false`.

File output uses a temporary `0600` file and rename after success. Multiple files
publish separately. Verification can write a failure report: do not use the input
XML path as the report output.

Exit codes are `0` success/help, `1` operation failure, `2` usage, `124` deadline,
`130` cancellation. `--json-errors` before the command selects JSON stderr errors.
Reports distinguish `valid`, `invalid`, `indeterminate` and unverified inspection.
Cryptographic success does not alone establish trust or protocol acceptance.

## XML signatures

```sh
xmlsec key generate -algorithm p256 -out signer.pem
xmlsec key public -in signer.pem -out signer.pub
xmlsec signature sign -in invoice.xml -key signer.pem -out signed.xml
xmlsec signature verify -in signed.xml -key signer.pub -root-local invoice
xmlsec signature inspect -in signed.xml
```

The restricted profile needs a root ID (`ID` by default), trusted verification
key and expected root. General XMLDSig uses `signature build`, `sign-template`
and `verify-core`; selection is zero-based and `inspect` lists indices.
`-expect-uri` checks exact references; `-require-root` / `-require-id` require
coverage. Core verification does not require a signed root by default.

Templates use the public JSON types; see the [API examples](../examples).
`-policy modern`, `pss` or `hmac` selects extra algorithms. HMAC uses
`-secret-file`; truncation needs `-allow-hmac-truncation` and a permitted bit count.
Preserving existing signatures needs `-preserve INDEX=PUBLIC_KEY_FILE`.

Manifest recursion is explicit: `-manifests recursive` for local graphs or
`recursive-external -resources resources.json` for external roots.
`-manifest-transforms` permits approved transformed Manifest XML; derived coverage
is separate from original-node coverage. Program transforms need `-allowed-programs`.

`-base-uri` enables relative URI/XML Base resolution and requires resources
authorized by complete resolved URIs, including fragments. Resource files supply
the already selected octets; the CLI neither fetches remote XML nor selects its
fragments automatically. See [coverage and resources](usage.md#signatures-and-coverage).

## Detached resources and transforms

A signing recipe can select digests/transforms:

```json
[{"uri":"urn:invoice:payload","path":"payload.xml",
  "digest_method":"http://www.w3.org/2001/04/xmlenc#sha256",
  "transforms":[{"algorithm":"http://www.w3.org/2006/12/xml-c14n11"}]}]
```

Verification accepts only URI/path pairs and requires exactly that URI set:

```json
[{"uri":"urn:invoice:payload","path":"payload.xml"}]
```

```sh
xmlsec signature sign-detached -key signer.pem -resources recipe.json -out sig.xml
xmlsec signature verify-detached -key signer.pub -in sig.xml -resources files.json
```

`-allowed-programs programs.json` approves exact XPath/Filter2/XSLT transforms,
including namespace bindings. Received XML cannot approve its own programs.

## Canonicalization and XPath/XSLT

```sh
xmlsec c14n -in input.xml -algorithm 'http://www.w3.org/2006/12/xml-c14n11'
xmlsec transform xpath -in input.xml -version 3.1 -expression 'sum(/r/value)'
xmlsec transform xslt -in input.xml -stylesheet transform.xsl -out result.xml
```

`-namespace PREFIX=URI` supplies static bindings. C14N `-xpath` is an XMLDSig
XPath 1.0 per-node predicate; `-id` selects a unique subtree. `-bindings` and
`-static-bindings` supply typed values; `-resources` authorizes external input.
Empty `-in ''` permits source-free calls. XPath text output needs a singleton;
JSON preserves sequences. XSLT text output rejects secondary results; JSON
includes them. See [language profiles](transforms.md).

## Encryption and keys

```sh
xmlsec key generate -algorithm aes256 -out data.key
xmlsec encryption encrypt -transport direct -key data.key -scope element \
  -id payload -in input.xml -out encrypted.xml
xmlsec encryption decrypt -transport direct -key data.key -scope element \
  -in encrypted.xml -out restored.xml
```

Transports are `rsa`, `wrap`, `direct`; scopes are `bytes`, `document`, `element`,
`content`. Decryption requires the configured algorithms, OAEP parameters and key
hint. `encryption externalize` returns CipherReference XML plus ciphertext;
reading it requires an exact URI/path resource entry.

CBC/TripleDES need `-allow-legacy-data` and exact algorithm flags. CBC does not
authenticate plaintext; establish ciphertext integrity before using it.

`key generate`, `public`, `convert`, `inspect` handle supported key formats.
Protected keys use `-key-format pkcs8|pkcs12` and `-password-file`; export uses
`-output-password-file`. Passwords are never command arguments. One final
LF/CRLF is removed from a password file. PKCS#12 export also needs a certificate.

`keyinfo build` / `inspect` describe untrusted keys. `signature verify-keyinfo`
needs an external key pin and coverage. KeyInfo retrieval has separate
`-keyinfo-resources` / `-keyinfo-base-uri` permissions; signed-data permissions
never grant KeyInfo access.

## Trust, timestamps, XAdES and SAML

Trust JSON supplies explicit roots, usages, revocation policy and offline evidence:

```json
{"roots":["root.pem"],"usages":["codeSigning"],
 "revocation":"require-crl","evidence":{"crls":["root.crl"]}}
```

```sh
xmlsec pki verify -certificate signer.crt -trust trust.json -at "$VERIFY_AT"
xmlsec timestamp request -in data.bin -tsa-policy 1.2.3.4 -out request.tsq
xmlsec timestamp verify -in response.tsr -request request.tsq \
  -trust tsa.json -at "$VERIFY_AT" -token-out token.der
```

`VERIFY_AT` is the intended trusted RFC 3339 validation time. TSA JSON wraps
`trust` with allowed `policies` and `certificates`. Timestamp responses bind to
their original request; inspection authenticates nothing.

`cms verify` needs certificate pins for every signer; `-trust` / `-at` adds PKIX.
`-content` supplies detached input; `-extract` publishes only verified content.
OCSP commands use explicit requests/responses and make no network requests.

`xades validate` uses `signer_trust`, `tsa_config`, `level` and the selected
[library profile](compatibility.md). SAML decoding/verification does not maintain
shared replay state or create browser sessions; use the SP/IdP APIs for stateful
integration. Authentication, cookies and endpoints remain application-owned.
