# Command-line application

Build with `make build` and run `bin/xmlsec --help`. Examples below assume `bin`
is on PATH. Use `xmlsec help signature` or `xmlsec signature sign -h` for command
and flag reference; `xmlsec algorithms` lists supported URIs and policies.
The CLI uses public Go APIs and requires no native XML/crypto tools.

## I/O and policy

`-in -` / `-out -` select stdin/stdout. Binary results are raw bytes; inspection
and verification reports are JSON. Keys, passwords, configurations and resources
must be regular files. Configuration JSON contains exactly one value; unknown
and duplicate keys fail. Referenced paths are relative to the configuration file.
Received XML never grants resource access or trust.

Processing commands expose byte/tree limits and `-timeout`; engine operations
also have `-engine-timeout`. Use each command's `-h` for defaults. Boolean flags
use `-flag=false`, without a separate positional `false`.

Local outputs use a temporary `0600` file and rename after success. Multiple
output files publish separately. Verification may write a diagnostic failure
report to `-out`; avoid using the input document as that report path.

Exit codes: `0` success/help, `1` operation/verification failure, `2` usage,
`124` deadline, `130` cancellation. `--json-errors` before the command enables
JSON errors on stderr. Verification reports contain `schema_version`, `status`,
`operation`, `trust` and `details`; failure reports include `error`. Status is
`valid`, `invalid` or `indeterminate`; inspection/decoding remains `unverified`.
A valid signature is separate from PKIX trust, protocol acceptance and a session.

## XML signatures

```sh
xmlsec key generate -algorithm p256 -out signer.pem
xmlsec key public -in signer.pem -out signer.pub
xmlsec signature sign -in invoice.xml -key signer.pem -out signed.xml
xmlsec signature verify -in signed.xml -key signer.pub -root-local invoice
xmlsec signature inspect -in signed.xml
```

The restricted profile requires an ID on the root (`-id-attr ID` by default).
Verification uses an externally trusted key and expected root name. General
XMLDSig uses `signature build`, `sign-template` and `verify-core`. Example
`template.json` for an enveloping signature:

```json
{
  "method": "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256",
  "references": [{
    "URI": "#payload",
    "Transforms": [{"algorithm": "http://www.w3.org/2001/10/xml-exc-c14n#"}]
  }],
  "objects": [{"id": "payload", "text": "authenticated data"}]
}
```

```sh
xmlsec signature build -config template.json -out template.xml
xmlsec signature sign-template -in template.xml -signature-index 0 \
  -key signer.pem -expect-uri '#payload' -out signed.xml
xmlsec signature verify-core -in signed.xml -signature-index 0 \
  -key signer.pub -expect-uri '#payload'
```

Selection is explicit and zero-based; `inspect` lists indices. `-expect-uri`
checks the exact direct-reference multiset. `-require-root` / `-require-id`
require coverage; core verification alone does not require a signed root.
Manifest recursion needs `-manifests recursive`; preservation requires a trusted
key for each existing signature through `-preserve INDEX=PUBLIC_KEY_FILE`.
Typed external `ds:Manifest` roots additionally need
`-manifests recursive-external -resources resources.json`. The resource file
explicitly allows every URI in the reachable graph; there is no network fallback.
The default external traversal accepts a complete Manifest with no transform or
one C14N transform. Add `-manifest-transforms` to explicitly follow typed references
whose allowed transforms produce standalone Manifest XML; this requires a recursive
mode. Program transforms also need `-allowed-programs`. Reports distinguish the
authenticated incoming reference from content validation, identify the resource URI
and mark derived snapshots with `transformed: true`. Derived-node coverage does
not establish original-node coverage.

Objects contain one of `text`, `xml_file`, `binary_file`, `manifest` and optional
`mime_type`. References/Manifests use the public template types' JSON fields.
Use `-policy modern` for fixed PSS/Ed25519/Ed25519ph or `-policy pss` for generic
PSS. A PSS template can set
`"parameters":{"pss":{"hash":"sha384","mgf_hash":"sha384","salt_length":24}}`.
HMAC requires `-policy hmac -secret-file secret.bin`; truncation additionally
requires `-allow-hmac-truncation` and a permitted `hmac_output_bits` template value.

`-base-uri https://example.test/signature.xml` explicitly enables relative URI
resolution for core signing and verification and requires `-resources`. Resource
entries then use complete resolved absolute URIs, including any fragment. Their
paths identify the already selected subresource bytes: a `list.xml#part` entry
must point to the standalone selected Manifest, not an unselected containing
file. The CLI performs no network fetching or automatic external ID selection.
The diagnostic `uri` retains signed spelling; `resource_uri` identifies the
authorized resolver URI. Same-document references keep their scope.

## Detached resources and transforms

A signing recipe may include digests and transforms:

```json
[{
  "uri": "urn:invoice:payload",
  "path": "payload.xml",
  "digest_method": "http://www.w3.org/2001/04/xmlenc#sha256",
  "transforms": [{"algorithm": "http://www.w3.org/2006/12/xml-c14n11"}]
}]
```

A verification allowlist contains only URI/path pairs:

```json
[{"uri": "urn:invoice:payload", "path": "payload.xml"}]
```

```sh
xmlsec signature sign-detached -key signer.pem -resources recipe.json -out sig.xml
xmlsec signature verify-detached -key signer.pub -in sig.xml -resources files.json
```

Verification requires exactly that URI set and rejects signing-only fields.
Use `-allowed-digests` / `-allowed-transforms` for verification policy. External
resources have separate per-resource and aggregate byte budgets.

XPath/Filter2/XSLT signature transforms need `-allowed-programs programs.json`:
a trusted array of exact `reference.Transform` values, including namespace
bindings. Approval occurs before resource I/O. Received programs are not
implicitly approved.

## Canonicalization and XPath/XSLT

```sh
xmlsec c14n -in input.xml -algorithm 'http://www.w3.org/2006/12/xml-c14n11'
xmlsec c14n -in input.xml -id payload -id-attr ID
xmlsec transform xpath -in input.xml -version 3.1 -expression 'sum(/r/value)'
xmlsec transform xslt -in input.xml -stylesheet transform.xsl -out result.xml
```

`-namespace PREFIX=URI` supplies static bindings. C14N `-xpath` is an XMLDSig
XPath 1.0 per-node predicate; `-id` selects a complete unique subtree.
Standalone XPath and XSLT use the [library language profiles](transforms.md).
`-bindings` / `-static-bindings` accept typed values:

```json
[{"name":{"Space":"urn:app","Local":"extra"},"type":"decimal","value":"2.5"}]
```

Types are `string`, `integer`, `decimal`, `boolean`, `dateTime`. Empty `-in ''`
permits context-free expressions or named templates. XPath text output requires
a singleton value; JSON preserves typed sequences. XSLT text output writes only
primary bytes and rejects secondary results; JSON includes secondary/messages.
`-resources` authorizes import/function resources explicitly.

## Encryption and keys

```sh
xmlsec key generate -algorithm aes256 -out data.key
xmlsec encryption encrypt -transport direct -key data.key -scope element \
  -id payload -in input.xml -out encrypted.xml
xmlsec encryption decrypt -transport direct -key data.key -scope element \
  -in encrypted.xml -out restored.xml
```

Transports are `rsa`, `wrap` and `direct`; scopes are `bytes`, `document`,
`element`, `content`. Decryption requires the configured suite, OAEP hash/label
and key hint. It selects exactly one EncryptedData (`-index` / `-id` when needed)
and publishes no plaintext on failure. `encryption externalize` writes a separate
ciphertext and CipherReference XML; decrypt with an exact URI/path resource entry.

`key generate`, `public`, `convert` and `inspect` handle supported key formats.
Private-key commands use `-key-format plain|pkcs8|pkcs12` and `-password-file`;
passwords are never argument values. Password files contain one line, with one
final LF/CRLF removed. Export uses a separate `-output-password-file` and bounded
KDF options. PKCS#12 export also needs a certificate.

`keyinfo build` / `inspect` handle untrusted key descriptions. `signature
verify-keyinfo` requires an external key pin, coverage and separately authorized
KeyInfo retrieval. Embedded material never expands that trust.
`keyinfo inspect -base-uri` requires its own `-resources`; `signature
verify-keyinfo -keyinfo-base-uri` requires `-keyinfo-resources`. Entries authorize
complete resolved absolute URIs and point to the already identified octets.
`-keyinfo-config`/`-config` can opt into `RetrievalProcessing`; approved retrieval
programs then use the trusted `-allowed-programs` file. KeyInfo and signed-data
resolver permissions remain separate.

## Trust, timestamps, XAdES and SAML

Trust configurations use explicit files. For example, `trust.json`:

```json
{
  "roots": ["root.pem"],
  "usages": ["codeSigning"],
  "revocation": "require-crl",
  "evidence": {"crls": ["root.crl"]}
}
```

Set `VERIFY_AT` to the intended trusted RFC 3339 verification time:

```sh
xmlsec pki verify -certificate signer.crt -trust trust.json -at "$VERIFY_AT"
```

`cms verify` requires certificate pins for every signer; optional `-trust` / `-at`
adds PKIX. `-content` supplies detached input and `-extract` publishes content
only after all checks pass. OCSP commands use explicit requests, nonces, response
files and verification time; they make no network requests.

TSA JSON wraps a trust configuration and policy/certificate constraints:

```json
{
  "trust": {"roots":["root.pem"],"revocation":"require-crl","evidence":{"crls":["root.crl"]}},
  "policies": ["1.2.3.4"],
  "certificates": ["tsa.pem"]
}
```

```sh
xmlsec timestamp request -in data.bin -tsa-policy 1.2.3.4 -out request.tsq
xmlsec timestamp verify -in response.tsr -request request.tsq \
  -trust tsa.json -at "$VERIFY_AT" -token-out token.der
```

Responses bind to the original request; standalone tokens need explicit original
data and expectations. Timestamp inspection authenticates nothing. Issuance
requires application-controlled signing keys, time and serial numbers.

`xades validate` accepts JSON with `signer_trust`, `tsa_config` and `level`
(B-B/B-T/B-LT/B-LTA). The `with-time` profile requires B-T and checked revocation.
These are the [library's bounded profiles](compatibility.md), not full historical
ETSI validation. Timestamp/material/archive commands compose offline evidence.

SAML commands accept the public metadata/protocol types' JSON fields and explicit
trust/expectation options. Protocol JSON omits signature policy; use CLI flags.
POST decoding is unverified; Redirect verification authenticates the raw query
before inflation. Offline verification does not check shared replay state or
create a browser session. Stateful SP/IdP integration, authentication, cookies
and HTTP endpoints belong to the application.
