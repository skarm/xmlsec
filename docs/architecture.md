# Package architecture

## Contents

- [Module layout](#module-layout)
- [XML and transforms](#xml-and-transforms)
- [Signatures, encryption and trust](#signatures-encryption-and-trust)
- [SAML](#saml)
- [Resources and ownership](#resources-and-ownership)
- [Commands and verification](#commands-and-verification)

## Module layout

The repository provides one public Go module and an optional CLI. Import packages
under `github.com/skarm/xmlsec`; the module root has no Go package.
[go.mod](../go.mod) defines the Go version and direct dependencies.

Public packages group APIs by format or protocol. Internal packages implement
shared parsing, cryptography and validation without separate application-facing
configuration. The [API guide](usage.md) describes how to compose these packages.

## XML and transforms

`document` exposes immutable XML snapshots and node handles backed by
`internal/tree`. Internal metadata operations are package functions in
`internal/tree/metadata.go`, keeping draft mutation out of the aliased public
`document.Document` method set. A handle belongs to one snapshot. Signing,
decryption and replacement return new snapshots; callers use the returned handles to read the
result. `c14n` writes canonical XML from documents, subtrees or explicit node sets.

`reference` executes bounded transform chains. It supports built-in transforms
and explicit application-approved extensions. `internal/transformxml` reads and
writes their XML parameters for XMLDSig, KeyInfo and XAdES consumers.

`transform` provides XPath and XSLT over the shared document model. Its private
XDM, XPath, XSLT and pattern packages own values, compilation and execution.
Compiled programs share immutable policy; each invocation has its own context,
resource state and work budgets. Language XML input and the document security
parser use [separate input profiles](transforms.md#xml-input-profiles).

## Signatures, encryption and trust

`xmldsig` authenticates SignatureValue and reference digests under explicit
algorithm, coverage and resource policy. `keyinfo` parses untrusted key
descriptions and authorized retrievals. `keys` parses and writes key and
certificate encodings. Neither parsing operation establishes identity or trust.

`xmlenc` handles data encryption, key transport, key wrapping and explicitly
enabled key graphs. Its algorithm and resource policy is independent of XMLDSig
policy. Encryption does not establish sender identity or signature coverage.

`cms` authenticates CMS content and signers. `timestamp` binds RFC 3161 tokens to
expected data and configured TSA trust. `pki` checks certificate paths and offline
revocation evidence. `xades` composes XML signatures, signed properties and
separate current-time, with-time and historical validation workflows.

`internal/historical` runs the format-independent historical workflow using
exact-byte inputs from format adapters. `internal/historicalproof` defines proof
roles and bindings shared with PKI. Authenticated evidence remains distinct from
untrusted acquisition metadata.

## SAML

The SAML packages separate wire encoding, protocol checks and application flow:

- `saml/binding` encodes POST messages and authenticates Redirect queries.
- `saml/metadata` parses roles, keys and endpoints under explicit metadata trust.
- `saml/protocol` builds and validates the supported solicited WebSSO messages.
- `saml/sp` and `saml/idp` compose protocol checks with metadata and state adapters.
- `saml/state` retains browser-bound pending requests.
- `saml/replay` atomically consumes identifier groups after validation.

Both memory stores use `saml/internal/expiry` for expiration. They coordinate one
process; multiple application instances need shared atomic storage. User
authentication, HTTP handlers, cookies and application sessions belong to callers.

`saml/internal/profile` owns bounded scalar rules for IDs, URIs, endpoints,
booleans and time values, plus ID generation. Both XML adapters and request state
use those rules directly. `saml/internal/xmlutil` handles XML structure and draft
construction; request storage does not depend on it or the document tree.

## Resources and ownership

`resource` supplies explicitly configured filesystem and HTTP adapters.
`evidence` owns untrusted byte observations and optional temporary-file storage;
`evidence/collect` retrieves observations through an application-supplied HTTP
client and exact URI allowlist. Offline PKI and signature verification do not
fetch missing evidence automatically.

Consumers enforce resource budgets and close resolver-owned readers. Caller-owned
streams remain open. Blocking readers, writers and callbacks must support their
own cancellation. Mutable data returned by public accessors is copied as
specified by each API. See [common contracts](usage.md#common-contracts) and
[storage requirements](streaming.md).

`internal/lexicon` contains shared immutable vocabulary. Encoding, name matching,
normalization and cryptographic helpers remain in focused internal packages.
Shared spellings do not combine protocol policies or grant trust.

## Commands and verification

`cmd/xmlsec` handles flags, local input and output publication through public
library APIs. `examples` demonstrates complete compositions with disposable
keys. `tests/integration` checks workflows across packages; `tests/testdata/consumer`
is a separate module that checks the external API. Component tests stay beside
their implementations. See [testing](testing.md) for commands and prerequisites.

Supported formats, exclusions and conformance gaps are maintained in
[compatibility](compatibility.md) and the [normative register](conformance.md).
