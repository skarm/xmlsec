# Package architecture

## Module layout

Import packages under `github.com/skarm/xmlsec`; the module root has no Go package.
[go.mod](../go.mod) defines the toolchain and dependencies. Public packages group
APIs by format or protocol; `internal` packages provide shared implementation.

## XML and transforms

- `document`: immutable XML snapshots, selections and record parsing.
- `c14n`: canonical serialization of documents, subtrees and node sets.
- `reference`: reference resolution and approved transform pipelines.
- `transform`: public XPath/XSLT engine and immutable XDM values. Its private
  `xdm`, `xpath`, `xslt` and `pattern` packages implement language processing;
  [source notices](engine-origin.md) record their origins.

`transform/internal/unparsedtext` owns bounded resource reading and text decoding
shared by XPath retrieval functions and XSLT text-error handling. It consumes
resolver and optional media-type methods without importing the public filesystem
or HTTP adapters. The public `transform` package wires application resolvers
into the language processors and applies aggregate invocation budgets.

## Signatures, encryption and trust

- `xmldsig`: XML signatures and authenticated reference coverage.
- `keyinfo`: untrusted key descriptions and explicitly authorized retrieval.
- `xmlenc`: bounded XML/byte encryption and configured key relationships.
- `keys`: key/container encodings.
- `pki`: offline certificate, CRL and OCSP validation.
- `cms`, `timestamp`, `xades`: signed containers, trusted timestamps and the
  supported XML signature-evidence workflows.

These layers keep cryptographic validity, application coverage and certificate
trust separate. [usage](usage.md) explains their composition.

## SAML

Packages under `saml/` separate transport, protocol validation and stateful flows:

- `binding`, `metadata` and `protocol`: wire formats, trusted role descriptions
  and authenticated message validation.
- `sp` and `idp`: solicited WebSSO, including encrypted claims, Artifact and ECP.
- `ecp` and `proof`: PAOS routing, channel bindings and X.509 holder-of-key proof.
- `artifact`: recipient-bound single-use SOAP artifact resolution.
- `session`: logout and NameID management with application-owned session state.
- `authority`: queries, assertion-ID/URI retrieval and NameID Mapping.
- `state` and `replay`: pending WebSSO requests and atomic replay rejection.

The supplied memory stores coordinate one process. Multiple instances need
shared atomic storage. Authentication, cookies and HTTP handlers belong to callers.
See [SAML integration](saml.md) and [authority integration](saml-authority.md).

## Resources and ownership

`resource` supplies explicit filesystem/HTTP adapters. `evidence` owns untrusted
observations and optional temporary-file storage; `evidence/collect` acquires
bytes under an application-supplied HTTP policy. Offline verification never
fetches missing trust material automatically.

Ownership and cancellation contracts are in [usage](usage.md#common-contracts);
retained storage is described in [streaming](streaming.md).

## Commands and verification

`cmd/xmlsec` and `examples` compose public APIs. Component tests stay beside
implementation; cross-package tests live in `tests/integration`, and
`tests/testdata/consumer` checks the public API from another module.
See [testing](testing.md) for commands and [compatibility](compatibility.md) for scope.
