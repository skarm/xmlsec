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

`binding`, `metadata` and `protocol` handle wire formats, trusted role descriptions
and message validation. `sp` and `idp` compose solicited WebSSO; `state` and
`replay` provide bounded single-process memory stores. Multiple instances need
shared atomic storage. Authentication, cookies and HTTP handlers belong to callers.

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
