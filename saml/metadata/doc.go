// Package metadata builds, authenticates and reads bounded SAML 2.0 SP and IdP
// metadata. Its snapshots supply authorized keys, endpoints and role requirements
// to the protocol and orchestration packages.
//
// # Establish metadata trust
//
// [NewVerifier] snapshots explicitly trusted public keys; [Verifier.Verify]
// authenticates signed metadata at an explicit time. [Verifier.VerifyReader]
// and [ParseTrustedReader] construct their XML snapshots from readers without
// complete source-byte buffers; the parsed snapshots remain in memory.
// Certificate text is decoded directly into bounded DER without complete joined
// or whitespace-filtered Base64 copies. Mutable getters return independent DER.
// [ParseTrusted] is the separate
// entry point for bytes authenticated out of band, such as an operator-provisioned
// file. It does not verify embedded XML signatures and must not receive an
// unauthenticated network response.
//
// A [Snapshot] contains immutable [Entity] and [Role] values with effective
// expiration. Snapshot lookup checks the requested entity and time. [SelectACS]
// selects from already authorized assertion-consumer endpoints; selection alone
// does not establish trust. [Build] and [Sign] create metadata for publication
// without configuring a remote party to trust it.
//
// # Keys, freshness and resource access
//
// Metadata certificates carry authorization keys, not automatically trusted PKIX
// anchors. Certificate validity dates do not replace authenticated metadata trust
// and expiration rules. [Options] bounds parsing and supported metadata collections.
//
// [Resolver] supplies already-authenticated or explicitly trusted entities to SP/IdP
// flows. A network implementation must authenticate, bound and cache its input and
// honor cancellation. Entity IDs and endpoint URIs do not trigger retrieval in
// this package. Artifact and SOAP constants identify metadata bindings; they do
// not enable those protocols.
package metadata
