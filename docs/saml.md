# SAML protocol integration

The library implements the SAML 2.0 (15 March 2005) Web SSO, Single Logout,
Name Identifier Management and Artifact Resolution profiles, with the applicable
[Approved Errata 05](https://docs.oasis-open.org/security/saml/v2.0/errata05/os/saml-v2.0-errata05-os.html).
These APIs provide protocol processing; applications provide user authentication,
account linking, HTTP routing, trusted metadata and authoritative session storage.

## Web SSO and ECP

`sp.BeginOptions.Binding` selects Redirect, POST, Artifact or PAOS. The response
binding defaults to POST; `ResponseBinding` can select Artifact. PAOS initiation
selects a PAOS ACS and a SOAP IdP SSO endpoint. Browser/session binding is required
for all response transports. Do not use RelayState as a redirect destination.

For ECP, advertise HTTP support with `ecp.Advertise`, check negotiation with
`ecp.Negotiated`, and return `Outbound.PAOS` with `ecp.WriteChallenge`.
`ecp.ParseChallenge` retains the original SP-controlled consumer URL and relay
header. `Exchange.ToIDP` removes ECP/PAOS headers before forwarding the SAML body
to a separately trusted IdP endpoint. The IdP uses `AcceptSOAP`, authenticates the
user, calls `Issue` or `Reject`, and returns `Issued.ECP`.

`Exchange.Finish` compares the IdP consumer URL with the retained SP URL and
restores relay/correlation headers. On mismatch it returns only a SOAP fault.
`Exchange.Deliver` posts that result, including a routing fault, to the original
SP endpoint; it never follows redirects. The SP consumes the returned envelope
with `ConsumePAOS`. Direct HTTP request decoding is available through
`ecp.ReadResponse`; parsing alone does not verify the assertion or browser state.

ECP support is the original bearer profile in
[SAML Profiles 4.2](https://docs.oasis-open.org/security/saml/v2.0/saml-profiles-2.0-os.pdf),
including errata E20/E21/E22/E35/E54. The later
[ECP 2.0 CS01 (2013)](https://docs.oasis-open.org/security/saml/Post2.0/saml-ecp/v2.0/cs01/saml-ecp-v2.0-cs01.html)
supersedes that profile and has additional implementation requirements for
holder-of-key, channel bindings and authentication mechanisms. Those requirements
are distinguished from the original profile. Channel binding and X.509 HoK with
TLS client authentication or whole-SOAP XML proof are implemented as described
below. The scope of §2.3.11's no-Transforms wording remains unresolved; see
[holder-of-key processing](#ecp-2013-holder-of-key). Unknown mandatory extension
headers fail rather than silently downgrading the exchange.
Identity provider discovery and interactive login remain application concerns.

For the CS01 channel-binding option, a client uses `AdvertiseChannelBindings`;
the SP checks `NegotiatedChannelBindings` before supplying `BeginOptions.ChannelBindings`.
Obtain `tls-server-end-point` with `ServerCertificateBinding` using the actual
server certificate of the authenticated client/SP connection (RFC 5929 4.1).
Do not fetch a certificate on a different connection or trust one supplied in XML.
Algorithms without a single defined certificate-signature hash are rejected.
`TLSExporterBinding` additionally implements RFC 9266 for a completed TLS 1.3
connection; that connection must be closed after the authentication instance.

The client calls `ParseChallengeWithBindings` with independently obtained
transport data. The SP data is inside the signed request; the client data is in
the forwarded SOAP header. `AcceptSOAP` compares them. A channel mismatch returns
both an authenticated `Request` and an error: use `Reject` to send a signed SAML
failure, never `Issue`. A successful issue includes matching signed assertion
Advice and a SOAP signal. `Finish` produces a fault if the IdP omits its signal;
`ConsumePAOS` also requires the signed Advice against the original pending state.
The ECP removes processed channel headers before the return hop.

### ECP 2013 holder of key

Metadata endpoints advertise HoK with `Binding: metadata.HoKSSO` and the actual
SOAP/PAOS transport in `ProtocolBinding`. `Endpoint.SupportedChannelBindings`
publishes the `cb:supportsChannelBindings` list. Nil omits the attribute; an empty
non-nil slice publishes an empty list. `Role.HoKACS` selects only explicitly
advertised HoK endpoints. SP/IdP orchestration uses their actual transport and
prefers HoK advertisements for an explicit HoK request; bearer requests cannot
select HoK-only endpoints. Ordinary PAOS/SOAP endpoints remain usable with explicit
HoK negotiation for peers that omit the SHOULD-level advertisement. Advertisement
does not prove key possession or establish a secure channel.

The client advertises `AdvertiseHoK`; the SP checks `HoKNegotiated` and supplies
`BeginOptions.HolderOfKey`. Pending state retains that requirement, preventing a
bearer downgrade. `ParseHoKChallenge` selects the client's exact certificate and
the actual SP channel data, if requested. If both bearer and HoK are offered,
`ParseChallenge` may select the explicit bearer alternative. A HoK-only challenge
cannot be processed by a bearer-only client.

For TLS proof, the client submits `Exchange.ToIDP` over a mutually authenticated
TLS connection. The IdP calls `ecp.VerifyTLSRequest` on the original server request
and passes the resulting opaque proof to `idp.AcceptECP`. For XML proof, the client
chooses one of two separate XML APIs:

- Declared W3C transform: `Exchange.ToIDPEnvelopedXML` and
  `ecp.VerifyEnvelopedXML`; for the return hop use `FinishEnvelopedXML`.
- Explicit CS01 compatibility: `Exchange.ToIDPCS01CompatXML` and
  `ecp.VerifyCS01CompatXML`; for the return hop use `FinishCS01CompatXML`.

The low-level methods are `proof.SignEnvelopedXML` / `VerifyEnvelopedXML` and
`proof.SignCS01CompatXML` / `VerifyCS01CompatXML`. Each verifier accepts only its
named format; neither auto-detects or retries the other. TLS proof needs neither
XML API.

[ECP CS01 §2.3.11](https://docs.oasis-open.org/security/saml/Post2.0/saml-ecp/v2.0/cs01/saml-ecp-v2.0-cs01.html)
requires an empty-URI Reference and excludes the proof Signature from coverage,
but its no-Transforms wording does not clearly distinguish direct SignedInfo
children from nested Reference/Transforms. Ordinary W3C XMLDSig requires a
declared transform for self-exclusion. The compatibility API applies that
exclusion outside W3C reference processing; generic xmlsec1 and JDK verification
reject its Reference digest. The declared-transform API follows W3C XMLDSig;
its full CS01 status remains unresolved. See the [selected standards](standards.md)
and [independent tests](testing.md#saml-interoperability).

The IdP's `AcceptECP` receives independently derived channel bindings and checks every
supplied client/IdP binding. These headers omit the SOAP actor; client/SP channel
headers use the next actor. `ServerCertificateBinding` supports the required
`tls-server-end-point` form on both channels. With XML proof, supplying and
verifying this binding is recommended by CS01 2.3.5.1.

`Request.HolderOfKeyCertificate` identifies the proven certificate. Before issuing
an assertion, the application must independently associate that key with the
authenticated principal and set `Authentication.HolderOfKeyCertificate` to the
associated certificate. Possession, a certificate DN, and successful XML parsing
do not establish that association. HTTP Basic can be implemented with standard
`Request.BasicAuth` and `Request.SetBasicAuth`; TLS, cookie storage and account
authentication remain in the application's HTTP configuration. The real mTLS
integration test demonstrates Basic authentication plus explicit key association.
PKIX validation is optional in this profile and is not silently required or
granted by these proof APIs.

`Issued.ECP` includes HoK confirmation data identical to the assertion producer's
data, including when the assertion is encrypted. Use `ecp.WriteIDPResponse` for
the SOAP HTTP response. The client checks that header in `Finish`, then presents
the same key to the SP using either TLS client authentication or the selected
`FinishEnvelopedXML` / `FinishCS01CompatXML` method.
The SP verifies the corresponding transport/XML proof and calls `ConsumeECP`.
SAML signatures, conditions, audience, recipient, request/session correlation and
replay remain mandatory. Certificates are matched byte for byte; a reissued
certificate with the same public key is insufficient for this matching form.
Proofs are bound to immutable SOAP snapshots and cannot be applied to another
document with the same XML ID. Never construct synthetic TLS state from a proxy
header. Optional non-X.509 keys and SKI/DN/issuer-serial confirmation forms are
not selected by these APIs.

## Artifact and SOAP

`artifact.Issuer` binds a random type 0x0004 artifact to the intended recipient,
endpoint index and an immutable message. `artifact.MemoryStore` implements atomic
single use, expiry and capacity bounds. A durable shared `artifact.Store` is
required across service instances. Its `Resolve` transaction commits consumption
only after the signed reply is ready; a signing failure preserves the message.
The default SourceID is the recommended SHA-1 entity-ID routing hash, not a
security signature. An explicitly agreed opaque SourceID can be configured on
both issuer and resolver. `Issuer.Limits` must match its request verifier's
freshness policy, including when a verified request is held before resolution.

Use `Outbound.IssueArtifact` or `Issued.IssueArtifact` for Web SSO. Deliver the
token with `binding.ArtifactURL` or `ArtifactForm`; decode GET/POST fields with
`DecodeArtifact`. `artifact.Resolver` uses a current trusted peer entity ID,
signing keys and indexed SOAP endpoints. Received XML or token bytes never supply
an endpoint to fetch. An unknown, expired, unauthorized or consumed artifact gets
a successful empty response. Resolution does not validate the nested protocol:
use `idp.AcceptArtifact`, `sp.ConsumeArtifact` or the relevant control verifier.

`binding.SOAPClient`, `ReadSOAPRequest` and `WriteSOAPResponse` implement SOAP 1.1
HTTP transport. SAML error statuses use HTTP 200; SOAP faults use HTTP 500.
Additional mandatory headers need explicit processing. SOAP parsing grants no
trust. Production endpoints require HTTPS unless an application explicitly opts
into HTTP for a trusted link; TLS configuration remains in its HTTP client/server.

Inclusive C14N signatures include ancestor namespaces. Sign control messages in
the final envelope using `protocol.SignSOAP`. For nested assertions or artifact
requests, set `protocol.Response.SOAPContext` or `AuthnRequest.SOAPContext` before
signing. High-level SP/IdP flows do this automatically. Arbitrarily wrapping an
already signed Inclusive C14N message can invalidate its signature.
Extracted payloads retain an immutable view of their original ancestors and the
full source ID domain. When inherited xml:* attributes cannot be flattened onto
a schema-constrained SAML root, isolated `XML` serialization returns an error;
serialize the original envelope or use `WrapSOAP` to preserve that context.

## Logout and managed identifiers

`session.Service` processes authenticated control requests, while `session.Store`
atomically manages sessions, current NameID bindings, pending exchanges and replay
markers. Each store belongs to one local entity. Register bindings only after
application-authenticated account linking. Add sessions after successful SSO,
retaining the complete `VerifiedAssertion.Identifier` and `SessionIndex`.
Authorization must consult the same authoritative session state. The in-memory
store is suitable for a single process; shared deployments need a durable adapter.
`session.Config` fixes the local entity and role, and `Store.Provider` prevents
accidental reuse for another provider. Persistent identifier qualifiers omitted
on the wire are resolved using that context. Pass the assertion's identifier to
`Session.NameID`; stale bindings are rejected, and management changes preserve
existing logout marks for the renamed identifier. `Service.Limits` must match
the incoming verifier's freshness policy.

For incoming messages, verify issuer, keys, endpoint, freshness and signature
through the typed protocol verifier. Redirect verifiers authenticate the original
query and return RelayState separately; echo it and correlate it with the
initiator's application state. Call `Service.Logout` or `Manage` with the current
trusted peer response endpoint. `Service.Endpoint` is the receiving local
endpoint; `ResponseEndpoint` handles a different metadata ResponseLocation.
SOAP requests may omit Destination; a present Destination is always checked.

Logout selects the complete NameID and supplied session indices; an authority
may omit indices to select all applicable sessions. Participant-initiated logout
requires at least one index. An IdP advertising SingleLogoutService must supply
SessionIndex during `Issue`; the SP rejects its omission. Incoming logout marks
also reject valid late-arriving assertions through NotOnOrAfter plus the configured
ClockSkew. `Service.Limits.ClockSkew` must cover the assertion verifier's clock
skew as well as the incoming control verifier's policy; custom Store adapters
must retain the logout block for this full interval. An authority
fans out under the matching AuthoritySession and reports PartialLogout if any
participant cannot be contacted or does not confirm success. `InitiateLogout`
starts the same process directly at the authority. Configure `Service.Notify`
using `BackChannel.Logout` or an application-managed front-channel exchange.

`BeginLogout` invalidates matching initiating local sessions and records pending
correlation and a logout block atomically. The block covers NotOnOrAfter plus
ClockSkew (or the two-hour replay lifetime if NotOnOrAfter is absent), independently
of receiving a response or expiring pending state. `Complete` accepts only the
exact verified response kind, peer and request ID, once. A name-management request from an SP changes
SPProvidedID; one from an IdP changes the primary NameID value. The format and
local account ID remain unchanged. `BeginManage` commits the initiating side's
rename only after a successful correlated response. Existing and replacement
identifiers can be encrypted and are decrypted only after authentication.
`NewPersistentNameID` generates an opaque pairwise identifier; persist it rather
than exposing a username in the persistent format. Persistent/transient values
are limited to 256 Unicode characters; transient values also follow NCName rules.

Terminate retires the identifier binding and preserves active sessions (errata
E8); it affects that identifier relationship, not other accounts or peers. Logout
must precede sending Terminate. Pending termination prevents a later logout for
the same binding. Sending Terminate immediately retires the initiating local
binding; a lost/error response or pending-state timeout does not restore it.
The reference store retains that retirement until the original relationship's
expiry and rejects new sessions or re-registration of the same identifier during
that period. Explicit account linking may register a different identifier.
Management of transient identifiers is rejected (E12). Unknown
or stale identifiers get Requester/UnknownPrincipal. Reply signatures are prepared
before incoming control state is committed, so signing failures leave it intact.
Custom Store adapters return Success, Success/PartialLogout,
Requester/UnknownPrincipal or Requester from Logout/Manage. Backend failures
return an error before committing; these four outcomes have prepared replies.

Stores bound capacity and lifetimes without evicting active entries. Defaults
include five-minute pending control exchanges, at most five-minute artifacts,
two-hour replay markers in Service and at most seven-day logout marks plus clock
skew. The configured acceptance window and durable-store retention must stay consistent.
The reference store retains one current identifier binding per local account/peer.
Queries, assertion retrieval and SOAP NameID Mapping use the separate
[authority APIs](saml-authority.md). Custom BaseID schema types, unsolicited SSO
and proxying profiles remain outside these APIs. Full SAML role conformance is
not claimed merely from the presence of these workflows.
