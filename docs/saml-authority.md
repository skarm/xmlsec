# SAML authorities, queries and identifier mapping

The `saml/authority` package composes SOAP/HTTP transport, authenticated metadata,
protocol validation, application authorization and replay protection. It is
separate from WebSSO: a query result never establishes a login. All three query
types, assertion-ID retrieval, the HTTP URI binding and SOAP NameID Mapping have
producer, consumer and application integration APIs.

See [standards](standards.md) for the selected SAML editions. Custom BaseID
schemas and automatic provider proxying are unsupported.

## Requests and assertions

`protocol.Query` selects `AuthenticationQuery`, `AttributeQuery`,
`AuthorizationQuery` or `AssertionRequest`. `NewSubject` builds a NameID subject;
an application-built Subject document can also include confirmation alternatives.
`SignQuery` and `VerifyQuery` authenticate the complete request before decrypting
its identifiers. Consent and foreign-namespace Extensions are retained.

Attribute filters contain complete immutable `saml:Attribute` documents. Values
may be structured XML, typed simple values, empty values or explicit nils.
Name and NameFormat identify an attribute; FriendlyName does not replace them.
Duplicate requested attributes are rejected. Attribute-value comparison retains
QName namespace bindings and uses identical canonical XML unless the application
supplies the attribute profile's equality operation.

`SignAuthorityAssertion` creates an assertion without imposing WebSSO bearer,
recipient or fresh-login requirements. It retains AuthnStatement,
AttributeStatement and AuthzDecisionStatement documents, conditions and advice.
Past AuthnInstant values remain past acts; AuthnQuery must never initiate a new
credential authentication. Assertion, identifier and attribute encryption can be
selected independently. Attribute-count/value/byte limits apply before issuance
and after authenticated decryption. Value byte limits cover canonical XML markup
and type annotations as well as text.

`SignQueryResponse` and `VerifyQueryResponse` support zero or more assertions.
An empty Success means no matching facts. Every returned subject must strongly
match the query; identifier content, attribute values and attribute presence are
retained. Authentication filters are checked across the result set. Attribute
filters prevent returning unrequested attributes or values. Authorization results
must concern the requested resource and actions. Assertion-ID results must contain
only requested IDs. A response issuer cannot implicitly authorize another
assertion issuer: `AssertionTrust` must explicitly resolve that issuer's keys.
Forwarding a completed assertion signed by another key also requires the signing
key's explicit `PreserveKeys` adapter. The service derives that adapter from its
assertion trust resolver and verifies preservation again while signing SOAP.

Exact AuthnContext URI comparison is built in. For minimum, maximum and better,
`QueryMatchOptions.Context` supplies the authority's strength ordering, including
maximum's strongest-available rule. It must not infer strength from URI spelling.
Errata E45 does not assign preference order to AuthnQuery references; better means
stronger than one requested context. If no context can be satisfied, the backend
returns `StatusError` with `NoAuthnContext`, or the service generates that status
when its final result check detects the mismatch.

`QueryMatchOptions.Confirm` must establish strong confirmation compatibility when
a query includes SubjectConfirmation. Missing confirmation or non-exact context
evaluators cause rejection. Evidence in authorization queries is untrusted input;
the backend must separately authenticate any embedded assertion it relies on.
Unknown assertion conditions are rejected as indeterminate. Audience restrictions
are ANDed, with OR within a restriction. OneTimeUse is retained for atomic replay
processing; ProxyRestriction is retained without granting permission to proxy.
Advice permits foreign namespace extensions; Evidence permits only the four
SAML assertion/reference alternatives. Reference syntax is checked without
fetching references or granting trust to embedded assertions.

## SOAP integration

`authority.NewService` selects supported request kinds and application callbacks.
`Config.Trust` resolves explicitly authenticated peer keys; neither KeyInfo nor an
HTTPS-looking issuer URI grants trust. `Config.Query` authorizes disclosure and
returns signed assertions about existing facts. `Config.Mapping` authorizes the
source principal, target federation and any requested identifier creation. A
signed request is consumed before a backend can create a binding. Backend and
replay adapters must support concurrent calls and honor context.

HTTP handlers compose `binding.ReadSOAPRequest`, `Service.Respond` and
`binding.WriteSOAPResponse`. `authority.Client` resolves the selected role's
current trusted endpoint, signs the request, performs the synchronous exchange,
checks the correlated result and atomically consumes replay entries. The HTTP
client supplies TLS, optional client certificates and preemptive HTTP Basic through
its transport. Applications own credentials, account authentication and authorization;
the package is not a password database or a deployed IdP product.

All SAML messages in this integration use XML signatures. Transport
adapters handle SOAP faults and HTTP errors. Received response endpoints cannot
redirect the client to another server. SOAP may omit Destination; a present
Destination must match an explicitly configured expected destination. Inclusive
C14N is signed in its final SOAP namespace context. Exclusive C14N for rich XML
uses InclusiveNamespaces so QName bindings cannot be changed outside the digest.

Multi-instance deployments need shared atomic replay storage. A result containing
63 OneTimeUse assertions needs a batch of 65 entries. The reference replay store
supports up to 256 entries atomically.
Configure store lifetimes to cover message age, assertion expiry and clock skew.
OneTimeUse assertions without a bounded expiry are rejected by the client.
The response limit is `protocol.MaxQueryAssertions` (63), within the shared
64-signature budget. Embedded Evidence signatures also count toward that budget.

## NameID Mapping

`SignNameIDMappingRequest` and `VerifyNameIDMappingRequest` retain the existing
NameID and the requested Format, SPNameQualifier and AllowCreate. Mapping does
not rename the source binding; ManageNameID remains the separate management
operation. An application can use `NewPersistentNameID` when it is authorized to
establish a new opaque pairwise persistent identifier.

The mapping backend normally returns an EncryptedID for the target provider's
metadata-authorized key. `EncryptMappedIdentifier` constructs this representation.
`Client.Map` verifies the signed, correlated envelope and returns the opaque
identifier without demanding the target's private key. A deployment-specific
plaintext exception requires `AllowPlaintextMapping` on the service. Plaintext
output is checked against the requested format and target namespace; the backend
must enforce those rules before encrypting opaque output.

Core's NameIDMappingResponse schema requires a NameID/EncryptedID even for an
error. `VerifiedNameIDMappingRequest.ErrorIdentifier` provides the original
representation for this purpose, preserving input encryption. Consumers expose
no mapped identifier when the status is not Success.

`EncryptMappedAssertion` implements the optional limited-use representation from
Profiles §7.4.2.1: a signed assertion with a subject and no statements is encrypted
into an EncryptedID. `DecryptMappedAssertion` verifies its issuer, signature and
conditions at the target. It must not be treated as a bare NameID. Raw decryption
helpers require authenticated encryption; legacy CBC/RSA-v1.5 additionally needs
the exact verified enclosing mapping result's `DecryptNameID`/`DecryptAssertion`
method. Private-key attempts share a bounded aggregate budget.

## Assertion URI retrieval

`binding.AssertionURL` creates the single, exact `ID` query. The configured
endpoint cannot already contain a query or fragment. Wildcards, duplicate IDs,
extra query parameters and invalid escapes are rejected. `URIHandler` authenticates
and authorizes before lookup, returns 403 for denied disclosure and 404 for an
unknown ID, and disables caching. `URIClient` never follows redirects and checks
the returned assertion's ID before higher-level signature/condition verification.

An assertion URI must forever designate the same assertion or return an error.
`MemoryAssertions` provides bounded immutable-ID insertion without eviction or
replacement. It is process-local; persistent published URIs need durable storage
with the same contract across restarts. `Get` does not itself authorize disclosure.

## Tests and independent evidence

`TestAuthoritySOAPAndURI` covers HTTPS/SOAP/URI integration, replay rejection,
authorized disclosure and immutable assertion IDs. Protocol tests cover filters,
multiple/empty results, independent issuers, encrypted claims and mapping;
`FuzzAuthorityQueryParsers` exercises untrusted inputs.

`TestOpenSAMLAuthorityContracts` checks query, assertion-ID and Mapping messages
in both directions against OpenSAML, including schema and signature validation.
Deployed-server tests cover Shibboleth AttributeQuery, OpenAM AuthnQuery,
AssertionIDRequest and Mapping, and Google GSA AuthzDecisionQuery.

OpenAM Mapping requires a test-runtime serializer patch; GSA returns unsigned
XML that the Go verifier rejects. These tests have different acceptance boundaries.
See [SAML interoperability tests](testing.md#saml-interoperability) for setup and
peer limitations.
