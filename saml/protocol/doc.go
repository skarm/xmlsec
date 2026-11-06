// Package protocol builds and verifies bounded SAML 2.0 messages for solicited
// WebSSO, logout, NameID management, artifact resolution, authority queries and
// NameID Mapping. It checks authenticated XML against application-supplied
// partner, endpoint, correlation and time expectations.
//
// # Requests and responses
//
// [BuildAuthnRequest] creates a request from [AuthnRequest]; [SignAuthnRequest]
// adds its XML signature. [VerifyAuthnRequest]
// requires an XML signature and trusted partner keys; [VerifyRedirectRequest]
// composes authenticated Redirect decoding with request checks.
//
// [SignResponse] signs a successful response and assertion from application-owned
// [Response] data. [VerifyResponse] accepts a solicited POST response under
// [ResponseOptions], including expected request ID, issuer, audience, destination,
// assertion-consumer endpoint and time. These expectations must come from trusted
// configuration and pending request state, not from the received response itself.
//
// [VerifiedRequest] and [VerifiedAssertion] expose accepted protocol data.
// [StatusError] describes an authenticated non-success response and is never a login.
// [Limits] bounds message age, assertion lifetime and attribute collections.
//
// [EncryptionOptions] encrypts Assertion, NameID and/or Attribute. Verification
// authenticates the original Response, decrypts an encrypted Assertion, verifies
// its signature, then decrypts inner identifiers and attributes before checking
// claims. [DecryptionOptions] fixes algorithms and a bounded private-key ring;
// received KeyInfo never supplies trust. CBC/RSA15 require prior enclosing
// authentication. RequireEncryption rejects plaintext at selected positions.
// [SigningKey] supports the original Canonical XML/SHA-1 baseline through
// explicit policies. [NewSharedSecret] selects protocol-level HMAC credentials
// separately from public keys; every secret holder can produce a valid MAC.
//
// # Authority queries and identifier mapping
//
// [SignQuery] and [VerifyQuery] handle authentication, attribute and authorization
// queries and assertion-ID requests. [SignQueryResponse] and [VerifyQueryResponse]
// retain zero or more separately authenticated assertions, including empty success.
// [SignAuthorityAssertion] does not impose WebSSO login or bearer semantics.
// [SignNameIDMappingRequest] and [VerifyNameIDMappingResponse] implement the
// separate mapping protocol. Opaque target-encrypted identifiers can be forwarded;
// they never become local identities merely by verifying the response envelope.
// Stateful SOAP, URI, authorization and replay integration lives in saml/authority.
//
// # Compose the surrounding flow
//
// The package does not authenticate a user, retrieve metadata, bind a request to a
// browser, consume replay identifiers or create application sessions. Use
// github.com/skarm/xmlsec/saml/sp and github.com/skarm/xmlsec/saml/idp to compose
// those checks with trusted adapters. Authentication statements supplied during
// issuance must reflect decisions actually made by the application.
// Logout, NameID management and artifact messages have separate authenticated
// request/response types. Their stateful processing is in saml/session and
// saml/artifact. SOAP/PAOS routing is in saml/binding and saml/ecp. Unsolicited
// SSO and custom BaseID extensions are outside this profile.
package protocol
