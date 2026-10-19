// Package protocol builds and verifies a closed, solicited SAML 2.0 Web Browser
// SSO profile. It checks authenticated XML against application-supplied partner,
// endpoint, correlation and time expectations.
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
// # Compose the surrounding flow
//
// The package does not authenticate a user, retrieve metadata, bind a request to a
// browser, consume replay identifiers or create application sessions. Use
// github.com/skarm/xmlsec/saml/sp and github.com/skarm/xmlsec/saml/idp to compose
// those checks with trusted adapters. Authentication statements supplied during
// issuance must reflect decisions actually made by the application.
// Unsolicited SSO, logout, Artifact/ECP and encrypted-assertion profiles are outside
// this protocol profile.
package protocol
