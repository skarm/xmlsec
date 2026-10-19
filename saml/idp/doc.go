// Package idp orchestrates solicited SAML Web Browser SSO response issuance for
// an identity provider. It validates requests using trusted SP metadata and issues
// signed responses from application-supplied authentication decisions.
//
// # Accept and issue
//
// [NewIdentityProvider] snapshots [Config] with metadata, signing and replay adapters.
// [IdentityProvider.AcceptPOST] and [IdentityProvider.AcceptRedirect] authenticate
// and validate a request for the endpoint at which the application received it.
// The resulting [Request] is bound to that IdentityProvider instance and cannot be
// substituted from an instance with another policy.
//
// After authenticating the user, supply [Authentication] to [IdentityProvider.Issue].
// The application must truthfully report the authentication instant, context and
// interaction conditions, including ForceAuthn and IsPassive requirements.
// Issue signs and self-verifies the response, then atomically consumes the request
// before returning [Issued] data for POST delivery.
//
// # Application integration
//
// The package provides no passwords, MFA, user database, HTTP handlers, cookies or
// sessions. It relies on authenticated metadata and application-owned adapters.
// A multi-instance deployment needs shared atomic replay storage; callbacks must
// honor context. The supported flow is solicited WebSSO, not a general SAML
// protocol server.
package idp
