// Package sp orchestrates solicited SAML Web Browser SSO for a service provider.
// It combines authenticated metadata, signed requests, browser-bound pending state,
// response validation and atomic replay rejection.
//
// # Begin and consume a login
//
// [NewServiceProvider] snapshots [Config] and requires application-owned metadata, signing,
// request-state and replay adapters. [ServiceProvider.Begin] selects trusted IdP
// and ACS endpoints, creates a signed AuthnRequest and stores its pending state.
// [Outbound] exposes the destination and binding-specific Redirect query or POST
// form for the application to send.
//
// The application supplies an unpredictable browser/session secret in
// [BeginOptions.BrowserBinding] and presents the same secret when consuming the
// response. RelayState alone is not browser correlation or an authorized redirect.
// [ServiceProvider.ConsumePOST] returns a verified assertion only after metadata,
// signature, protocol, correlation and atomic replay checks pass.
//
// # Application integration
//
// The application owns HTTP routing, transport security, cookies, redirects and
// session creation. A successful consume supplies protocol data from which the
// application can make its own authorization/session decision.
//
// Metadata resolvers and stores must honor context. In-memory state and replay
// stores support one process; multiple service instances need shared storage with
// atomic consumption. The package implements the documented solicited profile,
// not unsolicited login, logout or a general SAML server.
package sp
