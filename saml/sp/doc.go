// Package sp orchestrates solicited SAML Web Browser SSO for a service provider.
// It combines authenticated metadata, signed requests, browser-bound pending state,
// response validation and atomic replay rejection.
//
// # Begin and consume a login
//
// [NewServiceProvider] snapshots [Config] and requires application-owned metadata, signing,
// request-state and replay adapters. [ServiceProvider.Begin] selects trusted IdP
// and ACS endpoints, creates a signed AuthnRequest and stores its pending state.
// [Outbound] exposes the destination, Redirect query, POST writers, artifact
// issuance or PAOS challenge for the application to send.
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
// not unsolicited login or a general SAML server. Begin also supports Artifact
// and bearer or X.509 holder-of-key ECP/PAOS. ConsumeArtifact and ConsumePAOS
// retain the same browser, metadata, assertion and replay checks. ConsumeECP
// additionally requires proof bound to the exact HoK SOAP snapshot.
// Logout and identifier management use
// github.com/skarm/xmlsec/saml/session with the application's session store.
package sp
