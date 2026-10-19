// Package pki verifies explicit certificate trust and bounded offline
// revocation evidence. It also parses, creates and verifies the supported OCSP
// profiles.
//
// # Certificate verification
//
// Create a [Verifier] with [NewVerifier], supplying DER roots and the
// application's required key usages and revocation policy. [Verifier.Verify]
// checks at an explicit caller-supplied time, with optional intermediates and
// [Evidence]. System roots are never used. Successful [Result] values expose
// the verified chain and revocation outcome; [Report] is diagnostic.
//
// NoRevocation performs no revocation check. RequireCRL needs authenticated
// direct, complete CRLs; RequireOCSP needs authenticated offline OCSP
// responses. Certificate URLs do not trigger AIA, OCSP or CRL downloads.
// Indirect/delta CRLs are unsupported.
//
// # OCSP and pins
//
// [CreateOCSPRequest] builds a single-certificate request with an explicit
// issuer and optional caller-generated nonce. [WriteOCSPResponse] encodes the
// caller's asserted status and times directly to a writer; [CreateOCSPResponse]
// collects that output. Neither determines revocation status itself.
// [VerifyOCSP] returns a result only for an authenticated, fresh good response.
// The caller must establish issuer trust separately when using this low-level
// API.
//
// [KeyPin] checks SubjectPublicKeyInfo only. Pinning does not validate
// certificate lifetime, subject names, revocation or a PKIX path.
//
// # Time and scope
//
// Choosing a past verification time does not prove that a signature existed
// then. This package does not infer trust from XML KeyInfo or implement
// historical AdES proof-of-existence validation. Application code supplies
// trusted time, evidence collection and any network policy.
//
// # Input and storage
//
// Verifiers snapshot configured and operation-supplied certificates. Results
// share privately owned immutable chain DER; accessors return independent
// copies. CRL and OCSP evidence is borrowed for validation and must stay
// unchanged until the call returns. Standalone [VerifyOCSP] retains one owned
// response and its responder certificate.
//
// [WriteOCSPResponse] retains bounded signed metadata and a responder
// certificate snapshot. Certificate, CRL and OCSP parsers require complete
// DER/x509 models; these APIs do not promise constant-memory revocation
// parsing. Network access stays separate.
package pki
