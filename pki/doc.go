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
// NoRevocation performs no revocation check. RequireCRL authenticates bounded
// v1/v2 complete CRLs, scoped/indirect CRLs and applicable base/delta composites.
// Issuer-qualified entries, distribution points and reason coverage determine
// applicability; incomplete coverage remains unavailable. Supplied CRL signers
// must build to the target chain's same trust anchor and authorize cRLSign.
// CRLOptions controls delta use and the age bound when NextUpdate is absent.
// A present NextUpdate stays exclusive. With deltas enabled, advertised missing
// FreshestCRL evidence is unavailable. RequireOCSP needs authenticated offline
// responses. Certificate URLs never trigger AIA, OCSP or CRL downloads.
//
// Authenticated [VerifiedEvidence] values bind original DER, target certificate,
// issuer key, signer and scope to the explicit validation time. Successful
// results include only the evidence used by their policy; reports may retain
// authenticated stale or revoked diagnostics. [Evidence.Sources] attaches
// immutable observations only when kind and DER digest match. Acquisition URI,
// retrieved-at time and signed InvalidityDate do not establish historical proof
// of existence or an independently trusted compromise time.
//
// # OCSP and pins
//
// [CreateOCSPRequest] builds a single-certificate request with an explicit
// issuer and optional caller-generated nonce. Nonempty outgoing nonces require
// 32 through 128 caller-supplied bytes; the caller must generate them with
// cryptographically strong randomness. Legacy incoming
// nonce lengths remain accepted. [WriteOCSPResponse] encodes the caller's asserted
// status and whole-second UTC times directly to a writer; [CreateOCSPResponse]
// collects that output. Neither determines revocation status itself.
// [VerifyOCSP] returns a result only for an authenticated, fresh good response.
// The caller must establish issuer trust separately when using this low-level
// API.
// Responses can contain up to 64 status entries. Selection requires one exact
// CertID; duplicate/conflicting matches fail. Responder identity is checked
// against actual authenticated candidates, rather than trusting a matching name.
// [OCSPOptions.Authorities] explicitly binds local responder certificates to
// exact issuer certificates. Embedded certificates cannot create that authority.
// Unknown noncritical extensions are ignored; unknown critical meaning fails.
// Signed/batch requests and an OCSP server are outside this selected profile.
//
// [OCSPResult.Evidence] retains the original authenticated response assertion and
// any CRL dependencies used to authorize its delegated signer. [OCSPReport.Evidence]
// can retain authenticated stale, revoked or unknown diagnostic assertions without
// successful verification. [OCSPOptions.Sources] links exact supplied bytes to
// immutable acquisition observations; source URIs/times never establish trust.
//
// [KeyPin] checks SubjectPublicKeyInfo only. Pinning does not validate
// certificate lifetime, subject names, revocation or a PKIX path.
//
// # Time and scope
//
// Choosing a past verification time does not prove that a signature existed
// then. This package does not infer trust from XML KeyInfo, acquisition times,
// XML SigningTime or an unauthenticated timestamp generation time.
//
// [HistoricalSession] separates prospective exact path discovery, shell/chain
// calendar checking and original revocation-source authentication at issuance
// from present-time acceptance. Authentic stale assertions and exact signer
// chains are available through [HistoricalSession.AuthenticateEvidence] even
// when the target is expired now. They are not trusted-past results.
// [HistoricalSession.CheckCurrentPolicy] adds explicit historical-policy
// freshness, anchor-sunset and cryptographic cutoffs after current verification.
// The current [Verifier.Verify] policy and its result meaning remain unchanged.
//
// The library's historical workflow supplies an immutable, object-bound proof
// set to the past-certificate and time-sliding primitives. Revocation status
// issuance must precede control time; certificate/source proofs can equal it.
// Shell and chain models differ for noncompromise revocation. Delegated sources
// retain their own bounded authorization paths. A later not-listed assertion
// covers an expired target only with authenticated retention scope, such as
// expiredCertsOnCRL or OCSP archiveCutoff. A missing freshness constraint derives
// nextUpdate-thisUpdate; missing nextUpdate fails that checker. Explicit zero
// remains distinct. [PastCertificateResult] decides only that certificate
// building block; signature PoE extraction and past-signature acceptance belong
// to the separate historical signature workflow.
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
