// Package xades composes XML signatures, certificate bindings and timestamp
// evidence in baseline formats, closed root-enveloped profiles and a separate
// bounded historical workflow. These operations do not assert universal ETSI
// conformance or legal signature qualification.
//
// # Basic signatures
//
// [SignBasicEnveloped] creates SignedProperties with SigningTime,
// SigningCertificateV2 and DataObjectFormat. [VerifyBasicEnveloped] verifies an
// explicitly selected signature against an externally trusted certificate pin.
// A [BasicResult] establishes the supported XML bindings, not PKIX trust,
// revocation status or trusted signing time. Basic verification rejects
// unsigned preservation properties; use the evidence APIs for those documents.
//
// # Baseline formats
//
// [SignBaseline] and [VerifyBaseline] select a separate EN319132-1 V1.3.1
// baseline format. They support nested enveloped, enveloping, same-document
// detached and explicitly resolved external data, and independent signatures.
// Every typed SignedProperties Reference must itself cover the complete selected
// property subtree. Application coverage and external resources remain explicit
// XMLDSig policy. Baseline properties use direct incorporation, as required by
// clause 6.3; indirect QualifyingPropertiesReference is rejected.
//
// The signed claims include SigningCertificateV2 (additional DER references and
// issuer hints), complete format/object identifiers, commitments, production
// place, role containers, explicit/implied policy and content timestamps.
// SigningTime preserves the exact UTC year/fraction lexical; its convenience
// time.Time value can be zero when that precision/range is not representable.
// Claimed, certified-role and signed-assertion containers are distinguished;
// their outer authentication never establishes third-party authority. Domain
// assertion, attribute-certificate trust and authorization need separate policy.
//
// Content timestamps expose exact bounded imprint writers. The writers execute
// approved transforms once, sharing the final immutable node set between the
// signed digest and the timestamp canonicalization. Parsing a token grants no
// TSA trust. [VerifyCounterSignature] binds a separately authenticated enclosed
// signature to the complete enclosing SignatureValue; child trust is explicit.
// Policy bytes are supplied offline. The technical-specification digest callback
// is confined to SignaturePolicyId and is not a general XMLDSig transform.
//
// # Timestamps and preservation
//
// [AddSignatureTimestamp] obtains and verifies a nonce-bound TSA response;
// [AttachSignatureTimestamp] verifies an already obtained token. [NewValidator]
// configures signer/TSA trust and a required B-B, B-T, B-LT or B-LTA minimum.
// [Validator.EmbedValidationMaterial] and archive timestamp methods augment new
// immutable snapshots and validate their supported evidence. Current-time
// validation does not backdate certificate validity using SigningTime.
//
// # With-time validation
//
// [NewWithTimeValidator] selects a separate B-T profile. Supplied signer CRLs
// are limited to direct complete lists; indirect, delta and distribution-scoped
// CRL artifacts are rejected even though current-time PKI supports them.
// It establishes trusted SignatureValue existence from verified timestamp
// evidence, checks signer trust and revocation at the proof time, and checks TSA
// trust at verification time. It does not recover expired TSA paths, slide
// control time or process general archive evidence. Claimed SigningTime alone is never proof of
// existence.
//
// Successful results and diagnostic reports are distinct; inspect the returned
// error before consuming a result. [NewHistoricalValidator] selects the separate
// bounded EN319102-1 workflow; it does not broaden the closed current/with-time
// APIs. A baseline format result alone never assigns B-T, B-LT or B-LTA trust.
//
// # Historical validation
//
// [HistoricalValidator.Validate] separately checks exact-object PoE, shell/chain
// certificate models, authenticated offline revocation data, temporal algorithm
// constraints and expired TSA paths under EN319102-1 V1.4.1. Archive dependencies
// are processed before the tokens they protect; accuracy and ordering remain
// distinct from nominal GenTime. Absent accuracy needs an explicit TSA-policy
// assumption to produce an old-time proof. Source acquisition time and signer
// SigningTime never become PoE. Each reference/hash material needs its own proof.
//
// This workflow is a tested implementation subset, not the complete EN process.
// General evidence records, historical countersignature/attribute-authority
// workflows, broader preservation properties and all current-process indication
// branches remain outside it. Unsupported unsigned properties fail explicitly.
// [HistoricalReport] explains partial diagnostics; only a nonnil successful
// [HistoricalResult] accepts the selected signature under its configured policy.
//
// Closed timestamp/augmentation methods stream canonical bytes without retaining
// a complete archive input. Historical validation retains bounded exact objects
// while constructing its proof graph. XML snapshots and embedded certificate,
// revocation and timestamp models still occupy memory proportional to their content. Internal evidence
// shares immutable DER; public evidence getters return copies.
package xades
