// Package xades composes XML signatures, certificate bindings and timestamp
// evidence in closed root-enveloped XAdES profiles. Validation levels describe
// these profiles, not universal ETSI conformance or legal signature
// qualification.
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
// [NewWithTimeValidator] selects a separate B-T profile. It establishes trusted
// SignatureValue existence from verified timestamp evidence, checks signer
// trust and revocation at the proof time, and checks TSA trust at verification
// time. It does not recover expired TSA paths, slide control time or process
// general archive evidence. Claimed SigningTime alone is never proof of
// existence.
//
// Successful results and diagnostic reports are distinct; inspect the returned
// error before consuming a result. Unsupported signature policies,
// countersignatures and historical EN 319 102-1 profiles remain outside scope.
//
// Signature and archive timestamp imprints receive canonical bytes directly
// from XML/reference writers. The complete archive digest input is not
// retained. XML snapshots and embedded certificate, revocation and timestamp
// models still occupy memory proportional to their content. Internal evidence
// shares immutable DER; public evidence getters return copies.
package xades
