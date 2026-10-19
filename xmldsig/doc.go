// Package xmldsig signs and verifies bounded XML Signature profiles over
// immutable XML snapshots. It separates cryptographic verification, application
// coverage and key trust; certificate and protocol validation belong to higher
// layers.
//
// # Choose a signature profile
//
// [SignEnveloped] and [Verify] handle a single root-enveloped signature. The
// root needs an explicit application ID, and verification can constrain its
// expanded name with [VerifyOptions.ExpectedRoot].
//
// [SignDetached] and [VerifyDetached] authenticate external resources supplied
// by an application resolver. Verification requires the exact expected URI set
// and authenticates SignatureValue before reading those resources. Reference
// bytes flow directly into digest hashes; raw external resources are not
// retained. ReferenceResult.Digest and Size inspect authenticated processing
// metadata. ReferenceResult.WriteDigestInput explicitly replays transforms into
// a writer; external replay reopens the application resolver and rejects
// changed resources.
//
// [BuildTemplate], [SignTemplate] and [VerifySignature] support explicit
// signature selection, Object content, mixed references and multiple
// signatures. Local Manifest recursion is opt-in. Preserving existing nonempty
// signatures while signing a template requires separate trusted keys in
// [TemplateSignOptions.Preserve].
//
// # Verify the data the application uses
//
// [Signatures] lists untrusted handles; selecting one does not authenticate it.
// Set [SignatureOptions.RequiredElements] and/or ExpectedURIs to express the
// application's coverage requirements. General verification does not require
// the root to be signed by default. Consume data from the verified snapshot and
// use coverage checks only within their documented node, namespace and comment
// rules.
//
// Successful result objects exist only after all required checks pass.
// [VerificationReport] is diagnostic, including when some checks succeeded
// before an error. A valid signature does not establish PKIX trust, SAML
// acceptance or trusted signing time. Embedded KeyInfo is ignored for key
// selection unless the caller explicitly uses [VerifySignatureWithKeyInfo] with
// a trust selector.
//
// # Algorithms and transforms
//
// [DefaultPolicy] permits RSA/ECDSA with SHA-2. [ModernPolicy] adds fixed
// RSA-PSS and [Ed25519]/[Ed25519ph]; [ParameterizedPolicy] enables generic PSS.
// HMAC uses separate secret-based APIs and [HMACPolicy]; every secret holder
// can produce the same MAC. Approved XPath/Filter2/XSLT transforms use
// github.com/skarm/xmlsec/transform. There is no implicit HTTP/file lookup or
// full XMLDSig conformance claim.
//
// # Message input and memory
//
// [SignMessageReader], [VerifyMessageReader], [ComputeHMACReader] and
// [VerifyHMACReader] consume input incrementally under the configured byte
// budget. Parameterized public-key variants end in WithParametersReader. Their
// byte-slice counterparts use the same core. RSA, ECDSA, Ed25519ph and HMAC
// retain digests. Ed25519ph uses SHA-512 and an empty context; it must be
// selected explicitly and is not interchangeable with pure Ed25519. Pure
// Ed25519 needs the complete bounded message for the signing/provider API.
// Byte-slice calls borrow that message; other readers collect it in memory.
// External signers receive a protected copy, while standard Ed25519 keys read
// the message directly. Ed25519 keys use pure Ed25519 by default.
// XML operations retain complete source and result trees. Result accessors
// return independent copies of mutable data.
package xmldsig
