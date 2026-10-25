// Package cms creates, parses and verifies a bounded CMS SignedData profile
// based on RFC 5652, with definite-length generation and DER signed attributes.
// It supports attached and detached content and explicit signer certificates.
//
// # Sign and inspect
//
// [SignReader] reads content and writes definite-length DER directly. Detached
// messages use fixed-size hashing buffers; embedded messages are retained until
// their length and signatures are known. [Sign] collects the same writer core.
// [SignReader] starts output after consuming all content and verifying generated
// signatures; it does not emit a container prefix while reading the message.
// Resident byte input is borrowed for the operation. [ParseReader] retains one
// complete bounded DER encoding and a parsed model; it is not a constant-memory
// container parser.
//
// [Sign] takes caller-selected [Signer] key/certificate pairs and
// [SignOptions]. RSA and ECDSA signatures use SHA-2; RSA also supports
// fixed-parameter PSS. Signatures bind content and generated signed attributes.
// [Attribute] values can carry additional signed data, but the package does not
// infer application semantics from an unknown attribute.
//
// [Parse] checks bounded container structure, versions and attribute placement.
// [ParseBER] and [ParseBERReader] explicitly accept selected indefinite wrappers
// and constructed content OCTET STRINGs, preserving original signed attributes.
// They produce a normalized definite representation for DER/Size/WriterTo;
// the source encoding, metadata and intermediate buffers coexist temporarily.
// Default Parse/ParseReader retain their strict encoding rules. Other BER forms,
// including indefinite SignerInfos and certificate bags, remain unsupported.
// A parsed [SignedData] is unverified: embedded certificates and
// UnverifiedContent are inspection data, not authenticated results.
//
// # Verify and apply trust
//
// [SignedData.Verify] requires exactly the caller-selected signer certificates,
// an explicit expected content type and, for detached content, its exact bytes.
// [SignedData.VerifyReader] consumes detached content once without retaining
// it. Its result exposes [Result.ContentSize]; [Result.Content] is nil for
// streamed detached input. The byte-oriented Verify retains its supplied
// content. [VerifyOptions.DiscardContent] suppresses this result copy for
// either content mode. Parsed SignedData still owns its complete DER.
// [SignedData.WriterTo] replays that DER without another container-sized
// allocation. All signers and required certificate bindings must pass before a
// [Result] is returned. Certificate binding and cryptographic validity do not
// establish PKIX trust. [SignedData.VerifyWithTrust] and
// [SignedData.VerifyReaderWithTrust] additionally apply an explicit pki.Verifier
// at a caller-selected time to every authenticated signer. They return no Result
// after a partial trust failure; [Result.TrustChecked] and [SignerResult.Trust]
// distinguish full configured-policy checks from cryptographic authentication.
// Signed ESS identifiers after the signer constrain certification-path selection.
// This profile does not evaluate those optional restrictions: trusted operations
// return ErrUnsupported when they are present. Ordinary Verify binds only the
// first signer certificate and does not claim PKIX or ESS path-policy validation.
//
// [Limits] bounds bytes and collections; zero fields use the documented
// defaults. The package performs no implicit resource fetching and is not a
// general CMS/BER processor or certificate store.
package cms
