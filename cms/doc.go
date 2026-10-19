// Package cms creates, parses and verifies a bounded CMS SignedData profile
// based on RFC 5652, with definite-length encoding and DER signed attributes.
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
// establish PKIX trust; compose github.com/skarm/xmlsec/pki for chain, usage
// and revocation policy.
//
// [Limits] bounds bytes and collections; zero fields use the documented
// defaults. The package performs no implicit resource fetching and is not a
// general CMS/BER processor or certificate store.
package cms
