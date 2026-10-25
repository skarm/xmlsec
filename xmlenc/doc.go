// Package xmlenc implements bounded XML Encryption 1.1 envelopes.
// AES-GCM authenticates ciphertext; explicit legacy CBC provides confidentiality
// without authentication. Callers choose the data algorithm, key transport and
// key material; received XML does not select another algorithm or initiate
// implicit I/O.
//
// # Keys and algorithms
//
// [Options] defaults to AES-256-GCM with RSA-OAEP using SHA-256 for both OAEP
// and MGF1. Explicit options select other supported AES/SHA-2 sizes, independent
// digest/MGF1 hashes and a bounded OAEP label. [OAEPParameters.AllowLegacy]
// separately permits SHA-1 and the XMLENC 1.0 URI with fixed MGF1-SHA1. It never
// changes the selected parameters or permits wire-driven algorithm negotiation.
// Legacy OAEP is rejected with crypto/fips140 enabled; this is not a claim that
// the entire XMLENC profile can execute in FIPS-only mode.
// KeyWrap APIs use an application-supplied RFC 3394 AES key-encryption key
// or explicitly permitted RFC 3217 TripleDES wrapping of a TripleDES data key.
// WithKey APIs use a direct symmetric data key and emit no
// EncryptedKey. Direct-key callers must manage distribution and the per-key
// encryption bound documented by [EncryptBytesWithKey].
// ECDH-ES APIs use an explicitly supplied recipient and ConcatKDF, with P-256
// mandatory and P-384/P-521 also supported. Agreement derives wrapping material;
// it does not authenticate the sender. [DeriveConcatKey] also exposes bounded
// standalone derivation with XMLENC padding-count-prefixed bitstring fields.
//
// # Select what to encrypt
//
// Bytes APIs preserve arbitrary bytes. Document APIs encrypt the complete root
// element, excluding document-level comments and processing instructions.
// [EncryptElement] replaces one selected element; [EncryptContent] replaces all
// children of the selected parent while leaving that parent's attributes
// visible. Element and Content plaintext uses UTF-8/NFC; non-NFC serialization
// is rejected without normalization. NFC validation accepts normalized long
// combining sequences without inserting joiners or changing the encrypted
// plaintext.
//
// GCM decryption authenticates before parsing restored XML. Legacy CBC checks
// its padding but has no message authentication; a successful CBC decrypt does
// not establish integrity. No plaintext is returned on a reported failure.
// Element and Content replacement returns a new complete snapshot
// and its exact handles. Other encrypted siblings remain untouched; recursive
// decryption is not performed.
//
// # External ciphertext and trust
//
// [ExternalizeCiphertext] returns a new envelope and owned ciphertext for the
// application to store. Reading CipherReference requires an exact absolute URI
// and a bounded [CipherResolver], with raw bytes or one Base64 transform.
// The strict entry points keep wrapped keys inline. Explicit key-graph entry
// points additionally support nested, retrieved, derived and external key
// relationships under [KeyGraphOptions]. External key resources and ciphertext
// have separate permissions. References and key names grant no I/O permission
// or trust. Resolvers and readers must honor cancellation.
//
// GCM authentication does not establish sender identity or signature coverage;
// anyone with a recipient's public key can create an RSA-transport envelope.
// AES-CBC and TripleDES-CBC require Options.AllowLegacy and are denied in
// FIPS mode. Callers must establish any required ciphertext integrity before
// decryption, using an application protocol that binds integrity to the encryption
// key. Equal error strings and dummy-key processing do not prove resistance to
// decryption oracles. Keep CBC and GCM keys separate. Legacy permission never
// permits wire-selected algorithms or changes the GCM default.
// RSA PKCS#1 v1.5, finite-field DH, PBKDF2 and EXI are not implemented.
//
// # Storage requirements
//
// Encryption and decryption require a complete bounded message. GCM plaintext
// is returned only after tag verification. Unknown-length external ciphertext
// is collected in chunks and joined; the chunks and contiguous buffer coexist
// temporarily. XML operations retain complete source and result trees;
// reader/writer wrappers would not make this cryptographic core incremental.
package xmlenc
