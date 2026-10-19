// Package xmlenc encrypts and authenticates bounded XML Encryption 1.1
// envelopes with AES-GCM. Callers choose the data algorithm, key transport and
// key material; received XML does not select another algorithm or initiate
// implicit I/O.
//
// # Keys and algorithms
//
// [Options] defaults to AES-256-GCM with RSA-OAEP using SHA-256 for both OAEP
// and MGF1. Explicit options select other supported AES/SHA-2 sizes and a
// bounded OAEP label. KeyWrap APIs use an application-supplied RFC 3394 AES
// key-encryption key. WithKey APIs use a direct AES data key and emit no
// EncryptedKey. Direct-key callers must manage distribution and the per-key
// encryption bound documented by [EncryptBytesWithKey].
//
// # Select what to encrypt
//
// Bytes APIs preserve arbitrary bytes. Document APIs encrypt the complete root
// element, excluding document-level comments and processing instructions.
// [EncryptElement] replaces one selected element; [EncryptContent] replaces all
// children of the selected parent while leaving that parent's attributes
// visible. Element and Content plaintext uses UTF-8/NFC; non-NFC serialization
// is rejected without normalization. NFC validation accepts normalized long
// combining sequences without inserting joiners or changing the authenticated
// plaintext.
//
// Decryption authenticates before parsing restored XML and returns no plaintext
// on failure. Element and Content replacement returns a new complete snapshot
// and its exact handles. Other encrypted siblings remain untouched; recursive
// decryption is not performed.
//
// # External ciphertext and trust
//
// [ExternalizeCiphertext] returns a new envelope and owned ciphertext for the
// application to store. Reading CipherReference requires an exact absolute URI
// and a bounded [CipherResolver], with raw bytes or one Base64 transform.
// Wrapped keys remain inline. Resolvers and readers must honor cancellation.
//
// GCM authentication does not establish sender identity or signature coverage;
// anyone with a recipient's public key can create an RSA-transport envelope.
// CBC, RSA PKCS#1 v1.5 and key agreement are outside the supported profile.
//
// # Storage requirements
//
// AES-GCM uses cipher.AEAD and requires a complete bounded message. Plaintext
// is returned only after tag verification. Unknown-length external ciphertext
// is collected in chunks and joined for GCM; the chunks and contiguous buffer
// coexist temporarily. XML operations retain complete source and result trees;
// reader/writer wrappers would not make this cryptographic core incremental.
package xmlenc
