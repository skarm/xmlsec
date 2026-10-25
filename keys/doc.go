// Package keys imports and exports bounded key material without filesystem or
// network access. It separates encoding/password protection from application
// key-strength policy, certificate trust and identity.
//
// # Plain keys and certificates
//
// [ParsePrivate] accepts one unencrypted PKCS#8, RSA PKCS#1 or EC SEC1 PEM/DER
// key and returns a crypto.Signer. [ParsePublic] accepts SPKI, RSA PKCS#1 or an
// X.509 certificate as a public-key pin. [ParseCertificate] and [ParseCRL]
// return owned X.509 objects without validating their signatures, lifetimes or
// trust paths. Every operation accepts [Limits]; zero fields select
// [DefaultLimits]. Encoded input and decoded key, certificate, CRL and
// container budgets are independent. Ambiguous PEM, trailing DER and
// unsupported private-key structures are rejected.
//
// # Password-protected material
//
// [ParseEncryptedPrivate] and [MarshalEncryptedPrivate] handle PBES2 encrypted
// PKCS#8 with PBKDF2-HMAC-SHA-2 and AES-CBC. This standalone storage format has
// no integrity tag; it is unsuitable as an authenticated transport.
// [ParseEncryptedPrivateWithOptions] explicitly enables import-only SHA-1
// PBKDF2, including the RFC 8018 default PRF, and selected BER wrappers. SHA-1
// requires AllowLegacy and is rejected with the FIPS backend enabled. Export
// stays SHA-2/AES. [ParsePrivateWithOptions] enables the same unencrypted PKCS#8
// wrappers; embedded keys, algorithms and attributes retain strict DER rules.
//
// [ParsePKCS12] and [MarshalPKCS12] handle one private key and its matching
// certificate, plus optional untrusted extra certificates. PKCS#12 requires a
// MAC, verified before bag decryption. Export defaults to RFC 9879 PBMAC1;
// ClassicMAC selects traditional SHA-2 integrity for older readers. A valid
// container MAC does not authenticate a sender or validate a certificate chain.
// [ParsePKCS12WithOptions] explicitly enables selected BER wrappers, constructed
// data/ciphertext/certificate OCTET STRINGs and nested SafeContents. Algorithms,
// attributes and private keys keep their primitive/structural DER
// checks. PBMAC1 also accepts an explicitly encoded outer iterations DEFAULT1
// placeholder, as required by the published RFC 9879 vectors; this does not
// enable general BER in MAC parameters. Authentication always uses
// the original AuthenticatedSafe octets, before normalization. An exact SHA-256
// certificate selector chooses one identity only after all contents pass.
// [ParsePKCS12Identities] imports every unambiguous key/certificate pair for
// application selection. Neither API selects identities by received names.
//
// # Password and ownership policy
//
// [Limits] bounds each KDF and aggregate work across the entire operation. Use
// MinIterations to enforce an application storage policy; the import minimum is
// a compatibility limit, not a storage recommendation. Passwords are explicit
// byte slices with format-specific rules. PKCS#5 passwords are exact octets,
// including embedded NUL or non-UTF-8 bytes. PKCS#12 accepts UTF-8 content without
// normalization: classic integrity encodes BMP characters plus a terminator;
// PBMAC1 uses the supplied UTF-8 bytes without adding one. The APIs do not strip
// a BOM or truncate embedded NUL. Classic integrity rejects non-BMP characters.
// Explicit PKCS#12 AllowLegacy imports traditional SHA-1 MACs and SHA-1 PBKDF2,
// while RFC 9879 PBMAC1 retains SHA-2 policy. Non-default PBMAC1 MAC-key sizes
// require AllowNonDefaultMACKeyLength and must contain 16..64 bytes. By default,
// the key must match the MAC output size. Salt sizes are bounded to 8..64 bytes.
// Cancellation is checked during
// KDF work, CBC chunks and container MAC input. Export requires a nonempty
// password and an exportable software key. Container output remains one identity
// in DER. Containers without a MAC and unsupported bag types are rejected.
//
// # Input and storage
//
// Byte inputs are borrowed during parsing and must stay unchanged until the
// call returns. Returned keys, certificates and containers own their mutable
// data. Certificate and CRL objects retain owned DER; a public key extracted
// from a certificate does not retain the enclosing certificate DER.
// Callers control subsequent mutation and storage.
// Certificate objects can be shared among identities in one collection import;
// callers must coordinate mutation across that returned collection.
//
// [WriteEncryptedPrivate] and [WritePKCS12] write DER headers and payload
// segments directly to a caller-owned writer. Their Marshal counterparts
// collect this same output. Export still retains bounded key/certificate
// snapshots and ciphertext; it is not a constant-memory password-container
// pipeline. PKCS#12 import retains decrypted safe contents temporarily and
// independent certificates in its result.
package keys
