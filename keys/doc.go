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
//
// [ParsePKCS12] and [MarshalPKCS12] handle one private key and its matching
// certificate, plus optional untrusted extra certificates. PKCS#12 requires a
// MAC, verified before bag decryption. Export defaults to RFC 9879 PBMAC1;
// ClassicMAC selects traditional SHA-2 integrity for older readers. A valid
// container MAC does not authenticate a sender or validate a certificate chain.
//
// # Password and ownership policy
//
// [Limits] bounds each KDF and aggregate work across the entire operation. Use
// MinIterations to enforce an application storage policy; the import minimum is
// a compatibility limit, not a storage recommendation. Passwords are explicit
// byte slices with format-specific rules, and cancellation is checked during
// KDF work, CBC chunks and container MAC input. Export requires a nonempty
// password and an exportable software key. Legacy password algorithms, BER,
// multiple PKCS#12 identities and containers without a MAC are unsupported.
//
// # Input and storage
//
// Byte inputs are borrowed during parsing and must stay unchanged until the
// call returns. Returned keys, certificates and containers own their mutable
// data. Certificate and CRL objects retain owned DER; a public key extracted
// from a certificate does not retain the enclosing certificate DER.
// Callers control subsequent mutation and storage.
//
// [WriteEncryptedPrivate] and [WritePKCS12] write DER headers and payload
// segments directly to a caller-owned writer. Their Marshal counterparts
// collect this same output. Export still retains bounded key/certificate
// snapshots and ciphertext; it is not a constant-memory password-container
// pipeline. PKCS#12 import retains decrypted safe contents temporarily and
// independent certificates in its result.
package keys
