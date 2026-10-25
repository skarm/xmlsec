package xmlenc

import (
	"crypto"
	"errors"

	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/internal/lexicon"
)

const (
	// Namespace is the XML Encryption 1.0 namespace URI.
	Namespace = lexicon.NamespaceXMLEnc
	// Namespace11 is the XML Encryption 1.1 namespace URI.
	Namespace11 = lexicon.NamespaceXMLEnc11
	// SignatureNamespace is the XMLDSig namespace URI used by key information.
	SignatureNamespace = lexicon.NamespaceDSig
	// AES128GCM is the AES-128 GCM data encryption URI.
	AES128GCM = Namespace11 + "aes128-gcm"
	// AES192GCM is the AES-192 GCM data encryption URI.
	AES192GCM = Namespace11 + "aes192-gcm"
	// AES256GCM is the AES-256 GCM data encryption URI.
	AES256GCM = Namespace11 + "aes256-gcm"
	// AES128CBC is the legacy AES-128 CBC data encryption URI.
	AES128CBC = Namespace + "aes128-cbc"
	// AES192CBC is the optional legacy AES-192 CBC data encryption URI.
	AES192CBC = Namespace + "aes192-cbc"
	// AES256CBC is the legacy AES-256 CBC data encryption URI.
	AES256CBC = Namespace + "aes256-cbc"
	// TripleDESCBC is the legacy three-key TripleDES CBC data encryption URI.
	TripleDESCBC = Namespace + "tripledes-cbc"
	// TripleDESKeyWrap is the legacy CMS TripleDES Key Wrap URI.
	TripleDESKeyWrap = Namespace + "kw-tripledes"
	// AES128KeyWrap is the AES-128 Key Wrap URI.
	AES128KeyWrap = Namespace + "kw-aes128"
	// AES192KeyWrap is the AES-192 Key Wrap URI.
	AES192KeyWrap = Namespace + "kw-aes192"
	// AES256KeyWrap is the AES-256 Key Wrap URI.
	AES256KeyWrap = Namespace + "kw-aes256"
	// RSAOAEP is the XML Encryption 1.1 RSA-OAEP key transport URI.
	RSAOAEP = Namespace11 + "rsa-oaep"
	// RSAOAEP10 is the legacy XML Encryption RSA-OAEP URI with fixed MGF1-SHA1.
	RSAOAEP10 = Namespace + "rsa-oaep-mgf1p"
	// MGF1SHA1 is the MGF1-SHA1 mask-generation URI, requiring AllowLegacy.
	MGF1SHA1 = Namespace11 + "mgf1sha1"
	// MGF1SHA224 is the MGF1-SHA224 mask-generation URI.
	MGF1SHA224 = Namespace11 + "mgf1sha224"
	// MGF1SHA256 is the MGF1-SHA256 mask-generation URI.
	MGF1SHA256 = Namespace11 + "mgf1sha256"
	// MGF1SHA384 is the MGF1-SHA384 mask-generation URI.
	MGF1SHA384 = Namespace11 + "mgf1sha384"
	// MGF1SHA512 is the MGF1-SHA512 mask-generation URI.
	MGF1SHA512 = Namespace11 + "mgf1sha512"
	// SHA1 is the legacy SHA-1 digest URI, requiring AllowLegacy.
	SHA1 = lexicon.DigestSHA1
	// SHA224 is the SHA-224 digest algorithm URI.
	SHA224 = lexicon.DigestSHA224
	// SHA256 is the SHA-256 digest algorithm URI.
	SHA256 = lexicon.DigestSHA256
	// SHA384 is the SHA-384 digest algorithm URI.
	SHA384 = lexicon.DigestSHA384
	// SHA512 is the SHA-512 digest algorithm URI.
	SHA512 = lexicon.DigestSHA512
	// ElementType identifies plaintext representing one XML element.
	ElementType = Namespace + "Element"
	// ContentType identifies plaintext representing an XML element's content.
	ContentType = Namespace + "Content"
)

var (
	// ErrPolicy reports XML Encryption policy violation.
	ErrPolicy = errors.New("XML Encryption policy violation")
	// ErrFormat reports unsupported or malformed XML Encryption profile.
	ErrFormat = errors.New("unsupported or malformed XML Encryption profile")
	// ErrDecrypt reports XML Encryption decryption failed.
	ErrDecrypt = errors.New("XML Encryption decryption failed")
	// ErrResource reports a cipher or opt-in key-graph resource resolver/reader failure.
	ErrResource = errors.New("XML Encryption resource failure")
)

// Options selects the same data algorithm for encryption and decryption.
// Decryption rejects a different Algorithm in the XML, including another
// supported algorithm. Optional EncryptionMethod/KeySize must match the selected
// data key, KEK or RSA modulus size. The zero value selects AES256GCM and default limits.
type Options struct {
	// AllowLegacy explicitly permits CBC data encryption and TripleDES key wrap.
	// CBC plaintext is unauthenticated. Callers must establish any required
	// ciphertext integrity before decryption and keep legacy keys separate from
	// GCM keys. This flag changes no algorithm choice and grants no trust.
	// Selected legacy algorithms are rejected with crypto/fips140 enabled.
	// OAEP's SHA-1/legacy URI permission remains OAEPParameters.AllowLegacy.
	AllowLegacy bool
	// DataAlgorithm selects the expected data cipher; empty selects AES256GCM.
	// Decryption rejects ciphertext declaring a different algorithm.
	DataAlgorithm string
	// OAEP selects RSA-OAEP parameters. Nil uses SHA-256 and an empty label.
	// These parameters are rejected by direct-key and AES Key Wrap APIs.
	OAEP *OAEPParameters
	// External permits one exact application-selected CipherReference URI on
	// decryption. Nil denies external ciphertext; no implicit I/O is performed.
	External *ExternalCipherReference
	// MaxPlaintextBytes bounds plaintext bytes; default 8 MiB, maximum 32 MiB.
	MaxPlaintextBytes int
	// XMLLimits bounds decrypted XML; zero uses document defaults.
	XMLLimits document.Limits
}

// OAEPParameters selects the exact expected RSA-OAEP algorithm, hashes and label.
// Parameters are emitted explicitly, except the fixed MGF of RSAOAEP10.
// Omitted XML digest/MGF parameters mean SHA-1 under XMLENC; they are accepted
// only when the caller has explicitly selected the corresponding SHA-1 hash.
// No received parameter expands the caller's policy. SHA-1 and RSAOAEP10
// require AllowLegacy and are rejected when crypto/fips140 is enabled.
type OAEPParameters struct {
	// Algorithm selects RSAOAEP (default) or the legacy RSAOAEP10 URI.
	Algorithm string
	// Hash selects the digest; zero uses SHA-256. SHA-1 and SHA-2 are supported.
	Hash crypto.Hash
	// MGFHash selects the MGF1 hash; zero uses Hash for RSAOAEP and SHA-1 for
	// RSAOAEP10. RSAOAEP10 rejects an explicit hash other than SHA-1.
	MGFHash crypto.Hash
	// AllowLegacy explicitly permits SHA-1 and the RSAOAEP10 URI. It does not
	// change the selected parameters or permit alternative values on decryption.
	AllowLegacy bool
	// Label is the PSource byte string encoded in OAEPparams, bounded to 1024 bytes.
	// It must match the caller's expected value on decryption; it is not sender identity.
	Label []byte
}

// SymmetricOptions selects a direct data key supplied by the application.
// CBC requires Data.AllowLegacy and provides no authentication.
// The key must have the exact size selected by Data.DataAlgorithm. No EncryptedKey
// is generated or accepted, and no key is resolved from XML.
type SymmetricOptions struct {
	Data Options
	// KeyName supplies an optional untrusted KeyInfo hint, bounded to 1024 bytes.
	// When configured, decryption requires the same name. Empty requires no KeyInfo.
	KeyName string
}

// KeyWrapOptions selects the data algorithm and the algorithm of the explicitly
// supplied key-encryption key (KEK). An AES KEK must be exactly 16, 24 or 32 bytes,
// as selected by KeyAlgorithm; it is never inferred from the XML or key length.
// The zero value selects AES256GCM and AES256KeyWrap. TripleDESKeyWrap requires
// a 24-byte KEK, TripleDESCBC data and Data.AllowLegacy.
type KeyWrapOptions struct {
	Data Options
	// KeyAlgorithm defaults to AES256KeyWrap. The supplied key-encryption key
	// must match this algorithm's size; its length does not select the algorithm.
	KeyAlgorithm string
}
