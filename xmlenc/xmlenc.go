package xmlenc

import (
	"crypto"
	"errors"

	"github.com/skarm/xmlsec/document"
)

const (
	// Namespace is the XML Encryption 1.0 namespace URI.
	Namespace = "http://www.w3.org/2001/04/xmlenc#"
	// Namespace11 is the XML Encryption 1.1 namespace URI.
	Namespace11 = "http://www.w3.org/2009/xmlenc11#"
	// SignatureNamespace is the XMLDSig namespace URI used by key information.
	SignatureNamespace = "http://www.w3.org/2000/09/xmldsig#"
	// AES128GCM is the AES-128 GCM data encryption URI.
	AES128GCM = Namespace11 + "aes128-gcm"
	// AES192GCM is the AES-192 GCM data encryption URI.
	AES192GCM = Namespace11 + "aes192-gcm"
	// AES256GCM is the AES-256 GCM data encryption URI.
	AES256GCM = Namespace11 + "aes256-gcm"
	// AES128KeyWrap is the AES-128 Key Wrap URI.
	AES128KeyWrap = Namespace + "kw-aes128"
	// AES192KeyWrap is the AES-192 Key Wrap URI.
	AES192KeyWrap = Namespace + "kw-aes192"
	// AES256KeyWrap is the AES-256 Key Wrap URI.
	AES256KeyWrap = Namespace + "kw-aes256"
	// RSAOAEP is the XML Encryption 1.1 RSA-OAEP key transport URI.
	RSAOAEP = Namespace11 + "rsa-oaep"
	// MGF1SHA256 is the MGF1-SHA256 mask-generation URI.
	MGF1SHA256 = Namespace11 + "mgf1sha256"
	// MGF1SHA384 is the MGF1-SHA384 mask-generation URI.
	MGF1SHA384 = Namespace11 + "mgf1sha384"
	// MGF1SHA512 is the MGF1-SHA512 mask-generation URI.
	MGF1SHA512 = Namespace11 + "mgf1sha512"
	// SHA256 is the SHA-256 digest algorithm URI.
	SHA256 = Namespace + "sha256"
	// SHA384 is the SHA-384 digest algorithm URI.
	SHA384 = "http://www.w3.org/2001/04/xmldsig-more#sha384"
	// SHA512 is the SHA-512 digest algorithm URI.
	SHA512 = Namespace + "sha512"
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
	// ErrResource reports a CipherReference resolver or reader failure.
	ErrResource = errors.New("XML Encryption resource failure")
)

// Options selects the same data algorithm for encryption and decryption.
// Decryption rejects a different Algorithm in the XML, including another
// supported algorithm. The zero value selects AES256GCM and default limits.
type Options struct {
	// DataAlgorithm selects the expected AES-GCM algorithm; empty selects AES256GCM.
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

// OAEPParameters selects the same SHA-2 hash for the OAEP digest and MGF1.
// The digest is emitted explicitly; omitted XML parameters mean SHA-1 under
// XMLENC and are rejected by this profile. SHA-256, SHA-384 and SHA-512 are
// supported. Different digest/MGF hashes and legacy RSA-OAEP URIs are unsupported.
type OAEPParameters struct {
	// Hash selects the digest and MGF1 hash; zero uses SHA-256.
	Hash crypto.Hash
	// Label is the PSource byte string encoded in OAEPparams, bounded to 1024 bytes.
	// It must match the caller's expected value on decryption; it is not sender identity.
	Label []byte
}

// SymmetricOptions selects a direct AES-GCM data key supplied by the application.
// The key must have the exact size selected by Data.DataAlgorithm. No EncryptedKey
// is generated or accepted, and no key is resolved from XML.
type SymmetricOptions struct {
	Data Options
	// KeyName supplies an optional untrusted KeyInfo hint, bounded to 1024 bytes.
	// When configured, decryption requires the same name. Empty requires no KeyInfo.
	KeyName string
}

// KeyWrapOptions selects the data algorithm and the algorithm of the explicitly
// supplied key-encryption key (KEK). The KEK must be exactly 16, 24 or 32 bytes,
// as selected by KeyAlgorithm; it is never inferred from the XML or key length.
// The zero value selects AES256GCM and AES256KeyWrap.
type KeyWrapOptions struct {
	Data Options
	// KeyAlgorithm defaults to AES256KeyWrap. The supplied key-encryption key
	// must match this algorithm's size; its length does not select the algorithm.
	KeyAlgorithm string
}
