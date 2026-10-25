package keys

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"io"
	"math/big"

	"github.com/skarm/xmlsec/internal/der"
	"github.com/skarm/xmlsec/internal/ecdsakey"
	"github.com/skarm/xmlsec/internal/nilcheck"
)

// PrivateParseOptions explicitly enables selected PKCS#8 input forms.
// Traditional PKCS#1 and SEC1 encodings always remain strict DER.
type PrivateParseOptions struct {
	// AllowBER permits PKCS#8 SEQUENCE and privateKey OCTET STRING BER wrappers.
	// Algorithms, attributes and the encoded private-key payload remain strict DER.
	AllowBER bool
}

// EncryptedPrivateParseOptions explicitly enables compatibility during import.
// Export policy and the default strict DER/SHA-2 profile are unchanged.
type EncryptedPrivateParseOptions struct {
	// AllowLegacy permits PBKDF2-HMAC-SHA-1, including an omitted default PRF.
	// It is unavailable when the FIPS backend is enabled.
	AllowLegacy bool
	// AllowBER permits outer EncryptedPrivateKeyInfo and inner PrivateKeyInfo
	// BER wrappers and constructed OCTET STRINGs. Algorithms, attributes and
	// the encoded private-key payload remain strict DER.
	AllowBER bool
}

// ParsePrivateWithOptions parses one unencrypted private key with explicit
// PKCS#8 wrapper compatibility. It preserves the ownership and component limits
// of ParsePrivate, adds cancellation, and leaves input unchanged.
func ParsePrivateWithOptions(ctx context.Context, data []byte, options PrivateParseOptions, limits Limits) (crypto.Signer, error) {
	if ctx == nil {
		return nil, ErrPolicy
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	limits, err := normalizeLimits(limits)
	if err != nil {
		return nil, err
	}

	decoded, err := privateMaterial(ctx, data, limits.MaxKeyBytes, limits, options.AllowBER)
	if err != nil {
		return nil, err
	}
	defer decoded.clear()

	if options.AllowBER && (decoded.label == "" || decoded.label == "PRIVATE KEY") {
		// An unlabelled traditional key is already a strict DER format. Detect
		// only PrivateKeyInfo's AlgorithmIdentifier in the second field.
		normalized, err := normalizePrivateBER(ctx, decoded.der, limits.MaxKeyBytes, limits, false)
		if err != nil {
			return nil, err
		}
		defer clear(normalized)

		decoded.der = normalized
	}

	key, err := parsePrivateDER(decoded.label, decoded.der, limits)
	if err == nil {
		err = ctx.Err()
	}

	if err != nil {
		return nil, err
	}

	return key, nil
}

// ParseEncryptedPrivate decrypts one PEM ENCRYPTED PRIVATE KEY or DER
// EncryptedPrivateKeyInfo using explicit password bytes. PBES2/PBKDF2 with
// HMAC-SHA-256/384/512 and AES-128/192/256-CBC are accepted. Use
// ParseEncryptedPrivateWithOptions for explicit SHA-1/BER compatibility.
// The KDF is bounded and cancellable. Inputs remain unchanged, and temporary
// key/plaintext buffers are cleared. PKCS#8 has no ciphertext authentication.
func ParseEncryptedPrivate(ctx context.Context, data, password []byte, limits Limits) (crypto.Signer, error) {
	return ParseEncryptedPrivateWithOptions(ctx, data, password, EncryptedPrivateParseOptions{}, limits)
}

// ParseEncryptedPrivateWithOptions imports encrypted PKCS#8 with explicit
// compatibility choices. Passwords are exact octets: no UTF-8 validation,
// normalization, NUL termination or BOM handling is applied. Resource and
// iteration limits apply equally to all enabled forms and algorithms.
func ParseEncryptedPrivateWithOptions(ctx context.Context, data, password []byte, options EncryptedPrivateParseOptions, limits Limits) (crypto.Signer, error) {
	state, err := newPasswordState(ctx, password, limits)
	if err != nil {
		return nil, err
	}
	defer state.close()

	state.allowLegacy, state.allowBER = options.AllowLegacy, options.AllowBER

	decoded, err := privateMaterial(state.ctx, data, state.limits.MaxContainerBytes, state.limits, options.AllowBER)
	if err != nil {
		return nil, err
	}
	defer decoded.clear()

	if decoded.label != "" && decoded.label != "ENCRYPTED PRIVATE KEY" {
		return nil, ErrFormat
	}

	return decryptPrivateInfo(state, decoded.der)
}

// Framing is shared with strict DER import. Only an explicit BER option defers
// the structural scan to the schema-specific bounded wrapper normalizer.
func privateMaterial(ctx context.Context, data []byte, maximum int, limits Limits, allowBER bool) (decodedMaterial, error) {
	if !allowBER {
		return material(ctx, data, maximum, limits)
	}

	if len(data) > limits.MaxInputBytes {
		return decodedMaterial{}, ErrLimit
	}

	trimmed := bytes.TrimSpace(data)
	if bytes.HasPrefix(trimmed, []byte("-----BEGIN ")) {
		return decodePEM(ctx, trimmed, maximum)
	}

	if len(data) > maximum {
		return decodedMaterial{}, ErrLimit
	}

	return decodedMaterial{der: data}, nil
}

func decryptPrivateInfo(state *passwordState, raw []byte) (crypto.Signer, error) {
	if state.allowBER {
		normalized, err := normalizePrivateBER(state.ctx, raw, state.limits.MaxContainerBytes, state.limits, true)
		if err != nil {
			return nil, err
		}
		defer clear(normalized)

		raw = normalized
	}

	v, err := readDER(raw, state.limits.MaxContainerBytes, state.limits)
	if err != nil {
		return nil, err
	}

	f, err := der.Sequence(v, 2, 2)
	if err != nil || !der.Is(f[1], 0, asn1.TagOctetString, false) {
		return nil, ErrFormat
	}

	plain, err := decryptPBES2(state, f[0], f[1].Bytes, state.limits.MaxKeyBytes)
	if err != nil {
		return nil, err
	}
	defer clear(plain[:cap(plain)])

	return parseDecryptedPrivate(state, plain)
}

func parseDecryptedPrivate(state *passwordState, plain []byte) (crypto.Signer, error) {
	if state.allowBER {
		normalized, err := normalizePrivateBER(state.ctx, plain, state.limits.MaxKeyBytes, state.limits, false)
		if err != nil {
			if errors.Is(err, ErrLimit) || state.ctx.Err() != nil {
				return nil, err
			}

			return nil, ErrDecrypt
		}
		defer clear(normalized)

		plain = normalized
	}

	// Do not enable PEM, PKCS#1 or SEC1 parsing inside an encrypted PKCS#8 object.
	v, err := readDER(plain, state.limits.MaxKeyBytes, state.limits)
	if err != nil {
		if errors.Is(err, ErrLimit) {
			return nil, err
		}

		return nil, ErrDecrypt
	}

	if _, err := privateKeyInfoFields(v); err != nil {
		return nil, ErrDecrypt
	}

	key, err := parsePrivateDER("PRIVATE KEY", plain, state.limits)
	if err != nil {
		if !errors.Is(err, ErrLimit) {
			return nil, ErrDecrypt
		}

		return nil, err
	}

	if err := state.ctx.Err(); err != nil {
		return nil, err
	}

	return key, nil
}

// MarshalEncryptedPrivate encodes an exportable private key as DER encrypted
// PKCS#8. It uses fresh salt/IV and explicit SHA-2/AES PBES2 parameters; zero
// options select AES-256/SHA-256 with 600000 PBKDF2 iterations. Password must be
// nonempty. Opaque signers cannot be exported. The result may be PEM encoded by
// the application with label ENCRYPTED PRIVATE KEY. RSA exports obey the
// supplied component and prime-count limits and do not modify caller CRT state.
// Invalid key components are rejected before KDF work. It performs no I/O.
func MarshalEncryptedPrivate(ctx context.Context, key crypto.Signer, password []byte, options EncryptionOptions, limits Limits) ([]byte, error) {
	parts, err := prepareEncryptedPrivate(ctx, key, password, options, limits)
	if err != nil {
		return nil, err
	}

	return parts.bytes(ctx)
}

// WriteEncryptedPrivate writes encrypted PKCS#8 DER to dst. Encryption retains
// bounded key/plaintext and ciphertext storage; nested DER is emitted separately.
// Limits and KDF work are checked before output. It leaves dst open and may
// return a byte count with partial output after a write or cancellation error.
func WriteEncryptedPrivate(ctx context.Context, dst io.Writer, key crypto.Signer, password []byte, options EncryptionOptions, limits Limits) (int64, error) {
	if nilcheck.IsNil(dst) {
		return 0, ErrPolicy
	}

	parts, err := prepareEncryptedPrivate(ctx, key, password, options, limits)
	if err != nil {
		return 0, err
	}

	return parts.write(ctx, dst)
}

func privateEncoding(key crypto.Signer, limits Limits) ([]byte, crypto.Signer, error) {
	switch r := key.(type) {
	case *rsa.PrivateKey:
		if r == nil {
			return nil, nil, ErrPolicy
		}

		// x509 marshaling calls Precompute, which may mutate the supplied RSA
		// key. Snapshot its integers without copying shared CRT state.
		if len(r.Primes) < 2 {
			return nil, nil, ErrPolicy
		}

		if err := validateRSAPrivateParameters(r, limits); err != nil {
			return nil, nil, err
		}

		copyKey := &rsa.PrivateKey{N: new(big.Int).Set(r.N), E: r.E, D: new(big.Int).Set(r.D)}
		for _, prime := range r.Primes {
			copyKey.Primes = append(copyKey.Primes, new(big.Int).Set(prime))
		}

		if err := copyKey.Validate(); err != nil {
			return nil, nil, ErrFormat
		}

		key = copyKey
	case *ecdsa.PrivateKey:
		owned, err := copyECDSAPrivateKey(r)
		if err != nil {
			return nil, nil, err
		}

		key = owned
	case ed25519.PrivateKey:
		if r == nil {
			return nil, nil, ErrPolicy
		}

		if len(r) != ed25519.PrivateKeySize {
			return nil, nil, ErrFormat
		}

		derived := ed25519.NewKeyFromSeed(r[:ed25519.SeedSize])
		defer clear(derived)

		if !derived.Equal(r) {
			return nil, nil, ErrFormat
		}
	default:
		return nil, nil, ErrPolicy
	}

	raw, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, ErrFormat
	}

	if len(raw) > limits.MaxKeyBytes {
		clear(raw)
		return nil, nil, ErrLimit
	}

	if err := privateBudget(raw, limits); err != nil {
		clear(raw)
		return nil, nil, err
	}

	parseLimits := limits
	parseLimits.MaxInputBytes = limits.MaxKeyBytes

	parsed, err := ParsePrivate(raw, parseLimits)
	if err != nil {
		clear(raw)
		return nil, nil, err
	}

	return raw, parsed, nil
}

func copyECDSAPrivateKey(key *ecdsa.PrivateKey) (*ecdsa.PrivateKey, error) {
	if key == nil {
		return nil, ErrPolicy
	}

	if key.Curve == nil {
		return nil, ErrFormat
	}

	if key.Curve != elliptic.P224() && key.Curve != elliptic.P256() && key.Curve != elliptic.P384() && key.Curve != elliptic.P521() {
		return nil, ErrPolicy
	}

	raw, err := ecdsakey.PrivateBytes(key)
	if err != nil {
		return nil, ErrFormat
	}
	defer clear(raw)

	owned, err := ecdsa.ParseRawPrivateKey(key.Curve, raw)
	if err != nil || !key.PublicKey.Equal(owned.Public()) {
		return nil, ErrFormat
	}

	return owned, nil
}

func prepareEncryptedPrivate(ctx context.Context, key crypto.Signer, password []byte, options EncryptionOptions, limits Limits) (derParts, error) {
	if len(password) == 0 {
		return nil, ErrPolicy
	}

	options, err := normalizeEncryption(options)
	if err != nil {
		return nil, err
	}

	state, err := newPasswordState(ctx, password, limits)
	if err != nil {
		return nil, err
	}
	defer state.close()

	raw, _, err := privateEncoding(key, state.limits)
	if err != nil {
		return nil, err
	}
	defer clear(raw)

	alg, encrypted, err := encryptPBES2(state, raw, options)
	if err != nil {
		return nil, err
	}

	out := frameDER(0x30, derParts{alg}, frameDER(4, derParts{encrypted}))
	if out.size() > state.limits.MaxContainerBytes {
		return nil, ErrLimit
	}

	if err := state.ctx.Err(); err != nil {
		return nil, err
	}

	return out, nil
}

func validateRSAPrivateParameters(r *rsa.PrivateKey, limits Limits) error {
	if len(r.Primes) > limits.MaxRSAPrimes {
		return ErrLimit
	}

	for _, n := range append([]*big.Int{r.N, r.D}, r.Primes...) {
		if n == nil || n.Sign() <= 0 {
			return ErrFormat
		}

		if n.BitLen() > limits.MaxRSABits {
			return ErrLimit
		}
	}

	return nil
}
