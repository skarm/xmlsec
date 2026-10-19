package keys

import (
	"bytes"
	"context"
	"crypto"
	"crypto/hmac"
	_ "crypto/sha256"
	_ "crypto/sha512"
	"encoding/asn1"
	"encoding/binary"
	"errors"
)

var (
	// ErrPolicy reports unsupported password protection or invalid caller options.
	ErrPolicy = errors.New("key protection policy violation")
	// ErrDecrypt reports a wrong password or corrupted encrypted key material.
	// It does not distinguish a padding failure from an invalid decrypted key.
	ErrDecrypt = errors.New("key material decryption failed")
)

// EncryptionOptions selects PBES2 with PBKDF2-HMAC-SHA-2 and AES-CBC for key
// storage. Fresh 16-byte salts and IVs are generated for every encryption. Standalone
// encrypted PKCS#8 has no MAC; this is a storage format, not an authenticated
// transport or a network decryption service. XML Encryption still uses AES-GCM.
type EncryptionOptions struct {
	// KeyBits selects AES-128, AES-192 or AES-256; zero selects 256.
	KeyBits int
	// Hash selects PBKDF2-HMAC-SHA-256, SHA-384 or SHA-512; zero selects SHA-256.
	Hash crypto.Hash
	// Iterations is the PBKDF2 count per KDF; zero selects 600000.
	Iterations int
}

type passwordState struct {
	ctx       context.Context
	password  []byte
	limits    Limits
	remaining int
}

func newPasswordState(ctx context.Context, password []byte, limits Limits) (*passwordState, error) {
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

	if len(password) > limits.MaxPasswordBytes {
		return nil, ErrLimit
	}

	return &passwordState{ctx: ctx, password: bytes.Clone(password), limits: limits, remaining: limits.MaxKDFWork}, nil
}

func (p *passwordState) close() { clear(p.password) }
func (p *passwordState) charge(iterations, blocks int) error {
	if err := p.ctx.Err(); err != nil {
		return err
	}

	if iterations < p.limits.MinIterations || iterations > p.limits.MaxIterations || blocks < 1 || blocks > p.remaining/iterations {
		return ErrLimit
	}

	p.remaining -= iterations * blocks

	return nil
}

func (p *passwordState) derive(hash crypto.Hash, salt []byte, iterations, size int) ([]byte, error) {
	if !sha2(hash) || size < 1 || size > 64 || len(salt) < 8 || len(salt) > 64 {
		return nil, ErrPolicy
	}

	blocks := (size + hash.Size() - 1) / hash.Size()
	if err := p.charge(iterations, blocks); err != nil {
		return nil, err
	}

	prf := hmac.New(hash.New, p.password)
	out := make([]byte, blocks*hash.Size())

	u, t := make([]byte, hash.Size()), make([]byte, hash.Size())
	defer clear(u)
	defer clear(t)

	var counter [4]byte
	for block := 1; block <= blocks; block++ {
		binary.BigEndian.PutUint32(counter[:], uint32(block))
		prf.Reset()
		prf.Write(salt)
		prf.Write(counter[:])
		u = prf.Sum(u[:0])
		copy(t, u)

		for i := 1; i < iterations; i++ {
			if i%1024 == 0 {
				if err := p.ctx.Err(); err != nil {
					clear(out)
					return nil, err
				}
			}

			prf.Reset()
			prf.Write(u)

			u = prf.Sum(u[:0])
			for j := range t {
				t[j] ^= u[j]
			}
		}

		copy(out[(block-1)*hash.Size():], t)
	}

	if err := p.ctx.Err(); err != nil {
		clear(out)
		return nil, err
	}

	clear(out[size:])

	return out[:size:size], nil
}

func sha2(h crypto.Hash) bool { return h == crypto.SHA256 || h == crypto.SHA384 || h == crypto.SHA512 }

func normalizeEncryption(options EncryptionOptions) (EncryptionOptions, error) {
	if options.KeyBits == 0 {
		options.KeyBits = 256
	}

	if options.Hash == 0 {
		options.Hash = crypto.SHA256
	}

	if options.Iterations == 0 {
		options.Iterations = 600000
	}

	if (options.KeyBits != 128 && options.KeyBits != 192 && options.KeyBits != 256) || !sha2(options.Hash) || options.Iterations < 1 {
		return EncryptionOptions{}, ErrPolicy
	}

	return options, nil
}

func oidPBES2() asn1.ObjectIdentifier { return asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 13} }

func oidPBKDF2() asn1.ObjectIdentifier { return asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 12} }

func oidPBMAC1() asn1.ObjectIdentifier { return asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 14} }

func oidHMAC256() asn1.ObjectIdentifier { return asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 9} }

func oidHMAC384() asn1.ObjectIdentifier { return asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 10} }

func oidHMAC512() asn1.ObjectIdentifier { return asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 11} }

func oidAES128CBC() asn1.ObjectIdentifier {
	return asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 2}
}

func oidAES192CBC() asn1.ObjectIdentifier {
	return asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 22}
}

func oidAES256CBC() asn1.ObjectIdentifier {
	return asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 42}
}
