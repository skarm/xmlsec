package keys

import (
	"bytes"
	"context"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/subtle"
	"encoding/asn1"

	"github.com/skarm/xmlsec/internal/der"
)

// AlgorithmIdentifier has an OID and optional parameters. Key-structure and
// password-encryption parsers share these ASN.1 cardinalities.
const (
	algorithmIdentifierMinimumFields = 1
	algorithmIdentifierMaximumFields = 2
)

const (
	aes128KeyBytes        = 16
	aes192KeyBytes        = 24
	aes256KeyBytes        = 32
	defaultPBES2SaltBytes = 16
	// Caps chunks emitted by key/container exporters, in bytes.
	exportChunkBytes = 32 << 10
)

type pbes2Parameters struct {
	hash       crypto.Hash
	salt       []byte
	iv         []byte
	iterations int
	keyBytes   int
}

func algorithm(v asn1.RawValue) (asn1.ObjectIdentifier, asn1.RawValue, error) {
	f, err := der.Sequence(v, algorithmIdentifierMinimumFields, algorithmIdentifierMaximumFields)
	if err != nil {
		return nil, asn1.RawValue{}, ErrFormat
	}

	var oid asn1.ObjectIdentifier
	if !der.Is(f[0], asn1.ClassUniversal, asn1.TagOID, false) || der.Decode(f[0], &oid) != nil {
		return nil, asn1.RawValue{}, ErrFormat
	}

	if len(f) == algorithmIdentifierMinimumFields {
		return oid, asn1.RawValue{}, nil
	}

	return oid, f[1], nil
}

func hmacHash(v asn1.RawValue) (crypto.Hash, error) {
	return parseHMACHash(v, false)
}

func parseHMACHash(v asn1.RawValue, legacy bool) (crypto.Hash, error) {
	oid, param, err := algorithm(v)
	if err != nil {
		return 0, err
	}

	if len(param.FullBytes) > 0 && !der.Is(param, asn1.ClassUniversal, asn1.TagNull, false) {
		return 0, ErrFormat
	}

	switch {
	case oid.Equal(oidHMAC1()) && legacy:
		return crypto.SHA1, nil
	case oid.Equal(oidHMAC256()):
		return crypto.SHA256, nil
	case oid.Equal(oidHMAC384()):
		return crypto.SHA384, nil
	case oid.Equal(oidHMAC512()):
		return crypto.SHA512, nil
	}

	return 0, ErrPolicy
}

func hmacOID(h crypto.Hash) asn1.ObjectIdentifier {
	switch h {
	case crypto.SHA384:
		return oidHMAC384()
	case crypto.SHA512:
		return oidHMAC512()
	default:
		return oidHMAC256()
	}
}

func integer(v asn1.RawValue) (int, error) {
	var n int
	if !der.Is(v, asn1.ClassUniversal, asn1.TagInteger, false) || der.Decode(v, &n) != nil {
		return 0, ErrFormat
	}

	return n, nil
}

func parseKDF(v asn1.RawValue, expectedSize int, requiredSize bool) (pbes2Parameters, error) {
	// PBKDF2-params has two required and two optional fields.
	const maximumPBKDF2Fields = 4

	oid, params, err := algorithm(v)
	if err != nil {
		return pbes2Parameters{}, err
	}

	if !oid.Equal(oidPBKDF2()) {
		return pbes2Parameters{}, ErrPolicy
	}

	f, err := der.Sequence(params, 2, maximumPBKDF2Fields)
	if err != nil || !der.Is(f[0], asn1.ClassUniversal, asn1.TagOctetString, false) {
		return pbes2Parameters{}, ErrFormat
	}

	p := pbes2Parameters{salt: f[0].Bytes, keyBytes: expectedSize, hash: crypto.SHA1}
	if len(p.salt) < minimumSaltBytes || len(p.salt) > maximumSaltBytes {
		return p, ErrPolicy
	}

	p.iterations, err = integer(f[1])
	if err != nil {
		return p, err
	}

	at := 2
	if at < len(f) && der.Is(f[at], asn1.ClassUniversal, asn1.TagInteger, false) {
		n, err := integer(f[at])
		if err != nil || n < 1 {
			return p, ErrFormat
		}

		// PBES2 fixes the key size through its cipher. RFC 9879 only recommends
		// matching the MAC size; another explicitly encoded bounded size is valid.
		if n > maximumDerivedKeyBytes || !requiredSize && n != expectedSize {
			return p, ErrPolicy
		}

		p.keyBytes = n
		at++
	} else if requiredSize {
		return p, ErrFormat
	}

	if at < len(f) {
		p.hash, err = parseHMACHash(f[at], true)
		if err != nil {
			return p, err
		}

		at++
	}

	if at != len(f) {
		return p, ErrFormat
	}

	return p, nil
}

func parsePBES2(v asn1.RawValue) (pbes2Parameters, error) {
	const pbes2ParameterFields = 2 // key derivation and encryption scheme

	oid, params, err := algorithm(v)
	if err != nil {
		return pbes2Parameters{}, err
	}

	if !oid.Equal(oidPBES2()) {
		return pbes2Parameters{}, ErrPolicy
	}

	f, err := der.Sequence(params, pbes2ParameterFields, pbes2ParameterFields)
	if err != nil {
		return pbes2Parameters{}, ErrFormat
	}

	enc, iv, err := algorithm(f[1])
	if err != nil {
		return pbes2Parameters{}, err
	}

	var size int

	switch {
	case enc.Equal(oidAES128CBC()):
		size = aes128KeyBytes
	case enc.Equal(oidAES192CBC()):
		size = aes192KeyBytes
	case enc.Equal(oidAES256CBC()):
		size = aes256KeyBytes
	default:
		return pbes2Parameters{}, ErrPolicy
	}

	if !der.Is(iv, asn1.ClassUniversal, asn1.TagOctetString, false) || len(iv.Bytes) != aes.BlockSize {
		return pbes2Parameters{}, ErrFormat
	}

	p, err := parseKDF(f[0], size, false)
	if err != nil {
		return pbes2Parameters{}, err
	}

	p.iv = iv.Bytes

	return p, nil
}

func decryptPBES2(state *passwordState, algorithm asn1.RawValue, encrypted []byte, maximum int) ([]byte, error) {
	p, err := parsePBES2(algorithm)
	if err != nil {
		return nil, err
	}

	if len(encrypted) == 0 || len(encrypted)%aes.BlockSize != 0 {
		return nil, ErrFormat
	}

	if len(encrypted) > maximum && len(encrypted)-maximum > aes.BlockSize {
		return nil, ErrLimit
	}

	key, err := state.derive(p.hash, p.salt, p.iterations, p.keyBytes)
	if err != nil {
		return nil, err
	}
	defer clear(key)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, ErrPolicy
	}

	plain := make([]byte, len(encrypted))
	if err := cryptCBC(state.ctx, cipher.NewCBCDecrypter(block, p.iv), plain, encrypted); err != nil {
		clear(plain)
		return nil, err
	}

	padding := plain[len(plain)-1]
	paddingLen := int(padding)

	good := subtle.ConstantTimeLessOrEq(1, paddingLen) & subtle.ConstantTimeLessOrEq(paddingLen, aes.BlockSize)
	for i := range aes.BlockSize {
		inPadding := subtle.ConstantTimeLessOrEq(i+1, paddingLen)
		good &= 1 - inPadding | subtle.ConstantTimeByteEq(plain[len(plain)-1-i], padding)
	}

	if err := state.ctx.Err(); err != nil {
		clear(plain)
		return nil, err
	}

	if good != 1 {
		clear(plain)
		return nil, ErrDecrypt
	}

	if len(plain)-paddingLen > maximum {
		clear(plain)
		return nil, ErrLimit
	}

	return plain[:len(plain)-paddingLen], nil
}

func kdfEncoding(salt []byte, iterations, size int, hash crypto.Hash) []byte {
	params := der.Seq(der.Octets(salt), der.Int(iterations), der.Int(size), der.Seq(der.OID(hmacOID(hash)), []byte{asn1.TagNull, 0}))
	return der.Seq(der.OID(oidPBKDF2()), params)
}

func encryptPBES2(state *passwordState, plain []byte, options EncryptionOptions) ([]byte, []byte, error) {
	return encryptPBES2Parts(state, derParts{plain}, options)
}

func encryptPBES2Parts(state *passwordState, plain derParts, options EncryptionOptions) ([]byte, []byte, error) {
	size := plain.size()
	if size > state.limits.MaxContainerBytes || size > int(^uint(0)>>1)-aes.BlockSize {
		return nil, nil, ErrLimit
	}

	salt, iv := make([]byte, defaultPBES2SaltBytes), make([]byte, aes.BlockSize)
	if _, err := rand.Read(salt); err != nil {
		return nil, nil, err
	}

	if _, err := rand.Read(iv); err != nil {
		return nil, nil, err
	}

	key, err := state.derive(options.Hash, salt, options.Iterations, options.KeyBits/bitsPerOctet)
	if err != nil {
		return nil, nil, err
	}
	defer clear(key)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, ErrPolicy
	}

	padding := aes.BlockSize - size%aes.BlockSize

	out := make([]byte, size+padding)
	if _, err := plain.write(state.ctx, bytes.NewBuffer(out[:0])); err != nil {
		clear(out)
		return nil, nil, err
	}

	for i := size; i < len(out); i++ {
		out[i] = byte(padding)
	}

	if err := cryptCBC(state.ctx, cipher.NewCBCEncrypter(block, iv), out, out); err != nil {
		clear(out)
		return nil, nil, err
	}

	oid := oidAES256CBC()

	switch options.KeyBits {
	case aes128KeyBits:
		oid = oidAES128CBC()
	case aes192KeyBits:
		oid = oidAES192CBC()
	}

	params := der.Seq(kdfEncoding(salt, options.Iterations, options.KeyBits/bitsPerOctet, options.Hash), der.Seq(der.OID(oid), der.Octets(iv)))

	return der.Seq(der.OID(oidPBES2()), params), out, nil
}

func cryptCBC(ctx context.Context, mode cipher.BlockMode, dst, src []byte) error {
	for len(src) > 0 {
		if err := ctx.Err(); err != nil {
			return err
		}

		size := min(len(src), exportChunkBytes)
		mode.CryptBlocks(dst[:size], src[:size])
		dst, src = dst[size:], src[size:]
	}

	return ctx.Err()
}
