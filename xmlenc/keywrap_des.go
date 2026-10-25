package xmlenc

import (
	"context"
	"crypto/cipher"
	"crypto/des" // #nosec G502 -- Required XMLENC legacy key wrap, explicit policy only.
	"crypto/fips140"
	"crypto/rand"
	"crypto/sha1" // #nosec G505 -- RFC3217 requires this integrity checksum.
	"crypto/subtle"
	"io"
	"math/bits"
	"slices"
)

const tripleDESWrapIV = "\x4a\xdd\xa2\x2c\x79\xe8\x21\x05"

func tripleDESWrapProfile(p profile, kek []byte) (profile, error) {
	// RFC3217 wraps a TripleDES CEK; wrapping other key types is optional.
	if !p.options.AllowLegacy || fips140.Enabled() || len(kek) != 24 || !p.data.tripleDES {
		return profile{}, ErrPolicy
	}

	block, err := des.NewTripleDESCipher(kek) // #nosec G405 -- XMLENC-required legacy wrap, explicit policy and FIPS gate.
	if err != nil {
		return profile{}, ErrPolicy
	}

	p.transport = keyTransport{
		algorithm: TripleDESKeyWrap, wrappedBytes: 40, keyBits: 192,
		wrap: func(key []byte) ([]byte, error) { return wrapTripleDES(block, key) },
		unwrap: func(_ context.Context, wrapped []byte) ([]byte, error) {
			return unwrapTripleDES(block, wrapped)
		},
	}

	return p, nil
}

func oddDESParity(key []byte) {
	for i, b := range key {
		key[i] = b & 0xfe
		if bits.OnesCount8(key[i])%2 == 0 {
			key[i] |= 1
		}
	}
}

func wrapTripleDES(block cipher.Block, key []byte) ([]byte, error) {
	if len(key) != 24 {
		return nil, ErrPolicy
	}

	out := make([]byte, 40)
	if _, err := io.ReadFull(rand.Reader, out[:des.BlockSize]); err != nil {
		return nil, err
	}

	copy(out[8:32], key)
	oddDESParity(out[8:32])
	checksum := sha1.Sum(out[8:32]) // #nosec G401 -- RFC3217 integrity checksum, not a signature.
	copy(out[32:], checksum[:8])
	cipher.NewCBCEncrypter(block, out[:8]).CryptBlocks(out[8:], out[8:])
	slices.Reverse(out)
	cipher.NewCBCEncrypter(block, []byte(tripleDESWrapIV)).CryptBlocks(out, out) // #nosec G407 -- RFC3217§3.1step8 mandates this second-pass IV.

	return out, nil
}

func unwrapTripleDES(block cipher.Block, wrapped []byte) ([]byte, error) {
	if len(wrapped) != 40 {
		return nil, ErrDecrypt
	}

	buffer := slices.Clone(wrapped)
	defer clear(buffer)

	cipher.NewCBCDecrypter(block, []byte(tripleDESWrapIV)).CryptBlocks(buffer, buffer)
	slices.Reverse(buffer)
	cipher.NewCBCDecrypter(block, buffer[:8]).CryptBlocks(buffer[8:], buffer[8:])
	checksum := sha1.Sum(buffer[8:32]) // #nosec G401 -- RFC3217 requires SHA-1.

	parity := 0
	for _, b := range buffer[8:32] {
		parity |= (bits.OnesCount8(b) + 1) % 2
	}

	if subtle.ConstantTimeCompare(checksum[:8], buffer[32:]) != 1 || parity != 0 {
		return nil, ErrDecrypt
	}

	return slices.Clone(buffer[8:32]), nil
}
