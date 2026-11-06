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

const (
	tripleDESWrappedKeyBytes    = des.BlockSize + tripleDESKeyBytes + tripleDESWrapChecksumBytes
	tripleDESWrapChecksumBytes  = 8
	tripleDESWrapChecksumOffset = des.BlockSize + tripleDESKeyBytes
	tripleDESKeyBits            = tripleDESKeyBytes * keyOctetBits
)

const tripleDESWrapIV = "\x4a\xdd\xa2\x2c\x79\xe8\x21\x05"

func tripleDESWrapProfile(p profile, kek []byte) (profile, error) {
	// RFC3217 wraps a TripleDES CEK; wrapping other key types is optional.
	if !p.options.AllowLegacy || fips140.Enabled() || len(kek) != tripleDESKeyBytes || !p.data.tripleDES {
		return profile{}, ErrPolicy
	}

	block, err := des.NewTripleDESCipher(kek) // #nosec G405 -- XMLENC-required legacy wrap, explicit policy and FIPS gate.
	if err != nil {
		return profile{}, ErrPolicy
	}

	p.transport = keyTransport{
		algorithm: TripleDESKeyWrap, wrappedBytes: tripleDESWrappedKeyBytes, keyBits: tripleDESKeyBits,
		wrap: func(key []byte) ([]byte, error) { return wrapTripleDES(block, key) },
		unwrap: func(_ context.Context, wrapped []byte) ([]byte, error) {
			return unwrapTripleDES(block, wrapped)
		},
	}

	return p, nil
}

func oddDESParity(key []byte) {
	// DES stores odd parity in the low bit of each octet; the other bits carry key data.
	const (
		desParityBit   = 0x01
		desKeyDataMask = 0xfe
	)

	for i, b := range key {
		key[i] = b & desKeyDataMask
		if bits.OnesCount8(key[i])%2 == 0 {
			key[i] |= desParityBit
		}
	}
}

func wrapTripleDES(block cipher.Block, key []byte) ([]byte, error) {
	if len(key) != tripleDESKeyBytes {
		return nil, ErrPolicy
	}

	out := make([]byte, tripleDESWrappedKeyBytes)
	if _, err := io.ReadFull(rand.Reader, out[:des.BlockSize]); err != nil {
		return nil, err
	}

	copy(out[des.BlockSize:tripleDESWrapChecksumOffset], key)
	oddDESParity(out[des.BlockSize:tripleDESWrapChecksumOffset])
	checksum := sha1.Sum(out[des.BlockSize:tripleDESWrapChecksumOffset]) // #nosec G401 -- RFC3217 integrity checksum, not a signature.
	copy(out[tripleDESWrapChecksumOffset:], checksum[:tripleDESWrapChecksumBytes])
	cipher.NewCBCEncrypter(block, out[:des.BlockSize]).CryptBlocks(out[des.BlockSize:], out[des.BlockSize:])
	slices.Reverse(out)
	cipher.NewCBCEncrypter(block, []byte(tripleDESWrapIV)).CryptBlocks(out, out) // #nosec G407 -- RFC3217§3.1step8 mandates this second-pass IV.

	return out, nil
}

func unwrapTripleDES(block cipher.Block, wrapped []byte) ([]byte, error) {
	if len(wrapped) != tripleDESWrappedKeyBytes {
		return nil, ErrDecrypt
	}

	buffer := slices.Clone(wrapped)
	defer clear(buffer)

	cipher.NewCBCDecrypter(block, []byte(tripleDESWrapIV)).CryptBlocks(buffer, buffer)
	slices.Reverse(buffer)
	cipher.NewCBCDecrypter(block, buffer[:des.BlockSize]).CryptBlocks(buffer[des.BlockSize:], buffer[des.BlockSize:])
	checksum := sha1.Sum(buffer[des.BlockSize:tripleDESWrapChecksumOffset]) // #nosec G401 -- RFC3217 requires SHA-1.

	parity := 0
	for _, b := range buffer[des.BlockSize:tripleDESWrapChecksumOffset] {
		parity |= (bits.OnesCount8(b) + 1) % 2
	}

	if subtle.ConstantTimeCompare(checksum[:tripleDESWrapChecksumBytes], buffer[tripleDESWrapChecksumOffset:]) != 1 || parity != 0 {
		return nil, ErrDecrypt
	}

	return slices.Clone(buffer[des.BlockSize:tripleDESWrapChecksumOffset]), nil
}
