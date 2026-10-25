// RFC 3394 round functions adapted from github.com/knroy/go-xmlsec/xenc/keywrap.go
// at 038f602c093dcefd3c66f0022a243a9b67deb4ef.
// Copyright (c) 2026 Komol Nath Roy. MIT License.
//
// SPDX-License-Identifier: MIT
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

package xmlenc

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/subtle"
	"encoding/binary"
)

const keyWrapIV uint64 = 0xa6a6a6a6a6a6a6a6

// keyWrapProfile selects an authorized key-wrapping algorithm, validates the
// key-encryption key size and binds wrapping functions to the normalized
// data-encryption profile.
func keyWrapProfile(ctx context.Context, kek []byte, options KeyWrapOptions) (profile, error) {
	if options.Data.OAEP != nil {
		return profile{}, ErrPolicy
	}

	p, err := normalize(ctx, options.Data)
	if err != nil {
		return profile{}, err
	}

	algorithm := options.KeyAlgorithm
	if algorithm == "" {
		algorithm = AES256KeyWrap
	}

	if algorithm == TripleDESKeyWrap {
		return tripleDESWrapProfile(p, kek)
	}

	var kekBytes int

	switch algorithm {
	case AES128KeyWrap:
		kekBytes = 16
	case AES192KeyWrap:
		kekBytes = 24
	case AES256KeyWrap:
		kekBytes = 32
	default:
		return profile{}, ErrPolicy
	}

	if len(kek) != kekBytes {
		return profile{}, ErrPolicy
	}

	block, err := aes.NewCipher(kek)
	if err != nil {
		return profile{}, ErrPolicy
	}

	keyBytes := p.keyBytes
	p.transport = keyTransport{
		algorithm: algorithm, wrappedBytes: keyBytes + 8, keyBits: kekBytes * 8,
		wrap: func(key []byte) ([]byte, error) { return wrapKey(block, key) },
		unwrap: func(_ context.Context, wrapped []byte) ([]byte, error) {
			return unwrapKey(block, wrapped, keyBytes)
		},
	}

	return p, nil
}

func sessionKeySize(size int) bool { return size == 16 || size == 24 || size == 32 }

// wrapKey applies RFC 3394 wrapping to a supported session-key size using the
// supplied AES block. It returns newly allocated wrapped bytes.
func wrapKey(block cipher.Block, key []byte) ([]byte, error) {
	if !sessionKeySize(len(key)) {
		return nil, ErrPolicy
	}

	out := make([]byte, len(key)+8)
	copy(out[8:], key)

	a := keyWrapIV

	var buffer [aes.BlockSize]byte
	defer clear(buffer[:])

	var counter uint64

	for range 6 {
		for offset := 8; offset < len(out); offset += 8 {
			counter++

			binary.BigEndian.PutUint64(buffer[:8], a)
			copy(buffer[8:], out[offset:offset+8])
			block.Encrypt(buffer[:], buffer[:])
			a = binary.BigEndian.Uint64(buffer[:8]) ^ counter
			copy(out[offset:offset+8], buffer[8:])
		}
	}

	binary.BigEndian.PutUint64(out[:8], a)

	return out, nil
}

// unwrapKey validates the expected wrapped session-key size before RFC 3394
// unwrapping. A failed integrity check clears recovered key bytes and returns
// ErrDecrypt.
func unwrapKey(block cipher.Block, wrapped []byte, keyBytes int) ([]byte, error) {
	// Check the expected session-key size before allocation or AES operations.
	// General RFC 3394 inputs can be much larger than the bounded data-key profile.
	if !sessionKeySize(keyBytes) || len(wrapped) != keyBytes+8 {
		return nil, ErrDecrypt
	}

	out := make([]byte, keyBytes)
	copy(out, wrapped[8:])
	a := binary.BigEndian.Uint64(wrapped[:8])

	var buffer [aes.BlockSize]byte
	defer clear(buffer[:])

	counter := uint64(len(out) / 8 * 6)
	for range 6 {
		for offset := len(out) - 8; offset >= 0; offset -= 8 {
			binary.BigEndian.PutUint64(buffer[:8], a^counter)
			counter--

			copy(buffer[8:], out[offset:offset+8])
			block.Decrypt(buffer[:], buffer[:])
			a = binary.BigEndian.Uint64(buffer[:8])
			copy(out[offset:offset+8], buffer[8:])
		}
	}

	binary.BigEndian.PutUint64(buffer[:8], a)
	binary.BigEndian.PutUint64(buffer[8:], keyWrapIV)

	if subtle.ConstantTimeCompare(buffer[:8], buffer[8:]) != 1 {
		clear(out)
		return nil, ErrDecrypt
	}

	return out, nil
}
