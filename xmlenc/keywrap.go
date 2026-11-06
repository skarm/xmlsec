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

const (
	// Size of one RFC 3394 register, in bytes; also the wrapped-key overhead.
	keyWrapBlockBytes = 8
	keyWrapRounds     = 6
)

const keyWrapIV uint64 = 0xa6a6a6a6a6a6a6a6

// keyWrapProfile selects an authorized key-wrapping algorithm, validates the
// key-encryption key size and binds wrapping functions to the normalized
// data-encryption profile.
func keyWrapProfile(ctx context.Context, kek []byte, options KeyWrapOptions) (profile, error) {
	if options.Data.OAEP != nil || options.Data.KeyTransportAlgorithm != "" {
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
		kekBytes = aes128KeyBytes
	case AES192KeyWrap:
		kekBytes = aes192KeyBytes
	case AES256KeyWrap:
		kekBytes = aes256KeyBytes
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
		algorithm: algorithm, wrappedBytes: keyBytes + keyWrapBlockBytes, keyBits: kekBytes * keyOctetBits,
		wrap: func(key []byte) ([]byte, error) { return wrapKey(block, key) },
		unwrap: func(_ context.Context, wrapped []byte) ([]byte, error) {
			return unwrapKey(block, wrapped, keyBytes)
		},
	}

	return p, nil
}

func sessionKeySize(size int) bool {
	return size == aes128KeyBytes || size == aes192KeyBytes || size == aes256KeyBytes
}

// wrapKey applies RFC 3394 wrapping to a supported session-key size using the
// supplied AES block. It returns newly allocated wrapped bytes.
func wrapKey(block cipher.Block, key []byte) ([]byte, error) {
	if !sessionKeySize(len(key)) {
		return nil, ErrPolicy
	}

	out := make([]byte, len(key)+keyWrapBlockBytes)
	copy(out[keyWrapBlockBytes:], key)

	a := keyWrapIV

	var buffer [aes.BlockSize]byte
	defer clear(buffer[:])

	var counter uint64

	for range keyWrapRounds {
		for offset := keyWrapBlockBytes; offset < len(out); offset += keyWrapBlockBytes {
			counter++

			binary.BigEndian.PutUint64(buffer[:keyWrapBlockBytes], a)
			copy(buffer[keyWrapBlockBytes:], out[offset:offset+keyWrapBlockBytes])
			block.Encrypt(buffer[:], buffer[:])
			a = binary.BigEndian.Uint64(buffer[:keyWrapBlockBytes]) ^ counter
			copy(out[offset:offset+keyWrapBlockBytes], buffer[keyWrapBlockBytes:])
		}
	}

	binary.BigEndian.PutUint64(out[:keyWrapBlockBytes], a)

	return out, nil
}

// unwrapKey validates the expected wrapped session-key size before RFC 3394
// unwrapping. A failed integrity check clears recovered key bytes and returns
// ErrDecrypt.
func unwrapKey(block cipher.Block, wrapped []byte, keyBytes int) ([]byte, error) {
	// Check the expected session-key size before allocation or AES operations.
	// General RFC 3394 inputs can be much larger than the bounded data-key profile.
	if !sessionKeySize(keyBytes) || len(wrapped) != keyBytes+keyWrapBlockBytes {
		return nil, ErrDecrypt
	}

	out := make([]byte, keyBytes)
	copy(out, wrapped[keyWrapBlockBytes:])
	a := binary.BigEndian.Uint64(wrapped[:keyWrapBlockBytes])

	var buffer [aes.BlockSize]byte
	defer clear(buffer[:])

	counter := uint64(len(out) / keyWrapBlockBytes * keyWrapRounds)
	for range keyWrapRounds {
		for offset := len(out) - keyWrapBlockBytes; offset >= 0; offset -= keyWrapBlockBytes {
			binary.BigEndian.PutUint64(buffer[:keyWrapBlockBytes], a^counter)
			counter--

			copy(buffer[keyWrapBlockBytes:], out[offset:offset+keyWrapBlockBytes])
			block.Decrypt(buffer[:], buffer[:])
			a = binary.BigEndian.Uint64(buffer[:keyWrapBlockBytes])
			copy(out[offset:offset+keyWrapBlockBytes], buffer[keyWrapBlockBytes:])
		}
	}

	binary.BigEndian.PutUint64(buffer[:keyWrapBlockBytes], a)
	binary.BigEndian.PutUint64(buffer[keyWrapBlockBytes:], keyWrapIV)

	if subtle.ConstantTimeCompare(buffer[:keyWrapBlockBytes], buffer[keyWrapBlockBytes:]) != 1 {
		clear(out)
		return nil, ErrDecrypt
	}

	return out, nil
}
