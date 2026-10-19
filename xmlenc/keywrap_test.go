package xmlenc //nolint:testpackage // Checks private AES key-wrap primitives against RFC vectors.

import (
	"bytes"
	"crypto/aes"
	"encoding/hex"
	"errors"
	"testing"
)

// TestRFC3394Vectors checks the published vectors from RFC 3394 sections 4.1–4.6.
// Both directions must match the exact octets.
func TestRFC3394Vectors(t *testing.T) {
	const (
		key128 = "00112233445566778899aabbccddeeff"
		key192 = key128 + "0001020304050607"
		key256 = key192 + "08090a0b0c0d0e0f"
		kek128 = "000102030405060708090a0b0c0d0e0f"
		kek192 = kek128 + "1011121314151617"
		kek256 = kek192 + "18191a1b1c1d1e1f"
	)
	for _, tc := range []struct{ section, kek, key, wrapped string }{
		{"4.1", kek128, key128, "1fa68b0a8112b447aef34bd8fb5a7b829d3e862371d2cfe5"},
		{"4.2", kek192, key128, "96778b25ae6ca435f92b5b97c050aed2468ab8a17ad84e5d"},
		{"4.3", kek256, key128, "64e8c3f9ce0f5ba263e9777905818a2a93c8191e7d6e8ae7"},
		{"4.4", kek192, key192, "031d33264e15d33268f24ec260743edce1c6c7ddee725a936ba814915c6762d2"},
		{"4.5", kek256, key192, "a8f9bc1612c68b3ff6e6f4fbe30e71e4769c8b80a32cb8958cd5d17d6b254da1"},
		{"4.6", kek256, key256, "28c9f404c4b810f4cbccb35cfb87f8263f5786e2d80ed326cbc7f0e71a99f43bfb988b9b7a02dd21"},
	} {
		t.Run(tc.section, func(t *testing.T) { testRFC3394VectorsCase(t, &tc) })
	}
}

func testRFC3394VectorsCase(t *testing.T, tc *struct {
	section string
	kek     string
	key     string
	wrapped string
},
) {
	decode := func(text string) []byte {
		t.Helper()

		b, err := hex.DecodeString(text)
		if err != nil {
			t.Fatal(err)
		}

		return b
	}
	kek, key, want := decode(tc.kek), decode(tc.key), decode(tc.wrapped)
	keyBefore, wrappedBefore := bytes.Clone(key), bytes.Clone(want)

	block, err := aes.NewCipher(kek)
	if err != nil {
		t.Fatal(err)
	}

	wrapped, err := wrapKey(block, key)
	if err != nil || !bytes.Equal(wrapped, want) {
		t.Fatalf("wrap: got %x, want %x, err %v", wrapped, want, err)
	}

	plain, err := unwrapKey(block, want, len(key))
	if err != nil || !bytes.Equal(plain, key) {
		t.Fatalf("unwrap: got %x, want %x, err %v", plain, key, err)
	}

	if !bytes.Equal(key, keyBefore) || !bytes.Equal(want, wrappedBefore) {
		t.Fatal("input mutated")
	}

	for i := range want {
		for bit := byte(1); bit != 0; bit <<= 1 {
			bad := bytes.Clone(want)

			bad[i] ^= bit
			if out, err := unwrapKey(block, bad, len(key)); out != nil || !errors.Is(err, ErrDecrypt) {
				t.Fatalf("accepted changed wrapped key at byte %d bit %x", i, bit)
			}
		}
	}
}

func TestKeyWrapLengthRejectedBeforeAES(t *testing.T) {
	for _, size := range []int{-1, 0, 8, 16, 24, 32, 40, 1 << 20} {
		wrapped := make([]byte, size+1)
		if out, err := unwrapKey(forbiddenCipher{}, wrapped, 32); out != nil || !errors.Is(err, ErrDecrypt) {
			t.Fatalf("wrapped length %d: %v", len(wrapped), err)
		}
	}

	for _, size := range []int{-1, 0, 8, 17, 40, 1 << 20} {
		if out, err := unwrapKey(forbiddenCipher{}, make([]byte, 40), size); out != nil || !errors.Is(err, ErrDecrypt) {
			t.Fatalf("declared key length %d: %v", size, err)
		}
	}
}

type forbiddenCipher struct{}

func (forbiddenCipher) BlockSize() int { return aes.BlockSize }

func (forbiddenCipher) Encrypt(_, _ []byte) { panic("unexpected AES operation") }

func (forbiddenCipher) Decrypt(_, _ []byte) { panic("unexpected AES operation") }
