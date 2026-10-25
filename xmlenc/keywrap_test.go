package xmlenc //nolint:testpackage // Checks private AES key-wrap primitives against RFC vectors.

import (
	"bytes"
	"context"
	"crypto"
	"crypto/aes"
	"crypto/fips140"
	"encoding/hex"
	"errors"
	"strconv"
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

// TestConcatBitDigest checks literal NIST CAVS 11.0 bit-oriented SHAVS vectors,
// downloaded from https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/secure-hashing.
// Cases exercise every partial octet and both sides of SHA's padding/block boundary.
func TestConcatBitDigest(t *testing.T) {
	for _, tc := range []struct {
		algorithm       crypto.Hash
		length          int
		message, digest string
	}{
		{crypto.SHA1, 0, "00", "da39a3ee5e6b4b0d3255bfef95601890afd80709"},
		{crypto.SHA1, 1, "00", "bb6b3e18f0115b57925241676f5b1ae88747b08a"},
		{crypto.SHA1, 2, "40", "ec6b39952e1a3ec3ab3507185cf756181c84bbe2"},
		{crypto.SHA1, 3, "80", "a37596ec13a0d2f9e6c0b8b96f9112823aa6d961"},
		{crypto.SHA1, 4, "d0", "ba582f5967911beb91599684c2eb2baeefb78da7"},
		{crypto.SHA1, 5, "48", "3320540d1c28b96ddd03eee1b186a8f2ae883fbe"},
		{crypto.SHA1, 6, "20", "b372bd120957ebc3392cd060e131699d1fee6059"},
		{crypto.SHA1, 7, "44", "04f31807151181ad0db278a1660526b0aeef64c2"},
		{crypto.SHA1, 8, "5d", "4ff447b8ef42ca51fa6fb287bed8d40f49be58f1"},
		{crypto.SHA1, 447, "de11fa659cc16ad64de598bf7403be07b14d1b7de62f3b0f98247a3c98cdc4cce2449ebec5ae6a82440fe668bd63f759c8eaa5c562c366dc", "14c764e1369c26aa6a92e75384ea6394986d706b"},
		{crypto.SHA1, 448, "06024501b3a1b703e79089f132ad71b99a7d3322971ec25e627da8e26fc9a9753827a3873da7b9c54976b0eaf65699d8734cb1e78598857d", "8d405e3332002c4b645721fa38a78c2f99796e17"},
		{crypto.SHA1, 449, "e41de51ef465e8c8209f3a16aed159db3303bc07f145c2cb62f4e9fe153a40c0b9d41f5d7818157486362258f9be26b6db629a787dfe7eea00", "5b9800a8c20f91575446c707f78ea09d35d708ac"},
		{crypto.SHA1, 511, "99afae9df7a6cf61760a455cb11433b58445e21d29fc0804a1484b0d56fb01c0fe003a80c2ee00bca0dcdd690e789eafe05357e26b7fa7b5eb5c3daa22af9bcc", "cc58d7a6dd5b77d61d069bf3ecd0c9a7ae01098d"},
		{crypto.SHA1, 512, "a8a47716a69df1bbc0753da2e99f0b8a73785d4382e2966dc12fd482534280170df0245ee2ac7cf09e64cfc9d8a67f942107e02a82c5465526ab62d95335ceb5", "82e198367b5d64fa71782913ea6afbb4674bb912"},
		{crypto.SHA1, 611, "d372b4bf97daa3be77e0d78c123c7bb39dde10c82824c83f2250308320391247da419a167686b7320a5dc49b5cfc686eec76bb7034edaaeb2e029cb91791569e739c1bdb518418ffd07f0001e0", "c60a02fffa45deccb075e386be3aa9313c2df4f2"},
		{crypto.SHA1, 710, "9c270d3bc0f24cd817a15e8999a305cf4d2eac420229b28e404806bc7e79f4b3957f3efe75dc6fcf17f56c44b3714cea32e26980e6a7b7fd791155d423c4627620601218626101b78344c75afdeccc989d435e59352400e190", "2674630c2dbc2d6ef7dde647f292f5169501ecff"},
		{crypto.SHA1, 809, "94cc2d9a9417ad399a9b9c4242970913c4748d7418568dc95ef1b98d7c9ed8fb09adc80e6afdc0ac3acbd91ef0c8cdc4bb6efe07b193ba8e293fbdb565bbf73b75ea903a57dc2a5d63a1664de75ba96c0e9720c606de014561861424bcce73a59f2b8e07a580", "0aadec36139d9e80073bd815c4464d6e9375bbf5"},
		{crypto.SHA256, 0, "00", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
		{crypto.SHA256, 1, "00", "bd4f9e98beb68c6ead3243b1b4c7fed75fa4feaab1f84795cbd8a98676a2a375"},
		{crypto.SHA256, 2, "80", "18f331f626210ff9bad6995d8cff6e891adba50eb2fdbddcaa921221cdc333ae"},
		{crypto.SHA256, 3, "60", "1f7794d4b0b67d3a6edcd17aba2144a95828032f7943ed26bf0c7c7628945f48"},
		{crypto.SHA256, 4, "f0", "f30f6f1aa8675bcc33733b26baef25b9766f13256f0dba02f42f89d69db538f8"},
		{crypto.SHA256, 5, "98", "8f136783ea6f000dccc4295d4db99b648f1c8f483b27248db103ba7cd567dbba"},
		{crypto.SHA256, 6, "40", "5ef0224f79737bda30562831152184b939cc43fcd40d09f4945e081a39c6d542"},
		{crypto.SHA256, 7, "dc", "83e848e33f2aec12959a5de8232989ee09e7841f9f031147a651d286e8c7218e"},
		{crypto.SHA256, 8, "e5", "ab61ba11a38b007ff98baa3ab20e2a584e15269fd428db3c857e2a2d568b5725"},
		{crypto.SHA256, 447, "86f15b8b677b7655f358a2c7fd5785bc84d31e079ed859b6af88e198debd36fccaf0ffbc785aa17a9158102aca14e6d0a362b28b54e892d2", "eaec4af4f0632711ae6d78bcadb50eb53aee0d2e65c906cd903349750ea71c92"},
		{crypto.SHA256, 448, "3488a0d1c0998edf4c16f35f0293e1a73134bc20efc2f8f702fd241501342852b614cbe5c7be781f951c415a6574242cbe3d8de011321d26", "75fd02880ba7d64381f6391811ec64c6852e9f579f11e47f097438089d7ed905"},
		{crypto.SHA256, 449, "a42a253ec8dcf6562228421ff84d1cf5899f58eaf1da93b84cb674fa1ebc309bf357548e422ebfbf97b1ed4af1f27cec69b7e8b615cd9a0900", "271d9e654addefaa497e2a304f2dde96d303b43eddf3612bb451b4024f92ff70"},
		{crypto.SHA256, 511, "4de3ca0f86b9075bda56a5655272094c9cce8373a67581e06c4203e20ea24ff7259be6ec570eb646293991e1157fded7dd6c8fa31ef4538728fb0c2b0d1b8386", "db591c088de9d7fe8c4adae45ea845b2c9df1c5b386aafe702b0b84067ba9f69"},
		{crypto.SHA256, 512, "f6bb5d59b0fa9de0828b115303bf94aa987361ccdde48d0246c5d5ab068f9a322f192a3e1b6841280cc8d0b20f1bfcf626726a9ca5daba50dd795173f8d95c11", "f757fe6ec7239f7e9f6accade3990a15e74e435a932c48ecccfa70a66c3fdb9d"},
		{crypto.SHA256, 611, "58af737f436c07a56f4f5fd18a6822a30174e4eeb1f6ec69bf893ba8c474ca4b2e7f1276e305d181274b0cf0bf1050a556653e5421bf4738bf4bb3046381e81d34fce906f4891d1be07e5283c0", "0c71d6b38aab0a3db8b65a3317fa50190cad982c4e0cd8cf6694579c9cd821b3"},
		{crypto.SHA256, 710, "90d15fb5e724a3705c14263179d5d972e73bd342857dfd2fb73a0f6801b9bb23d475273da7d9a1204a488fea7760a4ccab805aaf33879c1e8adfc260e2bbc3e4019ca6e34e1a3a402ce107b386fa8426ab4c8b5f5d6209e024", "8ac449d4191b083926110a486d2ad2112f6416627c1ae1a636d26181e92939ad"},
		{crypto.SHA256, 809, "8219618b7728ac89237705ecf84012cc7c80293c4cf171d86139449d9361d8fe5b881f33ddd9ebd526ba56a8b24661b831fedba78abb854521e8736156edb5df4eee370bf5b6e62d43ee145ebf931e9942a74c15fe26f8d2be3bf3726fb4244be0b472bac680", "b857f827ec3a28a9997600f545cd8e189eb75185c9c8c8e0d046c9247e3c109e"},
	} {
		t.Run(tc.algorithm.String()+"/"+strconv.Itoa(tc.length), func(t *testing.T) {
			data, err := hex.DecodeString(tc.message)
			if err != nil {
				t.Fatal(err)
			}
			data = data[:(tc.length+7)/8]
			got, err := concatDigest(t.Context(), tc.algorithm, data, tc.length)
			if err != nil || hex.EncodeToString(got) != tc.digest {
				t.Fatalf("digest=%x want=%s err=%v", got, tc.digest, err)
			}
		})
	}
}

func TestConcatKDF(t *testing.T) {
	// OpenSSL 3 SSKDF -keylen 48, with explicit SHA-256/SHA-1, hexsecret
	// 736563726574 and hexinfo 616c676f726974686d70617274792d7570617274792d76.
	for _, tc := range []struct {
		hash crypto.Hash
		want string
	}{
		{crypto.SHA256, "decd092d8d48598e451375077940a69c91f27e53faa451bfd3eef6d0dec2a7808854c826bc0a5a4373592ab97ae6d5d8"},
		{crypto.SHA1, "91e31b35f5d607eaa125899b5dbb098c4d04051e0b9c5de2d97c120dedbd5a394a315a3448406628efb1110ea7f88cdc"},
	} {
		t.Run(tc.hash.String(), func(t *testing.T) {
			parameters := ConcatKDFParameters{Hash: tc.hash, AllowLegacy: true, AlgorithmID: append([]byte{0}, []byte("algorithm")...), PartyUInfo: append([]byte{0}, []byte("party-u")...), PartyVInfo: append([]byte{0}, []byte("party-v")...)}
			got, err := DeriveConcatKey(t.Context(), []byte("secret"), 384, parameters)
			if tc.hash == crypto.SHA1 && fips140.Enabled() {
				if got != nil || !errors.Is(err, ErrPolicy) {
					t.Fatal(got, err)
				}
				return
			}
			if err != nil || hex.EncodeToString(got) != tc.want {
				t.Fatalf("derived=%x want=%s err=%v", got, tc.want, err)
			}
			shortened, err := DeriveConcatKey(t.Context(), []byte("secret"), 379, parameters)
			if err != nil || !bytes.Equal(shortened[:47], got[:47]) || shortened[47] != got[47]&0xe0 {
				t.Fatal("partial output", shortened, err)
			}
		})
	}
	t.Run("unpad fields before concatenation", func(t *testing.T) {
		// XMLENC example 25: 00000000 || 11011 || 11010 = 00000000 11011110 10.
		split := ConcatKDFParameters{AlgorithmID: []byte{0, 0}, PartyUInfo: []byte{3, 0xd8}, PartyVInfo: []byte{3, 0xd0}}
		got, err := DeriveConcatKey(t.Context(), []byte("secret"), 256, split)
		if fips140.Enabled() {
			if got != nil || !errors.Is(err, ErrPolicy) {
				t.Fatal(got, err)
			}
			return
		}
		if err != nil {
			t.Fatal(err)
		}
		joined := ConcatKDFParameters{AlgorithmID: []byte{6, 0, 0xde, 0x80}}
		want, err := DeriveConcatKey(t.Context(), []byte("secret"), 256, joined)
		if err != nil || !bytes.Equal(got, want) {
			t.Fatalf("split=%x joined=%x err=%v", got, want, err)
		}
		wrong, err := DeriveConcatKey(t.Context(), []byte("secret"), 256, ConcatKDFParameters{AlgorithmID: []byte{0, 0, 0xd8, 0xd0}})
		if err != nil || bytes.Equal(got, wrong) {
			t.Fatal("used padded octets", err)
		}
		// Input snapshots are retained even when unaligned fields cross octets.
		if !bytes.Equal(split.PartyUInfo, []byte{3, 0xd8}) || !bytes.Equal(split.PartyVInfo, []byte{3, 0xd0}) {
			t.Fatal("input mutated")
		}
	})
	for _, tc := range []struct {
		name       string
		secret     []byte
		bits       int
		parameters ConcatKDFParameters
	}{
		{name: "empty secret", bits: 128},
		{name: "secret limit", secret: make([]byte, 1025), bits: 128},
		{name: "zero bits", secret: []byte{1}},
		{name: "negative bits", secret: []byte{1}, bits: -1},
		{name: "output limit", secret: []byte{1}, bits: 8193},
		{name: "hash selection", secret: []byte{1}, bits: 128, parameters: ConcatKDFParameters{Hash: crypto.SHA512}},
		{name: "legacy opt in", secret: []byte{1}, bits: 128, parameters: ConcatKDFParameters{Hash: crypto.SHA1}},
		{name: "invalid pad count", secret: []byte{1}, bits: 128, parameters: ConcatKDFParameters{AlgorithmID: []byte{8, 0}}},
		{name: "missing padded octet", secret: []byte{1}, bits: 128, parameters: ConcatKDFParameters{PartyUInfo: []byte{1}}},
		{name: "nonzero padding", secret: []byte{1}, bits: 128, parameters: ConcatKDFParameters{PartyVInfo: []byte{3, 0xd9}}},
		{name: "field limit", secret: []byte{1}, bits: 128, parameters: ConcatKDFParameters{SuppPubInfo: make([]byte, 4098)}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got, err := DeriveConcatKey(t.Context(), tc.secret, tc.bits, tc.parameters); got != nil || !errors.Is(err, ErrPolicy) {
				t.Fatal(got, err)
			}
		})
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if got, err := DeriveConcatKey(ctx, []byte{1}, 128, ConcatKDFParameters{}); got != nil || !errors.Is(err, context.Canceled) {
		t.Fatal(got, err)
	}
	if got, err := DeriveConcatKey(nil, []byte{1}, 128, ConcatKDFParameters{}); got != nil || !errors.Is(err, ErrPolicy) {
		t.Fatal(got, err)
	}
}
