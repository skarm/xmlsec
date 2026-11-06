package xmlenc

import (
	"context"
	"crypto"
	"crypto/fips140"
	"crypto/sha1" // #nosec G505 -- XMLENC requires SHA-1 only under explicit legacy policy.
	"crypto/sha256"
	"encoding/binary"
	"math"
	"math/bits"
)

const (
	maximumDerivedKeyBits = 8192
	maximumKDFFieldBytes  = 4097
	maximumKDFSecretBytes = 1024
)

// keyOctetBits converts key and digest byte widths to bits across this package.
const keyOctetBits = 8

// Representation widths shared by ConcatKDF assembly and bit-oriented SHA.
// The counter and hash word are distinct four-byte fields; length fields below
// count message bits rather than bytes or accepted derivation work.
const (
	kdfLastOctetBit         = keyOctetBits - 1
	kdfCounterBytes         = 4
	kdfHashWordBytes        = 4
	kdfFieldHeaderBytes     = 1
	concatSHA256StateWords  = sha256.Size / kdfHashWordBytes
	concatSHA1StateWords    = sha1.Size / kdfHashWordBytes
	concatInitialBlockWords = sha256.BlockSize / kdfHashWordBytes
)

// ConcatKDF is the XML Encryption 1.1 concatenation key derivation URI.
const ConcatKDF = Namespace11 + "ConcatKDF"

// ConcatKDFParameters supplies the exact XMLENC bit strings, before hex encoding.
// Each nonempty field starts with a padding-count octet (0..7), followed by the
// big-endian bits with zero padding in its last octet. Nil and empty fields
// represent an absent or empty bit string. For example, {3, 0xd8} encodes 11011.
// Each field is bounded to 4097 bytes, including the padding-count octet.
// The caller must bind the algorithm and party fields to its application; the
// derivation itself establishes neither the parties' identities nor trust.
type ConcatKDFParameters struct {
	// Hash selects SHA-256 (zero/default) or SHA-1 under AllowLegacy.
	Hash crypto.Hash
	// AlgorithmID identifies the algorithm that will consume the derived key.
	AlgorithmID []byte
	// PartyUInfo identifies the originator and any application-selected nonce.
	PartyUInfo []byte
	// PartyVInfo identifies the recipient.
	PartyVInfo []byte
	// SuppPubInfo contains application-selected supplementary public information.
	SuppPubInfo []byte
	// SuppPrivInfo contains application-selected supplementary private information.
	SuppPrivInfo []byte
	// AllowLegacy explicitly permits SHA-1, except in FIPS mode.
	AllowLegacy bool
}

// DeriveConcatKey implements XMLENC 1.1 section 5.4.1 and NIST SP 800-56A's
// counter || Z || OtherInfo construction. The secret is limited to 1024 bytes
// and keyBits to 1..8192. Non-octet output is left aligned with zero low bits.
// Input slices are never modified. Non-octet OtherInfo is rejected in FIPS mode
// because Go's validated hash backend accepts only whole octets.
func DeriveConcatKey(ctx context.Context, secret []byte, keyBits int, parameters ConcatKDFParameters) ([]byte, error) {
	if ctx == nil {
		return nil, ErrPolicy
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	if len(secret) == 0 || len(secret) > maximumKDFSecretBytes || keyBits < 1 || keyBits > maximumDerivedKeyBits {
		return nil, ErrPolicy
	}

	algorithm := parameters.Hash
	if algorithm == 0 {
		algorithm = crypto.SHA256
	}

	if algorithm != crypto.SHA256 && algorithm != crypto.SHA1 || algorithm == crypto.SHA1 && (!parameters.AllowLegacy || fips140.Enabled()) {
		return nil, ErrPolicy
	}

	fields := [][]byte{parameters.AlgorithmID, parameters.PartyUInfo, parameters.PartyVInfo, parameters.SuppPubInfo, parameters.SuppPrivInfo}
	otherBits := 0

	for _, field := range fields {
		n, ok := concatFieldBits(field)
		if !ok {
			return nil, ErrPolicy
		}

		otherBits += n
	}

	if otherBits%keyOctetBits != 0 && fips140.Enabled() {
		return nil, ErrPolicy
	}

	messageBits := (kdfCounterBytes+len(secret))*keyOctetBits + otherBits

	message := make([]byte, (messageBits+kdfLastOctetBit)/keyOctetBits)
	defer clear(message)

	copy(message[kdfCounterBytes:], secret)
	offset := (kdfCounterBytes + len(secret)) * keyOctetBits

	for _, field := range fields {
		n, _ := concatFieldBits(field)
		for i := range n {
			message[(offset+i)/keyOctetBits] |= ((field[kdfFieldHeaderBytes+i/keyOctetBits] >> (kdfLastOctetBit - i%keyOctetBits)) & 1) << (kdfLastOctetBit - (offset+i)%keyOctetBits)
		}

		offset += n
	}

	output := make([]byte, (keyBits+kdfLastOctetBit)/keyOctetBits)
	for offset, counter := 0, uint32(1); offset < len(output); counter++ {
		if err := ctx.Err(); err != nil {
			clear(output)
			return nil, err
		}

		binary.BigEndian.PutUint32(message, counter)

		digest, err := concatDigest(ctx, algorithm, message, messageBits)
		if err != nil {
			clear(output)
			return nil, err
		}

		offset += copy(output[offset:], digest)
		clear(digest)
	}

	if keyBits%keyOctetBits != 0 {
		output[len(output)-1] &= math.MaxUint8 << (keyOctetBits - keyBits%keyOctetBits)
	}

	return output, nil
}

func concatFieldBits(field []byte) (int, bool) {
	if len(field) == 0 {
		return 0, true
	}

	if len(field) > maximumKDFFieldBytes || field[0] > kdfLastOctetBit || len(field) == kdfFieldHeaderBytes && field[0] != 0 {
		return 0, false
	}

	padding := int(field[0])
	if padding != 0 && field[len(field)-1]&byte((1<<padding)-1) != 0 {
		return 0, false
	}

	return (len(field)-kdfFieldHeaderBytes)*keyOctetBits - padding, true
}

// Whole-octet messages use the standard library. Only XMLENC's arbitrary-bit
// OtherInfo requires the FIPS 180-4 compression and bit-length padding below.
// It is tested against NIST SHAVS bit-oriented SHA-1 and SHA-256 vectors.
func concatDigest(ctx context.Context, algorithm crypto.Hash, message []byte, length int) ([]byte, error) {
	const (
		lengthFieldBytes = 8
		lengthFieldBits  = lengthFieldBytes * keyOctetBits
		blockBits        = sha256.BlockSize * keyOctetBits
	)

	if length%keyOctetBits == 0 {
		if algorithm == crypto.SHA1 {
			digest := sha1.Sum(message) // #nosec G401 -- Explicit legacy policy is enforced by DeriveConcatKey.
			return digest[:], nil
		}

		digest := sha256.Sum256(message)

		return digest[:], nil
	}

	padded := make([]byte, ((length+1+lengthFieldBits+blockBits-1)/blockBits)*sha256.BlockSize)
	defer clear(padded)

	copy(padded, message)
	padded[length/keyOctetBits] &= math.MaxUint8 << (keyOctetBits - length%keyOctetBits)
	padded[length/keyOctetBits] |= 1 << (kdfLastOctetBit - length%keyOctetBits)
	binary.BigEndian.PutUint64(padded[len(padded)-lengthFieldBytes:], uint64(length)) // #nosec G115 -- DeriveConcatKey bounds this nonnegative bit length before allocation.

	state := [concatSHA256StateWords]uint32{0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19}
	defer clear(state[:])

	words := concatSHA256StateWords

	if algorithm == crypto.SHA1 {
		state = [concatSHA256StateWords]uint32{0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0}
		words = concatSHA1StateWords
	}

	for offset := 0; offset < len(padded); offset += sha256.BlockSize {
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		if algorithm == crypto.SHA1 {
			concatSHA1Block(&state, padded[offset:offset+sha256.BlockSize])
		} else {
			concatSHA256Block(&state, padded[offset:offset+sha256.BlockSize])
		}
	}

	output := make([]byte, words*kdfHashWordBytes)
	for i := range words {
		binary.BigEndian.PutUint32(output[kdfHashWordBytes*i:], state[i])
	}

	return output, nil
}

func concatSHA1Block(state *[concatSHA256StateWords]uint32, block []byte) {
	const (
		rounds         = 80
		roundsPerPhase = 20
	)

	var schedule [rounds]uint32
	defer clear(schedule[:])

	for i := range concatInitialBlockWords {
		schedule[i] = binary.BigEndian.Uint32(block[kdfHashWordBytes*i:])
	}

	for i := concatInitialBlockWords; i < rounds; i++ {
		schedule[i] = bits.RotateLeft32(schedule[i-3]^schedule[i-8]^schedule[i-14]^schedule[i-16], 1)
	}

	a, b, c, d, e := state[0], state[1], state[2], state[3], state[4]

	for i, word := range schedule {
		var f, k uint32

		switch {
		case i < roundsPerPhase:
			f, k = b&c|(^b)&d, 0x5a827999
		case i < 2*roundsPerPhase:
			f, k = b^c^d, 0x6ed9eba1
		case i < 3*roundsPerPhase:
			f, k = b&c|b&d|c&d, 0x8f1bbcdc
		default:
			f, k = b^c^d, 0xca62c1d6
		}

		a, b, c, d, e = bits.RotateLeft32(a, 5)+f+e+k+word, a, bits.RotateLeft32(b, 30), c, d
	}

	state[0] += a
	state[1] += b
	state[2] += c
	state[3] += d
	state[4] += e
}

func concatSHA256Block(state *[concatSHA256StateWords]uint32, block []byte) {
	constants := [...]uint32{
		0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
		0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
		0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
		0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
		0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
		0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
		0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
		0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
	}

	var schedule [len(constants)]uint32
	defer clear(schedule[:])

	for i := range concatInitialBlockWords {
		schedule[i] = binary.BigEndian.Uint32(block[kdfHashWordBytes*i:])
	}

	for i := concatInitialBlockWords; i < len(schedule); i++ {
		x, y := schedule[i-15], schedule[i-2]
		s0 := bits.RotateLeft32(x, -7) ^ bits.RotateLeft32(x, -18) ^ (x >> 3)
		s1 := bits.RotateLeft32(y, -17) ^ bits.RotateLeft32(y, -19) ^ (y >> 10)
		schedule[i] = schedule[i-16] + s0 + schedule[i-7] + s1
	}

	a, b, c, d, e, f, g, h := state[0], state[1], state[2], state[3], state[4], state[5], state[6], state[7]
	for i, word := range schedule {
		s1 := bits.RotateLeft32(e, -6) ^ bits.RotateLeft32(e, -11) ^ bits.RotateLeft32(e, -25)
		t1 := h + s1 + (e&f ^ (^e)&g) + constants[i] + word
		s0 := bits.RotateLeft32(a, -2) ^ bits.RotateLeft32(a, -13) ^ bits.RotateLeft32(a, -22)
		t2 := s0 + (a&b ^ a&c ^ b&c)
		a, b, c, d, e, f, g, h = t1+t2, a, b, c, d+t1, e, f, g
	}

	for i, value := range [...]uint32{a, b, c, d, e, f, g, h} {
		state[i] += value
	}
}
