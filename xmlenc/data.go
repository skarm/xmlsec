package xmlenc

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/des" // #nosec G502 -- XMLENC-required TripleDES is explicit legacy policy only.
	"crypto/fips140"
	"crypto/rand"
	"io"
)

const (
	// AES-128 key size in bytes, shared by cipher selection, key wrapping and agreement.
	aes128KeyBytes = 16
	// AES-192 key size in bytes, shared by cipher selection, key wrapping and agreement.
	aes192KeyBytes = 24
	// AES-256 key size in bytes, shared by cipher selection, key wrapping and agreement.
	aes256KeyBytes = 32
	// Three-key TripleDES key size in bytes, shared by CBC selection and legacy wrapping.
	tripleDESKeyBytes = 24
)

// dataCipher records the wire layout independently of key transport.
type dataCipher struct {
	keyBytes   int
	ivBytes    int
	blockBytes int
	extraBytes int
	tripleDES  bool
}

func (d dataCipher) overhead() int { return d.ivBytes + d.extraBytes }

func (d dataCipher) block(key []byte) (cipher.Block, error) {
	if d.tripleDES {
		return des.NewTripleDESCipher(key) // #nosec G405 -- Explicit XMLENC legacy profile; checked before construction.
	}

	return aes.NewCipher(key)
}

func (d dataCipher) seal(ctx context.Context, plaintext, storage []byte, block cipher.Block) ([]byte, error) {
	if storage == nil {
		storage = make([]byte, d.ivBytes, len(plaintext)+d.overhead())
	}

	iv := storage[:d.ivBytes]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}

	if d.blockBytes == 0 {
		aead, err := cipher.NewGCM(block)
		if err != nil {
			return nil, err
		}

		return aead.Seal(iv, iv, plaintext, nil), ctx.Err()
	}

	// XMLENC5.2.1 uses arbitrary preceding padding octets, not PKCS#7.
	n := d.blockBytes - len(plaintext)%d.blockBytes

	var padding [aes.BlockSize]byte
	if _, err := io.ReadFull(rand.Reader, padding[:n-1]); err != nil {
		return nil, err
	}

	padding[n-1] = byte(n) // #nosec G115 -- n is in1..blockBytes, which is8 or16.
	out := iv
	out = append(out, plaintext...)
	out = append(out, padding[:n]...)
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(out[d.ivBytes:], out[d.ivBytes:])

	return out, ctx.Err()
}

func (d dataCipher) open(ctx context.Context, data []byte, block cipher.Block, badKey bool) ([]byte, error) {
	if d.blockBytes == 0 {
		aead, err := cipher.NewGCM(block)
		if err != nil {
			return nil, ErrDecrypt
		}

		return openGCM(ctx, data, aead, badKey)
	}

	if len(data) < d.ivBytes+d.blockBytes || (len(data)-d.ivBytes)%d.blockBytes != 0 {
		return nil, ErrDecrypt
	}

	plaintext := make([]byte, len(data)-d.ivBytes)
	cipher.NewCBCDecrypter(block, data[:d.ivBytes]).CryptBlocks(plaintext, data[d.ivBytes:])

	n := int(plaintext[len(plaintext)-1])
	if badKey || n < 1 || n > d.blockBytes {
		clear(plaintext)
		return nil, ErrDecrypt
	}

	if err := ctx.Err(); err != nil {
		clear(plaintext)
		return nil, err
	}

	length := len(plaintext) - n
	clear(plaintext[length:])

	return plaintext[:length:length], nil
}

func dataAlgorithm(algorithm string, allowLegacy bool) (dataCipher, error) {
	var d dataCipher

	switch algorithm {
	case AES128GCM, AES192GCM, AES256GCM:
		d = dataCipher{keyBytes: aes128KeyBytes, ivBytes: gcmNonceBytes, extraBytes: gcmTagBytes}

		switch algorithm {
		case AES192GCM:
			d.keyBytes = aes192KeyBytes
		case AES256GCM:
			d.keyBytes = aes256KeyBytes
		}
	case AES128CBC, AES192CBC, AES256CBC:
		d = dataCipher{keyBytes: aes128KeyBytes, ivBytes: aes.BlockSize, blockBytes: aes.BlockSize, extraBytes: aes.BlockSize}

		switch algorithm {
		case AES192CBC:
			d.keyBytes = aes192KeyBytes
		case AES256CBC:
			d.keyBytes = aes256KeyBytes
		}
	case TripleDESCBC:
		d = dataCipher{keyBytes: tripleDESKeyBytes, ivBytes: des.BlockSize, blockBytes: des.BlockSize, extraBytes: des.BlockSize, tripleDES: true}
	default:
		return dataCipher{}, ErrPolicy
	}

	if d.blockBytes != 0 && (!allowLegacy || fips140.Enabled()) {
		return dataCipher{}, ErrPolicy
	}

	return d, nil
}
