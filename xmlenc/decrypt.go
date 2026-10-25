package xmlenc

import (
	"context"
	"crypto"
	"crypto/cipher"
	"crypto/rand"
	"io"

	"github.com/skarm/xmlsec/document"
)

// DecryptBytes accepts standalone, untyped EncryptedData and an explicit RSA
// recipient. An inline EncryptedKey selects no trust source or key.
func DecryptBytes(ctx context.Context, doc *document.Document, recipient crypto.Decrypter, options Options) ([]byte, error) {
	p, err := rsaDecryptProfile(ctx, options, recipient)
	if err != nil {
		return nil, err
	}

	return decrypt(ctx, doc, p, "")
}

// DecryptDocument accepts only Type #Element, decrypts the ciphertext and
// requires a single UTF-8/NFC element under the configured XML limits. No output
// is returned on failure, including malformed or over-budget decrypted XML.
func DecryptDocument(ctx context.Context, doc *document.Document, recipient crypto.Decrypter, options Options) (*document.Document, error) {
	p, err := rsaDecryptProfile(ctx, options, recipient)
	if err != nil {
		return nil, err
	}

	return decryptDocument(ctx, doc, p)
}

// DecryptBytesWithKeyWrap accepts untyped EncryptedData and the explicit KEK.
// Both Algorithm values must match the caller's options exactly.
func DecryptBytesWithKeyWrap(ctx context.Context, doc *document.Document, kek []byte, options KeyWrapOptions) ([]byte, error) {
	p, err := keyWrapProfile(ctx, kek, options)
	if err != nil {
		return nil, err
	}

	return decrypt(ctx, doc, p, "")
}

// DecryptDocumentWithKeyWrap accepts only Type #Element with an explicit KEK
// and requires a single UTF-8/NFC element under the configured XML limits.
func DecryptDocumentWithKeyWrap(ctx context.Context, doc *document.Document, kek []byte, options KeyWrapOptions) (*document.Document, error) {
	p, err := keyWrapProfile(ctx, kek, options)
	if err != nil {
		return nil, err
	}

	return decryptDocument(ctx, doc, p)
}

func decryptDocument(ctx context.Context, doc *document.Document, p profile) (*document.Document, error) {
	raw, err := decrypt(ctx, doc, p, ElementType)
	if err != nil {
		return nil, err
	}
	defer clear(raw)

	if err := elementEncoding(ctx, raw); err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}

		return nil, ErrDecrypt
	}

	parsed, err := document.Parse(ctx, raw, p.options.XMLLimits)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}

		return nil, ErrDecrypt
	}

	if !singleElement(parsed) {
		return nil, ErrDecrypt
	}

	return parsed, nil
}

func decrypt(ctx context.Context, doc *document.Document, p profile, typ string) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	wrapped, data, err := decodeProfile(ctx, doc, typ, p)
	if err != nil {
		return nil, err
	}

	if len(wrapped) != p.transport.wrappedBytes || len(data) < p.data.overhead() {
		return nil, ErrDecrypt
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	if p.direct != nil {
		return openData(ctx, data, p, p.direct, false)
	}

	key := make([]byte, p.keyBytes)
	defer clear(key)

	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, err
	}

	actual, unwrapErr := p.transport.unwrap(ctx, wrapped)
	defer clear(actual)

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	badKey := unwrapErr != nil || len(actual) != p.keyBytes
	if !badKey {
		copy(key, actual)
	}
	// A failed unwrap still performs the selected cipher checks with a random dummy key.
	// This is not a constant-time guarantee for external providers or a complete
	// oracle-resistance audit. Format and caller-policy errors remain distinct.
	block, err := p.data.block(key)
	if err != nil {
		return nil, ErrDecrypt
	}

	return openData(ctx, data, p, block, badKey)
}

func openData(ctx context.Context, data []byte, p profile, block cipher.Block, badKey bool) ([]byte, error) {
	plaintext, err := p.data.open(ctx, data, block, badKey)
	if err == nil && len(plaintext) > p.options.MaxPlaintextBytes {
		clear(plaintext)
		return nil, ErrDecrypt
	}

	return plaintext, err
}

func openGCM(ctx context.Context, data []byte, aead cipher.AEAD, badKey bool) ([]byte, error) {
	plaintext, err := aead.Open(data[gcmNonceBytes:gcmNonceBytes], data[:gcmNonceBytes], data[gcmNonceBytes:], nil)
	if badKey || err != nil {
		clear(plaintext)
		return nil, ErrDecrypt
	}

	if err := ctx.Err(); err != nil {
		clear(plaintext)
		return nil, err
	}

	return plaintext, nil
}
