package xmlenc

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"io"

	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/internal/tree"
)

// EncryptBytes creates standalone EncryptedData without a Type attribute.
func EncryptBytes(ctx context.Context, plaintext []byte, recipient *rsa.PublicKey, options Options) (*document.Document, error) {
	p, err := rsaEncryptProfile(ctx, options, recipient)
	if err != nil {
		return nil, err
	}

	return encrypt(ctx, plaintext, p, "")
}

// EncryptDocument encrypts the complete root element, excluding document-level
// PIs and comments. The Type is #Element. Non-NFC serialization is rejected;
// source nodes are never normalized or mutated.
func EncryptDocument(ctx context.Context, doc *document.Document, recipient *rsa.PublicKey, options Options) (*document.Document, error) {
	p, err := rsaEncryptProfile(ctx, options, recipient)
	if err != nil {
		return nil, err
	}

	return encryptDocument(ctx, doc, p)
}

// EncryptBytesWithKeyWrap encrypts bytes using the explicitly supplied KEK.
// The caller must keep the KEK secret and distribute it through a trusted channel.
func EncryptBytesWithKeyWrap(ctx context.Context, plaintext, kek []byte, options KeyWrapOptions) (*document.Document, error) {
	p, err := keyWrapProfile(ctx, kek, options)
	if err != nil {
		return nil, err
	}

	return encrypt(ctx, plaintext, p, "")
}

// EncryptDocumentWithKeyWrap encrypts the complete root element with Type
// #Element using the explicitly supplied KEK. Non-NFC serialization is rejected;
// source nodes are never normalized or mutated.
func EncryptDocumentWithKeyWrap(ctx context.Context, doc *document.Document, kek []byte, options KeyWrapOptions) (*document.Document, error) {
	p, err := keyWrapProfile(ctx, kek, options)
	if err != nil {
		return nil, err
	}

	return encryptDocument(ctx, doc, p)
}

func encryptDocument(ctx context.Context, doc *document.Document, p profile) (*document.Document, error) {
	if doc == nil || !doc.Root().Valid() {
		return nil, ErrFormat
	}

	return encryptSerializedElement(ctx, tree.Root(doc), p)
}

func encryptSerializedElement(ctx context.Context, node *tree.Node, p profile) (*document.Document, error) {
	// Keep local namespace declarations, including xmlns="". Selected-element
	// plaintext is reparsed in its unchanged parent's namespace context.
	plaintext, storage, err := serializePlaintext(ctx, []*tree.Node{node}, p.options.MaxPlaintextBytes)
	if err != nil {
		return nil, err
	}
	defer clear(storage)

	if err := elementEncoding(ctx, plaintext); err != nil {
		if errors.Is(err, ErrFormat) {
			err = ErrPolicy
		}

		return nil, err
	}

	return encryptOwned(ctx, plaintext, storage, p, ElementType)
}

// Count before allocating so XML is written directly into the buffer reused by
// GCM. The second serialization trades a traversal for bounded exact storage.
func serializePlaintext(ctx context.Context, nodes []*tree.Node, maximum int) ([]byte, []byte, error) {
	size, err := tree.WriteXMLFragment(ctx, io.Discard, nodes, maximum)
	if err != nil {
		if errors.Is(err, document.ErrLimit) {
			err = ErrPolicy
		}

		return nil, nil, err
	}

	storage := make([]byte, gcmNonceBytes, int(size)+gcmOverhead)

	output := bytes.NewBuffer(storage)
	if _, err := tree.WriteXMLFragment(ctx, output, nodes, maximum); err != nil {
		clear(output.Bytes())
		return nil, nil, err
	}

	storage = output.Bytes()

	return storage[gcmNonceBytes:], storage, nil
}

func encrypt(ctx context.Context, plaintext []byte, p profile, typ string) (*document.Document, error) {
	return encryptOwned(ctx, plaintext, nil, p, typ)
}

func encryptOwned(ctx context.Context, plaintext, storage []byte, p profile, typ string) (*document.Document, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	if len(plaintext) > p.options.MaxPlaintextBytes {
		return nil, ErrPolicy
	}

	aead := p.direct

	var wrapped []byte

	if aead == nil {
		key := make([]byte, p.keyBytes)
		defer clear(key)

		if _, err := io.ReadFull(rand.Reader, key); err != nil {
			return nil, err
		}

		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, err
		}

		aead, err = cipher.NewGCM(block)
		if err != nil {
			return nil, err
		}

		wrapped, err = p.transport.wrap(key)
		if err != nil {
			return nil, err
		}
	}

	if storage == nil {
		storage = make([]byte, gcmNonceBytes, gcmNonceBytes+len(plaintext)+aead.Overhead())
	}

	iv := storage[:gcmNonceBytes]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}

	encrypted := aead.Seal(iv, iv, plaintext, nil)

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	return encodeProfile(ctx, wrapped, encrypted, p, typ)
}
