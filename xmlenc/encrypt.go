package xmlenc

import (
	"bytes"
	"context"
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

	return encrypt(ctx, plaintext, p)
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

	return encrypt(ctx, plaintext, p)
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
	plaintext, storage, err := serializePlaintext(ctx, []*tree.Node{node}, p.options.MaxPlaintextBytes, p.data)
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
// the selected cipher. The second serialization trades a traversal for bounded
// exact storage.
func serializePlaintext(ctx context.Context, nodes []*tree.Node, maximum int, data dataCipher) ([]byte, []byte, error) {
	size, err := tree.WriteXMLFragment(ctx, io.Discard, nodes, maximum)
	if err != nil {
		if errors.Is(err, document.ErrLimit) {
			err = ErrPolicy
		}

		return nil, nil, err
	}

	storage := make([]byte, data.ivBytes, int(size)+data.overhead())

	output := bytes.NewBuffer(storage)
	if _, err := tree.WriteXMLFragment(ctx, output, nodes, maximum); err != nil {
		clear(output.Bytes())
		return nil, nil, err
	}

	storage = output.Bytes()

	return storage[data.ivBytes:], storage, nil
}

func encrypt(ctx context.Context, plaintext []byte, p profile) (*document.Document, error) {
	return encryptOwned(ctx, plaintext, nil, p, "")
}

func encryptOwned(ctx context.Context, plaintext, storage []byte, p profile, typ string) (*document.Document, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	if len(plaintext) > p.options.MaxPlaintextBytes {
		return nil, ErrPolicy
	}

	block := p.direct

	var wrapped []byte

	if block == nil {
		key := make([]byte, p.keyBytes)
		defer clear(key)

		if _, err := io.ReadFull(rand.Reader, key); err != nil {
			return nil, err
		}

		if p.data.tripleDES {
			oddDESParity(key)
		}

		var err error

		block, err = p.data.block(key)
		if err != nil {
			return nil, err
		}

		wrapped, err = p.transport.wrap(key)
		if err != nil {
			return nil, err
		}
	}

	encrypted, err := p.data.seal(ctx, plaintext, storage, block)
	if err != nil {
		return nil, err
	}

	return encodeProfile(ctx, wrapped, encrypted, p, typ)
}
