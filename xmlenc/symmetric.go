package xmlenc

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"strings"
	"unicode/utf8"

	"github.com/skarm/xmlsec/document"
)

// EncryptBytesWithKey encrypts bytes with an explicitly supplied AES data key.
// It creates a fresh random 96-bit nonce and a 128-bit tag, with no EncryptedKey.
// Applications must limit each data key to at most 2^32 encryptions and manage
// secret distribution. KeyName is an untrusted hint, not an identity assertion.
func EncryptBytesWithKey(ctx context.Context, plaintext, key []byte, options SymmetricOptions) (*document.Document, error) {
	p, err := symmetricProfile(ctx, key, options)
	if err != nil {
		return nil, err
	}

	return encrypt(ctx, plaintext, p, "")
}

// DecryptBytesWithKey authenticates untyped EncryptedData with an explicit AES
// data key and exact caller-selected algorithm and KeyName. It returns no plaintext
// on authentication, format, budget or cancellation failure.
func DecryptBytesWithKey(ctx context.Context, doc *document.Document, key []byte, options SymmetricOptions) ([]byte, error) {
	p, err := symmetricProfile(ctx, key, options)
	if err != nil {
		return nil, err
	}

	return decrypt(ctx, doc, p, "")
}

// EncryptDocumentWithKey encrypts the complete root element using an explicit
// AES data key. It has the serialization and limit contracts of EncryptDocument.
func EncryptDocumentWithKey(ctx context.Context, doc *document.Document, key []byte, options SymmetricOptions) (*document.Document, error) {
	p, err := symmetricProfile(ctx, key, options)
	if err != nil {
		return nil, err
	}

	return encryptDocument(ctx, doc, p)
}

// DecryptDocumentWithKey authenticates a standalone Type #Element envelope with
// an explicit AES data key before parsing it under the configured XML limits.
func DecryptDocumentWithKey(ctx context.Context, doc *document.Document, key []byte, options SymmetricOptions) (*document.Document, error) {
	p, err := symmetricProfile(ctx, key, options)
	if err != nil {
		return nil, err
	}

	return decryptDocument(ctx, doc, p)
}

// EncryptElementWithKey replaces exactly the selected element using an explicit
// AES data key. It has the snapshot, namespace and limit contracts of EncryptElement.
func EncryptElementWithKey(ctx context.Context, doc *document.Document, selected document.Element, key []byte, options SymmetricOptions) (*document.Document, document.Element, error) {
	node, err := selectedNode(doc, selected)
	if err != nil {
		return nil, document.Element{}, err
	}

	p, err := symmetricProfile(ctx, key, options)
	if err != nil {
		return nil, document.Element{}, err
	}

	return encryptSelected(ctx, doc, node, p)
}

// DecryptElementWithKey authenticates and restores exactly the selected element
// with an explicit AES data key, using its parent's original namespace context.
func DecryptElementWithKey(ctx context.Context, doc *document.Document, selected document.Element, key []byte, options SymmetricOptions) (*document.Document, document.Element, error) {
	node, err := selectedNode(doc, selected)
	if err != nil {
		return nil, document.Element{}, err
	}

	p, err := symmetricProfile(ctx, key, options)
	if err != nil {
		return nil, document.Element{}, err
	}

	return decryptSelected(ctx, doc, node, p)
}

// EncryptContentWithKey replaces the selected parent's complete content with
// one envelope using an explicit AES data key. Empty and mixed content are supported.
func EncryptContentWithKey(ctx context.Context, doc *document.Document, parent document.Element, key []byte, options SymmetricOptions) (*document.Document, document.Element, error) {
	node, err := contentParent(doc, parent)
	if err != nil {
		return nil, document.Element{}, err
	}

	p, err := symmetricProfile(ctx, key, options)
	if err != nil {
		return nil, document.Element{}, err
	}

	return encryptContent(ctx, doc, node, p)
}

// DecryptContentWithKey authenticates and restores selected Type #Content with
// an explicit AES data key. It has the snapshot and namespace contracts of DecryptContent.
func DecryptContentWithKey(ctx context.Context, doc *document.Document, selected document.Element, key []byte, options SymmetricOptions) (*document.Document, document.Element, error) {
	node, err := selectedNode(doc, selected)
	if err != nil || node.Parent == nil {
		return nil, document.Element{}, ErrFormat
	}

	p, err := symmetricProfile(ctx, key, options)
	if err != nil {
		return nil, document.Element{}, err
	}

	return decryptContent(ctx, doc, node, p)
}

func symmetricProfile(ctx context.Context, key []byte, options SymmetricOptions) (profile, error) {
	if options.Data.OAEP != nil {
		return profile{}, ErrPolicy
	}

	p, err := normalize(ctx, options.Data)
	if err != nil {
		return profile{}, err
	}

	if len(key) != p.keyBytes || len(options.KeyName) > 1024 || !utf8.ValidString(options.KeyName) || strings.TrimSpace(options.KeyName) != options.KeyName {
		return profile{}, ErrPolicy
	}

	for _, r := range options.KeyName {
		if r < 0x20 || r == 0x7f || r == 0xfffe || r == 0xffff {
			return profile{}, ErrPolicy
		}
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return profile{}, ErrPolicy
	}

	p.direct, err = cipher.NewGCM(block)
	if err != nil {
		return profile{}, ErrPolicy
	}

	p.keyName = options.KeyName

	return p, nil
}

func decodeDirectProfile(ctx context.Context, root document.Element, p profile) ([]byte, []byte, error) {
	names := []document.Name{elementName(Namespace, "EncryptionMethod")}
	if p.keyName != "" {
		names = append(names, elementName(SignatureNamespace, "KeyInfo"))
	}

	names = append(names, elementName(Namespace, "CipherData"))

	children, err := childElements(root, names...)
	if err != nil || !matchesMethod(children[0], p.options.DataAlgorithm, true) {
		return nil, nil, ErrFormat
	}

	if p.keyName != "" {
		info := children[1]

		hints, err := childElements(info, elementName(SignatureNamespace, "KeyName"))
		if err != nil || !exactAttributes(info) || !exactAttributes(hints[0]) || len(hints[0].Children()) != 0 || hints[0].Text() != p.keyName {
			return nil, nil, ErrFormat
		}
	}

	data, err := decodeCipherData(ctx, children[len(children)-1], p.options.MaxPlaintextBytes+gcmOverhead, p.options.External)

	return nil, data, err
}
