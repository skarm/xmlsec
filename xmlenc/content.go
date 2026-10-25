package xmlenc

import (
	"context"
	"crypto"
	"crypto/rsa"
	"errors"

	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/internal/tree"
)

// EncryptContent replaces all content of the selected parent with one Type
// #Content EncryptedData. The parent and its attributes remain visible. The
// result is a new snapshot and the exact EncryptedData handle in that snapshot.
// Mixed, text-only and empty content use UTF-8/NFC (XMLENC 1.1 sections 4.2–4.3).
// Whole-output and plaintext limits follow EncryptElement. Partial encryption
// of EncryptedData/EncryptedKey structures is forbidden.
func EncryptContent(ctx context.Context, doc *document.Document, parent document.Element, recipient *rsa.PublicKey, options Options) (*document.Document, document.Element, error) {
	node, err := contentParent(doc, parent)
	if err != nil {
		return nil, document.Element{}, err
	}

	p, err := rsaEncryptProfile(ctx, options, recipient)
	if err != nil {
		return nil, document.Element{}, err
	}

	return encryptContent(ctx, doc, node, p)
}

// EncryptContentWithKeyWrap has the EncryptContent snapshot/limit contracts
// and uses an explicitly supplied KEK instead of an RSA recipient.
func EncryptContentWithKeyWrap(ctx context.Context, doc *document.Document, parent document.Element, kek []byte, options KeyWrapOptions) (*document.Document, document.Element, error) {
	node, err := contentParent(doc, parent)
	if err != nil {
		return nil, document.Element{}, err
	}

	p, err := keyWrapProfile(ctx, kek, options)
	if err != nil {
		return nil, document.Element{}, err
	}

	return encryptContent(ctx, doc, node, p)
}

// DecryptContent decrypts one selected Type #Content EncryptedData and
// replaces it with its decrypted content in the actual parent's namespace
// context (XMLENC 1.1 sections 4.5.1–4.5.4). It returns a new snapshot and the
// restored parent handle: content can contain zero, one or many nodes of any
// supported XML kind. Other siblings are retained and no recursive decryption
// occurs. The selected EncryptedData must have an element parent. Plaintext and
// complete-output budgets follow DecryptElement. No result is returned on error;
// sender identity, signatures and application context require separate checks.
func DecryptContent(ctx context.Context, doc *document.Document, selected document.Element, recipient crypto.Decrypter, options Options) (*document.Document, document.Element, error) {
	node, err := selectedNode(doc, selected)
	if err != nil || node.Parent == nil {
		return nil, document.Element{}, ErrFormat
	}

	p, err := rsaDecryptProfile(ctx, options, recipient)
	if err != nil {
		return nil, document.Element{}, err
	}

	return decryptContent(ctx, doc, node, p)
}

// DecryptContentWithKeyWrap has the DecryptContent snapshot/context contracts
// using an explicitly supplied KEK.
func DecryptContentWithKeyWrap(ctx context.Context, doc *document.Document, selected document.Element, kek []byte, options KeyWrapOptions) (*document.Document, document.Element, error) {
	node, err := selectedNode(doc, selected)
	if err != nil || node.Parent == nil {
		return nil, document.Element{}, ErrFormat
	}

	p, err := keyWrapProfile(ctx, kek, options)
	if err != nil {
		return nil, document.Element{}, err
	}

	return decryptContent(ctx, doc, node, p)
}

func contentParent(doc *document.Document, parent document.Element) (*tree.Node, error) {
	node, err := selectedNode(doc, parent)
	if err != nil {
		return nil, err
	}

	if node.Name.Space == Namespace && (node.Name.Local == "EncryptedData" || node.Name.Local == "EncryptedKey") {
		return nil, ErrFormat
	}

	return node, nil
}

func encryptContent(ctx context.Context, doc *document.Document, parent *tree.Node, p profile) (*document.Document, document.Element, error) {
	raw, storage, err := serializePlaintext(ctx, parent.Children, p.options.MaxPlaintextBytes, p.data)
	if err != nil {
		return nil, document.Element{}, err
	}
	defer clear(storage)

	if err := contentEncoding(ctx, raw); err != nil {
		if errors.Is(err, ErrFormat) {
			err = ErrPolicy
		}

		return nil, document.Element{}, err
	}

	encrypted, err := encryptOwned(ctx, raw, storage, p, ContentType)
	if err != nil {
		return nil, document.Element{}, err
	}

	result, restoredParent, err := replaceElement(ctx, doc, parent, withContent(parent, []*tree.Node{tree.Root(encrypted)}))
	if errors.Is(err, document.ErrLimit) {
		return nil, document.Element{}, ErrPolicy
	}

	if err != nil {
		return nil, document.Element{}, err
	}

	return result, restoredParent.Children()[0], nil
}

func decryptContent(ctx context.Context, doc *document.Document, node *tree.Node, p profile) (*document.Document, document.Element, error) {
	view := tree.FromNodes([]*tree.Node{node}, tree.Policy(doc))

	raw, err := decrypt(ctx, view, p, ContentType)
	if err != nil {
		return nil, document.Element{}, err
	}
	defer clear(raw)

	plain, err := parseContentPlaintext(ctx, raw, node.Parent, p.options.XMLLimits, tree.Policy(doc).MaxBytes)
	if err == nil {
		children := make([]*tree.Node, 0, len(node.Parent.Children)+len(plain))
		for _, child := range node.Parent.Children {
			if child == node {
				children = append(children, plain...)
			} else {
				children = append(children, child)
			}
		}

		result, parent, replaceErr := replaceElement(ctx, doc, node.Parent, withContent(node.Parent, children))
		if replaceErr == nil {
			return result, parent, nil
		}
	}

	if ctx.Err() != nil {
		return nil, document.Element{}, ctx.Err()
	}

	return nil, document.Element{}, ErrDecrypt
}

// Build a private header without changing source child parents. replaceElement
// serializes borrowed children into an independently parsed snapshot.
func withContent(parent *tree.Node, children []*tree.Node) *tree.Node {
	return &tree.Node{
		Kind: tree.ElementNode, Name: parent.Name, Prefix: parent.Prefix,
		Attrs: parent.Attrs, NS: parent.NS, Children: children,
	}
}
