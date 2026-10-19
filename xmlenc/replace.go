package xmlenc

import (
	"context"
	"crypto"
	"crypto/rsa"
	"errors"
	"slices"

	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/internal/tree"
)

// EncryptElement replaces exactly the selected element with Type #Element
// EncryptedData in a new document snapshot. Selection must belong to doc.
// Parent namespace/xml:* context, siblings and document-level nodes are retained.
// The returned handle selects the new EncryptedData in that snapshot.
// Source parsing limits bound the complete output; MaxPlaintextBytes bounds
// the selected serialization. Non-NFC input is rejected without normalization.
// Super-encryption selects the entire EncryptedData/EncryptedKey, not its children.
func EncryptElement(ctx context.Context, doc *document.Document, selected document.Element, recipient *rsa.PublicKey, options Options) (*document.Document, document.Element, error) {
	node, err := selectedNode(doc, selected)
	if err != nil {
		return nil, document.Element{}, err
	}

	p, err := rsaEncryptProfile(ctx, options, recipient)
	if err != nil {
		return nil, document.Element{}, err
	}

	return encryptSelected(ctx, doc, node, p)
}

// EncryptElementWithKeyWrap replaces the selected element using the explicitly
// supplied KEK. It has the same snapshot/context contracts as EncryptElement.
func EncryptElementWithKeyWrap(ctx context.Context, doc *document.Document, selected document.Element, kek []byte, options KeyWrapOptions) (*document.Document, document.Element, error) {
	node, err := selectedNode(doc, selected)
	if err != nil {
		return nil, document.Element{}, err
	}

	p, err := keyWrapProfile(ctx, kek, options)
	if err != nil {
		return nil, document.Element{}, err
	}

	return encryptSelected(ctx, doc, node, p)
}

// DecryptElement authenticates exactly the selected Type #Element EncryptedData
// and replaces it in a new snapshot. XMLLimits bound the plaintext element;
// the source document's parsing limits also bound the complete output. Plaintext
// is parsed using the parent's namespaces (W3C XMLENC 1.1 section 4.5.1).
// The returned handle selects the restored element.
// No document or valid handle is returned on failure. The caller must separately
// verify sender identity, restored signatures and application context before use.
func DecryptElement(ctx context.Context, doc *document.Document, selected document.Element, recipient crypto.Decrypter, options Options) (*document.Document, document.Element, error) {
	node, err := selectedNode(doc, selected)
	if err != nil {
		return nil, document.Element{}, err
	}

	p, err := rsaDecryptProfile(ctx, options, recipient)
	if err != nil {
		return nil, document.Element{}, err
	}

	return decryptSelected(ctx, doc, node, p)
}

// DecryptElementWithKeyWrap replaces exactly the selected Type #Element
// EncryptedData after authentication with the explicit KEK. It does not search
// for other encrypted elements or recursively decrypt their contents.
// It returns the new snapshot and restored handle, with the limits/context
// contracts of DecryptElement.
func DecryptElementWithKeyWrap(ctx context.Context, doc *document.Document, selected document.Element, kek []byte, options KeyWrapOptions) (*document.Document, document.Element, error) {
	node, err := selectedNode(doc, selected)
	if err != nil {
		return nil, document.Element{}, err
	}

	p, err := keyWrapProfile(ctx, kek, options)
	if err != nil {
		return nil, document.Element{}, err
	}

	return decryptSelected(ctx, doc, node, p)
}

func selectedNode(doc *document.Document, selected document.Element) (*tree.Node, error) {
	owner, node := tree.Unwrap(selected)
	if doc == nil || !doc.Root().Valid() || owner != doc || node == nil {
		return nil, ErrFormat
	}
	// XMLENC 1.1 section 2.1.5 permits super-encryption of complete structures;
	// inserting EncryptedData into one of their descendants is outside this profile.
	for parent := node.Parent; parent != nil; parent = parent.Parent {
		if parent.Name.Space == Namespace && (parent.Name.Local == "EncryptedData" || parent.Name.Local == "EncryptedKey") {
			return nil, ErrFormat
		}
	}

	return node, nil
}

func encryptSelected(ctx context.Context, doc *document.Document, node *tree.Node, p profile) (*document.Document, document.Element, error) {
	encrypted, err := encryptSerializedElement(ctx, node, p)
	if err != nil {
		return nil, document.Element{}, err
	}

	result, element, err := replaceElement(ctx, doc, node, tree.Root(encrypted))
	if errors.Is(err, document.ErrLimit) {
		return nil, document.Element{}, ErrPolicy
	}

	return result, element, err
}

func decryptSelected(ctx context.Context, doc *document.Document, node *tree.Node, p profile) (*document.Document, document.Element, error) {
	fragment := tree.FromNodes([]*tree.Node{node}, tree.Policy(doc))

	raw, err := decrypt(ctx, fragment, p, ElementType)
	if err != nil {
		return nil, document.Element{}, err
	}
	defer clear(raw)

	plain, err := parseSelectedPlaintext(ctx, raw, node.Parent, p.options.XMLLimits, tree.Policy(doc).MaxBytes)
	if err == nil {
		var (
			result  *document.Document
			element document.Element
		)

		result, element, err = replaceElement(ctx, doc, node, plain)
		if err == nil {
			return result, element, nil
		}
	}

	if ctx.Err() != nil {
		return nil, document.Element{}, ctx.Err()
	}

	return nil, document.Element{}, ErrDecrypt
}

func replaceElement(ctx context.Context, doc *document.Document, selected, replacement *tree.Node) (*document.Document, document.Element, error) {
	if err := ctx.Err(); err != nil {
		return nil, document.Element{}, err
	}
	// Record child positions before replacement; handles never cross snapshots.
	var path []int

	for n := selected; n.Parent != nil; n = n.Parent {
		index := -1

		for i, child := range n.Parent.Children {
			if child == n {
				index = i
				break
			}
		}

		if index < 0 {
			return nil, document.Element{}, ErrFormat
		}

		path = append(path, index)
	}

	// Copy only ancestor headers/child lists. Serialization reads borrowed
	// subtrees without changing parent links; reparsing owns the final snapshot.
	imported := replacement

	for original := selected; original.Parent != nil; original = original.Parent {
		if err := ctx.Err(); err != nil {
			return nil, document.Element{}, err
		}

		parent := *original.Parent

		parent.Children = append([]*tree.Node(nil), original.Parent.Children...)
		for i, child := range parent.Children {
			if child == original {
				parent.Children[i] = imported
				break
			}
		}

		imported = &parent
	}

	children := append([]*tree.Node(nil), tree.Children(doc)...)
	for i, node := range children {
		if node == tree.Root(doc) {
			children[i] = imported
			break
		}
	}

	draft := tree.FromNodes(children, tree.Policy(doc))

	result, err := tree.Reparse(ctx, draft, tree.Policy(doc))
	if err != nil {
		return nil, document.Element{}, err
	}

	final := tree.Root(result)
	for _, p := range slices.Backward(path) {
		final = final.Children[p]
	}

	return result, tree.Wrap(result, final), nil
}
