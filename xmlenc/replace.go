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
func EncryptElement(ctx context.Context, doc *document.Document, selected document.Element, recipient *rsa.PublicKey, options RSAOptions) (*document.Document, document.Element, error) {
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

// DecryptElement decrypts exactly the selected Type #Element EncryptedData
// and replaces it in a new snapshot. XMLLimits bound the plaintext element;
// the source document's parsing limits also bound the complete output. Plaintext
// is parsed using the parent's namespaces (W3C XMLENC 1.1 section 4.5.1).
// The returned handle selects the restored element.
// No document or valid handle is returned on failure. The caller must separately
// verify sender identity, restored signatures and application context before use.
func DecryptElement(ctx context.Context, doc *document.Document, selected document.Element, recipient crypto.Decrypter, options RSAOptions, decryption DecryptOptions) (*document.Document, document.Element, error) {
	node, err := selectedNode(doc, selected)
	if err != nil {
		return nil, document.Element{}, err
	}

	p, err := rsaDecryptProfile(ctx, options, recipient, decryption)
	if err != nil {
		return nil, document.Element{}, err
	}

	return decryptSelected(ctx, doc, node, p)
}

// DecryptElementWithKeyWrap replaces exactly the selected Type #Element
// EncryptedData using the explicit KEK. It does not search
// for other encrypted elements or recursively decrypt their contents.
// It returns the new snapshot and restored handle, with the limits/context
// contracts of DecryptElement.
func DecryptElementWithKeyWrap(ctx context.Context, doc *document.Document, selected document.Element, kek []byte, options KeyWrapOptions, decryption DecryptOptions) (*document.Document, document.Element, error) {
	node, err := selectedNode(doc, selected)
	if err != nil {
		return nil, document.Element{}, err
	}

	p, err := keyWrapDecryptProfile(ctx, kek, options, decryption)
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
		if parent.Name.Space == Namespace && (parent.Name.Local == nameEncryptedData || parent.Name.Local == nameEncryptedKey) {
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

	plain, err := parseSelectedPlaintext(ctx, raw, node.Parent, p.decryption.XMLLimits, tree.Policy(doc).MaxBytes)
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
	// A scoped document borrows its ancestors. Keep their namespace and XML
	// attribute context in the new snapshot and publish only the original scope.
	source, scope := tree.Unwrap(tree.ContextElement(doc.Root()))

	path, scopePosition, err := replacementPath(ctx, selected, scope, tree.Root(source))
	if err != nil {
		return nil, document.Element{}, err
	}

	header := *replacement

	draft, err := tree.ReplaceDraft(ctx, source, selected, &header)
	if err != nil {
		return nil, document.Element{}, err
	}

	result, err := tree.Reparse(ctx, draft, tree.Policy(doc))
	if err != nil {
		return nil, document.Element{}, err
	}

	tree.SetBaseURI(result, tree.BaseURI(source))
	anchor := tree.Root(result)
	final := anchor

	for i, index := range slices.Backward(path) {
		final = elementAt(final, index)
		if final == nil {
			return nil, document.Element{}, ErrFormat
		}

		if i == scopePosition {
			anchor = final
		}
	}

	if doc != source {
		result, err = tree.ScopeDocument(result, tree.Wrap(result, anchor))
		if err != nil {
			return nil, document.Element{}, err
		}
	}

	return result, tree.Wrap(result, final), nil
}

func replacementPath(ctx context.Context, selected, scope, root *tree.Node) ([]int, int, error) {
	var path []int

	scopePosition := -1

	for node := selected; node != root; node = node.Parent {
		if err := ctx.Err(); err != nil {
			return nil, 0, err
		}

		if node.Parent == nil {
			return nil, 0, ErrFormat
		}

		if node == scope {
			scopePosition = len(path)
		}

		index := 0
		found := false

		// The parser may coalesce text nodes during the round trip.
		for _, child := range node.Parent.Children {
			if child == node {
				found = true

				break
			}

			if child.Kind == tree.ElementNode {
				index++
			}
		}

		if !found {
			return nil, 0, ErrFormat
		}

		path = append(path, index)
	}

	return path, scopePosition, nil
}

func elementAt(parent *tree.Node, index int) *tree.Node {
	for _, child := range parent.Children {
		if child.Kind != tree.ElementNode {
			continue
		}

		if index == 0 {
			return child
		}

		index--
	}

	return nil
}
