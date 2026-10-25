package xmlenc

import (
	"context"
	"crypto/rand"
	"errors"
	"io"

	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/internal/tree"
)

// DecryptBytesWithKeyGraph decrypts exactly selected EncryptedData using the
// explicitly authorized key graph. Type, MimeType and Encoding are advisory:
// bytes are returned unchanged, without transcoding, decompressing or recursion.
// KeyInfo and reference labels confer no trust. Authentication of the sender
// and application context remains the caller's responsibility.
func DecryptBytesWithKeyGraph(ctx context.Context, doc *document.Document, selected document.Element, options KeyGraphOptions) ([]byte, error) {
	raw, _, err := decryptGraph(ctx, doc, selected, options, "")
	return raw, err
}

// DecryptDocumentWithKeyGraph requires the selected Type #Element to contain a
// single UTF-8/NFC XML element. It returns only that decrypted document.
func DecryptDocumentWithKeyGraph(ctx context.Context, doc *document.Document, selected document.Element, options KeyGraphOptions) (*document.Document, error) {
	raw, p, err := decryptGraph(ctx, doc, selected, options, ElementType)
	if err != nil {
		return nil, err
	}
	defer clear(raw)

	if err := elementEncoding(ctx, raw); err != nil {
		return nil, graphPlainError(ctx)
	}

	parsed, err := document.Parse(ctx, raw, p.options.XMLLimits)
	if err != nil || !singleElement(parsed) {
		return nil, graphPlainError(ctx)
	}

	return parsed, nil
}

// DecryptElementWithKeyGraph replaces exactly selected Type #Element in a new
// document snapshot, preserving the parent's namespace context and siblings.
func DecryptElementWithKeyGraph(ctx context.Context, doc *document.Document, selected document.Element, options KeyGraphOptions) (*document.Document, document.Element, error) {
	node, err := selectedNode(doc, selected)
	if err != nil {
		return nil, document.Element{}, err
	}

	raw, p, err := decryptGraph(ctx, doc, selected, options, ElementType)
	if err != nil {
		return nil, document.Element{}, err
	}
	defer clear(raw)

	plain, err := parseSelectedPlaintext(ctx, raw, node.Parent, p.options.XMLLimits, tree.Policy(doc).MaxBytes)
	if err != nil {
		return nil, document.Element{}, graphPlainError(ctx)
	}

	result, restored, err := replaceElement(ctx, doc, node, plain)
	if err != nil {
		return nil, document.Element{}, graphPlainError(ctx)
	}

	return result, restored, nil
}

// DecryptContentWithKeyGraph replaces exactly selected Type #Content with its
// decrypted content in a new snapshot and returns the restored parent handle.
func DecryptContentWithKeyGraph(ctx context.Context, doc *document.Document, selected document.Element, options KeyGraphOptions) (*document.Document, document.Element, error) {
	node, err := selectedNode(doc, selected)
	if err != nil || node.Parent == nil {
		return nil, document.Element{}, ErrFormat
	}

	raw, p, err := decryptGraph(ctx, doc, selected, options, ContentType)
	if err != nil {
		return nil, document.Element{}, err
	}
	defer clear(raw)

	plain, err := parseContentPlaintext(ctx, raw, node.Parent, p.options.XMLLimits, tree.Policy(doc).MaxBytes)
	if err != nil {
		return nil, document.Element{}, graphPlainError(ctx)
	}

	children := make([]*tree.Node, 0, len(node.Parent.Children)+len(plain))
	for _, child := range node.Parent.Children {
		if child == node {
			children = append(children, plain...)
		} else {
			children = append(children, child)
		}
	}

	result, parent, err := replaceElement(ctx, doc, node.Parent, withContent(node.Parent, children))
	if err != nil {
		return nil, document.Element{}, graphPlainError(ctx)
	}

	return result, parent, nil
}

func graphPlainError(ctx context.Context) error {
	if ctx != nil && ctx.Err() != nil {
		return ctx.Err()
	}

	return ErrDecrypt
}

func decryptGraph(ctx context.Context, doc *document.Document, selected document.Element, options KeyGraphOptions, typ string) ([]byte, profile, error) {
	node, err := selectedNode(doc, selected)
	if err != nil || node.Name != elementName(Namespace, "EncryptedData") {
		return nil, profile{}, ErrFormat
	}

	g, principal, err := newKeyGraph(ctx, doc, options)
	if err != nil {
		return nil, profile{}, err
	}
	defer g.close()

	target := graphNode{principal, node}

	fields, err := graphEncrypted(target)
	if err != nil {
		return nil, profile{}, err
	}

	p := g.profile

	if typ != "" && attributeValue(selected, "Type") != typ {
		return nil, profile{}, ErrFormat
	}

	if fields.method.Valid() {
		if err := checkEncryptionMethod(ctx, fields.method, p.options.DataAlgorithm, p.keyBytes*8, false); err != nil {
			return nil, profile{}, err
		}
	}

	dataPlan, err := g.cipherPlan(principal, fields.cipherData, p.options.MaxPlaintextBytes+p.data.overhead())
	if err != nil {
		return nil, profile{}, err
	}
	// Explicit standalone candidates are loaded before discovering backlinks.
	for _, uri := range g.options.KeyURIs {
		candidate, err := g.referenceTarget(principal, doc.Root(), uri)
		if err != nil {
			return nil, profile{}, err
		}

		if graphRetrievalType(candidate.node.Name) == "" {
			return nil, profile{}, ErrFormat
		}

		g.standalone = append(g.standalone, candidate)
	}

	key, err := g.consumerKey(target, fields.keyInfo, p.options.DataAlgorithm, p.keyBytes, 0)
	if errors.Is(err, errGraphKeyUnavailable) {
		err = ErrPolicy
	}

	if err != nil {
		return nil, profile{}, err
	}

	// Validate every reachable node and obtain bounded resources before the first
	// private-key operation. No candidate is selected by trial decryption.
	if err := g.prepareKey(key, make(map[*graphKeyPlan]struct{})); err != nil {
		return nil, profile{}, err
	}

	ciphertext, err := g.readCipher(dataPlan)
	if err != nil {
		return nil, profile{}, err
	}

	if len(ciphertext) < p.data.overhead() {
		return nil, profile{}, ErrDecrypt
	}

	actual, unwrapErr := g.runKey(key)

	if ctx.Err() != nil {
		return nil, profile{}, ctx.Err()
	}

	material := make([]byte, p.keyBytes)
	defer clear(material)

	if _, err := io.ReadFull(rand.Reader, material); err != nil {
		return nil, profile{}, err
	}

	bad := unwrapErr != nil || len(actual) != p.keyBytes
	if !bad {
		copy(material, actual)
	}

	block, err := p.data.block(material)
	if err != nil {
		return nil, profile{}, ErrDecrypt
	}

	plaintext, err := openData(ctx, ciphertext, p, block, bad)

	return plaintext, p, err
}
