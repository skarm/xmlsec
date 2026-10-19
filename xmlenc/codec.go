package xmlenc

import (
	"context"
	"encoding/base64"
	"errors"
	"io"

	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/internal/streamio"
	"github.com/skarm/xmlsec/internal/tree"
)

func newElement(namespace, prefix, local string) *tree.Node {
	return &tree.Node{Kind: tree.ElementNode, Name: document.Name{Space: namespace, Local: local}, Prefix: prefix}
}

func encryptedElement(local string) *tree.Node { return newElement(Namespace, "xenc", local) }

func appendChild(parent, child *tree.Node) {
	parent.Children = append(parent.Children, child)
	child.Parent = parent
}

func setAttribute(node *tree.Node, local, value string) {
	node.Attrs = append(node.Attrs, tree.Attribute{Name: document.Name{Local: local}, Value: value})
}

func encodeCipherData(ctx context.Context, ciphertext []byte) (*tree.Node, error) {
	encoded, err := tree.EncodeBase64(ctx, ciphertext)
	if err != nil {
		return nil, err
	}

	data := encryptedElement("CipherData")
	value := encryptedElement("CipherValue")
	appendChild(value, &tree.Node{Kind: tree.TextNode, Data: encoded})
	appendChild(data, value)

	return data, nil
}

func encodeProfile(ctx context.Context, wrapped, encrypted []byte, p profile, typ string) (*document.Document, error) {
	root := encryptedElement("EncryptedData")

	method := encryptedElement("EncryptionMethod")
	setAttribute(method, "Algorithm", p.options.DataAlgorithm)
	appendChild(root, method)

	if p.direct == nil {
		keyInfo := newElement(SignatureNamespace, "ds", "KeyInfo")
		encryptedKey := encryptedElement("EncryptedKey")
		keyMethod := encryptedElement("EncryptionMethod")
		setAttribute(keyMethod, "Algorithm", p.transport.algorithm)

		if p.transport.algorithm == RSAOAEP {
			encodeOAEP(keyMethod, p.transport.oaep)
		}

		appendChild(encryptedKey, keyMethod)

		cipherData, err := encodeCipherData(ctx, wrapped)
		if err != nil {
			return nil, err
		}

		appendChild(encryptedKey, cipherData)
		appendChild(keyInfo, encryptedKey)
		appendChild(root, keyInfo)
	} else if p.keyName != "" {
		keyInfo := newElement(SignatureNamespace, "ds", "KeyInfo")
		name := newElement(SignatureNamespace, "ds", "KeyName")
		appendChild(name, &tree.Node{Kind: tree.TextNode, Data: p.keyName})
		appendChild(keyInfo, name)
		appendChild(root, keyInfo)
	}

	limits := document.DefaultLimits()
	limits.MaxBytes = base64.StdEncoding.EncodedLen(p.options.MaxPlaintextBytes+gcmOverhead) + 8192

	return tree.ParseProduced(ctx, func(dst io.Writer) error {
		return writeProfile(ctx, dst, root.Children, encrypted, typ, limits.MaxBytes)
	}, limits)
}

// Only fixed profile names and internally selected Type values enter markup.
// Metadata uses the XML serializer; the large CipherValue goes straight through
// its Base64 encoder into the parser that owns the published XML text.
func writeProfile(ctx context.Context, dst io.Writer, metadata []*tree.Node, encrypted []byte, typ string, maximum int) error {
	writer := &streamio.Writer{Context: ctx, Target: dst, Limit: int64(maximum), LimitError: document.ErrLimit}

	start := `<xenc:EncryptedData xmlns:xenc="` + Namespace + `" xmlns:xenc11="` + Namespace11 + `" xmlns:ds="` + SignatureNamespace + `"`
	if typ != "" {
		start += ` Type="` + typ + `"`
	}

	if _, err := writer.WriteString(start + ">"); err != nil {
		return err
	}

	if _, err := tree.WriteXMLFragment(ctx, writer, metadata, maximum); err != nil {
		return err
	}

	if _, err := writer.WriteString(`<xenc:CipherData><xenc:CipherValue>`); err != nil {
		return err
	}

	encoder := base64.NewEncoder(base64.StdEncoding, writer)
	if _, err := encoder.Write(encrypted); err != nil {
		return err
	}

	if err := encoder.Close(); err != nil {
		return err
	}

	_, err := writer.WriteString(`</xenc:CipherValue></xenc:CipherData></xenc:EncryptedData>`)

	return errors.Join(err, ctx.Err())
}

func attributeValue(element document.Element, local string) string {
	value, _ := element.Attribute(document.Name{Local: local})
	return value
}

func exactAttributes(element document.Element, allowed ...string) bool {
	_, node := tree.Unwrap(element)
	if node == nil || len(node.Attrs) != len(allowed) {
		return false
	}

	for _, attribute := range node.Attrs {
		found := false

		for _, local := range allowed {
			if attribute.Name == (document.Name{Local: local}) {
				found = true
				break
			}
		}

		if !found {
			return false
		}
	}

	return true
}

func elementName(namespace, local string) document.Name {
	return document.Name{Space: namespace, Local: local}
}

func childElements(element document.Element, names ...document.Name) ([]document.Element, error) {
	_, node := tree.Unwrap(element)
	if node == nil {
		return nil, ErrFormat
	}

	for _, child := range node.Children {
		if child.Kind == tree.TextNode && !xmlSpace(child.Data) {
			return nil, ErrFormat
		}
	}

	children := element.Children()
	if len(children) != len(names) {
		return nil, ErrFormat
	}

	for i, name := range names {
		if children[i].Name() != name {
			return nil, ErrFormat
		}
	}

	return children, nil
}

func matchesMethod(element document.Element, algorithm string, empty bool) bool {
	return exactAttributes(element, "Algorithm") && attributeValue(element, "Algorithm") == algorithm &&
		(!empty || (len(element.Children()) == 0 && xmlSpace(element.Text())))
}

func decodeCipherValue(ctx context.Context, element document.Element, maxBytes int) ([]byte, error) {
	children, err := childElements(element, elementName(Namespace, "CipherValue"))
	if err != nil || !exactAttributes(element) || !exactAttributes(children[0]) || len(children[0].Children()) != 0 {
		return nil, ErrFormat
	}

	return decodeBase64Text(ctx, children[0], maxBytes)
}

func decodeBase64Text(ctx context.Context, element document.Element, maxBytes int) ([]byte, error) {
	_, node := tree.Unwrap(element)

	value, err := tree.DecodeBase64(ctx, node, base64.StdEncoding.EncodedLen(maxBytes)+4096, maxBytes)
	if errors.Is(err, tree.ErrLimit) {
		return nil, errors.Join(ErrPolicy, err)
	}

	if err != nil {
		return nil, errors.Join(ErrFormat, err)
	}

	return value, nil
}

func decodeProfile(ctx context.Context, doc *document.Document, typ string, p profile) ([]byte, []byte, error) {
	if doc == nil || doc.Root().Name() != elementName(Namespace, "EncryptedData") {
		return nil, nil, ErrFormat
	}

	root := doc.Root()
	if typ == "" {
		if !exactAttributes(root) {
			return nil, nil, ErrFormat
		}
	} else if !exactAttributes(root, "Type") || attributeValue(root, "Type") != typ {
		return nil, nil, ErrFormat
	}

	if p.direct != nil {
		return decodeDirectProfile(ctx, root, p)
	}

	children, err := childElements(root, elementName(Namespace, "EncryptionMethod"), elementName(SignatureNamespace, "KeyInfo"), elementName(Namespace, "CipherData"))
	if err != nil || !matchesMethod(children[0], p.options.DataAlgorithm, true) {
		return nil, nil, ErrFormat
	}

	keyInfo, err := childElements(children[1], elementName(Namespace, "EncryptedKey"))
	if err != nil || !exactAttributes(children[1]) {
		return nil, nil, ErrFormat
	}

	key, err := childElements(keyInfo[0], elementName(Namespace, "EncryptionMethod"), elementName(Namespace, "CipherData"))
	if err != nil || !exactAttributes(keyInfo[0]) || !matchesMethod(key[0], p.transport.algorithm, p.transport.algorithm != RSAOAEP) {
		return nil, nil, ErrFormat
	}

	if p.transport.algorithm == RSAOAEP {
		if err := checkOAEP(ctx, key[0], p.transport.oaep); err != nil {
			return nil, nil, err
		}
	}
	// At most a 16384-bit RSA ciphertext. Key Wrap additionally requires the
	// exact session-key length plus eight bytes before any unwrap operations.
	wrapped, err := decodeCipherValue(ctx, key[1], 2048)
	if err != nil {
		return nil, nil, err
	}

	if len(wrapped) != p.transport.wrappedBytes {
		return nil, nil, ErrDecrypt
	}

	data, err := decodeCipherData(ctx, children[2], p.options.MaxPlaintextBytes+gcmOverhead, p.options.External)
	if err != nil {
		return nil, nil, err
	}

	return wrapped, data, nil
}

// XML S is only space, tab, CR and LF.
func xmlSpace(text string) bool {
	for i := 0; i < len(text); i++ {
		switch text[i] {
		case ' ', '\t', '\r', '\n':
		default:
			return false
		}
	}

	return true
}
