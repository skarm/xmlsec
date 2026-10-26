package xmlenc

import (
	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/internal/lexicon"
	"github.com/skarm/xmlsec/internal/nilcheck"
	"github.com/skarm/xmlsec/internal/tree"
)

func (g *keyGraph) graphAgreementOptions(binding KeyGraphKey) (ECDHOptions, error) {
	options := ECDHOptions{}
	if binding.ECDH != nil {
		options = *binding.ECDH
	}

	if options.Data != (Options{}) {
		return ECDHOptions{}, ErrPolicy
	}

	options.Data = g.profile.options
	// OAEP grants concern only RSA bindings in this same graph.
	options.Data.OAEP = nil
	if options.KeyAlgorithm != "" && options.KeyAlgorithm != binding.Algorithm {
		return ECDHOptions{}, ErrPolicy
	}

	options.KeyAlgorithm = binding.Algorithm
	if options.RecipientKeyName != "" && options.RecipientKeyName != binding.Name {
		return ECDHOptions{}, ErrPolicy
	}

	options.RecipientKeyName = binding.Name

	return options, nil
}

func (g *keyGraph) validateAgreementBinding(binding KeyGraphKey) error {
	if nilcheck.IsNil(binding.ECDHRecipient) || binding.Decrypter != nil || binding.PublicKey != nil || len(binding.Secret) != 0 || graphWrappingKeyBytes(binding.Algorithm) == 0 || binding.Algorithm == TripleDESKeyWrap {
		return ErrPolicy
	}

	options, err := g.graphAgreementOptions(binding)
	if err != nil {
		return err
	}

	_, err = ecdhDecryptKeyTransport(g.ctx, binding.ECDHRecipient, options, g.profile.keyBytes)

	return err
}

func (g *keyGraph) agreementEncryptedPlan(node graphNode, fields graphEncryptedFields, algorithm string, size int) (*graphKeyPlan, error) {
	name, err := graphAgreementName(fields.keyInfo)
	if err != nil {
		return nil, err
	}

	binding, exists := g.bindings[graphBinding{name, algorithm}]
	if !exists || nilcheck.IsNil(binding.ECDHRecipient) {
		return nil, ErrPolicy
	}

	options, err := g.graphAgreementOptions(binding)
	if err != nil {
		return nil, err
	}

	transport, err := ecdhDecryptKeyTransport(g.ctx, binding.ECDHRecipient, options, size)
	if err != nil {
		return nil, err
	}

	if transport.algorithm != algorithm {
		return nil, ErrPolicy
	}

	if fields.method.Valid() {
		if err := checkEncryptionMethod(g.ctx, fields.method, algorithm, transport.keyBits, false); err != nil {
			return nil, err
		}
	}

	info, err := graphAgreementInfo(fields.keyInfo)
	if err != nil {
		return nil, err
	}

	if err := transport.checkKeyInfo(g.ctx, info); err != nil {
		return nil, err
	}

	cipher, err := g.cipherPlan(node.document, fields.cipherData, transport.wrappedBytes)
	if err != nil {
		return nil, err
	}

	return &graphKeyPlan{algorithm: algorithm, keyBytes: size, cipher: cipher, unwrap: transport.unwrap}, nil
}

func graphAgreementName(info document.Element) (string, error) {
	if !graphAttributes(info, "Id") || !graphStructuralText(info) {
		return "", ErrFormat
	}

	methods, err := childElements(info, elementName(Namespace, "AgreementMethod"))
	if err != nil {
		return "", err
	}

	if attributeValue(methods[0], "Algorithm") != ECDHES {
		return "", ErrPolicy
	}

	for _, child := range methods[0].Children() {
		if child.Name() != elementName(Namespace, "RecipientKeyInfo") {
			continue
		}

		for _, hint := range child.Children() {
			if hint.Name() == elementName(SignatureNamespace, lexicon.DSigElementKeyName) {
				return graphNameText(hint)
			}
		}
	}

	return "", nil
}

func graphHasAgreement(info document.Element) bool {
	for _, child := range info.Children() {
		if child.Name() == elementName(Namespace, "AgreementMethod") {
			return true
		}
	}

	return false
}

// Graph ID indexing has already validated the original Id attributes. The
// strict leaf decoder receives a private structural view with only those
// supported schema attributes removed; caller nodes and namespaces are retained.
func graphAgreementInfo(info document.Element) (document.Element, error) {
	owner, node := tree.Unwrap(info)
	if !graphAttributes(info, "Id") || len(info.Children()) != 1 {
		return document.Element{}, ErrFormat
	}

	root := *node
	root.Attrs = nil

	root.Children = append([]*tree.Node(nil), node.Children...)
	for i, method := range root.Children {
		if method.Kind != tree.ElementNode {
			continue
		}

		cloned := *method

		cloned.Children = append([]*tree.Node(nil), method.Children...)
		for j, child := range cloned.Children {
			if child.Name != elementName(Namespace, "OriginatorKeyInfo") && child.Name != elementName(Namespace, "RecipientKeyInfo") {
				continue
			}

			if !graphAttributes(tree.Wrap(owner, child), "Id") {
				return document.Element{}, ErrFormat
			}

			header := *child
			header.Attrs = nil
			cloned.Children[j] = &header
		}

		root.Children[i] = &cloned
	}

	return tree.Wrap(owner, &root), nil
}
