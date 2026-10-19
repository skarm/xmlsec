package xmlenc

import (
	"bytes"
	"context"
	"crypto"
	"encoding/base64"

	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/internal/tree"
)

func normalizeOAEP(parameters *OAEPParameters) (OAEPParameters, error) {
	p := OAEPParameters{Hash: crypto.SHA256}
	if parameters != nil {
		p = *parameters
		if p.Hash == 0 {
			p.Hash = crypto.SHA256
		}

		if len(p.Label) > 1024 {
			return OAEPParameters{}, ErrPolicy
		}

		p.Label = bytes.Clone(p.Label)
	}

	if p.Hash != crypto.SHA256 && p.Hash != crypto.SHA384 && p.Hash != crypto.SHA512 {
		return OAEPParameters{}, ErrPolicy
	}

	return p, nil
}

func oaepURIs(hash crypto.Hash) (string, string) {
	switch hash {
	case crypto.SHA384:
		return SHA384, MGF1SHA384
	case crypto.SHA512:
		return SHA512, MGF1SHA512
	default:
		return SHA256, MGF1SHA256
	}
}

func encodeOAEP(method *tree.Node, p OAEPParameters) {
	if len(p.Label) != 0 {
		label := encryptedElement("OAEPparams")
		appendChild(label, &tree.Node{Kind: tree.TextNode, Data: base64.StdEncoding.EncodeToString(p.Label)})
		appendChild(method, label)
	}

	digestURI, mgfURI := oaepURIs(p.Hash)
	digest := newElement(SignatureNamespace, "ds", "DigestMethod")
	setAttribute(digest, "Algorithm", digestURI)

	mgf := newElement(Namespace11, "xenc11", "MGF")
	setAttribute(mgf, "Algorithm", mgfURI)
	appendChild(method, digest)
	appendChild(method, mgf)
}

func checkOAEP(ctx context.Context, method document.Element, expected OAEPParameters) error {
	// Algorithm-specific parameters are in xs:any; their order is not fixed.
	_, node := tree.Unwrap(method)
	for _, child := range node.Children {
		if child.Kind == tree.TextNode && !xmlSpace(child.Data) {
			return ErrFormat
		}
	}

	digestURI, mgfURI := oaepURIs(expected.Hash)
	digest, mgf, label := false, false, false

	for _, child := range method.Children() {
		switch child.Name() {
		case elementName(SignatureNamespace, "DigestMethod"):
			if digest || !matchesMethod(child, digestURI, true) {
				return ErrFormat
			}

			digest = true
		case elementName(Namespace11, "MGF"):
			if mgf || !matchesMethod(child, mgfURI, true) {
				return ErrFormat
			}

			mgf = true
		case elementName(Namespace, "OAEPparams"):
			if label || !exactAttributes(child) || len(child.Children()) != 0 {
				return ErrFormat
			}

			value, err := decodeBase64Text(ctx, child, 1024)
			if err != nil {
				return err
			}

			if !bytes.Equal(value, expected.Label) {
				return ErrFormat
			}

			label = true
		default:
			return ErrFormat
		}
	}

	if !digest || !mgf || len(expected.Label) != 0 && !label {
		return ErrFormat
	}

	return nil
}
