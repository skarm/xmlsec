package xmlenc

import (
	"bytes"
	"context"
	"crypto"
	"crypto/fips140"
	"encoding/base64"

	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/internal/lexicon"
	"github.com/skarm/xmlsec/internal/tree"
)

func normalizeOAEP(parameters *OAEPParameters) (OAEPParameters, error) {
	p := OAEPParameters{}
	if parameters != nil {
		p = *parameters
	}

	if p.Algorithm == "" {
		p.Algorithm = RSAOAEP
	}

	if p.Hash == 0 {
		p.Hash = crypto.SHA256
	}

	if p.MGFHash == 0 {
		p.MGFHash = p.Hash
		if p.Algorithm == RSAOAEP10 {
			p.MGFHash = crypto.SHA1
		}
	}

	if !rsaOAEPAlgorithm(p.Algorithm) || p.Algorithm == RSAOAEP10 && p.MGFHash != crypto.SHA1 ||
		!oaepHash(p.Hash) || !oaepHash(p.MGFHash) || len(p.Label) > 1024 {
		return OAEPParameters{}, ErrPolicy
	}

	if p.Algorithm == RSAOAEP10 || p.Hash == crypto.SHA1 || p.MGFHash == crypto.SHA1 {
		if !p.AllowLegacy || fips140.Enabled() {
			return OAEPParameters{}, ErrPolicy
		}
	}

	p.Label = bytes.Clone(p.Label)

	return p, nil
}

func rsaOAEPAlgorithm(algorithm string) bool { return algorithm == RSAOAEP || algorithm == RSAOAEP10 }

func oaepHash(hash crypto.Hash) bool {
	return hash == crypto.SHA1 || hash == crypto.SHA224 || hash == crypto.SHA256 || hash == crypto.SHA384 || hash == crypto.SHA512
}

func oaepURIs(hash crypto.Hash) (string, string) {
	switch hash {
	case crypto.SHA1:
		return SHA1, MGF1SHA1
	case crypto.SHA224:
		return SHA224, MGF1SHA224
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

	digestURI, _ := oaepURIs(p.Hash)
	digest := newElement(SignatureNamespace, "ds", lexicon.DSigElementDigestMethod)
	setAttribute(digest, "Algorithm", digestURI)

	appendChild(method, digest)

	if p.Algorithm == RSAOAEP {
		_, mgfURI := oaepURIs(p.MGFHash)
		mgf := newElement(Namespace11, "xenc11", "MGF")
		setAttribute(mgf, "Algorithm", mgfURI)
		appendChild(method, mgf)
	}
}

func checkOAEP(ctx context.Context, method document.Element, expected OAEPParameters) error {
	// OAEPparams precedes the xs:any extension point. DigestMethod and MGF
	// occupy that extension point and may appear in either relative order.
	_, node := tree.Unwrap(method)
	for _, child := range node.Children {
		if child.Kind == tree.TextNode && !xmlSpace(child.Data) {
			return ErrFormat
		}
	}

	digestURI, _ := oaepURIs(expected.Hash)
	_, mgfURI := oaepURIs(expected.MGFHash)
	digest, mgf, label := false, false, false

	for _, child := range method.Children() {
		switch child.Name() {
		case elementName(Namespace, "KeySize"):
			// The common EncryptionMethod checker validated value and order.
			continue
		case elementName(SignatureNamespace, lexicon.DSigElementDigestMethod):
			if digest || !matchesMethod(child, digestURI, true) {
				return ErrFormat
			}

			digest = true
		case elementName(Namespace11, "MGF"):
			if expected.Algorithm == RSAOAEP10 || mgf || !matchesMethod(child, mgfURI, true) {
				return ErrFormat
			}

			mgf = true
		case elementName(Namespace, "OAEPparams"):
			if label || digest || mgf {
				return ErrFormat
			}

			if err := checkOAEPLabel(ctx, child, expected.Label); err != nil {
				return err
			}

			label = true
		default:
			return ErrFormat
		}
	}

	if !digest && expected.Hash != crypto.SHA1 || !mgf && expected.MGFHash != crypto.SHA1 || len(expected.Label) != 0 && !label {
		return ErrFormat
	}

	return nil
}

func checkOAEPLabel(ctx context.Context, child document.Element, expected []byte) error {
	if !exactAttributes(child) || len(child.Children()) != 0 {
		return ErrFormat
	}

	value, err := decodeBase64Text(ctx, child, 1024)
	if err != nil {
		return err
	}

	if !bytes.Equal(value, expected) {
		return ErrFormat
	}

	return nil
}
