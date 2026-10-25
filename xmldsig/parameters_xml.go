package xmldsig

import (
	"crypto"
	"fmt"
	"strconv"
	"strings"

	"github.com/skarm/xmlsec/internal/lexicon"

	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/internal/tree"
)

func pssElement(n *tree.Node, local string) bool {
	return n != nil && n.Kind == tree.ElementNode && n.Name == (document.Name{Space: PSSNamespace, Local: local})
}

func newPSS(local string) *tree.Node {
	return &tree.Node{Kind: tree.ElementNode, Name: document.Name{Space: PSSNamespace, Local: local}, Prefix: "pss"}
}

// xmlInteger accepts the XML Schema signed integer lexical form, but bounds
// input before converting. Comments cannot splice a security parameter.
func xmlInteger(n *tree.Node) (int, error) {
	if err := attributes(n); err != nil {
		return 0, err
	}

	var value strings.Builder

	for _, c := range n.Children {
		if c.Kind != tree.TextNode {
			return 0, fmt.Errorf("%w: integer must contain only text", ErrStructure)
		}

		if value.Len()+len(c.Data) > 64 {
			return 0, fmt.Errorf("%w: integer too long", ErrStructure)
		}

		value.WriteString(c.Data)
	}

	v := strings.Trim(value.String(), " \t\r\n")

	number, err := strconv.ParseInt(v, 10, 32)
	if err != nil {
		return 0, fmt.Errorf("%w: invalid integer", ErrStructure)
	}

	return int(number), nil
}

func parseSignatureMethod(n *tree.Node, p Policy) (signatureSpec, error) {
	children, err := structure(n, lexicon.DSigElementSignatureMethod, "Algorithm")
	if err != nil {
		return signatureSpec{}, err
	}

	method, err := requiredAttribute(n, "Algorithm")
	if err != nil {
		return signatureSpec{}, err
	}

	params := SignatureParameters{}

	if method == RSAPSS {
		if len(children) > 1 {
			return signatureSpec{}, fmt.Errorf("%w: repeated RSA-PSS parameters", ErrStructure)
		}

		if len(children) == 1 {
			params.PSS, err = parsePSS(children[0])
			if err != nil {
				return signatureSpec{}, err
			}
		}
	} else if _, ok := macHash(method); ok {
		if len(children) > 1 || len(children) == 1 && !isDS(children[0], "HMACOutputLength") {
			return signatureSpec{}, fmt.Errorf("%w: HMAC parameters", ErrStructure)
		}

		if len(children) == 1 {
			params.HMACOutputLength, err = xmlInteger(children[0])
			if err != nil {
				return signatureSpec{}, err
			}

			if params.HMACOutputLength <= 0 {
				return signatureSpec{}, fmt.Errorf("%w: explicit nonpositive HMAC output length", ErrPolicy)
			}
		}
	} else if len(children) != 0 {
		return signatureSpec{}, fmt.Errorf("%w: parameters on a fixed SignatureMethod", ErrAlgorithm)
	}

	spec, err := normalizeSignatureSpec(method, params)
	if err == nil {
		err = spec.validatePolicy(p)
	}

	return spec, err
}

func parsePSS(n *tree.Node) (*PSSParameters, error) {
	if !pssElement(n, "RSAPSSParams") {
		return nil, fmt.Errorf("%w: expected pss:RSAPSSParams", ErrStructure)
	}

	if err := attributes(n); err != nil {
		return nil, err
	}

	children, err := elementChildren(n)
	if err != nil {
		return nil, err
	}

	p := PSSParameters{Hash: crypto.SHA256, TrailerField: 1}

	pos := 0
	if pos < len(children) && isDS(children[pos], lexicon.DSigElementDigestMethod) {
		uri, err := simpleAlgorithm(children[pos], lexicon.DSigElementDigestMethod)
		if err != nil {
			return nil, err
		}

		p.Hash, err = hashForDigest(uri)
		if err != nil {
			return nil, err
		}

		pos++
	}

	p.MGFHash = p.Hash

	if pos < len(children) && pssElement(children[pos], "MaskGenerationFunction") {
		mgf := children[pos]
		pos++

		p.MGFHash, err = parseMGFHash(mgf, p.MGFHash)
		if err != nil {
			return nil, err
		}
	}

	p.SaltLength = p.Hash.Size()
	if pos < len(children) && pssElement(children[pos], "SaltLength") {
		p.SaltLength, err = xmlInteger(children[pos])
		if err != nil {
			return nil, err
		}

		pos++
	}

	if pos < len(children) && pssElement(children[pos], "TrailerField") {
		p.TrailerField, err = xmlInteger(children[pos])
		if err != nil {
			return nil, err
		}

		pos++

		if p.TrailerField != 1 {
			return nil, fmt.Errorf("%w: only trailer field 1 is supported", ErrAlgorithm)
		}
	}

	if pos != len(children) {
		return nil, fmt.Errorf("%w: unexpected or out-of-order RSA-PSS parameter", ErrStructure)
	}

	return &p, nil
}

func signatureMethodNode(method string, params SignatureParameters) (*tree.Node, error) {
	spec, err := normalizeSignatureSpec(method, params)
	if err != nil {
		return nil, err
	}

	sm := newDS(lexicon.DSigElementSignatureMethod)
	setAttr(sm, "Algorithm", method)
	// Keep omission vs explicit defaults stable in a caller's template. When
	// supplied, emit every effective PSS parameter to avoid ambiguous output.
	if spec.pss != nil && params.PSS != nil {
		p := spec.pss
		root := newPSS("RSAPSSParams")
		root.NS = []tree.Namespace{{Prefix: "pss", URI: PSSNamespace}}
		dm := newDS(lexicon.DSigElementDigestMethod)
		uri, _ := digestURI(p.Hash)
		setAttr(dm, "Algorithm", uri)
		add(root, dm)

		mgf := newPSS("MaskGenerationFunction")
		setAttr(mgf, "Algorithm", MGF1)

		md := newDS(lexicon.DSigElementDigestMethod)
		uri, _ = digestURI(p.MGFHash)
		setAttr(md, "Algorithm", uri)
		add(mgf, md)
		add(root, mgf)

		salt := newPSS("SaltLength")
		text(salt, strconv.Itoa(p.SaltLength))
		add(root, salt)

		trailer := newPSS("TrailerField")
		text(trailer, "1")
		add(root, trailer)
		add(sm, root)
	}

	if spec.hmacBits != 0 && params.HMACOutputLength != 0 {
		length := newDS("HMACOutputLength")
		text(length, strconv.Itoa(spec.hmacBits))
		add(sm, length)
	}

	return sm, nil
}

func parseMGFHash(mgf *tree.Node, fallback crypto.Hash) (crypto.Hash, error) {
	hash := fallback
	if err := attributes(mgf, "Algorithm"); err != nil {
		return fallback, err
	}

	if uri, exists := getAttr(mgf, document.Name{Local: "Algorithm"}); exists && uri != MGF1 {
		return fallback, fmt.Errorf("%w: unsupported mask generation function", ErrAlgorithm)
	}

	inner, err := elementChildren(mgf)
	if err != nil {
		return fallback, err
	}

	if len(inner) > 1 {
		return fallback, fmt.Errorf("%w: repeated MGF DigestMethod", ErrStructure)
	}

	if len(inner) == 1 {
		uri, err := simpleAlgorithm(inner[0], lexicon.DSigElementDigestMethod)
		if err != nil {
			return fallback, err
		}

		hash, err = hashForDigest(uri)
		if err != nil {
			return fallback, err
		}
	}

	return hash, nil
}
