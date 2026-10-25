package xmlenc

import (
	"bytes"
	"context"
	"crypto"
	"encoding/hex"
	"strings"

	"github.com/skarm/xmlsec/internal/lexicon"

	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/internal/tree"
)

// These codecs implement XMLENC11 5.4.1's padding-count-prefixed hexBinary
// bitstrings. AgreementMethod and DerivedKey use the same representation.
func encodeConcatKDFParameters(ctx context.Context, parameters ConcatKDFParameters) (*tree.Node, error) {
	if ctx == nil {
		return nil, ErrPolicy
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	hash := parameters.Hash
	if hash == 0 {
		hash = crypto.SHA256
	}

	algorithm := SHA256
	if hash == crypto.SHA1 && parameters.AllowLegacy {
		algorithm = SHA1
	} else if hash != crypto.SHA256 {
		return nil, ErrPolicy
	}

	method := newElement(Namespace11, "xenc11", "KeyDerivationMethod")
	setAttribute(method, "Algorithm", ConcatKDF)

	params := newElement(Namespace11, "xenc11", "ConcatKDFParams")

	for _, field := range concatKDFFields(parameters) {
		if _, valid := concatFieldBits(field.value); !valid {
			return nil, ErrPolicy
		}

		if len(field.value) > 0 {
			setAttribute(params, field.name, hex.EncodeToString(field.value))
		}
	}

	digest := newElement(SignatureNamespace, "ds", lexicon.DSigElementDigestMethod)
	setAttribute(digest, "Algorithm", algorithm)
	appendChild(params, digest)
	appendChild(method, params)

	return method, ctx.Err()
}

func decodeConcatKDFParameters(ctx context.Context, method document.Element) (ConcatKDFParameters, error) {
	var parameters ConcatKDFParameters
	if ctx == nil {
		return parameters, ErrPolicy
	}

	if err := ctx.Err(); err != nil {
		return parameters, err
	}

	if method.Name() != elementName(Namespace11, "KeyDerivationMethod") || !exactAttributes(method, "Algorithm") || attributeValue(method, "Algorithm") != ConcatKDF {
		return parameters, ErrFormat
	}

	children, err := childElements(method, elementName(Namespace11, "ConcatKDFParams"))
	if err != nil || !graphAttributes(children[0], "AlgorithmID", "PartyUInfo", "PartyVInfo", "SuppPubInfo", "SuppPrivInfo") {
		return parameters, ErrFormat
	}

	digests, err := childElements(children[0], elementName(SignatureNamespace, lexicon.DSigElementDigestMethod))
	if err != nil || !exactAttributes(digests[0], "Algorithm") || len(digests[0].Children()) != 0 || !xmlSpace(digests[0].Text()) {
		return parameters, ErrFormat
	}

	switch attributeValue(digests[0], "Algorithm") {
	case SHA256:
		parameters.Hash = crypto.SHA256
	case SHA1:
		parameters.Hash = crypto.SHA1
	default:
		return parameters, ErrPolicy
	}

	fields := []*[]byte{&parameters.AlgorithmID, &parameters.PartyUInfo, &parameters.PartyVInfo, &parameters.SuppPubInfo, &parameters.SuppPrivInfo}
	for index, field := range concatKDFFields(parameters) {
		if err := ctx.Err(); err != nil {
			return ConcatKDFParameters{}, err
		}

		value := strings.Trim(attributeValue(children[0], field.name), " \t\r\n")
		if len(value) > 8194 {
			return ConcatKDFParameters{}, ErrPolicy
		}

		decoded, err := hex.DecodeString(value)
		if err != nil {
			return ConcatKDFParameters{}, ErrFormat
		}

		if _, valid := concatFieldBits(decoded); !valid {
			return ConcatKDFParameters{}, ErrFormat
		}

		*fields[index] = decoded
	}

	return parameters, ctx.Err()
}

func concatKDFFields(parameters ConcatKDFParameters) []struct {
	name  string
	value []byte
} {
	return []struct {
		name  string
		value []byte
	}{
		{"AlgorithmID", parameters.AlgorithmID},
		{"PartyUInfo", parameters.PartyUInfo},
		{"PartyVInfo", parameters.PartyVInfo},
		{"SuppPubInfo", parameters.SuppPubInfo},
		{"SuppPrivInfo", parameters.SuppPrivInfo},
	}
}

func sameConcatKDFParameters(actual, expected ConcatKDFParameters) bool {
	normalHash := func(hash crypto.Hash) crypto.Hash {
		if hash == 0 {
			return crypto.SHA256
		}

		return hash
	}
	if normalHash(actual.Hash) != normalHash(expected.Hash) {
		return false
	}

	a, b := concatKDFFields(actual), concatKDFFields(expected)
	for index := range a {
		x, validX := concatFieldBits(a[index].value)

		y, validY := concatFieldBits(b[index].value)
		if !validX || !validY || x != y || x != 0 && !bytes.Equal(a[index].value, b[index].value) {
			return false
		}
	}

	return true
}

func graphAttributes(element document.Element, allowed ...string) bool {
	_, node := tree.Unwrap(element)
	if node == nil {
		return false
	}

	for _, attribute := range node.Attrs {
		found := false

		for _, name := range allowed {
			if attribute.Name == (document.Name{Local: name}) {
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
