package protocol

import (
	"context"
	"strings"

	"github.com/skarm/xmlsec/c14n"
	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/internal/lexicon"
	"github.com/skarm/xmlsec/internal/tree"
	"github.com/skarm/xmlsec/internal/xmlchar"
	"github.com/skarm/xmlsec/saml/internal/xmlutil"
)

// Rich SAML XML can contain QName-valued content (xsi:type, xs:QName or an
// application datatype). Its namespace bindings must not remain outside the
// digest. A superset PrefixList preserves these bindings without guessing a
// custom datatype's semantics. Inclusive C14N already includes those bindings.
func namespaceSigningKey(target document.Element, key SigningKey) SigningKey {
	if key.Canonicalization != "" && key.Canonicalization != c14n.Exclusive {
		return key
	}

	prefixes := append([]string{lexicon.C14NDefaultPrefixToken}, key.InclusivePrefixes...)
	seen := map[string]bool{}

	_, root := tree.Unwrap(target)
	for n := root; n != nil; n = n.Parent {
		for _, ns := range n.NS {
			prefixes = append(prefixes, ns.Prefix)
		}
	}

	stack := []*tree.Node{root}
	for len(stack) > 0 {
		n := stack[len(stack)-1]
		stack = stack[:len(stack)-1]

		for _, ns := range n.NS {
			prefixes = append(prefixes, ns.Prefix)
		}

		stack = append(stack, n.Children...)
	}

	key.InclusivePrefixes = nil

	for _, prefix := range prefixes {
		if prefix == "" {
			prefix = lexicon.C14NDefaultPrefixToken
		}

		if prefix == lexicon.PrefixXML || seen[prefix] {
			continue
		}

		seen[prefix] = true
		key.InclusivePrefixes = append(key.InclusivePrefixes, prefix)
	}

	return key
}

func signRichExchange(ctx context.Context, n *tree.Node, key SigningKey, encryption *EncryptionOptions) (*document.Document, error) {
	d, err := xmlutil.Document(ctx, n)
	if err != nil {
		return nil, err
	}

	return signExchange(ctx, n, namespaceSigningKey(d.Root(), key), encryption)
}

func hasInclusiveNamespaces(e document.Element) bool {
	for _, s := range e.Children() {
		if s.Name() != xmlutil.Name(xmlutil.DS, lexicon.DSigElementSignature) {
			continue
		}

		for _, info := range s.Children() {
			if info.Name() != xmlutil.Name(xmlutil.DS, lexicon.DSigElementSignedInfo) {
				continue
			}

			for _, method := range info.Children() {
				for _, child := range method.Children() {
					if child.Name() == xmlutil.Name(c14n.Exclusive, lexicon.C14NElementInclusiveNamespaces) {
						return true
					}
				}
			}
		}
	}

	return false
}

func valuePrefixes(elements ...document.Element) []string {
	prefixes := []string{lexicon.C14NDefaultPrefixToken}
	seen := map[string]bool{lexicon.C14NDefaultPrefixToken: true}

	for _, e := range elements {
		_, n := tree.Unwrap(e)

		stack := []*tree.Node{n}
		for len(stack) > 0 {
			current := stack[len(stack)-1]
			stack = stack[:len(stack)-1]

			for _, s := range appendAttributeValues(current) {
				for token := range strings.FieldsSeq(s) {
					prefix, local, ok := strings.Cut(token, ":")
					if ok && xmlchar.IsValidNCName(prefix) && xmlchar.IsValidNCName(local) && !seen[prefix] {
						seen[prefix] = true
						prefixes = append(prefixes, prefix)
					}
				}
			}

			stack = append(stack, current.Children...)
		}
	}

	return prefixes
}

func appendAttributeValues(n *tree.Node) []string {
	values := make([]string, 0, len(n.Attrs)+1)

	values = append(values, n.Data)
	for _, a := range n.Attrs {
		values = append(values, a.Value)
	}

	return values
}
