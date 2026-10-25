package keyinfo

import (
	"fmt"

	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/internal/lexicon"
	"github.com/skarm/xmlsec/internal/tree"
)

// configureKeyData copies the caller's allowed key representations into
// operation-local state before callbacks. Nil permits the default set; an explicit
// empty list permits none. Duplicate or unsupported names fail policy validation.
//
// This follows XMLSec's enabledKeyData context model. Design reference: Aleksey Sanin
// and XMLSec contributors (MIT), docs/md/tutorial/using-contexts.md at commit
// 913a20d56dfb78279b5d181bb8cab2f4582ce3c1. This is an independent Go implementation;
// no upstream C code is copied.
func (p *parser) configureKeyData() error {
	if p.options.AllowedKeyData == nil {
		return nil
	}

	p.keyData = make(map[document.Name]struct{})
	for _, name := range p.options.AllowedKeyData {
		switch name {
		case document.Name{Space: Namespace, Local: lexicon.DSigElementKeyName},
			document.Name{Space: Namespace, Local: nameDSAKeyValue},
			document.Name{Space: Namespace, Local: nameRSAKeyValue},
			document.Name{Space: Namespace11, Local: nameECKeyValue},
			document.Name{Space: Namespace11, Local: nameDEREncodedKeyValue},
			document.Name{Space: Namespace, Local: nameX509Data},
			document.Name{Space: Namespace, Local: "RetrievalMethod"},
			document.Name{Space: Namespace11, Local: nameKeyInfoReference}:
			if _, exists := p.keyData[name]; exists {
				return fmt.Errorf("%w: duplicate AllowedKeyData", ErrPolicy)
			}

			p.keyData[name] = struct{}{}
		default:
			return fmt.Errorf("%w: unsupported AllowedKeyData {%s}%s", ErrPolicy, name.Space, name.Local)
		}
	}

	return nil
}

// requireKeyData rejects a representation absent from an explicit allowlist. Nil
// operation-local policy permits the default representations.
func (p *parser) requireKeyData(name document.Name) error {
	if _, allowed := p.keyData[name]; p.keyData != nil && !allowed {
		return fmt.Errorf("%w: key representation {%s}%s is disabled", ErrPolicy, name.Space, name.Local)
	}

	return nil
}

// checkKeyData checks the selected key representation against policy, unwrapping the
// single required KeyValue child when present.
func (p *parser) checkKeyData(node *tree.Node) error {
	if is(node, Namespace, lexicon.DSigElementKeyValue) {
		children, err := structure(node, Namespace, lexicon.DSigElementKeyValue)
		if err != nil || len(children) != 1 {
			return ErrInput
		}

		return p.requireKeyData(children[0].Name)
	}

	return p.requireKeyData(node.Name)
}
