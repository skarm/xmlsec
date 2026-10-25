package keyinfo

import (
	"fmt"

	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/internal/tree"
)

// Freeze the caller's allowlist into operation-local state before callbacks.
// This parallels XMLSec's enabledKeyData context without a global registry.
// Design reference: Aleksey Sanin and XMLSec contributors (MIT),
// docs/md/tutorial/using-contexts.md at commit 913a20d56dfb78279b5d181bb8cab2f4582ce3c1.
// This is an independent Go implementation; no upstream C code is copied.
func (p *parser) configureKeyData() error {
	if p.options.AllowedKeyData == nil {
		return nil
	}

	p.keyData = make(map[document.Name]bool)
	for _, name := range p.options.AllowedKeyData {
		switch name {
		case document.Name{Space: Namespace, Local: "KeyName"},
			document.Name{Space: Namespace, Local: nameDSAKeyValue},
			document.Name{Space: Namespace, Local: nameRSAKeyValue},
			document.Name{Space: Namespace11, Local: nameECKeyValue},
			document.Name{Space: Namespace11, Local: nameDEREncodedKeyValue},
			document.Name{Space: Namespace, Local: nameX509Data},
			document.Name{Space: Namespace, Local: "RetrievalMethod"},
			document.Name{Space: Namespace11, Local: nameKeyInfoReference}:
			if p.keyData[name] {
				return fmt.Errorf("%w: duplicate AllowedKeyData", ErrPolicy)
			}

			p.keyData[name] = true
		default:
			return fmt.Errorf("%w: unsupported AllowedKeyData {%s}%s", ErrPolicy, name.Space, name.Local)
		}
	}

	return nil
}

func (p *parser) requireKeyData(name document.Name) error {
	if p.keyData != nil && !p.keyData[name] {
		return fmt.Errorf("%w: key representation {%s}%s is disabled", ErrPolicy, name.Space, name.Local)
	}

	return nil
}

func (p *parser) checkKeyData(node *tree.Node) error {
	if is(node, Namespace, "KeyValue") {
		children, err := structure(node, Namespace, "KeyValue")
		if err != nil || len(children) != 1 {
			return ErrInput
		}

		return p.requireKeyData(children[0].Name)
	}

	return p.requireKeyData(node.Name)
}
