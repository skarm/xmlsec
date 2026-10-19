// Derived from lestrrat-go/helium at 7362c0a70122a757780f4d0b545a9b370dead6ab.
// Copyright (c) 2015 lestrrat. MIT License; see licenses/MIT-helium.txt at the repository root.

package xdm

import (
	"strings"
)

// StringValue returns the XPath 1.0/3.1 string value without a byte conversion.
// Elements and documents concatenate descendant text, excluding comments and PIs;
// other node kinds return their own character data.
func StringValue(n Node) string {
	// Check Attribute by type assertion first since etype may not be set
	if attr, ok := n.(*Attribute); ok {
		return attr.Value()
	}

	switch n.Type() {
	case DocumentNode, ElementNode, TextNode, CDATASectionNode, CommentNode,
		ProcessingInstructionNode, NamespaceNode:
		return CharacterData(n)
	}

	return ""
}

// LocalNameOf returns the local name of any node type.
func LocalNameOf(n Node) string {
	switch v := n.(type) {
	case *Element:
		return v.LocalName()
	case *Attribute:
		ln := v.LocalName()
		if _, after, ok := strings.Cut(ln, ":"); ok {
			return after
		}

		return ln
	case *ProcessingInstruction:
		return v.Name()
	case *NamespaceNodeWrapper:
		return v.Name()
	default:
		// Document, text, comment nodes have no local name per XPath spec
		return ""
	}
}

// NodeNamespaceURI returns the namespace URI of any node type.
func NodeNamespaceURI(n Node) string {
	type urier interface {
		URI() string
	}
	if u, ok := n.(urier); ok {
		return u.URI()
	}

	return ""
}

// NodePrefix returns the namespace prefix of any node type.
func NodePrefix(n Node) string {
	type prefixer interface {
		Prefix() string
	}
	if p, ok := n.(prefixer); ok {
		return p.Prefix()
	}

	return ""
}
