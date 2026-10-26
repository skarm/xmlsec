package xmlutil

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/internal/lexicon"
	"github.com/skarm/xmlsec/internal/tree"
	"github.com/skarm/xmlsec/saml/internal/profile"
)

// Assertion identifies the Assertion algorithm or protocol URI.
const Assertion = lexicon.NamespaceSAMLAssertion

// Protocol is the SAML 2.0 protocol namespace URI.
const Protocol = lexicon.NamespaceSAMLProtocol

// Metadata identifies the Metadata algorithm or protocol URI.
const Metadata = lexicon.NamespaceSAMLMetadata

// DS identifies the DS algorithm or protocol URI.
const DS = lexicon.NamespaceDSig

// Name constructs an expanded XML name.
func Name(ns, local string) document.Name { return document.Name{Space: ns, Local: local} }

// Attr returns an unqualified attribute value, or an empty string when absent.
func Attr(e document.Element, n string) string {
	s, _ := e.Attribute(document.Name{Local: n})
	return s
}

// BoolAttr reads an optional xs:boolean attribute, defaulting to false only
// when absent. An explicitly empty value is outside the boolean lexical space.
func BoolAttr(e document.Element, n string) (bool, error) {
	s, present := e.Attribute(document.Name{Local: n})
	if !present {
		return false, nil
	}

	return profile.Bool(s)
}

// Attrs requires the listed attributes and rejects undeclared attributes.
func Attrs(e document.Element, required, optional []string) error {
	seen := make(map[string]struct{})

	for _, a := range e.Attributes() {
		if a.Name.Space != "" {
			return profile.ErrSchema
		}

		ok := slices.Contains(required, a.Name.Local) || slices.Contains(optional, a.Name.Local)
		if !ok {
			return profile.ErrSchema
		}

		seen[a.Name.Local] = struct{}{}
	}

	for _, n := range required {
		if _, exists := seen[n]; !exists {
			return profile.ErrSchema
		}
	}

	return nil
}

// Space reports whether s contains only XML whitespace.
func Space(s string) bool {
	for _, r := range s {
		if r != ' ' && r != '\r' && r != '\n' && r != '\t' {
			return false
		}
	}

	return true
}

// Children returns direct element children and rejects non-whitespace mixed content.
func Children(e document.Element) ([]document.Element, error) {
	_, n := tree.Unwrap(e)
	if n == nil {
		return nil, profile.ErrSchema
	}

	for _, c := range n.Children {
		if c.Kind == tree.TextNode && !Space(c.Data) {
			return nil, profile.ErrSchema
		}
	}

	return e.Children(), nil
}

// Simple returns bounded simple text and rejects child elements and attributes.
func Simple(e document.Element, maximum int) (string, error) {
	if len(e.Attributes()) != 0 {
		return "", profile.ErrSchema
	}

	return SimpleText(e, maximum)
}

// SimpleText returns bounded direct text, ignoring comments/PIs and rejecting
// child elements. Attributes are validated separately by the caller.
func SimpleText(e document.Element, maximum int) (string, error) {
	if maximum < 0 || len(e.Children()) != 0 {
		return "", profile.ErrSchema
	}

	_, node := tree.Unwrap(e)
	if node == nil {
		return "", profile.ErrSchema
	}

	length := 0

	var single string

	segments := 0

	for _, child := range node.Children {
		if child.Kind != tree.TextNode {
			continue
		}

		if len(child.Data) > maximum-length {
			return "", profile.ErrSchema
		}

		length += len(child.Data)
		single = child.Data
		segments++
	}

	if segments < 2 {
		return single, nil
	}

	var out strings.Builder
	out.Grow(length)

	for _, child := range node.Children {
		if child.Kind == tree.TextNode {
			out.WriteString(child.Data)
		}
	}

	return out.String(), nil
}

// EmptyContent reports whether content contains only XML whitespace, comments
// and processing instructions, without joining text segments.
func EmptyContent(e document.Element) bool {
	_, node := tree.Unwrap(e)
	if node == nil {
		return false
	}

	for _, child := range node.Children {
		switch child.Kind {
		case tree.TextNode:
			if !Space(child.Data) {
				return false
			}
		case tree.CommentNode, tree.PINode:
		default:
			return false
		}
	}

	return true
}

// Node creates a private SAML element draft.
func Node(prefix, ns, local string) *tree.Node {
	return &tree.Node{Kind: tree.ElementNode, Prefix: prefix, Name: document.Name{Space: ns, Local: local}}
}

// Set sets an unqualified attribute on a private draft.
func Set(n *tree.Node, k, v string) {
	n.Attrs = append(n.Attrs, tree.Attribute{Name: document.Name{Local: k}, Value: v})
}

// Add attaches an owned child to a private draft.
func Add(n, c *tree.Node) { c.Parent = n; n.Children = append(n.Children, c) }

// Text adds text to a private draft.
func Text(n *tree.Node, s string) { Add(n, &tree.Node{Kind: tree.TextNode, Data: s}) }

// Document serializes and reparses a private draft to publish an immutable XML snapshot.
func Document(ctx context.Context, root *tree.Node) (*document.Document, error) {
	d := tree.FromNodes([]*tree.Node{root}, document.DefaultLimits())

	return tree.Reparse(ctx, d, document.DefaultLimits())
}

// Direct selects exactly one direct child with the required expanded name.
func Direct(e document.Element, n document.Name) (document.Element, error) {
	var out document.Element

	for _, c := range e.Children() {
		if c.Name() == n {
			if out.Valid() {
				return document.Element{}, profile.ErrSchema
			}

			out = c
		}
	}

	if !out.Valid() {
		return out, fmt.Errorf("%w: missing %s", profile.ErrSchema, n.Local)
	}

	return out, nil
}

// XMLLimits fills individual unset budgets without weakening supplied limits.
func XMLLimits(l document.Limits, capacity int) document.Limits {
	d := document.DefaultLimits()

	if l.MaxBytes == 0 || l.MaxBytes > capacity {
		l.MaxBytes = capacity
	}

	if l.MaxDepth == 0 {
		l.MaxDepth = d.MaxDepth
	}

	if l.MaxNodes == 0 {
		l.MaxNodes = d.MaxNodes
	}

	if l.MaxAttributesPerElement == 0 {
		l.MaxAttributesPerElement = d.MaxAttributesPerElement
	}

	if l.MaxInScopeNamespaces == 0 {
		l.MaxInScopeNamespaces = d.MaxInScopeNamespaces
	}

	if l.MaxNodeSetNodes == 0 {
		l.MaxNodeSetNodes = d.MaxNodeSetNodes
	}

	return l
}
