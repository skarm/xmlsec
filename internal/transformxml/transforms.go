// Package transformxml shares transform XML between XMLDSig and KeyInfo.
package transformxml

import (
	"bytes"
	"context"
	"fmt"
	"maps"
	"slices"
	"sort"
	"strings"

	"github.com/skarm/xmlsec/c14n"
	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/internal/tree"
	"github.com/skarm/xmlsec/reference"
)

const Namespace = "http://www.w3.org/2000/09/xmldsig#"

func ParseProgram(ctx context.Context, n *tree.Node, doc *document.Document) (reference.Transform, error) {
	var t reference.Transform

	children, err := structure(n, "Transform", "Algorithm")
	if err != nil {
		return t, err
	}

	t.Algorithm, err = requiredAttribute(n, "Algorithm")
	if err != nil {
		return t, err
	}

	if err := parseTransformContent(ctx, &t, children, doc); err != nil {
		return t, err
	}

	if err = reference.ValidateTransformParameters(t); err != nil {
		return t, err
	}

	return t, nil
}

func standaloneTransformXML(ctx context.Context, doc *document.Document, n *tree.Node) ([]byte, error) {
	d := tree.FromNodes([]*tree.Node{tree.ImportSubtree(n)}, tree.Policy(doc))

	var output bytes.Buffer
	if _, err := d.WriteXML(ctx, &output, 1<<20); err != nil {
		return nil, err
	}

	return output.Bytes(), nil
}

func AppendProgram(ctx context.Context, n *tree.Node, t reference.Transform) error {
	if err := reference.ValidateTransformParameters(t); err != nil {
		return err
	}

	if t.Algorithm == reference.XSLT {
		d, err := document.Parse(ctx, t.Stylesheet, document.DefaultLimits())
		if err != nil {
			return err
		}

		add(n, tree.ImportSubtree(tree.Root(d)))

		return nil
	}

	for _, x := range t.XPath {
		ns, prefix := Namespace, "ds"
		if t.Algorithm == reference.XPathFilter2 {
			ns, prefix = reference.XPathFilter2, "xf"
		}

		if u, ok := x.Namespaces[prefix]; ok && u != ns {
			return fmt.Errorf("%w: reserved transform prefix %s", reference.ErrPolicy, prefix)
		}

		child := &tree.Node{Kind: tree.ElementNode, Name: document.Name{Space: ns, Local: "XPath"}, Prefix: prefix}
		bindings := make(map[string]string, len(x.Namespaces)+1)
		maps.Copy(bindings, x.Namespaces)
		bindings[prefix] = ns

		keys := make([]string, 0, len(bindings))
		for p := range bindings {
			keys = append(keys, p)
		}

		sort.Strings(keys)

		for _, p := range keys {
			if p != "xml" {
				child.NS = append(child.NS, tree.Namespace{Prefix: p, URI: bindings[p]})
			}
		}

		if x.Filter != "" {
			setAttr(child, "Filter", x.Filter)
		}

		text(child, x.Expression)
		add(n, child)
	}

	return nil
}

func parseTransformContent(ctx context.Context, t *reference.Transform, children []*tree.Node, doc *document.Document) error {
	if t.Algorithm == reference.XSLT {
		if len(children) != 1 {
			return reference.ErrInput
		}

		var err error

		t.Stylesheet, err = standaloneTransformXML(ctx, doc, children[0])

		return err
	}

	for _, node := range children {
		parameter, err := parseXPathParameter(ctx, node, doc, t.Algorithm)
		if err != nil {
			return err
		}

		t.XPath = append(t.XPath, parameter)
	}

	return nil
}

func parseXPathParameter(ctx context.Context, n *tree.Node, doc *document.Document, algorithm string) (reference.XPathExpression, error) {
	ns := Namespace
	if algorithm == reference.XPathFilter2 {
		ns = reference.XPathFilter2
	}

	if n.Name != (document.Name{Space: ns, Local: "XPath"}) {
		return reference.XPathExpression{}, fmt.Errorf("%w: XPath element namespace", reference.ErrInput)
	}

	x := reference.XPathExpression{Namespaces: make(map[string]string), Here: tree.Wrap(doc, n)}

	var err error
	if algorithm == reference.XPathFilter2 {
		err = attributes(n, "Filter")
		x.Filter, _ = getAttr(n, document.Name{Local: "Filter"})
	} else {
		err = attributes(n)
	}

	if err != nil {
		return x, err
	}

	length := 0

	for _, child := range n.Children {
		if err := ctx.Err(); err != nil {
			return x, err
		}

		switch child.Kind {
		case tree.TextNode:
			if len(child.Data) > (16<<10)-length {
				return x, reference.ErrLimit
			}

			length += len(child.Data)
		case tree.CommentNode, tree.PINode:
		default:
			return x, reference.ErrInput
		}
	}

	var expression strings.Builder
	expression.Grow(length)

	for _, child := range n.Children {
		if err := ctx.Err(); err != nil {
			return x, err
		}

		if child.Kind == tree.TextNode {
			expression.WriteString(child.Data)
		}
	}

	x.Expression = expression.String()

	for _, binding := range tree.Wrap(doc, n).NamespaceNodes() {
		x.Namespaces[binding.Name().Local] = binding.Value()
	}

	return x, nil
}

func ParseCanonical(n *tree.Node, local string) (reference.Transform, error) {
	children, err := structure(n, local, "Algorithm")
	if err != nil {
		return reference.Transform{}, err
	}

	uri, err := requiredAttribute(n, "Algorithm")
	if err != nil {
		return reference.Transform{}, err
	}

	if !canonicalAlgorithm(uri) {
		return reference.Transform{}, fmt.Errorf("%w: canonicalization method", reference.ErrUnsupported)
	}

	if len(children) == 0 {
		return reference.Transform{Algorithm: uri}, nil
	}

	if uri != c14n.Exclusive && uri != c14n.ExclusiveWithComments {
		return reference.Transform{}, fmt.Errorf("%w: canonicalization parameters", reference.ErrInput)
	}

	if len(children) != 1 || children[0].Name != (document.Name{Space: c14n.Exclusive, Local: "InclusiveNamespaces"}) {
		return reference.Transform{}, fmt.Errorf("%w: canonicalization parameters", reference.ErrInput)
	}

	child := children[0]
	if err := attributes(child, "PrefixList"); err != nil {
		return reference.Transform{}, err
	}

	nested, err := elementChildren(child)
	if err != nil {
		return reference.Transform{}, err
	}

	if len(nested) != 0 {
		return reference.Transform{}, fmt.Errorf("%w: InclusiveNamespaces must be empty", reference.ErrInput)
	}

	list, err := requiredAttribute(child, "PrefixList")
	if err != nil {
		return reference.Transform{}, err
	}

	prefixes := strings.FieldsFunc(list, func(r rune) bool { return r == ' ' || r == '\t' || r == '\r' || r == '\n' })
	if len(prefixes) > 128 {
		return reference.Transform{}, fmt.Errorf("%w: too many inclusive prefixes", reference.ErrLimit)
	}

	for _, p := range prefixes {
		if p != "#default" && (!tree.NCName(p) || p == "xmlns") {
			return reference.Transform{}, fmt.Errorf("%w: inclusive prefix", reference.ErrInput)
		}
	}

	return reference.Transform{Algorithm: uri, InclusivePrefixes: prefixes}, nil
}

func canonicalAlgorithm(uri string) bool {
	switch uri {
	case c14n.Exclusive, c14n.ExclusiveWithComments, c14n.Canonical10, c14n.Canonical10WithComments, c14n.Canonical11, c14n.Canonical11WithComments:
		return true
	default:
		return false
	}
}

func attributes(n *tree.Node, allowed ...string) error {
	for _, a := range n.Attrs {
		ok := false

		if a.Name.Space == "" {
			if slices.Contains(allowed, a.Name.Local) {
				ok = true
			}
		}

		if !ok {
			return fmt.Errorf("%w: unexpected attribute on %s", reference.ErrInput, n.Name.Local)
		}
	}

	return nil
}

func structure(n *tree.Node, local string, allowed ...string) ([]*tree.Node, error) {
	if !isDS(n, local) {
		return nil, fmt.Errorf("%w: expected ds:%s", reference.ErrInput, local)
	}

	if err := attributes(n, allowed...); err != nil {
		return nil, err
	}

	return elementChildren(n)
}

func elementChildren(n *tree.Node) ([]*tree.Node, error) {
	var children []*tree.Node

	for _, c := range n.Children {
		switch c.Kind {
		case tree.ElementNode:
			children = append(children, c)
		case tree.CommentNode:
		case tree.TextNode:
			if !tree.IsXMLSpace(c.Data) {
				return nil, fmt.Errorf("%w: unexpected text in %s", reference.ErrInput, n.Name.Local)
			}
		default:
			return nil, fmt.Errorf("%w: processing instruction in signature structure", reference.ErrInput)
		}
	}

	return children, nil
}

// Parse reads a complete ds:Transform without executing an application program.
func Parse(ctx context.Context, doc *document.Document, n *tree.Node) (reference.Transform, error) {
	if ctx == nil || n == nil {
		return reference.Transform{}, reference.ErrInput
	}

	if err := ctx.Err(); err != nil {
		return reference.Transform{}, err
	}

	algorithm, err := requiredAttribute(n, "Algorithm")
	if err != nil {
		return reference.Transform{}, err
	}

	if reference.IsExtension(algorithm) {
		return ParseProgram(ctx, n, doc)
	}

	if canonicalAlgorithm(algorithm) {
		return ParseCanonical(n, "Transform")
	}

	children, err := structure(n, "Transform", "Algorithm")
	if err != nil {
		return reference.Transform{}, err
	}

	if len(children) != 0 {
		return reference.Transform{}, reference.ErrInput
	}

	return reference.Transform{Algorithm: algorithm}, nil
}

// AppendParameters emits supported canonicalization or program parameters.
func AppendParameters(ctx context.Context, n *tree.Node, t reference.Transform) error {
	if err := reference.ValidateTransformParameters(t); err != nil {
		return err
	}

	if len(t.InclusivePrefixes) != 0 {
		if t.Algorithm != c14n.Exclusive && t.Algorithm != c14n.ExclusiveWithComments {
			return reference.ErrInput
		}

		child := &tree.Node{Kind: tree.ElementNode, Name: document.Name{Space: c14n.Exclusive, Local: "InclusiveNamespaces"}, Prefix: "ec", NS: []tree.Namespace{{Prefix: "ec", URI: c14n.Exclusive}}}
		setAttr(child, "PrefixList", strings.Join(t.InclusivePrefixes, " "))
		add(n, child)

		if _, err := ParseCanonical(n, "Transform"); err != nil {
			return err
		}
	}

	if reference.IsExtension(t.Algorithm) {
		return AppendProgram(ctx, n, t)
	}

	if !canonicalAlgorithm(t.Algorithm) && t.Algorithm != reference.Base64 && t.Algorithm != reference.EnvelopedSignature {
		return reference.ErrUnsupported
	}

	return nil
}

func requiredAttribute(n *tree.Node, local string) (string, error) {
	value, ok := getAttr(n, document.Name{Local: local})
	if !ok {
		return "", fmt.Errorf("%w: missing %s", reference.ErrInput, local)
	}

	return value, nil
}

func getAttr(n *tree.Node, name document.Name) (string, bool) {
	for _, a := range n.Attrs {
		if a.Name == name {
			return a.Value, true
		}
	}

	return "", false
}

func isDS(n *tree.Node, local string) bool {
	return n != nil && n.Kind == tree.ElementNode && n.Name == (document.Name{Space: Namespace, Local: local})
}

func add(parent, child *tree.Node) {
	parent.Children = append(parent.Children, child)
	child.Parent = parent
}

func setAttr(n *tree.Node, local, value string) {
	n.Attrs = append(n.Attrs, tree.Attribute{Name: document.Name{Local: local}, Value: value})
}
func text(n *tree.Node, value string) { add(n, &tree.Node{Kind: tree.TextNode, Data: value}) }
