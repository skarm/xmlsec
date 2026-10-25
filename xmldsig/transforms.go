package xmldsig

import (
	"bytes"
	"context"
	"fmt"
	"maps"
	"sort"
	"strings"

	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/internal/tree"
	"github.com/skarm/xmlsec/reference"
)

func parseProgramTransform(ctx context.Context, n *tree.Node, doc *document.Document) (reference.Transform, error) {
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
		return t, processingError(err)
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

func appendProgramParameters(ctx context.Context, n *tree.Node, t reference.Transform) error {
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
			return fmt.Errorf("%w: reserved transform prefix %s", ErrPolicy, prefix)
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

func prepareProgramReferences(ctx context.Context, p *corePlan) error {
	for _, task := range p.graph.tasks {
		if err := reference.PrepareTransforms(ctx, task.ref.transforms, p.processing); err != nil {
			return task.wrap("preflight", processingError(err))
		}
	}

	return nil
}

func parseTransformContent(ctx context.Context, t *reference.Transform, children []*tree.Node, doc *document.Document) error {
	if t.Algorithm == reference.XSLT {
		if len(children) != 1 {
			return ErrStructure
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
		return reference.XPathExpression{}, fmt.Errorf("%w: XPath element namespace", ErrStructure)
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
			return x, ErrStructure
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
