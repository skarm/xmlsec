// Derived from lestrrat-go/helium at 7362c0a70122a757780f4d0b545a9b370dead6ab.
// Copyright (c) 2015 lestrrat. MIT License; see licenses/MIT-helium.txt at the repository root.

package xslt

import (
	"context"

	"github.com/skarm/xmlsec/transform/internal/xdm"
	"github.com/skarm/xmlsec/transform/internal/xpath"
)

type inputTreeKey struct {
	root xdm.Node
	pkg  *Stylesheet
}

type inputTreeCopy struct {
	root  xdm.Node
	nodes map[xdm.Node]xdm.Node
}

// A document is preprocessed once per package, regardless of how many of its
// nodes occur in the initial selection or in collections. Original trees remain
// available to packages with different rules; keys use tree identity, not URIs.
func (ec *execContext) prepareInputNode(ctx context.Context, node xdm.Node) (xdm.Node, error) {
	if node == nil {
		return nil, nil //nolint:nilnil // a stripped input node is absent
	}

	if original := ec.inputOriginalNodes[node]; original != nil {
		node = original
	} else if namespace, ok := node.(*xdm.NamespaceNodeWrapper); ok {
		if original := remapNamespaceWrapper(ec.inputOriginalNodes, namespace); original != nil {
			node = original
		}
	}

	root := xdm.DocumentRoot(node)
	if len(ec.effectiveStripSpace()) == 0 || root.Type() != xdm.DocumentNode && root.Type() != xdm.ElementNode {
		return node, nil
	}

	key := inputTreeKey{root: root, pkg: ec.effectiveStylesheet()}

	prepared, found := ec.inputTrees[key]
	if !found {
		var err error

		prepared, err = ec.copyAndStripTree(ctx, root)
		if err != nil {
			return nil, err
		}

		if ec.inputTrees == nil {
			ec.inputTrees = make(map[inputTreeKey]inputTreeCopy)
			ec.inputOriginalNodes = make(map[xdm.Node]xdm.Node)
		}

		ec.inputTrees[key] = prepared
		for original, copied := range prepared.nodes {
			ec.inputOriginalNodes[copied] = original
		}
	}

	if namespace, ok := node.(*xdm.NamespaceNodeWrapper); ok {
		return remapNamespaceWrapper(prepared.nodes, namespace), nil
	}
	// Missing entries are whitespace text nodes deliberately omitted from the copy.
	return prepared.nodes[node], nil
}

func (ec *execContext) copyAndStripTree(ctx context.Context, src xdm.Node) (inputTreeCopy, error) {
	if err := xpath.ChargeTree(ctx, src); err != nil {
		return inputTreeCopy{}, err
	}

	dst, err := xdm.CopyTree(src)
	if err != nil {
		return inputTreeCopy{}, err
	}

	nodes := make(map[xdm.Node]xdm.Node)

	var walk func(xdm.Node, xdm.Node)

	walk = func(a, b xdm.Node) {
		nodes[a] = b
		if ea, ok := a.(*xdm.Element); ok {
			eb := b.(*xdm.Element) //nolint:forcetypeassert // cloning retains node kinds
			mapElementAttributes(nodes, ea, eb)
		}

		if a.FirstChild() == nil {
			return
		}

		x, y := a.FirstChild(), b.FirstChild()
		for x != nil && y != nil {
			nx, ny := x.NextSibling(), y.NextSibling()
			if !ec.shouldStripWhitespace(y) {
				walk(x, y)
			}

			x, y = nx, ny
		}

		xdm.FilterChildren(b, func(n xdm.Node) bool { return !ec.shouldStripWhitespace(n) })
	}
	walk(src, dst)
	ec.remapAnnotationsToCopy(nodes)

	return inputTreeCopy{root: dst, nodes: nodes}, nil
}
