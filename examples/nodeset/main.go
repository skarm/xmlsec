// Command nodeset demonstrates the corresponding XML security API.
// Demonstrates explicit node selection. This is canonicalization, NOT signing
// or verifying the resulting fragment. No XPath expression is evaluated.

package main

import (
	"bytes"
	"context"
	"fmt"
	"os"

	"github.com/skarm/xmlsec/c14n"
	"github.com/skarm/xmlsec/document"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	ctx := context.Background()

	doc, err := document.Parse(ctx, []byte(`<Envelope xml:lang="ru" xml:base="https://example.test/a/"><Payload xml:base="../b/">данные<!--служебный комментарий--></Payload></Envelope>`), document.DefaultLimits())
	if err != nil {
		return err
	}

	nodes, err := subtreeWithoutComments(ctx, doc.Root().Children()[0])
	if err != nil {
		return err
	}

	var result bytes.Buffer
	if err := c14n.WriteNodeSet(ctx, &result, nodes, c14n.Options{
		Algorithm: c14n.Canonical11WithComments,
	}); err != nil {
		return err
	}
	// The omitted ancestor contributes xml:lang and xml:base. WithComments
	// cannot reselect a comment explicitly removed from the set.
	fmt.Println(result.String())

	return nil
}

func subtreeWithoutComments(ctx context.Context, root document.Element) (document.NodeSet, error) {
	// Subtree includes the element's text and attributes. root.Node() selects
	// just the element itself.
	nodes, err := root.Subtree(ctx)
	if err != nil {
		return document.NodeSet{}, err
	}

	for _, node := range nodes.Nodes() {
		if node.Kind() == document.CommentNode {
			nodes, err = nodes.Without(node)
			if err != nil {
				return document.NodeSet{}, err
			}
		}
	}

	return nodes, nil
}
