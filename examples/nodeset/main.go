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
	doc, err := document.Parse(context.Background(), []byte(`<Envelope xml:lang="ru" xml:base="https://example.test/a/"><Payload xml:base="../b/">данные<!--служебный комментарий--></Payload></Envelope>`), document.DefaultLimits())
	if err != nil {
		return err
	}

	payload := doc.Root().Children()[0]

	nodes, err := payload.Subtree(context.Background())
	if err != nil {
		return err
	}
	// Selecting just payload.Node() would NOT include its text/attributes.
	for _, node := range nodes.Nodes() {
		if node.Kind() == document.CommentNode {
			nodes, err = nodes.Without(node)
			if err != nil {
				return err
			}
		}
	}

	var result bytes.Buffer
	if err := c14n.WriteNodeSet(context.Background(), &result, nodes, c14n.Options{
		Algorithm: c14n.Canonical11WithComments,
	}); err != nil {
		return err
	}
	// The omitted ancestor contributes xml:lang and xml:base. WithComments
	// cannot reselect a comment explicitly removed from the set.
	fmt.Println(result.String())

	return nil
}
