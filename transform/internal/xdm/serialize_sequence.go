package xdm

import (
	"context"
	"io"
	"iter"

	"github.com/skarm/xmlsec/internal/tree"
)

// XMLItem borrows a node or supplies text to the sequence serializer.
type XMLItem struct {
	Node Node
	Text string
}

// WriteSequence serializes borrowed nodes and text without building another DOM.
// Node storage is read-only for the duration of the call.
func (w XMLSerialization) WriteSequence(ctx context.Context, dst io.Writer, items iter.Seq2[XMLItem, error]) error {
	options := w.XMLWriteOptions
	options.SelfClose, options.Reconcile = true, true
	nodes := func(yield func(*tree.Node, error) bool) {
		for item, err := range items {
			if err != nil {
				yield(nil, err)
				return
			}

			var node *tree.Node
			if item.Node != nil {
				node = item.Node.view().raw
			} else {
				node = &tree.Node{Kind: tree.TextNode, Data: item.Text}
			}

			if !yield(node, nil) {
				return
			}
		}
	}
	_, err := tree.WriteXMLSequence(ctx, dst, nodes, int(^uint(0)>>1), options)

	return err
}
