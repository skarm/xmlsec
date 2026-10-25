package xdm

import (
	"context"
	"errors"
	"io"
	"iter"
	"strings"

	"github.com/skarm/xmlsec/internal/tree"
)

// XMLItem borrows a node or supplies text to the sequence serializer.
type XMLItem struct {
	Node Node
	Text string
}

// WriteAttributeValue applies the XML character rules to a standalone adaptive
// attribute/namespace representation without constructing a containing tree.
func (w XMLSerialization) WriteAttributeValue(ctx context.Context, dst io.Writer, value string) error {
	_, err := tree.WriteXMLCharacters(ctx, dst, value, tree.XMLAttributeValue, int(^uint(0)>>1), w.XMLWriteOptions)
	if errors.Is(err, tree.ErrUnencodable) {
		return &Error{Code: "SERE0008", Message: err.Error(), Cause: err}
	}

	if errors.Is(err, tree.ErrMalformed) {
		return &Error{Code: "SERE0006", Message: err.Error(), Cause: err}
	}

	return err
}

// WriteSequence serializes borrowed nodes and text without building another DOM.
// Node storage is read-only for the duration of the call.
func (w XMLSerialization) WriteSequence(ctx context.Context, dst io.Writer, items iter.Seq2[XMLItem, error]) error {
	options := w.XMLWriteOptions

	options.SelfClose, options.Reconcile, options.NormalizeXMLID = true, true, true
	if strings.EqualFold(w.Encoding, "US-ASCII") {
		options.ASCII = true
	}

	doctype := w.Doctype
	nodes := func(yield func(*tree.Node, error) bool) {
		for item, err := range items {
			if err != nil {
				yield(nil, err)
				return
			}

			var node *tree.Node

			if item.Node != nil {
				if doctype != nil && !w.OmitDoctype && item.Node.Type() == ElementNode {
					declaration := *doctype

					declaration.Name = item.Node.Name()
					if err := writeDoctype(dst, &declaration); err != nil {
						yield(nil, err)
						return
					}

					doctype = nil
				}

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
	if errors.Is(err, tree.ErrUnencodable) {
		return &Error{Code: "SERE0008", Message: err.Error(), Cause: err}
	}

	if errors.Is(err, tree.ErrMalformed) {
		return &Error{Code: "SERE0006", Message: err.Error(), Cause: err}
	}

	return err
}
