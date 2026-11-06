package xdm

import (
	"context"
	"errors"
	"io"
	"iter"
	"strings"

	"github.com/skarm/xmlsec/internal/lexicon"
	"github.com/skarm/xmlsec/internal/tree"
)

// Sequence serialization enables compact empty elements, reconciles namespace
// bindings and normalizes xml:id. The canonical ASCII label selects the
// existing ASCII-only output option without changing codec admission.
const (
	sequenceSelfClose           = true
	sequenceReconcileNamespaces = true
	sequenceNormalizeXMLID      = true
	asciiOutputEncoding         = "US-ASCII"
)

// XMLItem borrows a node or supplies text to the sequence serializer.
type XMLItem struct {
	// Node supplies a borrowed XML node. When non-nil, the serializer uses it instead of
	// Text.
	Node Node
	// Text supplies character data when Node is nil.
	Text string
}

// WriteAttributeValue applies the XML character rules to a standalone adaptive
// attribute/namespace representation without constructing a containing tree.
func (w XMLSerialization) WriteAttributeValue(ctx context.Context, dst io.Writer, value string) error {
	_, err := tree.WriteXMLCharacters(ctx, dst, value, tree.XMLAttributeValue, maxInt, w.XMLWriteOptions)
	if errors.Is(err, tree.ErrUnencodable) {
		return &Error{Code: lexicon.ErrSERE0008, Message: err.Error(), Cause: err}
	}

	if errors.Is(err, tree.ErrMalformed) {
		return &Error{Code: lexicon.ErrSERE0006, Message: err.Error(), Cause: err}
	}

	return err
}

// WriteSequence serializes borrowed nodes and text without building another DOM.
// Node storage is read-only for the duration of the call.
func (w XMLSerialization) WriteSequence(ctx context.Context, dst io.Writer, items iter.Seq2[XMLItem, error]) error {
	options := w.XMLWriteOptions

	options.SelfClose, options.Reconcile, options.NormalizeXMLID = sequenceSelfClose, sequenceReconcileNamespaces, sequenceNormalizeXMLID
	if strings.EqualFold(w.Encoding, asciiOutputEncoding) {
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

	_, err := tree.WriteXMLSequence(ctx, dst, nodes, maxInt, options)
	if errors.Is(err, tree.ErrUnencodable) {
		return &Error{Code: lexicon.ErrSERE0008, Message: err.Error(), Cause: err}
	}

	if errors.Is(err, tree.ErrMalformed) {
		return &Error{Code: lexicon.ErrSERE0006, Message: err.Error(), Cause: err}
	}

	return err
}
