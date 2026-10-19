package xslt

import (
	"context"
	"io"

	"github.com/skarm/xmlsec/transform/internal/xdm"
	"github.com/skarm/xmlsec/transform/internal/xdm/lexicon"
	"github.com/skarm/xmlsec/transform/internal/xpath"
)

// SerializeValue serializes a completed immutable result. Common output methods
// borrow the result and write incrementally. Other options use private intermediate
// storage without requiring callers to select a different API.
func SerializeValue(ctx context.Context, w io.Writer, result ValueResult) error {
	definition := cloneOutputDef(result.Output)
	if definition == nil {
		definition = defaultOutputDef()
	}

	definition.Method = effectiveStreamMethod(result, definition)
	if err := validateSerializationParams(definition, result.Document); err != nil {
		return err
	}

	if handled, err := streamValue(ctx, w, result, definition); handled {
		return err
	}

	if definition.Method == methodAdaptive {
		doc, err := xdm.CopyDoc(result.Document)
		if err != nil {
			return err
		}

		return SerializeItems(w, result.Items, doc, definition)
	}

	normalizer := valueNormalizer{ctx: ctx, doc: xdm.NewDefaultDocument(), separator: definition.ItemSeparator}
	if err := normalizer.appendItems(result.Items, 0); err != nil {
		return err
	}

	return SerializeResult(w, normalizer.doc, definition)
}

// streamValue reports handled=false only before writing anything. This is an
// internal implementation choice, not a restriction on writer-based public APIs.
func streamValue(ctx context.Context, w io.Writer, result ValueResult, definition *OutputDef) (bool, error) {
	switch definition.Method {
	case methodXML, methodText, methodHTML, methodJSON:
	default:
		return false, nil
	}

	if definition.Method != methodJSON && (sequenceHasDOEMarkers(result.Items) || definition.NormalizationForm == lexicon.NormFullyNormalized) {
		return false, nil
	}

	writer, closeOutput, err := encodedOutput(ctx, w, definition)
	if err != nil {
		return true, err
	}

	switch definition.Method {
	case methodXML:
		err = streamXMLValue(ctx, writer, result, definition)
	case methodText:
		err = streamTextValue(ctx, writer, result, definition)
	case methodHTML:
		err = streamHTMLValue(ctx, writer, result, definition)
	case methodJSON:
		err = SerializeItems(writer, result.Items, result.Document, definition)
	}

	if err != nil {
		return true, err
	}

	return true, closeOutput()
}

type valueNormalizer struct {
	ctx                          context.Context
	doc                          *xdm.Document
	separator                    *string
	previousAtomic, previousItem bool
}

func (n *valueNormalizer) text(value string) error {
	if err := xpath.ChargeString(n.ctx, len(value)); err != nil {
		return err
	}

	return n.doc.AddChild(n.doc.CreateText(value))
}

func (n *valueNormalizer) appendItems(items xdm.Sequence, depth int) error {
	if depth > xpath.DepthLimit(n.ctx, 128) {
		return xpath.ErrBudget
	}

	for item := range xdm.SequenceItems(items) {
		if err := xpath.Charge(n.ctx, 1); err != nil {
			return err
		}

		if array, ok := item.(xdm.ArrayItem); ok {
			for _, member := range array.MembersView() {
				if err := n.appendItems(member, depth+1); err != nil {
					return err
				}
			}

			continue
		}

		if err := n.appendItem(item); err != nil {
			return err
		}
	}

	return nil
}

func (n *valueNormalizer) appendItem(item xdm.Item) error {
	if n.previousItem && n.separator != nil {
		if err := n.text(*n.separator); err != nil {
			return err
		}
	}

	switch value := item.(type) {
	case xdm.AtomicValue:
		if n.previousAtomic && n.separator == nil {
			if err := n.text(" "); err != nil {
				return err
			}
		}

		s, err := xpath.AtomicToString(value)
		if err != nil {
			return err
		}

		if err := n.text(s); err != nil {
			return err
		}

		n.previousAtomic = true
	case xdm.NodeItem:
		if err := n.node(value.Node); err != nil {
			return err
		}

		n.previousAtomic = false
	default:
		return dynamicError("SENR0001", "cannot serialize maps or functions using this output method")
	}

	n.previousItem = true

	return nil
}

func (n *valueNormalizer) node(value xdm.Node) error {
	if value == nil || value.Type() == xdm.AttributeNode || value.Type() == xdm.NamespaceNode {
		return dynamicError("SENR0001", "cannot serialize a free attribute or namespace")
	}

	if err := xpath.ChargeTree(n.ctx, value); err != nil {
		return err
	}

	if value.Type() == xdm.DocumentNode {
		for child := range xdm.Children(value) {
			if err := n.node(child); err != nil {
				return err
			}
		}

		return nil
	}

	if element, ok := value.(*xdm.Element); ok {
		subtree, err := xdm.ElementDocument(n.ctx, element)
		if err != nil {
			return err
		}

		return n.doc.AddChild(subtree.DocumentElement())
	}

	cloned, err := xdm.CopyNode(value, n.doc)
	if err != nil {
		return err
	}

	return n.doc.AddChild(cloned)
}
