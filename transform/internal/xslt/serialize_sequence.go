package xslt

import (
	"context"
	"fmt"
	"io"
	"iter"
	"slices"
	"strings"

	"github.com/skarm/xmlsec/internal/tree"
	"github.com/skarm/xmlsec/transform/internal/xdm"
	"github.com/skarm/xmlsec/transform/internal/xdm/lexicon"
	"github.com/skarm/xmlsec/transform/internal/xpath"
)

type serializationSequence struct {
	ctx                          context.Context
	definition                   *OutputDef
	previousAtomic, previousItem bool
}

func (s *serializationSequence) items(seq xdm.Sequence) iter.Seq2[xdm.XMLItem, error] {
	return func(yield func(xdm.XMLItem, error) bool) { s.append(seq, 0, yield) }
}

func (s *serializationSequence) append(seq xdm.Sequence, depth int, yield func(xdm.XMLItem, error) bool) bool {
	if depth > xpath.DepthLimit(s.ctx, 128) {
		yield(xdm.XMLItem{}, xpath.ErrBudget)
		return false
	}

	for item := range xdm.SequenceItems(seq) {
		if err := xpath.Charge(s.ctx, 1); err != nil {
			yield(xdm.XMLItem{}, err)
			return false
		}

		if array, ok := item.(xdm.ArrayItem); ok {
			for _, member := range array.MembersView() {
				if !s.append(member, depth+1, yield) {
					return false
				}
			}

			continue
		}

		if !s.item(item, yield) {
			return false
		}

		s.previousItem = true
	}

	return true
}

func (s *serializationSequence) item(item xdm.Item, yield func(xdm.XMLItem, error) bool) bool {
	if s.previousItem && s.definition.ItemSeparator != nil {
		if !yield(xdm.XMLItem{Text: *s.definition.ItemSeparator}, nil) {
			return false
		}
	}

	switch value := item.(type) {
	case xdm.AtomicValue:
		if s.previousAtomic && s.definition.ItemSeparator == nil {
			if !yield(xdm.XMLItem{Text: " "}, nil) {
				return false
			}
		}

		text, err := xpath.AtomicToString(value)
		if err != nil {
			yield(xdm.XMLItem{}, err)
			return false
		}

		if !yield(xdm.XMLItem{Text: text}, nil) {
			return false
		}

		s.previousAtomic = true
	case xdm.NodeItem:
		if !s.node(value.Node, yield) {
			return false
		}

		s.previousAtomic = false
	default:
		yield(xdm.XMLItem{}, dynamicError("SENR0001", "cannot serialize maps or functions using this output method"))
		return false
	}

	return true
}

func (s *serializationSequence) node(node xdm.Node, yield func(xdm.XMLItem, error) bool) bool {
	if node == nil || node.Type() == xdm.AttributeNode || node.Type() == xdm.NamespaceNode {
		yield(xdm.XMLItem{}, dynamicError("SENR0001", "cannot serialize a free attribute or namespace"))
		return false
	}

	if node.Type() != xdm.DocumentNode {
		return yield(xdm.XMLItem{Node: node}, nil)
	}

	for child := range xdm.Children(node) {
		if !yield(xdm.XMLItem{Node: child}, nil) {
			return false
		}
	}

	return true
}

func firstSerializationElement(seq xdm.Sequence) *xdm.Element {
	for item := range xdm.SequenceItems(seq) {
		switch value := item.(type) {
		case xdm.ArrayItem:
			for _, member := range value.MembersView() {
				if elem := firstSerializationElement(member); elem != nil {
					return elem
				}
			}
		case xdm.NodeItem:
			if elem, ok := value.Node.(*xdm.Element); ok {
				return elem
			}

			if doc, ok := value.Node.(*xdm.Document); ok {
				if root := doc.DocumentElement(); root != nil {
					return root
				}
			}
		}
	}

	return nil
}

func streamXMLValue(ctx context.Context, w io.Writer, result ValueResult, definition *OutputDef) error {
	if err := writeXMLProlog(w, definition); err != nil {
		return err
	}

	options := streamXMLWriteOptions(definition, strings.ToLower(definition.Encoding))
	sequence := serializationSequence{ctx: ctx, definition: definition}

	writer := xdm.XMLSerialization{XMLWriteOptions: options}
	if definition.DoctypeSystem != "" {
		writer.Doctype = &xdm.Doctype{PublicID: definition.DoctypePublic, SystemID: definition.DoctypeSystem}
	}

	return xmlInvalidCharError(writer.WriteSequence(ctx, w, sequence.items(result.Items)))
}

func writeXMLProlog(w io.Writer, definition *OutputDef) error {
	version := validOutputXMLVersion(definition.Version)
	if version == "" {
		version = lexicon.XSLTVersion10
	}

	if !definition.OmitDeclaration {
		name := definition.Encoding
		if name == "" {
			name = lexicon.EncodingUTF8U
		}

		declaration := fmt.Sprintf("<?xml version=\"%s\" encoding=\"%s\"", version, name)
		if definition.Standalone == "yes" || definition.Standalone == "no" {
			declaration += " standalone=\"" + definition.Standalone + "\""
		}

		declaration += "?>"
		if definition.Indent {
			declaration += "\n"
		}

		if err := writeFullString(w, declaration); err != nil {
			return err
		}
	}

	return nil
}

func streamXMLWriteOptions(definition *OutputDef, encoding string) tree.XMLWriteOptions {
	version := validOutputXMLVersion(definition.Version)
	if version == "" {
		version = lexicon.XSLTVersion10
	}

	options := tree.XMLWriteOptions{CanEncode: definition.canEncode, Version: version, Indent: definition.Indent, ASCII: encoding == encodingASCII, CharacterMap: definition.ResolvedCharMap, Normalization: definition.NormalizationForm, PrefixUndeclarations: definition.UndeclarePrefixes}
	if options.Normalization == lexicon.NormFullyNormalized {
		options.Normalization = "NFC"
	}

	if len(definition.CDATASections) > 0 {
		options.CDATA = make(map[string]struct{})
		for _, name := range definition.CDATASections {
			options.CDATA[writerExpandedName(name)] = struct{}{}
		}
	}

	if len(definition.SuppressIndentation) > 0 {
		options.SuppressIndent = make(map[string]struct{})
		for _, name := range definition.SuppressIndentation {
			options.SuppressIndent[writerExpandedName(name)] = struct{}{}
		}
	}

	return options
}

func sequenceHasDOEMarkers(items xdm.Sequence) bool {
	for item := range xdm.SequenceItems(items) {
		switch value := item.(type) {
		case xdm.ArrayItem:
			if slices.ContainsFunc(value.MembersView(), sequenceHasDOEMarkers) {
				return true
			}
		case xdm.NodeItem:
			if hasDOEMarkers(value.Node) {
				return true
			}
		}
	}

	return false
}

func writerExpandedName(name string) string {
	if strings.HasPrefix(name, "{") {
		return name
	}

	return "{}" + name
}
