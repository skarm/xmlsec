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
	ctx        context.Context
	definition *OutputDef
}

func (s *serializationSequence) items(seq xdm.Sequence) iter.Seq2[xdm.XMLItem, error] {
	coalesce := s.definition.NormalizationForm != "" && s.definition.NormalizationForm != "none" && s.definition.NormalizationForm != "NONE"
	return xpath.SerializationItems(s.ctx, seq, s.definition.ItemSeparator, coalesce)
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
		if definition.Standalone == lexicon.ValueYes || definition.Standalone == lexicon.ValueNo {
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

	options := tree.XMLWriteOptions{EscapeControlChars: true, CanEncode: definition.canEncode, Version: version, Indent: definition.Indent, ASCII: encoding == encodingASCII, CharacterMap: definition.ResolvedCharMap, Normalization: definition.NormalizationForm, PrefixUndeclarations: definition.UndeclarePrefixes}
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
