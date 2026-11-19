package xslt

import (
	"context"
	"fmt"
	"io"
	"iter"
	"slices"
	"strings"

	"github.com/skarm/xmlsec/internal/lexicon"
	"github.com/skarm/xmlsec/internal/tree"
	"github.com/skarm/xmlsec/transform/internal/xdm"
	"github.com/skarm/xmlsec/transform/internal/xpath"
)

type serializationSequence struct {
	ctx        context.Context
	definition *OutputDef
}

func (s *serializationSequence) items(seq xdm.Sequence) iter.Seq2[xdm.XMLItem, error] {
	const (
		normalizationFormNoneLower = "none"
	)

	coalesce := s.definition.NormalizationForm != "" && s.definition.NormalizationForm != normalizationFormNoneLower && s.definition.NormalizationForm != normalizationFormNone

	return xpath.SerializationItems(s.ctx, seq, s.definition.ItemSeparator, coalesce)
}

// firstSerializationElement returns the first normalized element only when
// all text before it is XML whitespace.
func firstSerializationElement(ctx context.Context, seq xdm.Sequence, separator *string) (*xdm.Element, error) {
	if xdm.SequenceLen(seq) == 1 {
		if item, ok := seq.Get(0).(xdm.NodeItem); ok {
			switch node := item.Node.(type) {
			case *xdm.Element:
				return node, ctx.Err()
			case *xdm.Document:
				return firstDocumentSerializationElement(ctx, node)
			}
		}
	}

	for item, err := range xpath.SerializationItems(ctx, seq, separator, false) {
		if err != nil {
			return nil, err
		}

		if elem, ok := item.Node.(*xdm.Element); ok {
			return elem, nil
		}

		nonWhitespace, err := leadingSerializationText(ctx, item)
		if err != nil || nonWhitespace {
			return nil, err
		}
	}

	return nil, ctx.Err()
}

func firstDocumentSerializationElement(ctx context.Context, doc *xdm.Document) (*xdm.Element, error) {
	if doc == nil {
		return nil, ctx.Err()
	}

	for child := range xdm.Children(doc) {
		if elem, ok := child.(*xdm.Element); ok {
			return elem, ctx.Err()
		}

		if err := xpath.Charge(ctx, 1); err != nil {
			return nil, err
		}

		nonWhitespace, err := leadingSerializationText(ctx, xdm.XMLItem{Node: child})
		if err != nil || nonWhitespace {
			return nil, err
		}
	}

	return nil, ctx.Err()
}

func leadingSerializationText(ctx context.Context, item xdm.XMLItem) (bool, error) {
	const scanChunkBytes = 4096

	for value := serializationText(item); len(value) > 0; {
		if err := xpath.Charge(ctx, 1); err != nil {
			return false, err
		}

		end := min(len(value), scanChunkBytes)
		if !isXMLWhitespaceOnly(value[:end]) {
			return true, nil
		}

		value = value[end:]
	}

	return false, nil
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
	const (
		xmlDeclarationFormat = "<?xml version=\"%s\" encoding=\"%s\""
		xmlStandalonePrefix  = " standalone=\""
	)

	version := validOutputXMLVersion(definition.Version)
	if version == "" {
		version = lexicon.XMLVersion10
	}

	if !definition.OmitDeclaration {
		name := definition.Encoding
		if name == "" {
			name = lexicon.EncodingUTF8U
		}

		declaration := fmt.Sprintf(xmlDeclarationFormat, version, name)
		if definition.Standalone == lexicon.ValueYes || definition.Standalone == lexicon.ValueNo {
			declaration += xmlStandalonePrefix + definition.Standalone + "\""
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
		version = lexicon.XMLVersion10
	}

	options := tree.XMLWriteOptions{EscapeControlChars: true, CanEncode: definition.canEncode, Version: version, Indent: definition.Indent, ASCII: encoding == encodingASCII, CharacterMap: definition.ResolvedCharMap, Normalization: definition.NormalizationForm, PrefixUndeclarations: definition.UndeclarePrefixes}
	if options.Normalization == lexicon.NormFullyNormalized {
		options.Normalization = lexicon.NormalizationFormNFC
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
