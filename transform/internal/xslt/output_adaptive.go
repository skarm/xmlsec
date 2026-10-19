// Derived from lestrrat-go/helium at 7362c0a70122a757780f4d0b545a9b370dead6ab.
// Copyright (c) 2015 lestrrat. MIT License; see licenses/MIT-helium.txt at the repository root.

package xslt

import (
	"bytes"
	"fmt"
	"io"

	"github.com/skarm/xmlsec/transform/internal/xdm"
	"github.com/skarm/xmlsec/transform/internal/xdm/lexicon"
	"github.com/skarm/xmlsec/transform/internal/xpath"
)

// serializeAdaptiveItems serializes a sequence of items using the adaptive
// serialization method. Each item is serialized according to its type.
func serializeAdaptiveItems(w io.Writer, items xdm.Sequence, doc *xdm.Document, itemSep *string, xmlVersion, normalizationForm string, charMaps ...map[rune]string) error {
	if (items == nil || xdm.SequenceLen(items) == 0) && doc != nil {
		return serializeAdaptiveDocument(w, doc, charMaps, itemSep, xmlVersion, normalizationForm)
	}

	var cm map[rune]string
	if len(charMaps) > 0 {
		cm = charMaps[0]
	}

	sep := "\n"
	if itemSep != nil {
		sep = *itemSep
	}
	// Per XSLT 3.0 §20: when adaptive output contains a single document or
	// element node, serialize it using the XML method (which includes the
	// XML declaration by default). When there are multiple items, serialize
	// each without a declaration.
	singleNodeItem := items != nil && xdm.SequenceLen(items) == 1

	adaptIdx := 0
	for item := range xdm.SequenceItems(items) {
		if adaptIdx > 0 && sep != "" {
			if err := writeFullString(w, sep); err != nil {
				return err
			}
		}

		if ni, ok := item.(xdm.NodeItem); singleNodeItem && ok {
			if elem, ok := ni.Node.(*xdm.Element); ok {
				if err := serializeAdaptiveElement(w, elem, xmlVersion, normalizationForm, cm); err != nil {
					return err
				}

				continue
			}
		}

		s, err := serializeItemAdaptive(item, xmlVersion, normalizationForm, cm)
		if err != nil {
			return err
		}

		if err := writeFullString(w, s); err != nil {
			return err
		}

		adaptIdx++
	}

	return nil
}

// adaptiveStandaloneMarkupDocument reports whether doc contains only top-level
// comments and processing instructions. The adaptive method serializes that
// markup without an XML declaration.
func adaptiveStandaloneMarkupDocument(doc *xdm.Document) bool {
	if doc == nil || doc.DocumentElement() != nil {
		return false
	}

	hasMarkup := false

	for child := range xdm.Children(doc) {
		switch child.Type() {
		case xdm.CommentNode, xdm.ProcessingInstructionNode:
			hasMarkup = true
		default:
			return false
		}
	}

	return hasMarkup
}

// serializeAdaptiveStandaloneMarkup serializes every top-level comment and
// processing instruction as an adaptive item. The XML writer validates each
// item against the output version without adding a document declaration. Its
// separator is text character data, so character maps and normalization apply
// to it but not to the comment or processing-instruction data.
func serializeAdaptiveStandaloneMarkup(w io.Writer, doc *xdm.Document, itemSep *string, xmlVersion, normalizationForm string, charMap map[rune]string) error {
	sep := "\n"
	if itemSep != nil {
		sep = *itemSep
	}

	writerNormalizationForm := normalizationForm
	if writerNormalizationForm == lexicon.NormFullyNormalized {
		writerNormalizationForm = normalizationFormNFC
	} else if _, ok := resolveNormForm(writerNormalizationForm); !ok {
		writerNormalizationForm = ""
	}

	writer := xdm.XMLSerialization{OmitDeclaration: true, CharacterMap: charMap, Normalization: writerNormalizationForm, Version: adaptiveXMLVersion(xmlVersion)}

	first := true
	for child := range xdm.Children(doc) {
		if !first && sep != "" {
			separator := doc.CreateText(sep)
			if err := xmlInvalidCharError(writer.WriteTo(w, separator)); err != nil {
				return err
			}
		}

		if err := xmlInvalidCharError(writer.WriteTo(w, child)); err != nil {
			return err
		}

		first = false
	}

	return nil
}

// adaptiveXMLVersion returns the XML version used whenever adaptive output
// delegates an element, document, comment, or processing-instruction item to
// XML serialization. xmlVersion was validated by validOutputXMLVersion; an
// absent value uses the XML 1.0 default.
func adaptiveXMLVersion(xmlVersion string) string {
	if xmlVersion != "" {
		return xmlVersion
	}

	return defaultOutputDef().Version
}

// adaptiveQuoteString wraps a string in double quotes for adaptive output.
// Unlike JSON escaping, adaptive serialization only escapes embedded double
// quotes by doubling them (XSLT 3.0 §26.3.5). Other characters such as
// backslashes are emitted literally.
func adaptiveQuoteString(s string) string {
	var buf bytes.Buffer
	buf.WriteByte('"')

	for _, r := range s {
		if r == '"' {
			buf.WriteString("\"\"")
		} else {
			buf.WriteRune(r)
		}
	}

	buf.WriteByte('"')

	return buf.String()
}

// isAdaptiveQuotedType returns true when an atomic type should be serialized
// with double-quote wrapping in adaptive output (XSLT 3.0 §26.3.5).
// String-like types use JSON quoting; numeric types and xs:boolean do not.
func isAdaptiveQuotedType(typeName string) bool {
	switch typeName {
	case "xs:boolean",
		"xs:integer", "xs:decimal", "xs:float", "xs:double",
		"xs:long", "xs:int", "xs:short", "xs:byte",
		"xs:unsignedLong", "xs:unsignedInt", "xs:unsignedShort", "xs:unsignedByte",
		"xs:nonNegativeInteger", "xs:nonPositiveInteger",
		"xs:positiveInteger", "xs:negativeInteger":
		return false
	}

	return true
}

// serializeItemAdaptive serializes a single item using the adaptive method.
// xmlVersion is the validated xml-method version. Every element, document,
// comment, and processing-instruction item uses adaptiveXMLVersion, so the XML
// 1.0 default does not inherit a document's own version. Normalization applies
// only to unmapped character-data runs; comments and processing instructions
// preserve their data.
func serializeItemAdaptive(item xdm.Item, xmlVersion, normalizationForm string, charMap map[rune]string) (string, error) {
	switch v := item.(type) {
	case xdm.MapItem:
		return serializeMapAdaptive(v, xmlVersion, normalizationForm, charMap)
	case xdm.ArrayItem:
		return serializeArrayAdaptive(v, xmlVersion, normalizationForm, charMap)
	case xdm.NodeItem:
		var buf bytes.Buffer

		switch v.Node.(type) {
		case *xdm.Element, *xdm.Document:
			writerNormalizationForm := normalizationForm
			if writerNormalizationForm == lexicon.NormFullyNormalized {
				writerNormalizationForm = normalizationFormNFC
			}

			writer := xdm.XMLSerialization{OmitDeclaration: true, CharacterMap: charMap, Normalization: writerNormalizationForm, Version: adaptiveXMLVersion(xmlVersion)}
			if err := writer.WriteTo(&buf, v.Node); err != nil {
				return "", xmlInvalidCharError(err)
			}

			return buf.String(), nil
		case *xdm.Comment, *xdm.ProcessingInstruction:
			writer := xdm.XMLSerialization{OmitDeclaration: true, Version: adaptiveXMLVersion(xmlVersion)}
			if err := writer.WriteTo(&buf, v.Node); err != nil {
				return "", xmlInvalidCharError(err)
			}

			return buf.String(), nil
		case *xdm.Attribute:
			attr, _ := xdm.AsNode[*xdm.Attribute](v.Node)
			buf.WriteString(attr.Name())
			buf.WriteString("=\"")
			buf.WriteString(adaptiveAtomicString(xdm.CharacterData(attr), charMap, normalizationForm))
			buf.WriteString("\"")
		default:
			buf.WriteString(adaptiveAtomicString(xdm.CharacterData(v.Node), charMap, normalizationForm))
		}

		return buf.String(), nil
	case xdm.AtomicValue:
		s, _ := xpath.AtomicToString(v)

		s = adaptiveAtomicString(s, charMap, normalizationForm)
		if isAdaptiveQuotedType(v.TypeName) {
			return adaptiveQuoteString(s), nil
		}

		return s, nil
	default:
		if av, ok := item.(xdm.AtomicValue); ok {
			s, _ := xpath.AtomicToString(av)

			s = adaptiveAtomicString(s, charMap, normalizationForm)
			if isAdaptiveQuotedType(av.TypeName) {
				return adaptiveQuoteString(s), nil
			}

			return s, nil
		}

		return fmt.Sprintf("%v", item), nil
	}
}

// adaptiveAtomicString delegates atomic character-data processing to the Text
// output method before adaptive serialization quotes or escapes the value.
func adaptiveAtomicString(s string, charMap map[rune]string, normalizationForm string) string {
	return applyCharacterMapWithNormalization(s, charMap, normalizationForm)
}

func serializeMapAdaptive(m xdm.MapItem, xmlVersion, normalizationForm string, charMap map[rune]string) (string, error) {
	var buf bytes.Buffer
	buf.WriteString("map{")

	first := true

	var serErr error

	_ = m.ForEach(func(k xdm.AtomicValue, v xdm.Sequence) error {
		if serErr != nil {
			return serErr
		}

		if !first {
			buf.WriteByte(',')
		}

		first = false
		ks, _ := xpath.AtomicToString(k)
		ks = adaptiveAtomicString(ks, charMap, normalizationForm)
		buf.WriteString(jsonEscapeString(ks))
		buf.WriteByte(':')

		vLen2 := 0
		if v != nil {
			vLen2 = xdm.SequenceLen(v)
		}

		switch vLen2 {
		case 1:
			s, err := serializeItemAdaptive(v.Get(0), xmlVersion, normalizationForm, charMap)
			if err != nil {
				serErr = err
				return err
			}

			buf.WriteString(s)
		case 0:
			buf.WriteString("()")
		default:
			buf.WriteByte('(')

			for i := range vLen2 {
				if i > 0 {
					buf.WriteByte(',')
				}

				s, err := serializeItemAdaptive(v.Get(i), xmlVersion, normalizationForm, charMap)
				if err != nil {
					serErr = err
					return err
				}

				buf.WriteString(s)
			}

			buf.WriteByte(')')
		}

		return nil
	})

	if serErr != nil {
		return "", serErr
	}

	buf.WriteByte('}')

	return buf.String(), nil
}

func serializeArrayAdaptive(a xdm.ArrayItem, xmlVersion, normalizationForm string, charMap map[rune]string) (string, error) {
	var buf bytes.Buffer
	buf.WriteByte('[')

	members := a.Members()
	for i, member := range members {
		if i > 0 {
			buf.WriteByte(',')
		}

		mLen2 := 0
		if member != nil {
			mLen2 = xdm.SequenceLen(member)
		}

		switch mLen2 {
		case 1:
			s, err := serializeItemAdaptive(member.Get(0), xmlVersion, normalizationForm, charMap)
			if err != nil {
				return "", err
			}

			buf.WriteString(s)
		case 0:
			buf.WriteString("()")
		default:
			buf.WriteByte('(')

			for j := range mLen2 {
				if j > 0 {
					buf.WriteByte(',')
				}

				s, err := serializeItemAdaptive(member.Get(j), xmlVersion, normalizationForm, charMap)
				if err != nil {
					return "", err
				}

				buf.WriteString(s)
			}

			buf.WriteByte(')')
		}
	}

	buf.WriteByte(']')

	return buf.String(), nil
}

func serializeAdaptiveDocument(w io.Writer, doc *xdm.Document, charMaps []map[rune]string, itemSep *string, xmlVersion, normalizationForm string) error {
	var cm map[rune]string
	if len(charMaps) > 0 {
		cm = charMaps[0]
	}

	if adaptiveStandaloneMarkupDocument(doc) {
		return serializeAdaptiveStandaloneMarkup(w, doc, itemSep, xmlVersion, normalizationForm, cm)
	}

	xmlOutDef := defaultOutputDef()
	xmlOutDef.Version = adaptiveXMLVersion(xmlVersion)
	xmlOutDef.NormalizationForm = normalizationForm

	return serializeXML(w, doc, xmlOutDef, cm)
}

func serializeAdaptiveElement(w io.Writer, elem *xdm.Element, xmlVersion, normalizationForm string, cm map[rune]string) error {
	// Wrap in a temp document to get the XML declaration.
	tmpDoc := xdm.NewDefaultDocument()

	clone, _ := xdm.CopyNode(elem, tmpDoc)
	if clone != nil {
		_ = tmpDoc.AddChild(clone)
	}

	xmlOutDef := defaultOutputDef()
	xmlOutDef.Version = adaptiveXMLVersion(xmlVersion)

	xmlOutDef.NormalizationForm = normalizationForm
	if err := serializeXML(w, tmpDoc, xmlOutDef, cm); err != nil {
		return err
	}

	return nil
}
