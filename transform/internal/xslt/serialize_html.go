package xslt

import (
	"bufio"
	"context"
	"io"
	"strings"

	"github.com/skarm/xmlsec/internal/xmloutput"
	"github.com/skarm/xmlsec/transform/internal/xdm"
	htmlpkg "github.com/skarm/xmlsec/transform/internal/xdm/html"
	"github.com/skarm/xmlsec/transform/internal/xdm/lexicon"
	"github.com/skarm/xmlsec/transform/internal/xpath"
)

func streamHTMLValue(ctx context.Context, w io.Writer, result ValueResult, definition *OutputDef) error {
	writer := htmlResultWriter(definition)

	explicitDoctype := definition.DoctypePublic != "" || definition.DoctypeSystem != ""
	buffer := bufio.NewWriterSize(w, 4096)
	sequence := serializationSequence{ctx: ctx, definition: definition}
	items := func(yield func(xdm.XMLItem, error) bool) {
		emitted := false
		automatic := effectiveHTMLVersion5(definition)

		for item, err := range sequence.items(result.Items) {
			if err == nil {
				err = xpath.ValidateHTMLItem(ctx, item, effectiveHTMLVersion5(definition))
			}

			if !emitted && serializationHasNonWhitespaceText(item) {
				automatic = false
			}

			if err == nil && !emitted && item.Node != nil && item.Node.Type() == xdm.ElementNode {
				err = writeHTMLResultDoctype(buffer, item.Node, definition, explicitDoctype, automatic)
				emitted = true
			}

			if !yield(item, err) || err != nil {
				return
			}
		}

		if err := writeRootlessHTMLDoctype(buffer, definition, emitted); err != nil {
			yield(xdm.XMLItem{}, err)
		}
	}

	if err := writer.WriteSequence(ctx, buffer, items); err != nil {
		return err
	}

	return buffer.Flush()
}

func htmlResultWriter(definition *OutputDef) htmlpkg.Writer {
	cdata := make(map[string]struct{}, len(definition.CDATASections))
	for _, name := range definition.CDATASections {
		cdata[name] = struct{}{}
	}

	normalization := definition.NormalizationForm
	if normalization == lexicon.NormFullyNormalized {
		normalization = normalizationFormNFC
	}

	writer := htmlpkg.NewWriter().DefaultDTD(false).Format(false).PreserveCase(true).
		EscapeControlChars(effectiveHTMLVersion5(definition)).
		NullNamespaceHTMLOnly(!effectiveHTMLVersion5(definition)).
		ForeignNamespaces(effectiveHTMLVersion5(definition)).
		CDATAElements(cdata).
		CharacterMap(definition.ResolvedCharMap).Normalization(normalization).Repertoire(definition.canEncode)
	if definition.EscapeURIAttributes != nil {
		writer = writer.EscapeURIAttributes(*definition.EscapeURIAttributes)
	}

	if definition.IncludeContentType == nil || *definition.IncludeContentType {
		media := definition.MediaType
		if media == "" {
			media = "text/html"
		}

		encoding := definition.Encoding
		if encoding == "" {
			encoding = "UTF-8"
		}

		writer = writer.ContentType(media + "; charset=" + encoding)
	}

	return writer
}

// Both HTML paths choose references before octet encoding, preserving CDATA
// boundaries and character-map provenance instead of rewriting serialized text.
func serializeEncodedHTML(w io.Writer, doc *xdm.Document, definition *OutputDef, charMap map[rune]string) error {
	output, finish, err := encodedOutput(context.Background(), w, definition)
	if err != nil {
		return err
	}

	if err := serializeHTMLResult(output, doc, definition, charMap); err != nil {
		return err
	}

	return finish()
}

func effectiveStreamMethod(result ValueResult, definition *OutputDef) string {
	root := firstSerializationElement(result.Items)
	if !definition.MethodExplicit && root != nil && root.LocalName() == methodHTML {
		if root.URI() == "" && allowsHTMLAutoDetection(definition, result.Document) {
			return methodHTML
		}

		if definition.languageVersion != 10 && !definition.implicitXMLMethod && root.URI() == lexicon.NamespaceXHTML {
			return methodXHTML
		}
	}

	if definition.Method == "" {
		return methodXML
	}

	return definition.Method
}

func serializationHasNonWhitespaceText(item xdm.XMLItem) bool {
	if item.Node == nil {
		return !isXMLWhitespaceOnly(item.Text)
	}

	return item.Node.Type() == xdm.TextNode && !isXMLWhitespaceOnly(xdm.CharacterData(item.Node))
}

func writeHTMLResultDoctype(w io.Writer, node xdm.Node, definition *OutputDef, explicit, automatic bool) error {
	if explicit {
		if err := xmloutput.WriteHTMLDoctype(w, methodHTML, definition.DoctypePublic, definition.DoctypeSystem); err != nil {
			return err
		}

		return writeFullString(w, "\n")
	}

	element, ok := node.(*xdm.Element)
	if automatic && ok && strings.EqualFold(element.LocalName(), methodHTML) && (element.URI() == "" || element.URI() == lexicon.NamespaceXHTML) {
		return writeFullString(w, "<!DOCTYPE html>")
	}

	return nil
}

func writeRootlessHTMLDoctype(w io.Writer, definition *OutputDef, emitted bool) error {
	if emitted || definition.DoctypePublic == "" && definition.DoctypeSystem == "" {
		return nil
	}

	return writeHTMLResultDoctype(w, nil, definition, true, false)
}
