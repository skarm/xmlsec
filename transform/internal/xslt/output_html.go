// Derived from lestrrat-go/helium at 7362c0a70122a757780f4d0b545a9b370dead6ab.
// Copyright (c) 2015 lestrrat. MIT License; see licenses/MIT-helium.txt at the repository root.

package xslt

import (
	"context"
	"io"
	"strings"

	"github.com/skarm/xmlsec/internal/lexicon"
	"github.com/skarm/xmlsec/transform/internal/xdm"
	htmlpkg "github.com/skarm/xmlsec/transform/internal/xdm/html"
)

func serializeHTML(w io.Writer, doc *xdm.Document, outDef *OutputDef, charMap map[rune]string) error {
	writer := htmlResultWriter(outDef).DOEMarkers(true).CharacterMap(charMap)
	return serializeHTMLChildren(w, doc, writer, outDef)
}

func serializeHTMLChildren(w io.Writer, doc *xdm.Document, hw htmlpkg.Writer, outDef *OutputDef) error {
	emitted := false
	automatic := effectiveHTMLVersion5(outDef)
	explicit := outDef.DoctypePublic != "" || outDef.DoctypeSystem != ""
	items := func(yield func(xdm.XMLItem, error) bool) {
		for child := range xdm.Children(doc) {
			if !emitted && serializationHasNonWhitespaceText(xdm.XMLItem{Node: child}) {
				automatic = false
			}

			if child.Type() == xdm.ElementNode && !emitted {
				if err := writeHTMLResultDoctype(w, child, outDef, explicit, automatic); err != nil {
					yield(xdm.XMLItem{}, err)
					return
				}

				emitted = true
			}

			if !yield(xdm.XMLItem{Node: child}, nil) {
				return
			}
		}

		if err := writeRootlessHTMLDoctype(w, outDef, emitted); err != nil {
			yield(xdm.XMLItem{}, err)
		}
	}

	return hw.WriteSequence(context.Background(), w, items)
}

func allowsAutomaticResultDoctype(doc *xdm.Document) bool {
	for child := range xdm.Children(doc) {
		if child.Type() == xdm.ElementNode {
			return true
		}

		if serializationHasNonWhitespaceText(xdm.XMLItem{Node: child}) {
			return false
		}
	}

	return false
}

// XHTML uses the common XML writer, with structural rules applied to owned
// nodes and original attribute values rather than to serialized markup.
func serializeXHTML(w io.Writer, doc *xdm.Document, definition *OutputDef, charMap map[rune]string) error {
	owned, err := xdm.CopyDoc(doc)
	if err != nil {
		return err
	}

	return serializeOwnedXHTML(w, owned, definition, charMap)
}

// The caller transfers a private normalized tree; namespace and metadata edits
// must never reach nodes retained by a reusable Result or borrowed document.
func serializeOwnedXHTML(w io.Writer, owned *xdm.Document, definition *OutputDef, charMap map[rune]string) error {
	html5 := isHTMLVersion5(definition.HTMLVersion)
	contentType := ""

	if definition.IncludeContentType == nil || *definition.IncludeContentType {
		media, encoding := definition.MediaType, definition.Encoding
		if media == "" {
			media = "text/html"
		}

		if encoding == "" {
			encoding = lexicon.EncodingUTF8U
		}

		contentType = media + "; charset=" + encoding
	}

	if err := htmlpkg.PrepareXHTML(context.Background(), owned, html5, contentType); err != nil {
		return err
	}

	root := owned.DocumentElement()
	if definition.DoctypeSystem != "" && root != nil {
		owned.SetDoctype(root.Name(), definition.DoctypePublic, definition.DoctypeSystem)
	} else if html5 && root != nil && htmlpkg.XHTMLIsElement(root.URI(), root.LocalName(), true) && strings.EqualFold(root.LocalName(), lexicon.MethodHTML) && allowsAutomaticResultDoctype(owned) {
		owned.SetDoctype(root.LocalName(), "", "")
	} else {
		owned.Doctype = nil
	}

	options := streamXMLWriteOptions(definition, strings.ToLower(definition.Encoding))
	options.CharacterMap, options.DOEMarkers = charMap, true
	escapeURI := definition.EscapeURIAttributes == nil || *definition.EscapeURIAttributes
	htmlpkg.ConfigureXHTML(&options, html5, escapeURI, definition.serializationVersion)

	writer := xdm.XMLSerialization{XMLWriteOptions: options, Encoding: definition.Encoding, OmitDeclaration: definition.OmitDeclaration, CompactDeclaration: true}
	if definition.Standalone == lexicon.ValueYes || definition.Standalone == lexicon.ValueNo {
		writer.Standalone = definition.Standalone
	}

	return xmlInvalidCharError(writer.WriteTo(w, owned))
}

func serializeEncodedXHTML(w io.Writer, doc *xdm.Document, definition *OutputDef, charMap map[rune]string) error {
	output, finish, err := encodedOutput(context.Background(), w, definition)
	if err != nil {
		return err
	}

	if err = serializeXHTML(output, doc, definition, charMap); err != nil {
		return err
	}

	return finish()
}

func serializeEncodedOwnedXHTML(ctx context.Context, w io.Writer, owned *xdm.Document, definition *OutputDef) error {
	if err := validateSerializationParams(ctx, definition, owned); err != nil {
		return err
	}

	output, finish, err := encodedOutput(ctx, w, definition)
	if err != nil {
		return err
	}

	if err := serializeOwnedXHTML(output, owned, definition, definition.ResolvedCharMap); err != nil {
		return err
	}

	return finish()
}
