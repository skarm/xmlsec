package xslt

import (
	"bufio"
	"context"
	"io"
	"strings"

	"github.com/skarm/xmlsec/internal/xmloutput"
	"github.com/skarm/xmlsec/transform/internal/xdm"
	htmlpkg "github.com/skarm/xmlsec/transform/internal/xdm/html"
)

func streamHTMLValue(ctx context.Context, w io.Writer, result ValueResult, definition *OutputDef) error {
	writer := htmlpkg.NewWriter().DefaultDTD(false).Format(false).PreserveCase(true).
		EscapeControlChars(effectiveHTMLVersion5(definition)).
		NullNamespaceHTMLOnly(isHTMLVersionBelow5(definition.HTMLVersion)).
		ForeignNamespaces(isHTMLVersion5(definition.HTMLVersion)).
		CharacterMap(definition.ResolvedCharMap).Normalization(definition.NormalizationForm).Repertoire(definition.canEncode)
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

	root := firstSerializationElement(result.Items)

	explicitDoctype := definition.DoctypePublic != "" || definition.DoctypeSystem != ""
	if explicitDoctype {
		name := "html"
		if root != nil {
			name = root.Name()
		}

		if err := xmloutput.WriteHTMLDoctype(w, name, definition.DoctypePublic, definition.DoctypeSystem); err != nil {
			return err
		}

		if err := writeFullString(w, "\n"); err != nil {
			return err
		}
	}

	buffer := bufio.NewWriterSize(w, 4096)
	sequence := serializationSequence{ctx: ctx, definition: definition}
	items := func(yield func(xdm.XMLItem, error) bool) {
		emitted := explicitDoctype || !isHTMLVersion5(definition.HTMLVersion)
		for item, err := range sequence.items(result.Items) {
			if err == nil && !emitted && item.Node != nil && item.Node.Type() == xdm.ElementNode {
				err = writeFullString(buffer, "<!DOCTYPE html>")
				emitted = true
			}

			if !yield(item, err) || err != nil {
				return
			}
		}
	}

	if err := writer.WriteSequence(ctx, buffer, items); err != nil {
		return err
	}

	return buffer.Flush()
}

func effectiveStreamMethod(result ValueResult, definition *OutputDef) string {
	root := firstSerializationElement(result.Items)
	if !definition.MethodExplicit && root != nil && strings.EqualFold(root.LocalName(), methodHTML) && root.URI() == "" && allowsHTMLAutoDetection(definition, result.Document) {
		return methodHTML
	}

	if definition.Method == "" {
		return methodXML
	}

	return definition.Method
}
