package xslt

import (
	"context"
	"io"
	"strings"

	"github.com/skarm/xmlsec/transform/internal/xdm"
	"github.com/skarm/xmlsec/transform/internal/xdm/lexicon"
	"github.com/skarm/xmlsec/transform/internal/xpath"
)

// Adaptive values use one implementation across XPath and XSLT. Node items
// retain the host's XML serialization parameters and original input ownership.
func serializeAdaptiveItems(ctx context.Context, w io.Writer, items xdm.Sequence, doc *xdm.Document, definition *OutputDef) error {
	if xdm.SequenceLen(items) == 0 && doc != nil && doc.FirstChild() != nil {
		items = xdm.ItemSlice{xdm.NodeItem{Node: doc}}
	}

	options := streamXMLWriteOptions(definition, strings.ToLower(definition.Encoding))
	if options.Normalization == lexicon.NormFullyNormalized {
		options.Normalization = normalizationFormNFC
	}

	writer := xdm.XMLSerialization{XMLWriteOptions: options, Encoding: definition.Encoding, OmitDeclaration: definition.OmitDeclaration, OmitDoctype: definition.DoctypeSystem == "", CompactDeclaration: !definition.Indent}
	if definition.Standalone == lexicon.ValueYes || definition.Standalone == lexicon.ValueNo {
		writer.Standalone = definition.Standalone
	}

	if definition.DoctypeSystem != "" {
		writer.Doctype = &xdm.Doctype{PublicID: definition.DoctypePublic, SystemID: definition.DoctypeSystem}
	}

	return (xpath.AdaptiveSerialization{XML: writer, ItemSeparator: definition.ItemSeparator}).WriteTo(ctx, w, items)
}

// Construction can defer separators while its fallback tree is markup-only.
func adaptiveStandaloneMarkupDocument(doc *xdm.Document) bool {
	if doc == nil || doc.FirstChild() == nil {
		return false
	}

	for child := range xdm.Children(doc) {
		if child.Type() != xdm.CommentNode && child.Type() != xdm.ProcessingInstructionNode {
			return false
		}
	}

	return true
}
