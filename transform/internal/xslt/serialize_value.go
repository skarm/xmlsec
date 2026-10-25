package xslt

import (
	"context"
	"io"

	"github.com/skarm/xmlsec/internal/lexicon"
	"github.com/skarm/xmlsec/transform/internal/xdm"
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
	if err := validateSerializationParams(ctx, definition, result.Document); err != nil {
		return err
	}

	if (definition.Method == lexicon.MethodXML || definition.Method == lexicon.MethodXHTML) && (definition.DoctypeSystem != "" || definition.Standalone == lexicon.ValueYes || definition.Standalone == lexicon.ValueNo) {
		if err := xpath.ValidateSerializationDocument(ctx, result.Items, definition.ItemSeparator); err != nil {
			return err
		}
	}

	if handled, err := streamValue(ctx, w, result, definition); handled {
		return err
	}

	if definition.Method == lexicon.MethodAdaptive {
		doc, err := xdm.CopyDoc(result.Document)
		if err != nil {
			return err
		}

		return SerializeItems(ctx, w, result.Items, doc, definition)
	}

	doc, err := xpath.NormalizeSerialization(ctx, result.Items, definition.ItemSeparator, "")
	if err != nil {
		return err
	}

	return serializeResult(ctx, w, doc, definition)
}

// streamValue reports handled=false only before writing anything. This is an
// internal implementation choice, not a restriction on writer-based public APIs.
func streamValue(ctx context.Context, w io.Writer, result ValueResult, definition *OutputDef) (bool, error) {
	switch definition.Method {
	case lexicon.MethodXML, lexicon.MethodText, lexicon.MethodHTML, lexicon.MethodJSON:
	default:
		return false, nil
	}

	if definition.Method != lexicon.MethodJSON && (sequenceHasDOEMarkers(result.Items) || definition.NormalizationForm == lexicon.NormFullyNormalized) {
		return false, nil
	}

	writer, closeOutput, err := encodedOutput(ctx, w, definition)
	if err != nil {
		return true, err
	}

	switch definition.Method {
	case lexicon.MethodXML:
		err = streamXMLValue(ctx, writer, result, definition)
	case lexicon.MethodText:
		err = streamTextValue(ctx, writer, result, definition)
	case lexicon.MethodHTML:
		err = streamHTMLValue(ctx, writer, result, definition)
	case lexicon.MethodJSON:
		err = SerializeItems(ctx, writer, result.Items, result.Document, definition)
	}

	if err != nil {
		return true, err
	}

	return true, closeOutput()
}

// NormalizeExecution applies stylesheet-directed or forced final tree
// construction to raw values without serializing or modifying their nodes.
func NormalizeExecution(ctx context.Context, execution *Execution, forceTree *bool, baseURI string) (*Execution, error) {
	primary, err := normalizeValue(ctx, execution.Primary, forceTree, baseURI)
	if err != nil {
		return nil, err
	}

	result := &Execution{Primary: primary, Secondary: make(map[string]ValueResult, len(execution.Secondary))}
	for uri, value := range execution.Secondary {
		normalized, err := normalizeValue(ctx, value, forceTree, uri)
		if err != nil {
			return nil, err
		}

		result.Secondary[uri] = normalized
	}

	return result, ctx.Err()
}

func normalizeValue(ctx context.Context, value ValueResult, forceTree *bool, baseURI string) (ValueResult, error) {
	buildTree := true

	var separator *string

	if value.Output != nil {
		buildTree = !isItemSerializationMethod(value.Output.Method)
		if value.Output.BuildTree != nil {
			buildTree = *value.Output.BuildTree
		}

		separator = value.Output.ItemSeparator
	}

	if forceTree != nil {
		buildTree = *forceTree
	}

	if !buildTree {
		return value, ctx.Err()
	}

	if baseURI == "" && value.Document != nil {
		baseURI = value.Document.URL()
	}

	doc, err := xpath.NormalizeSerialization(ctx, value.Items, separator, baseURI)
	if err != nil {
		return ValueResult{}, err
	}

	value.Document = doc
	value.Items = xdm.ItemSlice{xdm.NodeItem{Node: doc}}

	return value, nil
}
