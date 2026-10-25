// Derived from lestrrat-go/helium at 7362c0a70122a757780f4d0b545a9b370dead6ab.
// Copyright (c) 2015 lestrrat. MIT License; see licenses/MIT-helium.txt at the repository root.

package xpath

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"math"
	"strings"
	"unicode/utf8"

	"github.com/skarm/xmlsec/transform/internal/xdm"
	"github.com/skarm/xmlsec/transform/internal/xdm/lexicon"
)

func lookupFunctionsJsonXml(name string) (*builtinFunc, bool) {
	switch name {
	case "json-to-xml":
		return &builtinFunc{name: name, min: 1, max: 2, fn: fnJSONToXML}, true
	case "xml-to-json":
		return &builtinFunc{name: name, min: 1, max: 2, fn: fnXMLToJSON}, true
	}

	return nil, false
}

func fnJSONToXML(ctx context.Context, args []xdm.Sequence) (xdm.Sequence, error) {
	// Coerce the xs:string? input FIRST so an atomized-empty argument (empty
	// array / nilled node) returns the empty sequence \u2014 like a syntactically
	// empty one \u2014 without parsing the options map, matching F&O 3.1.
	s, empty, err := coerceAtomizedString(ctx, args[0])
	if err != nil {
		return nil, err
	}

	if empty {
		return nil, nil
	}

	opts, err := parseJSONToXMLOptions(ctx, args)
	if err != nil {
		return nil, err
	}

	if ec := getFnContext(ctx); opts.validate && (ec == nil || ec.schemaDeclarations == nil) {
		return nil, &xdm.Error{Code: errCodeFOJS0004, Message: "json-to-xml: schema validation and typed data are unavailable"}
	}

	s = strings.TrimPrefix(s, "\uFEFF")

	s, invalidEsc, err := preprocessJSONStringLiterals(s)
	if err != nil {
		return nil, err
	}

	opts.invalidEsc = invalidEsc

	dec := json.NewDecoder(strings.NewReader(s))
	dec.UseNumber()

	item, err := parseJSONValue(ctx, dec, opts, newJSONBudget(ctx), 0)
	if err != nil {
		return nil, err
	}

	var extra json.Token

	extra, err = dec.Token()
	if err == nil {
		return nil, &xdm.Error{Code: errCodeFOJS0001, Message: fmt.Sprintf("unexpected trailing content after JSON value: %v", extra)}
	}

	if !errors.Is(err, io.EOF) {
		return nil, &xdm.Error{Code: errCodeFOJS0001, Message: fmt.Sprintf("invalid trailing content: %v", err)}
	}

	ec := getFnContext(ctx)

	doc := xdm.NewDefaultDocument()
	if ec != nil && ec.baseURI != "" {
		doc.SetURL(ec.baseURI)
	}

	// When validate=true(), record a type annotation for every result node so
	// that downstream instance-of / schema-aware type tests over the produced
	// tree (element(j:map, j:mapType), element(j:string, j:stringType), ...)
	// observe the types defined by the json-to-xml result schema. The mapping
	// is a fixed function of each node's JSON kind, so no general XSD validation
	// pass is required.
	var annotations map[xdm.Node]string
	if opts.validate {
		annotations = make(map[xdm.Node]string)
	}

	root, err := buildJSONToXMLTree(doc, item, opts, annotations)
	if err != nil {
		return nil, err
	}

	if err := doc.SetDocumentElement(root); err != nil {
		return nil, &xdm.Error{Code: errCodeFOER0000, Message: fmt.Sprintf("json-to-xml: failed to build result: %v", err)}
	}

	if opts.validate && ec != nil && len(annotations) > 0 {
		installJSONToXMLAnnotations(ec, annotations)
	}

	return xdm.ItemSlice{xdm.NodeItem{Node: doc}}, nil
}

// installJSONToXMLAnnotations merges the json-to-xml result-tree annotations
// into the evaluation context's node→type map. The map handed to the evaluator
// by the caller (cfg.typeAnnotations) is shared across concurrent Evaluate
// calls and must not be mutated in place; this copies it into a fresh map owned
// by the per-evaluation evalContext before adding the new nodes' annotations.
// The new nodes only exist in this call's freshly built result tree, so the
// merge cannot collide with annotations for any pre-existing input node.
func installJSONToXMLAnnotations(ec *evalContext, annotations map[xdm.Node]string) {
	merged := make(map[xdm.Node]string, len(ec.typeAnnotations)+len(annotations))
	maps.Copy(merged, ec.typeAnnotations)
	maps.Copy(merged, annotations)
	ec.typeAnnotations = merged
}

// jsonToXMLTypeAnnotation maps a json-to-xml result element name to the type
// annotation defined by the json-to-xml result schema (schema-for-json.xsd),
// whose target namespace is the fn namespace. The boolean element is typed
// directly as xs:boolean; the others use the named complex/simple types.
func jsonToXMLTypeAnnotation(name string) string {
	switch name {
	case jsonKindMap:
		return xdm.QAnnotation(NSFn, "mapType")
	case jsonKindArray:
		return xdm.QAnnotation(NSFn, "arrayType")
	case lexicon.TypeString:
		return xdm.QAnnotation(NSFn, "stringType")
	case lexicon.TypeNumber:
		return xdm.QAnnotation(NSFn, "numberType")
	case lexicon.TypeBoolean:
		return xdm.TypeBoolean
	case jsonKindNull:
		return xdm.QAnnotation(NSFn, "nullType")
	default:
		return ""
	}
}

func buildJSONToXMLTree(doc *xdm.Document, item xdm.Item, opts jsonOptions, annotations map[xdm.Node]string) (*xdm.Element, error) {
	elem, err := createJSONToXMLElement(doc, jsonToXMLItemName(item), annotations)
	if err != nil {
		return nil, err
	}

	if err := populateJSONToXMLElement(doc, elem, item, opts, annotations); err != nil {
		return nil, err
	}

	return elem, nil
}

func jsonToXMLItemName(item xdm.Item) string {
	switch value := item.(type) {
	case xdm.MapItem:
		return jsonKindMap
	case xdm.ArrayItem:
		return jsonKindArray
	case xdm.JSONNumber:
		return lexicon.TypeNumber
	case xdm.AtomicValue:
		switch value.TypeName {
		case xdm.TypeString:
			return lexicon.TypeString
		case xdm.TypeBoolean:
			return lexicon.TypeBoolean
		default:
			return lexicon.TypeNumber
		}
	default:
		return jsonKindNull
	}
}

func createJSONToXMLElement(doc *xdm.Document, name string, annotations map[xdm.Node]string) (*xdm.Element, error) {
	elem, err := doc.CreateElement(name)
	if err != nil {
		return nil, err
	}

	if annotations != nil {
		if annotation := jsonToXMLTypeAnnotation(name); annotation != "" {
			annotations[elem] = annotation
		}
	}

	// Every element declares fn so an extracted descendant serializes alone.
	if err := elem.DeclareNamespace("", NSFn); err != nil {
		return nil, &xdm.Error{Code: errCodeFOER0000, Message: fmt.Sprintf("json-to-xml: failed to build result: %v", err)}
	}

	if err := elem.SetActiveNamespace("", NSFn); err != nil {
		return nil, &xdm.Error{Code: errCodeFOER0000, Message: fmt.Sprintf("json-to-xml: failed to build result: %v", err)}
	}

	return elem, nil
}

func populateJSONToXMLElement(doc *xdm.Document, elem *xdm.Element, item xdm.Item, opts jsonOptions, annotations map[xdm.Node]string) error {
	switch value := item.(type) {
	case nil:
		return nil
	case xdm.JSONNumber:
		// Retain exact JSON lexical forms, including exponent spelling and -0.
		return appendJSONToXMLText(elem, value.Lexical, "numeric")
	case xdm.MapItem:
		return buildJSONToXMLMapEntries(value, doc, opts, annotations, elem)
	case xdm.ArrayItem:
		return buildJSONToXMLTreeMembersView(&value, doc, &opts, annotations, elem)
	case xdm.AtomicValue:
		return appendJSONToXMLAtomic(elem, value, opts)
	default:
		return &xdm.Error{Code: errCodeFOER0000, Message: fmt.Sprintf("json-to-xml: unsupported item type %T", item)}
	}
}

func buildJSONToXMLMapEntries(value xdm.MapItem, doc *xdm.Document, opts jsonOptions, annotations map[xdm.Node]string, elem *xdm.Element) error {
	return value.ForEachView(func(key xdm.AtomicValue, member xdm.Sequence) error {
		child, err := buildJSONToXMLTree(doc, jsonSequenceToItem(member), opts, annotations)
		if err != nil {
			return err
		}

		keyText := key.StringVal()
		_ = child.SetAttribute("key", keyText)
		// Escaped-key is present only when escape=true and a backslash occurs.
		if opts.escape && strings.Contains(keyText, "\\") {
			_ = child.SetAttribute("escaped-key", lexicon.ValueTrue)
		}

		if err := elem.AddChild(child); err != nil {
			return &xdm.Error{Code: errCodeFOER0000, Message: fmt.Sprintf("json-to-xml: failed to attach child: %v", err)}
		}

		return nil
	})
}

func appendJSONToXMLAtomic(elem *xdm.Element, value xdm.AtomicValue, opts jsonOptions) error {
	switch value.TypeName {
	case xdm.TypeString:
		// Escaped strings carry this attribute only when a backslash occurs.
		if opts.escape && strings.Contains(value.StringVal(), "\\") {
			_ = elem.SetAttribute("escaped", lexicon.ValueTrue)
		}

		return appendJSONToXMLText(elem, value.StringVal(), lexicon.TypeString)
	case xdm.TypeBoolean:
		text := lexicon.ValueFalse
		if value.BooleanVal() {
			text = lexicon.ValueTrue
		}

		return appendJSONToXMLText(elem, text, lexicon.TypeBoolean)
	default:
		text, err := atomicToString(value)
		if err != nil {
			return &xdm.Error{Code: errCodeFOER0000, Message: fmt.Sprintf("json-to-xml: failed to format numeric value: %v", err)}
		}

		return appendJSONToXMLText(elem, text, "numeric")
	}
}

func appendJSONToXMLText(elem *xdm.Element, text, kind string) error {
	if err := elem.AppendText(text); err != nil {
		return &xdm.Error{Code: errCodeFOER0000, Message: fmt.Sprintf("json-to-xml: failed to append %s value: %v", kind, err)}
	}

	return nil
}

func jsonSequenceToItem(seq xdm.Sequence) xdm.Item {
	if xdm.SequenceLen(seq) == 0 {
		return nil
	}

	return seq.Get(0)
}

func parseJSONToXMLOptions(ctx context.Context, args []xdm.Sequence) (jsonOptions, error) {
	opts := jsonOptions{duplicates: nameRetain, retainNumberLexical: true}
	if len(args) <= 1 || xdm.SequenceLen(args[1]) == 0 {
		return opts, nil
	}

	if xdm.SequenceLen(args[1]) != 1 {
		return opts, &xdm.Error{Code: lexicon.ErrXPTY0004, Message: "json-to-xml options must be a single map"}
	}

	options, ok := args[1].Get(0).(xdm.MapItem)
	if !ok {
		return opts, &xdm.Error{Code: lexicon.ErrXPTY0004, Message: "json-to-xml options must be a map"}
	}

	var err error

	opts.liberal, err = parseJSONBooleanOption(ctx, options, "liberal")
	if err != nil {
		return opts, err
	}

	opts.validate, err = parseJSONBooleanOption(ctx, options, "validate")
	if err != nil {
		return opts, err
	}

	opts.escape, err = parseJSONBooleanOption(ctx, options, "escape")
	if err != nil {
		return opts, err
	}

	duplicates, explicit, err := parseJSONXMLDuplicatesOption(ctx, options)
	if err != nil {
		return opts, err
	}

	opts.duplicates = duplicates
	// Validation defaults to reject and cannot retain duplicate keys.
	if opts.validate && !explicit {
		opts.duplicates = duplicatesReject
	}

	if opts.validate && opts.duplicates == nameRetain {
		return opts, &xdm.Error{Code: errCodeFOJS0005, Message: "json-to-xml: 'validate' cannot be combined with duplicates='retain'"}
	}

	if err := finalizeJSONFallbackOption(ctx, options, &opts); err != nil {
		return opts, err
	}

	return opts, nil
}

func parseJSONXMLDuplicatesOption(ctx context.Context, options xdm.MapItem) (string, bool, error) {
	value, found := options.Get(xdm.AtomicValue{TypeName: xdm.TypeString, Value: nameDuplicates})
	if !found {
		return nameRetain, false, nil
	}

	// Atomization precedes exactly-one cardinality, retaining FOTY0012.
	policy, err := coerceArgToStringRequired(ctx, value)
	if err != nil {
		if isNoTypedValueError(err) {
			return "", true, err
		}

		return "", true, &xdm.Error{Code: lexicon.ErrXPTY0004, Message: "option 'duplicates' must be a single xs:string"}
	}

	switch policy {
	case duplicatesReject, duplicatesUseFirst, nameRetain:
		return policy, true, nil
	case nameUseLast:
		return "", true, &xdm.Error{Code: errCodeFOJS0005, Message: "option 'duplicates' must not be 'use-last' for json-to-xml"}
	default:
		return "", true, &xdm.Error{Code: errCodeFOJS0005, Message: fmt.Sprintf("invalid value for 'duplicates' option: %q", policy)}
	}
}

type xmlToJSONOptions struct {
	indent bool
}

type xmlJSONInherited struct {
	escaped    bool
	escapedKey bool
}

type xmlJSONMeta struct {
	kind       string
	inherited  xmlJSONInherited
	hasKey     bool
	keyActual  string
	keyEncoded string
}

func fnXMLToJSON(ctx context.Context, args []xdm.Sequence) (xdm.Sequence, error) {
	if xdm.SequenceLen(args[0]) == 0 {
		return nil, nil
	}

	if xdm.SequenceLen(args[0]) != 1 {
		return nil, &xdm.Error{Code: lexicon.ErrXPTY0004, Message: "xml-to-json expects zero or one node"}
	}

	opts, err := parseXMLToJSONOptions(ctx, args)
	if err != nil {
		return nil, err
	}

	ni, ok := args[0].Get(0).(xdm.NodeItem)
	if !ok {
		return nil, &xdm.Error{Code: lexicon.ErrXPTY0004, Message: "xml-to-json expects an element or document node"}
	}

	root, err := xmlToJSONRootElement(ni.Node)
	if err != nil {
		return nil, err
	}

	jsonText, _, err := serializeJSONXMLElement(root, xmlJSONInherited{}, opts, 0)
	if err != nil {
		return nil, err
	}

	return xdm.SingleString(jsonText), nil
}

func parseXMLToJSONOptions(ctx context.Context, args []xdm.Sequence) (xmlToJSONOptions, error) {
	var opts xmlToJSONOptions
	if len(args) <= 1 {
		return opts, nil
	}

	if xdm.SequenceLen(args[1]) != 1 {
		return opts, &xdm.Error{Code: lexicon.ErrXPTY0004, Message: "xml-to-json options must be a single map"}
	}

	m, ok := args[1].Get(0).(xdm.MapItem)
	if !ok {
		return opts, &xdm.Error{Code: lexicon.ErrXPTY0004, Message: "xml-to-json options must be a map"}
	}

	var err error

	opts.indent, err = parseJSONBooleanOption(ctx, m, "indent")

	return opts, err
}

func xmlToJSONRootElement(node xdm.Node) (*xdm.Element, error) {
	switch n := node.(type) {
	case *xdm.Document:
		root := n.DocumentElement()
		if root == nil {
			return nil, &xdm.Error{Code: errCodeFOJS0006, Message: "xml-to-json: document has no document element"}
		}
		// FOJS0006: document must have exactly one element child.
		elemCount := 0

		for child := range xdm.Children(n) {
			if child.Type() == xdm.ElementNode {
				elemCount++
			}
		}

		if elemCount != 1 {
			return nil, &xdm.Error{Code: errCodeFOJS0006, Message: "xml-to-json: document must have exactly one element child"}
		}

		return root, nil
	case *xdm.Element:
		return n, nil
	default:
		return nil, &xdm.Error{Code: lexicon.ErrXPTY0004, Message: "xml-to-json expects an element or document node"}
	}
}

func serializeJSONXMLElement(elem *xdm.Element, inherited xmlJSONInherited, opts xmlToJSONOptions, depth int) (string, xmlJSONMeta, error) {
	meta, err := parseXMLJSONMeta(elem, inherited)
	if err != nil {
		return "", xmlJSONMeta{}, err
	}

	value, err := serializeJSONXMLContent(elem, meta, opts, depth)
	if err != nil {
		return "", xmlJSONMeta{}, err
	}

	return value, meta, nil
}

func serializeJSONXMLContent(elem *xdm.Element, meta xmlJSONMeta, opts xmlToJSONOptions, depth int) (string, error) {
	switch meta.kind {
	case jsonKindMap:
		return serializeJSONXMLMap(elem, meta.inherited, opts, depth)
	case jsonKindArray:
		return serializeJSONXMLArray(elem, meta.inherited, opts, depth)
	case lexicon.TypeString:
		return serializeJSONXMLString(elem, meta.inherited.escaped)
	case nameNumber:
		content, err := scalarElementText(elem, true)
		if err != nil {
			return "", err
		}

		return canonicalizeXMLJSONNumber(content)
	case fnNameBoolean:
		content, err := scalarElementText(elem, true)
		if err != nil {
			return "", err
		}

		return canonicalizeXMLJSONBoolean(content)
	case jsonKindNull:
		if err := validateNullElement(elem); err != nil {
			return "", err
		}

		return jsonKindNull, nil
	default:
		return "", &xdm.Error{Code: errCodeFOJS0006, Message: fmt.Sprintf("xml-to-json: unsupported element %s", meta.kind)}
	}
}

func serializeJSONXMLMap(elem *xdm.Element, inherited xmlJSONInherited, opts xmlToJSONOptions, depth int) (string, error) {
	children, err := jsonElementChildren(elem, true)
	if err != nil {
		return "", err
	}

	parts := make([]string, 0, len(children))

	seen := make(map[string]struct{}, len(children))
	for _, child := range children {
		value, meta, err := serializeJSONXMLElement(child, inherited, opts, depth+1)
		if err != nil {
			return "", err
		}

		if !meta.hasKey {
			return "", &xdm.Error{Code: errCodeFOJS0006, Message: "xml-to-json: map child is missing key attribute"}
		}

		if _, exists := seen[meta.keyActual]; exists {
			return "", &xdm.Error{Code: errCodeFOJS0006, Message: fmt.Sprintf("xml-to-json: duplicate key %q", meta.keyActual)}
		}

		seen[meta.keyActual] = struct{}{}
		parts = append(parts, "\""+meta.keyEncoded+"\":"+valueSeparator(opts.indent)+value)
	}

	return formatJSONComposite("{", "}", parts, depth, opts.indent), nil
}

func serializeJSONXMLArray(elem *xdm.Element, inherited xmlJSONInherited, opts xmlToJSONOptions, depth int) (string, error) {
	children, err := jsonElementChildren(elem, false)
	if err != nil {
		return "", err
	}

	parts := make([]string, 0, len(children))
	for _, child := range children {
		value, _, err := serializeJSONXMLElement(child, inherited, opts, depth+1)
		if err != nil {
			return "", err
		}

		parts = append(parts, value)
	}

	return formatJSONComposite("[", "]", parts, depth, opts.indent), nil
}

func serializeJSONXMLString(elem *xdm.Element, escaped bool) (string, error) {
	content, err := scalarElementText(elem, true)
	if err != nil {
		return "", err
	}

	if escaped {
		encoded, _, err := validateEscapedJSONContent(content)
		if err != nil {
			return "", err
		}

		return "\"" + encoded + "\"", nil
	}

	return "\"" + encodeJSONStringContent(content) + "\"", nil
}

func parseXMLJSONMeta(elem *xdm.Element, inherited xmlJSONInherited) (xmlJSONMeta, error) {
	if elem.URI() != NSFn {
		return xmlJSONMeta{}, &xdm.Error{Code: errCodeFOJS0006, Message: fmt.Sprintf("xml-to-json: invalid namespace %q", elem.URI())}
	}

	meta := xmlJSONMeta{
		kind:      elem.LocalName(),
		inherited: inherited,
	}

	switch meta.kind {
	case jsonKindMap, jsonKindArray, lexicon.TypeString, nameNumber, fnNameBoolean, jsonKindNull:
	default:
		return xmlJSONMeta{}, &xdm.Error{Code: errCodeFOJS0006, Message: fmt.Sprintf("xml-to-json: invalid element %q", meta.kind)}
	}

	for _, attr := range elem.Attributes() {
		switch attr.URI() {
		case "":
			switch attr.LocalName() {
			case "key":
				meta.hasKey = true
				meta.keyActual = attr.Value()
			case "escaped":
				v, err := parseXMLJSONBooleanAttr(attr.Value())
				if err != nil {
					return xmlJSONMeta{}, err
				}

				meta.inherited.escaped = v
			case "escaped-key":
				v, err := parseXMLJSONBooleanAttr(attr.Value())
				if err != nil {
					return xmlJSONMeta{}, err
				}

				meta.inherited.escapedKey = v
			default:
				return xmlJSONMeta{}, &xdm.Error{Code: errCodeFOJS0006, Message: fmt.Sprintf("xml-to-json: invalid attribute %q", attr.Name())}
			}
		case NSFn:
			return xmlJSONMeta{}, &xdm.Error{Code: errCodeFOJS0006, Message: fmt.Sprintf("xml-to-json: invalid attribute namespace for %q", attr.Name())}
		default:
			// Attributes in other namespaces are ignored.
		}
	}

	if meta.hasKey {
		if meta.inherited.escapedKey {
			encoded, actual, err := validateEscapedJSONContent(meta.keyActual)
			if err != nil {
				return xmlJSONMeta{}, err
			}

			meta.keyEncoded = encoded
			meta.keyActual = actual
		} else {
			meta.keyEncoded = encodeJSONStringContent(meta.keyActual)
		}
	}

	return meta, nil
}

func jsonElementChildren(elem *xdm.Element, insideMap bool) ([]*xdm.Element, error) {
	var children []*xdm.Element

	for child := range xdm.Children(elem) {
		switch v := child.(type) {
		case *xdm.Element:
			children = append(children, v)
		case *xdm.Text, *xdm.CDATASection:
			if strings.Trim(xdm.CharacterData(child), " \t\r\n") != "" {
				kind := jsonKindArray
				if insideMap {
					kind = jsonKindMap
				}

				return nil, &xdm.Error{Code: errCodeFOJS0006, Message: fmt.Sprintf("xml-to-json: %s contains non-whitespace text", kind)}
			}
		case *xdm.Comment, *xdm.ProcessingInstruction:
			continue
		default:
			return nil, &xdm.Error{Code: errCodeFOJS0006, Message: textXmlToJsonInvalidChildNode}
		}
	}

	return children, nil
}

func scalarElementText(elem *xdm.Element, allowComments bool) (string, error) {
	var b strings.Builder

	for child := range xdm.Children(elem) {
		switch child.Type() {
		case xdm.TextNode, xdm.CDATASectionNode:
			b.WriteString(xdm.CharacterData(child))
		case xdm.CommentNode, xdm.ProcessingInstructionNode:
			if !allowComments {
				return "", &xdm.Error{Code: errCodeFOJS0006, Message: textXmlToJsonInvalidChildNode}
			}
		case xdm.ElementNode:
			return "", &xdm.Error{Code: errCodeFOJS0006, Message: "xml-to-json: scalar value contains element children"}
		default:
			return "", &xdm.Error{Code: errCodeFOJS0006, Message: textXmlToJsonInvalidChildNode}
		}
	}

	return b.String(), nil
}

func validateNullElement(elem *xdm.Element) error {
	for child := range xdm.Children(elem) {
		switch child.Type() {
		case xdm.TextNode, xdm.CDATASectionNode:
			if strings.Trim(xdm.CharacterData(child), " \t\r\n") != "" {
				return &xdm.Error{Code: errCodeFOJS0006, Message: "xml-to-json: null element must not contain text"}
			}
		case xdm.CommentNode, xdm.ProcessingInstructionNode:
			continue
		case xdm.ElementNode:
			return &xdm.Error{Code: errCodeFOJS0006, Message: "xml-to-json: null element must not contain child elements"}
		default:
			return &xdm.Error{Code: errCodeFOJS0006, Message: textXmlToJsonInvalidChildNode}
		}
	}

	return nil
}

func parseXMLJSONBooleanAttr(s string) (bool, error) {
	switch strings.Trim(s, " \t\r\n") {
	case lexicon.ValueTrue, "1":
		return true, nil
	case lexicon.ValueFalse, "0":
		return false, nil
	default:
		return false, &xdm.Error{Code: errCodeFOJS0006, Message: fmt.Sprintf("xml-to-json: invalid boolean attribute value %q", s)}
	}
}

func canonicalizeXMLJSONBoolean(s string) (string, error) {
	switch strings.Trim(s, " \t\r\n") {
	case lexicon.ValueTrue, "1":
		return lexicon.ValueTrue, nil
	case lexicon.ValueFalse, "0":
		return lexicon.ValueFalse, nil
	default:
		return "", &xdm.Error{Code: errCodeFOJS0006, Message: fmt.Sprintf("xml-to-json: invalid boolean value %q", s)}
	}
}

func canonicalizeXMLJSONNumber(s string) (string, error) {
	norm := strings.Trim(s, " \t\r\n")
	if norm == "" {
		return "", &xdm.Error{Code: errCodeFOJS0006, Message: "xml-to-json: invalid number value"}
	}

	if strings.EqualFold(norm, "nan") || strings.Contains(strings.ToUpper(norm), "INF") {
		return "", &xdm.Error{Code: errCodeFOJS0006, Message: fmt.Sprintf("xml-to-json: invalid number value %q", s)}
	}

	norm = preprocessXMLJSONNumber(norm)

	av, err := CastFromString(norm, xdm.TypeDouble)
	if err != nil || math.IsInf(av.DoubleVal(), 0) || math.IsNaN(av.DoubleVal()) {
		return "", &xdm.Error{Code: errCodeFOJS0006, Message: fmt.Sprintf("xml-to-json: invalid number value %q", s)}
	}

	return formatXPathDouble(av.DoubleVal()), nil
}

func preprocessXMLJSONNumber(s string) string {
	sign := ""
	if strings.HasPrefix(s, "+") || strings.HasPrefix(s, "-") {
		sign = s[:1]
		s = s[1:]
	}

	exp := ""
	if idx := strings.IndexAny(s, "eE"); idx >= 0 {
		exp = s[idx:]
		s = s[:idx]
	}

	if strings.HasPrefix(s, ".") {
		s = "0" + s
	}

	s = strings.TrimSuffix(s, ".")
	if s == "" {
		s = "0"
	}

	intPart := s
	fracPart := ""

	if before, after, ok := strings.Cut(s, "."); ok {
		intPart = before
		fracPart = after
	}

	if intPart == "" {
		intPart = "0"
	}

	intPart = strings.TrimLeft(intPart, "0")
	if intPart == "" {
		intPart = "0"
	}

	if fracPart != "" {
		return sign + intPart + "." + fracPart + exp
	}

	return sign + intPart + exp
}

func validateEscapedJSONContent(s string) (string, string, error) {
	var (
		out     strings.Builder
		decoded strings.Builder
	)

	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		if r != '\\' {
			appendSerializedJSONStringRune(&out, r)
			decoded.WriteRune(r)

			i += size

			continue
		}

		if i+1 >= len(s) {
			return "", "", &xdm.Error{Code: errCodeFOJS0007, Message: "xml-to-json: invalid trailing backslash in escaped string"}
		}

		switch s[i+1] {
		case '"':
			out.WriteString(`\"`)
			decoded.WriteByte('"')

			i += 2
		case '\\':
			out.WriteString(`\\`)
			decoded.WriteByte('\\')

			i += 2
		case '/':
			out.WriteString(`\/`)
			decoded.WriteByte('/')

			i += 2
		case 'b':
			out.WriteString(`\b`)
			decoded.WriteByte('\b')

			i += 2
		case 'f':
			out.WriteString(`\f`)
			decoded.WriteByte('\f')

			i += 2
		case 'n':
			out.WriteString(`\n`)
			decoded.WriteByte('\n')

			i += 2
		case 'r':
			out.WriteString(`\r`)
			decoded.WriteByte('\r')

			i += 2
		case 't':
			out.WriteString(`\t`)
			decoded.WriteByte('\t')

			i += 2
		case 'u':
			encoded, actual, consumed, err := parseEscapedUnicodeSequence(s[i:])
			if err != nil {
				return "", "", err
			}

			out.WriteString(encoded)
			decoded.WriteString(actual)

			i += consumed
		default:
			return "", "", &xdm.Error{Code: errCodeFOJS0007, Message: fmt.Sprintf("xml-to-json: invalid escape sequence \\%c", s[i+1])}
		}
	}

	return out.String(), decoded.String(), nil
}

func parseEscapedUnicodeSequence(s string) (string, string, int, error) {
	if len(s) < 6 {
		return "", "", 0, &xdm.Error{Code: errCodeFOJS0007, Message: "xml-to-json: incomplete \\u escape"}
	}

	if s[0] != '\\' || s[1] != 'u' || !isHexQuad(s[2:6]) {
		return "", "", 0, &xdm.Error{Code: errCodeFOJS0007, Message: "xml-to-json: invalid \\u escape"}
	}

	cp, _ := parseJSONHexEscape(s[2:6])
	encoded := s[:6]

	switch {
	case cp >= 0xD800 && cp <= 0xDBFF:
		if len(s) < 12 || s[6] != '\\' || s[7] != 'u' || !isHexQuad(s[8:12]) {
			return "", "", 0, &xdm.Error{Code: errCodeFOJS0007, Message: "xml-to-json: invalid surrogate pair"}
		}

		cp2, _ := parseJSONHexEscape(s[8:12])
		if cp2 < 0xDC00 || cp2 > 0xDFFF {
			return "", "", 0, &xdm.Error{Code: errCodeFOJS0007, Message: "xml-to-json: invalid surrogate pair"}
		}

		r := rune(((cp - 0xD800) << 10) + (cp2 - 0xDC00) + 0x10000)

		return encoded + s[6:12], string(r), 12, nil
	case cp >= 0xDC00 && cp <= 0xDFFF:
		return "", "", 0, &xdm.Error{Code: errCodeFOJS0007, Message: "xml-to-json: invalid low surrogate"}
	default:
		return encoded, string(rune(cp)), 6, nil
	}
}

func isHexQuad(s string) bool {
	if len(s) != 4 {
		return false
	}

	for _, r := range s {
		switch {
		case r >= '0' && r <= '9':
		case r >= 'a' && r <= 'f':
		case r >= 'A' && r <= 'F':
		default:
			return false
		}
	}

	return true
}

func encodeJSONStringContent(s string) string {
	var b strings.Builder
	for _, r := range s {
		appendSerializedJSONStringRune(&b, r)
	}

	return b.String()
}

func formatJSONComposite(open, closeBracket string, parts []string, depth int, indent bool) string {
	if !indent || len(parts) == 0 {
		return open + strings.Join(parts, ",") + closeBracket
	}

	var b strings.Builder

	childIndent := strings.Repeat("  ", depth+1)
	parentIndent := strings.Repeat("  ", depth)

	b.WriteString(open)
	b.WriteByte('\n')

	for i, part := range parts {
		if i > 0 {
			b.WriteString(",\n")
		}

		b.WriteString(childIndent)
		b.WriteString(part)
	}

	b.WriteByte('\n')
	b.WriteString(parentIndent)
	b.WriteString(closeBracket)

	return b.String()
}

func valueSeparator(indent bool) string {
	if indent {
		return " "
	}

	return ""
}

func buildJSONToXMLTreeMembersView(v *xdm.ArrayItem, doc *xdm.Document, opts *jsonOptions, annotations map[xdm.Node]string, elem *xdm.Element) error {
	for _, member := range v.MembersView() {
		child, err := buildJSONToXMLTree(doc, jsonSequenceToItem(member), *opts, annotations)
		if err != nil {
			return err
		}

		if err := elem.AddChild(child); err != nil {
			return &xdm.Error{Code: errCodeFOER0000, Message: fmt.Sprintf("json-to-xml: failed to attach child: %v", err)}
		}
	}

	return nil
}
