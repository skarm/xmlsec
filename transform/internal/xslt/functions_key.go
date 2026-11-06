// Derived from lestrrat-go/helium at 7362c0a70122a757780f4d0b545a9b370dead6ab.
// Copyright (c) 2015 lestrrat. MIT License; see licenses/MIT-helium.txt at the repository root.

package xslt

import (
	"context"
	"errors"
	"fmt"
	"math/bits"
	"slices"

	"github.com/skarm/xmlsec/internal/lexicon"
	"github.com/skarm/xmlsec/internal/xmlchar"
	"github.com/skarm/xmlsec/transform/internal/xdm"
	uripath "github.com/skarm/xmlsec/transform/internal/xdm/uri"
	"github.com/skarm/xmlsec/transform/internal/xpath"
)

// Local names of system-property and available-system-properties QNames in the XSLT namespace; output serialization parameters use their own vocabulary.
const (
	systemPropertyProductVersion = "product-version"
	systemPropertyVendor         = "vendor"
	systemPropertyVendorURL      = "vendor-url"
	systemPropertyVersion        = "version"
	systemPropertyXPathVersion   = "xpath-version"
	systemPropertyXSDVersion     = "xsd-version"
)

type keyFunction struct {
	ec    *execContext
	scope *Stylesheet
}

func (f *keyFunction) MinArity() int { return 2 }

func (f *keyFunction) MaxArity() int { return 3 }

func (f *keyFunction) FuncParamTypesForArity(arity int) []xdm.SequenceType {
	return xsltFunctionTypes()[functionTypeKey{keyLocalName, arity}].params
}

func (f *keyFunction) FuncReturnTypeForArity(arity int) *xdm.SequenceType {
	return xsltFunctionTypes()[functionTypeKey{keyLocalName, arity}].result
}

func (f *keyFunction) BindFunctionReference() xpath.Function {
	return &keyFunction{ec: f.ec.captureFunctionContext(), scope: f.scope}
}

func (f *keyFunction) Call(ctx context.Context, args []xdm.Sequence) (xdm.Sequence, error) {
	ec, err := functionExecution(ctx, f.ec)
	if err != nil {
		return nil, err
	}

	ctx = withExecContext(ctx, ec)

	defer ec.pushPackage(f.scope)()

	return ec.fnKey(ctx, args)
}

func (ec *execContext) fnKey(ctx context.Context, args []xdm.Sequence) (xdm.Sequence, error) {
	if len(args) != 2 && len(args) != 3 {
		return nil, dynamicError(lexicon.ErrXPST0017, "key() requires two or three arguments")
	}

	name, err := keyArgumentName(ctx, args[0], ec.stylesheet.processorLanguage())
	if err != nil {
		return nil, err
	}

	defs := ec.effectiveKeys()[name]
	if len(defs) == 0 {
		return nil, dynamicError(errCodeXTDE1260, "unknown key %q", name)
	}

	root, err := ec.keyArgumentRoot(ctx, args)
	if err != nil {
		return nil, err
	}

	values, err := xpath.FnAtomize(ctx, args[1])
	if err != nil {
		return nil, err
	}

	var nodes []xdm.Node
	if defs[0].Composite {
		nodes, err = ec.lookupCompositeKey(ctx, name, values, root)
	} else {
		nodes, err = ec.lookupKeyValues(ctx, name, values, root)
	}

	if err != nil {
		return nil, err
	}

	if err := xpath.Charge(ctx, len(nodes)); err != nil {
		return nil, err
	}

	if len(nodes) > 1 {
		// Reserve the sorting work before indexing or comparing document positions.
		if err := xpath.Charge(ctx, len(nodes)*bits.Len(uint(len(nodes)))); err != nil {
			return nil, err
		}

		if ec.docOrderCache == nil {
			ec.docOrderCache = xpath.NewDocOrderCache()
		}

		ec.docOrderCache.BuildFrom(root)
		slices.SortStableFunc(nodes, ec.docOrderCache.Compare)
	}

	seq := make(xdm.ItemSlice, len(nodes))
	for i, node := range nodes {
		seq[i] = xdm.NodeItem{Node: node}
	}

	return seq, nil
}

func (ec *execContext) keyArgumentRoot(ctx context.Context, args []xdm.Sequence) (xdm.Node, error) {
	var root xdm.Node

	if len(args) == 3 {
		if xdm.SequenceLen(args[2]) != 1 {
			return nil, dynamicError(lexicon.ErrXPTY0004, "key() third argument must be one node")
		}

		node, ok := args[2].Get(0).(xdm.NodeItem)
		if !ok {
			return nil, dynamicError(lexicon.ErrXPTY0004, "key() third argument must be a node")
		}

		root = normalizeNode(node.Node)
	} else {
		root = xpath.FnContextNode(ctx)
	}

	if root == nil {
		return nil, dynamicError(errCodeXTDE1270, "key() requires a context node")
	}

	for ancestor := root; ancestor != nil; ancestor = ancestor.Parent() {
		if err := xpath.Charge(ctx, 1); err != nil {
			return nil, err
		}

		if ancestor.Parent() == nil && ancestor.Type() != xdm.DocumentNode {
			return nil, dynamicError(errCodeXTDE1270, "key() requires a document-rooted tree")
		}
	}

	if len(args) == 2 {
		root = documentRoot(root)
	}

	return root, nil
}

// system-property(name) returns XSLT system properties.
func (ec *execContext) fnSystemProperty(ctx context.Context, args []xdm.Sequence) (xdm.Sequence, error) {
	return introspectionSystemProperty(ctx, args, ec.stylesheet.processorLanguage(), ec.stylesheet.dynamicEvaluationDisabled)
}

// fnStreamAvailable implements XSLT stream-available(): it checks read policy
// and the resource prolog without loading a complete source tree. A true result
// does not imply W3C streamable execution support.
func (ec *execContext) fnStreamAvailable(ctx context.Context, args []xdm.Sequence) (xdm.Sequence, error) {
	const (
		errCodeFODC0005 = "FODC0005"
	)

	if xdm.SequenceLen(args[0]) == 0 {
		return xdm.SingleBoolean(false), nil
	}

	atom, err := xpath.AtomizeItem(args[0].Get(0))
	if err != nil {
		return nil, err
	}

	uri, err := xpath.AtomicToString(atom)
	if err != nil {
		return nil, err
	}

	resolved, err := xpath.ResolveDocumentURI(ctx, uri)
	if err != nil {
		if failure := preserveControlFailure(ctx, err); failure != nil {
			return nil, failure
		}

		if detail, ok := errors.AsType[*xdm.Error](err); ok && detail.Code == errCodeFODC0005 {
			return nil, err
		}

		return xdm.SingleBoolean(false), nil
	}

	if err := ec.CheckRead(ctx, resolved); err != nil {
		return nil, err
	}

	if doc, found := ec.docCache[ec.docCacheKey(resolved)]; found {
		_, err := ec.existingDocumentRead(ctx, doc)
		return xdm.SingleBoolean(err == nil), err
	}

	reader, err := ec.retrieveDocumentReader(ctx, resolved)
	if err != nil {
		if failure := preserveControlFailure(ctx, err); failure != nil {
			return nil, failure
		}

		if _, hostFailure := errors.AsType[*xdm.ResourceAccessError](err); hostFailure {
			return nil, err
		}

		return xdm.SingleBoolean(false), nil
	}

	var options xdm.ParseOptions
	if configured := ec.inputParseOptions(); configured != nil {
		options = *configured
	}

	options = options.WithByteLimit(ec.resourceLimit())
	err = options.CheckXMLProlog(ctx, reader)

	err = errors.Join(err, reader.Close())
	if failure := preserveControlFailure(ctx, err); failure != nil {
		return nil, failure
	}

	return xdm.SingleBoolean(err == nil), nil
}

// fnCurrentOutputURI implements current-output-uri() — returns the URI
// of the current output destination.
// Temporary local variables retain the URI; non-contextual calls and global
// initialization clear it independently of the output construction state.
func (ec *execContext) fnCurrentOutputURI(ctx context.Context, _ []xdm.Sequence) (xdm.Sequence, error) {
	if xpath.IsDynamicCall(ctx) || ec.inPatternMatch || ec.inSortKeyEval || ec.currentOutputURI == "" {
		return xdm.EmptySequence(), nil
	}

	return xdm.ItemSlice{xdm.AtomicValue{TypeName: xdm.TypeAnyURI, Value: ec.currentOutputURI}}, nil
}

// unparsed-entity-uri(name [, doc]) returns the URI of an unparsed entity.
func (ec *execContext) fnUnparsedEntityURI(ctx context.Context, args []xdm.Sequence) (xdm.Sequence, error) {
	return ec.unparsedEntity(ctx, args, nameUnparsedEntityURI, errCodeXTDE1370)
}

// unparsed-entity-public-id(name) returns the public identifier of an unparsed entity.
func (ec *execContext) fnUnparsedEntityPublicID(ctx context.Context, args []xdm.Sequence) (xdm.Sequence, error) {
	return ec.unparsedEntity(ctx, args, nameUnparsedEntityPublicID, errCodeXTDE1380)
}

func documentRoot(node xdm.Node) xdm.Node {
	for parent := node.Parent(); parent != nil; parent = node.Parent() {
		node = parent
	}

	return node
}

func keyArgumentName(ctx context.Context, arg xdm.Sequence, processor int) (string, error) {
	var name string

	if xpath.FnXPath10Compat(ctx) {
		var err error

		name, err = xpath.XPath10String(arg)
		if err != nil {
			return "", err
		}
	} else {
		atoms, err := xpath.FnAtomize(ctx, arg)
		if err != nil {
			return "", err
		}

		if len(atoms) != 1 || !isStringLikeType(atoms[0].TypeName) {
			return "", dynamicError(lexicon.ErrXPTY0004, "key name must be one xs:string")
		}

		name, err = xpath.AtomicToString(atoms[0])
		if err != nil {
			return "", err
		}
	}

	if processor < processorXSLT30 && !xmlchar.IsValidQName(name) {
		return "", dynamicError(errCodeXTDE1260, "invalid key name %q", name)
	}

	resolved, err := resolveIntrospectionName(name, "", errCodeXTDE1260, func(prefix string) (string, bool) { return xpath.FnNamespace(ctx, prefix) })
	if err != nil {
		return "", err
	}

	if resolved.URI == "" {
		return resolved.Local, nil
	}

	return xdm.ClarkName(resolved.URI, resolved.Local), nil
}

func introspectionSystemProperty(ctx context.Context, args []xdm.Sequence, processor int, disabled bool) (xdm.Sequence, error) {
	name, err := introspectionArgumentName(ctx, args, "", errCodeXTDE1390, processor)
	if err != nil {
		return nil, err
	}

	ns, local := name.URI, name.Local

	if ns != lexicon.NamespaceXSLT {
		return xdm.SingleString(""), nil
	}

	if local == nameSupportsDynamicEvaluation {
		if disabled {
			return xdm.SingleString(lexicon.ValueNo), nil
		}

		return xdm.SingleString(lexicon.ValueYes), nil
	}

	return systemPropertyValue(ctx, local, processor), nil
}

func systemPropertyValue(ctx context.Context, local string, processor int) xdm.Sequence {
	const (
		processorMajorVersionFormat = "%d.0"
		processorProductVersion     = "0.1"
		processorVendorURL          = "https://github.com/skarm/xmlsec"
	)

	// Text advertised by the version properties is distinct from encoded selector
	// integers and from XML output declaration versions.
	const (
		xpathVersion10Text     = "1.0"
		xpathVersion20Text     = "2.0"
		xpathVersion31Text     = "3.1"
		xmlSchemaVersion10Text = "1.0"
		xmlSchemaVersion11Text = "1.1"
	)

	switch local {
	case systemPropertyVersion:
		if processor == processorXSLT10 {
			return xdm.SingleDouble(xsltMajorVersion1)
		}

		return xdm.SingleString(fmt.Sprintf(processorMajorVersionFormat, processor/processorVersionScale))
	case systemPropertyVendor:
		return xdm.SingleString(processorProductName)
	case systemPropertyVendorURL:
		return xdm.SingleString(processorVendorURL)
	case nameProductName:
		return xdm.SingleString(processorProductName)
	case systemPropertyProductVersion:
		return xdm.SingleString(processorProductVersion)
	case nameIsSchemaAware:
		return xdm.SingleString(lexicon.ValueNo)
	case nameSupportsSerialization:
		return xdm.SingleString(lexicon.ValueYes)
	case textSupportsBackwardsCompatibility:
		return xdm.SingleString(lexicon.ValueYes)
	case nameSupportsNamespaceAxis:
		return xdm.SingleString(lexicon.ValueYes)
	case nameSupportsStreaming:
		return xdm.SingleString(lexicon.ValueNo)
	case nameSupportsDynamicEvaluation:
		if dynamicEvaluationDisabled(ctx) {
			return xdm.SingleString(lexicon.ValueNo)
		}

		return xdm.SingleString(lexicon.ValueYes)
	case textSupportsHigherOrderFunctions:
		return xdm.SingleString(lexicon.ValueYes)
	case systemPropertyXPathVersion:
		return xdm.SingleString(map[int]string{processorXSLT10: xpathVersion10Text, processorXSLT20: xpathVersion20Text, processorXSLT30: xpathVersion31Text}[processor])
	case systemPropertyXSDVersion:
		if xpath.XMLSchemaVersion(ctx) == xmlSchemaProfile10 {
			return xdm.SingleString(xmlSchemaVersion10Text)
		}

		return xdm.SingleString(xmlSchemaVersion11Text)
	default:
		return xdm.SingleString("")
	}
}

func fnAvailableSystemProperties(_ context.Context, _ []xdm.Sequence) (xdm.Sequence, error) {
	const (
		systemPropertyQNamePrefix = "xsl"
	)

	props := []string{
		systemPropertyVersion, systemPropertyVendor, systemPropertyVendorURL, nameProductName, systemPropertyProductVersion,
		nameIsSchemaAware, nameSupportsSerialization,
		textSupportsBackwardsCompatibility, nameSupportsNamespaceAxis,
		nameSupportsStreaming, nameSupportsDynamicEvaluation,
		textSupportsHigherOrderFunctions, systemPropertyXPathVersion, systemPropertyXSDVersion,
	}

	seq := make(xdm.ItemSlice, 0, len(props))
	for _, p := range props {
		seq = append(seq, xdm.AtomicValue{
			TypeName: xdm.TypeQName,
			Value:    xdm.QNameValue{Prefix: systemPropertyQNamePrefix, URI: lexicon.NamespaceXSLT, Local: p},
		})
	}

	return seq, nil
}

// xslMultiArityFunc wraps multiple xsl:function overloads (same QName,
// different arity) as a single xpath.Function that dispatches by arg count.

// unparsedEntity retains the prescribed context checks before looking up
// identifiers from the parsed document, without retrieving an unparsed entity.
func (ec *execContext) unparsedEntity(ctx context.Context, args []xdm.Sequence, functionName, errorCode string) (xdm.Sequence, error) {
	var item xdm.Item
	if len(args) == 2 {
		item = args[1].Get(0) // The declared node() signature enforces cardinality.
	} else {
		var err error

		item, err = xpath.FnContextItem(ctx)
		if err != nil {
			if ec.stylesheet.processorLanguage() < processorXSLT30 {
				return nil, dynamicError(errorCode, "%s requires a context node", functionName)
			}

			return nil, err
		}
	}

	node, ok := item.(xdm.NodeItem)
	if !ok {
		if ec.stylesheet.processorLanguage() < processorXSLT30 {
			return nil, dynamicError(errorCode, "%s requires a context node", functionName)
		}

		return nil, dynamicError(lexicon.ErrXPTY0004, "%s requires a node", functionName)
	}

	doc := documentNodeFromNode(node.Node)
	if doc == nil {
		return nil, dynamicError(errorCode, "%s requires a document-rooted tree", functionName)
	}

	atom, err := xpath.AtomizeItem(args[0].Get(0))
	if err != nil {
		return nil, err
	}

	name, err := xpath.AtomicToString(atom)
	if err != nil {
		return nil, err
	}

	entity, found := doc.UnparsedEntity(name)
	value := ""

	if found {
		value = entity.PublicID
		if functionName == nameUnparsedEntityURI {
			value, err = uripath.ResolveIRIReference(entity.SystemID, entity.BaseURI)
			if err != nil {
				return nil, err
			}
		}
	}

	if functionName == nameUnparsedEntityURI {
		return xdm.ItemSlice{xdm.AtomicValue{TypeName: xdm.TypeAnyURI, Value: value}}, nil
	}

	return xdm.SingleString(value), nil
}

// documentNodeFromNode walks up to the root of a node's tree and returns
// the document node if the root is a document, or nil otherwise.
func documentNodeFromNode(n xdm.Node) *xdm.Document {
	n = normalizeNode(n)
	if n == nil {
		return nil
	}

	for {
		parent := normalizeNode(n.Parent())
		if parent == nil {
			break
		}

		n = parent
	}

	if doc, ok := n.(*xdm.Document); ok {
		return doc
	}

	return nil
}
