// Derived from lestrrat-go/helium at 7362c0a70122a757780f4d0b545a9b370dead6ab.
// Copyright (c) 2015 lestrrat. MIT License; see licenses/MIT-helium.txt at the repository root.

package xslt

import (
	"context"
	"errors"
	"fmt"
	"math/bits"
	"slices"
	"strings"

	"github.com/skarm/xmlsec/internal/xmlchar"
	"github.com/skarm/xmlsec/transform/internal/xdm"
	"github.com/skarm/xmlsec/transform/internal/xdm/lexicon"
	"github.com/skarm/xmlsec/transform/internal/xpath"
)

type keyFunction struct {
	ec    *execContext
	scope *Stylesheet
}

func (f *keyFunction) MinArity() int { return 2 }
func (f *keyFunction) MaxArity() int { return 3 }
func (f *keyFunction) FuncParamTypesForArity(arity int) []xdm.SequenceType {
	return xsltFunctionTypes()[functionTypeKey{nameKey2, arity}].params
}

func (f *keyFunction) FuncReturnTypeForArity(arity int) *xdm.SequenceType {
	return xsltFunctionTypes()[functionTypeKey{nameKey2, arity}].result
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
		return nil, dynamicError("XPST0017", "key() requires two or three arguments")
	}

	name, err := keyArgumentName(ctx, args[0])
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

func documentRoot(node xdm.Node) xdm.Node {
	for node.Parent() != nil {
		node = node.Parent()
	}

	return node
}

func keyArgumentName(ctx context.Context, arg xdm.Sequence) (string, error) {
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
			return "", dynamicError(errCodeXPTY0004, "key name must be one xs:string")
		}

		name, err = xpath.AtomicToString(atoms[0])
		if err != nil {
			return "", err
		}
	}

	if !xmlchar.IsValidQName(name) && !isValidEQName(name) {
		return "", dynamicError(errCodeXTDE1260, "invalid key name %q", name)
	}

	if strings.HasPrefix(name, "Q{") {
		return resolveQName(name, nil), nil
	}

	if prefix, local, found := strings.Cut(name, ":"); found {
		uri, ok := xpath.FnNamespace(ctx, prefix)
		if !ok || uri == "" {
			return "", dynamicError(errCodeXTDE1260, "undeclared prefix in key name %q", name)
		}

		return xdm.ClarkName(uri, local), nil
	}

	return name, nil
}

func (ec *execContext) keyArgumentRoot(ctx context.Context, args []xdm.Sequence) (xdm.Node, error) {
	var root xdm.Node

	if len(args) == 3 {
		if xdm.SequenceLen(args[2]) != 1 {
			return nil, dynamicError(errCodeXPTY0004, "key() third argument must be one node")
		}

		node, ok := args[2].Get(0).(xdm.NodeItem)
		if !ok {
			return nil, dynamicError(errCodeXPTY0004, "key() third argument must be a node")
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

func introspectionSystemProperty(ctx context.Context, args []xdm.Sequence, processor int, disabled bool) (xdm.Sequence, error) {
	name, err := introspectionArgumentName(ctx, args, "", errCodeXTDE1390)
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
	switch local {
	case paramVersion:
		if processor == 10 {
			return xdm.SingleDouble(1)
		}

		return xdm.SingleString(fmt.Sprintf("%d.0", processor/10))
	case "vendor":
		return xdm.SingleString(processorProductName)
	case "vendor-url":
		return xdm.SingleString("https://github.com/skarm/xmlsec")
	case nameProductName:
		return xdm.SingleString(processorProductName)
	case "product-version":
		return xdm.SingleString("0.1")
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
	case "xpath-version":
		return xdm.SingleString(map[int]string{10: lexicon.XSLTVersion10, 20: lexicon.XSLTVersion20, 30: "3.1"}[processor])
	case "xsd-version":
		if xpath.XMLSchemaVersion(ctx) == 10 {
			return xdm.SingleString(lexicon.XSLTVersion10)
		}

		return xdm.SingleString("1.1")
	default:
		return xdm.SingleString("")
	}
}

// available-system-properties() returns a sequence of QNames for all
// available system properties in the XSLT namespace.
// fnStreamAvailable implements fn:stream-available — returns true when the
// URI identifies a resource that can be streamed.
func (ec *execContext) fnStreamAvailable(ctx context.Context, args []xdm.Sequence) (xdm.Sequence, error) {
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
		if detail, ok := errors.AsType[*xdm.Error](err); ok && detail.Code == "FODC0005" {
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
		if _, hostFailure := errors.AsType[*xdm.ResourceAccessError](err); hostFailure {
			return nil, err
		}

		return xdm.SingleBoolean(false), nil
	}

	options := ec.inputParseOptions().WithByteLimit(ec.resourceLimit())
	err = options.CheckXMLProlog(ctx, reader)
	err = errors.Join(err, reader.Close())

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

func fnAvailableSystemProperties(_ context.Context, _ []xdm.Sequence) (xdm.Sequence, error) {
	props := []string{
		paramVersion, "vendor", "vendor-url", nameProductName, "product-version",
		nameIsSchemaAware, nameSupportsSerialization,
		textSupportsBackwardsCompatibility, nameSupportsNamespaceAxis,
		nameSupportsStreaming, nameSupportsDynamicEvaluation,
		textSupportsHigherOrderFunctions, "xpath-version", "xsd-version",
	}

	seq := make(xdm.ItemSlice, 0, len(props))
	for _, p := range props {
		seq = append(seq, xdm.AtomicValue{
			TypeName: xdm.TypeQName,
			Value:    xdm.QNameValue{Prefix: "xsl", URI: lexicon.NamespaceXSLT, Local: p},
		})
	}

	return seq, nil
}

// unparsed-entity-uri(name [, doc]) returns the URI of an unparsed entity.
func (ec *execContext) fnUnparsedEntityURI(ctx context.Context, args []xdm.Sequence) (xdm.Sequence, error) {
	return ec.emptyUnparsedEntity(ctx, args, "unparsed-entity-uri", errCodeXTDE1370)
}

// unparsed-entity-public-id(name) returns the public identifier of an unparsed entity.
func (ec *execContext) fnUnparsedEntityPublicID(ctx context.Context, args []xdm.Sequence) (xdm.Sequence, error) {
	return ec.emptyUnparsedEntity(ctx, args, "unparsed-entity-public-id", errCodeXTDE1380)
}

// xslMultiArityFunc wraps multiple xsl:function overloads (same QName,
// different arity) as a single xpath.Function that dispatches by arg count.

// emptyUnparsedEntity validates the document context in the DTD-free input model.
func (ec *execContext) emptyUnparsedEntity(ctx context.Context, args []xdm.Sequence, functionName, errorCode string) (xdm.Sequence, error) {
	var item xdm.Item
	if len(args) == 2 {
		item = args[1].Get(0) // The declared node() signature enforces cardinality.
	} else {
		var err error

		item, err = xpath.FnContextItem(ctx)
		if err != nil {
			if ec.stylesheet.processorLanguage() < 30 {
				return nil, dynamicError(errorCode, "%s requires a context node", functionName)
			}

			return nil, err
		}
	}

	node, ok := item.(xdm.NodeItem)
	if !ok {
		if ec.stylesheet.processorLanguage() < 30 {
			return nil, dynamicError(errorCode, "%s requires a context node", functionName)
		}

		return nil, dynamicError(errCodeXPTY0004, "%s requires a node", functionName)
	}

	if documentNodeFromNode(node.Node) == nil {
		return nil, dynamicError(errorCode, "%s requires a document-rooted tree", functionName)
	}

	if functionName == nameUnparsedEntityUri {
		return xdm.ItemSlice{xdm.AtomicValue{TypeName: xdm.TypeAnyURI, Value: ""}}, nil
	}

	return xdm.SingleString(""), nil
}

// documentNodeFromNode walks up to the root of a node's tree and returns
// the document node if the root is a document, or nil otherwise.
func documentNodeFromNode(n xdm.Node) *xdm.Document {
	for n.Parent() != nil {
		n = n.Parent()
	}

	if doc, ok := n.(*xdm.Document); ok {
		return doc
	}

	return nil
}
