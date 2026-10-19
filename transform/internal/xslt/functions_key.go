// Derived from lestrrat-go/helium at 7362c0a70122a757780f4d0b545a9b370dead6ab.
// Copyright (c) 2015 lestrrat. MIT License; see licenses/MIT-helium.txt at the repository root.

package xslt

import (
	"context"
	"strings"

	"github.com/skarm/xmlsec/internal/xmlchar"
	"github.com/skarm/xmlsec/transform/internal/xdm"
	"github.com/skarm/xmlsec/transform/internal/xdm/lexicon"
	"github.com/skarm/xmlsec/transform/internal/xpath"
)

func (ec *execContext) fnKey(ctx context.Context, args []xdm.Sequence) (xdm.Sequence, error) {
	if len(args) < 2 {
		return nil, dynamicError(errCodeXTDE1170, "key() requires at least 2 arguments")
	}

	// fn:key($key-name as xs:string, ...): the first argument is required to be
	// a single string. An empty sequence is a type error, not a panic.
	if args[0] == nil || xdm.SequenceLen(args[0]) == 0 {
		return nil, dynamicError(errCodeXPTY0004, "key() first argument must be a single xs:string, got empty sequence")
	}

	nameAV, err := xpath.AtomizeItem(args[0].Get(0))
	if err != nil {
		return nil, err
	}

	name, err := xpath.AtomicToString(nameAV)
	if err != nil {
		return nil, err
	}

	// Resolve prefixed key names to expanded names using stylesheet namespaces
	name = resolveQName(name, ec.stylesheet.namespaces)

	if args[1] == nil || xdm.SequenceLen(args[1]) == 0 {
		return xdm.EmptySequence(), nil
	}

	// Determine the root for key lookup.
	// Default: use the document containing the context node (per XSLT spec §16.3).
	// When the 3rd argument is provided, use that node directly as the search root.
	// This allows scoping to a subtree (e.g., key('k', 'v', $tree/sub)).
	var root xdm.Node = ec.sourceDoc

	if returned1, matchedBranch := fnKeyLen(ctx, args, &root, ec); matchedBranch {
		return nil, returned1
	}

	isComposite := false
	if defs, ok := ec.effectiveKeys()[name]; ok && len(defs) > 0 {
		isComposite = defs[0].Composite
	}

	if isComposite {
		// Composite key: the entire second argument sequence is a single
		// composite lookup key (matched element-by-element).
		avs := make([]xdm.AtomicValue, 0, xdm.SequenceLen(args[1]))
		for item := range xdm.SequenceItems(args[1]) {
			av, err := xpath.AtomizeItem(item)
			if err != nil {
				return nil, err
			}

			avs = append(avs, av)
		}

		nodes, err := ec.lookupCompositeKey(ctx, name, avs, root)
		if err != nil {
			return nil, err
		}

		var seq xdm.ItemSlice
		for _, n := range nodes {
			seq = append(seq, xdm.NodeItem{Node: n})
		}

		return seq, nil
	}

	// Non-composite: look up each value individually and union the results
	// (XSLT 2.0+ §16.3.2).
	seen := make(map[xdm.Node]struct{})

	var seq xdm.ItemSlice

	for item := range xdm.SequenceItems(args[1]) {
		valAV, err := xpath.AtomizeItem(item)
		if err != nil {
			return nil, err
		}

		nodes, err := ec.lookupKey(ctx, name, valAV, root)
		if err != nil {
			return nil, err
		}

		for _, n := range nodes {
			if _, dup := seen[n]; !dup {
				seen[n] = struct{}{}
				seq = append(seq, xdm.NodeItem{Node: n})
			}
		}
	}

	return seq, nil
}

// documentRoot walks up to the document root of the given node.
func documentRoot(n xdm.Node) xdm.Node {
	for n.Parent() != nil {
		n = n.Parent()
	}

	return n
}

func fnKeyLen(ctx context.Context, args []xdm.Sequence, root *xdm.Node, ec *execContext) (returned1 error, matchedBranch bool) {
	if len(args) >= 3 && args[2] != nil && xdm.SequenceLen(args[2]) > 0 {
		ni, ok := args[2].Get(0).(xdm.NodeItem)
		if ok {
			// XTDE1270: 3rd arg must have a document node as root
			r := ni.Node
			for r.Parent() != nil {
				r = r.Parent()
			}

			if r.Type() != xdm.DocumentNode {
				return dynamicError(errCodeXTDE1270,
					"key() third argument: root of tree is not a document node"), true
			}

			(*root) = ni.Node
		}
	} else {
		// 2-arg form: context node is required
		ctxNode := xpath.FnContextNode(ctx)
		if ctxNode == nil {
			ctxNode = ec.contextNode
		}

		if ctxNode == nil {
			// XTDE1270: no context node
			return dynamicError(errCodeXTDE1270,
				"key() called with no context node"), true
		}
		// XTDE1270: root of context node's tree must be a document node
		r := ctxNode
		for r.Parent() != nil {
			r = r.Parent()
		}

		if r.Type() != xdm.DocumentNode {
			return dynamicError(errCodeXTDE1270,
				"key() context node's root is not a document node"), true
		}

		(*root) = documentRoot(ctxNode)
	}

	return
}

// generate-id(node?) returns a unique string identifier for a node.
// With no arguments, returns the ID of the context node.
// With an empty sequence argument, returns the empty string.
func (ec *execContext) fnGenerateID(ctx context.Context, args []xdm.Sequence) (xdm.Sequence, error) {
	var node xdm.Node

	if len(args) == 0 {
		// No argument: use the XPath context node (correct inside
		// predicates), and never the XSLT context node.
		if xpathNode := xpath.FnContextNode(ctx); xpathNode != nil {
			node = xpathNode
		} else {
			node = ec.contextNode
		}
	} else {
		if args[0] == nil || xdm.SequenceLen(args[0]) == 0 {
			// Argument is an empty sequence: return empty string per spec.
			return xdm.SingleString(""), nil
		}

		ni, ok := args[0].Get(0).(xdm.NodeItem)
		if !ok {
			return nil, dynamicError(errCodeXPTY0004, "generate-id() argument must be a node")
		}

		node = ni.Node
	}

	if node == nil {
		return xdm.SingleString(""), nil
	}

	return xdm.SingleString(xpath.StableNodeID(node)), nil
}

// system-property(name) returns XSLT system properties.
func (ec *execContext) fnSystemProperty(ctx context.Context, args []xdm.Sequence) (xdm.Sequence, error) {
	if len(args) == 0 || (args[0] == nil || xdm.SequenceLen(args[0]) == 0) {
		return xdm.SingleString(""), nil
	}

	av, err := xpath.AtomizeItem(args[0].Get(0))
	if err != nil {
		return nil, err
	}

	name, err := xpath.AtomicToString(av)
	if err != nil {
		return nil, err
	}

	// XTDE1390: validate that the argument is a valid QName or EQName.
	if !strings.HasPrefix(name, "Q{") && !xmlchar.IsValidQName(name) {
		return nil, dynamicError(errCodeXTDE1390,
			"system-property argument %q is not a valid QName", name)
	}

	// Resolve QName: only prefixed names in the XSLT namespace return
	// XSLT properties. Unprefixed names are in no namespace and return "".
	local := name
	ns := ""

	if strings.HasPrefix(name, "Q{") {
		// URIQualifiedName: Q{uri}local
		end := strings.IndexByte(name, '}')
		if end > 2 {
			ns = name[2:end]
			local = name[end+1:]
		}
	} else if prefix, l, ok := strings.Cut(name, ":"); ok {
		local = l
		// Resolve prefix via stylesheet-level namespaces.
		resolved := false

		if uri, ok := ec.stylesheet.namespaces[prefix]; ok {
			ns = uri
			resolved = true
		}
		// XTDE1390: prefix has no namespace declaration
		if !resolved {
			return nil, dynamicError(errCodeXTDE1390,
				"system-property prefix %q has no namespace declaration", prefix)
		}
	}

	if ns != lexicon.NamespaceXSLT {
		return xdm.SingleString(""), nil
	}

	switch local {
	case paramVersion:
		if isBackwardsCompatible(ec.stylesheet.version) {
			return xdm.SingleDouble(1), nil
		}

		return xdm.SingleString(lexicon.XSLTVersion30), nil
	case "vendor":
		return xdm.SingleString("xmlsec"), nil
	case "vendor-url":
		return xdm.SingleString("https://github.com/skarm/xmlsec"), nil
	case "product-name":
		return xdm.SingleString("xmlsec"), nil
	case "product-version":
		return xdm.SingleString("0.1"), nil
	case nameIsSchemaAware:
		return xdm.SingleString(lexicon.ValueNo), nil
	case nameSupportsSerialization:
		return xdm.SingleString(lexicon.ValueYes), nil
	case textSupportsBackwardsCompatibility:
		return xdm.SingleString(lexicon.ValueYes), nil
	case nameSupportsNamespaceAxis:
		return xdm.SingleString(lexicon.ValueYes), nil
	case nameSupportsStreaming:
		return xdm.SingleString(lexicon.ValueNo), nil
	case nameSupportsDynamicEvaluation:
		return xdm.SingleString(lexicon.ValueYes), nil
	case textSupportsHigherOrderFunctions:
		return xdm.SingleString(lexicon.ValueYes), nil
	case "xpath-version":
		return xdm.SingleString("3.1"), nil
	case "xsd-version":
		return xdm.SingleString("1.1"), nil
	default:
		return xdm.SingleString(""), nil
	}
}

// available-system-properties() returns a sequence of QNames for all
// available system properties in the XSLT namespace.
// fnStreamAvailable implements fn:stream-available — returns true when the
// URI identifies a resource that can be streamed.
func (ec *execContext) fnStreamAvailable(ctx context.Context, args []xdm.Sequence) (xdm.Sequence, error) {
	if len(args) == 0 || (args[0] == nil || xdm.SequenceLen(args[0]) == 0) {
		return xdm.SingleBoolean(false), nil
	}

	av, err := xpath.AtomizeItem(args[0].Get(0))
	if err != nil {
		return nil, err
	}

	uri, err := xpath.AtomicToString(av)
	if err != nil {
		return nil, err
	}

	if uri == "" {
		return xdm.SingleBoolean(false), nil
	}
	// Retrieve through the configured URIResolver / HTTPClient, stat-ing no
	// host filesystem directly. We only need the leading bytes
	// to decide whether the resource is XML, so read a bounded prefix instead
	// of the whole document. With no resolver installed this fails the
	// default-deny check; an unavailable resource is reported as not
	// streamable (false), and never surfaced as an error.
	resolved := ec.resolveDocumentURI(uri, ec.baseDir())

	prefix, err := ec.retrieveDocumentPrefix(ctx, resolved, 256)
	if err != nil {
		// fn:stream-available reports availability, not retrieval failure:
		// a resource we cannot fetch is simply not streamable.
		return xdm.SingleBoolean(false), nil //nolint:nilerr
	}
	// Only XML resources can be streamed. Quick check on the leading bytes.
	content := strings.TrimSpace(string(prefix))
	isXML := strings.HasPrefix(content, "<?xml") || strings.HasPrefix(content, "<")

	return xdm.SingleBoolean(isXML), nil
}

// fnCurrentOutputURI implements current-output-uri() — returns the URI
// of the current output destination.
// Returns empty sequence in temporary output state or when no base output URI is set.
func (ec *execContext) fnCurrentOutputURI(_ context.Context, _ []xdm.Sequence) (xdm.Sequence, error) {
	if ec.inPatternMatch || ec.inSortKeyEval || ec.temporaryOutputDepth > 0 || ec.currentOutputURI == "" {
		return xdm.EmptySequence(), nil
	}

	return xdm.ItemSlice{xdm.AtomicValue{TypeName: xdm.TypeAnyURI, Value: ec.currentOutputURI}}, nil
}

func (ec *execContext) fnAvailableSystemProperties(_ context.Context, _ []xdm.Sequence) (xdm.Sequence, error) {
	props := []string{
		paramVersion, "vendor", "vendor-url", "product-name", "product-version",
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

// emptyUnparsedEntity checks context and argument types before returning an empty entity result.
func (ec *execContext) emptyUnparsedEntity(ctx context.Context, args []xdm.Sequence, functionName, errorCode string) (xdm.Sequence, error) {
	// Determine the document node: 2-arg form uses the second arg, 1-arg form uses context node.
	var doc *xdm.Document

	if len(args) >= 2 && args[1] != nil && xdm.SequenceLen(args[1]) > 0 {
		if ni, ok := args[1].Get(0).(xdm.NodeItem); ok {
			doc = documentNodeFromNode(ni.Node)
		}
	}

	if doc == nil {
		// 1-arg form: use XPath context node, then XSLT context node
		ctxNode := xpath.FnContextNode(ctx)
		if ctxNode == nil {
			ctxNode = ec.contextNode
		}

		if ctxNode == nil {
			return nil, dynamicError(errorCode,
				"%s called when there is no context node", functionName)
		}

		root := ctxNode
		for root.Parent() != nil {
			root = root.Parent()
		}

		if root.Type() != xdm.DocumentNode {
			return nil, dynamicError(errorCode,
				"%s called when root of context tree is not a document node", functionName)
		}
	}

	if args[0] == nil || xdm.SequenceLen(args[0]) == 0 {
		return xdm.SingleString(""), nil
	}

	av, err := xpath.AtomizeItem(args[0].Get(0))
	if err != nil {
		return xdm.SingleString(""), nil //nolint:nilerr // unparsed-entity-uri returns "" on atomization failure
	}

	_, err = xpath.AtomicToString(av)
	if err != nil {
		return xdm.SingleString(""), nil //nolint:nilerr // unparsed-entity-uri returns "" on string conversion failure
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
