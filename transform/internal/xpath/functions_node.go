// Derived from lestrrat-go/helium at 7362c0a70122a757780f4d0b545a9b370dead6ab.
// Copyright (c) 2015 lestrrat. MIT License; see licenses/MIT-helium.txt at the repository root.

package xpath

import (
	"context"
	"errors"
	"fmt"
	"math"
	"slices"
	"strings"

	"github.com/skarm/xmlsec/internal/xmlchar"
	"github.com/skarm/xmlsec/transform/internal/xdm"
	"github.com/skarm/xmlsec/transform/internal/xdm/lexicon"
	unparsedtext "github.com/skarm/xmlsec/transform/internal/xpath/text"
)

func lookupFunctionsNode(name string) (*builtinFunc, bool) {
	switch name {
	case nameNodeName:
		return &builtinFunc{name: name, min: 0, max: 1, fn: fnNodeName}, true
	case "nilled":
		return &builtinFunc{name: name, min: 0, max: 1, fn: fnNilled}, true
	case "data":
		return &builtinFunc{name: name, min: 0, max: 1, fn: fnData}, true
	case "base-uri":
		return &builtinFunc{name: name, min: 0, max: 1, fn: fnBaseURI}, true
	case "document-uri":
		return &builtinFunc{name: name, min: 0, max: 1, fn: fnDocumentURI}, true
	case "root":
		return &builtinFunc{name: name, min: 0, max: 1, fn: fnRoot}, true
	case namePath:
		return &builtinFunc{name: name, min: 0, max: 1, fn: fnPath}, true
	case nameHasChildren:
		return &builtinFunc{name: name, min: 0, max: 1, fn: fnHasChildren}, true
	case "innermost":
		return &builtinFunc{name: name, min: 1, max: 1, fn: fnInnermost}, true
	case "outermost":
		return &builtinFunc{name: name, min: 1, max: 1, fn: fnOutermost}, true
	case nameLang:
		return &builtinFunc{name: name, min: 1, max: 2, fn: fnLang}, true
	case nameLocalName:
		return &builtinFunc{name: name, min: 0, max: 1, fn: fnLocalName}, true
	case nameName2:
		return &builtinFunc{name: name, min: 0, max: 1, fn: fnName}, true
	case nameNamespaceUri:
		return &builtinFunc{name: name, min: 0, max: 1, fn: fnNamespaceURI}, true
	case nameNumber:
		return &builtinFunc{name: name, min: 0, max: 1, fn: fnNumber}, true
	case nameGenerateId:
		return &builtinFunc{name: name, min: 0, max: 1, fn: fnGenerateID}, true
	case "parse-xml":
		return &builtinFunc{name: name, min: 1, max: 1, fn: fnParseXML}, true
	case "parse-xml-fragment":
		return &builtinFunc{name: name, min: 1, max: 1, fn: fnParseXMLFragment}, true
	case "doc":
		return &builtinFunc{name: name, min: 1, max: 1, fn: fnDoc}, true
	case "doc-available":
		return &builtinFunc{name: name, min: 1, max: 1, fn: fnDocAvailable}, true
	case "id":
		return &builtinFunc{name: name, min: 1, max: 2, fn: fnID}, true
	case "idref":
		return &builtinFunc{name: name, min: 1, max: 2, fn: fnIDRef}, true
	case "element-with-id":
		return &builtinFunc{name: name, min: 1, max: 2, fn: fnElementWithID}, true
	case "collection":
		return &builtinFunc{name: name, min: 0, max: 1, fn: fnCollection}, true
	case "uri-collection":
		return &builtinFunc{name: name, min: 0, max: 1, fn: fnURICollection}, true
	}

	return nil, false
}

func fnNodeName(ctx context.Context, args []xdm.Sequence) (xdm.Sequence, error) {
	n, err := nodeArgOrCtx(ctx, args)
	if err != nil {
		return nil, err
	}

	if n == nil {
		return nil, nil
	}

	switch n.Type() {
	case xdm.ElementNode, xdm.AttributeNode:
		local := xdm.LocalNameOf(n)
		uri := xdm.NodeNamespaceURI(n)
		prefix := xdm.NodePrefix(n)

		return xdm.SingleAtomic(xdm.AtomicValue{
			TypeName: xdm.TypeQName,
			Value:    xdm.QNameValue{Prefix: prefix, Local: local, URI: uri},
		}), nil
	case xdm.ProcessingInstructionNode:
		return xdm.SingleAtomic(xdm.AtomicValue{
			TypeName: xdm.TypeQName,
			Value:    xdm.QNameValue{Local: n.Name()},
		}), nil
	case xdm.NamespaceNode:
		return xdm.SingleAtomic(xdm.AtomicValue{
			TypeName: xdm.TypeQName,
			Value:    xdm.QNameValue{Local: n.Name()},
		}), nil
	}

	return nil, nil
}

func fnNilled(ctx context.Context, args []xdm.Sequence) (xdm.Sequence, error) {
	n, err := nodeArgOrCtx(ctx, args)
	if err != nil {
		return nil, err
	}

	if n == nil {
		return nil, nil
	}
	// fn:nilled returns the nilled property of an element node, else () for a
	// non-element. The nilled property is the PSVI [nil] property: true only for
	// an element that the XSD validator confirmed carried a valid xsi:nil="true"
	// (recorded in the evaluator's NilledElements set). Without a schema-aware
	// nilled set every element is not-nilled → false.
	if n.Type() == xdm.ElementNode {
		return xdm.SingleBoolean(nodeIsNilled(ctx, n)), nil
	}

	return nil, nil
}

// nodeIsNilled reports whether node n is in the active evaluation's
// schema-derived nilled-element set. It is safe when no set is configured
// (non-schema-aware evaluation): it returns false.
func nodeIsNilled(ctx context.Context, n xdm.Node) bool {
	ec := getFnContext(ctx)
	if ec == nil || ec.nilledElements == nil {
		return false
	}

	_, ok := ec.nilledElements[n]

	return ok
}

func fnData(ctx context.Context, args []xdm.Sequence) (xdm.Sequence, error) {
	if len(args) == 0 {
		fc := getFnContext(ctx)
		if fc == nil {
			return nil, &xdm.Error{Code: errCodeXPDY0002, Message: "data() requires a context item"}
		}

		if fc.contextItem != nil {
			args = []xdm.Sequence{xdm.ItemSlice{fc.contextItem}}
		} else if fc.node != nil {
			args = []xdm.Sequence{xdm.ItemSlice{nodeItemFor(ctx, fc, fc.node)}}
		} else {
			return nil, &xdm.Error{Code: errCodeXPDY0002, Message: "data() requires a context item"}
		}
	}

	atoms, err := atomizeTypedValue(ctx, args[0])
	if err != nil {
		return nil, err
	}

	result := make(xdm.ItemSlice, len(atoms))
	for i, a := range atoms {
		result[i] = a
	}

	return result, nil
}

// atomizeTypedValue atomizes a sequence through the XDM 3.1 §5.15 typed-value
// rules, interleaving a typed-value check with atomization: a NILLED element has
// no typed value and is skipped (typed value ()); an element whose schema type
// annotation resolves to ELEMENT-ONLY complex content has no typed value and
// raises err:FOTY0012, fabricating no xs:untypedAtomic from its
// string value; an element with EMPTY complex content has typed value () and is
// skipped (contributes no atoms); mixed/simple content and everything else
// atomize normally. It backs fn:data AND the xs:string?-argument function
// conversion (coerceAtomizedString / seqToStringErr), since atomizing an
// element-only node has no typed value for ANY caller per XDM. The check is
// threaded through atomizeStreamCont, so it walks items in the SAME encounter
// order and with the SAME array recursion as atomization: the FIRST offending
// item wins (a map/function atomized earlier still raises FOTY0013 before a
// later element-only element), and nilled / element-only / empty nodes nested
// inside arrays are handled. The check fires only when a nilled-element set is
// configured or the active SchemaDeclarations implements the optional
// ContentTypeKindProvider; without either this is exactly AtomizeSequence, so
// other AtomizeItem callers (comparisons, casts) are unaffected.
func atomizeTypedValue(ctx context.Context, seq xdm.Sequence) ([]xdm.AtomicValue, error) {
	check := typedValueItemCheck(ctx)
	if check == nil {
		return AtomizeSequence(seq)
	}

	if seq == nil {
		return nil, nil
	}

	result := make([]xdm.AtomicValue, 0, seq.Len())

	_, err := atomizeStreamCont(seq, check, func(av xdm.AtomicValue) (bool, error) {
		result = append(result, av)
		return true, nil
	})
	if err != nil {
		return nil, err
	}

	return result, nil
}

// atomizeItemCheck is a per-item pre-check consulted by atomizeStreamCont (the
// fn:data / typed-value path only) BEFORE an item is atomized, in the same
// encounter order and array recursion as atomization. It returns skip=true when
// the item has typed value () and contributes no atoms, or a non-nil error
// (e.g. FOTY0012) to reject the item.
type atomizeItemCheck func(item xdm.Item) (skip bool, err error)

// typedValueItemCheck builds the typed-value pre-check for the active
// evaluation, reading the evalContext stashed in ctx. It is the ctx-based entry
// point for callers past the function boundary (fn:data, coerceAtomizedString);
// the function-signature coercion, which runs BEFORE the fnContext is stashed in
// ctx, uses typedValueItemCheckFor with its explicit ec instead.
func typedValueItemCheck(ctx context.Context) atomizeItemCheck {
	return typedValueItemCheckFor(getFnContext(ctx))
}

// typedValueItemCheckFor builds the typed-value pre-check from an explicit
// evalContext, combining the two schema-aware sources: the nilled-element set (a
// nilled element has no typed value → skipped) and the optional
// ContentTypeKindProvider (element-only → FOTY0012, empty → skipped). It returns
// nil when neither is configured, so non-schema-aware atomization stays plain
// (AtomizeSequence). Nilled is checked first: a nilled element's content type is
// irrelevant, its typed value is always ().
func typedValueItemCheckFor(ec *evalContext) atomizeItemCheck {
	if ec == nil {
		return nil
	}

	provider := ec.contentKindProvider()

	nilled := ec.nilledElements
	if provider == nil && len(nilled) == 0 {
		return nil
	}

	return func(item xdm.Item) (bool, error) {
		ni, ok := item.(xdm.NodeItem)
		if !ok {
			return false, nil
		}

		if ni.Node != nil && ni.Node.Type() == xdm.ElementNode {
			if _, isNilled := nilled[ni.Node]; isNilled {
				return true, nil
			}
		}

		if provider != nil {
			return checkContentKindItem(provider, item)
		}

		return false, nil
	}
}

// contentKindProvider returns the active ContentTypeKindProvider for this
// evalContext, or nil when no schema-aware provider is configured.
func (ec *evalContext) contentKindProvider() ContentTypeKindProvider {
	if ec == nil || ec.schemaDeclarations == nil {
		return nil
	}

	provider, _ := ec.schemaDeclarations.(ContentTypeKindProvider)

	return provider
}

// nodeStringValue returns the XPath dm:string-value of a node. In a schema-aware
// run it strips INSIGNIFICANT whitespace: a whitespace-only text-node child of an
// element whose type annotation resolves (via the ContentTypeKindProvider) to
// ELEMENT-ONLY complex content is not part of the string value (XDM 3.1 PSVI
// construction). Without a provider/annotations, or for any element that is not
// element-only, this is byte-identical to xdm.StringValue.
func (ec *evalContext) nodeStringValue(n xdm.Node) string {
	if n == nil {
		return ""
	}

	provider := ec.contentKindProvider()
	if provider == nil || ec.typeAnnotations == nil {
		return xdm.StringValue(n)
	}

	switch n.Type() {
	case xdm.DocumentNode, xdm.ElementNode:
		// only element/document nodes can contain element-only descendants
	default:
		return xdm.StringValue(n)
	}

	var b strings.Builder
	ec.appendSchemaStringValue(&b, n, provider)

	return b.String()
}

// appendSchemaStringValue walks descendants in document order (iteratively, so a
// deep tree does not truncate) concatenating text/CDATA content, with the same
// node rules as xdm.StringValue: child lists are enumerated through
// xdm.Children (the owned-child boundary), an entity reference adds the text
// it expands to (its Content), and a document's DTD, comments and PIs add
// nothing. A whitespace-only text-node or entity-reference child of an
// element-only element is skipped as insignificant.
func (ec *evalContext) appendSchemaStringValue(b *strings.Builder, root xdm.Node, provider ContentTypeKindProvider) {
	stack := []xdm.Node{root}

	var kids []xdm.Node

	for len(stack) > 0 {
		cur := stack[len(stack)-1]
		stack = stack[:len(stack)-1]

		switch cur.Type() {
		case xdm.TextNode, xdm.CDATASectionNode:
			b.WriteString(xdm.CharacterData(cur))
			continue
		case xdm.ElementNode, xdm.DocumentNode:
		default:
			continue
		}

		elementOnly := cur.Type() == xdm.ElementNode && ec.isElementOnlyContent(cur, provider)
		kids = kids[:0]

		for child := range xdm.Children(cur) {
			if elementOnly && isInsignificantWhitespaceText(child) {
				continue
			}

			kids = append(kids, child)
		}

		for _, child := range slices.Backward(kids) {
			stack = append(stack, child)
		}
	}
}

// isInsignificantWhitespaceText reports whether n is a text or CDATA-section node,
// or an entity reference expanding to text, whose content is entirely XSD
// whitespace (space, tab, CR, LF). XSD treats whitespace-only text and CDATA
// identically for element-only content, xdm.StringValue includes CDATA as a
// text descendant, and a reference counts as the text a substituted parse
// stores in its place, so each is skipped when a child of an element-only
// element (not part of its string value).
func isInsignificantWhitespaceText(n xdm.Node) bool {
	switch n.Type() {
	case xdm.TextNode, xdm.CDATASectionNode:
		return isXSDWhitespaceOnly(xdm.CharacterData(n))
	default:
		return false
	}
}

// isElementOnlyContent reports whether n's resolved type annotation is an
// element-only complex content type.
func (ec *evalContext) isElementOnlyContent(n xdm.Node, provider ContentTypeKindProvider) bool {
	ann := ec.typeAnnotations[n]
	if ann == "" {
		return false
	}

	kind, ok := provider.SchemaTypeContentKind(ann)

	return ok && kind == ContentTypeElementOnly
}

// checkContentKindItem resolves the typed-value ACTION for one item
// (XDM 3.1 §5.15). For an element node whose type annotation resolves (via the
// ContentTypeKindProvider) to a complex content kind it returns: element-only →
// err:FOTY0012 (no typed value); empty → skip=true (typed value (), no atoms).
// Mixed/simple content, an unresolved annotation, and every non-element /
// non-schema-aware item return skip=false, nil — left to normal atomization.
func checkContentKindItem(provider ContentTypeKindProvider, item xdm.Item) (skip bool, err error) {
	ni, ok := item.(xdm.NodeItem)
	if !ok {
		return false, nil
	}

	if ni.TypeAnnotation == "" || ni.Node == nil || ni.Node.Type() != xdm.ElementNode {
		return false, nil
	}

	kind, found := provider.SchemaTypeContentKind(ni.TypeAnnotation)
	if !found {
		return false, nil
	}

	switch kind {
	case ContentTypeElementOnly:
		return false, &xdm.Error{
			Code:    errCodeFOTY0012,
			Message: "element with element-only complex content has no typed value",
		}
	case ContentTypeEmpty:
		return true, nil
	default:
		return false, nil
	}
}

func fnBaseURI(ctx context.Context, args []xdm.Sequence) (xdm.Sequence, error) {
	n, err := nodeArgOrCtx(ctx, args)
	if err != nil {
		return nil, err
	}

	if n == nil {
		return nil, nil
	}
	// Namespace nodes have no base URI per the XPath data model.
	if n.Type() == xdm.NamespaceNode {
		return nil, nil
	}
	// Per XDM: attribute, text, comment, and PI nodes derive their base URI
	// from their parent element. If they have no parent, their base URI is
	// the empty sequence.
	nodeType := n.Type()
	if nodeType == xdm.AttributeNode || nodeType == xdm.TextNode ||
		nodeType == xdm.CommentNode || nodeType == xdm.ProcessingInstructionNode {
		if n.Parent() == nil {
			return nil, nil
		}
	}
	// Walk up the parent chain to find the actual document the node lives
	// in. OwnerDocument() may return a different document when nodes are
	// created in one document and then moved to another (e.g. in XSLT
	// xsl:result-document).
	var doc *xdm.Document
	if d, ok := n.(*xdm.Document); ok {
		doc = d
	} else {
		cur := n
		for cur.Parent() != nil {
			cur = cur.Parent()
		}

		if d, ok := cur.(*xdm.Document); ok {
			doc = d
		} else {
			doc = n.OwnerDocument()
		}
	}

	base := xdm.NodeGetBase(doc, n)
	if base == "" {
		return nil, nil
	}

	return xdm.SingleAtomic(xdm.AtomicValue{TypeName: xdm.TypeAnyURI, Value: base}), nil
}

func fnDocumentURI(ctx context.Context, args []xdm.Sequence) (xdm.Sequence, error) {
	n, err := nodeArgOrCtx(ctx, args)
	if err != nil {
		return nil, err
	}

	if n == nil {
		return nil, nil
	}

	if n.Type() != xdm.DocumentNode {
		return nil, nil
	}

	if doc, ok := n.(*xdm.Document); ok {
		if doc.HasProperty(xdm.DocInternal) {
			return nil, nil
		}

		if uri := doc.URL(); uri != "" {
			return xdm.SingleAtomic(xdm.AtomicValue{TypeName: xdm.TypeAnyURI, Value: uri}), nil
		}
	}

	return nil, nil
}

func fnRoot(ctx context.Context, args []xdm.Sequence) (xdm.Sequence, error) {
	n, err := nodeArgOrCtx(ctx, args)
	if err != nil {
		return nil, err
	}

	if n == nil {
		return nil, nil
	}

	return xdm.SingleNode(xdm.DocumentRoot(n)), nil
}

func fnPath(ctx context.Context, args []xdm.Sequence) (xdm.Sequence, error) {
	n, err := nodeArgOrCtx(ctx, args)
	if err != nil {
		return nil, err
	}

	if n == nil {
		return nil, nil
	}

	return xdm.SingleString(buildNodePath(n)), nil
}

func buildNodePath(n xdm.Node) string {
	const fnRoot = "Q{http://www.w3.org/2005/xpath-functions}root()"

	if n.Type() == xdm.DocumentNode {
		return "/"
	}

	var parts []string

	for cur := n; cur != nil && cur.Type() != xdm.DocumentNode; cur = cur.Parent() {
		// Skip the root of a non-document tree — it is represented by Q{...}root()
		if cur.Parent() == nil {
			break
		}

		switch cur.Type() {
		case xdm.ElementNode:
			local := xdm.LocalNameOf(cur)
			uri := xdm.NodeNamespaceURI(cur)
			pos := elementPosition(cur)
			parts = append(parts, fmt.Sprintf("Q{%s}%s[%d]", uri, local, pos))
		case xdm.AttributeNode:
			local := xdm.LocalNameOf(cur)

			uri := xdm.NodeNamespaceURI(cur)
			if uri != "" {
				parts = append(parts, fmt.Sprintf("@Q{%s}%s", uri, local))
			} else {
				parts = append(parts, "@"+local)
			}
		case xdm.TextNode, xdm.CDATASectionNode:
			pos := textPosition(cur)
			parts = append(parts, fmt.Sprintf("text()[%d]", pos))
		case xdm.CommentNode:
			pos := commentPosition(cur)
			parts = append(parts, fmt.Sprintf("comment()[%d]", pos))
		case xdm.ProcessingInstructionNode:
			parts = append(parts, fmt.Sprintf("processing-instruction(%s)[1]", cur.Name()))
		case xdm.NamespaceNode:
			if cur.Name() == "" {
				parts = append(parts, fmt.Sprintf(`namespace::*[Q{%s}local-name()=""]`, NSFn))
			} else {
				parts = append(parts, "namespace::"+cur.Name())
			}
		}
	}
	// Reverse
	for i, j := 0, len(parts)-1; i < j; i, j = i+1, j-1 {
		parts[i], parts[j] = parts[j], parts[i]
	}
	// Check if the node is rooted in a document node.
	// Per XPath 3.1: document root → path starts with "/",
	// non-document root (orphan tree) → path starts with "Q{...}root()".
	root := n
	for root.Parent() != nil {
		root = root.Parent()
	}

	if root.Type() == xdm.DocumentNode {
		return "/" + strings.Join(parts, "/")
	}

	if len(parts) == 0 {
		return fnRoot
	}

	return fnRoot + "/" + strings.Join(parts, "/")
}

func elementPosition(n xdm.Node) int {
	local := xdm.LocalNameOf(n)
	uri := xdm.NodeNamespaceURI(n)
	pos := 1

	for sib := n.PrevSibling(); sib != nil; sib = sib.PrevSibling() {
		if sib.Type() == xdm.ElementNode &&
			xdm.LocalNameOf(sib) == local &&
			xdm.NodeNamespaceURI(sib) == uri {
			pos++
		}
	}

	return pos
}

func textPosition(n xdm.Node) int {
	pos := 1

	for sib := n.PrevSibling(); sib != nil; sib = sib.PrevSibling() {
		if sib.Type() == xdm.TextNode || sib.Type() == xdm.CDATASectionNode {
			pos++
		}
	}

	return pos
}

func commentPosition(n xdm.Node) int {
	pos := 1

	for sib := n.PrevSibling(); sib != nil; sib = sib.PrevSibling() {
		if sib.Type() == xdm.CommentNode {
			pos++
		}
	}

	return pos
}

func fnHasChildren(ctx context.Context, args []xdm.Sequence) (xdm.Sequence, error) {
	n, err := nodeArgOrCtx(ctx, args)
	if err != nil {
		return nil, err
	}

	if n == nil {
		return xdm.SingleBoolean(false), nil
	}
	// Per XPath spec, only document and element nodes can have children
	switch n.(type) {
	case *xdm.Document, *xdm.Element:
		return xdm.SingleBoolean(n.FirstChild() != nil), nil
	default:
		return xdm.SingleBoolean(false), nil
	}
}

func fnInnermost(ctx context.Context, args []xdm.Sequence) (xdm.Sequence, error) {
	nodes, ok := xdm.NodesFrom(args[0])
	if !ok {
		return nil, &xdm.Error{Code: lexicon.ErrXPTY0004, Message: "innermost() requires node-set"}
	}

	nodeSet := make(map[xdm.Node]struct{}, len(nodes))
	for _, n := range nodes {
		nodeSet[n] = struct{}{}
	}
	// A node is innermost if it is not an ancestor of any other node in the set.
	// Collect all ancestors of nodes in the set, then exclude them.
	ancestors := make(map[xdm.Node]struct{})

	for _, n := range nodes {
		for p := n.Parent(); p != nil; p = p.Parent() {
			if _, ok := ancestors[p]; ok {
				break // already traced this path
			}

			ancestors[p] = struct{}{}
		}
	}

	var result []xdm.Node

	for _, n := range nodes {
		if _, ok := ancestors[n]; !ok {
			result = append(result, n)
		}
	}

	return sequenceFromDocOrderedNodes(ctx, result)
}

func fnOutermost(ctx context.Context, args []xdm.Sequence) (xdm.Sequence, error) {
	nodes, ok := xdm.NodesFrom(args[0])
	if !ok {
		return nil, &xdm.Error{Code: lexicon.ErrXPTY0004, Message: "outermost() requires node-set"}
	}

	nodeSet := make(map[xdm.Node]struct{}, len(nodes))
	for _, n := range nodes {
		nodeSet[n] = struct{}{}
	}

	var result []xdm.Node

	for _, n := range nodes {
		isOuter := true

		for p := n.Parent(); p != nil; p = p.Parent() {
			if _, ok := nodeSet[p]; ok {
				isOuter = false
				break
			}
		}

		if isOuter {
			result = append(result, n)
		}
	}

	return sequenceFromDocOrderedNodes(ctx, result)
}

func fnLang(ctx context.Context, args []xdm.Sequence) (xdm.Sequence, error) {
	langArg, err := coerceArgToString(ctx, args[0])
	if err != nil {
		return nil, err
	}

	if err := ChargeString(ctx, len(langArg)); err != nil {
		return nil, err
	}

	langArg = strings.ToLower(langArg)

	var n xdm.Node

	if len(args) > 1 {
		nodes, ok := xdm.NodesFrom(args[1])
		if !ok || len(nodes) == 0 {
			return nil, &xdm.Error{Code: lexicon.ErrXPTY0004, Message: "fn:lang second argument must be a node"}
		}

		n = nodes[0]
	} else {
		fc := getFnContext(ctx)
		if fc == nil || (fc.contextItem == nil && fc.node == nil) {
			return nil, &xdm.Error{Code: errCodeXPDY0002, Message: errMsgContextItemAbsent}
		}

		if fc.node == nil {
			return nil, &xdm.Error{Code: lexicon.ErrXPTY0004, Message: "context item is not a node for fn:lang"}
		}

		n = fc.node
	}

	for owner := n; owner != nil; owner = owner.Parent() {
		if err := Charge(ctx, 1); err != nil {
			return nil, err
		}

		if e, ok := owner.(*xdm.Element); ok {
			if lang, found := e.GetAttributeNS(nameLang, lexicon.NamespaceXML); found {
				if err := ChargeString(ctx, len(lang)); err != nil {
					return nil, err
				}

				break
			}
		}
	}

	matched, _ := xdm.XMLLangMatches(n, langArg)

	return xdm.SingleBoolean(matched), nil
}

func fnLocalName(ctx context.Context, args []xdm.Sequence) (xdm.Sequence, error) {
	n, err := nodeArgOrCtx(ctx, args)
	if err != nil {
		return nil, err
	}

	if n == nil {
		return xdm.SingleString(""), nil
	}

	return xdm.SingleString(xdm.LocalNameOf(n)), nil
}

func fnName(ctx context.Context, args []xdm.Sequence) (xdm.Sequence, error) {
	n, err := nodeArgOrCtx(ctx, args)
	if err != nil {
		return nil, err
	}

	if n == nil {
		return xdm.SingleString(""), nil
	}

	switch n.Type() {
	case xdm.ElementNode, xdm.AttributeNode,
		xdm.ProcessingInstructionNode, xdm.NamespaceNode:
		return xdm.SingleString(n.Name()), nil
	}

	return xdm.SingleString(""), nil
}

func fnNamespaceURI(ctx context.Context, args []xdm.Sequence) (xdm.Sequence, error) {
	n, err := nodeArgOrCtx(ctx, args)
	if err != nil {
		return nil, err
	}

	if n == nil {
		return xdm.SingleAtomic(xdm.AtomicValue{TypeName: xdm.TypeAnyURI, Value: ""}), nil
	}

	return xdm.SingleAtomic(xdm.AtomicValue{TypeName: xdm.TypeAnyURI, Value: xdm.NodeNamespaceURI(n)}), nil
}

func fnNumber(ctx context.Context, args []xdm.Sequence) (xdm.Sequence, error) {
	if len(args) == 0 {
		fc := getFnContext(ctx)
		if fc == nil || (fc.contextItem == nil && fc.node == nil) {
			return nil, &xdm.Error{Code: errCodeXPDY0002, Message: errMsgContextItemAbsent}
		}

		s, ok := fc.contextStringValue()
		if !ok {
			return xdm.SingleDouble(math.NaN()), nil
		}

		a, err := CastFromString(s, xdm.TypeDouble)
		if err != nil {
			return xdm.SingleDouble(math.NaN()), nil //nolint:nilerr // fn:number returns NaN on cast failure per spec
		}

		return xdm.SingleDouble(a.DoubleVal()), nil
	}

	if xdm.SequenceLen(args[0]) == 0 {
		return xdm.SingleDouble(math.NaN()), nil
	}

	a, err := AtomizeItem(args[0].Get(0))
	if err != nil {
		// FOTY0013 (atomizing function items) must propagate per XPath 3.1 §2.7.2
		var xpErr *xdm.Error
		if errors.As(err, &xpErr) && xpErr.Code == errCodeFOTY0013 {
			return nil, err
		}

		return xdm.SingleDouble(math.NaN()), nil
	}

	dbl, err := CastAtomic(a, xdm.TypeDouble)
	if err != nil {
		return xdm.SingleDouble(math.NaN()), nil //nolint:nilerr // fn:number returns NaN on cast failure per spec
	}

	return xdm.SingleDouble(dbl.DoubleVal()), nil
}

func fnGenerateID(ctx context.Context, args []xdm.Sequence) (xdm.Sequence, error) {
	n, err := nodeArgOrCtx(ctx, args)
	if err != nil {
		return nil, err
	}

	if n == nil {
		return xdm.SingleString(""), nil
	}

	return xdm.SingleString(StableNodeID(n)), nil
}

func fnParseXML(ctx context.Context, args []xdm.Sequence) (xdm.Sequence, error) {
	// xs:string? argument: an atomized-empty value (empty array / nilled node)
	// returns the empty sequence, like a syntactically empty one.
	s, empty, err := coerceAtomizedString(ctx, args[0])
	if err != nil {
		return nil, err
	}

	if empty {
		return nil, nil
	}

	ec := getFnContext(ctx)

	parseOptions := ec.xmlParseOptions()
	if ec != nil && ec.baseURI != "" {
		parseOptions.BaseURI = ec.baseURI
	}

	doc, err := parseOptions.ParseText(ctx, s)
	if err != nil {
		return nil, &xdm.Error{Code: errCodeFODC0006, Message: fmt.Sprintf("parse-xml: %v", err), Cause: err}
	}

	doc.SetProperties(doc.Properties() | xdm.DocInternal)

	return xdm.ItemSlice{xdm.NodeItem{Node: doc}}, nil
}

func fnParseXMLFragment(ctx context.Context, args []xdm.Sequence) (xdm.Sequence, error) {
	// xs:string? argument: an atomized-empty value returns the empty sequence,
	// like a syntactically empty one.
	s, empty, err := coerceAtomizedString(ctx, args[0])
	if err != nil {
		return nil, err
	}

	if empty {
		return nil, nil
	}

	ec := getFnContext(ctx)

	options := ec.xmlParseOptions()
	if ec != nil && ec.baseURI != "" {
		options.BaseURI = ec.baseURI
	}

	doc, err := options.ParseFragment(ctx, s)
	if err != nil {
		return nil, &xdm.Error{Code: errCodeFODC0006, Message: fmt.Sprintf("parse-xml-fragment: %v", err), Cause: err}
	}

	doc.SetProperties(doc.Properties() | xdm.DocInternal)

	return xdm.ItemSlice{xdm.NodeItem{Node: doc}}, nil
}

func fnID(ctx context.Context, args []xdm.Sequence) (xdm.Sequence, error) {
	return idLookup(ctx, args, false)
}

// idLookup implements both fn:id and fn:element-with-id. The two functions
// agree whenever the is-id node is an attribute (the result is the element
// bearing the attribute) and differ when the is-id node is an element: fn:id
// returns that element itself, whereas fn:element-with-id returns its parent
// element. The elementWithID flag selects the latter behavior.
func idLookup(ctx context.Context, args []xdm.Sequence, elementWithID bool) (xdm.Sequence, error) {
	doc, err := resolveIDLookupDocument(ctx, args)
	if err != nil {
		return nil, err
	}

	tokens, err := idLookupTokens(ctx, args[0])
	if err != nil {
		return nil, err
	}

	if len(tokens) == 0 {
		return nil, nil
	}

	nodes := make([]xdm.Node, 0, len(tokens))
	for _, token := range tokens {
		// GetElementByID resolves DTD-declared ID attributes; the returned
		// element already bears the ID attribute, so it is the correct
		// result for both fn:id and fn:element-with-id.
		if elem := doc.GetElementByID(token); elem != nil {
			nodes = append(nodes, elem)
		}
	}

	nodes = append(nodes, idElementsFromTypeAnnotations(doc, tokens, getFnContext(ctx), elementWithID)...)

	return sequenceFromDocOrderedNodes(ctx, nodes)
}

func idElementsFromTypeAnnotations(doc *xdm.Document, tokens []string, ec *evalContext, elementWithID bool) []xdm.Node {
	if ec == nil || len(tokens) == 0 {
		return nil
	}

	if ec.typeAnnotations == nil && ec.preservedIDAnnotations == nil && ec.idNodes == nil {
		return nil
	}

	wanted := make(map[string]struct{}, len(tokens))
	for _, token := range tokens {
		wanted[token] = struct{}{}
	}

	// Gather every candidate is-id node exactly once. A node is an is-id node
	// when its type annotation is xs:ID (or derived from it) OR the xsd validator
	// flagged it in the PSVI is-id set — the latter covers a singleton list of
	// xs:ID and a union that selects an xs:ID-derived member, neither of which is
	// a name-level subtype of xs:ID. Both regular and preserved ID annotations are
	// consulted (the latter are kept when input-type-annotations="strip" removes
	// regular annotations but retains the is-id/is-idref properties).
	candidates := make(map[xdm.Node]struct{})

	for _, annMap := range []map[xdm.Node]string{ec.typeAnnotations, ec.preservedIDAnnotations} {
		for node, typeName := range annMap {
			if annotationMatchesIDType(typeName, ec) {
				candidates[node] = struct{}{}
			}
		}
	}

	for node := range ec.idNodes {
		candidates[node] = struct{}{}
	}

	seen := make(map[xdm.Node]struct{})

	var nodes []xdm.Node

	for node := range candidates {
		if xdm.DocumentRoot(node) != doc {
			continue
		}

		result, ok := idNodeResult(node, wanted, elementWithID)
		if !ok {
			continue
		}

		if _, dup := seen[result]; dup {
			continue
		}

		seen[result] = struct{}{}
		nodes = append(nodes, result)
	}

	return nodes
}

// idNodeResult maps an is-id node to the node fn:id / fn:element-with-id should
// return for it, or (nil, false) when the node's value is not among wanted (or
// it has no element parent where one is required). For an ID attribute both
// functions return the bearing element. For an ID-typed element, fn:id returns
// that element itself and fn:element-with-id (elementWithID) returns its parent.
func idNodeResult(node xdm.Node, wanted map[string]struct{}, elementWithID bool) (xdm.Node, bool) {
	switch typed := node.(type) {
	case *xdm.Attribute:
		if _, ok := wanted[strings.Trim(xdm.StringValue(typed), " \t\r\n")]; !ok {
			return nil, false
		}

		parent, ok := typed.Parent().(*xdm.Element)
		if !ok {
			return nil, false
		}

		return parent, true
	case *xdm.Element:
		if _, ok := wanted[strings.Trim(xdm.StringValue(typed), " \t\r\n")]; !ok {
			return nil, false
		}

		if elementWithID {
			parent, ok := typed.Parent().(*xdm.Element)
			if !ok {
				return nil, false
			}

			return parent, true
		}

		return typed, true
	}

	return nil, false
}

func annotationMatchesIDType(typeName string, ec *evalContext) bool {
	if typeName == "" {
		return false
	}

	if xdm.IsSubtypeOf(typeName, xdm.TypeID) {
		return true
	}

	if ec == nil || ec.schemaDeclarations == nil {
		return false
	}

	return ec.schemaDeclarations.IsSubtypeOf(typeName, xdm.TypeID)
}

func fnIDRef(ctx context.Context, args []xdm.Sequence) (xdm.Sequence, error) {
	doc, err := resolveIDLookupDocument(ctx, args)
	if err != nil {
		return nil, err
	}

	// Input strings match individual IDREF tokens as-is; do not tokenize input.
	atoms, err := AtomizeSequence(args[0])
	if err != nil {
		return nil, err
	}

	if len(atoms) == 0 {
		return nil, nil
	}

	wanted := make(map[string]struct{}, len(atoms))
	if err := fnIDRefAtoms(atoms, wanted); err != nil {
		return nil, err
	}

	lookup := idRefLookup{ctx: ctx, ec: getFnContext(ctx), wanted: wanted}
	if err := xdm.Walk(doc, xdm.NodeWalkerFunc(lookup.visit)); err != nil {
		return nil, err
	}

	return sequenceFromDocOrderedNodes(ctx, lookup.nodes)
}

type idRefLookup struct {
	ctx    context.Context
	ec     *evalContext
	wanted map[string]struct{}
	nodes  []xdm.Node
}

func (l *idRefLookup) visit(node xdm.Node) error {
	// Charge once per visited node, including non-element nodes.
	if err := fnCountOp(l.ctx, l.ec); err != nil {
		return err
	}

	element, ok := node.(*xdm.Element)
	if !ok {
		return nil
	}

	l.collectAttributes(element)

	if l.ec != nil && nodeHasIDRefAnnotation(l.ec, element) {
		if hasIDRefToken(strings.Trim(xdm.StringValue(element), " \t\r\n"), l.wanted) {
			l.nodes = append(l.nodes, element)
		}
	}

	return nil
}

func (l *idRefLookup) collectAttributes(element *xdm.Element) {
	for _, attribute := range element.Attributes() {
		isIDRef := attribute.IDType() == xdm.IDRefAttribute || attribute.IDType() == xdm.IDRefsAttribute
		if !isIDRef && l.ec != nil {
			isIDRef = nodeHasIDRefAnnotation(l.ec, attribute)
		}

		if isIDRef && hasIDRefToken(attribute.Value(), l.wanted) {
			l.nodes = append(l.nodes, attribute)
		}
	}
}

// nodeHasIDRefAnnotation checks regular and preserved IDREF/IDREFS annotations.
func nodeHasIDRefAnnotation(ec *evalContext, node xdm.Node) bool {
	for _, annMap := range []map[xdm.Node]string{ec.typeAnnotations, ec.preservedIDAnnotations} {
		if ann, ok := annMap[node]; ok && isIDRefAnnotation(ann, ec) {
			return true
		}
	}

	return false
}

// isIDRefAnnotation returns true if the type name is xs:IDREF, xs:IDREFS, or
// a subtype thereof.
func isIDRefAnnotation(typeName string, ec *evalContext) bool {
	if typeName == "" {
		return false
	}

	if xdm.IsSubtypeOf(typeName, xdm.TypeIDREF) || xdm.IsSubtypeOf(typeName, xdm.TypeIDREFS) {
		return true
	}

	if ec != nil && ec.schemaDeclarations != nil {
		return ec.schemaDeclarations.IsSubtypeOf(typeName, xdm.TypeIDREF) || ec.schemaDeclarations.IsSubtypeOf(typeName, xdm.TypeIDREFS)
	}

	return false
}

func hasIDRefToken(value string, wanted map[string]struct{}) bool {
	for token := range strings.FieldsFuncSeq(value, xmlchar.IsSpace) {
		if _, found := wanted[token]; found {
			return true
		}
	}

	return false
}

func fnElementWithID(ctx context.Context, args []xdm.Sequence) (xdm.Sequence, error) {
	return idLookup(ctx, args, true)
}

func fnCollection(ctx context.Context, args []xdm.Sequence) (xdm.Sequence, error) {
	uri, hasURI, err := collectionURIArg(ctx, args)
	if err != nil {
		return nil, err
	}

	if hasURI {
		uri, err = resolveCollectionURI(ctx, uri, "fn:collection")
		if err != nil {
			return nil, err
		}
	} else {
		uri = ""
	}

	ec := getFnContext(ctx)
	if ec == nil || ec.collectionResolver == nil {
		return nil, &xdm.Error{Code: errCodeFODC0002, Message: "fn:collection: no collection resolver configured"}
	}

	seq, err := ec.collectionResolver.ResolveCollection(ctx, uri)
	if err != nil {
		return nil, &xdm.Error{Code: errCodeFODC0002, Message: fmt.Sprintf("fn:collection: cannot resolve collection: %v", err), Cause: err}
	}

	return seq, nil
}

func fnURICollection(ctx context.Context, args []xdm.Sequence) (xdm.Sequence, error) {
	uri, hasURI, err := collectionURIArg(ctx, args)
	if err != nil {
		return nil, err
	}

	if hasURI {
		uri, err = resolveCollectionURI(ctx, uri, "fn:uri-collection")
		if err != nil {
			return nil, err
		}
	} else {
		uri = ""
	}

	ec := getFnContext(ctx)
	if ec == nil || ec.collectionResolver == nil {
		return nil, &xdm.Error{Code: errCodeFODC0002, Message: "fn:uri-collection: no collection resolver configured"}
	}

	uris, err := ec.collectionResolver.ResolveURICollection(ctx, uri)
	if err != nil {
		return nil, &xdm.Error{Code: errCodeFODC0002, Message: fmt.Sprintf("fn:uri-collection: cannot resolve collection: %v", err), Cause: err}
	}

	result := make(xdm.ItemSlice, 0, len(uris))
	for _, uri := range uris {
		result = append(result, xdm.AtomicValue{TypeName: xdm.TypeAnyURI, Value: uri})
	}

	return result, nil
}

func fnDoc(ctx context.Context, args []xdm.Sequence) (xdm.Sequence, error) {
	// xs:string? URI: an atomized-empty argument (empty array / nilled node)
	// returns the empty sequence, like a syntactically empty one. Emptiness is
	// tested AFTER atomization; a raw seqLen gate would miss the atomized-empty
	// case and try to load an empty URI.
	uri, empty, err := coerceAtomizedString(ctx, args[0])
	if err != nil {
		return nil, err
	}

	if empty {
		return nil, nil
	}

	doc, err := loadDoc(ctx, uri)
	if err != nil {
		return nil, err
	}

	return xdm.SingleNode(doc), nil
}

func fnDocAvailable(ctx context.Context, args []xdm.Sequence) (xdm.Sequence, error) {
	// An empty URI (syntactic or atomized-empty) makes no document available.
	uri, empty, err := coerceAtomizedString(ctx, args[0])
	if err != nil {
		return nil, err
	}

	if empty {
		return xdm.SingleBoolean(false), nil
	}

	_, err = loadDoc(ctx, uri)

	return xdm.SingleBoolean(err == nil), nil
}

func loadDoc(ctx context.Context, uri string) (xdm.Node, error) {
	if strings.Contains(uri, "#") {
		return nil, &xdm.Error{Code: errCodeFODC0005, Message: "fn:doc: URI must not contain a fragment identifier"}
	}

	resolved, err := resolveDocURI(ctx, uri)
	if err != nil {
		return nil, err
	}
	// An empty argument resolves to the base URI verbatim, which may itself
	// carry a fragment identifier. Re-check the resolved URI so doc("") with a
	// fragmented base URI is rejected the same as a fragmented argument.
	if strings.Contains(resolved, "#") {
		return nil, &xdm.Error{Code: errCodeFODC0005, Message: "fn:doc: URI must not contain a fragment identifier"}
	}

	ec := getFnContext(ctx)

	parseOptions := xdm.ParseOptions{}
	if ec != nil {
		parseOptions = ec.xmlParseOptions().WithByteLimit(ec.maxResourceBytes)

		if doc, ok := ec.docCache[resolved]; ok {
			return doc, nil
		}
	}

	reader, err := unparsedtext.OpenURI(ctx, unparsedTextConfig(ctx), resolved)
	if err != nil {
		return nil, &xdm.Error{Code: errCodeFODC0002, Message: fmt.Sprintf("fn:doc: cannot retrieve resource: %v", err), Cause: err}
	}

	doc, parseErr := parseOptions.ParseReader(ctx, reader)
	if err := errors.Join(parseErr, reader.Close()); err != nil {
		return nil, &xdm.Error{Code: errCodeFODC0002, Message: fmt.Sprintf("fn:doc: cannot parse document: %v", err), Cause: err}
	}

	doc.SetURL(resolved)

	if ec != nil {
		ec.docCache[resolved] = doc
	}

	return doc, nil
}

func collectionURIArg(ctx context.Context, args []xdm.Sequence) (string, bool, error) {
	if len(args) == 0 {
		return "", false, nil
	}
	// xs:string? URI: atomize FIRST, then apply the singleton-or-empty
	// cardinality. An atomized-empty argument (empty array / nilled node) is
	// treated as "URI absent" — the same as a syntactically empty sequence — so
	// the default collection is used. coerceAtomizedString raises XPTY0004 for a
	// post-atomization length > 1, so no pre-atomization gate belongs here.
	uri, empty, err := coerceAtomizedString(ctx, args[0])
	if err != nil {
		return "", false, err
	}

	if empty {
		return "", false, nil
	}

	return uri, true, nil
}

func resolveCollectionURI(ctx context.Context, uri, fnName string) (string, error) {
	if uri == "" {
		return "", nil
	}

	ref, err := parseURIReference(uri)
	if err != nil {
		return "", &xdm.Error{Code: errCodeFODC0004, Message: fmt.Sprintf("%s: invalid URI: %v", fnName, err), Cause: err}
	}

	if ref.IsAbs() {
		return uri, nil
	}

	if baseURI := baseURIFromContext(ctx); baseURI != "" {
		if _, err := parseURIReference(baseURI); err != nil {
			return "", &xdm.Error{Code: errCodeFODC0004, Message: fmt.Sprintf("%s: invalid base URI: %v", fnName, err), Cause: err}
		}

		resolved, err := resolveURIReference(baseURI, uri)
		if err != nil {
			return "", &xdm.Error{Code: errCodeFODC0004, Message: fmt.Sprintf("%s: invalid base URI: %v", fnName, err), Cause: err}
		}

		return resolved, nil
	}

	return uri, nil
}

func resolveDocURI(ctx context.Context, uri string) (string, error) {
	if uri == "" {
		// doc("") returns the document at the base URI (XSLT §14.1, XPath §14.1.1)
		if ec := getFnContext(ctx); ec != nil && ec.baseURI != "" {
			return ec.baseURI, nil
		}

		return "", &xdm.Error{Code: errCodeFODC0002, Message: "fn:doc: empty URI"}
	}

	parsed, err := parseURIReference(uri)
	if err != nil {
		return "", &xdm.Error{Code: errCodeFODC0005, Message: fmt.Sprintf("fn:doc: invalid URI: %s", uri), Cause: err}
	}

	if parsed.Scheme != "" {
		if ec := getFnContext(ctx); !isSupportedResourceScheme(parsed.Scheme) && (ec == nil || ec.uriResolver == nil) {
			return "", &xdm.Error{Code: errCodeFODC0002, Message: fmt.Sprintf("fn:doc: unsupported URI scheme: %s", parsed.Scheme)}
		}

		return uri, nil
	}

	// Relative URI — resolve against base URI
	if baseURI := baseURIFromContext(ctx); baseURI != "" {
		resolved, err := resolveURIReference(baseURI, uri)
		if err == nil {
			return resolved, nil
		}
	}

	return "", &xdm.Error{Code: errCodeFODC0002, Message: "fn:doc: relative URI has no usable static base URI"}
}

func resolveIDLookupDocument(ctx context.Context, args []xdm.Sequence) (*xdm.Document, error) {
	var node xdm.Node

	if len(args) > 1 {
		if xdm.SequenceLen(args[1]) != 1 {
			return nil, &xdm.Error{Code: lexicon.ErrXPTY0004, Message: "fn:id second argument must be a single node"}
		}

		ni, ok := args[1].Get(0).(xdm.NodeItem)
		if !ok {
			return nil, &xdm.Error{Code: lexicon.ErrXPTY0004, Message: "fn:id second argument must be a node"}
		}

		node = ni.Node
	} else {
		fc := getFnContext(ctx)
		switch {
		case fc == nil || (fc.node == nil && fc.contextItem == nil):
			return nil, &xdm.Error{Code: errCodeXPDY0002, Message: errMsgContextItemAbsent}
		case fc.node != nil:
			node = fc.node
		default:
			return nil, &xdm.Error{Code: lexicon.ErrXPTY0004, Message: "context item is not a node"}
		}
	}

	root := xdm.DocumentRoot(node)

	doc, ok := root.(*xdm.Document)
	if !ok {
		return nil, &xdm.Error{Code: errCodeFODC0001, Message: "fn:id requires a node whose root is a document node"}
	}

	return doc, nil
}

func idLookupTokens(ctx context.Context, seq xdm.Sequence) ([]string, error) {
	atoms, err := AtomizeSequence(seq)
	if err != nil {
		return nil, err
	}

	var tokens []string

	for _, atom := range atoms {
		s, err := atomicToString(atom)
		if err != nil {
			return nil, err
		}

		for token := range strings.FieldsFuncSeq(s, func(r rune) bool { return r == ' ' || r == '\t' || r == '\r' || r == '\n' }) {
			if xmlchar.IsValidNCName(token) {
				limit := maxNodeSetLength
				if ec := getFnContext(ctx); ec != nil {
					limit = ec.maxNodes
				}

				if len(tokens) >= limit {
					return nil, ErrNodeSetLimit
				}

				if err := fnCountOp(ctx, getFnContext(ctx)); err != nil {
					return nil, err
				}

				tokens = append(tokens, token)
			}
		}
	}

	return tokens, nil
}

func sequenceFromDocOrderedNodes(ctx context.Context, nodes []xdm.Node) (xdm.Sequence, error) {
	if len(nodes) == 0 {
		return nil, nil
	}

	cache := &xdm.DocOrderCache{}
	maxNodes := maxNodeSetLength

	fc := getFnContext(ctx)
	if fc != nil {
		cache = fc.docOrder
		maxNodes = fc.maxNodes
	}

	deduped, err := xdm.DeduplicateNodes(nodes, cache, maxNodes)
	if err != nil {
		return nil, err
	}

	result := make(xdm.ItemSlice, 0, len(deduped))
	for _, node := range deduped {
		result = append(result, nodeItemFor(ctx, fc, node))
	}

	return result, nil
}

// nodeArgOrCtx extracts a node from the first argument or falls back to the context node.
func nodeArgOrCtx(ctx context.Context, args []xdm.Sequence) (xdm.Node, error) {
	if len(args) == 0 {
		fc := getFnContext(ctx)
		if fc == nil || fc.node == nil && fc.contextItem == nil {
			return nil, &xdm.Error{Code: errCodeXPDY0002, Message: errMsgContextItemAbsent}
		}

		if fc.node == nil {
			return nil, &xdm.Error{Code: lexicon.ErrXPTY0004, Message: "context item is not a node"}
		}

		return fc.node, nil
	}

	if xdm.SequenceLen(args[0]) == 0 {
		return nil, nil //nolint:nilnil
	}

	if xdm.SequenceLen(args[0]) > 1 {
		// XPath 1.0 compatibility mode uses the first node; otherwise a >1 node
		// argument is a type error.
		if !getFnContext(ctx).xpath10CompatMode() {
			return nil, &xdm.Error{Code: lexicon.ErrXPTY0004, Message: "expected single node, got sequence of length > 1"}
		}
	}

	ni, ok := args[0].Get(0).(xdm.NodeItem)
	if !ok {
		return nil, &xdm.Error{Code: lexicon.ErrXPTY0004, Message: "expected node"}
	}

	return ni.Node, nil
}

func fnIDRefAtoms(atoms []xdm.AtomicValue, wanted map[string]struct{}) error {
	for _, atom := range atoms {
		s, sErr := atomicToString(atom)
		if sErr != nil {
			return sErr
		}

		if s != "" {
			wanted[s] = struct{}{}
		}
	}

	return nil
}
