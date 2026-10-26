// Derived from lestrrat-go/helium at 7362c0a70122a757780f4d0b545a9b370dead6ab.
// Copyright (c) 2015 lestrrat. MIT License; see licenses/MIT-helium.txt at the repository root.

package xslt

import (
	"context"

	"github.com/skarm/xmlsec/internal/lexicon"
	"github.com/skarm/xmlsec/transform/internal/xdm"
)

// stripStackFrame is one entry of stripWhitespaceFromNodeInto's explicit
// traversal stack: node, plus the xml:space preserve state in effect for
// node's own children.
type stripStackFrame struct {
	node     xdm.Node
	preserve bool
}

// applyBuiltinRules applies the built-in template rules per XSLT spec.
func (ec *execContext) applyBuiltinRules(ctx context.Context, node xdm.Node, mode string, paramValues ...map[string]xdm.Sequence) error {
	defer ec.pushPackage(ec.activeModePackage())()

	// The current mode includes its package identity, including when a helper
	// or an overriding rule is declared in a different package.
	return ec.applyOnNoMatch(ctx, node, modeCurrent, ec.builtinTemplateBehavior(mode), paramValues...)
}

func (ec *execContext) builtinTemplateBehavior(mode string) string {
	if definition := ec.lookupModeDef(mode); definition != nil && definition.OnNoMatch != "" {
		return definition.OnNoMatch
	}

	return onNoMatchTextOnlyCopy
}

func (ec *execContext) applyOnNoMatch(ctx context.Context, node xdm.Node, mode, behavior string, paramValues ...map[string]xdm.Sequence) error {
	switch behavior {
	case onNoMatchShallowCopy:
		return ec.onNoMatchShallowCopy(ctx, node, mode, paramValues...)
	case onNoMatchDeepCopy:
		return ec.onNoMatchDeepCopy(node)
	case onNoMatchShallowSkip:
		if element, ok := node.(*xdm.Element); ok {
			if err := ec.applyTemplatesToAttributes(ctx, element, mode, paramValues...); err != nil {
				return err
			}
		}

		if node.Type() == xdm.DocumentNode || node.Type() == xdm.ElementNode {
			return ec.applyTemplatesToChildren(ctx, node, mode, paramValues...)
		}

		return nil
	case onNoMatchDeepSkip:
		if node.Type() == xdm.DocumentNode {
			return ec.applyTemplatesToChildren(ctx, node, mode, paramValues...)
		}

		return nil
	case onNoMatchFail:
		return dynamicError(errCodeXTDE0555, "no matching template in mode %q (on-no-match=fail)", mode)
	default:
		return ec.onNoMatchTextOnlyCopy(ctx, node, mode, paramValues...)
	}
}

func (ec *execContext) onNoMatchTextOnlyCopy(ctx context.Context, node xdm.Node, mode string, paramValues ...map[string]xdm.Sequence) error {
	switch node.Type() {
	case xdm.DocumentNode, xdm.ElementNode:
		return ec.applyTemplatesToChildren(ctx, node, mode, paramValues...)
	case xdm.TextNode, xdm.CDATASectionNode, xdm.AttributeNode:
		return ec.addNode(ec.resultDoc.CreateText(xdm.CharacterData(node)))
	default:
		return nil
	}
}

func (ec *execContext) onNoMatchShallowCopy(ctx context.Context, node xdm.Node, mode string, paramValues ...map[string]xdm.Sequence) error {
	switch node.Type() {
	case xdm.DocumentNode:
		// The built-in template for document nodes in shallow-copy mode
		// creates a new document node and applies templates to the children.
		// When in sequence mode (e.g., inside a function returning
		// document-node()), wrap the result in a document node so the
		// return type matches. Otherwise, emit children directly.
		return onNoMatchShallowCopyDocumentNode(ctx, ec, node, mode, paramValues)
	case xdm.ElementNode:
		srcElem, _ := xdm.AsNode[*xdm.Element](node)

		newElem, err := ec.resultDoc.CreateElement(srcElem.LocalName())
		if err != nil {
			return err
		}

		for _, ns := range srcElem.Namespaces() {
			_ = newElem.DeclareNamespace(ns.Prefix(), ns.URI())
		}

		if srcElem.URI() != "" {
			_ = newElem.SetActiveNamespace(srcElem.Prefix(), srcElem.URI())
		}

		if err := ec.addNode(newElem); err != nil {
			return err
		}

		if newElem.Parent() == nil {
			if srcBase := xdm.NodeGetBase(srcElem.OwnerDocument(), srcElem); srcBase != "" {
				xdm.SetNodeBaseURI(newElem, srcBase)
			}
		}

		out := ec.currentOutput()
		savedCurrent := out.current
		savedSeqMode := out.sequenceMode
		savedCapture := out.captureItems
		out.current = newElem
		// Temporarily disable sequenceMode and captureItems so that
		// children are added to this element normally (not captured as
		// separate items in the sequence). This mirrors execElement.
		out.sequenceMode = false

		out.captureItems = false
		defer func() {
			out.current = savedCurrent
			out.sequenceMode = savedSeqMode
			out.captureItems = savedCapture
		}()
		// Apply templates to attributes first (so user templates can
		// intercept attribute nodes, e.g. match="w/@id"), then children.
		if err := ec.applyTemplatesToAttributes(ctx, srcElem, mode, paramValues...); err != nil {
			return err
		}

		return ec.applyTemplatesToChildren(ctx, srcElem, mode, paramValues...)
	case xdm.TextNode, xdm.CDATASectionNode:
		text := ec.resultDoc.CreateText(xdm.CharacterData(node))
		return ec.addNode(text)
	case xdm.CommentNode:
		comment := ec.resultDoc.CreateComment(xdm.CharacterData(node))
		return ec.addNode(comment)
	case xdm.ProcessingInstructionNode:
		pi := ec.resultDoc.CreatePI(node.Name(), xdm.CharacterData(node))
		return ec.addNode(pi)
	case xdm.AttributeNode:
		attr, _ := xdm.AsNode[*xdm.Attribute](node)
		return ec.copyAttributeNodeToOutput(attr)
	case xdm.NamespaceNode:
		namespace, _ := xdm.AsNode[*xdm.NamespaceNodeWrapper](node)
		return ec.copyNamespaceNodeToOutput(namespace)

	default:
		return nil
	}
}

func (ec *execContext) onNoMatchDeepCopy(node xdm.Node) error {
	// Deep copy: copy the entire subtree to the output without template matching.
	switch node.Type() {
	case xdm.DocumentNode:
		return onNoMatchDeepCopyDocumentNode(ec, node)
	case xdm.ElementNode, xdm.TextNode, xdm.CDATASectionNode,
		xdm.CommentNode, xdm.ProcessingInstructionNode:
		out := ec.currentOutput()
		pendingBefore := len(out.pendingItems)

		copied, err := xdm.CopyNode(node, ec.resultDoc)
		if err != nil {
			return err
		}

		if err := ec.addNode(copied); err != nil {
			return err
		}

		if node.Type() == xdm.ElementNode && copied.Parent() == nil {
			srcElem, _ := xdm.AsNode[*xdm.Element](node)
			if srcBase := xdm.NodeGetBase(srcElem.OwnerDocument(), srcElem); srcBase != "" {
				xdm.SetNodeBaseURI(copied, srcBase)
			}
		}
		// XSLT 3.0 §16.1.1: on-no-match="deep-copy" preserves type annotations.
		// Transfer the source subtree's annotations to the copy and surface them
		// on the captured NodeItem so instance-of checks on the result succeed.
		ec.deepTransferAnnotations(node, copied)
		ec.propagateValidationAnnotationsToPending(out, pendingBefore)

		return nil
	case xdm.AttributeNode:
		attribute, _ := xdm.AsNode[*xdm.Attribute](node)
		return ec.copyAttributeNodeToOutput(attribute)

	case xdm.NamespaceNode:
		namespace, _ := xdm.AsNode[*xdm.NamespaceNodeWrapper](node)
		return ec.copyNamespaceNodeToOutput(namespace)
	default:
		return nil
	}
}

// stripVerdict reports whether elem's whitespace-only text-node children would
// be stripped, per the schema classifier, xsl:strip-space/preserve-space rules,
// and DTD element-only content — everything shouldStripWhitespace decides
// EXCEPT the xml:space ancestor override, which the caller applies afterward.
func (ec *execContext) stripVerdict(elem *xdm.Element) bool { return ec.isElementStripped(elem) }

// shouldStripWhitespace returns true if a text node is whitespace-only
// and its parent element matches a strip-space pattern or has element-only
// content per its DTD declaration (XDM 3.1 Section 6.7.1).
//
// inheritedXMLSpace's ancestor walk runs LAST, after stripVerdict, rather than
// first: xml:space="preserve" can only ever convert a strip verdict into a
// preserve, never the reverse, so it cannot change stripVerdict's answer for
// any node. Deferring it means the common case — no xsl:strip-space, no DTD
// element-only content, no schema annotations, where stripVerdict is false —
// never walks the ancestor chain at all.
//
// Without schema type annotations, stripVerdict is a strip-rule scan plus a DTD
// lookup, which is cheaper than reading the text (a copy), so it runs before
// the whitespace check and the common no-strip case never reads the text. With
// annotations, stripVerdict walks the ancestors, so the text check runs first.
func (ec *execContext) shouldStripWhitespace(node xdm.Node) bool {
	elem, ok := textStripParent(node)
	if !ok {
		return false
	}

	if ec.typeAnnotations == nil {
		if !ec.stripVerdict(elem) || !isWhitespaceOnlyText(node) {
			return false
		}
	} else if !isWhitespaceOnlyText(node) || !ec.stripVerdict(elem) {
		return false
	}

	return !ec.xmlSpacePreserve(elem)
}

// xmlSpacePreserve is inheritedXMLSpace(elem) == lexicon.SpacePreserve, memoized
// per transform in ec.xmlSpacePreserveMemo (see the field comment on
// execContext for the invariant that makes this safe). It targets the
// retained-whitespace case: xsl:strip-space matches an element, but an
// xml:space="preserve" ancestor keeps its whitespace, so every whitespace-only
// text node under that ancestor is re-checked as applyTemplates visits it —
// without the memo, each check re-walks the full ancestor chain.
//
// The walk stops at the first memoized ancestor or the first element with its
// own xml:space attribute, then backfills every element it passed with that
// same verdict (correct because xml:space is inherited unchanged down to the
// first override, so all of them share it).
func (ec *execContext) xmlSpacePreserve(elem *xdm.Element) bool {
	if v, ok := ec.xmlSpacePreserveMemo[elem]; ok {
		return v
	}

	var chain []*xdm.Element

	preserve := false

	for n := xdm.Node(elem); n != nil; n = n.Parent() {
		e, ok := n.(*xdm.Element)
		if !ok {
			continue
		}

		if v, ok := ec.xmlSpacePreserveMemo[e]; ok {
			preserve = v
			break
		}

		if v, ok := e.GetAttribute("xml:space"); ok {
			preserve = v == lexicon.SpacePreserve

			chain = append(chain, e)

			break
		}

		chain = append(chain, e)
	}

	if ec.xmlSpacePreserveMemo == nil {
		ec.xmlSpacePreserveMemo = make(map[*xdm.Element]bool, len(chain))
	}

	for _, e := range chain {
		ec.xmlSpacePreserveMemo[e] = preserve
	}

	return preserve
}

// isElementStripped checks if an element matches strip-space rules.
// preserve-space overrides strip-space for the same element.
// Uses the effective (package-scoped) strip/preserve rules.
func (ec *execContext) isElementStripped(elem *xdm.Element) bool {
	stripRules := ec.effectiveStripSpace()
	if len(stripRules) == 0 {
		return false
	}

	// Find the most authoritative matching strip rule, ordered first by import
	// precedence (higher wins) and then by NameTest specificity priority.
	stripPrec, stripPriority, stripped := -1, -1, false
	stripOrder := -1

	for _, nt := range stripRules {
		if !matchSpaceNameTest(nt, elem) {
			continue
		}

		if !stripped || rankSpaceRule(nt) > packSpaceRank(stripPrec, stripPriority) || rankSpaceRule(nt) == packSpaceRank(stripPrec, stripPriority) && nt.SpaceOrder > stripOrder {
			stripPrec = nt.ImportPrec
			stripPriority = nameTestPriority(nt)
			stripOrder = nt.SpaceOrder
			stripped = true
		}
	}

	if !stripped {
		return false
	}

	// A matching preserve rule overrides strip when it is at least as
	// authoritative (import precedence, then specificity).
	stripRank := packSpaceRank(stripPrec, stripPriority)
	for _, nt := range ec.effectivePreserveSpace() {
		if matchSpaceNameTest(nt, elem) && (rankSpaceRule(nt) > stripRank || rankSpaceRule(nt) == stripRank && nt.SpaceOrder >= stripOrder) {
			return false
		}
	}

	return true
}

// stripWhitespaceFromDoc removes whitespace-only text nodes from a document
// tree according to the stylesheet's xsl:strip-space and xsl:preserve-space rules.
// This is called when loading documents so that XPath evaluation sees the
// correctly stripped tree.
func (ec *execContext) stripWhitespaceFromDoc(doc *xdm.Document) {
	ec.stripWhitespaceFromNode(doc)
}

func (ec *execContext) stripWhitespaceFromNode(root xdm.Node) {
	ec.stripWhitespaceFromNodeInto(root, nil)
}

// stripWhitespaceFromNodeInto is stripWhitespaceFromNode with an optional out
// parameter: when removed is non-nil, every unlinked whitespace-only node is
// recorded in it. The in-place strip of a schema-validated source copy uses this
// so a selected node the strip removes can be dropped from the initial match
// selection.
//
// preserve threads the in-scope xml:space state top-down through the stack,
// mirroring copyAndStrip's childPreserve: it is seeded once from root via
// inheritedXMLSpace (root can be an element subtree with real ancestors of its
// own, not always a document root — see execute_transform.go's in-place strip
// of a schema-validated copy), then recomputed at each pushed element from its
// own xml:space attribute if it declares one, else inherited from its parent
// frame. This replaces a per-whitespace-node ancestor walk with one O(1) check
// per node, and keeps this pre-pass consistent with shouldStripWhitespace
// (both ultimately consult stripVerdict) without calling it directly.
func (ec *execContext) stripWhitespaceFromNodeInto(root xdm.Node, removed map[xdm.Node]struct{}) {
	// Use an explicit stack to avoid deep recursion on large documents.
	stack := make([]stripStackFrame, 0, 32)

	stack = append(stack, stripStackFrame{node: root, preserve: inheritedXMLSpace(root) == lexicon.SpacePreserve})
	for len(stack) > 0 {
		frame := stack[len(stack)-1]
		stack = stack[:len(stack)-1]

		child := frame.node.FirstChild()
		for child != nil {
			next := child.NextSibling()
			if elem, ok := whitespaceStripParent(child); ok && !frame.preserve && ec.stripVerdict(elem) {
				if removed != nil {
					removed[child] = struct{}{}
				}

				xdm.UnlinkNode(child.(xdm.MutableNode)) //nolint:forcetypeassert // Tree child nodes implement MutableNode.
			} else if child.FirstChild() != nil {
				stack = append(stack, stripStackFrame{node: child, preserve: childXMLSpacePreserve(child, frame.preserve)})
			}

			child = next
		}
	}
}

// applyTemplatesToChildren applies templates in mode to the XDM children of
// node, in document order, as the built-in template rules do. A DOCTYPE
// declaration or an entity reference is not an XDM child, so no rule sees it.
func (ec *execContext) applyTemplatesToChildren(ctx context.Context, node xdm.Node, mode string, paramValues ...map[string]xdm.Sequence) error {
	var items xdm.ItemSlice

	for child := range xdm.Children(node) {
		if xdm.IsXDMChild(child) {
			items = append(items, xdm.NodeItem{Node: child})
		}
	}

	var params map[string]xdm.Sequence
	if len(paramValues) > 0 {
		params = paramValues[0]
	}

	return ec.applyTemplatesToSequence(ctx, items, mode, params)
}

func (ec *execContext) applyTemplatesToAttributes(ctx context.Context, element *xdm.Element, mode string, paramValues ...map[string]xdm.Sequence) error {
	attributes := element.Attributes()

	items := make(xdm.ItemSlice, 0, len(attributes))
	for _, attribute := range attributes {
		items = append(items, xdm.NodeItem{Node: attribute})
	}

	var params map[string]xdm.Sequence
	if len(paramValues) > 0 {
		params = paramValues[0]
	}

	return ec.applyTemplatesToSequence(ctx, items, mode, params)
}

func onNoMatchShallowCopyDocumentNode(ctx context.Context, ec *execContext, node xdm.Node, mode string, paramValues []map[string]xdm.Sequence) error {
	out := ec.currentOutput()
	if out.sequenceMode || out.captureItems {
		tmpDoc := newCopyDocument(node)

		frame := &outputFrame{doc: tmpDoc, current: tmpDoc}
		ec.outputStack = append(ec.outputStack, frame)
		savedResult := ec.resultDoc

		ec.resultDoc = tmpDoc

		err := ec.applyTemplatesToChildren(ctx, node, mode, paramValues...)
		ec.resultDoc = savedResult
		ec.outputStack = ec.outputStack[:len(ec.outputStack)-1]

		if err != nil {
			return err
		}
		// Always capture the document (even empty) so fn:base-uri works.
		out.captureSequenceItems(xdm.ItemSlice{xdm.NodeItem{Node: tmpDoc}})

		return nil
	}

	return ec.applyTemplatesToChildren(ctx, node, mode, paramValues...)
}

func onNoMatchDeepCopyDocumentNode(ec *execContext, node xdm.Node) error {
	out := ec.currentOutput()
	if out.sequenceMode || out.captureItems {
		copied, err := ec.copyDocumentNode(node)
		if err != nil {
			return err
		}

		ec.deepTransferAnnotations(node, copied)

		out.captureSequenceItems(xdm.ItemSlice{xdm.NodeItem{Node: copied}})

		return nil
	}

	for child := range xdm.Children(node) {
		if err := ec.onNoMatchDeepCopy(child); err != nil {
			return err
		}
	}

	return nil
}

// rankSpaceRule combines a rule's import precedence and NameTest specificity
// into a single comparable rank (import precedence dominates).
func rankSpaceRule(nt nameTest) int {
	return packSpaceRank(nt.ImportPrec, nameTestPriority(nt))
}

func packSpaceRank(importPrec, priority int) int {
	return importPrec<<2 | priority
}

// matchSpaceNameTest checks if an element matches a strip/preserve-space
// nameTest pattern. The namespace URI of a prefixed or default-namespace name
// is resolved at compile time (nt.URI / nt.HasURI), using the namespace context
// in scope at the declaration, so no runtime binding map is consulted here.
func matchSpaceNameTest(nt nameTest, elem *xdm.Element) bool {
	return matchSpaceExpandedName(nt, elem.LocalName(), elem.URI())
}

func matchSpaceExpandedName(nt nameTest, local, uri string) bool {
	if nt.Local == "*" && nt.Prefix == "" && !nt.HasURI {
		return true // "*" matches all
	}

	if nt.Prefix == "*" {
		// "*:NCName" matches elements with given local name in any namespace
		return local == nt.Local
	}

	if nt.Local == "*" {
		// "prefix:*" matches elements in the resolved namespace
		return nt.HasURI && uri == nt.URI
	}
	// Named test: namespace URI was resolved at compile time.
	if nt.HasURI {
		return local == nt.Local && uri == nt.URI
	}
	// "local" with no namespace binding matches the local name in no namespace.
	return local == nt.Local && uri == ""
}

// nameTestPriority returns the priority of a nameTest for conflict resolution.
// Specific names > prefix:* or *:NCName > *
func nameTestPriority(nt nameTest) int {
	if nt.Local == "*" && nt.Prefix == "" && !nt.HasURI {
		return 0 // "*" (matches any element in any namespace)
	}

	if nt.Local == "*" || nt.Prefix == "*" {
		// "prefix:*" / "Q{uri}*" (namespace wildcard) or "*:NCName"
		return 1
	}

	return 2 // specific name
}

// whitespaceStripParent returns the parent element to evaluate strip/preserve
// verdicts against for node, and whether node is even a candidate: a
// whitespace-only text/CDATA node with an element parent. It is the preamble
// of the strip pre-pass (stripWhitespaceFromNodeInto).
func whitespaceStripParent(node xdm.Node) (*xdm.Element, bool) {
	elem, ok := textStripParent(node)
	if !ok || !isWhitespaceOnlyText(node) {
		return nil, false
	}

	return elem, true
}

// inheritedXMLSpace walks up the ancestor chain, starting at node itself, to
// find the nearest xml:space attribute and returns its value ("preserve" or
// "default"). Returns "" if no xml:space is declared on node or any ancestor.
// node need not be an *xdm.Element (e.g. the strip pre-pass seeds from a
// *xdm.Document root); non-element nodes are simply skipped while walking.
func inheritedXMLSpace(node xdm.Node) string {
	for n := node; n != nil; n = n.Parent() {
		e, ok := n.(*xdm.Element)
		if !ok {
			continue
		}

		if v, ok := e.GetAttribute("xml:space"); ok {
			return v
		}
	}

	return ""
}

// childXMLSpacePreserve computes the xml:space preserve state to apply to
// node's own children: node's own xml:space attribute if it declares one,
// otherwise the state inherited from its parent frame.
func childXMLSpacePreserve(node xdm.Node, inherited bool) bool {
	elem, ok := xdm.AsNode[*xdm.Element](node)
	if !ok {
		return inherited
	}

	if v, ok := elem.GetAttribute("xml:space"); ok {
		return v == lexicon.SpacePreserve
	}

	return inherited
}

// textStripParent returns the element whose strip/preserve verdict applies to
// node, and whether node is even a candidate: a text/CDATA node with an element
// parent. It looks only at the tree shape, never at the text itself.
func textStripParent(node xdm.Node) (*xdm.Element, bool) {
	if normalizeNode(node) == nil {
		return nil, false
	}
	// Only strip text/CDATA nodes, not elements or other node types
	if node.Type() != xdm.TextNode && node.Type() != xdm.CDATASectionNode {
		return nil, false
	}

	parent := node.Parent()
	if parent == nil || parent.Type() != xdm.ElementNode {
		return nil, false
	}

	return xdm.AsNode[*xdm.Element](parent)
}

// isWhitespaceOnlyText reports whether node's content consists only of XML
// whitespace (space, tab, CR, LF).
func isWhitespaceOnlyText(node xdm.Node) bool {
	for _, b := range xdm.CharacterData(node) {
		if b != ' ' && b != '\t' && b != '\n' && b != '\r' {
			return false
		}
	}

	return true
}

// selectDefaultNodes returns the default node-set for apply-templates
// (child::node()): the XDM children of node. An attribute or namespace node
// has no children, and a DOCTYPE declaration or an entity reference is not an
// XDM child.
func selectDefaultNodes(node xdm.Node) []xdm.Node {
	node = normalizeNode(node)
	if node == nil {
		return nil
	}

	switch node.Type() {
	case xdm.AttributeNode, xdm.NamespaceNode:
		return nil
	}

	var nodes []xdm.Node

	for child := range xdm.Children(node) {
		if xdm.IsXDMChild(child) {
			nodes = append(nodes, child)
		}
	}

	return nodes
}
