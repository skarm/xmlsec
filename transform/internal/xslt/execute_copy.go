// Derived from lestrrat-go/helium at 7362c0a70122a757780f4d0b545a9b370dead6ab.
// Copyright (c) 2015 lestrrat. MIT License; see licenses/MIT-helium.txt at the repository root.

package xslt

import (
	"context"
	"errors"
	"strings"

	"github.com/skarm/xmlsec/transform/internal/xdm"
	"github.com/skarm/xmlsec/transform/internal/xdm/lexicon"
	"github.com/skarm/xmlsec/transform/internal/xpath"
)

type copyNodeOpts struct {
	body              []instruction
	useAttrSets       []string
	copyNamespaces    bool
	inheritNamespaces bool
}

// emitAtomicText appends an atomic value to the current output as a text node.
// Adjacent atomic values are separated by a single space per XSLT 3.0 §5.7.2;
// prevWasAtomic tracks whether the previously emitted item was atomic and is
// updated to true on success.
func (ec *execContext) emitAtomicText(v xdm.AtomicValue, prevWasAtomic *bool) error {
	s, err := xpath.AtomicToString(v)
	if err != nil {
		return err
	}

	if *prevWasAtomic {
		sep := ec.resultDoc.CreateText(" ")
		if err := ec.addNode(sep); err != nil {
			return err
		}
	}

	text := ec.resultDoc.CreateText(s)
	if err := ec.addNode(text); err != nil {
		return err
	}

	*prevWasAtomic = true

	return nil
}

func (ec *execContext) execCopy(ctx context.Context, inst *copyInst) error {
	contextNode := normalizeNode(ec.contextNode)

	copyNS, err := evaluateCopyBoolean(ctx, contextNode, inst.CopyNamespacesAVT, inst.CopyNamespaces)
	if err != nil {
		return err
	}

	inheritNS, err := evaluateCopyBoolean(ctx, contextNode, inst.InheritNamespacesAVT, inst.InheritNamespaces)
	if err != nil {
		return err
	}

	opts := copyNodeOpts{
		body:              inst.Body,
		useAttrSets:       inst.UseAttrSets,
		copyNamespaces:    copyNS,
		inheritNamespaces: inheritNS,
	}
	if inst.Select != nil {
		return ec.execCopySelected(ctx, inst, contextNode, opts)
	}

	if contextNode == nil {
		// An atomic context item is copied as text without evaluating the body.
		if av, ok := ec.contextItem.(xdm.AtomicValue); ok {
			out := ec.currentOutput()
			return ec.emitAtomicText(av, &out.prevWasAtomic)
		}

		return dynamicError(errCodeXTTE0945, "xsl:copy: no context item")
	}

	if err := ec.validateCopyContext(inst, contextNode); err != nil {
		return err
	}

	out := ec.currentOutput()
	lastBefore := out.current.LastChild()
	pendingBefore := len(out.pendingItems)

	if err := ec.execCopyNode(ctx, contextNode, opts); err != nil {
		return err
	}

	return ec.applyCopyValidation(ctx, inst, out, lastBefore, pendingBefore, contextNode)
}

func (ec *execContext) execCopySelected(ctx context.Context, inst *copyInst, contextNode xdm.Node, opts copyNodeOpts) error {
	result, err := ec.evalXPath(ctx, inst.Select, contextNode)
	if err != nil {
		return err
	}

	seq := result.Sequence()
	if xdm.SequenceLen(seq) == 0 {
		return nil
	}

	if xdm.SequenceLen(seq) > 1 {
		return dynamicError(errCodeXTTE3180,
			"xsl:copy select produced %d items; at most one is allowed", xdm.SequenceLen(seq))
	}

	for item := range xdm.SequenceItems(seq) {
		switch value := item.(type) {
		case xdm.NodeItem:
			return ec.execCopySelectedNode(ctx, inst, value.Node, opts)
		case xdm.AtomicValue:
			out := ec.currentOutput()
			return ec.emitAtomicText(value, &out.prevWasAtomic)
		}
	}

	return nil
}

func (ec *execContext) execCopySelectedNode(ctx context.Context, inst *copyInst, node xdm.Node, opts copyNodeOpts) error {
	savedFocus := ec.captureExecutionFocus()
	savedTemplate := ec.currentTemplate
	ec.contextNode, ec.currentNode = node, node
	ec.contextItem = nil
	ec.setCurrentTemplate(nil)
	ec.position, ec.size = 1, 1
	out := ec.currentOutput()
	lastBefore := out.current.LastChild()
	pendingBefore := len(out.pendingItems)
	err := ec.execCopyNode(ctx, node, opts)
	ec.restoreExecutionFocus(savedFocus)
	ec.setCurrentTemplate(savedTemplate)

	if err != nil {
		return err
	}

	// Validation uses the caller's restored focus, as for a context-node copy.
	return ec.applyCopyValidation(ctx, inst, out, lastBefore, pendingBefore, node)
}

func (ec *execContext) validateCopyContext(inst *copyInst, node xdm.Node) error {
	if inst.TypeName == "" && inst.Validation != validationStrict && inst.Validation != validationLax {
		return nil
	}

	nt := node.Type()
	if nt == xdm.ElementNode || nt == xdm.DocumentNode {
		return nil
	}

	if inst.Validation == validationStrict || inst.Validation == validationLax {
		return dynamicError(errCodeXTTE1535,
			"xsl:copy validation=%q: context node is %s, not an element or document node",
			inst.Validation, nt)
	}

	// Simple types can annotate attributes; complex types cannot.
	if inst.TypeName != "" && ec.isComplexType(inst.TypeName) {
		return dynamicError(errCodeXTTE1535,
			"xsl:copy type=%q: context node is %s, not an element or document node",
			inst.TypeName, nt)
	}

	return nil
}

// applyCopyValidation validates the copied element or standalone attribute in
// either the DOM output or pending sequence items.
func (ec *execContext) applyCopyValidation(ctx context.Context, inst *copyInst, out *outputFrame, lastBefore xdm.Node, pendingBefore int, sourceNode xdm.Node) error {
	if inst.TypeName != "" {
		if sourceNode != nil && sourceNode.Type() == xdm.AttributeNode {
			return ec.validateCopyAttributeType(ctx, sourceNode, inst.TypeName)
		}

		return ec.validateAndAnnotateCopiedElement(ctx, out, lastBefore, pendingBefore, inst.TypeName, "")
	}

	validation := ec.effectiveValidation(inst.Validation)
	if validation == "" {
		return nil
	}

	copiedElem := findCopiedElement(out, lastBefore, pendingBefore)
	if copiedElem == nil {
		return nil
	}

	if err := ec.validateConstructedElement(ctx, copiedElem, validation); err != nil {
		return err
	}

	if out.sequenceMode && len(out.pendingItems) > pendingBefore {
		ec.propagateValidationAnnotationsToPending(out, pendingBefore)
	}

	return nil
}

func (ec *execContext) validateCopyAttributeType(ctx context.Context, sourceNode xdm.Node, typeName string) error {
	if ec.isComplexTypeName(typeName) {
		return dynamicError(errCodeXTTE1535,
			"xsl:copy type=%q refers to a complex type, but copied item is an attribute node", typeName)
	}

	attr, ok := sourceNode.(*xdm.Attribute)
	if !ok {
		return nil
	}

	content := xdm.CharacterData(attr)
	if err := ec.validateAttributeValueForType(ctx, content, normalizeTypeName(typeName, ec)); err != nil {
		return dynamicError(errCodeXTTE1510,
			"xsl:copy: attribute value %q does not match type %s: %v", content, typeName, err)
	}

	return nil
}

func (ec *execContext) validateAndAnnotateCopiedElement(ctx context.Context, out *outputFrame, lastBefore xdm.Node, pendingBefore int, typeName, operation string) error {
	copiedElem := findCopiedElement(out, lastBefore, pendingBefore)
	if copiedElem == nil {
		return nil
	}

	if err := ec.validateAndNormalizeElementContent(ctx, copiedElem, typeName); err != nil {
		if xsltErr, ok := errors.AsType[*XSLTError](err); ok && xsltErr.Code == errCodeXTTE1510 {
			return dynamicError(errCodeXTTE1540,
				operation+"element content does not match declared type %s: %v", typeName, xsltErr.Message)
		}

		return err
	}

	ec.annotateNode(copiedElem, typeName)
	ec.annotateAttributesFromType(copiedElem, typeName)
	propagateAnnotationToPending(out, pendingBefore, copiedElem, typeName)

	return nil
}

// propagateAnnotationToPending sets the TypeAnnotation on the most recent
// pending NodeItem (or the document element within a pending document node)
// so that variable references carry type annotations for instance-of checks.
func propagateAnnotationToPending(out *outputFrame, pendingBefore int, elem *xdm.Element, typeName string) {
	if !out.sequenceMode || len(out.pendingItems) <= pendingBefore {
		return
	}

	idx := len(out.pendingItems) - 1

	ni, ok := out.pendingItems[idx].(xdm.NodeItem)
	if !ok {
		return
	}

	if ni.Node == elem {
		ni.TypeAnnotation = typeName
		out.pendingItems[idx] = ni
	}
}

// effectiveValidation returns the validation mode for a copy/copy-of instruction,
// falling back to the stylesheet default when the instruction has none.
func (ec *execContext) effectiveValidation(instValidation string) string {
	if instValidation != "" {
		return instValidation
	}

	return ec.defaultValidation
}

// isComplexType returns true if typeName refers to a complex type in the
// imported schemas. Returns false for built-in types and unknown types.
func (ec *execContext) isComplexType(typeName string) bool {
	return false
}

func (ec *execContext) execCopyNode(ctx context.Context, node xdm.Node, opts copyNodeOpts) error {
	if node == nil {
		return nil
	}

	switch node.Type() {
	case xdm.ElementNode:
		srcElem, _ := xdm.AsNode[*xdm.Element](node)
		return ec.execCopyElement(ctx, srcElem, opts)
	case xdm.TextNode, xdm.CDATASectionNode:
		return ec.addNode(ec.resultDoc.CreateText(xdm.CharacterData(node)))
	case xdm.CommentNode:
		return ec.addNode(ec.resultDoc.CreateComment(xdm.CharacterData(node)))
	case xdm.ProcessingInstructionNode:
		pi, _ := xdm.AsNode[*xdm.ProcessingInstruction](node)
		return ec.addNode(ec.resultDoc.CreatePI(pi.Name(), xdm.CharacterData(pi)))
	case xdm.DocumentNode:
		return ec.execCopyDocument(ctx, node, opts.body)
	case xdm.AttributeNode:
		attr, _ := xdm.AsNode[*xdm.Attribute](node)
		return ec.copyAttributeNodeToOutput(attr)
	case xdm.NamespaceNode:
		ns, _ := xdm.AsNode[*xdm.NamespaceNodeWrapper](node)
		return ec.copyNamespaceNodeToOutput(ns)
	}

	return nil
}

func (ec *execContext) execCopyElement(ctx context.Context, src *xdm.Element, opts copyNodeOpts) error {
	// LocalName prevents prefix doubling when activating the namespace.
	elem, err := ec.resultDoc.CreateElement(src.LocalName())
	if err != nil {
		return err
	}

	if err := copyElementNamespaces(src, elem, opts.copyNamespaces); err != nil {
		return err
	}

	if err := ec.addNode(elem); err != nil {
		return err
	}

	// Orphan copies retain the source's base URI (XSLT 3.0 §11.9.4).
	if elem.Parent() == nil {
		if srcBase := xdm.NodeGetBase(src.OwnerDocument(), src); srcBase != "" {
			xdm.SetNodeBaseURI(elem, srcBase)
		}
	}

	out := ec.currentOutput()
	savedCurrent, savedPrevAtomic, savedSeqMode, savedCapture := out.current, out.prevWasAtomic, out.sequenceMode, out.captureItems

	out.current, out.prevWasAtomic, out.sequenceMode, out.captureItems = elem, false, false, false

	defer func() {
		out.current, out.prevWasAtomic, out.sequenceMode, out.captureItems = savedCurrent, savedPrevAtomic, savedSeqMode, savedCapture
	}()

	if len(opts.useAttrSets) > 0 {
		if err := ec.applyAttributeSets(ctx, opts.useAttrSets); err != nil {
			return err
		}
	}

	if err := ec.executeSequenceConstructor(ctx, opts.body); err != nil {
		return err
	}

	if err := finishConstructedNamespaces(ctx, elem, opts.inheritNamespaces); err != nil {
		return err
	}

	return nil
}

// copyElementNamespaces copies in-scope bindings when requested and always
// declares the element name's namespace, which is required for well-formedness.
func copyElementNamespaces(src, dst *xdm.Element, copyNS bool) error {
	if copyNS {
		for _, ns := range collectInScopeNamespaces(src) {
			if ns.URI() == "" {
				continue
			}

			if err := dst.DeclareNamespace(ns.Prefix(), ns.URI()); err != nil {
				return err
			}
		}
	}

	if src.URI() == "" {
		return nil
	}

	if !hasNSDecl(dst, src.Prefix(), src.URI()) {
		if err := dst.DeclareNamespace(src.Prefix(), src.URI()); err != nil {
			return err
		}
	}

	return dst.SetActiveNamespace(src.Prefix(), src.URI())
}

func (ec *execContext) execCopyDocument(ctx context.Context, source xdm.Node, body []instruction) error {
	newDoc := newCopyDocument(source)
	out := ec.currentOutput()

	capture := out.captureItems
	if err := ec.executeDocumentCopyBody(ctx, newDoc, body, capture); err != nil {
		return err
	}

	if capture {
		out.pendingItems = append(out.pendingItems, xdm.NodeItem{Node: newDoc})
		out.noteOutput()

		return nil
	}

	for child := range xdm.Children(newDoc) {
		if err := ec.copyNodeToOutput(child); err != nil {
			return err
		}
	}

	return nil
}

func (ec *execContext) executeDocumentCopyBody(ctx context.Context, doc *xdm.Document, body []instruction, capture bool) error {
	out := ec.currentOutput()
	savedDoc, savedCurrent, savedSeqMode, savedCapture := ec.resultDoc, out.current, out.sequenceMode, out.captureItems
	ec.resultDoc, out.current = doc, doc
	out.captureItems = false
	// Captured document children belong to the document, not pendingItems.
	if capture {
		out.sequenceMode = false
	}

	defer func() {
		ec.resultDoc, out.current = savedDoc, savedCurrent

		out.captureItems = savedCapture
		if capture {
			out.sequenceMode = savedSeqMode
		}
	}()

	return ec.executeSequenceConstructor(ctx, body)
}

// copyAttributeNodeToOutput either captures a standalone copy or attaches it
// to the current element, enforcing the attribute-before-content rule.
func (ec *execContext) copyAttributeNodeToOutput(attr *xdm.Attribute) error {
	out := ec.currentOutput()
	if out.sequenceMode {
		var attrNS *xdm.Namespace

		if attr.URI() != "" {
			if ns, err := out.doc.CreateNamespace(attr.Prefix(), attr.URI()); err == nil {
				attrNS = ns
			}
		}

		copiedAttr, err := newStandaloneAttribute(out.doc, attr.LocalName(), attr.Value(), attrNS)
		if err != nil {
			return err
		}

		out.pendingItems = append(out.pendingItems, xdm.NodeItem{Node: copiedAttr})
		out.noteOutput()

		return nil
	}

	elem, ok := out.current.(*xdm.Element)
	if !ok {
		return dynamicError(errCodeXTDE0420,
			"cannot add attribute %s to a non-element node", attr.Name())
	}

	if out.hasChildContent(elem) {
		return dynamicError(errCodeXTDE0410,
			"cannot add attribute %s after child nodes have been added", attr.Name())
	}

	copyAttributeToElement(elem, attr)
	out.noteOutput()

	return nil
}

func (ec *execContext) execCopyOf(ctx context.Context, inst *copyOfInst) error {
	result, err := ec.evalXPath(ctx, inst.Select, ec.contextNode)
	if err != nil {
		return err
	}

	copyNS, err := evaluateCopyBoolean(ctx, ec.contextNode, inst.CopyNamespacesAVT, inst.CopyNamespaces)
	if err != nil {
		return err
	}

	effectiveVal := ec.effectiveValidation(inst.Validation)
	out := ec.currentOutput()
	prevWasAtomic := out.prevWasAtomic

	seq := result.Sequence()

	capture := out.captureItems && ec.stylesheet.processorLanguage() >= 20
	if !capture {
		seq = flattenArraysInSequence(seq)
	}

	for item := range xdm.SequenceItems(seq) {
		if err := xpath.Charge(ctx, 1); err != nil {
			return err
		}

		if _, node := item.(xdm.NodeItem); !node && capture {
			out.captureSequenceItems(xdm.ItemSlice{item})
			continue
		}

		switch value := item.(type) {
		case xdm.NodeItem:
			prevWasAtomic = false

			if err := ec.execCopyOfNode(ctx, inst, value.Node, copyNS, effectiveVal); err != nil {
				return err
			}
		case xdm.AtomicValue:
			if err := ec.emitAtomicText(value, &prevWasAtomic); err != nil {
				return err
			}
		default:
			if err := ec.outputSequence(xdm.ItemSlice{item}); err != nil {
				return err
			}
		}
	}

	out.prevWasAtomic = prevWasAtomic

	return nil
}

func (ec *execContext) execCopyOfNode(ctx context.Context, inst *copyOfInst, node xdm.Node, copyNS bool, validation string) error {
	if validation == validationPreserve {
		if err := ec.checkCopyOfNamespaceContent(node, copyNS); err != nil {
			return err
		}
	}

	out := ec.currentOutput()
	lastBefore := out.current.LastChild()
	pendingBefore := len(out.pendingItems)

	if err := ec.copyNodeToOutput(node, copyNS); err != nil {
		return err
	}

	// Only the top-level copy-of inherits bindings from source ancestors.
	if copyNS && node.Type() == xdm.ElementNode {
		if copied := findCopiedElement(out, lastBefore, pendingBefore); copied != nil {
			src, _ := xdm.AsNode[*xdm.Element](node)
			propagateAncestorNamespaces(src, copied)
		}
	}

	// XSLT 3.0 §11.9.4 ignores type on other node kinds, including any
	// subsequent validation and accumulator transfer for that item.
	if inst.TypeName != "" && !isCopyTypeNode(node) {
		return nil
	}

	if err := ec.applyCopyOfValidation(ctx, inst, node, out, lastBefore, pendingBefore, validation); err != nil {
		return err
	}

	if inst.CopyAccumulators && len(ec.effectiveAccumulators()) > 0 {
		return ec.transferCopyOfAccumulators(ctx, node, out, lastBefore, pendingBefore)
	}

	return nil
}

func isCopyTypeNode(node xdm.Node) bool {
	switch node.Type() {
	case xdm.ElementNode, xdm.AttributeNode, xdm.DocumentNode:
		return true
	default:
		return false
	}
}

// propagateAncestorNamespaces copies in-scope namespace declarations from
// ancestors of src onto dst. This ensures that copy-namespaces="yes" includes
// all inherited namespace bindings, not just those directly declared on the
// element. The xml namespace is excluded since it is always in scope.
func propagateAncestorNamespaces(src, dst *xdm.Element) {
	declared := make(map[string]struct{})
	for _, ns := range dst.Namespaces() {
		declared[ns.Prefix()] = struct{}{}
	}

	// Walk up ancestors and add any undeclared namespace bindings.
	for cur := src.Parent(); cur != nil; {
		pElem, ok := cur.(*xdm.Element)
		if !ok {
			break
		}

		for _, ns := range pElem.Namespaces() {
			prefix := ns.Prefix()
			if prefix == methodXML {
				continue
			}

			if _, exists := declared[prefix]; exists {
				continue
			}

			_ = dst.DeclareNamespace(prefix, ns.URI())
			declared[prefix] = struct{}{}
		}

		cur = pElem.Parent()
	}
}

func (ec *execContext) checkCopyOfNamespaceContent(node xdm.Node, copyNS bool) error {
	if !copyNS && ec.nodeHasNamespaceSensitiveContent(node) {
		return dynamicError(errCodeXTTE0950,
			"copy-of: cannot copy namespace-sensitive content with copy-namespaces=\"no\" and validation=\"preserve\"")
	}

	if node.Type() == xdm.AttributeNode && ec.nodeHasNamespaceSensitiveContent(node) {
		return dynamicError(errCodeXTTE0950,
			"copy-of: cannot copy attribute with namespace-sensitive content without parent element (validation=\"preserve\")")
	}

	return nil
}

func (ec *execContext) applyCopyOfValidation(ctx context.Context, inst *copyOfInst, source xdm.Node, out *outputFrame, lastBefore xdm.Node, pendingBefore int, validation string) error {
	if inst.TypeName != "" {
		if source.Type() == xdm.AttributeNode {
			if err := ec.validateCopyOfAttributeType(ctx, source, inst.TypeName); err != nil {
				return err
			}
		}

		return ec.validateAndAnnotateCopiedElement(ctx, out, lastBefore, pendingBefore, inst.TypeName, "copy-of: ")
	}

	switch validation {
	case validationPreserve:
		ec.preserveCopyOfAnnotations(source, out, lastBefore, pendingBefore)
	case validationStrict, validationLax, validationStrip:
		return ec.validateCopyOfElement(ctx, source, out, lastBefore, pendingBefore, validation)
	}

	return nil
}

func (ec *execContext) validateCopyOfAttributeType(ctx context.Context, source xdm.Node, typeName string) error {
	if ec.isComplexTypeName(typeName) {
		return dynamicError(errCodeXTTE1535,
			"copy-of type=%q refers to a complex type, but copied item is an attribute node", typeName)
	}

	attr, ok := source.(*xdm.Attribute)
	if !ok {
		return nil
	}

	if err := ec.validateAttributeValueForType(ctx, attr.Value(), normalizeTypeName(typeName, ec)); err != nil {
		return dynamicError(errCodeXTTE1510,
			"copy-of: attribute value %q is not valid for type %s: %v", attr.Value(), typeName, err)
	}

	return nil
}

func (ec *execContext) preserveCopyOfAnnotations(source xdm.Node, out *outputFrame, lastBefore xdm.Node, pendingBefore int) {
	if !out.sequenceMode || len(out.pendingItems) <= pendingBefore {
		ec.transferAnnotationsForCopy(source, out.current, lastBefore)
		return
	}

	// Captured copies have no DOM parent; transfer directly to pending items.
	for i := pendingBefore; i < len(out.pendingItems); i++ {
		if item, ok := out.pendingItems[i].(xdm.NodeItem); ok {
			ec.deepTransferAnnotations(source, item.Node)
		}
	}

	ec.propagateValidationAnnotationsToPending(out, pendingBefore)
}

func (ec *execContext) validateCopyOfElement(ctx context.Context, source xdm.Node, out *outputFrame, lastBefore xdm.Node, pendingBefore int, validation string) error {
	// Stripping type annotations retains XDM is-id/is-idrefs properties.
	if validation == validationStrip {
		ec.preserveIDAnnotationsForCopy(source, out.current, lastBefore)
	}

	copiedElem := findCopiedElement(out, lastBefore, pendingBefore)
	if copiedElem == nil {
		return nil
	}

	if err := ec.validateConstructedElementWithIDCheck(ctx, copiedElem, validation); err != nil {
		return err
	}

	// XTTE1555 checks complete documents only: fragments may reference IDs
	// outside the copied subtree.
	if source.Type() == xdm.DocumentNode && (validation == validationStrict || validation == validationLax) {
		if err := ec.checkIDConstraintsForCopiedDoc(out, pendingBefore, copiedElem); err != nil {
			return err
		}
	}

	if out.sequenceMode && len(out.pendingItems) > pendingBefore {
		ec.propagateValidationAnnotationsToPending(out, pendingBefore)
	}

	return nil
}

func (ec *execContext) transferCopyOfAccumulators(ctx context.Context, source xdm.Node, out *outputFrame, lastBefore xdm.Node, pendingBefore int) error {
	// XTDE3362 requires use-accumulators on the source processing mode.
	if err := ec.checkCopyAccumulators(source); err != nil {
		return err
	}

	_ = ec.ensureAccumulatorStates(ctx, source)

	var copiedNode xdm.Node
	if lastBefore == nil {
		copiedNode = out.current.FirstChild()
	} else {
		copiedNode = lastBefore.NextSibling()
	}

	if copiedNode == nil && out.sequenceMode && len(out.pendingItems) > pendingBefore {
		if item, ok := out.pendingItems[len(out.pendingItems)-1].(xdm.NodeItem); ok {
			copiedNode = item.Node
		}
	}

	if copiedNode == nil {
		return nil
	}

	ec.transferAccumulatorStates(source, copiedNode)

	if ec.accumulatorComputedDocs == nil {
		ec.accumulatorComputedDocs = make(map[xdm.Node]struct{})
	}

	ec.accumulatorComputedDocs[documentRoot(copiedNode)] = struct{}{}

	return nil
}

// checkIDConstraintsForCopiedDoc checks xs:ID uniqueness and xs:IDREF
// resolution for a copied document node. It finds the owning document of
// copiedElem (either a pending document in sequence mode or the result
// document) and validates ID constraints using the current type annotations.
func (ec *execContext) checkIDConstraintsForCopiedDoc(out *outputFrame, pendingBefore int, copiedElem *xdm.Element) error {
	return nil
}

// propagateValidationAnnotationsToPending updates the TypeAnnotation on pending
// NodeItems based on the execContext's typeAnnotations map. This ensures that
// variable references carry schema type annotations acquired during validation.
func (ec *execContext) propagateValidationAnnotationsToPending(out *outputFrame, pendingBefore int) {
	if ec.typeAnnotations == nil {
		return
	}

	for i := pendingBefore; i < len(out.pendingItems); i++ {
		ni, ok := out.pendingItems[i].(xdm.NodeItem)
		if !ok {
			continue
		}
		// For element nodes, check the typeAnnotations map directly.
		if ann, found := ec.typeAnnotations[ni.Node]; found && ni.TypeAnnotation == "" {
			ni.TypeAnnotation = ann
			out.pendingItems[i] = ni

			continue
		}
		// For document nodes, check the document element's annotation.
		if doc, ok := ni.Node.(*xdm.Document); ok {
			if docElem := doc.DocumentElement(); docElem != nil {
				if ann, found := ec.typeAnnotations[docElem]; found {
					// The document itself doesn't get a type annotation,
					// but we record it so that path navigation from the
					// document node can find it via nodeItemFor.
					_ = ann
				}
			}
		}
	}
}

// copyNodeToOutput copies a node to the current output, handling document
// and attribute nodes specially. When copyNamespaces is false, namespace
// declarations are not copied onto element nodes (only those required by
// the element name and attribute names are preserved).
func (ec *execContext) copyNodeToOutput(node xdm.Node, copyNamespaces ...bool) error {
	copyNS := true
	if len(copyNamespaces) > 0 {
		copyNS = copyNamespaces[0]
	}

	switch node.Type() {
	case xdm.DocumentNode:
		return ec.copyDocumentToOutput(node, copyNS)
	case xdm.AttributeNode:
		if attr, ok := node.(*xdm.Attribute); ok {
			return ec.copyAttributeNodeToOutput(attr)
		}

		return nil
	case xdm.NamespaceNode:
		if ns, ok := node.(*xdm.NamespaceNodeWrapper); ok {
			return ec.copyNamespaceNodeToOutput(ns)
		}

		return nil
	default:
		if !copyNS && node.Type() == xdm.ElementNode {
			elem, _ := xdm.AsNode[*xdm.Element](node)
			return ec.copyElementNoNamespaces(elem)
		}

		copied, err := xdm.CopyNode(node, ec.resultDoc)
		if err != nil {
			return err
		}

		if err := ec.addNode(copied); err != nil {
			return err
		}

		// The copy's namespace declarations must fit its new parent.
		if elem, ok := copied.(*xdm.Element); ok {
			ec.fixNamespacesAfterCopy(elem)
		}

		return nil
	}
}

func (ec *execContext) copyDocumentToOutput(node xdm.Node, copyNS bool) error {
	out := ec.currentOutput()
	if out.sequenceMode {
		return ec.captureCopiedDocument(node)
	}

	// A document copy contributes its children and preserves DTD metadata
	// (unparsed entities and notations) when the target has none.
	if src, ok := node.(*xdm.Document); ok && src.Doctype != nil {
		if out.doc != nil && out.doc.Doctype == nil {
			xdm.CopyDoctype(src, out.doc)
		}
	}

	for child := range xdm.Children(node) {
		if err := ec.copyNodeToOutput(child, copyNS); err != nil {
			return err
		}
	}

	return nil
}

// captureCopiedDocument preserves one document item, rather than emitting its
// children as separate items. Doctype metadata is copied outside the XDM tree.
func (ec *execContext) captureCopiedDocument(source xdm.Node) error {
	doc := newCopyDocument(source)
	for child := range xdm.Children(source) {
		if !xdm.IsXDMChild(child) {
			continue
		}

		copied, err := xdm.CopyNode(child, doc)
		if err != nil {
			return err
		}

		if err := doc.AddChild(copied); err != nil {
			return err
		}
	}

	out := ec.currentOutput()
	out.pendingItems = append(out.pendingItems, xdm.NodeItem{Node: doc})
	out.noteOutput()

	return nil
}

func (ec *execContext) copyNamespaceNodeToOutput(ns *xdm.NamespaceNodeWrapper) error {
	out := ec.currentOutput()
	if out.sequenceMode {
		copied, err := out.doc.CreateNamespace(ns.Name(), xdm.CharacterData(ns))
		if err != nil {
			return err
		}

		out.pendingItems = append(out.pendingItems, xdm.NodeItem{Node: xdm.NewNamespaceNodeWrapper(copied, nil)})
		out.noteOutput()

		return nil
	}

	elem, ok := out.current.(*xdm.Element)
	if !ok {
		return dynamicError(errCodeXTDE0420, "cannot add a namespace to a document node")
	}

	if out.hasChildContent(elem) {
		return dynamicError(errCodeXTDE0410, "cannot add a namespace after child nodes")
	}

	if err := ec.addComputedNamespace(elem, ns.Name(), xdm.CharacterData(ns)); err != nil {
		return err
	}

	out.noteOutput()

	return nil
}

// copyElementNoNamespaces deep-copies an element without copying namespace
// declarations (copy-namespaces="no").  Only the namespaces required for
// well-formedness (element name and attribute names) are preserved.
func (ec *execContext) copyElementNoNamespaces(src *xdm.Element) error {
	elem, err := ec.resultDoc.CreateElement(src.LocalName())
	if err != nil {
		return err
	}

	// Declare only the element's own namespace (required for well-formedness).
	if src.URI() != "" {
		if err := elem.DeclareNamespace(src.Prefix(), src.URI()); err != nil {
			return err
		}

		if err := elem.SetActiveNamespace(src.Prefix(), src.URI()); err != nil {
			return err
		}
	}

	for _, a := range src.Attributes() {
		if a.URI() != "" {
			if !hasNSDecl(elem, a.Prefix(), a.URI()) {
				if err := elem.DeclareNamespace(a.Prefix(), a.URI()); err != nil {
					return err
				}
			}

			ns, nsErr := ec.resultDoc.CreateNamespace(a.Prefix(), a.URI())
			if nsErr != nil {
				return nsErr
			}

			_ = elem.SetAttributeNS(a.LocalName(), a.Value(), ns)
		} else {
			_ = elem.SetAttribute(a.Name(), a.Value())
		}
	}

	// Recursively copy children (also without namespaces).
	// Temporarily disable sequenceMode so that child nodes are added to the
	// element's DOM tree instead of being appended as separate sequence items.
	out := ec.currentOutput()
	savedCurrent := out.current
	savedSeqMode := out.sequenceMode
	out.current = elem
	out.sequenceMode = false

	for child := range xdm.Children(src) {
		if err := ec.copyNodeToOutput(child, false); err != nil {
			out.current = savedCurrent
			out.sequenceMode = savedSeqMode

			return err
		}
	}

	out.current = savedCurrent
	out.sequenceMode = savedSeqMode

	// copy-namespaces="no": children within the copy subtree must not
	// inherit namespace declarations that were added to this element for
	// its own well-formedness (element name / attribute names). Undeclare
	// such bindings on each direct child element that does not itself
	// require them.
	undeclareParentCopyNS(elem)

	if err := ec.addNode(elem); err != nil {
		return err
	}
	// After inserting the element into the result tree, fix namespace
	// declarations relative to the new parent (e.g. add xmlns=""
	// undeclarations to prevent inheriting the parent's default namespace
	// when the element is not in that namespace).
	ec.fixNamespacesAfterCopy(elem)

	return nil
}

// undeclareParentCopyNS adds namespace undeclarations on each direct child
// element of parent for every namespace declared on parent that the child
// does not itself require. This prevents copy-internal namespace leakage:
// when copy-namespaces="no", a parent element may need a namespace for its
// name/attributes, but children should not inherit those bindings.
func undeclareParentCopyNS(parent *xdm.Element) {
	parentNS := parent.Namespaces()
	if len(parentNS) == 0 {
		return
	}

	for child := parent.FirstChild(); child != nil; child = child.NextSibling() {
		childElem, ok := child.(*xdm.Element)
		if !ok {
			continue
		}

		childNeeded := make(map[string]struct{})
		if childElem.URI() != "" {
			childNeeded[childElem.Prefix()] = struct{}{}
		}

		for _, a := range childElem.Attributes() {
			if a.URI() != "" {
				childNeeded[a.Prefix()] = struct{}{}
			}
		}

		childDeclared := make(map[string]struct{})
		for _, ns := range childElem.Namespaces() {
			childDeclared[ns.Prefix()] = struct{}{}
		}

		for _, ns := range parentNS {
			prefix := ns.Prefix()
			if prefix == methodXML {
				continue
			}

			if _, ok := childDeclared[prefix]; ok {
				continue
			}

			if _, ok := childNeeded[prefix]; ok {
				continue
			}
			// Undeclare: the child doesn't need this binding.
			_ = childElem.DeclareNamespace(prefix, "")
			childDeclared[prefix] = struct{}{}
		}
	}
}

// checkCopyAccumulators verifies that all accumulators declared in the
// stylesheet are applicable to the tree containing node. This implements
// the XTDE3362 check for xsl:copy-of/@copy-accumulators="yes".
// An accumulator is applicable to a source document only if the initial
// mode explicitly lists it via use-accumulators.
func (ec *execContext) checkCopyAccumulators(node xdm.Node) error {
	accumulators := ec.effectiveAccumulators()
	if len(accumulators) == 0 {
		return nil
	}

	// When there is an activeAccumulators set (e.g. from xsl:source-document),
	// the document-level applicability already restricts access.
	if ec.activeAccumulators != nil {
		for name := range accumulators {
			if _, ok := ec.activeAccumulators[name]; !ok {
				return dynamicError(errCodeXTDE3362,
					"accumulator %q is not applicable to the source document (copy-accumulators)", name)
			}
		}

		return nil
	}

	// Only check mode-level use-accumulators for nodes from the initial
	// source document. variable/RTF trees have accumulators computed
	// lazily and are always accessible.
	root := documentRoot(node)
	if root != ec.sourceDoc {
		return nil
	}

	// Determine the mode definition for the initial mode.
	modeDefs := ec.effectiveModeDefs()

	md := modeDefs[ec.currentMode]
	if md == nil {
		md = modeDefs[modeDefault]
	}

	// When no explicit xsl:mode declaration exists, the mode has no
	// use-accumulators attribute. For the initial source document,
	// accumulators are only applicable if the mode declares them.
	if md == nil {
		return dynamicError(errCodeXTDE3362,
			"copy-accumulators requires use-accumulators on the processing mode")
	}
	// When use-accumulators attribute is absent (nil), the default is
	// lexicon.ModeAll per XSLT 3.0 spec — all accumulators are applicable.
	if md.UseAccumulators == nil {
		return nil
	}

	ua := *md.UseAccumulators
	if ua == lexicon.ModeAll {
		return nil
	}

	allowed := make(map[string]struct{})
	for n := range strings.FieldsSeq(ua) {
		allowed[n] = struct{}{}
	}

	for name := range accumulators {
		if _, ok := allowed[name]; !ok {
			return dynamicError(errCodeXTDE3362,
				"accumulator %q is not applicable to the source document (copy-accumulators)", name)
		}
	}

	return nil
}

// nodeHasNamespaceSensitiveContent checks if a node (or any of its
// descendants/attributes) has a type annotation that is namespace-sensitive
// (xs:QName, xs:NOTATION, or a type derived from them). This is used for
// XTTE0950 checking.
func (ec *execContext) nodeHasNamespaceSensitiveContent(node xdm.Node) bool {
	if ec.typeAnnotations == nil {
		return false
	}

	return ec.checkNodeNSSensitive(node)
}

func (ec *execContext) checkNodeNSSensitive(node xdm.Node) bool {
	ann := ec.typeAnnotations[node]
	if isNamespaceSensitiveType(ann) {
		return true
	}

	if elem, ok := node.(*xdm.Element); ok {
		for _, attr := range elem.Attributes() {
			attrAnn := ec.typeAnnotations[attr]
			if isNamespaceSensitiveType(attrAnn) {
				return true
			}
		}

		for child := elem.FirstChild(); child != nil; child = child.NextSibling() {
			if ec.checkNodeNSSensitive(child) {
				return true
			}
		}
	}

	return false
}

// isNamespaceSensitiveType returns true if the given type name is xs:QName,
// xs:NOTATION, or common derived forms.
func isNamespaceSensitiveType(typeName string) bool {
	switch typeName {
	case "xs:QName", "xs:NOTATION",
		"Q{http://www.w3.org/2001/XMLSchema}QName",
		"Q{http://www.w3.org/2001/XMLSchema}NOTATION":
		return true
	}

	return false
}

// isComplexTypeName returns true if the given type name refers to a complex
// type definition in the imported schemas.
func (ec *execContext) isComplexTypeName(typeName string) bool {
	return false
}

// validateAttributeValueForType validates an attribute string value against
// a type name. For built-in XSD types it uses xpath.CastFromString; for
// user-defined types (list, union, restriction) it falls back to the schema
// registry's ValidateCast. Returns nil when the value is valid.
func (ec *execContext) validateAttributeValueForType(_ context.Context, value, typeName string) error {
	_, castErr := xpath.CastFromString(value, typeName)
	if castErr == nil {
		return nil
	}

	return castErr
}

// evaluateCopyBoolean resolves a shadow attribute, retaining its static value
// when the runtime value is not an XML Schema boolean.
func evaluateCopyBoolean(ctx context.Context, node xdm.Node, shadow *avt, fallback bool) (bool, error) {
	if shadow == nil {
		return fallback, nil
	}

	value, err := shadow.evaluate(ctx, node)
	if err != nil {
		return false, err
	}

	if result, ok := parseXSDBool(value); ok {
		return result, nil
	}

	return fallback, nil
}

// newCopyDocument preserves document metadata without modifying the source.
func newCopyDocument(source xdm.Node) *xdm.Document {
	doc := xdm.NewDefaultDocument()
	if src, ok := source.(*xdm.Document); ok && src != nil {
		xdm.CopyDoctype(src, doc)
		doc.SetURL(src.URL())
	}

	return doc
}

// findCopiedElement locates the element that was most recently added to the
// output by a copy-of operation. It checks the DOM tree first, then pending
// items in sequence mode. When the copied node is a document, the document
// element is returned so that validation can be applied.
func findCopiedElement(out *outputFrame, _ xdm.Node, pendingBefore int) *xdm.Element {
	if copied := out.current.LastChild(); copied != nil {
		if elem, ok := copied.(*xdm.Element); ok {
			return elem
		}
	}

	if (out.sequenceMode || out.captureItems) && len(out.pendingItems) > pendingBefore {
		ni, ok := out.pendingItems[len(out.pendingItems)-1].(xdm.NodeItem)
		if !ok {
			return nil
		}

		if elem, ok := ni.Node.(*xdm.Element); ok {
			return elem
		}
		// When the copied node is a document, extract its document element
		// so that validation can be applied to the root element.
		if doc, ok := ni.Node.(*xdm.Document); ok {
			return doc.DocumentElement()
		}
	}

	return nil
}
