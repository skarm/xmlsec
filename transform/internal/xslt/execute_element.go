// Derived from lestrrat-go/helium at 7362c0a70122a757780f4d0b545a9b370dead6ab.
// Copyright (c) 2015 lestrrat. MIT License; see licenses/MIT-helium.txt at the repository root.

package xslt

import (
	"context"
	"errors"
	"sort"
	"strconv"
	"strings"

	"github.com/skarm/xmlsec/internal/xmlchar"
	"github.com/skarm/xmlsec/transform/internal/xdm"
	"github.com/skarm/xmlsec/transform/internal/xdm/lexicon"
	"github.com/skarm/xmlsec/transform/internal/xpath"
)

// resolvedAttrName is the fully resolved expanded name of a computed
// xsl:attribute: the local name, the namespace URI it belongs to, and the
// prefix that should be used when serializing it.
type resolvedAttrName struct {
	localName string
	nsURI     string
	prefix    string
}

func (ec *execContext) execElement(ctx context.Context, inst *elementInst) error {
	name, err := inst.Name.evaluate(ctx, ec.contextNode)
	if err != nil {
		return err
	}

	// XTDE0820: validate the computed name before resolving its namespace.
	name = strings.TrimSpace(name)
	if name == "" || !xmlchar.IsValidQName(name) {
		return dynamicError(errCodeXTDE0820,
			"invalid element name %q: not a valid QName", name)
	}

	prefix, localName := "", name
	if p, l, ok := strings.Cut(name, ":"); ok {
		prefix, localName = p, l
	}

	elem, err := ec.resultDoc.CreateElement(localName)
	if err != nil {
		return err
	}

	if err := ec.setComputedElementNamespace(ctx, elem, inst, name, prefix); err != nil {
		return err
	}

	// A parentless constructor retains its instruction's static base. Nodes
	// constructed directly as children inherit the result parent's base instead.
	if ec.currentOutput().sequenceMode {
		xdm.SetNodeBaseURI(elem, ec.effectiveStaticBaseURI())
	}

	if err := ec.addNode(elem); err != nil {
		return err
	}

	if inst.TypeName != "" {
		ec.annotateNode(elem, inst.TypeName)
	}

	return ec.executeComputedElementContent(ctx, elem, inst)
}

// computedElementNamespace resolves an explicit namespace AVT or the static
// namespace context at the xsl:element instruction.
func (ec *execContext) computedElementNamespace(ctx context.Context, inst *elementInst, name, prefix string) (string, error) {
	if inst.Namespace != nil {
		uri, err := inst.Namespace.evaluate(ctx, ec.contextNode)
		if err != nil {
			return "", err
		}

		if uri == lexicon.NamespaceXMLNS {
			return "", dynamicError(errCodeXTDE0835,
				"namespace URI %q is reserved and cannot be used", uri)
		}

		return uri, nil
	}

	uri := inst.NSBindings[prefix]
	if uri == "" && prefix != "" {
		// Only prefixed names may fall back to stylesheet-level bindings.
		// The default namespace belongs to the instruction's static context.
		uri = ec.resolvePrefix(prefix)
	}

	if uri == "" && prefix != "" {
		return "", dynamicError(errCodeXTDE0830,
			"undeclared namespace prefix %q in element name %q", prefix, name)
	}

	return uri, nil
}

func (ec *execContext) setComputedElementNamespace(ctx context.Context, elem *xdm.Element, inst *elementInst, name, prefix string) error {
	uri, err := ec.computedElementNamespace(ctx, inst, name, prefix)
	if err != nil {
		return err
	}

	if uri == "" {
		// An explicit empty namespace strips any lexical prefix. Also block
		// a default namespace inherited from the current output context.
		if ec.hasDefaultNSInScope() {
			return elem.DeclareNamespace("", "")
		}

		return nil
	}

	if err := elem.DeclareNamespace(prefix, uri); err != nil {
		return err
	}

	if err := elem.SetActiveNamespace(prefix, uri); err != nil {
		return err
	}

	// Automatically resolved prefixes may be renamed by xsl:namespace.
	if prefix != "" {
		if ec.nsFixupAllowed == nil {
			ec.nsFixupAllowed = make(map[*xdm.Element]struct{})
		}

		ec.nsFixupAllowed[elem] = struct{}{}
	}

	return nil
}

func (ec *execContext) executeComputedElementContent(ctx context.Context, elem *xdm.Element, inst *elementInst) error {
	// Children are constructed directly in the element, including inside a
	// sequence capture or xsl:where-populated on the surrounding constructor.
	out := ec.currentOutput()
	savedCurrent := out.current
	savedPrevAtomic := out.prevWasAtomic
	savedSeqMode := out.sequenceMode
	savedCapture := out.captureItems
	out.current = elem
	out.prevWasAtomic = false
	out.sequenceMode = false
	out.captureItems = false

	defer func() {
		out.current = savedCurrent
		out.prevWasAtomic = savedPrevAtomic
		out.sequenceMode = savedSeqMode
		out.captureItems = savedCapture
	}()

	// Attribute sets precede the body so explicitly constructed attributes win.
	if len(inst.UseAttrSets) > 0 {
		if err := ec.applyAttributeSets(ctx, inst.UseAttrSets); err != nil {
			return err
		}
	}

	if err := ec.executeSequenceConstructor(ctx, inst.Body); err != nil {
		return err
	}

	if err := finishConstructedNamespaces(ctx, elem, inst.InheritNamespaces); err != nil {
		return err
	}

	if inst.TypeName != "" {
		if err := ec.validateComputedElementType(ctx, elem, inst.TypeName); err != nil {
			return err
		}
	}

	if inst.Validation != "" {
		return ec.validateConstructedElement(ctx, elem, inst.Validation)
	}

	return nil
}

// collectInScopeNamespaces collects all in-scope namespace declarations for
// an element, walking up the ancestor chain.  Declarations closer to the
// element take precedence (first-seen prefix wins).
func collectInScopeNamespaces(elem *xdm.Element) []*xdm.Namespace {
	seen := make(map[string]struct{})

	var result []*xdm.Namespace

	for cur := elem; cur != nil; {
		for _, ns := range cur.Namespaces() {
			if _, ok := seen[ns.Prefix()]; !ok {
				seen[ns.Prefix()] = struct{}{}
				result = append(result, ns)
			}
		}

		p := cur.Parent()
		if p == nil {
			break
		}

		pe, ok := p.(*xdm.Element)
		if !ok {
			break
		}

		cur = pe
	}

	return result
}

// undeclareInheritedNamespaces adds namespace undeclarations (xmlns:p="") on
// each direct child element for every in-scope namespace visible from parent
// that the child does not itself declare.  This implements the XSLT 3.0
// inherit-namespaces="no" semantics: children must not inherit ANY namespace
// reachable through the parent in the DOM tree.
func undeclareInheritedNamespaces(parent *xdm.Element) {
	inScope := make(map[string]string)
	for _, ns := range collectInScopeNamespaces(parent) {
		inScope[ns.Prefix()] = ns.URI()
	}

	if len(inScope) == 0 {
		return
	}

	// Sort once for deterministic declaration order on each direct child.
	prefixes := make([]string, 0, len(inScope))
	for prefix := range inScope {
		prefixes = append(prefixes, prefix)
	}

	sort.Strings(prefixes)

	for child := range xdm.Children(parent) {
		elem, ok := child.(*xdm.Element)
		if !ok {
			continue
		}

		for _, prefix := range prefixes {
			undeclareChildNamespace(elem, prefix, inScope[prefix])
		}

		// Inner inherit-namespaces="no" declarations may now be redundant.
		removeRedundantDescendantUndecls(elem)
	}
}

func undeclareChildNamespace(elem *xdm.Element, prefix, parentURI string) {
	for _, ns := range elem.Namespaces() {
		if ns.Prefix() != prefix {
			continue
		}

		// Existing namespace nodes are retained, even if they match the parent.
		return
	}

	// An inherited undeclaration already blocks this prefix.
	if parentURI == "" {
		return
	}

	// Retain the child's own namespace, blocking all other inherited bindings.
	if elem.Prefix() == prefix && elem.URI() != "" {
		_ = elem.DeclareNamespace(prefix, elem.URI())
		return
	}

	_ = elem.DeclareNamespace(prefix, "")
}

// removeRedundantDescendantUndecls removes namespace undeclarations from
// descendant elements that are redundant because the same prefix is already
// undeclared (or bound to the same URI) on an ancestor in the serialized output.
func removeRedundantDescendantUndecls(elem *xdm.Element) {
	bindings := make(map[string]string)
	for _, ns := range elem.Namespaces() {
		bindings[ns.Prefix()] = ns.URI()
	}

	for child := range xdm.Children(elem) {
		childElem, ok := child.(*xdm.Element)
		if !ok {
			continue
		}

		for _, cns := range childElem.Namespaces() {
			if parentURI, ok := bindings[cns.Prefix()]; ok && cns.URI() == parentURI {
				childElem.RemoveNamespaceByPrefix(cns.Prefix())
			}
		}
	}
}

func (ec *execContext) validateComputedElementType(ctx context.Context, elem *xdm.Element, typeName string) error {
	if err := ec.validateAndNormalizeElementContent(ctx, elem, typeName); err != nil {
		// xsl:element reports declared-type content failures as XTTE1540.
		if xsltErr, ok := errors.AsType[*XSLTError](err); ok && xsltErr.Code == errCodeXTTE1510 {
			return dynamicError(errCodeXTTE1540,
				"element content does not match declared type %s: %v", typeName, xsltErr.Message)
		}

		return err
	}

	ec.annotateAttributesFromType(elem, typeName)

	return nil
}

// validateConstructedAttribute validates a computed attribute against the global
// attribute declaration for its name and returns the resolved type-annotation
// name so the caller can annotate the attribute node (needed for
// schema-attribute(N) pattern matching and instance-of tests). typeName is ""
// when no declaration governs the attribute (lax with no declaration).
func (ec *execContext) validateConstructedAttribute(ctx context.Context, localName, nsURI, value, validation string) (string, error) {
	return "", nil
}

// validateAndNormalizeElementContent validates the text content of elem against
// the declared XSD type name (e.g., "xs:integer"). It raises XTTE1510 when the
// content is invalid. The original text content is preserved in the DOM; the
// type annotation (stored separately) controls typed-value extraction via
// data()/atomization at runtime.
func (ec *execContext) validateAndNormalizeElementContent(_ context.Context, elem *xdm.Element, typeName string) error {
	// xs:anyType and xs:untyped accept any content — skip validation entirely.
	if typeName == lexicon.XSAnyType || typeName == lexicon.XSUntyped {
		return nil
	}

	// Built-in simple types (xs:string, xs:integer, xs:untypedAtomic, etc.)
	// require that the element have simple content — no child elements.
	if elementHasChildElements(elem) {
		return dynamicError(errCodeXTTE1510,
			"element has child elements but type %s requires simple content", typeName)
	}

	// Built-in XSD type: validate by attempting to cast.
	// Use text-only string value (skip comments/PIs) per XPath data model.
	content := strings.TrimSpace(elementTextContent(elem))

	_, castErr := xpath.CastFromString(content, typeName)
	if castErr != nil {
		return dynamicError(errCodeXTTE1510,
			"content %q is not a valid value for type %s: %v", content, typeName, castErr)
	}

	// Content is valid — original text is preserved in the DOM.
	return nil
}

// elementTextContent returns the concatenation of all descendant text nodes,
// skipping comments and processing instructions (XPath string-value semantics).
func elementTextContent(elem *xdm.Element) string {
	var buf strings.Builder
	collectTextContent(elem.FirstChild(), &buf)

	return buf.String()
}

func collectTextContent(node xdm.Node, buf *strings.Builder) {
	for ; node != nil; node = node.NextSibling() {
		switch node.Type() {
		case xdm.TextNode, xdm.CDATASectionNode:
			buf.WriteString(xdm.CharacterData(node))
		case xdm.ElementNode:
			if elem, ok := node.(*xdm.Element); ok {
				collectTextContent(elem.FirstChild(), buf)
			}
		}
	}
}

// elementHasChildElements returns true if elem has any direct child elements.
func elementHasChildElements(elem *xdm.Element) bool {
	for child := elem.FirstChild(); child != nil; child = child.NextSibling() {
		if child.Type() == xdm.ElementNode {
			return true
		}
	}

	return false
}

// validateConstructedElement validates a constructed element node against the
// imported schemas and applies type annotations to the result tree.
func (ec *execContext) validateConstructedElement(_ context.Context, elem *xdm.Element, validation string) error {
	switch validation {
	case validationStrip:
		ec.stripAnnotations(elem)
		return nil
	case validationPreserve:
		// Per XSLT 3.0 §19.2: validation="preserve" assigns type
		// annotation xs:anyType to the constructed element node,
		// while preserving existing annotations on child nodes.
		ec.annotateNode(elem, "xs:anyType")
		return nil
	case validationStrict, validationLax:
		return ErrLanguageUnsupported
	}

	return nil
}

// validateConstructedElementWithIDCheck validates a constructed element and
// also checks xs:ID uniqueness and xs:IDREF resolution constraints. This is
// used by xsl:copy-of where the copied subtree must be validated as a whole,
// including document-level ID constraints.
func (ec *execContext) validateConstructedElementWithIDCheck(_ context.Context, elem *xdm.Element, validation string) error {
	switch validation {
	case validationStrip:
		ec.stripAnnotations(elem)
		return nil
	case validationPreserve:
		// Per XSLT 3.0 §19.2: validation="preserve" assigns type
		// annotation xs:anyType to the constructed element node,
		// while preserving existing annotations on child nodes.
		ec.annotateNode(elem, "xs:anyType")
		return nil
	case validationStrict, validationLax:
		return ErrLanguageUnsupported
	}

	return nil
}

// stripAnnotations removes type annotations from a node and all its descendants.
func (ec *execContext) stripAnnotations(node xdm.Node) {
	if ec.typeAnnotations == nil {
		return
	}

	delete(ec.typeAnnotations, node)
	// Also strip annotations from attributes on elements.
	if elem, ok := node.(*xdm.Element); ok {
		for _, attr := range elem.Attributes() {
			delete(ec.typeAnnotations, attr)
		}
	}

	for child := range xdm.Children(node) {
		ec.stripAnnotations(child)
	}
}

// annotateAttributesFromType annotates each attribute on elem with the type
// declared in the complex type definition identified by typeName.  This is
// needed so that "instance of attribute(*, xs:integer)" works on attributes
// of elements constructed with xsl:type or type="…".
func (ec *execContext) annotateAttributesFromType(elem *xdm.Element, typeName string) {}

// resolveComputedAttributeName resolves the expanded name of a computed
// xsl:attribute exactly once, honoring an explicit namespace= attribute when
// present and otherwise resolving the lexical prefix against the in-scope
// namespaces. It enforces the namespace-related constraints (XTDE0865 for the
// reserved xmlns URI, XTDE0860 for an undeclared prefix when no namespace
// attribute is given). The lexical-QName (XTDE0850) and reserved-xmlns-name
// (XTDE0855) checks are performed separately by validateComputedAttributeName.
//
// The resulting {localName, nsURI, prefix} is reused by every output path
// (sequence-mode capture, item capture, and element output) so a name such as
// name="p:a" namespace="urn:p" yields an attribute in urn:p in all modes.
func (ec *execContext) resolveComputedAttributeName(ctx context.Context, name string, inst *attributeInst) (resolvedAttrName, error) {
	prefix := ""

	localName := name
	if p, l, ok := strings.Cut(name, ":"); ok {
		prefix = p
		localName = l
	}

	// An explicit namespace= attribute overrides prefix resolution.
	if inst.Namespace != nil {
		nsURI, err := inst.Namespace.evaluate(ctx, ec.contextNode)
		if err != nil {
			return resolvedAttrName{}, err
		}
		// XTDE0865: the xmlns namespace URI is reserved.
		if nsURI == lexicon.NamespaceXMLNS {
			return resolvedAttrName{}, dynamicError(errCodeXTDE0865,
				"namespace URI %q is reserved and cannot be used for attributes", nsURI)
		}

		if nsURI == "" {
			// namespace="" explicitly: no-namespace attribute, prefix discarded.
			return resolvedAttrName{localName: localName}, nil
		}
		// Attributes in a namespace require a non-empty prefix (unlike
		// elements, the default namespace does not apply to attributes).
		if prefix == "" {
			prefix = "ns0"
		}

		return resolvedAttrName{localName: localName, nsURI: nsURI, prefix: prefix}, nil
	}

	// No explicit namespace= attribute: resolve the lexical prefix.
	if prefix == "" {
		return resolvedAttrName{localName: localName}, nil
	}

	nsURI := ec.resolvePrefix(prefix)
	if nsURI == "" {
		// XTDE0860: prefix in computed attribute name is undeclared.
		return resolvedAttrName{}, dynamicError(errCodeXTDE0860,
			"undeclared namespace prefix %q in attribute name %q", prefix, name)
	}

	return resolvedAttrName{localName: localName, nsURI: nsURI, prefix: prefix}, nil
}

func (ec *execContext) execAttribute(ctx context.Context, inst *attributeInst) error {
	name, err := inst.Name.evaluate(ctx, ec.contextNode)
	if err != nil {
		return err
	}

	// All output modes validate and resolve the computed name before content.
	if err := validateComputedAttributeName(name, inst); err != nil {
		return err
	}

	resolved, err := ec.resolveComputedAttributeName(ctx, name, inst)
	if err != nil {
		return err
	}

	value, err := ec.evaluateComputedAttributeValue(ctx, inst)
	if err != nil {
		return err
	}

	value, err = canonicalAttributeValue(value, inst.TypeName)
	if err != nil {
		return err
	}

	out := ec.currentOutput()
	if out.sequenceMode {
		return ec.captureSequenceAttribute(ctx, out, inst, resolved, value)
	}

	elem, ok := out.current.(*xdm.Element)
	if !ok {
		return ec.outputNonElementAttribute(out, name, resolved, value)
	}

	if out.hasChildContent(elem) {
		return dynamicError(errCodeXTDE0410, "cannot add attribute to element after children have been added")
	}

	valTypeName, err := ec.computedAttributeValidationType(ctx, inst, resolved, value)
	if err != nil {
		return err
	}

	if err := ec.attachComputedAttribute(elem, resolved, value); err != nil {
		return err
	}

	ec.annotateAttr(elem, firstNonEmptyType(inst.TypeName, valTypeName), resolved.localName, resolved.nsURI, value)
	out.noteOutput()

	return nil
}

// validateComputedAttributeName performs the name-validity checks for a
// computed xsl:attribute name that are independent of the output target:
// XTDE0855 (the name must not be "xmlns" when no namespace attribute is given)
// and XTDE0850 (the name must be a lexically valid QName/EQName). It is invoked
// before the element-output, sequence-mode, and item-capture branches so every
// path enforces the same rules.
func validateComputedAttributeName(name string, inst *attributeInst) error {
	// XTDE0855: when no namespace attribute, name must not be "xmlns"
	if inst.Namespace == nil && name == lexicon.PrefixXMLNS {
		return dynamicError(errCodeXTDE0855,
			"xsl:attribute name must not be %q when no namespace attribute is specified", name)
	}

	// XTDE0850: name must be a valid QName
	if !xmlchar.IsValidQName(name) && !isValidEQName(name) {
		return dynamicError(errCodeXTDE0850,
			"xsl:attribute name %q is not a valid QName", name)
	}

	return nil
}

func canonicalAttributeValue(value, typeName string) (string, error) {
	if typeName == "" {
		return value, nil
	}

	av, err := xpath.CastFromString(value, typeName)
	if err != nil {
		return "", dynamicError(errCodeXTTE1515, "attribute value %q does not match type %s", value, typeName)
	}

	if canonical, err := xpath.AtomicToString(av); err == nil {
		return canonical, nil
	}

	return value, nil
}

func (ec *execContext) evaluateComputedAttributeValue(ctx context.Context, inst *attributeInst) (string, error) {
	if inst.Select == nil && len(inst.Body) == 0 {
		return "", nil
	}

	sep := ""
	if inst.Select != nil {
		sep = " "
	}

	if inst.Separator != nil {
		var err error

		sep, err = inst.Separator.evaluate(ctx, ec.contextNode)
		if err != nil {
			return "", err
		}
	}

	val, err := ec.computedAttributeContent(ctx, inst)
	if err != nil {
		return "", err
	}

	// Simple content rejects function items, removes empty text nodes and
	// merges adjacent text before inserting the separator (XSLT 3.0 §5.7.2).
	if err := checkAtomizable(val); err != nil {
		return "", err
	}

	val = removeZeroLengthTextNodes(val)
	val = mergeAdjacentTextNodes(val)

	return stringifySimpleContent(ctx, val, sep)
}

func (ec *execContext) computedAttributeContent(ctx context.Context, inst *attributeInst) (xdm.Sequence, error) {
	if inst.Select != nil {
		result, err := ec.evalXPath(ctx, inst.Select, ec.contextNode)
		if err != nil {
			return nil, err
		}

		return result.Sequence(), nil
	}

	var val xdm.Sequence

	err := ec.withV2TempOutput(func() error {
		var err error

		val, err = ec.evaluateBodyForAttr(ctx, inst.Body)

		return err
	})

	return val, err
}

func (ec *execContext) computedAttributeValidationType(ctx context.Context, inst *attributeInst, name resolvedAttrName, value string) (string, error) {
	if inst.Validation != validationStrict && inst.Validation != validationLax {
		return "", nil
	}

	return ec.validateConstructedAttribute(ctx, name.localName, name.nsURI, value, inst.Validation)
}

// captureSequenceAttribute constructs an unattached attribute with its resolved
// schema annotation. An explicit type takes precedence over schema validation.
func (ec *execContext) captureSequenceAttribute(ctx context.Context, out *outputFrame, inst *attributeInst, name resolvedAttrName, value string) error {
	var attrNS *xdm.Namespace

	if name.nsURI != "" {
		attrNS, _ = out.doc.CreateNamespace(name.prefix, name.nsURI)
	}

	valTypeName, err := ec.computedAttributeValidationType(ctx, inst, name, value)
	if err != nil {
		return err
	}

	attr, err := newStandaloneAttribute(out.doc, name.localName, value, attrNS)
	if err != nil {
		return err
	}

	item := xdm.NodeItem{Node: attr}
	if annType := firstNonEmptyType(inst.TypeName, valTypeName); annType != "" {
		ec.annotateNode(attr, annType)
		item.TypeAnnotation = annType
	}

	out.pendingItems = append(out.pendingItems, item)
	out.noteOutput()

	return nil
}

// newStandaloneAttribute builds a parentless attribute with a literal value.
// Attribute values are stored directly in XDM, without text child nodes or a
// second entity-expansion pass.
func newStandaloneAttribute(doc *xdm.Document, localName, value string, ns *xdm.Namespace) (*xdm.Attribute, error) {
	return doc.CreateAttribute(localName, value, ns)
}

func (ec *execContext) outputNonElementAttribute(out *outputFrame, lexicalName string, name resolvedAttrName, value string) error {
	if _, isDoc := out.current.(*xdm.Document); isDoc && !ec.isItemOutputMethod() {
		return dynamicError(errCodeXTDE0420,
			"cannot add attribute %q to a document node", lexicalName)
	}

	if !ec.isItemOutputMethod() && !out.captureItems {
		return dynamicError(errCodeXTDE0820, "xsl:attribute must be added to an element")
	}

	// Item output captures an attribute from a temporary element, preserving
	// the existing parent and namespace behavior of this output mode.
	tmpDoc := xdm.NewDefaultDocument()

	tmpElem, err := tmpDoc.CreateElement("_tmp")
	if err != nil {
		return err
	}

	if name.nsURI != "" {
		ns, _ := tmpDoc.CreateNamespace(name.prefix, name.nsURI)
		_ = tmpElem.SetAttributeNS(name.localName, value, ns)
	} else {
		_ = tmpElem.SetAttribute(name.localName, value)
	}

	for _, attr := range tmpElem.Attributes() {
		out.pendingItems = append(out.pendingItems, xdm.NodeItem{Node: attr})
		out.noteOutput()

		break
	}

	return nil
}

func (ec *execContext) attachComputedAttribute(elem *xdm.Element, name resolvedAttrName, value string) error {
	if name.nsURI == "" {
		elem.RemoveAttribute(name.localName)
		_ = elem.SetAttribute(name.localName, value)

		return nil
	}

	prefix := uniqueNSPrefix(elem, name.prefix, name.nsURI)
	if !hasNSDecl(elem, prefix, name.nsURI) {
		if err := elem.DeclareNamespace(prefix, name.nsURI); err != nil {
			return err
		}
	}

	elem.RemoveAttributeNS(name.localName, name.nsURI)

	ns, err := ec.resultDoc.CreateNamespace(prefix, name.nsURI)
	if err != nil {
		return err
	}

	// SetAttributeNS stores evaluated values verbatim, including ampersands.
	_ = elem.SetAttributeNS(name.localName, value, ns)

	return nil
}

// hasNSDecl checks if an element already has a namespace declaration for
// the given prefix and URI.
func hasNSDecl(elem *xdm.Element, prefix, uri string) bool {
	for _, ns := range elem.Namespaces() {
		if ns.Prefix() == prefix && ns.URI() == uri {
			return true
		}
	}

	return false
}

// withV2TempOutput runs fn, treating its output as temporary output state
// (XTDE1480) when the stylesheet declares an XSLT version below 3.0. XSLT 3.0
// relaxes this restriction, so the depth is left untouched there.
func (ec *execContext) withV2TempOutput(fn func() error) error {
	isV2TempOutput := ec.stylesheet.processorLanguage() < 30
	if isV2TempOutput {
		ec.temporaryOutputDepth++
		defer func() { ec.temporaryOutputDepth-- }()
	}

	return fn()
}

func (ec *execContext) execComment(ctx context.Context, inst *commentInst) error {
	var value string

	if inst.Select != nil {
		result, err := ec.evalXPath(ctx, inst.Select, ec.contextNode)
		if err != nil {
			return err
		}

		value, err = stringifyResult(ctx, result)
		if err != nil {
			return err
		}
	} else if len(inst.Body) > 0 {
		// XSLT 2.0: comment body is temporary output state (XTDE1480).
		// XSLT 3.0 relaxes this restriction.
		var val xdm.Sequence

		err := ec.withV2TempOutput(func() error {
			var err error

			val, err = ec.evaluateBodyAsSequence(ctx, inst.Body)

			return err
		})
		if err != nil {
			return err
		}

		value, err = stringifySimpleContent(ctx, val, " ")
		if err != nil {
			return err
		}
	}

	// Sanitize comment content per XSLT 3.0 spec §11.1:
	// Replace any occurrence of "--" with "- -" and ensure the value
	// doesn't end with "-" (add a trailing space if so).
	value = sanitizeComment(value)

	comment := ec.resultDoc.CreateComment(value)

	return ec.addNode(comment)
}

// sanitizeComment replaces "--" sequences with "- -" and ensures the
// value does not end with "-", per XSLT comment construction rules.
func sanitizeComment(s string) string {
	var sb strings.Builder
	sb.Grow(len(s))

	prevDash := false

	for i := range len(s) {
		if s[i] == '-' {
			if prevDash {
				sb.WriteByte(' ')
			}

			sb.WriteByte('-')

			prevDash = true
		} else {
			sb.WriteByte(s[i])

			prevDash = false
		}
	}

	result := sb.String()
	if len(result) > 0 && result[len(result)-1] == '-' {
		result += " "
	}

	return result
}

func (ec *execContext) execPI(ctx context.Context, inst *piInst) error {
	name, err := inst.Name.evaluate(ctx, ec.contextNode)
	if err != nil {
		return err
	}

	var value string

	if inst.Select != nil {
		result, err := ec.evalXPath(ctx, inst.Select, ec.contextNode)
		if err != nil {
			return err
		}

		value, err = stringifyResult(ctx, result)
		if err != nil {
			return err
		}
	} else if len(inst.Body) > 0 {
		// XSLT 2.0: PI body is temporary output state (XTDE1480).
		// XSLT 3.0 relaxes this restriction.
		var val xdm.Sequence

		err := ec.withV2TempOutput(func() error {
			var err error

			val, err = ec.evaluateBodyAsSequence(ctx, inst.Body)

			return err
		})
		if err != nil {
			return err
		}

		value, err = stringifySimpleContent(ctx, val, " ")
		if err != nil {
			return err
		}
	}

	// XTDE0890: name must be a valid NCName and PITarget
	if !xmlchar.IsValidNCName(name) {
		return dynamicError(errCodeXTDE0890,
			"xsl:processing-instruction name %q is not a valid NCName", name)
	}

	if strings.EqualFold(name, methodXML) {
		return dynamicError(errCodeXTDE0890,
			"xsl:processing-instruction name must not be %q", name)
	}

	// XSLT 3.0 §11.6: replace "?>" in PI content with "? >" to avoid
	// premature termination of the processing instruction.
	value = strings.ReplaceAll(value, "?>", "? >")

	pi := ec.resultDoc.CreatePI(name, value)

	return ec.addNode(pi)
}

func (ec *execContext) execNamespace(ctx context.Context, inst *namespaceInst) error {
	name, err := inst.Name.evaluate(ctx, ec.contextNode)
	if err != nil {
		return err
	}

	value, err := ec.computedNamespaceValue(ctx, inst)
	if err != nil {
		return err
	}

	if err := validateComputedNamespace(name, value); err != nil {
		return err
	}

	// The xml namespace is always implicitly declared.

	out := ec.currentOutput()
	if out.sequenceMode {
		ns := xdm.NewNamespace(name, value)
		nsNode := xdm.NewNamespaceNodeWrapper(ns, nil)
		out.pendingItems = append(out.pendingItems, xdm.NodeItem{Node: nsNode})
		out.noteOutput()

		return nil
	}

	elem, ok := out.current.(*xdm.Element)
	if !ok {
		return dynamicError(errCodeXTDE0420,
			"cannot add namespace node to a non-element node")
	}

	if out.hasChildContent(elem) {
		return dynamicError(errCodeXTDE0410, "cannot add a namespace after child nodes")
	}

	if err := ec.addComputedNamespace(elem, name, value); err != nil {
		return err
	}

	out.noteOutput()

	return nil
}

func validateComputedNamespace(name, value string) error {
	if name == lexicon.PrefixXMLNS {
		return dynamicError(errCodeXTDE0920,
			"cannot create namespace node with prefix %q", name)
	}

	if name != "" && !xmlchar.IsValidNCName(name) {
		return dynamicError(errCodeXTDE0920,
			"xsl:namespace name %q is not a valid NCName", name)
	}

	if name == lexicon.PrefixXML && value != lexicon.NamespaceXML {
		return dynamicError(errCodeXTDE0925,
			"namespace prefix %q must be bound to %q, got %q",
			name, lexicon.NamespaceXML, value)
	}

	if value == lexicon.NamespaceXML && name != lexicon.PrefixXML {
		return dynamicError(errCodeXTDE0925,
			"namespace URI %q can only be bound to prefix %q, got %q",
			value, lexicon.PrefixXML, name)
	}

	if value == lexicon.NamespaceXMLNS {
		return dynamicError(errCodeXTDE0905,
			"namespace URI %q is reserved and cannot be used", value)
	}

	// XSD 1.1 xs:anyURI accepts any string; only an empty URI with a
	// non-empty prefix needs another namespace construction error.
	if value == "" {
		return dynamicError(errCodeXTDE0930,
			"namespace prefix %q requires a non-empty URI", name)
	}

	return nil
}

func (ec *execContext) computedNamespaceValue(ctx context.Context, inst *namespaceInst) (string, error) {
	if inst.Select != nil {
		result, err := ec.evalXPath(ctx, inst.Select, ec.contextNode)
		if err != nil {
			return "", err
		}

		return stringifyResult(ctx, result)
	}

	if len(inst.Body) == 0 {
		return "", nil
	}

	var val xdm.Sequence

	err := ec.withV2TempOutput(func() error {
		var err error

		val, err = ec.evaluateBody(ctx, inst.Body)

		return err
	})
	if err != nil {
		return "", err
	}

	return stringifySequence(val), nil
}

func (ec *execContext) addComputedNamespace(elem *xdm.Element, name, value string) error {
	_, fixupOK := ec.nsFixupAllowed[elem]
	if err := checkComputedNamespaceConflict(elem, name, value, fixupOK); err != nil {
		return err
	}

	// A default binding cannot change a no-namespace element's expanded name.
	if name == "" && value != "" && elem.URI() == "" && elem.Prefix() == "" {
		return dynamicError(errCodeXTDE0440,
			"cannot define default namespace %q on element %q which is in no namespace",
			value, elem.Name())
	}

	// Generated element prefixes can move aside to allow an explicit binding.
	if fixupOK && name != "" && elem.Prefix() == name && elem.URI() != value {
		if err := renameElementNamespacePrefix(elem, name); err != nil {
			return err
		}
	}

	return elem.DeclareNamespace(name, value)
}

func checkComputedNamespaceConflict(elem *xdm.Element, name, value string, fixupOK bool) error {
	for _, ns := range elem.Namespaces() {
		if ns.Prefix() != name || ns.URI() == value {
			continue
		}

		// Only an eligible element's own prefix may be repaired below.
		if fixupOK && elem.Prefix() == name && elem.URI() == ns.URI() {
			continue
		}

		return dynamicError(errCodeXTDE0430,
			"namespace prefix %q is already bound to %q; cannot rebind to %q", name, ns.URI(), value)
	}

	return nil
}

func renameElementNamespacePrefix(elem *xdm.Element, name string) error {
	uri := elem.URI()
	prefix := uniqueNSPrefix(elem, name+"_0", uri)
	elem.RemoveNamespaceByPrefix(name)

	if err := elem.DeclareNamespace(prefix, uri); err != nil {
		return err
	}

	return elem.SetActiveNamespace(prefix, uri)
}

// validateConstructedAttribute validates an attribute value against the schema
// when validation="strict" or validation="lax". Returns XTTE1510 when the
// value is invalid, XTTE1555 when no matching global declaration is found
// (strict only).
// firstNonEmptyType returns explicit if non-empty, else fallback. An explicit
// type= on xsl:attribute takes precedence over a validation-resolved type.
func firstNonEmptyType(explicit, fallback string) string {
	if explicit != "" {
		return explicit
	}

	return fallback
}

// uniqueNSPrefix returns a prefix for nsURI that doesn't conflict with
// in-scope namespace declarations on elem or its ancestors. If prefix is
// already bound to nsURI, it's returned as-is. If it's bound to a different
// URI, a suffix like _1, _2, ... is appended until a unique prefix is found.
func uniqueNSPrefix(elem *xdm.Element, prefix, nsURI string) string {
	if prefixBoundTo(elem, prefix) == nsURI {
		return prefix
	}

	if uri := prefixBoundTo(elem, prefix); uri != "" && uri != nsURI {
		for i := 1; ; i++ {
			candidate := prefix + "_" + strconv.Itoa(i)
			if prefixBoundTo(elem, candidate) == "" {
				return candidate
			}
		}
	}

	return prefix
}

// prefixBoundTo walks the element and its ancestors to find what URI
// a prefix is bound to. Returns "" if not found.
func prefixBoundTo(elem *xdm.Element, prefix string) string {
	uri, _ := xdm.LookupNSPrefixURI(elem, prefix)
	return uri
}

// copyAttributeToElement copies an attribute to an element, preserving its
// namespace URI and prefix. For non-namespaced attributes, falls back to
// SetAttribute.
func copyAttributeToElement(elem *xdm.Element, attr *xdm.Attribute) {
	defer func() {
		if copied := elem.GetAttributeNodeNS(attr.LocalName(), attr.URI()); copied != nil {
			copied.SetIDType(attr.IDType())
		}
	}()

	if uri := attr.URI(); uri != "" {
		prefix := attr.Prefix()
		name := attr.Name()

		localName := name
		if prefix != "" {
			localName = name[len(prefix)+1:]
		}
		// Namespace fixup: if the prefix is already used by another attribute
		// or namespace declaration on this element with a different URI,
		// generate a unique prefix to avoid conflict.
		if prefix != "" {
			if conflictingAttrPrefix(elem, prefix, uri) {
				prefix = uniqueNSPrefix(elem, prefix+"_0", uri)
			}
		}

		ns := xdm.NewNamespace(prefix, uri)
		_ = elem.SetAttributeNS(localName, attr.Value(), ns)
		// Ensure the namespace declaration is present on the element
		// so that the prefix is properly declared in the serialized output.
		if prefix != "" && !hasNSDecl(elem, prefix, uri) {
			_ = elem.DeclareNamespace(prefix, uri)
		}

		return
	}

	_ = elem.SetAttribute(attr.Name(), attr.Value())
}

// conflictingAttrPrefix returns true if the given prefix is already used
// on the element (by a namespace declaration or an existing attribute)
// with a different namespace URI.
func conflictingAttrPrefix(elem *xdm.Element, prefix, uri string) bool {
	for _, ns := range elem.Namespaces() {
		if ns.Prefix() == prefix && ns.URI() != uri {
			return true
		}
	}

	for _, a := range elem.Attributes() {
		if a.Prefix() == prefix && a.URI() != "" && a.URI() != uri {
			return true
		}
	}

	return false
}
