// Copyright (c) 2026 xmlsec contributors. MIT License.

package xslt

import (
	"context"
	"maps"
	"slices"

	"github.com/skarm/xmlsec/internal/lexicon"
	"github.com/skarm/xmlsec/transform/internal/xdm"
	"github.com/skarm/xmlsec/transform/internal/xpath"
)

type pendingLiteralResult struct {
	element    *xdm.Element
	result     *literalResultElement
	namespaces map[string]string
	excludes   map[string]struct{}
}

type staticImportScope struct{ parent *staticImportScope }

type pendingPackageUse struct {
	element, root *xdm.Element
	baseURI       string
}

func (c *compiler) compilePendingPackageUse(ctx context.Context, use pendingPackageUse) error {
	base, root, version := c.baseURI, c.moduleRoot, c.effectiveVersion
	c.baseURI, c.moduleRoot = use.baseURI, embeddedModuleRoot(use.root)

	c.effectiveVersion = elementXSLTVersion(use.root)
	defer func() { c.baseURI, c.moduleRoot, c.effectiveVersion = base, root, version }()
	defer c.enterModuleNamespaceScope(use.root)()

	return c.collectTopLevelPackage(ctx, use.element)
}

type staticDeclarationBinding struct {
	scope *staticImportScope
	kind  string
	value xdm.Sequence
}

func lowerStaticScope(current, previous *staticImportScope) bool {
	for scope := current.parent; scope != nil; scope = scope.parent {
		if scope == previous {
			return true
		}
	}

	return false
}

// Static values must be identical, rather than merely have equal string
// representations. Function items (including maps/arrays) are forbidden in
// initialized declarations being checked for consistency (XSLT 3.0 section 9.6).
func staticSequenceIdentical(ctx context.Context, a, b xdm.Sequence) (bool, error) {
	if xdm.SequenceLen(a) != xdm.SequenceLen(b) {
		return false, nil
	}

	for i := range xdm.SequenceLen(a) {
		if err := xpath.Charge(ctx, 1); err != nil {
			return false, err
		}

		switch av := a.Get(i).(type) {
		case xdm.AtomicValue:
			bv, ok := b.Get(i).(xdm.AtomicValue)
			if !ok || av.TypeName != bv.TypeName || !xpath.AtomicEquals(av, bv) {
				return false, nil
			}
		case xdm.NodeItem:
			bv, ok := b.Get(i).(xdm.NodeItem)
			if !ok || !xdm.SameNode(av.Node, bv.Node) {
				return false, nil
			}
		default:
			return false, nil
		}
	}

	return true, nil
}

// A prior declaration in an importing module has higher precedence even when
// the imported module's declaration occurs later in stylesheet tree order.
func (c *compiler) bindStaticValue(ctx context.Context, name string, value xdm.Sequence) {
	previous := c.staticValueScopes[name]
	if lowerStaticScope(c.staticImportScope, previous) {
		return
	}

	if c.staticValueScopes == nil {
		c.staticValueScopes = make(map[string]*staticImportScope)
	}

	c.staticValueScopes[name] = c.staticImportScope
	c.setStaticVar(ctx, name, value)
}

// Namespace aliases have package-wide effect, including declarations that
// follow an import. Resolve them only after all module preprocessing is done.
func (c *compiler) completeLiteralResultAliases(ctx context.Context) {
	namespaces, excludes := c.nsBindings, c.localExcludes
	defer func() { c.nsBindings, c.localExcludes = namespaces, excludes }()

	for _, pending := range c.pendingLiteralResults {
		c.nsBindings, c.localExcludes = pending.namespaces, pending.excludes
		pending.result.Namespaces = c.literalResultNamespaces(pending.element)
		c.applyLiteralResultAliases(ctx, pending.result)
		pending.result.NamespacePrefixes = slices.Sorted(maps.Keys(pending.result.Namespaces))
	}

	c.pendingLiteralResults = nil
}

func hasConditionalAttributes(elem *xdm.Element, processor int) bool {
	if elem.URI() != lexicon.NamespaceXSLT {
		_, present := elem.GetAttributeNS(xslAttrUseWhen, lexicon.NamespaceXSLT)
		return present
	}

	if _, present := elem.GetAttribute(xslAttrUseWhen); present {
		return true
	}

	if processor >= 30 {
		for _, attr := range elem.Attributes() {
			if attr.URI() == "" && isShadowAttributeName(attr.LocalName()) {
				return true
			}
		}
	}

	return false
}

// preprocessConditionalElement runs in stylesheet tree order, before later
// static declarations enter scope. Only attributes needed by use-when are
// evaluated on an excluded element. The source is a private prepared tree.
func (c *compiler) preprocessConditionalElement(ctx context.Context, elem *xdm.Element, moduleRoot bool) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}

	if c.stylesheet.processorLanguage() < 20 || !hasConditionalAttributes(elem, c.stylesheet.processorLanguage()) {
		return true, nil
	}

	if c.deferredLanguageChecks == nil {
		c.deferredLanguageChecks = make(map[*xdm.Element]bool)
	}

	for ancestor := xdm.Node(elem); ancestor != nil; ancestor = ancestor.Parent() {
		if element, ok := ancestor.(*xdm.Element); ok {
			c.deferredLanguageChecks[element] = true
		}
	}

	restore := c.enterStaticElementContext(elem)
	defer restore()

	if err := xpath.Charge(ctx, len(c.nsBindings)+1); err != nil {
		return false, err
	}

	if elem.URI() == lexicon.NamespaceXSLT && c.stylesheet.processorLanguage() >= 30 {
		if err := c.resolveSingleShadowAttribute(ctx, elem, nameXpathDefaultNamespace); err != nil {
			return false, err
		}

		c.xpathDefaultNS, c.hasXPathDefaultNS = c.declarationDefaultNamespace(elem)
		if err := c.resolveSingleShadowAttribute(ctx, elem, xslAttrUseWhen); err != nil {
			return false, err
		}
	}

	include, err := c.topLevelUseWhen(ctx, elem)
	if err != nil {
		return false, err
	}

	if !include && !moduleRoot {
		return false, nil
	}

	if elem.URI() == lexicon.NamespaceXSLT {
		if c.stylesheet.processorLanguage() >= 30 {
			if err := c.resolveShadowAttributes(ctx, elem); err != nil {
				return false, err
			}
		}

		elem.RemoveAttribute(xslAttrUseWhen)
	} else {
		elem.RemoveAttributeNS(xslAttrUseWhen, lexicon.NamespaceXSLT)
	}

	if !include {
		xdm.FilterChildren(elem, func(xdm.Node) bool { return false })
	}

	return include, nil
}

func (c *compiler) validatePreparedLanguage(root *xdm.Element) error {
	if c.stylesheet.processorLanguage() >= 20 && c.deferredLanguageChecks[root] {
		return checkModernLanguage(root, elementXSLTVersion(root), c.stylesheet.processorLanguage())
	}

	return nil
}

func (c *compiler) enterStaticElementContext(elem *xdm.Element) func() {
	namespaces, defaultNS, hasDefault, base := c.nsBindings, c.xpathDefaultNS, c.hasXPathDefaultNS, c.baseURI
	c.nsBindings = inScopeNamespaces(elem)
	c.xpathDefaultNS, c.hasXPathDefaultNS = c.declarationDefaultNamespace(elem)
	c.baseURI = stylesheetBaseURI(elem, base, c.moduleRoot)

	return func() {
		c.nsBindings, c.xpathDefaultNS, c.hasXPathDefaultNS, c.baseURI = namespaces, defaultNS, hasDefault, base
	}
}

func (c *compiler) preprocessStaticSubtree(ctx context.Context, elem *xdm.Element) (bool, error) {
	if err := xpath.Charge(ctx, 1); err != nil {
		return false, err
	}

	include, err := c.preprocessConditionalElement(ctx, elem, false)
	if err != nil || !include {
		return include, err
	}

	forwards := elem.URI() == lexicon.NamespaceXSLT && unavailableInstruction(elem.LocalName(), c.stylesheet.processorLanguage()) && elementForwardsCompatible(elem, c.stylesheet.processorLanguage())

	var excluded map[xdm.Node]struct{}

	for child := range xdm.Children(elem) {
		if nested, ok := child.(*xdm.Element); ok && (!forwards || nested.URI() == lexicon.NamespaceXSLT && nested.LocalName() == lexicon.XSLTElementFallback) {
			included, err := c.preprocessStaticSubtree(ctx, nested)
			if err != nil {
				return false, err
			}

			if !included {
				if excluded == nil {
					excluded = make(map[xdm.Node]struct{})
				}

				excluded[nested] = struct{}{}
			}
		}
	}

	removeExcludedChildren(elem, excluded)

	return true, nil
}

// Remove excluded siblings in one pass, avoiding repeated slice shifts and
// reindexing when a stylesheet contains many conditional declarations.
func removeExcludedChildren(parent *xdm.Element, excluded map[xdm.Node]struct{}) {
	if len(excluded) > 0 {
		xdm.FilterChildren(parent, func(child xdm.Node) bool {
			_, remove := excluded[child]
			return !remove
		})
	}
}
