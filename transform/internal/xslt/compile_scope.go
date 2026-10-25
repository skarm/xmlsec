package xslt

import (
	"context"
	"strings"

	"github.com/skarm/xmlsec/internal/lexicon"
	"github.com/skarm/xmlsec/transform/internal/xdm"
	"github.com/skarm/xmlsec/transform/internal/xpath"
)

// Variable names come from the compiled XPath AST, which has already removed
// bindings introduced by for/let/quantified expressions and inline functions.
// Keep their stylesheet positions until imports, packages and global forward
// declarations have all been resolved (XSLT 2.0 section 9.7 / 3.0 section 9.9).
type pendingVariableReference struct {
	node                 xdm.Node
	name                 string
	lexical              string
	accumulatorRuleMatch bool
}

func (c *compiler) pushVariableScopeNode(node xdm.Node) func() {
	previous := c.variableScopeNode
	c.variableScopeNode = node

	return func() { c.variableScopeNode = previous }
}

func (c *compiler) recordVariableReferences(names []string, namespaces map[string]string, node xdm.Node, accumulatorRuleMatch bool) error {
	// Processor 1.0 retains its evaluation-time variable lookup. A nil position
	// denotes a static host expression (for example a shadow attribute), whose
	// restricted static-variable context is checked by its compile-time evaluator.
	if c.stylesheet.processorLanguage() < 20 || node == nil {
		return nil
	}

	if err := xpath.Charge(c.invocation, len(names)); err != nil {
		return err
	}

	for _, name := range names {
		expanded := xpath.VariableKey(name, namespaces)
		if expanded == xdm.ClarkName(lexicon.NamespaceXSLT, nameOriginal) {
			// compileXPath separately checks this binding against the overriding
			// component and rejects absent or abstract originals.
			continue
		}

		c.pendingVariableReferences = append(c.pendingVariableReferences, pendingVariableReference{
			node: node, name: expanded, lexical: name, accumulatorRuleMatch: accumulatorRuleMatch,
		})
	}

	return nil
}

func (c *compiler) validateVariableReferences(ctx context.Context) error {
	globals := make(map[string]globalBinding, len(c.stylesheet.globalVars)+len(c.stylesheet.globalParams))
	for _, binding := range c.stylesheet.globalVars {
		globals[binding.Name] = binding.binding()
	}

	for _, binding := range c.stylesheet.globalParams {
		globals[binding.Name] = binding.binding()
	}

	checker := variableScopeChecker{globals: globals, sources: c.globalVariableSources, names: make(map[*xdm.Element]string)}
	for _, reference := range c.pendingVariableReferences {
		visible, err := checker.visible(ctx, reference)
		if err != nil {
			return err
		}

		if !visible {
			return staticError(lexicon.ErrXPST0008, "variable $%s is not in scope", reference.lexical)
		}
	}

	return nil
}

type variableScopeChecker struct {
	globals map[string]globalBinding
	sources map[*xdm.Element]globalBinding
	names   map[*xdm.Element]string
}

func (c *compiler) recordGlobalBindingSource(element *xdm.Element, binding globalBinding) {
	if c.globalVariableSources == nil {
		c.globalVariableSources = make(map[*xdm.Element]globalBinding)
	}

	c.globalVariableSources[element] = binding
}

func (s *variableScopeChecker) bindingName(element *xdm.Element) string {
	if name, cached := s.names[element]; cached {
		return name
	}

	name := resolveQName(getAttr(element, xslAttrName), inScopeNamespaces(element))
	s.names[element] = name

	return name
}

func (s *variableScopeChecker) visible(ctx context.Context, reference pendingVariableReference) (bool, error) {
	var self globalBinding

	for node := reference.node; node != nil; node = node.Parent() {
		if err := xpath.Charge(ctx, 1); err != nil {
			return false, err
		}

		element, isElement := node.(*xdm.Element)
		if isElement && element.URI() == lexicon.NamespaceXSLT {
			if scope := element.LocalName(); scope == nameStylesheet || scope == fnNameTransform || scope == namePackage {
				break
			}

			if implicitVariableVisible(element, reference) {
				return true, nil
			}

			if isVariableBinding(element) && isGlobalBindingElement(element) {
				self = s.sources[element]
			}
		}

		if isElement && isScopeBarrier(element) {
			// A sibling variable in a try/extension instruction belongs to the
			// main constructor, not to its catch/fallback constructor. Outer
			// bindings remain visible, so continue at the parent afterwards.
			continue
		}

		for sibling := node.PrevSibling(); sibling != nil; sibling = sibling.PrevSibling() {
			if err := xpath.Charge(ctx, 1); err != nil {
				return false, err
			}

			binding, ok := sibling.(*xdm.Element)
			if ok && isVariableBinding(binding) && !isGlobalBindingElement(binding) && s.bindingName(binding) == reference.name {
				return true, nil
			}
		}
	}

	global, visible := s.globals[reference.name]

	return visible && global != self, nil
}

func isVariableBinding(element *xdm.Element) bool {
	return element.URI() == lexicon.NamespaceXSLT && (element.LocalName() == nameVariable || element.LocalName() == nameParam)
}

func isGlobalBindingElement(element *xdm.Element) bool {
	parent, ok := element.Parent().(*xdm.Element)
	if !ok || parent.URI() != lexicon.NamespaceXSLT {
		return false
	}

	switch parent.LocalName() {
	case nameStylesheet, fnNameTransform, namePackage, xslElemOverride:
		return true
	default:
		return false
	}
}

func isScopeBarrier(element *xdm.Element) bool {
	return element.URI() == lexicon.NamespaceXSLT && (element.LocalName() == lexicon.XSLTElementCatch || element.LocalName() == lexicon.XSLTElementFallback)
}

func implicitVariableVisible(element *xdm.Element, reference pendingVariableReference) bool {
	switch element.LocalName() {
	case lexicon.XSLTElementAccumulatorRule:
		return reference.name == lexicon.AttrValue && !(reference.accumulatorRuleMatch && element == reference.node)
	case lexicon.XSLTElementCatch:
		local, inErrors := strings.CutPrefix(reference.name, "{"+xpath.NSErr+"}")
		if !inErrors {
			return false
		}

		switch local {
		case "code", "description", lexicon.AttrValue, "module", "line-number", "column-number":
			return true
		}
	}

	return false
}

func (c *compiler) compileLiteralTextAt(node xdm.Node, text string) (*literalTextInst, error) {
	defer c.pushVariableScopeNode(node)()

	return c.compileLiteralText(text)
}
