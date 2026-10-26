// Derived from lestrrat-go/helium at 7362c0a70122a757780f4d0b545a9b370dead6ab.
// Copyright (c) 2015 lestrrat. MIT License; see licenses/MIT-helium.txt at the repository root.

package xslt

import (
	"context"
	"fmt"
	"strings"

	"github.com/skarm/xmlsec/internal/lexicon"
	"github.com/skarm/xmlsec/internal/xmlchar"
	"github.com/skarm/xmlsec/transform/internal/xdm"
	"github.com/skarm/xmlsec/transform/internal/xpath"
)

// componentVisibility tracks the effective visibility of a component.
// The default visibility for package components is "private" per XSLT 3.0 §3.6.1.
// The default for stylesheet (non-package) components is "public".
const (
	visPublic   = "public"
	visPrivate  = "private"
	visFinal    = "final"
	visAbstract = "abstract"
	visHidden   = "hidden"

	xslAttrComponent  = "component"
	xslAttrNames      = "names"
	xslAttrVisibility = "visibility"

	xslElemAccept       = "accept"
	xslElemExpose       = "expose"
	xslElemOverride     = "override"
	xslElemTemplate     = lexicon.XSLTElementTemplate
	xslElemFunction     = lexicon.XSLTElementFunction
	xslElemVariable     = lexicon.XSLTElementVariable
	xslElemParam        = lexicon.XSLTElementParam
	xslElemAttributeSet = lexicon.XSLTElementAttributeSet
	xslElemMode         = lexicon.XSLTElementMode

	xslWildcard = "*"
)

// defaultComponentVisibility returns the default visibility for a component
// in the given stylesheet context.
func defaultComponentVisibility(ss *Stylesheet) string {
	if ss.isPackage {
		return visPrivate
	}

	return visPublic
}

type acceptRule struct {
	component  string // "template", "function", "variable", "attribute-set", "mode", "*"
	names      string // name pattern (e.g., "*", "foo", "ns:*")
	visibility string // target visibility
}

// parseAcceptRules validates acceptance declarations before merging components.
func parseAcceptRules(ctx context.Context, usePackageElem *xdm.Element) ([]acceptRule, error) {
	var rules []acceptRule

	for elem := range xdm.ChildElements(usePackageElem) {
		if elem.URI() != lexicon.NamespaceXSLT || elem.LocalName() != xslElemAccept {
			continue
		}

		parsed, err := parseComponentRules(ctx, elem, true)
		if err != nil {
			return nil, err
		}

		rules = append(rules, parsed...)
	}

	return rules, nil
}

func parseComponentRules(ctx context.Context, elem *xdm.Element, accept bool) ([]acceptRule, error) {
	kind := elem.LocalName()
	for _, name := range []string{xslAttrComponent, xslAttrNames, xslAttrVisibility} {
		if _, present := elem.GetAttribute(name); !present {
			return nil, staticError(errCodeXTSE0010, "xsl:%s requires %s", kind, name)
		}
	}

	component := strings.Trim(getAttr(elem, xslAttrComponent), " \t\r\n")
	visibility := strings.Trim(getAttr(elem, xslAttrVisibility), " \t\r\n")

	switch component {
	case xslElemTemplate, xslElemFunction, xslElemVariable, xslElemAttributeSet, xslElemMode, xslWildcard:
	default:
		return nil, staticError(errCodeXTSE0020, "invalid xsl:%s component %q", kind, component)
	}

	switch visibility {
	case visPublic, visPrivate, visFinal, visAbstract:
	case visHidden:
		if !accept {
			return nil, staticError(errCodeXTSE0020, "hidden is not an xsl:expose visibility")
		}
	default:
		return nil, staticError(errCodeXTSE0020, "invalid xsl:%s visibility %q", kind, visibility)
	}

	names := strings.FieldsFunc(getAttr(elem, xslAttrNames), xmlchar.IsSpace)
	if len(names) == 0 {
		return nil, staticError(errCodeXTSE0020, "xsl:%s requires a nonempty names list", kind)
	}

	rules := make([]acceptRule, 0, len(names))
	for _, name := range names {
		if err := xpath.Charge(ctx, 1); err != nil {
			return nil, err
		}

		resolved, err := resolveComponentReference(name, component, elem)
		if err != nil {
			return nil, err
		}

		if component == xslWildcard && !isWildcard(resolved) {
			code := errCodeXTSE3022
			if accept {
				code = errCodeXTSE3032
			}

			return nil, staticError(code, "xsl:%s component='*' requires wildcard names", kind)
		}

		rules = append(rules, acceptRule{component: component, names: resolved, visibility: visibility})
	}

	return rules, nil
}

func resolveComponentReference(name, component string, elem *xdm.Element) (string, error) {
	base, arity, present := splitComponentArity(name)
	if present {
		if component != xslElemFunction || arity == "" {
			return "", staticError(errCodeXTSE0020, "invalid component name %q", name)
		}

		var err error

		arity, err = normalizedComponentArity(arity, name)
		if err != nil {
			return "", err
		}
	}

	ns := inScopeNamespaces(elem)

	wildcard := base == xslWildcard || strings.HasPrefix(base, "*:") || strings.HasSuffix(base, ":*") || strings.HasSuffix(base, "}*")
	if arity != "" && wildcard {
		return "", staticError(errCodeXTSE0020, "a named function reference requires an EQName: %q", name)
	}

	switch {
	case base == xslWildcard:
		return base, nil
	case strings.HasPrefix(base, "*:"):
		if xmlchar.IsValidNCName(base[2:]) {
			return base, nil
		}
	case strings.HasSuffix(base, ":*"):
		prefix := base[:len(base)-2]
		if xmlchar.IsValidNCName(prefix) && ns[prefix] != "" {
			return xdm.ClarkName(ns[prefix], "*"), nil
		}
	case strings.HasPrefix(base, "Q{") && strings.HasSuffix(base, "}*"):
		if isValidEQName(base[:len(base)-1] + "x") {
			return base[1:], nil
		}
	default:
		if xmlchar.IsValidQName(base) || isValidEQName(base) {
			if prefix, _, prefixed := strings.Cut(base, ":"); prefixed && !strings.HasPrefix(base, "Q{") && ns[prefix] == "" {
				return "", staticError(errCodeXTSE0280, "unbound prefix %q in component name", prefix)
			}

			return resolveQName(base, ns) + arity, nil
		}
	}

	return "", staticError(errCodeXTSE0020, "invalid component name %q", name)
}

func normalizedComponentArity(arity, name string) (string, error) {
	for _, c := range arity {
		if c < '0' || c > '9' {
			return "", staticError(errCodeXTSE0020, "invalid function arity in %q", name)
		}
	}

	arity = strings.TrimLeft(arity, "0")
	if arity == "" {
		arity = "0"
	}

	return "#" + arity, nil
}

// applyAcceptRules selects an accepted component's visibility. An incompatible
// wildcard is ignored; explicit incompatibilities are rejected before merging.
func applyAcceptRules(compType, compName string, rules []acceptRule, declared string) string {
	bestVis := visHidden
	if declared == visPublic || declared == visFinal {
		bestVis = visPrivate
	}

	bestPriority := -1

	for _, rule := range rules {
		if rule.component != xslWildcard && rule.component != compType || !componentNameMatches(compName, rule.names) || !isAcceptVisibilityCompatible(declared, rule.visibility) {
			continue
		}

		priority := componentRulePriority(rule.names)
		if priority >= bestPriority {
			bestPriority, bestVis = priority, rule.visibility
		}
	}

	return bestVis
}

// processExpose processes xsl:expose children of xsl:package to set component
// visibility. This is called during package compilation.
func (c *compiler) processExpose(ctx context.Context, root *xdm.Element) error {
	if !c.stylesheet.isPackage {
		return nil
	}

	var rules []acceptRule

	for elem := range xdm.ChildElements(root) {
		if elem.URI() != lexicon.NamespaceXSLT || elem.LocalName() != xslElemExpose {
			continue
		}

		excluded, err := c.excludedByUseWhen(ctx, elem)
		if err != nil {
			return err
		}

		if excluded {
			continue
		}

		parsed, err := parseComponentRules(ctx, elem, false)
		if err != nil {
			return err
		}

		rules = append(rules, parsed...)
	}

	c.initializeTemplateFunctionVisibility()
	c.initializeVariableAttributeVisibility()
	c.initializeImplicitExposedModes()
	c.initializeDeclaredModeVisibility()
	c.saveDeclaredComponentVisibility()
	components := c.localExposedComponents()

	for _, rule := range rules {
		matched := false

		for _, component := range components {
			if err := xpath.Charge(ctx, 1); err != nil {
				return err
			}

			if component.matches(rule) {
				matched = true
			}
		}

		if !matched && !isWildcard(rule.names) {
			return staticError(errCodeXTSE3020, "xsl:expose: no %s matches %q", rule.component, rule.names)
		}
	}

	for _, component := range components {
		visibility, exposed, err := component.exposedVisibility(ctx, rules)
		if err != nil {
			return err
		}

		component.set(visibility, exposed)
	}

	return nil
}

func (c *compiler) initializeImplicitExposedModes() {
	if c.stylesheet.declaredModes {
		return
	}

	for name, templates := range c.stylesheet.modeTemplates {
		if name == "" || name == modeDefault || name == modeAll || c.stylesheet.modeDefs[name] != nil {
			continue
		}

		for _, tmpl := range templates {
			if tmpl.OwnerPackage == nil || tmpl.OwnerPackage == c.stylesheet {
				if c.stylesheet.modeDefs == nil {
					c.stylesheet.modeDefs = make(map[string]*modeDef)
				}

				c.stylesheet.modeDefs[name] = &modeDef{Name: name, Implicit: true}

				break
			}
		}
	}
}

func (c *compiler) localExposedComponents() []exposedComponent {
	var components []exposedComponent

	for name, tmpl := range c.stylesheet.namedTemplates {
		if tmpl.OwnerPackage != nil && tmpl.OwnerPackage != c.stylesheet {
			continue
		}

		components = append(components, exposedComponent{kind: xslElemTemplate, name: name, declared: c.declaredTemplateVis[name], set: func(vis string, _ bool) { tmpl.Visibility = vis; c.stylesheet.templateVisibility[name] = vis }})
	}

	for key, fn := range c.stylesheet.functions {
		if fn.OwnerPackage != nil && fn.OwnerPackage != c.stylesheet {
			continue
		}

		name := functionVisKey(key.Name, len(fn.Params))
		components = append(components, exposedComponent{kind: xslElemFunction, name: name, declared: c.declaredFunctionVis[name], set: func(vis string, _ bool) { fn.Visibility = vis; c.stylesheet.functionVisibility[name] = vis }})
	}

	for _, v := range c.stylesheet.globalVars {
		if v.OwnerPackage != nil && v.OwnerPackage != c.stylesheet {
			continue
		}

		components = append(components, exposedComponent{kind: xslElemVariable, name: v.Name, declared: c.declaredVariableVis[v.Name], set: func(vis string, _ bool) { v.Visibility = vis; c.stylesheet.variableVisibility[v.Name] = vis }})
	}

	for name, attrs := range c.stylesheet.attributeSets {
		if attrs.OwnerPackage != nil && attrs.OwnerPackage != c.stylesheet {
			continue
		}

		components = append(components, exposedComponent{kind: xslElemAttributeSet, name: name, declared: c.declaredAttrSetVis[name], set: func(vis string, _ bool) { attrs.Visibility = vis; c.stylesheet.attrSetVisibility[name] = vis }})
	}

	for name, mode := range c.stylesheet.modeDefs {
		if name == "" || name == modeDefault || name == modeUnnamed || mode.OwnerPackage != nil {
			continue
		}

		components = append(components, exposedComponent{kind: xslElemMode, name: name, declared: c.declaredModeVis[name], set: func(vis string, exposed bool) { mode.Visibility = vis; mode.Implicit = mode.Implicit && !exposed }})
	}

	return components
}

func (c *compiler) initializeTemplateFunctionVisibility() {
	c.stylesheet.templateVisibility = make(map[string]string)
	c.stylesheet.functionVisibility = make(map[string]string)
	c.stylesheet.variableVisibility = make(map[string]string)
	c.stylesheet.attrSetVisibility = make(map[string]string)
	c.stylesheet.globalParamVisibility = make(map[string]string)

	// Set defaults: all package components default to private
	for _, tmpl := range c.stylesheet.templates {
		if tmpl.Name != "" {
			if tmpl.Visibility != "" {
				c.stylesheet.templateVisibility[tmpl.Name] = tmpl.Visibility
			} else {
				c.stylesheet.templateVisibility[tmpl.Name] = visPrivate
			}
		}
	}

	for fk, fn := range c.stylesheet.functions {
		key := functionVisKey(fk.Name, len(fn.Params))
		if fn.Visibility != "" {
			c.stylesheet.functionVisibility[key] = fn.Visibility
		} else {
			c.stylesheet.functionVisibility[key] = visPrivate
		}
	}
}

func (c *compiler) initializeVariableAttributeVisibility() {
	for _, v := range c.stylesheet.globalVars {
		if v.Visibility != "" {
			c.stylesheet.variableVisibility[v.Name] = v.Visibility
		} else {
			c.stylesheet.variableVisibility[v.Name] = visPrivate
		}
	}

	for _, p := range c.stylesheet.globalParams {
		if p.Visibility != "" {
			c.stylesheet.globalParamVisibility[p.Name] = p.Visibility
		} else {
			c.stylesheet.globalParamVisibility[p.Name] = visPublic
		}
	}

	for name, asd := range c.stylesheet.attributeSets {
		if asd != nil && asd.Visibility != "" {
			c.stylesheet.attrSetVisibility[name] = asd.Visibility
		} else {
			c.stylesheet.attrSetVisibility[name] = visPrivate
		}
	}
}

func (c *compiler) initializeDeclaredModeVisibility() {
	// Save explicitly declared mode visibility before defaults are applied.
	c.declaredModeVis = make(map[string]string)
	if c.stylesheet.modeDefs != nil {
		for _, md := range c.stylesheet.modeDefs {
			if md.Visibility != "" {
				c.declaredModeVis[md.Name] = md.Visibility
			}

			if md.Visibility == "" {
				md.Visibility = visPrivate
			}
		}
	}
}

func (c *compiler) saveDeclaredComponentVisibility() {
	// Save explicitly declared visibility before expose rules modify them.
	// Only store components that had an explicit visibility attribute — default
	// (private) does not restrict expose. XTSE3010 only applies when the
	// component was explicitly declared with a visibility.
	c.declaredTemplateVis = make(map[string]string)
	for _, tmpl := range c.stylesheet.templates {
		if tmpl.Name != "" && tmpl.Visibility != "" {
			c.declaredTemplateVis[tmpl.Name] = tmpl.Visibility
		}
	}

	c.declaredFunctionVis = make(map[string]string)
	for fk, fn := range c.stylesheet.functions {
		if fn.Visibility != "" {
			key := functionVisKey(fk.Name, len(fn.Params))
			c.declaredFunctionVis[key] = fn.Visibility
		}
	}

	c.declaredVariableVis = make(map[string]string)
	for _, v := range c.stylesheet.globalVars {
		if v.Visibility != "" {
			c.declaredVariableVis[v.Name] = v.Visibility
		}
	}

	c.declaredAttrSetVis = make(map[string]string)
	for name, as := range c.stylesheet.attributeSets {
		if as.Visibility != "" {
			c.declaredAttrSetVis[name] = as.Visibility
		}
	}
}

// collectElemNamespaces gathers namespace bindings from an element and its ancestors.
func (c *compiler) collectElemNamespaces(_ context.Context, elem *xdm.Element) map[string]string {
	return inScopeNamespaces(elem)
}

// collectOverrideNames scans xsl:override children of xsl:use-package and returns
// a set of "type:name" keys for components being overridden. Elements in
// excluded (removed by use-when) override nothing and are skipped.
func (c *compiler) collectOverrideNames(_ context.Context, usePackageElem *xdm.Element, nsBindings map[string]string, excluded map[*xdm.Element]struct{}) map[string]struct{} {
	names := make(map[string]struct{})

	for child := range xdm.Children(usePackageElem) {
		elem, ok := child.(*xdm.Element)
		if !ok || elem.URI() != lexicon.NamespaceXSLT || elem.LocalName() != xslElemOverride {
			continue
		}

		if _, skip := excluded[elem]; skip {
			continue
		}

		collectOverrideBlockNames(elem, nsBindings, excluded, names)
	}

	return names
}

type exposedComponent struct {
	kind     string
	name     string
	declared string
	set      func(string, bool)
}

func (component exposedComponent) matches(rule acceptRule) bool {
	return (rule.component == xslWildcard || rule.component == component.kind) && componentNameMatches(component.name, rule.names)
}

func (component exposedComponent) exposedVisibility(ctx context.Context, rules []acceptRule) (string, bool, error) {
	visibility := component.declared

	priority := -1
	if visibility != "" {
		priority = 2
	} else {
		visibility = visPrivate
	}

	explicit, exposed := false, false

	for _, rule := range rules {
		if err := xpath.Charge(ctx, 1); err != nil {
			return "", false, err
		}

		if !component.matches(rule) {
			continue
		}

		exposed = true

		candidate := componentRulePriority(rule.names)
		if candidate >= priority {
			priority, visibility = candidate, rule.visibility
			explicit = candidate == 3
		}
	}

	if explicit {
		code, message := checkExposeVisibility(component.name, visibility, component.declared)
		if code != "" {
			return "", false, staticError(code, "%s", message)
		}
	} else if visibility == visAbstract && component.declared != visAbstract {
		return "", false, staticError(errCodeXTSE3025, "xsl:expose cannot make %q abstract", component.name)
	}

	return visibility, exposed, nil
}

func componentRulePriority(name string) int {
	if name == xslWildcard {
		return 0
	}

	if isWildcard(name) {
		return 1
	}

	return 3
}

func collectOverrideBlockNames(block *xdm.Element, bindings map[string]string, excluded map[*xdm.Element]struct{}, names map[string]struct{}) {
	for child := range xdm.Children(block) {
		elem, ok := child.(*xdm.Element)
		if !ok || elem.URI() != lexicon.NamespaceXSLT {
			continue
		}

		if _, skip := excluded[elem]; skip {
			continue
		}

		if key := overrideComponentKey(elem, bindings); key != "" {
			names[key] = struct{}{}
		}
	}
}

func overrideComponentKey(elem *xdm.Element, bindings map[string]string) string {
	kind := elem.LocalName()
	switch kind {
	case xslElemTemplate, xslElemVariable, xslElemParam, xslElemAttributeSet:
		name := resolveQName(getAttr(elem, xslAttrName), bindings)
		if name == "" {
			return ""
		}

		if kind == xslElemParam {
			kind = xslElemVariable
		}

		return kind + ":" + name
	case xslElemFunction:
		name := getAttr(elem, xslAttrName)
		if name != "" {
			return xslElemFunction + ":" + resolveQName(name, bindings) + fmt.Sprintf("#%d", overrideFunctionArity(elem))
		}
	}

	return ""
}

func overrideFunctionArity(elem *xdm.Element) int {
	arity := 0

	for child := range xdm.Children(elem) {
		if param, ok := child.(*xdm.Element); ok && param.URI() == lexicon.NamespaceXSLT && param.LocalName() == lexicon.XSLTElementParam {
			arity++
		}
	}

	return arity
}

// checkExposeVisibility applies the explicit exposure/declaration table in 3.5.3.1.
func checkExposeVisibility(name, newVis, declaredVis string) (string, string) {
	if declaredVis != "" {
		allowed := false

		switch newVis {
		case visPublic:
			allowed = declaredVis == visPublic
		case visPrivate:
			allowed = declaredVis != visAbstract
		case visFinal:
			allowed = declaredVis == visPublic || declaredVis == visFinal
		case visAbstract:
			allowed = declaredVis == visAbstract
		}

		if !allowed {
			return errCodeXTSE3010, fmt.Sprintf("xsl:expose: visibility %s is inconsistent with declared %s on %q", newVis, declaredVis, name)
		}
	}

	if newVis == visAbstract && declaredVis != visAbstract {
		return errCodeXTSE3025, fmt.Sprintf("xsl:expose: %q was not declared abstract", name)
	}

	return "", ""
}

// splitComponentArity ignores hashes inside an expanded namespace URI.
func splitComponentArity(name string) (string, string, bool) {
	start := 0

	if strings.HasPrefix(name, "{") || strings.HasPrefix(name, "Q{") {
		if end := strings.IndexByte(name, '}'); end >= 0 {
			start = end + 1
		}
	}

	if offset := strings.IndexByte(name[start:], '#'); offset >= 0 {
		offset += start
		return name[:offset], name[offset+1:], true
	}

	return name, "", false
}

// componentNameMatches checks if a component name matches a name pattern.
// Patterns: "*" matches all, "{ns}*" matches all in namespace, "*:local" matches
// any namespace with that local name, "{ns}local" matches exactly.
func componentNameMatches(compName, pattern string) bool {
	if pattern == xslWildcard {
		return true
	}

	pattern, patternArity, hasArity := splitComponentArity(pattern)
	compNameBase, compArity, _ := splitComponentArity(compName)
	// If pattern has arity, it must match
	if hasArity && patternArity != compArity {
		return false
	}

	// {ns}* pattern — matches any local name in that namespace
	if strings.HasSuffix(pattern, "}*") && strings.HasPrefix(pattern, "{") {
		ns := pattern[1 : len(pattern)-2]
		if ns == "" {
			// {}* matches names with no namespace, which may be
			// stored without Clark notation prefix.
			return !strings.HasPrefix(compNameBase, "{") || strings.HasPrefix(compNameBase, "{}")
		}

		return strings.HasPrefix(compNameBase, "{"+ns+"}")
	}

	// *:local pattern — matches any namespace with that local name
	if strings.HasPrefix(pattern, "*:") {
		local := pattern[2:]

		compLocal := compNameBase
		if idx := strings.LastIndex(compNameBase, "}"); idx >= 0 {
			compLocal = compNameBase[idx+1:]
		}

		return compLocal == local
	}

	// Exact match
	return compNameBase == pattern
}

func isWildcard(pattern string) bool {
	return pattern == xslWildcard || strings.HasSuffix(pattern, "}*") || strings.HasPrefix(pattern, "*:")
}

// functionVisKey creates a visibility map key for a function (name#arity).
func functionVisKey(qn xpath.QualifiedName, arity int) string {
	return fmt.Sprintf("{%s}%s#%d", qn.URI, qn.Name, arity)
}
