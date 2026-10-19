// Derived from lestrrat-go/helium at 7362c0a70122a757780f4d0b545a9b370dead6ab.
// Copyright (c) 2015 lestrrat. MIT License; see licenses/MIT-helium.txt at the repository root.

package xslt

import (
	"context"
	"fmt"
	"maps"
	"strings"

	"github.com/skarm/xmlsec/transform/internal/xdm"
	"github.com/skarm/xmlsec/transform/internal/xdm/lexicon"
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

// parseAcceptRules extracts xsl:accept children from an xsl:use-package element.
func parseAcceptRules(usePackageElem *xdm.Element, nsBindings map[string]string) []acceptRule {
	var rules []acceptRule

	for child := range xdm.Children(usePackageElem) {
		elem, ok := child.(*xdm.Element)
		if !ok || elem.URI() != lexicon.NamespaceXSLT || elem.LocalName() != xslElemAccept {
			continue
		}

		comp := getAttr(elem, xslAttrComponent)
		names := getAttr(elem, xslAttrNames)
		vis := getAttr(elem, xslAttrVisibility)
		// Resolve namespace prefixes in names
		for name := range strings.FieldsSeq(names) {
			resolvedName := resolveComponentName(name, nsBindings, elem)
			rules = append(rules, acceptRule{
				component:  comp,
				names:      resolvedName,
				visibility: vis,
			})
		}
	}

	return rules
}

// applyAcceptRules determines the effective visibility of a component after
// applying xsl:accept rules. Returns the visibility and whether the component
// should be included (hidden components are excluded).
// acceptRules are processed in order; more specific patterns override wildcards.
func applyAcceptRules(compType, compName string, rules []acceptRule, defaultVis string) string {
	bestVis := defaultVis
	bestSpecificity := -1

	for _, rule := range rules {
		if rule.component != xslWildcard && rule.component != compType {
			continue
		}

		if !componentNameMatches(compName, rule.names) {
			continue
		}

		// Calculate specificity based on name token only (XSLT 3.0 §3.6.2):
		// * = 0, ns:* or *:local = 1, explicit name = 2.
		// Component attribute does NOT affect priority.
		// When priority ties, last matching rule (document order) wins.
		spec := 0
		if rule.names == xslWildcard {
			spec = 0
		} else if strings.HasSuffix(rule.names, "}*") || strings.HasPrefix(rule.names, "*:") {
			spec = 1
		} else {
			spec = 2
		}

		if spec >= bestSpecificity {
			bestSpecificity = spec
			bestVis = rule.visibility
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

	c.initializeTemplateFunctionVisibility()
	c.initializeVariableAttributeVisibility()
	c.initializeDeclaredModeVisibility()
	c.saveDeclaredComponentVisibility()

	for child := range xdm.Children(root) {
		elem, ok := child.(*xdm.Element)
		if !ok || elem.URI() != lexicon.NamespaceXSLT || elem.LocalName() != xslElemExpose {
			continue
		}

		if err := c.compileExpose(ctx, elem); err != nil {
			return err
		}
	}

	c.publishComponentVisibility()

	return nil
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
			c.stylesheet.globalParamVisibility[p.Name] = visPrivate
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

	c.declaredParamVis = make(map[string]string)
	for _, p := range c.stylesheet.globalParams {
		if p.Visibility != "" {
			c.declaredParamVis[p.Name] = p.Visibility
		}
	}
}

func (c *compiler) publishComponentVisibility() {
	for _, tmpl := range c.stylesheet.templates {
		if tmpl.Name != "" {
			if vis, ok := c.stylesheet.templateVisibility[tmpl.Name]; ok {
				tmpl.Visibility = vis
			}
		}
	}

	for fk, fn := range c.stylesheet.functions {
		key := functionVisKey(fk.Name, len(fn.Params))
		if vis, ok := c.stylesheet.functionVisibility[key]; ok {
			fn.Visibility = vis
		}
	}

	for _, v := range c.stylesheet.globalVars {
		if vis, ok := c.stylesheet.variableVisibility[v.Name]; ok {
			v.Visibility = vis
		}
	}

	for _, p := range c.stylesheet.globalParams {
		if vis, ok := c.stylesheet.globalParamVisibility[p.Name]; ok {
			p.Visibility = vis
		}
	}
}

func (c *compiler) compileExpose(ctx context.Context, elem *xdm.Element) error {
	component := getAttr(elem, xslAttrComponent)
	names := getAttr(elem, xslAttrNames)
	visibility := getAttr(elem, xslAttrVisibility)

	if component == "" || names == "" || visibility == "" {
		return staticError(errCodeXTSE0010, "xsl:expose requires component, names, and visibility attributes")
	}

	// Validate visibility value
	switch visibility {
	case visPublic, visPrivate, visFinal, visAbstract, visHidden:
		// ok
	default:
		return staticError(errCodeXTSE0020, "invalid visibility value %q on xsl:expose", visibility)
	}

	// Validate component type
	validComponents := map[string]struct{}{
		xslElemTemplate: {}, xslElemFunction: {}, xslElemVariable: {},
		xslElemAttributeSet: {}, xslElemMode: {}, xslWildcard: {},
	}
	if _, ok := validComponents[component]; !ok {
		return staticError(errCodeXTSE0020, "invalid component type %q on xsl:expose", component)
	}

	nsBindings := c.collectElemNamespaces(ctx, elem)

	for name := range strings.FieldsSeq(names) {
		resolvedName := resolveComponentName(name, nsBindings, elem)

		if err := c.applyExposeComponent(ctx, component, resolvedName, name, visibility); err != nil {
			return err
		}
	}

	return nil
}

// resolveComponentName resolves a component name (possibly prefixed) to an
// expanded Clark notation name. Handles wildcards like "*", "ns:*", "*:local".
func resolveComponentName(name string, nsBindings map[string]string, elem *xdm.Element) string {
	arity := ""
	if idx := strings.LastIndex(name, "#"); idx >= 0 {
		arity = name[idx:]
		name = name[:idx]
	}

	if name == xslWildcard {
		return xslWildcard + arity
	}

	if strings.HasPrefix(name, "*:") {
		return name + arity
	}

	if strings.HasPrefix(name, "Q{") {
		return name[1:] + arity
	}

	if prefix, local, ok := strings.Cut(name, ":"); ok {
		uri := componentNamespaceURI(prefix, nsBindings, elem)

		if uri != "" {
			if local == "*" {
				return "{" + uri + "}*" + arity
			}

			return xdm.ClarkName(uri, local) + arity
		}
		// If no URI found, return as-is (may be an error in the stylesheet)
		return name + arity
	}

	return name + arity
}

func componentNamespaceURI(prefix string, bindings map[string]string, elem *xdm.Element) string {
	uri := bindings[prefix]
	if uri != "" {
		return uri
	}

	for node := xdm.Node(elem); node != nil; node = node.Parent() {
		element, ok := node.(*xdm.Element)
		if !ok {
			continue
		}

		for _, namespace := range element.Namespaces() {
			if namespace.Prefix() == prefix {
				uri = namespace.URI()
				break
			}
		}

		if uri != "" {
			return uri
		}
	}

	return ""
}

func (c *compiler) applyExposeComponent(ctx context.Context, component, resolvedName, originalName, visibility string) error {
	switch component {
	case xslElemTemplate:
		if err := c.applyExposeToTemplates(ctx, resolvedName, visibility, false); err != nil {
			return err
		}
	case xslElemFunction:
		// XTSE3020 (erratum E36): non-wildcard function names must include
		// arity (e.g., "f#2"). A bare name without "#" is an error.
		if !isWildcard(resolvedName) && !strings.Contains(resolvedName, "#") {
			return staticError(errCodeXTSE3020,
				"xsl:expose: function name %q must include arity (e.g. %s#0)", originalName, originalName)
		}

		if err := c.applyExposeToFunctionsStrict(ctx, resolvedName, visibility); err != nil {
			return err
		}
	case xslElemVariable:
		if err := c.applyExposeToVariablesStrict(ctx, resolvedName, visibility); err != nil {
			return err
		}
	case xslElemAttributeSet:
		if err := c.applyExposeToAttrSets(ctx, resolvedName, visibility, true); err != nil {
			return err
		}
	case xslElemMode:
		if err := c.applyExposeToModes(ctx, resolvedName, visibility, true); err != nil {
			return err
		}
	case xslWildcard:
		return c.applyWildcardExpose(ctx, resolvedName, visibility)
	}

	return nil
}

func (c *compiler) applyWildcardExpose(ctx context.Context, resolvedName, visibility string) error {
	// When component="*", apply to all component types.
	// Use non-strict mode so we don't error when a name matches
	// in one component type but not others. But propagate XTSE3025
	// (abstract on non-abstract) which applies regardless.
	for _, fn := range []func() error{
		func() error { return c.applyExposeToTemplates(ctx, resolvedName, visibility, true) },
		func() error { return c.applyExposeToFunctions(ctx, resolvedName, visibility) },
		func() error { return c.applyExposeToVariables(ctx, resolvedName, visibility) },
		func() error { return c.applyExposeToAttrSets(ctx, resolvedName, visibility, false) },
		func() error { return c.applyExposeToModes(ctx, resolvedName, visibility, false) },
	} {
		if err := fn(); err != nil {
			if xErr, ok := err.(*XSLTError); ok && xErr.Code == errCodeXTSE3025 {
				return err
			}
		}
	}

	return nil
}

// collectElemNamespaces gathers namespace bindings from an element and its ancestors.
func (c *compiler) collectElemNamespaces(_ context.Context, elem *xdm.Element) map[string]string {
	bindings := make(map[string]string)
	maps.Copy(bindings, c.nsBindings)

	for n := xdm.Node(elem); n != nil; n = n.Parent() {
		if e, ok := n.(*xdm.Element); ok {
			for _, ns := range e.Namespaces() {
				if _, exists := bindings[ns.Prefix()]; !exists {
					bindings[ns.Prefix()] = ns.URI()
				}
			}
		}
	}

	return bindings
}

func (c *compiler) applyExposeToTemplates(_ context.Context, pattern, visibility string, isWildcardComponent bool) error {
	matched := false

	isWild := isWildcard(pattern)
	for name := range c.stylesheet.templateVisibility {
		if componentNameMatches(name, pattern) {
			declared := c.declaredTemplateVis[name] // "" if not explicitly declared
			// Only check conflicts for non-wildcard patterns
			if !isWild {
				code, msg := checkExposeVisibility(name, visibility, declared)
				if code != "" {
					return staticError(code, "%s", msg)
				}
			} else {
				// For wildcard patterns, XTSE3025 (abstract) is still a
				// hard error, but XTSE3010 (visibility increase) silently
				// skips the component instead of erroring.
				code, msg := checkExposeVisibility(name, visibility, declared)
				if code == errCodeXTSE3025 {
					return staticError(code, "%s", msg)
				}

				if declared != "" && isVisibilityIncrease(declared, visibility) {
					continue
				}
			}

			c.stylesheet.templateVisibility[name] = visibility
			matched = true
		}
	}

	if !matched && !isWildcard(pattern) && !isWildcardComponent {
		return staticError(errCodeXTSE3010, "xsl:expose: no template %q found in package", pattern)
	}

	return nil
}

func (c *compiler) applyExposeToFunctions(_ context.Context, pattern, visibility string) error {
	matched := false

	isWild := isWildcard(pattern)
	for key := range c.stylesheet.functionVisibility {
		if componentNameMatches(key, pattern) {
			declared := c.declaredFunctionVis[key]
			if !isWild {
				code, msg := checkExposeVisibility(key, visibility, declared)
				if code != "" {
					return staticError(code, "%s", msg)
				}
			} else {
				code, msg := checkExposeVisibility(key, visibility, declared)
				if code != "" {
					return staticError(code, "%s", msg)
				}

				if declared != "" && visibilityLevel(visibility) > visibilityLevel(declared) {
					continue
				}
			}

			c.stylesheet.functionVisibility[key] = visibility
			matched = true
		}
	}

	_ = matched

	return nil
}

// applyExposeToFunctionsStrict is like applyExposeToFunctions but reports
// XTSE3010 when a non-wildcard pattern has no match. Used when the expose
// element has component="function" (not component="*").
func (c *compiler) applyExposeToFunctionsStrict(_ context.Context, pattern, visibility string) error {
	matched := false

	isWild := isWildcard(pattern)
	for key := range c.stylesheet.functionVisibility {
		if componentNameMatches(key, pattern) {
			declared := c.declaredFunctionVis[key]
			if !isWild {
				code, msg := checkExposeVisibility(key, visibility, declared)
				if code != "" {
					return staticError(code, "%s", msg)
				}
			} else {
				code, msg := checkExposeVisibility(key, visibility, declared)
				if code != "" {
					return staticError(code, "%s", msg)
				}

				if declared != "" && visibilityLevel(visibility) > visibilityLevel(declared) {
					continue
				}
			}

			c.stylesheet.functionVisibility[key] = visibility
			matched = true
		}
	}

	if !matched && !isWildcard(pattern) {
		return staticError(errCodeXTSE3010, "xsl:expose: no function %q found in package", pattern)
	}

	return nil
}

func (c *compiler) applyExposeToVariables(_ context.Context, pattern, visibility string) error {
	if _, err := applyExposeVisibilityMap(c.stylesheet.variableVisibility, c.declaredVariableVis, pattern, visibility); err != nil {
		return err
	}

	_, err := applyExposeVisibilityMap(c.stylesheet.globalParamVisibility, c.declaredParamVis, pattern, visibility)

	return err
}

// applyExposeToVariablesStrict rejects a parameter-only explicit name and
// reports XTSE3010 when neither variables nor params match a non-wildcard name.
func (c *compiler) applyExposeToVariablesStrict(_ context.Context, pattern, visibility string) error {
	variableMatched, err := applyExposeVisibilityMap(c.stylesheet.variableVisibility, c.declaredVariableVis, pattern, visibility)
	if err != nil {
		return err
	}

	paramMatched := false

	wildcard := isWildcard(pattern)
	for name := range c.stylesheet.globalParamVisibility {
		if !componentNameMatches(name, pattern) {
			continue
		}

		if !wildcard && !variableMatched {
			return staticError(errCodeXTSE3020, "xsl:expose: %q is a stylesheet parameter, not a variable", name)
		}

		allowed, err := exposeVisibilityAllowed(name, visibility, c.declaredParamVis[name], wildcard)
		if err != nil {
			return err
		}

		if allowed {
			c.stylesheet.globalParamVisibility[name] = visibility
			paramMatched = true
		}
	}

	if !variableMatched && !paramMatched && !wildcard {
		return staticError(errCodeXTSE3010, "xsl:expose: no variable or parameter %q found in package", pattern)
	}

	return nil
}

func (c *compiler) applyExposeToAttrSets(_ context.Context, pattern, visibility string, strict bool) error {
	matched := false

	isWild := isWildcard(pattern)
	for name := range c.stylesheet.attrSetVisibility {
		if componentNameMatches(name, pattern) {
			declared := c.declaredAttrSetVis[name]
			if !isWild {
				code, msg := checkExposeVisibility(name, visibility, declared)
				if code != "" {
					return staticError(code, "%s", msg)
				}
			} else {
				// For wildcard patterns, XTSE3025 (abstract) is still a
				// hard error, but XTSE3010 (visibility increase) silently
				// skips the component instead of erroring.
				code, msg := checkExposeVisibility(name, visibility, declared)
				if code == errCodeXTSE3025 {
					return staticError(code, "%s", msg)
				}

				if declared != "" && isVisibilityIncrease(declared, visibility) {
					continue
				}
			}

			c.stylesheet.attrSetVisibility[name] = visibility
			matched = true
		}
	}

	if strict && !matched && !isWildcard(pattern) {
		return staticError(errCodeXTSE3010, "xsl:expose: no attribute-set %q found in package", pattern)
	}

	return nil
}

func (c *compiler) applyExposeToModes(_ context.Context, pattern, visibility string, strict bool) error {
	if c.stylesheet.modeDefs == nil {
		c.stylesheet.modeDefs = make(map[string]*modeDef)
	}

	matched, err := c.exposeDeclaredModes(pattern, visibility)
	if err != nil {
		return err
	}

	if c.exposeImplicitModes(pattern, visibility) {
		matched = true
	}

	if strict && !matched && !isWildcard(pattern) {
		return staticError(errCodeXTSE3010, "xsl:expose: no mode %q found in package", pattern)
	}

	return nil
}

func (c *compiler) exposeDeclaredModes(pattern, visibility string) (bool, error) {
	matched := false

	isWild := isWildcard(pattern)
	for _, md := range c.stylesheet.modeDefs {
		if componentNameMatches(md.Name, pattern) {
			allowed, err := exposeModeVisibilityAllowed(md.Name, visibility, c.declaredModeVis[md.Name], isWild)
			if err != nil {
				return false, err
			}

			if !allowed {
				continue
			}

			md.Visibility = visibility
			matched = true
		}
	}

	return matched, nil
}

func exposeModeVisibilityAllowed(name, visibility, declared string, wildcard bool) (bool, error) {
	code, message := checkExposeVisibility(name, visibility, declared)
	if wildcard && code == errCodeXTSE3010 {
		return false, nil
	}

	if code != "" {
		return false, staticError(code, "%s", message)
	}

	return true, nil
}

func (c *compiler) exposeImplicitModes(pattern, visibility string) bool {
	matched := false
	// When declared-modes="false", also match implicit modes from templates
	// that have no explicit xsl:mode declaration.
	if !c.stylesheet.declaredModes {
		for modeName := range c.stylesheet.modeTemplates {
			if modeName == modeAll {
				continue
			}
			// Skip modes already in modeDefs (including unnamed mode
			// stored under "#default").
			if _, exists := c.stylesheet.modeDefs[modeName]; exists {
				continue
			}

			if modeName == "" {
				if _, exists := c.stylesheet.modeDefs[modeDefault]; exists {
					continue
				}
			}

			if componentNameMatches(modeName, pattern) {
				// Create a modeDef entry for this implicit mode so
				// visibility is tracked. Only Visibility is set; other
				// mode properties (on-no-match etc.) remain at defaults.
				md := &modeDef{
					Name:       modeName,
					Visibility: visibility,
				}
				c.stylesheet.modeDefs[modeName] = md
				matched = true
			}
		}
	}

	return matched
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

// visibilityLevel returns a numeric accessibility level for visibility.
// Higher level = more accessible. Used to enforce the rule that xsl:expose
// cannot make a component more accessible than its declared level.
// "final" and "public" are at the same accessibility level.
func visibilityLevel(vis string) int {
	switch vis {
	case visHidden:
		return 0
	case visPrivate:
		return 1
	case visPublic, visFinal, visAbstract:
		return 2
	default:
		return 1 // treat unknown as private
	}
}

// isVisibilityIncrease returns true if changing from 'from' to 'to' is
// considered an increase in accessibility (which is not allowed by xsl:expose).
// The ordering (from most restricted to most accessible) is:
//
//	hidden < private < final < public
//
// abstract is special and handled separately.
func isVisibilityIncrease(from, to string) bool {
	order := map[string]int{
		visHidden:  0,
		visPrivate: 1,
		visFinal:   2,
		visPublic:  3,
	}
	f, okF := order[from]

	t, okT := order[to]
	if !okF || !okT {
		return false
	}

	return t > f
}

// checkExposeVisibility validates whether setting a component's visibility via
// xsl:expose is allowed. Returns an error code and message, or "" if valid.
// Rules:
//   - XTSE3010: declared visibility is explicitly set and expose tries to change
//     it to a different "kind" (e.g., public→abstract) or to a higher level.
func checkExposeVisibility(name, newVis, declaredVis string) (string, string) {
	effectiveVis := declaredVis
	if effectiveVis == "" {
		effectiveVis = visPrivate // default for package components
	}
	// XTSE3025: cannot make a non-abstract component abstract
	if newVis == visAbstract && effectiveVis != visAbstract {
		return errCodeXTSE3025, fmt.Sprintf(
			"xsl:expose: cannot change visibility of %q from %s to abstract", name, effectiveVis)
	}
	// XTSE3010: cannot change an abstract component to non-abstract
	if effectiveVis == visAbstract && newVis != visAbstract {
		return errCodeXTSE3010, fmt.Sprintf(
			"xsl:expose: cannot change visibility of abstract component %q to %s", name, newVis)
	}
	// XTSE3010: cannot increase visibility beyond declared level.
	// public→final is allowed (restricting overridability is not an increase).
	// final→public is NOT allowed (removing restriction is an increase).
	if declaredVis != "" && newVis != declaredVis {
		if isVisibilityIncrease(declaredVis, newVis) {
			return errCodeXTSE3010, fmt.Sprintf(
				"xsl:expose: cannot change visibility of %q from %s to %s", name, declaredVis, newVis)
		}
	}

	return "", ""
}

// componentNameMatches checks if a component name matches a name pattern.
// Patterns: "*" matches all, "{ns}*" matches all in namespace, "*:local" matches
// any namespace with that local name, "{ns}local" matches exactly.
func componentNameMatches(compName, pattern string) bool {
	if pattern == xslWildcard {
		return true
	}

	patternArity := ""
	if idx := strings.LastIndex(pattern, "#"); idx >= 0 {
		patternArity = pattern[idx:]
		pattern = pattern[:idx]
	}

	compArity := ""

	compNameBase := compName
	if idx := strings.LastIndex(compName, "#"); idx >= 0 {
		compArity = compName[idx:]
		compNameBase = compName[:idx]
	}

	// If pattern has arity, it must match
	if patternArity != "" && patternArity != compArity {
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

func applyExposeVisibilityMap(values, declared map[string]string, pattern, visibility string) (bool, error) {
	matched := false
	wildcard := isWildcard(pattern)

	for name := range values {
		if !componentNameMatches(name, pattern) {
			continue
		}

		allowed, err := exposeVisibilityAllowed(name, visibility, declared[name], wildcard)
		if err != nil {
			return false, err
		}

		if allowed {
			values[name] = visibility
			matched = true
		}
	}

	return matched, nil
}

// exposeVisibilityAllowed reports declaration conflicts for explicit patterns;
// wildcard patterns skip visibility increases, retaining hard abstract errors.
func exposeVisibilityAllowed(name, visibility, declared string, wildcard bool) (bool, error) {
	code, message := checkExposeVisibility(name, visibility, declared)
	if !wildcard || code == errCodeXTSE3025 {
		if code != "" {
			return false, staticError(code, "%s", message)
		}
	}

	if wildcard && declared != "" && isVisibilityIncrease(declared, visibility) {
		return false, nil
	}

	return true, nil
}

func isWildcard(pattern string) bool {
	return pattern == xslWildcard || strings.HasSuffix(pattern, "}*") || strings.HasPrefix(pattern, "*:")
}

// functionVisKey creates a visibility map key for a function (name#arity).
func functionVisKey(qn xpath.QualifiedName, arity int) string {
	return fmt.Sprintf("{%s}%s#%d", qn.URI, qn.Name, arity)
}
