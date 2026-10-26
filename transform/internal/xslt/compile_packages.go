// Derived from lestrrat-go/helium at 7362c0a70122a757780f4d0b545a9b370dead6ab.
// Copyright (c) 2015 lestrrat. MIT License; see licenses/MIT-helium.txt at the repository root.

package xslt

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/skarm/xmlsec/internal/lexicon"
	"github.com/skarm/xmlsec/transform/internal/xdm"
	"github.com/skarm/xmlsec/transform/internal/xpath"
)

// compileUsePackage handles xsl:use-package by resolving and compiling the
// referenced package, then merging its public components into the current
// stylesheet.
func (c *compiler) compileUsePackage(ctx context.Context, elem *xdm.Element) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	pkgName := getAttr(elem, xslAttrName)
	if pkgName == "" {
		return staticError(errCodeXTSE0010, "xsl:use-package requires name attribute")
	}

	pkgVersion := getAttr(elem, namePackageVersion)
	if !ParseVersionConstraint(pkgVersion).Valid() {
		return staticError(errCodeXTSE0020, "invalid package version range %q", pkgVersion)
	}

	acceptRules, err := parseAcceptRules(ctx, elem)
	if err != nil {
		return err
	}

	if c.packageResolver == nil {
		return staticError(errCodeXTSE3000,
			"xsl:use-package requires a PackageResolver but none is configured (package %q)", pkgName)
	}

	rc, pkgBaseURI, err := c.packageResolver.ResolvePackage(ctx, pkgName, pkgVersion)
	if err != nil {
		return staticErrorCause(errCodeXTSE3000, err,
			"xsl:use-package: cannot resolve package %q version %q: %v", pkgName, pkgVersion, err)
	}

	doc, err := parseXMLResource(ctx, c.parseOptions, rc, pkgBaseURI, c.maxResourceBytes)
	if err != nil {
		return fmt.Errorf("xsl:use-package: cannot parse package %q: %w", pkgName, err)
	}

	if err := checkResolvedPackage(doc, pkgName, pkgVersion); err != nil {
		return err
	}

	// Compile the package with its own compiler
	pkgCfg := &compileConfig{
		processorVersion: c.stylesheet.processorLanguage(),
		baseURI:          pkgBaseURI,
		resolver:         c.resolver,
		packageResolver:  c.packageResolver,
		isSubPackage:     true,
		maxResourceBytes: c.maxResourceBytes,

		parseOptions: c.parseOptions,
	}

	pkgSS, err := compile(ctx, doc, pkgCfg)
	if err != nil {
		return fmt.Errorf("xsl:use-package: cannot compile package %q: %w", pkgName, err)
	}

	if err := checkCompiledPackage(pkgSS, pkgName, pkgVersion); err != nil {
		return err
	}

	c.stylesheet.usedPackages = append(c.stylesheet.usedPackages, pkgSS)

	// Carry over the used package's backwards-compatible expression set: its
	// component pointers are merged into this stylesheet, so isCompatExpr (which
	// only consults c.stylesheet) must see the package's compat expressions too.
	for e := range pkgSS.compatExprs {
		c.markCompatExpr(e)
	}

	oset, err := c.processOverrides(ctx, elem, pkgSS)
	if err != nil {
		return err
	}

	// Merge components from the package, respecting visibility, xsl:accept rules, and overrides.
	if err := c.mergePackageComponents(ctx, pkgSS, elem, oset, acceptRules); err != nil {
		return err
	}

	return nil
}

// mergePackageComponents merges components from a used package into the
// current stylesheet, respecting visibility and xsl:accept rules.
func (c *compiler) mergePackageComponents(ctx context.Context, pkg *Stylesheet, usePackageElem *xdm.Element, oset *overrideSet, acceptRules []acceptRule) error {
	nsBindings := c.collectElemNamespaces(ctx, usePackageElem)

	var excluded map[*xdm.Element]struct{}
	if oset != nil {
		excluded = oset.excluded
	}

	overrideNames := c.collectOverrideNames(ctx, usePackageElem, nsBindings, excluded)
	if err := c.validatePackageOverrideConflicts(oset); err != nil {
		return err
	}

	if err := c.validatePackageAcceptVisibility(ctx, pkg, acceptRules); err != nil {
		return err
	}

	if err := c.validatePackageAcceptOverrides(acceptRules, overrideNames); err != nil {
		return err
	}

	if err := c.mergePackageTemplates(pkg, acceptRules, overrideNames); err != nil {
		return err
	}

	if err := c.mergePackageFunctions(pkg, acceptRules, overrideNames); err != nil {
		return err
	}

	if err := c.mergePackageVariables(pkg, acceptRules, overrideNames); err != nil {
		return err
	}

	if err := c.mergePackageParams(pkg, overrideNames); err != nil {
		return err
	}
	// Keys, decimal formats and named outputs remain package-scoped and are
	// obtained by package code through their effective* accessors.
	if err := c.mergePackageModes(pkg, acceptRules); err != nil {
		return err
	}

	c.mergePackageAccumulators(pkg)
	c.mergePackageAttributeSets(pkg, acceptRules, overrideNames)

	return c.mergePackageOverrides(ctx, pkg, oset)
}

func (c *compiler) validatePackageOverrideConflicts(oset *overrideSet) error {
	// XTSE3055: it is a static error if an override declaration is homonymous
	// with any other declaration in the using package, regardless of import
	// precedence.
	if oset != nil {
		for name := range oset.namedTemplates {
			if _, exists := c.localTemplateNames[name]; exists {
				return staticError(errCodeXTSE3055,
					"override template %q conflicts with a local template of the same name", name)
			}
		}

		for fk := range oset.functions {
			if _, exists := c.stylesheet.functions[fk]; exists {
				return staticError(errCodeXTSE3055,
					"override function %s#%d conflicts with a local function of the same name",
					fmt.Sprintf("{%s}%s", fk.Name.URI, fk.Name.Name), fk.Arity)
			}
		}

		for name := range oset.variables {
			if _, local := c.localVarNames[name]; local {
				return staticError(errCodeXTSE3055,
					"override variable %q conflicts with a local variable of the same name", name)
			}
		}

		for name := range oset.params {
			if _, local := c.localVarNames[name]; local {
				return staticError(errCodeXTSE3055, "override parameter %q conflicts with a local declaration", name)
			}
		}
	}

	return nil
}

func (c *compiler) validatePackageAcceptVisibility(ctx context.Context, pkg *Stylesheet, rules []acceptRule) error {
	components := packageComponents(pkg)

	for _, rule := range rules {
		wildcard, matched := isWildcard(rule.names), false

		for _, component := range components {
			if err := xpath.Charge(ctx, 1); err != nil {
				return err
			}

			if wildcard || rule.component != xslWildcard && rule.component != component.kind || !componentNameMatches(component.name, rule.names) {
				continue
			}

			matched = true

			if !isAcceptVisibilityCompatible(component.visibility, rule.visibility) {
				return staticError(errCodeXTSE3040, "xsl:accept: visibility %q is incompatible with %s %q (declared %s)", rule.visibility, component.kind, component.name, component.visibility)
			}
		}

		if !wildcard && !matched {
			return staticError(errCodeXTSE3030, "xsl:accept: no %s matches %q", rule.component, rule.names)
		}
	}

	return nil
}

func (c *compiler) validatePackageAcceptOverrides(acceptRules []acceptRule, overrideNames map[string]struct{}) error {
	// XTSE3051: it is a static error if a non-wildcard token in the names
	// attribute of xsl:accept matches the symbolic name of a component
	// declared within an xsl:override child of the same xsl:use-package.
	if len(acceptRules) > 0 && len(overrideNames) > 0 {
		for _, rule := range acceptRules {
			if isWildcard(rule.names) {
				continue // wildcards are exempt
			}

			for overKey := range overrideNames {
				// overKey is "type:name" (e.g., "template:t-public")
				parts := splitOverrideKey(overKey)
				if parts == nil {
					continue
				}

				overType, overName := parts[0], parts[1]
				if rule.component != xslWildcard && rule.component != overType {
					continue
				}

				if componentNameMatches(overName, rule.names) {
					return staticError(errCodeXTSE3051,
						"xsl:accept name %q matches overridden component %q", rule.names, overName)
				}
			}
		}
	}

	return nil
}

func (c *compiler) mergePackageTemplates(pkg *Stylesheet, acceptRules []acceptRule, overrideNames map[string]struct{}) error {
	for _, tmpl := range pkg.templates {
		if err := c.mergePackageTemplate(pkg, tmpl, acceptRules, overrideNames); err != nil {
			return err
		}
	}

	return nil
}

func (c *compiler) mergePackageTemplate(pkg *Stylesheet, tmpl *template, acceptRules []acceptRule, overrideNames map[string]struct{}) error {
	// A named template and its match rules are separate declarations. Rules
	// belong to their mode even when the template's name is private or hidden.
	// Accepted modes retain their own rule lists; only the name is merged here.
	if tmpl.Name == "" {
		return nil
	}

	accepted := *tmpl
	tmpl = &accepted

	pkgVis := getComponentVisibility(pkg, xslElemTemplate, tmpl.Name)
	if !isVisibleFromOutside(pkgVis) {
		return nil
	}

	tmpl.Visibility = applyAcceptRules(xslElemTemplate, tmpl.Name, acceptRules, pkgVis)
	if tmpl.Visibility == visHidden {
		return nil
	}

	if _, overridden := overrideNames[xslElemTemplate+":"+tmpl.Name]; overridden {
		return nil
	}

	if _, local := c.localTemplateNames[tmpl.Name]; local {
		return staticError(errCodeXTSE3050,
			"local template %q conflicts with public component from used package", tmpl.Name)
	}

	tmpl.ImportPrec = c.importPrec - 1

	tmpl.MinImportPrec = tmpl.ImportPrec // package templates have no sub-imports
	if tmpl.OwnerPackage == nil {
		tmpl.OwnerPackage = pkg
	}

	c.stylesheet.templates = append(c.stylesheet.templates, tmpl)
	if tmpl.Name != "" {
		if existing, exists := c.stylesheet.namedTemplates[tmpl.Name]; !exists {
			c.stylesheet.namedTemplates[tmpl.Name] = tmpl
		} else if existing.OwnerPackage != nil && existing.OwnerPackage != pkg {
			// XTSE3050: two use-packages accept homonymous components
			// with non-hidden visibility.
			return staticError(errCodeXTSE3050,
				"template %q accepted from multiple packages with non-hidden visibility",
				tmpl.Name)
		}
	}

	return nil
}

func (c *compiler) mergePackageFunctions(pkg *Stylesheet, acceptRules []acceptRule, overrideNames map[string]struct{}) error {
	// Merge functions
	for fk, fn := range pkg.functions {
		key := functionVisKey(fk.Name, len(fn.Params))

		pkgVis := getComponentVisibility(pkg, xslElemFunction, key)
		if !isVisibleFromOutside(pkgVis) {
			continue
		}

		accepted := *fn
		fn = &accepted

		fn.Visibility = applyAcceptRules(xslElemFunction, key, acceptRules, pkgVis)
		if fn.Visibility == visHidden {
			continue
		}

		if _, overridden := overrideNames[xslElemFunction+":"+key]; overridden {
			continue
		}

		if fn.OwnerPackage == nil {
			fn.OwnerPackage = pkg
		}

		fn.AcceptedFrom = pkg
		if existing, exists := c.stylesheet.functions[fk]; !exists {
			c.stylesheet.functions[fk] = fn
		} else if existing.AcceptedFrom != nil && existing.AcceptedFrom != pkg {
			// XTSE3050: two use-packages accept the same function
			// with non-hidden visibility.
			return staticError(errCodeXTSE3050,
				"function %q accepted from multiple packages with non-hidden visibility",
				key)
		}
	}

	return nil
}

func (c *compiler) mergePackageVariables(pkg *Stylesheet, acceptRules []acceptRule, overrideNames map[string]struct{}) error {
	// Merge global variables from the used package.
	for _, v := range pkg.globalVars {
		pkgVis := getComponentVisibility(pkg, xslElemVariable, v.Name)
		if _, overridden := overrideNames[xslElemVariable+":"+v.Name]; overridden {
			continue
		}

		if !isVisibleFromOutside(pkgVis) {
			continue
		}

		accepted := *v
		accepted.Declaration = v.binding().variable
		v = &accepted

		v.Visibility = applyAcceptRules(xslElemVariable, v.Name, acceptRules, pkgVis)
		if v.Visibility == visHidden {
			continue
		}

		// XTSE3050: local variable with same name as package component
		if _, local := c.localVarNames[v.Name]; local {
			return staticError(errCodeXTSE3050,
				"local variable %q conflicts with public component from used package", v.Name)
		}

		if v.OwnerPackage == nil {
			v.OwnerPackage = pkg
		}

		if err := c.checkAcceptedGlobalName(v.Name); err != nil {
			return err
		}

		c.stylesheet.globalVars = append(c.stylesheet.globalVars, v)
	}

	return nil
}

func (c *compiler) mergePackageParams(pkg *Stylesheet, overrides map[string]struct{}) error {
	for _, p := range pkg.globalParams {
		if p.IsStatic {
			continue
		}

		if _, overridden := overrides[xslElemVariable+":"+p.Name]; overridden {
			continue
		}

		if _, local := c.localVarNames[p.Name]; local {
			return staticError(errCodeXTSE3050, "local declaration conflicts with accepted parameter %q", p.Name)
		}

		if err := c.checkAcceptedGlobalName(p.Name); err != nil {
			return err
		}

		accepted := *p

		accepted.Declaration = p.binding().param
		if accepted.OwnerPackage == nil {
			accepted.OwnerPackage = pkg
		}

		c.stylesheet.globalParams = append(c.stylesheet.globalParams, &accepted)
	}

	return nil
}

func (c *compiler) checkAcceptedGlobalName(name string) error {
	if err := xpath.Charge(c.invocation, len(c.stylesheet.globalVars)+len(c.stylesheet.globalParams)+1); err != nil {
		return err
	}

	for _, v := range c.stylesheet.globalVars {
		if v.Name == name {
			return staticError(errCodeXTSE3050, "variable %q accepted more than once", name)
		}
	}

	for _, p := range c.stylesheet.globalParams {
		if p.Name == name {
			return staticError(errCodeXTSE3050, "parameter %q accepted more than once", name)
		}
	}

	return nil
}

func (c *compiler) mergePackageModes(pkg *Stylesheet, acceptRules []acceptRule) error {
	// Merge mode definitions
	if pkg.modeDefs != nil {
		if c.stylesheet.modeDefs == nil {
			c.stylesheet.modeDefs = make(map[string]*modeDef)
		}

		for name, md := range pkg.modeDefs {
			if !isVisibleFromOutside(md.Visibility) {
				continue
			}

			accepted := *md
			md = &accepted
			md.OwnerPackage = pkg.modePackage(name)

			md.Visibility = applyAcceptRules(xslElemMode, name, acceptRules, md.Visibility)
			if md.Visibility == visHidden {
				continue
			}

			// XTSE3050: local mode with same name as package mode
			if _, local := c.localModeNames[name]; local {
				return staticError(errCodeXTSE3050,
					"local mode %q conflicts with public component from used package", name)
			}

			if _, exists := c.stylesheet.modeDefs[name]; exists {
				return staticError(errCodeXTSE3050, "mode %q accepted from multiple packages", name)
			}

			c.stylesheet.modeDefs[name] = md
		}
	}

	return nil
}

func (c *compiler) mergePackageAccumulators(pkg *Stylesheet) {
	// Merge accumulators from the used package. Mark them as package-imported
	// so that a local accumulator with the same name can shadow them without
	// raising XTSE3350 (accumulators in different packages may share a name).
	for name, acc := range pkg.accumulators {
		if _, exists := c.stylesheet.accumulators[name]; !exists {
			acc.FromPackage = true
			c.stylesheet.accumulators[name] = acc
			c.stylesheet.accumulatorOrder = append(c.stylesheet.accumulatorOrder, name)
		}
	}
}

func (c *compiler) mergePackageAttributeSets(pkg *Stylesheet, acceptRules []acceptRule, overrideNames map[string]struct{}) {
	// Package-internal references use the original package map; only
	// accepted attribute sets enter the using package scope.
	if pkg.attributeSets != nil {
		if c.stylesheet.attributeSets == nil {
			c.stylesheet.attributeSets = make(map[string]*attributeSetDef)
		}

		for name, as := range pkg.attributeSets {
			if _, overridden := overrideNames[xslElemAttributeSet+":"+name]; overridden {
				continue
			}

			pkgVis := getComponentVisibility(pkg, xslElemAttributeSet, name)
			accepted := *as
			as = &accepted

			as.Visibility = applyAcceptRules(xslElemAttributeSet, name, acceptRules, pkgVis)
			if as.Visibility == visHidden {
				continue
			}

			as.OwnerPackage = pkg
			if _, exists := c.stylesheet.attributeSets[name]; !exists {
				c.stylesheet.attributeSets[name] = as
			}
		}
	}
}

func (c *compiler) mergePackageOverrides(ctx context.Context, pkg *Stylesheet, oset *overrideSet) error {
	// Merge override components (these replace the originals).
	// Override functions/templates/variables also replace the entries in the
	// package's own maps so that package-internal calls dispatch to the
	// override (XSLT 3.0 late-binding / virtual-dispatch semantics).
	if oset == nil {
		return nil
	}

	for qn, fn := range oset.functions {
		c.stylesheet.functions[qn] = fn
		// Update the package's function map for late binding.
		// Package-internal calls dispatch to the override.
		pkg.functions[qn] = fn
	}

	for name, tmpl := range oset.namedTemplates {
		tmpl.ImportPrec = c.importPrec - 1
		tmpl.OwnerPackage = c.stylesheet
		c.stylesheet.templates = append(c.stylesheet.templates, tmpl)
		c.stylesheet.namedTemplates[name] = tmpl
		// Update the package's own named template map for late binding
		pkg.namedTemplates[name] = tmpl
	}

	modeRules := make(map[string][]*template)

	for _, tmpl := range oset.matchTemplates {
		tmpl.OwnerPackage = c.stylesheet
		// A template with both a name and a match is already in
		// templates from the namedTemplates loop above. Adding it again
		// would make a package that uses this one register its rules
		// twice, and two splits of one union rule would then conflict
		// under on-multiple-match="fail".
		if tmpl.Name == "" || oset.namedTemplates[tmpl.Name] != tmpl {
			c.stylesheet.templates = append(c.stylesheet.templates, tmpl)
		}

		rules := templateRules(tmpl)
		for _, mode := range resolveTemplateModes(tmpl.Mode) {
			modeRules[mode] = append(modeRules[mode], rules...)
		}
	}

	for mode, rules := range modeRules {
		if err := extendPackageMode(ctx, pkg.modePackage(mode), mode, rules); err != nil {
			return err
		}
	}

	for _, v := range oset.variables {
		c.stylesheet.globalVars = append(c.stylesheet.globalVars, v)
		if err := replacePackageGlobal(ctx, pkg, v.Original, v.binding()); err != nil {
			return err
		}
	}

	for _, p := range oset.params {
		c.stylesheet.globalParams = append(c.stylesheet.globalParams, p)
		if err := replacePackageGlobal(ctx, pkg, p.Original, p.binding()); err != nil {
			return err
		}
	}

	for name, as := range oset.attributeSets {
		if c.stylesheet.attributeSets == nil {
			c.stylesheet.attributeSets = make(map[string]*attributeSetDef)
		}
		// Link original attribute-set for xsl:original support.
		// The original comes from the used package, not the
		// stylesheet (it was skipped during merge because it's
		// overridden).
		if pkg.attributeSets != nil {
			if origAS, ok := pkg.attributeSets[name]; ok {
				as.OriginalAttrSet = origAS
			}
		}

		c.stylesheet.attributeSets[name] = as
		// Update the package's own attribute set map for late binding
		if pkg.attributeSets == nil {
			pkg.attributeSets = make(map[string]*attributeSetDef)
		}

		pkg.attributeSets[name] = as
	}

	return nil
}

type acceptedComponent struct {
	kind       string
	name       string
	visibility string
}

func packageComponents(pkg *Stylesheet) []acceptedComponent {
	var components []acceptedComponent
	for name := range pkg.namedTemplates {
		components = append(components, acceptedComponent{xslElemTemplate, name, getComponentVisibility(pkg, xslElemTemplate, name)})
	}

	for key := range pkg.functions {
		name := functionVisKey(key.Name, key.Arity)
		components = append(components, acceptedComponent{xslElemFunction, name, getComponentVisibility(pkg, xslElemFunction, name)})
	}

	for _, v := range pkg.globalVars {
		components = append(components, acceptedComponent{xslElemVariable, v.Name, getComponentVisibility(pkg, xslElemVariable, v.Name)})
	}

	for name := range pkg.attributeSets {
		components = append(components, acceptedComponent{xslElemAttributeSet, name, getComponentVisibility(pkg, xslElemAttributeSet, name)})
	}

	for name := range pkg.modeDefs {
		if name != "" && name != modeDefault && name != modeUnnamed {
			components = append(components, acceptedComponent{xslElemMode, name, getComponentVisibility(pkg, xslElemMode, name)})
		}
	}

	return components
}

// isAcceptVisibilityCompatible implements the table in XSLT 3.0 3.5.3.2.
func isAcceptVisibilityCompatible(declared, accepted string) bool {
	switch declared {
	case visPublic:
		return accepted == visPublic || accepted == visPrivate || accepted == visFinal || accepted == visHidden
	case visFinal:
		return accepted == visPrivate || accepted == visFinal || accepted == visHidden
	case visAbstract:
		return accepted == visAbstract || accepted == visHidden
	default:
		return false
	}
}

func splitOverrideKey(key string) []string {
	typ, name, ok := strings.Cut(key, ":")
	if !ok {
		return nil
	}

	return []string{typ, name}
}

// modePackage identifies the rule list bound to a mode, independently of the
// lexical package of the template currently executing. Accepted modes retain
// this identity through re-exports and further overrides.
func (ss *Stylesheet) modePackage(mode string) *Stylesheet {
	if md := ss.modeDefs[mode]; md != nil && md.OwnerPackage != nil {
		return md.OwnerPackage
	}

	return ss
}

func extendPackageMode(ctx context.Context, pkg *Stylesheet, mode string, rules []*template) error {
	existing := pkg.modeTemplates[mode]
	if err := xpath.Charge(ctx, len(existing)+len(rules)); err != nil {
		return err
	}

	maxPrec := 0
	for _, rule := range existing {
		maxPrec = max(maxPrec, rule.ImportPrec)
	}

	// One using package is a precedence layer above every rule of the used
	// package. Within that layer, priority and declaration order still decide.
	added := make([]*template, 0, len(rules))
	for _, rule := range rules {
		copyRule := *rule
		copyRule.ImportPrec = maxPrec + 1
		copyRule.MinImportPrec = copyRule.ImportPrec // used packages are not stylesheet imports
		added = append(added, &copyRule)
	}

	slices.Reverse(added)
	slices.SortStableFunc(added, func(a, b *template) int {
		if a.Priority > b.Priority {
			return -1
		}

		if a.Priority < b.Priority {
			return 1
		}

		return 0
	})
	pkg.modeTemplates[mode] = append(added, existing...)
	// The package was already compiled and indexed before its using package
	// supplied these rules. Rebuild this index from the new final positions.
	if pkg.modeIndex == nil {
		pkg.modeIndex = make(map[string]*templateIndex)
	}

	pkg.modeIndex[mode] = buildTemplateIndex(pkg.modeTemplates[mode])

	return nil
}

// getComponentVisibility returns the effective visibility of a component.
// It checks the per-component visibility maps first, then falls back to
// the component's own Visibility field, then to the default.
func getComponentVisibility(pkg *Stylesheet, compType, compName string) string {
	var visibility map[string]string

	switch compType {
	case xslElemTemplate:
		visibility = pkg.templateVisibility
	case xslElemFunction:
		visibility = pkg.functionVisibility
	case xslElemVariable:
		if value, ok := pkg.variableVisibility[compName]; ok {
			return value
		}

		visibility = pkg.globalParamVisibility
	case xslElemAttributeSet:
		visibility = pkg.attrSetVisibility
	case xslElemMode:
		if mode, ok := pkg.modeDefs[compName]; ok && mode.Visibility != "" {
			return mode.Visibility
		}
	}

	if value, ok := visibility[compName]; ok {
		return value
	}

	return defaultComponentVisibility(pkg)
}

// isVisibleFromOutside returns true if the component's visibility allows
// it to be seen from a using stylesheet.
func isVisibleFromOutside(vis string) bool {
	return vis == visPublic || vis == visFinal || vis == visAbstract
}

// resolveTemplateModes splits a mode string into individual modes for
// registration in modeTemplates. Handles multi-mode ("m3 m4"), #all,
// #default, #unnamed, and the empty string (default mode).
func resolveTemplateModes(mode string) []string {
	if mode == modeAll {
		// A #all template applies to the default mode AND, via the modeAll
		// fallback key, to every named mode. Local templates register under
		// both "" and modeAll (see registerTemplateInModes); used-package
		// templates must follow the same path so they are eligible from
		// named modes, not only the default mode.
		return []string{"", modeAll}
	}

	fields := strings.Fields(mode)
	if len(fields) == 0 {
		return []string{mode}
	}

	if len(fields) == 1 {
		m := fields[0]
		if m == lexicon.ModeDefault || m == lexicon.ModeUnnamed {
			return []string{""}
		}

		return []string{m}
	}

	var modes []string

	for _, m := range fields {
		if m == lexicon.ModeDefault || m == lexicon.ModeUnnamed {
			m = ""
		}

		modes = append(modes, m)
	}

	return modes
}

// Redirect references to the overridden component throughout its package
// instance graph; homonymous private declarations retain their own bindings.
func replacePackageGlobal(ctx context.Context, pkg *Stylesheet, original, replacement globalBinding) error {
	stack := []*Stylesheet{pkg}
	seen := make(map[*Stylesheet]struct{})

	for len(stack) != 0 {
		current := stack[len(stack)-1]
		stack = stack[:len(stack)-1]

		if _, visited := seen[current]; visited {
			continue
		}

		if err := xpath.Charge(ctx, len(current.globalVars)+len(current.globalParams)+1); err != nil {
			return err
		}

		seen[current] = struct{}{}
		matched := false
		current.globalVars = slices.DeleteFunc(current.globalVars, func(v *variable) bool {
			if v.binding() == original {
				matched = true
				return true
			}

			return false
		})
		current.globalParams = slices.DeleteFunc(current.globalParams, func(p *param) bool {
			if p.binding() == original {
				matched = true
				return true
			}

			return false
		})

		if matched {
			if replacement.variable != nil {
				current.globalVars = append(current.globalVars, replacement.variable)
			} else {
				current.globalParams = append(current.globalParams, replacement.param)
			}
		}

		stack = append(stack, current.usedPackages...)
	}

	return nil
}
