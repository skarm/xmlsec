// Derived from lestrrat-go/helium at 7362c0a70122a757780f4d0b545a9b370dead6ab.
// Copyright (c) 2015 lestrrat. MIT License; see licenses/MIT-helium.txt at the repository root.

package xslt

import (
	"context"
	"fmt"
	"strings"

	"github.com/skarm/xmlsec/transform/internal/xdm"
	"github.com/skarm/xmlsec/transform/internal/xdm/lexicon"
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
	if !ParseVersionConstraint(pkgVersion).valid {
		return staticError(errCodeXTSE3000, "invalid package version range %q", pkgVersion)
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
	if err := c.mergePackageComponents(ctx, pkgSS, elem, oset); err != nil {
		return err
	}

	return nil
}

// mergePackageComponents merges components from a used package into the
// current stylesheet, respecting visibility and xsl:accept rules.
func (c *compiler) mergePackageComponents(ctx context.Context, pkg *Stylesheet, usePackageElem *xdm.Element, oset *overrideSet) error {
	nsBindings := c.collectElemNamespaces(ctx, usePackageElem)

	acceptRules := parseAcceptRules(usePackageElem, nsBindings)
	for _, rule := range acceptRules {
		if rule.component == xslWildcard && !isWildcard(rule.names) {
			return staticError(errCodeXTSE3032,
				"xsl:accept with component='*' requires names to be a wildcard, got %q", rule.names)
		}
	}

	var excluded map[*xdm.Element]struct{}
	if oset != nil {
		excluded = oset.excluded
	}

	overrideNames := c.collectOverrideNames(ctx, usePackageElem, nsBindings, excluded)
	if err := c.validatePackageOverrideConflicts(oset); err != nil {
		return err
	}

	if err := c.validatePackageAcceptVisibility(pkg, acceptRules); err != nil {
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

	c.mergePackageParams(pkg, acceptRules)
	// Keys, decimal formats and named outputs remain package-scoped and are
	// obtained by package code through their effective* accessors.
	if err := c.mergePackageModes(pkg, acceptRules); err != nil {
		return err
	}

	c.mergePackageAccumulators(pkg)
	c.mergePackageAttributeSets(pkg, acceptRules, overrideNames)
	c.mergePackageOverrides(pkg, oset)

	return nil
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
			for _, v := range c.stylesheet.globalVars {
				if v.Name == name && v.OwnerPackage == nil {
					return staticError(errCodeXTSE3055,
						"override variable %q conflicts with a local variable of the same name", name)
				}
			}
		}
	}

	return nil
}

func (c *compiler) validatePackageAcceptVisibility(pkg *Stylesheet, acceptRules []acceptRule) error {
	// XTSE3040 excludes wildcard tokens from visibility compatibility checks.
	for _, rule := range acceptRules {
		if isWildcard(rule.names) {
			continue
		}

		for _, tmpl := range pkg.templates {
			if tmpl.Name == "" {
				continue
			}

			if err := validateAcceptedPackageComponent(pkg, rule, xslElemTemplate, tmpl.Name); err != nil {
				return err
			}
		}

		for key, fn := range pkg.functions {
			if err := validateAcceptedPackageComponent(pkg, rule, xslElemFunction, functionVisKey(key.Name, len(fn.Params))); err != nil {
				return err
			}
		}

		for _, variable := range pkg.globalVars {
			if err := validateAcceptedPackageComponent(pkg, rule, xslElemVariable, variable.Name); err != nil {
				return err
			}
		}
	}

	return nil
}

func validateAcceptedPackageComponent(pkg *Stylesheet, rule acceptRule, kind, name string) error {
	if rule.component != xslWildcard && rule.component != kind {
		return nil
	}

	if !componentNameMatches(name, rule.names) {
		return nil
	}

	visibility := getComponentVisibility(pkg, kind, name)
	if !isAcceptVisibilityCompatible(visibility, rule.visibility) {
		return staticError(errCodeXTSE3040,
			"xsl:accept: visibility %q is incompatible with component %q (declared %s)",
			rule.visibility, name, visibility)
	}

	return nil
}

// isAcceptVisibilityCompatible checks whether changing a component's visibility
// from 'declared' to 'accepted' is allowed by the XSLT 3.0 spec §3.6.2.
// The rule: xsl:accept cannot increase the visibility of a component.
// private → public/final/abstract is not allowed.
// final → public is not allowed.
// hidden is always allowed (decreasing).
func isAcceptVisibilityCompatible(declared, accepted string) bool {
	if accepted == visHidden {
		return true // hiding is always allowed
	}
	// Cannot make private component visible (public/final/abstract)
	if declared == visPrivate && (accepted == visPublic || accepted == visFinal || accepted == visAbstract) {
		return false
	}
	// Cannot make final component public or abstract
	if declared == visFinal && (accepted == visPublic || accepted == visAbstract) {
		return false
	}
	// Cannot make non-abstract component abstract
	if declared != visAbstract && accepted == visAbstract {
		return false
	}

	return true
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

func splitOverrideKey(key string) []string {
	typ, name, ok := strings.Cut(key, ":")
	if !ok {
		return nil
	}

	return []string{typ, name}
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
	if tmpl.Name != "" {
		pkgVis := getComponentVisibility(pkg, xslElemTemplate, tmpl.Name)
		if !isVisibleFromOutside(pkgVis) {
			return nil // private components are not merged
		}
		// Apply accept rules
		if len(acceptRules) > 0 {
			acceptVis := applyAcceptRules(xslElemTemplate, tmpl.Name, acceptRules, pkgVis)
			if acceptVis == visHidden {
				return nil
			}

			tmpl.Visibility = acceptVis
		}
	}

	if tmpl.Name != "" {
		if _, overridden := overrideNames[xslElemTemplate+":"+tmpl.Name]; overridden {
			return nil
		}
	}

	// XTSE3050: local template with same name as package component
	if tmpl.Name != "" {
		if _, local := c.localTemplateNames[tmpl.Name]; local {
			return staticError(errCodeXTSE3050,
				"local template %q conflicts with public component from used package", tmpl.Name)
		}
	}

	tmpl.ImportPrec = c.importPrec - 1
	tmpl.MinImportPrec = tmpl.ImportPrec // package templates have no sub-imports
	tmpl.OwnerPackage = pkg

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

	if tmpl.Match != nil {
		rules := templateRules(tmpl)
		for _, mode := range resolveTemplateModes(tmpl.Mode) {
			c.stylesheet.modeTemplates[mode] = append(c.stylesheet.modeTemplates[mode], rules...)
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

		if len(acceptRules) > 0 {
			acceptVis := applyAcceptRules(xslElemFunction, key, acceptRules, pkgVis)
			if acceptVis == visHidden {
				continue
			}

			fn.Visibility = acceptVis
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

		if len(acceptRules) > 0 {
			acceptVis := applyAcceptRules(xslElemVariable, v.Name, acceptRules, pkgVis)
			if acceptVis == visHidden {
				continue
			}

			v.Visibility = acceptVis
		}
		// XTSE3050: local variable with same name as package component
		if _, local := c.localVarNames[v.Name]; local {
			return staticError(errCodeXTSE3050,
				"local variable %q conflicts with public component from used package", v.Name)
		}

		v.OwnerPackage = pkg
		c.stylesheet.globalVars = append(c.stylesheet.globalVars, v)
	}

	return nil
}

func (c *compiler) mergePackageParams(pkg *Stylesheet, acceptRules []acceptRule) {
	// Merge global params
	for _, p := range pkg.globalParams {
		pkgVis := getComponentVisibility(pkg, xslElemVariable, p.Name)
		if !isVisibleFromOutside(pkgVis) {
			continue
		}

		if len(acceptRules) > 0 {
			acceptVis := applyAcceptRules(xslElemVariable, p.Name, acceptRules, pkgVis)
			if acceptVis == visHidden {
				continue
			}
		}

		c.stylesheet.globalParams = append(c.stylesheet.globalParams, p)
	}
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

			if len(acceptRules) > 0 {
				acceptVis := applyAcceptRules(xslElemMode, name, acceptRules, md.Visibility)
				if acceptVis == visHidden {
					continue
				}

				md.Visibility = acceptVis
			}
			// XTSE3050: local mode with same name as package mode
			if _, local := c.localModeNames[name]; local {
				return staticError(errCodeXTSE3050,
					"local mode %q conflicts with public component from used package", name)
			}

			if _, exists := c.stylesheet.modeDefs[name]; !exists {
				c.stylesheet.modeDefs[name] = md
			}
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
	// Merge attribute sets. Private attribute-sets are also merged (for
	// package-internal use-attribute-sets references) but keep their visibility.
	if pkg.attributeSets != nil {
		if c.stylesheet.attributeSets == nil {
			c.stylesheet.attributeSets = make(map[string]*attributeSetDef)
		}

		for name, as := range pkg.attributeSets {
			if _, overridden := overrideNames[xslElemAttributeSet+":"+name]; overridden {
				continue
			}

			pkgVis := getComponentVisibility(pkg, xslElemAttributeSet, name)
			if len(acceptRules) > 0 {
				acceptVis := applyAcceptRules(xslElemAttributeSet, name, acceptRules, pkgVis)
				if acceptVis == visHidden {
					// Mark as hidden but still merge so that package-
					// internal use-attribute-sets references resolve.
					as.Visibility = visHidden
				}
			}

			as.OwnerPackage = pkg
			if _, exists := c.stylesheet.attributeSets[name]; !exists {
				c.stylesheet.attributeSets[name] = as
			}
		}
	}
}

func (c *compiler) mergePackageOverrides(pkg *Stylesheet, oset *overrideSet) {
	// Merge override components (these replace the originals).
	// Override functions/templates/variables also replace the entries in the
	// package's own maps so that package-internal calls dispatch to the
	// override (XSLT 3.0 late-binding / virtual-dispatch semantics).
	if oset == nil {
		return
	}

	for qn, fn := range oset.functions {
		c.stylesheet.functions[qn] = fn
		// Update the package's function map for late binding.
		// Package-internal calls dispatch to the override.
		pkg.functions[qn] = fn
	}

	for name, tmpl := range oset.namedTemplates {
		tmpl.ImportPrec = c.importPrec - 1
		tmpl.OwnerPackage = pkg
		c.stylesheet.templates = append(c.stylesheet.templates, tmpl)
		c.stylesheet.namedTemplates[name] = tmpl
		// Update the package's own named template map for late binding
		pkg.namedTemplates[name] = tmpl
	}

	for _, tmpl := range oset.matchTemplates {
		tmpl.ImportPrec = c.importPrec - 1
		tmpl.OwnerPackage = pkg
		// A template with both a name and a match is already in
		// templates from the namedTemplates loop above. Adding it again
		// would make a package that uses this one register its rules
		// twice, and two splits of one union rule would then conflict
		// under on-multiple-match="fail".
		if tmpl.Name == "" || oset.namedTemplates[tmpl.Name] != tmpl {
			c.stylesheet.templates = append(c.stylesheet.templates, tmpl)
		}

		rules := templateRules(tmpl)
		// Resolve mode list: may be multi-mode (e.g. "m3 m4")
		for _, mode := range resolveTemplateModes(tmpl.Mode) {
			c.stylesheet.modeTemplates[mode] = append(c.stylesheet.modeTemplates[mode], rules...)
			// Update the package's mode template list for late binding
			pkg.modeTemplates[mode] = append(pkg.modeTemplates[mode], rules...)
		}
	}

	for _, v := range oset.variables {
		c.stylesheet.globalVars = append(c.stylesheet.globalVars, v)
		// Update the package's own global vars for late binding
		for i, pv := range pkg.globalVars {
			if pv.Name == v.Name {
				pkg.globalVars[i] = v
				break
			}
		}
	}

	for _, p := range oset.params {
		c.stylesheet.globalParams = append(c.stylesheet.globalParams, p)
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
