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

type overrideSet struct {
	functions      map[funcKey]*xslFunction
	namedTemplates map[string]*template
	matchTemplates []*template
	variables      map[string]*variable
	params         map[string]*param
	attributeSets  map[string]*attributeSetDef
	// excluded holds the xsl:override elements and override declarations
	// that use-when="false()" removed; collectOverrideNames skips them.
	excluded map[*xdm.Element]struct{}
}

// standardAttrScope holds the compiler settings pushStandardAttrs replaced,
// so restoreStandardAttrs can put them back.
type standardAttrScope struct {
	nsBindings        map[string]string
	version           string
	xpathDefaultNS    string
	hasXPathDefaultNS bool
	expandText        bool
	defaultCollation  string
	defaultMode       string
}

// pendingOverrideTypeCheck is a deferred XTSE3070 same-type check for an
// xsl:override of a global variable whose required type is a custom schema type.
// It is resolved after all top-level declarations (including the using package's
// own xsl:import-schema) are compiled, so c.stylesheet.schemas is populated.
type pendingOverrideTypeCheck struct {
	varName    string
	overrideAs string
	overrideNS map[string]string
	baseAs     string
	basePkg    *Stylesheet
}

// processOverrides handles xsl:override children of xsl:use-package.
// It compiles the override children in the context of the package components,
// validates they match existing package components, and returns the override set.
func (c *compiler) processOverrides(ctx context.Context, usePackageElem *xdm.Element, pkg *Stylesheet) (*overrideSet, error) {
	oset := &overrideSet{
		functions:      make(map[funcKey]*xslFunction),
		namedTemplates: make(map[string]*template),
		variables:      make(map[string]*variable),
		params:         make(map[string]*param),
		attributeSets:  make(map[string]*attributeSetDef),
		excluded:       make(map[*xdm.Element]struct{}),
	}

	scope, err := c.pushStandardAttrs(ctx, usePackageElem)
	if err != nil {
		return nil, err
	}
	defer c.restoreStandardAttrs(scope)

	for child := range xdm.Children(usePackageElem) {
		elem, ok := child.(*xdm.Element)
		if !ok || elem.URI() != lexicon.NamespaceXSLT || elem.LocalName() != xslElemOverride {
			continue
		}

		if err := c.compileOverrideChildren(ctx, elem, pkg, oset); err != nil {
			return nil, err
		}
	}

	return oset, nil
}

// pushStandardAttrs brings elem's namespace declarations into scope and
// applies the standard attributes of xsl:use-package, xsl:override, or an
// overriding xsl:template ([xsl:]version, xpath-default-namespace,
// expand-text, default-collation, default-mode; XSLT 3.0 §3.5) to the
// compiler settings the elements inside inherit, and returns the settings it
// replaced. The namespace bindings are copied first, so neither these
// declarations nor any an inner element adds outlive the scope.
func (c *compiler) pushStandardAttrs(ctx context.Context, elem *xdm.Element) (standardAttrScope, error) {
	saved := standardAttrScope{
		nsBindings:        c.nsBindings,
		version:           c.effectiveVersion,
		xpathDefaultNS:    c.xpathDefaultNS,
		hasXPathDefaultNS: c.hasXPathDefaultNS,
		expandText:        c.expandText,
		defaultCollation:  c.defaultCollation,
		defaultMode:       c.defaultMode,
	}
	c.nsBindings = maps.Clone(c.nsBindings)
	c.pushElementNamespaces(ctx, elem)

	if et, ok := elem.GetAttribute(nameExpandText); ok {
		v, valid := parseXSDBool(et)
		if !valid {
			c.restoreStandardAttrs(saved)
			return saved, staticError(errCodeXTSE0020, "%q is not a valid value for xsl:%s/@expand-text", et, elem.LocalName())
		}

		c.expandText = v
	}

	if ver := elementXSLTVersion(elem); ver != "" {
		c.effectiveVersion = ver
	}

	if xdn, ok := elem.GetAttribute(nameXpathDefaultNamespace); ok {
		c.xpathDefaultNS = xdn
		c.hasXPathDefaultNS = true
	}

	if dc := getAttr(elem, nameDefaultCollation); dc != "" {
		if uri := resolveDefaultCollation(dc); uri != "" {
			c.defaultCollation = uri
		}
	}

	if dm := getAttr(elem, nameDefaultMode); dm != "" {
		c.defaultMode = c.resolveMode(ctx, dm)
	}

	return saved, nil
}

// restoreStandardAttrs puts back the compiler settings pushStandardAttrs
// replaced.
func (c *compiler) restoreStandardAttrs(s standardAttrScope) {
	c.nsBindings = s.nsBindings
	c.effectiveVersion = s.version
	c.xpathDefaultNS = s.xpathDefaultNS
	c.hasXPathDefaultNS = s.hasXPathDefaultNS
	c.expandText = s.expandText
	c.defaultCollation = s.defaultCollation
	c.defaultMode = s.defaultMode
}

func (c *compiler) compileOverrideChildren(ctx context.Context, overrideElem *xdm.Element, pkg *Stylesheet, oset *overrideSet) error {
	scope, err := c.pushStandardAttrs(ctx, overrideElem)
	if err != nil {
		return err
	}
	defer c.restoreStandardAttrs(scope)

	excluded, err := c.excludedByUseWhen(ctx, overrideElem)
	if err != nil {
		return err
	}

	if excluded {
		oset.excluded[overrideElem] = struct{}{}
		return nil
	}

	for child := range xdm.Children(overrideElem) {
		elem, ok := child.(*xdm.Element)
		if !ok {
			if child.Type() == xdm.TextNode || child.Type() == xdm.CDATASectionNode {
				if !isXMLWhitespaceOnly(xdm.CharacterData(child)) {
					return staticError(errCodeXTSE0010, "text is not allowed as a child of xsl:override")
				}
			}

			continue
		}

		if err := c.compileOverrideChild(ctx, elem, pkg, oset); err != nil {
			return err
		}
	}

	return nil
}

func (c *compiler) compileOverrideChild(ctx context.Context, elem *xdm.Element, pkg *Stylesheet, oset *overrideSet) error {
	if elem.URI() != lexicon.NamespaceXSLT {
		return staticError(errCodeXTSE0010,
			"non-XSLT element %q is not allowed inside xsl:override", elem.Name())
	}

	// Resolve shadow attributes (e.g. _version) so an override child's computed
	// values govern its compilation, mirroring top-level elements.
	if err := c.resolveShadowAttributes(ctx, elem); err != nil {
		return err
	}

	// A use-when="false()" declaration is removed before compilation, so
	// it neither overrides anything nor counts toward XTSE3055.
	c.collectNamespaces(ctx, elem)

	excluded, err := c.excludedByUseWhen(ctx, elem)
	if err != nil {
		return err
	}

	if excluded {
		oset.excluded[elem] = struct{}{}
		return nil
	}

	return c.compileOverrideComponent(ctx, elem, pkg, oset)
}

func (c *compiler) compileOverrideComponent(ctx context.Context, elem *xdm.Element, pkg *Stylesheet, oset *overrideSet) error {
	switch elem.LocalName() {
	case xslElemFunction:
		fn, qn, err := c.compileOverrideFunction(ctx, elem, pkg)
		if err != nil {
			return err
		}

		fk := funcKey{Name: qn, Arity: len(fn.Params)}
		if _, dup := oset.functions[fk]; dup {
			return staticError(errCodeXTSE0770,
				"duplicate override of function %s#%d in xsl:override",
				fmt.Sprintf("{%s}%s", qn.URI, qn.Name), len(fn.Params))
		}

		oset.functions[fk] = fn

	case xslElemTemplate:
		tmpl, err := c.compileOverrideTemplate(ctx, elem, pkg)
		if err != nil {
			return err
		}

		if tmpl.Name != "" {
			if err := c.claimOverrideDecl(xslElemTemplate, tmpl.Name); err != nil {
				return err
			}

			oset.namedTemplates[tmpl.Name] = tmpl
		}

		if tmpl.Match != nil {
			oset.matchTemplates = append(oset.matchTemplates, tmpl)
		}

	case xslElemVariable:
		v, err := c.compileOverrideVariable(ctx, elem, pkg)
		if err != nil {
			return err
		}

		if err := c.claimOverrideDecl(xslElemVariable, v.Name); err != nil {
			return err
		}

		oset.variables[v.Name] = v

	case xslElemParam:
		p, err := c.compileOverrideParam(ctx, elem, pkg)
		if err != nil {
			return err
		}
		// Variables and parameters share one symbol space.
		if err := c.claimOverrideDecl(xslElemVariable, p.Name); err != nil {
			return err
		}

		oset.params[p.Name] = p

	case xslElemAttributeSet:
		as, err := c.compileOverrideAttributeSet(ctx, elem, pkg)
		if err != nil {
			return err
		}

		if err := c.claimOverrideDecl(xslElemAttributeSet, as.Name); err != nil {
			return err
		}

		oset.attributeSets[as.Name] = as

	default:
		return staticError(errCodeXTSE0010,
			"xsl:override may only contain template, function, variable, param, or attribute-set; got xsl:%s",
			elem.LocalName())
	}

	return nil
}

// excludedByUseWhen reports whether elem's use-when attribute evaluates to
// false, which removes the element from the stylesheet (XSLT 3.0 §3.13.1).
func (c *compiler) excludedByUseWhen(ctx context.Context, elem *xdm.Element) (bool, error) {
	uw := getAttr(elem, xslAttrUseWhen)
	if uw == "" {
		return false, nil
	}

	include, err := c.evaluateUseWhen(ctx, uw)
	if err != nil {
		return false, err
	}

	return !include, nil
}

// claimOverrideDecl records an xsl:override declaration of the given
// component kind and name. XTSE3055: a declaration inside xsl:override must
// not be homonymous with any other overriding declaration in the using
// package, whether under the same xsl:use-package or a different one.
func (c *compiler) claimOverrideDecl(kind, name string) error {
	key := kind + ":" + name
	if _, dup := c.overrideDecls[key]; dup {
		return staticError(errCodeXTSE3055,
			"xsl:override declares %s %q more than once in the using package", kind, name)
	}

	if c.overrideDecls == nil {
		c.overrideDecls = make(map[string]struct{})
	}

	c.overrideDecls[key] = struct{}{}

	return nil
}

func (c *compiler) compileOverrideFunction(ctx context.Context, elem *xdm.Element, pkg *Stylesheet) (*xslFunction, xpath.QualifiedName, error) {
	defer c.pushElementVersion(elem)()

	name := getAttr(elem, xslAttrName)
	if name == "" {
		return nil, xpath.QualifiedName{}, staticError(errCodeXTSE0110, "xsl:function in xsl:override requires name attribute")
	}

	c.collectNamespaces(ctx, elem)

	var qn xpath.QualifiedName

	if strings.HasPrefix(name, "Q{") {
		closeBrace := strings.IndexByte(name, '}')
		if closeBrace < 0 {
			return nil, xpath.QualifiedName{}, staticError(errCodeXTSE0010, "malformed EQName in xsl:function name %q", name)
		}

		uri := name[2:closeBrace]
		local := name[closeBrace+1:]
		qn = xpath.QualifiedName{URI: uri, Name: local}
	} else if prefix, local, ok := strings.Cut(name, ":"); ok {
		uri := c.nsBindings[prefix]
		if uri == "" {
			uri = c.stylesheet.namespaces[prefix]
		}

		if uri == "" {
			return nil, xpath.QualifiedName{}, staticError(errCodeXTSE0010, "unresolved namespace prefix %q in xsl:function name %q", prefix, name)
		}

		qn = xpath.QualifiedName{URI: uri, Name: local}
	} else {
		return nil, xpath.QualifiedName{}, staticError(errCodeXTSE0010, "xsl:function name %q must have a namespace prefix", name)
	}

	// Check that the function exists in the package (check by name, any arity)
	var pkgFn *xslFunction

	for fk, fn := range pkg.functions {
		if fk.Name == qn {
			pkgFn = fn
			break
		}
	}

	if pkgFn == nil {
		return nil, xpath.QualifiedName{}, staticError(errCodeXTSE3058,
			"xsl:override function %q not found in used package", name)
	}

	if pkgFn.Visibility == visFinal {
		return nil, xpath.QualifiedName{}, staticError(errCodeXTSE3070,
			"cannot override final function %q", name)
	}

	// XTSE3070: new-each-time on the override must match the base component.
	// The base defaults to "maybe" (empty string) when not specified.
	overrideNET := getAttr(elem, "new-each-time")
	if overrideNET != "" {
		baseNET := pkgFn.NewEachTime
		if baseNET == "" {
			baseNET = nameMaybe // default per spec
		}

		if overrideNET != baseNET {
			return nil, xpath.QualifiedName{}, staticError(errCodeXTSE3070,
				"override function %q: new-each-time=%q does not match base component value %q",
				name, overrideNET, baseNET)
		}
	}

	savedExpandText := c.expandText

	if et, hasET := elem.GetAttribute(nameExpandText); hasET {
		if v, ok := parseXSDBool(et); ok {
			c.expandText = v
		}
	}

	body, params, err := c.compileTemplateBody(ctx, elem)
	c.expandText = savedExpandText

	if err != nil {
		return nil, xpath.QualifiedName{}, err
	}

	fn := &xslFunction{
		Name:       qn,
		Params:     params,
		Body:       body,
		As:         getAttr(elem, "as"),
		Visibility: getAttr(elem, xslAttrVisibility),
		IsOverride: true,
	}
	fn.prepareCall()

	// Inherit the base component's visibility so that processExpose
	// in the using package does not default it to private. Abstract
	// becomes public since the override provides an implementation.
	if pkgFn.Visibility != "" {
		if pkgFn.Visibility == visAbstract {
			fn.Visibility = visPublic
		} else {
			fn.Visibility = pkgFn.Visibility
		}
	}

	// Link the original function for xsl:original() calls.
	// Try exact arity match first, then fall back to any match by name.
	exactKey := funcKey{Name: qn, Arity: len(params)}
	if orig, ok := pkg.functions[exactKey]; ok {
		fn.OriginalFunc = orig
	} else {
		fn.OriginalFunc = pkgFn
	}

	return fn, qn, nil
}

func (c *compiler) compileOverrideTemplate(ctx context.Context, elem *xdm.Element, pkg *Stylesheet) (*template, error) {
	if err := c.validateXSLTAttrs(ctx, elem, templateAllowedAttrs); err != nil {
		return nil, err
	}

	scope, err := c.pushStandardAttrs(ctx, elem)
	if err != nil {
		return nil, err
	}
	defer c.restoreStandardAttrs(scope)

	tmpl := &template{
		ImportPrec:       c.importPrec,
		MinImportPrec:    c.minImportPrec,
		BaseURI:          c.baseURI,
		XPathDefaultNS:   c.xpathDefaultNS,
		DefaultCollation: c.defaultCollation,
	}

	matchAttr := getAttr(elem, nameMatch2)
	if matchAttr != "" {
		p, err := c.compilePattern(matchAttr, elem, c.xpathDefaultNS, c.hasXPathDefaultNS)
		if err != nil {
			return nil, err
		}

		tmpl.Match = p
		// Defer function validation until after all xsl:function declarations are processed.
		c.pendingPatternValidations = append(c.pendingPatternValidations, pendingPatternValidation{p, matchAttr})
	}

	name, err := c.checkTemplateName(ctx, elem, matchAttr)
	if err != nil {
		return nil, err
	}

	tmpl.Name = name

	if err := c.checkTemplateMode(elem); err != nil {
		return nil, err
	}

	modeAttr := getAttr(elem, nameMode)
	if modeAttr != "" {
		tmpl.Mode = c.resolveMode(ctx, modeAttr)
	} else if tmpl.Match != nil && c.defaultMode != "" {
		// When no explicit mode is specified and a default-mode is active,
		// match templates use the default mode.
		tmpl.Mode = c.defaultMode
	}

	if prio := getAttr(elem, "priority"); prio != "" {
		f, err := parseTemplatePriority(prio)
		if err != nil {
			return nil, err
		}

		tmpl.Priority = f
		tmpl.explicitPriority = true
	} else if tmpl.Match != nil && len(tmpl.Match.Alternatives) == 1 {
		tmpl.Priority = tmpl.Match.Alternatives[0].priority
	}

	// XTSE3440: override match template can only use modes that are public
	// or abstract in the used package. Using a mode that doesn't exist in the
	// package, or a private/final/hidden mode, is a static error.
	if err := compileOverrideTemplateMatch(tmpl, pkg); err != nil {
		return nil, err
	}

	// Validate: named template must exist in package
	if tmpl.Name != "" {
		existing, exists := pkg.namedTemplates[tmpl.Name]
		if !exists {
			return nil, staticError(errCodeXTSE3058,
				"xsl:override template %q not found in used package", tmpl.Name)
		}

		if existing.Visibility == visFinal {
			return nil, staticError(errCodeXTSE3070,
				"cannot override final template %q", tmpl.Name)
		}

		pkgVis := getComponentVisibility(pkg, xslElemTemplate, tmpl.Name)
		if pkgVis == visPrivate || pkgVis == visHidden {
			return nil, staticError(errCodeXTSE3050,
				"cannot override %s template %q", pkgVis, tmpl.Name)
		}
	}

	ctxDecl, body, params, err := c.compileTemplateBodyEx(ctx, elem, false)
	if err != nil {
		return nil, err
	}

	tmpl.Params = params
	tmpl.Body = body

	tmpl.As = getAttr(elem, "as")
	if vis := getAttr(elem, xslAttrVisibility); vis != "" {
		tmpl.Visibility = vis
	}

	if ctxDecl != nil {
		tmpl.ContextItemAs = ctxDecl.as
		tmpl.ContextItemUse = ctxDecl.use
	}

	// XTSE3070: check type compatibility of override against base template.
	if err := compileOverrideTemplateName(tmpl, pkg); err != nil {
		return nil, err
	}

	return tmpl, nil
}

// checkOverrideTemplateCompat validates that an override template is compatible
// with the base template it replaces. XTSE3070 is raised when parameter types
// differ or new required parameters are added.
func checkOverrideTemplateCompat(override, base *template) error {
	// XTSE3070: check return type compatibility.
	// If both templates have 'as' attributes, they must be compatible
	// (the override's return type must be a subtype of the base's).
	if base.As != "" && override.As != "" && base.As != override.As {
		return staticError(errCodeXTSE3070,
			"override template %q return type %q does not match base type %q",
			override.Name, override.As, base.As)
	}

	// XTSE3070: check context-item compatibility.
	// The override must have the same context-item type and use as the base.
	if override.ContextItemAs != "" && override.ContextItemAs != base.ContextItemAs {
		return staticError(errCodeXTSE3070,
			"override template %q context-item type %q does not match base type %q",
			override.Name, override.ContextItemAs, base.ContextItemAs)
	}

	if override.ContextItemUse != "" && override.ContextItemUse != base.ContextItemUse {
		return staticError(errCodeXTSE3070,
			"override template %q context-item use %q does not match base use %q",
			override.Name, override.ContextItemUse, base.ContextItemUse)
	}

	baseParams := make(map[string]*param)
	for _, p := range base.Params {
		baseParams[p.Name] = p
	}

	for _, op := range override.Params {
		bp, exists := baseParams[op.Name]
		if !exists {
			// New parameter in override that doesn't exist in base
			if op.Required {
				return staticError(errCodeXTSE3070,
					"override template %q adds required parameter $%s not in base", override.Name, op.Name)
			}

			continue
		}

		if bp.As != "" && op.As != "" && bp.As != op.As {
			return staticError(errCodeXTSE3070,
				"override template %q parameter $%s type %q does not match base type %q",
				override.Name, op.Name, op.As, bp.As)
		}
	}

	return nil
}

// checkOverrideModeVisibility validates that a mode used by an override
// template is public/abstract in the used package.
func checkOverrideModeVisibility(mode, displayMode string, pkg *Stylesheet) error {
	if pkg.modeDefs != nil {
		if md, ok := pkg.modeDefs[mode]; ok {
			if md.Visibility == visFinal {
				return staticError(errCodeXTSE3060,
					"cannot override templates in final mode %q", displayMode)
			}

			if md.Visibility == visPrivate || md.Visibility == visHidden {
				return staticError(errCodeXTSE3440,
					"cannot override templates in %s mode %q", md.Visibility, displayMode)
			}

			return nil
		}
	}
	// Mode not defined in the package — check default visibility
	defVis := defaultComponentVisibility(pkg)
	if defVis == visPrivate {
		return staticError(errCodeXTSE3440,
			"mode %q is not defined in the used package (default visibility is private)", displayMode)
	}

	return nil
}

func compileOverrideTemplateModes(modes []string, tmpl *template, pkg *Stylesheet) error {
	for _, m := range modes {
		// Resolve special names to empty string for lookup
		if m == "#unnamed" || m == "#default" {
			m = ""
		}

		if err := checkOverrideModeVisibility(m, tmpl.Mode, pkg); err != nil {
			return err
		}
	}

	return nil
}

func compileOverrideTemplateName(tmpl *template, pkg *Stylesheet) error {
	if tmpl.Name != "" {
		if existing, ok := pkg.namedTemplates[tmpl.Name]; ok {
			if err := checkOverrideTemplateCompat(tmpl, existing); err != nil {
				return err
			}
			// Link the original template for xsl:original calls
			tmpl.OriginalTemplate = existing
			// Inherit the base component's visibility so that processExpose
			// in the using package does not default it to private. Abstract
			// becomes public since the override provides an implementation.
			if existing.Visibility != "" {
				if existing.Visibility == visAbstract {
					tmpl.Visibility = visPublic
				} else {
					tmpl.Visibility = existing.Visibility
				}
			}
		}
	}

	return nil
}

func compileOverrideTemplateMatch(tmpl *template, pkg *Stylesheet) error {
	if tmpl.Match != nil && tmpl.Mode != modeAll {
		modes := strings.Fields(tmpl.Mode)
		if len(modes) == 0 {
			// No explicit mode: check unnamed mode
			modes = []string{""}
		}

		if err := compileOverrideTemplateModes(modes, tmpl, pkg); err != nil {
			return err
		}
	}

	return nil
}

func (c *compiler) compileOverrideVariable(ctx context.Context, elem *xdm.Element, pkg *Stylesheet) (*variable, error) {
	// A static="yes" variable is a version-independent compile-time value (forced
	// non-compat even in a < 2.0 module); otherwise honor its version attribute.
	if xsdBoolTrue(getAttr(elem, nameStatic)) {
		defer c.pushStaticVersion()()
	} else {
		defer c.pushElementVersion(elem)()
	}

	name := getAttr(elem, xslAttrName)
	if name == "" {
		return nil, staticError(errCodeXTSE0110, "xsl:variable in xsl:override requires name attribute")
	}

	resolvedName := resolveQName(name, c.nsBindings)

	pkgVar, found := lookupOverrideVariable(pkg, resolvedName)
	if !found {
		return nil, staticError(errCodeXTSE3058,
			"xsl:override variable %q not found in used package", name)
	}

	effectiveVis := overrideVariableVisibility(pkg, pkgVar, resolvedName)
	if err := checkOverrideVariableVisibility(name, effectiveVis); err != nil {
		return nil, err
	}

	v := &variable{Name: resolvedName, As: getAttr(elem, "as"), Visibility: getAttr(elem, xslAttrVisibility)}

	// XTSE3070: the required type of the override must be the same as the base
	// variable's required type. A standard XSD/keyword type pair is compared
	// lexically. For a custom schema type (a named simpleType from
	// xsl:import-schema) the comparison is STRUCTURAL: the override's type is
	// resolved against the using package's schemas, the base's type against the
	// declaring package's schemas, and the two definitions are compared for type
	// identity (same builtin base, or same flattened union member-type set). This
	// is what distinguishes override-v-005 (u2 = union{time,dateTime,date} is the
	// same type as base u1 = union{date,time,dateTime}, accepted) from
	// override-v-006 (u6 = union{dateTime,date} is a different type, rejected).
	// The comparison only fires when BOTH names resolve to a definition we can
	// compare confidently; anything else is left un-flagged to avoid a false
	// XTSE3070.
	if err := c.checkOverrideVariableType(pkgVar, v, name, pkg); err != nil {
		return nil, err
	}

	inheritOverriddenVariable(v, pkgVar)

	// The override's own visibility attribute takes precedence over the
	// inherited base visibility. This allows e.g. visibility="private"
	// on the override to hide the variable from the using package.
	if overrideVis := getAttr(elem, xslAttrVisibility); overrideVis != "" {
		v.Visibility = overrideVis
	}

	selectAttr := getAttr(elem, xslAttrSelect)
	if selectAttr != "" {
		expr, err := c.compileXPath(selectAttr, c.nsBindings)
		if err != nil {
			return nil, err
		}

		v.Select = expr
	} else {
		body, err := c.compileChildren(ctx, elem)
		if err != nil {
			return nil, err
		}

		v.Body = body
	}

	return v, nil
}

func lookupOverrideVariable(pkg *Stylesheet, resolvedName string) (*variable, bool) {
	for _, v := range pkg.globalVars {
		if v.Name == resolvedName {
			return v, true
		}
	}

	for _, p := range pkg.globalParams {
		if p.Name == resolvedName {
			return nil, true
		}
	}

	return nil, false
}

func overrideVariableVisibility(pkg *Stylesheet, pkgVar *variable, resolvedName string) string {
	effectiveVis := ""
	if pkgVar != nil {
		effectiveVis = pkgVar.Visibility
	}

	if v, ok := pkg.variableVisibility[resolvedName]; ok {
		effectiveVis = v
	}

	if effectiveVis == "" {
		if v, ok := pkg.globalParamVisibility[resolvedName]; ok {
			effectiveVis = v
		}
	}

	return effectiveVis
}

func checkOverrideVariableVisibility(name, effectiveVis string) error {
	switch effectiveVis {
	case visFinal:
		return staticError(errCodeXTSE3060,
			"cannot override final variable %q", name)
	case visPrivate, visHidden:
		return staticError(errCodeXTSE3060,
			"cannot override %s variable %q", effectiveVis, name)
	}

	return nil
}

func inheritOverriddenVariable(v, pkgVar *variable) {
	// Link the original variable for $xsl:original references.
	// Inherit the base component's visibility so that processExpose
	// in the using package does not default it to private. Abstract
	// becomes public since the override provides an implementation.
	if pkgVar != nil {
		v.OriginalVar = pkgVar
		if pkgVar.Visibility != "" {
			if pkgVar.Visibility == visAbstract {
				v.Visibility = visPublic
			} else {
				v.Visibility = pkgVar.Visibility
			}
		}
	}
}

func (c *compiler) compileOverrideParam(ctx context.Context, elem *xdm.Element, pkg *Stylesheet) (*param, error) {
	// compileParamDef pushes the element version (exempting static="yes"), so no
	// outer push here — that would compat-mark a static override param's select.
	p, err := c.compileParamDef(ctx, elem)
	if err != nil {
		return nil, err
	}

	// Check that the param or variable exists in the package.
	// In XSLT 3.0, variables and parameters share the same component
	// namespace, so a param can override a variable (and vice versa).
	found := false

	for _, pp := range pkg.globalParams {
		if pp.Name == p.Name {
			found = true
			break
		}
	}

	if !found {
		for _, v := range pkg.globalVars {
			if v.Name == p.Name {
				found = true
				break
			}
		}
	}

	if !found {
		return nil, staticError(errCodeXTSE3058,
			"xsl:override param %q not found in used package", p.Name)
	}

	return p, nil
}

func (c *compiler) compileOverrideAttributeSet(ctx context.Context, elem *xdm.Element, pkg *Stylesheet) (*attributeSetDef, error) {
	defer c.pushElementVersion(elem)()

	name := getAttr(elem, xslAttrName)
	if name == "" {
		return nil, staticError(errCodeXTSE0110, "xsl:attribute-set in xsl:override requires name attribute")
	}

	resolvedName := resolveQName(name, c.nsBindings)

	if pkg.attributeSets == nil {
		return nil, staticError(errCodeXTSE3058,
			"xsl:override attribute-set %q not found in used package", name)
	}

	pkgAS, exists := pkg.attributeSets[resolvedName]
	if !exists {
		return nil, staticError(errCodeXTSE3058,
			"xsl:override attribute-set %q not found in used package", name)
	}

	// Check visibility: cannot override final/private/hidden attribute-set.
	// Effective visibility comes from xsl:expose (attrSetVisibility map) or
	// the declared visibility attribute on the xsl:attribute-set element.
	effectiveVis := ""
	if pkgAS != nil {
		effectiveVis = pkgAS.Visibility
	}

	if v, ok := pkg.attrSetVisibility[resolvedName]; ok {
		effectiveVis = v
	}

	switch effectiveVis {
	case visFinal:
		return nil, staticError(errCodeXTSE3060,
			"cannot override final attribute-set %q", name)
	case visPrivate, visHidden:
		return nil, staticError(errCodeXTSE3060,
			"cannot override %s attribute-set %q", effectiveVis, name)
	}

	asd := &attributeSetDef{Name: resolvedName}

	var useAttrSets []string

	if uas := getAttr(elem, nameUseAttributeSets); uas != "" {
		for n := range strings.FieldsSeq(uas) {
			resolved := resolveQName(n, c.nsBindings)
			asd.UseAttrSets = append(asd.UseAttrSets, resolved)
			useAttrSets = append(useAttrSets, resolved)
		}
	}

	var attrs []instruction

	for child := range xdm.Children(elem) {
		childElem, ok := child.(*xdm.Element)
		if !ok {
			continue
		}

		if childElem.URI() == lexicon.NamespaceXSLT && childElem.LocalName() == lexicon.XSLTElementAttribute {
			inst, err := c.compileAttribute(ctx, childElem)
			if err != nil {
				return nil, err
			}

			asd.Attrs = append(asd.Attrs, inst)
			attrs = append(attrs, inst)
		}
	}

	asd.Parts = []attributeSetPart{{UseAttrSets: useAttrSets, Attrs: attrs}}

	return asd, nil
}

// isStandardType returns true if the type name is a well-known XSD type
// (xs: prefix) or standard type keyword. Returns false for custom schema
// types defined via xsl:import-schema.
// checkPendingOverrideTypes runs the deferred XTSE3070 override-variable
// same-type checks after all top-level declarations have been compiled, so the
// using package's own xsl:import-schema types are available in
// c.stylesheet.schemas.
func (c *compiler) checkPendingOverrideTypes() error { return nil }

// checkOverrideVariableType rejects incompatible built-in types and defers
// structural comparison of user-defined types until the package is assembled.
func (c *compiler) checkOverrideVariableType(pkgVar, v *variable, name string, pkg *Stylesheet) error {
	if pkgVar != nil && v.As != "" && pkgVar.As != "" && v.As != pkgVar.As {
		if isStandardType(v.As) && isStandardType(pkgVar.As) {
			return staticError(errCodeXTSE3070,
				"override variable %q type %q does not match base type %q",
				name, v.As, pkgVar.As)
		}
		// Custom schema types are compared structurally, but the using package's
		// own xsl:import-schema declarations are not yet compiled at this point in
		// the pass (xsl:use-package precedes xsl:import-schema in the compile
		// order). Defer the comparison to the end of compilation, when
		// c.stylesheet.schemas is fully populated. The base package's schemas are
		// already available via the stable pkg pointer.
		c.pendingOverrideTypeChecks = append(c.pendingOverrideTypeChecks, pendingOverrideTypeCheck{
			varName:    name,
			overrideAs: v.As,
			overrideNS: maps.Clone(c.nsBindings),
			baseAs:     pkgVar.As,
			basePkg:    pkg,
		})
	}

	return nil
}

func isStandardType(as string) bool {
	// Strip occurrence indicator
	name := strings.TrimRight(as, "?*+")

	name = strings.TrimSpace(name)
	if strings.HasPrefix(name, "xs:") {
		return true
	}
	// Standard keywords
	switch name {
	case lexicon.NodeTestItem, lexicon.NodeTestNode, lexicon.NodeTestElement, lexicon.NodeTestAttribute, lexicon.NodeTestText,
		lexicon.NodeTestComment, "processing-instruction()", lexicon.NodeTestDocumentNode,
		"namespace-node()", "schema-element()", "schema-attribute()",
		"function(*)", "map(*)", "array(*)":
		return true
	}

	return false
}
