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
// expand-text, default-collation; XSLT 3.0 §3.5) to the
// compiler settings the elements inside inherit, and returns the settings it
// replaced. The namespace bindings are copied first, so neither these
// declarations nor any an inner element adds outlive the scope.
func (c *compiler) pushStandardAttrs(ctx context.Context, elem *xdm.Element) (standardAttrScope, error) {
	if err := c.checkDefaultModeAttribute(ctx, elem); err != nil {
		return standardAttrScope{}, err
	}

	saved := standardAttrScope{
		nsBindings:        c.nsBindings,
		version:           c.effectiveVersion,
		xpathDefaultNS:    c.xpathDefaultNS,
		hasXPathDefaultNS: c.hasXPathDefaultNS,
		expandText:        c.expandText,
		defaultCollation:  c.defaultCollation,
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
		Name:         qn,
		Params:       params,
		Body:         body,
		As:           getAttr(elem, "as"),
		Visibility:   getAttr(elem, xslAttrVisibility),
		IsOverride:   true,
		OwnerPackage: c.stylesheet,
	}
	fn.signatureTypeKey = c.declarationTypeKey(elem, fn.As)
	fn.NewEachTime = getAttr(elem, "new-each-time")
	fn.Streamability = getAttr(elem, "streamability")

	pkgFn := pkg.functions[funcKey{Name: qn, Arity: len(params)}]
	if pkgFn == nil {
		return nil, xpath.QualifiedName{}, staticError(errCodeXTSE3058, "xsl:override function %q#%d not found in used package", name, len(params))
	}

	visibility := getComponentVisibility(pkg, xslElemFunction, functionVisKey(qn, len(params)))
	if visibility != visPublic && visibility != visAbstract {
		return nil, xpath.QualifiedName{}, staticError(errCodeXTSE3060, "cannot override %s function %q", visibility, name)
	}

	if err := checkOverrideFunctionSignature(fn, pkgFn); err != nil {
		return nil, xpath.QualifiedName{}, err
	}

	if err := c.prepareCompiledFunction(ctx, fn, elem); err != nil {
		return nil, xpath.QualifiedName{}, err
	}

	if fn.Visibility == "" {
		fn.Visibility = visPublic
		if visibility != visAbstract {
			fn.Visibility = visibility
		}
	}

	fn.OriginalFunc = pkgFn

	return fn, qn, nil
}

func defaultContextItemType(as string) string {
	if as == "" {
		return lexicon.NodeTestItem
	}

	return as
}

func checkOverrideFunctionSignature(override, base *xslFunction) error {
	if override.signatureTypeKey != base.signatureTypeKey {
		return staticError(errCodeXTSE3070, "override function %s has a different return type", override.Name.Name)
	}

	for i, p := range override.Params {
		if p.signatureTypeKey != base.Params[i].signatureTypeKey {
			return staticError(errCodeXTSE3070, "override function %s parameter %d has a different required type", override.Name.Name, i+1)
		}
	}

	net := func(value string) string {
		if value == "" {
			return lexicon.ValueYes
		}

		return value
	}
	if net(override.NewEachTime) != net(base.NewEachTime) {
		return staticError(errCodeXTSE3070, "override function %s has a different new-each-time value", override.Name.Name)
	}

	if base.Streamability != "" && base.Streamability != lexicon.StreamUnclassified && override.Streamability != base.Streamability {
		return staticError(errCodeXTSE3070, "override function %s has incompatible streamability", override.Name.Name)
	}

	return nil
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

	matchAttr, hasMatch := elem.GetAttribute(nameMatch2)
	if hasMatch {
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

	tmpl.Mode, err = compileTemplateModes(ctx, elem)
	if err != nil {
		return nil, err
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

	// An overriding rule needs a public named mode; unnamed/#all modes are
	// forbidden by XTSE3440 and private/final modes by XTSE3060.
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
			return nil, staticError(errCodeXTSE3060,
				"cannot override final template %q", tmpl.Name)
		}

		pkgVis := getComponentVisibility(pkg, xslElemTemplate, tmpl.Name)
		if pkgVis == visPrivate || pkgVis == visHidden {
			return nil, staticError(errCodeXTSE3060,
				"cannot override %s template %q", pkgVis, tmpl.Name)
		}
	}

	savedOverrideRule := c.inOverrideRule

	c.inOverrideRule = tmpl.Match != nil
	defer func() { c.inOverrideRule = savedOverrideRule }()

	ctxDecl, body, params, err := c.compileTemplateBodyEx(ctx, elem, false)
	if err != nil {
		return nil, err
	}

	tmpl.Params = params
	tmpl.Body = body

	tmpl.As = getAttr(elem, "as")
	tmpl.signatureTypeKey = c.declarationTypeKey(elem, tmpl.As)

	tmpl.contextTypeKey = c.declarationTypeKey(elem, lexicon.NodeTestItem)
	if vis := getAttr(elem, xslAttrVisibility); vis != "" {
		tmpl.Visibility = vis
	}

	if ctxDecl != nil {
		tmpl.ContextItemAs = ctxDecl.as
		tmpl.ContextItemUse = ctxDecl.use
		tmpl.contextTypeKey = ctxDecl.typeKey
		tmpl.contextItemType = ctxDecl.itemType
	}

	// XTSE3070: check type compatibility of override against base template.
	if err := compileOverrideTemplateName(tmpl, pkg); err != nil {
		return nil, err
	}

	return tmpl, nil
}

// checkOverrideTemplateCompat applies the signature rules in XSLT 3.0 3.5.3.3.
func checkOverrideTemplateCompat(override, base *template) error {
	use := func(t *template) string {
		if t.ContextItemUse != "" {
			return t.ContextItemUse
		}

		return ctxItemOptional
	}
	if override.signatureTypeKey != base.signatureTypeKey || override.contextTypeKey != base.contextTypeKey || use(override) != use(base) {
		return staticError(errCodeXTSE3070, "override template %q has an incompatible return or context-item type", override.Name)
	}

	baseParams, overrideParams := make(map[string]*param), make(map[string]*param)
	for _, p := range base.Params {
		baseParams[p.Name] = p
	}

	for _, p := range override.Params {
		overrideParams[p.Name] = p
	}

	for name, bp := range baseParams {
		op := overrideParams[name]
		if op == nil {
			if bp.Tunnel {
				continue
			}

			return staticError(errCodeXTSE3070, "override template %q omits parameter $%s", override.Name, name)
		}

		if op.Tunnel != bp.Tunnel || op.signatureTypeKey != bp.signatureTypeKey || !bp.Tunnel && op.Required != bp.Required {
			return staticError(errCodeXTSE3070, "override template %q has incompatible parameter $%s", override.Name, name)
		}
	}

	for name, op := range overrideParams {
		if baseParams[name] == nil && op.Required {
			return staticError(errCodeXTSE3070, "override template %q adds required parameter $%s", override.Name, name)
		}
	}

	return nil
}

// checkOverrideModeVisibility validates that a mode used by an override
// template is public/abstract in the used package.
func checkOverrideModeVisibility(mode, displayMode string, pkg *Stylesheet) error {
	if mode == "" || mode == modeAll {
		return staticError(errCodeXTSE3440, "override template cannot use the unnamed mode or #all")
	}

	if pkg.modeDefs != nil {
		if md, ok := pkg.modeDefs[mode]; ok {
			if md.Visibility == visFinal {
				return staticError(errCodeXTSE3060,
					"cannot override templates in final mode %q", displayMode)
			}

			if md.Visibility == visPrivate || md.Visibility == visHidden {
				return staticError(errCodeXTSE3060,
					"cannot override templates in %s mode %q", md.Visibility, displayMode)
			}

			return nil
		}
	}
	// Mode not defined in the package — check default visibility
	defVis := defaultComponentVisibility(pkg)
	if defVis == visPrivate {
		return staticError(errCodeXTSE3060,
			"mode %q is not defined in the used package (default visibility is private)", displayMode)
	}

	return nil
}

func compileOverrideTemplateModes(modes []string, tmpl *template, pkg *Stylesheet) error {
	for _, m := range modes {
		// Resolve special names to empty string for lookup
		if m == modeUnnamed || m == "#default" {
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
	if tmpl.Match != nil {
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
	if err := c.validateXSLTAttrs(ctx, elem, variableAllowedAttrs); err != nil {
		return nil, err
	}
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

	base := lookupOverrideGlobal(pkg, resolvedName)
	if base == (globalBinding{}) {
		return nil, staticError(errCodeXTSE3058,
			"xsl:override variable %q not found in used package", name)
	}

	effectiveVis := getComponentVisibility(pkg, xslElemVariable, resolvedName)
	if err := checkOverrideVariableVisibility(name, effectiveVis); err != nil {
		return nil, err
	}

	savedOriginal := c.originalVariableVisibility

	c.originalVariableVisibility = effectiveVis
	defer func() { c.originalVariableVisibility = savedOriginal }()

	v := &variable{Name: resolvedName, As: getAttr(elem, "as"), Visibility: getAttr(elem, xslAttrVisibility), OwnerPackage: c.stylesheet}
	if err := c.validateAsSequenceType(ctx, elem, v.As, "overriding variable"); err != nil {
		return nil, err
	}

	v.signatureTypeKey = c.declarationTypeKey(elem, v.As)

	if err := checkOverrideGlobalType(base, v.signatureTypeKey, resolvedName); err != nil {
		return nil, err
	}

	v.Original = base
	v.StaticBaseURI = stylesheetBaseURI(elem, c.baseURI, c.moduleRoot)
	v.XPathDefaultNS = c.xpathDefaultNS
	v.TypeNamespaces = inScopeNamespaces(elem)
	v.XPathDefaultNS, v.HasXPathDefaultNS = c.declarationDefaultNamespace(elem)

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

func lookupOverrideGlobal(pkg *Stylesheet, name string) globalBinding {
	for _, v := range pkg.globalVars {
		if v.Name == name {
			return v.binding()
		}
	}

	for _, p := range pkg.globalParams {
		if p.Name == name {
			return p.binding()
		}
	}

	return globalBinding{}
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

func (c *compiler) compileOverrideParam(ctx context.Context, elem *xdm.Element, pkg *Stylesheet) (*param, error) {
	name := resolveQName(getAttr(elem, xslAttrName), c.nsBindings)

	base := lookupOverrideGlobal(pkg, name)
	if base == (globalBinding{}) {
		return nil, staticError(errCodeXTSE3058, "xsl:override param %q not found in used package", name)
	}

	if err := checkOverrideVariableVisibility(name, getComponentVisibility(pkg, xslElemVariable, name)); err != nil {
		return nil, err
	}

	savedOriginal := c.originalVariableVisibility

	c.originalVariableVisibility = getComponentVisibility(pkg, xslElemVariable, name)
	defer func() { c.originalVariableVisibility = savedOriginal }()

	p, err := c.compileParamDef(ctx, elem)
	if err != nil {
		return nil, err
	}

	if err := checkOverrideGlobalType(base, p.signatureTypeKey, p.Name); err != nil {
		return nil, err
	}

	p.OwnerPackage, p.Original, p.Visibility = c.stylesheet, base, visPublic
	p.TypeNamespaces = inScopeNamespaces(elem)
	p.XPathDefaultNS, p.HasXPathDefaultNS = c.declarationDefaultNamespace(elem)

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

	asd := &attributeSetDef{Name: resolvedName, OwnerPackage: c.stylesheet, Visibility: getAttr(elem, xslAttrVisibility)}

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

// Schema-defined type identity belongs to the separate schema-aware profile.
// Basic signatures compare the captured, namespace-resolved type keys.
func checkOverrideGlobalType(base globalBinding, typeKey, name string) error {
	if base.typeKey() != typeKey {
		return staticError(errCodeXTSE3070, "override variable %q has a different required type", name)
	}

	return nil
}
