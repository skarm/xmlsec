// Derived from lestrrat-go/helium at 7362c0a70122a757780f4d0b545a9b370dead6ab.
// Copyright (c) 2015 lestrrat. MIT License; see licenses/MIT-helium.txt at the repository root.

package xslt

import (
	"context"
	"maps"
	"slices"
	"sort"

	"github.com/skarm/xmlsec/internal/lexicon"
	"github.com/skarm/xmlsec/transform/internal/xdm"
	"github.com/skarm/xmlsec/transform/internal/xpath"
)

// collectNamespaces gathers namespace declarations from an element.
func (c *compiler) collectNamespaces(_ context.Context, elem *xdm.Element) {
	c.nsBindings = inScopeNamespaces(elem)
	for _, ns := range elem.Namespaces() {
		prefix := ns.Prefix()
		uri := ns.URI()
		// All namespace bindings (including XSLT) are needed for XPath
		// resolution (e.g., document('')/*/xsl:template).
		c.stylesheet.namespaces[prefix] = uri
	}
}

// compileTopLevel processes namespace aliases, imports and declarations in the
// order required to establish import precedence before compiling components.
func (c *compiler) compileTopLevel(ctx context.Context, root *xdm.Element) error {
	previousScope := c.staticImportScope

	c.staticImportScope = &staticImportScope{parent: previousScope}
	defer func() { c.staticImportScope = previousScope }()

	if err := ctx.Err(); err != nil {
		return err
	}

	if err := validateTopLevelText(root); err != nil {
		return err
	}

	var aliases []*xdm.Element

	previousAliases := c.moduleAliases

	c.moduleAliases = &aliases
	defer func() { c.moduleAliases = previousAliases }()

	var packages []pendingPackageUse

	previousPackages := c.modulePackageUses

	c.modulePackageUses = &packages
	defer func() { c.modulePackageUses = previousPackages }()

	dv := c.stylesheet.defaultValidation
	if requiresSchemaAttribute(nameDefaultValidation, dv, c.stylesheet.processorLanguage()) && !c.stylesheet.schemaAware {
		return staticError("XTSE1660", "default-validation=%q requires a schema-aware processor", dv)
	}

	if err := c.collectTopLevelImports(ctx, root); err != nil {
		return err
	}

	if err := c.collectLocalComponentNames(ctx, root); err != nil {
		return err
	}

	for _, use := range packages {
		if err := c.compilePendingPackageUse(ctx, use); err != nil {
			return err
		}
	}

	if err := c.collectTopLevelNamespaceAliases(ctx, root); err != nil {
		return err
	}

	for _, alias := range aliases {
		savedNS := c.nsBindings
		c.nsBindings = inScopeNamespaces(alias)
		err := c.compileNamespaceAlias(ctx, alias)
		c.nsBindings = savedNS

		if err != nil {
			return err
		}
	}

	if err := c.validatePreparedLanguage(root); err != nil {
		return err
	}

	if err := ctx.Err(); err != nil {
		return err
	}

	return c.compileTopLevelDeclarations(ctx, root)
}

func (c *compiler) collectTopLevelNamespaceAliases(_ context.Context, root *xdm.Element) error {
	for child := range xdm.Children(root) {
		elem, ok := child.(*xdm.Element)
		if !ok || elem.URI() != lexicon.NamespaceXSLT || elem.LocalName() != lexicon.XSLTElementNamespaceAlias {
			continue
		}

		*c.moduleAliases = append(*c.moduleAliases, elem)
	}

	return nil
}

// collectLocalComponentNames precedes package imports so package conflict checks
// see declarations from the current module, including implicitly declared modes.
func (c *compiler) collectLocalComponentNames(ctx context.Context, root *xdm.Element) error {
	c.localTemplateNames = make(map[string]struct{})
	c.localVarNames = make(map[string]struct{})
	c.localModeNames = make(map[string]struct{})
	c.localFunctionNames = make(map[funcKey]struct{})

	return c.collectModuleComponentNames(ctx, root)
}

func (c *compiler) collectModuleComponentNames(ctx context.Context, root *xdm.Element) error {
	for elem := range xdm.ChildElements(root) {
		if elem.URI() != lexicon.NamespaceXSLT {
			continue
		}

		if err := xpath.Charge(ctx, 1); err != nil {
			return err
		}

		if elem.LocalName() == nameInclude {
			if included := c.includedDeclarationRoots[elem]; included != nil {
				if err := c.collectModuleComponentNames(ctx, included); err != nil {
					return err
				}
			}

			continue
		}

		c.collectLocalComponentName(elem)
	}

	return nil
}

func (c *compiler) collectLocalComponentName(elem *xdm.Element) {
	name := getAttr(elem, xslAttrName)

	mode := getAttr(elem, lexicon.AttrMode)
	if name == "" && (elem.LocalName() != nameTemplate || c.stylesheet.declaredModes || mode == "") {
		return
	}

	namespaces := inScopeNamespaces(elem)
	switch elem.LocalName() {
	case lexicon.XSLTElementTemplate:
		if n := getAttr(elem, xslAttrName); n != "" {
			c.localTemplateNames[resolveQName(n, namespaces)] = struct{}{}
		}

		if !c.stylesheet.declaredModes {
			if m := getAttr(elem, lexicon.AttrMode); m != "" && m != lexicon.ModeDefault && m != lexicon.ModeAll && m != modeUnnamed {
				c.localModeNames[resolveQName(m, namespaces)] = struct{}{}
			}
		}
	case lexicon.XSLTElementFunction:
		qualified, err := functionName(name, namespaces)
		if err != nil {
			return // The normal declaration compiler reports the invalid name.
		}

		arity := 0

		for child := range xdm.ChildElements(elem) {
			if child.URI() == lexicon.NamespaceXSLT && child.LocalName() == xslElemParam {
				arity++
			}
		}

		c.localFunctionNames[funcKey{Name: qualified, Arity: arity}] = struct{}{}
	case lexicon.XSLTElementVariable, xslElemParam:
		if n := getAttr(elem, xslAttrName); n != "" {
			c.localVarNames[resolveQName(n, namespaces)] = struct{}{}
		}
	case xslElemMode:
		if n := getAttr(elem, xslAttrName); n != "" {
			c.localModeNames[resolveQName(n, namespaces)] = struct{}{}
		}
	}
}

// Static expressions are evaluated once at their declaration's position.
func (c *compiler) evaluateStaticSelect(ctx context.Context, elem *xdm.Element) (xdm.Sequence, error) {
	restore := c.enterStaticElementContext(elem)
	defer restore()

	compiled, err := c.compileStaticSelect(ctx, elem)
	if err != nil {
		return nil, err
	}

	evaluator := c.staticEvaluator(ctx)

	result, err := evaluator.Evaluate(ctx, compiled, nil)
	if err != nil {
		return nil, err
	}

	return c.convertStaticDeclarationValue(ctx, elem, result.Sequence())
}

func (c *compiler) compileStaticSelect(ctx context.Context, elem *xdm.Element) (*xpath.Expression, error) {
	compiled, err := xpath.NewCompiler().Context(ctx).Language(c.stylesheet.xpathVersion(), c.xpathNamespaces(c.nsBindings)).Compile(getAttr(elem, xslAttrSelect))
	if err != nil {
		return nil, err
	}

	compiled = compiled.BindNamespaceContext(c.xpathNamespaces(c.nsBindings), c.nsBindings[""])
	if err := c.staticEvaluator(ctx).ValidateExpression(ctx, compiled); err != nil {
		return nil, err
	}

	return compiled, nil
}

// Static values must be converted before another declaration, use-when or
// shadow attribute observes them, rather than only when the stylesheet runs.
func (c *compiler) convertStaticDeclarationValue(ctx context.Context, elem *xdm.Element, value xdm.Sequence) (xdm.Sequence, error) {
	if elem.LocalName() == nameParam && xsdBoolTrue(getAttr(elem, ctxItemRequired)) {
		if err := validateRequiredParamDefault(elem); err != nil {
			return nil, err
		}
	}

	as := getAttr(elem, "as")
	if err := c.validateAsSequenceType(ctx, elem, as, "static "+elem.LocalName()); err != nil {
		return nil, err
	}

	if as == "" {
		return value, nil
	}

	st, err := xpath.ParseSequenceType(as)
	if err != nil {
		return nil, err
	}

	defaultNS, _ := c.declarationDefaultNamespace(elem)

	st, err = xpath.BindSequenceType(ctx, st, inScopeNamespaces(elem), defaultNS)
	if err != nil {
		return nil, err
	}

	converted, err := c.staticEvaluator(ctx).ConvertToSequenceType(ctx, value, st, c.stylesheet.xpathVersion())
	if err == nil {
		return converted, nil
	}

	if failure := preserveControlFailure(ctx, err); failure != nil {
		return nil, failure
	}

	code := errCodeXTTE0570
	if elem.LocalName() == nameParam {
		code = errCodeXTTE0590
	}

	return nil, staticErrorCause(code, err, "static %s $%s: %v", elem.LocalName(), getAttr(elem, xslAttrName), err)
}

func (c *compiler) bindImplicitStaticParam(ctx context.Context, elem *xdm.Element) error {
	if elem.LocalName() != nameParam || hasSignificantContent(elem) {
		return nil
	}

	as := getAttr(elem, "as")
	if err := c.validateAsSequenceType(ctx, elem, as, "static parameter"); err != nil {
		return err
	}

	if xsdBoolTrue(getAttr(elem, ctxItemRequired)) || as != "" && !allowsEmptySequence(as) {
		return staticError(errCodeXTDE0050, "required static parameter $%s was not supplied", getAttr(elem, xslAttrName))
	}

	var value xdm.Sequence
	if as == "" {
		value = xdm.SingleString("")
	}

	return c.setStaticVarWithKind(ctx, resolveQName(getAttr(elem, xslAttrName), inScopeNamespaces(elem)), nameParam, value)
}

// bindExternalStaticParam establishes the supplied value at the declaration's
// position in static scope. Undeclared external names never enter that scope,
// and a supplied parameter's default cannot replace its value for dependants.
func (c *compiler) bindExternalStaticParam(ctx context.Context, elem *xdm.Element) (bool, error) {
	if elem.LocalName() != nameParam {
		return false, nil
	}

	name := resolveQName(getAttr(elem, xslAttrName), inScopeNamespaces(elem))

	value, supplied := c.externalStaticParams[name]
	if !supplied {
		return false, nil
	}

	value, err := c.convertStaticDeclarationValue(ctx, elem, value)
	if err != nil {
		return false, err
	}

	return true, c.setStaticVarWithKind(ctx, name, nameParam, value)
}

func (c *compiler) evaluateStaticDeclaration(ctx context.Context, elem *xdm.Element) error {
	include, err := c.topLevelDeclarationIncluded(ctx, elem)
	if err != nil {
		return err
	}

	if !include {
		return nil
	}

	if supplied, err := c.bindExternalStaticParam(ctx, elem); supplied || err != nil {
		return err
	}

	name := getAttr(elem, xslAttrName)
	if name == "" {
		return nil
	}

	if _, present := elem.GetAttribute(xslAttrSelect); !present {
		return c.bindImplicitStaticParam(ctx, elem)
	}

	value, err := c.evaluateStaticSelect(ctx, elem)
	if err != nil {
		return err
	}

	return c.setStaticVarWithKind(ctx, resolveQName(name, inScopeNamespaces(elem)), elem.LocalName(), value)
}

func (c *compiler) collectTopLevelImports(ctx context.Context, root *xdm.Element) error {
	if err := c.validateModuleImportOrder(ctx, root); err != nil {
		return err
	}

	var excluded map[xdm.Node]struct{}

	for child := range xdm.Children(root) {
		elem, ok := child.(*xdm.Element)
		if !ok || c.ignoredTopLevelDeclaration(elem) {
			continue
		}

		include, err := c.preprocessStaticSubtree(ctx, elem)
		if err != nil {
			return err
		}

		if !include {
			if excluded == nil {
				excluded = make(map[xdm.Node]struct{})
			}

			excluded[elem] = struct{}{}

			continue
		}

		if isStaticTopLevelDeclaration(elem) {
			if err := c.evaluateStaticDeclaration(ctx, elem); err != nil {
				return err
			}
		}

		if elem.URI() == lexicon.NamespaceXSLT {
			switch elem.LocalName() {
			case lexicon.XSLTElementImport, lexicon.XSLTElementInclude:
				if err := c.collectTopLevelModule(ctx, elem); err != nil {
					return err
				}
			case lexicon.XSLTElementUsePackage:
				if c.insideImport {
					return staticError(errCodeXTSE3008, "xsl:use-package is not allowed in an imported stylesheet module")
				}

				*c.modulePackageUses = append(*c.modulePackageUses, pendingPackageUse{element: elem, root: root, baseURI: c.baseURI})
			}
		}
	}

	removeExcludedChildren(root, excluded)

	return nil
}

func (c *compiler) collectTopLevelModule(ctx context.Context, elem *xdm.Element) error {
	include, err := c.topLevelUseWhen(ctx, elem)
	if err != nil || !include {
		return err
	}

	if err := c.validateXSLTAttrs(ctx, elem, attributeNames(lexicon.AttrHref, xslAttrUseWhen)); err != nil {
		return err
	}

	if err := c.validateEmptyElement(ctx, elem, "xsl:"+elem.LocalName()); err != nil {
		return err
	}

	if elem.LocalName() == lexicon.XSLTElementImport {
		return c.compileImport(ctx, elem)
	}

	return c.collectIncludeImports(ctx, elem)
}

func (c *compiler) collectTopLevelPackage(ctx context.Context, elem *xdm.Element) error {
	include, err := c.topLevelUseWhen(ctx, elem)
	if err != nil || !include {
		return err
	}

	if c.insideImport {
		return staticError(errCodeXTSE3008,
			"xsl:use-package is not allowed in an imported stylesheet module")
	}

	if err := c.validateKnownElementAttributes(ctx, elem); err != nil {
		return err
	}

	return c.compileUsePackage(ctx, elem)
}

func (c *compiler) topLevelUseWhen(ctx context.Context, elem *xdm.Element) (bool, error) {
	value, present := elem.GetAttribute(xslAttrUseWhen)
	if elem.URI() != lexicon.NamespaceXSLT {
		value, present = elem.GetAttributeNS(xslAttrUseWhen, lexicon.NamespaceXSLT)
	}

	if present {
		return c.evaluateDeclarationUseWhen(ctx, elem, value)
	}

	return true, nil
}

func (c *compiler) ignoredTopLevelDeclaration(elem *xdm.Element) bool {
	if c.stylesheet.processorLanguage() >= 30 {
		if _, shadow := elem.GetAttribute("_version"); shadow {
			return false
		}
	}

	return elem.URI() == lexicon.NamespaceXSLT && elementForwardsCompatible(elem, c.stylesheet.processorLanguage()) && unavailableInstruction(elem.LocalName(), c.stylesheet.processorLanguage())
}

func (c *compiler) validateModuleImportOrder(ctx context.Context, root *xdm.Element) error {
	if c.stylesheet.processorLanguage() >= 30 {
		return nil
	}

	late, err := hasLateModuleImport(ctx, root)
	if err != nil || !late {
		return err
	}

	seenOther := false

	for elem := range xdm.ChildElements(root) {
		if err := ctx.Err(); err != nil {
			return err
		}

		if c.ignoredTopLevelDeclaration(elem) {
			continue
		}

		include, err := c.topLevelUseWhen(ctx, elem)
		if err != nil {
			return err
		}

		if !include {
			continue
		}

		if elem.URI() == lexicon.NamespaceXSLT && elem.LocalName() == nameImport {
			if seenOther {
				return staticError("XTSE0200", "xsl:import must precede other module elements in XSLT 1.0/2.0")
			}
		} else {
			seenOther = true
		}
	}

	return nil
}

func (c *compiler) compileTopLevelDeclarations(ctx context.Context, root *xdm.Element) error {
	for child := range xdm.Children(root) {
		elem, ok := child.(*xdm.Element)
		if !ok {
			continue
		}

		if elem.URI() != lexicon.NamespaceXSLT {
			if elem.URI() == "" {
				return staticError(errCodeXTSE0130,
					"top-level element %q has no namespace; all top-level elements must be in a non-null namespace", elem.Name())
			}

			continue
		}

		if c.ignoredTopLevelDeclaration(elem) {
			continue
		}

		if err := c.resolveShadowAttributes(ctx, elem); err != nil {
			return err
		}

		include, err := c.topLevelDeclarationIncluded(ctx, elem)
		if err != nil {
			return err
		}

		if !include {
			continue
		}

		// Module/package declarations were checked only when included, before I/O.
		switch elem.LocalName() {
		case nameImport, nameInclude, nameUsePackage:
		default:
			if err := c.validateKnownElementAttributes(ctx, elem); err != nil {
				return err
			}
		}

		if err := c.compileTopLevelDeclaration(ctx, elem); err != nil {
			return err
		}
	}

	return nil
}

// topLevelDeclarationIncluded applies declaration use-when rules. Imports,
// packages and templates perform their own checks in their compilation stages.
func (c *compiler) topLevelDeclarationIncluded(ctx context.Context, elem *xdm.Element) (bool, error) {
	ln := elem.LocalName()
	switch ln {
	case nameImport, nameInclude, nameUsePackage, nameTemplate:
		return true, nil
	}

	uw := getAttr(elem, xslAttrUseWhen)
	if uw == "" {
		return true, nil
	}

	include, err := c.evaluateDeclarationUseWhen(ctx, elem, uw)
	if err == nil {
		return include, nil
	}

	if !isKnownXSLTElement(ln) || !isTopLevelXSLTElement(ln) {
		elemVer := getAttr(elem, lexicon.SerializationVersion)
		if c.forwardsCompatible(c.effectiveVersion) || c.forwardsCompatible(elemVer) {
			return false, nil
		}
	}

	return false, err
}

// evaluateDeclarationUseWhen evaluates in the declaration's namespace scope.
// The tree-order preprocessing pass has not bound this declaration yet.
func (c *compiler) evaluateDeclarationUseWhen(ctx context.Context, elem *xdm.Element, uw string) (bool, error) {
	savedNS, savedDefault, savedHas := c.nsBindings, c.xpathDefaultNS, c.hasXPathDefaultNS
	c.nsBindings = inScopeNamespaces(elem)

	c.xpathDefaultNS, c.hasXPathDefaultNS = c.declarationDefaultNamespace(elem)
	defer func() { c.nsBindings, c.xpathDefaultNS, c.hasXPathDefaultNS = savedNS, savedDefault, savedHas }()

	return c.evaluateUseWhen(ctx, uw)
}

func (c *compiler) compileTopLevelDeclaration(ctx context.Context, elem *xdm.Element) error {
	if c.ignoredTopLevelDeclaration(elem) {
		return nil
	}

	switch elem.LocalName() {
	case lexicon.XSLTElementImport, lexicon.XSLTElementUsePackage,
		lexicon.XSLTElementNamespaceAlias, lexicon.XSLTElementExpose:
		return nil // processed in an earlier pass or after compilation
	case lexicon.XSLTElementInclude:
		include, err := c.topLevelUseWhen(ctx, elem)
		if err != nil || !include {
			return err
		}

		return c.compileIncludeTemplates(ctx, elem)
	case lexicon.XSLTElementTemplate:
		return c.compileTemplate(ctx, elem)
	case lexicon.XSLTElementVariable:
		return c.compileGlobalVariable(ctx, elem)
	case lexicon.XSLTElementParam:
		return c.compileGlobalParam(ctx, elem)
	case lexicon.XSLTElementKey:
		return c.compileKey(ctx, elem)
	case lexicon.XSLTElementOutput:
		return c.compileOutput(ctx, elem)
	case lexicon.XSLTElementStripSpace:
		return c.compileSpaceHandling(ctx, elem, true)
	case lexicon.XSLTElementPreserveSpace:
		return c.compileSpaceHandling(ctx, elem, false)
	case lexicon.XSLTElementFunction:
		return c.compileFunction(ctx, elem)
	case lexicon.XSLTElementDecimalFormat:
		return c.compileDecimalFormat(ctx, elem)
	case lexicon.XSLTElementMode:
		return c.compileMode(ctx, elem)
	case lexicon.XSLTElementImportSchema:
		return c.compileImportSchema(ctx, elem)
	case lexicon.XSLTElementAccumulator:
		return c.compileAccumulator(ctx, elem)
	case lexicon.XSLTElementAttributeSet:
		return c.compileAttributeSet(ctx, elem)
	case lexicon.XSLTElementCharacterMap:
		return c.compileCharacterMap(ctx, elem)
	case lexicon.XSLTElementGlobalContextItem:
		return c.compileGlobalContextItem(ctx, elem)
	default:
		elemVer := getAttr(elem, lexicon.SerializationVersion)
		if !c.forwardsCompatible(c.effectiveVersion) && !c.forwardsCompatible(elemVer) {
			return staticError(errCodeXTSE0010,
				"element xsl:%s is not allowed as a top-level declaration", elem.LocalName())
		}

		return nil
	}
}

// resolveNamespaceAlias looks up the namespace alias for a given stylesheet URI.
// Returns the result URI, result prefix, and true if an alias was found.
// If multiple aliases target the same stylesheet URI, the one with the highest
// import precedence wins.
func (c *compiler) resolveNamespaceAlias(_ context.Context, stylesheetURI string) (string, string, bool) {
	bestPrec := -1

	var bestURI, bestPrefix string

	found := false

	for _, alias := range c.stylesheet.namespaceAliases {
		if alias.StylesheetURI == stylesheetURI {
			if !found || alias.ImportPrec > bestPrec {
				bestPrec = alias.ImportPrec
				bestURI = alias.ResultURI
				bestPrefix = alias.ResultPrefix
				found = true
			}
		}
	}

	return bestURI, bestPrefix, found
}

// checkConflictingNamespaceAliases checks for XTSE0810: multiple namespace-alias
// declarations with the same stylesheet URI, same import precedence, but different
// result URIs, unless overridden by a higher-precedence alias.
func (c *compiler) checkConflictingNamespaceAliases(_ context.Context) error {
	aliases := c.stylesheet.namespaceAliases
	// Group by stylesheet URI
	type aliasInfo struct {
		resultURI  string
		importPrec int
	}

	byURI := make(map[string][]aliasInfo)
	maxPrec := make(map[string]int)

	for _, a := range aliases {
		byURI[a.StylesheetURI] = append(byURI[a.StylesheetURI], aliasInfo{a.ResultURI, a.ImportPrec})
		if a.ImportPrec > maxPrec[a.StylesheetURI] {
			maxPrec[a.StylesheetURI] = a.ImportPrec
		}
	}

	for uri, group := range byURI {
		if len(group) < 2 {
			continue
		}
		// For each precedence level, check if all result URIs are the same
		precResults := make(map[int]map[string]struct{})
		for _, a := range group {
			if precResults[a.importPrec] == nil {
				precResults[a.importPrec] = make(map[string]struct{})
			}

			precResults[a.importPrec][a.resultURI] = struct{}{}
		}

		for prec, results := range precResults {
			if len(results) > 1 && prec >= maxPrec[uri] {
				return staticError(errCodeXTSE0810,
					"conflicting namespace-alias declarations for namespace %q with different result namespaces at the same import precedence", uri)
			}
		}
	}

	return nil
}

// compileNamespaceAlias compiles an xsl:namespace-alias declaration.
func (c *compiler) compileNamespaceAlias(ctx context.Context, elem *xdm.Element) error {
	if err := c.validateXSLTAttrs(ctx, elem, attributeNames("stylesheet-prefix", "result-prefix", xslAttrUseWhen)); err != nil {
		return err
	}

	stylesheetPrefix, hasStylesheetPrefix := elem.GetAttribute("stylesheet-prefix")
	resultPrefix, hasResultPrefix := elem.GetAttribute("result-prefix")

	if !hasStylesheetPrefix {
		return staticError(errCodeXTSE0010, "xsl:namespace-alias requires stylesheet-prefix attribute")
	}

	if !hasResultPrefix {
		return staticError(errCodeXTSE0010, "xsl:namespace-alias requires result-prefix attribute")
	}

	// Build a local namespace map from the element's in-scope namespaces.
	// This is critical because namespace-alias prefixes are resolved in the
	// namespace context of the xsl:namespace-alias element itself, not the
	// stylesheet root (test namespace-alias-0903).
	localNS := make(map[string]string)
	maps.Copy(localNS, c.nsBindings)

	for _, ns := range elem.Namespaces() {
		localNS[ns.Prefix()] = ns.URI()
	}

	// Resolve stylesheet-prefix to a URI
	var stylesheetURI string
	if stylesheetPrefix == lexicon.ModeDefault {
		stylesheetURI = localNS[""]
	} else {
		uri, ok := localNS[stylesheetPrefix]
		if !ok {
			return staticError(errCodeXTSE0812, "xsl:namespace-alias: stylesheet-prefix %q is not bound to a namespace", stylesheetPrefix)
		}

		stylesheetURI = uri
	}

	// Resolve result-prefix to a URI and preferred prefix
	var (
		resultURI string
		resultPfx string
	)

	switch resultPrefix {
	case lexicon.ModeDefault:
		resultURI = localNS[""]
		resultPfx = ""
	case lexicon.PrefixXML:
		resultURI = lexicon.NamespaceXML
		resultPfx = lexicon.PrefixXML
	default:
		uri, ok := localNS[resultPrefix]
		if !ok {
			return staticError(errCodeXTSE0812, "xsl:namespace-alias: result-prefix %q is not bound to a namespace", resultPrefix)
		}

		resultURI = uri
		resultPfx = resultPrefix
	}

	c.stylesheet.namespaceAliases = append(c.stylesheet.namespaceAliases, namespaceAlias{
		StylesheetURI: stylesheetURI,
		ResultURI:     resultURI,
		ResultPrefix:  resultPfx,
		ImportPrec:    c.importPrec,
	})

	return nil
}

func (c *compiler) sortTemplates(_ context.Context) {
	// Ensure #all templates are registered in every mode (including modes
	// that were created after the #all template was compiled).
	allTemplates := c.stylesheet.modeTemplates[modeAll]
	if len(allTemplates) > 0 {
		for mode := range c.stylesheet.modeTemplates {
			if mode == modeAll {
				continue
			}

			existing := c.stylesheet.modeTemplates[mode]
			for _, at := range allTemplates {
				if !slices.Contains(existing, at) {
					c.stylesheet.modeTemplates[mode] = append(c.stylesheet.modeTemplates[mode], at)
				}
			}
		}
	}

	for mode := range c.stylesheet.modeTemplates {
		templates := c.stylesheet.modeTemplates[mode]
		sort.SliceStable(templates, func(i, j int) bool {
			// Higher import precedence first
			if templates[i].ImportPrec != templates[j].ImportPrec {
				return templates[i].ImportPrec > templates[j].ImportPrec
			}
			// Higher priority first
			if templates[i].Priority != templates[j].Priority {
				return templates[i].Priority > templates[j].Priority
			}
			// Same priority: later declaration order wins (XSLT spec §6.4)
			return i > j
		})
	}

	// Build the dispatch index from the now-final sorted order. This must run
	// AFTER every mode list above is fully sorted: buildTemplateIndex records
	// each template's POSITION in the sorted slice, and that position is the
	// only thing a dispatch-time merge (dispatch_index.go candidates) can use
	// to recover the original scan order — the tiebreak above compares live
	// slice indices, not a well-defined ordering over the templates
	// themselves, so the index can only ever inherit the sort's result, never
	// re-derive it.
	c.stylesheet.modeIndex = make(map[string]*templateIndex, len(c.stylesheet.modeTemplates))
	for mode, templates := range c.stylesheet.modeTemplates {
		if idx := buildTemplateIndex(templates); idx != nil {
			c.stylesheet.modeIndex[mode] = idx
		}
	}
}

func validateTopLevelText(root *xdm.Element) error {
	for child := range xdm.Children(root) {
		if child.Type() == xdm.TextNode && xdm.CharacterData(child) != "" {
			return staticError(errCodeXTSE0120, "non-whitespace text node in xsl:stylesheet")
		}
	}

	return nil
}

// A module already ordered structurally needs no additional use-when evaluation.
func hasLateModuleImport(ctx context.Context, root *xdm.Element) (bool, error) {
	seenOther := false

	for elem := range xdm.ChildElements(root) {
		if err := ctx.Err(); err != nil {
			return false, err
		}

		if elem.URI() == lexicon.NamespaceXSLT && elem.LocalName() == nameImport {
			if seenOther {
				return true, nil
			}
		} else {
			seenOther = true
		}
	}

	return false, nil
}

func isStaticTopLevelDeclaration(elem *xdm.Element) bool {
	ln := elem.LocalName()

	return elem.URI() == lexicon.NamespaceXSLT &&
		(ln == lexicon.XSLTElementParam || ln == lexicon.XSLTElementVariable) &&
		xsdBoolTrue(getAttr(elem, nameStatic))
}
