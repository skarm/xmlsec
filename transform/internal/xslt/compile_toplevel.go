// Derived from lestrrat-go/helium at 7362c0a70122a757780f4d0b545a9b370dead6ab.
// Copyright (c) 2015 lestrrat. MIT License; see licenses/MIT-helium.txt at the repository root.

package xslt

import (
	"context"
	"errors"
	"maps"
	"slices"
	"sort"

	"github.com/skarm/xmlsec/transform/internal/xdm"
	"github.com/skarm/xmlsec/transform/internal/xdm/lexicon"
	"github.com/skarm/xmlsec/transform/internal/xpath"
	"github.com/skarm/xmlsec/transform/internal/xslt/internal/elements"
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
	if err := ctx.Err(); err != nil {
		return err
	}

	if err := validateTopLevelText(root); err != nil {
		return err
	}

	aliasStartIdx := len(c.stylesheet.namespaceAliases)
	if err := c.collectTopLevelNamespaceAliases(ctx, root); err != nil {
		return err
	}

	aliasEndIdx := len(c.stylesheet.namespaceAliases)

	dv := c.stylesheet.defaultValidation
	if requiresSchemaAttribute(nameDefaultValidation, dv, c.stylesheet.processorLanguage()) && !c.stylesheet.schemaAware {
		return staticError("XTSE1660", "default-validation=%q requires a schema-aware processor", dv)
	}

	c.collectLocalComponentNames(root)

	moduleStaticNames := collectModuleStaticNames(root)
	if err := c.evaluateStaticDeclarations(ctx, root, true, moduleStaticNames); err != nil {
		return err
	}

	if err := c.resolveImportShadowAttributes(ctx, root); err != nil {
		return err
	}

	if err := c.collectTopLevelImports(ctx, root); err != nil {
		return err
	}

	if !c.insideImport {
		if err := c.checkStaticVarKindConflicts(ctx, root); err != nil {
			return err
		}
	}

	if err := c.resolveStaticDeclarationShadows(ctx, root); err != nil {
		return err
	}

	if err := c.detectStaticParamCycles(ctx, root); err != nil {
		return err
	}

	if err := c.evaluateStaticDeclarations(ctx, root, false, nil); err != nil {
		return err
	}

	// Only this module's aliases acquire its final import precedence. Imported
	// modules added their own aliases after aliasEndIdx and keep their precedence.
	for i := aliasStartIdx; i < aliasEndIdx; i++ {
		c.stylesheet.namespaceAliases[i].ImportPrec = c.importPrec
	}

	if err := ctx.Err(); err != nil {
		return err
	}

	return c.compileTopLevelDeclarations(ctx, root)
}

func validateTopLevelText(root *xdm.Element) error {
	for child := range xdm.Children(root) {
		if child.Type() == xdm.TextNode && !isXMLWhitespaceOnly(xdm.CharacterData(child)) {
			return staticError(errCodeXTSE0120, "non-whitespace text node in xsl:stylesheet")
		}
	}

	return nil
}

// collectModuleStaticNames retains document order for forward-reference checks.
func collectModuleStaticNames(root *xdm.Element) []string {
	var names []string

	for child := range xdm.Children(root) {
		elem, ok := child.(*xdm.Element)
		if !ok || !isStaticTopLevelDeclaration(elem) {
			continue
		}

		if name := getAttr(elem, xslAttrName); name != "" {
			names = append(names, name)
		}
	}

	return names
}

func (c *compiler) collectTopLevelNamespaceAliases(ctx context.Context, root *xdm.Element) error {
	for child := range xdm.Children(root) {
		elem, ok := child.(*xdm.Element)
		if !ok || elem.URI() != lexicon.NamespaceXSLT || elem.LocalName() != lexicon.XSLTElementNamespaceAlias {
			continue
		}

		if err := c.compileNamespaceAlias(ctx, elem); err != nil {
			return err
		}
	}

	return nil
}

// collectLocalComponentNames precedes package imports so package conflict checks
// see declarations from the current module, including implicitly declared modes.
func (c *compiler) collectLocalComponentNames(root *xdm.Element) {
	c.localTemplateNames = make(map[string]struct{})
	c.localVarNames = make(map[string]struct{})
	c.localModeNames = make(map[string]struct{})

	for child := range xdm.Children(root) {
		elem, ok := child.(*xdm.Element)
		if !ok || elem.URI() != lexicon.NamespaceXSLT {
			continue
		}

		switch elem.LocalName() {
		case lexicon.XSLTElementTemplate:
			if n := getAttr(elem, xslAttrName); n != "" {
				c.localTemplateNames[resolveQName(n, c.nsBindings)] = struct{}{}
			}

			if !c.stylesheet.declaredModes {
				if m := getAttr(elem, nameMode); m != "" && m != lexicon.ModeDefault && m != lexicon.ModeAll && m != modeUnnamed {
					c.localModeNames[resolveQName(m, c.nsBindings)] = struct{}{}
				}
			}
		case lexicon.XSLTElementVariable, xslElemParam:
			if n := getAttr(elem, xslAttrName); n != "" {
				c.localVarNames[resolveQName(n, c.nsBindings)] = struct{}{}
			}
		case xslElemMode:
			if n := getAttr(elem, xslAttrName); n != "" {
				c.localModeNames[resolveQName(n, c.nsBindings)] = struct{}{}
			}
		}
	}
}

// The early pass can defer malformed expressions until imports are known.
// Final passes report compilation and evaluation errors without suppressing them.
func (c *compiler) tryEvaluateStaticSelect(ctx context.Context, elem *xdm.Element, speculative bool) (xdm.Sequence, bool, error) {
	savedNS, savedDefault, savedHas := c.nsBindings, c.xpathDefaultNS, c.hasXPathDefaultNS

	c.nsBindings = inScopeNamespaces(elem)

	c.xpathDefaultNS, c.hasXPathDefaultNS = c.declarationDefaultNamespace(elem)
	defer func() { c.nsBindings, c.xpathDefaultNS, c.hasXPathDefaultNS = savedNS, savedDefault, savedHas }()

	compiled, err := xpath.NewCompiler().Context(ctx).Language(c.stylesheet.xpathVersion(), c.xpathNamespaces(c.nsBindings)).Compile(getAttr(elem, xslAttrSelect))
	if err != nil {
		if failure := preserveControlFailure(ctx, err); failure != nil {
			return nil, false, failure
		}

		if !speculative {
			return nil, false, err
		}

		return nil, false, nil //nolint:nilerr // This speculative pass defers syntax errors to main compilation.
	}

	compiled = compiled.BindNamespaceContext(c.xpathNamespaces(c.nsBindings), c.nsBindings[""])

	eval := c.staticEvaluator(ctx)
	if elemBase := getAttr(elem, lexicon.QNameXMLBase); elemBase != "" {
		eval = c.resolveXMLBaseEvaluator(ctx, eval, elemBase)
	}

	if len(c.staticVars) > 0 {
		eval = eval.Variables(c.staticVars)
	}

	result, err := eval.Evaluate(ctx, compiled, nil)
	if err != nil {
		return nil, false, err
	}

	value, err := c.convertStaticDeclarationValue(ctx, elem, result.Sequence())

	return value, err == nil, err
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

func (c *compiler) evaluateStaticDeclarations(ctx context.Context, root *xdm.Element, speculative bool, moduleStaticNames []string) error {
	for child := range xdm.Children(root) {
		if err := ctx.Err(); err != nil {
			return err
		}

		elem, ok := child.(*xdm.Element)
		if !ok || !isStaticTopLevelDeclaration(elem) {
			continue
		}

		if err := c.evaluateStaticDeclaration(ctx, elem, speculative, moduleStaticNames); err != nil {
			return err
		}
	}

	return nil
}

func (c *compiler) evaluateStaticDeclaration(ctx context.Context, elem *xdm.Element, speculative bool, moduleStaticNames []string) error {
	include, err := c.topLevelDeclarationIncluded(ctx, elem)
	if err != nil {
		return staticDeclarationFailure(ctx, elem, err, speculative, moduleStaticNames)
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

	value, evaluated, err := c.tryEvaluateStaticSelect(ctx, elem, speculative)
	if err != nil {
		return staticDeclarationFailure(ctx, elem, err, speculative, moduleStaticNames)
	}

	if !evaluated {
		return nil
	}

	return c.setStaticVarWithKind(ctx, resolveQName(name, inScopeNamespaces(elem)), elem.LocalName(), value)
}

// Imports can establish missing bindings after the early pass. Type and control
// failures already have an authoritative cause and must not be deferred.
func staticDeclarationFailure(ctx context.Context, elem *xdm.Element, err error, speculative bool, moduleStaticNames []string) error {
	if failure := preserveControlFailure(ctx, err); failure != nil {
		return failure
	}

	if !speculative {
		return err
	}

	if detail, ok := errors.AsType[*xdm.Error](err); ok && (detail.Code == errCodeXTTE0590 || detail.Code == errCodeXTTE0570) {
		return err
	}

	name := getAttr(elem, xslAttrName)
	if errors.Is(err, xpath.ErrUndefinedVariable) && isForwardRef(err, moduleStaticNames, name) {
		return staticError(errCodeXPST0008, "static %s %q references undefined variable: %v", elem.LocalName(), name, err)
	}

	return nil
}

func (c *compiler) resolveImportShadowAttributes(ctx context.Context, root *xdm.Element) error {
	for child := range xdm.Children(root) {
		elem, ok := child.(*xdm.Element)
		if !ok || elem.URI() != lexicon.NamespaceXSLT {
			continue
		}

		ln := elem.LocalName()
		if ln == nameInclude || ln == lexicon.XSLTElementImport {
			if err := c.resolveShadowAttributes(ctx, elem); err != nil {
				return err
			}
		}
	}

	return nil
}

func (c *compiler) collectTopLevelImports(ctx context.Context, root *xdm.Element) error {
	if err := c.validateModuleImportOrder(ctx, root); err != nil {
		return err
	}

	for child := range xdm.Children(root) {
		elem, ok := child.(*xdm.Element)
		if !ok || elem.URI() != lexicon.NamespaceXSLT {
			continue
		}

		if c.ignoredTopLevelDeclaration(elem) {
			continue
		}

		switch elem.LocalName() {
		case lexicon.XSLTElementImport, lexicon.XSLTElementInclude:
			if err := c.collectTopLevelModule(ctx, elem); err != nil {
				return err
			}
		case lexicon.XSLTElementUsePackage:
			if err := c.collectTopLevelPackage(ctx, elem); err != nil {
				return err
			}
		}
	}

	return nil
}

func (c *compiler) collectTopLevelModule(ctx context.Context, elem *xdm.Element) error {
	include, err := c.topLevelUseWhen(ctx, elem)
	if err != nil || !include {
		return err
	}

	if err := c.validateXSLTAttrs(ctx, elem, attributeNames(nameHref, xslAttrUseWhen)); err != nil {
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

func (c *compiler) resolveStaticDeclarationShadows(ctx context.Context, root *xdm.Element) error {
	for child := range xdm.Children(root) {
		elem, ok := child.(*xdm.Element)
		if !ok || elem.URI() != lexicon.NamespaceXSLT {
			continue
		}

		ln := elem.LocalName()
		if ln == lexicon.XSLTElementParam || ln == nameVariable {
			if err := c.resolveSingleShadowAttribute(ctx, elem, nameStatic); err != nil {
				return err
			}
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

	if !elements.IsKnown(ln) || !elements.IsTopLevel(ln) {
		elemVer := getAttr(elem, paramVersion)
		if c.forwardsCompatible(c.effectiveVersion) || c.forwardsCompatible(elemVer) {
			return false, nil
		}
	}

	return false, err
}

// evaluateDeclarationUseWhen removes a static declaration's own value for this
// evaluation so self references report XPST0008, then restores the static scope.
func (c *compiler) evaluateDeclarationUseWhen(ctx context.Context, elem *xdm.Element, uw string) (bool, error) {
	savedNS, savedDefault, savedHas := c.nsBindings, c.xpathDefaultNS, c.hasXPathDefaultNS
	c.nsBindings = inScopeNamespaces(elem)

	c.xpathDefaultNS, c.hasXPathDefaultNS = c.declarationDefaultNamespace(elem)
	defer func() { c.nsBindings, c.xpathDefaultNS, c.hasXPathDefaultNS = savedNS, savedDefault, savedHas }()

	if isStaticTopLevelDeclaration(elem) {
		if selfName := resolveQName(getAttr(elem, xslAttrName), inScopeNamespaces(elem)); selfName != "" {
			if oldVal, had := c.staticVars[selfName]; had {
				delete(c.staticVars, selfName)

				defer func() { c.staticVars[selfName] = oldVal }()
			}
		}
	}

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
		elemVer := getAttr(elem, paramVersion)
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

func isStaticTopLevelDeclaration(elem *xdm.Element) bool {
	ln := elem.LocalName()

	return elem.URI() == lexicon.NamespaceXSLT &&
		(ln == lexicon.XSLTElementParam || ln == lexicon.XSLTElementVariable) &&
		xsdBoolTrue(getAttr(elem, nameStatic))
}
