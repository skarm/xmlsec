// Derived from lestrrat-go/helium at 7362c0a70122a757780f4d0b545a9b370dead6ab.
// Copyright (c) 2015 lestrrat. MIT License; see licenses/MIT-helium.txt at the repository root.

package xslt

import (
	"context"
	"maps"
	"strconv"
	"strings"

	"github.com/skarm/xmlsec/internal/xmlchar"
	"github.com/skarm/xmlsec/transform/internal/xdm"
	"github.com/skarm/xmlsec/transform/internal/xdm/lexicon"
	"github.com/skarm/xmlsec/transform/internal/xpath"
)

func templateAllowedAttrs(key string) bool {
	switch key {
	case nameMatch2, xslAttrName, "priority", nameMode, "as", xslAttrVisibility, xslAttrUseWhen:
		return true
	}

	return false
}

// splitOrigin identifies a union rule by allocation identity across packages.
// Its nonzero size guarantees distinct live identities for separate rules.
// Keep non-zero size so distinct origins have distinct pointer identities.
type splitOrigin struct{ _ byte }

func (c *compiler) compileTemplate(ctx context.Context, elem *xdm.Element) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	if err := c.validateXSLTAttrs(ctx, elem, templateAllowedAttrs); err != nil {
		return err
	}
	// A version attribute on the template governs its effective version — set it
	// before compiling the match pattern and body so their expressions are
	// backwards-compatible when it is < 2.0.
	defer c.pushElementVersion(elem)()
	// Collect namespace declarations and xpath-default-namespace before
	// evaluating use-when so the expression has the correct namespace context.
	c.collectNamespaces(ctx, elem)
	savedXPathDefaultNS := c.xpathDefaultNS

	savedHasXPathDefaultNS := c.hasXPathDefaultNS
	if xdn, ok := elem.GetAttribute(nameXpathDefaultNamespace); ok {
		c.xpathDefaultNS = xdn
		c.hasXPathDefaultNS = true
	}

	restoreXPathDefaultNS := func() {
		c.xpathDefaultNS = savedXPathDefaultNS
		c.hasXPathDefaultNS = savedHasXPathDefaultNS
	}

	if uw := getAttr(elem, xslAttrUseWhen); uw != "" {
		include, err := c.evaluateUseWhen(ctx, uw)
		if err != nil {
			restoreXPathDefaultNS()
			return err
		}

		if !include {
			restoreXPathDefaultNS()
			return nil
		}
	}

	// Compute effective base URI considering xml:base on the template element.
	// Only check the template element itself (not ancestors), since c.baseURI
	// already accounts for xml:base on the stylesheet root and includes.
	templateBaseURI := c.baseURI
	if xmlBase, ok := elem.GetAttributeNS("base", lexicon.NamespaceXML); ok && xmlBase != "" {
		templateBaseURI = xdm.BuildURI(xmlBase, c.baseURI)
	}

	tmpl := &template{
		ImportPrec:    c.importPrec,
		MinImportPrec: c.minImportPrec,
		BaseURI:       templateBaseURI,
	}
	tmpl.XPathDefaultNS = c.xpathDefaultNS

	defer restoreXPathDefaultNS()

	// Inherit or override default-collation
	savedDefaultCollation := c.defaultCollation

	if dc := getAttr(elem, nameDefaultCollation); dc != "" {
		if uri := resolveDefaultCollation(dc); uri != "" {
			c.defaultCollation = uri
		}
	}

	tmpl.DefaultCollation = c.defaultCollation
	defer func() { c.defaultCollation = savedDefaultCollation }()

	matchAttr := getAttr(elem, nameMatch2)
	if matchAttr != "" {
		p, err := c.compilePattern(matchAttr, elem, c.xpathDefaultNS, c.hasXPathDefaultNS)
		if err != nil {
			return err
		}

		tmpl.Match = p
		// Defer function validation until after all xsl:function declarations are processed.
		c.pendingPatternValidations = append(c.pendingPatternValidations, pendingPatternValidation{p, matchAttr})
	}

	name, err := c.checkTemplateName(ctx, elem, matchAttr)
	if err != nil {
		return err
	}

	tmpl.Name = name

	// XSLT 3.0 §3.8.2: default-mode on xsl:template affects both the
	// template's own mode (when mode is omitted) and xsl:apply-templates
	// within the template body. Read it before resolving the mode so
	// the template's own default-mode is visible to the mode defaulting.
	savedDefaultMode := c.defaultMode
	if dm := getAttr(elem, nameDefaultMode); dm != "" {
		c.defaultMode = dm
	}
	defer func() { c.defaultMode = savedDefaultMode }()

	if err := c.compileTemplateModeAndPriority(ctx, elem, tmpl, matchAttr); err != nil {
		return err
	}

	ctxDecl, body, params, err := c.compileScopedTemplateBody(ctx, elem)
	if err != nil {
		return err
	}

	tmpl.Params = params
	tmpl.Body = body

	if ctxDecl != nil {
		tmpl.ContextItemAs = ctxDecl.as
		tmpl.ContextItemUse = ctxDecl.use
	}

	tmplAs := getAttr(elem, "as")
	if err := c.validateAsSequenceType(ctx, tmplAs, "xsl:template"); err != nil {
		return err
	}

	tmpl.As = tmplAs
	tmpl.Visibility = getAttr(elem, xslAttrVisibility)
	// Only set Version when the template has its own version attribute.
	// Stylesheet-level version is NOT propagated to templates because
	// shadow attributes (_version) may override the stylesheet version.
	tmpl.Version = getAttr(elem, paramVersion)
	if c.stylesheet.isPackage {
		tmpl.OwnerPackage = c.stylesheet
	}

	return c.registerCompiledTemplate(ctx, tmpl)
}

func (c *compiler) compileTemplateModeAndPriority(ctx context.Context, elem *xdm.Element, tmpl *template, matchAttr string) error {
	if err := c.checkTemplateMode(elem); err != nil {
		return err
	}

	modeAttr := getAttr(elem, nameMode)
	if modeAttr != "" {
		// Resolve mode QNames to Clark notation for namespace-aware matching
		tmpl.Mode = c.resolveMode(ctx, modeAttr)
	}
	// XSLT 3.0 §6.7: if the stylesheet (or an included/imported module) has
	// default-mode, templates without an explicit mode attribute belong to it.
	if tmpl.Mode == "" && c.defaultMode != "" {
		tmpl.Mode = c.resolveMode(ctx, c.defaultMode)
	}

	// Record mode usage for XTSE3085 checking (only match templates have modes)
	if matchAttr != "" {
		c.recordModeUsage(ctx, tmpl.Mode)
	}

	if prio := getAttr(elem, "priority"); prio != "" {
		f, err := parseTemplatePriority(prio)
		if err != nil {
			return err
		}

		tmpl.Priority = f
		tmpl.explicitPriority = true
	} else if tmpl.Match != nil && len(tmpl.Match.Alternatives) == 1 {
		tmpl.Priority = tmpl.Match.Alternatives[0].priority
	}

	return nil
}

// parseTemplatePriority parses xsl:template's priority attribute, which must
// be a valid xs:decimal (XTSE0530).
func parseTemplatePriority(prio string) (float64, error) {
	// XTSE0530: priority must be a valid xs:decimal — no exponent notation.
	if !isXSDecimal(prio) {
		return 0, staticError(errCodeXTSE0530, "priority %q is not a valid xs:decimal", prio)
	}
	// xs:decimal ignores leading and trailing whitespace; isXSDecimal already
	// trims it, so ParseFloat must see the trimmed form too.
	f, err := strconv.ParseFloat(strings.TrimSpace(prio), 64)
	if err != nil {
		return 0, staticError(errCodeXTSE0530, "invalid priority %q: %v", prio, err)
	}

	return f, nil
}

// templateResultExcludes resolves prefixes at the declaration site and returns
// the existing set unchanged when the template has no local exclusion setting.
func (c *compiler) templateResultExcludes(elem *xdm.Element) map[string]struct{} {
	if erp := getAttr(elem, nameExcludeResultPrefixes); erp != "" {
		newExcludes := make(map[string]struct{})
		maps.Copy(newExcludes, c.localExcludes)

		if erp == lexicon.ModeAll {
			for prefix := range c.stylesheet.namespaces {
				if uri, ok := c.nsBindings[prefix]; ok && uri != "" {
					newExcludes[uri] = struct{}{}
				}
			}
		} else {
			for prefix := range strings.FieldsSeq(erp) {
				if uri, ok := c.nsBindings[prefix]; ok && uri != "" {
					newExcludes[uri] = struct{}{}
				}
			}
		}

		return newExcludes
	}

	return c.localExcludes
}

func (c *compiler) compileScopedTemplateBody(ctx context.Context, elem *xdm.Element) (*contextItemDecl, []instruction, []*param, error) {
	savedExcludes, savedExpandText, savedPreserveSpace := c.localExcludes, c.expandText, c.preserveSpace

	c.localExcludes = c.templateResultExcludes(elem)
	defer func() {
		c.localExcludes, c.expandText, c.preserveSpace = savedExcludes, savedExpandText, savedPreserveSpace
	}()

	if value, present := elem.GetAttribute(nameExpandText); present {
		expand, ok := parseXSDBool(value)
		if !ok {
			return nil, nil, nil, staticError(errCodeXTSE0020, "%q is not a valid value for xsl:template/@expand-text", value)
		}

		c.expandText = expand
	}

	if value := getAttr(elem, lexicon.QNameXMLSpace); value != "" {
		c.preserveSpace = value == lexicon.SpacePreserve
	}

	return c.compileTemplateBodyEx(ctx, elem, false)
}

func (c *compiler) registerCompiledTemplate(ctx context.Context, tmpl *template) error {
	// Register the template
	c.stylesheet.templates = append(c.stylesheet.templates, tmpl)

	if tmpl.Name != "" {
		if existing, exists := c.stylesheet.namedTemplates[tmpl.Name]; exists {
			// Same import precedence = error; different = higher precedence wins
			if existing.ImportPrec == tmpl.ImportPrec {
				return staticError(errCodeXTSE0080, "duplicate template name %q", tmpl.Name)
			}

			if tmpl.ImportPrec > existing.ImportPrec {
				c.stylesheet.namedTemplates[tmpl.Name] = tmpl
			}
			// else keep existing (higher precedence)
		} else {
			c.stylesheet.namedTemplates[tmpl.Name] = tmpl
		}
	}

	if tmpl.Match != nil {
		mode := tmpl.Mode
		for _, rule := range templateRules(tmpl) {
			c.registerTemplateInModes(ctx, rule, mode)
		}
	}

	return nil
}

func nextSplitOriginID() *splitOrigin { return &splitOrigin{} }

// templateRules returns the template rules a match template contributes to
// its modes. XSLT 3.0 §6.4: a template rule whose pattern is a union P1 | P2
// and that has no priority attribute is treated as one template rule per
// alternative, each with that alternative's default priority (§6.5), so the
// union is split into one template entry per alternative. Any other template
// is its own single rule. Every caller that registers a template in a mode
// list (a local template, a used package's template, an xsl:override
// template) goes through here so all of them split the same way.
func templateRules(tmpl *template) []*template {
	if tmpl.explicitPriority || len(tmpl.Match.Alternatives) <= 1 {
		return []*template{tmpl}
	}
	// All split branches of one union rule share a stable origin id so the
	// on-multiple-match conflict checks can recognize them as a single rule
	// even when they have an empty body (no &Body[0] identity to compare).
	// See hasConflictingMatch / hasConflictingAtomicMatch.
	//
	// The id must be unique across the entire compilation, not just within
	// one stylesheet/package: under xsl:use-package, split templates from
	// different packages are merged into one mode list, and a per-stylesheet
	// counter (which restarts at 0 per compile) would hand identical ids to
	// unrelated union rules from different packages, wrongly suppressing a
	// genuine cross-package XTDE0540 match. The allocation identity of a
	// nonzero-size object guarantees distinct identities for live union rules.
	originID := nextSplitOriginID()

	rules := make([]*template, 0, len(tmpl.Match.Alternatives))
	for _, alt := range tmpl.Match.Alternatives {
		split := *tmpl // shallow copy shares Body, Params, etc.
		// Copy the whole pattern so each alternative keeps every compile-site
		// property (namespace context, xpath-default-namespace,
		// backwards-compatible processing, compiled predicates); only the
		// alternative list narrows.
		altPattern := *tmpl.Match
		altPattern.Alternatives = []*patternAlt{alt}
		split.Match = &altPattern
		split.Priority = alt.priority
		split.splitOriginID = originID
		rules = append(rules, &split)
	}

	return rules
}

// checkTemplateName validates xsl:template's name attribute and the
// attribute combinations that depend on match and name (XTSE0020, XTSE0080,
// XTSE0500), and returns the resolved name ("" when there is none). It applies
// to a top-level xsl:template and to one inside xsl:override alike.
func (c *compiler) checkTemplateName(ctx context.Context, elem *xdm.Element, matchAttr string) (string, error) {
	nameAttr := strings.TrimSpace(getAttr(elem, xslAttrName))
	if nameAttr != "" && !xmlchar.IsValidQName(nameAttr) && !isValidEQName(nameAttr) {
		return "", staticError(errCodeXTSE0020, "invalid name %q on xsl:template", nameAttr)
	}

	if nameAttr != "" {
		if err := c.checkQNamePrefix(ctx, nameAttr, "xsl:template"); err != nil {
			return "", err
		}
	}

	name := resolveQName(nameAttr, c.nsBindings)

	// XTSE0080: template name must not be in the XSLT namespace
	// Exception: xsl:initial-template is explicitly allowed (XSLT 3.0 §3.11).
	if name != "" && strings.HasPrefix(name, "{"+lexicon.NamespaceXSLT+"}") && name != xdm.ClarkName(lexicon.NamespaceXSLT, "initial-template") {
		return "", staticError(errCodeXTSE0080, "xsl:template name %q is in the XSLT namespace", getAttr(elem, xslAttrName))
	}

	// XTSE0500: template must have match or name (or both).
	if matchAttr == "" && name == "" {
		return "", staticError(errCodeXTSE0500, "xsl:template must have a @match or @name attribute")
	}
	// XTSE0500: template without match must not have mode or priority.
	if matchAttr == "" {
		if _, hasMode := elem.GetAttribute(nameMode); hasMode {
			return "", staticError(errCodeXTSE0500, "xsl:template without @match must not have @mode")
		}

		if _, hasPrio := elem.GetAttribute("priority"); hasPrio {
			return "", staticError(errCodeXTSE0500, "xsl:template without @match must not have @priority")
		}
	}
	// XTSE0500: template without name must not have visibility.
	if name == "" {
		if _, hasVis := elem.GetAttribute(xslAttrVisibility); hasVis {
			return "", staticError(errCodeXTSE0500, "xsl:template without @name must not have @visibility")
		}
	}

	return name, nil
}

// checkTemplateMode validates xsl:template's mode attribute (XTSE0550,
// XTSE0280). It applies to a top-level xsl:template and to one inside
// xsl:override alike.
func (c *compiler) checkTemplateMode(elem *xdm.Element) error {
	if modeAttrVal, hasMode := elem.GetAttribute(nameMode); hasMode {
		// XTSE0550: empty mode list is invalid.
		if strings.TrimSpace(modeAttrVal) == "" {
			return staticError(errCodeXTSE0550, "mode attribute on xsl:template must not be empty")
		}
	}

	modeAttr := getAttr(elem, nameMode)
	if modeAttr == "" {
		return nil
	}

	modeFields := strings.Fields(modeAttr)
	seenModes := make(map[string]struct{}, len(modeFields))
	hasAll := false

	for _, m := range modeFields {
		if m[0] != '#' && !xmlchar.IsValidQName(m) && !isValidEQName(m) {
			return staticError(errCodeXTSE0550, "invalid mode name %q on xsl:template", m)
		}
		// XTSE0280: check for undeclared prefix in mode name.
		if idx := strings.IndexByte(m, ':'); idx > 0 {
			prefix := m[:idx]
			if _, ok := c.nsBindings[prefix]; !ok {
				return staticError(errCodeXTSE0280, "undeclared namespace prefix %q in mode name %q", prefix, m)
			}
		}

		if m == modeAll {
			hasAll = true
		}

		if _, dup := seenModes[m]; dup {
			return staticError(errCodeXTSE0550, "duplicate mode %q in xsl:template/@mode", m)
		}

		seenModes[m] = struct{}{}
	}

	if hasAll && len(modeFields) > 1 {
		return staticError(errCodeXTSE0550, "#all must not appear with other modes in xsl:template/@mode")
	}

	return nil
}

// registerTemplateInModes adds a template to the appropriate mode template lists.
func (c *compiler) registerTemplateInModes(_ context.Context, tmpl *template, mode string) {
	if mode == modeAll {
		// Register in all existing modes plus default
		for m := range c.stylesheet.modeTemplates {
			c.stylesheet.modeTemplates[m] = append(c.stylesheet.modeTemplates[m], tmpl)
		}

		c.stylesheet.modeTemplates[""] = append(c.stylesheet.modeTemplates[""], tmpl)
		// Also store under the modeAll key so findBestTemplate's fallback
		// can find these templates for modes that don't exist yet.
		c.stylesheet.modeTemplates[modeAll] = append(c.stylesheet.modeTemplates[modeAll], tmpl)

		return
	}
	// XSLT 2.0+: mode can be a whitespace-separated list of mode names.
	// Each mode name can be a QName, "#default", "#unnamed", or lexicon.ModeAll.
	modes := strings.Fields(mode)
	if len(modes) <= 1 {
		// Single mode (or empty = default mode)
		if mode == modeDefault || mode == modeUnnamed {
			mode = ""
		}

		c.stylesheet.modeTemplates[mode] = append(c.stylesheet.modeTemplates[mode], tmpl)
	} else {
		for _, m := range modes {
			if m == modeDefault || m == modeUnnamed {
				m = ""
			} else if m == modeAll {
				// In a mode list, #all means register in all modes
				c.stylesheet.modeTemplates[modeAll] = append(c.stylesheet.modeTemplates[modeAll], tmpl)
				continue
			}

			c.stylesheet.modeTemplates[m] = append(c.stylesheet.modeTemplates[m], tmpl)
		}
	}
}

func (c *compiler) compileTemplateBody(ctx context.Context, elem *xdm.Element) ([]instruction, []*param, error) {
	_, body, params, err := c.compileTemplateBodyEx(ctx, elem, false)
	return body, params, err
}

func (c *compiler) compileTemplateBodyEx(ctx context.Context, elem *xdm.Element, isFunction bool) (*contextItemDecl, []instruction, []*param, error) {
	lastDecl := lastTemplateDeclaration(elem)

	body := templateBodyCompiler{
		compiler: c, isFunction: isFunction, lastDecl: lastDecl,
		inParams: true, pastDecls: lastDecl == nil,
	}
	for child := range xdm.Children(elem) {
		if err := body.compileChild(ctx, child); err != nil {
			return nil, nil, nil, err
		}
	}

	if err := validateUniqueTemplateParams(body.params); err != nil {
		return nil, nil, nil, err
	}

	return body.context, body.body, body.params, nil
}

// lastTemplateDeclaration bounds whitespace stripping in the prologue even
// when xml:space preserves whitespace elsewhere in the body.
func lastTemplateDeclaration(elem *xdm.Element) xdm.Node {
	var last xdm.Node

	for child := range xdm.Children(elem) {
		declaration, ok := child.(*xdm.Element)
		if !ok || declaration.URI() != lexicon.NamespaceXSLT {
			continue
		}

		if name := declaration.LocalName(); name == nameContextItem || name == lexicon.XSLTElementParam {
			last = child
		}
	}

	return last
}

func validateUniqueTemplateParams(params []*param) error {
	seen := make(map[string]struct{}, len(params))
	for _, param := range params {
		if _, duplicate := seen[param.Name]; duplicate {
			return staticError(errCodeXTSE0580, "duplicate parameter name %q", param.Name)
		}

		seen[param.Name] = struct{}{}
	}

	return nil
}

// validateContextItem checks compile-time constraints on xsl:context-item.
func (c *compiler) validateContextItem(ctx context.Context, elem *xdm.Element) error {
	// XTSE0090: reject unknown attributes (e.g. select)
	if err := c.validateXSLTAttrs(ctx, elem, contextItemAllowedAttrs); err != nil {
		return err
	}

	asAttr := getAttr(elem, "as")
	if asAttr != "" {
		// XTSE0020: occurrence indicators (?, *, +) not allowed
		trimmed := strings.TrimSpace(asAttr)
		if len(trimmed) > 0 {
			last := trimmed[len(trimmed)-1]
			if last == '?' || last == '*' || last == '+' {
				return staticError(errCodeXTSE0020,
					"xsl:context-item/@as must not have an occurrence indicator: %q", asAttr)
			}
		}
	}

	useAttr := strings.TrimSpace(getAttr(elem, nameUse))
	if useAttr != "" && useAttr != ctxItemRequired && useAttr != ctxItemOptional && useAttr != ctxItemAbsent {
		return staticError(errCodeXTSE0020,
			"xsl:context-item/@use must be 'required', 'optional', or 'absent': %q", useAttr)
	}

	// XTSE0020: if use="absent", cannot also have as=
	if useAttr == ctxItemAbsent && asAttr != "" {
		return staticError(errCodeXTSE0020,
			"xsl:context-item with use=\"absent\" must not have @as")
	}

	// xsl:context-item must not have child elements or text content
	for child := range xdm.Children(elem) {
		if child.Type() == xdm.ElementNode {
			return staticError(errCodeXTSE0010, "xsl:context-item must be empty")
		}

		if child.Type() == xdm.TextNode {
			if !c.shouldStripText(ctx, xdm.CharacterData(child)) {
				return staticError(errCodeXTSE0010, "xsl:context-item must be empty")
			}
		}
	}

	return nil
}

func (c *compiler) compileParamDef(ctx context.Context, elem *xdm.Element) (*param, error) {
	// A static="yes" parameter is a compile-time static-context value and is
	// version-independent (forced non-compat even inside a version < 2.0 module);
	// a non-static param honors its own version attribute.
	if xsdBoolTrue(getAttr(elem, nameStatic)) {
		defer c.pushStaticVersion()()
	} else {
		defer c.pushElementVersion(elem)()
	}

	savedNS := c.pushElementNamespaces(ctx, elem)
	defer func() { c.nsBindings = savedNS }()

	// Validate attributes on xsl:param
	if err := c.validateXSLTAttrs(ctx, elem, paramAllowedAttrs); err != nil {
		return nil, err
	}

	name := getAttr(elem, xslAttrName)
	if name == "" {
		return nil, staticError(errCodeXTSE0110, "xsl:param requires name attribute")
	}

	if !xmlchar.IsValidQName(name) && !isValidEQName(name) {
		return nil, staticError(errCodeXTSE0020, "invalid name %q on xsl:param", name)
	}

	// Validate boolean attribute values (including empty string)
	if reqAttr, hasReq := elem.GetAttribute(ctxItemRequired); hasReq {
		if err := validateBooleanAttr("xsl:param", ctxItemRequired, reqAttr); err != nil {
			return nil, err
		}
	}

	if tunnelAttr, hasTunnel := elem.GetAttribute(nameTunnel); hasTunnel {
		if err := validateBooleanAttr("xsl:param", nameTunnel, tunnelAttr); err != nil {
			return nil, err
		}
	}

	required := getAttr(elem, ctxItemRequired) == lexicon.ValueYes

	if required {
		if err := validateRequiredParamDefault(elem); err != nil {
			return nil, err
		}
	}

	// XTSE0020: validate static attribute (boolean)
	if staticVal, hasStatic := elem.GetAttribute(nameStatic); hasStatic {
		if err := validateBooleanAttr("xsl:param", nameStatic, staticVal); err != nil {
			return nil, err
		}
	}

	// XTSE0010: A static parameter must not have a sequence constructor (body content).
	// Static params default to empty sequence when no select is provided.
	isStatic := xsdBoolTrue(getAttr(elem, nameStatic))

	// XTSE0020: static parameter must not have tunnel="yes"
	if isStatic && xsdBoolTrue(getAttr(elem, nameTunnel)) {
		return nil, staticError(errCodeXTSE0020,
			"xsl:param %q with static='yes' must not have tunnel='yes'", name)
	}

	if isStatic && hasParamDefaultContent(elem) {
		return nil, staticError(errCodeXTSE0010,
			"xsl:param %q with static='yes' must not have content (use select attribute instead)", name)
	}

	asAttr := getAttr(elem, "as")
	if err := c.validateAsSequenceType(ctx, asAttr, "xsl:param "+name); err != nil {
		return nil, err
	}

	p := &param{
		Name:       resolveQName(name, c.nsBindings),
		As:         asAttr,
		Required:   required,
		Tunnel:     xsdBoolTrue(getAttr(elem, nameTunnel)),
		Visibility: getAttr(elem, xslAttrVisibility),
	}

	// Capture the declaration-site static base URI (the module base, plus any
	// xml:base override) so that body evaluation resolves resources against the
	// declaration site, never the currently-executing template's base URI.
	p.StaticBaseURI = stylesheetBaseURI(elem, c.baseURI, c.moduleRoot)

	selectAttr := getAttr(elem, xslAttrSelect)
	if selectAttr != "" {
		expr, err := c.compileXPath(selectAttr, c.nsBindings)
		if err != nil {
			return nil, err
		}

		p.Select = expr
	}

	if selectAttr == "" {
		body, err := c.compileChildren(ctx, elem)
		if err != nil {
			return nil, err
		}

		p.Body = body
	}

	return p, nil
}

// validateRequiredParamDefault rejects a supplied default before any static
// parameter checks, preserving declaration validation order.
func validateRequiredParamDefault(elem *xdm.Element) error {
	if getAttr(elem, xslAttrSelect) != "" {
		return staticError(errCodeXTSE0010, "xsl:param with required='yes' must not have a select attribute")
	}

	if hasParamDefaultContent(elem) {
		return staticError(errCodeXTSE0010, "xsl:param with required='yes' must not have content")
	}

	return nil
}

func hasParamDefaultContent(elem *xdm.Element) bool {
	for child := range xdm.Children(elem) {
		switch child.Type() {
		case xdm.ElementNode:
			return true
		case xdm.TextNode, xdm.CDATASectionNode:
			if !isXMLWhitespaceOnly(xdm.CharacterData(child)) {
				return true
			}
		}
	}

	return false
}

func (c *compiler) compileGlobalVariable(ctx context.Context, elem *xdm.Element) error {
	savedNS := c.pushElementNamespaces(ctx, elem)
	defer func() { c.nsBindings = savedNS }()

	// A version attribute on the declaration overrides the effective version for
	// its select/body (XSLT 3.0 §3.10), so a version="1.0" variable evaluates its
	// select in backwards-compatible / XPath 1.0 compatibility mode even when the
	// stylesheet module is 2.0/3.0. A static="yes" variable is exempt: it is a
	// compile-time static-context value, version-independent even in a < 2.0 module.
	if xsdBoolTrue(getAttr(elem, nameStatic)) {
		defer c.pushStaticVersion()()
	} else {
		defer c.pushElementVersion(elem)()
	}

	savedExpandText := c.expandText

	if et, hasET := elem.GetAttribute(nameExpandText); hasET {
		if v, ok := parseXSDBool(et); ok {
			c.expandText = v
		}
	}

	defer func() { c.expandText = savedExpandText }()

	// Validate attributes on xsl:variable
	if err := c.validateXSLTAttrs(ctx, elem, variableAllowedAttrs); err != nil {
		return err
	}

	name := getAttr(elem, xslAttrName)
	if name == "" {
		return staticError(errCodeXTSE0110, "xsl:variable requires name attribute")
	}

	if !xmlchar.IsValidQName(name) && !isValidEQName(name) {
		return staticError(errCodeXTSE0020, "invalid name %q on xsl:variable", name)
	}

	// XTSE0020: validate static attribute (boolean)
	if staticVal, hasStatic := elem.GetAttribute(nameStatic); hasStatic {
		if err := validateBooleanAttr("xsl:variable", nameStatic, staticVal); err != nil {
			return err
		}
	}

	// XTSE0020: static variable must not have visibility attribute
	if xsdBoolTrue(getAttr(elem, nameStatic)) {
		if vis := getAttr(elem, xslAttrVisibility); vis != "" {
			return staticError(errCodeXTSE0020,
				"xsl:variable %q with static='yes' must not have visibility attribute", name)
		}
	}

	asAttr := getAttr(elem, "as")
	if err := c.validateAsSequenceType(ctx, asAttr, "xsl:variable "+name); err != nil {
		return err
	}

	v := &variable{
		Name:           resolveQName(name, c.nsBindings),
		As:             asAttr,
		Visibility:     getAttr(elem, xslAttrVisibility),
		XPathDefaultNS: c.xpathDefaultNS,
	}
	if c.stylesheet.isPackage {
		v.OwnerPackage = c.stylesheet
	}

	// Capture the declaration-site static base URI (the module base, plus any
	// xml:base override) so that body evaluation resolves resources against the
	// declaration site, never the currently-executing template's base URI.
	v.StaticBaseURI = stylesheetBaseURI(elem, c.baseURI, c.moduleRoot)

	// For static variables, use the pre-computed value from compile-time
	// evaluation instead of the runtime select expression. This ensures
	// static variables reference other static variables' values, not
	// runtime non-static variables with the same name.
	if xsdBoolTrue(getAttr(elem, nameStatic)) {
		if sv, ok := c.staticVars[v.Name]; ok {
			v.StaticValue = sv
		}
	}

	selectAttr := getAttr(elem, xslAttrSelect)
	if selectAttr != "" {
		// XTSE0620: select and non-empty content are mutually exclusive.
		// Use-when-aware check: elements excluded by use-when don't count as content.
		if c.hasEffectiveContent(ctx, elem) {
			return staticError(errCodeXTSE0620, "xsl:variable %q has both @select and content", name)
		}

		expr, err := c.compileXPath(selectAttr, c.nsBindings)
		if err != nil {
			return err
		}
		// XPST0008: a global variable is out of scope within its own
		// declaration. Detect self-references in the select expression.
		if xpathExprReferencesVar(expr.AST(), name, c.nsBindings) {
			return staticError(errCodeXPST0008,
				"global variable %q references itself in its select expression", name)
		}

		v.Select = expr
	} else {
		body, err := c.compileChildren(ctx, elem)
		if err != nil {
			return err
		}

		v.Body = body
	}

	return c.registerGlobalVariable(v)
}

// xpathExprReferencesVar walks an XPath AST and returns true if any
// VariableExpr references the given variable name. The name parameter
// is the raw XSLT name attribute (may be prefixed like "ns:local");
// nsBindings are used to resolve prefixes for matching.
func xpathExprReferencesVar(expr xpath.Expr, name string, _ map[string]string) bool {
	if expr == nil {
		return false
	}

	// Determine the local name and optional resolved name for matching.
	// In XPath AST, VariableExpr stores Prefix and Name separately.
	rawLocal := name

	var rawPrefix string
	if p, l, ok := strings.Cut(name, ":"); ok {
		rawPrefix = p
		rawLocal = l
	}

	return xpathExprRefsVarWalk(expr, rawLocal, rawPrefix)
}

func xpathExprRefsVarWalk(expr xpath.Expr, local, prefix string) bool {
	switch node := expr.(type) {
	case xpath.VariableExpr:
		return node.Name == local && node.Prefix == prefix
	case xpath.InlineFunctionExpr:
		for _, param := range node.Params {
			if param.Name == local {
				return false // Shadowed inside the function body.
			}
		}

		return xpathExprRefsVarWalk(node.Body, local, prefix)
	case xpath.FLWORExpr:
		return xpathFLWORRefsVar(node, local, prefix)
	case xpath.QuantifiedExpr:
		return xpathQuantifiedRefsVar(node, local, prefix)
	default:
		return xpathCompositeRefsVar(expr, local, prefix)
	}
}

func xpathCompositeRefsVar(expr xpath.Expr, local, prefix string) bool {
	switch node := expr.(type) {
	case xpath.BinaryExpr, xpath.ConcatExpr, xpath.SimpleMapExpr, xpath.RangeExpr,
		xpath.UnionExpr, xpath.IntersectExceptExpr, xpath.PathStepExpr, xpath.IfExpr:
		return xpathBranchRefsVar(expr, local, prefix)
	case xpath.UnaryExpr:
		return xpathExprRefsVarWalk(node.Operand, local, prefix)
	case xpath.FilterExpr:
		return xpathExprRefsVarWalk(node.Expr, local, prefix) || xpathExprListRefsVar(node.Predicates, local, prefix)
	case xpath.PathExpr:
		return xpathPathRefsVar(node, local, prefix)
	case xpath.LookupExpr:
		return xpathExprRefsVarWalk(node.Expr, local, prefix) || xpathExprRefsVarWalk(node.Key, local, prefix)
	case xpath.UnaryLookupExpr:
		return xpathExprRefsVarWalk(node.Key, local, prefix)
	case xpath.FunctionCall:
		return xpathExprListRefsVar(node.Args, local, prefix)
	case xpath.DynamicFunctionCall:
		return xpathExprRefsVarWalk(node.Func, local, prefix) || xpathExprListRefsVar(node.Args, local, prefix)
	case xpath.TryCatchExpr:
		return xpathTryCatchRefsVar(node, local, prefix)
	case xpath.InstanceOfExpr:
		return xpathExprRefsVarWalk(node.Expr, local, prefix)
	case xpath.CastExpr:
		return xpathExprRefsVarWalk(node.Expr, local, prefix)
	case xpath.CastableExpr:
		return xpathExprRefsVarWalk(node.Expr, local, prefix)
	case xpath.TreatAsExpr:
		return xpathExprRefsVarWalk(node.Expr, local, prefix)
	case xpath.MapConstructorExpr:
		return xpathMapConstructorRefsVar(node, local, prefix)
	case xpath.ArrayConstructorExpr:
		return xpathExprListRefsVar(node.Items, local, prefix)
	case xpath.SequenceExpr:
		return xpathExprListRefsVar(node.Items, local, prefix)
	default:
		// Preserve the leaf treatment of bare LocationPath as well as literals,
		// root/context items, named functions and placeholders.
		return false
	}
}

func xpathBranchRefsVar(expr xpath.Expr, local, prefix string) bool {
	switch node := expr.(type) {
	case xpath.BinaryExpr:
		return xpathExprRefsVarWalk(node.Left, local, prefix) || xpathExprRefsVarWalk(node.Right, local, prefix)
	case xpath.ConcatExpr:
		return xpathExprRefsVarWalk(node.Left, local, prefix) || xpathExprRefsVarWalk(node.Right, local, prefix)
	case xpath.SimpleMapExpr:
		return xpathExprRefsVarWalk(node.Left, local, prefix) || xpathExprRefsVarWalk(node.Right, local, prefix)
	case xpath.RangeExpr:
		return xpathExprRefsVarWalk(node.Start, local, prefix) || xpathExprRefsVarWalk(node.End, local, prefix)
	case xpath.UnionExpr:
		return xpathExprRefsVarWalk(node.Left, local, prefix) || xpathExprRefsVarWalk(node.Right, local, prefix)
	case xpath.IntersectExceptExpr:
		return xpathExprRefsVarWalk(node.Left, local, prefix) || xpathExprRefsVarWalk(node.Right, local, prefix)
	case xpath.PathStepExpr:
		return xpathExprRefsVarWalk(node.Left, local, prefix) || xpathExprRefsVarWalk(node.Right, local, prefix)
	case xpath.IfExpr:
		return xpathExprRefsVarWalk(node.Cond, local, prefix) ||
			xpathExprRefsVarWalk(node.Then, local, prefix) ||
			xpathExprRefsVarWalk(node.Else, local, prefix)
	default:
		return false
	}
}

func xpathExprListRefsVar(exprs []xpath.Expr, local, prefix string) bool {
	for _, expr := range exprs {
		if xpathExprRefsVarWalk(expr, local, prefix) {
			return true
		}
	}

	return false
}

func xpathPathRefsVar(path xpath.PathExpr, local, prefix string) bool {
	if xpathExprRefsVarWalk(path.Filter, local, prefix) {
		return true
	}

	if path.Path != nil {
		for _, step := range path.Path.Steps {
			if xpathExprListRefsVar(step.Predicates, local, prefix) {
				return true
			}
		}
	}

	return false
}

func xpathFLWORRefsVar(expr xpath.FLWORExpr, local, prefix string) bool {
	for _, clause := range expr.Clauses {
		switch binding := clause.(type) {
		case xpath.ForClause:
			if xpathExprRefsVarWalk(binding.Expr, local, prefix) {
				return true
			}

			if binding.Var == local {
				return false // Subsequent clauses and return are shadowed.
			}
		case xpath.LetClause:
			if xpathExprRefsVarWalk(binding.Expr, local, prefix) {
				return true
			}

			if binding.Var == local {
				return false
			}
		}
	}

	return xpathExprRefsVarWalk(expr.Return, local, prefix)
}

func xpathQuantifiedRefsVar(expr xpath.QuantifiedExpr, local, prefix string) bool {
	for _, binding := range expr.Bindings {
		if xpathExprRefsVarWalk(binding.Domain, local, prefix) {
			return true
		}

		if binding.Var == local {
			return false
		}
	}

	return xpathExprRefsVarWalk(expr.Satisfies, local, prefix)
}

func xpathTryCatchRefsVar(expr xpath.TryCatchExpr, local, prefix string) bool {
	if xpathExprRefsVarWalk(expr.Try, local, prefix) {
		return true
	}

	for _, catch := range expr.Catches {
		if xpathExprRefsVarWalk(catch.Expr, local, prefix) {
			return true
		}
	}

	return false
}

func xpathMapConstructorRefsVar(expr xpath.MapConstructorExpr, local, prefix string) bool {
	for _, pair := range expr.Pairs {
		if xpathExprRefsVarWalk(pair.Key, local, prefix) || xpathExprRefsVarWalk(pair.Value, local, prefix) {
			return true
		}
	}

	return false
}

func (c *compiler) registerGlobalVariable(v *variable) error {
	// XTSE0630: duplicate global variable with same name and same import precedence.
	// Only flag duplicates within the same module (same importPrec).
	for _, existing := range c.stylesheet.globalVars {
		if existing.Name == v.Name && existing.ImportPrec == c.importPrec {
			return staticError(errCodeXTSE0630, "duplicate global variable %q", v.Name)
		}
	}

	for _, existing := range c.stylesheet.globalParams {
		if existing.Name == v.Name && existing.ImportPrec == c.importPrec {
			return staticError(errCodeXTSE0630, "duplicate global variable/param %q", v.Name)
		}
	}

	v.ImportPrec = c.importPrec
	c.stylesheet.globalVars = append(c.stylesheet.globalVars, v)

	return nil
}

func (c *compiler) compileGlobalParam(ctx context.Context, elem *xdm.Element) error {
	// A version attribute on the declaration overrides the effective version for
	// its select/body (XSLT 3.0 §3.10). A static="yes" parameter is exempt: it is
	// a compile-time static-context value, which is version-independent.
	if !xsdBoolTrue(getAttr(elem, nameStatic)) {
		defer c.pushElementVersion(elem)()
	}
	// XTSE0020: tunnel="yes" is not allowed on a stylesheet parameter
	if getAttr(elem, nameTunnel) == lexicon.ValueYes {
		return staticError(errCodeXTSE0020, "tunnel=\"yes\" is not allowed on a stylesheet parameter")
	}

	p, err := c.compileParamDef(ctx, elem)
	if err != nil {
		return err
	}

	if xsdBoolTrue(getAttr(elem, nameStatic)) {
		p.IsStatic = true
		p.StaticValue = xdm.CloneSequence(c.staticVars[p.Name])
	}
	// XTSE0630: duplicate global param/variable with same name and same import precedence
	for _, existing := range c.stylesheet.globalParams {
		if existing.Name == p.Name && existing.ImportPrec == c.importPrec {
			return staticError(errCodeXTSE0630, "duplicate global param %q", p.Name)
		}
	}

	for _, existing := range c.stylesheet.globalVars {
		if existing.Name == p.Name && existing.ImportPrec == c.importPrec {
			return staticError(errCodeXTSE0630, "duplicate global param/variable %q", p.Name)
		}
	}

	p.ImportPrec = c.importPrec
	c.stylesheet.globalParams = append(c.stylesheet.globalParams, p)

	return nil
}

// contextItemDecl holds the parsed xsl:context-item declaration from a template body.
type contextItemDecl struct {
	as  string // type constraint (e.g., "xs:string", "element()")
	use string // "required", "optional", "absent"
}

type templateBodyCompiler struct {
	lastDecl   xdm.Node
	compiler   *compiler
	context    *contextItemDecl
	params     []*param
	body       []instruction
	isFunction bool
	inParams   bool
	pastDecls  bool
	sawContent bool
}

func (b *templateBodyCompiler) compileChild(ctx context.Context, child xdm.Node) error {
	switch node := child.(type) {
	case *xdm.Element:
		return b.compileElement(ctx, node)
	case *xdm.Text:
		text := xdm.CharacterData(node)
		if !b.pastDecls && isXMLWhitespaceOnly(text) {
			return nil
		}

		if b.compiler.shouldStripText(ctx, text) {
			return nil
		}

		return b.appendText(text)
	case *xdm.CDATASection:
		return b.appendText(xdm.CharacterData(node))
	default:
		return nil
	}
}

func (b *templateBodyCompiler) compileElement(ctx context.Context, elem *xdm.Element) error {
	if elem.URI() == lexicon.NamespaceXSLT {
		switch elem.LocalName() {
		case lexicon.XSLTElementContextItem:
			if err := b.compileContextItem(ctx, elem); err != nil {
				return err
			}

			b.pastDecls = b.pastDecls || elem == b.lastDecl

			return nil
		case lexicon.XSLTElementParam:
			if err := b.compileParam(ctx, elem); err != nil {
				return err
			}

			b.pastDecls = b.pastDecls || elem == b.lastDecl

			return nil
		}
	}

	b.inParams, b.sawContent = false, true

	inst, err := b.compiler.compileInstruction(ctx, elem)
	if err != nil {
		return err
	}

	if inst != nil {
		b.body = append(b.body, inst)
	}

	return nil
}

func (b *templateBodyCompiler) compileContextItem(ctx context.Context, elem *xdm.Element) error {
	if b.isFunction {
		return staticError(errCodeXTSE0010, "xsl:context-item is not allowed in xsl:function")
	}

	if b.context != nil {
		return staticError(errCodeXTSE0010, "duplicate xsl:context-item")
	}

	if b.sawContent {
		return staticError(errCodeXTSE0010, "xsl:context-item must appear before other children")
	}

	if len(b.params) > 0 {
		return staticError(errCodeXTSE0010, "xsl:context-item must appear before xsl:param")
	}

	if err := b.compiler.validateContextItem(ctx, elem); err != nil {
		return err
	}

	// An omitted use stays empty; runtime selects the named/match default.
	b.context = &contextItemDecl{
		as: getAttr(elem, "as"), use: strings.TrimSpace(getAttr(elem, nameUse)),
	}

	return nil
}

func (b *templateBodyCompiler) compileParam(ctx context.Context, elem *xdm.Element) error {
	if !b.inParams {
		return staticError(errCodeXTSE0010,
			"xsl:param must appear before other content in xsl:template/xsl:function")
	}

	if _, hasStatic := elem.GetAttribute(nameStatic); hasStatic {
		return staticError(errCodeXTSE0020,
			"xsl:param %q: static attribute is not allowed on template/function parameters", getAttr(elem, xslAttrName))
	}

	param, err := b.compiler.compileParamDef(ctx, elem)
	if err != nil {
		return err
	}

	b.params = append(b.params, param)

	return nil
}

func (b *templateBodyCompiler) appendText(text string) error {
	b.inParams, b.sawContent = false, true

	inst := &literalTextInst{Value: text}
	if b.compiler.expandText && strings.ContainsAny(text, "{}") {
		avt, err := b.compiler.compileAVT(text, b.compiler.nsBindings)
		if err != nil {
			return err
		}

		inst.TVT = avt
	}

	b.body = append(b.body, inst)

	return nil
}

// contextItemAllowedAttrs lists the valid attributes for xsl:context-item.
func contextItemAllowedAttrs(key string) bool {
	switch key {
	case "as", nameUse:
		return true
	}

	return false
}
