// Derived from lestrrat-go/helium at 7362c0a70122a757780f4d0b545a9b370dead6ab.
// Copyright (c) 2015 lestrrat. MIT License; see licenses/MIT-helium.txt at the repository root.

package xslt

import (
	"context"
	"maps"
	"strings"

	"github.com/skarm/xmlsec/internal/xmlchar"
	"github.com/skarm/xmlsec/transform/internal/xdm"
	"github.com/skarm/xmlsec/transform/internal/xdm/lexicon"
)

func (c *compiler) compileApplyTemplates(ctx context.Context, elem *xdm.Element) (*applyTemplatesInst, error) {
	if err := c.validateXSLTAttrs(ctx, elem, attributeNames(xslAttrSelect, nameMode)); err != nil {
		return nil, err
	}

	mode, err := c.compileApplyTemplatesMode(ctx, elem)
	if err != nil {
		return nil, err
	}

	inst := &applyTemplatesInst{
		Mode: mode,
	}

	selectAttr := getAttr(elem, xslAttrSelect)
	if selectAttr != "" {
		expr, err := c.compileXPath(selectAttr, c.nsBindings)
		if err != nil {
			return nil, err
		}

		inst.Select = expr
	}

	for child := range xdm.Children(elem) {
		childElem, ok := child.(*xdm.Element)
		if !ok {
			// XTSE0010: non-element content not allowed in xsl:apply-templates
			if isNonWhitespaceTextNode(child) {
				return nil, staticError(errCodeXTSE0010, "text is not allowed as a child of xsl:apply-templates")
			}

			continue
		}

		if childElem.URI() != lexicon.NamespaceXSLT {
			return nil, staticError(errCodeXTSE0010, "non-XSLT element %q is not allowed as a child of xsl:apply-templates", childElem.Name())
		}

		switch childElem.LocalName() {
		case lexicon.XSLTElementSort:
			if err := c.appendCompiledSortKey(ctx, childElem, &inst.Sort); err != nil {
				return nil, err
			}
		case lexicon.XSLTElementWithParam:
			if err := c.appendCompiledWithParam(ctx, childElem, &inst.Params); err != nil {
				return nil, err
			}
		default:
			// XTSE0010: only xsl:sort and xsl:with-param are allowed
			return nil, staticError(errCodeXTSE0010, "xsl:%s is not allowed as a child of xsl:apply-templates", childElem.LocalName())
		}
	}

	return inst, nil
}

func (c *compiler) compileApplyTemplatesMode(ctx context.Context, elem *xdm.Element) (string, error) {
	mode := strings.TrimSpace(getAttr(elem, nameMode))
	// Validate mode name is a valid QName.
	if mode != "" && mode[0] != '#' {
		if !xmlchar.IsValidQName(mode) && !isValidEQName(mode) {
			return "", staticError(errCodeXTSE0550, "invalid mode name %q on xsl:apply-templates", mode)
		}
		// XTSE0280: check for undeclared prefix.
		if idx := strings.IndexByte(mode, ':'); idx > 0 {
			prefix := mode[:idx]
			if _, ok := c.nsBindings[prefix]; !ok {
				return "", staticError(errCodeXTSE0280, "undeclared namespace prefix %q in mode name %q", prefix, mode)
			}
		}
	}
	// When mode is absent, use the current default-mode (set by
	// compileInstruction from ancestor or self default-mode attributes).
	if mode == "" && c.defaultMode != "" {
		mode = c.defaultMode
	}
	// Resolve mode QName to Clark notation (namespace-aware)
	mode = c.resolveMode(ctx, mode)
	// Record mode usage for XTSE3085 checking
	if mode != modeCurrent {
		c.recordModeUsage(ctx, mode)
	}

	return mode, nil
}

func (c *compiler) appendCompiledSortKey(ctx context.Context, elem *xdm.Element, keys *[]*sortKey) error {
	if len(*keys) > 0 {
		if _, present := elem.GetAttribute("stable"); present {
			return staticError(errCodeXTSE1017, "the stable attribute is permitted only on the first xsl:sort element")
		}
	}

	key, err := c.compileSortKey(ctx, elem)
	if err != nil {
		return err
	}

	if key != nil {
		*keys = append(*keys, key)
	}

	return nil
}

func (c *compiler) appendCompiledWithParam(ctx context.Context, elem *xdm.Element, params *[]*withParam) error {
	param, err := c.compileWithParam(ctx, elem)
	if err != nil {
		return err
	}

	if param == nil {
		return nil
	}

	if err := checkDuplicateWithParam(*params, param); err != nil {
		return err
	}

	*params = append(*params, param)

	return nil
}

func (c *compiler) compileCallTemplate(ctx context.Context, elem *xdm.Element) (*callTemplateInst, error) {
	if err := c.validateXSLTAttrs(ctx, elem, attributeNames(xslAttrName)); err != nil {
		return nil, err
	}

	name := strings.TrimSpace(getAttr(elem, xslAttrName))
	if name == "" {
		return nil, staticError(errCodeXTSE0110, "xsl:call-template requires name attribute")
	}

	inst := &callTemplateInst{Name: resolveQName(name, c.nsBindings), Compat: c.backwardsCompatible()}

	for child := range xdm.Children(elem) {
		childElem, ok := child.(*xdm.Element)
		if !ok {
			if isNonWhitespaceTextNode(child) {
				return nil, staticError(errCodeXTSE0010, "text is not allowed as a child of xsl:call-template")
			}

			continue
		}

		if childElem.URI() != lexicon.NamespaceXSLT {
			return nil, staticError(errCodeXTSE0010, "non-XSLT element %q is not allowed as a child of xsl:call-template", childElem.Name())
		}

		if childElem.LocalName() != lexicon.XSLTElementWithParam {
			return nil, staticError(errCodeXTSE0010, "xsl:%s is not allowed as a child of xsl:call-template", childElem.LocalName())
		}

		wp, err := c.compileWithParam(ctx, childElem)
		if err != nil {
			return nil, err
		}

		if wp != nil {
			if err := checkDuplicateWithParam(inst.Params, wp); err != nil {
				return nil, err
			}

			inst.Params = append(inst.Params, wp)
		}
	}

	return inst, nil
}

func (c *compiler) compileIf(ctx context.Context, elem *xdm.Element) (*ifInst, error) {
	testAttr := getAttr(elem, nameTest2)
	if testAttr == "" {
		return nil, staticError(errCodeXTSE0110, "xsl:if requires test attribute")
	}

	expr, err := c.compileXPath(testAttr, c.nsBindings)
	if err != nil {
		return nil, err
	}

	body, err := c.compileChildren(ctx, elem)
	if err != nil {
		return nil, err
	}

	return &ifInst{Test: expr, Body: body}, nil
}

func (c *compiler) compileChoose(ctx context.Context, elem *xdm.Element) (*chooseInst, error) {
	inst := &chooseInst{DefaultCollation: c.defaultCollation}
	hasOtherwise := false

	for child := range xdm.Children(elem) {
		// XTSE0010: xsl:choose must contain only xsl:when and xsl:otherwise elements
		switch child.(type) {
		case *xdm.Text, *xdm.CDATASection:
			if !isXMLWhitespaceOnly(xdm.CharacterData(child)) {
				return nil, staticError(errCodeXTSE0010, "text is not allowed as a child of xsl:choose")
			}

			continue
		case *xdm.Element:
			// handled below
		default:
			continue
		}

		childElem, _ := xdm.AsNode[*xdm.Element](child)
		if childElem.URI() != lexicon.NamespaceXSLT {
			return nil, staticError(errCodeXTSE0010, "non-XSLT element %q is not allowed as a child of xsl:choose", childElem.Name())
		}

		switch childElem.LocalName() {
		case lexicon.XSLTElementWhen:
			// XTSE0010: xsl:when must not appear after xsl:otherwise
			if hasOtherwise {
				return nil, staticError(errCodeXTSE0010, "xsl:when must not appear after xsl:otherwise in xsl:choose")
			}

			clause, err := c.compileWhenClause(ctx, childElem)
			if err != nil {
				return nil, err
			}

			inst.When = append(inst.When, clause)

		case lexicon.XSLTElementOtherwise:
			// XTSE0010: at most one xsl:otherwise is allowed
			if hasOtherwise {
				return nil, staticError(errCodeXTSE0010, "xsl:choose must not contain more than one xsl:otherwise")
			}

			hasOtherwise = true

			if err := c.compileOtherwiseClause(ctx, childElem, inst); err != nil {
				return nil, err
			}

		default:
			// XTSE0010: only xsl:when and xsl:otherwise are allowed inside xsl:choose
			return nil, staticError(errCodeXTSE0010, "xsl:%s is not allowed as a child of xsl:choose", childElem.LocalName())
		}
	}

	// XTSE0010: xsl:choose must contain at least one xsl:when
	if len(inst.When) == 0 {
		return nil, staticError(errCodeXTSE0010, "xsl:choose must contain at least one xsl:when")
	}

	return inst, nil
}

func (c *compiler) compileWhenClause(ctx context.Context, elem *xdm.Element) (*whenClause, error) {
	savedBindings := c.pushElementNamespaces(ctx, elem)
	hasLocal, restoreText := c.pushFlowClauseTextContext(elem)

	restoreVersion := c.pushElementVersion(elem)
	defer func() {
		c.nsBindings = savedBindings

		restoreText()
		restoreVersion()
	}()

	testAttr := getAttr(elem, nameTest2)
	if testAttr == "" {
		return nil, staticError(errCodeXTSE0110, "xsl:when requires test attribute")
	}

	expression, err := c.compileXPath(testAttr, c.nsBindings)
	if err != nil {
		return nil, err
	}

	var namespaces map[string]string
	if len(c.nsBindings) > 0 {
		namespaces = make(map[string]string, len(c.nsBindings))
		maps.Copy(namespaces, c.nsBindings)
	}

	collation := getAttr(elem, nameDefaultCollation)
	body, err := c.compileChildren(ctx, elem)
	clause := &whenClause{Test: expression, Body: body, Namespaces: namespaces, DefaultCollation: collation}
	clause.XPathDefaultNS = c.xpathDefaultNS
	clause.HasXPathDefaultNS = hasLocal

	if err != nil {
		return nil, err
	}

	return clause, nil
}

// pushFlowClauseTextContext preserves the clause's permissive expand-text
// parsing and records whether xpath-default-namespace was locally specified.
func (c *compiler) pushFlowClauseTextContext(elem *xdm.Element) (bool, func()) {
	savedNS := c.xpathDefaultNS
	savedHasNS := c.hasXPathDefaultNS
	savedExpand := c.expandText
	hasLocal := false

	if namespace, present := elem.GetAttribute(nameXpathDefaultNamespace); present {
		c.xpathDefaultNS = namespace
		c.hasXPathDefaultNS = true
		hasLocal = true
	}

	if text := getAttr(elem, nameExpandText); text != "" {
		if value, valid := parseXSDBool(text); valid {
			c.expandText = value
		}
	}

	return hasLocal, func() {
		c.xpathDefaultNS = savedNS
		c.hasXPathDefaultNS = savedHasNS
		c.expandText = savedExpand
	}
}

func (c *compiler) compileOtherwiseClause(ctx context.Context, elem *xdm.Element, inst *chooseInst) error {
	hasLocal, restore := c.pushFlowClauseTextContext(elem)
	defer restore()

	body, err := c.compileChildren(ctx, elem)
	if hasLocal {
		inst.OtherwiseXPNS = c.xpathDefaultNS
		inst.HasOtherwiseXPNS = true
	}

	if err != nil {
		return err
	}

	inst.Otherwise = body

	return nil
}

func (c *compiler) compileForEach(ctx context.Context, elem *xdm.Element) (*forEachInst, error) {
	// xsl:break / xsl:next-iteration not allowed inside xsl:for-each.
	savedBreak := c.breakAllowed

	c.breakAllowed = false
	defer func() { c.breakAllowed = savedBreak }()

	selectAttr := getAttr(elem, xslAttrSelect)
	if selectAttr == "" {
		return nil, staticError(errCodeXTSE0110, "xsl:for-each requires select attribute")
	}

	expr, err := c.compileXPath(selectAttr, c.nsBindings)
	if err != nil {
		return nil, err
	}

	inst := &forEachInst{Select: expr}

	lastSort, err := c.collectForEachSorts(ctx, elem, inst)
	if err != nil {
		return nil, err
	}

	if err := c.compileForEachBody(ctx, elem, inst, lastSort); err != nil {
		return nil, err
	}

	return inst, nil
}

func (c *compiler) collectForEachSorts(ctx context.Context, elem *xdm.Element, inst *forEachInst) (xdm.Node, error) {
	var lastSort xdm.Node

	pastContent := false

	for child := range xdm.Children(elem) {
		element, ok := child.(*xdm.Element)
		if !ok {
			continue
		}

		if element.URI() != lexicon.NamespaceXSLT || element.LocalName() != lexicon.XSLTElementSort {
			pastContent = true
			continue
		}

		if pastContent {
			return nil, staticError(errCodeXTSE0010, "xsl:sort must come before other content in xsl:for-each")
		}

		lastSort = child

		if err := c.appendCompiledSortKey(ctx, element, &inst.Sort); err != nil {
			return nil, err
		}
	}

	return lastSort, nil
}

func (c *compiler) compileForEachBody(ctx context.Context, elem *xdm.Element, inst *forEachInst, lastSort xdm.Node) error {
	pastSort := lastSort == nil // true once we've passed all sort elements
	for child := range xdm.Children(elem) {
		if child == lastSort {
			pastSort = true
			continue
		}

		switch v := child.(type) {
		case *xdm.Element:
			if v.URI() == lexicon.NamespaceXSLT && v.LocalName() == lexicon.XSLTElementSort {
				continue
			}

			pastSort = true

			childInst, err := c.compileInstruction(ctx, v)
			if err != nil {
				return err
			}

			if childInst != nil {
				inst.Body = append(inst.Body, childInst)
			}
		case *xdm.Text:
			text := xdm.CharacterData(v)
			// Strip whitespace-only text nodes in the sort region (before/between sorts)
			if !pastSort && isXMLWhitespaceOnly(text) {
				continue
			}

			if !c.shouldStripText(ctx, text) {
				lit, err := c.compileLiteralText(text)
				if err != nil {
					return err
				}

				inst.Body = append(inst.Body, lit)
			}
		case *xdm.CDATASection:
			lit, err := c.compileLiteralText(xdm.CharacterData(v))
			if err != nil {
				return err
			}

			inst.Body = append(inst.Body, lit)
		}
	}

	return nil
}

func (c *compiler) compileSortKey(ctx context.Context, elem *xdm.Element) (*sortKey, error) {
	defer c.pushElementVersion(elem)()

	if uw := getAttr(elem, xslAttrUseWhen); uw != "" {
		include, err := c.evaluateUseWhen(ctx, uw)
		if err != nil {
			return nil, err
		}

		if !include {
			return nil, nil //nolint:nilnil
		}
	}

	// Validate boolean attribute: stable (including empty string).
	// Skip validation for AVTs (contain '{' and '}') since the value
	// is determined at runtime.
	if stableAttr, hasStable := elem.GetAttribute("stable"); hasStable {
		if !strings.ContainsAny(stableAttr, "{}") {
			if err := validateBooleanAttr("xsl:sort", "stable", stableAttr); err != nil {
				return nil, err
			}
		}
	}

	sk := &sortKey{forwards10: isBackwardsCompatible(c.stylesheet.version) && forwards10(elem)}

	selectAttr := getAttr(elem, xslAttrSelect)
	// XTSE1015: xsl:sort with select must not have content
	if selectAttr != "" && c.hasEffectiveContent(ctx, elem) {
		return nil, staticError(errCodeXTSE1015, "xsl:sort with a select attribute must not have content")
	}

	if selectAttr != "" {
		expr, err := c.compileXPath(selectAttr, c.nsBindings)
		if err != nil {
			return nil, err
		}

		sk.Select = expr
	} else {
		body, err := c.compileChildren(ctx, elem)
		if err != nil {
			return nil, err
		}

		if len(body) > 0 {
			sk.Body = body
		} else {
			expr, err := c.compileXPath(".", c.nsBindings)
			if err != nil {
				return nil, err
			}

			sk.Select = expr
		}
	}

	if err := c.compileSortKeyOptions(elem, sk); err != nil {
		return nil, err
	}

	return sk, nil
}

func (c *compiler) compileSortKeyOptions(elem *xdm.Element, key *sortKey) error {
	for _, option := range []struct {
		name   string
		target **avt
	}{
		{nameOrder, &key.Order},
		{nameDataType, &key.DataType},
		{nameCaseOrder, &key.CaseOrder},
		{nameLang, &key.Lang},
		{nameCollation, &key.Collation},
		{"stable", &key.Stable},
	} {
		value := getAttr(elem, option.name)
		if value == "" {
			continue
		}

		compiled, err := c.compileAVT(value, c.nsBindings)
		if err != nil {
			return err
		}

		*option.target = compiled
	}

	return nil
}

func (c *compiler) compileWithParam(ctx context.Context, elem *xdm.Element) (*withParam, error) {
	defer c.pushElementVersion(elem)()

	if uw := getAttr(elem, xslAttrUseWhen); uw != "" {
		include, err := c.evaluateUseWhen(ctx, uw)
		if err != nil {
			return nil, err
		}

		if !include {
			return nil, nil //nolint:nilnil
		}
	}

	// Push element-local namespace declarations (for EQName variable refs)
	saved := c.pushElementNamespaces(ctx, elem)
	defer func() { c.nsBindings = saved }()

	// Validate attributes: xsl:with-param allows name, select, as, tunnel
	// but NOT required (that's only for xsl:param)
	if err := c.validateXSLTAttrs(ctx, elem, withParamAllowedAttrs); err != nil {
		return nil, err
	}

	name := getAttr(elem, xslAttrName)
	if name == "" {
		return nil, staticError(errCodeXTSE0110, "xsl:with-param requires name attribute")
	}

	// Validate tunnel attribute value if present (including empty string)
	if tunnelAttr, hasTunnel := elem.GetAttribute(nameTunnel); hasTunnel {
		if err := validateBooleanAttr("xsl:with-param", nameTunnel, tunnelAttr); err != nil {
			return nil, err
		}
	}

	asAttr := getAttr(elem, "as")
	if err := c.validateAsSequenceType(ctx, asAttr, "xsl:with-param "+name); err != nil {
		return nil, err
	}

	wp := &withParam{
		Name: resolveQName(name, c.nsBindings),
		As:   asAttr,
	}

	wp.Tunnel = xsdBoolTrue(getAttr(elem, nameTunnel))

	selectAttr := getAttr(elem, xslAttrSelect)
	if selectAttr != "" {
		// XTSE0620: select and non-empty content are mutually exclusive.
		if err := c.validateEmptyElement(ctx, elem, "xsl:with-param"); err != nil {
			return nil, staticError(errCodeXTSE0620, "xsl:with-param %q has both @select and content", name)
		}

		expr, err := c.compileXPath(selectAttr, c.nsBindings)
		if err != nil {
			return nil, err
		}

		wp.Select = expr
	} else {
		body, err := c.compileChildren(ctx, elem)
		if err != nil {
			return nil, err
		}

		wp.Body = body
	}

	return wp, nil
}

func (c *compiler) compilePerformSort(ctx context.Context, elem *xdm.Element) (*performSortInst, error) {
	inst := &performSortInst{}

	selectAttr := getAttr(elem, xslAttrSelect)
	if selectAttr != "" {
		expr, err := c.compileXPath(selectAttr, c.nsBindings)
		if err != nil {
			return nil, err
		}

		inst.Select = expr

		if err := validatePerformSortSelectContent(elem); err != nil {
			return nil, err
		}
	}

	// Collect sort keys and body. xsl:sort must come before other content.
	pastSort := false

	for child := range xdm.Children(elem) {
		childElem, ok := child.(*xdm.Element)
		if !ok {
			continue
		}

		if childElem.URI() == lexicon.NamespaceXSLT && childElem.LocalName() == lexicon.XSLTElementSort {
			if pastSort {
				return nil, staticError(errCodeXTSE0010, "xsl:sort must come before other content in xsl:perform-sort")
			}

			if err := c.appendCompiledSortKey(ctx, childElem, &inst.Sort); err != nil {
				return nil, err
			}
		} else {
			pastSort = true

			childInst, err := c.compileInstruction(ctx, childElem)
			if err != nil {
				return nil, err
			}

			if childInst != nil {
				inst.Body = append(inst.Body, childInst)
			}
		}
	}

	return inst, nil
}

func validatePerformSortSelectContent(elem *xdm.Element) error {
	// XTSE1040: when select is present, only xsl:sort and xsl:fallback are allowed
	for child := range xdm.Children(elem) {
		childElem, ok := child.(*xdm.Element)
		if !ok {
			continue
		}

		if childElem.URI() == lexicon.NamespaceXSLT {
			ln := childElem.LocalName()
			if ln != lexicon.XSLTElementSort && ln != nameFallback {
				return staticError(errCodeXTSE1040,
					"xsl:perform-sort with select attribute must not contain xsl:%s", ln)
			}
		} else {
			return staticError(errCodeXTSE1040,
				"xsl:perform-sort with select attribute must not contain non-XSLT content")
		}
	}

	return nil
}

func (c *compiler) compileNextMatch(ctx context.Context, elem *xdm.Element) (*nextMatchInst, error) {
	inst := &nextMatchInst{}

	for child := range xdm.Children(elem) {
		childElem, ok := child.(*xdm.Element)
		if !ok {
			continue
		}

		if childElem.URI() == lexicon.NamespaceXSLT && childElem.LocalName() == lexicon.XSLTElementWithParam {
			wp, err := c.compileWithParam(ctx, childElem)
			if err != nil {
				return nil, err
			}

			if wp != nil {
				if err := checkDuplicateWithParam(inst.Params, wp); err != nil {
					return nil, err
				}

				inst.Params = append(inst.Params, wp)
			}
		}
	}

	return inst, nil
}

func (c *compiler) compileApplyImports(ctx context.Context, elem *xdm.Element) (*applyImportsInst, error) {
	if err := c.validateXSLTAttrs(ctx, elem, attributeNames()); err != nil {
		return nil, err
	}

	inst := &applyImportsInst{}

	for child := range xdm.Children(elem) {
		childElem, ok := child.(*xdm.Element)
		if !ok {
			if isNonWhitespaceTextNode(child) {
				return nil, staticError(errCodeXTSE0010, "text is not allowed as a child of xsl:apply-imports")
			}

			continue
		}

		if childElem.URI() != lexicon.NamespaceXSLT {
			return nil, staticError(errCodeXTSE0010, "non-XSLT element %q is not allowed as a child of xsl:apply-imports", childElem.Name())
		}

		if childElem.LocalName() != lexicon.XSLTElementWithParam {
			return nil, staticError(errCodeXTSE0010, "xsl:%s is not allowed as a child of xsl:apply-imports", childElem.LocalName())
		}

		wp, err := c.compileWithParam(ctx, childElem)
		if err != nil {
			return nil, err
		}

		if wp != nil {
			if err := checkDuplicateWithParam(inst.Params, wp); err != nil {
				return nil, err
			}

			inst.Params = append(inst.Params, wp)
		}
	}

	return inst, nil
}

func (c *compiler) compileTry(ctx context.Context, elem *xdm.Element) (*tryCatchInst, error) {
	inst := &tryCatchInst{RollbackOutput: true}

	if rb := getAttr(elem, "rollback-output"); rb == lexicon.ValueNo {
		inst.RollbackOutput = false
	}

	// xsl:try select attribute
	if sel := getAttr(elem, xslAttrSelect); sel != "" {
		expr, err := c.compileXPath(sel, c.nsBindings)
		if err != nil {
			return nil, err
		}

		inst.Select = expr
	}

	for child := range xdm.Children(elem) {
		if err := c.compileTryChild(ctx, child, inst); err != nil {
			return nil, err
		}
	}

	return inst, nil
}

func (c *compiler) compileTryChild(ctx context.Context, child xdm.Node, inst *tryCatchInst) error {
	elem, ok := child.(*xdm.Element)
	if !ok {
		if inst.Select != nil {
			if text, ok := child.(*xdm.Text); ok && !isXMLWhitespaceOnly(xdm.CharacterData(text)) {
				return staticError(errCodeXTSE3140, "xsl:try with select attribute must not have non-catch/fallback children")
			}
		}

		return nil
	}

	if elem.URI() == lexicon.NamespaceXSLT {
		switch elem.LocalName() {
		case lexicon.XSLTElementCatch:
			clause, err := c.compileCatchClause(ctx, elem)
			if err != nil {
				return err
			}

			inst.Catches = append(inst.Catches, clause)

			return nil
		case lexicon.XSLTElementFallback:
			return nil
		}
	}

	if inst.Select != nil {
		return staticError(errCodeXTSE3140, "xsl:try with select attribute must not have non-catch/fallback children")
	}

	compiled, err := c.compileInstruction(ctx, elem)
	if err != nil {
		return err
	}

	if compiled != nil {
		inst.Try = append(inst.Try, compiled)
	}

	return nil
}

func (c *compiler) compileCatchClause(ctx context.Context, elem *xdm.Element) (*catchClause, error) {
	clause := &catchClause{}

	defer c.pushElementVersion(elem)()

	// Parse errors attribute (space-separated list of error codes).
	// Namespace declarations on xsl:catch itself must be visible
	// when resolving prefixed error codes (e.g. err:XTDE0555).
	if errAttr := getAttr(elem, "errors"); errAttr != "" {
		catchNS := make(map[string]string, len(c.nsBindings))
		maps.Copy(catchNS, c.nsBindings)

		for _, ns := range elem.Namespaces() {
			catchNS[ns.Prefix()] = ns.URI()
		}

		for code := range strings.FieldsSeq(errAttr) {
			clause.Errors = append(clause.Errors, resolveQName(code, catchNS))
		}
	}

	// xsl:catch select attribute
	// XTSE3150: xsl:catch with select must have empty content.
	if sel := getAttr(elem, xslAttrSelect); sel != "" {
		if hasNonEmptyContent(elem) {
			return nil, staticError(errCodeXTSE3150, "xsl:catch with select attribute must have empty content")
		}

		expr, err := c.compileXPath(sel, c.nsBindings)
		if err != nil {
			return nil, err
		}

		clause.Select = expr
	} else {
		body, err := c.compileChildren(ctx, elem)
		if err != nil {
			return nil, err
		}

		clause.Body = body
	}

	return clause, nil
}

func (c *compiler) compileForEachGroup(ctx context.Context, elem *xdm.Element) (*forEachGroupInst, error) {
	selectAttr := getAttr(elem, xslAttrSelect)
	if selectAttr == "" {
		return nil, staticError(errCodeXTSE0110, "xsl:for-each-group requires select attribute")
	}

	if err := validateGroupingAttributes(elem); err != nil {
		return nil, err
	}

	expr, err := c.compileXPath(selectAttr, c.nsBindings)
	if err != nil {
		return nil, err
	}

	inst := &forEachGroupInst{Select: expr}

	if err := c.compileGroupingOptions(elem, inst); err != nil {
		return nil, err
	}

	if err := c.compileGroupingBody(ctx, elem, inst); err != nil {
		return nil, err
	}

	return inst, nil
}

func validateGroupingAttributes(elem *xdm.Element) error {
	// XTSE1080: exactly one of group-by, group-adjacent, group-starting-with,
	// group-ending-with must be present
	groupingCount := 0
	if getAttr(elem, "group-by") != "" {
		groupingCount++
	}

	if getAttr(elem, "group-adjacent") != "" {
		groupingCount++
	}

	if getAttr(elem, "group-starting-with") != "" {
		groupingCount++
	}

	if getAttr(elem, "group-ending-with") != "" {
		groupingCount++
	}

	if groupingCount == 0 {
		return staticError(errCodeXTSE1080, "xsl:for-each-group requires one of group-by, group-adjacent, group-starting-with, or group-ending-with")
	}

	if groupingCount > 1 {
		return staticError(errCodeXTSE1080, "xsl:for-each-group must have at most one of group-by, group-adjacent, group-starting-with, or group-ending-with")
	}

	// XTSE1090: collation/composite only with group-by or group-adjacent
	hasGroupBy := getAttr(elem, "group-by") != ""

	hasGroupAdjacent := getAttr(elem, "group-adjacent") != ""
	if !hasGroupBy && !hasGroupAdjacent {
		if getAttr(elem, nameCollation) != "" {
			return staticError(errCodeXTSE1090,
				"collation attribute on xsl:for-each-group requires group-by or group-adjacent")
		}

		if getAttr(elem, nameComposite) != "" {
			return staticError(errCodeXTSE1090,
				"composite attribute on xsl:for-each-group requires group-by or group-adjacent")
		}
	}

	return nil
}

func (c *compiler) compileGroupingOptions(elem *xdm.Element, inst *forEachGroupInst) error {
	// Compile collation avt
	if collAttr := getAttr(elem, nameCollation); collAttr != "" {
		collAVT, collErr := c.compileAVT(collAttr, c.nsBindings)
		if collErr != nil {
			return collErr
		}

		inst.Collation = collAVT
	}

	// Validate boolean attribute: composite
	if comp, hasComp := elem.GetAttribute(nameComposite); hasComp {
		if err := validateBooleanAttr("xsl:for-each-group", nameComposite, comp); err != nil {
			return err
		}

		if comp == lexicon.ValueYes || comp == lexicon.ValueTrue || comp == "1" {
			inst.Composite = true
		}
	}

	if gb := getAttr(elem, "group-by"); gb != "" {
		gbExpr, gbErr := c.compileXPath(gb, c.nsBindings)
		if gbErr != nil {
			return gbErr
		}

		inst.GroupBy = gbExpr
	}

	if ga := getAttr(elem, "group-adjacent"); ga != "" {
		gaExpr, gaErr := c.compileXPath(ga, c.nsBindings)
		if gaErr != nil {
			return gaErr
		}

		inst.GroupAdjacent = gaExpr
	}

	if gs := getAttr(elem, "group-starting-with"); gs != "" {
		gsPat, gsErr := c.compilePattern(gs, elem, c.xpathDefaultNS, c.hasXPathDefaultNS)
		if gsErr != nil {
			return gsErr
		}

		inst.GroupStartingWith = gsPat
	}

	if ge := getAttr(elem, "group-ending-with"); ge != "" {
		gePat, geErr := c.compilePattern(ge, elem, c.xpathDefaultNS, c.hasXPathDefaultNS)
		if geErr != nil {
			return geErr
		}

		inst.GroupEndingWith = gePat
	}

	return nil
}

func (c *compiler) compileGroupingBody(ctx context.Context, elem *xdm.Element, inst *forEachGroupInst) error {
	// Compile body (skip sort elements)
	for child := range xdm.Children(elem) {
		switch v := child.(type) {
		case *xdm.Element:
			if v.URI() == lexicon.NamespaceXSLT && v.LocalName() == lexicon.XSLTElementSort {
				if err := c.appendCompiledSortKey(ctx, v, &inst.Sort); err != nil {
					return err
				}

				continue
			}

			childInst, childErr := c.compileInstruction(ctx, v)
			if childErr != nil {
				return childErr
			}

			if childInst != nil {
				inst.Body = append(inst.Body, childInst)
			}
		case *xdm.Text:
			text := xdm.CharacterData(v)
			if !c.shouldStripText(ctx, text) {
				lit, err := c.compileLiteralText(text)
				if err != nil {
					return err
				}

				inst.Body = append(inst.Body, lit)
			}
		}
	}

	return nil
}

func (c *compiler) compileAnalyzeString(ctx context.Context, elem *xdm.Element) (*analyzeStringInst, error) {
	selectAttr := getAttr(elem, xslAttrSelect)
	if selectAttr == "" {
		return nil, staticError(errCodeXTSE0110, "xsl:analyze-string requires select attribute")
	}

	regexAttr, regexFound := elem.GetAttribute("regex")
	if !regexFound {
		return nil, staticError(errCodeXTSE0110, "xsl:analyze-string requires regex attribute")
	}

	selectExpr, err := c.compileXPath(selectAttr, c.nsBindings)
	if err != nil {
		return nil, err
	}

	regexAVT, err := c.compileAVT(regexAttr, c.nsBindings)
	if err != nil {
		return nil, err
	}

	inst := &analyzeStringInst{
		Select: selectExpr,
		Regex:  regexAVT,
	}

	flagsAttr := getAttr(elem, "flags")
	if flagsAttr != "" {
		flagsAVT, err := c.compileAVT(flagsAttr, c.nsBindings)
		if err != nil {
			return nil, err
		}

		inst.Flags = flagsAVT
	}

	// Compile xsl:matching-substring and xsl:non-matching-substring children.
	// The spec requires: matching-substring? then non-matching-substring? then fallback*.
	// (XTSE0010 if out of order)
	const (
		phaseInit     = 0
		phaseMatching = 1
		phaseNonMatch = 2
		phaseFallback = 3
	)

	phase := phaseInit

	for child := range xdm.Children(elem) {
		childElem, ok := child.(*xdm.Element)
		if !ok {
			continue
		}

		if childElem.URI() != lexicon.NamespaceXSLT {
			continue
		}

		switch childElem.LocalName() {
		case lexicon.XSLTElementMatchingSubstring:
			if phase >= phaseMatching {
				return nil, staticError(errCodeXTSE0010, "xsl:matching-substring must precede xsl:non-matching-substring and xsl:fallback")
			}

			phase = phaseMatching

			body, err := c.compileChildren(ctx, childElem)
			if err != nil {
				return nil, err
			}

			inst.MatchingBody = body
		case lexicon.XSLTElementNonMatchingSubstring:
			if phase >= phaseNonMatch {
				return nil, staticError(errCodeXTSE0010, "xsl:non-matching-substring out of order in xsl:analyze-string")
			}

			phase = phaseNonMatch

			body, err := c.compileChildren(ctx, childElem)
			if err != nil {
				return nil, err
			}

			inst.NonMatchingBody = body
		case lexicon.XSLTElementFallback:
			phase = phaseFallback
		}
	}

	// XTSE1130: at least one of matching-substring or non-matching-substring is required
	if len(inst.MatchingBody) == 0 && len(inst.NonMatchingBody) == 0 {
		return nil, staticError(errCodeXTSE1130, "xsl:analyze-string must contain xsl:matching-substring or xsl:non-matching-substring")
	}

	return inst, nil
}

func (c *compiler) compileEvaluate(ctx context.Context, elem *xdm.Element) (instruction, error) {
	inst := &evaluateInst{}

	// xpath attribute is required
	xpathAttr := getAttr(elem, "xpath")
	if xpathAttr == "" {
		return nil, staticError(errCodeXTSE0010, "xsl:evaluate requires an xpath attribute")
	}

	expr, err := c.compileXPath(xpathAttr, c.nsBindings)
	if err != nil {
		return nil, err
	}

	inst.XPath = expr

	// context-item (optional)
	if ci := getAttr(elem, nameContextItem); ci != "" {
		ciExpr, err := c.compileXPath(ci, c.nsBindings)
		if err != nil {
			return nil, err
		}

		inst.ContextItem = ciExpr
	}

	// base-uri (optional avt)
	if bu := getAttr(elem, "base-uri"); bu != "" {
		avt, err := c.compileAVT(bu, c.nsBindings)
		if err != nil {
			return nil, err
		}

		inst.BaseURI = avt
	}

	// namespace-context (optional XPath expression producing a node)
	if nc := getAttr(elem, "namespace-context"); nc != "" {
		ncExpr, err := c.compileXPath(nc, c.nsBindings)
		if err != nil {
			return nil, err
		}

		inst.NamespaceContext = ncExpr
	}

	// with-params (optional map expression)
	if wp := getAttr(elem, "with-params"); wp != "" {
		wpExpr, err := c.compileXPath(wp, c.nsBindings)
		if err != nil {
			return nil, err
		}

		inst.WithParamsExpr = wpExpr
	}

	// as (optional type name)
	inst.As = getAttr(elem, "as")

	// schema-aware (optional avt that evaluates to boolean)
	if saStr, hasSA := elem.GetAttribute("schema-aware"); hasSA {
		saAVT, err := c.compileAVT(saStr, c.nsBindings)
		if err != nil {
			return nil, err
		}

		inst.SchemaAwareAVT = saAVT
	}

	if err := c.compileEvaluateParams(ctx, elem, inst); err != nil {
		return nil, err
	}

	return inst, nil
}

func (c *compiler) compileEvaluateParams(ctx context.Context, elem *xdm.Element, inst *evaluateInst) error {
	// Compile child xsl:with-param elements
	for child := range xdm.Children(elem) {
		childElem, ok := child.(*xdm.Element)
		if !ok {
			continue
		}

		if childElem.URI() != lexicon.NamespaceXSLT {
			continue
		}

		if childElem.LocalName() == lexicon.XSLTElementWithParam {
			if err := c.appendCompiledWithParam(ctx, childElem, &inst.Params); err != nil {
				return err
			}
		} else if childElem.LocalName() == lexicon.XSLTElementFallback {
			// skip
		} else {
			return staticError(errCodeXTSE0010, "xsl:evaluate may only contain xsl:with-param or xsl:fallback, found xsl:%s", childElem.LocalName())
		}
	}

	return nil
}

// checkDuplicateWithParam reports XTSE0670 when wp names the same expanded
// QName as an earlier sibling xsl:with-param in params. Tunnel and non-tunnel
// parameters share one name space for this rule.
func checkDuplicateWithParam(params []*withParam, wp *withParam) error {
	for _, prev := range params {
		if prev.Name == wp.Name {
			return staticError(errCodeXTSE0670, "duplicate xsl:with-param name %q", wp.Name)
		}
	}

	return nil
}
