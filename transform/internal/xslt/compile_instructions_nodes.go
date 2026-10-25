// Derived from lestrrat-go/helium at 7362c0a70122a757780f4d0b545a9b370dead6ab.
// Copyright (c) 2015 lestrrat. MIT License; see licenses/MIT-helium.txt at the repository root.

package xslt

import (
	"context"
	"maps"
	"strings"

	"github.com/skarm/xmlsec/internal/lexicon"
	"github.com/skarm/xmlsec/transform/internal/xdm"
	"github.com/skarm/xmlsec/transform/internal/xpath"
)

func (c *compiler) compileValueOf(ctx context.Context, elem *xdm.Element) (*valueOfInst, error) {
	inst := &valueOfInst{}

	selectAttr, hasSelect := elem.GetAttribute(xslAttrSelect)
	if !hasSelect && c.stylesheet.processorLanguage() == 10 {
		return nil, staticError(errCodeXTSE0010, "xsl:value-of requires select in XSLT 1.0")
	}

	if !hasSelect && c.stylesheet.processorLanguage() == 20 && !c.hasEffectiveContent(ctx, elem) {
		return nil, staticError(errCodeXTSE0870, "XSLT 2.0 xsl:value-of requires select or non-empty content")
	}

	if hasSelect {
		expr, err := c.compileXPath(selectAttr, c.nsBindings)
		if err != nil {
			return nil, err
		}

		inst.Select = expr
	}

	if sep, ok := elem.GetAttribute("separator"); ok {
		avt, err := c.compileAVT(sep, c.nsBindings)
		if err != nil {
			return nil, err
		}

		inst.Separator = avt
	}

	// XTSE0870: xsl:value-of with select must have empty content after
	// stylesheet whitespace stripping.
	if hasSelect {
		for child := range xdm.Children(elem) {
			switch child.Type() {
			case xdm.TextNode, xdm.CDATASectionNode:
				if xdm.CharacterData(child) != "" {
					return nil, staticError(errCodeXTSE0870, "xsl:value-of with select attribute must not have content")
				}
			case xdm.ElementNode:
				return nil, staticError(errCodeXTSE0870, "xsl:value-of with select attribute must not have content")
			}
		}
	} else {
		// Sequence constructor body (XSLT 2.0+)
		body, err := c.compileChildren(ctx, elem)
		if err != nil {
			return nil, err
		}
		// XSLT 3.0: empty xsl:value-of is allowed (produces zero-length string).
		inst.Body = body
	}

	doeAttr := getAttr(elem, nameDisableOutputEscaping)
	if doeAttr != "" {
		doe, err := parseDOEAttr(doeAttr)
		if err != nil {
			return nil, err
		}

		inst.DisableOutputEscaping = doe
	}

	return inst, nil
}

func (c *compiler) compileText(_ context.Context, elem *xdm.Element) (*textInst, error) {
	// xsl:text must contain only text and CDATA sections — no child elements (XTSE0010)
	var sb strings.Builder

	for child := range xdm.Children(elem) {
		switch child.Type() {
		case xdm.TextNode, xdm.CDATASectionNode:
			sb.WriteString(xdm.CharacterData(child))
		case xdm.ElementNode:
			return nil, staticError(errCodeXTSE0010, "xsl:text must not contain child elements")
		}
	}

	text := sb.String()
	inst := &textInst{
		Value: text,
	}

	doeAttr := getAttr(elem, nameDisableOutputEscaping)
	if doeAttr != "" {
		doe, err := parseDOEAttr(doeAttr)
		if err != nil {
			return nil, err
		}

		inst.DisableOutputEscaping = doe
	}

	if c.expandText && strings.ContainsAny(text, "{}") {
		avt, err := c.compileAVT(text, c.nsBindings)
		if err != nil {
			return nil, err
		}

		inst.TVT = avt
	}

	return inst, nil
}

func (c *compiler) compileElement(ctx context.Context, elem *xdm.Element) (*elementInst, error) {
	// xsl:break / xsl:next-iteration not allowed inside element constructors.
	savedBreak := c.breakAllowed

	c.breakAllowed = false
	defer func() { c.breakAllowed = savedBreak }()

	// Validate attributes
	if err := c.validateXSLTAttrs(ctx, elem, attributeNames(xslAttrName, nameNamespace, nameInheritNamespaces, nameUseAttributeSets, lexicon.AttrType, nameValidation)); err != nil {
		return nil, err
	}

	// Validate boolean attributes (including empty string)
	if inAttr, hasIn := elem.GetAttribute(nameInheritNamespaces); hasIn {
		if err := validateBooleanAttr("xsl:element", nameInheritNamespaces, inAttr); err != nil {
			return nil, err
		}
	}

	nameAttr, hasName := elem.GetAttribute(xslAttrName)
	if !hasName {
		return nil, staticError(errCodeXTSE0010, "xsl:element requires name attribute")
	}

	nameAVT, err := c.compileAVT(nameAttr, c.nsBindings)
	if err != nil {
		return nil, err
	}

	inst := &elementInst{Name: nameAVT, InheritNamespaces: true}

	if inAttr, present := elem.GetAttribute(nameInheritNamespaces); present {
		inst.InheritNamespaces = xsdBoolTrue(inAttr)
	}

	// Capture compile-time namespace bindings for runtime name resolution.
	if len(c.nsBindings) > 0 {
		inst.NSBindings = make(map[string]string, len(c.nsBindings))
		maps.Copy(inst.NSBindings, c.nsBindings)
	}

	typeAttr := getAttr(elem, lexicon.AttrType)
	validation := getAttr(elem, nameValidation)

	if err := checkValidationTypeExclusive("xsl:element", validation, typeAttr); err != nil {
		return nil, err
	}

	if typeAttr != "" {
		if err := c.checkTypeAttrSchemaAware(ctx, "xsl:element", typeAttr); err != nil {
			return nil, err
		}

		inst.TypeName = resolveXSDTypeName(typeAttr, c.nsBindings)
	}

	if validation != "" {
		if err := validateValidationAttr("xsl:element", validation); err != nil {
			return nil, err
		}

		inst.Validation = basicValidation(validation)
	}

	if nsAttr, hasNS := elem.GetAttribute(nameNamespace); hasNS {
		nsAVT, err := c.compileAVT(nsAttr, c.nsBindings)
		if err != nil {
			return nil, err
		}

		inst.Namespace = nsAVT
	}

	if uas := getAttr(elem, nameUseAttributeSets); uas != "" {
		for name := range strings.FieldsSeq(uas) {
			resolved := resolveQName(name, c.nsBindings)
			inst.UseAttrSets = append(inst.UseAttrSets, resolved)
			c.usedAttrSetRefs = append(c.usedAttrSetRefs, resolved)
		}
	}

	// Capture xml:base for static base URI override during body execution.
	effectiveBase := stylesheetBaseURI(elem, c.baseURI, c.moduleRoot)
	if effectiveBase != c.baseURI {
		inst.StaticBaseURI = effectiveBase
	}

	body, err := c.compileChildren(ctx, elem)
	if err != nil {
		return nil, err
	}

	inst.Body = body

	return inst, nil
}

func (c *compiler) compileAttribute(ctx context.Context, elem *xdm.Element) (*attributeInst, error) {
	nameAttr, hasName := elem.GetAttribute(xslAttrName)
	if !hasName {
		return nil, staticError(errCodeXTSE0010, "xsl:attribute requires name attribute")
	}

	nameAVT, err := c.compileAVT(nameAttr, c.nsBindings)
	if err != nil {
		return nil, err
	}

	inst := &attributeInst{Name: nameAVT}

	if typeAttr := getAttr(elem, lexicon.AttrType); typeAttr != "" {
		if err := c.checkTypeAttrSchemaAware(ctx, "xsl:attribute", typeAttr); err != nil {
			return nil, err
		}

		inst.TypeName = resolveXSDTypeName(typeAttr, c.nsBindings)
	}

	if valAttr := getAttr(elem, nameValidation); valAttr != "" {
		if err := validateValidationAttr("xsl:attribute", valAttr); err != nil {
			return nil, err
		}

		if !c.stylesheet.schemaAware && valAttr == validationStrict {
			return nil, staticError(errCodeXTSE0220, "validation attribute requires schema-aware processing")
		}

		inst.Validation = basicValidation(valAttr)
	}

	if nsAttr, hasNS := elem.GetAttribute(nameNamespace); hasNS {
		nsAVT, err := c.compileAVT(nsAttr, c.nsBindings)
		if err != nil {
			return nil, err
		}

		inst.Namespace = nsAVT
	}

	if sep, hasSep := elem.GetAttribute("separator"); hasSep {
		sepAVT, err := c.compileAVT(sep, c.nsBindings)
		if err != nil {
			return nil, err
		}

		inst.Separator = sepAVT
	}

	selectAttr, hasSelect := elem.GetAttribute(xslAttrSelect)
	if hasSelect {
		// XTSE0840: xsl:attribute with select must have empty content.
		if hasNonEmptyContent(elem) {
			return nil, staticError(errCodeXTSE0840, "xsl:attribute with select attribute must have empty content")
		}

		expr, err := c.compileXPath(selectAttr, c.nsBindings)
		if err != nil {
			return nil, err
		}

		inst.Select = expr
	} else {
		body, err := c.compileChildren(ctx, elem)
		if err != nil {
			return nil, err
		}

		inst.Body = body
	}

	return inst, nil
}

func (c *compiler) compileComment(ctx context.Context, elem *xdm.Element) (*commentInst, error) {
	inst := &commentInst{}

	selectAttr, hasSelect := elem.GetAttribute(xslAttrSelect)
	if hasSelect {
		// XTSE0940: select and non-empty content are mutually exclusive.
		if err := c.validateEmptyElement(ctx, elem, "xsl:comment"); err != nil {
			return nil, staticError(errCodeXTSE0940, "xsl:comment has both @select and content")
		}

		expr, err := c.compileXPath(selectAttr, c.nsBindings)
		if err != nil {
			return nil, err
		}

		inst.Select = expr
	} else {
		body, err := c.compileChildren(ctx, elem)
		if err != nil {
			return nil, err
		}

		inst.Body = body
	}

	return inst, nil
}

func (c *compiler) compilePI(ctx context.Context, elem *xdm.Element) (*piInst, error) {
	nameAttr, hasName := elem.GetAttribute(xslAttrName)
	if !hasName {
		return nil, staticError(errCodeXTSE0010, "xsl:processing-instruction requires name attribute")
	}

	nameAVT, err := c.compileAVT(nameAttr, c.nsBindings)
	if err != nil {
		return nil, err
	}

	inst := &piInst{Name: nameAVT}

	selectAttr, hasSelect := elem.GetAttribute(xslAttrSelect)
	if hasSelect {
		// XTSE0940: select and non-empty content are mutually exclusive.
		if err := c.validateEmptyElement(ctx, elem, "xsl:processing-instruction"); err != nil {
			return nil, staticError("XTSE0880", "xsl:processing-instruction has both @select and content")
		}

		expr, err := c.compileXPath(selectAttr, c.nsBindings)
		if err != nil {
			return nil, err
		}

		inst.Select = expr
	} else {
		body, err := c.compileChildren(ctx, elem)
		if err != nil {
			return nil, err
		}

		inst.Body = body
	}

	return inst, nil
}

func (c *compiler) compileCopy(ctx context.Context, elem *xdm.Element) (*copyInst, error) {
	if err := validateCopyBooleanAttrs(elem, "xsl:copy", nameInheritNamespaces, "copy-namespaces"); err != nil {
		return nil, err
	}

	inst := &copyInst{
		CopyNamespaces:    true,
		InheritNamespaces: true,
	}

	if cn := getAttr(elem, "copy-namespaces"); cn != "" {
		if v, ok := parseXSDBool(cn); ok && !v {
			inst.CopyNamespaces = false
		}
	}

	if in := getAttr(elem, nameInheritNamespaces); in != "" {
		if v, ok := parseXSDBool(in); ok && !v {
			inst.InheritNamespaces = false
		}
	}

	// Shadow attributes (_attr overrides attr via avt at runtime)
	if scn := getAttr(elem, "_copy-namespaces"); scn != "" {
		avt, err := c.compileAVT(scn, c.nsBindings)
		if err != nil {
			return nil, err
		}

		inst.CopyNamespacesAVT = avt
	}

	if sin := getAttr(elem, "_inherit-namespaces"); sin != "" {
		avt, err := c.compileAVT(sin, c.nsBindings)
		if err != nil {
			return nil, err
		}

		inst.InheritNamespacesAVT = avt
	}

	if v := getAttr(elem, nameValidation); v != "" {
		if err := validateValidationAttr("xsl:copy", v); err != nil {
			return nil, err
		}

		inst.Validation = basicValidation(v)
	}

	if typeAttr := getAttr(elem, lexicon.AttrType); typeAttr != "" {
		inst.TypeName = resolveXSDTypeName(typeAttr, c.nsBindings)
	}

	if selectAttr, present := elem.GetAttribute(xslAttrSelect); present {
		expr, err := c.compileXPath(selectAttr, c.nsBindings)
		if err != nil {
			return nil, err
		}

		inst.Select = expr
	}

	if uas := getAttr(elem, nameUseAttributeSets); uas != "" {
		for name := range strings.FieldsSeq(uas) {
			resolved := resolveQName(name, c.nsBindings)
			inst.UseAttrSets = append(inst.UseAttrSets, resolved)
			c.usedAttrSetRefs = append(c.usedAttrSetRefs, resolved)
		}
	}

	body, err := c.compileChildren(ctx, elem)
	if err != nil {
		return nil, err
	}

	inst.Body = body

	return inst, nil
}

func (c *compiler) compileCopyOf(_ context.Context, elem *xdm.Element) (*copyOfInst, error) {
	if err := validateCopyOfStructure(elem); err != nil {
		return nil, err
	}

	if err := validateCopyBooleanAttrs(elem, "xsl:copy-of", "copy-namespaces"); err != nil {
		return nil, err
	}

	selectAttr, hasSelect := elem.GetAttribute(xslAttrSelect)
	if !hasSelect {
		return nil, staticError(errCodeXTSE0010, "xsl:copy-of requires select attribute")
	}

	expr, err := c.compileXPath(selectAttr, c.nsBindings)
	if err != nil {
		return nil, err
	}

	inst := &copyOfInst{
		Select:         expr,
		CopyNamespaces: true,
	}

	if cn := getAttr(elem, "copy-namespaces"); cn != "" {
		if v, ok := parseXSDBool(cn); ok && !v {
			inst.CopyNamespaces = false
		}
	}
	// Shadow attribute _copy-namespaces overrides at runtime
	if scn := getAttr(elem, "_copy-namespaces"); scn != "" {
		avt, err := c.compileAVT(scn, c.nsBindings)
		if err != nil {
			return nil, err
		}

		inst.CopyNamespacesAVT = avt
	}

	if v := getAttr(elem, nameValidation); v != "" {
		if err := validateValidationAttr("xsl:copy-of", v); err != nil {
			return nil, err
		}

		inst.Validation = basicValidation(v)
	}

	if typeAttr := getAttr(elem, lexicon.AttrType); typeAttr != "" {
		inst.TypeName = resolveXSDTypeName(typeAttr, c.nsBindings)
	}

	if ca := getAttr(elem, "copy-accumulators"); ca != "" {
		if v, ok := parseXSDBool(ca); ok && v {
			inst.CopyAccumulators = true
		}
	}

	return inst, nil
}

func validateCopyOfStructure(elem *xdm.Element) error {
	// XTSE0260: xsl:copy-of must have no significant content
	for child := range xdm.Children(elem) {
		switch child.Type() {
		case xdm.ElementNode:
			return staticError(errCodeXTSE0260,
				"xsl:copy-of must be empty, but contains child element %s", child.Name())
		case xdm.TextNode, xdm.CDATASectionNode:
			if xdm.CharacterData(child) != "" {
				return staticError(errCodeXTSE0260,
					"xsl:copy-of must be empty, but contains text content")
			}
		}
	}

	// XTSE0090: reject specific attributes that are not allowed on xsl:copy-of
	for _, attr := range elem.Attributes() {
		if attr.URI() != "" {
			continue
		}

		if attr.LocalName() == lexicon.AttrMatch || attr.LocalName() == lexicon.AttrCount || attr.LocalName() == "from" {
			return staticError(errCodeXTSE0090,
				"attribute %q is not allowed on xsl:copy-of", attr.LocalName())
		}
	}

	return nil
}

func (c *compiler) compileNumber(_ context.Context, elem *xdm.Element) (*numberInst, error) {
	inst := &numberInst{
		Level: getAttr(elem, "level"),
	}
	if inst.Level == "" {
		inst.Level = nameSingle
	}

	if err := c.compileNumberCounting(elem, inst); err != nil {
		return nil, err
	}

	if err := c.compileNumberFormatting(elem, inst); err != nil {
		return nil, err
	}

	if sel, present := elem.GetAttribute(xslAttrSelect); present {
		expr, err := c.compileXPath(sel, c.nsBindings)
		if err != nil {
			return nil, err
		}

		inst.Select = expr
	}

	for _, option := range []struct {
		name  string
		value **avt
	}{
		{lexicon.AttrLang, &inst.Lang},
		{nameLetterValue, &inst.LetterValue},
	} {
		if err := c.compileNumberOption(elem, option.name, option.value); err != nil {
			return nil, err
		}
	}

	return inst, nil
}

func (c *compiler) compileNumberCounting(elem *xdm.Element, inst *numberInst) error {
	if countAttr, present := elem.GetAttribute("count"); present {
		p, err := c.compilePattern(countAttr, elem, c.xpathDefaultNS, c.hasXPathDefaultNS)
		if err != nil {
			return err
		}

		inst.Count = p
	}

	if fromAttr, present := elem.GetAttribute("from"); present {
		p, err := c.compilePattern(fromAttr, elem, c.xpathDefaultNS, c.hasXPathDefaultNS)
		if err != nil {
			return err
		}

		inst.From = p
	}

	inst.memoizable = !patternReadsVariables(inst.Count) && !patternReadsVariables(inst.From)

	if valueAttr, present := elem.GetAttribute("value"); present {
		// XTSE0975: when value is present, select/level/count/from must be absent.
		for _, attribute := range []string{xslAttrSelect, "level", lexicon.AttrCount, lexicon.AttrFrom} {
			if _, specified := elem.GetAttribute(attribute); specified {
				return staticError(errCodeXTSE0975, "xsl:number: when @value is present, @select, @level, @count, and @from must be absent")
			}
		}

		expr, err := c.compileXPath(valueAttr, c.nsBindings)
		if err != nil {
			return err
		}

		inst.Value = expr
	}

	return nil
}

// patternReadsVariables reports whether any alternative of p references a
// variable it does not bind itself. A nil pattern reads none.
func patternReadsVariables(p *pattern) bool {
	if p == nil {
		return false
	}

	for _, alt := range p.Alternatives {
		if len(alt.compiled.StaticReferences(nil).FreeVariables) > 0 {
			return true
		}
	}

	return false
}

func (c *compiler) compileNumberFormatting(elem *xdm.Element, inst *numberInst) error {
	for _, option := range []struct {
		name  string
		value **avt
	}{
		{nameFormat, &inst.Format},
		{nameGroupingSeparator, &inst.GroupingSeparator},
		{nameGroupingSize, &inst.GroupingSize},
		{"ordinal", &inst.Ordinal},
		{nameStartAt, &inst.StartAt},
	} {
		if err := c.compileNumberOption(elem, option.name, option.value); err != nil {
			return err
		}
	}

	return nil
}

func (c *compiler) compileNumberOption(elem *xdm.Element, name string, target **avt) error {
	value, present := elem.GetAttribute(name)
	if !present {
		return nil
	}

	compiled, err := c.compileAVT(value, c.nsBindings)
	if err != nil {
		return err
	}

	if literal, static := compiled.staticValue(); static && c.stylesheet.processorLanguage() >= 20 && !validNumberOption(name, literal) {
		return staticError(errCodeXTSE0020, "%q is not a valid value for xsl:number/@%s", literal, name)
	}

	*target = compiled

	return nil
}

func (c *compiler) compileNamespace(ctx context.Context, elem *xdm.Element) (*namespaceInst, error) {
	nameAttr, hasName := elem.GetAttribute(xslAttrName)
	if !hasName {
		return nil, staticError(errCodeXTSE0010, "xsl:namespace requires name attribute")
	}
	// name="" is valid: it sets the default namespace

	nameAVT, err := c.compileAVT(nameAttr, c.nsBindings)
	if err != nil {
		return nil, err
	}

	inst := &namespaceInst{Name: nameAVT}

	selectAttr, hasSelect := elem.GetAttribute(xslAttrSelect)
	hasContent := c.hasEffectiveContent(ctx, elem)
	// XTSE0910: select and content are mutually exclusive on xsl:namespace
	if hasSelect && hasContent {
		return nil, staticError(errCodeXTSE0910, "xsl:namespace must not have both a select attribute and content")
	}

	if !hasSelect && !hasContent {
		return nil, staticError(errCodeXTSE0910, "xsl:namespace must have either a select attribute or content")
	}

	if hasSelect {
		expr, err := c.compileXPath(selectAttr, c.nsBindings)
		if err != nil {
			return nil, err
		}

		inst.Select = expr
	} else {
		body, err := c.compileChildren(ctx, elem)
		if err != nil {
			return nil, err
		}

		inst.Body = body
	}

	return inst, nil
}

func (c *compiler) compileDocument(ctx context.Context, elem *xdm.Element) (*documentInst, error) {
	inst := &documentInst{}

	if v := getAttr(elem, nameValidation); v != "" {
		if err := validateValidationAttr("xsl:document", v); err != nil {
			return nil, err
		}

		inst.Validation = basicValidation(v)
	}

	if typeAttr := getAttr(elem, lexicon.AttrType); typeAttr != "" {
		inst.TypeName = resolveXSDTypeName(typeAttr, c.nsBindings)
	}

	body, err := c.compileChildren(ctx, elem)
	if err != nil {
		return nil, err
	}

	inst.Body = body

	return inst, nil
}

func (c *compiler) compileSequence(ctx context.Context, elem *xdm.Element) (instruction, error) {
	if err := c.validateXSLTAttrs(ctx, elem, attributeNames(xslAttrSelect)); err != nil {
		return nil, err
	}

	selectAttr, hasSelect := elem.GetAttribute(xslAttrSelect)
	if hasSelect {
		// XTSE3185: when @select is present, only xsl:fallback children are allowed.
		if hasSignificantChildren(elem) {
			code := errCodeXTSE3185
			if c.stylesheet.processorLanguage() == 20 {
				code = errCodeXTSE0010
			}

			return nil, staticError(code, "xsl:sequence with @select must not have content other than xsl:fallback")
		}

		expr, err := c.compileXPath(selectAttr, c.nsBindings)
		if err != nil {
			return nil, err
		}

		return &xslSequenceInst{Select: expr}, nil
	}

	body, err := c.compileChildren(ctx, elem)
	if err != nil {
		return nil, err
	}

	inst := &sequenceInst{Body: body}
	if dvAttr := getAttr(elem, nameDefaultValidation); dvAttr != "" {
		inst.DefaultValidation = basicValidation(dvAttr)
	}

	return inst, nil
}

func (c *compiler) compileLiteralResultElement(ctx context.Context, elem *xdm.Element) (*literalResultElement, error) {
	// xsl:break / xsl:next-iteration not allowed inside element constructors.
	savedBreak := c.breakAllowed

	c.breakAllowed = false
	defer func() { c.breakAllowed = savedBreak }()

	// An xsl:version on a literal result element sets the effective version for
	// this element and its subtree (its AVTs and descendants), so they evaluate in
	// XPath 1.0 compatibility mode when that version is < 2.0. pushElementVersion
	// reads xsl:version on an LRE (an unqualified version is a result attribute).
	// This also covers an LRE compiled directly (a simplified stylesheet root),
	// not via the generic instruction path.
	defer c.pushElementVersion(elem)()

	lre := &literalResultElement{
		Name:              elem.Name(),
		Namespace:         elem.URI(),
		Prefix:            elem.Prefix(),
		LocalName:         elem.LocalName(),
		Namespaces:        make(map[string]string),
		InheritNamespaces: true,
	}

	// xsl:inherit-namespaces on LRE
	if inAttr, ok := elem.GetAttributeNS(nameInheritNamespaces, lexicon.NamespaceXSLT); ok {
		if err := validateBooleanAttr("literal result element", "xsl:inherit-namespaces", inAttr); err != nil {
			return nil, err
		}

		if v, vok := parseXSDBool(inAttr); vok {
			lre.InheritNamespaces = v
		}
	}

	savedExcludes := c.localExcludes

	excludes, err := c.elementResultExcludes(elem)
	if err != nil {
		return nil, err
	}

	c.localExcludes = excludes
	savedExtURIs := c.extensionURIs
	c.addLiteralResultExtensionURIs(elem)

	defer func() {
		c.localExcludes = savedExcludes
		c.extensionURIs = savedExtURIs
	}()

	if err := c.compileLiteralResultAttrs(elem, lre); err != nil {
		return nil, err
	}

	if err := xpath.Charge(ctx, len(c.nsBindings)+len(c.localExcludes)+1); err != nil {
		return nil, err
	}

	c.pendingLiteralResults = append(c.pendingLiteralResults, pendingLiteralResult{
		element: elem, result: lre, namespaces: maps.Clone(c.nsBindings), excludes: maps.Clone(c.localExcludes),
	})

	if err := c.compileLiteralResultOptions(ctx, elem, lre); err != nil {
		return nil, err
	}

	// Compile children
	body, err := c.compileChildren(ctx, elem)
	if err != nil {
		return nil, err
	}

	lre.Body = body

	return lre, nil
}

// pushResultNamespacePolicy applies cumulative standard attributes at every
// declaration/instruction entry, including structural clauses compiled directly.
func (c *compiler) pushResultNamespacePolicy(elem *xdm.Element) (func(), error) {
	excludes, extensions := c.localExcludes, c.extensionURIs
	namespaces := c.nsBindings
	c.nsBindings = inScopeNamespaces(elem)

	localExcludes, err := c.elementResultExcludes(elem)
	if err != nil {
		c.nsBindings = namespaces
		return nil, err
	}

	c.localExcludes = localExcludes
	c.setInstructionExtensionURIs(elem)
	c.nsBindings = namespaces

	return func() { c.localExcludes, c.extensionURIs = excludes, extensions }, nil
}

func (c *compiler) elementResultExcludes(elem *xdm.Element) (map[string]struct{}, error) {
	erp, hasERP := elem.GetAttributeNS(nameExcludeResultPrefixes, lexicon.NamespaceXSLT)

	eep, hasEEP := elem.GetAttributeNS(nameExtensionElementPrefixes, lexicon.NamespaceXSLT)
	if elem.URI() == lexicon.NamespaceXSLT {
		erp, hasERP = elem.GetAttribute(nameExcludeResultPrefixes)
		eep, hasEEP = elem.GetAttribute(nameExtensionElementPrefixes)
	}

	if !hasERP && !hasEEP {
		return c.localExcludes, nil
	}

	excludes := make(map[string]struct{}, len(c.localExcludes)+4)
	maps.Copy(excludes, c.localExcludes)

	if hasERP {
		if err := c.addLiteralResultExclusions(excludes, erp); err != nil {
			return nil, err
		}
	}

	for prefix := range strings.FieldsSeq(eep) {
		if prefix == lexicon.ModeDefault {
			prefix = ""
		}

		if uri := c.nsBindings[prefix]; uri != "" {
			excludes[uri] = struct{}{}
		} else {
			return nil, staticError(errCodeXTSE1430, "undeclared namespace prefix %q in extension-element-prefixes", prefix)
		}
	}

	return excludes, nil
}

func (c *compiler) addLiteralResultExclusions(excludes map[string]struct{}, prefixes string) error {
	if prefixes == lexicon.ModeAll {
		for _, uri := range c.nsBindings {
			if uri != "" {
				excludes[uri] = struct{}{}
			}
		}

		return nil
	}

	for prefix := range strings.FieldsSeq(prefixes) {
		if prefix == lexicon.ModeDefault {
			if uri, ok := c.nsBindings[""]; ok && uri != "" {
				excludes[uri] = struct{}{}
			} else {
				return staticError(errCodeXTSE0809,
					"#default in exclude-result-prefixes but no default namespace is declared")
			}

			continue
		}

		if uri, ok := c.nsBindings[prefix]; ok && uri != "" {
			excludes[uri] = struct{}{}
		} else {
			return staticError(errCodeXTSE0808,
				"undeclared namespace prefix %q in exclude-result-prefixes", prefix)
		}
	}

	return nil
}

func (c *compiler) addLiteralResultExtensionURIs(elem *xdm.Element) {
	// Also register extension-element-prefixes URIs so that child elements
	// in those namespaces are recognised as extension elements (and their
	// xsl:fallback children are compiled).
	if eep, ok := elem.GetAttributeNS(nameExtensionElementPrefixes, lexicon.NamespaceXSLT); ok {
		newExtURIs := make(map[string]struct{})
		maps.Copy(newExtURIs, c.extensionURIs)

		for prefix := range strings.FieldsSeq(eep) {
			if uri, uriOK := c.nsBindings[prefix]; uriOK && uri != "" {
				newExtURIs[uri] = struct{}{}
			}
		}

		c.extensionURIs = newExtURIs
	}
}

func (c *compiler) literalResultNamespaces(elem *xdm.Element) map[string]string {
	// Each pending literal result carries exclusions from its own module and
	// ancestors; the principal stylesheet's policy cannot apply globally.
	excludedURIs := maps.Clone(c.localExcludes)

	// Namespace aliases override exclusions for both their source and result URI.
	for _, alias := range c.stylesheet.namespaceAliases {
		if alias.StylesheetURI != "" {
			delete(excludedURIs, alias.StylesheetURI)
		}

		if alias.ResultURI != "" {
			delete(excludedURIs, alias.ResultURI)
		}
	}

	namespaces := make(map[string]string)
	// Copy in-scope namespace declarations that are not excluded.
	// Use c.nsBindings (scoped to this element's position in the stylesheet),
	// and never c.stylesheet.namespaces (which accumulates globally and
	// leaks namespaces from sibling variable trees).
	for prefix, uri := range c.nsBindings {
		if uri == lexicon.NamespaceXSLT || prefix == "" {
			continue
		}

		if namespaceURIExcluded(excludedURIs, uri) {
			continue
		}

		namespaces[prefix] = uri
	}
	// Override/add from directly declared namespaces on this element.
	// Include default namespace declarations (prefix="") when they have a
	// non-empty URI — these are explicit xmlns="..." on the LRE and must
	// be propagated to the result tree.
	for _, ns := range elem.Namespaces() {
		uri := ns.URI()
		prefix := ns.Prefix()

		if uri == lexicon.NamespaceXSLT {
			continue
		}

		if prefix == "" && uri == "" {
			continue // skip xmlns="" undeclarations from inherited context
		}

		if namespaceURIExcluded(excludedURIs, uri) {
			if prefix != "" {
				delete(namespaces, prefix)
			}

			continue
		}

		namespaces[prefix] = uri
	}

	return namespaces
}

func namespaceURIExcluded(excluded map[string]struct{}, uri string) bool {
	_, ok := excluded[uri]
	return ok
}

func (c *compiler) compileLiteralResultAttrs(elem *xdm.Element, lre *literalResultElement) error {
	// Validate and compile attributes
	for _, attr := range elem.Attributes() {
		if attr.URI() == lexicon.NamespaceXSLT {
			// XTSE0805: only certain XSLT attributes are allowed on LREs
			if ok := lreAllowedXSLTAttrs(attr.LocalName()); !ok {
				// In forwards-compatible mode (version > 3.0), unknown
				// XSLT attributes on LREs are silently ignored.
				if c.forwardsCompatible(c.effectiveVersion) {
					continue
				}

				return staticError(errCodeXTSE0805,
					"attribute xsl:%s is not allowed on a literal result element", attr.LocalName())
			}

			continue
		}

		avt, err := c.compileAVT(attr.Value(), c.nsBindings)
		if err != nil {
			return err
		}

		lre.Attrs = append(lre.Attrs, &literalAttribute{
			Name:      attr.Name(),
			Namespace: attr.URI(),
			Prefix:    attr.Prefix(),
			LocalName: attr.LocalName(),
			Value:     avt,
		})
	}

	return nil
}

func (c *compiler) applyLiteralResultAliases(ctx context.Context, lre *literalResultElement) {
	// Apply namespace aliases (xsl:namespace-alias).
	// This must happen after namespace declarations and attributes are collected,
	// but before children are compiled.
	if len(c.stylesheet.namespaceAliases) > 0 {
		// Alias the element itself
		if resultURI, resultPfx, ok := c.resolveNamespaceAlias(ctx, lre.Namespace); ok {
			lre.Namespace = resultURI
			if resultPfx != "" {
				lre.Prefix = resultPfx
				lre.Name = resultPfx + ":" + lre.LocalName
			} else {
				lre.Prefix = ""
				lre.Name = lre.LocalName
			}
		}

		// Alias attributes
		for _, attr := range lre.Attrs {
			if attr.Namespace == "" {
				continue
			}

			if resultURI, resultPfx, ok := c.resolveNamespaceAlias(ctx, attr.Namespace); ok {
				attr.Namespace = resultURI
				if resultPfx != "" {
					attr.Prefix = resultPfx
					attr.Name = resultPfx + ":" + attr.LocalName
				} else {
					attr.Prefix = ""
					attr.Name = attr.LocalName
				}
			}
		}

		lre.Namespaces = c.aliasLiteralResultNamespaces(ctx, lre.Namespaces)
	}
}

func (c *compiler) aliasLiteralResultNamespaces(ctx context.Context, namespaces map[string]string) map[string]string {
	// Alias namespace declarations
	aliasedNS := make(map[string]string)

	for prefix, uri := range namespaces {
		if resultURI, resultPfx, ok := c.resolveNamespaceAlias(ctx, uri); ok {
			if resultPfx != "" {
				aliasedNS[resultPfx] = resultURI
			} else if resultURI != "" {
				// Only keep aliased prefix when the result URI is non-empty.
				// Mapping a prefixed namespace to "" (no namespace) means
				// the prefix is no longer needed — dropping it avoids
				// emitting the illegal xmlns:p="" undeclaration.
				aliasedNS[prefix] = resultURI
			}
			// else: prefixed namespace aliased to #default with no default
			// namespace → drop entirely (the element/attr already got the
			// correct no-namespace treatment above).
		} else {
			aliasedNS[prefix] = uri
		}
	}

	return aliasedNS
}

func (c *compiler) compileLiteralResultOptions(ctx context.Context, elem *xdm.Element, lre *literalResultElement) error {
	if uas, ok := elem.GetAttributeNS(nameUseAttributeSets, lexicon.NamespaceXSLT); ok {
		for name := range strings.FieldsSeq(uas) {
			resolved := resolveQName(name, c.nsBindings)
			lre.UseAttrSets = append(lre.UseAttrSets, resolved)
			c.usedAttrSetRefs = append(c.usedAttrSetRefs, resolved)
		}
	}

	if valAttr, ok := elem.GetAttributeNS(nameValidation, lexicon.NamespaceXSLT); ok {
		if err := validateValidationAttr("LRE (xsl:validation)", valAttr); err != nil {
			return err
		}

		if !c.stylesheet.schemaAware && valAttr == validationStrict {
			return staticError(errCodeXTSE0220, "xsl:validation requires schema-aware processing")
		}

		lre.Validation = basicValidation(valAttr)
	}

	if typeAttr, ok := elem.GetAttributeNS(lexicon.AttrType, lexicon.NamespaceXSLT); ok {
		if err := c.checkTypeAttrSchemaAware(ctx, "LRE (xsl:type)", typeAttr); err != nil {
			return err
		}

		lre.TypeName = resolveXSDTypeNameNS(typeAttr, c.nsBindings, c.xpathDefaultNS, c.hasXPathDefaultNS)
	}

	// Handle xsl:default-validation on LRE (XSLT 3.0 §3.6)
	if dvAttr, ok := elem.GetAttributeNS(nameDefaultValidation, lexicon.NamespaceXSLT); ok {
		lre.DefaultValidation = basicValidation(dvAttr)
	}

	// Compute effective static base URI: if any ancestor stylesheet element
	// (including this one) has xml:base, the static base URI for expressions
	// inside this LRE differs from the template/stylesheet base URI.
	effectiveBase := stylesheetBaseURI(elem, c.baseURI, c.moduleRoot)
	if effectiveBase != c.baseURI {
		lre.StaticBaseURI = effectiveBase
	}

	return nil
}

func validateCopyBooleanAttrs(elem *xdm.Element, instructionName string, names ...string) error {
	for _, name := range names {
		if value, present := elem.GetAttribute(name); present {
			if err := validateBooleanAttr(instructionName, name, value); err != nil {
				return err
			}
		}
	}

	return nil
}
