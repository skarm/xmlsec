// Derived from lestrrat-go/helium at 7362c0a70122a757780f4d0b545a9b370dead6ab.
// Copyright (c) 2015 lestrrat. MIT License; see licenses/MIT-helium.txt at the repository root.

package xslt

import (
	"context"
	"maps"
	"slices"
	"strconv"
	"strings"

	"github.com/skarm/xmlsec/internal/xmlchar"
	"github.com/skarm/xmlsec/transform/internal/xdm"
	"github.com/skarm/xmlsec/transform/internal/xdm/lexicon"
	"github.com/skarm/xmlsec/transform/internal/xpath"
)

// Attribute predicates validate compile-time vocabulary without mutable tables.
func withParamAllowedAttrs(name string) bool {
	switch name {
	case xslAttrName, xslAttrSelect, "as", nameTunnel:
		return true
	default:
		return false
	}
}

func paramAllowedAttrs(name string) bool {
	switch name {
	case xslAttrName, xslAttrSelect, "as", ctxItemRequired, nameTunnel, nameStatic:
		return true
	default:
		return false
	}
}

func variableAllowedAttrs(name string) bool {
	switch name {
	case xslAttrName, xslAttrSelect, "as", nameStatic, xslAttrVisibility:
		return true
	default:
		return false
	}
}

func lreAllowedXSLTAttrs(name string) bool {
	switch name {
	case nameUseAttributeSets, nameExpandText, nameXpathDefaultNamespace, nameExcludeResultPrefixes,
		nameExtensionElementPrefixes, paramVersion, nameType, nameValidation,
		nameDefaultCollation, nameDefaultMode, nameDefaultValidation, nameInheritNamespaces,
		xslAttrUseWhen:
		return true
	default:
		return false
	}
}

// validateBooleanAttr checks that a boolean attribute value is valid xs:boolean.
// Valid values are "yes", "no", "true", "false", "1", "0" (with optional whitespace).
// Returns XTSE0020 if the value is not valid.
func validateBooleanAttr(elemName, attrName, value string) error {
	if _, ok := parseXSDBool(value); !ok {
		return staticError(errCodeXTSE0020, "%q is not a valid value for %s/@%s", value, elemName, attrName)
	}

	return nil
}

func attributeNames(names ...string) func(string) bool {
	return func(name string) bool { return slices.Contains(names, name) }
}

// validateXSLTAttrs checks that an XSLT element has only allowed unprefixed attributes
// and no attributes in the XSLT namespace. Returns XTSE0090 for unknown attributes.
// Standard attributes (use-when, expand-text, etc.) are always allowed per XSLT 3.0 §3.5.
// In forwards-compatible mode (version > 3.0), unknown attributes are silently ignored
// per XSLT 3.0 §3.8.
func (c *compiler) validateXSLTAttrs(_ context.Context, elem *xdm.Element, allowed func(string) bool) error {
	fc := c.forwardsCompatible(c.effectiveVersion)
	if !fc {
		// Also check the element's own version attribute
		if elemVer := getAttr(elem, paramVersion); elemVer != "" {
			fc = c.forwardsCompatible(elemVer)
		}
	}

	for _, attr := range elem.Attributes() {
		// Attributes in the XSLT namespace are not allowed on XSLT elements
		if attr.URI() == lexicon.NamespaceXSLT {
			if fc {
				continue
			}

			return staticError(errCodeXTSE0090,
				"attribute %q in the XSLT namespace is not allowed on xsl:%s", attr.LocalName(), elem.LocalName())
		}
		// Skip attributes in other (non-null) namespaces — those are extension attributes
		if attr.URI() != "" {
			continue
		}

		name := attr.LocalName()
		// Shadow attributes (prefixed with _) are compile-time AVTs
		if strings.HasPrefix(name, "_") {
			continue
		}

		if allowed(name) {
			continue
		}

		if xsltStandardAttrs(name) {
			continue
		}

		if fc {
			continue
		}

		return staticError(errCodeXTSE0090,
			"attribute %q is not allowed on xsl:%s", name, elem.LocalName())
	}

	return nil
}

// xsltStandardAttrs reports attributes permitted on every XSLT element.
func xsltStandardAttrs(name string) bool {
	switch name {
	case nameDefaultCollation, nameDefaultMode, nameDefaultValidation, nameExcludeResultPrefixes,
		nameExpandText, nameExtensionElementPrefixes, xslAttrUseWhen, nameXpathDefaultNamespace,
		paramVersion:
		return true
	default:
		return false
	}
}

// checkTypeAttrSchemaAware verifies that the type attribute is only used when
// the stylesheet has imported at least one schema, unless typeName resolves to
// a built-in XSD type (xs: / xsd: namespace). Returns XTSE0215 otherwise.
func (c *compiler) checkTypeAttrSchemaAware(_ context.Context, elemName, typeName string) error {
	if isBuiltinXSDTypeName(typeName, c.nsBindings) {
		return nil
	}

	return staticError(errCodeXTSE0215, "%s/@type requires a schema import (xsl:import-schema)", elemName)
}

// isBuiltinXSDTypeName reports whether typeName refers to the built-in XSD
// namespace (http://www.w3.org/2001/XMLSchema). It recognises the conventional
// xs: and xsd: prefixes directly, and also resolves any other prefix via ns.
func isBuiltinXSDTypeName(typeName string, ns map[string]string) bool {
	if strings.HasPrefix(typeName, "xs:") || strings.HasPrefix(typeName, "xsd:") {
		return true
	}

	prefix, _, ok := strings.Cut(typeName, ":")
	if !ok {
		return false
	}

	uri, ok := ns[prefix]

	return ok && uri == lexicon.NamespaceXSD
}

func (c *compiler) compileInstruction(ctx context.Context, elem *xdm.Element) (instruction, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	// Push element-local namespace declarations into scope
	saved := c.pushElementNamespaces(ctx, elem)
	defer func() { c.nsBindings = saved }()

	include, err := c.instructionUseWhen(ctx, elem)
	if err != nil {
		return nil, err
	}

	if !include {
		return nil, nil //nolint:nilnil
	}

	if err := c.prepareInstructionAttributes(ctx, elem); err != nil {
		return nil, err
	}

	// Handle version inheritance. On an XSLT element this is the unqualified
	// version attribute; on a literal result element it is xsl:version (an
	// unqualified version there is a result attribute, not an XSLT version).
	savedVersion := c.effectiveVersion
	if ver := elementXSLTVersion(elem); ver != "" {
		c.effectiveVersion = ver
	}
	defer func() { c.effectiveVersion = savedVersion }()

	savedPreserve := c.preserveSpace
	if xs := getAttr(elem, lexicon.QNameXMLSpace); xs != "" {
		c.preserveSpace = (xs == lexicon.SpacePreserve)
	}
	defer func() { c.preserveSpace = savedPreserve }()

	// Handle expand-text inheritance (check both unprefixed and xsl:-prefixed for LREs)
	savedExpandText := c.expandText

	if err := c.setInstructionExpandText(elem); err != nil {
		return nil, err
	}

	defer func() { c.expandText = savedExpandText }()

	// Handle per-instruction xpath-default-namespace
	// On XSLT elements: check unprefixed attribute.
	// On LREs: only check xsl:-prefixed (in XSLT namespace).
	savedXPathDefaultNS := c.xpathDefaultNS

	savedHasXPathDefaultNS := c.hasXPathDefaultNS
	hasLocalXPNS := c.setInstructionXPathDefaultNS(elem)

	defer func() {
		c.xpathDefaultNS = savedXPathDefaultNS
		c.hasXPathDefaultNS = savedHasXPathDefaultNS
	}()

	savedDefaultCollation := c.defaultCollation

	c.setInstructionDefaultCollation(elem)

	defer func() { c.defaultCollation = savedDefaultCollation }()

	// Handle per-instruction default-mode (XSLT 3.0 standard attribute)
	// On XSLT elements: default-mode="..."
	// On LREs: xsl:default-mode="..."
	// Mode names are stored as raw QNames (not Clark notation) for consistency
	// with how template mode attributes are stored.
	savedDefaultMode := c.defaultMode
	c.setInstructionDefaultMode(elem)

	defer func() { c.defaultMode = savedDefaultMode }()

	// Handle extension-element-prefixes on both XSLT instructions and LREs.
	// On XSLT elements: extension-element-prefixes="..."
	// On LREs: xsl:extension-element-prefixes="..." — must be processed
	// before the extension element check so that an LRE declaring its own
	// namespace as extension is recognized as an extension element.
	savedExtURIs := c.extensionURIs

	c.setInstructionExtensionURIs(elem)

	defer func() { c.extensionURIs = savedExtURIs }()

	inst, decorate, err := c.compileInstructionPayload(ctx, elem)
	if err != nil {
		return nil, err
	}

	if !decorate {
		return inst, nil
	}

	c.setInstructionXPathNS(ctx, inst, hasLocalXPNS)
	c.recordInstructionSource(elem, inst)
	// Wrap in collation scope if default-collation changed on this element.
	// This ensures the runtime ec.defaultCollation is set correctly for
	// XPath expressions evaluated by the wrapped instruction.
	if c.defaultCollation != savedDefaultCollation {
		inst = &collationScopeInst{
			DefaultCollation: c.defaultCollation,
			Inner:            inst,
		}
	}

	return inst, nil
}

// compileInstructionPayload distinguishes fallback instructions that return
// directly from normal instructions whose static context and source are recorded.
func (c *compiler) compileInstructionPayload(ctx context.Context, elem *xdm.Element) (instruction, bool, error) {
	if elem.URI() == lexicon.NamespaceXSLT {
		if c.stylesheet.processorLanguage() == 10 {
			if _, known := lookupxslt10Attributes(elem.LocalName()); !known {
				inst, err := c.compileForwardsCompat(ctx, elem)
				return inst, false, err
			}
		}

		inst, err := c.compileXSLTInstruction(ctx, elem)

		return inst, true, err
	}

	if uri := elem.URI(); uri != "" && c.extensionURIs != nil {
		if _, isExt := c.extensionURIs[uri]; isExt {
			inst, err := c.compileForwardsCompat(ctx, elem)
			return inst, false, err
		}
	}

	inst, err := c.compileLiteralResultElement(ctx, elem)

	return inst, true, err
}

func (c *compiler) instructionUseWhen(ctx context.Context, elem *xdm.Element) (bool, error) {
	if elem.URI() == lexicon.NamespaceXSLT {
		if value := getAttr(elem, xslAttrUseWhen); value != "" {
			return c.evaluateUseWhen(ctx, value)
		}
	} else if value, present := elem.GetAttributeNS(xslAttrUseWhen, lexicon.NamespaceXSLT); present {
		return c.evaluateUseWhen(ctx, value)
	}

	return true, nil
}

func (c *compiler) prepareInstructionAttributes(ctx context.Context, elem *xdm.Element) error {
	if elem.URI() != lexicon.NamespaceXSLT {
		return nil
	}

	for _, attr := range elem.Attributes() {
		if attr.URI() == lexicon.NamespaceXSLT {
			return staticError(errCodeXTSE0090,
				"attribute %q in the XSLT namespace is not allowed on xsl:%s", attr.LocalName(), elem.LocalName())
		}
	}

	return c.resolveShadowAttributes(ctx, elem)
}

func (c *compiler) setInstructionExpandText(elem *xdm.Element) error {
	if et, hasET := elem.GetAttribute(nameExpandText); elem.URI() == lexicon.NamespaceXSLT && hasET {
		if v, ok := parseXSDBool(et); ok {
			c.expandText = v
		} else if elem.URI() == lexicon.NamespaceXSLT {
			// XTSE0020: invalid boolean value for expand-text on XSLT element
			return staticError(errCodeXTSE0020, "%q is not a valid value for xsl:%s/@expand-text", et, elem.LocalName())
		}
	} else if et, ok := elem.GetAttributeNS(nameExpandText, lexicon.NamespaceXSLT); ok {
		if v, ok := parseXSDBool(et); ok {
			c.expandText = v
		} else {
			// XTSE0020: invalid boolean value for xsl:expand-text on LRE
			return staticError(errCodeXTSE0020, "%q is not a valid value for xsl:expand-text", et)
		}
	}

	return nil
}

func (c *compiler) setInstructionXPathDefaultNS(elem *xdm.Element) bool {
	hasLocalXPNS := false

	if elem.URI() == lexicon.NamespaceXSLT {
		if xdn, ok := elem.GetAttribute(nameXpathDefaultNamespace); ok {
			c.xpathDefaultNS = xdn
			c.hasXPathDefaultNS = true
			hasLocalXPNS = true
		}
	} else if xdn, ok := elem.GetAttributeNS(nameXpathDefaultNamespace, lexicon.NamespaceXSLT); ok {
		c.xpathDefaultNS = xdn
		c.hasXPathDefaultNS = true
		hasLocalXPNS = true
	}

	return hasLocalXPNS
}

func (c *compiler) setInstructionDefaultCollation(elem *xdm.Element) {
	if dc, ok := elem.GetAttribute(nameDefaultCollation); elem.URI() == lexicon.NamespaceXSLT && ok {
		if uri := resolveDefaultCollation(dc); uri != "" {
			c.defaultCollation = uri
		}
	} else if dc, ok := elem.GetAttributeNS(nameDefaultCollation, lexicon.NamespaceXSLT); ok {
		if uri := resolveDefaultCollation(dc); uri != "" {
			c.defaultCollation = uri
		}
	}
}

func (c *compiler) setInstructionDefaultMode(elem *xdm.Element) {
	if dm := getAttr(elem, nameDefaultMode); elem.URI() == lexicon.NamespaceXSLT && dm != "" {
		c.defaultMode = dm
	} else if dm, ok := elem.GetAttributeNS(nameDefaultMode, lexicon.NamespaceXSLT); ok {
		c.defaultMode = dm
	}
}

func (c *compiler) setInstructionExtensionURIs(elem *xdm.Element) {
	if elem.URI() == lexicon.NamespaceXSLT {
		if eep := getAttr(elem, nameExtensionElementPrefixes); eep != "" {
			newExtURIs := make(map[string]struct{})
			maps.Copy(newExtURIs, c.extensionURIs)

			for prefix := range strings.FieldsSeq(eep) {
				if uri, ok := c.nsBindings[prefix]; ok && uri != "" {
					newExtURIs[uri] = struct{}{}
				}
			}

			c.extensionURIs = newExtURIs
		}
	} else if eep, ok := elem.GetAttributeNS(nameExtensionElementPrefixes, lexicon.NamespaceXSLT); ok {
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

func (c *compiler) recordInstructionSource(elem *xdm.Element, inst instruction) {
	// Record source location for $err:line-number / $err:module in xsl:catch
	if si, ok := inst.(interface{ setSourceInfo(int, string) }); ok {
		module := ""
		if doc := elem.OwnerDocument(); doc != nil {
			module = doc.URL()
		}

		si.setSourceInfo(elem.Line(), module)
	}
	// Compute effective static base URI from xml:base on the stylesheet element.
	// This is set generically so that static-base-uri() returns the correct
	// value for any XSLT instruction or LRE that carries xml:base.
	if effectiveBase := stylesheetBaseURI(elem, c.baseURI, c.moduleRoot); effectiveBase != c.baseURI {
		if si, ok := inst.(interface{ getStaticBaseURI() string }); ok {
			// Only set if not already set by a specific compile function
			if si.getStaticBaseURI() == "" {
				if setter, ok2 := inst.(interface{ setStaticBaseURI(string) }); ok2 {
					setter.setStaticBaseURI(effectiveBase)
				}
			}
		}
	}
}

// setInstructionXPathNS stores the current xpath-default-namespace on
// instructions that embed xpathNS.
func (c *compiler) setInstructionXPathNS(_ context.Context, inst instruction, hasLocal bool) {
	set := func(ns *xpathNS) {
		ns.XPathDefaultNS = c.xpathDefaultNS
		// Mark as set when either explicitly declared locally or inherited non-empty
		ns.HasXPathDefaultNS = hasLocal || c.xpathDefaultNS != ""
		ns.HasLocalXPathDefaultNS = hasLocal
	}

	switch v := inst.(type) {
	case *applyTemplatesInst:
		set(&v.xpathNS)
	case *ifInst:
		set(&v.xpathNS)
	case *valueOfInst:
		set(&v.xpathNS)
	case *forEachInst:
		set(&v.xpathNS)
	case *chooseInst:
		set(&v.xpathNS)
	case *evaluateInst:
		set(&v.xpathNS)
	case *literalResultElement:
		set(&v.xpathNS)
	case *variableInst:
		set(&v.xpathNS)
	}
}

// validateDescendantUseWhen recursively validates use-when XPath expressions
// on all descendant elements. This is used for elements like xsl:fallback whose
// children are not compiled but whose use-when expressions must still be
// syntactically valid per XSLT 3.0.
func (c *compiler) validateDescendantUseWhen(ctx context.Context, parent *xdm.Element) error {
	for child := range xdm.Children(parent) {
		childElem, ok := child.(*xdm.Element)
		if !ok {
			continue
		}
		// Check use-when on XSLT elements and xsl:use-when on LREs
		var uw string
		if childElem.URI() == lexicon.NamespaceXSLT {
			uw = getAttr(childElem, xslAttrUseWhen)
		} else {
			uw, _ = childElem.GetAttributeNS(xslAttrUseWhen, lexicon.NamespaceXSLT)
		}

		if uw != "" {
			if _, err := c.evaluateUseWhen(ctx, uw); err != nil {
				return err
			}
		}

		if err := c.validateDescendantUseWhen(ctx, childElem); err != nil {
			return err
		}
	}

	return nil
}

// evaluateUseWhen evaluates a use-when XPath expression at compile time.
// Returns (true, nil) to include the element, (false, nil) to exclude,
// or (false, error) to propagate a compile-time error.
// Provides XSLT static context functions: function-available, system-property,
// type-available, element-available per XSLT 3.0 §3.14.
func (c *compiler) evaluateUseWhen(ctx context.Context, expr string) (bool, error) {
	compiled, err := xpath.NewCompiler().Compile(expr)
	if err != nil {
		// XPST0003: invalid XPath in use-when is a static error
		return false, staticError(errCodeXPST0003,
			"invalid XPath expression in use-when: %s: %v", expr, err)
	}

	eval := c.useWhenEvaluator(ctx)

	result, err := eval.Evaluate(ctx, compiled, nil)
	if err != nil {
		// Propagate all errors from use-when evaluation.
		// XSLT 3.0 spec requires static errors (XPST0003, XPST0008,
		// XPST0017, XPST0051, XPST0081) and dynamic errors to be reported.
		return false, err
	}

	b, err := result.EBV()
	if err != nil {
		return true, nil //nolint:nilerr // use-when defaults to true on EBV failure
	}

	return b, nil
}

func (c *compiler) useWhenFunctionAvailable(_ context.Context, args []xdm.Sequence) (xdm.Sequence, error) {
	if len(args) == 0 || args[0] == nil || xdm.SequenceLen(args[0]) == 0 {
		return xdm.SingleBoolean(false), nil
	}

	av, err := xpath.AtomizeItem(args[0].Get(0))
	if err != nil {
		return xdm.SingleBoolean(false), nil //nolint:nilerr // function-available returns false on atomization failure
	}

	name, _ := xpath.AtomicToString(av)

	// XTDE1400: function name must be a valid QName
	if !strings.HasPrefix(name, "Q{") && !xmlchar.IsValidQName(name) {
		return nil, dynamicError(errCodeXTDE1400,
			"function-available: %q is not a valid QName", name)
	}

	if prefix, _, ok := strings.Cut(name, ":"); ok {
		if _, ok := c.nsBindings[prefix]; !ok {
			return nil, dynamicError(errCodeXTDE1400,
				"undeclared namespace prefix %q in function-available(%q)", prefix, name)
		}
	}

	// Only XSLT static context functions are available in use-when.
	// Runtime-only functions (current, key, document, generate-id, etc.)
	// are NOT available in the use-when static context per XSLT 3.0 spec 3.4.6.
	switch name {
	case fnNameFunctionAvailable, funcSystemProperty, fnNameTypeAvailable,
		fnNameElementAvailable, funcAvailableSystemProperties:
		return xdm.SingleBoolean(true), nil
	}

	// XPath built-in functions: resolve prefixed names to namespace URI.
	localName := name
	ns := ""

	if prefix, ln, ok := strings.Cut(name, ":"); ok {
		localName = ln
		ns = c.nsBindings[prefix] // already validated above
	} else if strings.HasPrefix(name, "Q{") {
		// EQName: Q{uri}local
		end := strings.IndexByte(name, '}')
		if end >= 0 {
			ns = name[2:end]
			localName = name[end+1:]
		}
	}

	if ns != "" {
		if xpath.IsBuiltinFunctionNS(ns, localName) {
			return xdm.SingleBoolean(true), nil
		}
	} else {
		if xpath.IsBuiltinFunction(localName) {
			return xdm.SingleBoolean(true), nil
		}
	}

	return xdm.SingleBoolean(false), nil
}

func (c *compiler) useWhenSystemProperty(_ context.Context, args []xdm.Sequence) (xdm.Sequence, error) {
	if len(args) == 0 || args[0] == nil || xdm.SequenceLen(args[0]) == 0 {
		return xdm.SingleString(""), nil
	}

	av, err := xpath.AtomizeItem(args[0].Get(0))
	if err != nil {
		return xdm.SingleString(""), nil //nolint:nilerr // system-property returns "" on atomization failure
	}

	name, _ := xpath.AtomicToString(av)

	resolved := resolveQName(name, c.nsBindings)
	switch resolved {
	case xdm.ClarkName(lexicon.NamespaceXSLT, paramVersion):
		return xdm.SingleString("3.0"), nil
	case xdm.ClarkName(lexicon.NamespaceXSLT, "vendor"):
		return xdm.SingleString("xmlsec"), nil
	case xdm.ClarkName(lexicon.NamespaceXSLT, "vendor-url"):
		return xdm.SingleString("https://github.com/skarm/xmlsec"), nil
	case xdm.ClarkName(lexicon.NamespaceXSLT, "product-name"):
		return xdm.SingleString("xmlsec"), nil
	case xdm.ClarkName(lexicon.NamespaceXSLT, "product-version"):
		return xdm.SingleString("0.1"), nil
	case xdm.ClarkName(lexicon.NamespaceXSLT, nameIsSchemaAware):
		return xdm.SingleString(lexicon.ValueYes), nil
	case xdm.ClarkName(lexicon.NamespaceXSLT, nameSupportsSerialization):
		return xdm.SingleString(lexicon.ValueYes), nil
	case xdm.ClarkName(lexicon.NamespaceXSLT, textSupportsBackwardsCompatibility):
		return xdm.SingleString(lexicon.ValueYes), nil
	case xdm.ClarkName(lexicon.NamespaceXSLT, nameSupportsNamespaceAxis):
		return xdm.SingleString(lexicon.ValueYes), nil
	case xdm.ClarkName(lexicon.NamespaceXSLT, nameSupportsStreaming):
		return xdm.SingleString(lexicon.ValueNo), nil
	case xdm.ClarkName(lexicon.NamespaceXSLT, nameSupportsDynamicEvaluation):
		return xdm.SingleString(lexicon.ValueYes), nil
	case xdm.ClarkName(lexicon.NamespaceXSLT, textSupportsHigherOrderFunctions):
		return xdm.SingleString(lexicon.ValueYes), nil
	case xdm.ClarkName(lexicon.NamespaceXSLT, "xpath-version"):
		return xdm.SingleString("3.1"), nil
	case xdm.ClarkName(lexicon.NamespaceXSLT, "xsd-version"):
		return xdm.SingleString("1.1"), nil
	}

	return xdm.SingleString(""), nil
}

func (c *compiler) useWhenTypeAvailable(_ context.Context, args []xdm.Sequence) (xdm.Sequence, error) {
	if len(args) == 0 || args[0] == nil || xdm.SequenceLen(args[0]) == 0 {
		return xdm.SingleBoolean(false), nil
	}

	av, err := xpath.AtomizeItem(args[0].Get(0))
	if err != nil {
		return xdm.SingleBoolean(false), nil //nolint:nilerr // type-available returns false on atomization failure
	}

	name, _ := xpath.AtomicToString(av)
	resolved := resolveQName(name, c.nsBindings)

	return xdm.SingleBoolean(xdm.IsKnownXSDType(resolved)), nil
}

func (c *compiler) useWhenElementAvailable(_ context.Context, args []xdm.Sequence) (xdm.Sequence, error) {
	if len(args) == 0 || args[0] == nil || xdm.SequenceLen(args[0]) == 0 {
		return xdm.SingleBoolean(false), nil
	}

	av, err := xpath.AtomizeItem(args[0].Get(0))
	if err != nil {
		return xdm.SingleBoolean(false), nil //nolint:nilerr // element-available returns false on atomization failure
	}

	name, _ := xpath.AtomicToString(av)

	resolved := resolveQName(name, c.nsBindings)
	if strings.HasPrefix(resolved, "{"+lexicon.NamespaceXSLT+"}") {
		local := resolved[len("{"+lexicon.NamespaceXSLT+"}"):]
		switch local {
		case lexicon.XSLTElementApplyTemplates, lexicon.XSLTElementCallTemplate, lexicon.XSLTElementApplyImports,
			lexicon.XSLTElementForEach, lexicon.XSLTElementValueOf, lexicon.XSLTElementCopyOf, lexicon.XSLTElementNumber, lexicon.XSLTElementChoose,
			lexicon.XSLTElementIf, lexicon.XSLTElementText, lexicon.XSLTElementCopy, lexicon.XSLTElementVariable, lexicon.XSLTElementMessage, lexicon.XSLTElementFallback,
			lexicon.XSLTElementProcessingInstruction, lexicon.XSLTElementComment, lexicon.XSLTElementElement, lexicon.XSLTElementAttribute,
			lexicon.XSLTElementSort, lexicon.XSLTElementOutput, lexicon.XSLTElementKey, lexicon.XSLTElementTemplate, lexicon.XSLTElementParam, lexicon.XSLTElementWithParam,
			lexicon.XSLTElementForEachGroup, lexicon.XSLTElementSequence, lexicon.XSLTElementDocument, lexicon.XSLTElementResultDocument,
			lexicon.XSLTElementAnalyzeString, lexicon.XSLTElementNamespace, lexicon.XSLTElementPerformSort, lexicon.XSLTElementNextMatch,
			lexicon.XSLTElementTry, lexicon.XSLTElementIterate, lexicon.XSLTElementSourceDocument, lexicon.XSLTElementMerge, lexicon.XSLTElementOnEmpty,
			lexicon.XSLTElementOnNonEmpty, lexicon.XSLTElementWherePopulated, lexicon.XSLTElementEvaluate, lexicon.XSLTElementAssert,
			lexicon.XSLTElementMap, lexicon.XSLTElementMapEntry, lexicon.XSLTElementBreak, lexicon.XSLTElementNextIteration:
			return xdm.SingleBoolean(true), nil
		}
	}

	return xdm.SingleBoolean(false), nil
}

// pushElementNamespaces adds namespace declarations from elem to nsBindings
// and to the stylesheet's runtime namespace map. Returns previous nsBindings
// for restoring.
func (c *compiler) pushElementNamespaces(_ context.Context, elem *xdm.Element) map[string]string {
	nsList := elem.Namespaces()
	if len(nsList) == 0 {
		return c.nsBindings
	}

	saved := c.nsBindings
	newBindings := make(map[string]string, len(saved)+len(nsList))
	maps.Copy(newBindings, saved)

	for _, ns := range nsList {
		prefix := ns.Prefix()
		uri := ns.URI()
		newBindings[prefix] = uri
		// Also add to stylesheet namespaces for runtime XPath evaluation,
		// but only for prefixes not already declared at a higher scope.
		// Local redeclarations (e.g. xmlns:x="..." on a literal result
		// element inside a template) must not overwrite the top-level
		// stylesheet binding that user-defined functions are registered under.
		if _, exists := c.stylesheet.namespaces[prefix]; !exists {
			c.stylesheet.namespaces[prefix] = uri
		}
	}

	c.nsBindings = newBindings

	return saved
}

func (c *compiler) compileXSLTInstruction(ctx context.Context, elem *xdm.Element) (instruction, error) {
	switch elem.LocalName() {
	case lexicon.XSLTElementApplyTemplates, lexicon.XSLTElementCallTemplate, lexicon.XSLTElementIf, lexicon.XSLTElementChoose,
		lexicon.XSLTElementForEach, lexicon.XSLTElementVariable, lexicon.XSLTElementParam, lexicon.XSLTElementPerformSort,
		lexicon.XSLTElementNextMatch, lexicon.XSLTElementApplyImports:
		return c.compileTemplateControlInstruction(ctx, elem)
	case lexicon.XSLTElementValueOf, lexicon.XSLTElementText, lexicon.XSLTElementElement, lexicon.XSLTElementAttribute,
		lexicon.XSLTElementComment, lexicon.XSLTElementProcessingInstruction, lexicon.XSLTElementCopy, lexicon.XSLTElementCopyOf,
		lexicon.XSLTElementNumber, lexicon.XSLTElementNamespace, lexicon.XSLTElementSequence, lexicon.XSLTElementDocument:
		return c.compileNodeInstruction(ctx, elem)
	case lexicon.XSLTElementMessage:
		return c.compileMessage(ctx, elem)
	case lexicon.XSLTElementResultDocument:
		return c.compileResultDocument(ctx, elem)
	case lexicon.XSLTElementWherePopulated:
		// xsl:where-populated: execute body and only include if non-empty
		body, err := c.compileChildren(ctx, elem)
		if err != nil {
			return nil, err
		}

		return &wherePopulatedInst{Body: body}, nil
	case lexicon.XSLTElementOnEmpty, lexicon.XSLTElementOnNonEmpty:
		return c.compileConditionalContent(ctx, elem)
	case lexicon.XSLTElementTry:
		return c.compileTry(ctx, elem)
	case lexicon.XSLTElementForEachGroup:
		return c.compileForEachGroup(ctx, elem)
	case lexicon.XSLTElementMap:
		return c.compileMap(ctx, elem)
	case lexicon.XSLTElementMapEntry:
		return c.compileMapEntry(ctx, elem)
	case lexicon.XSLTElementSort:
		// XTSE0010: xsl:sort is only allowed as a child of xsl:apply-templates,
		// xsl:for-each, xsl:for-each-group, or xsl:perform-sort.
		// Those instructions handle xsl:sort directly; if we reach here, xsl:sort
		// appears in an invalid context (e.g. inside xsl:template body or xsl:call-template).
		return nil, staticError(errCodeXTSE0010,
			"xsl:sort is not allowed in this position")
	case lexicon.XSLTElementFallback:
		// xsl:fallback is only activated when the parent is unrecognized;
		// when we reach here the parent was recognized, so skip.
		// But we still need to validate use-when XPath on descendant elements
		// since use-when is evaluated during static analysis (XPST0003).
		if err := c.validateDescendantUseWhen(ctx, elem); err != nil {
			return nil, err
		}

		return nil, nil //nolint:nilnil
	case lexicon.XSLTElementContextItem:
		// xsl:context-item declares the expected context item type.
		// Currently a no-op — validation happens at the mode level.
		return nil, nil //nolint:nilnil
	case lexicon.XSLTElementAssert:
		return c.compileAssert(ctx, elem)
	case lexicon.XSLTElementAnalyzeString:
		return c.compileAnalyzeString(ctx, elem)
	case lexicon.XSLTElementEvaluate:
		return c.compileEvaluate(ctx, elem)
	case lexicon.XSLTElementSourceDocument, lexicon.XSLTElementIterate, lexicon.XSLTElementFork, lexicon.XSLTElementBreak,
		lexicon.XSLTElementNextIteration, lexicon.XSLTElementMerge:
		return c.compileStreamingInstruction(ctx, elem)
	case lexicon.XSLTElementMergeSource:
		// xsl:merge-source must be a direct child of xsl:merge
		return nil, staticError(errCodeXTSE0010, "xsl:merge-source must be a direct child of xsl:merge")
	case lexicon.XSLTElementMergeAction:
		// xsl:merge-action must be a direct child of xsl:merge
		return nil, staticError(errCodeXTSE0010, "xsl:merge-action must be a direct child of xsl:merge")
	case lexicon.XSLTElementMergeKey:
		// xsl:merge-key must be a direct child of xsl:merge-source
		return nil, staticError(errCodeXTSE0010, "xsl:merge-key must be a direct child of xsl:merge-source")
	case lexicon.XSLTElementOnCompletion:
		// xsl:on-completion must be a direct child of xsl:iterate — if we reach
		// here, it was encountered outside that context.
		return nil, staticError(errCodeXTSE0010, "xsl:on-completion must be a direct child of xsl:iterate")
	default:
		return c.compileUnknownXSLTInstruction(ctx, elem)
	}
}

// compileConditionalContent shares select-or-constructor compilation for the
// two conditional output instructions while retaining their distinct behavior.
func (c *compiler) compileConditionalContent(ctx context.Context, elem *xdm.Element) (instruction, error) {
	var (
		selectExpr *xpath.Expression
		body       []instruction
		err        error
	)

	if selectAttr := getAttr(elem, xslAttrSelect); selectAttr != "" {
		selectExpr, err = c.compileXPath(selectAttr, c.nsBindings)
	} else {
		body, err = c.compileChildren(ctx, elem)
	}

	if err != nil {
		return nil, err
	}

	if elem.LocalName() == lexicon.XSLTElementOnEmpty {
		return &onEmptyInst{Select: selectExpr, Body: body}, nil
	}

	return &onNonEmptyInst{Select: selectExpr, Body: body}, nil
}

func (c *compiler) compileNodeInstruction(ctx context.Context, elem *xdm.Element) (instruction, error) {
	switch elem.LocalName() {
	case lexicon.XSLTElementValueOf:
		return c.compileValueOf(ctx, elem)
	case lexicon.XSLTElementText:
		return c.compileText(ctx, elem)
	case lexicon.XSLTElementElement:
		return c.compileElement(ctx, elem)
	case lexicon.XSLTElementAttribute:
		return c.compileAttribute(ctx, elem)
	case lexicon.XSLTElementComment:
		return c.compileComment(ctx, elem)
	case lexicon.XSLTElementProcessingInstruction:
		return c.compilePI(ctx, elem)
	case lexicon.XSLTElementCopy:
		return c.compileCopy(ctx, elem)
	case lexicon.XSLTElementCopyOf:
		return c.compileCopyOf(ctx, elem)
	case lexicon.XSLTElementNumber:
		return c.compileNumber(ctx, elem)
	case lexicon.XSLTElementNamespace:
		return c.compileNamespace(ctx, elem)
	case lexicon.XSLTElementSequence:
		return c.compileSequence(ctx, elem)
	case lexicon.XSLTElementDocument:
		return c.compileDocument(ctx, elem)
	default:
		return c.compileUnknownXSLTInstruction(ctx, elem)
	}
}

func (c *compiler) compileTemplateControlInstruction(ctx context.Context, elem *xdm.Element) (instruction, error) {
	switch elem.LocalName() {
	case lexicon.XSLTElementApplyTemplates:
		return c.compileApplyTemplates(ctx, elem)
	case lexicon.XSLTElementCallTemplate:
		return c.compileCallTemplate(ctx, elem)
	case lexicon.XSLTElementIf:
		return c.compileIf(ctx, elem)
	case lexicon.XSLTElementChoose:
		return c.compileChoose(ctx, elem)
	case lexicon.XSLTElementForEach:
		return c.compileForEach(ctx, elem)
	case lexicon.XSLTElementVariable:
		return c.compileLocalVariable(ctx, elem)
	case lexicon.XSLTElementParam:
		// XTSE0010: xsl:param is only allowed at the top of xsl:template,
		// xsl:function, or xsl:iterate. If we reach here, it means
		// xsl:param appears in a general sequence constructor context.
		return nil, staticError(errCodeXTSE0010,
			"xsl:param is not allowed in this position; it must appear at the start of xsl:template, xsl:function, or xsl:iterate")
	case lexicon.XSLTElementPerformSort:
		return c.compilePerformSort(ctx, elem)
	case lexicon.XSLTElementNextMatch:
		return c.compileNextMatch(ctx, elem)
	case lexicon.XSLTElementApplyImports:
		return c.compileApplyImports(ctx, elem)
	default:
		return c.compileUnknownXSLTInstruction(ctx, elem)
	}
}

func (c *compiler) compileStreamingInstruction(ctx context.Context, elem *xdm.Element) (instruction, error) {
	switch elem.LocalName() {
	case lexicon.XSLTElementSourceDocument:
		return c.compileSourceDocument(ctx, elem)
	case lexicon.XSLTElementIterate:
		return c.compileIterate(ctx, elem)
	case lexicon.XSLTElementFork:
		return c.compileFork(ctx, elem)
	case lexicon.XSLTElementBreak:
		return c.compileBreak(ctx, elem)
	case lexicon.XSLTElementNextIteration:
		return c.compileNextIteration(ctx, elem)
	case lexicon.XSLTElementMerge:
		return c.compileMerge(ctx, elem)
	default:
		return c.compileUnknownXSLTInstruction(ctx, elem)
	}
}

func (c *compiler) compileUnknownXSLTInstruction(ctx context.Context, elem *xdm.Element) (instruction, error) {
	// Forwards-compatible processing (XSLT 3.0 §3.8): if the effective
	// version > 3.0, unknown instructions are allowed and
	// xsl:fallback children are used at runtime.
	if c.effectiveVersion > "3.0" {
		return c.compileForwardsCompat(ctx, elem)
	}

	return nil, staticError(errCodeXTSE0090, "unknown XSLT instruction xsl:%s", elem.LocalName())
}

func (c *compiler) compileResultDocument(ctx context.Context, elem *xdm.Element) (instruction, error) {
	inst := &resultDocumentInst{}

	if href := getAttr(elem, nameHref); href != "" {
		avt, err := c.compileAVT(href, c.nsBindings)
		if err != nil {
			return nil, err
		}

		inst.Href = avt
	}

	if err := validateResultDocumentOutputAttrs(elem); err != nil {
		return nil, err
	}

	if fmtAttr := getAttr(elem, "format"); fmtAttr != "" {
		if strings.ContainsAny(fmtAttr, "{}") {
			avt, err := c.compileAVT(fmtAttr, c.nsBindings)
			if err != nil {
				return nil, err
			}

			inst.FormatAVT = avt
		} else {
			inst.Format = resolveQName(fmtAttr, c.nsBindings)
		}
	}

	inst.Method = getAttr(elem, paramMethod)
	if is := getAttr(elem, paramItemSeparator); is != "" {
		inst.ItemSeparatorSet = true
		// item-separator="#absent" means explicitly absent (use default, blocks format inheritance)
		if is != "#absent" {
			avt, err := c.compileAVT(is, c.nsBindings)
			if err != nil {
				return nil, err
			}

			inst.ItemSeparator = avt
		}
	}

	if v := getAttr(elem, nameValidation); v != "" {
		if err := validateValidationAttr("xsl:result-document", v); err != nil {
			return nil, err
		}

		inst.Validation = v
	}

	if typeAttr := getAttr(elem, nameType); typeAttr != "" {
		inst.TypeName = resolveXSDTypeName(typeAttr, c.nsBindings)
	}

	if ucm := getAttr(elem, paramUseCharacterMaps); ucm != "" {
		for n := range strings.FieldsSeq(ucm) {
			inst.UseCharacterMaps = append(inst.UseCharacterMaps, resolveQName(n, c.nsBindings))
		}
	}

	if err := c.compileResultDocumentOutputAVTs(elem, inst); err != nil {
		return nil, err
	}

	if err := c.compileResultDocumentParameters(ctx, elem, inst); err != nil {
		return nil, err
	}

	if si := getAttr(elem, paramSuppressIndentation); si != "" {
		names := strings.Fields(si)

		resolved := make([]string, len(names))
		for i, n := range names {
			resolved[i] = resolveQName(n, c.nsBindings)
		}

		inst.SuppressIndentation = resolved
	}

	body, err := c.compileChildren(ctx, elem)
	if err != nil {
		return nil, err
	}

	inst.Body = body
	inst.NSBindings = c.nsBindings

	return inst, nil
}

// validateValidationAttr checks that the validation attribute value is one of
// the four legal values. Returns XTSE0020 for invalid values.
func validateValidationAttr(elemName, validation string) error {
	switch validation {
	case validationStrict, validationLax, validationPreserve, validationStrip:
		return nil
	default:
		return staticError(errCodeXTSE0020, "invalid value %q for %s/@validation: must be strict, lax, preserve, or strip", validation, elemName)
	}
}

func validateResultDocumentOutputAttrs(elem *xdm.Element) error {
	// Validate html-version: must be a decimal number if present and not an avt
	if hv := getAttr(elem, paramHTMLVersion); hv != "" {
		if !strings.ContainsAny(hv, "{}") {
			if _, err := strconv.ParseFloat(hv, 64); err != nil {
				return staticError(errCodeXTSE0020, "%q is not a valid value for xsl:result-document/@html-version", hv)
			}
		}
	}
	// Validate boolean output attributes on xsl:result-document.
	for _, boolAttr := range []string{
		paramAllowDuplicateNames, paramBuildTree, paramByteOrderMark, paramEscapeURIAttributes,
		paramIncludeContentType, paramIndent, paramOmitXMLDeclaration, paramUndeclarePrefixes,
	} {
		if v := getAttr(elem, boolAttr); v != "" {
			if !strings.ContainsAny(v, "{}") {
				if _, ok := parseXSDBool(v); !ok {
					return staticError(errCodeSEPM0016, "%q is not a valid value for xsl:result-document/@%s", v, boolAttr)
				}
			}
		}
	}
	// Validate standalone on xsl:result-document.
	if v := getAttr(elem, paramStandalone); v != "" {
		if !strings.ContainsAny(v, "{}") {
			sv := strings.TrimSpace(v)
			switch sv {
			case lexicon.ValueYes, lexicon.ValueNo, lexicon.ValueOmit, nameTrue, lexicon.ValueFalse, "1", "0":
				// valid
			default:
				return staticError(errCodeSEPM0016, "%q is not a valid value for xsl:result-document/@standalone", v)
			}
		}
	}

	return nil
}

func (c *compiler) compileResultDocumentOutputAVTs(elem *xdm.Element, inst *resultDocumentInst) error {
	// Compile serialization parameter AVTs.
	for _, sp := range []struct {
		attr string
		dst  **avt
	}{
		{"output-version", &inst.OutputVersion},
		{paramEncoding, &inst.Encoding},
		{paramIndent, &inst.Indent},
		{paramOmitXMLDeclaration, &inst.OmitXMLDeclaration},
		{paramStandalone, &inst.Standalone},
		{paramDoctypeSystem, &inst.DoctypeSystem},
		{paramDoctypePublic, &inst.DoctypePublic},
		{paramCDATASectionElements, &inst.CDATASectionElements},
		{paramByteOrderMark, &inst.ByteOrderMark},
		{paramMediaType, &inst.MediaType},
		{paramHTMLVersion, &inst.HTMLVersion},
		{paramIncludeContentType, &inst.IncludeContentType},
		{paramAllowDuplicateNames, &inst.AllowDuplicateNames},
		{paramUndeclarePrefixes, &inst.UndeclarePrefixes},
		{paramEscapeURIAttributes, &inst.EscapeURIAttributes},
		{paramJSONNodeOutputMethod, &inst.JSONNodeOutputMethodAVT},
		{paramNormalizationForm, &inst.NormalizationForm},
		{paramBuildTree, &inst.BuildTree},
	} {
		if v := getAttr(elem, sp.attr); v != "" {
			avt, err := c.compileAVT(v, c.nsBindings)
			if err != nil {
				return err
			}

			*sp.dst = avt
		}
	}
	// method attribute as avt (complements the static Method field)
	if v := getAttr(elem, paramMethod); v != "" {
		avt, err := c.compileAVT(v, c.nsBindings)
		if err != nil {
			return err
		}

		inst.MethodAVT = avt
	}

	return nil
}

func (c *compiler) compileResultDocumentParameters(ctx context.Context, elem *xdm.Element, inst *resultDocumentInst) error {
	if pd := getAttr(elem, paramParameterDocument); pd != "" {
		if strings.ContainsAny(pd, "{}") {
			avt, err := c.compileAVT(pd, c.nsBindings)
			if err != nil {
				return err
			}

			inst.ParameterDocAVT = avt
		} else {
			// Static parameter-document: load at compile time
			outDef := &OutputDef{}
			baseURI := stylesheetBaseURI(elem, c.baseURI, c.moduleRoot)

			_, presence, err := c.loadParameterDocument(ctx, outDef, baseURI, pd, false)
			if err != nil {
				return err
			}

			inst.ParameterDocOutputDef = outDef
			inst.ParameterDocPresence = presence
			// If the parameter-document sets the method, use it as the
			// compile-time method so isItemOutputMethod works.
			if outDef.Method != "" && inst.Method == "" {
				inst.Method = outDef.Method
			}
		}
	}

	return nil
}

// compileForwardsCompat compiles an unknown XSLT instruction under
// forwards-compatible processing rules (XSLT 3.0 §3.8).
// It collects xsl:fallback children as the body. At runtime, if the body
// is empty, XTDE1450 is raised.
func (c *compiler) compileForwardsCompat(ctx context.Context, elem *xdm.Element) (*fallbackInst, error) {
	inst := &fallbackInst{
		Name: "xsl:" + elem.LocalName(),
	}
	for child := range xdm.Children(elem) {
		childElem, ok := child.(*xdm.Element)
		if !ok {
			continue
		}

		if childElem.URI() == lexicon.NamespaceXSLT && childElem.LocalName() == lexicon.XSLTElementFallback {
			inst.HasFallback = true

			body, err := c.compileChildren(ctx, childElem)
			if err != nil {
				return nil, err
			}

			inst.Body = append(inst.Body, body...)
		}
	}

	return inst, nil
}

func (c *compiler) compileChildren(ctx context.Context, parent *xdm.Element) ([]instruction, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	// The parent's own version governs its content (§3.10). For an instruction
	// compiled via compileInstruction this is already in effect (redundant, same
	// value); for a structural child compiled directly by its parent loop
	// (xsl:otherwise, xsl:matching-substring, xsl:merge-action, xsl:fallback, …)
	// this is where its version takes effect, so a local version < 2.0 makes its
	// body backwards-compatible.
	defer c.pushElementVersion(parent)()

	state := &sequenceConstructorState{}

	for child := parent.FirstChild(); child != nil; child = child.NextSibling() {
		switch value := child.(type) {
		case *xdm.Element:
			inst, err := c.compileInstruction(ctx, value)
			if err != nil {
				return nil, err
			}

			if inst != nil {
				if err := state.add(inst); err != nil {
					return nil, err
				}
			}
		case *xdm.Text, *xdm.CDATASection:
			text, last := collectAdjacentStylesheetText(child)
			child = last

			if c.shouldStripText(ctx, text) {
				continue
			}

			if err := state.checkPosition(); err != nil {
				return nil, err
			}

			inst, err := c.compileLiteralText(text)
			if err != nil {
				return nil, err
			}

			state.body = append(state.body, inst)
		}
	}

	return state.body, nil
}

// collectAdjacentStylesheetText merges text/CDATA across comments and PIs,
// returning the final consumed text node for the caller's sibling traversal.
func collectAdjacentStylesheetText(first xdm.Node) (string, xdm.Node) {
	var buf strings.Builder
	buf.WriteString(xdm.CharacterData(first))
	last := first

	for next := first.NextSibling(); next != nil; next = next.NextSibling() {
		switch next.Type() {
		case xdm.CommentNode, xdm.ProcessingInstructionNode:
			continue
		case xdm.TextNode, xdm.CDATASectionNode:
			buf.WriteString(xdm.CharacterData(next))
			last = next
		default:
			return buf.String(), last
		}
	}

	return buf.String(), last
}

func (c *compiler) compileLiteralText(text string) (*literalTextInst, error) {
	inst := &literalTextInst{Value: text}
	if c.expandText && strings.ContainsAny(text, "{}") {
		avt, err := c.compileAVT(text, c.nsBindings)
		if err != nil {
			return nil, err
		}

		inst.TVT = avt
	}

	return inst, nil
}

func (c *compiler) compileLocalVariable(ctx context.Context, elem *xdm.Element) (*variableInst, error) {
	name := getAttr(elem, xslAttrName)
	if name == "" {
		return nil, staticError(errCodeXTSE0110, "xsl:variable requires name attribute")
	}

	asAttr := c.resolveAsType(ctx, getAttr(elem, "as"))
	if err := c.validateAsSequenceType(ctx, asAttr, "xsl:variable "+name); err != nil {
		return nil, err
	}

	inst := &variableInst{
		Name: resolveQName(name, c.nsBindings),
		As:   asAttr,
	}

	// Capture xml:base for static base URI override during body/select evaluation.
	effectiveBase := stylesheetBaseURI(elem, c.baseURI, c.moduleRoot)
	if effectiveBase != c.baseURI {
		inst.StaticBaseURI = effectiveBase
	}

	selectAttr := getAttr(elem, xslAttrSelect)
	if selectAttr != "" {
		// XTSE0620: select and non-empty content are mutually exclusive.
		if err := c.validateEmptyElement(ctx, elem, "xsl:variable"); err != nil {
			return nil, staticError(errCodeXTSE0620, "xsl:variable %q has both @select and content", name)
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

func (c *compiler) compileMessage(ctx context.Context, elem *xdm.Element) (*messageInst, error) {
	inst := &messageInst{}

	selectAttr := getAttr(elem, xslAttrSelect)
	if selectAttr != "" {
		expr, err := c.compileXPath(selectAttr, c.nsBindings)
		if err != nil {
			return nil, err
		}

		inst.Select = expr
	}
	// XSLT 3.0: both select and body content are allowed
	body, err := c.compileChildren(ctx, elem)
	if err != nil {
		return nil, err
	}

	inst.Body = body

	termAttr := getAttr(elem, "terminate")
	if termAttr != "" {
		avt, err := c.compileAVT(termAttr, c.nsBindings)
		if err != nil {
			return nil, err
		}
		// If the avt is a static value, validate it is "yes" or "no"
		if sv, ok := avt.staticValue(); ok {
			if sv != lexicon.ValueYes && sv != lexicon.ValueNo {
				return nil, staticError(errCodeXTSE0020, "%q is not a valid value for xsl:message/@terminate", sv)
			}
		}

		inst.Terminate = avt
	}

	errorCodeAttr := getAttr(elem, "error-code")
	if errorCodeAttr != "" {
		avt, err := c.compileAVT(errorCodeAttr, c.nsBindings)
		if err != nil {
			return nil, err
		}

		inst.ErrorCode = avt
	}

	return inst, nil
}

func (c *compiler) compileMap(ctx context.Context, elem *xdm.Element) (*mapInst, error) {
	body, err := c.compileChildren(ctx, elem)
	if err != nil {
		return nil, err
	}

	return &mapInst{Body: body}, nil
}

func (c *compiler) compileMapEntry(ctx context.Context, elem *xdm.Element) (*mapEntryInst, error) {
	inst := &mapEntryInst{}

	keyAttr := getAttr(elem, nameKey2)
	if keyAttr != "" {
		expr, err := c.compileXPath(keyAttr, c.nsBindings)
		if err != nil {
			return nil, err
		}

		inst.Key = expr
	} else {
		return nil, staticError(errCodeXTSE0010, "xsl:map-entry requires key attribute")
	}

	selectAttr := getAttr(elem, xslAttrSelect)

	hasBody := hasSignificantChildren(elem)
	if selectAttr != "" && hasBody {
		return nil, staticError(errCodeXTSE3280, "xsl:map-entry must not have both a select attribute and a sequence constructor body")
	}

	if selectAttr != "" {
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

// compileAssert compiles xsl:assert.
// Required attribute: test.
// Optional attributes: select, error-code.
// The body provides the error message if no select attribute is present.
func (c *compiler) compileAssert(ctx context.Context, elem *xdm.Element) (instruction, error) {
	testAttr := getAttr(elem, nameTest2)
	if testAttr == "" {
		return nil, staticError(errCodeXTSE0010, "xsl:assert requires a test attribute")
	}

	testExpr, err := c.compileXPath(testAttr, c.nsBindings)
	if err != nil {
		return nil, err
	}

	inst := &assertInst{
		Test:      testExpr,
		ErrorCode: errCodeXTMM9001, // default error code per XSLT 3.0 spec
	}

	// xpath-default-namespace
	if xdn := getAttr(elem, nameXpathDefaultNamespace); xdn != "" {
		inst.XPathDefaultNS = xdn
		inst.HasXPathDefaultNS = true
	}

	// error-code attribute
	if ec := getAttr(elem, "error-code"); ec != "" {
		inst.ErrorCode = resolveQName(ec, c.nsBindings)
	}

	// select attribute
	if sel := getAttr(elem, xslAttrSelect); sel != "" {
		selExpr, err := c.compileXPath(sel, c.nsBindings)
		if err != nil {
			return nil, err
		}

		inst.Select = selExpr
	}

	// Compile body (error message content)
	body, err := c.compileChildren(ctx, elem)
	if err != nil {
		return nil, err
	}

	inst.Body = body

	return inst, nil
}

// checkValidationTypeExclusive verifies that validation and type are not both
// specified on the same instruction. Returns XTSE0220 if both are present.
func checkValidationTypeExclusive(elemName, validation, typeName string) error {
	if validation != "" && typeName != "" {
		return staticError(errCodeXTSE0220, "%s: validation and type attributes are mutually exclusive", elemName)
	}

	return nil
}

type sequenceConstructorState struct {
	body          []instruction
	sawTerminator bool
	sawOnEmpty    bool
}

func (state *sequenceConstructorState) checkPosition() error {
	if state.sawTerminator {
		return staticError(errCodeXTSE3120, "no instruction may follow xsl:break or xsl:next-iteration")
	}

	if state.sawOnEmpty {
		return staticError(errCodeXTSE0010, "xsl:on-empty must be the last instruction in a sequence constructor")
	}

	return nil
}

func (state *sequenceConstructorState) add(inst instruction) error {
	if err := state.checkPosition(); err != nil {
		return err
	}

	state.body = append(state.body, inst)
	switch inst.(type) {
	case *breakInst, *nextIterationInst:
		state.sawTerminator = true
	case *onEmptyInst:
		state.sawOnEmpty = true
	}

	return nil
}
