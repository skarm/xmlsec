// Derived from lestrrat-go/helium at 7362c0a70122a757780f4d0b545a9b370dead6ab.
// Copyright (c) 2015 lestrrat. MIT License; see licenses/MIT-helium.txt at the repository root.

package xslt

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"maps"
	"slices"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/skarm/xmlsec/internal/lexicon"
	"github.com/skarm/xmlsec/internal/xmlchar"
	"github.com/skarm/xmlsec/transform/internal/xdm"
	uripath "github.com/skarm/xmlsec/transform/internal/xdm/uri"
	"github.com/skarm/xmlsec/transform/internal/xpath"
)

type characterMapDeclaration struct {
	precedence int
	conflict   bool
}

type characterMapDependencies struct {
	name string
	uses []string
}

func (c *compiler) compileCharacterMap(ctx context.Context, elem *xdm.Element) error {
	if err := c.validateXSLTAttrs(ctx, elem, attributeNames(xslAttrName, lexicon.SerializationUseCharacterMaps, xslAttrUseWhen)); err != nil {
		return err
	}

	saved := c.pushElementNamespaces(ctx, elem)
	defer func() { c.nsBindings = saved }()

	name := getAttr(elem, xslAttrName)
	if name == "" {
		return staticError(errCodeXTSE0010, "xsl:character-map requires name attribute")
	}

	name = resolveQName(name, c.nsBindings)

	cm := &characterMapDef{
		Name:     name,
		Mappings: make(map[rune]string),
	}

	if ucm := getAttr(elem, lexicon.SerializationUseCharacterMaps); ucm != "" {
		for n := range strings.FieldsSeq(ucm) {
			cm.UseCharacterMaps = append(cm.UseCharacterMaps, resolveQName(n, c.nsBindings))
		}
	}

	for child := range xdm.Children(elem) {
		childElem, ok := child.(*xdm.Element)
		if !ok {
			if err := validateStructuralText(child, elem); err != nil {
				return err
			}

			continue
		}

		if childElem.URI() != lexicon.NamespaceXSLT || childElem.LocalName() != lexicon.XSLTElementOutputCharacter {
			return staticError(errCodeXTSE0010, "unexpected child element in xsl:character-map: %s", childElem.Name())
		}

		charAttr, hasCharacter := childElem.GetAttribute(nameCharacter)
		if !hasCharacter {
			return staticError(errCodeXTSE0010,
				"xsl:output-character requires 'character' attribute")
		}

		if utf8.RuneCountInString(charAttr) != 1 {
			return staticError(errCodeXTSE0020, "xsl:output-character/@character must contain exactly one Unicode character")
		}

		r := firstRune(charAttr)

		str, hasString := childElem.GetAttribute(nameOutputCharacterString)
		if !hasString {
			return staticError(errCodeXTSE0010,
				"xsl:output-character requires 'string' attribute")
		}

		cm.Mappings[r] = str
	}

	if c.stylesheet.characterMaps == nil {
		c.stylesheet.characterMaps = make(map[string]*characterMapDef)
	}

	if c.characterMapDeclarations == nil {
		c.characterMapDeclarations = make(map[string]characterMapDeclaration)
	}

	// The highest-precedence declaration supplies the entire map. A later
	// higher-precedence declaration also resolves any conflict at this level.
	previous, found := c.characterMapDeclarations[name]
	discarded := cm

	if !found || c.importPrec > previous.precedence {
		discarded = c.stylesheet.characterMaps[name]
		c.stylesheet.characterMaps[name] = cm
		c.characterMapDeclarations[name] = characterMapDeclaration{precedence: c.importPrec}
	} else if c.importPrec == previous.precedence {
		previous.conflict = true
		c.characterMapDeclarations[name] = previous
	}

	// Even a shadowed declaration may not refer to an undefined map.
	if discarded != nil && len(discarded.UseCharacterMaps) != 0 {
		c.shadowedCharacterMaps = append(c.shadowedCharacterMaps, characterMapDependencies{
			name: discarded.Name, uses: discarded.UseCharacterMaps,
		})
	}

	return nil
}

func (c *compiler) compileKey(ctx context.Context, elem *xdm.Element) error {
	defer c.pushElementVersion(elem)()

	if err := c.validateXSLTAttrs(ctx, elem, attributeNames(xslAttrName, lexicon.AttrMatch, lexicon.AttrUse, nameCollation, nameComposite, xslAttrUseWhen, nameDefaultCollation)); err != nil {
		return err
	}

	c.collectNamespaces(ctx, elem)

	// Handle per-element default-collation override (standard attribute)
	savedDefaultCollation := c.defaultCollation

	if err := c.setInstructionDefaultCollation(elem); err != nil {
		return err
	}

	defer func() { c.defaultCollation = savedDefaultCollation }()

	name := getAttr(elem, xslAttrName)
	if c.stylesheet.processorLanguage() >= processorXSLT20 {
		name = strings.Trim(name, lexicon.XMLWhitespace)
	}

	if name == "" {
		return staticError(errCodeXTSE0010, "xsl:key requires name attribute")
	}

	if !xmlchar.IsValidQName(name) && !isValidEQName(name) {
		return staticError(errCodeXTSE0020, "invalid name %q on xsl:key", name)
	}

	matchAttr, hasMatch := elem.GetAttribute(lexicon.AttrMatch)
	if !hasMatch {
		return staticError(errCodeXTSE0010, "xsl:key requires match attribute")
	}

	// Apply a local xpath-default-namespace on the xsl:key element (presence,
	// even an empty value, overrides the inherited default) so the @match
	// pattern's unprefixed names resolve consistently with NameTest semantics.
	xpathDefaultNS := c.xpathDefaultNS
	hasXPathDefaultNS := c.hasXPathDefaultNS

	savedDefaultNS, savedHasDefaultNS := c.xpathDefaultNS, c.hasXPathDefaultNS
	defer func() { c.xpathDefaultNS, c.hasXPathDefaultNS = savedDefaultNS, savedHasDefaultNS }()

	if xdn, ok := elem.GetAttribute(nameXPathDefaultNamespace); ok {
		xpathDefaultNS = xdn
		hasXPathDefaultNS = true
		c.xpathDefaultNS, c.hasXPathDefaultNS = xdn, true
	}

	matchPat, err := c.compilePattern(matchAttr, elem, xpathDefaultNS, hasXPathDefaultNS)
	if err != nil {
		return err
	}

	expandedName := resolveQName(name, c.nsBindings)
	composite, _ := parseXSDBool(getAttr(elem, nameComposite))

	// XTSE1222: if there is already a key with the same name, the composite
	// attribute must agree
	if existingDefs, ok := c.stylesheet.keys[expandedName]; ok && len(existingDefs) > 0 {
		if existingDefs[0].Composite != composite {
			return staticError(errCodeXTSE1222,
				"xsl:key declarations with name %q have conflicting composite attributes", expandedName)
		}
	}

	// Resolve collation: explicit attribute takes precedence over default-collation.
	baseURI := stylesheetBaseURI(elem, c.baseURI, c.moduleRoot)
	collationURI := ""

	if collAttr := getAttr(elem, nameCollation); collAttr != "" {
		collationURI = resolveAgainstBaseURI(collAttr, baseURI)
		// XTSE1210: collation must be a recognized URI
		if !xpath.IsCollationSupported(collationURI) {
			return staticError(errCodeXTSE1210, "unrecognized collation URI %q on xsl:key", collAttr)
		}
	} else if c.defaultCollation != "" {
		collationURI = c.defaultCollation
	}

	// XTSE1220: if there is already a key with the same name, the collation
	// must agree across all declarations
	if existingDefs, ok := c.stylesheet.keys[expandedName]; ok && len(existingDefs) > 0 {
		if existingDefs[0].Collation != collationURI {
			return staticError(errCodeXTSE1220,
				"xsl:key declarations with name %q have conflicting collation attributes", expandedName)
		}
	}

	kd := &keyDef{
		StaticBaseURI: baseURI,
		Name:          expandedName,
		Match:         matchPat,
		Composite:     composite,
		Collation:     collationURI,
		Compat:        c.backwardsCompatible(),
	}

	if err := c.compileKeyValue(ctx, elem, kd); err != nil {
		return err
	}

	c.stylesheet.keys[expandedName] = append(c.stylesheet.keys[expandedName], kd)

	return nil
}

func (c *compiler) compileKeyValue(ctx context.Context, elem *xdm.Element, kd *keyDef) error {
	useAttr, hasUse := elem.GetAttribute(lexicon.AttrUse)
	hasContent := c.hasEffectiveContent(ctx, elem)
	// XTSE1205: must have either use attr or content, not both, and not neither
	if hasUse && hasContent {
		return staticError(errCodeXTSE1205, "xsl:key must not have both a use attribute and content")
	}

	if !hasUse && !hasContent {
		return staticError(errCodeXTSE1205, "xsl:key must have either a use attribute or content")
	}

	if hasUse {
		useExpr, err := c.compileXPath(useAttr, c.nsBindings)
		if err != nil {
			return err
		}

		if c.stylesheet.processorLanguage() == processorXSLT10 {
			if err := validateLegacyKeyUse(useExpr, c.nsBindings); err != nil {
				return err
			}
		}

		kd.Use = useExpr
	} else {
		// XSLT 2.0+: key may use body content instead of use attribute.
		body, _, err := c.compileTemplateBody(ctx, elem)
		if err != nil {
			return err
		}

		kd.Body = body
	}

	return nil
}

const itemSeparatorAbsentToken = "#absent"

func (c *compiler) compileOutput(ctx context.Context, elem *xdm.Element) error {
	if err := c.validateXSLTAttrs(ctx, elem, attributeNames(xslAttrName, lexicon.SerializationMethod, lexicon.SerializationVersion, lexicon.SerializationEncoding, lexicon.SerializationOmitXMLDeclaration, lexicon.SerializationStandalone, lexicon.SerializationDoctypePublic, lexicon.SerializationDoctypeSystem, lexicon.SerializationCDATASectionElements, lexicon.SerializationIndent, lexicon.SerializationMediaType, lexicon.SerializationByteOrderMark, lexicon.SerializationEscapeURIAttributes, lexicon.SerializationIncludeContentType, lexicon.SerializationNormalizationForm, lexicon.SerializationUndeclarePrefixes, lexicon.SerializationUseCharacterMaps, lexicon.SerializationSuppressIndentation, lexicon.SerializationHTMLVersion, lexicon.SerializationItemSeparator, lexicon.SerializationJSONNodeOutputMethod, lexicon.SerializationParameterDocument, lexicon.SerializationBuildTree, lexicon.SerializationAllowDuplicateNames, xslAttrUseWhen)); err != nil {
		return err
	}

	saved := c.pushElementNamespaces(ctx, elem)
	defer func() { c.nsBindings = saved }()

	name := strings.TrimFunc(getAttr(elem, xslAttrName), xmlchar.IsSpace)
	if name != "" {
		namespaces := inScopeNamespaces(elem)
		if prefix, _, qualified := strings.Cut(name, ":"); qualified && !strings.HasPrefix(name, lexicon.EQNamePrefix) && namespaces[prefix] == "" {
			return staticError(errCodeXTSE0280, "undeclared namespace prefix %q in xsl:output/@name %q", prefix, name)
		}

		name = resolveQName(name, namespaces)
	}

	methodStr := strings.TrimSpace(strings.ToLower(getAttr(elem, lexicon.SerializationMethod)))
	if err := validateOutputMethod(methodStr); err != nil {
		return err
	}

	outDef := &OutputDef{
		serializationVersion: c.stylesheet.processorLanguage(),
		Name:                 name,
		Method:               methodStr,
		MethodExplicit:       methodStr != "",
		Encoding:             getAttr(elem, lexicon.SerializationEncoding),
		Version:              getAttr(elem, lexicon.SerializationVersion),
		ImportPrec:           c.importPrec,
		MethodRaw:            getAttr(elem, lexicon.SerializationMethod),
		EncodingRaw:          getAttr(elem, lexicon.SerializationEncoding),
		VersionRaw:           getAttr(elem, lexicon.SerializationVersion),
	}

	if outDef.Method == "" {
		outDef.Method = lexicon.MethodXML
	}

	if outDef.Encoding == "" {
		outDef.Encoding = lexicon.EncodingUTF8U
	}

	// Determine the accepted lexical space for boolean serialization parameters.
	// XSLT 2.0 (and 1.0) restrict them to yes/no; XSLT 3.0+ accepts the full
	// xs:boolean lexical space. The selected processor governs these rules;
	// XSLT 3.0 defines no differing behavior for a 2.0 declaration.
	yesNoOnly := c.stylesheet.processorLanguage() < processorXSLT30

	if err := compileOutputBooleans(elem, outDef, yesNoOnly); err != nil {
		return err
	}

	if err := c.compileOutputSerialization(elem, outDef, yesNoOnly); err != nil {
		return err
	}

	if err := c.compileOutputSequenceParameters(elem, outDef, yesNoOnly); err != nil {
		return err
	}

	if href, present := elem.GetAttribute(lexicon.SerializationParameterDocument); present {
		outDef.ParameterDocument = parameterDocumentURI(stylesheetBaseURI(elem, c.baseURI, c.moduleRoot), href)
	}

	return c.mergeOutputDeclaration(ctx, elem, outDef)
}

func (c *compiler) compileOutputSerialization(elem *xdm.Element, out *OutputDef, yesNoOnly bool) error {
	standalone := getAttr(elem, lexicon.SerializationStandalone)

	var err error

	out.Standalone, err = outputStandalone(standalone, yesNoOnly)
	if err != nil {
		return err
	}

	out.StandaloneRaw = standalone
	out.DoctypePublic = getAttr(elem, lexicon.SerializationDoctypePublic)
	out.DoctypeSystem = getAttr(elem, lexicon.SerializationDoctypeSystem)
	out.MediaType = getAttr(elem, lexicon.SerializationMediaType)

	if version := getAttr(elem, lexicon.SerializationHTMLVersion); version != "" {
		version = strings.TrimSpace(version)
		if _, err := strconv.ParseFloat(version, float64ParseBits); err != nil {
			return staticError(errCodeXTSE0020, "%q is not a valid value for xsl:output/@html-version", version)
		}

		out.HTMLVersion = version
	}

	out.CDATASections = resolveOutputNames(getAttr(elem, lexicon.SerializationCDATASectionElements), c.nsBindings)
	if separator, present := elem.GetAttribute(lexicon.SerializationItemSeparator); present {
		if separator == itemSeparatorAbsentToken {
			out.ItemSeparatorAbsent = true
		} else {
			out.ItemSeparator = &separator
		}
	}

	if form := getAttr(elem, lexicon.SerializationNormalizationForm); form != "" {
		out.NormalizationForm = strings.ToUpper(strings.TrimSpace(form))
	}

	if attr := getAttr(elem, lexicon.SerializationUseCharacterMaps); attr != "" {
		for name := range strings.FieldsSeq(attr) {
			out.UseCharacterMaps = append(out.UseCharacterMaps, resolveQName(name, c.nsBindings))
		}
	}

	if method := getAttr(elem, lexicon.SerializationJSONNodeOutputMethod); method != "" {
		out.JSONNodeOutputMethod = strings.TrimSpace(method)
	}

	return nil
}

func (c *compiler) compileOutputSequenceParameters(elem *xdm.Element, out *OutputDef, yesNoOnly bool) error {
	value, explicit, err := outputBoolAttr(elem, lexicon.SerializationAllowDuplicateNames, yesNoOnly)
	if err != nil {
		return err
	}

	if explicit {
		out.AllowDuplicateNames = value
	}

	out.SuppressIndentation = resolveOutputNames(getAttr(elem, lexicon.SerializationSuppressIndentation), c.nsBindings)

	buildTree, present, err := outputBoolAttr(elem, lexicon.SerializationBuildTree, yesNoOnly)
	if err != nil {
		return err
	}

	if present {
		out.BuildTree = &buildTree
	}

	return nil
}

// loadParameterDocument applies the effective external parameter values after
// direct output declarations have been merged (XSLT3.0 §26). Scalars override;
// cdata-section-elements and suppress-indentation are unions.
func (c *compiler) loadParameterDocument(ctx context.Context, outDef *OutputDef, baseURI, href string, adnExplicit bool) (bool, paramDocPresence, error) {
	// Compile-time loading is opt-in: a URIResolver must be configured via
	// Compiler.URIResolver. There is no implicit filesystem access.
	openResource := func(ctx context.Context, uri string) (io.ReadCloser, error) {
		if c.resolver == nil {
			return nil, staticError(errCodeXTSE0090, "cannot read parameter-document %q: no URIResolver configured", href)
		}

		return c.resolver.Resolve(ctx, uri)
	}

	return loadParameterDocumentFromFile(ctx, c.parseOptions, outDef, baseURI, href, openResource, false, adnExplicit, c.maxResourceBytes)
}

func (c *compiler) compileAttributeSet(ctx context.Context, elem *xdm.Element) error {
	defer c.pushElementVersion(elem)()

	if err := c.validateXSLTAttrs(ctx, elem, attributeNames(xslAttrName, nameUseAttributeSets, xslAttrVisibility, nameStreamable, xslAttrUseWhen)); err != nil {
		return err
	}

	name := getAttr(elem, xslAttrName)
	if c.stylesheet.processorLanguage() >= processorXSLT20 {
		name = strings.Trim(name, lexicon.XMLWhitespace)
	}

	if name == "" {
		return staticError(errCodeXTSE0010, "xsl:attribute-set requires name attribute")
	}

	if !xmlchar.IsValidQName(name) && !isValidEQName(name) {
		return staticError(errCodeXTSE0020, "invalid name %q on xsl:attribute-set", name)
	}

	if err := c.checkQNamePrefix(ctx, name, "xsl:attribute-set"); err != nil {
		return err
	}

	name = resolveQName(name, c.nsBindings)

	streamable := false

	if s := getAttr(elem, nameStreamable); s != "" {
		v, ok := parseXSDBool(s)
		if !ok {
			return staticError(errCodeXTSE0020, "invalid value %q for streamable attribute on xsl:attribute-set", s)
		}

		streamable = v
	}

	asd := &attributeSetDef{
		Name:       name,
		Visibility: getAttr(elem, xslAttrVisibility),
		Streamable: streamable,
	}

	if c.stylesheet.isPackage {
		asd.OwnerPackage = c.stylesheet
	}

	if uas := getAttr(elem, nameUseAttributeSets); uas != "" {
		for n := range strings.FieldsSeq(uas) {
			asd.UseAttrSets = append(asd.UseAttrSets, resolveQName(n, c.nsBindings))
		}
	}

	for child := range xdm.Children(elem) {
		childElem, ok := child.(*xdm.Element)
		if !ok {
			// XTSE0010: text content not allowed in xsl:attribute-set
			if isStylesheetTextNode(child) {
				return staticError(errCodeXTSE0010, "text is not allowed as a child of xsl:attribute-set")
			}

			continue
		}

		if childElem.URI() != lexicon.NamespaceXSLT || childElem.LocalName() != lexicon.XSLTElementAttribute {
			return staticError(errCodeXTSE0010, "only xsl:attribute is allowed as a child of xsl:attribute-set")
		}

		inst, err := c.compileAttribute(ctx, childElem)
		if err != nil {
			return err
		}

		asd.Attrs = append(asd.Attrs, inst)
	}

	if c.stylesheet.attributeSets == nil {
		c.stylesheet.attributeSets = make(map[string]*attributeSetDef)
	}

	effectiveBase := stylesheetBaseURI(elem, c.baseURI, c.moduleRoot)
	part := attributeSetPart{
		UseAttrSets:   asd.UseAttrSets,
		Attrs:         asd.Attrs,
		StaticBaseURI: effectiveBase,
	}
	// Same-named local declarations merge; an accepted component conflicts.
	if existing := c.stylesheet.attributeSets[name]; existing != nil {
		if existing.OwnerPackage != nil && existing.OwnerPackage != c.stylesheet {
			return staticError(errCodeXTSE3050, "local attribute-set %q conflicts with an accepted component", name)
		}

		existing.Attrs = append(existing.Attrs, asd.Attrs...)
		existing.UseAttrSets = append(existing.UseAttrSets, asd.UseAttrSets...)
		existing.Parts = append(existing.Parts, part)
	} else {
		asd.Parts = []attributeSetPart{part}
		c.stylesheet.attributeSets[name] = asd
	}

	return nil
}

func (c *compiler) compileDecimalFormat(ctx context.Context, elem *xdm.Element) error {
	if err := c.validateXSLTAttrs(ctx, elem, attributeNames(xslAttrName, nameDecimalSeparator, nameGroupingSeparator, nameInfinity, nameMinusSign, lexicon.DecimalFormatNaN, namePercent, namePerMille, nameZeroDigit, nameDigit, namePatternSeparator, nameExponentSeparator, xslAttrUseWhen)); err != nil {
		return err
	}
	// Push element-local namespace declarations so prefixed names resolve correctly
	saved := c.pushElementNamespaces(ctx, elem)
	defer func() { c.nsBindings = saved }()

	if err := validateDecimalFormatCharacters(elem); err != nil {
		return err
	}

	qn, err := c.decimalFormatName(elem)
	if err != nil {
		return err
	}

	if c.stylesheet.decimalFormats == nil {
		c.stylesheet.decimalFormats = make(map[xpath.QualifiedName]xpath.DecimalFormat)
	}

	// XTSE1295: zero-digit must be a Unicode character with digit value zero
	if v := getAttr(elem, nameZeroDigit); v != "" {
		zd := firstRune(v)
		if !unicode.IsDigit(zd) || !isDigitZero(zd) {
			return staticError(errCodeXTSE1295,
				"zero-digit %q is not a Unicode digit-zero character", string(zd))
		}
	}

	df, exists := c.stylesheet.decimalFormats[qn]

	if !exists {
		df = xpath.DefaultDecimalFormat()
		df.ExponentDisabled = c.stylesheet.processorLanguage() < processorXSLT30
	}

	if c.decimalFormatProperties == nil {
		c.decimalFormatProperties = make(map[xpath.QualifiedName]map[string]decimalFormatProperty)
	}

	properties := c.decimalFormatProperties[qn]
	if properties == nil {
		properties = make(map[string]decimalFormatProperty)
		c.decimalFormatProperties[qn] = properties
	}

	mergeDecimalFormatAttributes(&df, elem, properties, c.importPrec)
	c.stylesheet.decimalFormats[qn] = df

	return nil
}

func (c *compiler) decimalFormatName(elem *xdm.Element) (xpath.QualifiedName, error) {
	name, present := elem.GetAttribute(xslAttrName)
	if !present {
		return xpath.QualifiedName{}, nil
	}

	name = strings.TrimFunc(name, xmlchar.IsSpace)
	if !xmlchar.IsValidQName(name) && !(c.stylesheet.processorLanguage() >= processorXSLT30 && isValidEQName(name)) {
		return xpath.QualifiedName{}, staticError(errCodeXTSE0020, "invalid name %q on xsl:decimal-format", name)
	}

	qn, err := resolveIntrospectionName(name, "", errCodeXTSE0280, nsResolverFromMap(inScopeNamespaces(elem)))
	if err != nil {
		return xpath.QualifiedName{}, err
	}

	return xpath.QualifiedName{URI: qn.URI, Name: qn.Local}, nil
}

func (c *compiler) compileSpaceHandling(ctx context.Context, elem *xdm.Element, strip bool) error {
	if err := c.validateXSLTAttrs(ctx, elem, attributeNames(nameElements)); err != nil {
		return err
	}
	// XTSE0260: strip-space/preserve-space must be empty
	kind := nameStripSpace
	if !strip {
		kind = namePreserveSpace
	}

	if err := c.validateEmptyElement(ctx, elem, "xsl:"+kind); err != nil {
		return err
	}

	elements := getAttr(elem, nameElements)
	if !elem.HasAttribute(nameElements) {
		return staticError(errCodeXTSE0010, "xsl:%s requires the elements attribute", kind)
	}

	// Apply per-element xpath-default-namespace
	savedXPathDefaultNS := c.xpathDefaultNS
	if xdn, ok := elem.GetAttribute(nameXPathDefaultNamespace); ok {
		c.xpathDefaultNS = xdn
	}
	defer func() { c.xpathDefaultNS = savedXPathDefaultNS }()

	// Resolve prefixes using the namespace context in scope at this
	// declaration. Imported modules may bind the same prefix to a different
	// URI than the importing module, so resolution must use the element's own
	// in-scope bindings, and no single flat stylesheet-wide map.
	declNS := c.spaceDeclNamespaces(elem)

	for name := range strings.FieldsSeq(elements) {
		nt := nameTest{
			ImportPrec: c.importPrec,
			SpaceOrder: len(c.stylesheet.stripSpace) + len(c.stylesheet.preserveSpace),
		}

		if strings.HasPrefix(name, lexicon.EQNamePrefix) {
			if closeIdx := strings.IndexByte(name, '}'); closeIdx > 0 {
				nt.URI = name[2:closeIdx]
				nt.HasURI = true
				nt.Local = name[closeIdx+1:]
			} else {
				nt.Local = name
			}
		} else if prefix, local, ok := strings.Cut(name, ":"); ok {
			nt.Prefix = prefix
			nt.Local = local
			// "*:NCName" matches the local name in any namespace; no URI binding.
			if prefix != "*" {
				// XTSE0280: the prefix must be declared in scope here.
				uri, ok := declNS[prefix]
				if !ok {
					return staticError(errCodeXTSE0280, "undeclared namespace prefix %q in xsl:%s elements attribute", prefix, kind)
				}

				nt.URI = uri
				nt.HasURI = true
			}
		} else {
			nt.Local = name
			// Apply xpath-default-namespace for unprefixed names (not wildcards)
			if name != "*" && c.xpathDefaultNS != "" {
				nt.URI = c.xpathDefaultNS
				nt.HasURI = true
			}
		}

		if strip {
			c.stylesheet.stripSpace = append(c.stylesheet.stripSpace, nt)
		} else {
			c.stylesheet.preserveSpace = append(c.stylesheet.preserveSpace, nt)
		}
	}

	return nil
}

// spaceDeclNamespaces returns the namespace bindings in scope at an
// xsl:strip-space / xsl:preserve-space declaration. Only the element's own
// ancestor chain in the source tree (plus the implicit "xml" prefix) is
// authoritative for declaration-time resolution. Compiler-wide bindings are NOT
// consulted: they may carry prefixes from imported modules that are not in
// scope here, which would wrongly accept an undeclared prefix instead of
// raising XTSE0280.
func (c *compiler) spaceDeclNamespaces(elem *xdm.Element) map[string]string {
	bindings := map[string]string{
		// The "xml" prefix is implicitly bound in every XML document.
		lexicon.PrefixXML: lexicon.NamespaceXML,
	}
	// Walk descendant-to-ancestor; nearest declaration wins.
	for n := xdm.Node(elem); n != nil; n = n.Parent() {
		e, ok := n.(*xdm.Element)
		if !ok {
			continue
		}

		for _, ns := range e.Namespaces() {
			if _, exists := bindings[ns.Prefix()]; !exists {
				bindings[ns.Prefix()] = ns.URI()
			}
		}
	}

	return bindings
}

// checkSpaceConflicts detects NameTests that appear in both xsl:strip-space and
// xsl:preserve-space. Conflicts are resolved per-name by import precedence and
// match priority: for a given element name, the rule of highest import precedence
// (then highest match priority) decides whether it is stripped or preserved.
//
// Per the W3C XTSE0270 semantics, a STATIC conflict arises for a strip rule and a
// preserve rule that match an OVERLAPPING set of names at the SAME import
// precedence AND the SAME match priority, where neither rule outranks the other
// for the names they both match. Two cases produce such an unresolvable overlap:
//
//   - SAME resolved NameTest (same kind, same name-set): e.g. "item" vs "item",
//     or "*:item" vs "*:item". Detected via nameTestKey.
//   - DIFFERENT-shape wildcards of EQUAL priority whose match-sets intersect:
//     "*:item" (local-name wildcard) vs "Q{urn:A}*" (namespace wildcard) both
//     match Q{urn:A}item at priority -0.25, and neither is more specific than the
//     other on that name, so the strip/preserve outcome is undecidable. Detected
//     via nameTestsOverlapEqualPriority + the derived overlap region.
//
// A NameTest of HIGHER priority that intersects the other (e.g. an exact name vs
// a wildcard) is NOT a static conflict: the more specific rule wins per-name at
// RUNTIME, so those pairs are deliberately left to runtime resolution.
//
// A candidate same-precedence/priority overlap is still NOT a genuine conflict
// when a rule of STRICTLY HIGHER import precedence (of either kind) covers the
// entire overlap region: per XSLT's per-name precedence resolution, XTSE0270
// fires only at the HIGHEST precedence that matches a given name, so a
// higher-precedence rule resolves the names it matches (see spaceRegionCovered).
//
// The check must NOT be filtered by each kind's globally-highest precedence: an
// unrelated higher-precedence rule (e.g. a higher-precedence strip-space for "b")
// does not cover the name-set of an "a" vs "a" conflict, so it must not cancel
// that genuine same-precedence conflict.
func (c *compiler) checkSpaceConflicts(_ context.Context) error {
	if c.stylesheet.processorLanguage() == processorXSLT20 {
		// XSLT 2.0 §3.4 permits recovery from XTRE0270 by using the last
		// declaration. XSLT 3.0 makes the conflict a static error instead.
		return nil
	}

	if len(c.stylesheet.stripSpace) == 0 || len(c.stylesheet.preserveSpace) == 0 {
		return nil
	}
	// Scan every strip/preserve pair. A pair is a candidate conflict when its
	// rules carry equal import precedence and an unresolvable overlap (same
	// name-set, or different-shape wildcards of equal priority that intersect). It
	// is a genuine conflict only if no rule of higher import precedence covers the
	// overlap region.
	for _, sNT := range c.stylesheet.stripSpace {
		sKey := nameTestKey(sNT)
		for _, pNT := range c.stylesheet.preserveSpace {
			if sNT.ImportPrec != pNT.ImportPrec {
				continue
			}

			region, ok := spaceConflictRegion(sNT, pNT, sKey)
			if !ok {
				continue
			}

			if c.spaceRegionCovered(region, sNT.ImportPrec) {
				continue
			}

			return staticError(errCodeXTSE0270,
				"conflicting xsl:strip-space and xsl:preserve-space for %q at the same import precedence",
				nameTestKey(region))
		}
	}

	return nil
}

// spaceRegionCovered reports whether the entire overlap region of a conflicting
// strip/preserve pair (declared at import precedence prec) is matched by some
// rule of STRICTLY HIGHER import precedence — strip OR preserve, either kind.
// Such a rule resolves every name in the region per XSLT's per-name precedence
// rule, so no XTSE0270 conflict survives. Coverage of a (possibly wildcard)
// region is decided one rule at a time: a wildcard region is only ever covered by
// a single rule at least as general as it, so a union of narrower higher rules
// can never spuriously "cover" it (see ruleCoversRegion).
func (c *compiler) spaceRegionCovered(region nameTest, prec int) bool {
	for _, h := range c.stylesheet.stripSpace {
		if h.ImportPrec > prec && ruleCoversRegion(h, region) {
			return true
		}
	}

	for _, h := range c.stylesheet.preserveSpace {
		if h.ImportPrec > prec && ruleCoversRegion(h, region) {
			return true
		}
	}

	return false
}

func validateLegacyKeyUse(expression *xpath.Expression, bindings map[string]string) error {
	refs := expression.StaticReferences(bindings)
	if len(refs.FreeVariables) > 0 {
		return staticError(errCodeXTSE1205, "variables are unavailable in XSLT 1.0 keys")
	}

	for _, fn := range refs.FunctionNames {
		if fn.Prefix == "" && fn.Name == keyLocalName {
			return staticError(errCodeXTSE1205, "key() is unavailable in XSLT 1.0 key declarations")
		}
	}

	return nil
}

func validateOutputMethod(method string) error {
	if method == "" {
		return nil
	}

	if strings.Contains(method, ":") {
		if !xmlchar.IsValidQName(method) && !isValidEQName(method) {
			return staticError(errCodeXTSE1570, "invalid output method %q", method)
		}

		return nil
	}

	switch method {
	case lexicon.MethodXML, lexicon.MethodHTML, lexicon.MethodXHTML, lexicon.MethodText, lexicon.MethodJSON, lexicon.MethodAdaptive:
		return nil
	default:
		return staticError(errCodeXTSE1570, "invalid output method %q", method)
	}
}

func compileOutputBooleans(elem *xdm.Element, out *OutputDef, yesNoOnly bool) error {
	// Attribute metadata keeps value, explicitness and lexical spelling together.
	plain := []struct {
		name     string
		value    *bool
		explicit *bool
		raw      *string
	}{
		{lexicon.SerializationIndent, &out.Indent, nil, &out.IndentRaw},
		{lexicon.SerializationOmitXMLDeclaration, &out.OmitDeclaration, &out.OmitDeclarationExplicit, nil},
		{lexicon.SerializationUndeclarePrefixes, &out.UndeclarePrefixes, nil, nil},
		{lexicon.SerializationByteOrderMark, &out.ByteOrderMark, nil, nil},
	}
	for _, attribute := range plain {
		value, present, err := outputBoolAttr(elem, attribute.name, yesNoOnly)
		if err != nil {
			return err
		}

		if !present {
			continue
		}

		*attribute.value = value
		if attribute.explicit != nil {
			*attribute.explicit = true
		}

		if attribute.raw != nil {
			*attribute.raw = getAttr(elem, attribute.name)
		}
	}

	optional := []struct {
		name  string
		value **bool
	}{
		{lexicon.SerializationEscapeURIAttributes, &out.EscapeURIAttributes},
		{lexicon.SerializationIncludeContentType, &out.IncludeContentType},
	}
	for _, attribute := range optional {
		value, present, err := outputBoolAttr(elem, attribute.name, yesNoOnly)
		if err != nil {
			return err
		}

		if present {
			*attribute.value = &value
		}
	}

	return nil
}

type outputDeclarations struct {
	direct  *OutputDef
	scalars map[string]outputScalar
}

type outputScalar struct {
	value, lexical string
	precedence     int
	conflict       error
}

// mergeOutputDeclaration keeps explicit attributes separate from the
// parameter-document overlay. The effective document is read at the same
// declaration order and overrides the merged direct values.
func (c *compiler) mergeOutputDeclaration(ctx context.Context, elem *xdm.Element, declaration *OutputDef) error {
	if c.outputDeclarations == nil {
		c.outputDeclarations = make(map[string]*outputDeclarations)
	}

	state := c.outputDeclarations[declaration.Name]
	if state == nil {
		state = &outputDeclarations{
			direct: &OutputDef{
				Name: declaration.Name, Method: lexicon.MethodXML, Encoding: lexicon.EncodingUTF8U,
				serializationVersion: declaration.serializationVersion,
			},
			scalars: make(map[string]outputScalar),
		}

		c.outputDeclarations[declaration.Name] = state
	}

	state.merge(elem, declaration, c.nsBindings)
	effective := cloneOutputDef(state.direct)

	if effective.ParameterDocument != "" {
		_, explicit := state.scalars[lexicon.SerializationAllowDuplicateNames]
		if _, _, err := c.loadParameterDocument(ctx, effective, "", effective.ParameterDocument, explicit); err != nil {
			return err
		}
	}

	c.stylesheet.outputs[declaration.Name] = effective

	return nil
}

func (s *outputDeclarations) record(name, value, lexical string, precedence int) bool {
	previous, exists := s.scalars[name]
	if exists && precedence < previous.precedence {
		return false
	}

	next := outputScalar{value: value, lexical: lexical, precedence: precedence}
	if exists && precedence == previous.precedence {
		next.conflict = previous.conflict
		if previous.value != value && next.conflict == nil {
			next.conflict = staticError(errCodeXTSE1560,
				"conflicting values for xsl:output/@%s: %q vs %q", name, previous.lexical, lexical)
		}
	}

	s.scalars[name] = next

	return true
}

func (s *outputDeclarations) merge(elem *xdm.Element, source *OutputDef, namespaces map[string]string) {
	target := s.direct
	target.ImportPrec = max(target.ImportPrec, source.ImportPrec)
	target.CDATASections = unionOutputNames(target.CDATASections, source.CDATASections)
	target.SuppressIndentation = unionOutputNames(target.SuppressIndentation, source.SuppressIndentation)
	target.UseCharacterMaps = append(target.UseCharacterMaps, source.UseCharacterMaps...)

	for _, attr := range []struct {
		name, value string
		apply       func()
	}{
		{lexicon.SerializationMethod, outputMethodIdentity(source, namespaces), func() {
			target.Method, target.MethodExplicit, target.MethodRaw = source.Method, source.MethodExplicit, source.MethodRaw
		}},
		{lexicon.SerializationIndent, strconv.FormatBool(source.Indent), func() { target.Indent, target.IndentRaw = source.Indent, source.IndentRaw }},
		{lexicon.SerializationEncoding, source.EncodingRaw, func() { target.Encoding, target.EncodingRaw = source.Encoding, source.EncodingRaw }},
		{lexicon.SerializationVersion, source.VersionRaw, func() { target.Version, target.VersionRaw = source.Version, source.VersionRaw }},
		{lexicon.SerializationStandalone, source.Standalone, func() { target.Standalone, target.StandaloneRaw = source.Standalone, source.StandaloneRaw }},
		{lexicon.SerializationOmitXMLDeclaration, strconv.FormatBool(source.OmitDeclaration), func() {
			target.OmitDeclaration, target.OmitDeclarationExplicit = source.OmitDeclaration, source.OmitDeclarationExplicit
		}},
		{lexicon.SerializationUndeclarePrefixes, strconv.FormatBool(source.UndeclarePrefixes), func() { target.UndeclarePrefixes = source.UndeclarePrefixes }},
		{lexicon.SerializationDoctypePublic, source.DoctypePublic, func() { target.DoctypePublic = source.DoctypePublic }},
		{lexicon.SerializationDoctypeSystem, source.DoctypeSystem, func() { target.DoctypeSystem = source.DoctypeSystem }},
		{lexicon.SerializationMediaType, source.MediaType, func() { target.MediaType = source.MediaType }},
		{lexicon.SerializationItemSeparator, getAttr(elem, lexicon.SerializationItemSeparator), func() {
			target.ItemSeparator, target.ItemSeparatorAbsent = source.ItemSeparator, source.ItemSeparatorAbsent
		}},
		{lexicon.SerializationNormalizationForm, source.NormalizationForm, func() { target.NormalizationForm = source.NormalizationForm }},
		{lexicon.SerializationHTMLVersion, source.HTMLVersion, func() { target.HTMLVersion = source.HTMLVersion }},
		{lexicon.SerializationJSONNodeOutputMethod, resolveQName(source.JSONNodeOutputMethod, namespaces), func() { target.JSONNodeOutputMethod = source.JSONNodeOutputMethod }},
		{lexicon.SerializationParameterDocument, source.ParameterDocument, func() { target.ParameterDocument = source.ParameterDocument }},
		{lexicon.SerializationAllowDuplicateNames, strconv.FormatBool(source.AllowDuplicateNames), func() { target.AllowDuplicateNames = source.AllowDuplicateNames }},
		{lexicon.SerializationByteOrderMark, strconv.FormatBool(source.ByteOrderMark), func() { target.ByteOrderMark = source.ByteOrderMark }},
		{lexicon.SerializationBuildTree, outputBooleanIdentity(source.BuildTree), func() { target.BuildTree = source.BuildTree }},
		{lexicon.SerializationIncludeContentType, outputBooleanIdentity(source.IncludeContentType), func() { target.IncludeContentType = source.IncludeContentType }},
		{lexicon.SerializationEscapeURIAttributes, outputBooleanIdentity(source.EscapeURIAttributes), func() { target.EscapeURIAttributes = source.EscapeURIAttributes }},
	} {
		lexical, present := elem.GetAttribute(attr.name)
		if present && s.record(attr.name, attr.value, lexical, source.ImportPrec) {
			attr.apply()
		}
	}
}

func outputMethodIdentity(output *OutputDef, namespaces map[string]string) string {
	if strings.ContainsAny(output.MethodRaw, ":{") {
		return resolveQName(output.MethodRaw, namespaces)
	}

	return output.Method
}

func outputBooleanIdentity(value *bool) string {
	return strconv.FormatBool(value != nil && *value)
}

func (c *compiler) checkOutputDeclarationConflicts() error {
	for _, name := range slices.Sorted(maps.Keys(c.outputDeclarations)) {
		scalars := c.outputDeclarations[name].scalars
		for _, attribute := range slices.Sorted(maps.Keys(scalars)) {
			if err := scalars[attribute].conflict; err != nil {
				return err
			}
		}
	}

	return nil
}

func outputStandalone(value string, yesNoOnly bool) (string, error) {
	if value == "" {
		return "", nil
	}

	value = strings.TrimSpace(value)
	switch value {
	case lexicon.ValueYes, lexicon.ValueNo, lexicon.ValueOmit:
		return value, nil
	case lexicon.ValueTrue, booleanDigitTrue:
		if !yesNoOnly {
			return lexicon.ValueYes, nil
		}
	case lexicon.ValueFalse, booleanDigitFalse:
		if !yesNoOnly {
			return lexicon.ValueNo, nil
		}
	}

	return "", staticError(lexicon.ErrSEPM0016, "%q is not a valid value for xsl:output/@standalone", value)
}

// loadParameterDocumentFromFile shares validated parameter extraction between
// compile-time and runtime callers. Present false/empty values remain explicit;
// malformed/schema-invalid documents retain their serialization error codes.
// Ordinary missing resources are ignored, while authorization, cancellation,
// exhausted budgets and non-missing retrieval failures preserve their causes.
// adnExplicit is the existing allow-duplicate-names merge bookkeeping.
func loadParameterDocumentFromFile(ctx context.Context, injected *xdm.ParseOptions, outDef *OutputDef, baseURI, href string, openResource func(context.Context, string) (io.ReadCloser, error), runtime bool, adnExplicit bool, resourceLimit int64) (bool, paramDocPresence, error) {
	values := parameterDocumentValues{output: outDef, explicit: adnExplicit}

	root, err := loadParameterDocumentRoot(ctx, injected, baseURI, href, openResource, runtime, resourceLimit)
	if err != nil {
		return values.explicit, values.presence, err
	}

	if root == nil {
		return values.explicit, nil, nil
	}

	parameters, err := xpath.ReadSerializationParameters(ctx, root, xpathProfile31)
	if err != nil {
		return values.explicit, nil, err
	}

	values.applyValidated(parameters)

	return values.explicit, values.presence, nil
}

func parameterDocumentURI(baseURI, href string) string {
	uri, err := resolveModuleURI(href, baseURI)
	if err != nil {
		return uripath.EscapeResourceReference(href)
	}

	return uri
}

func loadParameterDocumentRoot(ctx context.Context, injected *xdm.ParseOptions, baseURI, href string, openResource func(context.Context, string) (io.ReadCloser, error), runtime bool, resourceLimit int64) (*xdm.Element, error) {
	const (
		serializationParametersElement = "serialization-parameters"
	)

	const (
		errCodeSEPM0017 = "SEPM0017"
	)

	reader, err := openResource(ctx, parameterDocumentURI(baseURI, href))
	if err != nil {
		err = closeFailedResolution(reader, err)
		if failure := preserveControlFailure(ctx, err); failure != nil {
			return nil, failure
		}

		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}

		return nil, parameterDocumentLoadError(err, href, runtime)
	}
	// Parameter documents use the fixed W3C schema and no external entities.
	// The injected parse options and resource limit still apply to parsing.
	doc, err := parseXMLResource(ctx, injected, reader, "", resourceLimit)
	if err != nil {
		if failure := preserveControlFailure(ctx, err); failure != nil {
			return nil, failure
		}

		return nil, &xdm.Error{Code: errCodeSEPM0017, Message: "ill-formed serialization parameter document", Cause: err}
	}

	root := doc.DocumentElement()
	if root == nil || root.LocalName() != serializationParametersElement || root.URI() != lexicon.NamespaceSerialization {
		return nil, &xdm.Error{Code: errCodeSEPM0017, Message: "serialization parameter document requires output:serialization-parameters"}
	}

	return root, nil
}

func parameterDocumentLoadError(err error, href string, runtime bool) error {
	if _, hostFailure := errors.AsType[*xdm.ResourceAccessError](err); hostFailure {
		return err
	}
	// Runtime failures are dynamic, while their raw cause survives the wrapper.
	if runtime {
		return dynamicErrorCause(lexicon.ErrFODC0002, err, "cannot read parameter-document %q: %v", href, err)
	}
	// Compile-time loaders already supply XTSE0090; do not wrap it twice.
	if _, ok := errors.AsType[*XSLTError](err); ok {
		return err
	}

	return staticErrorCause(errCodeXTSE0090, err, "cannot read parameter-document %q: %v", href, err)
}

func validateDecimalFormatCharacters(elem *xdm.Element) error {
	for _, name := range []string{nameDecimalSeparator, nameGroupingSeparator, namePercent, namePerMille, nameZeroDigit, nameDigit, namePatternSeparator, nameExponentSeparator, nameMinusSign} {
		if value, present := elem.GetAttribute(name); present && utf8.RuneCountInString(value) != 1 {
			return staticError(errCodeXTSE0020, "%s on xsl:decimal-format must be one character", name)
		}
	}

	return nil
}

type decimalFormatProperty struct {
	value      string
	precedence int
	conflict   bool
}

func mergeDecimalFormatAttributes(df *xpath.DecimalFormat, elem *xdm.Element, properties map[string]decimalFormatProperty, precedence int) {
	choose := func(name string) (string, bool) {
		value, present := elem.GetAttribute(name)
		previous, defined := properties[name]

		if !present || defined && precedence < previous.precedence {
			return "", false
		}

		// An explicitly specified higher-precedence value resolves conflicts
		// only for this property. Other properties keep their own precedence.
		conflict := defined && precedence == previous.precedence && (previous.conflict || previous.value != value)
		properties[name] = decimalFormatProperty{value: value, precedence: precedence, conflict: conflict}

		return value, true
	}

	for _, attribute := range []struct {
		name   string
		target *rune
	}{
		{nameDecimalSeparator, &df.DecimalSeparator},
		{nameGroupingSeparator, &df.GroupingSeparator},
		{namePercent, &df.Percent},
		{namePerMille, &df.PerMille},
		{nameZeroDigit, &df.ZeroDigit},
		{nameDigit, &df.Digit},
		{namePatternSeparator, &df.PatternSeparator},
		{nameExponentSeparator, &df.ExponentSeparator},
		{nameMinusSign, &df.MinusSign},
	} {
		if value, chosen := choose(attribute.name); chosen {
			*attribute.target = firstRune(value)
		}
	}

	if value, chosen := choose(nameInfinity); chosen {
		df.Infinity = value
	}

	if value, chosen := choose(lexicon.DecimalFormatNaN); chosen {
		df.NaN = value
	}
}

func isDigitZero(r rune) bool {
	return xpath.DecimalZeroDigit(r)
}

// nameTestKey returns a canonical conflict key for a nameTest. The key encodes
// the NameTest KIND in addition to its resolved name so that NameTests of
// different shapes never collide. A collision would raise a false XTSE0270 for a
// strip/preserve pair whose match priorities differ and is therefore resolved at
// runtime, and is no genuine conflict. XTSE0270 must fire only for two
// rules of the SAME kind and SAME name at the same import precedence.
//
// The four distinguished kinds (with their effective match priorities) are:
//
//   - universal wildcard "*"        (priority -0.5)
//   - namespace wildcard "prefix:*" / "Q{uri}*" (priority -0.25)
//   - local-name wildcard "*:local" (priority -0.25)
//   - exact expanded name           (priority  0)
//
// The two -0.25 kinds share a priority but never match the same node by the same
// criterion (one fixes the namespace, the other fixes the local name), so they
// are kept as separate kinds.
func nameTestKey(nt nameTest) string {
	const (
		spaceConflictExactPrefix     = "E:"
		spaceConflictLocalPrefix     = "L:"
		spaceConflictNamespacePrefix = "N:"
		spaceConflictUniversalKey    = "U:"
	)

	uri := ""
	if nt.HasURI {
		uri = nt.URI
	}

	switch {
	case nt.Prefix == "*":
		// "*:local" — local-name wildcard (namespace unconstrained).
		return spaceConflictLocalPrefix + nt.Local
	case nt.Local == "*" && nt.HasURI:
		// "prefix:*" / "Q{uri}*" — namespace wildcard.
		return spaceConflictNamespacePrefix + uri
	case nt.Local == "*":
		// "*" — universal wildcard.
		return spaceConflictUniversalKey
	default:
		// Exact expanded name.
		return spaceConflictExactPrefix + xdm.ClarkName(uri, nt.Local)
	}
}

// spaceConflictRegion reports whether a strip NameTest s and a preserve NameTest
// p form an unresolvable static overlap (equal match priority, intersecting
// match-sets, neither outranking the other) and, if so, returns the NameTest
// describing the overlap region — the set of names BOTH match. sKey is
// nameTestKey(s), passed in to avoid recomputation.
//
// Only EQUAL-priority pairs can be statically unresolvable: when priorities
// differ, the higher-priority rule wins per-name at runtime. Among equal-priority
// pairs the cases are:
//
//   - same kind, same name-set (equal nameTestKey): the region is that shared
//     NameTest itself.
//   - namespace wildcard "Q{ns}*" vs local-name wildcard "*:local" (both priority
//     -0.25): they always intersect on the single exact name Q{ns}local, which is
//     the overlap region.
//
// Two namespace wildcards (or two local-name wildcards) of DIFFERENT name never
// intersect, and equal-name same-kind pairs are caught by the equal-key case, so
// no other equal-priority cross pairs reach the wildcard branch.
func spaceConflictRegion(s, p nameTest, sKey string) (nameTest, bool) {
	if sKey == nameTestKey(p) {
		// Same resolved NameTest: the overlap region is the shared name-set.
		return s, true
	}

	if nameTestPriority(s) != nameTestPriority(p) {
		// Differing priority: the more specific rule decides per-name at runtime.
		return nameTest{}, false
	}
	// Equal priority, different keys. The only such intersecting pair is a
	// namespace wildcard vs a local-name wildcard; their overlap is the single
	// exact name Q{ns}local.
	ns, ok := nsAndLocalWildcardOverlap(s, p)
	if !ok {
		return nameTest{}, false
	}

	return ns, true
}

// nsAndLocalWildcardOverlap returns the exact-name overlap region of a namespace
// wildcard "Q{ns}*" and a local-name wildcard "*:local" — the single name
// Q{ns}local that both match — in either argument order. ok is false when the
// pair is not one namespace wildcard and one local-name wildcard.
func nsAndLocalWildcardOverlap(a, b nameTest) (nameTest, bool) {
	nsw, lw := a, b
	if isLocalWildcardNameTest(a) && isNSWildcardNameTest(b) {
		nsw, lw = b, a
	}

	if !isNSWildcardNameTest(nsw) || !isLocalWildcardNameTest(lw) {
		return nameTest{}, false
	}
	// Exact name in the namespace of the namespace wildcard with the local name of
	// the local-name wildcard.
	return nameTest{
		Local:  lw.Local,
		URI:    nameTestURI(nsw),
		HasURI: nsw.HasURI,
	}, true
}

// ruleCoversRegion reports whether NameTest h matches EVERY expanded name in
// region's match-set (h's set ⊇ region's set). A region is one of the four
// NameTest kinds. Because a wildcard region has infinitely many names, only a
// rule at least as general as the region can cover it; finitely many narrower
// rules never can. This makes single-rule coverage both sound and complete for
// deciding whether a higher-precedence layer resolves a strip/preserve overlap.
func ruleCoversRegion(h, region nameTest) bool {
	switch {
	case isUniversalNameTest(h):
		return true // "*" matches every name
	case isNSWildcardNameTest(h):
		// Covers a region only if every name in the region lies in uri(h):
		// the same namespace wildcard, or an exact name in that namespace.
		switch {
		case isNSWildcardNameTest(region):
			return nameTestURI(h) == nameTestURI(region)
		case !isUniversalNameTest(region) && !isLocalWildcardNameTest(region) && region.Local != "*":
			// region is exact
			return nameTestURI(h) == nameTestURI(region)
		default:
			return false // universal / local-name-wildcard region spans other namespaces
		}
	case isLocalWildcardNameTest(h):
		// Covers a region only if every name in the region has local name h.Local:
		// the same local-name wildcard, or an exact name with that local.
		switch {
		case isLocalWildcardNameTest(region):
			return h.Local == region.Local
		case !isUniversalNameTest(region) && !isNSWildcardNameTest(region):
			// region is exact
			return h.Local == region.Local
		default:
			return false // universal / namespace-wildcard region spans other local names
		}
	default: // h is exact; can only cover a single exact name equal to it
		if isUniversalNameTest(region) || isNSWildcardNameTest(region) || isLocalWildcardNameTest(region) {
			return false
		}

		return nameTestURI(h) == nameTestURI(region) && h.Local == region.Local
	}
}

// outputBoolAttr reads a boolean xsl:output attribute. When the attribute is
// absent (present=false) the value is ignored; when present but not a valid
// value it returns SEPM0016. The attr name is embedded in the error verbatim,
// matching the param constants' literal values.
//
// The accepted value space depends on the stylesheet's effective XSLT version.
// XSLT 3.0 uses Serialization 3.0, whose boolean serialization parameters accept
// the full xs:boolean lexical space {yes, no, true, false, 1, 0}. XSLT 2.0 (and
// 1.0) use the earlier serialization spec, restricting them to {yes, no}; when
// yesNoOnly is true any other lexical form (including true/false/1/0) is invalid.
func outputBoolAttr(elem *xdm.Element, attr string, yesNoOnly bool) (bool, bool, error) {
	v, present := elem.GetAttribute(attr)
	if !present {
		return false, false, nil
	}

	if yesNoOnly {
		switch strings.TrimSpace(v) {
		case lexicon.ValueYes:
			return true, true, nil
		case lexicon.ValueNo:
			return false, true, nil
		default:
			return false, false, staticError(lexicon.ErrSEPM0016, "%q is not a valid value for xsl:output/@"+attr, v)
		}
	}

	b, ok := parseXSDBool(v)
	if !ok {
		return false, false, staticError(lexicon.ErrSEPM0016, "%q is not a valid value for xsl:output/@"+attr, v)
	}

	return b, true, nil
}

func resolveOutputNames(value string, bindings map[string]string) []string {
	if value == "" {
		return nil
	}

	names := strings.Fields(value)
	resolved := make([]string, len(names))

	for i, name := range names {
		resolved[i] = resolveOutputName(name, bindings)
	}

	return resolved
}

func resolveOutputName(name string, bindings map[string]string) string {
	if !strings.ContainsAny(name, ":{") && bindings[""] != "" {
		return xdm.ClarkName(bindings[""], name)
	}

	return resolveQName(name, bindings)
}

func firstRune(s string) rune {
	for _, r := range s {
		return r
	}

	return 0
}

// nameTestURI returns the effective namespace URI of a NameTest ("" when unset).
func nameTestURI(nt nameTest) string {
	if nt.HasURI {
		return nt.URI
	}

	return ""
}

func isUniversalNameTest(nt nameTest) bool {
	return nt.Local == "*" && nt.Prefix == "" && !nt.HasURI
}

// isNSWildcardNameTest reports whether nt is a namespace wildcard "Q{uri}*" /
// "prefix:*", which matches every local name in a fixed namespace.
func isNSWildcardNameTest(nt nameTest) bool {
	return nt.Local == "*" && !isUniversalNameTest(nt)
}

// isLocalWildcardNameTest reports whether nt is a local-name wildcard "*:local",
// which matches a fixed local name in any namespace.
func isLocalWildcardNameTest(nt nameTest) bool {
	return nt.Prefix == "*"
}

type parameterDocumentValues struct {
	output   *OutputDef
	explicit bool
	presence paramDocPresence
}

func (p *parameterDocumentValues) applyValidated(parameters xpath.SerializationParameters) {
	p.presence = make(paramDocPresence)
	for name, value := range parameters.Booleans {
		p.presence[name] = struct{}{}
		p.applyBoolean(name, value)
	}

	for name, value := range parameters.Strings {
		p.presence[name] = struct{}{}
		p.applyString(name, value)
	}

	for name, values := range parameters.Names {
		p.presence[name] = struct{}{}
		switch name {
		case lexicon.SerializationCDATASectionElements:
			p.output.CDATASections = unionOutputNames(p.output.CDATASections, values)
		case lexicon.SerializationSuppressIndentation:
			p.output.SuppressIndentation = unionOutputNames(p.output.SuppressIndentation, values)
		}
	}

	if parameters.CharactersSet {
		p.presence[lexicon.SerializationUseCharacterMaps] = struct{}{}
		p.output.UseCharacterMaps = nil
		p.output.ResolvedCharMap = make(map[rune]string, len(parameters.Characters))
		maps.Copy(p.output.ResolvedCharMap, parameters.Characters)
	}
}

func (p *parameterDocumentValues) applyBoolean(name string, value bool) {
	switch name {
	case lexicon.SerializationIndent:
		p.output.Indent = value
	case lexicon.SerializationOmitXMLDeclaration:
		p.output.OmitDeclaration, p.output.OmitDeclarationExplicit = value, true
	case lexicon.SerializationUndeclarePrefixes:
		p.output.UndeclarePrefixes = value
	case lexicon.SerializationAllowDuplicateNames:
		p.output.AllowDuplicateNames, p.explicit = value, true
	case lexicon.SerializationByteOrderMark:
		p.output.ByteOrderMark = value
	case lexicon.SerializationEscapeURIAttributes:
		p.output.EscapeURIAttributes = &value
	case lexicon.SerializationIncludeContentType:
		p.output.IncludeContentType = &value
	}
}

func (p *parameterDocumentValues) applyString(name, value string) {
	switch name {
	case lexicon.SerializationMethod:
		p.output.Method, p.output.MethodExplicit = value, true
	case lexicon.SerializationEncoding:
		p.output.Encoding = value
	case lexicon.SerializationVersion:
		p.output.Version = value
	case lexicon.SerializationStandalone:
		p.output.Standalone = value
	case lexicon.SerializationDoctypePublic:
		p.output.DoctypePublic = value
	case lexicon.SerializationDoctypeSystem:
		p.output.DoctypeSystem = value
	case lexicon.SerializationMediaType:
		p.output.MediaType = value
	case lexicon.SerializationItemSeparator:
		p.output.ItemSeparator, p.output.ItemSeparatorAbsent = &value, false
	case lexicon.SerializationNormalizationForm:
		p.output.NormalizationForm = strings.ToUpper(value)
	case lexicon.SerializationHTMLVersion:
		p.output.HTMLVersion = value
	case lexicon.SerializationJSONNodeOutputMethod:
		p.output.JSONNodeOutputMethod = value
	}
}

func unionOutputNames(left, right []string) []string {
	seen := make(map[string]struct{}, len(left)+len(right))
	result := make([]string, 0, len(left)+len(right))

	for _, names := range [][]string{left, right} {
		for _, name := range names {
			if _, present := seen[name]; !present {
				seen[name] = struct{}{}
				result = append(result, name)
			}
		}
	}

	return result
}

// checkAttributeSetCycles detects cyclic use-attribute-sets references (XTSE0720).
// Must be called after all attribute-set definitions have been compiled and merged.
func checkAttributeSetCycles(ss *Stylesheet) error {
	const (
		unvisited = 0
		visiting  = 1
		done      = 2
	)

	state := make(map[string]int, len(ss.attributeSets))

	var visit func(name string) error

	visit = func(name string) error {
		switch state[name] {
		case done:
			return nil
		case visiting:
			if ss.processorLanguage() >= processorXSLT30 {
				return nil
			}

			return staticError(errCodeXTSE0720,
				"attribute-set %q has a circular use-attribute-sets reference", name)
		}

		state[name] = visiting
		if asd := ss.attributeSets[name]; asd != nil {
			if asd.OwnerPackage != nil && asd.OwnerPackage != ss {
				state[name] = done
				return nil
			}

			for _, ref := range asd.UseAttrSets {
				// use-attribute-sets="xsl:original" refers to the
				// original attribute-set being overridden, not a
				// named attribute-set in the stylesheet.
				if ref == xdm.ClarkName(lexicon.NamespaceXSLT, nameOriginal) && asd.OriginalAttrSet != nil {
					continue
				}

				if _, ok := ss.attributeSets[ref]; !ok {
					return staticError(errCodeXTSE0710,
						"attribute-set %q references undeclared attribute-set %q", name, ref)
				}

				if err := visit(ref); err != nil {
					return err
				}
			}
		}

		state[name] = done

		return nil
	}

	for name := range ss.attributeSets {
		if err := visit(name); err != nil {
			return err
		}
	}

	return nil
}

// checkAttributeSetStreamable checks XTSE0730: if an attribute set specifies
// streamable="yes", every attribute set referenced in its use-attribute-sets
// must also specify streamable="yes".
func checkAttributeSetStreamable(ss *Stylesheet) error {
	for _, asd := range ss.attributeSets {
		if !asd.Streamable || asd.OwnerPackage != nil && asd.OwnerPackage != ss {
			continue
		}

		for _, ref := range asd.UseAttrSets {
			used := ss.attributeSets[ref]
			if used == nil {
				continue
			}

			if !used.Streamable {
				return staticError(errCodeXTSE0730,
					"streamable attribute-set %q references non-streamable attribute-set %q",
					asd.Name, ref)
			}
		}
	}

	return nil
}

// checkDecimalFormatCharConflicts raises XTSE1300 if any two formatting characters
// in the decimal format are the same.
func checkDecimalFormatCharConflicts(df xpath.DecimalFormat) error {
	type charRole struct {
		char rune
		role string
	}

	roles := []charRole{
		{df.DecimalSeparator, nameDecimalSeparator},
		{df.GroupingSeparator, nameGroupingSeparator},
		{df.Percent, namePercent},
		{df.PerMille, namePerMille},
		{df.ZeroDigit, nameZeroDigit},
		{df.Digit, nameDigit},
		{df.PatternSeparator, namePatternSeparator},
	}
	if !df.ExponentDisabled {
		roles = append(roles, charRole{df.ExponentSeparator, nameExponentSeparator})
	}

	for _, role := range roles {
		if role.role != nameZeroDigit && role.char >= df.ZeroDigit && role.char <= df.ZeroDigit+9 {
			return staticError(errCodeXTSE1300, "%s conflicts with the zero-digit family", role.role)
		}
	}

	for i := range roles {
		for j := i + 1; j < len(roles); j++ {
			if roles[i].char == roles[j].char {
				return staticError(errCodeXTSE1300,
					"%s and %s use the same character %q",
					roles[i].role, roles[j].role, string(roles[i].char))
			}
		}
	}

	return nil
}
