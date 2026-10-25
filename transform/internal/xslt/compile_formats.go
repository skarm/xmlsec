// Derived from lestrrat-go/helium at 7362c0a70122a757780f4d0b545a9b370dead6ab.
// Copyright (c) 2015 lestrrat. MIT License; see licenses/MIT-helium.txt at the repository root.

package xslt

import (
	"context"
	"errors"
	"io"
	"maps"
	"path"
	"strconv"
	"strings"
	"unicode"

	"github.com/skarm/xmlsec/internal/xmlchar"
	"github.com/skarm/xmlsec/transform/internal/xdm"
	"github.com/skarm/xmlsec/transform/internal/xdm/lexicon"
	uripath "github.com/skarm/xmlsec/transform/internal/xdm/uri"
	"github.com/skarm/xmlsec/transform/internal/xpath"
)

func (c *compiler) compileCharacterMap(ctx context.Context, elem *xdm.Element) error {
	if err := c.validateXSLTAttrs(ctx, elem, attributeNames(xslAttrName, paramUseCharacterMaps, xslAttrUseWhen)); err != nil {
		return err
	}

	saved := c.pushElementNamespaces(ctx, elem)
	defer func() { c.nsBindings = saved }()

	name := getAttr(elem, xslAttrName)
	if name == "" {
		return staticError(errCodeXTSE0110, "xsl:character-map requires name attribute")
	}

	name = resolveQName(name, c.nsBindings)

	cm := &characterMapDef{
		Name:     name,
		Mappings: make(map[rune]string),
	}

	if ucm := getAttr(elem, paramUseCharacterMaps); ucm != "" {
		for n := range strings.FieldsSeq(ucm) {
			cm.UseCharacterMaps = append(cm.UseCharacterMaps, resolveQName(n, c.nsBindings))
		}
	}

	for child := range xdm.Children(elem) {
		childElem, ok := child.(*xdm.Element)
		if !ok {
			continue
		}

		if childElem.URI() != lexicon.NamespaceXSLT || childElem.LocalName() != lexicon.XSLTElementOutputCharacter {
			continue
		}

		charAttr := getAttr(childElem, "character")
		if charAttr == "" {
			return staticError(errCodeXTSE0010,
				"xsl:output-character requires 'character' attribute")
		}

		r := firstRune(charAttr)
		str := getAttr(childElem, "string")
		cm.Mappings[r] = str
	}

	if c.stylesheet.characterMaps == nil {
		c.stylesheet.characterMaps = make(map[string]*characterMapDef)
	}

	if c.charMapModuleKeys == nil {
		c.charMapModuleKeys = make(map[string]string)
	}
	// XTSE1580: duplicate character-map declarations with same name in the
	// same stylesheet module. Different modules may define the same name;
	// higher import precedence overrides, same precedence merges.
	if prevModule, exists := c.charMapModuleKeys[name]; exists && prevModule == c.moduleKey {
		return staticError(errCodeXTSE1580,
			"duplicate character-map declaration %q", name)
	}

	c.charMapModuleKeys[name] = c.moduleKey

	if existing, ok := c.stylesheet.characterMaps[name]; ok {
		// Merge: later-compiled mappings override earlier ones for the
		// same character. Since imports compile before the importing
		// module, the importing module's mappings naturally take precedence.
		maps.Copy(existing.Mappings, cm.Mappings)
		existing.UseCharacterMaps = append(existing.UseCharacterMaps, cm.UseCharacterMaps...)
	} else {
		c.stylesheet.characterMaps[name] = cm
	}

	return nil
}

func (c *compiler) compileKey(ctx context.Context, elem *xdm.Element) error {
	defer c.pushElementVersion(elem)()

	if err := c.validateXSLTAttrs(ctx, elem, attributeNames(xslAttrName, nameMatch2, nameUse, nameCollation, nameComposite, xslAttrUseWhen, nameDefaultCollation)); err != nil {
		return err
	}

	c.collectNamespaces(ctx, elem)

	// Handle per-element default-collation override (standard attribute)
	savedDefaultCollation := c.defaultCollation

	if dc := getAttr(elem, nameDefaultCollation); dc != "" {
		if uri := resolveDefaultCollation(dc); uri != "" {
			c.defaultCollation = uri
		}
	}

	defer func() { c.defaultCollation = savedDefaultCollation }()

	name := getAttr(elem, xslAttrName)
	if name == "" {
		return staticError(errCodeXTSE0110, "xsl:key requires name attribute")
	}

	if !xmlchar.IsValidQName(name) && !isValidEQName(name) {
		return staticError(errCodeXTSE0020, "invalid name %q on xsl:key", name)
	}

	matchAttr := getAttr(elem, nameMatch2)
	if matchAttr == "" {
		return staticError(errCodeXTSE0110, "xsl:key requires match attribute")
	}

	// Apply a local xpath-default-namespace on the xsl:key element (presence,
	// even an empty value, overrides the inherited default) so the @match
	// pattern's unprefixed names resolve consistently with NameTest semantics.
	xpathDefaultNS := c.xpathDefaultNS
	hasXPathDefaultNS := c.hasXPathDefaultNS

	if xdn, ok := elem.GetAttribute(nameXpathDefaultNamespace); ok {
		xpathDefaultNS = xdn
		hasXPathDefaultNS = true
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
	collationURI := ""

	if collAttr := getAttr(elem, nameCollation); collAttr != "" {
		// XTSE1210: collation must be a recognized URI
		if !xpath.IsCollationSupported(collAttr) {
			return staticError(errCodeXTSE1210, "unrecognized collation URI %q on xsl:key", collAttr)
		}

		collationURI = collAttr
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
		Name:      expandedName,
		Match:     matchPat,
		Composite: composite,
		Collation: collationURI,
		Compat:    c.backwardsCompatible(),
	}

	if err := c.compileKeyValue(ctx, elem, kd); err != nil {
		return err
	}

	c.stylesheet.keys[expandedName] = append(c.stylesheet.keys[expandedName], kd)

	return nil
}

func (c *compiler) compileKeyValue(ctx context.Context, elem *xdm.Element, kd *keyDef) error {
	useAttr := getAttr(elem, nameUse)
	hasContent := c.hasEffectiveContent(ctx, elem)
	// XTSE1205: must have either use attr or content, not both, and not neither
	if useAttr != "" && hasContent {
		return staticError(errCodeXTSE1205, "xsl:key must not have both a use attribute and content")
	}

	if useAttr == "" && !hasContent {
		return staticError(errCodeXTSE1205, "xsl:key must have either a use attribute or content")
	}

	if useAttr != "" {
		useExpr, err := c.compileXPath(useAttr, c.nsBindings)
		if err != nil {
			return err
		}

		if c.stylesheet.processorLanguage() == 10 {
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

func validateLegacyKeyUse(expression *xpath.Expression, bindings map[string]string) error {
	refs := expression.StaticReferences(bindings)
	if len(refs.FreeVariables) > 0 {
		return staticError("XTSE1205", "variables are unavailable in XSLT 1.0 keys")
	}

	for _, fn := range refs.FunctionNames {
		if fn.Prefix == "" && fn.Name == nameKey2 {
			return staticError("XTSE1205", "key() is unavailable in XSLT 1.0 key declarations")
		}
	}

	return nil
}

func (c *compiler) compileOutput(ctx context.Context, elem *xdm.Element) error {
	if err := c.validateXSLTAttrs(ctx, elem, attributeNames(xslAttrName, paramMethod, paramVersion, paramEncoding, paramOmitXMLDeclaration, paramStandalone, paramDoctypePublic, paramDoctypeSystem, paramCDATASectionElements, paramIndent, paramMediaType, paramByteOrderMark, paramEscapeURIAttributes, paramIncludeContentType, paramNormalizationForm, paramUndeclarePrefixes, paramUseCharacterMaps, paramSuppressIndentation, paramHTMLVersion, paramItemSeparator, paramJSONNodeOutputMethod, paramParameterDocument, paramBuildTree, paramAllowDuplicateNames, xslAttrUseWhen)); err != nil {
		return err
	}

	saved := c.pushElementNamespaces(ctx, elem)
	defer func() { c.nsBindings = saved }()

	name := getAttr(elem, xslAttrName)
	if name != "" {
		name = resolveQName(name, c.nsBindings)
	}

	methodStr := strings.TrimSpace(strings.ToLower(getAttr(elem, paramMethod)))
	if err := validateOutputMethod(methodStr); err != nil {
		return err
	}

	outDef := &OutputDef{
		Name:           name,
		Method:         methodStr,
		MethodExplicit: methodStr != "",
		Encoding:       getAttr(elem, paramEncoding),
		Version:        getAttr(elem, paramVersion),
		ImportPrec:     c.importPrec,
		MethodRaw:      getAttr(elem, paramMethod),
		EncodingRaw:    getAttr(elem, paramEncoding),
		VersionRaw:     getAttr(elem, paramVersion),
	}

	if outDef.Method == "" {
		outDef.Method = methodXML
	}

	if outDef.Encoding == "" {
		outDef.Encoding = lexicon.EncodingUTF8U
	}

	// Determine the accepted lexical space for boolean serialization parameters.
	// XSLT 2.0 (and 1.0) restrict them to yes/no; XSLT 3.0+ accepts the full
	// xs:boolean lexical space. The selected processor governs these rules;
	// XSLT 3.0 defines no differing behavior for a 2.0 declaration.
	yesNoOnly := c.stylesheet.processorLanguage() < 30

	if err := compileOutputBooleans(elem, outDef, yesNoOnly); err != nil {
		return err
	}

	if err := c.compileOutputSerialization(elem, outDef, yesNoOnly); err != nil {
		return err
	}

	// Presence is merge bookkeeping, including values from parameter documents.
	adnExplicit, err := c.compileOutputSequenceParameters(elem, outDef, yesNoOnly)
	if err != nil {
		return err
	}

	if v := getAttr(elem, paramParameterDocument); v != "" {
		outDef.ParameterDocument = v
		baseURI := stylesheetBaseURI(elem, c.baseURI, c.moduleRoot)

		var err error
		// This applies the parameter-document directly onto the xsl:output's
		// OutputDef (not a delta to be folded later), so the boolean presence
		// flags are not needed here and are discarded.
		if adnExplicit, _, err = c.loadParameterDocument(ctx, outDef, baseURI, v, adnExplicit); err != nil {
			return err
		}
	}

	if existing, ok := c.stylesheet.outputs[name]; ok {
		if existing.ImportPrec == c.importPrec {
			if err := checkOutputConflicts(existing, elem); err != nil {
				return err
			}
		}

		mergeOutputDefinition(outDef, existing, elem)
		// A parameter-document value is explicit and must survive inheritance.
		if !adnExplicit {
			outDef.AllowDuplicateNames = existing.AllowDuplicateNames
			adnExplicit = c.outputAllowDupExplicit[name]
		}
	}

	c.stylesheet.outputs[name] = outDef
	if c.outputAllowDupExplicit == nil {
		c.outputAllowDupExplicit = make(map[string]bool)
	}

	c.outputAllowDupExplicit[name] = adnExplicit

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
	case methodXML, methodHTML, methodXHTML, methodText, methodJSON, methodAdaptive:
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
		{paramIndent, &out.Indent, nil, &out.IndentRaw},
		{paramOmitXMLDeclaration, &out.OmitDeclaration, &out.OmitDeclarationExplicit, nil},
		{paramUndeclarePrefixes, &out.UndeclarePrefixes, nil, nil},
		{paramByteOrderMark, &out.ByteOrderMark, nil, nil},
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
		{paramEscapeURIAttributes, &out.EscapeURIAttributes},
		{paramIncludeContentType, &out.IncludeContentType},
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

func checkOutputConflicts(existing *OutputDef, elem *xdm.Element) error {
	checks := []struct {
		name     string
		previous string
	}{
		{paramMethod, existing.MethodRaw},
		{paramIndent, existing.IndentRaw},
		{paramEncoding, existing.EncodingRaw},
		{paramVersion, existing.VersionRaw},
		{paramStandalone, existing.StandaloneRaw},
	}
	for _, check := range checks {
		value := getAttr(elem, check.name)
		if value != "" && check.previous != "" && check.previous != value {
			return staticError(errCodeXTSE1560,
				"conflicting values for xsl:output/@%s: %q vs %q", check.name, check.previous, value)
		}
	}

	return nil
}

// mergeOutputDefinition inherits settings omitted by a later declaration.
func mergeOutputDefinition(out, existing *OutputDef, elem *xdm.Element) {
	if len(existing.UseCharacterMaps) > 0 {
		out.UseCharacterMaps = append(existing.UseCharacterMaps, out.UseCharacterMaps...)
	}

	if getAttr(elem, paramMethod) == "" {
		out.Method = existing.Method
		out.MethodExplicit = existing.MethodExplicit
	}

	if getAttr(elem, paramEncoding) == "" {
		out.Encoding = existing.Encoding
	}

	if getAttr(elem, paramVersion) == "" {
		out.Version = existing.Version
	}

	if getAttr(elem, paramIndent) == "" {
		out.Indent = existing.Indent
	}

	if getAttr(elem, paramOmitXMLDeclaration) == "" {
		out.OmitDeclaration = existing.OmitDeclaration
		out.OmitDeclarationExplicit = existing.OmitDeclarationExplicit
	}

	if getAttr(elem, paramStandalone) == "" {
		out.Standalone = existing.Standalone
	}

	if getAttr(elem, paramUndeclarePrefixes) == "" {
		out.UndeclarePrefixes = existing.UndeclarePrefixes
	}

	if !elem.HasAttribute(paramDoctypePublic) {
		out.DoctypePublic = existing.DoctypePublic
	}

	if !elem.HasAttribute(paramDoctypeSystem) {
		out.DoctypeSystem = existing.DoctypeSystem
	}

	if getAttr(elem, paramMediaType) == "" {
		out.MediaType = existing.MediaType
	}

	if getAttr(elem, paramCDATASectionElements) == "" {
		out.CDATASections = existing.CDATASections
	}

	if getAttr(elem, paramItemSeparator) == "" {
		out.ItemSeparator = existing.ItemSeparator
	}

	if getAttr(elem, paramNormalizationForm) == "" {
		out.NormalizationForm = existing.NormalizationForm
	}

	if getAttr(elem, paramHTMLVersion) == "" {
		out.HTMLVersion = existing.HTMLVersion
	}

	if out.IncludeContentType == nil {
		out.IncludeContentType = existing.IncludeContentType
	}

	if getAttr(elem, paramJSONNodeOutputMethod) == "" {
		out.JSONNodeOutputMethod = existing.JSONNodeOutputMethod
	}
}

func (c *compiler) compileOutputSerialization(elem *xdm.Element, out *OutputDef, yesNoOnly bool) error {
	standalone := getAttr(elem, paramStandalone)

	var err error

	out.Standalone, err = outputStandalone(standalone, yesNoOnly)
	if err != nil {
		return err
	}

	out.StandaloneRaw = standalone
	out.DoctypePublic = getAttr(elem, paramDoctypePublic)
	out.DoctypeSystem = getAttr(elem, paramDoctypeSystem)
	out.MediaType = getAttr(elem, paramMediaType)

	if version := getAttr(elem, paramHTMLVersion); version != "" {
		version = strings.TrimSpace(version)
		if _, err := strconv.ParseFloat(version, 64); err != nil {
			return staticError(errCodeXTSE0020, "%q is not a valid value for xsl:output/@html-version", version)
		}

		out.HTMLVersion = version
	}

	out.CDATASections = resolveOutputNames(getAttr(elem, paramCDATASectionElements), c.nsBindings)
	if separator := getAttr(elem, paramItemSeparator); separator != "" {
		out.ItemSeparator = &separator
	}

	if form := getAttr(elem, paramNormalizationForm); form != "" {
		out.NormalizationForm = strings.ToUpper(strings.TrimSpace(form))
	}

	if maps := getAttr(elem, paramUseCharacterMaps); maps != "" {
		for name := range strings.FieldsSeq(maps) {
			out.UseCharacterMaps = append(out.UseCharacterMaps, resolveQName(name, c.nsBindings))
		}
	}

	if method := getAttr(elem, paramJSONNodeOutputMethod); method != "" {
		out.JSONNodeOutputMethod = strings.TrimSpace(method)
	}

	return nil
}

func outputStandalone(value string, yesNoOnly bool) (string, error) {
	if value == "" {
		return "", nil
	}

	value = strings.TrimSpace(value)
	switch value {
	case lexicon.ValueYes, lexicon.ValueNo, nameOmit:
		return value, nil
	case lexicon.ValueTrue, "1":
		if !yesNoOnly {
			return lexicon.ValueYes, nil
		}
	case lexicon.ValueFalse, "0":
		if !yesNoOnly {
			return lexicon.ValueNo, nil
		}
	}

	return "", staticError(errCodeSEPM0016, "%q is not a valid value for xsl:output/@standalone", value)
}

func (c *compiler) compileOutputSequenceParameters(elem *xdm.Element, out *OutputDef, yesNoOnly bool) (bool, error) {
	value, explicit, err := outputBoolAttr(elem, paramAllowDuplicateNames, yesNoOnly)
	if err != nil {
		return false, err
	}

	if explicit {
		out.AllowDuplicateNames = value
	}

	out.SuppressIndentation = resolveOutputNames(getAttr(elem, paramSuppressIndentation), c.nsBindings)

	buildTree, present, err := outputBoolAttr(elem, paramBuildTree, yesNoOnly)
	if err != nil {
		return false, err
	}

	if present {
		out.BuildTree = &buildTree
	}

	return explicit, nil
}

// loadParameterDocument loads a serialization parameter document (XSLT 3.0 §9.2)
// and applies its settings to the given OutputDef. Parameters explicitly set on
// the xsl:output element take precedence; the parameter document provides defaults.
// adnExplicit carries the allow-duplicate-names explicitness in and out so the
// parameter document does not override a value already set on xsl:output and the
// caller can fold the result into its compile-time merge bookkeeping.
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

// loadParameterDocumentFromFile loads a serialization parameter document and
// applies its settings to the given OutputDef. This standalone version can be
// called at both compile-time and runtime; the openResource callback performs the
// actual retrieval so each caller supplies its own (opt-in) loader.
//
// runtime selects the error taxonomy: at compile time (runtime=false) a load or
// parse failure is a static error (XTSE0090); at runtime (runtime=true, e.g. an
// xsl:result-document parameter-document AVT) it is a dynamic error (FODC0002).
// A runtime failure must NOT also satisfy errors.Is(err, ErrStaticError), so the
// runtime path never applies the static wrapper. A distinguishable cause such as
// [ErrResourceTooLarge] survives either way via errors.Join.
//
// adnExplicit (allow-duplicate-names explicitness) is threaded in and out rather
// than stored on the public OutputDef: when already true on input the parameter
// document must not override the value, and the returned value reports whether
// the parameter document supplied it so the caller can fold it into its own
// compile-time merge bookkeeping.
//
// The returned paramDocPresence reports which plain-boolean serialization
// parameters this parameter-document explicitly supplied. These presence flags
// are kept off the public OutputDef (a plain bool cannot distinguish "omitted"
// from "explicit false") and travel alongside the resulting delta so
// foldParamDocOverrides leaves an inherited xsl:output default intact for any
// boolean the parameter-document omits.
func loadParameterDocumentFromFile(ctx context.Context, injected *xdm.ParseOptions, outDef *OutputDef, baseURI, href string, openResource func(context.Context, string) (io.ReadCloser, error), runtime bool, adnExplicit bool, resourceLimit int64) (bool, paramDocPresence, error) {
	values := parameterDocumentValues{output: outDef, explicit: adnExplicit}

	root, err := loadParameterDocumentRoot(ctx, injected, baseURI, href, openResource, runtime, resourceLimit)
	if err != nil {
		return values.explicit, values.presence, err
	}

	for child := range xdm.Children(root) {
		elem, ok := child.(*xdm.Element)
		if !ok || elem.URI() != lexicon.NamespaceSerialization {
			continue
		}

		values.apply(elem)
	}

	return values.explicit, values.presence, nil
}

func parameterDocumentURI(baseURI, href string) string {
	// Scheme detection follows RFC 3986, including schemes without an authority.
	// Local filesystem bases retain forward slashes on every operating system.
	if baseURI == "" {
		return href
	}

	if uripath.URIScheme(href) != "" || uripath.URIScheme(baseURI) != "" {
		resolved, err := uripath.ResolveSchemaURI(href, baseURI)
		if err == nil {
			return resolved
		}

		return href
	}

	if !uripath.IsAbsolutePath(href) {
		return uripath.JoinLocalBaseDir(path.Dir(uripath.ToSlash(baseURI)), href)
	}

	return href
}

func loadParameterDocumentRoot(ctx context.Context, injected *xdm.ParseOptions, baseURI, href string, openResource func(context.Context, string) (io.ReadCloser, error), runtime bool, resourceLimit int64) (*xdm.Element, error) {
	reader, err := openResource(ctx, parameterDocumentURI(baseURI, href))
	if err != nil {
		return nil, parameterDocumentLoadError(err, href, runtime)
	}
	// Parameter documents use the fixed W3C schema and no external entities.
	// The injected parse options and resource limit still apply to parsing.
	doc, err := parseXMLResource(ctx, injected, reader, "", resourceLimit)
	if err != nil {
		if runtime {
			return nil, dynamicErrorCause(errCodeFODC0002, err, "cannot parse parameter-document %q: %v", href, err)
		}

		return nil, staticErrorCause(errCodeXTSE0090, err, "cannot parse parameter-document %q: %v", href, err)
	}

	root := doc.DocumentElement()
	if root == nil || root.LocalName() != "serialization-parameters" || root.URI() != lexicon.NamespaceSerialization {
		if runtime {
			return nil, dynamicError(errCodeFODC0002, "parameter-document %q: root element must be {%s}serialization-parameters", href, lexicon.NamespaceSerialization)
		}

		return nil, staticError(errCodeXTSE0090, "parameter-document %q: root element must be {%s}serialization-parameters", href, lexicon.NamespaceSerialization)
	}

	return root, nil
}

func parameterDocumentLoadError(err error, href string, runtime bool) error {
	// Runtime failures are dynamic, while their raw cause survives the wrapper.
	if runtime {
		return dynamicErrorCause(errCodeFODC0002, err, "cannot read parameter-document %q: %v", href, err)
	}
	// Compile-time loaders already supply XTSE0090; do not wrap it twice.
	if _, ok := errors.AsType[*XSLTError](err); ok {
		return err
	}

	return staticErrorCause(errCodeXTSE0090, err, "cannot read parameter-document %q: %v", href, err)
}

func (c *compiler) compileAttributeSet(ctx context.Context, elem *xdm.Element) error {
	defer c.pushElementVersion(elem)()

	if err := c.validateXSLTAttrs(ctx, elem, attributeNames(xslAttrName, nameUseAttributeSets, xslAttrVisibility, nameStreamable, xslAttrUseWhen)); err != nil {
		return err
	}

	name := getAttr(elem, xslAttrName)
	if name == "" {
		return staticError(errCodeXTSE0110, "xsl:attribute-set requires name attribute")
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

	if uas := getAttr(elem, nameUseAttributeSets); uas != "" {
		for n := range strings.FieldsSeq(uas) {
			asd.UseAttrSets = append(asd.UseAttrSets, resolveQName(n, c.nsBindings))
		}
	}

	for child := range xdm.Children(elem) {
		childElem, ok := child.(*xdm.Element)
		if !ok {
			// XTSE0010: text content not allowed in xsl:attribute-set
			if isNonWhitespaceTextNode(child) {
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
	// Merge same-named attribute-sets (XSLT spec: union of all definitions).
	// When an existing entry comes from a used package (OwnerPackage != nil)
	// and the new definition is local, the local definition replaces the
	// package's private attribute-set, merging with none of it.
	if existing, ok := c.stylesheet.attributeSets[name]; ok {
		if existing.OwnerPackage != nil {
			// Replace package-scoped attribute-set with local definition.
			asd.Parts = []attributeSetPart{part}
			c.stylesheet.attributeSets[name] = asd
		} else {
			existing.Attrs = append(existing.Attrs, asd.Attrs...)
			existing.UseAttrSets = append(existing.UseAttrSets, asd.UseAttrSets...)
			existing.Parts = append(existing.Parts, part)
		}
	} else {
		asd.Parts = []attributeSetPart{part}
		c.stylesheet.attributeSets[name] = asd
	}

	return nil
}

func (c *compiler) compileDecimalFormat(ctx context.Context, elem *xdm.Element) error {
	if err := c.validateXSLTAttrs(ctx, elem, attributeNames(xslAttrName, nameDecimalSeparator, nameGroupingSeparator, nameInfinity, nameMinusSign, valueNaN, namePercent, namePerMille, nameZeroDigit, nameDigit, namePatternSeparator, nameExponentSeparator, xslAttrUseWhen)); err != nil {
		return err
	}
	// Push element-local namespace declarations so prefixed names resolve correctly
	saved := c.pushElementNamespaces(ctx, elem)
	defer func() { c.nsBindings = saved }()

	qn, err := decimalFormatName(getAttr(elem, xslAttrName), c.nsBindings)
	if err != nil {
		return err
	}

	if c.stylesheet.decimalFormats == nil {
		c.stylesheet.decimalFormats = make(map[xpath.QualifiedName]xpath.DecimalFormat)
		c.stylesheet.decimalFmtPrec = make(map[xpath.QualifiedName]int)
		c.stylesheet.decimalFmtSet = make(map[xpath.QualifiedName]map[string]struct{})
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
	existingPrec := c.stylesheet.decimalFmtPrec[qn]

	if !exists {
		df = xpath.DefaultDecimalFormat()
	}

	// XTSE1290: record potential conflicts for deferred checking after all imports.
	// Higher precedence declarations can override lower-precedence conflicts.
	if exists && c.importPrec == existingPrec {
		prevSet := c.stylesheet.decimalFmtSet[qn]
		if err := checkDecimalFormatConflictExplicit(df, elem, prevSet); err != nil {
			// Record the conflict and its precedence for deferred checking
			if c.stylesheet.decimalFmtConflicts == nil {
				c.stylesheet.decimalFmtConflicts = make(map[xpath.QualifiedName]int)
			}

			c.stylesheet.decimalFmtConflicts[qn] = c.importPrec
		}
	}

	// If current declaration has higher or equal import precedence, merge properties.
	// Lower precedence declarations' explicitly-set properties are inherited.
	if !exists || c.importPrec >= existingPrec {
		applyDecimalFormatAttributes(&df, elem)

		c.stylesheet.decimalFormats[qn] = df
		c.stylesheet.decimalFmtPrec[qn] = c.importPrec

		// Track which properties were explicitly set
		if c.stylesheet.decimalFmtSet[qn] == nil {
			c.stylesheet.decimalFmtSet[qn] = make(map[string]struct{})
		}
		// If higher precedence, clear previously tracked properties
		if exists && c.importPrec > existingPrec {
			c.stylesheet.decimalFmtSet[qn] = make(map[string]struct{})
		}

		setProps := c.stylesheet.decimalFmtSet[qn]

		for _, attr := range []string{
			nameDecimalSeparator, nameGroupingSeparator, namePercent,
			namePerMille, nameZeroDigit, nameDigit, namePatternSeparator, nameExponentSeparator,
			nameInfinity, valueNaN, nameMinusSign,
		} {
			if elem.HasAttribute(attr) {
				setProps[attr] = struct{}{}
			}
		}
	}

	return nil
}

func decimalFormatName(name string, bindings map[string]string) (xpath.QualifiedName, error) {
	qn := xpath.QualifiedName{}

	if name != "" {
		if !xmlchar.IsValidQName(name) && !isValidEQName(name) {
			return qn, staticError(errCodeXTSE0020, "invalid name %q on xsl:decimal-format", name)
		}

		qn = xpath.QualifiedName{Name: name}
		if prefix, local, ok := strings.Cut(name, ":"); ok {
			if uri, ok := bindings[prefix]; ok {
				qn = xpath.QualifiedName{URI: uri, Name: local}
			} else {
				qn.Name = local
			}
		}
	}

	return qn, nil
}

func applyDecimalFormatAttributes(df *xpath.DecimalFormat, elem *xdm.Element) {
	// Merge explicitly-set properties
	if v := getAttr(elem, nameDecimalSeparator); v != "" {
		df.DecimalSeparator = firstRune(v)
	}

	if v := getAttr(elem, nameGroupingSeparator); v != "" {
		df.GroupingSeparator = firstRune(v)
	}

	if v := getAttr(elem, namePercent); v != "" {
		df.Percent = firstRune(v)
	}

	if v := getAttr(elem, namePerMille); v != "" {
		df.PerMille = firstRune(v)
	}

	if v := getAttr(elem, nameZeroDigit); v != "" {
		df.ZeroDigit = firstRune(v)
	}

	if v := getAttr(elem, nameDigit); v != "" {
		df.Digit = firstRune(v)
	}

	if v := getAttr(elem, namePatternSeparator); v != "" {
		df.PatternSeparator = firstRune(v)
	}

	if v := getAttr(elem, nameExponentSeparator); v != "" {
		df.ExponentSeparator = firstRune(v)
	}

	if v, present := elem.GetAttribute(nameInfinity); present {
		df.Infinity = v
	}

	if v, present := elem.GetAttribute(valueNaN); present {
		df.NaN = v
	}

	if v := getAttr(elem, nameMinusSign); v != "" {
		df.MinusSign = firstRune(v)
	}
}

func isDigitZero(r rune) bool {
	return xpath.DecimalZeroDigit(r)
}

// checkDecimalFormatConflictExplicit raises XTSE1290 if any property
// explicitly set in elem conflicts with a property explicitly set in a prior
// declaration of the same name at the same import precedence.
func checkDecimalFormatConflictExplicit(existing xpath.DecimalFormat, elem *xdm.Element, prevSet map[string]struct{}) error {
	type runeCheck struct {
		attr string
		cur  rune
	}

	runeChecks := []runeCheck{
		{nameDecimalSeparator, existing.DecimalSeparator},
		{nameGroupingSeparator, existing.GroupingSeparator},
		{namePercent, existing.Percent},
		{namePerMille, existing.PerMille},
		{nameZeroDigit, existing.ZeroDigit},
		{nameDigit, existing.Digit},
		{namePatternSeparator, existing.PatternSeparator},
		{nameExponentSeparator, existing.ExponentSeparator},
		{nameMinusSign, existing.MinusSign},
	}
	for _, rc := range runeChecks {
		v := getAttr(elem, rc.attr)
		if v == "" {
			continue
		}
		// Only conflict if the property was explicitly set in a prior declaration
		if _, wasSet := prevSet[rc.attr]; !wasSet {
			continue
		}

		newVal := firstRune(v)
		if newVal != rc.cur {
			return staticError(errCodeXTSE1290,
				"conflicting xsl:decimal-format declarations: %s was %q, now %q",
				rc.attr, string(rc.cur), string(newVal))
		}
	}
	// String properties
	if v, present := elem.GetAttribute(nameInfinity); present {
		if _, wasSet := prevSet[nameInfinity]; wasSet && v != existing.Infinity {
			return staticError(errCodeXTSE1290,
				"conflicting xsl:decimal-format declarations: infinity was %q, now %q",
				existing.Infinity, v)
		}
	}

	if v, present := elem.GetAttribute(valueNaN); present {
		if _, wasSet := prevSet[valueNaN]; wasSet && v != existing.NaN {
			return staticError(errCodeXTSE1290,
				"conflicting xsl:decimal-format declarations: NaN was %q, now %q",
				existing.NaN, v)
		}
	}

	return nil
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
	if xdn, ok := elem.GetAttribute(nameXpathDefaultNamespace); ok {
		c.xpathDefaultNS = xdn
	}
	defer func() { c.xpathDefaultNS = savedXPathDefaultNS }()

	// Resolve prefixes using the namespace context in scope at this
	// declaration. Imported modules may bind the same prefix to a different
	// URI than the importing module, so resolution must use the element's own
	// in-scope bindings, and no single flat stylesheet-wide map.
	declNS := c.spaceDeclNamespaces(elem)

	for name := range strings.FieldsSeq(elements) {
		nt := nameTest{ImportPrec: c.importPrec}

		if strings.HasPrefix(name, "Q{") {
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
	uri := ""
	if nt.HasURI {
		uri = nt.URI
	}

	switch {
	case nt.Prefix == "*":
		// "*:local" — local-name wildcard (namespace unconstrained).
		return "L:" + nt.Local
	case nt.Local == "*" && nt.HasURI:
		// "prefix:*" / "Q{uri}*" — namespace wildcard.
		return "N:" + uri
	case nt.Local == "*":
		// "*" — universal wildcard.
		return "U:"
	default:
		// Exact expanded name.
		return "E:" + xdm.ClarkName(uri, nt.Local)
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
	v := getAttr(elem, attr)
	if v == "" {
		return false, false, nil
	}

	if yesNoOnly {
		switch strings.TrimSpace(v) {
		case lexicon.ValueYes:
			return true, true, nil
		case lexicon.ValueNo:
			return false, true, nil
		default:
			return false, false, staticError(errCodeSEPM0016, "%q is not a valid value for xsl:output/@"+attr, v)
		}
	}

	b, ok := parseXSDBool(v)
	if !ok {
		return false, false, staticError(errCodeSEPM0016, "%q is not a valid value for xsl:output/@"+attr, v)
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
		resolved[i] = resolveQName(name, bindings)
	}

	return resolved
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

func (p *parameterDocumentValues) apply(elem *xdm.Element) {
	name := elem.LocalName()
	value := getAttr(elem, "value")

	switch name {
	case paramIndent, paramOmitXMLDeclaration, paramUndeclarePrefixes,
		paramAllowDuplicateNames, paramByteOrderMark, paramEscapeURIAttributes,
		paramIncludeContentType, paramBuildTree:
		p.applyBoolean(name, value)
	case paramMethod, paramEncoding, paramStandalone, paramVersion:
		p.applyIdentity(name, value)
	case paramUseCharacterMaps:
		p.applyCharacterMaps(elem)
	default:
		p.applyPresentation(name, value)
	}
}

func (p *parameterDocumentValues) applyBoolean(name, value string) {
	if value == "" {
		return
	}

	boolean, ok := parseXSDBool(value)
	if !ok {
		return
	}

	switch name {
	case paramIndent:
		if p.output.IndentRaw == "" {
			p.output.Indent = boolean
			p.presence.indent = true
		}
	case paramOmitXMLDeclaration:
		if !p.output.OmitDeclarationExplicit {
			p.output.OmitDeclaration = boolean
			p.output.OmitDeclarationExplicit = true
		}
	case paramUndeclarePrefixes:
		p.output.UndeclarePrefixes = boolean
		p.presence.undeclarePrefixes = true
	case paramAllowDuplicateNames:
		if !p.explicit {
			p.output.AllowDuplicateNames = boolean
			p.presence.allowDuplicateNames = true
			p.explicit = true
		}
	case paramByteOrderMark:
		p.output.ByteOrderMark = boolean
		p.presence.byteOrderMark = true
	case paramEscapeURIAttributes:
		if p.output.EscapeURIAttributes == nil {
			p.output.EscapeURIAttributes = &boolean
		}
	case paramIncludeContentType:
		if p.output.IncludeContentType == nil {
			p.output.IncludeContentType = &boolean
		}
	case paramBuildTree:
		if p.output.BuildTree == nil {
			p.output.BuildTree = &boolean
		}
	}
}

func (p *parameterDocumentValues) applyIdentity(name, value string) {
	if value == "" {
		return
	}

	switch name {
	case paramMethod:
		if p.output.MethodRaw == "" {
			p.output.Method = strings.ToLower(strings.TrimSpace(value))
			p.output.MethodExplicit = true
		}
	case paramEncoding:
		if p.output.EncodingRaw == "" {
			p.output.Encoding = strings.TrimSpace(value)
		}
	case paramVersion:
		if p.output.VersionRaw == "" {
			p.output.Version = strings.TrimSpace(value)
		}
	case paramStandalone:
		if p.output.StandaloneRaw == "" {
			value = strings.TrimSpace(value)
			switch value {
			case lexicon.ValueYes, lexicon.ValueNo, nameOmit:
				p.output.Standalone = value
			}
		}
	}
}

func (p *parameterDocumentValues) applyPresentation(name, value string) {
	if value == "" {
		return
	}

	switch name {
	case paramCDATASectionElements:
		if len(p.output.CDATASections) == 0 {
			p.output.CDATASections = strings.Fields(value)
		}
	case paramDoctypePublic:
		if p.output.DoctypePublic == "" {
			p.output.DoctypePublic = value
		}
	case paramDoctypeSystem:
		if p.output.DoctypeSystem == "" {
			p.output.DoctypeSystem = value
		}
	case paramMediaType:
		if p.output.MediaType == "" {
			p.output.MediaType = value
		}
	case paramItemSeparator:
		if p.output.ItemSeparator == nil {
			p.output.ItemSeparator = &value
		}
	case paramNormalizationForm:
		if p.output.NormalizationForm == "" {
			p.output.NormalizationForm = strings.ToUpper(strings.TrimSpace(value))
		}
	case paramSuppressIndentation:
		if len(p.output.SuppressIndentation) == 0 {
			p.output.SuppressIndentation = strings.Fields(value)
		}
	case paramHTMLVersion:
		if p.output.HTMLVersion == "" {
			p.output.HTMLVersion = strings.TrimSpace(value)
		}
	case paramJSONNodeOutputMethod:
		if p.output.JSONNodeOutputMethod == "" {
			p.output.JSONNodeOutputMethod = strings.TrimSpace(value)
		}
	}
}

func (p *parameterDocumentValues) applyCharacterMaps(elem *xdm.Element) {
	if p.output.ResolvedCharMap == nil {
		p.output.ResolvedCharMap = make(map[rune]string)
	}

	for child := range xdm.Children(elem) {
		mapping, ok := child.(*xdm.Element)
		if !ok || mapping.LocalName() != "character-map" {
			continue
		}

		characters := []rune(getAttr(mapping, "character"))
		if len(characters) != 1 {
			continue
		}

		p.output.ResolvedCharMap[characters[0]] = getAttr(mapping, "map-string")
	}
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
			return staticError(errCodeXTSE0720,
				"attribute-set %q has a circular use-attribute-sets reference", name)
		}

		state[name] = visiting
		if asd := ss.attributeSets[name]; asd != nil {
			for _, ref := range asd.UseAttrSets {
				// use-attribute-sets="xsl:original" refers to the
				// original attribute-set being overridden, not a
				// named attribute-set in the stylesheet.
				if ref == xdm.ClarkName(lexicon.NamespaceXSLT, "original") && asd.OriginalAttrSet != nil {
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
		if !asd.Streamable {
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
		{df.ExponentSeparator, nameExponentSeparator},
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
