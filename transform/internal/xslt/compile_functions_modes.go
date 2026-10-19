// Derived from lestrrat-go/helium at 7362c0a70122a757780f4d0b545a9b370dead6ab.
// Copyright (c) 2015 lestrrat. MIT License; see licenses/MIT-helium.txt at the repository root.

package xslt

import (
	"context"
	"strings"

	"github.com/skarm/xmlsec/internal/xmlchar"
	"github.com/skarm/xmlsec/transform/internal/xdm"
	"github.com/skarm/xmlsec/transform/internal/xdm/lexicon"
	"github.com/skarm/xmlsec/transform/internal/xpath"
)

func (c *compiler) compileGlobalContextItem(ctx context.Context, elem *xdm.Element) error {
	if err := c.validateXSLTAttrs(ctx, elem, attributeNames("as", nameUse, xslAttrUseWhen)); err != nil {
		return err
	}

	asAttr := getAttr(elem, "as")

	// Capture the declaration-site static namespace context BEFORE validating
	// the @as sequence type, so that schema-element()/schema-attribute() (and
	// plain element/attribute tests) resolve their prefixes against the context
	// in scope at this element, and never against the runtime stylesheet-wide
	// map. The in-scope bindings are derived from the element's own and ancestor
	// xmlns declarations on the DOM tree — that is authoritative and immune to
	// pollution of the mutable c.nsBindings by earlier xsl:include processing.
	nsBindings := inScopeNamespaces(elem)

	// xpath-default-namespace on this element takes precedence over the
	// inherited value. An explicitly present empty value clears any inherited
	// default element namespace, so distinguish absent from empty via the
	// presence-aware accessor.
	xpathDefaultNS := c.xpathDefaultNS

	hasXPathDefaultNS := c.xpathDefaultNS != ""
	if xdn, has := elem.GetAttribute(nameXpathDefaultNamespace); has {
		xpathDefaultNS = xdn
		hasXPathDefaultNS = true
	}

	if err := c.validateAsSequenceTypeWithNS(ctx, asAttr, "xsl:global-context-item", nsBindings, xpathDefaultNS, hasXPathDefaultNS); err != nil {
		return err
	}

	def := &globalContextItemDef{
		Use: getAttr(elem, nameUse),
		As:  asAttr,
	}
	if def.Use == "" {
		def.Use = ctxItemOptional
	}

	def.Namespaces = nsBindings
	def.XPathDefaultNS = xpathDefaultNS

	def.HasXPathDefaultNS = hasXPathDefaultNS
	if def.Use == ctxItemAbsent && def.As != "" {
		return staticError(errCodeXTSE3089, "xsl:global-context-item with use=\"absent\" must not specify @as")
	}

	moduleKey := c.moduleKey
	if moduleKey == "" {
		moduleKey = "<main>"
	}

	if c.stylesheet.globalContextModules == nil {
		c.stylesheet.globalContextModules = make(map[string]*globalContextItemDef)
	}
	// XTSE3087: more than one declaration in the same stylesheet module.
	if _, exists := c.stylesheet.globalContextModules[moduleKey]; exists {
		return staticError(errCodeXTSE3087, "multiple xsl:global-context-item declarations in stylesheet module")
	}

	c.stylesheet.globalContextModules[moduleKey] = def

	// XTSE3087: declarations in different modules of one package must agree.
	// Two @as values agree when they denote the same sequence type, which is a
	// namespace-aware notion: a raw text compare wrongly conflicts lexically
	// different but equivalent types (e.g. xs:integer vs a user prefix bound to
	// the XSD namespace) and wrongly accepts lexically equal types that resolve a
	// shared prefix to different namespaces across the two declaration sites.
	// Canonicalize each @as against its own declaration-site namespace context.
	if existing := c.stylesheet.globalContextItem; existing != nil {
		existingKey := canonicalSequenceTypeKey(existing.As,
			nsResolverFromMap(existing.Namespaces), existing.XPathDefaultNS, existing.HasXPathDefaultNS)

		defKey := canonicalSequenceTypeKey(def.As,
			nsResolverFromMap(def.Namespaces), def.XPathDefaultNS, def.HasXPathDefaultNS)
		if existing.Use != def.Use || existingKey != defKey {
			return staticError(errCodeXTSE3087, "conflicting xsl:global-context-item declarations")
		}

		return nil
	}

	c.stylesheet.globalContextItem = def

	return nil
}

// canonicalSequenceTypeKey returns a namespace-resolved canonical string for an
// @as sequence type. It reuses the xpath sequence-type parseOptions AST and the single
// resolveSequenceTypeQName resolver so that the XTSE3087 cross-module agreement
// check compares the meaning of two types, and never their lexical form: two
// declarations agree iff their canonical keys are equal. On a parse failure (the
// type was already rejected upstream) it falls back to whitespace-normalized text.
func canonicalSequenceTypeKey(as string, resolve nsResolver, defaultElemNS string, hasDefaultElemNS bool) string {
	st, err := xpath.ParseSequenceType(strings.TrimSpace(as))
	if err != nil {
		return strings.Join(strings.Fields(as), "")
	}

	var b strings.Builder

	writer := canonicalTypeWriter{b: &b, resolve: resolve, defaultElemNS: defaultElemNS, hasDefaultElemNS: hasDefaultElemNS}
	writer.sequenceType(st)

	return b.String()
}

// inScopeNamespaces returns the in-scope namespace bindings (prefix→URI) for
// elem by walking the DOM tree from the element up through its ancestors.
// Nearer declarations take precedence over more distant ones, matching XML
// namespace scoping. This reflects the namespaces actually written on the
// element and its ancestors, independent of any mutable compiler state.
func inScopeNamespaces(elem *xdm.Element) map[string]string {
	bindings := make(map[string]string)

	for cur := xdm.Node(elem); cur != nil; cur = cur.Parent() {
		ce, ok := cur.(*xdm.Element)
		if !ok {
			continue
		}
		// Closer declarations win: only record a prefix not already seen on a
		// nearer (already-visited) element.
		for _, ns := range ce.Namespaces() {
			if _, seen := bindings[ns.Prefix()]; !seen {
				bindings[ns.Prefix()] = ns.URI()
			}
		}
	}
	// The xml prefix is implicitly in scope on every element (XML Namespaces
	// spec), so it must resolve even without an explicit xmlns:xml declaration.
	// An explicit declaration recorded above takes precedence over this default.
	if _, seen := bindings[lexicon.PrefixXML]; !seen {
		bindings[lexicon.PrefixXML] = lexicon.NamespaceXML
	}

	return bindings
}

func (c *compiler) compileFunction(ctx context.Context, elem *xdm.Element) error {
	defer c.pushElementVersion(elem)()

	if err := c.validateXSLTAttrs(ctx, elem, attributeNames(xslAttrName, "as", xslAttrVisibility, nameStreamable, "streamability", "override-extension-function", xslElemOverride, "identity-sensitive", "cache", "new-each-time", xslAttrUseWhen)); err != nil {
		return err
	}

	name := getAttr(elem, xslAttrName)
	if name == "" {
		return staticError(errCodeXTSE0110, "xsl:function requires name attribute")
	}

	c.collectNamespaces(ctx, elem)

	// Resolve the prefixed name to a QualifiedName
	qn, err := c.functionName(name)
	if err != nil {
		return err
	}

	// XTSE0080: function name must not be in a reserved namespace
	if isReservedFunctionNS(qn.URI) {
		return staticError(errCodeXTSE0080, "xsl:function name %q is in a reserved namespace", name)
	}

	// Handle expand-text on xsl:function (using GetAttribute to catch empty values)
	savedExpandText := c.expandText

	if et, hasET := elem.GetAttribute(nameExpandText); hasET {
		if v, ok := parseXSDBool(et); ok {
			c.expandText = v
		} else {
			return staticError(errCodeXTSE0020, "%q is not a valid value for xsl:function/@expand-text", et)
		}
	}

	if err := validateFunctionOptions(elem); err != nil {
		return err
	}

	// Compile function body (params + instructions)
	_, body, params, err := c.compileTemplateBodyEx(ctx, elem, true)
	c.expandText = savedExpandText

	if err != nil {
		return err
	}

	// XTSE0020: xsl:param inside xsl:function must not have required="no"
	// (function params are implicitly required; required="yes" is allowed as redundant)
	for child := range xdm.Children(elem) {
		childElem, ok := child.(*xdm.Element)
		if !ok {
			continue
		}

		if err := compileFunctionURI(childElem); err != nil {
			return err
		}
	}

	fnAs := getAttr(elem, "as")
	if err := c.validateAsSequenceType(ctx, fnAs, "xsl:function "+name); err != nil {
		return err
	}

	// XTSE3155: xsl:function with no params and streamability != unclassified
	streamability := getAttr(elem, "streamability")
	if streamability == "" {
		streamability = getAttr(elem, nameStreamable)
		switch streamability {
		case lexicon.ValueYes:
			streamability = lexicon.StreamAbsorbing
		case lexicon.ValueNo, "":
			streamability = ""
		}
	}

	if len(params) == 0 && streamability != "" && streamability != lexicon.StreamUnclassified {
		return staticError(errCodeXTSE3155,
			"xsl:function %q with no parameters must not have streamability=%q (only unclassified allowed)", name, streamability)
	}

	fn := &xslFunction{
		Name:          qn,
		Params:        params,
		Body:          body,
		As:            fnAs,
		Cache:         xsdBoolTrue(getAttr(elem, "cache")),
		Streamability: getAttr(elem, "streamability"),
		Visibility:    getAttr(elem, xslAttrVisibility),
		NewEachTime:   getAttr(elem, "new-each-time"),
		ImportPrec:    c.importPrec,
	}
	if c.stylesheet.isPackage {
		fn.OwnerPackage = c.stylesheet
	}

	fn.prepareCall()

	// XTSE0770: it is a static error if a stylesheet contains two or more
	// functions with the same expanded QName, the same arity, and the same
	// import precedence. Functions from different import levels are allowed;
	// the one with the highest precedence wins.
	fk := funcKey{Name: qn, Arity: len(fn.Params)}
	if existing, ok := c.stylesheet.functions[fk]; ok {
		if existing.ImportPrec == fn.ImportPrec {
			return staticError(errCodeXTSE0770,
				"duplicate xsl:function %s with arity %d", name, len(fn.Params))
		}
	}
	// XTSE0770: it is a static error if an xsl:function has the same
	// expanded QName and arity as a schema-defined constructor function.
	c.stylesheet.functions[fk] = fn

	return nil
}

// isReservedFunctionNS returns true if the given namespace URI is reserved
// by the XSLT 3.0 spec and may not be used for user-defined functions.
func isReservedFunctionNS(uri string) bool {
	switch uri {
	case lexicon.NamespaceXSLT, xpath.NSFn, xpath.NSMath, xpath.NSMap, xpath.NSArray, xpath.NSXS:
		return true
	}

	return false
}

func validateFunctionOptions(elem *xdm.Element) error {
	// XTSE0020: validate override-extension-function (boolean)
	if oef, has := elem.GetAttribute("override-extension-function"); has {
		if err := validateBooleanAttr("xsl:function", "override-extension-function", oef); err != nil {
			return err
		}
	}
	// XTSE0020: validate override (boolean)
	if ov, hasOv := elem.GetAttribute(xslElemOverride); hasOv {
		if err := validateBooleanAttr("xsl:function", xslElemOverride, ov); err != nil {
			return err
		}
		// Having both @override and @override-extension-function is only an error
		// when they disagree (XTSE0020 per spec function-0117).
		if oef, hasOEF := elem.GetAttribute("override-extension-function"); hasOEF {
			ovBool, _ := parseXSDBool(ov)

			oefBool, _ := parseXSDBool(oef)
			if ovBool != oefBool {
				return staticError(errCodeXTSE0020,
					"xsl:function has conflicting @override=%q and @override-extension-function=%q", ov, oef)
			}
		}
	}
	// XTSE0020: validate new-each-time (yes|no|maybe)
	if net := getAttr(elem, "new-each-time"); net != "" {
		switch net {
		case lexicon.ValueYes, lexicon.ValueNo, nameMaybe:
			// valid
		default:
			return staticError(errCodeXTSE0020,
				"%q is not a valid value for xsl:function/@new-each-time", net)
		}
	}

	return nil
}

func compileFunctionChildren(childElem *xdm.Element) error {
	for ch := range xdm.Children(childElem) {
		if ch.Type() == xdm.ElementNode {
			return staticError(errCodeXTSE0760,
				"xsl:param %q in xsl:function must not have content", getAttr(childElem, xslAttrName))
		}

		if ch.Type() == xdm.TextNode && !isXMLWhitespaceOnly(xdm.CharacterData(ch)) {
			return staticError(errCodeXTSE0760,
				"xsl:param %q in xsl:function must not have content", getAttr(childElem, xslAttrName))
		}
	}

	return nil
}

func compileFunctionURI(childElem *xdm.Element) error {
	if childElem.URI() == lexicon.NamespaceXSLT && childElem.LocalName() == lexicon.XSLTElementParam {
		if reqVal, hasReq := childElem.GetAttribute(ctxItemRequired); hasReq {
			if reqVal != lexicon.ValueYes && reqVal != "1" && reqVal != lexicon.ValueTrue {
				pname := getAttr(childElem, xslAttrName)

				return staticError(errCodeXTSE0020,
					"xsl:param %q in xsl:function must not have required=%q", pname, reqVal)
			}
		}
		// XTSE0020: tunnel="yes" is not allowed on a function parameter
		if getAttr(childElem, nameTunnel) == lexicon.ValueYes {
			return staticError(errCodeXTSE0020,
				"tunnel=\"yes\" is not allowed on a function parameter")
		}
		// XTSE0760: function params must not have a default value
		if getAttr(childElem, xslAttrSelect) != "" {
			return staticError(errCodeXTSE0760,
				"xsl:param %q in xsl:function must not have a select attribute", getAttr(childElem, xslAttrName))
		}

		if childElem.FirstChild() != nil {
			if err := compileFunctionChildren(childElem); err != nil {
				return err
			}
		}
	}

	return nil
}

func (c *compiler) compileMode(ctx context.Context, elem *xdm.Element) error {
	if err := c.validateXSLTAttrs(ctx, elem, attributeNames(xslAttrName, nameStreamable, "on-no-match", "on-multiple-match", "warning-on-no-match", "warning-on-multiple-match", nameTyped, xslAttrVisibility, xslAttrUseWhen, nameUseAccumulators)); err != nil {
		return err
	}
	// xsl:mode must be empty (no children)
	if elem.FirstChild() != nil {
		return staticError(errCodeXTSE0010, "xsl:mode must be empty")
	}

	md, streamableStr, err := c.modeDefinition(ctx, elem)
	if err != nil {
		return err
	}

	c.mergeModeDefinition(md, streamableStr)

	return nil
}

func (c *compiler) modeDefinition(ctx context.Context, elem *xdm.Element) (*modeDef, string, error) {
	name, err := c.modeDeclarationName(ctx, elem)
	if err != nil {
		return nil, "", err
	}

	streamable, streamableStr, err := parseModeStreamable(elem)
	if err != nil {
		return nil, "", err
	}

	md := &modeDef{Name: name, Streamable: streamable, ImportPrec: c.importPrec}
	if err := readModePolicies(elem, md); err != nil {
		return nil, "", err
	}

	md.UseAccumulators = c.modeAccumulatorNames(elem)
	md.Typed = getAttr(elem, nameTyped)

	return md, streamableStr, nil
}

func parseModeStreamable(elem *xdm.Element) (bool, string, error) {
	streamableStr := strings.TrimSpace(getAttr(elem, nameStreamable))
	streamable := false

	if streamableStr != "" {
		v, ok := parseXSDBool(streamableStr)
		if !ok {
			return false, streamableStr, staticError(errCodeXTSE0020, "invalid value %q for streamable on xsl:mode", streamableStr)
		}

		streamable = v
	}

	return streamable, streamableStr, nil
}

func readModePolicies(elem *xdm.Element, md *modeDef) error {
	// Validate on-no-match
	md.OnNoMatch = strings.TrimSpace(getAttr(elem, "on-no-match"))
	if md.OnNoMatch != "" {
		switch md.OnNoMatch {
		case onNoMatchTextOnlyCopy, onNoMatchShallowCopy, onNoMatchDeepCopy, onNoMatchShallowSkip, onNoMatchDeepSkip, onNoMatchFail:
			// valid
		default:
			return staticError(errCodeXTSE0020, "invalid value %q for on-no-match on xsl:mode", md.OnNoMatch)
		}
	}
	// Note: we keep onNoMatch as "" when not specified, so we can detect
	// conflicts properly. The default "text-only-copy" is applied later.

	if err := validateModeFlags(elem); err != nil {
		return err
	}

	md.Visibility = strings.TrimSpace(getAttr(elem, xslAttrVisibility))
	// XTSE0020: unnamed mode cannot have visibility="public" or "final"
	if md.Name == modeDefault && (md.Visibility == visPublic || md.Visibility == visFinal) {
		return staticError(errCodeXTSE0020, "unnamed mode cannot have visibility %q", md.Visibility)
	}

	md.OnMultipleMatch = strings.TrimSpace(getAttr(elem, "on-multiple-match"))
	if md.OnMultipleMatch != "" {
		switch md.OnMultipleMatch {
		case onMultipleMatchUseLast, onNoMatchFail:
			// valid
		default:
			return staticError(errCodeXTSE0020, "invalid value %q for on-multiple-match on xsl:mode", md.OnMultipleMatch)
		}
	}

	return nil
}

func validateModeFlags(elem *xdm.Element) error {
	// Validate boolean attributes
	if v := getAttr(elem, "warning-on-no-match"); v != "" {
		if _, ok := parseXSDBool(v); !ok {
			return staticError(errCodeXTSE0020, "invalid value %q for warning-on-no-match on xsl:mode", v)
		}
	}

	if v := getAttr(elem, "warning-on-multiple-match"); v != "" {
		if _, ok := parseXSDBool(v); !ok {
			return staticError(errCodeXTSE0020, "invalid value %q for warning-on-multiple-match on xsl:mode", v)
		}
	}

	if v := getAttr(elem, nameTyped); v != "" {
		// typed accepts "yes", "no", "true", "false", "1", "0",
		// "strict", "lax", "unspecified"
		switch v {
		case validationStrict, validationLax, validationUnspecified:
			// valid non-boolean values
		default:
			if _, ok := parseXSDBool(v); !ok {
				return staticError(errCodeXTSE0020, "invalid value %q for typed on xsl:mode", v)
			}
		}
	}

	return nil
}

func (c *compiler) mergeModeDefinition(md *modeDef, streamableStr string) {
	name := md.Name

	if c.stylesheet.modeDefs == nil {
		c.stylesheet.modeDefs = make(map[string]*modeDef)
	}

	// Check for conflicting declarations at the same import precedence
	if existing, ok := c.stylesheet.modeDefs[name]; ok {
		if existing.ImportPrec == c.importPrec {
			mergeSamePrecedenceMode(existing, md, streamableStr != "")

			return
		}
		// Different precedence: higher precedence wins, but inherit
		// unspecified attributes from the lower-precedence declaration.
		c.mergeModeImportPrecedence(existing, md, streamableStr, name)

		return
	}

	c.stylesheet.modeDefs[name] = md
}

func mergeSamePrecedenceMode(existing, md *modeDef, hasStreamable bool) {
	// Same precedence: check for conflicting attribute values (XTSE0545).
	// Instead of erroring immediately, defer the conflict — a higher-
	// precedence declaration may resolve it later.
	if existing.OnNoMatch != "" && md.OnNoMatch != "" && existing.OnNoMatch != md.OnNoMatch {
		existing.conflictOnNoMatch = true
	}

	if hasStreamable && existing.Streamable != md.Streamable {
		existing.conflictStreamable = true
	}

	if existing.Visibility != "" && md.Visibility != "" && existing.Visibility != md.Visibility {
		existing.conflictVisibility = true
	}

	if existing.OnMultipleMatch != "" && md.OnMultipleMatch != "" && existing.OnMultipleMatch != md.OnMultipleMatch {
		existing.conflictOnMultiple = true
	}

	if existing.UseAccumulators != nil && md.UseAccumulators != nil && !sameAccumulatorSet(*existing.UseAccumulators, *md.UseAccumulators) {
		existing.conflictAccumulator = true
	}
	// Non-conflicting: merge attributes (use non-empty values from new decl)
	if md.OnNoMatch != "" {
		existing.OnNoMatch = md.OnNoMatch
	}

	if md.Visibility != "" {
		existing.Visibility = md.Visibility
	}

	if md.OnMultipleMatch != "" {
		existing.OnMultipleMatch = md.OnMultipleMatch
	}

	if md.UseAccumulators != nil {
		existing.UseAccumulators = md.UseAccumulators
	}
}

// sameAccumulatorSet checks whether two use-accumulators values contain
// the same set of accumulator names (order-independent).
func sameAccumulatorSet(a, b string) bool {
	if a == b {
		return true
	}

	as := make(map[string]struct{})
	for s := range strings.FieldsSeq(a) {
		as[s] = struct{}{}
	}

	bs := make(map[string]struct{})
	for s := range strings.FieldsSeq(b) {
		bs[s] = struct{}{}
	}

	if len(as) != len(bs) {
		return false
	}

	for k := range as {
		if _, ok := bs[k]; !ok {
			return false
		}
	}

	return true
}

func (c *compiler) modeDeclarationName(ctx context.Context, elem *xdm.Element) (string, error) {
	name := strings.TrimSpace(getAttr(elem, xslAttrName))
	if name == "" {
		return modeDefault, nil
	}

	if name == modeUnnamed || name == modeAll || name == modeCurrent {
		return "", staticError(errCodeXTSE0020, "invalid mode name %q on xsl:mode", name)
	}

	if name[0] != '#' {
		// Resolve QName to Clark notation so mode declarations and mode
		// references (on xsl:template/@mode, xsl:apply-templates/@mode)
		// use the same key format.
		name = c.resolveMode(ctx, name)
	}

	return name, nil
}

func (c *compiler) modeAccumulatorNames(elem *xdm.Element) *string {
	// Resolve accumulator QNames to expanded names for proper comparison
	// across modules with different namespace prefixes.
	rawUA := getAttr(elem, nameUseAccumulators)
	_, hasUseAccumulators := elem.GetAttribute(nameUseAccumulators)

	var useAccumulators *string

	if hasUseAccumulators {
		var resolvedParts []string

		for tok := range strings.FieldsSeq(rawUA) {
			if tok == "#all" {
				resolvedParts = append(resolvedParts, tok)
			} else {
				resolvedParts = append(resolvedParts, resolveQName(tok, c.nsBindings))
			}
		}

		s := strings.Join(resolvedParts, " ")
		useAccumulators = &s
	}

	return useAccumulators
}

// mergeModeImportPrecedence inherits unspecified mode attributes while retaining
// the declaration with the higher import precedence.
func (c *compiler) mergeModeImportPrecedence(existing, md *modeDef, streamableStr, name string) {
	if c.importPrec > existing.ImportPrec {
		// Preserve conflict flags from the lower-precedence entry,
		// but clear them for attributes the higher-prec explicitly specifies.
		md.conflictStreamable = existing.conflictStreamable && streamableStr == ""
		md.conflictOnNoMatch = existing.conflictOnNoMatch && md.OnNoMatch == ""
		md.conflictVisibility = existing.conflictVisibility && md.Visibility == ""
		md.conflictOnMultiple = existing.conflictOnMultiple && md.OnMultipleMatch == ""
		md.conflictAccumulator = existing.conflictAccumulator && md.UseAccumulators == nil
		// Inherit attributes not explicitly set in higher-precedence decl
		if md.OnNoMatch == "" {
			md.OnNoMatch = existing.OnNoMatch
		}

		if md.OnMultipleMatch == "" {
			md.OnMultipleMatch = existing.OnMultipleMatch
		}

		if md.UseAccumulators == nil {
			md.UseAccumulators = existing.UseAccumulators
		}

		if md.Visibility == "" {
			md.Visibility = existing.Visibility
		}

		c.stylesheet.modeDefs[name] = md
	} else {
		// Lower precedence than existing: merge unspecified attrs into existing.
		if existing.OnNoMatch == "" && md.OnNoMatch != "" {
			existing.OnNoMatch = md.OnNoMatch
		}

		if existing.OnMultipleMatch == "" && md.OnMultipleMatch != "" {
			existing.OnMultipleMatch = md.OnMultipleMatch
		}

		if existing.UseAccumulators == nil && md.UseAccumulators != nil {
			existing.UseAccumulators = md.UseAccumulators
		}

		if existing.Visibility == "" && md.Visibility != "" {
			existing.Visibility = md.Visibility
		}
	}
}

// functionName resolves a function's prefixed QName or EQName in its static context.
func (c *compiler) functionName(name string) (xpath.QualifiedName, error) {
	var qn xpath.QualifiedName

	if strings.HasPrefix(name, "Q{") {
		// EQName: Q{uri}local
		closeBrace := strings.IndexByte(name, '}')
		if closeBrace < 0 {
			return qn, staticError(errCodeXTSE0010, "malformed EQName in xsl:function name %q", name)
		}

		uri := name[2:closeBrace]

		local := name[closeBrace+1:]
		if uri == "" {
			return qn, staticError(errCodeXTSE0010, "xsl:function name %q must be in a non-null namespace", name)
		}

		qn = xpath.QualifiedName{URI: uri, Name: local}
	} else if prefix, local, ok := strings.Cut(name, ":"); ok {
		if !xmlchar.IsValidNCName(prefix) || !xmlchar.IsValidNCName(local) {
			return qn, staticError(errCodeXTSE0020, "xsl:function name %q is not a valid QName", name)
		}

		uri := c.nsBindings[prefix]
		if uri == "" {
			uri = c.stylesheet.namespaces[prefix]
		}

		if uri == "" {
			return qn, staticError(errCodeXTSE0010, "unresolved namespace prefix %q in xsl:function name %q", prefix, name)
		}

		qn = xpath.QualifiedName{URI: uri, Name: local}
	} else {
		return qn, staticError(errCodeXTSE0010, "xsl:function name %q must have a namespace prefix", name)
	}

	return qn, nil
}

type canonicalTypeWriter struct {
	b                *strings.Builder
	resolve          nsResolver
	defaultElemNS    string
	hasDefaultElemNS bool
}

func (writer canonicalTypeWriter) sequenceType(st xdm.SequenceType) {
	if st.Void {
		writer.b.WriteString(nameEmptySequence)
		return
	}

	writer.nodeTest(st.ItemTest)

	switch st.Occurrence {
	case xdm.OccurrenceZeroOrOne:
		writer.b.WriteByte('?')
	case xdm.OccurrenceZeroOrMore:
		writer.b.WriteByte('*')
	case xdm.OccurrenceOneOrMore:
		writer.b.WriteByte('+')
	}
}

// nodeTest writes a canonical, namespace-resolved rendering of a
// sequence-type item test. Every embedded QName is expanded to Q{uri}local form
// (or "*" for an absent/wildcard name) using the position-specific rules of
// resolveSequenceTypeQName, so prefixes and default-namespace differences are
// normalized away.
func (writer canonicalTypeWriter) nodeTest(nt xdm.NodeTest) {
	switch t := nt.(type) {
	case xdm.AtomicOrUnionType:
		qn := t.Name
		if t.Prefix != "" {
			qn = t.Prefix + ":" + t.Name
		}

		writer.qname(qn, qnameTypeName)
	case xdm.ElementTest:
		writer.b.WriteString("element(")
		writer.qname(t.Name, qnameElementName)

		if t.TypeName != "" {
			writer.b.WriteByte(',')
			writer.qname(t.TypeName, qnameTypeName)

			if t.Nillable {
				writer.b.WriteString(",?")
			}
		}

		writer.b.WriteByte(')')
	case xdm.AttributeTest:
		writer.b.WriteString("attribute(")
		writer.qname(t.Name, qnameAttributeName)

		if t.TypeName != "" {
			writer.b.WriteByte(',')
			writer.qname(t.TypeName, qnameTypeName)
		}

		writer.b.WriteByte(')')
	case xdm.SchemaElementTest:
		writer.b.WriteString("schema-element(")
		writer.qname(t.Name, qnameElementName)
		writer.b.WriteByte(')')
	case xdm.SchemaAttributeTest:
		writer.b.WriteString("schema-attribute(")
		writer.qname(t.Name, qnameAttributeName)
		writer.b.WriteByte(')')
	case xdm.DocumentTest:
		writer.b.WriteString("document-node(")

		if t.Inner != nil {
			writer.nodeTest(t.Inner)
		}

		writer.b.WriteByte(')')
	case xdm.PITest:
		writer.b.WriteString("processing-instruction(")
		writer.b.WriteString(t.Target)
		writer.b.WriteByte(')')
	case xdm.TypeTest:
		switch t.Kind {
		case xdm.NodeKindText:
			writer.b.WriteString("text()")
		case xdm.NodeKindComment:
			writer.b.WriteString("comment()")
		case xdm.NodeKindProcessingInstruction:
			writer.b.WriteString("processing-instruction()")
		default:
			writer.b.WriteString("node()")
		}
	case xdm.NamespaceNodeTest:
		writer.b.WriteString("namespace-node()")
	case xdm.AnyItemTest:
		writer.b.WriteString("item()")
	case xdm.NameTest:
		qn := t.Local
		if t.URI != "" {
			qn = "Q{" + t.URI + "}" + t.Local
		} else if t.Prefix != "" {
			qn = t.Prefix + ":" + t.Local
		}

		writer.qname(qn, qnameElementName)
	case xdm.FunctionTest:
		writer.functionTest(t)
	case xdm.MapTest:
		if t.AnyType {
			writer.b.WriteString("map(*)")
			return
		}

		writer.b.WriteString("map(")
		writer.nodeTest(t.KeyType)
		writer.b.WriteByte(',')
		writer.sequenceType(t.ValType)
		writer.b.WriteByte(')')
	case xdm.ArrayTest:
		if t.AnyType {
			writer.b.WriteString("array(*)")
			return
		}

		writer.b.WriteString("array(")
		writer.sequenceType(t.MemberType)
		writer.b.WriteByte(')')
	default:
		// Unknown/absent test: a stable placeholder so two unknowns compare equal
		// without misrepresenting them as item().
		writer.b.WriteString("?unknown?")
	}
}

func (writer canonicalTypeWriter) qname(qname string, kind qnameKind) {
	local, ns := resolveSequenceTypeQName(qname, kind, writer.resolve, writer.defaultElemNS, writer.hasDefaultElemNS)
	if local == "" || local == "*" {
		writer.b.WriteByte('*')
		return
	}

	writer.b.WriteString("Q{")
	writer.b.WriteString(ns)
	writer.b.WriteByte('}')
	writer.b.WriteString(local)
}

func (writer canonicalTypeWriter) functionTest(t xdm.FunctionTest) {
	if t.AnyFunction {
		writer.b.WriteString("function(*)")
		return
	}

	writer.b.WriteString("function(")

	for i, pt := range t.ParamTypes {
		if i > 0 {
			writer.b.WriteByte(',')
		}

		writer.sequenceType(pt)
	}

	writer.b.WriteString(")as")
	writer.sequenceType(t.ReturnType)
}

// isBuiltinXSDLocalName reports whether an unprefixed type name denotes a
// built-in XML Schema type (interpreted in the XSD namespace) per the runtime
// normalizeTypeName mapping, and no user type in no namespace.
func isBuiltinXSDLocalName(local string) bool {
	switch local {
	case lexicon.TypeString, nameInteger, nameDecimal, nameDouble, nameFloat,
		lexicon.TypeBoolean, "date", nameDateTime, nameTime, nameDuration,
		nameDayTimeDuration, nameYearMonthDuration, "anyURI", nameUntypedAtomic:
		return true
	}

	return false
}
