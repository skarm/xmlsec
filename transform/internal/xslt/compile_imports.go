// Derived from lestrrat-go/helium at 7362c0a70122a757780f4d0b545a9b370dead6ab.
// Copyright (c) 2015 lestrrat. MIT License; see licenses/MIT-helium.txt at the repository root.

package xslt

import (
	"context"
	"maps"
	"path"
	"slices"
	"strings"

	"github.com/skarm/xmlsec/internal/tree"
	"github.com/skarm/xmlsec/transform/internal/xdm"
	"github.com/skarm/xmlsec/transform/internal/xdm/lexicon"
	uripath "github.com/skarm/xmlsec/transform/internal/xdm/uri"
	"github.com/skarm/xmlsec/transform/internal/xpath"
)

// enterModuleNamespaceScope establishes the compilation namespace scope for an
// imported/included module root: it snapshots c.nsBindings and c.localExcludes,
// seeds c.nsBindings with the module root's in-scope namespaces (so the module's
// literal result elements see ITS declarations, not a sibling module's), and adds
// the module root's exclude-result-prefixes / extension-element-prefixes to the
// exclusion set (resolved to URIs against the module root's own namespaces, per
// XSLT 3.0 §11.1.3). The returned function restores both maps. Without this, an
// imported module's root namespaces would leak into later-compiled siblings and
// its exclude-result-prefixes would be ignored, so literal result elements emit
// spurious namespace declarations.
func (c *compiler) enterModuleNamespaceScope(root *xdm.Element) func() {
	savedNS := c.nsBindings
	savedExcludes := c.localExcludes
	defaultNS, hasDefault := c.xpathDefaultNS, c.hasXPathDefaultNS
	c.xpathDefaultNS, c.hasXPathDefaultNS = c.declarationDefaultNamespace(root)

	inScope := inScopeNamespaces(root)
	newBindings := make(map[string]string, len(savedNS)+len(inScope))
	maps.Copy(newBindings, savedNS)
	// The module root's in-scope namespaces override any inherited binding.
	maps.Copy(newBindings, inScope)
	c.nsBindings = newBindings

	newExcludes := c.moduleResultPrefixExcludes(root, inScope, savedExcludes)
	if newExcludes != nil {
		c.localExcludes = newExcludes
	}

	return func() {
		c.nsBindings = savedNS
		c.localExcludes = savedExcludes
		c.xpathDefaultNS, c.hasXPathDefaultNS = defaultNS, hasDefault
	}
}

// moduleResultPrefixExcludes resolves a module root's exclude-result-prefixes and
// extension-element-prefixes to the set of namespace URIs to exclude from result
// trees, unioned onto base. inScope is the module root's in-scope namespaces.
// Returns nil when the module declares neither attribute (so the caller keeps the
// existing exclusion map).
func (c *compiler) moduleResultPrefixExcludes(root *xdm.Element, inScope map[string]string, base map[string]struct{}) map[string]struct{} {
	erp := getAttr(root, nameExcludeResultPrefixes)

	eep := getAttr(root, nameExtensionElementPrefixes)
	if erp == "" && eep == "" {
		return nil
	}

	out := make(map[string]struct{}, len(base)+4)
	maps.Copy(out, base)

	addPrefix := func(prefix string) {
		if prefix == lexicon.ModeDefault {
			if uri, ok := inScope[""]; ok && uri != "" {
				out[uri] = struct{}{}
			}

			return
		}

		if uri, ok := inScope[prefix]; ok && uri != "" {
			out[uri] = struct{}{}
		}
	}

	if erp == lexicon.ModeAll {
		for _, uri := range inScope {
			if uri != "" {
				out[uri] = struct{}{}
			}
		}
	} else if erp != "" {
		for prefix := range strings.FieldsSeq(erp) {
			addPrefix(prefix)
		}
	}

	for prefix := range strings.FieldsSeq(eep) {
		addPrefix(prefix)
	}

	return out
}

func (c *compiler) compileImport(ctx context.Context, elem *xdm.Element) error {
	if err := c.validateXSLTAttrs(ctx, elem, attributeNames(nameHref, xslAttrUseWhen)); err != nil {
		return err
	}

	href := getAttr(elem, nameHref)
	if href == "" {
		return staticError(errCodeXTSE0010, "xsl:import requires href attribute")
	}

	return c.loadExternalStylesheet(ctx, stylesheetBaseURI(elem, c.baseURI, c.moduleRoot), href, true)
}

func (c *compiler) resolveIncludeURI(_ context.Context, elem *xdm.Element) (string, string, error) {
	href := getAttr(elem, nameHref)
	if href == "" {
		return "", "", staticError(errCodeXTSE0010, "xsl:include requires href attribute")
	}

	baseURI := stylesheetBaseURI(elem, c.baseURI, c.moduleRoot)

	var fragment string
	if idx := strings.IndexByte(href, '#'); idx >= 0 {
		fragment = href[idx+1:]
		href = href[:idx]
	}

	uri, err := resolveModuleURI(href, baseURI)
	if err != nil {
		return "", "", err
	}

	importKey := uri
	if fragment != "" {
		importKey = uri + "#" + fragment
	}

	return uri, importKey, nil
}

// collectIncludeImports is the first phase of two-phase include processing.
// It loads the included document, caches the parsed root, and recursively
// processes only xsl:import elements (and imports within nested includes).
// This ensures importPrec is finalized before any templates are compiled.
func (c *compiler) collectIncludeImports(ctx context.Context, elem *xdm.Element) error {
	// Check use-when before loading the included file (avoids loading
	// non-existent files when use-when="false()").
	if uw := getAttr(elem, xslAttrUseWhen); uw != "" {
		include, err := c.evaluateDeclarationUseWhen(ctx, elem, uw)
		if err != nil {
			return err
		}

		if !include {
			return nil
		}
	}

	uri, importKey, err := c.resolveIncludeURI(ctx, elem)
	if err != nil {
		return err
	}

	restore, err := c.enterModule(importKey, false)
	if err != nil {
		return err
	}
	defer restore()

	root, err := c.loadAndCacheInclude(ctx, uri, importKey)
	if err != nil {
		return err
	}

	if c.includedDeclarationRoots == nil {
		c.includedDeclarationRoots = make(map[*xdm.Element]*xdm.Element)
	}

	c.includedDeclarationRoots[elem] = root

	if root == nil {
		// Simplified stylesheet — no imports to collect.
		return nil
	}

	savedBase := c.baseURI

	c.baseURI = moduleEffectiveBaseURI(root, uri)
	defer func() { c.baseURI = savedBase }()

	savedModuleKey := c.moduleKey

	c.moduleKey = importKey
	defer func() { c.moduleKey = savedModuleKey }()

	savedModuleRoot := c.moduleRoot

	c.moduleRoot = embeddedModuleRoot(root)
	defer func() { c.moduleRoot = savedModuleRoot }()

	// Seed the module root's namespaces into a SCOPED nsBindings so this phase's
	// namespace-alias/nested-import processing resolves prefixes against the
	// included module's own declarations, then restore on return so they do not
	// leak into later-compiled sibling modules. collectNamespaces still populates
	// c.stylesheet.namespaces (global, for XPath QName resolution).
	restoreNS := c.enterModuleNamespaceScope(root)
	defer restoreNS()

	c.collectNamespaces(ctx, root)

	if err := c.validateModuleImportOrder(ctx, root); err != nil {
		return err
	}

	if err := c.collectTopLevelImports(ctx, root); err != nil {
		return err
	}

	if err := c.validatePreparedLanguage(root); err != nil {
		return err
	}

	if err := validateTopLevelText(root); err != nil {
		return err
	}

	restoreVersion := c.pushElementVersion(root)
	err = c.validateKnownElementAttributes(ctx, root)

	restoreVersion()

	if err != nil {
		return err
	}

	return c.collectTopLevelNamespaceAliases(ctx, root)
}

// loadModuleDoc resolves, reads, and parses a stylesheet module document at uri.
// It enforces the opt-in URIResolver requirement (XTSE0165) and returns the
// parsed document; callers handle module-doc registration and base-URI/fragment
// bookkeeping. The resolved resource is closed before returning.
func (c *compiler) loadModuleDoc(ctx context.Context, uri string) (*xdm.Document, error) {
	if c.resolver == nil {
		return nil, staticError(errCodeXTSE0165, "cannot load %q: no URIResolver configured (filesystem access is opt-in; set Compiler.URIResolver)", uri)
	}

	rc, resolveErr := c.resolver.Resolve(ctx, uri)
	if resolveErr != nil {
		return nil, staticErrorCause(errCodeXTSE0165, resolveErr, "cannot resolve %q: %v", uri, resolveErr)
	}

	doc, err := parseXMLResource(ctx, c.parseOptions, rc, uri, c.maxResourceBytes)
	if err != nil {
		return nil, staticErrorCause(errCodeXTSE0165, err, "cannot parse %q: %v", uri, err)
	}

	original := doc

	doc, err = prepareModule(ctx, doc, c.stylesheet.processorLanguage())
	if err != nil {
		return nil, err
	}

	if doc != original {
		if c.moduleSources == nil {
			c.moduleSources = make(map[*xdm.Document]*xdm.Document)
		}

		c.moduleSources[doc] = original
	}

	return doc, nil
}

// loadAndCacheInclude loads a stylesheet document and caches its root element.
func (c *compiler) loadAndCacheInclude(ctx context.Context, uri, importKey string) (*xdm.Element, error) {
	if root, ok := c.includeRoots[importKey]; ok {
		return root, nil
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	doc, err := c.loadModuleDoc(ctx, uri)
	if err != nil {
		return nil, err
	}

	if c.stylesheet.moduleDocs == nil {
		c.stylesheet.moduleDocs = make(map[string]*xdm.Document)
	}

	c.stylesheet.moduleDocs[uri] = c.sourceModule(doc)

	// Handle fragment identifiers (importKey = uri + "#" + fragment)
	var fragment string
	if uri != importKey && len(importKey) > len(uri)+1 && importKey[len(uri)] == '#' {
		fragment = importKey[len(uri)+1:]
	}

	if err := c.checkFragment10(doc, fragment); err != nil {
		return nil, err
	}

	var root *xdm.Element
	if fragment != "" {
		root = findElementByID(doc, fragment)
		if root == nil {
			return nil, staticError(errCodeXTSE0010, "no element with id=%q in %q", fragment, uri)
		}
	} else {
		if _, err := CheckProcessorLanguage(doc, 0, c.stylesheet.processorLanguage()); err != nil {
			return nil, err
		}

		root = doc.DocumentElement()
	}

	if root == nil {
		return nil, staticError(errCodeXTSE0010, "included document %q is not a stylesheet", uri)
	}

	if root.URI() != lexicon.NamespaceXSLT {
		expanded, err := expandSimplifiedModule(ctx, doc, root)
		if err != nil {
			return nil, err
		}

		if c.moduleSources == nil {
			c.moduleSources = make(map[*xdm.Document]*xdm.Document)
		}

		c.moduleSources[expanded] = c.sourceModule(doc)
		doc, root = expanded, expanded.DocumentElement()
	}

	// Also cache the module document under its FOLDED effective base (the
	// xml:base ancestor chain folded into the module URI — the module root's own
	// xml:base for a document root, plus wrapper/document xml:base for an embedded
	// root). This module's templates compile with BaseURI =
	// moduleEffectiveBaseURI(root, uri), and doc('')/document('') from within the
	// module looks up moduleDocs by that folded key; without this entry the lookup
	// misses and wrongly falls back to the principal stylesheet. The bare-uri
	// entry above is kept for other lookups; when no xml:base applies the folded
	// base equals uri and this is a no-op.
	if effBase := moduleEffectiveBaseURI(root, uri); effBase != uri {
		c.stylesheet.moduleDocs[effBase] = c.sourceModule(doc)
	}

	// Check use-when on the included/imported stylesheet's root element.
	// If use-when evaluates to false, skip the entire module. Evaluate against
	// the module's effective static base (its root xml:base folded into the
	// module URI) so doc-available()/doc() in the root use-when resolve like the
	// module's own globals, not the including module's base.
	savedBase := c.baseURI
	c.baseURI = moduleEffectiveBaseURI(root, uri)
	_, conditionalErr := c.preprocessConditionalElement(ctx, root, true)
	c.baseURI = savedBase

	if conditionalErr != nil {
		return nil, conditionalErr
	}

	c.includeRoots[importKey] = root

	return root, nil
}

// compileIncludeTemplates is the second phase of two-phase include processing.
// It compiles all non-import declarations from the cached included document
// in document order, interleaving with nested includes' templates.
func (c *compiler) compileIncludeTemplates(ctx context.Context, elem *xdm.Element) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	uri, importKey, err := c.resolveIncludeURI(ctx, elem)
	if err != nil {
		return err
	}

	root := c.includeRoots[importKey]
	if root == nil {
		return c.loadExternalStylesheet(ctx, stylesheetBaseURI(elem, c.baseURI, c.moduleRoot), getAttr(elem, nameHref), false)
	}

	savedBase := c.baseURI

	c.baseURI = moduleEffectiveBaseURI(root, uri)
	defer func() { c.baseURI = savedBase }()

	savedModuleKey := c.moduleKey

	c.moduleKey = importKey
	defer func() { c.moduleKey = savedModuleKey }()

	savedModuleRoot := c.moduleRoot

	c.moduleRoot = embeddedModuleRoot(root)
	defer func() { c.moduleRoot = savedModuleRoot }()

	// Establish the included module's namespace scope for its template phase: its
	// root namespaces (so literal result elements declare ITS namespaces, not the
	// including module's) and its exclude-result-prefixes / extension-element-prefixes.
	defer c.enterModuleNamespaceScope(root)()

	// Apply xpath-default-namespace from included module root. Presence (even an
	// empty value, which resets to no-namespace) overrides the importing
	// module's default; absence inherits it.
	savedXPathDefaultNS := c.xpathDefaultNS

	savedHasXPathDefaultNS := c.hasXPathDefaultNS
	if xdn, ok := root.GetAttribute(nameXpathDefaultNamespace); ok {
		c.xpathDefaultNS = xdn
		c.hasXPathDefaultNS = true
	}
	defer func() {
		c.xpathDefaultNS = savedXPathDefaultNS
		c.hasXPathDefaultNS = savedHasXPathDefaultNS
	}()

	// The included module's version governs backwards-/forwards-compatible
	// processing of its own declarations (XSLT 3.0 §3.10), independent of the
	// including module's version. A _version shadow attribute takes precedence
	// over the literal (§3.5.2), so resolve it first — mirroring the top-level
	// root — so an included module whose computed version is < 2.0 enters
	// backwards-compatible mode.
	savedVersion := c.effectiveVersion
	if _, hasShadow := root.GetAttribute("_version"); hasShadow {
		if err := c.resolveSingleShadowAttribute(ctx, root, paramVersion); err != nil {
			return err
		}
	}

	if ver := getAttr(root, paramVersion); ver != "" {
		c.effectiveVersion = ver
	}

	defer func() { c.effectiveVersion = savedVersion }()

	if err := c.checkModuleInputAnnotations(root, "included"); err != nil {
		return err
	}

	return c.compileTopLevelDeclarations(ctx, root)
}

// checkModuleInputAnnotations reconciles the shared strip/preserve setting,
// retaining unspecified until a module supplies an explicit value.
func (c *compiler) checkModuleInputAnnotations(root *xdm.Element, relation string) error {
	moduleValue := getAttr(root, nameInputTypeAnnotations)
	if moduleValue == "" || moduleValue == validationUnspecified {
		return nil
	}

	mainValue := c.stylesheet.inputTypeAnnotations
	if mainValue != "" && mainValue != validationUnspecified && mainValue != moduleValue {
		return staticError(errCodeXTSE0265,
			"conflicting input-type-annotations: main module has %q, %s module has %q",
			mainValue, relation, moduleValue)
	}

	if mainValue == "" || mainValue == validationUnspecified {
		c.stylesheet.inputTypeAnnotations = moduleValue
	}

	return nil
}

func (c *compiler) loadExternalStylesheet(ctx context.Context, baseURI, href string, isImport bool) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	// Extract fragment identifier (e.g. "file.xml#embedded" → fragment="embedded").
	// The fragment selects an embedded stylesheet element by ID within the document.
	var fragment string
	if idx := strings.IndexByte(href, '#'); idx >= 0 {
		fragment = href[idx+1:]
		href = href[:idx]
	}

	// Resolve URI relative to base. An absolute-URI href is passed through
	// uncorrupted; a relative href is resolved against the base.
	uri, err := resolveModuleURI(href, baseURI)
	if err != nil {
		return err
	}

	// Circular import detection (use uri+fragment for uniqueness)
	importKey := uri
	if fragment != "" {
		importKey = uri + "#" + fragment
	}

	restore, err := c.enterModule(importKey, isImport)
	if err != nil {
		return err
	}
	defer restore()

	doc, err := c.loadModuleDoc(ctx, uri)
	if err != nil {
		return err
	}

	if err := c.checkFragment10(doc, fragment); err != nil {
		return err
	}

	savedBase := c.baseURI

	c.baseURI = uri
	defer func() { c.baseURI = savedBase }()

	savedModuleKey := c.moduleKey

	c.moduleKey = importKey
	defer func() { c.moduleKey = savedModuleKey }()

	// Store the module document for document("") resolution.
	if c.stylesheet.moduleDocs == nil {
		c.stylesheet.moduleDocs = make(map[string]*xdm.Document)
	}

	c.stylesheet.moduleDocs[uri] = c.sourceModule(doc)

	// When a fragment identifier is present, locate the embedded stylesheet
	// element by its ID attribute instead of using the document element.
	var importedRoot *xdm.Element
	if fragment != "" {
		importedRoot = findElementByID(doc, fragment)
		if importedRoot == nil {
			return staticError(errCodeXTSE0010, "no element with id=%q in %q", fragment, uri)
		}
	} else {
		if _, err := CheckProcessorLanguage(doc, 0, c.stylesheet.processorLanguage()); err != nil {
			return err
		}

		importedRoot = doc.DocumentElement()
	}

	if importedRoot == nil {
		return staticError(errCodeXTSE0010, "imported document %q is not a stylesheet", uri)
	}
	// XTSE0165: a package must not import another package via xsl:import.
	if isImport && importedRoot.URI() == lexicon.NamespaceXSLT && importedRoot.LocalName() == lexicon.XSLTElementPackage {
		return staticError(errCodeXTSE0165,
			"cannot import xsl:package %q (use xsl:use-package instead)", uri)
	}

	if importedRoot.URI() != lexicon.NamespaceXSLT {
		expanded, err := expandSimplifiedModule(ctx, doc, importedRoot)
		if err != nil {
			return err
		}

		if c.moduleSources == nil {
			c.moduleSources = make(map[*xdm.Document]*xdm.Document)
		}

		c.moduleSources[expanded] = c.sourceModule(doc)
		doc, importedRoot = expanded, expanded.DocumentElement()
	}

	return c.compileExternalModule(ctx, doc, importedRoot, uri, isImport)
}

// expandSimplifiedModule applies the equivalence in XSLT section 3.8. The
// original source remains available to document(""); only a private module tree
// receives the implicit stylesheet/template wrappers.
func expandSimplifiedModule(ctx context.Context, doc *xdm.Document, root *xdm.Element) (*xdm.Document, error) {
	version := root.GetAttributeNodeNS(paramVersion, lexicon.NamespaceXSLT)
	if version == nil {
		return nil, staticError(errCodeXTSE0150, "simplified stylesheet requires xsl:version")
	}

	_, raw := tree.UnwrapNode(root.Reference())

	cloned, err := tree.Clone(ctx, tree.FromNodes([]*tree.Node{tree.ExtractSubtree(raw)}, tree.DefaultLimits()))
	if err != nil {
		return nil, err
	}

	literal := tree.Root(cloned)

	wrapper := &tree.Node{
		Kind: tree.ElementNode, Name: tree.Name{Space: lexicon.NamespaceXSLT, Local: nameStylesheet}, Prefix: version.Prefix(), SourceLine: literal.SourceLine,
		NS: []tree.Namespace{{Prefix: version.Prefix(), URI: lexicon.NamespaceXSLT}}, Attrs: []tree.Attribute{{Name: tree.Name{Local: paramVersion}, Value: version.Value()}},
	}
	if base := xpath.NodeBaseURI(root.Parent()); base != "" && base != doc.URL() {
		wrapper.Attrs = append(wrapper.Attrs, tree.Attribute{Name: tree.Name{Space: lexicon.NamespaceXML, Local: "base"}, Prefix: "xml", Value: base})
	}

	tmpl := &tree.Node{
		Kind: tree.ElementNode, Name: tree.Name{Space: lexicon.NamespaceXSLT, Local: nameTemplate}, Prefix: version.Prefix(), SourceLine: literal.SourceLine, Parent: wrapper,
		Attrs: []tree.Attribute{{Name: tree.Name{Local: lexicon.AttrMatch}, Value: "/"}}, Children: []*tree.Node{literal},
	}
	literal.Parent = tmpl
	wrapper.Children = []*tree.Node{tmpl}

	prepared, err := xdm.WrapDocument(ctx, tree.FromNodes([]*tree.Node{wrapper}, tree.DefaultLimits()))
	if err != nil {
		return nil, err
	}

	prepared.SetURL(doc.URL())

	return prepared, nil
}

func (c *compiler) compileExternalModule(ctx context.Context, doc *xdm.Document, importedRoot *xdm.Element, uri string, isImport bool) error {
	// Fold the module root's xml:base chain into the effective static base URI so
	// this module's globals and templates resolve relative references against the
	// declaration-site base (matching the main module's compile() handling), not
	// the bare module URI. For an EMBEDDED (fragment-selected) root this folds the
	// embedded root's own xml:base plus any wrapper/document xml:base; moduleRoot
	// is set so descendant xml:base walks stop at the embedded root and don't
	// re-apply that chain. moduleDocs stays keyed on the unmodified uri too.
	c.baseURI = moduleEffectiveBaseURI(importedRoot, uri)
	savedModuleRoot := c.moduleRoot

	c.moduleRoot = embeddedModuleRoot(importedRoot)
	defer func() { c.moduleRoot = savedModuleRoot }()

	// Also cache the module document under its FOLDED effective base so doc('') /
	// document('') from within this module (whose templates compile under
	// c.baseURI) resolves to the module's own document, falling back to no
	// principal stylesheet. The bare-uri entry stored above is kept for other
	// lookups; when no xml:base applies the folded base equals uri and this is a
	// no-op.
	if c.baseURI != uri {
		c.stylesheet.moduleDocs[c.baseURI] = c.sourceModule(doc)
	}

	// Check use-when on the imported/included stylesheet's root element. If
	// use-when evaluates to false, skip the entire module. moduleEffectiveBaseURI
	// already gives the module's full effective base (folding the embedded root's
	// xml:base and any wrapper/document xml:base for a fragment-selected root), so
	// c.baseURI is the correct base for the root use-when.
	if _, err := c.preprocessConditionalElement(ctx, importedRoot, true); err != nil {
		return err
	}

	// Save/restore expand-text: each stylesheet module has its own setting.
	savedExpandText := c.expandText
	c.expandText = false // default for new module

	if et, hasET := importedRoot.GetAttribute(nameExpandText); hasET {
		if v, ok := parseXSDBool(et); ok {
			c.expandText = v
		}
	}

	defer func() { c.expandText = savedExpandText }()

	// Save/restore effective version; a _version shadow attribute takes precedence
	// over the literal (§3.5.2), so resolve it first — mirroring the top-level root
	// and included modules — so an imported module whose computed version is < 2.0
	// enters backwards-compatible mode.
	savedVersion := c.effectiveVersion
	if _, hasShadow := importedRoot.GetAttribute("_version"); hasShadow {
		if err := c.resolveSingleShadowAttribute(ctx, importedRoot, paramVersion); err != nil {
			return err
		}
	}

	if ver := getAttr(importedRoot, paramVersion); ver != "" {
		c.effectiveVersion = ver
	}

	defer func() { c.effectiveVersion = savedVersion }()

	if err := c.checkModuleInputAnnotations(importedRoot, "imported"); err != nil {
		return err
	}

	if isImport {
		// For imports: the imported stylesheet gets current (lower) precedence.
		// After compiling, increment so the importing module's remaining
		// templates get a higher precedence.
		//
		// Set minImportPrec so the imported module's templates know the
		// boundary of their own import tree (for xsl:apply-imports).
		savedMinImportPrec := c.minImportPrec
		c.minImportPrec = c.importPrec
		savedInsideImport := c.insideImport
		c.insideImport = true
		restoreNS := c.enterModuleNamespaceScope(importedRoot)
		c.collectNamespaces(ctx, importedRoot)

		if err := c.compileTopLevel(ctx, importedRoot); err != nil {
			restoreNS()

			c.minImportPrec = savedMinImportPrec
			c.insideImport = savedInsideImport

			return err
		}

		restoreNS()

		c.minImportPrec = savedMinImportPrec
		c.insideImport = savedInsideImport
		c.importPrec++
	} else {
		// Include: same precedence as the including module.
		// Inherit minImportPrec from the including module so that
		// xsl:apply-imports in included templates searches the
		// including module's full import tree.
		restoreNS := c.enterModuleNamespaceScope(importedRoot)
		c.collectNamespaces(ctx, importedRoot)

		if err := c.compileTopLevel(ctx, importedRoot); err != nil {
			restoreNS()
			return err
		}

		restoreNS()
	}

	return nil
}

// resolveModuleURI resolves an xsl:include / xsl:import href (with any fragment
// already stripped) against the stylesheet base URI.
//
// An absolute-URI href (it carries its own scheme, e.g. "urn:shared",
// "file:/modules/m.xsl", "mem:/m.xsl") addresses its own location and is
// returned UNCHANGED — it must never be filepath.Join'ed onto the base, which
// would corrupt it (e.g. "/styles/urn:shared"). A relative href against a URI
// base is resolved with RFC 3986 semantics; against a local filesystem base it
// uses filepath.Join semantics. Resolution is delegated to
// [uripath.ResolveSchemaURI] / [uripath.URIScheme] — the single canonical URI helper
// shared with the schema loader — so the two layers cannot drift. Windows
// drive-letter paths (single-letter "scheme") stay filesystem paths.
func resolveModuleURI(href, baseURI string) (string, error) {
	if href == "" || baseURI == "" {
		return href, nil
	}
	// A Windows drive-letter href ("C:/..." or "C:\\...") is a filesystem path,
	// not a URI: its single-letter "scheme" is rejected by uripath.URIScheme, so
	// without this branch it would fall through to ResolveSchemaURI and be
	// lowercased / dot-segment-mangled by RFC 3986 resolution against a URI
	// base. Address its own location verbatim. This must run BEFORE the URI
	// branch below.
	if isWindowsDrivePath(href) {
		return href, nil
	}
	// Absolute-URI href, or any href against a URI base: defer to the shared
	// canonical resolver (RFC 3986 + OmitHost preservation).
	if uripath.URIScheme(href) != "" || uripath.URIScheme(baseURI) != "" {
		return uripath.ResolveSchemaURI(href, baseURI) //nolint:wrapcheck // static error passthrough
	}
	// Local filesystem base (a FILE path): resolve with forward-slash (path)
	// semantics so the result uses '/' on every OS. A Windows-absolute href was
	// already handled by isWindowsDrivePath above; uripath.IsAbsolutePath here
	// keeps a POSIX-absolute href verbatim. On Windows filepath.Dir/Join would
	// emit '\' and corrupt a virtual or POSIX-shaped base (e.g. "/virtual/x.xsl"
	// against href "common.xsl" -> "\\virtual\\common.xsl"), missing a resolver
	// keyed on the forward-slash form.
	if uripath.IsAbsolutePath(href) {
		return href, nil
	}

	return uripath.JoinLocalBaseDir(path.Dir(uripath.ToSlash(baseURI)), href), nil
}

// isWindowsDrivePath reports whether s begins with a Windows drive-letter prefix
// ("C:/" or "C:\\"). Such paths are local filesystem paths, not URI references:
// their single-letter "scheme" is deliberately not recognized by uripath.URIScheme,
// so they must be handled as filesystem paths before any URI resolution.
func isWindowsDrivePath(s string) bool {
	if len(s) < 3 {
		return false
	}

	c := s[0]
	if (c < 'A' || c > 'Z') && (c < 'a' || c > 'z') {
		return false
	}

	return s[1] == ':' && (s[2] == '/' || s[2] == '\\')
}

// moduleEffectiveBaseURI computes the effective static base URI against which an
// included/imported stylesheet module's root use-when, globals, and templates
// resolve relative references (doc(), unparsed-text(), document(”), etc.).
//
// The MAIN module gets this treatment in compile() via resolveRootXMLBase, but
// external modules are loaded with c.baseURI set to the bare module URI and
// compiled directly (loadExternalStylesheet → compileTopLevel; or the two-phase
// include path). Without this, a root xml:base on an included/imported module
// is silently dropped and its globals resolve against the bare module URI
// instead of the declaration-site static base.
//
// For a module root that IS the document element, only its own xml:base is
// folded (via resolveRootXMLBase). For an EMBEDDED module root (one selected by
// a fragment identifier, whose parent is another element and not the
// Document) the FULL xml:base ancestor chain — the embedded root's own xml:base,
// any wrapper element xml:base(s), and the document element's xml:base — is
// folded onto the module URI, because all of those ancestors lie above the
// module root and so are NOT visited by the descendant stylesheetBaseURI walk
// (which stops at the module root). The computed base is therefore the single
// authoritative base for the whole module: c.baseURI, the moduleDocs key, and
// the boundary that descendant walks stop at.
func moduleEffectiveBaseURI(root *xdm.Element, uri string) string {
	if _, isDoc := root.Parent().(*xdm.Document); isDoc {
		if xmlBase, present := root.GetAttributeNS("base", lexicon.NamespaceXML); present {
			return resolveRootXMLBase(uri, xmlBase)
		}

		return uri
	}
	// Embedded module root: fold every xml:base from the embedded root up
	// through the document element onto the module URI.
	var bases []string

	for cur := xdm.Node(root); cur != nil; cur = cur.Parent() {
		elem, ok := cur.(*xdm.Element)
		if !ok {
			continue
		}

		if xmlBase, ok := elem.GetAttributeNS("base", lexicon.NamespaceXML); ok {
			bases = append(bases, xmlBase)
		}
	}

	return foldXMLBases(uri, bases)
}

// embeddedModuleRoot reports root as an EMBEDDED (fragment-selected) stylesheet
// module root — its parent is an element, and not the Document — otherwise
// nil. The result is assigned to c.moduleRoot so descendant xml:base walks stop
// at the embedded root (whose xml:base, plus any wrapper/document xml:base, is
// already folded into the module's effective base URI by moduleEffectiveBaseURI).
// A nil result restores the document-root boundary ("stop before the document
// element"), which is correct for a non-embedded module's own document tree.
func embeddedModuleRoot(root *xdm.Element) *xdm.Element {
	if _, isDoc := root.Parent().(*xdm.Document); isDoc {
		return nil
	}

	return root
}

// stylesheetBaseURI folds the xml:base of n and its ancestors onto fallback,
// yielding the effective static base URI for a node WITHIN a stylesheet module.
// The walk stops at the module root (stopAt, the embedded stylesheet element for
// a fragment-selected module) — or, when stopAt is nil, before the document
// element — because the module root's xml:base (and everything above it) is
// already folded into fallback (the module's effective base URI), so re-applying
// it would double-count.
func stylesheetBaseURI(n xdm.Node, fallback string, stopAt *xdm.Element) string {
	var bases []string

	for cur := n; cur != nil; cur = cur.Parent() {
		elem, ok := cur.(*xdm.Element)
		if !ok {
			continue
		}

		if stopAt != nil {
			if elem == stopAt {
				break
			}
		} else if p := elem.Parent(); p != nil {
			// Stop before the document element (stylesheet root). Its xml:base is
			// already factored into fallback, so including it again double-counts.
			if _, isDoc := p.(*xdm.Document); isDoc {
				break
			}
		}

		if xmlBase, ok := elem.GetAttributeNS("base", lexicon.NamespaceXML); ok {
			bases = append(bases, xmlBase)
		}
		// An external parsed entity supplies a new physical base, independent
		// of the containing stylesheet's URI and ancestor xml:base values.
		if override := xdm.NodeBaseOverride(elem); override != "" {
			return foldXMLBases(override, bases)
		}
	}

	return foldXMLBases(fallback, bases)
}

// foldXMLBases folds a bottom-up-ordered slice of xml:base reference values onto
// base per RFC 3986. bases[0] is the nearest (deepest) xml:base, so the slice is
// applied from the topmost ancestor down and the deepest value wins.
func foldXMLBases(base string, bases []string) string {
	for _, v := range slices.Backward(bases) {
		if base == "" {
			base = v
			continue
		}

		resolved := xdm.BuildURI(v, base)
		// Per RFC 3986, resolving a directory-denoting reference (one that ends
		// in '/', or whose last segment is "." / "..") yields a base that itself
		// names a directory and so ends in '/'. xdm.BuildURI strips that
		// trailing slash, which would make a directory base such as the result of
		// xml:base=".." ("…/tests/fn/") indistinguishable from a stylesheet FILE
		// base ("…/tests/fn") — so a later sibling reference resolved through
		// documentBaseDir (path.Dir) would drop the real "fn" segment. Restore the
		// RFC-correct trailing slash so the directory form is preserved, inserting
		// it into the PATH (before any '?'/'#') so a directory base carrying a
		// query ("…/dir?v") becomes "…/dir/?v", never "…/dir?v/".
		if resolved != "" && refDenotesDirectory(v) {
			resolved = ensureDirSlash(resolved)
		}

		base = resolved
	}

	return base
}

// refDenotesDirectory reports whether a URI reference names a directory rather
// than a file, i.e. resolving it per RFC 3986 produces a base ending in '/'. A
// reference denotes a directory when its PATH portion ends in '/' or its last
// path segment is "." or ".." (a pure dot-segment that resolves to the
// containing directory). The query/fragment is excluded from the test, and a
// reference with an empty path portion (query-only "?v" or fragment-only
// "#frag") is NOT directory-denoting — path.Base("") == "." must not be
// mistaken for a "." dot-segment.
func refDenotesDirectory(ref string) bool {
	pathPart := ref
	if i := strings.IndexAny(pathPart, "?#"); i >= 0 {
		pathPart = pathPart[:i]
	}

	if pathPart == "" {
		return false
	}

	if strings.HasSuffix(pathPart, "/") {
		return true
	}

	last := path.Base(pathPart)

	return last == "." || last == ".."
}

// ensureDirSlash guarantees that the PATH portion of a resolved URI ends in
// '/', inserting the slash before any query ('?') or fragment ('#') component,
// and never at the very end. A directory base carrying a query ("…/dir?v")
// thus becomes "…/dir/?v", never "…/dir?v/" (which would corrupt the query and
// misplace the directory boundary). Idempotent when the path already ends in
// '/'.
func ensureDirSlash(uri string) string {
	pathEnd := len(uri)
	if i := strings.IndexAny(uri, "?#"); i >= 0 {
		pathEnd = i
	}

	if pathEnd > 0 && uri[pathEnd-1] == '/' {
		return uri
	}

	return uri[:pathEnd] + "/" + uri[pathEnd:]
}

// findElementByID performs a depth-first search for an element whose "id"
// attribute matches the given value. This is used for embedded stylesheet
// modules referenced via fragment identifiers (e.g. "file.xml#embedded").
func findElementByID(doc *xdm.Document, id string) *xdm.Element {
	var walk func(xdm.Node) *xdm.Element

	walk = func(n xdm.Node) *xdm.Element {
		for child := range xdm.Children(n) {
			elem, ok := child.(*xdm.Element)
			if !ok {
				continue
			}

			if v, found := elem.GetAttribute("id"); found && v == id {
				return elem
			}

			if v, found := elem.GetAttributeNS("id", lexicon.NamespaceXML); found && v == id {
				return elem
			}

			if result := walk(elem); result != nil {
				return result
			}
		}

		return nil
	}

	return walk(doc)
}

// moduleLoad records the edge entering a module; a cycle contains its closing
// edge and the edges after the earlier occurrence of that module.
type moduleLoad struct {
	URI    string
	Import bool
}

func (c *compiler) enterModule(uri string, imported bool) (func(), error) {
	if position, found := c.importStack[uri]; found {
		hasImport := imported

		cycle := make([]string, 0, len(c.modulePath)-position+1)
		for index, frame := range c.modulePath[position:] {
			if index > 0 {
				hasImport = hasImport || frame.Import
			}

			cycle = append(cycle, frame.URI)
		}

		cycle = append(cycle, uri)

		code := errCodeXTSE0180
		if hasImport {
			code = errCodeXTSE0210
		}

		return nil, staticError(code, "circular import/include: %s", strings.Join(cycle, " -> "))
	}

	c.importStack[uri] = len(c.modulePath)
	c.modulePath = append(c.modulePath, moduleLoad{URI: uri, Import: imported})

	return func() {
		c.modulePath = c.modulePath[:len(c.modulePath)-1]
		delete(c.importStack, uri)
	}, nil
}
