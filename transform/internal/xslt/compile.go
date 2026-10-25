// Derived from lestrrat-go/helium at 7362c0a70122a757780f4d0b545a9b370dead6ab.
// Copyright (c) 2015 lestrrat. MIT License; see licenses/MIT-helium.txt at the repository root.

package xslt

import (
	"context"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/skarm/xmlsec/internal/xmlchar"
	"github.com/skarm/xmlsec/transform/internal/xdm"
	"github.com/skarm/xmlsec/transform/internal/xdm/lexicon"
	uripath "github.com/skarm/xmlsec/transform/internal/xdm/uri"
	"github.com/skarm/xmlsec/transform/internal/xpath"
)

// Compiler configures XSLT 3.0 stylesheet compilation.
// It is a value-style wrapper: fluent methods return updated copies
// and the original is never mutated. The terminal method Compile
// creates an internal compileCtx immediately; downstream compilation
// uses that context, never the Compiler itself.
type Compiler struct {
	cfg *xsltCompilerCfg
}

type xsltCompilerCfg struct {
	baseURI         string
	uriResolver     URIResolver
	packageResolver PackageResolver
	staticParams    *Parameters

	maxResourceBytes int64

	parseOptions *xdm.ParseOptions
}

// NewCompiler creates a new Compiler with default settings.
func NewCompiler() Compiler {
	return Compiler{cfg: &xsltCompilerCfg{}}
}

// BaseURI sets the base URI for resolving relative URIs in xsl:import
// and xsl:include.
func (c Compiler) BaseURI(uri string) Compiler {
	c = c.clone()
	c.cfg.baseURI = uri

	return c
}

// URIResolver sets a custom URI resolver for loading external
// stylesheets during compilation.
func (c Compiler) URIResolver(r URIResolver) Compiler {
	c = c.clone()
	c.cfg.uriResolver = r

	return c
}

// PackageResolver sets a package resolver for xsl:use-package references.
func (c Compiler) PackageResolver(r PackageResolver) Compiler {
	c = c.clone()
	c.cfg.packageResolver = r

	return c
}

// StaticParameters sets the static parameters for compilation.
// The Parameters collection is cloned.
func (c Compiler) StaticParameters(p *Parameters) Compiler {
	c = c.clone()
	c.cfg.staticParams = p.Clone()

	return c
}

// SetStaticParameter sets a single static parameter value.
// Clone-on-write: the existing parameters are cloned before mutation
// if shared with another Compiler value.
func (c Compiler) SetStaticParameter(name string, value xdm.Sequence) Compiler {
	c = c.clone()
	if c.cfg.staticParams == nil {
		c.cfg.staticParams = NewParameters()
	} else {
		c.cfg.staticParams = c.cfg.staticParams.Clone()
	}

	c.cfg.staticParams.Set(name, value)

	return c
}

// MaxResourceBytes sets the maximum number of bytes read from a single
// external resource loaded during compilation through the configured
// URIResolver / PackageResolver — xsl:import / xsl:include, xsl:use-package
// package loads, xsl:import-schema, and serialization parameter documents. It
// also governs the runtime resource reads performed by XSLT's own loader —
// fn:doc / document(), xsl:source-document, xsl:merge, xsl:result-document
// parameter documents, xsi:schemaLocation source schemas, and fn:transform
// stylesheet / package sources — unless overridden per-invocation by
// [Invocation.MaxResourceBytes].
//
// A value of 0 selects the [MaxResourceBytes] default; a negative value
// disables the bound. Reads exceeding the cap on these XSLT-owned paths fail
// with [ErrResourceTooLarge]. The same cap also bounds xsl:analyze-string
// match enumeration: an empty- or near-empty-matching regex over a large input
// is rejected with [ErrResourceTooLarge] once the running match count exceeds
// the cap, so the work stays bounded regardless of input size.
//
// The XPath built-ins fn:unparsed-text, fn:unparsed-text-lines, and
// fn:json-doc read through the xpath layer, and never the XSLT loader: they
// honor the same byte cap but do NOT surface [ErrResourceTooLarge]. An over-cap
// fn:unparsed-text / fn:unparsed-text-lines read surfaces FOUT1170
// (fn:unparsed-text-available returns false), and an over-cap fn:json-doc read
// surfaces FODC0002.
func (c Compiler) MaxResourceBytes(n int64) Compiler {
	c = c.clone()
	c.cfg.maxResourceBytes = n

	return c
}

// ParseOptions sets XML limits and base URI for stylesheet modules, parameter
// documents and nested XPath evaluation. Invocations inherit these options.
// Resource retrieval is configured separately through URIResolver.
func (c Compiler) ParseOptions(p xdm.ParseOptions) Compiler {
	c = c.clone()
	c.cfg.parseOptions = &p

	return c
}

// ClearStaticParameters removes all static parameter bindings.
func (c Compiler) ClearStaticParameters() Compiler {
	c = c.clone()
	c.cfg.staticParams = nil

	return c
}

// Compile compiles a parsed XSLT stylesheet document into a reusable
// Stylesheet. ctx is used for cancellation/deadlines.
func (c Compiler) Compile(ctx context.Context, doc *xdm.Document) (*Stylesheet, error) {
	if doc == nil {
		return nil, errNilDocument
	}

	return compile(ctx, doc, c.toCompileConfig())
}

func compile(ctx context.Context, doc *xdm.Document, cfg *compileConfig) (*Stylesheet, error) {
	var stackErr error

	ctx, stackErr = enterPackage(ctx, doc)
	if stackErr != nil {
		return nil, stackErr
	}

	version, err := CheckLanguage(doc, 0)
	if err != nil {
		return nil, err
	}

	prepared := doc
	if version == 10 {
		prepared, err = prepareModule10(ctx, doc)
		if err != nil {
			return nil, err
		}
	}

	s, err := compilePrepared(ctx, prepared, cfg)
	if s != nil {
		s.sourceDoc = doc
		for uri, module := range s.moduleDocs {
			if module == prepared {
				s.moduleDocs[uri] = doc
			}
		}
	}

	return s, err
}

func compilePrepared(ctx context.Context, doc *xdm.Document, cfg *compileConfig) (*Stylesheet, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	root := doc.DocumentElement()
	if root == nil {
		return nil, staticError(errCodeXTSE0010, "empty stylesheet document")
	}

	if root.URI() != lexicon.NamespaceXSLT {
		// Could be a simplified stylesheet (literal result element)
		return compileSimplified(ctx, doc, root, cfg)
	}

	localName := root.LocalName()
	if localName != nameStylesheet && localName != fnNameTransform && localName != namePackage {
		return nil, staticError(errCodeXTSE0010, "root element must be xsl:stylesheet, xsl:transform, or xsl:package, got %s", root.Name())
	}

	c := &compiler{
		invocation: ctx,
		stylesheet: &Stylesheet{
			namedTemplates:   make(map[string]*template),
			modeTemplates:    make(map[string][]*template),
			keys:             make(map[string][]*keyDef),
			outputs:          make(map[string]*OutputDef),
			functions:        make(map[funcKey]*xslFunction),
			namespaces:       make(map[string]string),
			accumulators:     make(map[string]*accumulatorDef),
			accumulatorOrder: make([]string, 0),
		},
		nsBindings:    make(map[string]string),
		importStack:   make(map[string]struct{}),
		localExcludes: make(map[string]struct{}),
		includeRoots:  make(map[string]*xdm.Element),
	}

	if err := c.readPackageMetadata(root, localName); err != nil {
		return nil, err
	}

	c.applyPreparedConfig(cfg)

	if err := c.configureRootContext(ctx, root); err != nil {
		return nil, err
	}

	if err := c.readRootVersion(ctx, root, localName); err != nil {
		return nil, err
	}

	if err := c.readResultNamespacePolicy(root); err != nil {
		return nil, err
	}

	if err := c.compileTopLevel(ctx, root); err != nil {
		return nil, err
	}

	if err := c.completeTopLevelDeclarations(ctx, root, cfg); err != nil {
		return nil, err
	}

	c.sortTemplates(ctx)
	c.recordStylesheetSource(doc)

	if err := c.validateDeferredReferences(ctx); err != nil {
		return nil, err
	}

	c.finalizeCompiledStylesheet()

	return c.stylesheet, nil
}

// MustCompile is like Compile but panics on error.
// Note: context cancellation or timeout will cause a panic.
func (c Compiler) MustCompile(ctx context.Context, doc *xdm.Document) *Stylesheet {
	ss, err := c.Compile(ctx, doc)
	if err != nil {
		panic("xslt: Compile: " + err.Error())
	}

	return ss
}

func (c Compiler) clone() Compiler {
	if c.cfg == nil {
		return Compiler{cfg: &xsltCompilerCfg{}}
	}

	cp := *c.cfg

	return Compiler{cfg: &cp}
}

func (c Compiler) toCompileConfig() *compileConfig {
	if c.cfg == nil {
		return &compileConfig{}
	}

	cfg := &compileConfig{
		baseURI:         c.cfg.baseURI,
		resolver:        c.cfg.uriResolver,
		packageResolver: c.cfg.packageResolver,

		maxResourceBytes: c.cfg.maxResourceBytes,

		parseOptions: c.cfg.parseOptions,
	}
	if c.cfg.staticParams != nil {
		cfg.staticParams = maps.Clone(c.cfg.staticParams.toMap())
	}

	return cfg
}

type pendingPatternValidation struct {
	pattern *pattern
	source  string
}

type staticParamDefinition struct {
	name       string
	selectExpr string
}

type staticDependencyState uint8

const (
	staticDependencyUnvisited staticDependencyState = iota
	staticDependencyVisiting
	staticDependencyComplete
)

type compiler struct {
	invocation              context.Context
	resolver                URIResolver
	packageResolver         PackageResolver
	stylesheet              *Stylesheet
	nsBindings              map[string]string
	importStack             map[string]struct{}             // circular import detection
	parseOptions            *xdm.ParseOptions               // injected base parseOptions governing parse policy (nil = hardened default)
	moduleRoot              *xdm.Element                    // embedded (fragment-selected) module root; descendant xml:base walks stop here. nil = stop before the document element
	localExcludes           map[string]struct{}             // accumulated LRE-level exclude-result-prefixes (stores URIs, not prefixes)
	extensionURIs           map[string]struct{}             // namespace URIs declared as extension-element-prefixes
	includeRoots            map[string]*xdm.Element         // cached parsed roots from collectIncludeImports for reuse in compileIncludeTemplates
	useWhenExcluded         map[string]struct{}             // import keys excluded by use-when="false()" on the root element
	staticVars              map[string]xdm.Sequence         // static="yes" params evaluated at compile time
	staticVarKinds          map[string]string               // tracks "param" or "variable" for each static var (XTSE3450)
	mainStaticVarValues     map[string]xdm.Sequence         // values set by main module only (for XTSE3450 value conflict)
	importedStaticVarKinds  map[string]string               // kinds set by imported modules only
	importedStaticVarValues map[string]xdm.Sequence         // values set by imported modules only
	externalStaticParams    map[string]xdm.Sequence         // externally supplied static param overrides
	charMapModuleKeys       map[string]string               // character-map name -> moduleKey that first defined it (for XTSE1580)
	moduleSources           map[*xdm.Document]*xdm.Document // original source of normalized 1.0 modules
	usedModes               map[string]struct{}             // all mode names referenced (for XTSE3085)
	outputAllowDupExplicit  map[string]bool                 // per-output-name: allow-duplicate-names explicitly set (compile-time merge bookkeeping, keyed like stylesheet.outputs)
	localTemplateNames      map[string]struct{}             // pre-scanned named templates in this module (for XTSE3055)
	overrideDecls           map[string]struct{}             // "kind:name" of every xsl:override declaration so far (for XTSE3055)
	localVarNames           map[string]struct{}             // pre-scanned variable names in this module (for XTSE3050)
	localModeNames          map[string]struct{}             // pre-scanned mode names in this module (for XTSE3050)
	// Declared visibility snapshots (before xsl:expose modification)
	declaredTemplateVis map[string]string
	declaredFunctionVis map[string]string
	declaredVariableVis map[string]string
	declaredAttrSetVis  map[string]string
	declaredParamVis    map[string]string
	declaredModeVis     map[string]string
	// patternNamespaceMaps holds the shared in-scope namespace maps of the
	// patterns compiled so far, keyed by their sorted bindings; see
	// internPatternNamespaces. Lazily allocated.
	patternNamespaceMaps      map[string]map[string]string
	xpathDefaultNS            string // current xpath-default-namespace value
	baseURI                   string
	moduleKey                 string
	defaultMode               string                     // current default-mode (inherited through instruction nesting)
	defaultCollation          string                     // current default-collation URI (resolved from space-separated list)
	effectiveVersion          string                     // effective XSLT version for forwards-compat processing
	pendingPatternValidations []pendingPatternValidation // deferred pattern function validations
	pendingOverrideTypeChecks []pendingOverrideTypeCheck // deferred XTSE3070 override variable same-type checks
	usedAttrSetRefs           []string                   // all use-attribute-sets names referenced (for XTSE0710)
	importPrec                int
	minImportPrec             int   // importPrec value before processing this module's xsl:import elements
	maxResourceBytes          int64 // per-resource read cap; 0 = MaxResourceBytes default, <0 = unbounded
	iterateDepth              int   // nesting depth of xsl:iterate (for xsl:break/next-iteration validation)
	hasXPathDefaultNS         bool  // whether an xpath-default-namespace is in effect (distinguishes explicit "" reset from absent)
	preserveSpace             bool  // xml:space="preserve" in effect
	expandText                bool  // expand-text="yes" — text value templates enabled
	breakAllowed              bool  // true when xsl:break/xsl:next-iteration are allowed at this position
	insideImport              bool  // true when compiling an imported module (for XTSE3008)
}

// recordModeUsage records a mode name (or space-separated list of mode names)
// as being referenced, for later XTSE3085 validation.
func (c *compiler) recordModeUsage(_ context.Context, mode string) {
	if c.usedModes == nil {
		c.usedModes = make(map[string]struct{})
	}

	for m := range strings.FieldsSeq(mode) {
		c.usedModes[m] = struct{}{}
	}

	if mode == "" {
		// Empty mode means unnamed mode is used
		c.usedModes[""] = struct{}{}
	}
}

// resolveMode resolves mode name QNames to expanded Clark notation.
// Special mode names (#all, #default, #unnamed, #current) are returned as-is.
// Whitespace-separated lists are handled: each token is resolved independently.
func (c *compiler) resolveMode(_ context.Context, mode string) string {
	modes := strings.Fields(mode)
	if len(modes) <= 1 {
		mode = strings.TrimSpace(mode)
		if mode == "" || mode[0] == '#' {
			return mode // special names
		}

		return resolveQName(mode, c.nsBindings)
	}

	resolved := make([]string, len(modes))
	for i, m := range modes {
		if m[0] == '#' {
			resolved[i] = m
		} else {
			resolved[i] = resolveQName(m, c.nsBindings)
		}
	}

	return strings.Join(resolved, " ")
}

// shouldStripText returns true if a whitespace-only text node should be stripped
// during compilation (i.e., xml:space is not "preserve").
// Uses the XML definition of whitespace (#x20, #x9, #xD, #xA) so that
// characters like U+00A0 (non-breaking space) are NOT stripped.
func (c *compiler) shouldStripText(_ context.Context, text string) bool {
	if c.preserveSpace {
		return false
	}

	return isXMLWhitespaceOnly(text)
}

// resolveAsType resolves an "as" attribute sequence type string using
// the current xpath-default-namespace. When the xpath-default-namespace
// is the XSD namespace and the type name is unqualified, prefix it
// with "xs:" so runtime type checks resolve correctly.
func (c *compiler) resolveAsType(_ context.Context, asAttr string) string {
	if asAttr == "" || c.xpathDefaultNS == "" {
		return asAttr
	}

	if c.xpathDefaultNS != lexicon.NamespaceXSD {
		return asAttr
	}
	// Only resolve unqualified type names (no prefix, no Q{}).
	// Strip occurrence indicator for the check.
	typePart := strings.TrimRight(asAttr, "?*+")
	if typePart == "" || strings.ContainsAny(typePart, ":{") {
		return asAttr
	}

	candidate := "xs:" + typePart
	if xdm.IsKnownXSDType(candidate) {
		suffix := asAttr[len(typePart):]
		return candidate + suffix
	}

	return asAttr
}

// backwardsCompatible reports whether the compiler's current effective version
// selects backwards-compatible processing.
func (c *compiler) backwardsCompatible() bool {
	return isBackwardsCompatible(c.effectiveVersion)
}

// pushElementVersion sets the effective version from a declaration element's own
// version attribute (if present) for the duration of its compilation, returning
// a restore function to defer. Top-level declaration compilers (template, key,
// function, accumulator, attribute-set) must call this before compiling any
// pattern or XPath expression so a local version < 2.0 makes those expressions
// backwards-compatible (XSLT 3.0 §3.10) — the generic instruction path already
// pushes the version, but these direct paths bypass it.
func (c *compiler) pushElementVersion(elem *xdm.Element) func() {
	saved := c.effectiveVersion
	if ver := elementXSLTVersion(elem); ver != "" {
		c.effectiveVersion = ver
	}

	return func() { c.effectiveVersion = saved }
}

// elementXSLTVersion returns the XSLT version declared on an element: the
// unqualified version attribute on an XSLT-namespace element, or the xsl:version
// attribute on a literal result element. On an LRE an unqualified version is an
// ordinary literal result attribute (copied to the output), NOT an XSLT version,
// so it must not affect the effective version.
func elementXSLTVersion(elem *xdm.Element) string {
	if elem.URI() == lexicon.NamespaceXSLT {
		return getAttr(elem, paramVersion)
	}

	ver, _ := elem.GetAttributeNS(paramVersion, lexicon.NamespaceXSLT)

	return ver
}

// pushStaticVersion forces a non-backwards-compatible effective version for the
// duration of a compile-time static-context evaluation (a static="yes" variable
// or parameter). The static context is NOT subject to backwards-compatible
// processing — consistent with use-when — so its select must not be compat-marked
// even inside a version < 2.0 module. Returns a restore function to defer.
func (c *compiler) pushStaticVersion() func() {
	saved := c.effectiveVersion
	c.effectiveVersion = lexicon.XSLTVersion30

	return func() { c.effectiveVersion = saved }
}

// markCompatExpr records an expression that must evaluate in XPath 1.0
// compatibility mode. Keyed by pointer identity; lazily allocates the set so a
// stylesheet with no backwards-compatible subtree keeps a nil map.
func (c *compiler) markCompatExpr(expr *xpath.Expression) {
	if expr == nil {
		return
	}

	if c.stylesheet.compatExprs == nil {
		c.stylesheet.compatExprs = make(map[*xpath.Expression]struct{})
	}

	c.stylesheet.compatExprs[expr] = struct{}{}
}

// validateEmptyElement checks that an XSLT element required to be empty has
// no non-whitespace text content or element children. Returns XTSE0260 on violation.
// When xml:space="preserve" is in effect, even whitespace-only text nodes are errors.
func (c *compiler) validateEmptyElement(_ context.Context, elem *xdm.Element, name string) error {
	xmlSpacePreserve := getAttr(elem, lexicon.QNameXMLSpace) == validationPreserve
	for child := range xdm.Children(elem) {
		switch child.Type() {
		case xdm.ElementNode:
			return staticError(errCodeXTSE0260, "%s must be empty, found child element", name)
		case xdm.TextNode:
			content := xdm.CharacterData(child)
			if !isXMLWhitespaceOnly(content) {
				return staticError(errCodeXTSE0260, "%s must be empty, found text content", name)
			}

			if xmlSpacePreserve && content != "" {
				return staticError(errCodeXTSE0260, "%s must be empty, whitespace preserved by xml:space", name)
			}
		}
	}

	return nil
}

// hasEffectiveContent returns true if the element has non-whitespace content
// after considering use-when exclusions. Child elements whose use-when evaluates
// to false are not counted as content.
func (c *compiler) hasEffectiveContent(ctx context.Context, elem *xdm.Element) bool {
	for child := range xdm.Children(elem) {
		switch v := child.(type) {
		case *xdm.Element:
			// Check use-when: XSLT elements use "use-when", LREs use "xsl:use-when"
			var uw string
			if v.URI() == lexicon.NamespaceXSLT {
				uw = getAttr(v, xslAttrUseWhen)
			} else {
				uw, _ = v.GetAttributeNS(xslAttrUseWhen, lexicon.NamespaceXSLT)
			}

			if uw != "" {
				include, err := c.evaluateUseWhen(ctx, uw)
				if err == nil && !include {
					continue // excluded by use-when
				}
			}

			return true
		case *xdm.Text:
			if !isXMLWhitespaceOnly(xdm.CharacterData(v)) {
				return true
			}
		}
	}

	return false
}

// setStaticVar sets a static variable value and records its kind
// ("param" or "variable") for XTSE3450 conflict detection.
func (c *compiler) setStaticVar(_ context.Context, name string, value xdm.Sequence) {
	if c.staticVars == nil {
		c.staticVars = make(map[string]xdm.Sequence)
	}

	c.staticVars[name] = value
}

// setStaticVarWithKind sets a static variable value and records its
// kind ("param" or "variable") for XTSE3450 conflict detection.
// When called from an imported module, the kind is recorded in
// importedStaticVarKinds. When called from the main module, it
// checks against previously imported kinds for conflicts.
func (c *compiler) setStaticVarWithKind(ctx context.Context, name, kind string, value xdm.Sequence) error { //nolint:unparam // always nil but callers check for future-proofing
	if c.insideImport {
		if c.importedStaticVarKinds == nil {
			c.importedStaticVarKinds = make(map[string]string)
		}

		if c.importedStaticVarValues == nil {
			c.importedStaticVarValues = make(map[string]xdm.Sequence)
		}
		// Record the import's kind. If two imports disagree, record
		// the conflict (first import wins for kind tracking).
		if _, exists := c.importedStaticVarKinds[name]; !exists {
			c.importedStaticVarKinds[name] = kind
			c.importedStaticVarValues[name] = value
		}

		c.setStaticVar(ctx, name, value)

		return nil
	}
	// Main module: check against imported kinds for conflicts.
	if c.staticVarKinds == nil {
		c.staticVarKinds = make(map[string]string)
	}

	if c.mainStaticVarValues == nil {
		c.mainStaticVarValues = make(map[string]xdm.Sequence)
	}

	c.staticVarKinds[name] = kind
	c.mainStaticVarValues[name] = value
	c.setStaticVar(ctx, name, value)

	return nil
}

// detectStaticParamCycles checks for circular references among
// static params/variables. Even if external values break the cycle
// at runtime, the circularity in definitions is XPST0008.
func (c *compiler) detectStaticParamCycles(_ context.Context, root *xdm.Element) error {
	defs := collectStaticParamDefinitions(root)
	if len(defs) < 2 {
		return nil
	}

	deps := staticParamDependencies(defs)
	state := make(map[string]staticDependencyState)

	for _, def := range defs {
		if state[def.name] == staticDependencyUnvisited && hasStaticDependencyCycle(def.name, deps, state) {
			return staticError(errCodeXPST0008,
				"circular reference among static parameters/variables")
		}
	}

	return nil
}

func collectStaticParamDefinitions(root *xdm.Element) []staticParamDefinition {
	var defs []staticParamDefinition

	for child := range xdm.Children(root) {
		elem, ok := child.(*xdm.Element)
		if !ok || elem.URI() != lexicon.NamespaceXSLT {
			continue
		}

		local := elem.LocalName()
		if local != lexicon.XSLTElementParam && local != lexicon.XSLTElementVariable {
			continue
		}

		if !xsdBoolTrue(getAttr(elem, nameStatic)) {
			continue
		}

		name := getAttr(elem, xslAttrName)
		selectExpr := getAttr(elem, xslAttrSelect)

		if name != "" && selectExpr != "" {
			defs = append(defs, staticParamDefinition{name: name, selectExpr: selectExpr})
		}
	}

	return defs
}

func staticParamDependencies(defs []staticParamDefinition) map[string][]string {
	deps := make(map[string][]string)

	for _, def := range defs {
		for _, other := range defs {
			if other.name != def.name && containsStaticParamReference(def.selectExpr, other.name) {
				deps[def.name] = append(deps[def.name], other.name)
			}
		}
	}

	return deps
}

// containsStaticParamReference retains the static scan's name-boundary rule:
// a reference to $foo must not also match $foobar, $foo_1 or $foo-bar.
func containsStaticParamReference(expr, name string) bool {
	ref := "$" + name
	for offset := 0; offset < len(expr); {
		match := strings.Index(expr[offset:], ref)
		if match < 0 {
			return false
		}

		end := offset + match + len(ref)
		if end == len(expr) || !isStaticParamNameByte(expr[end]) {
			return true
		}

		offset = end
	}

	return false
}

func isStaticParamNameByte(ch byte) bool {
	return ch == '_' || ch == '-' || ch == '.' ||
		(ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9')
}

func hasStaticDependencyCycle(name string, deps map[string][]string, state map[string]staticDependencyState) bool {
	state[name] = staticDependencyVisiting
	for _, dep := range deps[name] {
		switch state[dep] {
		case staticDependencyVisiting:
			return true
		case staticDependencyUnvisited:
			if hasStaticDependencyCycle(dep, deps, state) {
				return true
			}
		}
	}

	state[name] = staticDependencyComplete

	return false
}

// checkStaticVarKindConflicts checks for XTSE3450 conflicts between
// the main module's static declarations and imported modules' declarations.
// Must be called after all imports have been processed.
func (c *compiler) checkStaticVarKindConflicts(_ context.Context, root *xdm.Element) error {
	if len(c.importedStaticVarKinds) == 0 || len(c.staticVarKinds) == 0 {
		return nil
	}
	// Walk the main module's children in document order. When we see
	// an xsl:import followed (later in document order) by a static
	// param/variable with the same name but different kind than what
	// the import declared, raise XTSE3450.
	// Also raise XTSE3450 when the kind matches but the value differs.
	seenImport := false

	for child := range xdm.Children(root) {
		elem, ok := child.(*xdm.Element)
		if !ok || elem.URI() != lexicon.NamespaceXSLT {
			continue
		}

		ln := elem.LocalName()
		if ln == nameImport {
			seenImport = true
			continue
		}

		if !seenImport {
			continue
		}

		if (ln == lexicon.XSLTElementParam || ln == lexicon.XSLTElementVariable) && xsdBoolTrue(getAttr(elem, nameStatic)) {
			name := getAttr(elem, xslAttrName)
			if importedKind, ok := c.importedStaticVarKinds[name]; ok {
				if importedKind != ln {
					return staticError(errCodeXTSE3450,
						"static %s $%s conflicts with imported declaration as %s", ln, name, importedKind)
				}
				// Same kind: check for value conflict.
				if importedVal, haveVal := c.importedStaticVarValues[name]; haveVal {
					mainVal := c.mainStaticVarValues[name]
					if !staticSequenceEqual(mainVal, importedVal) {
						return staticError(errCodeXTSE3450,
							"static %s $%s has conflicting values between main module and imported module", ln, name)
					}
				}
			}
		}
	}

	return nil
}

// staticSequenceEqual compares two xdm.Sequence values for equality
// by comparing their string representations. Suitable for static variable
// values which are simple atomic types.
func staticSequenceEqual(a, b xdm.Sequence) bool {
	aLen := 0
	if a != nil {
		aLen = xdm.SequenceLen(a)
	}

	bLen := 0
	if b != nil {
		bLen = b.Len()
	}

	if aLen != bLen {
		return false
	}

	for i := range aLen {
		if fmt.Sprint(a.Get(i)) != fmt.Sprint(b.Get(i)) {
			return false
		}
	}

	return true
}

// checkQNamePrefix validates that if a QName has a prefix, that prefix is declared
// in the current namespace bindings. Returns XTSE0280 for undeclared prefixes.
func (c *compiler) checkQNamePrefix(_ context.Context, name, context string) error {
	if strings.HasPrefix(name, "Q{") {
		return nil // EQName, no prefix to resolve
	}

	if idx := strings.IndexByte(name, ':'); idx > 0 {
		prefix := name[:idx]
		if _, ok := c.nsBindings[prefix]; !ok {
			if _, ok := c.stylesheet.namespaces[prefix]; !ok {
				return staticError(errCodeXTSE0280, "undeclared namespace prefix %q in %s name %q", prefix, context, name)
			}
		}
	}

	return nil
}

// resolveShadowAttributes processes shadow attributes on an XSLT element.
// A shadow attribute _foo="avt" is evaluated at compile time and replaces
// the regular foo attribute. Per XSLT 3.0 §3.5.2: "A shadow attribute
// takes precedence over the corresponding regular attribute."
func (c *compiler) resolveShadowAttributes(ctx context.Context, elem *xdm.Element) error {
	attrs := elem.Attributes()
	for _, attr := range attrs {
		name := attr.LocalName()
		if attr.URI() != "" || len(name) < 2 || name[0] != '_' {
			continue
		}

		realName := name[1:]
		avtStr := attr.Value()

		avt, err := c.compileAVT(avtStr, c.nsBindings)
		if err != nil {
			return staticError(errCodeXTSE0020,
				"invalid AVT in shadow attribute _%s: %v", realName, err)
		}

		// Evaluate using static variables and XSLT static functions
		// (system-property, function-available, etc. per XSLT 3.0 §3.5.2)
		eval := c.useWhenEvaluator(ctx)

		val, err := avt.evaluateStatic(ctx, eval, nil)
		if err != nil {
			return staticError(errCodeXTSE0020,
				"error evaluating shadow attribute _%s: %v", realName, err)
		}

		// Remove the shadow attribute and set the real one.
		// SetAttribute stores verbatim: avt values are plain text that may contain &.
		elem.RemoveAttribute("_" + realName)
		_ = elem.SetAttribute(realName, val)
	}

	return nil
}

// resolveSingleShadowAttribute resolves just one shadow attribute (_name) on
// an element, leaving all other shadow attributes intact.
func (c *compiler) resolveSingleShadowAttribute(ctx context.Context, elem *xdm.Element, name string) error {
	shadowName := "_" + name

	avtStr, hasShadow := elem.GetAttribute(shadowName)
	if !hasShadow {
		return nil
	}

	avt, err := c.compileAVT(avtStr, c.nsBindings)
	if err != nil {
		return staticError(errCodeXTSE0020,
			"invalid AVT in shadow attribute _%s: %v", name, err)
	}

	eval := c.useWhenEvaluator(ctx)

	val, err := avt.evaluateStatic(ctx, eval, nil)
	if err != nil {
		return staticError(errCodeXTSE0020,
			"error evaluating shadow attribute _%s: %v", name, err)
	}

	elem.RemoveAttribute(shadowName)
	_ = elem.SetAttribute(name, val)

	return nil
}

// compileXPath compiles an XPath expression with the given namespace bindings.
// staticEvaluator returns an Evaluator suitable for evaluating static
// XPath expressions at compile time (static="yes" params/variables). It
// provides fn:transform and other XSLT static functions so that compile-time
// evaluation can invoke dynamic transforms (used by use-when patterns).
func (c *compiler) staticEvaluator(_ context.Context) xpath.Evaluator {
	fns := map[string]xpath.Function{
		fnNameTransform: &xsltFunc{min: 1, max: 1, fn: c.staticFnTransform},
	}

	eval := xpath.NewEvaluator(xpath.DefaultEvaluatorOptions).TraceWriter(io.Discard).
		Functions(fns, nil)
	if c.parseOptions != nil {
		eval = eval.ParseOptions(*c.parseOptions)
	}

	ns := make(map[string]string, len(c.nsBindings)+1)
	maps.Copy(ns, c.nsBindings)

	if c.xpathDefaultNS != "" {
		ns[""] = c.xpathDefaultNS
	}

	if len(ns) > 0 {
		eval = eval.Namespaces(ns)
	}

	if c.baseURI != "" {
		eval = eval.BaseURI(c.baseURI)
	}

	return eval
}

// resolveXMLBaseEvaluator resolves an xml:base attribute value against the
// compiler's base URI and returns an evaluator with the updated base URI.
func (c *compiler) resolveXMLBaseEvaluator(_ context.Context, eval xpath.Evaluator, xmlBase string) xpath.Evaluator {
	if strings.Contains(xmlBase, "://") {
		return eval.BaseURI(xmlBase)
	}

	if c.baseURI == "" {
		return eval
	}

	base, err := url.Parse(c.baseURI)
	if err != nil {
		return eval
	}

	ref, err := url.Parse(xmlBase)
	if err != nil {
		return eval
	}

	resolved := base.ResolveReference(ref).String()

	return eval.BaseURI(resolved)
}

// staticFnTransform implements fn:transform for compile-time evaluation of
// static variables. It compiles and executes the referenced stylesheet in a
// fresh transform context.
func (c *compiler) staticFnTransform(ctx context.Context, args []xdm.Sequence) (xdm.Sequence, error) {
	// Create a temporary execContext with the compiler's base URI so that
	// relative stylesheet-location paths resolve correctly. The compile-time
	// URIResolver is propagated so fn:transform stylesheet-location loading is
	// permitted at compile time exactly when the compiler opts in (it is
	// default-deny without a resolver). The compiler's MaxResourceBytes cap is
	// seeded on both the temp Stylesheet (consulted by nested compiles via
	// newNestedCompiler) and the transformConfig (consulted by runtime reads)
	// so Compiler.MaxResourceBytes governs static-variable transform() loads.
	ec := &execContext{
		stylesheet:          &Stylesheet{baseURI: c.baseURI, uriResolver: c.resolver, maxResourceBytes: c.maxResourceBytes, parseOptions: c.parseOptions},
		resultDoc:           xdm.NewDefaultDocument(),
		globalVars:          make(map[string]xdm.Sequence),
		outputStack:         []*outputFrame{{doc: xdm.NewDefaultDocument(), current: xdm.NewDefaultDocument()}},
		keyTables:           make(map[string]*keyTable),
		docCache:            make(map[string]*xdm.Document),
		functionResultCache: make(map[string]xdm.Sequence),
		accumulatorState:    make(map[string]xdm.Sequence),
		resultDocuments:     make(map[string]*xdm.Document),
		usedResultURIs:      make(map[string]struct{}),
		transformConfig:     &transformConfig{maxResourceBytes: c.maxResourceBytes, parseOptions: c.parseOptions},
	}
	ec.setCurrentTemplate(nil)

	return ec.fnTransform(ctx, args)
}

// useWhenEvaluator builds a compile-time evaluator for use-when evaluation
// and shadow attribute resolution. It provides XSLT static functions
// (system-property, function-available, type-available, element-available).
func (c *compiler) useWhenEvaluator(_ context.Context) xpath.Evaluator {
	fns := map[string]xpath.Function{
		fnNameFunctionAvailable: &xsltFunc{min: 1, max: 2, fn: c.useWhenFunctionAvailable},
		funcSystemProperty:      &xsltFunc{min: 1, max: 1, fn: c.useWhenSystemProperty},
		fnNameTypeAvailable:     &xsltFunc{min: 1, max: 1, fn: c.useWhenTypeAvailable},
		fnNameElementAvailable:  &xsltFunc{min: 1, max: 1, fn: c.useWhenElementAvailable},
	}

	eval := xpath.NewEvaluator(xpath.DefaultEvaluatorOptions).TraceWriter(io.Discard).
		Functions(fns, nil)
	if c.parseOptions != nil {
		eval = eval.ParseOptions(*c.parseOptions)
	}

	if len(c.nsBindings) > 0 || c.xpathDefaultNS != "" {
		ns := make(map[string]string, len(c.nsBindings)+1)
		maps.Copy(ns, c.nsBindings)

		if c.xpathDefaultNS != "" {
			ns[""] = c.xpathDefaultNS
		}

		eval = eval.Namespaces(ns)
	}

	if len(c.staticVars) > 0 {
		eval = eval.Variables(c.staticVars)
	}

	if c.baseURI != "" {
		eval = eval.BaseURI(ensureFileURI(c.baseURI))
	}
	// Route compile-time doc()/doc-available() in use-when through the same
	// resolver that loads stylesheet modules, so a root use-when can probe for a
	// resource relative to the module's effective static base.
	if c.resolver != nil {
		eval = eval.URIResolver(c.resolver)
	}
	// Honor the compiler's per-resource read cap on compile-time doc() /
	// doc-available() (and any other bounded XPath built-in) so a root use-when
	// probing a resource obeys Compiler.MaxResourceBytes, matching the runtime
	// evaluator. resolveResourceLimit maps the xslt 0-means-default convention
	// onto the concrete xpath limit.
	eval = eval.MaxResourceBytes(resolveResourceLimit(c.maxResourceBytes))

	return eval
}

func (c *compiler) compileXPath(expr string, _ map[string]string) (*xpath.Expression, error) {
	version := 31
	if v, _ := strconv.ParseFloat(c.effectiveVersion, 64); v < 2 {
		version = 10
	} else if v == 2 {
		version = 20
	}

	if isBackwardsCompatible(c.stylesheet.version) {
		version = 10
	}

	compiled, err := xpath.NewCompiler().Context(c.invocation).Language(version, c.nsBindings).Compile(expr)
	if err != nil {
		if isBackwardsCompatible(c.stylesheet.version) && c.forwardsCompatible(c.effectiveVersion) {
			return xpath.DeferredExpression(err, 10), nil
		}

		code := "XPST0003"

		if detail, ok := errors.AsType[*xdm.Error](err); ok {
			code = detail.Code
		}

		return nil, staticErrorCause(code, err, "invalid XPath %q: %v", expr, err)
	}
	// XSLT backwards-compatible processing: an expression compiled under an
	// effective version < 2.0 is evaluated in XPath 1.0 compatibility mode. Record
	// it by pointer identity so evalXPath can select the compat evaluator.
	if c.backwardsCompatible() {
		c.markCompatExpr(compiled)
	}

	return compiled, nil
}

func (c *compiler) readPackageMetadata(root *xdm.Element, localName string) error {
	if localName == namePackage {
		c.stylesheet.packageName = getAttr(root, xslAttrName)
		c.stylesheet.packageVersion = getAttr(root, namePackageVersion)
		c.stylesheet.isPackage = true
		c.stylesheet.declaredModes = true // default for xsl:package

		if dm := getAttr(root, "declared-modes"); dm != "" {
			if v, ok := parseXSDBool(dm); ok {
				c.stylesheet.declaredModes = v
			}
		}
	} else {
		// package-version is only allowed on xsl:package, not xsl:stylesheet/xsl:transform.
		// In forwards-compatible mode (version > 3.0), unknown attributes are silently ignored.
		ver := getAttr(root, paramVersion)
		if getAttr(root, namePackageVersion) != "" && !isForwardsCompatible(ver) {
			return staticError(errCodeXTSE0090,
				"attribute package-version is not allowed on xsl:%s", localName)
		}
	}

	return nil
}

// isForwardsCompatible returns true if the version string indicates
// forwards-compatible mode (version > 3.0).
func isForwardsCompatible(ver string) bool {
	if ver == "" || ver == "3.0" {
		return false
	}

	f, err := strconv.ParseFloat(ver, 64)
	if err != nil {
		return false
	}

	return f > 3.0
}

func (c *compiler) applyPreparedConfig(cfg *compileConfig) {
	if cfg != nil {
		c.baseURI = cfg.baseURI
		c.moduleKey = cfg.baseURI
		c.resolver = cfg.resolver
		c.packageResolver = cfg.packageResolver
		c.externalStaticParams = cfg.staticParams

		c.maxResourceBytes = cfg.maxResourceBytes

		c.parseOptions = cfg.parseOptions
	}

	if c.moduleKey == "" {
		c.moduleKey = "<main>"
	}
}

// configureRootContext establishes the static context before shadow version
// evaluation, preserving the order of collation and expand-text validation.
func (c *compiler) configureRootContext(ctx context.Context, root *xdm.Element) error {
	// Process xml:base on the stylesheet root element to adjust the
	// static base URI for all expressions in this module.
	// xml:base="innerdoc/" on a stylesheet at /a/b/style.xsl means
	// the effective base URI becomes /a/b/innerdoc/style.xsl, so that
	// filepath.Dir() returns /a/b/innerdoc for relative URI resolution.
	if xmlBase := getAttr(root, lexicon.QNameXMLBase); xmlBase != "" {
		c.baseURI = resolveRootXMLBase(c.baseURI, xmlBase)
	}

	c.collectNamespaces(ctx, root)

	// Read default-validation from stylesheet root (XSLT 3.0).
	// Per §3.6, the default value is "strip".
	if dv := getAttr(root, nameDefaultValidation); dv != "" {
		c.stylesheet.defaultValidation = dv
	} else if c.stylesheet.defaultValidation == "" {
		c.stylesheet.defaultValidation = validationStrip
	}

	if ita := getAttr(root, nameInputTypeAnnotations); ita != "" {
		c.stylesheet.inputTypeAnnotations = ita
	}

	// Read xpath-default-namespace from stylesheet root. Presence (even an
	// empty value) governs unprefixed pattern names; absence leaves the
	// inherited/default behavior untouched.
	if xdn, ok := root.GetAttribute(nameXpathDefaultNamespace); ok {
		c.xpathDefaultNS = xdn
		c.hasXPathDefaultNS = true
	}

	if dc := getAttr(root, nameDefaultCollation); dc != "" {
		if uri := resolveDefaultCollation(dc); uri != "" {
			c.defaultCollation = uri
			c.stylesheet.defaultCollation = uri
		} else {
			return staticError(errCodeXTSE0125,
				"no recognized collation URI in default-collation %q", dc)
		}
	}

	// Read expand-text from stylesheet root (XSLT 3.0, using GetAttribute to catch empty values)
	if et, hasET := root.GetAttribute(nameExpandText); hasET {
		if v, ok := parseXSDBool(et); ok {
			c.expandText = v
		} else {
			return staticError(errCodeXTSE0020, "%q is not a valid value for xsl:stylesheet/@expand-text", et)
		}
	}

	if dm := getAttr(root, nameDefaultMode); dm != "" {
		resolved := resolveQName(dm, c.nsBindings)
		c.stylesheet.defaultMode = resolved
		c.defaultMode = resolved
	}

	return nil
}

// resolveDefaultCollation takes a space-separated list of collation URIs
// (as specified by XSLT's default-collation attribute) and returns the first
// URI that is supported by the XPath engine.  Returns "" if none is supported.
func resolveDefaultCollation(list string) string {
	for uri := range strings.FieldsSeq(list) {
		if xpath.IsCollationSupported(uri) {
			return uri
		}
	}

	return ""
}

// resolveRootXMLBase resolves a root-element xml:base value against the current
// module base URI to produce the new effective base URI.
//
// Absoluteness is decided with [uripath.URIScheme] (RFC 3986), not a "://"
// substring check: an absolute-URI xml:base may carry a scheme with no "//"
// authority (e.g. xml:base="urn:base") and must be used as-is, while a
// relative/root-relative xml:base under a URI base must be resolved per RFC
// 3986 so the base scheme/authority survives. Only when both the current base
// and xml:base are local filesystem paths is filepath used.
//
// To mirror the local-path branch — which re-appends the stylesheet filename so
// filepath.Dir() recovers the directory downstream — the URI branch resolves
// xml:base as a directory and re-resolves the original filename against it:
// xml:base="innerdoc/" under "mem:/a/b/style.xsl" yields
// "mem:/a/b/innerdoc/style.xsl".
func resolveRootXMLBase(baseURI, xmlBase string) string {
	switch {
	case uripath.URIScheme(xmlBase) != "":
		// Absolute URI — use as-is.
		return xmlBase
	case baseURI != "" && uripath.URIScheme(baseURI) != "":
		baseName := filepath.Base(baseURI)

		dirURI, err := uripath.ResolveSchemaURI(xmlBase, baseURI)
		if err != nil {
			return baseURI
		}

		resolved, err := uripath.ResolveSchemaURI(baseName, dirURI)
		if err != nil {
			return baseURI
		}

		return resolved
	case baseURI != "":
		baseDir := filepath.Dir(baseURI)
		baseName := filepath.Base(baseURI)

		return filepath.Join(baseDir, xmlBase, baseName)
	default:
		return baseURI
	}
}

func (c *compiler) readRootVersion(ctx context.Context, root *xdm.Element, localName string) error {
	// A _version shadow attribute takes precedence over a literal version
	// attribute (XSLT 3.0 §3.5.2). Resolve it up front so the effective version —
	// which governs whether backwards-compatible processing applies — reflects the
	// computed value (e.g. _version="{system-property('xsl:version')}" yields 3.0,
	// disabling BC even when version="1.0" is also present).
	if _, hasShadow := root.GetAttribute("_version"); hasShadow {
		if err := c.resolveSingleShadowAttribute(ctx, root, paramVersion); err != nil {
			return err
		}
	}
	// Read version — required on xsl:stylesheet and xsl:transform (XTSE0010).
	// Allow _version shadow attribute (resolved above) to satisfy the check.
	c.stylesheet.version = getAttr(root, paramVersion)
	if err := compilePreparedVersion(c, root, localName); err != nil {
		return err
	}

	c.effectiveVersion = c.stylesheet.version

	// Validate attributes on root element now that effectiveVersion is known.
	if err := c.validateXSLTAttrs(ctx, root, attributeNames(paramVersion, "id", nameDefaultMode, nameDefaultValidation, nameInputTypeAnnotations, nameDefaultCollation, xslAttrUseWhen, xslAttrName, namePackageVersion, "declared-modes")); err != nil {
		return err
	}

	return nil
}

// isXSDecimal returns true if s is a valid xs:decimal lexical form:
// optional sign, digits, optional dot followed by digits. No exponent.
func isXSDecimal(s string) bool {
	s = strings.TrimSpace(s)
	if s == "" {
		return false
	}

	i := 0
	if s[i] == '+' || s[i] == '-' {
		i++
	}

	if i >= len(s) {
		return false
	}

	hasDigit := false
	for i < len(s) && s[i] >= '0' && s[i] <= '9' {
		hasDigit = true
		i++
	}

	if i < len(s) && s[i] == '.' {
		i++
		for i < len(s) && s[i] >= '0' && s[i] <= '9' {
			hasDigit = true
			i++
		}
	}

	return hasDigit && i == len(s)
}

func compilePreparedVersion(c *compiler, root *xdm.Element, localName string) error {
	if c.stylesheet.version == "" {
		if _, hasShadow := root.GetAttribute("_version"); !hasShadow {
			return staticError(errCodeXTSE0010, "xsl:%s requires a version attribute", localName)
		}

		c.stylesheet.version = lexicon.XSLTVersion30 // placeholder until shadow resolution
	} else if !isXSDecimal(c.stylesheet.version) {
		// XTSE0110: version must be a valid xs:decimal value
		return staticError(errCodeXTSE0110,
			"xsl:%s version attribute %q is not a valid xs:decimal", localName, c.stylesheet.version)
	}

	return nil
}

func (c *compiler) readResultNamespacePolicy(root *xdm.Element) error {
	c.stylesheet.excludePrefixes = make(map[string]struct{})
	c.stylesheet.excludeURIs = make(map[string]struct{})

	if erp := getAttr(root, nameExcludeResultPrefixes); erp != "" {
		if erp == "#all" {
			for prefix := range c.stylesheet.namespaces {
				c.stylesheet.excludePrefixes[prefix] = struct{}{}
			}
		} else {
			if err := compilePreparedFieldsSeq(erp, c); err != nil {
				return err
			}
		}
	}
	// extension-element-prefixes are also excluded from output.
	// XTSE0800: reserved namespaces must not be used as extension namespaces.
	if eep := getAttr(root, nameExtensionElementPrefixes); eep != "" {
		for prefix := range strings.FieldsSeq(eep) {
			uri := c.nsBindings[prefix]
			if isReservedNamespace(uri) {
				return staticError(errCodeXTSE0800,
					"reserved namespace %q (prefix %q) must not be used as an extension namespace", uri, prefix)
			}

			c.stylesheet.excludePrefixes[prefix] = struct{}{}
			if uri != "" {
				if c.extensionURIs == nil {
					c.extensionURIs = make(map[string]struct{})
				}

				c.extensionURIs[uri] = struct{}{}
			}
		}
	}
	// Resolve excluded prefixes to URIs now, before template processing
	// can mutate c.stylesheet.namespaces. XSLT spec: exclude-result-prefixes
	// identifies namespace URIs, not prefix names.
	for prefix := range c.stylesheet.excludePrefixes {
		if uri, ok := c.stylesheet.namespaces[prefix]; ok {
			c.stylesheet.excludeURIs[uri] = struct{}{}
		}
	}

	return nil
}

func isReservedNamespace(uri string) bool {
	switch uri {
	case lexicon.NamespaceXSLT,
		lexicon.NamespaceXSD,
		lexicon.NamespaceFn,
		lexicon.NamespaceMath,
		lexicon.NamespaceMap,
		lexicon.NamespaceArray,
		lexicon.NamespaceXML,
		lexicon.NamespaceXMLNS:
		return true
	}

	return false
}

func compilePreparedFieldsSeq(erp string, c *compiler) error {
	for prefix := range strings.FieldsSeq(erp) {
		if prefix == lexicon.ModeDefault {
			c.stylesheet.excludePrefixes[""] = struct{}{}
			continue
		}
		// XTSE0808: prefix must be declared
		if _, ok := c.stylesheet.namespaces[prefix]; !ok {
			if _, ok := c.nsBindings[prefix]; !ok {
				return staticError(errCodeXTSE0808,
					"undeclared namespace prefix %q in exclude-result-prefixes", prefix)
			}
		}

		c.stylesheet.excludePrefixes[prefix] = struct{}{}
	}

	return nil
}

// completeTopLevelDeclarations runs checks that depend on finalized import
// precedence before sorting templates or validating cross-component references.
func (c *compiler) completeTopLevelDeclarations(ctx context.Context, root *xdm.Element, cfg *compileConfig) error {
	// XTSE0810: check for conflicting namespace-alias declarations
	// (same stylesheet URI, same import precedence, different result URIs)
	// unless a higher-precedence alias overrides. This runs after all
	// imports/includes are processed so import precedences are finalized.
	if err := c.checkConflictingNamespaceAliases(ctx); err != nil {
		return err
	}

	// XTSE0270: check for conflicting strip-space/preserve-space at same precedence
	if err := c.checkSpaceConflicts(ctx); err != nil {
		return err
	}

	// Process xsl:expose declarations for packages (after all components are compiled)
	if err := c.processExpose(ctx, root); err != nil {
		return err
	}

	// XTSE1290: check deferred decimal-format conflicts after all imports
	for qn, conflictPrec := range c.stylesheet.decimalFmtConflicts {
		actualPrec := c.stylesheet.decimalFmtPrec[qn]
		if actualPrec == conflictPrec {
			return staticError(errCodeXTSE1290,
				"conflicting xsl:decimal-format declarations")
		}
	}

	// XTSE1300: validate decimal format character uniqueness after all declarations
	for _, df := range c.stylesheet.decimalFormats {
		if err := checkDecimalFormatCharConflicts(df); err != nil {
			return err
		}
	}

	// XTSE0545: check deferred mode property conflicts after all imports
	if err := compilePreparedModeDefs(c); err != nil {
		return err
	}

	// XTSE3350: check deferred accumulator duplicate conflicts
	for name, acc := range c.stylesheet.accumulators {
		if acc.conflictDuplicate {
			return staticError(errCodeXTSE3350,
				"duplicate xsl:accumulator %q at the same import precedence", name)
		}
	}

	// XTSE3080: check that no abstract components remain unimplemented.
	// Only check for the top-level stylesheet, not sub-packages (which
	// may intentionally pass abstract components through).
	if !cfg.isSubPackage {
		if err := c.checkAbstractComponents(ctx); err != nil {
			return err
		}
	}

	return nil
}

func compilePreparedModeDefs(c *compiler) error {
	for name, md := range c.stylesheet.modeDefs {
		if md.conflictOnNoMatch {
			return staticError(errCodeXTSE0545, "conflicting on-no-match values for mode %q", name)
		}

		if md.conflictStreamable {
			return staticError(errCodeXTSE0545, "conflicting streamable values for mode %q", name)
		}

		if md.conflictVisibility {
			return staticError(errCodeXTSE0545, "conflicting visibility values for mode %q", name)
		}

		if md.conflictOnMultiple {
			return staticError(errCodeXTSE0545, "conflicting on-multiple-match values for mode %q", name)
		}

		if md.conflictAccumulator {
			return staticError(errCodeXTSE0545, "conflicting use-accumulators values for mode %q", name)
		}
	}

	return nil
}

func (c *compiler) recordStylesheetSource(doc *xdm.Document) {
	c.stylesheet.sourceDoc = doc
	c.stylesheet.baseURI = c.baseURI

	// Store the main module document in moduleDocs for document("") resolution.
	if c.stylesheet.moduleDocs == nil {
		c.stylesheet.moduleDocs = make(map[string]*xdm.Document)
	}

	if c.baseURI != "" {
		c.stylesheet.moduleDocs[c.baseURI] = doc
	}
}

func (c *compiler) validateDeferredReferences(ctx context.Context) error {
	// Validate deferred pattern function calls now that all xsl:function
	// declarations have been processed.
	for _, pv := range c.pendingPatternValidations {
		if err := c.validatePatternFunctions(ctx, pv.pattern, pv.source); err != nil {
			return err
		}
	}

	// XTSE0680: when xsl:call-template passes a non-tunnel parameter that
	// the target template declares as tunnel="yes" (or vice versa), that is
	// a static error.
	if err := checkCallTemplateTunnelMismatch(c.stylesheet); err != nil {
		return err
	}

	// XTSE1590: validate character map references.
	if err := checkCharacterMapRefs(c.stylesheet); err != nil {
		return err
	}

	// XTSE0720: detect cyclic use-attribute-sets references.
	if err := checkAttributeSetCycles(c.stylesheet); err != nil {
		return err
	}

	// XTSE0730: streamable attribute set must only reference other streamable sets.
	if err := checkAttributeSetStreamable(c.stylesheet); err != nil {
		return err
	}

	// XTSE0710: validate all use-attribute-sets references point to declared attribute sets.
	// Hidden/private attribute-sets from used packages are in the map for
	// internal reference resolution but must not be directly used from the
	// using stylesheet. Locally declared private attribute-sets (OwnerPackage
	// == nil) are always accessible from the stylesheet's own code.
	for _, ref := range c.usedAttrSetRefs {
		asd, ok := c.stylesheet.attributeSets[ref]
		if !ok {
			return staticError(errCodeXTSE0710, "use-attribute-sets references undeclared attribute-set %q", ref)
		}

		if asd != nil && asd.OwnerPackage != nil && (asd.Visibility == visHidden || asd.Visibility == visPrivate) {
			return staticError(errCodeXTSE0710, "use-attribute-sets references undeclared attribute-set %q", ref)
		}
	}

	// XTSE3085: when declared-modes is true (default for xsl:package),
	// all modes used in templates or xsl:apply-templates must be explicitly
	// declared via xsl:mode.
	if c.stylesheet.declaredModes {
		if err := checkDeclaredModes(c.stylesheet, c.usedModes); err != nil {
			return err
		}
	}

	// XTSE3105: for modes with typed="strict", check that match pattern
	// element names are declared in the imported schemas.
	if err := checkTypedModePatterns(c.stylesheet); err != nil {
		return err
	}

	// XTSE3070: deferred override-variable same-type checks for custom schema
	// types, now that the using package's import-schema types are compiled.
	if err := c.checkPendingOverrideTypes(); err != nil {
		return err
	}

	return nil
}

// checkDeclaredModes verifies that all modes referenced in the stylesheet
// (on xsl:template and xsl:apply-templates) are declared via xsl:mode when
// declared-modes is true (XTSE3085). The usedModes set is populated during
// compilation from both template mode attributes and apply-templates mode
// attributes.
func checkDeclaredModes(ss *Stylesheet, usedModes map[string]struct{}) error {
	for mode := range usedModes {
		if mode == modeCurrent || mode == modeAll {
			continue
		}
		// The unnamed mode ("", lexicon.ModeDefault, "#unnamed") must also be declared
		// when declared-modes is in effect.
		if mode == "" || mode == modeDefault || mode == modeUnnamed {
			// Check if unnamed mode is declared. It can be declared as "",
			// lexicon.ModeDefault, or "#unnamed" in modeDefs.
			if ss.modeDefs != nil {
				if _, ok := ss.modeDefs[""]; ok {
					continue
				}

				if _, ok := ss.modeDefs[modeDefault]; ok {
					continue
				}

				if _, ok := ss.modeDefs[modeUnnamed]; ok {
					continue
				}
			}

			displayName := mode
			if displayName == "" {
				displayName = modeUnnamed
			}

			return staticError(errCodeXTSE3085, "mode %q is used but not declared (declared-modes is in effect)", displayName)
		}

		if _, ok := ss.modeDefs[mode]; !ok {
			return staticError(errCodeXTSE3085, "mode %q is used but not declared (declared-modes is in effect)", mode)
		}
	}

	return nil
}

// checkCharacterMapRefs validates XTSE1590: all character map references
// (in use-character-maps attributes) must resolve to defined character maps.
func checkCharacterMapRefs(ss *Stylesheet) error {
	for _, cm := range ss.characterMaps {
		for _, ref := range cm.UseCharacterMaps {
			if _, ok := ss.characterMaps[ref]; !ok {
				return staticError(errCodeXTSE1590,
					"character map %q references undefined character map %q", cm.Name, ref)
			}
		}
	}
	// XTSE1600: detect circular character-map references
	var detectCycle func(name string, visited map[string]struct{}) error

	detectCycle = func(name string, visited map[string]struct{}) error {
		if _, inPath := visited[name]; inPath {
			return staticError(errCodeXTSE1600,
				"circular reference in character-map %q", name)
		}

		cm, ok := ss.characterMaps[name]
		if !ok {
			return nil
		}

		visited[name] = struct{}{}
		for _, ref := range cm.UseCharacterMaps {
			if err := detectCycle(ref, visited); err != nil {
				return err
			}
		}

		delete(visited, name)

		return nil
	}
	for name := range ss.characterMaps {
		if err := detectCycle(name, make(map[string]struct{})); err != nil {
			return err
		}
	}

	for _, outDef := range ss.outputs {
		for _, ref := range outDef.UseCharacterMaps {
			if _, ok := ss.characterMaps[ref]; !ok {
				return staticError(errCodeXTSE1590,
					"xsl:output references undefined character map %q", ref)
			}
		}
	}

	return nil
}

// checkCallTemplateTunnelMismatch validates XTSE0680: when xsl:call-template
// passes a parameter, the tunnel attribute on xsl:with-param must match the
// tunnel attribute on the target template's xsl:param.
func checkCallTemplateTunnelMismatch(ss *Stylesheet) error {
	params := collectTemplateCallParameters(ss)
	for _, tmpl := range ss.templates {
		if err := params.checkBody(tmpl.Body); err != nil {
			return err
		}
	}

	for _, fn := range ss.functions {
		if err := params.checkBody(fn.Body); err != nil {
			return err
		}
	}

	for _, variable := range ss.globalVars {
		if err := params.checkBody(variable.Body); err != nil {
			return err
		}
	}

	return nil
}

func collectTemplateCallParameters(ss *Stylesheet) templateCallParameters {
	params := make(templateCallParameters)

	for _, tmpl := range ss.templates {
		if tmpl.Name == "" {
			continue
		}

		declared := make(map[string]templateCallParam)
		for _, param := range tmpl.Params {
			declared[param.Name] = templateCallParam{tunnel: param.Tunnel, required: param.Required}
		}

		params[tmpl.Name] = declared
	}

	return params
}

func (c *compiler) finalizeCompiledStylesheet() {
	// Preserve compiler configuration so fn:transform nested compiles
	// behave consistently with top-level compilation.
	if c.packageResolver != nil {
		c.stylesheet.packageResolver = c.packageResolver
	}

	if c.resolver != nil {
		c.stylesheet.uriResolver = c.resolver
	}

	c.stylesheet.maxResourceBytes = c.maxResourceBytes

	c.stylesheet.parseOptions = c.parseOptions

	// Topologically sort accumulators so dependencies are evaluated first.
	sortAccumulatorOrder(c.stylesheet)

	finalizeOutput10(c.stylesheet)
}

// checkAbstractComponents checks that no abstract components remain
// unimplemented in the final compiled stylesheet. XTSE3080.
func (c *compiler) checkAbstractComponents(_ context.Context) error {
	for name, tmpl := range c.stylesheet.namedTemplates {
		if tmpl.Visibility == visAbstract {
			return staticError(errCodeXTSE3080,
				"abstract template %q has no implementation", name)
		}
	}

	for fk, fn := range c.stylesheet.functions {
		if fn.Visibility == visAbstract {
			return staticError(errCodeXTSE3080,
				"abstract function %s#%d has no implementation",
				fmt.Sprintf("{%s}%s", fk.Name.URI, fk.Name.Name), fk.Arity)
		}
	}

	return nil
}

// isXMLWhitespaceOnly returns true if s is empty or contains only XML
// whitespace characters: space (#x20), tab (#x9), CR (#xD), LF (#xA).
func isXMLWhitespaceOnly(s string) bool {
	for i := range len(s) {
		switch s[i] {
		case ' ', '\t', '\r', '\n':
			continue
		default:
			return false
		}
	}

	return true
}

func getAttr(elem *xdm.Element, name string) string {
	v, _ := elem.GetAttribute(name)
	return v
}

// parseXSDBool parses an xs:boolean value ("yes"/"no", lexicon.ValueTrue/lexicon.ValueFalse, "1"/"0")
// with whitespace trimming per the XSD specification.
func parseXSDBool(s string) (bool, bool) {
	switch strings.TrimSpace(s) {
	case lexicon.ValueYes, lexicon.ValueTrue, "1":
		return true, true
	case lexicon.ValueNo, lexicon.ValueFalse, "0":
		return false, true
	default:
		return false, false
	}
}

// xsdBoolTrue is a convenience wrapper: returns true when s parses as an XSD
// boolean with a true value, false otherwise (including empty/absent).
func xsdBoolTrue(s string) bool {
	v, _ := parseXSDBool(s)
	return v
}

// isBackwardsCompatible reports whether an effective XSLT version selects
// backwards-compatible processing — XSLT 1.0 behavior plus XPath 1.0
// compatibility mode. Per XSLT 3.0 §3.10 this is any effective version below 2.0
// (an effective version in [2.0, 3.0) behaves identically to 3.0).
func isBackwardsCompatible(ver string) bool {
	ver = strings.TrimSpace(ver)
	if ver == "" {
		return false
	}

	f, err := strconv.ParseFloat(ver, 64)
	if err != nil {
		return false
	}

	return f < 2.0
}

// resolveQName resolves a QName (prefix:local or just local) to an expanded name.
// If the QName has a prefix, it is resolved using the given namespace bindings
// and the result is returned in Clark notation: {uri}local.
// If no prefix, the name is returned as-is.
func resolveQName(qname string, nsBindings map[string]string) string {
	qname = strings.TrimSpace(qname)
	if braceIdx := strings.IndexByte(qname, '{'); braceIdx >= 0 {
		closeIdx := strings.IndexByte(qname, '}')
		if closeIdx > braceIdx {
			uri := qname[braceIdx+1 : closeIdx]

			local := qname[closeIdx+1:]
			if uri == "" {
				return local // Q{}local → just local (no namespace)
			}

			return xdm.ClarkName(uri, local)
		}
	}

	prefix, local, ok := strings.Cut(qname, ":")
	if !ok {
		return qname
	}

	if uri, ok := nsBindings[prefix]; ok {
		return xdm.ClarkName(uri, local)
	}
	// prefix not found; return as-is
	return qname
}

// isNonWhitespaceTextNode returns true if the node is a text or CDATA node
// containing non-whitespace content.
func isNonWhitespaceTextNode(n xdm.Node) bool {
	switch n.(type) {
	case *xdm.Text, *xdm.CDATASection:
		return !isXMLWhitespaceOnly(xdm.CharacterData(n))
	}

	return false
}

// hasNonEmptyContent returns true if the element has any child elements or
// non-whitespace text content.
func hasNonEmptyContent(elem *xdm.Element) bool {
	for child := range xdm.Children(elem) {
		if _, ok := child.(*xdm.Element); ok {
			return true
		}

		if isNonWhitespaceTextNode(child) {
			return true
		}
	}

	return false
}

// parseDOEAttr validates and parses a disable-output-escaping attribute value.
// Valid values are "yes"/"no"/lexicon.ValueTrue/lexicon.ValueFalse/"1"/"0" (with whitespace trimming).
// Returns SEPM0016 for invalid values.
func parseDOEAttr(v string) (bool, error) {
	v = strings.TrimSpace(v)
	switch v {
	case lexicon.ValueYes, lexicon.ValueTrue, "1":
		return true, nil
	case lexicon.ValueNo, lexicon.ValueFalse, "0":
		return false, nil
	default:
		return false, staticError(errCodeSEPM0016,
			"%q is not a valid value for disable-output-escaping", v)
	}
}

// hasSignificantContent returns true if the element has child elements or
// non-whitespace text content (i.e., it has a sequence constructor body).
func hasSignificantContent(elem *xdm.Element) bool {
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

// hasSignificantChildren returns true if elem has any non-whitespace-only
// text children, or element children other than xsl:fallback.
func hasSignificantChildren(elem *xdm.Element) bool {
	for child := range xdm.Children(elem) {
		switch c := child.(type) {
		case *xdm.Element:
			if c.URI() == lexicon.NamespaceXSLT && c.LocalName() == lexicon.XSLTElementFallback {
				continue
			}

			return true
		case *xdm.Text:
			if !isXMLWhitespaceOnly(xdm.CharacterData(c)) {
				return true
			}
		}
	}

	return false
}

func isValidEQName(s string) bool {
	if !strings.HasPrefix(s, "Q{") {
		return false
	}

	closeIdx := strings.IndexByte(s, '}')
	if closeIdx < 0 || closeIdx == len(s)-1 {
		return false
	}

	local := s[closeIdx+1:]

	return xmlchar.IsValidNCName(local)
}

// isForwardRef checks whether an ErrUndefinedVariable error references a
// variable that has NOT been declared yet in the module. moduleStaticNames
// lists the names seen so far (including currentName). If the undefined
// variable name is NOT in that list, it may come from an import that has
// not been processed yet, which is not a forward-reference error.
func isForwardRef(err error, moduleStaticNames []string, currentName string) bool {
	msg := err.Error()
	// Extract the variable name from "xpath: undefined variable: $NAME"
	const prefix = "$"

	idx := strings.LastIndex(msg, prefix)
	if idx < 0 {
		return false
	}

	refName := msg[idx+1:]

	// The referenced name must be declared in this module's static
	// names list but AFTER the current name.
	foundCurrent := false

	for _, n := range moduleStaticNames {
		if n == currentName {
			foundCurrent = true
			continue
		}

		if foundCurrent && n == refName {
			return true // forward reference within same module
		}
	}

	return false
}

type templateCallParam struct {
	tunnel   bool
	required bool
}

type templateCallParameters map[string]map[string]templateCallParam

func (params templateCallParameters) checkBody(body []instruction) error {
	for _, inst := range body {
		if call, ok := inst.(*callTemplateInst); ok {
			if err := params.checkCall(call); err != nil {
				return err
			}
		}

		for _, children := range instructionChildren(inst) {
			if err := params.checkBody(children); err != nil {
				return err
			}
		}
	}

	return nil
}

func (params templateCallParameters) checkCall(call *callTemplateInst) error {
	target, found := params[call.Name]
	if !found {
		return nil
	}

	supplied := make(map[string]struct{})

	for _, param := range call.Params {
		if param.Tunnel {
			continue
		}

		supplied[param.Name] = struct{}{}
		declared, exists := target[param.Name]

		if exists && declared.tunnel {
			return staticError(errCodeXTSE0680,
				"xsl:call-template: non-tunnel parameter %q corresponds to tunnel parameter in target template",
				param.Name)
		}

		if !exists && !call.Compat {
			return staticError(errCodeXTSE0680,
				"xsl:call-template: parameter %q not declared in target template %q",
				param.Name, call.Name)
		}
	}

	// Required non-tunnel parameters are checked after supplied parameters,
	// so XTSE0680 takes precedence over XTSE0690 when both are present.
	for name, declared := range target {
		if !declared.required || declared.tunnel {
			continue
		}

		if _, ok := supplied[name]; !ok {
			return staticError(errCodeXTSE0690,
				"xsl:call-template: required parameter %q not supplied for template %q",
				name, call.Name)
		}
	}

	return nil
}
