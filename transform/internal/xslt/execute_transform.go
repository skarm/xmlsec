// Derived from lestrrat-go/helium at 7362c0a70122a757780f4d0b545a9b370dead6ab.
// Copyright (c) 2015 lestrrat. MIT License; see licenses/MIT-helium.txt at the repository root.

package xslt

import (
	"context"
	"maps"
	"strings"
	"time"

	"github.com/skarm/xmlsec/transform/internal/xdm"
	"github.com/skarm/xmlsec/transform/internal/xdm/lexicon"
	"github.com/skarm/xmlsec/transform/internal/xpath"
)

// remapValidationNode resolves a node from the original (validated) source tree to
// the corresponding node in the stripped copy the transform runs on. Strict source
// validation runs on the original tree, so its type annotations and nilled flags are
// keyed by original nodes; the transform navigates the copy, so those keys must be
// remapped. When nodeMap is nil (no strip rules — original and copy are the same
// tree) or the node has no copy (e.g. it was omitted from the copy), the node is
// returned unchanged.
func remapValidationNode(nodeMap map[xdm.Node]xdm.Node, node xdm.Node) xdm.Node {
	if nodeMap == nil || node == nil {
		return node
	}

	if mapped, ok := nodeMap[node]; ok {
		return mapped
	}

	return node
}

// mapElementAttributes records the correspondence between the attributes of an
// original element and those of its copy, keyed by expanded (URI, local) name
// (unique within a single element).
func mapElementAttributes(nodeMap map[xdm.Node]xdm.Node, ea, eb *xdm.Element) {
	copyAttrs := make(map[string]*xdm.Attribute)
	for _, attr := range eb.Attributes() {
		copyAttrs[xdm.ClarkName(attr.URI(), attr.LocalName())] = attr
	}

	for _, attr := range ea.Attributes() {
		if dst, ok := copyAttrs[xdm.ClarkName(attr.URI(), attr.LocalName())]; ok {
			nodeMap[attr] = dst
		}
	}
}

// executeTransform keeps source preparation, global initialization, initial
// invocation and result delivery in their required evaluation order.
func executeTransform(ctx context.Context, source *xdm.Document, ss *Stylesheet, cfg *transformConfig) (*xdm.Document, error) {
	if ss == nil {
		return nil, errNilStylesheet
	}

	var matchSelection xdm.Sequence
	if cfg != nil {
		matchSelection = cfg.initialMatchSelection
	}
	// Remember that a selection was supplied even if stripping removes every
	// selected node; an empty selection must not fall back to the source root.
	selectionSupplied := matchSelection != nil

	ec := newTransformExecContext(ctx, source, ss, cfg)
	resultDoc := ec.resultDoc

	matchSelection, err := ec.prepareTransformSource(matchSelection)
	if err != nil {
		return nil, err
	}

	restoreGlobalContextItem := ec.prepareTransformGlobalContext(ctx, cfg)
	ctx = withExecContext(ctx, ec)

	if err := ec.initializeTransformGlobals(ctx, cfg, restoreGlobalContextItem); err != nil {
		return nil, err
	}

	if err := ec.prepareTransformAccumulators(ctx); err != nil {
		return nil, err
	}

	if cfg != nil && cfg.initialFunction != "" {
		return ec.executeInitialFunction(ctx, cfg)
	}

	if err := ec.executeInitialTemplates(ctx, cfg, matchSelection, selectionSupplied); err != nil {
		return nil, err
	}

	if cfg != nil && cfg.rawSequence {
		for uri, doc := range ec.resultDocuments {
			items := ec.resultDocItems[uri]
			if items == nil {
				for child := range xdm.Children(doc) {
					items = xdm.ItemSlice(append(xdm.Materialize(items), xdm.NodeItem{Node: child}))
				}
			}

			cfg.valueResults[uri] = ValueResult{Document: doc, Items: items, Output: ec.resultDocOutputDefs[uri]}
		}
	} else if err := ec.serializeSecondaryResults(); err != nil {
		return nil, err
	}

	if err := ec.deliverSecondaryResults(cfg); err != nil {
		return nil, err
	}

	if err := ec.deliverRawResult(cfg); err != nil {
		return nil, err
	}

	if err := ec.deliverPrimaryItems(cfg); err != nil {
		return nil, err
	}

	outDef := ec.resolvePrimaryOutputDef()
	if cfg != nil {
		cfg.resolvedOutputDef = outDef
	}

	if err := ec.deliverTransformAnnotations(cfg); err != nil {
		return nil, err
	}

	return resultDoc, nil
}

func newTransformExecContext(ctx context.Context, source *xdm.Document, ss *Stylesheet, cfg *transformConfig) *execContext {
	resultDoc := xdm.NewDefaultDocument()

	captureItems := cfg != nil && cfg.rawCapture
	if defOut := ss.outputs[""]; defOut != nil && isItemSerializationMethod(defOut.Method) {
		captureItems = true
	}

	ec := &execContext{
		budgetCtx:           ctx,
		stylesheet:          ss,
		sourceDoc:           source,
		resultDoc:           resultDoc,
		globalVars:          make(map[string]xdm.Sequence),
		currentMode:         "",
		outputStack:         []*outputFrame{{doc: resultDoc, current: resultDoc, itemSeparator: ss.defaultItemSeparator(), captureItems: captureItems, sequenceMode: cfg != nil && cfg.rawSequence}},
		keyTables:           make(map[string]*keyTable),
		docCache:            make(map[string]*xdm.Document),
		functionResultCache: make(map[string]xdm.Sequence),
		accumulatorState:    make(map[string]xdm.Sequence),
		currentTime:         xpath.CurrentTime(ctx, time.Now().UTC()),
		resultDocuments:     make(map[string]*xdm.Document),
		resultDocItems:      make(map[string]xdm.Sequence),
		resultDocOutputDefs: make(map[string]*OutputDef),
		resultDocHrefs:      make(map[string]string),
		usedResultURIs:      make(map[string]struct{}),
		defaultValidation:   ss.defaultValidation,
		defaultCollation:    ss.defaultCollation,
		docOrderCache:       xpath.NewDocOrderCache(),
	}
	ec.setCurrentTemplate(nil) // start with no current template; baseDir() falls back to the stylesheet base
	// Set the principal output method so that isItemOutputMethod() returns
	// true when the default xsl:output method is json or adaptive.  Without
	// this, maps/arrays/functions produced during the principal result tree
	// construction would raise XTDE0450 even though the serialization method
	// allows non-node items.
	if defOut := ss.outputs[""]; defOut != nil && defOut.Method != "" {
		ec.currentResultDocMethod = defOut.Method
	}
	// Record the output XML version on the result document so any serializer —
	// including a plain DOM writer that does not consult the output definition —
	// serializes XML 1.1 restricted control characters as character references.
	if defOut := ss.outputs[""]; defOut != nil && defOut.Version != "" {
		resultDoc.SetVersion(defOut.Version)
	}

	if source != nil {
		ec.currentNode = source
		ec.contextNode = source
		ec.position = 1
		ec.size = 1
	}

	if cfg != nil && cfg.msgHandler != nil {
		ec.msgHandler = cfg.msgHandler
	}

	if cfg != nil && cfg.traceWriter != nil {
		ec.traceWriter = cfg.traceWriter
	}

	if cfg != nil && cfg.baseOutputURI != "" {
		ec.currentOutputURI = cfg.baseOutputURI
		// The principal result tree always exists and its URI is the base output
		// URI, so reserve the canonical form of that URI up front. A secondary
		// xsl:result-document whose href resolves to it denotes the SAME final
		// result tree and must raise XTDE1490. Canonicalize with the SAME resolver
		// the secondary duplicate key uses (canonicalResultURIKey) so a relative
		// secondary href and the equivalent absolute one both match this seed.
		// The primary output itself keys on the "" sentinel, so this distinct
		// canonical key never makes the primary collide with itself.
		ec.canonicalPrimaryURI = canonicalResultURIKey(cfg.baseOutputURI, "")
		ec.usedResultURIs[ec.canonicalPrimaryURI] = struct{}{}
	} else if cfg != nil && cfg.outputBaseURI != "" {
		// No base-output-uri was supplied, so the principal output has no declared
		// URI (no canonicalPrimaryURI reservation; the principal result-map key
		// stays "output"). Secondary xsl:result-document output URIs still resolve
		// against the best available base — the call's effective static base URI —
		// so their result-map keys are absolute whenever any base exists.
		ec.currentOutputURI = cfg.outputBaseURI
	}
	// Make the transform config (and thus its URIResolver) available before
	// any runtime resource loading. initGlobalVars also assigns this; setting
	// it here ensures schema-location loads below route through the resolver.
	ec.transformConfig = cfg

	return ec
}

func (ec *execContext) prepareTransformSource(matchSelection xdm.Sequence) (xdm.Sequence, error) {
	effectiveSource := ec.sourceDoc
	ss := ec.stylesheet

	// Whitespace stripping uses a private project-tree clone. Unchanged source
	// snapshots retain their original node identity and are never mutated.
	if effectiveSource != nil && len(ss.stripSpace) > 0 {
		needSelectionMap := matchSelection != nil && xdm.SequenceLen(matchSelection) > 0

		srcCopy, nodeMap, copyErr := copyAndStrip(effectiveSource, ss.stripSpace, ss.preserveSpace, needSelectionMap || len(ec.typeAnnotations) > 0)
		if copyErr != nil {
			return nil, copyErr
		}

		if needSelectionMap {
			matchSelection = remapSelectionToCopy(matchSelection, effectiveSource, nodeMap)
		}

		if nodeMap != nil {
			ec.remapAnnotationsToCopy(nodeMap)
		}

		ec.sourceDoc = srcCopy
		ec.currentNode = srcCopy
		ec.contextNode = srcCopy
	}

	// Apply input-type-annotations="strip": remove all type annotations from
	// the source document so elements are xs:untyped and attributes xs:untypedAtomic.
	// The is-id and is-idref properties are preserved (per XSLT 3.0 §3.12)
	// so that fn:id() and fn:idref() still work.
	if ss.inputTypeAnnotations == validationStrip && ec.typeAnnotations != nil {
		ec.preserveIDAnnotations()

		for k := range ec.typeAnnotations {
			delete(ec.typeAnnotations, k)
		}
	}

	return matchSelection, nil
}

// remapSelectionToCopy rewrites the node items of an initial match selection so
// that any node belonging to the original source document points instead to the
// corresponding node in the stripped copy. Items that are not nodes, or that
// belong to a different document (e.g. fn:doc()-loaded), are passed through
// unchanged. A node that DID belong to the original source but has no copy (a
// whitespace-only text/CDATA node that strip-space omitted) is DROPPED from the
// selection, so it neither points at the unstripped original nor inflates the
// sequence length that drives position()/last() in the apply loop.
//
// src is the original source document the selection was computed against; it is
// used only to distinguish an omitted source node (drop) from a node in another
// document (pass through).
//
// nodeMap is the original->copy correspondence built by copyAndStrip during the
// single-pass copy. Because whitespace-only nodes are omitted from the copy, the
// two trees no longer share a child shape, so the map (not a parallel walk) is
// the only correct source of correspondence. It already covers elements,
// text/comment/PI leaves, the document node, and each element's attributes (keyed
// by expanded name). Namespace nodes are wrappers off the child spine; a selected
// *xdm.NamespaceNodeWrapper is remapped by locating the mapped owner element
// and rebuilding an equivalent wrapper bound to a matching namespace declaration
// in scope on the copy. This ensures every selected node (element, text, comment,
// PI, attribute, namespace) points into the stripped copy, so XPath navigation
// from a matched template observes the same tree as the context node.
func remapSelectionToCopy(sel xdm.Sequence, src *xdm.Document, nodeMap map[xdm.Node]xdm.Node) xdm.Sequence {
	items := make(xdm.ItemSlice, 0, xdm.SequenceLen(sel))
	for i := range xdm.SequenceLen(sel) {
		item := sel.Get(i)

		ni, ok := item.(xdm.NodeItem)
		if !ok {
			items = append(items, item)
			continue
		}
		// Namespace nodes are wrappers off the child spine: remap by relocating
		// the owner element onto the copy and rebuilding an equivalent wrapper.
		if nsw, ok := ni.Node.(*xdm.NamespaceNodeWrapper); ok {
			if mapped := remapNamespaceWrapper(nodeMap, nsw); mapped != nil {
				items = append(items, xdm.NodeItem{Node: mapped})
				continue
			}

			items = append(items, item)

			continue
		}

		if mapped, found := nodeMap[ni.Node]; found {
			items = append(items, xdm.NodeItem{Node: mapped})
			continue
		}
		// No copy exists. If the node belonged to the original source, strip-space
		// omitted it (whitespace-only text/CDATA): drop it so it is absent from the
		// stripped selection and does not skew position()/last(). Nodes from other
		// documents (e.g. fn:doc()-loaded) keep their identity and pass through.
		if ni.Node != nil && ni.Node.OwnerDocument() == src {
			continue
		}

		items = append(items, item)
	}

	return items
}

// remapNamespaceWrapper rebuilds an initial-selection namespace node so that it
// belongs to the copied tree. It maps the wrapper's owner element onto the copy,
// then returns a fresh wrapper bound to a matching namespace, with the COPIED
// owner as parent. Returns nil only if the owner element could not be mapped.
//
// The wrapper is re-bound by preference to an in-scope declaration on the copied
// owner (or an ancestor) with the same prefix and URI, since namespace nodes can
// be reported on a descendant of the element that declares them. When no such
// declaration exists, the namespace is one the XPath axis SYNTHESIZES, and none
// stored in Namespaces() — most notably the implicit `xml` binding, which the
// namespace axis fabricates and which never appears in any element's declarations
// (see transform/internal/xpath/axes.go CollectNamespaceNodes). For those, synthesize an
// equivalent Namespace bound to the copied owner, mirroring the axis, so the
// wrapper still points into the stripped copy instead of falling back to the
// unstripped original.
func remapNamespaceWrapper(nodeMap map[xdm.Node]xdm.Node, nsw *xdm.NamespaceNodeWrapper) xdm.Node {
	owner := nsw.Parent()
	if owner == nil {
		return nil
	}

	mappedOwner, ok := nodeMap[owner]
	if !ok {
		return nil
	}

	prefix := nsw.Name()
	uri := xdm.CharacterData(nsw)
	// Prefer an actual in-scope declaration on the copied owner or an ancestor
	// that matches the original wrapper's (prefix, URI).
	for n := mappedOwner; n != nil; n = n.Parent() {
		nc, ok := n.(xdm.NamespaceContainer)
		if !ok {
			continue
		}

		for _, ns := range nc.Namespaces() {
			if ns.Prefix() == prefix && ns.URI() == uri {
				return xdm.NewNamespaceNodeWrapper(ns, mappedOwner)
			}
		}
	}
	// No stored declaration matches: the namespace is synthesized by the axis
	// (e.g. the implicit `xml` binding). Re-synthesize it against the copied
	// owner so the wrapper still belongs to the stripped copy.
	return xdm.NewNamespaceNodeWrapper(xdm.NewNamespace(prefix, uri), mappedOwner)
}

func (ec *execContext) prepareTransformGlobalContext(ctx context.Context, cfg *transformConfig) bool {
	effectiveSource := ec.sourceDoc
	ss := ec.stylesheet

	// When a globalContextSelect expression is provided, evaluate it against
	// the (possibly stripped) source document.  If the result is empty, the
	// global context item is absent and global variables referencing "."
	// will raise XPDY0002.
	if cfg != nil && cfg.globalContextSelect != "" && effectiveSource != nil {
		expr, compErr := xpath.NewCompiler().Compile(cfg.globalContextSelect)
		if compErr == nil {
			gcEval := xpath.NewEvaluator(xpath.DefaultEvaluatorOptions)
			if cfg.parseOptions != nil {
				gcEval = gcEval.ParseOptions(*cfg.parseOptions)
			}

			result, evalErr := gcEval.Evaluate(ctx, expr, effectiveSource)
			if evalErr != nil || xdm.SequenceLen(result.Sequence()) == 0 {
				ec.globalContextAbsent = true
			}
		}
	}

	// Establish the global context item used when evaluating global
	// variables/parameters, per F&O 3.1 §14.8 (the global-context-item option is
	// an item()) and XSLT 3.0 §5.4.3.1 (xsl:global-context-item).
	//   - use="absent": the global context item is absent regardless of any
	//     supplied option, so a supplied global-context-item is NOT installed and
	//     a global "." reference raises XPDY0002.
	//   - an explicit global-context-item overrides the default (the source
	//     document node). When it is a node, global initialisers see it as "."
	//     (globalSourceNode) while the initial match selection still drives
	//     template matching independently; a non-node item (atomic/map/array/
	//     function) has no context node, so it is exposed through ec.contextItem
	//     for the duration of global evaluation only.
	//   - no source-node and no explicit item (cfg.globalContextAbsent): the
	//     global context item is absent (XPDY0002 on "."; XTDE3086 if required).
	restoreGlobalContextItem := false

	switch {
	case ss.globalContextItem != nil && ss.globalContextItem.Use == ctxItemAbsent:
		ec.globalContextAbsent = true
	case cfg != nil && cfg.globalContextItem != nil:
		ec.globalContextItem = cfg.globalContextItem
		if _, isNode := cfg.globalContextItem.(xdm.NodeItem); !isNode {
			ec.contextItem = cfg.globalContextItem
			restoreGlobalContextItem = true
		}
	case cfg != nil && cfg.globalContextAbsent:
		ec.globalContextAbsent = true
	}

	return restoreGlobalContextItem
}

func (ec *execContext) initializeTransformGlobals(ctx context.Context, cfg *transformConfig, restoreGlobalContextItem bool) error {
	effectiveSource := ec.sourceDoc
	ss := ec.stylesheet

	if err := ec.initGlobalVars(ctx, cfg); err != nil {
		return err
	}

	// XTTE0590: validate global context item against declared type.
	if err := ec.validateGlobalContextItem(ctx, effectiveSource); err != nil {
		return err
	}

	// XPDY0002: when the initial mode is streamable and the principal source
	// document is provided, global variables whose select expressions depend
	// on the document context are not allowed — the streamed document is not
	// available for random access.
	if effectiveSource != nil && cfg != nil && cfg.initialMode != "" {
		if md := ss.modeDefs[cfg.initialMode]; md != nil && md.Streamable {
			if err := checkGlobalVarsStreamingContext(ss); err != nil {
				return err
			}
		}
	}

	// Eagerly evaluate all global variables and parameters so that errors
	// (e.g. FOAR0001 from division by zero) are raised before any template
	// execution begins.  This ensures that global-variable evaluation errors
	// are non-recoverable and cannot be caught by xsl:try/xsl:catch.
	if err := ec.evaluateAllGlobals(ctx); err != nil {
		return err
	}
	// The non-node global-context-item was exposed as ec.contextItem only for
	// global evaluation; clear it so it does not leak into template execution.
	if restoreGlobalContextItem {
		ec.contextItem = nil
	}

	return nil
}

func (ec *execContext) prepareTransformAccumulators(ctx context.Context) error {
	effectiveSource := ec.sourceDoc
	ss := ec.stylesheet

	// Pre-compute accumulator states for the main source document so that
	// accumulator-before() / accumulator-after() work during template execution.
	// This mirrors what xsl:source-document does via prepareSourceDocumentAccumulators.
	if len(ss.accumulators) > 0 && effectiveSource != nil {
		names := append([]string(nil), ss.accumulatorOrder...)
		if err := ec.computeAccumulatorStates(ctx, effectiveSource, names); err != nil {
			return err
		}
		// Mark this document as computed so lazy computation doesn't redo it.
		if ec.accumulatorComputedDocs == nil {
			ec.accumulatorComputedDocs = make(map[xdm.Node]struct{})
		}

		ec.accumulatorComputedDocs[documentRoot(effectiveSource)] = struct{}{}
	}

	return nil
}

func (ec *execContext) executeInitialFunction(ctx context.Context, cfg *transformConfig) (*xdm.Document, error) {
	ss := ec.stylesheet

	cfg.resolvedOutputDef = cloneOutputDef(ss.outputs[""])

	doc, err := ec.invokeInitialFunction(ctx, cfg)
	if err != nil {
		return nil, err
	}

	if err := ec.deliverRawResult(cfg); err != nil {
		return nil, err
	}

	out := ec.currentOutput()
	if out != nil && len(out.pendingItems) > 0 {
		if cfg.rawCapture {
			cfg.rawCapturedItems = out.pendingItems
		}

		cfg.primaryItems = out.pendingItems
	}

	return doc, nil
}

func (ec *execContext) initialTemplateName(cfg *transformConfig) string {
	initialTemplateName := ""
	if cfg != nil && cfg.initialTemplate != "" {
		initialTemplateName = resolveQName(cfg.initialTemplate, ec.stylesheet.namespaces)
	}

	// XSLT 3.0: if no explicit initial template, check for xsl:initial-template
	if initialTemplateName == "" {
		xsltInitial := xdm.ClarkName(lexicon.NamespaceXSLT, "initial-template")
		if _, ok := ec.stylesheet.namedTemplates[xsltInitial]; ok {
			initialTemplateName = xsltInitial
		} else if _, ok := ec.stylesheet.namedTemplates["xsl:initial-template"]; ok {
			initialTemplateName = "xsl:initial-template"
		}
	}

	return initialTemplateName
}

func (ec *execContext) executeInitialTemplates(ctx context.Context, cfg *transformConfig, matchSelection xdm.Sequence, selectionSupplied bool) error {
	initialTemplateName := ec.initialTemplateName(cfg)
	initialMode := ""

	if cfg != nil && cfg.initialMode != "" {
		initialMode = cfg.initialMode
	}

	if initialTemplateName != "" {
		return ec.executeNamedInitialTemplate(ctx, cfg, initialTemplateName, initialMode)
	}

	return ec.applyInitialTemplates(ctx, cfg, matchSelection, selectionSupplied, initialMode)
}

func (ec *execContext) executeNamedInitialTemplate(ctx context.Context, cfg *transformConfig, initialTemplateName, initialMode string) error {
	// XSLT 3.0 section 2.3.4 defaults the initial template's singleton focus
	// to the global context item, independently of the initial match selection.
	effectiveSource := ec.globalSourceNode()

	savedItem := ec.contextItem

	ec.contextItem = nil
	if !ec.globalContextAbsent && effectiveSource == nil {
		ec.contextItem = ec.globalContextItem
	}
	defer func() { ec.contextItem = savedItem }()

	ec.position, ec.size = 1, 1

	tmpl := ec.stylesheet.namedTemplates[initialTemplateName]
	if tmpl == nil {
		return dynamicError(errCodeXTDE0040, "initial template %q not found", initialTemplateName)
	}
	// XTDE0040: initial template must be public in a package context
	if ec.stylesheet.isPackage && tmpl.Visibility != "" && tmpl.Visibility != visPublic && tmpl.Visibility != visFinal {
		return dynamicError(errCodeXTDE0040, "initial template %q is not public (visibility=%q)", initialTemplateName, tmpl.Visibility)
	}
	// Also check for templates with no explicit visibility in packages (default=private)
	if ec.stylesheet.isPackage && tmpl.Visibility == "" {
		return dynamicError(errCodeXTDE0040, "initial template %q is not public", initialTemplateName)
	}
	// XTDE0060: initial template must not have any required parameters
	// that are not supplied by the caller.
	for _, p := range tmpl.Params {
		if !p.Required {
			continue
		}

		supplied := false

		if cfg != nil {
			parameters := cfg.initialTemplateParams
			if p.Tunnel {
				parameters = cfg.initialTemplateTunnel
			}

			if _, ok := parameters[p.Name]; ok {
				supplied = true
			}
		}

		if !supplied {
			return dynamicError(errCodeXTDE0700, "initial template %q has required parameter $%s", initialTemplateName, p.Name)
		}
	}
	// Pass caller-supplied initial-template params.
	var initialParams map[string]xdm.Sequence
	if cfg != nil && len(cfg.initialTemplateParams) > 0 {
		initialParams = cloneSequenceMap(cfg.initialTemplateParams)
	}

	if cfg != nil && len(cfg.initialTemplateTunnel) > 0 {
		ec.tunnelParams = cloneSequenceMap(cfg.initialTemplateTunnel)
	}

	if err := ec.executeTemplate(ctx, tmpl, effectiveSource, initialMode, initialParams); err != nil {
		return err
	}

	return nil
}

func (ec *execContext) applyInitialTemplates(ctx context.Context, cfg *transformConfig, matchSelection xdm.Sequence, selectionSupplied bool, initialMode string) error {
	if initialMode != "" {
		if err := ec.checkInitialMode(initialMode); err != nil {
			return err
		}
	}

	if ec.sourceDoc == nil && !selectionSupplied {
		return dynamicError(errCodeXTDE0040, "no source document and no initial template")
	}

	var initialModeParams map[string]xdm.Sequence
	if cfg != nil && len(cfg.initialModeParams) > 0 {
		initialModeParams = cloneSequenceMap(cfg.initialModeParams)
	}

	savedTunnel := ec.tunnelParams
	if cfg != nil && len(cfg.initialModeTunnel) > 0 {
		ec.tunnelParams = cloneSequenceMap(cfg.initialModeTunnel)
	}

	defer func() { ec.tunnelParams = savedTunnel }()

	if selectionSupplied {
		return ec.applyInitialSelection(ctx, matchSelection, initialMode, initialModeParams)
	}

	return ec.applyTemplates(ctx, ec.sourceDoc, initialMode, initialModeParams)
}

func (ec *execContext) applyInitialSelection(ctx context.Context, selection xdm.Sequence, initialMode string, params map[string]xdm.Sequence) error {
	resolvedMode := ec.resolveInitialSelectionMode(initialMode)
	selLen := xdm.SequenceLen(selection)

	for i := range selLen {
		item := selection.Get(i)
		switch v := item.(type) {
		case xdm.NodeItem:
			ec.contextNode = v.Node
			ec.currentNode = v.Node
			ec.position = i + 1
			ec.size = selLen

			if err := ec.applyTemplates(ctx, v.Node, initialMode, params); err != nil {
				return err
			}
		case xdm.AtomicValue:
			ec.contextItem = v
			ec.position = i + 1
			ec.size = selLen

			if err := ec.applyInitialAtomic(ctx, v, resolvedMode, params); err != nil {
				return err
			}
		}
	}

	return nil
}

func (ec *execContext) resolveInitialSelectionMode(mode string) string {
	switch mode {
	case modeCurrent:
		mode = ec.currentMode
	case modeUnnamed:
		mode = ""
	case modeDefault, "":
		mode = ec.stylesheet.defaultMode
	}

	if mode == modeUnnamed {
		return ""
	}

	return mode
}

func (ec *execContext) applyInitialAtomic(ctx context.Context, value xdm.AtomicValue, mode string, params map[string]xdm.Sequence) error {
	tmpl, err := ec.findAtomicTemplate(ctx, value, mode)
	if err != nil {
		return err
	}

	if tmpl != nil {
		return ec.executeAtomicTemplate(ctx, tmpl, value, mode, params)
	}

	// Built-in atomic template: emit its string value and preserve conversion errors.
	atomic, err := xpath.AtomizeItem(value)
	if err != nil {
		return err
	}

	text, err := xpath.AtomicToString(atomic)
	if err != nil {
		return err
	}

	return ec.addNode(ec.resultDoc.CreateText(text))
}

func (ec *execContext) serializeSecondaryResults() error {
	ss := ec.stylesheet

	// For secondary result documents with json/adaptive method, serialize
	// captured items into the document so the handler receives the complete output.
	// Keys here are the RESOLVED absolute output URI (the same key used across
	// resultDocItems/resultDocuments/resultDocOutputDefs).
	for uri, items := range ec.resultDocItems {
		if items == nil || xdm.SequenceLen(items) == 0 {
			continue
		}

		doc := ec.resultDocuments[uri]
		if doc == nil {
			doc = xdm.NewDefaultDocument()
			doc.SetURL(uri)
			ec.resultDocuments[uri] = doc
		}
		// Serialize items into a text node in the document.
		var buf strings.Builder

		outDef := ec.resultDocOutputDefs[uri]
		if outDef == nil {
			outDef = ss.outputs[""] // fallback to default
		}
		// A serialization failure (e.g. SERE0006 for a character invalid in the
		// target XML version) must surface as a transform error, not a silently
		// empty secondary document.
		if err := SerializeItems(&buf, items, doc, outDef); err != nil {
			return err
		}

		text := doc.CreateText(buf.String())
		if text != nil {
			_ = doc.AddChild(text)
		}
	}

	return nil
}

func (ec *execContext) deliverSecondaryResults(cfg *transformConfig) error {
	if cfg == nil || cfg.resultDocHandler == nil {
		return nil
	}

	for uri, doc := range ec.resultDocuments {
		outDef := ec.resultDocOutputDefs[uri]
		if err := cfg.resultDocHandler.HandleResultDocument(uri, doc, outDef); err != nil {
			return err
		}
	}

	return nil
}

func (ec *execContext) deliverRawResult(cfg *transformConfig) error {
	if cfg != nil && cfg.rawResultHandler != nil && ec.rawResultSequence != nil {
		return cfg.rawResultHandler.HandleRawResult(ec.rawResultSequence)
	}

	return nil
}

func (ec *execContext) deliverPrimaryItems(cfg *transformConfig) error {
	out := ec.currentOutput()
	if cfg == nil || out == nil || len(out.pendingItems) == 0 {
		return nil
	}

	if err := ec.validatePrimaryJSONItems(out.pendingItems); err != nil && !cfg.rawSequence {
		return err
	}

	if cfg.rawCapture {
		cfg.rawCapturedItems = out.pendingItems
	}

	cfg.primaryItems = out.pendingItems
	if cfg.primaryItemsHandler != nil {
		return cfg.primaryItemsHandler.HandlePrimaryItems(out.pendingItems)
	}

	return nil
}

// validatePrimaryJSONItems uses the effective primary output definition,
// including overrides already folded in by xsl:result-document.
func (ec *execContext) validatePrimaryJSONItems(items xdm.Sequence) error {
	if ec.currentResultDocMethod != methodJSON {
		return nil
	}

	allowDupes := false
	if defOut := ec.stylesheet.outputs[""]; defOut != nil {
		allowDupes = defOut.AllowDuplicateNames
	}

	if ec.primaryOutputOverrides != nil {
		allowDupes = ec.primaryOutputOverrides.AllowDuplicateNames
	}

	if !allowDupes {
		return validateJSONItems(items)
	}

	return nil
}

func (ec *execContext) resolvePrimaryOutputDef() *OutputDef {
	ss := ec.stylesheet

	// Build the per-invocation output definition for the primary result.
	// Clone before mutating so the compiled stylesheet is never modified.
	outDef := ss.outputs[""]
	if outDef != nil {
		outDef = cloneOutputDef(outDef)
		allMapNames := outDef.UseCharacterMaps

		allMapNames = append(allMapNames, ec.primaryCharacterMaps...)
		if len(allMapNames) > 0 {
			// If we already have package-resolved character maps, use those
			// instead of re-resolving from the main stylesheet (package
			// isolation: character maps are scoped per-package).
			if len(ec.primaryResolvedCharMap) > 0 {
				outDef.ResolvedCharMap = ec.primaryResolvedCharMap
			} else {
				outDef.ResolvedCharMap = resolveCharacterMaps(ss, allMapNames)
			}
		}
	} else if len(ec.primaryCharacterMaps) > 0 {
		outDef = &OutputDef{Method: methodXML, Encoding: lexicon.EncodingUTF8U}
		if len(ec.primaryResolvedCharMap) > 0 {
			outDef.ResolvedCharMap = ec.primaryResolvedCharMap
		} else {
			outDef.ResolvedCharMap = resolveCharacterMaps(ss, ec.primaryCharacterMaps)
		}
	} else if len(ec.primaryResolvedCharMap) > 0 {
		outDef = &OutputDef{Method: methodXML, Encoding: lexicon.EncodingUTF8U}
		outDef.ResolvedCharMap = ec.primaryResolvedCharMap
	}

	return ec.applyPrimaryOutputOverrides(outDef)
}

func (ec *execContext) applyPrimaryOutputOverrides(outDef *OutputDef) *OutputDef {
	if ec.primaryOutputOverrides == nil {
		return outDef
	}

	if outDef == nil {
		outDef = &OutputDef{Method: methodXML, Encoding: lexicon.EncodingUTF8U}
	}
	// Clone the overrides so the pointer/slice/map fields merged below are
	// independent allocations; the terminal outDef (exposed via
	// ResolvedOutputDef and handlers) must not alias shared override state.
	ov := cloneOutputDef(ec.primaryOutputOverrides)
	if ov.Method != "" {
		outDef.Method = ov.Method
		// Carry the override's explicitness, forcing it true nowhere:
		// an override built solely from AVT-only attributes (media-type,
		// html-version, etc.) inherits the base method without making it
		// explicit, so forcing MethodExplicit=true here would wrongly
		// disable html/xhtml auto-detection in serializeResult.
		outDef.MethodExplicit = ov.MethodExplicit
	}

	if ov.Standalone != "" {
		outDef.Standalone = ov.Standalone
	}

	if ov.Encoding != "" {
		outDef.Encoding = ov.Encoding
	}
	// ov folds in the default xsl:output base via evalResultDocOutputDef, so
	// it is the effective output definition. Assign the boolean serialization
	// fields directly, OR-ing with no outDef: an explicit false on
	// the result-document (e.g. indent="{false()}") must override an inherited
	// true. OR-ing would wrongly keep the inherited true on.
	outDef.Indent = ov.Indent
	outDef.OmitDeclaration = ov.OmitDeclaration
	// Carry the omit-xml-declaration explicitness so the xhtml/html5
	// serializer respects an explicit value, defaulting it to no
	// "yes" (output_html.go keys on OmitDeclarationExplicit).
	outDef.OmitDeclarationExplicit = ov.OmitDeclarationExplicit
	if ov.DoctypeSystem != "" {
		outDef.DoctypeSystem = ov.DoctypeSystem
	}

	if ov.DoctypePublic != "" {
		outDef.DoctypePublic = ov.DoctypePublic
	}

	if ov.MediaType != "" {
		outDef.MediaType = ov.MediaType
	}

	if ov.HTMLVersion != "" {
		outDef.HTMLVersion = ov.HTMLVersion
	}
	// Effective (base-folded) values; assign directly so an explicit false
	// overrides an inherited true.
	outDef.IncludeContentType = ov.IncludeContentType

	outDef.ByteOrderMark = ov.ByteOrderMark
	if len(ov.CDATASections) > 0 {
		outDef.CDATASections = ov.CDATASections
	}

	if ov.NormalizationForm != "" {
		outDef.NormalizationForm = ov.NormalizationForm
	}

	if ov.Version != "" {
		outDef.Version = ov.Version
	}

	outDef.EscapeURIAttributes = ov.EscapeURIAttributes
	if len(ov.SuppressIndentation) > 0 {
		outDef.SuppressIndentation = ov.SuppressIndentation
	}

	if len(ov.ResolvedCharMap) > 0 {
		outDef.ResolvedCharMap = ov.ResolvedCharMap
	}

	if ov.JSONNodeOutputMethod != "" {
		outDef.JSONNodeOutputMethod = ov.JSONNodeOutputMethod
	}

	if ov.ItemSeparator != nil {
		outDef.ItemSeparator = ov.ItemSeparator
	} else if ov.ItemSeparatorAbsent {
		outDef.ItemSeparator = nil
		outDef.ItemSeparatorAbsent = true
	}

	if ov.BuildTree != nil {
		outDef.BuildTree = ov.BuildTree
	}
	// ov folds in the default xsl:output base via evalResultDocOutputDef, so
	// this is the effective allow-duplicate-names for the primary output.
	outDef.AllowDuplicateNames = ov.AllowDuplicateNames
	// Likewise, ov folds in the default xsl:output base, so this is the
	// effective undeclare-prefixes for the primary output.
	outDef.UndeclarePrefixes = ov.UndeclarePrefixes

	return outDef
}

func (ec *execContext) deliverTransformAnnotations(cfg *transformConfig) error {
	if cfg == nil || cfg.annotationHandler == nil || ec.typeAnnotations == nil {
		return nil
	}

	var sd xpath.SchemaDeclarations

	return cfg.annotationHandler.HandleAnnotations(ec.typeAnnotations, sd)
}

// checkInitialMode verifies the initial mode is available and returns an error
// if it is not. Returns XTDE0044 if the mode exists but is not public in a
// package, or XTDE0045 if the mode is not found.
func (ec *execContext) checkInitialMode(mode string) error {
	// Resolve #default to the actual default mode name
	resolvedMode := mode
	switch mode {
	case "", modeDefault:
		resolvedMode = ec.stylesheet.defaultMode
	case modeUnnamed:
		resolvedMode = ""
	}

	// The stylesheet's default-mode is always eligible as an initial mode,
	// even if private (per XSLT 3.0 spec).
	if resolvedMode == ec.stylesheet.defaultMode {
		return nil
	}

	// The unnamed mode (#unnamed) is always eligible as an initial mode
	// when explicitly requested, even if private in a package (XSLT 3.0 §2.4).
	if mode == modeUnnamed || resolvedMode == "" {
		return nil
	}

	if ec.stylesheet.isPackage {
		// In packages, check if the resolved mode is public
		if md := ec.stylesheet.modeDefs[resolvedMode]; md != nil {
			if md.Visibility == visPrivate || md.Visibility == "" {
				return dynamicError(errCodeXTDE0044, "initial mode %q is not public in the package", mode)
			}

			return nil
		}
		// For packages with declared-modes="true" (default), undeclared modes
		// are implicitly private.
		if ec.stylesheet.declaredModes {
			return dynamicError(errCodeXTDE0044, "initial mode %q is not declared in the package", mode)
		}
	} else {
		// In non-package stylesheets, special modes are always available
		switch mode {
		case "", modeDefault, modeUnnamed:
			return nil
		}
	}

	if md := ec.stylesheet.modeDefs[mode]; md != nil {
		if md.Visibility == visPrivate {
			return dynamicError(errCodeXTDE0044, "initial mode %q is not public", mode)
		}

		if ec.stylesheet.isPackage && md.Visibility == "" {
			return dynamicError(errCodeXTDE0044, "initial mode %q is not public in the package", mode)
		}

		return nil
	}
	// The initial mode must have at least one template rule (XTDE0045).
	if len(ec.stylesheet.modeTemplates[mode]) > 0 {
		return nil
	}

	return dynamicError(errCodeXTDE0045, "initial mode %q not found", mode)
}

// cloneOutputDef returns a deep copy of an OutputDef. All pointer, slice, and
// map fields are freshly allocated so that mutating the clone (or the original)
// never affects the other. Returns nil if src is nil.
func cloneOutputDef(src *OutputDef) *OutputDef {
	if src == nil {
		return nil
	}

	cp := *src
	if src.ResolvedCharMap != nil {
		cp.ResolvedCharMap = make(map[rune]string, len(src.ResolvedCharMap))
		maps.Copy(cp.ResolvedCharMap, src.ResolvedCharMap)
	}

	if src.UseCharacterMaps != nil {
		cp.UseCharacterMaps = append([]string(nil), src.UseCharacterMaps...)
	}

	if src.CDATASections != nil {
		cp.CDATASections = append([]string(nil), src.CDATASections...)
	}

	if src.SuppressIndentation != nil {
		cp.SuppressIndentation = append([]string(nil), src.SuppressIndentation...)
	}

	if src.IncludeContentType != nil {
		v := *src.IncludeContentType
		cp.IncludeContentType = &v
	}

	if src.ItemSeparator != nil {
		v := *src.ItemSeparator
		cp.ItemSeparator = &v
	}

	if src.EscapeURIAttributes != nil {
		v := *src.EscapeURIAttributes
		cp.EscapeURIAttributes = &v
	}

	if src.BuildTree != nil {
		v := *src.BuildTree
		cp.BuildTree = &v
	}

	return &cp
}

func cloneSequenceMap(in map[string]xdm.Sequence) map[string]xdm.Sequence {
	if len(in) == 0 {
		return nil
	}

	out := make(map[string]xdm.Sequence, len(in))
	for k, v := range in {
		out[k] = append(xdm.ItemSlice(nil), xdm.Materialize(v)...)
	}

	return out
}

// initGlobalVars registers global variables and parameters for lazy evaluation.
