// Derived from lestrrat-go/helium at 7362c0a70122a757780f4d0b545a9b370dead6ab.
// Copyright (c) 2015 lestrrat. MIT License; see licenses/MIT-helium.txt at the repository root.

package xslt

import (
	"context"
	"fmt"
	"io"
	"maps"
	"reflect"
	"slices"
	"strings"
	"time"

	"github.com/skarm/xmlsec/transform/internal/xdm"
	"github.com/skarm/xmlsec/transform/internal/xdm/lexicon"
	"github.com/skarm/xmlsec/transform/internal/xpath"
)

// baseEvalSlots is the number of base evaluators baseXPathEvaluator keeps per
// mode (outside pattern matching, and during it).
const baseEvalSlots = 2

// scopedEvalSlots is the number of scoped evaluators scopedXPathEvaluator
// keeps.
const scopedEvalSlots = 4

type execContextKey struct{}

// scopeArena reuses scopes within one transformation, including context copies.
type scopeArena struct{ free []*varScope }

// baseEvalEntry is one cached base evaluator. gen is 0 for an empty entry.
type baseEvalEntry struct {
	key  baseEvalKey
	eval xpath.Evaluator
	gen  uint64
	// patternNS holds the map key.patternNS identifies, so the map stays
	// reachable while it is cached and its address cannot be reused by a
	// different map.
	patternNS map[string]string
}

// scopedEvalCache holds one evaluator scopedXPathEvaluator built, plus its
// XPath 1.0 compatibility-mode variant, which is built on first use.
type scopedEvalCache struct {
	key         scopedEvalKey
	valid       bool
	eval        xpath.Evaluator
	compat      xpath.Evaluator
	compatValid bool
}

// baseEvalKey identifies every input of buildBaseXPathEvaluator that varies
// within one transform.
type baseEvalKey struct {
	pkg            *Stylesheet
	xpathDefaultNS string
	baseURI        string
	// patternNS is the identity of the matching pattern's namespace map
	// (pattern.nsBindings), which the evaluator's namespaces are built from
	// during pattern matching; it is 0 outside pattern matching, where the
	// map is not read. The compiler interns those maps, so patterns with the
	// same in-scope namespaces share one evaluator.
	patternNS         uintptr
	hasXPathDefaultNS bool
	inPattern         bool
}

// scopedEvalKey identifies every input of the scoped evaluator (see
// scopedXPathEvaluator). Maps are compared by identity: the cached evaluator
// borrows each keyed map, which keeps it reachable, so a different map can
// never reuse the address of a cached one.
type scopedEvalKey struct {
	baseGen     uint64
	vars        uintptr
	fns         uintptr
	fnsNS       uintptr
	typeAnn     uintptr
	nilled      uintptr
	preservedID uintptr
	collation   string
	docOrder    *xpath.DocOrderCache
}

// execContext holds XSLT transformation state. Stored inside context.Context.
type executionIdentity [1]byte

type execContext struct {
	initialTemplateCall    bool // Consumed before matching, so recursive built-in rules are ordinary calls.
	execution              *executionIdentity
	attributeSetEvaluating map[*attributeSetDef]struct{}
	scopeArena             *scopeArena
	budgetCtx              context.Context // xmlsec: invocation-local shared resource budget.

	stylesheet                   *Stylesheet // immutable after construction; do not reassign
	sourceDoc                    *xdm.Document
	resultDoc                    *xdm.Document
	currentNode                  xdm.Node // XSLT current() node
	contextNode                  xdm.Node // XPath context node
	contextItem                  xdm.Item // non-nil when context is an atomic value (for-each over atomics)
	position                     int
	size                         int
	localVars                    *varScope
	globalVars                   map[string]xdm.Sequence
	globalVarDefs                map[string]*variable       // unevaluated global variable definitions (lazy)
	globalParamDefs              map[string]*param          // unevaluated global param definitions (lazy)
	globalEvaluating             map[globalBinding]struct{} // circular dependency detection
	collectingVars               bool                       // reentrancy guard for collectAllVars
	currentMode                  string
	currentModePackage           *Stylesheet             // bound mode identity, independent of the current component's lexical scope
	currentTemplate              *template               // use setCurrentTemplate(); do not assign directly
	currentPackage               *Stylesheet             // owning package of currently executing template/function
	xpathDefaultNS               string                  // current xpath-default-namespace
	hasXPathDefaultNS            bool                    // true when xpathDefaultNS is explicitly set
	nsOverride                   map[string]string       // when non-nil, overrides stylesheet.namespaces for sequence-type prefix resolution
	defaultValidation            string                  // runtime copy of stylesheet.defaultValidation (save/restore per scope)
	defaultCollation             string                  // current default-collation URI (empty = codepoint)
	tunnelParams                 map[string]xdm.Sequence // tunnel parameters passed through apply-templates
	currentGroup                 xdm.Sequence            // current-group() value during for-each-group
	currentGroupKey              xdm.Sequence            // current-grouping-key() value during for-each-group
	inGroupContext               bool                    // true when inside for-each-group body
	groupHasKey                  bool                    // true when innermost for-each-group uses group-by or group-adjacent
	depth                        int                     // recursion depth
	outputStack                  []*outputFrame
	keyTables                    map[string]*keyTable
	inputTrees                   map[inputTreeKey]inputTreeCopy
	inputOriginalNodes           map[xdm.Node]xdm.Node
	docCache                     map[string]*xdm.Document
	collectionCache              map[string]xdm.Sequence
	uriCollectionCache           map[string][]string
	functionResultCache          map[string]xdm.Sequence
	functionLexical              *execContext              // immutable environment shared by escaping function references
	cachedFns                    map[string]xpath.Function // cached xsltFunctions() result
	cachedFnsPackage             *Stylesheet
	cachedFnsNS                  map[xpath.QualifiedName]xpath.Function // cached xsltFunctionsNS() result
	globalVarsGen                uint64                                 // incremented when globalVars changes
	cachedVarsMap                map[string]xdm.Sequence                // cached result of collectAllVars; never mutated once built
	cachedVarsGen                uint64                                 // globalVarsGen at time cachedVarsMap was built
	accumulatorState             map[string]xdm.Sequence                // accumulator name -> current value
	accumulatorStateError        map[string]error                       // accumulator name -> deferred error
	accumulatorBeforeByNode      map[xdm.Node]map[string]xdm.Sequence
	accumulatorAfterByNode       map[xdm.Node]map[string]xdm.Sequence
	accumulatorBeforeErrorByNode map[xdm.Node]map[string]error // deferred errors for accumulator-before
	accumulatorAfterErrorByNode  map[xdm.Node]map[string]error // deferred errors for accumulator-after
	accumulatorComputedDocs      map[xdm.Node]struct{}         // document roots for which accumulator states have been computed
	accumulatorComputedPkgs      map[string]struct{}           // package-scoped accumulator computation tracking
	activeAccumulators           map[string]struct{}           // accumulator names allowed in current source-document context
	evaluatingAccumulator        bool
	evaluatingMergeKey           bool
	regexGroups                  []string                // captured groups for regex-group() inside xsl:matching-substring
	breakValue                   xdm.Sequence            // value produced by xsl:break
	nextIterParams               map[string]xdm.Sequence // param values from xsl:next-iteration
	inMergeAction                bool                    // true inside xsl:merge-action (for XTDE3480/XTDE3510)
	errSourceLine                int                     // source line of last-executed instruction (for xsl:catch)
	errSourceModule              string                  // source module of last-executed instruction (for xsl:catch)
	msgHandler                   MessageHandler
	transformConfig              *transformConfig
	currentTime                  time.Time // stable fn:current-* value for whole transformation
	dynamicProperties            xpath.DynamicProperties
	typeAnnotations              map[xdm.Node]string        // node → xs:... type annotation (schema-aware)
	preservedIDAnnotations       map[xdm.Node]string        // ID/IDREF annotations preserved after input-type-annotations="strip"
	nilledElements               map[*xdm.Element]struct{}  // elements with xsi:nil="true" confirmed by XSD validation
	validatedDocs                map[*xdm.Document]struct{} // documents that have been schema-validated
	resultDocuments              map[string]*xdm.Document   // secondary result documents keyed by RESOLVED canonical absolute output URI
	resultDocItems               map[string]xdm.Sequence    // secondary result document items for json/adaptive serialization, keyed by RESOLVED URI
	resultDocOutputDefs          map[string]*OutputDef      // effective output definition per secondary result document, keyed by RESOLVED URI
	resultDocHrefs               map[string]string          // RESOLVED URI → the raw href as written on xsl:result-document, for the public ResultDocumentHandler
	usedResultURIs               map[string]struct{}        // URIs already written by xsl:result-document (includes "")
	readResourceURIs             map[string]struct{}
	resourceOwner                *execContext          // live caller when an escaped stylesheet function runs
	currentResultDocMethod       string                // effective output method during result-document body execution
	temporaryOutputDepth         int                   // >0 when inside a temporary output state (XTDE1480)
	primaryClaimedImplicitly     bool                  // true when implicit content has been written to primary output
	staticBaseURIOverride        string                // non-empty when xml:base on an LRE overrides the template's base URI
	staticBaseURIPinned          bool                  // true while evaluating a global var/param body: base is pinned to the declaration site, never the current template
	currentOutputURI             string                // current output URI for current-output-uri() function
	baseOutputURI                string                // fixed base for resolving all result-document hrefs
	canonicalPrimaryURI          string                // canonical explicitly supplied principal output URI
	inPatternMatch               bool                  // true during pattern matching (current-output-uri() returns empty)
	patternNamespaces            map[string]string     // the matching pattern's lexical xmlns snapshot (prefix→URI) during pattern matching
	patternMatchErr              error                 // non-nil if a fatal error occurred during pattern matching
	inSortKeyEval                bool                  // true during sort key evaluation (current-output-uri() returns empty)
	patternCompat                bool                  // true while matching a backwards-compatible pattern (predicate XPath in 1.0 compat mode)
	atomicTextNodes              map[xdm.Node]struct{} // text nodes created from atomic item serialization
	nodeMemoIDs                  map[xdm.Node]uint64   // stable per-transform node identities for function caching
	nextNodeMemoID               uint64
	fnScratchDoc                 *xdm.Document                      // output wrapper shared by every select-only xsl:function call
	fnScratchRoot                *xdm.Element                       // fnScratchDoc's document element; always childless
	paramDocOutputDefs           map[*resultDocumentInst]*OutputDef // scoped parameter-document output defs
	paramDocCache                map[string]parameterDocumentResult
	paramDocPresences            map[*resultDocumentInst]paramDocPresence // scoped parameter-document plain-boolean presence flags
	primaryCharacterMaps         []string                                 // character map names from xsl:result-document targeting primary output
	primaryResolvedCharMap       map[rune]string                          // resolved character map from parameter-document for primary output
	primaryOutputOverrides       *OutputDef                               // serialization param overrides from primary xsl:result-document
	rawResultSequence            xdm.Sequence                             // raw XDM result sequence (set when initial template has as="...")
	nsFixupAllowed               map[*xdm.Element]struct{}                // elements whose prefix namespace is eligible for fixup
	overridingTemplate           *template                                // currently executing overriding template (for xsl:original)
	originalGlobal               globalBinding                            // hidden original bound in the current global scope
	originalFunc                 xpath.Function                           // current xsl:original function (set during overriding function call)
	currentAttrSetOriginal       *attributeSetDef                         // original attribute-set for use-attribute-sets="xsl:original"
	docOrderCache                *xpath.DocOrderCache                     // shared document-order cache for consistent cross-document ordering
	globalValueCache             map[globalBinding]xdm.Sequence           // cached values by global declaration identity
	globalContextAbsent          bool                                     // true when global context item is absent (select evaluated to empty)
	globalContextItem            xdm.Item                                 // explicit global context item (overrides sourceDoc for global var/param eval); nil = use sourceDoc
	traceWriter                  io.Writer                                // destination for fn:trace output (nil = os.Stderr)
	// xmlSpacePreserveMemo caches inheritedXMLSpace's ancestor-walk result
	// (elem -> whether xml:space="preserve" is in scope) for the
	// retained-whitespace case, where the same element's whitespace-only text
	// children are re-checked repeatedly (e.g. once by the strip pre-pass, then
	// again as each is visited by applyTemplates). Safe ONLY because nothing
	// inside one transform changes an element's in-scope xml:space: the source
	// is never mutated in place (a private copy is stripped instead), and a
	// result/temporary tree is memoized only once fully linked into its final
	// parent — never while still being assembled. A future change that
	// traverses a tree while it is still being built must clear this map (or
	// not memoize) at that seam. Lazily allocated; nil means empty.
	xmlSpacePreserveMemo map[*xdm.Element]bool
	// numberMemos holds, per xsl:number instruction, the count its last
	// level="single" or level="any" evaluation produced, so numbering a list
	// in document order walks back only to the previous numbered node (see
	// numberMemo). Lazily allocated; nil means empty.
	numberMemos map[*numberInst]numberMemo

	// baseEvals caches the base XPath evaluators baseXPathEvaluator built:
	// row 0 serves evaluation outside pattern matching and row 1 serves
	// pattern matching, so switching between the two for every matched node
	// evicts neither. Each row is refilled round-robin from baseEvalNext.
	// baseEvalGen is the generation number handed to the last evaluator
	// built; scopedXPathEvaluator keys its own cache on it.
	baseEvals    [2][baseEvalSlots]baseEvalEntry
	baseEvalNext [2]int
	baseEvalGen  uint64

	// scopedEvals caches the base evaluator plus the per-scope overlays
	// (variables, functions, schema state, collation); see
	// scopedXPathEvaluator. It is refilled round-robin from scopedEvalNext.
	scopedEvals    [scopedEvalSlots]scopedEvalCache
	scopedEvalNext int

	// localVarsVer is incremented whenever a binding is added to a local
	// variable scope (setVar/setVarDeferred) and when a scope that holds
	// bindings is popped. Together with the innermost non-empty scope
	// (visibleVarScope) it tells collectAllVars whether its cached map is
	// still current.
	localVarsVer       uint64
	cachedVarsScope    *varScope   // visibleVarScope() when cachedVarsMap was built
	cachedVarsScopeVer uint64      // localVarsVer when cachedVarsMap was built
	cachedVarsPackage  *Stylesheet // currentPackage when cachedVarsMap was built

	// nilledGen is incremented on every change to nilledElements; nilledNodes
	// caches nilledElementNodes' conversion of it as of nilledNodesGen.
	nilledGen      uint64
	nilledNodes    map[xdm.Node]struct{}
	nilledNodesGen uint64

	// patternPredicates holds the matching pattern's compiled step predicates
	// (pattern.predicates) during pattern matching, beside patternNamespaces
	// and patternCompat.
	patternPredicates map[*xpath.Expr]*patternPredicate
}

// Globals and key specifiers use the initial grouping/regex context.
func (ec *execContext) pushAbsentGroupingContext() func() {
	group, key, regex := ec.currentGroup, ec.currentGroupKey, ec.regexGroups
	inGroup, hasKey, inMerge := ec.inGroupContext, ec.groupHasKey, ec.inMergeAction
	ec.currentGroup, ec.currentGroupKey, ec.regexGroups = nil, nil, nil
	ec.inGroupContext, ec.groupHasKey, ec.inMergeAction = false, false, false

	return func() {
		ec.currentGroup, ec.currentGroupKey, ec.regexGroups = group, key, regex
		ec.inGroupContext, ec.groupHasKey, ec.inMergeAction = inGroup, hasKey, inMerge
	}
}

// ResolveFunction implements xpath.FunctionResolver. It resolves
// xsl:original() calls without exposing the function to function-lookup.
func (ec *execContext) ResolveFunction(_ context.Context, uri, name string, arity int) (xpath.Function, bool, error) {
	if uri == lexicon.NamespaceXSLT && name == nameOriginal && ec.originalFunc != nil {
		return ec.originalFunc, true, nil
	}
	// Strict expressions reject missing functions during compilation. Calls
	// deferred by compatibility processing bind an extension fallback instead;
	// the resolver is deliberately excluded from function-lookup.
	if !isReservedFunctionNS(uri) {
		return &xsltFunc{min: arity, max: arity, fn: func(context.Context, []xdm.Sequence) (xdm.Sequence, error) {
			return nil, dynamicError("XTDE1425", "extension function Q{%s}%s#%d is unavailable", uri, name, arity)
		}}, true, nil
	}

	return nil, false, nil
}

// ResolveVariable implements xpath.VariableResolver. It lazily evaluates
// global variables and parameters that have not yet been evaluated, allowing
// XPath expressions to reference globals that aren't in the snapshot built
// by collectAllVars (e.g. during circular-but-unused variable scenarios).
func (ec *execContext) ResolveVariable(ctx context.Context, name string) (xdm.Sequence, bool, error) {
	// Handle $xsl:original — resolve to the original overridden variable's value.
	// The name may come as either the expanded form "{uri}original" or the
	// prefixed form "xsl:original" depending on whether namespace resolution
	// happened in the XPath evaluator.
	isXSLOriginal := name == xdm.ClarkName(lexicon.NamespaceXSLT, nameOriginal) || name == "xsl:original"
	if isXSLOriginal && ec.originalGlobal != (globalBinding{}) {
		return ec.resolveOriginalVariable(ctx)
	}

	expandedName := ec.expandVariableName(name)

	lookupNames := []string{name}
	if expandedName != name {
		lookupNames = append(lookupNames, expandedName)
	}

	if value, found, err := ec.resolveLocalVariable(lookupNames); found || err != nil {
		return value, found, err
	}

	if ec.currentPackage != nil && ec.currentPackage != ec.stylesheet {
		return ec.resolveOwnPackageDeclaration(ctx, expandedName)
	}

	for _, lookup := range lookupNames {
		if value, found := ec.globalVars[lookup]; found {
			return value, true, nil
		}
	}

	if value, found, err := ec.resolvePendingGlobalVariable(ctx, lookupNames); found || err != nil {
		return value, found, err
	}

	return ec.resolvePendingGlobalParam(ctx, lookupNames)
}

func (ec *execContext) setCurrentTemplate(tmpl *template) {
	ec.currentTemplate = tmpl
}

// baseDir returns the base directory for resolving relative URIs in the
// XSLT-aware functions fn:doc / fn:document / fn:stream-available.
//
// It is derived from effectiveStaticBaseURI() — the in-scope static base URI —
// so that every base-URI override is honored consistently: an xml:base on an
// LRE/instruction, the pinned declaration-site base of a lazily-evaluated
// global, and the base-uri attribute of an xsl:evaluate (which installs a
// staticBaseURIOverride for the duration of the dynamic evaluation). This keeps
// fn:doc resolution aligned with the native xpath functions (fn:unparsed-text,
// fn:collection) that resolve against the same effective base.
func (ec *execContext) baseDir() string {
	return documentBaseDir(ec.effectiveStaticBaseURI())
}

func (ec *execContext) markAtomicTextNode(node xdm.Node) {
	if node == nil {
		return
	}

	if ec.atomicTextNodes == nil {
		ec.atomicTextNodes = make(map[xdm.Node]struct{})
	}

	ec.atomicTextNodes[node] = struct{}{}
}

func (ec *execContext) isAtomicTextNode(node xdm.Node) bool {
	if node == nil || ec.atomicTextNodes == nil {
		return false
	}

	_, ok := ec.atomicTextNodes[node]

	return ok
}

func (ec *execContext) clearAtomicTextNode(node xdm.Node) {
	if node == nil || ec.atomicTextNodes == nil {
		return
	}

	delete(ec.atomicTextNodes, node)
}

// annotateAttr applies a type annotation to a just-set attribute on an element.
// If typeName is empty, this is a no-op.
func (ec *execContext) annotateAttr(elem *xdm.Element, typeName, localName, nsURI, value string) {
	if typeName == "" {
		return
	}

	if nsURI != "" {
		if attr := elem.GetAttributeNodeNS(localName, nsURI); attr != nil {
			ec.annotateNode(attr, typeName)
		}
	} else {
		for _, attr := range elem.Attributes() {
			if attr.Name() == localName {
				ec.annotateNode(attr, typeName)
				break
			}
		}
	}

	if ec.annotationIsID(typeName) {
		// Register on the document that owns this element (may be a
		// temporary document during variable/function body evaluation).
		out := ec.currentOutput()
		out.doc.RegisterID(value, elem)
	}
}

func (ec *execContext) annotationIsID(typeName string) bool {
	if typeName == "" {
		return false
	}

	if xdm.BuiltinIsSubtypeOf(typeName, xdm.TypeID) {
		return true
	}

	return false
}

// annotateNode records a type annotation for a result-tree node.
func (ec *execContext) annotateNode(node xdm.Node, typeName string) {
	if typeName == "" {
		return
	}

	if ec.typeAnnotations == nil {
		ec.typeAnnotations = make(map[xdm.Node]string)
	}

	ec.typeAnnotations[node] = typeName
}

// remapAnnotationsToCopy rewrites the type-annotation and nilled-element maps,
// gathered against the original (validated) source tree, so their keys point at
// the corresponding nodes of the strip copy the transform navigates. nodeMap is
// the original->copy correspondence produced by copyAndStrip; an annotated node
// always has a copy (whitespace-only omitted nodes are never annotated), so no
// entry is lost.
func (ec *execContext) remapAnnotationsToCopy(nodeMap map[xdm.Node]xdm.Node) {
	if nodeMap == nil {
		return
	}

	if len(ec.typeAnnotations) > 0 {
		remapped := make(map[xdm.Node]string, len(ec.typeAnnotations))
		for node, typeName := range ec.typeAnnotations {
			remapped[remapValidationNode(nodeMap, node)] = typeName
		}

		ec.typeAnnotations = remapped
	}

	if len(ec.nilledElements) > 0 {
		remapped := make(map[*xdm.Element]struct{}, len(ec.nilledElements))
		for elem := range ec.nilledElements {
			if mapped, ok := remapValidationNode(nodeMap, elem).(*xdm.Element); ok {
				remapped[mapped] = struct{}{}
			}
		}

		ec.nilledElements = remapped
		ec.nilledGen++
	}
}

// markNilled records that an element was confirmed nilled by XSD validation.
func (ec *execContext) markNilled(elem *xdm.Element) {
	if ec.nilledElements == nil {
		ec.nilledElements = make(map[*xdm.Element]struct{})
	}

	ec.nilledElements[elem] = struct{}{}
	ec.nilledGen++
}

// preserveIDAnnotations populates the document-level ID index and sets
// attribute AType for IDREF/IDREFS attributes based on schema type annotations.
// This ensures fn:id() and fn:idref() still work after input-type-annotations="strip".
func (ec *execContext) preserveIDAnnotations() {
	for node, annotation := range ec.typeAnnotations {
		switch typed := node.(type) {
		case *xdm.Attribute:
			preserveAttributeIDType(typed, annotation)
		case *xdm.Element:
			if isIDType(annotation) {
				if doc, ok := documentRoot(typed).(*xdm.Document); ok {
					doc.RegisterID(strings.TrimSpace(xdm.CharacterData(typed)), typed)
				}
			}
		}
	}
}

func preserveAttributeIDType(attr *xdm.Attribute, annotation string) {
	switch annotation {
	case "xs:ID":
		attr.SetIDType(xdm.IDAttribute)

		if parent, ok := attr.Parent().(*xdm.Element); ok {
			if doc, ok := documentRoot(parent).(*xdm.Document); ok {
				doc.RegisterID(strings.TrimSpace(attr.Value()), parent)
			}
		}
	case "xs:IDREF":
		attr.SetIDType(xdm.IDRefAttribute)
	case "xs:IDREFS":
		attr.SetIDType(xdm.IDRefsAttribute)
	}
}

// transferNilledStatus transfers the nilled property from a source subtree to
// a destination subtree (used when copy-of/snapshot creates a deep copy).
func (ec *execContext) transferNilledStatus(src, dst xdm.Node) {
	if ec.nilledElements == nil {
		return
	}

	if srcElem, ok := src.(*xdm.Element); ok {
		if dstElem, ok := dst.(*xdm.Element); ok {
			if _, nilled := ec.nilledElements[srcElem]; nilled {
				ec.markNilled(dstElem)
			}
			// Recursively transfer for child elements.
			srcChild := srcElem.FirstChild()

			dstChild := dstElem.FirstChild()
			for srcChild != nil && dstChild != nil {
				ec.transferNilledStatus(srcChild, dstChild)
				srcChild = srcChild.NextSibling()
				dstChild = dstChild.NextSibling()
			}
		}
	}
	// For document nodes, transfer nilled status for all children.
	if srcDoc, ok := src.(*xdm.Document); ok {
		if dstDoc, ok := dst.(*xdm.Document); ok {
			srcChild := srcDoc.FirstChild()

			dstChild := dstDoc.FirstChild()
			for srcChild != nil && dstChild != nil {
				ec.transferNilledStatus(srcChild, dstChild)
				srcChild = srcChild.NextSibling()
				dstChild = dstChild.NextSibling()
			}
		}
	}
}

// isNilled returns true if the element was confirmed nilled during XSD validation.
func (ec *execContext) isNilled(elem *xdm.Element) bool {
	if ec.nilledElements == nil {
		return false
	}

	_, ok := ec.nilledElements[elem]

	return ok
}

// nilledElementNodes returns the confirmed-nilled elements as a xdm.Node-keyed
// set for forwarding into the xpath evaluator (xpath.Evaluator.NilledElements),
// or nil when there is nothing to forward. This is what makes fn:data (a nilled
// element has typed value ()) and an element(name, type) instance-of test
// nilled-aware inside xpath-evaluated expressions, consistent with xslt's own
// nilled tracking. Under input-type-annotations="strip" the source type
// annotations are removed, so the PSVI nilled property is likewise unavailable
// and this returns nil — matching fnNilled's strip handling and the
// type-annotation forwarding, which forwards an emptied annotation map.
func (ec *execContext) nilledElementNodes() map[xdm.Node]struct{} {
	if len(ec.nilledElements) == 0 || ec.stylesheet.inputTypeAnnotations == validationStrip {
		return nil
	}
	// The conversion is cached until nilledElements changes. A change builds
	// a new map, so a map already handed to an evaluator is never mutated.
	if ec.nilledNodes != nil && ec.nilledNodesGen == ec.nilledGen {
		return ec.nilledNodes
	}

	out := make(map[xdm.Node]struct{}, len(ec.nilledElements))
	for elem := range ec.nilledElements {
		out[elem] = struct{}{}
	}

	ec.nilledNodes = out
	ec.nilledNodesGen = ec.nilledGen

	return out
}

// deepTransferAnnotations recursively copies type annotations from a source
// subtree to a destination subtree. The trees must have the same structure.
func (ec *execContext) deepTransferAnnotations(src, dst xdm.Node) {
	if ec.typeAnnotations == nil {
		return
	}
	// The nilled property is preserved by validation="preserve" alongside the
	// type annotation, so a deep (xsl:copy-of) copy carries it to the copy.
	if srcElem, ok := src.(*xdm.Element); ok {
		if dstElem, ok := dst.(*xdm.Element); ok {
			if ec.isNilled(srcElem) {
				ec.markNilled(dstElem)
			}
		}
	}

	if ann, ok := ec.typeAnnotations[src]; ok {
		ec.annotateNode(dst, ann)
	}

	if source, ok := src.(*xdm.Element); ok {
		if target, ok := dst.(*xdm.Element); ok {
			ec.transferCopiedAttributeAnnotations(source, target)
		}
	}
	// Transfer child annotations recursively
	srcChild := src.FirstChild()

	dstChild := dst.FirstChild()
	for srcChild != nil && dstChild != nil {
		ec.deepTransferAnnotations(srcChild, dstChild)
		srcChild = srcChild.NextSibling()
		dstChild = dstChild.NextSibling()
	}
}

func (ec *execContext) transferCopiedAttributeAnnotations(source, target *xdm.Element) {
	for _, attr := range source.Attributes() {
		annotation, ok := ec.typeAnnotations[attr]
		if !ok {
			continue
		}

		for _, copied := range target.Attributes() {
			if attr.LocalName() == copied.LocalName() && attr.URI() == copied.URI() {
				ec.annotateNode(copied, annotation)
				break
			}
		}
	}
}

// transferAnnotationsForCopy transfers type annotations from a source node to
// newly-copied children of parent. lastBefore is the last child of parent
// before the copy (nil if parent was empty). For document-node sources, the
// children of the document are matched pairwise with the newly-added children.
// For non-document sources, the single new child (parent's last child) is
// matched with the source.
func (ec *execContext) transferAnnotationsForCopy(src xdm.Node, parent xdm.Node, lastBefore xdm.Node) {
	if ec.typeAnnotations == nil {
		return
	}

	if src.Type() == xdm.DocumentNode {
		// Document node: children were copied individually.
		// Walk src children and match them to the newly-added children.
		var firstNew xdm.Node
		if lastBefore == nil {
			firstNew = parent.FirstChild()
		} else {
			firstNew = lastBefore.NextSibling()
		}

		srcChild := src.FirstChild()

		dstChild := firstNew
		for srcChild != nil && dstChild != nil {
			ec.deepTransferAnnotations(srcChild, dstChild)
			srcChild = srcChild.NextSibling()
			dstChild = dstChild.NextSibling()
		}
	} else {
		// Non-document: a single node was copied as the last child.
		last := parent.LastChild()
		if last != nil {
			ec.deepTransferAnnotations(src, last)
		}
	}
}

// idFamilyAnnotation returns node's type annotation when it is xs:ID / xs:IDREF
// / xs:IDREFS (or a subtype), else "". It consults both the live and the
// preserved annotation maps so a strip copy of an already-stripped tree keeps
// the is-id property.
func (ec *execContext) idFamilyAnnotation(node xdm.Node) string {
	ann := ""
	if ec.typeAnnotations != nil {
		ann = ec.typeAnnotations[node]
	}

	if ann == "" && ec.preservedIDAnnotations != nil {
		ann = ec.preservedIDAnnotations[node]
	}

	if ann == "" {
		return ""
	}

	if isIDType(ann) || isIDRefType(ann) || isIDRefsType(ann) {
		return ann
	}

	return ""
}

func isIDRefType(ann string) bool {
	return ann == "xs:IDREF"
}

func isIDRefsType(ann string) bool {
	return ann == "xs:IDREFS"
}

func (ec *execContext) preserveNodeIDAnnotation(node xdm.Node, ann string) {
	if ec.preservedIDAnnotations == nil {
		ec.preservedIDAnnotations = make(map[xdm.Node]string)
	}

	ec.preservedIDAnnotations[node] = ann
}

// deepPreserveIDAnnotations records the is-id / is-idref(s) property of each
// source node onto the corresponding copy node in preservedIDAnnotations. Per
// XDM, validation="strip" removes the type annotation but retains the is-id /
// is-idrefs properties, so fn:id()/fn:idref() still resolve over the stripped
// copy. The two subtrees must have the same structure.
func (ec *execContext) deepPreserveIDAnnotations(src, dst xdm.Node) {
	if ann := ec.idFamilyAnnotation(src); ann != "" {
		ec.preserveNodeIDAnnotation(dst, ann)
	}

	if srcElem, ok := src.(*xdm.Element); ok {
		if dstElem, ok := dst.(*xdm.Element); ok {
			for _, srcAttr := range srcElem.Attributes() {
				ann := ec.idFamilyAnnotation(srcAttr)
				if ann == "" {
					continue
				}

				for _, dstAttr := range dstElem.Attributes() {
					if srcAttr.LocalName() == dstAttr.LocalName() && srcAttr.URI() == dstAttr.URI() {
						ec.preserveNodeIDAnnotation(dstAttr, ann)
						break
					}
				}
			}
		}
	}

	srcChild := src.FirstChild()

	dstChild := dst.FirstChild()
	for srcChild != nil && dstChild != nil {
		ec.deepPreserveIDAnnotations(srcChild, dstChild)
		srcChild = srcChild.NextSibling()
		dstChild = dstChild.NextSibling()
	}
}

// preserveIDAnnotationsForCopy records is-id / is-idrefs properties from a
// stripped copy's source subtree onto the newly-copied nodes, mirroring
// transferAnnotationsForCopy's document-vs-single-node structure matching.
func (ec *execContext) preserveIDAnnotationsForCopy(src, parent, lastBefore xdm.Node) {
	if src.Type() == xdm.DocumentNode {
		var firstNew xdm.Node
		if lastBefore == nil {
			firstNew = parent.FirstChild()
		} else {
			firstNew = lastBefore.NextSibling()
		}

		srcChild := src.FirstChild()

		dstChild := firstNew
		for srcChild != nil && dstChild != nil {
			ec.deepPreserveIDAnnotations(srcChild, dstChild)
			srcChild = srcChild.NextSibling()
			dstChild = dstChild.NextSibling()
		}

		return
	}

	if last := parent.LastChild(); last != nil {
		ec.deepPreserveIDAnnotations(src, last)
	}
}

func (ec *execContext) acquireVarScope() *varScope {
	if ec.scopeArena == nil {
		ec.scopeArena = &scopeArena{}
	}

	a := ec.scopeArena
	if len(a.free) == 0 {
		return &varScope{}
	}

	last := len(a.free) - 1
	scope := a.free[last]
	a.free[last] = nil
	a.free = a.free[:last]

	return scope
}

func (ec *execContext) pushVarScope() {
	vs := ec.acquireVarScope()
	vs.parent = ec.localVars
	ec.localVars = vs
}

func (ec *execContext) popVarScope() {
	if ec.localVars == nil {
		return
	}

	old := ec.localVars

	ec.localVars = old.parent
	if len(old.vars) > 0 {
		ec.localVarsVer++
	}

	old.parent = nil
	clear(old.vars)
	clear(old.deferredErrors)

	if ec.scopeArena == nil {
		ec.scopeArena = &scopeArena{}
	}

	ec.scopeArena.free = append(ec.scopeArena.free, old)
}

func (ec *execContext) setVar(name string, value xdm.Sequence) {
	if ec.localVars == nil {
		ec.localVars = ec.acquireVarScope()
	}

	if ec.localVars.vars == nil {
		ec.localVars.vars = make(map[string]xdm.Sequence, 4)
	}

	ec.localVars.vars[name] = value
	ec.localVarsVer++
}

// setVarDeferred stores a variable with a deferred error. The variable
// is set to an empty sequence; the error is raised only when the variable
// is actually referenced via ResolveVariable.
func (ec *execContext) setVarDeferred(name string, err error) {
	if ec.localVars == nil {
		ec.localVars = ec.acquireVarScope()
	}

	if ec.localVars.vars == nil {
		ec.localVars.vars = make(map[string]xdm.Sequence, 4)
	}

	ec.localVars.vars[name] = xdm.EmptySequence()
	if ec.localVars.deferredErrors == nil {
		ec.localVars.deferredErrors = make(map[string]error, 2)
	}

	ec.localVars.deferredErrors[name] = err
	ec.localVarsVer++
}

// lookupTypeNamespaceOK resolves a namespace prefix used inside a sequence
// type, honoring nsOverride when set (e.g. the declaration-site context of an
// xsl:global-context-item), falling back to the stylesheet-wide namespace map.
// It reports whether the prefix was bound.
func (ec *execContext) lookupTypeNamespaceOK(prefix string) (string, bool) {
	if ec.nsOverride != nil {
		if ns, ok := ec.nsOverride[prefix]; ok {
			return ns, true
		}

		return "", false
	}

	if ec.stylesheet != nil {
		ns, ok := ec.stylesheet.namespaces[prefix]
		return ns, ok
	}

	return "", false
}

func (ec *execContext) resolvePrefix(prefix string) string {
	// During pattern matching, resolve prefixes against the pattern's own
	// lexical namespace snapshot (and the predeclared XPath prefixes as a
	// fallback), never the mutable stylesheet-global map. This keeps node-test
	// prefixes (e.g. prefix:* in a match pattern) consistent with the rest of
	// pattern resolution and prevents an earlier top-level declaration from
	// leaking into a later pattern.
	if ec.inPatternMatch {
		return resolvePatternPrefix(ec.patternNamespaces, prefix)
	}

	ss := ec.effectiveStylesheet()
	if uri, ok := ss.namespaces[prefix]; ok {
		return uri
	}
	// Fall back to the main stylesheet's namespaces in case the
	// prefix is declared only at the top level.
	if ss != ec.stylesheet {
		if uri, ok := ec.stylesheet.namespaces[prefix]; ok {
			return uri
		}
	}
	// The xml prefix is universally predeclared per XML Namespaces spec.
	if prefix == lexicon.PrefixXML {
		return lexicon.NamespaceXML
	}

	return ""
}

// currentOutput returns the current output frame.
func (ec *execContext) currentOutput() *outputFrame {
	return ec.outputStack[len(ec.outputStack)-1]
}

func (ec *execContext) addNodeUntracked(node xdm.Node) error {
	if err := xpath.ChargeTree(ec.budgetCtx, node); err != nil {
		return err
	}

	out := ec.currentOutput()
	if err := out.current.AddChild(node); err != nil {
		return err
	}
	// Record text nodes in the active conditional scope so that separator
	// artifacts can be removed when on-empty fires (separators between
	// zero-length strings must not make content non-empty per XSLT 3.0).
	// Comment nodes (used as on-empty/on-non-empty placeholders) are
	// excluded — they are managed by resolveConditionalScope directly.
	if node.Type() == xdm.TextNode {
		if n := len(out.conditionalScopes); n > 0 {
			out.conditionalScopes[n-1].untrackedNodes = append(out.conditionalScopes[n-1].untrackedNodes, node.(xdm.MutableNode)) //nolint:forcetypeassert
		}
	}

	return nil
}

// addNode adds a node to the current output insertion point.
func (ec *execContext) addNode(node xdm.Node) error {
	if err := xpath.ChargeTree(ec.budgetCtx, node); err != nil {
		return err
	}

	out := ec.currentOutput()
	// When sequenceMode is set, capture all nodes as separate items in
	// the pending list. This prevents DOM text-node merging and keeps
	// attributes, comments, PIs, and elements as distinct sequence items.
	// Used by variable/param/with-param with an as attribute.
	if out.sequenceMode {
		out.pendingItems = append(out.pendingItems, xdm.NodeItem{Node: node})
		out.noteOutput()

		return nil
	}

	nodeType := node.Type()
	isText := nodeType == xdm.TextNode

	// When separateTextNodes is set, capture each text node as a separate
	// string item to avoid DOM text-node merging.  This is needed by
	// xsl:value-of with separator + body content so that each produced
	// text value remains a distinct item for separator insertion.
	if out.separateTextNodes && isText {
		// Keep as NodeItem so that mergeAdjacentTextNodes can merge them.
		out.pendingItems = append(out.pendingItems, xdm.NodeItem{Node: node})
		out.noteOutput()

		return nil
	}
	// Reset atomic adjacency tracking when any node (text or element)
	// is added via addNode. Text nodes from xsl:value-of or xsl:text
	// break the "consecutive atomic" chain from xsl:sequence outputs.
	out.prevWasAtomic = false

	// For text nodes, borrow the content and compute
	// whitespace-only once; both are used by multiple checks below.
	var text string

	isNonWhitespaceText := false

	if isText {
		text = xdm.CharacterData(node)
		isNonWhitespaceText = !isXMLWhitespaceOnly(text)
	}

	if err := ec.prepareNodeSeparators(out, node, nodeType, text); err != nil {
		return err
	}

	// Zero-length text nodes are discarded from the result tree
	// (XSLT 3.0 §11.4.1: "If the result ... is a zero-length string,
	// then no text node is created").
	if isText && len(text) == 0 {
		return nil
	}
	// When a text node is about to be merged (via addChild) with an
	// existing text node that was marked as atomic (from xsl:on-empty /
	// xsl:sequence splice), clear the atomic marker.  The DOM's addChild
	// merges adjacent text nodes, so the combined text is no longer purely
	// an atomic serialization and must not trigger inter-atomic space
	// separators in subsequent splice operations.
	if isText {
		if last := out.current.LastChild(); last != nil && last.Type() == xdm.TextNode {
			ec.clearAtomicTextNode(last)
		}
	}

	if err := out.current.AddChild(node); err != nil {
		return err
	}

	out.noteOutput()
	// Track that output was produced for item-separator insertion
	// between non-atomic items (e.g., comment→atomic, element→atomic).
	// Whitespace-only text nodes between instructions don't count.
	if !isText || isNonWhitespaceText {
		out.prevHadOutput = true
	}

	return nil
}

func (ec *execContext) prepareNodeSeparators(out *outputFrame, node xdm.Node, nodeType xdm.ElementType, text string) error {
	isText := nodeType == xdm.TextNode
	if len(out.deferredMarkupSeps) > 0 &&
		(!isText || len(text) > 0) &&
		!isAdaptiveStandaloneMarkupNode(node) {
		if err := out.materializeDeferredMarkupSeps(); err != nil {
			return err
		}
	}

	// When item-separator is explicitly set, insert it between any pair
	// of adjacent items in the result sequence (XSLT 3.0 serialization).
	// This covers nodes produced by instructions like xsl:comment, xsl:element,
	// xsl:processing-instruction that don't go through execXSLSequence.
	// Only non-text nodes trigger this; text nodes from xsl:text/xsl:value-of
	// are not separate "items" in the serialization sense.
	if out.itemSeparator != nil && out.prevHadOutput && !isText && nodeType != xdm.AttributeNode {
		sepStr := *out.itemSeparator
		if sepStr != "" && !ec.deferAdaptiveMarkupSeparator(out, node, sepStr) {
			sep := ec.resultDoc.CreateText(sepStr)
			if err := out.current.AddChild(sep); err != nil {
				return err
			}
		}
	}

	return nil
}

// deferAdaptiveMarkupSeparator keeps an adaptive item separator outside the
// DOM while the current result document contains only top-level markup. A later
// fallback restores every deferred separator at its original boundary.
func (ec *execContext) deferAdaptiveMarkupSeparator(out *outputFrame, node xdm.Node, sep string) bool {
	if ec.currentResultDocMethod != methodAdaptive || out.current != out.doc || !isAdaptiveStandaloneMarkupNode(node) {
		return false
	}

	if !adaptiveStandaloneMarkupDocument(out.doc) {
		return false
	}

	right, ok := node.(xdm.MutableNode)
	if !ok {
		return false
	}

	out.deferredMarkupSeps = append(out.deferredMarkupSeps, deferredMarkupSeparator{
		right: right,
		text:  sep,
	})

	return true
}

func (ec *execContext) executeSequenceConstructor(ctx context.Context, body []instruction) error {
	if len(body) == 0 {
		return nil
	}

	out := ec.currentOutput()
	out.seqConstructorGen++
	scopeIdx := len(out.conditionalScopes)
	out.conditionalScopes = append(out.conditionalScopes, conditionalScope{pendingStart: len(out.pendingItems)})

	for _, inst := range body {
		_, isOnEmpty := inst.(*onEmptyInst)
		_, isOnNonEmpty := inst.(*onNonEmptyInst)

		snap := out.outputSerial
		if err := ec.executeInstruction(ctx, inst); err != nil {
			out.conditionalScopes = out.conditionalScopes[:scopeIdx]
			return err
		}

		if !isOnEmpty && !isOnNonEmpty && out.outputSerial != snap {
			out.conditionalScopes[scopeIdx].hasOutput = true
		}
	}

	scope := out.conditionalScopes[scopeIdx]
	out.conditionalScopes = out.conditionalScopes[:scopeIdx]

	return ec.resolveConditionalScope(ctx, scope)
}

func (ec *execContext) resolveConditionalScope(ctx context.Context, scope conditionalScope) error {
	if ec.currentOutput().sequenceMode && len(scope.actions) > 0 {
		return ec.resolveConditionalItems(ctx, scope)
	}
	// When on-empty fires (!scope.hasOutput), remove nodes that were added
	// via addNodeUntracked. These are separator artifacts inserted between
	// zero-length atomic values and must not appear in the output (XSLT 3.0:
	// "Separators between zero-length strings do not make the content
	// non-empty").
	if !scope.hasOutput {
		for _, n := range scope.untrackedNodes {
			xdm.UnlinkNode(n)
		}
	}

	for _, action := range scope.actions {
		shouldRun := (action.kind == conditionalOnEmpty && !scope.hasOutput) ||
			(action.kind == conditionalOnNonEmpty && scope.hasOutput)
		if !shouldRun {
			if action.placeholder != nil {
				xdm.UnlinkNode(action.placeholder)
			}

			continue
		}

		content, err := ec.evaluateConditionalAction(ctx, action)
		if err != nil {
			return err
		}

		if err := ec.spliceConditionalSequence(action.placeholder, content, action.prevWasAtomic); err != nil {
			return err
		}
	}

	return nil
}

func (ec *execContext) evaluateConditionalAction(ctx context.Context, action conditionalAction) (xdm.Sequence, error) {
	local, base, ns, hasNS := ec.localVars, ec.staticBaseURIOverride, ec.xpathDefaultNS, ec.hasXPathDefaultNS
	ec.localVars, ec.staticBaseURIOverride, ec.xpathDefaultNS, ec.hasXPathDefaultNS = action.localVars, action.staticBaseURI, action.xpathDefaultNS, action.hasXPathDefaultNS
	ec.localVarsVer++

	ec.errSourceLine, ec.errSourceModule = action.sourceLine, action.sourceModule
	defer func() {
		ec.localVars, ec.staticBaseURIOverride, ec.xpathDefaultNS, ec.hasXPathDefaultNS = local, base, ns, hasNS
		ec.localVarsVer++
	}()

	return ec.evaluateConditionalInstruction(ctx, action.selectExpr, action.body)
}

// resolveConditionalItems substitutes deferred actions in the raw sequence,
// without converting atomics, arrays or parentless nodes to temporary DOM text.
func (ec *execContext) resolveConditionalItems(ctx context.Context, scope conditionalScope) error {
	out := ec.currentOutput()

	actions := make(map[xdm.Node]conditionalAction, len(scope.actions))
	for _, action := range scope.actions {
		actions[action.placeholder] = action
	}

	items := out.pendingItems[scope.pendingStart:]

	hasOnEmpty := false
	for _, action := range scope.actions {
		hasOnEmpty = hasOnEmpty || action.kind == conditionalOnEmpty
	}

	hasOutput, err := conditionalItemsNonVacuous(ctx, items, actions)
	if err != nil {
		return err
	}
	// Build separately: an action may expand, so appending over items while
	// reading them could overwrite a later sibling before it is visited.
	var result xdm.ItemSlice

	for _, item := range items {
		if err := xpath.Charge(ctx, 1); err != nil {
			return err
		}

		if action, placeholder := conditionalActionForItem(actions, item); placeholder {
			if (action.kind == conditionalOnEmpty && !hasOutput) || (action.kind == conditionalOnNonEmpty && hasOutput) {
				content, err := ec.evaluateConditionalAction(ctx, action)
				if err != nil {
					return err
				}

				result = append(result, xdm.Materialize(content)...)
			}

			continue
		}

		if hasOutput || !hasOnEmpty {
			result = append(result, item)
		}
	}

	out.pendingItems = append(out.pendingItems[:scope.pendingStart], result...)
	if len(result) > 0 {
		out.noteOutput()
	}

	return nil
}

func conditionalActionForItem(actions map[xdm.Node]conditionalAction, item xdm.Item) (conditionalAction, bool) {
	node, ok := item.(xdm.NodeItem)
	if !ok {
		return conditionalAction{}, false
	}

	action, ok := actions[node.Node]

	return action, ok
}

func conditionalItemsNonVacuous(ctx context.Context, items xdm.ItemSlice, actions map[xdm.Node]conditionalAction) (bool, error) {
	for _, item := range items {
		if _, placeholder := conditionalActionForItem(actions, item); placeholder {
			continue
		}

		empty, err := conditionalItemEmpty(ctx, item, vacuousItem, 0)
		if err != nil || !empty {
			return !empty, err
		}
	}

	return false, nil
}

func (ec *execContext) spliceConditionalSequence(placeholder xdm.MutableNode, seq xdm.Sequence, prevWasAtomic bool) error {
	if placeholder == nil {
		return ec.outputSequence(seq)
	}

	parent := placeholder.Parent()
	out := ec.currentOutput()

	savedCurrent := out.current
	if parent != nil {
		out.current = parent.(xdm.MutableNode) //nolint:forcetypeassert
		defer func() {
			out.current = savedCurrent
		}()
	}

	seq = flattenArraysInSequence(seq)

	var nodes []xdm.Node
	// Determine whether the content preceding this splice was an atomic value.
	// We use two signals:
	//   (a) prevWasAtomic captured at registration time (reflects the
	//       xsl:sequence / xsl:value-of state at the point on-empty was seen)
	//   (b) isAtomicTextNode on the placeholder's previous DOM sibling
	//       (reflects spliced atomic text that hasn't been merged away)
	// Either being true means we need an inter-atomic space separator.
	prevAtomic := prevWasAtomic || ec.isAtomicTextNode(placeholder.PrevSibling())

	for item := range xdm.SequenceItems(seq) {
		var err error

		switch value := item.(type) {
		case xdm.NodeItem:
			prevAtomic = false
			nodes, err = ec.appendConditionalNode(nodes, value.Node, parent)
		case xdm.AtomicValue:
			nodes, err = ec.appendConditionalAtomic(nodes, value, prevAtomic)
			prevAtomic = true
		}

		if err != nil {
			return err
		}
	}

	if len(nodes) == 0 {
		// Even though no DOM nodes were produced, update prevWasAtomic
		// if an empty-string atomic was seen. This ensures that
		// subsequent xsl:sequence or on-empty instructions see the
		// correct atomic adjacency state (e.g., on-non-empty with
		// select="''" should contribute to the inter-atomic chain).
		if prevAtomic {
			out.prevWasAtomic = true
		}

		xdm.UnlinkNode(placeholder)

		return nil
	}

	spliceReplace(placeholder, nodes)
	// Fix namespace declarations on spliced elements that moved into a
	// context with a different default namespace (e.g. a no-namespace
	// element placed under a parent with xmlns="...").
	for _, n := range nodes {
		if elem, ok := n.(*xdm.Element); ok {
			ec.fixNamespacesAfterCopy(elem)
		}
	}
	// Update prevWasAtomic to reflect the spliced content so that
	// subsequent instructions see the correct atomic adjacency state.
	out.prevWasAtomic = prevAtomic
	out.noteOutput()

	return nil
}

func spliceReplace(target xdm.MutableNode, nodes []xdm.Node) {
	if len(nodes) == 0 {
		xdm.UnlinkNode(target)
		return
	}

	_ = target.Replace(nodes...)
}

func (ec *execContext) appendConditionalNode(nodes []xdm.Node, node, parent xdm.Node) ([]xdm.Node, error) {
	switch node.Type() {
	case xdm.DocumentNode:
		for child := range xdm.Children(node) {
			if !xdm.IsXDMChild(child) {
				continue
			}

			copied, err := xdm.CopyNode(child, ec.resultDoc)
			if err != nil {
				return nil, err
			}

			nodes = append(nodes, copied)
		}
	case xdm.AttributeNode:
		elem, ok := parent.(*xdm.Element)
		if !ok {
			return nil, dynamicError(errCodeXTDE0410, "cannot add attribute to a non-element node")
		}

		attr, _ := xdm.AsNode[*xdm.Attribute](node)
		copyAttributeToElement(elem, attr)
		ec.currentOutput().noteOutput()
	default:
		copied, err := xdm.CopyNode(node, ec.resultDoc)
		if err != nil {
			return nil, err
		}

		nodes = append(nodes, copied)
	}

	return nodes, nil
}

func (ec *execContext) appendConditionalAtomic(nodes []xdm.Node, value xdm.AtomicValue, previousAtomic bool) ([]xdm.Node, error) {
	text, err := xpath.AtomicToString(value)
	if err != nil {
		return nil, err
	}

	// Even an empty atomic contributes a separator after another atomic.
	if previousAtomic {
		nodes = append(nodes, ec.resultDoc.CreateText(" "))
	}

	if text != "" {
		node := ec.resultDoc.CreateText(text)
		nodes = append(nodes, node)
		ec.markAtomicTextNode(node)
	}

	return nodes, nil
}

func (ec *execContext) collectionResolver() xpath.CollectionResolver {
	if ec.transformConfig == nil || ec.transformConfig.collectionResolver == nil {
		return nil
	}

	return executionCollectionResolver{
		base: ec.transformConfig.collectionResolver,
		ec:   ec,
	}
}

// sortXPathEvalState creates a reusable xpath.EvalState from the base context.
// Used by sort to avoid per-item newEvalContext allocations.
func (ec *execContext) sortXPathEvalState(ctx context.Context) *xpath.EvalState {
	return ec.xpathEvaluator(ctx).NewEvalState(nil)
}

// xpathContext returns a context.Context suitable for XPath evaluation.
// It carries cancellation/deadlines and the xslt exec context, but
// NOT XPath config (that comes from the Evaluator). When ctx already resolves
// to ec (the transform attaches it at the start), ctx is returned as is
// instead of wrapping it again on every evaluation.
func (ec *execContext) xpathContext(ctx context.Context) context.Context {
	if ec.stylesheet.dynamicEvaluationDisabled && !dynamicEvaluationDisabled(ctx) {
		ctx = WithDynamicEvaluationDisabled(ctx)
	}

	if getExecContext(ctx) == ec {
		return ctx
	}

	return withExecContext(ctx, ec)
}

func withExecContext(ctx context.Context, ec *execContext) context.Context {
	return context.WithValue(ctx, execContextKey{}, ec)
}

func getExecContext(ctx context.Context) *execContext {
	v, _ := ctx.Value(execContextKey{}).(*execContext)
	return v
}

// baseXPathEvaluator returns a base XPath evaluator for the current static
// context (xpath-default-namespace, effective base URI, package, and, during
// pattern matching, the pattern's namespaces) together with its generation
// number. Evaluators are cached per baseEvalKey and built only on a miss.
func (ec *execContext) baseXPathEvaluator() (xpath.Evaluator, uint64) {
	key := baseEvalKey{
		xpathDefaultNS:    ec.xpathDefaultNS,
		hasXPathDefaultNS: ec.hasXPathDefaultNS,
		baseURI:           ec.effectiveStaticBaseURI(),
		pkg:               ec.currentPackage,
		inPattern:         ec.inPatternMatch,
	}
	mode := 0

	var patternNS map[string]string

	if ec.inPatternMatch {
		mode = 1
		patternNS = ec.patternNamespaces
		key.patternNS = mapIdentity(patternNS)
	}

	row := &ec.baseEvals[mode]
	for i := range row {
		if row[i].gen != 0 && row[i].key == key {
			return row[i].eval, row[i].gen
		}
	}

	eval := ec.buildBaseXPathEvaluator(key.baseURI)
	ec.baseEvalGen++
	slot := &row[ec.baseEvalNext[mode]]
	ec.baseEvalNext[mode] = (ec.baseEvalNext[mode] + 1) % baseEvalSlots
	*slot = baseEvalEntry{key: key, eval: eval, gen: ec.baseEvalGen, patternNS: patternNS}

	return eval, ec.baseEvalGen
}

// buildBaseXPathEvaluator constructs the base evaluator from scratch.
// Variables and functions are NOT included — they change per-scope
// and are applied in xpathEvaluator() as per-call overlays.
func (ec *execContext) buildBaseXPathEvaluator(baseURI string) xpath.Evaluator {
	eval := xpath.NewEvaluator(xpath.EvalBorrowing).
		VariableResolver(ec).
		FunctionResolver(ec).
		CurrentTime(ec.currentTime).
		ImplicitTimezone(ec.dynamicProperties.Timezone).
		AllowXML11Chars().
		TraceWriter(ec.traceWriter)
	if ec.stylesheet.processorLanguage() >= 30 {
		eval = eval.ResourceReads(ec)
	}

	if ns := ec.effectiveXPathNamespaces(); ns != nil {
		eval = eval.Namespaces(ns).StrictPrefixes()
	}

	if ec.inPatternMatch {
		eval = eval.DefaultXMLNamespace(ec.patternNamespaces[""])
	}

	if baseURI != "" {
		eval = eval.BaseURI(ensureFileURI(baseURI))
	}

	dfmts := ec.effectiveDecimalFormats()
	if len(dfmts) > 0 {
		for qn, df := range dfmts {
			if qn == (xpath.QualifiedName{}) {
				eval = eval.DefaultDecimalFormat(df)
			}
		}

		eval = eval.NamedDecimalFormats(dfmts)
	}

	if resolver := ec.collectionResolver(); resolver != nil {
		eval = eval.CollectionResolver(resolver)
	}

	if ec.transformConfig != nil {
		if r := ec.transformConfig.uriResolver; r != nil {
			eval = eval.URIResolver(r)
		}

		if c := ec.transformConfig.httpClient; c != nil {
			eval = eval.HTTPClient(c)
		}
		// Forward the injected base parseOptions so fn:doc / fn:parse-xml inside XPath
		// expressions parse under the same policy as the rest of the engine.
		if p := ec.transformConfig.parseOptions; p != nil {
			eval = eval.ParseOptions(*p)
		}
		// Map the xslt resource cap onto the xpath evaluator so
		// fn:unparsed-text / fn:json-doc reads honor the same bound. The
		// xpath setter takes 0 = unparsedtext default, so translate the
		// xslt 0-means-default convention into the concrete default here.
		eval = eval.MaxResourceBytes(resolveResourceLimit(ec.resourceLimit()))
	}

	return eval
}

// effectiveXPathNamespaces returns the prefix→URI bindings for the strict
// XPath evaluator, or nil when there are no bindings to apply. The evaluator is
// built with StrictPrefixes(), so it does NOT consult the XPath predeclared
// fallback (fn/math/map/array/xs/err) on its own. Stylesheet-declared bindings
// always take precedence; explicit declarations override the fallback.
func (ec *execContext) effectiveXPathNamespaces() map[string]string {
	// During pattern matching, prefix resolution must use the PATTERN's own
	// lexical namespace snapshot (captured at compile time from the xmlns
	// declarations in scope at the pattern's position), overlaid on the XPath
	// predeclared prefixes (fn/math/map/...). It must NOT consult the mutable
	// stylesheet-global namespace map, which is polluted in document order by
	// every top-level declaration's namespaces — using it would let an earlier
	// unrelated xmlns:math="urn:custom" override the predeclared math namespace
	// for a later pattern that has no local xmlns:math. This keeps runtime
	// resolution symmetric with compile-time pattern validation.
	if ec.inPatternMatch {
		ns := make(map[string]string, len(xpath.PredeclaredNamespaces())+len(ec.patternNamespaces)+1)
		// Seed the predeclared bindings first so the pattern's explicit lexical
		// declarations below override them.
		maps.Copy(ns, xpath.PredeclaredNamespaces())
		// Copy only NON-EMPTY prefixes from the pattern's lexical snapshot. A
		// stylesheet xmlns="..." default namespace lands in the snapshot under
		// the "" key, but the XML default namespace must NOT become the XPath
		// default ELEMENT namespace for unprefixed pattern names. Unprefixed
		// names default to no-namespace unless xpath-default-namespace is set.
		for prefix, uri := range ec.patternNamespaces {
			if prefix == "" {
				continue
			}

			ns[prefix] = uri
		}

		if ec.hasXPathDefaultNS {
			ns[""] = ec.xpathDefaultNS
		}

		return ns
	}

	if len(ec.stylesheet.namespaces) == 0 && !ec.hasXPathDefaultNS {
		return nil
	}

	ns := make(map[string]string, len(ec.stylesheet.namespaces)+1)
	collectPackageNamespaces(ec.stylesheet, ns)

	for k, v := range ec.stylesheet.namespaces {
		if k == "" && !ec.hasXPathDefaultNS {
			continue
		}

		ns[k] = v
	}

	if ec.hasXPathDefaultNS {
		ns[""] = ec.xpathDefaultNS
	}

	return ns
}

// collectPackageNamespaces recursively collects all namespace bindings from
// used packages into the provided map. Main stylesheet bindings take precedence.
func collectPackageNamespaces(ss *Stylesheet, ns map[string]string) {
	for _, pkg := range ss.usedPackages {
		collectPackageNamespaces(pkg, ns)

		for k, v := range pkg.namespaces {
			if k == "" {
				continue
			}

			if _, exists := ns[k]; !exists {
				ns[k] = v
			}
		}
	}
}

// effectiveDecimalFormats returns the decimal formats for the current
// execution scope. When executing code from a used package, the
// package's own decimal formats are used (package-scoped isolation).
func (ec *execContext) effectiveDecimalFormats() map[xpath.QualifiedName]xpath.DecimalFormat {
	if ec.currentPackage != nil && ec.currentPackage != ec.stylesheet {
		return ec.currentPackage.decimalFormats
	}

	return ec.stylesheet.decimalFormats
}

// effectiveKeys returns the key definitions for the current execution
// scope. When executing code from a used package, the package's own
// keys are used (package-scoped isolation).
func (ec *execContext) effectiveKeys() map[string][]*keyDef {
	if ec.currentPackage != nil && ec.currentPackage != ec.stylesheet {
		return ec.currentPackage.keys
	}

	return ec.stylesheet.keys
}

// effectiveOutputs returns the output definitions for the current
// execution scope. When executing code from a used package, the
// package's own outputs are used (package-scoped isolation).
func (ec *execContext) effectiveOutputs() map[string]*OutputDef {
	if ec.currentPackage != nil && ec.currentPackage != ec.stylesheet {
		return ec.currentPackage.outputs
	}

	return ec.stylesheet.outputs
}

// effectiveStylesheet returns the stylesheet for the current execution
// scope. When executing code from a used package, the package is returned.
func (ec *execContext) effectiveStylesheet() *Stylesheet {
	if ec.currentPackage != nil && ec.currentPackage != ec.stylesheet {
		return ec.currentPackage
	}

	return ec.stylesheet
}

// effectiveModeDefs returns definitions from the package bound to the active
// mode. A named helper can have a different lexical package without changing it.
func (ec *execContext) effectiveModeDefs() map[string]*modeDef {
	return ec.activeModePackage().modeDefs
}

func (ec *execContext) activeModePackage() *Stylesheet {
	if ec.currentModePackage != nil {
		return ec.currentModePackage
	}

	return ec.effectiveStylesheet().modePackage(ec.currentMode)
}

func (ec *execContext) pushMode(mode string) (string, func()) {
	savedMode, savedPackage := ec.currentMode, ec.currentModePackage
	pkg := ec.effectiveStylesheet()

	switch mode {
	case modeCurrent:
		mode, pkg = ec.currentMode, ec.activeModePackage()
	case modeUnnamed:
		mode = ""
	case modeDefault, "":
		mode = pkg.defaultMode
		if mode == modeUnnamed {
			mode = ""
		}
	}

	ec.currentMode, ec.currentModePackage = mode, pkg.modePackage(mode)

	return mode, func() { ec.currentMode, ec.currentModePackage = savedMode, savedPackage }
}

func (ec *execContext) pushPackage(pkg *Stylesheet) func() {
	savedPackage, savedFns := ec.currentPackage, ec.cachedFnsNS
	if pkg != ec.currentPackage {
		ec.currentPackage, ec.cachedFnsNS = pkg, nil
	}

	return func() { ec.currentPackage, ec.cachedFnsNS = savedPackage, savedFns }
}

// effectiveAttributeSets returns the attribute-set definitions for the
// current execution scope. When executing code from a used package, the
// package's own attribute-sets are used (package-scoped isolation).
func (ec *execContext) effectiveAttributeSets() map[string]*attributeSetDef {
	if ec.currentPackage != nil && ec.currentPackage != ec.stylesheet {
		return ec.currentPackage.attributeSets
	}

	return ec.stylesheet.attributeSets
}

// effectiveAccumulators returns the accumulator definitions for the current
// execution scope. When executing code from a used package, the package's
// own accumulators are used (package-scoped isolation).
func (ec *execContext) effectiveAccumulators() map[string]*accumulatorDef {
	if ec.currentPackage != nil && ec.currentPackage != ec.stylesheet {
		return ec.currentPackage.accumulators
	}

	return ec.stylesheet.accumulators
}

// accumulatorStateKey returns a package-scoped key for accumulator state
// storage. When executing in a used package, the key includes the package
// pointer to isolate same-named accumulators from different packages.
func (ec *execContext) accumulatorStateKey(name string) string {
	if ec.currentPackage != nil && ec.currentPackage != ec.stylesheet {
		return fmt.Sprintf("%s@%p", name, ec.currentPackage)
	}

	return name
}

// scopedXPathEvaluator returns the base evaluator overlaid with everything
// except the dynamic focus: variables, functions, schema state, collation, and
// the doc-order cache. These change only when a variable scope, package,
// collation, or schema state changes, so the result is cached and rebuilt only
// when none of the cached ones matches all of its inputs (scopedEvalKey).
// compat selects the XPath 1.0 compatibility-mode variant.
func (ec *execContext) scopedXPathEvaluator(ctx context.Context, compat bool) xpath.Evaluator {
	vars := ec.collectAllVars(ctx)
	base, baseGen := ec.baseXPathEvaluator()
	fns := ec.xsltFunctions()
	fnsNS := ec.xsltFunctionsNS()
	nilled := ec.nilledElementNodes()
	key := scopedEvalKey{
		baseGen:     baseGen,
		vars:        mapIdentity(vars),
		fns:         mapIdentity(fns),
		fnsNS:       mapIdentity(fnsNS),
		typeAnn:     mapIdentity(ec.typeAnnotations),
		nilled:      mapIdentity(nilled),
		preservedID: mapIdentity(ec.preservedIDAnnotations),
		collation:   ec.defaultCollation,
		docOrder:    ec.docOrderCache,
	}

	var cache *scopedEvalCache

	for i := range ec.scopedEvals {
		if ec.scopedEvals[i].valid && ec.scopedEvals[i].key == key {
			cache = &ec.scopedEvals[i]
			break
		}
	}

	if cache == nil {
		cache = &ec.scopedEvals[ec.scopedEvalNext]
		ec.scopedEvalNext = (ec.scopedEvalNext + 1) % scopedEvalSlots

		eval := base.Variables(vars).Functions(fns, fnsNS)
		if ec.typeAnnotations != nil {
			eval = eval.TypeAnnotations(ec.typeAnnotations)
		}

		if nilled != nil {
			eval = eval.NilledElements(nilled)
		}

		if ec.preservedIDAnnotations != nil {
			eval = eval.PreservedIDAnnotations(ec.preservedIDAnnotations)
		}

		if ec.defaultCollation != "" {
			eval = eval.DefaultCollation(ec.defaultCollation)
		}

		if ec.docOrderCache != nil {
			eval = eval.DocOrderCache(ec.docOrderCache)
		}

		*cache = scopedEvalCache{key: key, valid: true, eval: eval}
	}

	if !compat {
		return cache.eval
	}

	if !cache.compatValid {
		cache.compat = cache.eval.XPath10Compat()
		cache.compatValid = true
	}

	return cache.compat
}

// withFocus applies the current dynamic focus (context item, position, size)
// to eval. When no focus is set, eval is returned unchanged.
func (ec *execContext) withFocus(eval xpath.Evaluator) xpath.Evaluator {
	if ec.contextItem == nil && ec.position <= 0 && ec.size <= 0 {
		return eval
	}

	return eval.Focus(ec.contextItem, ec.position, ec.size)
}

// xpathEvaluator returns the scoped evaluator with the current dynamic focus
// applied.
func (ec *execContext) xpathEvaluator(ctx context.Context) xpath.Evaluator {
	return ec.withFocus(ec.scopedXPathEvaluator(ctx, false))
}

// evalXPath evaluates an XPath expression using the Evaluator-based path.
func (ec *execContext) evalXPath(ctx context.Context, expr *xpath.Expression, node xdm.Node) (*xpath.Result, error) {
	eval := ec.withFocus(ec.scopedXPathEvaluator(ctx, ec.isCompatExpr(expr)))
	return eval.Evaluate(ec.xpathContext(ctx), expr, node)
}

// evalXPathEBV evaluates an XPath expression as evalXPath does and returns
// its effective boolean value. A node path that is the whole expression
// stops at its first node (xpath.Evaluator.EvaluateEBV).
func (ec *execContext) evalXPathEBV(ctx context.Context, expr *xpath.Expression, node xdm.Node) (bool, error) {
	eval := ec.withFocus(ec.scopedXPathEvaluator(ctx, ec.isCompatExpr(expr)))
	return eval.EvaluateEBV(ec.xpathContext(ctx), expr, node)
}

// evalPatternExpr evaluates a match-pattern (or predicate) expression, which is
// compiled at runtime and so is not in compatExprs. A backwards-compatible
// pattern evaluates in XPath 1.0 compatibility mode. Unlike a persistent
// ec.patternCompat read inside evalXPath, this applies compat ONLY to the
// pattern expression itself — a called xsl:function/template evaluates its own
// body via evalXPath under its OWN version, so compat does not leak across the
// component boundary.
func (ec *execContext) evalPatternExpr(ctx context.Context, expr *xpath.Expression, node xdm.Node) (*xpath.Result, error) {
	eval := ec.withFocus(ec.scopedXPathEvaluator(ctx, ec.patternCompat))
	return eval.Evaluate(ec.xpathContext(ctx), expr, node)
}

// isCompatExpr reports whether expr was compiled under XSLT backwards-compatible
// processing and must evaluate in XPath 1.0 compatibility mode.
func (ec *execContext) isCompatExpr(expr *xpath.Expression) bool {
	if ec.stylesheet == nil || ec.stylesheet.compatExprs == nil {
		return false
	}

	_, ok := ec.stylesheet.compatExprs[expr]

	return ok
}

// withCompat applies XPath 1.0 compatibility mode to a custom-built evaluator
// when expr is compat-marked. Used at the few evaluation sites that build their
// own Evaluator instead of going through evalXPath.
func (ec *execContext) withCompat(eval xpath.Evaluator, expr *xpath.Expression) xpath.Evaluator {
	if ec.isCompatExpr(expr) {
		return eval.XPath10Compat()
	}

	return eval
}

// visibleVarScope returns the innermost local scope that holds bindings, or nil
// when no local binding is in scope. Empty scopes (a template or instruction
// that declares no variables) contribute nothing to the visible variables, so
// collectAllVars keys its cache on this scope instead of ec.localVars. The
// bindings of this scope and of its ancestors change only through setVar and
// setVarDeferred, which increment localVarsVer.
func (ec *execContext) visibleVarScope() *varScope {
	for s := ec.localVars; s != nil; s = s.parent {
		if len(s.vars) > 0 {
			return s
		}
	}

	return nil
}

func (ec *execContext) collectAllVars(ctx context.Context) map[string]xdm.Sequence {
	// Eagerly evaluate all pending global vars/params, but only at the
	// top level. Nested calls (from within evaluateGlobalVar/param →
	// newXPathContext → collectAllVars) just snapshot what's available;
	// the lazy lookupVar path handles remaining references on demand.
	if !ec.collectingVars && (len(ec.globalVarDefs) > 0 || len(ec.globalParamDefs) > 0) {
		ec.collectingVars = true
		defer func() { ec.collectingVars = false }()

		ec.evaluatePendingGlobals(ctx)
	}

	// Fast path: when neither the globals, the visible local bindings, nor
	// the package context changed since the cached map was built, return it.
	// Callers must not mutate the returned map.
	visible := ec.visibleVarScope()
	if ec.cachedVarsMap != nil &&
		ec.cachedVarsGen == ec.globalVarsGen &&
		ec.cachedVarsScope == visible &&
		ec.cachedVarsScopeVer == ec.localVarsVer &&
		ec.cachedVarsPackage == ec.currentPackage {
		return ec.cachedVarsMap
	}

	inPackage := ec.currentPackage != nil && ec.currentPackage != ec.stylesheet

	vars := make(map[string]xdm.Sequence, len(ec.globalVars))
	// Start with globals
	if !inPackage {
		maps.Copy(vars, ec.globalVars)
	}
	// Walk from outermost to innermost scope so inner scopes override
	var scopes []*varScope
	for s := ec.localVars; s != nil; s = s.parent {
		scopes = append(scopes, s)
	}

	for _, v := range slices.Backward(scopes) {
		maps.Copy(vars, v.vars)
	}

	ec.cachedVarsMap = vars
	ec.cachedVarsGen = ec.globalVarsGen
	ec.cachedVarsScope = visible
	ec.cachedVarsScopeVer = ec.localVarsVer
	ec.cachedVarsPackage = ec.currentPackage

	return vars
}

func (ec *execContext) evaluatePendingGlobals(ctx context.Context) {
	for len(ec.globalVarDefs) > 0 || len(ec.globalParamDefs) > 0 {
		if !ec.evaluatePendingGlobalPass(ctx) {
			return // No progress: leave circular dependencies to lazy lookup.
		}
	}
}

func (ec *execContext) evaluatePendingGlobalPass(ctx context.Context) bool {
	progress := false
	// Sorted names preserve document-order-cache registration deterministically.
	for _, name := range slices.Sorted(maps.Keys(ec.globalVarDefs)) {
		variable, ok := ec.globalVarDefs[name]
		if !ok || variable.OwnerPackage != nil && variable.OwnerPackage != ec.stylesheet {
			continue
		}

		if _, err := ec.evaluateGlobalVar(ctx, variable); err == nil {
			progress = true
		}
	}

	for _, name := range slices.Sorted(maps.Keys(ec.globalParamDefs)) {
		param, ok := ec.globalParamDefs[name]
		if !ok || param.OwnerPackage != nil && param.OwnerPackage != ec.stylesheet {
			continue
		}

		if _, err := ec.evaluateGlobalParam(ctx, param); err == nil {
			progress = true
		}
	}

	return progress
}

func (ec *execContext) resolveOriginalVariable(ctx context.Context) (xdm.Sequence, bool, error) {
	value, err := ec.evaluateGlobalBinding(ctx, ec.originalGlobal)
	return value, err == nil, err
}

func (ec *execContext) expandVariableName(name string) string {
	expandedName := name
	if !strings.HasPrefix(name, "{") && strings.Contains(name, ":") {
		parts := strings.SplitN(name, ":", 2)
		if uri, ok := ec.stylesheet.namespaces[parts[0]]; ok {
			expandedName = xdm.ClarkName(uri, parts[1])
		}

		if expandedName == name && ec.currentPackage != nil {
			if uri, ok := ec.currentPackage.namespaces[parts[0]]; ok {
				expandedName = xdm.ClarkName(uri, parts[1])
			}
		}
	}

	return expandedName
}

func (ec *execContext) resolveLocalVariable(lookupNames []string) (xdm.Sequence, bool, error) {
	// Check local vars (in case the scope was pushed after the snapshot)
	if ec.localVars != nil {
		for _, n := range lookupNames {
			if v, ok := ec.localVars.lookup(n); ok {
				if err := ec.localVars.lookupDeferred(n); err != nil {
					return nil, false, err
				}

				return v, true, nil
			}
		}
	}

	return nil, false, nil
}

func (ec *execContext) resolvePendingGlobalVariable(ctx context.Context, lookupNames []string) (xdm.Sequence, bool, error) {
	// Try to lazily evaluate a pending global variable
	for _, n := range lookupNames {
		if def, ok := ec.globalVarDefs[n]; ok {
			val, err := ec.evaluateGlobalVar(ctx, def)
			if err != nil {
				return nil, false, err
			}

			return val, true, nil
		}
	}

	return nil, false, nil
}

func (ec *execContext) resolveOwnPackageDeclaration(ctx context.Context, name string) (xdm.Sequence, bool, error) {
	// When evaluating in a package context, also check the package's own
	// global variables (including private ones not merged into the stylesheet).
	if ec.currentPackage != nil {
		for _, v := range ec.currentPackage.globalVars {
			if v.Name == name {
				val, err := ec.evaluateGlobalVar(ctx, v)
				if err != nil {
					return nil, false, err
				}

				return val, true, nil
			}
		}
		// Also check package-scoped global params (e.g. private params
		// that were not merged into the using stylesheet).
		for _, p := range ec.currentPackage.globalParams {
			if p.Name == name {
				val, err := ec.evaluateGlobalParam(ctx, p)
				if err != nil {
					return nil, false, err
				}

				return val, true, nil
			}
		}
	}

	return nil, false, nil
}

func (ec *execContext) resolvePendingGlobalParam(ctx context.Context, lookupNames []string) (xdm.Sequence, bool, error) {
	// Try to lazily evaluate a pending global parameter
	for _, n := range lookupNames {
		if def, ok := ec.globalParamDefs[n]; ok {
			val, err := ec.evaluateGlobalParam(ctx, def)
			if err != nil {
				return nil, false, err
			}

			return val, true, nil
		}
	}

	return nil, false, nil
}

// executeInstruction dispatches execution of a compiled XSLT instruction.
func (ec *execContext) executeInstruction(ctx context.Context, inst instruction) (err error) {
	// Check at instruction boundaries so a collision caused by any output
	// path (including raw item capture) can be caught by the enclosing xsl:try.
	defer func() {
		if err == nil {
			err = ec.checkImplicitPrimaryOutput()
		}
	}()

	if err := xpath.Charge(ctx, 1); err != nil {
		return err
	}
	// Track source location for xsl:catch error variables ($err:line-number, $err:module)
	if s, ok := inst.(interface {
		getSourceLine() int
		getSourceModule() string
	}); ok {
		ec.errSourceLine = s.getSourceLine()
		ec.errSourceModule = s.getSourceModule()
	}

	// Apply per-instruction static base URI override from xml:base
	if s, ok := inst.(interface{ getStaticBaseURI() string }); ok {
		if sbu := s.getStaticBaseURI(); sbu != "" {
			savedBase := ec.staticBaseURIOverride

			ec.staticBaseURIOverride = sbu
			defer func() { ec.staticBaseURIOverride = savedBase }()
		}
	}

	// Apply per-instruction xpath-default-namespace if set
	if h, ok := inst.(xpathNSHolder); ok && h.xpathNSIsSet() {
		savedNS := ec.xpathDefaultNS
		savedHas := ec.hasXPathDefaultNS
		ec.xpathDefaultNS = h.getXPathDefaultNS()

		ec.hasXPathDefaultNS = true
		defer func() {
			ec.xpathDefaultNS = savedNS
			ec.hasXPathDefaultNS = savedHas
		}()
	}

	switch inst.(type) {
	case *applyTemplatesInst, *callTemplateInst, *nextMatchInst, *applyImportsInst:
		return ec.executeTemplateInstruction(ctx, inst)
	case *valueOfInst, *textInst, *literalTextInst, *elementInst, *attributeInst, *commentInst, *piInst, *copyInst, *copyOfInst, *literalResultElement, *resultDocumentInst, *xslSequenceInst, *wherePopulatedInst, *onEmptyInst, *onNonEmptyInst, *namespaceInst, *mapInst, *mapEntryInst, *documentInst:
		return ec.executeOutputInstruction(ctx, inst)
	default:
		return ec.executeControlInstruction(ctx, inst)
	}
}

func (ec *execContext) checkImplicitPrimaryOutput() error {
	if _, explicit := ec.usedResultURIs[""]; explicit && ec.primaryClaimedImplicitly {
		return dynamicError(errCodeXTDE1490, "principal output URI already used by xsl:result-document")
	}

	if ec.primaryClaimedImplicitly {
		return ec.checkResourceWrite(ec.canonicalPrimaryURI)
	}

	return nil
}

func (ec *execContext) executeTemplateInstruction(ctx context.Context, inst instruction) error {
	switch v := inst.(type) {
	case *applyTemplatesInst:
		return ec.execApplyTemplates(ctx, v)
	case *callTemplateInst:
		return ec.execCallTemplate(ctx, v)
	case *nextMatchInst:
		return ec.execNextMatch(ctx, v)
	case *applyImportsInst:
		return ec.execApplyImports(ctx, v)
	default:
		return dynamicError(errCodeXTDE0820, "unsupported instruction type %T", inst)
	}
}

func (ec *execContext) executeOutputInstruction(ctx context.Context, inst instruction) error {
	switch v := inst.(type) {
	case *valueOfInst:
		return ec.execValueOf(ctx, v)
	case *textInst:
		return ec.execText(ctx, v)
	case *literalTextInst:
		return ec.execLiteralText(ctx, v)
	case *elementInst:
		return ec.execElement(ctx, v)
	case *attributeInst:
		return ec.execAttribute(ctx, v)
	case *commentInst:
		return ec.execComment(ctx, v)
	case *piInst:
		return ec.execPI(ctx, v)
	case *copyInst:
		return ec.execCopy(ctx, v)
	case *copyOfInst:
		return ec.execCopyOf(ctx, v)
	case *literalResultElement:
		return ec.execLiteralResultElement(ctx, v)
	case *resultDocumentInst:
		return ec.execResultDocument(ctx, v)
	case *xslSequenceInst:
		return ec.execXSLSequence(ctx, v)
	case *wherePopulatedInst:
		return ec.execWherePopulated(ctx, v)
	case *onEmptyInst:
		return ec.execOnEmpty(ctx, v)
	case *onNonEmptyInst:
		return ec.execOnNonEmpty(ctx, v)
	case *namespaceInst:
		return ec.execNamespace(ctx, v)
	case *mapInst:
		return ec.execMap(ctx, v)
	case *mapEntryInst:
		return ec.execMapEntry(ctx, v)
	case *documentInst:
		return ec.execDocument(ctx, v)
	default:
		return dynamicError(errCodeXTDE0820, "unsupported instruction type %T", inst)
	}
}

func (ec *execContext) executeControlInstruction(ctx context.Context, inst instruction) error {
	switch v := inst.(type) {
	case *ifInst:
		return ec.execIf(ctx, v)
	case *chooseInst:
		return ec.execChoose(ctx, v)
	case *forEachInst:
		return ec.execForEach(ctx, v)
	case *variableInst:
		return ec.execVariable(ctx, v)
	case *paramInst:
		return ec.execParam(ctx, v)
	case *messageInst:
		return ec.execMessage(ctx, v)
	case *numberInst:
		return ec.execNumber(ctx, v)
	case *sequenceInst:
		if v.DefaultValidation != "" {
			saved := ec.defaultValidation
			ec.defaultValidation = v.DefaultValidation
			err := ec.executeSequenceConstructor(ctx, v.Body)
			ec.defaultValidation = saved

			return err
		}

		return ec.executeSequenceConstructor(ctx, v.Body)
	case *performSortInst:
		return ec.execPerformSort(ctx, v)
	case *tryCatchInst:
		return ec.execTryCatch(ctx, v)
	case *forEachGroupInst:
		return ec.execForEachGroup(ctx, v)
	case *sourceDocumentInst:
		return ec.execSourceDocument(ctx, v)
	case *iterateInst:
		return ec.execIterate(ctx, v)
	case *forkInst:
		return ec.execFork(ctx, v)
	case *breakInst:
		return ec.execBreak(ctx, v)
	case *nextIterationInst:
		return ec.execNextIteration(ctx, v)
	case *mergeInst:
		return ec.execMerge(ctx, v)
	case *analyzeStringInst:
		return ec.execAnalyzeString(ctx, v)
	case *assertInst:
		return ec.execAssert(ctx, v)
	case *evaluateInst:
		return ec.execEvaluate(ctx, v)
	case *fallbackInst:
		return ec.execFallback(ctx, v)
	case *collationScopeInst:
		saved := ec.defaultCollation
		ec.defaultCollation = v.DefaultCollation
		err := ec.executeInstruction(ctx, v.Inner)
		ec.defaultCollation = saved

		return err
	default:
		return dynamicError(errCodeXTDE0820, "unsupported instruction type %T", inst)
	}
}

// execFallback executes a forwards-compatible unknown instruction.
// If fallback instructions are present, they are executed; otherwise XTDE1450.
func (ec *execContext) execFallback(ctx context.Context, inst *fallbackInst) error {
	if !inst.HasFallback {
		if inst.ErrorCode != "" {
			return dynamicError(inst.ErrorCode, "%s is disabled and has no xsl:fallback", inst.Name)
		}

		return dynamicError(errCodeXTDE1450,
			"no xsl:fallback was found for forwards-compatible instruction %s", inst.Name)
	}

	return ec.executeSequenceConstructor(ctx, inst.Body)
}

// effectiveStripSpace returns the strip-space rules for the current execution
// scope. When executing code from a used package, the package's own rules
// are used (package-scoped isolation).
func (ec *execContext) effectiveStripSpace() []nameTest {
	if ec.currentPackage != nil && ec.currentPackage != ec.stylesheet {
		return ec.currentPackage.stripSpace
	}

	return ec.stylesheet.stripSpace
}

// effectivePreserveSpace returns the preserve-space rules for the current
// execution scope.
func (ec *execContext) effectivePreserveSpace() []nameTest {
	if ec.currentPackage != nil && ec.currentPackage != ec.stylesheet {
		return ec.currentPackage.preserveSpace
	}

	return ec.stylesheet.preserveSpace
}

// docCacheKey returns a package-scoped key for document caching. When
// executing in a used package with different strip-space rules, the key
// includes the package pointer so each package gets its own stripped copy.
func (ec *execContext) docCacheKey(uri string) string {
	if ec.currentPackage != nil && ec.currentPackage != ec.stylesheet {
		return fmt.Sprintf("%s@%p", uri, ec.currentPackage)
	}

	return uri
}

func isIDType(ann string) bool {
	return ann == "xs:ID"
}

// isAdaptiveStandaloneMarkupNode reports whether node can remain in a
// declaration-free adaptive markup-only document.
func isAdaptiveStandaloneMarkupNode(node xdm.Node) bool {
	switch node.Type() {
	case xdm.CommentNode, xdm.ProcessingInstructionNode:
		return true
	default:
		return false
	}
}

// mapIdentity returns a stable identity value for a map so the cached
// evaluators can be invalidated when an input map is replaced (for example
// when the active pattern's lexical namespace snapshot changes). A nil map
// yields 0; two non-nil maps share an identity iff they are the same
// underlying map. reflect is used because Go offers no other way to read a
// map's identity; the value never leaves this function.
func mapIdentity[M ~map[K]V, K comparable, V any](m M) uintptr {
	if m == nil {
		return 0
	}

	return reflect.ValueOf(m).Pointer()
}

func normalizeNode(node xdm.Node) xdm.Node {
	if xdm.IsNilNode(node) {
		return nil
	}

	return node
}

// varScope is a variable scope chain.
type varScope struct {
	vars           map[string]xdm.Sequence
	deferredErrors map[string]error // errors deferred until variable is actually used
	parent         *varScope
}

func (vs *varScope) lookup(name string) (xdm.Sequence, bool) {
	for s := vs; s != nil; s = s.parent {
		if v, ok := s.vars[name]; ok {
			return v, true
		}
	}

	return nil, false
}

// lookupDeferred returns a deferred error for a variable, if one exists.
func (vs *varScope) lookupDeferred(name string) error {
	for s := vs; s != nil; s = s.parent {
		if s.deferredErrors != nil {
			if err, ok := s.deferredErrors[name]; ok {
				return err
			}
		}
	}

	return nil
}

type executionCollectionResolver struct {
	base xpath.CollectionResolver
	ec   *execContext
}

func (r executionCollectionResolver) ResolveCollection(ctx context.Context, uri string) (xdm.Sequence, error) {
	key := r.ec.docCacheKey(uri)
	if seq, found := r.ec.collectionCache[key]; found {
		return seq, nil
	}

	seq, err := r.base.ResolveCollection(ctx, uri)
	if err != nil {
		return nil, err
	}

	out := make(xdm.ItemSlice, 0, xdm.SequenceLen(seq))
	for item := range xdm.SequenceItems(seq) {
		ni, ok := item.(xdm.NodeItem)
		if !ok {
			out = append(out, item)
			continue
		}

		node, err := r.prepareNode(ctx, ni.Node)
		if err != nil {
			return nil, err
		}

		if node != nil {
			ni.Node = node
			out = append(out, ni)
		}
	}

	r.ec.collectionCache[key] = out

	return out, nil
}

func (r executionCollectionResolver) prepareNode(ctx context.Context, node xdm.Node) (xdm.Node, error) {
	if err := xpath.Charge(ctx, 1); err != nil {
		return nil, err
	}

	prepared, err := r.ec.prepareInputNode(ctx, node)
	if err != nil || prepared == nil {
		return prepared, err
	}

	node = prepared

	if doc, ok := xdm.DocumentRoot(node).(*xdm.Document); ok && !doc.HasProperty(xdm.DocInternal) && doc.URL() != "" {
		cacheKey := r.ec.docCacheKey(doc.URL())
		if previous, found := r.ec.docCache[cacheKey]; found && previous != doc {
			return nil, &xdm.Error{Code: "FODC0003", Message: "collection supplied conflicting document identities for " + doc.URL()}
		}

		r.ec.docCache[cacheKey] = doc
	}

	return node, nil
}

func (r executionCollectionResolver) ResolveURICollection(ctx context.Context, uri string) ([]string, error) {
	key := r.ec.docCacheKey(uri)
	if values, found := r.ec.uriCollectionCache[key]; found {
		return values, nil
	}

	values, err := r.base.ResolveURICollection(ctx, uri)
	if err != nil {
		return nil, err
	}

	r.ec.uriCollectionCache[key] = values

	return values, nil
}
