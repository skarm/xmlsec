// Derived from lestrrat-go/helium at 7362c0a70122a757780f4d0b545a9b370dead6ab.
// Copyright (c) 2015 lestrrat. MIT License; see licenses/MIT-helium.txt at the repository root.

package xslt

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"strconv"
	"strings"

	"github.com/skarm/xmlsec/internal/lexicon"
	"github.com/skarm/xmlsec/transform/internal/xdm"
	"github.com/skarm/xmlsec/transform/internal/xpath"
)

type xslMultiArityFunc struct {
	variants []*xslUserFunc
	minArity int
	maxArity int
}

func (f *xslMultiArityFunc) MinArity() int { return f.minArity }

func (f *xslMultiArityFunc) MaxArity() int { return f.maxArity }

func (f *xslMultiArityFunc) AcceptsArity(arity int) bool { return f.findVariant(arity) != nil }

// DynamicRefSnapshot selects and captures only the requested overload.
func (f *xslMultiArityFunc) DynamicRefSnapshot(ctx context.Context, arity int) (xdm.FunctionItem, bool) {
	if variant := f.findVariant(arity); variant != nil {
		return variant.DynamicRefSnapshot(ctx, arity)
	}

	return xdm.FunctionItem{}, false
}

func (f *xslMultiArityFunc) Call(ctx context.Context, args []xdm.Sequence) (xdm.Sequence, error) {
	for _, v := range f.variants {
		if len(args) == len(v.def.Params) {
			return v.Call(ctx, args)
		}
	}

	return nil, fmt.Errorf("xpath: arity mismatch: no overload accepts %d arguments", len(args))
}

func (f *xslMultiArityFunc) FuncParamTypesForArity(arity int) []xdm.SequenceType {
	if v := f.findVariant(arity); v != nil {
		return v.FuncParamTypes()
	}

	return nil
}

func (f *xslMultiArityFunc) FuncReturnTypeForArity(arity int) *xdm.SequenceType {
	if v := f.findVariant(arity); v != nil {
		return v.FuncReturnType()
	}

	return nil
}

func (f *xslMultiArityFunc) findVariant(arity int) *xslUserFunc {
	for _, v := range f.variants {
		if len(v.def.Params) == arity {
			return v
		}
	}

	return nil
}

func (f *xslMultiArityFunc) addVariant(v *xslUserFunc) {
	f.variants = append(f.variants, v)

	arity := len(v.def.Params)
	if arity < f.minArity {
		f.minArity = arity
	}

	if arity > f.maxArity {
		f.maxArity = arity
	}
}

// xslUserFunc wraps an xsl:function for use as an xpath.Function.
type xslUserFunc struct {
	def *xslFunction
	ec  *execContext
}

func (f *xslUserFunc) MinArity() int { return len(f.def.Params) }

func (f *xslUserFunc) MaxArity() int { return len(f.def.Params) }

// DynamicRefSnapshot retains the lexical environment, without invocation caches
// or the XPath caller's variable bindings and context chain.
func (f *xslUserFunc) DynamicRefSnapshot(_ context.Context, arity int) (xdm.FunctionItem, bool) {
	if arity != len(f.def.Params) {
		return xdm.FunctionItem{}, false
	}

	fn := &xslUserFunc{def: f.def, ec: f.ec.captureFunctionContext()}

	return xpath.NewFunctionReference(f.def.Name, arity, fn), true
}

// FuncParamTypes returns the parameter types prepareCall parsed at compile
// time. Callers share the slice and must not modify it.
func (f *xslUserFunc) FuncParamTypes() []xdm.SequenceType {
	// The XSLT 2.0 call boundary performs conversion itself so that a mismatch
	// raises XTTE0790. XPath's generic precheck would mask it with XPTY0004.
	if f.ec.stylesheet.processorLanguage() == 20 {
		return nil
	}

	return f.def.paramTypes
}

// FuncReturnType returns the return type prepareCall parsed at compile time.
func (f *xslUserFunc) FuncReturnType() *xdm.SequenceType { return f.def.returnType }

func (f *xslUserFunc) Call(ctx context.Context, args []xdm.Sequence) (xdm.Sequence, error) {
	// The body has its own XSLT context. It clears inherited host state below,
	// and its instructions may establish fresh groups, regex matches and merges.
	ctx = xpath.WithoutDynamicCall(ctx)

	if f.def.Visibility == visAbstract {
		return nil, dynamicError(errCodeXTDE3052, "abstract function %s#%d was invoked without an implementation", f.def.Name.Name, len(f.def.Params))
	}

	ec, err := functionExecution(ctx, f.ec)
	if err != nil {
		return nil, err
	}

	ctx = withExecContext(ctx, ec)

	cacheKey, cacheable := ec.functionCacheKey(f.def, args)
	if cacheable {
		if result, ok := ec.functionResultCache[cacheKey]; ok {
			return cloneXPathSequence(result), nil
		}
	}

	// Recursion depth check
	ec.depth++
	if ec.depth > xpath.DepthLimit(ctx, maxRecursionDepth) {
		ec.depth--
		return nil, fmt.Errorf("xsl:function %s: %w", f.def.Name.Name, xpath.ErrRecursionLimit)
	}
	defer func() { ec.depth-- }()

	// If the function belongs to a package, switch function scope.
	// Override functions always run in the main stylesheet context
	// (currentPackage=nil) because their body is defined in the using
	// stylesheet and may reference functions from that scope.
	savedFnsNS := ec.cachedFnsNS

	savedPackage := ec.currentPackage
	callIsOverride(f, ec)

	// Save and restore execution state.
	// xsl:function creates a new scope — tunnel params and current mode
	// are NOT inherited (XSLT 2.0 erratum XT.E19).
	savedContext := ec.contextNode
	savedCurrent := ec.currentNode
	savedItem := ec.contextItem
	savedPos := ec.position
	savedSize := ec.size
	savedTunnel := ec.tunnelParams
	savedMode, savedModePackage := ec.currentMode, ec.currentModePackage
	savedGroups := ec.regexGroups
	savedInMerge := ec.inMergeAction
	savedGroup, savedKey := ec.currentGroup, ec.currentGroupKey
	savedInGroup, savedHasKey := ec.inGroupContext, ec.groupHasKey
	savedOutputURI := ec.currentOutputURI
	savedLocals := ec.localVars
	savedTemplate := ec.currentTemplate
	ec.setCurrentTemplate(nil)
	ec.localVars = nil
	ec.localVarsVer++
	ec.contextNode = nil
	ec.currentNode = nil
	ec.contextItem = nil
	ec.currentGroup, ec.currentGroupKey = nil, nil
	ec.inGroupContext, ec.groupHasKey = false, false
	ec.currentOutputURI = ""
	ec.tunnelParams = nil
	ec.currentMode, ec.currentModePackage = "", ec.effectiveStylesheet()
	ec.regexGroups = nil // regex-group() returns empty inside xsl:function

	ec.inMergeAction = false // XTDE3480/XTDE3510: merge context not available in functions
	defer func() {
		ec.contextNode = savedContext
		ec.currentNode = savedCurrent
		ec.contextItem = savedItem
		ec.position = savedPos
		ec.size = savedSize
		ec.tunnelParams = savedTunnel
		ec.currentMode, ec.currentModePackage = savedMode, savedModePackage
		ec.regexGroups = savedGroups
		ec.inMergeAction = savedInMerge
		ec.currentGroup, ec.currentGroupKey = savedGroup, savedKey
		ec.inGroupContext, ec.groupHasKey = savedInGroup, savedHasKey
		ec.currentOutputURI = savedOutputURI
		ec.localVars = savedLocals
		ec.localVarsVer++
		ec.setCurrentTemplate(savedTemplate)
		ec.cachedFnsNS = savedFnsNS
		ec.currentPackage = savedPackage
	}()

	// Track the original function for xsl:original() support.
	// Stored on execContext so FunctionResolver can find it without
	// polluting fnsNS (which would make it visible to function-lookup).
	savedOriginalFunc := ec.originalFunc
	if f.def.OriginalFunc != nil {
		ec.originalFunc = &xslUserFunc{def: f.def.OriginalFunc, ec: ec}
	}
	defer func() { ec.originalFunc = savedOriginalFunc }()

	// Push new variable scope for parameters
	ec.pushVarScope()
	defer ec.popVarScope()

	// Bind parameters with XPath function conversion.
	if err := callParams(ctx, f, args, ec); err != nil {
		return nil, err
	}

	// Execute the function body, collecting result into a temporary document.
	// For functions returning atomic types, use captureItems mode so that
	// attribute nodes returned by xsl:sequence are preserved directly
	// (writing them to a DOM tree loses them as attributes of the wrapper).
	tmpDoc, tmpRoot, err := ec.functionOutputRoot(f.def)
	if err != nil {
		return nil, err
	}

	frame := &outputFrame{current: tmpRoot, doc: tmpDoc, captureItems: true, sequenceMode: true}
	ec.outputStack = append(ec.outputStack, frame)

	ec.temporaryOutputDepth++
	defer func() {
		ec.temporaryOutputDepth--
		ec.outputStack = ec.outputStack[:len(ec.outputStack)-1]
	}()

	for _, inst := range f.def.Body {
		if err := ec.executeInstruction(ctx, inst); err != nil {
			return nil, err
		}
	}

	if f.def.selectOnly && tmpRoot.FirstChild() != nil {
		// prepareCall rules this out. Should a node ever land on the shared
		// wrapper, detach it, so no other call sharing the wrapper sees it,
		// and return it ahead of the captured items.
		frame.pendingItems = append(ec.collectNodeChildren(tmpRoot), frame.pendingItems...)
	}

	// Return captured items if any, otherwise collect from DOM. Declared atomic
	// results are atomized by function conversion, preserving conversion errors.
	// Per XSLT 3.0 §5.7.2, adjacent text nodes in a sequence are NOT
	// merged (merging only applies to tree construction). Zero-length
	// text nodes are preserved as distinct items.
	var result xdm.ItemSlice

	callPendingItems(frame, tmpRoot, &result, ec)

	// Strip DOE marker PIs — DOE is ignored in function return values
	// (temporary output state per XSLT 3.0 §20.1).
	stripped, _ := stripDOEMarkers(result)
	result = xdm.Materialize(stripped)

	// Type check against the declared as type
	if f.def.As != "" {
		checked, err := ec.convertFunctionArgument(ctx, result, *f.def.returnType)
		if err != nil {
			if failure := preserveControlFailure(ctx, err); failure != nil {
				return nil, failure
			}

			return nil, dynamicError(errCodeXTTE0780, "function %s: %s", f.def.Name.Name, err)
		}

		result = xdm.Materialize(checked)
	}

	if cacheable && f.def.cacheResult(result) {
		ec.functionResultCache[cacheKey] = cloneXPathSequence(result)
	}

	return result, nil
}

func cloneXPathSequence(seq xdm.Sequence) xdm.Sequence {
	if seq == nil {
		return nil
	}

	return append(xdm.ItemSlice(nil), xdm.Materialize(seq)...)
}

func callParams(ctx context.Context, f *xslUserFunc, args []xdm.Sequence, ec *execContext) error {
	for i, param := range f.def.Params {
		if i < len(args) {
			val := args[i]
			if param.As != "" {
				checked, err := ec.convertFunctionArgument(ctx, val, f.def.paramTypes[i])
				if err != nil {
					return err
				}

				val = checked
			}

			ec.setVar(param.Name, val)
		} else if param.Select != nil {
			result, err := ec.evalXPath(ctx, param.Select, ec.contextNode)
			if err != nil {
				return err
			}

			ec.setVar(param.Name, result.Sequence())
		} else {
			ec.setVar(param.Name, xdm.EmptySequence())
		}
	}

	return nil
}

func (ec *execContext) SnapshotVariableResolver() xpath.VariableResolver {
	return &globalVariableResolver{lexical: ec.captureFunctionContext(), owner: ec.effectiveStylesheet(), original: ec.originalGlobal}
}

func (ec *execContext) convertSequenceType(ctx context.Context, value xdm.Sequence, st xdm.SequenceType) (xdm.Sequence, error) {
	eval, _ := ec.baseXPathEvaluator()
	if ec.typeAnnotations != nil {
		eval = eval.TypeAnnotations(ec.typeAnnotations)
	}

	return eval.ConvertToSequenceType(ec.xpathContext(ctx), value, st, ec.stylesheet.processorLanguage())
}

func (ec *execContext) convertFunctionArgument(ctx context.Context, value xdm.Sequence, st xdm.SequenceType) (xdm.Sequence, error) {
	converted, err := ec.convertSequenceType(ctx, value, st)
	if err != nil && ec.stylesheet.processorLanguage() == 20 {
		var detail *xdm.Error
		if errors.As(err, &detail) && detail.Code == lexicon.ErrXPTY0004 {
			return nil, dynamicError(errCodeXTTE0790, "function argument: %s", detail.Message)
		}
	}

	return converted, err
}

func (ec *execContext) captureFunctionContext() *execContext {
	if ec.functionLexical == nil {
		lexical := ec.functionInvocation(context.Background())
		// The producing transformation can finish lazy globals after a reference
		// is created. Retain these maps, which are frozen when results are
		// published, rather than retaining the mutable execution context itself.
		lexical.globalVars = ec.globalVars
		lexical.globalVarDefs = ec.globalVarDefs
		lexical.globalParamDefs = ec.globalParamDefs
		lexical.globalValueCache = ec.globalValueCache

		if config := lexical.transformConfig; config != nil {
			config.initialMatchSelection, config.initialFunctionParams = nil, nil
			config.sequenceParams, config.initialModeParams, config.initialModeTunnel = nil, nil, nil
			config.initialTemplateParams, config.initialTemplateTunnel = nil, nil
			config.rawResultHandler, config.primaryItemsHandler = nil, nil
			config.resultDocHandler, config.annotationHandler = nil, nil
			config.msgHandler = nil
		}

		lexical.msgHandler = nil

		lexical.functionLexical = lexical
		ec.functionLexical = lexical
	}

	return ec.functionLexical
}

// functionOutputRoot returns the document and wrapper element a call of def
// writes its body's output into.
//
// A select-only body (see prepareCall) never appends to the wrapper, so every
// such call on ec shares one scratch wrapper, nested and recursive calls
// included: each call keeps its items in its own outputFrame, and the wrapper
// stays childless. Any other body gets a fresh document. That document is not
// freed after the call: the nodes the body builds are allocated from it and
// are returned to the caller, and ec keeps per-node state (nsFixupAllowed,
// typeAnnotations, ...) keyed by node identity, which a recycled slab would
// alias.
func (ec *execContext) functionOutputRoot(def *xslFunction) (*xdm.Document, *xdm.Element, error) {
	if def.selectOnly && ec.fnScratchRoot != nil {
		return ec.fnScratchDoc, ec.fnScratchRoot, nil
	}

	doc := xdm.NewDefaultDocument()

	root, err := doc.CreateElement("_xsl_fn_result")
	if err != nil {
		return nil, nil, err
	}

	_ = doc.SetDocumentElement(root)
	if def.selectOnly {
		ec.fnScratchDoc = doc
		ec.fnScratchRoot = root
	}

	return doc, root, nil
}

// functionInvocation retains lexical globals but starts all mutable execution
// caches, scopes and output documents anew when a function escapes to XPath.
func (ec *execContext) functionInvocation(ctx context.Context) *execContext {
	var cfg *transformConfig

	if ec.transformConfig != nil {
		config := *ec.transformConfig
		config.rawCapturedItems, config.primaryItems = nil, nil
		config.valueResults = make(map[string]ValueResult)
		cfg = &config
	}

	local := newTransformExecContext(ctx, ec.sourceDoc, ec.stylesheet, cfg)
	local.functionLexical = ec.functionLexical
	local.execution = ec.execution
	local.currentTime = ec.currentTime
	local.dynamicProperties = ec.dynamicProperties

	if ec.globalVars != nil {
		local.globalVars = maps.Clone(ec.globalVars)
	}

	local.globalVarDefs = maps.Clone(ec.globalVarDefs)
	local.globalParamDefs = maps.Clone(ec.globalParamDefs)
	local.globalEvaluating = make(map[globalBinding]struct{})
	local.globalValueCache = maps.Clone(ec.globalValueCache)
	local.globalContextItem, local.globalContextAbsent = ec.globalContextItem, ec.globalContextAbsent
	local.currentPackage = ec.currentPackage
	local.defaultCollation, local.defaultValidation = ec.defaultCollation, ec.defaultValidation
	local.xpathDefaultNS, local.hasXPathDefaultNS = ec.xpathDefaultNS, ec.hasXPathDefaultNS
	local.nsOverride = ec.nsOverride
	local.typeAnnotations = maps.Clone(ec.typeAnnotations)
	local.preservedIDAnnotations = maps.Clone(ec.preservedIDAnnotations)
	local.nilledElements = maps.Clone(ec.nilledElements)
	local.validatedDocs = maps.Clone(ec.validatedDocs)
	// Input tree copies are immutable lexical context, like captured globals.
	// Clone the indexes so later invocations can add their own prepared trees.
	local.inputTrees = maps.Clone(ec.inputTrees)
	local.inputOriginalNodes = maps.Clone(ec.inputOriginalNodes)
	local.cacheInputDocument(ec.sourceDoc)

	if item, ok := ec.globalContextItem.(xdm.NodeItem); ok {
		local.cacheInputDocument(item.Node)
	}

	return local
}

func (ec *execContext) functionCacheKey(def *xslFunction, args []xdm.Sequence) (string, bool) {
	if ec == nil || def == nil {
		return "", false
	}
	// Proactive functions (including the default) retain fresh node identity.
	// A cache hint does not change their evaluation contract.
	if def.NewEachTime != lexicon.ValueNo && !(def.Cache && (def.NewEachTime == nameMaybe || proactiveSelfBinding(def))) {
		return "", false
	}

	var b strings.Builder
	if def.OwnerPackage != nil {
		fmt.Fprintf(&b, "pkg:%p|", def.OwnerPackage)
	}

	b.WriteString(def.Name.URI)
	b.WriteByte('|')
	b.WriteString(def.Name.Name)
	b.WriteByte('#')
	b.WriteString(strconv.Itoa(len(args)))

	for _, arg := range args {
		b.WriteByte('|')

		if !ec.writeFunctionCacheSequence(&b, arg) {
			return "", false
		}
	}

	return b.String(), true
}

func (ec *execContext) writeFunctionCacheSequence(b *strings.Builder, seq xdm.Sequence) bool {
	b.WriteByte('[')
	b.WriteString(strconv.Itoa(xdm.SequenceLen(seq)))

	for item := range xdm.SequenceItems(seq) {
		b.WriteByte(';')

		if !ec.writeFunctionCacheItem(b, item) {
			return false
		}
	}

	b.WriteByte(']')

	return true
}

func (ec *execContext) writeFunctionCacheItem(b *strings.Builder, item xdm.Item) bool {
	switch v := item.(type) {
	case xdm.AtomicValue:
		s, err := xpath.AtomicToString(v)
		if err != nil {
			return false
		}

		b.WriteString("a:")
		b.WriteString(v.TypeName)
		b.WriteByte('=')
		// AtomicToString for QName returns prefix:local, which omits the
		// namespace URI. Two QNames can share a local name but differ in URI,
		// so we must include the URI in the cache key.
		if q, ok := v.Value.(xdm.QNameValue); ok {
			b.WriteString("{")
			b.WriteString(q.URI)
			b.WriteString("}")
			b.WriteString(q.Local)
		} else {
			b.WriteString(s)
		}

		return true
	case xdm.NodeItem:
		b.WriteString("n:")
		b.WriteString(strconv.FormatUint(ec.memoNodeID(v.Node), 10))

		if v.TypeAnnotation != "" {
			b.WriteByte('@')
			b.WriteString(v.TypeAnnotation)
		}

		if v.AtomizedType != "" {
			b.WriteByte('!')
			b.WriteString(v.AtomizedType)
		}

		return true
	case xdm.MapItem:
		b.WriteString("m{")

		for _, key := range v.Keys() {
			if !ec.writeFunctionCacheItem(b, key) {
				return false
			}

			b.WriteByte(':')

			val, _ := v.Get(key)
			if !ec.writeFunctionCacheSequence(b, val) {
				return false
			}

			b.WriteByte(',')
		}

		b.WriteByte('}')

		return true
	case xdm.ArrayItem:
		b.WriteString("r[")

		for _, member := range v.Members() {
			if !ec.writeFunctionCacheSequence(b, member) {
				return false
			}

			b.WriteByte(',')
		}

		b.WriteByte(']')

		return true
	case xdm.FunctionItem:
		return false
	default:
		return false
	}
}

func (ec *execContext) memoNodeID(node xdm.Node) uint64 {
	if node == nil {
		return 0
	}

	if ec.nodeMemoIDs == nil {
		ec.nodeMemoIDs = make(map[xdm.Node]uint64)
	}

	if id, ok := ec.nodeMemoIDs[node]; ok {
		return id
	}

	ec.nextNodeMemoID++
	ec.nodeMemoIDs[node] = ec.nextNodeMemoID

	return ec.nextNodeMemoID
}

func (ec *execContext) collectNodeChildren(node xdm.Node) xdm.ItemSlice {
	var children []xdm.Node
	for child := range xdm.Children(node) {
		children = append(children, child)
	}

	if len(children) == 0 {
		return nil
	}

	seq := make(xdm.ItemSlice, 0, len(children))
	for _, child := range children {
		xdm.UnlinkNode(child.(xdm.MutableNode)) //nolint:forcetypeassert // Tree child nodes implement MutableNode.
		seq = append(seq, xdm.NodeItem{Node: child})
	}

	return seq
}

func callIsOverride(f *xslUserFunc, ec *execContext) {
	if f.def.OwnerPackage != ec.currentPackage {
		ec.cachedFnsNS = nil
		ec.currentPackage = f.def.OwnerPackage
	}
}

func callPendingItems(frame *outputFrame, tmpRoot *xdm.Element, result *xdm.ItemSlice, ec *execContext) {
	if len(frame.pendingItems) == 0 {
		*result = ec.collectNodeChildren(tmpRoot)
		return
	}

	var seq xdm.ItemSlice
	for child := range xdm.Children(tmpRoot) {
		seq = append(seq, xdm.NodeItem{Node: child})
	}

	seq = append(seq, frame.pendingItems...)
	*result = seq
}

type globalVariableResolver struct {
	lexical  *execContext
	owner    *Stylesheet
	original globalBinding
}

func (r *globalVariableResolver) ResolveVariable(ctx context.Context, name string) (xdm.Sequence, bool, error) {
	ec, err := functionExecution(ctx, r.lexical)
	if err != nil {
		return nil, false, err
	}
	defer ec.pushPackage(r.owner)()

	locals, original := ec.localVars, ec.originalGlobal
	ec.localVars, ec.originalGlobal = nil, r.original

	ec.localVarsVer++
	defer func() { ec.localVars, ec.originalGlobal = locals, original; ec.localVarsVer++ }()

	return ec.ResolveVariable(withExecContext(ctx, ec), name)
}

// Returned functions keep the producing transformation's global bindings,
// even when called by another execution of the same compiled stylesheet.
func functionExecution(ctx context.Context, lexical *execContext) (*execContext, error) {
	caller := getExecContext(ctx)
	if caller != nil && caller.execution != nil && caller.execution == lexical.execution {
		return caller, nil
	}

	if lexical.functionLexical != nil {
		lexical = lexical.functionLexical
	}

	value := xpath.InvocationState(ctx, lexical, func() any {
		local := lexical.functionInvocation(ctx)
		if caller != nil {
			local.msgHandler = caller.msgHandler

			local.resourceOwner = caller
			if caller.resourceOwner != nil {
				local.resourceOwner = caller.resourceOwner
			}
		}

		return local
	})

	ec, ok := value.(*execContext)
	if !ok {
		return nil, dynamicError(errCodeXTDE0820, "invalid XSLT function invocation state")
	}

	return ec, nil
}

// A separately retrieved original function can still bind recursive calls to
// an override. Its arithmetic body alone cannot establish that target's effects.
func proactiveSelfBinding(def *xslFunction) bool {
	if !def.cacheAtomicSelf {
		return false
	}

	if def.OwnerPackage == nil {
		return true
	}

	target := def.OwnerPackage.functions[funcKey{Name: def.Name, Arity: len(def.Params)}]
	if target == nil || target.OwnerPackage != def.OwnerPackage || len(target.Body) != len(def.Body) {
		return false
	}

	return len(def.Body) == 0 || &target.Body[0] == &def.Body[0]
}

// prepareCompiledFunction recognizes a narrow scalar memoization case. A cache
// hint alone cannot remove proactive node construction, messages or callbacks.
func (c *compiler) prepareCompiledFunction(ctx context.Context, fn *xslFunction, elem *xdm.Element) error {
	defaultNS, _ := c.declarationDefaultNamespace(elem)
	if err := fn.prepareCall(ctx, inScopeNamespaces(elem), defaultNS); err != nil {
		return err
	}

	if !fn.Cache || !fn.selectOnly {
		return nil
	}

	namespaces := inScopeNamespaces(elem)
	for child := range xdm.ChildElements(elem) {
		if child.URI() != lexicon.NamespaceXSLT || child.LocalName() != lexicon.XSLTElementSequence {
			continue
		}

		for prefix, uri := range inScopeNamespaces(child) {
			if namespaces[prefix] != uri {
				return nil
			}
		}
	}

	for _, inst := range fn.Body {
		sequence, ok := inst.(*xslSequenceInst)
		if !ok || sequence.Select == nil {
			return nil
		}

		analysis, err := sequence.Select.Analyze(ctx, namespaces)
		if err != nil {
			return err
		}

		if analysis.DynamicCalls || analysis.ContextItem {
			return nil
		}

		for _, reference := range analysis.Functions {
			if reference.Name != fn.Name || reference.Arity != len(fn.Params) {
				return nil
			}
		}
	}

	fn.cacheAtomicSelf = true

	return nil
}

func (fn *xslFunction) cacheResult(result xdm.Sequence) bool {
	if fn.NewEachTime == lexicon.ValueNo || fn.NewEachTime == nameMaybe {
		return true
	}

	for item := range xdm.SequenceItems(result) {
		if _, ok := item.(xdm.AtomicValue); !ok {
			return false
		}
	}

	return fn.cacheAtomicSelf
}

// prepareCall derives the data every call needs from the compiled function, so
// that a call parses no sequence type and inspects no body instruction. It runs
// once, when the function is compiled.
func (fn *xslFunction) prepareCall(ctx context.Context, namespaces map[string]string, defaultNS string) error {
	fn.paramTypes = make([]xdm.SequenceType, 0, len(fn.Params))

	for _, p := range fn.Params {
		as := p.As
		if as == "" {
			as = "item()*"
		}

		st, err := xpath.ParseSequenceType(as)
		if err != nil {
			return staticError(lexicon.ErrXPST0003, "invalid function parameter type %q: %s", as, err)
		}

		bound, err := xpath.BindSequenceType(ctx, st, p.TypeNamespaces, p.XPathDefaultNS)
		if err != nil {
			return err
		}

		fn.paramTypes = append(fn.paramTypes, bound)
	}

	fn.returnType = nil
	if fn.As != "" {
		st, err := xpath.ParseSequenceType(fn.As)
		if err != nil {
			return staticError(lexicon.ErrXPST0003, "invalid function return type %q: %s", fn.As, err)
		}

		bound, err := xpath.BindSequenceType(ctx, st, namespaces, defaultNS)
		if err != nil {
			return err
		}

		fn.returnType = &bound
	}

	// A body made only of select-form xsl:sequence instructions never adds a
	// node to the call's output wrapper: execXSLSequence captures each item
	// into the frame's pendingItems because the frame captures items and its
	// insertion point is the wrapper itself. Every other instruction (an LRE,
	// xsl:element, a contained-constructor xsl:sequence, xsl:on-empty,
	// xsl:try, ...) may build nodes under the wrapper. An empty body writes
	// nothing either.
	fn.selectOnly = true
	for _, inst := range fn.Body {
		if _, ok := inst.(*xslSequenceInst); !ok {
			fn.selectOnly = false
			break
		}
	}

	return nil
}
