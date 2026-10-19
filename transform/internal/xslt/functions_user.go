// Derived from lestrrat-go/helium at 7362c0a70122a757780f4d0b545a9b370dead6ab.
// Copyright (c) 2015 lestrrat. MIT License; see licenses/MIT-helium.txt at the repository root.

package xslt

import (
	"context"
	"fmt"
	"maps"
	"strconv"
	"strings"

	"github.com/skarm/xmlsec/transform/internal/xdm"
	"github.com/skarm/xmlsec/transform/internal/xdm/lexicon"
	"github.com/skarm/xmlsec/transform/internal/xpath"
)

type xslMultiArityFunc struct {
	variants []*xslUserFunc
	minArity int
	maxArity int
}

func (f *xslMultiArityFunc) MinArity() int { return f.minArity }

func (f *xslMultiArityFunc) MaxArity() int { return f.maxArity }

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
func (f *xslUserFunc) FuncParamTypes() []xdm.SequenceType { return f.def.paramTypes }

// FuncReturnType returns the return type prepareCall parsed at compile time.
func (f *xslUserFunc) FuncReturnType() *xdm.SequenceType { return f.def.returnType }

func (f *xslUserFunc) Call(ctx context.Context, args []xdm.Sequence) (xdm.Sequence, error) {
	// Retrieve the XSLT exec context from the context.Context
	ec := getExecContext(ctx)
	if ec == nil {
		value := xpath.InvocationState(ctx, f.ec, func() any { return f.ec.functionInvocation(ctx) })

		var ok bool

		ec, ok = value.(*execContext)
		if !ok {
			return nil, dynamicError(errCodeXTDE0820, "invalid XSLT function invocation state")
		}

		ctx = context.WithValue(ctx, execContextKey{}, ec)
	}

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
		return nil, dynamicErrorCause(errCodeXTDE0820, xpath.ErrBudget, "recursion depth exceeded in xsl:function %s", f.def.Name.Name)
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
	savedPos := ec.position
	savedSize := ec.size
	savedTunnel := ec.tunnelParams
	savedMode := ec.currentMode
	savedGroups := ec.regexGroups
	savedInMerge := ec.inMergeAction
	ec.contextNode = nil
	ec.currentNode = nil
	ec.tunnelParams = nil
	ec.currentMode = ec.stylesheet.defaultMode
	ec.regexGroups = nil // regex-group() returns empty inside xsl:function

	ec.inMergeAction = false // XTDE3480/XTDE3510: merge context not available in functions
	defer func() {
		ec.contextNode = savedContext
		ec.currentNode = savedCurrent
		ec.position = savedPos
		ec.size = savedSize
		ec.tunnelParams = savedTunnel
		ec.currentMode = savedMode
		ec.regexGroups = savedGroups
		ec.inMergeAction = savedInMerge
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

	// Bind parameters with type checking/coercion (XTTE0790)
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

	atomicReturn := f.def.As != "" && isAtomicTypeName(f.def.As)
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

	// Return captured items if any, otherwise collect from DOM.
	// For atomic return types, atomize the captured items.
	// Per XSLT 3.0 §5.7.2, adjacent text nodes in a sequence are NOT
	// merged (merging only applies to tree construction). Zero-length
	// text nodes are preserved as distinct items.
	var result xdm.ItemSlice

	callPendingItems(frame, tmpRoot, atomicReturn, &result, ec)

	// Strip DOE marker PIs — DOE is ignored in function return values
	// (temporary output state per XSLT 3.0 §20.1).
	stripped, _ := stripDOEMarkers(result)
	result = xdm.Materialize(stripped)

	// Type check against the declared as type
	if f.def.As != "" {
		checked, err := checkSequenceType(ctx, result, f.def.returnCheckType, errCodeXTTE0780, "function "+f.def.Name.Name, ec)
		if err != nil {
			return nil, err
		}

		result = xdm.Materialize(checked)
	}

	if cacheable {
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

// isAtomicTypeName returns true if the given type name (from an as="" attribute)
// represents an atomic/simple type (not a node type or function type).
// Handles occurrence indicators (?, *, +) and xs: prefixed types.
func isAtomicTypeName(as string) bool {
	// Strip occurrence indicator
	name := strings.TrimRight(as, "?*+")
	name = strings.TrimSpace(name)
	// xs:string, xs:integer, xs:boolean, xs:double, etc.
	if strings.HasPrefix(name, "xs:") {
		return true
	}
	// unprefixed atomic types (rare but possible)
	switch name {
	case lexicon.TypeString, lexicon.TypeInteger, lexicon.TypeBoolean, lexicon.TypeDouble, lexicon.TypeFloat, nameDecimal,
		lexicon.TypeDate, nameDateTime, lexicon.TypeTime, lexicon.TypeDuration, lexicon.TypeAnyURI:
		return true
	}

	return false
}

// element-available(name) returns true if the named XSLT element is available.

func callParams(ctx context.Context, f *xslUserFunc, args []xdm.Sequence, ec *execContext) error {
	for i, param := range f.def.Params {
		if i < len(args) {
			val := args[i]
			if param.As != "" {
				st := f.def.paramCheckTypes[i]

				checked, err := checkSequenceType(ctx, val, st, errCodeXTTE0790, "param $"+param.Name, ec)
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

func callIsOverride(f *xslUserFunc, ec *execContext) {
	if f.def.IsOverride && ec.currentPackage != nil {
		ec.cachedFnsNS = nil
		ec.currentPackage = nil
	} else if f.def.OwnerPackage != nil && f.def.OwnerPackage != ec.currentPackage {
		ec.cachedFnsNS = nil
		ec.currentPackage = f.def.OwnerPackage
	}
}

func callPendingItems(frame *outputFrame, tmpRoot *xdm.Element, atomicReturn bool, result *xdm.ItemSlice, ec *execContext) {
	if len(frame.pendingItems) > 0 {
		if tmpRoot.FirstChild() != nil {
			var seq xdm.ItemSlice
			for child := range xdm.Children(tmpRoot) {
				seq = append(seq, xdm.NodeItem{Node: child})
			}

			seq = append(seq, frame.pendingItems...)
			if atomicReturn {
				(*result) = xdm.Materialize(atomizeSequence(seq))
			} else {
				(*result) = xdm.Materialize(seq)
			}
		} else if atomicReturn {
			(*result) = xdm.Materialize(atomizeSequence(frame.pendingItems))
		} else {
			(*result) = xdm.Materialize(frame.pendingItems)
		}
	} else {
		(*result) = ec.collectNodeChildren(tmpRoot)
		if atomicReturn {
			(*result) = xdm.Materialize(atomizeSequence((*result)))
		}
	}
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
		lexical.packageVarCache = ec.packageVarCache

		if config := lexical.transformConfig; config != nil {
			config.initialMatchSelection, config.initialFunctionParams = nil, nil
			config.sequenceParams, config.initialModeParams, config.initialModeTunnel = nil, nil, nil
			config.initialTemplateParams, config.initialTemplateTunnel = nil, nil
			config.rawResultHandler, config.primaryItemsHandler = nil, nil
			config.resultDocHandler, config.annotationHandler = nil, nil
		}

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

	if ec.globalVars != nil {
		local.globalVars = maps.Clone(ec.globalVars)
	}

	local.globalVarDefs = maps.Clone(ec.globalVarDefs)
	local.globalParamDefs = maps.Clone(ec.globalParamDefs)
	local.globalEvaluating = make(map[string]struct{})
	local.packageVarCache = maps.Clone(ec.packageVarCache)
	local.globalContextItem, local.globalContextAbsent = ec.globalContextItem, ec.globalContextAbsent
	local.currentPackage = ec.currentPackage
	local.defaultCollation, local.defaultValidation = ec.defaultCollation, ec.defaultValidation
	local.xpathDefaultNS, local.hasXPathDefaultNS = ec.xpathDefaultNS, ec.hasXPathDefaultNS
	local.nsOverride = ec.nsOverride
	local.typeAnnotations = maps.Clone(ec.typeAnnotations)
	local.preservedIDAnnotations = maps.Clone(ec.preservedIDAnnotations)
	local.nilledElements = maps.Clone(ec.nilledElements)
	local.validatedDocs = maps.Clone(ec.validatedDocs)

	return local
}

func (ec *execContext) functionCacheKey(def *xslFunction, args []xdm.Sequence) (string, bool) {
	if ec == nil || def == nil {
		return "", false
	}
	// Cache when cache="yes" or new-each-time="no" (deterministic function).
	if !def.Cache && def.NewEachTime != lexicon.ValueNo {
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
		xdm.UnlinkNode(child.(xdm.MutableNode)) //nolint:forcetypeassert
		seq = append(seq, xdm.NodeItem{Node: child})
	}

	return seq
}

// prepareCall derives the data every call needs from the compiled function, so
// that a call parses no sequence type and inspects no body instruction. It runs
// once, when the function is compiled.
func (fn *xslFunction) prepareCall() {
	fn.paramTypes = make([]xdm.SequenceType, 0, len(fn.Params))

	fn.paramCheckTypes = make([]sequenceType, len(fn.Params))
	for i, p := range fn.Params {
		if p.As != "" {
			fn.paramCheckTypes[i] = parseSequenceType(p.As)
		}

		if fn.paramTypes == nil {
			continue
		}

		as := p.As
		if as == "" {
			as = "item()*"
		}

		st, err := xpath.ParseSequenceType(as)
		if err != nil {
			fn.paramTypes = nil
			continue
		}

		fn.paramTypes = append(fn.paramTypes, st)
	}

	fn.returnType = nil
	if fn.As != "" {
		fn.returnCheckType = parseSequenceType(fn.As)
		if st, err := xpath.ParseSequenceType(fn.As); err == nil {
			fn.returnType = &st
		}
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
}
