// Derived from lestrrat-go/helium at 7362c0a70122a757780f4d0b545a9b370dead6ab.
// Copyright (c) 2015 lestrrat. MIT License; see licenses/MIT-helium.txt at the repository root.

package xslt

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"strings"

	"github.com/skarm/xmlsec/internal/lexicon"
	"github.com/skarm/xmlsec/transform/internal/xdm"
	"github.com/skarm/xmlsec/transform/internal/xpath"
)

type analyzeStringSource struct {
	text     string
	version2 bool
	present  bool
}

func (ec *execContext) execAnalyzeString(ctx context.Context, inst *analyzeStringInst) error {
	input, err := ec.analyzeStringInput(ctx, inst)
	if err != nil {
		return err
	}

	if !input.present {
		return nil
	}

	regex, err := inst.Regex.evaluate(ctx, ec.contextNode)
	if err != nil {
		return err
	}

	flags := ""
	if inst.Flags != nil {
		flags, err = inst.Flags.evaluate(ctx, ec.contextNode)
		if err != nil {
			return err
		}
	}

	// Version 2.0 restrictions
	if input.version2 {
		// XSLT 2.0: 'q' flag is not allowed (XTDE1145)
		if strings.ContainsRune(flags, 'q') {
			return dynamicError(errCodeXTDE1145, "xsl:analyze-string flag 'q' is not allowed in XSLT 2.0")
		}
		// XSLT 2.0: non-capturing groups (?:...) are not allowed (XTDE1140)
		if strings.Contains(regex, "(?:") {
			return dynamicError(errCodeXTDE1140, "non-capturing groups are not allowed in XSLT 2.0 regex")
		}
	}

	// Compile the regex using XPath regex semantics
	re, err := xpath.CompileRegexContext(ctx, regex, flags)
	if err != nil {
		if failure := preserveControlFailure(ctx, err); failure != nil {
			return failure
		}

		// Map XPath regex errors to XSLT error codes
		var detail *xdm.Error
		if errors.As(err, &detail) && detail.Code == "FORX0001" {
			return dynamicErrorCause(errCodeXTDE1145, err, "xsl:analyze-string invalid flags: %v", err)
		}

		return dynamicErrorCause(errCodeXTDE1140, err, "xsl:analyze-string invalid regex: %v", err)
	}

	if input.version2 {
		emptyMatch, err := re.MatchString(ctx, "")
		if err != nil {
			return err
		}

		if emptyMatch {
			return dynamicError(errCodeXTDE1150, "XSLT 2.0 analyze-string regular expression must not match an empty string")
		}
	}

	// XSLT 3.0 removed the XTDE1150 error for zero-length regex matches.
	// Zero-length matches are handled by advancing past each one to avoid
	// infinite loops (see below).
	// Bound the number of matches against the execution resource budget. An
	// empty- or near-empty-matching regex matches at every character boundary,
	// so an N-byte input yields ~N matches; accumulating every match (e.g. via
	// FindAllSubmatchIndex) would amplify a bounded input string into millions
	// of match/segment allocations and exhaust memory before a cancelled
	// context can intervene. The streamable paths enumerate one match at a time
	// and the per-resource byte cap (MaxResourceBytes; <0 selects unbounded)
	// caps how many they will surface; the default cap is far above any
	// legitimate match count. The shared pattern engine checks cancellation
	// and operation/storage limits throughout both streaming passes.
	maxMatches := -1
	if limit := resolveResourceLimit(ec.resourceLimit()); limit >= 0 {
		maxMatches = max(clampInt64ToInt(limit), 1)
	}

	// findLimit caps how many matches EachSubmatchIndex may produce. The callback
	// rejects once it observes match maxMatches+1, so the enumeration must be able
	// to surface that one extra match; passing maxMatches+1 lets the callback see
	// it. A non-positive maxMatches (unbounded cap) and an int overflow both fall
	// back to -1 (no enumeration limit).
	findLimit := -1

	if maxMatches >= 0 {
		if n := maxMatches + 1; n > 0 {
			findLimit = n
		}
	}

	if err := ctx.Err(); err != nil {
		return err
	}

	totalSegments, err := countAnalyzeStringSegments(ctx, re, input.text, maxMatches, findLimit)
	if err != nil {
		return err
	}

	return ec.executeAnalyzeStringSegments(ctx, inst, re, input.text, findLimit, totalSegments)
}

func (ec *execContext) analyzeStringInput(ctx context.Context, inst *analyzeStringInst) (analyzeStringSource, error) {
	result, err := ec.evalXPath(ctx, inst.Select, ec.contextNode)
	if err != nil {
		return analyzeStringSource{}, err
	}

	seq := result.Sequence()

	// The select expression must produce a single xs:string value.
	// A sequence of more than one item, or a non-string item, is XPTY0004.
	isV2 := ec.stylesheet.processorLanguage() < 30
	if seq == nil || xdm.SequenceLen(seq) == 0 {
		if isV2 {
			// XSLT 2.0: empty sequence is XPTY0004
			return analyzeStringSource{}, dynamicError(lexicon.ErrXPTY0004, "xsl:analyze-string select must be a single xs:string, got empty sequence")
		}
		// XSLT 3.0: empty sequence treated as ""
		return analyzeStringSource{}, nil
	}

	if xdm.SequenceLen(seq) > 1 {
		return analyzeStringSource{}, dynamicError(lexicon.ErrXPTY0004, "xsl:analyze-string select must be a single xs:string, got sequence of %d items", xdm.SequenceLen(seq))
	}

	av, err := xpath.AtomizeItem(seq.Get(0))
	if err != nil {
		return analyzeStringSource{}, dynamicError(lexicon.ErrXPTY0004, "xsl:analyze-string select must be xs:string: %v", err)
	}
	// Accept xs:string, xs:anyURI, xs:untypedAtomic, and any schema type derived
	// from xs:string (a user simple type such as StandardDate atomizes to a
	// string-backed value whose BaseType is xs:string — subtype substitution makes
	// it a valid xs:string for the analyze-string select). Reject genuinely
	// non-string atomic types (xs:integer, etc.).
	if !analyzeStringSelectTypeOK(av) {
		return analyzeStringSource{}, dynamicError(lexicon.ErrXPTY0004, "xsl:analyze-string select must be xs:string, got %s", av.TypeName)
	}

	input, err := xpath.AtomicToString(av)
	if err != nil {
		return analyzeStringSource{}, dynamicError(lexicon.ErrXPTY0004, "xsl:analyze-string select must be xs:string: %v", err)
	}

	return analyzeStringSource{text: input, version2: isV2, present: true}, nil
}

func (ec *execContext) executeAnalyzeStringSegments(ctx context.Context, inst *analyzeStringInst, re *xpath.Regex, input string, findLimit, totalSegments int) error {
	// Save and restore context state
	savedNode := ec.contextNode
	savedCurrent := ec.currentNode
	savedItem := ec.contextItem
	savedPos := ec.position
	savedSize := ec.size

	savedGroups := ec.regexGroups
	defer func() {
		ec.contextNode = savedNode
		ec.currentNode = savedCurrent
		ec.contextItem = savedItem
		ec.position = savedPos
		ec.size = savedSize
		ec.regexGroups = savedGroups
	}()

	segIdx := 0
	// runSegment sets the focus for one segment and executes its body.
	runSegment := func(start, end int, body []instruction, groups []string) error {
		segIdx++

		if len(body) == 0 {
			return nil
		}

		var text string
		if len(groups) > 0 {
			text = groups[0]
		} else {
			text = analyzeStringPart(input, start, end)
		}

		ec.position = segIdx
		ec.size = totalSegments
		ec.contextItem = xdm.AtomicValue{TypeName: xdm.TypeString, Value: text}
		ec.contextNode = nil
		ec.currentNode = nil

		ec.regexGroups = groups
		for _, bodyInst := range body {
			if err := ec.executeInstruction(ctx, bodyInst); err != nil {
				return err
			}
		}

		return nil
	}

	// Second pass: re-stream the matches and execute each segment's body as its
	// span is discovered. Like the count pass, matches are never accumulated.
	pos := 0

	var execErr error

	execIterErr := re.EachSubmatchIndex(ctx, input, findLimit, func(m []int) bool {
		if err := ctx.Err(); err != nil {
			execErr = err
			return false
		}

		start, end := m[0], m[1]
		if start > pos {
			if err := runSegment(pos, start, inst.NonMatchingBody, nil); err != nil {
				execErr = err
				return false
			}
		}

		if len(inst.MatchingBody) == 0 {
			segIdx++
			pos = end

			return true
		}

		groups := analyzeStringGroups(input, m)

		if err := runSegment(start, end, inst.MatchingBody, groups); err != nil {
			execErr = err
			return false
		}

		pos = end

		return true
	})

	if execErr != nil {
		return execErr
	}

	if execIterErr != nil {
		if failure := preserveControlFailure(ctx, execIterErr); failure != nil {
			return failure
		}

		return dynamicErrorCause(errCodeXTDE1140, execIterErr, "xsl:analyze-string regex match error: %v", execIterErr)
	}

	if pos < len(input) {
		if err := ctx.Err(); err != nil {
			return err
		}

		if err := runSegment(pos, len(input), inst.NonMatchingBody, nil); err != nil {
			return err
		}
	}

	return nil
}

// execWherePopulated applies section 8.4.1 to each item before the caller
// constructs complex content. Capturing the raw sequence preserves document,
// text, attribute and array boundaries until after deemed-empty filtering.
func (ec *execContext) execWherePopulated(ctx context.Context, inst *wherePopulatedInst) error {
	seq, err := ec.evaluateBodyAsSequence(ctx, inst.Body)
	if err != nil {
		return err
	}

	var populated xdm.ItemSlice

	for item := range xdm.SequenceItems(seq) {
		empty, err := conditionalItemEmpty(ctx, item, deemedEmpty, 0)
		if err != nil {
			return err
		}

		if !empty {
			populated = append(populated, item)
		}
	}

	return ec.outputSequence(populated)
}

func (ec *execContext) evaluateConditionalInstruction(ctx context.Context, selectExpr *xpath.Expression, body []instruction) (xdm.Sequence, error) {
	if selectExpr != nil {
		result, err := ec.evalXPath(ctx, selectExpr, ec.contextNode)
		if err != nil {
			return nil, err
		}

		return result.Sequence(), nil
	}

	return ec.evaluateBodyAsSequence(ctx, body)
}

func (ec *execContext) execOnEmpty(ctx context.Context, inst *onEmptyInst) error {
	return ec.registerConditionalOutput(ctx, inst.Select, inst.Body, conditionalOnEmpty)
}

func (ec *execContext) execOnNonEmpty(ctx context.Context, inst *onNonEmptyInst) error {
	return ec.registerConditionalOutput(ctx, inst.Select, inst.Body, conditionalOnNonEmpty)
}

func (ec *execContext) registerConditionalOutput(ctx context.Context, selectExpr *xpath.Expression, body []instruction, kind conditionalKind) error {
	out := ec.currentOutput()
	if len(out.conditionalScopes) == 0 || out.current == nil {
		return nil
	}

	var local *varScope

	if ec.localVars != nil {
		if err := xpath.Charge(ctx, len(ec.localVars.vars)); err != nil {
			return err
		}

		local = &varScope{vars: maps.Clone(ec.localVars.vars), deferredErrors: maps.Clone(ec.localVars.deferredErrors), parent: ec.localVars.parent}
	}

	placeholder := out.doc.CreateComment("")
	if out.sequenceMode {
		out.pendingItems = append(out.pendingItems, xdm.NodeItem{Node: placeholder})
	} else if err := ec.addNodeUntracked(placeholder); err != nil {
		return err
	}

	scopeIdx := len(out.conditionalScopes) - 1
	out.conditionalScopes[scopeIdx].actions = append(out.conditionalScopes[scopeIdx].actions, conditionalAction{
		kind:       kind,
		selectExpr: selectExpr, body: body, localVars: local,
		staticBaseURI: ec.staticBaseURIOverride, xpathDefaultNS: ec.xpathDefaultNS, hasXPathDefaultNS: ec.hasXPathDefaultNS,
		sourceLine: ec.errSourceLine, sourceModule: ec.errSourceModule,
		placeholder:   placeholder,
		prevWasAtomic: out.prevWasAtomic,
	})

	return nil
}

// execMap combines a sequence of maps using the shared duplicate-key rules.
func (ec *execContext) execMap(ctx context.Context, inst *mapInst) error {
	maps, err := ec.evaluateBodyAsSequence(ctx, inst.Body)
	if err != nil {
		return err
	}

	builder := xdm.NewMapBuilder(xdm.MergeReject, xdm.SequenceLen(maps))
	for item := range xdm.SequenceItems(maps) {
		if err := xpath.Charge(ctx, 1); err != nil {
			return err
		}

		m, ok := item.(xdm.MapItem)
		if !ok {
			return dynamicError("XTTE3375", "xsl:map body produced non-map item %T", item)
		}

		if err := m.ForEachView(func(key xdm.AtomicValue, value xdm.Sequence) error {
			if err := xpath.Charge(ctx, 1); err != nil {
				return err
			}

			if err := builder.Add(key, value); err != nil {
				return dynamicError(errCodeXTDE3365, "duplicate key in xsl:map")
			}

			if builder.Size() > xpath.NodeLimit(ctx, xdm.DefaultMaxNodeSetLength) {
				return xpath.ErrBudget
			}

			return nil
		}); err != nil {
			return err
		}
	}

	return ec.outputSequence(xdm.ItemSlice{builder.Build()})
}

// execMapEntry constructs one map entry, including outside xsl:map.
func (ec *execContext) execMapEntry(ctx context.Context, inst *mapEntryInst) error {
	keyResult, err := ec.evalXPath(ctx, inst.Key, ec.contextNode)
	if err != nil {
		return err
	}

	key, err := ec.convertSequenceType(ctx, keyResult.Sequence(), xdm.SequenceType{ItemTest: xdm.AtomicOrUnionType{Name: "Q{http://www.w3.org/2001/XMLSchema}anyAtomicType"}})
	if err != nil {
		return err
	}

	keyValue, err := xpath.AtomizeItem(key.Get(0))
	if err != nil {
		return err
	}

	var value xdm.Sequence

	if inst.Select != nil {
		result, err := ec.evalXPath(ctx, inst.Select, ec.contextNode)
		if err != nil {
			return err
		}

		value = result.Sequence()
	} else if len(inst.Body) > 0 {
		value, err = ec.evaluateBodyAsSequence(ctx, inst.Body)
		if err != nil {
			return err
		}
	}

	return ec.outputSequence(xdm.ItemSlice{xdm.SingleEntryMap(keyValue, value)})
}

// execAssert implements xsl:assert when externally enabled. False tests and
// ordinary dynamic test errors follow the terminating message rules.
func (ec *execContext) execAssert(ctx context.Context, inst *assertInst) error {
	enabled, _ := ctx.Value(assertionsKey{}).(bool)
	if !enabled || inst.Test == nil {
		return nil
	}

	passed, err := ec.evalXPathEBV(ctx, inst.Test, ec.contextNode)
	if err != nil {
		if err := preserveControlFailure(ctx, err); err != nil {
			return err
		}
	}

	if passed {
		return nil
	}

	message := &messageInst{sourceInfo: inst.sourceInfo, Select: inst.Select, Body: inst.Body, ErrorCode: inst.ErrorCode, ErrorNamespaces: inst.ErrorNamespaces}

	return ec.execMessageWithDefaults(ctx, message, true, errCodeXTMM9001)
}

// execEvaluate implements xsl:evaluate — dynamically compile and evaluate
// an XPath expression string at runtime.
func (ec *execContext) execEvaluate(ctx context.Context, inst *evaluateInst) error {
	xpathStr, err := ec.evaluateXPathSource(ctx, inst)
	if err != nil {
		return err
	}

	if limit := dynamicProgramLimit(ctx, ec.resourceLimit()); limit > 0 && int64(len(xpathStr)) > limit {
		return xpath.ErrBudget
	}

	if err := xpath.Charge(ctx, len(xpathStr)); err != nil {
		return err
	}

	dynContextNode, dynContextItem, hasContextItem, err := ec.evaluateContextItem(ctx, inst)
	if err != nil {
		return err
	}

	nsBindings, err := ec.evaluateNamespaces(ctx, inst)
	if err != nil {
		return err
	}

	if err := ec.checkEvaluateSchemaAwareness(ctx, inst); err != nil {
		return err
	}

	dynExpr, compileErr := xpath.NewCompiler().Context(ctx).Language(31, nsBindings).Compile(xpathStr)
	if compileErr != nil {
		if failure := preserveControlFailure(ctx, compileErr); failure != nil {
			return failure
		}

		return dynamicError(errCodeXTDE3160, "xsl:evaluate: cannot compile XPath expression %q: %v", xpathStr, compileErr)
	}

	dynCtx := ec.xpathContext(ctx)

	vars, err := ec.evaluateVariables(ctx, inst)
	if err != nil {
		return err
	}

	eval := ec.dynamicXPathEvaluator(vars, nsBindings)
	if err := eval.ValidateExpression(ctx, dynExpr); err != nil {
		if failure := preserveControlFailure(ctx, err); failure != nil {
			return failure
		}

		return dynamicError(errCodeXTDE3160, "xsl:evaluate static context: %s", err)
	}

	if inst.BaseURI != nil {
		baseURI, buErr := inst.BaseURI.evaluate(dynCtx, ec.contextNode)
		if buErr != nil {
			return buErr
		}

		if baseURI != "" {
			eval = eval.BaseURI(ensureFileURI(baseURI))
			// The base-uri attribute governs not only the native xpath
			// functions (fn:unparsed-text, fn:collection — they read the
			// evaluator BaseURI above) but also the XSLT-aware functions
			// fn:doc / fn:document / fn:stream-available, which resolve relative
			// URIs through ec.baseDir() / effectiveStaticBaseURI(). Install the
			// declared base as a static-base override for the duration of the
			// dynamic evaluation so those functions resolve against the SAME
			// base instead of the using template's static base.
			savedOverride := ec.staticBaseURIOverride

			ec.staticBaseURIOverride = baseURI
			defer func() { ec.staticBaseURIOverride = savedOverride }()
		}
	} else if baseURI := ec.effectiveStaticBaseURI(); baseURI != "" {
		eval = eval.BaseURI(ensureFileURI(baseURI))
	}

	eval = ec.configureDynamicCollation(eval)
	if dynContextItem != nil {
		eval = eval.ContextItem(dynContextItem)
	}

	if hasContextItem {
		eval = eval.Position(1).Size(1)
	}

	// 7. Evaluate the dynamic expression.
	var evalNode xdm.Node
	if dynContextNode != nil {
		evalNode = dynContextNode
	} else if hasContextItem && ec.contextNode != nil {
		evalNode = ec.contextNode
	}

	result, evalErr := eval.Evaluate(dynCtx, dynExpr, evalNode)
	if evalErr != nil {
		return evalErr
	}

	seq := result.Sequence()

	if inst.ResultType != nil {
		converted, err := ec.convertSequenceType(ctx, seq, *inst.ResultType)
		if err != nil {
			return err
		}

		seq = converted
	}

	return ec.outputSequence(seq)
}

func (ec *execContext) evaluateXPathSource(ctx context.Context, inst *evaluateInst) (string, error) {
	xpathResult, err := ec.evalXPath(ctx, inst.XPath, ec.contextNode)
	if err != nil {
		return "", err
	}

	value, err := ec.convertSequenceType(ctx, xpathResult.Sequence(), xdm.SequenceType{ItemTest: xdm.AtomicOrUnionType{Name: "Q{http://www.w3.org/2001/XMLSchema}string"}})
	if err != nil {
		return "", err
	}

	xpathStr := value.Get(0).(xdm.AtomicValue).StringVal() //nolint:forcetypeassert // conversion requires one xs:string

	if strings.TrimSpace(xpathStr) == "" {
		return "", dynamicError(errCodeXTDE3160, "xsl:evaluate: xpath expression is empty")
	}

	return xpathStr, nil
}

func (ec *execContext) evaluateContextItem(ctx context.Context, inst *evaluateInst) (xdm.Node, xdm.Item, bool, error) {
	var (
		dynContextNode xdm.Node
		dynContextItem xdm.Item
	)

	hasContextItem := true

	if inst.ContextItem != nil {
		ciResult, ciErr := ec.evalXPath(ctx, inst.ContextItem, ec.contextNode)
		if ciErr != nil {
			return nil, nil, false, ciErr
		}

		ciSeq := ciResult.Sequence()

		ciLen := 0
		if ciSeq != nil {
			ciLen = xdm.SequenceLen(ciSeq)
		}

		if ciLen > 1 {
			return nil, nil, false, dynamicError(errCodeXTTE3210, "xsl:evaluate: context-item must be a single item, got %d items", ciLen)
		}

		if ciLen == 1 {
			switch v := ciSeq.Get(0).(type) {
			case xdm.NodeItem:
				dynContextNode = v.Node
			default:
				dynContextItem = v
			}
		} else {
			// Empty sequence: no context item
			hasContextItem = false
		}
	} else {
		// Per XSLT 3.0 §10.4.2: when no context-item attribute is present,
		// the context item for the dynamic expression is absent.
		hasContextItem = false
	}

	return dynContextNode, dynContextItem, hasContextItem, nil
}

func (ec *execContext) evaluateNamespaces(ctx context.Context, inst *evaluateInst) (map[string]string, error) {
	nsBindings := make(map[string]string)

	if inst.NamespaceContext == nil {
		for prefix, uri := range inst.Namespaces {
			if prefix != "" {
				nsBindings[prefix] = uri
			}
		}
	}

	// If namespace-context is specified, collect namespaces from that node
	if inst.NamespaceContext != nil {
		ncResult, ncErr := ec.evalXPath(ctx, inst.NamespaceContext, ec.contextNode)
		if ncErr != nil {
			return nil, ncErr
		}

		ncSeq := ncResult.Sequence()

		ncLen := 0
		if ncSeq != nil {
			ncLen = xdm.SequenceLen(ncSeq)
		}
		// XTTE3170: when the namespace-context attribute is supplied, its value
		// must be a single node. An empty sequence, multiple items, or a non-node
		// item is a type error, and is never silently ignored.
		if ncLen != 1 {
			return nil, dynamicError(errCodeXTTE3170,
				"xsl:evaluate namespace-context produced %d items; a single node is required", ncLen)
		}

		ni, nodeOK := ncSeq.Get(0).(xdm.NodeItem)
		if !nodeOK {
			return nil, dynamicError(errCodeXTTE3170,
				"xsl:evaluate namespace-context must be a single node")
		}

		if err := collectEvaluateNamespaces(ctx, ni.Node, nsBindings); err != nil {
			return nil, err
		}
	}

	if inst.NamespaceContext == nil && inst.HasXPathDefaultNS {
		nsBindings[""] = inst.XPathDefaultNS
	}

	return nsBindings, nil
}

func (ec *execContext) checkEvaluateSchemaAwareness(ctx context.Context, inst *evaluateInst) error {
	if inst.SchemaAwareAVT != nil {
		saStr, saErr := inst.SchemaAwareAVT.evaluate(ctx, ec.contextNode)
		if saErr != nil {
			return saErr
		}

		sa, ok := parseXSDBool(saStr)
		if !ok {
			return staticError(errCodeXTSE0020, "xsl:evaluate: invalid value %q for schema-aware attribute", saStr)
		}

		if sa {
			return ErrLanguageUnsupported
		}
	}

	return nil
}

func (ec *execContext) evaluateVariables(ctx context.Context, inst *evaluateInst) (map[string]xdm.Sequence, error) {
	// Only explicit parameters are in the target expression's static scope.
	vars := make(map[string]xdm.Sequence)

	if err := xpath.Charge(ctx, len(inst.Params)); err != nil {
		return nil, err
	}

	for _, wp := range inst.Params {
		paramVal, paramErr := ec.evaluateWithParam(ctx, wp)
		if paramErr != nil {
			return nil, paramErr
		}

		vars[wp.Name] = paramVal
	}

	// Add with-params map variables (higher priority, overrides xsl:with-param)
	if inst.WithParamsExpr != nil {
		wpResult, wpErr := ec.evalXPath(ctx, inst.WithParamsExpr, ec.contextNode)
		if wpErr != nil {
			return nil, wpErr
		}

		wpSeq := wpResult.Sequence()
		if xdm.SequenceLen(wpSeq) != 1 {
			return nil, dynamicError(errCodeXTTE3165, "xsl:evaluate: with-params must be a single QName-keyed map")
		}

		wpMap, ok := wpSeq.Get(0).(xdm.MapItem)
		if !ok {
			return nil, dynamicError(errCodeXTTE3165, "xsl:evaluate: with-params must be a single QName-keyed map")
		}

		if err := wpMap.ForEach(func(key xdm.AtomicValue, value xdm.Sequence) error {
			if err := xpath.Charge(ctx, 1); err != nil {
				return err
			}

			if key.TypeName != xdm.TypeQName {
				return dynamicError(errCodeXTTE3165, "xsl:evaluate: with-params map keys must be xs:QName")
			}

			name, err := paramKeyToClark(key)
			if err != nil {
				return err
			}

			vars[name] = value

			return nil
		}); err != nil {
			return nil, err
		}
	}

	return vars, nil
}

func (ec *execContext) dynamicXPathEvaluator(vars map[string]xdm.Sequence, nsBindings map[string]string) xpath.Evaluator {
	// XSLT 3.0 section 10.4 exposes the standard XPath library and visible
	// public/final stylesheet functions, without XSLT-specific built-ins.
	evalFns := ec.xsltEvaluateFunctions()

	eval := xpath.NewEvaluator(xpath.EvalBorrowing).
		Variables(vars).
		Functions(evalFns, ec.xsltEvaluateFunctionsNS())
	if ec.stylesheet.processorLanguage() >= 30 {
		eval = eval.ResourceReads(ec)
	}

	// Forward the same runtime evaluator configuration that ordinary XPath
	// evaluation uses (see buildBaseXPathEvaluator), so a dynamically-evaluated
	// XPath honors the configured resource resolvers, resource caps, stable
	// clock, trace sink, and shared document-order cache instead of silently
	// dropping them. Without this, fn:unparsed-text / fn:json-doc / fn:collection
	// inside xsl:evaluate behave differently from the same call made statically.
	eval = eval.
		CurrentTime(ec.currentTime).
		ImplicitTimezone(ec.dynamicProperties.Timezone).
		AllowXML11Chars().
		TraceWriter(ec.traceWriter)
	if resolver := ec.collectionResolver(); resolver != nil {
		eval = eval.CollectionResolver(resolver)
	}

	if ec.transformConfig != nil {
		if r := ec.transformConfig.uriResolver; r != nil {
			eval = eval.URIResolver(resourceURIResolver{r})
		}

		eval = eval.MaxResourceBytes(resolveResourceLimit(ec.resourceLimit()))
	}

	if ec.docOrderCache != nil {
		eval = eval.DocOrderCache(ec.docOrderCache)
	}

	// Forward the injected base parseOptions so fn:doc / fn:parse-xml inside the
	// dynamically-evaluated XPath uses the same parse policy as the engine.
	if p := ec.inputParseOptions(); p != nil {
		eval = eval.ParseOptions(*p)
	}

	eval = eval.Namespaces(nsBindings).StrictPrefixes()

	if ec.typeAnnotations != nil {
		eval = eval.TypeAnnotations(ec.typeAnnotations)
	}

	if nilled := ec.nilledElementNodes(); nilled != nil {
		eval = eval.NilledElements(nilled)
	}

	if ec.preservedIDAnnotations != nil {
		eval = eval.PreservedIDAnnotations(ec.preservedIDAnnotations)
	}

	return eval
}

func (ec *execContext) configureDynamicCollation(eval xpath.Evaluator) xpath.Evaluator {
	// Default collation
	if ec.defaultCollation != "" {
		eval = eval.DefaultCollation(ec.defaultCollation)
	}

	// Decimal formats (package-scoped)
	dfmts := ec.effectiveDecimalFormats()
	if len(dfmts) > 0 {
		for qn, df := range dfmts {
			if qn == (xpath.QualifiedName{}) {
				eval = eval.DefaultDecimalFormat(df)
			}
		}

		eval = eval.NamedDecimalFormats(dfmts)
	}

	return eval
}

// countAnalyzeStringSegments streams matches and rejects the first over-budget
// match before segment output or an input-sized match list can be built.
func countAnalyzeStringSegments(ctx context.Context, re *xpath.Regex, input string, maxMatches, findLimit int) (int, error) {
	totalSegments := 0
	matchCount := 0
	pos := 0

	var earlyErr error

	countErr := re.EachSubmatchIndex(ctx, input, findLimit, func(m []int) bool {
		if err := ctx.Err(); err != nil {
			earlyErr = err
			return false
		}

		matchCount++
		if maxMatches >= 0 && matchCount > maxMatches {
			earlyErr = fmt.Errorf("xsl:analyze-string produced more than %d matches: %w", maxMatches, ErrResourceTooLarge)

			return false
		}

		if m[0] > pos {
			totalSegments++
		}

		totalSegments++
		pos = m[1]

		return true
	})

	if earlyErr != nil {
		return 0, earlyErr
	}

	if countErr != nil {
		if failure := preserveControlFailure(ctx, countErr); failure != nil {
			return 0, failure
		}

		return 0, dynamicErrorCause(errCodeXTDE1140, countErr, "xsl:analyze-string regex match error: %v", countErr)
	}

	if pos < len(input) {
		totalSegments++
	}

	return totalSegments, nil
}

// analyzeStringSelectTypeOK reports whether an atomized select value is usable as
// the xs:string input of xsl:analyze-string: xs:string / xs:anyURI /
// xs:untypedAtomic, or a schema-defined simple type derived from xs:string (whose
// BaseType is xs:string, so its string-backed value substitutes for xs:string).
func analyzeStringSelectTypeOK(av xdm.AtomicValue) bool {
	switch av.TypeName {
	case xdm.TypeString, xdm.TypeUntypedAtomic, xdm.TypeAnyURI:
		return true
	}
	// A user-defined simple type carries its built-in base in BaseType; accept it
	// when that base is (or derives from) xs:string.
	if av.BaseType == xdm.TypeString || av.BaseType == xdm.TypeAnyURI {
		return true
	}

	if av.BaseType != "" && xdm.BuiltinIsSubtypeOf(av.BaseType, xdm.TypeString) {
		return true
	}

	return false
}

// analyzeStringPart detaches segments that can escape through xsl:sequence or
// regex-group(), without copying an unchanged complete input.
func analyzeStringPart(input string, start, end int) string {
	if start == 0 && end == len(input) {
		return input
	}

	return strings.Clone(input[start:end])
}

func analyzeStringGroups(input string, matches []int) []string {
	groups := make([]string, len(matches)/2)
	for g := range groups {
		start, end := matches[2*g], matches[2*g+1]
		if start >= 0 && end >= 0 {
			groups[g] = analyzeStringPart(input, start, end)
		}
	}

	return groups
}

type conditionalEmptiness uint8

const (
	deemedEmpty conditionalEmptiness = iota
	vacuousItem
)

// conditionalItemEmpty keeps the distinct definitions in sections 8.4.1 and
// 8.4.2 while sharing bounded recursive array flattening and atomic conversion.
func conditionalItemEmpty(ctx context.Context, item xdm.Item, rule conditionalEmptiness, depth int) (bool, error) {
	if err := xpath.Charge(ctx, 1); err != nil {
		return false, err
	}

	if depth > xpath.DepthLimit(ctx, 128) {
		return false, xpath.ErrBudget
	}

	switch value := item.(type) {
	case xdm.NodeItem:
		kind := value.Node.Type()
		if kind == xdm.DocumentNode || (rule == deemedEmpty && kind == xdm.ElementNode) {
			return value.Node.FirstChild() == nil, nil
		}

		if rule == deemedEmpty || kind == xdm.TextNode || kind == xdm.CDATASectionNode {
			return xdm.StringValue(value.Node) == "", nil
		}

		return false, nil
	case xdm.AtomicValue:
		text, err := xpath.AtomicToString(value)
		return text == "", err
	case xdm.MapItem:
		return rule == deemedEmpty && value.Size() == 0, nil
	case xdm.ArrayItem:
		return conditionalArrayEmpty(ctx, value, rule, depth)
	case *xdm.ArrayItem:
		return conditionalArrayEmpty(ctx, *value, rule, depth)
	default:
		return false, nil
	}
}

func conditionalArrayEmpty(ctx context.Context, array xdm.ArrayItem, rule conditionalEmptiness, depth int) (bool, error) {
	for i := 1; i <= array.Size(); i++ {
		if err := xpath.Charge(ctx, 1); err != nil {
			return false, err
		}

		member, err := array.GetView(i)
		if err != nil {
			return false, err
		}

		for item := range xdm.SequenceItems(member) {
			empty, err := conditionalItemEmpty(ctx, item, rule, depth+1)
			if err != nil || !empty {
				return empty, err
			}
		}
	}

	return true, nil
}

type assertionsKey struct{}

type dynamicEvaluationDisabledKey struct{}

// WithDynamicEvaluationDisabled selects a static feature restriction inherited
// by nested compilation. It cannot enable evaluation in a disabled outer scope.
func WithDynamicEvaluationDisabled(ctx context.Context) context.Context {
	return context.WithValue(ctx, dynamicEvaluationDisabledKey{}, true)
}

// WithAssertions selects the invocation's external XSLT assertion policy.
func WithAssertions(ctx context.Context, enabled bool) context.Context {
	return context.WithValue(ctx, assertionsKey{}, enabled)
}

func dynamicEvaluationDisabled(ctx context.Context) bool {
	disabled, _ := ctx.Value(dynamicEvaluationDisabledKey{}).(bool)
	return disabled
}

func collectEvaluateNamespaces(ctx context.Context, node xdm.Node, bindings map[string]string) error {
	for node != nil {
		if err := xpath.Charge(ctx, 1); err != nil {
			return err
		}

		if _, element := node.(*xdm.Element); element {
			break
		}

		node = node.Parent()
	}

	seen := make(map[string]struct{})

	for current := node; current != nil; current = current.Parent() {
		if err := xpath.Charge(ctx, 1); err != nil {
			return err
		}

		element, ok := current.(*xdm.Element)
		if !ok {
			continue
		}

		for _, namespace := range element.Namespaces() {
			if err := xpath.Charge(ctx, 1); err != nil {
				return err
			}

			prefix := namespace.Prefix()
			if _, exists := seen[prefix]; exists {
				continue
			}

			seen[prefix] = struct{}{}
			bindings[prefix] = namespace.URI()
		}
	}

	return nil
}
