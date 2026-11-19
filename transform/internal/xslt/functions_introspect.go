// Derived from lestrrat-go/helium at 7362c0a70122a757780f4d0b545a9b370dead6ab.
// Copyright (c) 2015 lestrrat. MIT License; see licenses/MIT-helium.txt at the repository root.

package xslt

import (
	"context"
	"strings"

	"github.com/skarm/xmlsec/internal/lexicon"
	"github.com/skarm/xmlsec/internal/xmlchar"
	"github.com/skarm/xmlsec/transform/internal/xdm"
	"github.com/skarm/xmlsec/transform/internal/xpath"
)

func (ec *execContext) fnElementAvailable(ctx context.Context, args []xdm.Sequence) (xdm.Sequence, error) {
	return introspectionElementAvailable(ctx, args, ec.stylesheet.processorLanguage(), ec.stylesheet.dynamicEvaluationDisabled)
}

// function-available(name, arity?) returns true if the named function is available.
func (ec *execContext) fnFunctionAvailable(ctx context.Context, args []xdm.Sequence) (xdm.Sequence, error) {
	name, err := introspectionArgumentName(ctx, args, xpath.NSFn, errCodeXTDE1400, ec.stylesheet.processorLanguage())
	if err != nil {
		return nil, err
	}

	arity, valid := functionAvailableArity(args)
	if !valid {
		return xdm.SingleBoolean(false), nil
	}

	return xdm.SingleBoolean(ec.functionAvailable(ctx, name, arity)), nil
}

func (ec *execContext) functionAvailable(ctx context.Context, name xdm.QNameValue, arity int) bool {
	if ec.stylesheet.processorLanguage() == processorXSLT10 {
		if name.URI != xpath.NSFn {
			function := xpath.FnRegisteredFunction(ctx, name.URI, name.Local)
			return function != nil && functionAvailableAtArity(function, arity)
		}

		_, core := xpath.XPath10FunctionArity(name.Local)
		_, host := lookupXSLT10FunctionArity(name.Local)

		return core || host
	}

	qname := xpath.QualifiedName{URI: name.URI, Name: name.Local}
	if ec.stylesheetFunctionDefined(qname, arity) {
		return ec.dynamicStylesheetFunction(qname, arity) != nil
	}

	if function := xpath.FnRegisteredFunction(ctx, name.URI, name.Local); function != nil {
		return functionAvailableAtArity(function, arity)
	}

	if name.URI == xpath.NSFn {
		if function, found := ec.xsltFunctions()[name.Local]; found {
			return functionAvailableAtArity(function, arity)
		}
	}

	if function, found := ec.xsltFunctionsNS()[qname]; found {
		return functionAvailableAtArity(function, arity)
	}

	return ec.builtinFunctionAvailable(name.URI, name.Local, arity)
}

// type-available(name) returns true if the named type is available.
func (ec *execContext) fnTypeAvailable(ctx context.Context, args []xdm.Sequence) (xdm.Sequence, error) {
	return introspectionTypeAvailable(ctx, args, ec.stylesheet.processorLanguage())
}

// current-group() returns the items in the current group during for-each-group.
func (ec *execContext) fnCurrentGroup(ctx context.Context, _ []xdm.Sequence) (xdm.Sequence, error) {
	if !ec.inGroupContext || xpath.IsDynamicCall(ctx) {
		if ec.stylesheet.processorLanguage() < processorXSLT30 {
			return xdm.EmptySequence(), nil
		}

		return nil, dynamicError(errCodeXTDE1061, "current-group() called outside xsl:for-each-group")
	}

	if ec.currentGroup != nil {
		return ec.currentGroup, nil
	}

	return xdm.EmptySequence(), nil
}

// current-grouping-key() returns the grouping key for the current group.
// XTDE1071: it is a non-recoverable dynamic error if called when the innermost
// xsl:for-each-group uses group-starting-with or group-ending-with (which do
// not establish a grouping key), or when called outside xsl:for-each-group.
func (ec *execContext) fnCurrentGroupingKey(ctx context.Context, _ []xdm.Sequence) (xdm.Sequence, error) {
	if !ec.inGroupContext || xpath.IsDynamicCall(ctx) {
		if ec.stylesheet.processorLanguage() < processorXSLT30 {
			return xdm.EmptySequence(), nil
		}

		return nil, dynamicError(errCodeXTDE1071, "current-grouping-key() called outside xsl:for-each-group")
	}

	if !ec.groupHasKey {
		if ec.stylesheet.processorLanguage() < processorXSLT30 {
			return xdm.EmptySequence(), nil
		}

		return nil, dynamicError(errCodeXTDE1071, "current-grouping-key() called within xsl:for-each-group that uses group-starting-with or group-ending-with")
	}

	if ec.currentGroupKey != nil {
		return ec.currentGroupKey, nil
	}

	return xdm.EmptySequence(), nil
}

// current-merge-group(source?) returns the current merge group sequence.
// The actual implementation is wired in execute_streaming.go; this stub
// is registered so that function-available() reports the function.
func (ec *execContext) fnCurrentMergeGroup(_ context.Context, _ []xdm.Sequence) (xdm.Sequence, error) {
	if !ec.inMergeAction {
		return nil, dynamicError(errCodeXTDE3480, "current-merge-group() called outside xsl:merge-action")
	}

	return xdm.EmptySequence(), nil
}

// current-merge-key() returns the current merge key value.
// See fnCurrentMergeGroup comment.
func (ec *execContext) fnCurrentMergeKey(_ context.Context, _ []xdm.Sequence) (xdm.Sequence, error) {
	if !ec.inMergeAction {
		return nil, dynamicError(errCodeXTDE3510, "current-merge-key() called outside xsl:merge-action")
	}

	return xdm.EmptySequence(), nil
}

func (ec *execContext) fnAccumulatorBefore(ctx context.Context, args []xdm.Sequence) (xdm.Sequence, error) {
	return ec.accumulatorLookup(ctx, args, nameAccumulatorBefore, func() (map[xdm.Node]map[string]xdm.Sequence, map[xdm.Node]map[string]error) {
		return ec.accumulatorBeforeByNode, ec.accumulatorBeforeErrorByNode
	})
}

func (ec *execContext) fnAccumulatorAfter(ctx context.Context, args []xdm.Sequence) (xdm.Sequence, error) {
	return ec.accumulatorLookup(ctx, args, nameAccumulatorAfter, func() (map[xdm.Node]map[string]xdm.Sequence, map[xdm.Node]map[string]error) {
		return ec.accumulatorAfterByNode, ec.accumulatorAfterErrorByNode
	})
}

// accumulatorLookup implements both accumulator-before() and accumulator-after().
// The caller passes an accessor that returns the per-node value and error maps
// for the appropriate phase. An accessor is used, in place of passing the maps
// directly, because the maps are lazily allocated: ensureAccumulatorStates may
// assign a new map to the execContext field after the call begins.
func (ec *execContext) accumulatorLookup(
	ctx context.Context,
	args []xdm.Sequence,
	fnName string,
	nodeMaps func() (map[xdm.Node]map[string]xdm.Sequence, map[xdm.Node]map[string]error),
) (xdm.Sequence, error) {
	resolved, err := introspectionArgumentName(ctx, args, "", errCodeXTDE3340, ec.stylesheet.processorLanguage())
	if err != nil {
		return nil, err
	}

	name := resolved.Local
	if resolved.URI != "" {
		name = xdm.ClarkName(resolved.URI, resolved.Local)
	}

	definition, ok := ec.effectiveAccumulators()[name]
	if !ok {
		return nil, dynamicError(errCodeXTDE3340, "no accumulator %q is declared in this stylesheet", name)
	}

	node, err := ec.accumulatorLookupNode(ctx, fnName)
	if err != nil {
		return nil, err
	}

	key := ec.accumulatorTreeKey(node)
	if !ec.accumulatorApplies(key.root, definition) {
		return nil, dynamicError(errCodeXTDE3362, "accumulator %q is not applicable to the context tree", name)
	}

	if ec.accumulatorComputationFailed {
		if err := ec.accumulatorTreeErrors[key]; err != nil {
			return nil, err
		}
	}

	stateKey := ec.accumulatorStateKey(name)
	if ec.accumulatorEvaluationTree == key {
		// Completed phases have node-specific snapshots. The live state
		// remains available to rules in the phase currently being evaluated.
		if value, found, err := accumulatorNodeValue(node, stateKey, nodeMaps); found {
			return value, err
		}

		if value, found, err := ec.currentAccumulatorValue(name); found {
			return value, err
		}
	}

	// Merge keys prefer after-values before looking at phase-specific maps.
	if value, found := ec.mergeKeyAccumulatorValue(node, stateKey); found {
		return value, nil
	}

	if node != nil {
		if value, found, err := accumulatorNodeValue(node, stateKey, nodeMaps); found {
			return value, err
		}

		if err := ec.ensureAccumulatorStates(ctx, node); err != nil {
			return nil, err
		}

		// The accessor must run again: lazy evaluation can allocate new maps.
		if value, found, err := accumulatorNodeValue(node, stateKey, nodeMaps); found {
			return value, err
		}
	}

	return xdm.EmptySequence(), nil
}

func (ec *execContext) accumulatorLookupNode(ctx context.Context, fnName string) (xdm.Node, error) {
	item, err := xpath.FnContextItem(ctx)
	if err != nil {
		return nil, dynamicErrorCause(errCodeXTDE3350, err, "%s requires a context item", fnName)
	}

	value, isNode := item.(xdm.NodeItem)
	if !isNode || xdm.IsNilNode(value.Node) {
		return nil, dynamicError(errCodeXTTE3360, "%s requires context to be a node", fnName)
	}

	if kind := value.Node.Type(); kind == xdm.AttributeNode || kind == xdm.NamespaceNode {
		return nil, dynamicError(errCodeXTTE3360, "%s cannot be called on an attribute or namespace node", fnName)
	}

	return value.Node, nil
}

func (ec *execContext) currentAccumulatorValue(name string) (xdm.Sequence, bool, error) {
	if deferred, found := ec.accumulatorStateError[name]; found {
		return nil, true, deferred
	}

	value, found := ec.accumulatorState[name]

	return value, found, nil
}

func (ec *execContext) mergeKeyAccumulatorValue(node xdm.Node, stateKey string) (xdm.Sequence, bool) {
	if ec.evaluatingMergeKey && node != nil && ec.accumulatorAfterByNode != nil {
		if values, found := ec.accumulatorAfterByNode[node]; found {
			value, found := values[stateKey]
			return value, found
		}
	}

	return nil, false
}

func (ec *execContext) accumulatorApplies(root xdm.Node, def *accumulatorDef) bool {
	allowed, restricted := ec.accumulatorGrants[root]
	if !restricted {
		return true
	}

	_, applies := allowed[def]

	return applies
}

func (ec *execContext) addAccumulatorGrant(root xdm.Node, allowed map[*accumulatorDef]struct{}) {
	if ec.accumulatorGrants == nil {
		ec.accumulatorGrants = make(map[xdm.Node]map[*accumulatorDef]struct{})
	}

	ec.accumulatorGrants[root] = allowed
}

func accumulatorGrant(names []string, scope *Stylesheet) map[*accumulatorDef]struct{} {
	allowed := make(map[*accumulatorDef]struct{}, len(names))

	for _, name := range names {
		if name == lexicon.ModeAll {
			for _, def := range scope.accumulators {
				allowed[def] = struct{}{}
			}

			break
		}

		if def := scope.accumulators[name]; def != nil {
			allowed[def] = struct{}{}
		}
	}

	return allowed
}

func (ec *execContext) registerInitialAccumulatorGrants(cfg *transformConfig, selection xdm.Sequence, supplied bool) {
	if len(ec.stylesheet.accumulators) == 0 && len(ec.stylesheet.usedPackages) == 0 {
		return
	}

	mode := ec.stylesheet.defaultMode
	if cfg != nil && cfg.initialMode != "" && cfg.initialMode != modeDefault {
		mode = cfg.initialMode
	}

	if mode == "" || mode == modeUnnamed {
		mode = modeDefault
	}

	scope := ec.stylesheet.modePackage(mode)

	var names []string
	if def := scope.modeDefs[mode]; def != nil && def.UseAccumulators != nil {
		names = strings.Fields(*def.UseAccumulators)
	}

	grant := accumulatorGrant(names, scope)

	if supplied {
		for item := range xdm.SequenceItems(selection) {
			if node, ok := item.(xdm.NodeItem); ok && !xdm.IsNilNode(node.Node) {
				ec.addAccumulatorGrant(documentRoot(node.Node), grant)
			}
		}
	} else if ec.sourceDoc != nil {
		ec.addAccumulatorGrant(ec.sourceDoc, grant)
	}
}

type accumulatorCopy struct {
	source, target xdm.Node
	ancestors      bool
}

func (ec *execContext) recordCopiedAccumulatorTree(lineage accumulatorCopy) {
	original, result := documentRoot(lineage.source), documentRoot(lineage.target)
	if allowed, restricted := ec.accumulatorGrants[original]; restricted {
		ec.addAccumulatorGrant(result, allowed)
	}

	if ec.accumulatorCopies == nil {
		ec.accumulatorCopies = make(map[xdm.Node]accumulatorCopy)
	}

	ec.accumulatorCopies[result] = lineage
	ec.recordAccumulatorTree(ec.accumulatorTreeKey(result), nil)
}

type accumulatorTreeKey struct {
	root  xdm.Node
	scope *Stylesheet
}

func (ec *execContext) accumulatorTreeKey(node xdm.Node) accumulatorTreeKey {
	return accumulatorTreeKey{root: documentRoot(node), scope: ec.effectiveStylesheet()}
}

func (ec *execContext) recordAccumulatorTree(key accumulatorTreeKey, err error) {
	if ec.accumulatorTreeErrors == nil {
		ec.accumulatorTreeErrors = make(map[accumulatorTreeKey]error)
	}

	ec.accumulatorTreeErrors[key] = err
	ec.accumulatorComputationFailed = ec.accumulatorComputationFailed || err != nil
}

// ensureAccumulatorStates lazily computes accumulator states for the containing
// tree. Partial per-node results are inaccessible after computation fails.
func (ec *execContext) ensureAccumulatorStates(ctx context.Context, node xdm.Node) error {
	if xdm.IsNilNode(node) || len(ec.effectiveAccumulators()) == 0 {
		return nil
	}

	key := ec.accumulatorTreeKey(node)
	if err, started := ec.accumulatorTreeErrors[key]; started {
		return err
	}

	// Register the computation before walking because a rule can reference an
	// accumulator on the same tree.
	ec.recordAccumulatorTree(key, nil)

	if origin, isCopy := ec.accumulatorCopies[key.root]; isCopy {
		if err := xpath.Charge(ctx, 1); err != nil {
			ec.recordAccumulatorTree(key, err)

			return err
		}

		err := ec.ensureAccumulatorStates(ctx, origin.source)
		if err == nil {
			ec.transferCopiedAccumulatorStates(origin)
		}

		ec.recordAccumulatorTree(key, err)

		return err
	}

	var names []string

	for _, name := range key.scope.accumulatorOrder {
		if def := key.scope.accumulators[name]; def != nil && ec.accumulatorApplies(key.root, def) {
			names = append(names, name)
		}
	}

	if len(names) == 0 {
		return nil
	}

	err := ec.computeAccumulatorStates(ctx, key.root, names)
	ec.recordAccumulatorTree(key, err)

	return err
}

func (ec *execContext) builtinFunctionAvailable(uri, local string, arity int) bool {
	return xpath.BuiltinFunctionAvailable(ec.stylesheet.xpathVersion(), uri, local, arity)
}

func introspectionElementAvailable(ctx context.Context, args []xdm.Sequence, processor int, disabled bool) (xdm.Sequence, error) {
	name, err := introspectionArgumentName(ctx, args, xpath.FnDefaultXMLNamespace(ctx), errCodeXTDE1440, processor)
	if err != nil {
		return nil, err
	}

	return xdm.SingleBoolean(elementAvailable(name, processor, disabled)), nil
}

func introspectionArgumentName(ctx context.Context, args []xdm.Sequence, defaultNS, code string, processor int) (xdm.QNameValue, error) {
	value, err := xpath.AtomizeItem(args[0].Get(0))
	if err != nil {
		return xdm.QNameValue{}, err
	}

	name, err := xpath.AtomicToString(value)
	if err != nil {
		return xdm.QNameValue{}, err
	}

	if processor < processorXSLT30 && !xmlchar.IsValidQName(name) {
		return xdm.QNameValue{}, dynamicError(code, "%q is not a valid QName", name)
	}

	return resolveIntrospectionName(name, defaultNS, code, func(prefix string) (string, bool) { return xpath.FnNamespace(ctx, prefix) })
}

func elementAvailable(name xdm.QNameValue, processor int, disabled bool) bool {
	if name.URI != lexicon.NamespaceXSLT || !isImplementedXSLTElement(name.Local) {
		return false
	}

	if name.Local == lexicon.XSLTElementEvaluate && disabled {
		return false
	}

	if processor < processorXSLT30 && !isXSLTInstruction(name.Local) {
		return false
	}

	switch minXSLTElementVersion(name.Local) {
	case lexicon.XSLTVersion30:
		return processor >= processorXSLT30
	case lexicon.XSLTVersion20:
		return processor >= processorXSLT20
	default:
		return true
	}
}

// functionAvailableArity reserves -1 for an omitted argument. Huge positive
// integers saturate, preserving variadic availability without an int overflow.
func functionAvailableArity(args []xdm.Sequence) (int, bool) {
	if len(args) < 2 {
		return -1, true
	}

	value, ok := args[1].Get(0).(xdm.AtomicValue)
	if !ok {
		return 0, false
	}

	arity, fits := value.Int64Val()
	if !fits {
		return int(^uint(0) >> 1), value.BigInt().Sign() >= 0
	}

	if arity < 0 {
		return 0, false
	}

	if uint64(arity) > uint64(^uint(0)>>1) {
		return int(^uint(0) >> 1), true
	}

	return int(arity), true
}

func introspectionTypeAvailable(ctx context.Context, args []xdm.Sequence, processor int) (xdm.Sequence, error) {
	name, err := introspectionArgumentName(ctx, args, xpath.FnDefaultXMLNamespace(ctx), errCodeXTDE1428, processor)
	if err != nil {
		return nil, err
	}

	return xdm.SingleBoolean(typeAvailable(name, processor)), nil
}

func typeAvailable(name xdm.QNameValue, processor int) bool {
	if name.URI != lexicon.NamespaceXSD || !xdm.IsKnownXSDType(lexicon.PrefixXS+":"+name.Local) {
		return false
	}

	if name.Local == lexicon.TypeNumeric && processor < processorXSLT30 {
		return false
	}

	return true
}

func accumulatorNodeValue(
	node xdm.Node,
	stateKey string,
	nodeMaps func() (map[xdm.Node]map[string]xdm.Sequence, map[xdm.Node]map[string]error),
) (xdm.Sequence, bool, error) {
	values, deferredErrors := nodeMaps()
	if nodeErrors, found := deferredErrors[node]; found {
		if deferred, found := nodeErrors[stateKey]; found {
			return nil, true, deferred
		}
	}

	if nodeValues, found := values[node]; found {
		value, found := nodeValues[stateKey]
		return value, found, nil
	}

	return nil, false, nil
}

func functionAvailableAtArity(function xpath.Function, arity int) bool {
	if arity < 0 {
		return true
	}

	if overloads, ok := function.(interface{ AcceptsArity(int) bool }); ok {
		return overloads.AcceptsArity(arity)
	}

	return arity >= function.MinArity() && (function.MaxArity() < 0 || arity <= function.MaxArity())
}

// copy-of() returns a deep copy of the context node (zero-argument XSLT 3.0 streaming function).
