// Derived from lestrrat-go/helium at 7362c0a70122a757780f4d0b545a9b370dead6ab.
// Copyright (c) 2015 lestrrat. MIT License; see licenses/MIT-helium.txt at the repository root.

package xslt

import (
	"context"
	"fmt"
	"strings"

	"github.com/skarm/xmlsec/internal/xmlchar"
	"github.com/skarm/xmlsec/transform/internal/xdm"
	"github.com/skarm/xmlsec/transform/internal/xdm/lexicon"
	"github.com/skarm/xmlsec/transform/internal/xpath"
	"github.com/skarm/xmlsec/transform/internal/xslt/internal/elements"
)

func (ec *execContext) fnElementAvailable(ctx context.Context, args []xdm.Sequence) (xdm.Sequence, error) {
	return introspectionElementAvailable(ctx, args, ec.stylesheet.processorLanguage(), ec.stylesheet.dynamicEvaluationDisabled)
}

func introspectionElementAvailable(ctx context.Context, args []xdm.Sequence, processor int, disabled bool) (xdm.Sequence, error) {
	name, err := introspectionArgumentName(ctx, args, xpath.FnDefaultXMLNamespace(ctx), errCodeXTDE1440)
	if err != nil {
		return nil, err
	}

	return xdm.SingleBoolean(elementAvailable(name, processor, disabled)), nil
}

func introspectionArgumentName(ctx context.Context, args []xdm.Sequence, defaultNS, code string) (xdm.QNameValue, error) {
	value, err := xpath.AtomizeItem(args[0].Get(0))
	if err != nil {
		return xdm.QNameValue{}, err
	}

	name, err := xpath.AtomicToString(value)
	if err != nil {
		return xdm.QNameValue{}, err
	}

	return resolveIntrospectionName(name, defaultNS, code, func(prefix string) (string, bool) { return xpath.FnNamespace(ctx, prefix) })
}

func elementAvailable(name xdm.QNameValue, processor int, disabled bool) bool {
	if name.URI != lexicon.NamespaceXSLT || !elements.IsImplemented(name.Local) {
		return false
	}

	if name.Local == lexicon.XSLTElementEvaluate && disabled {
		return false
	}

	if processor < 30 && !elements.IsInstruction(name.Local) {
		return false
	}

	switch elements.MinVersion(name.Local) {
	case "3.0":
		return processor >= 30
	case "2.0":
		return processor >= 20
	default:
		return true
	}
}

// function-available(name, arity?) returns true if the named function is available.
func (ec *execContext) fnFunctionAvailable(ctx context.Context, args []xdm.Sequence) (xdm.Sequence, error) {
	name, err := introspectionArgumentName(ctx, args, xpath.NSFn, errCodeXTDE1400)
	if err != nil {
		return nil, err
	}

	arity, valid := functionAvailableArity(args)
	if !valid {
		return xdm.SingleBoolean(false), nil
	}

	return xdm.SingleBoolean(ec.functionAvailable(name, arity)), nil
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

func (ec *execContext) functionAvailable(name xdm.QNameValue, arity int) bool {
	if ec.stylesheet.processorLanguage() == 10 {
		if name.URI != xpath.NSFn {
			return false
		}

		_, core := xpath.XPath10FunctionArity(name.Local)
		_, host := lookupxslt10Functions(name.Local)

		return core || host
	}

	qname := xpath.QualifiedName{URI: name.URI, Name: name.Local}
	if ec.stylesheetFunctionDefined(qname, arity) {
		return ec.dynamicStylesheetFunction(qname, arity) != nil
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
func fnTypeAvailable(ctx context.Context, args []xdm.Sequence) (xdm.Sequence, error) {
	name, err := introspectionArgumentName(ctx, args, xpath.FnDefaultXMLNamespace(ctx), errCodeXTDE1428)
	if err != nil {
		return nil, err
	}

	return xdm.SingleBoolean(typeAvailable(ctx, name)), nil
}

func typeAvailable(ctx context.Context, name xdm.QNameValue) bool {
	if name.URI != lexicon.NamespaceXSD || !xdm.IsKnownXSDType("xs:"+name.Local) {
		return false
	}

	return name.Local != "dateTimeStamp" || xpath.XMLSchemaVersion(ctx) >= 11
}

// current-group() returns the items in the current group during for-each-group.
func (ec *execContext) fnCurrentGroup(ctx context.Context, _ []xdm.Sequence) (xdm.Sequence, error) {
	if !ec.inGroupContext || xpath.IsDynamicCall(ctx) {
		if ec.stylesheet.processorLanguage() < 30 {
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
		if ec.stylesheet.processorLanguage() < 30 {
			return xdm.EmptySequence(), nil
		}

		return nil, dynamicError(errCodeXTDE1071, "current-grouping-key() called outside xsl:for-each-group")
	}

	if !ec.groupHasKey {
		if ec.stylesheet.processorLanguage() < 30 {
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
	if len(args) == 0 || (args[0] == nil || xdm.SequenceLen(args[0]) == 0) {
		return xdm.EmptySequence(), nil
	}

	av, err := xpath.AtomizeItem(args[0].Get(0))
	if err != nil {
		return xdm.EmptySequence(), nil //nolint:nilerr // accumulator lookup returns empty on atomization failure
	}

	name, err := xpath.AtomicToString(av)
	if err != nil {
		return xdm.EmptySequence(), nil //nolint:nilerr // accumulator lookup returns empty on string conversion failure
	}

	if err := validateAccumulatorName(name, fnName); err != nil {
		return nil, err
	}

	name = resolveQName(name, ec.stylesheet.namespaces)
	if err := ec.checkAccumulatorAccess(name); err != nil {
		return nil, err
	}

	node, err := ec.accumulatorLookupNode(ctx, fnName)
	if err != nil {
		return nil, err
	}

	stateKey := ec.accumulatorStateKey(name)
	if ec.evaluatingAccumulator {
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

	if value, found, err := ec.currentAccumulatorValue(name); found {
		return value, err
	}

	return xdm.EmptySequence(), nil
}

func validateAccumulatorName(name, fnName string) error {
	if !xmlchar.IsValidQName(name) && !isValidEQName(name) {
		return dynamicError(errCodeXTDE3340, "%q is not a valid EQName for %s", name, fnName)
	}

	return nil
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

func (ec *execContext) accumulatorLookupNode(ctx context.Context, fnName string) (xdm.Node, error) {
	node := xpath.FnContextNode(ctx)
	if node == nil {
		node = ec.contextNode
	}

	if !ec.evaluatingAccumulator && node == nil {
		return nil, dynamicError(errCodeXTTE3360, "%s requires context to be a node", fnName)
	}

	if !ec.evaluatingAccumulator && !xdm.IsNilNode(node) {
		if kind := node.Type(); kind == xdm.AttributeNode || kind == xdm.NamespaceNode {
			return nil, dynamicError(errCodeXTTE3360, "%s cannot be called on an attribute or namespace node", fnName)
		}
	}

	return node, nil
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

func (ec *execContext) checkAccumulatorAccess(name string) error {
	// XTDE3340: the name must correspond to a declared accumulator.
	if _, ok := ec.effectiveAccumulators()[name]; !ok {
		return dynamicError(errCodeXTDE3340, "no accumulator %q is declared in this stylesheet", name)
	}
	// Document-level accumulator applicability (XTDE3362).
	// This check must be performed even during accumulator evaluation
	// so that an accumulator rule referencing a non-applicable peer
	// (e.g. one not listed in use-accumulators) is rejected.
	if ec.activeAccumulators != nil {
		if _, ok := ec.activeAccumulators[name]; !ok {
			return dynamicError(errCodeXTDE3362, "accumulator %q is not applicable in the current source-document", name)
		}
	}

	if ec.evaluatingAccumulator {
		return nil
	}
	// XTDE3362: check mode-level use-accumulators restriction.
	// If the current mode explicitly declares use-accumulators, only
	// those accumulators are accessible from templates in that mode.
	if md := ec.effectiveModeDefs()[ec.currentMode]; md != nil && md.UseAccumulators != nil {
		switch *md.UseAccumulators {
		case lexicon.ModeAll:
			// all accumulators allowed
		case "":
			// use-accumulators="" means NO accumulators allowed
			return dynamicError(errCodeXTDE3362,
				"accumulator %q is not applicable in mode %q (use-accumulators is empty)", name, ec.currentMode)
		default:
			allowed := make(map[string]struct{})
			for n := range strings.FieldsSeq(*md.UseAccumulators) {
				allowed[n] = struct{}{}
			}

			if _, ok := allowed[name]; !ok {
				return dynamicError(errCodeXTDE3362,
					"accumulator %q is not applicable in mode %q (not in use-accumulators)", name, ec.currentMode)
			}
		}
	}

	return nil
}

// ensureAccumulatorStates lazily computes accumulator states for the document
// tree containing the given node, if not already computed.
func (ec *execContext) ensureAccumulatorStates(ctx context.Context, node xdm.Node) error {
	if xdm.IsNilNode(node) || len(ec.effectiveAccumulators()) == 0 {
		return nil
	}

	root := documentRoot(node)

	if ec.accumulatorComputedDocs == nil {
		ec.accumulatorComputedDocs = make(map[xdm.Node]struct{})
	}
	// Use a package-scoped key so that different packages' accumulators
	// are computed independently for the same document.
	cacheKey := root
	if ec.currentPackage != nil && ec.currentPackage != ec.stylesheet {
		// Create a synthetic key node per package to avoid collision.
		// We reuse the root but track per-package with a separate map entry.
		pkgKey := fmt.Sprintf("%p@%p", root, ec.currentPackage)
		if ec.accumulatorComputedPkgs == nil {
			ec.accumulatorComputedPkgs = make(map[string]struct{})
		}

		if _, done := ec.accumulatorComputedPkgs[pkgKey]; done {
			return nil
		}

		ec.accumulatorComputedPkgs[pkgKey] = struct{}{}
	} else {
		if _, done := ec.accumulatorComputedDocs[cacheKey]; done {
			return nil
		}

		ec.accumulatorComputedDocs[cacheKey] = struct{}{}
	}

	names := append([]string(nil), ec.effectiveStylesheet().accumulatorOrder...)

	return ec.computeAccumulatorStates(ctx, root, names)
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

func (ec *execContext) builtinFunctionAvailable(uri, local string, arity int) bool {
	return xpath.BuiltinFunctionAvailable(ec.stylesheet.xpathVersion(), uri, local, arity)
}

// copy-of() returns a deep copy of the context node (zero-argument XSLT 3.0 streaming function).
