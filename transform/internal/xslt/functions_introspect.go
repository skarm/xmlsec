// Derived from lestrrat-go/helium at 7362c0a70122a757780f4d0b545a9b370dead6ab.
// Copyright (c) 2015 lestrrat. MIT License; see licenses/MIT-helium.txt at the repository root.

package xslt

import (
	"context"
	"fmt"
	"strings"

	"github.com/skarm/xmlsec/internal/xmlchar"
	"github.com/skarm/xmlsec/transform/internal/xdm"
	"github.com/skarm/xmlsec/transform/internal/xdm/intconv"
	"github.com/skarm/xmlsec/transform/internal/xdm/lexicon"
	"github.com/skarm/xmlsec/transform/internal/xpath"
	"github.com/skarm/xmlsec/transform/internal/xslt/internal/elements"
)

func (ec *execContext) fnElementAvailable(_ context.Context, args []xdm.Sequence) (xdm.Sequence, error) {
	if len(args) == 0 || (args[0] == nil || xdm.SequenceLen(args[0]) == 0) {
		return xdm.SingleBoolean(false), nil
	}

	av, err := xpath.AtomizeItem(args[0].Get(0))
	if err != nil {
		return xdm.SingleBoolean(false), nil //nolint:nilerr // element-available returns false on atomization failure
	}

	name, _ := xpath.AtomicToString(av)

	// XTDE1440: element name must be a valid QName or EQName
	if !strings.HasPrefix(name, "Q{") && !xmlchar.IsValidQName(name) {
		return nil, dynamicError(errCodeXTDE1440,
			"element-available: %q is not a valid EQName", name)
	}

	// Resolve prefix:local or Q{uri}local to namespace + local
	local := name
	ns := lexicon.NamespaceXSLT

	if strings.HasPrefix(name, "Q{") {
		if end := strings.IndexByte(name, '}'); end > 2 {
			ns = name[2:end]
			local = name[end+1:]
		}
	} else if prefix, l, ok := strings.Cut(name, ":"); ok {
		local = l
		resolved := false

		if uri, ok := ec.stylesheet.namespaces[prefix]; ok {
			ns = uri
			resolved = true
		}
		// XTDE1440: prefix has no namespace declaration
		if !resolved {
			return nil, dynamicError(errCodeXTDE1440,
				"element-available: prefix %q has no namespace declaration", prefix)
		}
	}

	if ns != lexicon.NamespaceXSLT {
		return xdm.SingleBoolean(false), nil
	}

	if !elements.IsKnown(local) || !elements.IsImplemented(local) {
		return xdm.SingleBoolean(false), nil
	}

	if minVer := elements.MinVersion(local); fmt.Sprintf("%d.0", ec.stylesheet.processorLanguage()/10) < minVer {
		return xdm.SingleBoolean(false), nil
	}

	return xdm.SingleBoolean(true), nil
}

// function-available(name, arity?) returns true if the named function is available.
func (ec *execContext) fnFunctionAvailable(_ context.Context, args []xdm.Sequence) (xdm.Sequence, error) {
	if len(args) == 0 || (args[0] == nil || xdm.SequenceLen(args[0]) == 0) {
		return xdm.SingleBoolean(false), nil
	}

	av, err := xpath.AtomizeItem(args[0].Get(0))
	if err != nil {
		return xdm.SingleBoolean(false), nil //nolint:nilerr // function-available returns false on atomization failure
	}

	name, _ := xpath.AtomicToString(av)
	if !strings.HasPrefix(name, "Q{") && !xmlchar.IsValidQName(name) {
		return nil, dynamicError(errCodeXTDE1400, "function-available: %q is not a valid QName", name)
	}

	available, err := ec.functionAvailable(name, functionAvailableArity(args))
	if err != nil {
		return nil, err
	}

	return xdm.SingleBoolean(available), nil
}

func functionAvailableArity(args []xdm.Sequence) int {
	if len(args) < 2 || args[1] == nil || xdm.SequenceLen(args[1]) == 0 {
		return -1
	}

	atom, err := xpath.AtomizeItem(args[1].Get(0))
	if err != nil {
		return -1
	}

	text, _ := xpath.AtomicToString(atom)
	// Atoi saturates int64 values outside int on 32-bit platforms.
	arity, err := intconv.Atoi(strings.TrimSpace(text))
	if err != nil {
		return -1
	}

	return arity
}

func (ec *execContext) functionAvailable(name string, arity int) (bool, error) {
	if ec.stylesheet.processorLanguage() == 10 {
		if strings.Contains(name, ":") {
			return false, nil
		}

		_, core := xpath.XPath10FunctionArity(name)
		_, host := lookupxslt10Functions(name)

		return core || host, nil
	}

	if function, found := ec.xsltFunctions()[name]; found {
		return functionAvailableAtArity(function, arity), nil
	}

	if strings.HasPrefix(name, "Q{") {
		if closeIndex := strings.IndexByte(name, '}'); closeIndex > 0 {
			return ec.eqNameFunctionAvailable(name[2:closeIndex], name[closeIndex+1:], arity), nil
		}
	}

	if prefix, local, found := strings.Cut(name, ":"); found {
		return ec.prefixedFunctionAvailable(name, prefix, local, arity)
	}

	return ec.builtinFunctionAvailable(xpath.NSFn, name, arity), nil
}

func (ec *execContext) eqNameFunctionAvailable(uri, local string, arity int) bool {
	if ec.findXSLFunction(xpath.QualifiedName{URI: uri, Name: local}, arity) != nil {
		return true
	}

	// EQNames consult declared functions and XPath builtins.
	return ec.builtinFunctionAvailable(uri, local, arity)
}

func (ec *execContext) prefixedFunctionAvailable(name, prefix, local string, arity int) (bool, error) {
	uri, found := ec.stylesheet.namespaces[prefix]
	if !found {
		return false, dynamicError(errCodeXTDE1400,
			"undeclared namespace prefix %q in function-available(%q)", prefix, name)
	}

	qname := xpath.QualifiedName{URI: uri, Name: local}
	if ec.findXSLFunction(qname, arity) != nil {
		return true, nil
	}

	if functions := ec.xsltFunctionsNS(); functions != nil {
		if function, found := functions[qname]; found {
			return functionAvailableAtArity(function, arity), nil
		}
	}

	if xpath.IsBuiltinFunctionNS(uri, local) {
		return ec.builtinFunctionAvailable(uri, local, arity), nil
	}

	return ec.builtinFunctionAvailable(xpath.NSFn, name, arity), nil
}

// type-available(name) returns true if the named type is available.
func (ec *execContext) fnTypeAvailable(_ context.Context, args []xdm.Sequence) (xdm.Sequence, error) {
	if len(args) == 0 || (args[0] == nil || xdm.SequenceLen(args[0]) == 0) {
		return xdm.SingleBoolean(false), nil
	}

	av, err := xpath.AtomizeItem(args[0].Get(0))
	if err != nil {
		return xdm.SingleBoolean(false), nil //nolint:nilerr // type-available returns false on atomization failure
	}

	name, _ := xpath.AtomicToString(av)

	// XTDE1428: type name must be a valid QName or EQName
	if !strings.HasPrefix(name, "Q{") && !xmlchar.IsValidQName(name) {
		return nil, dynamicError(errCodeXTDE1428,
			"type-available: %q is not a valid EQName", name)
	}

	// XTDE1428: if it's a prefixed QName, the prefix must have a namespace declaration
	if !strings.HasPrefix(name, "Q{") {
		if prefix, _, ok := strings.Cut(name, ":"); ok {
			if prefix != "xs" && prefix != lexicon.PrefixXSD {
				if _, ok := ec.stylesheet.namespaces[prefix]; !ok {
					return nil, dynamicError(errCodeXTDE1428,
						"type-available: prefix %q has no namespace declaration", prefix)
				}
			}
		}
	}

	// Resolve QName to canonical xs:... form
	resolved := resolveQName(name, ec.stylesheet.namespaces)
	// If it resolved to {uri}local, normalize XSD namespace to xs: prefix
	if strings.HasPrefix(resolved, "{"+lexicon.NamespaceXSD+"}") {
		local := resolved[len("{"+lexicon.NamespaceXSD+"}"):]
		resolved = "xs:" + local
	} else if prefix, local, ok := strings.Cut(name, ":"); ok {
		if prefix == "xs" || prefix == nameXsd {
			resolved = "xs:" + local
		} else if uri, ok := ec.stylesheet.namespaces[prefix]; ok && uri == lexicon.NamespaceXSD {
			resolved = "xs:" + local
		}
	}

	// xs:error is never available (it's the error type, not a real XSD type).
	// xs:dateTimeStamp is a valid XSD 1.1 type that we support, so it is NOT excluded.
	switch resolved {
	case "xs:error":
		return xdm.SingleBoolean(false), nil
	}

	if xdm.IsKnownXSDType(resolved) {
		return xdm.SingleBoolean(true), nil
	}

	return xdm.SingleBoolean(false), nil
}

// current-group() returns the items in the current group during for-each-group.
func (ec *execContext) fnCurrentGroup(_ context.Context, _ []xdm.Sequence) (xdm.Sequence, error) {
	if !ec.inGroupContext {
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
func (ec *execContext) fnCurrentGroupingKey(_ context.Context, _ []xdm.Sequence) (xdm.Sequence, error) {
	if !ec.inGroupContext {
		return nil, dynamicError(errCodeXTDE1071, "current-grouping-key() called outside xsl:for-each-group")
	}

	if !ec.groupHasKey {
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
	if xpath.IsDynamicCall(ctx) && ec.isStreamableMode() {
		return nil, dynamicError(errCodeXTDE3350, "%s called via dynamic reference in streaming mode", fnName)
	}

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

// isStreamableMode returns true when the current mode has streamable="yes".
func (ec *execContext) isStreamableMode() bool {
	mode := ec.currentMode
	modeDefs := ec.effectiveModeDefs()

	md := modeDefs[mode]
	if md == nil && (mode == "" || mode == modeUnnamed) {
		md = modeDefs[modeDefault]
	}

	return md != nil && md.Streamable
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

	if !ec.requireStreamableAccums {
		return nil
	}

	def, ok := ec.effectiveAccumulators()[name]
	if !ok || def.Streamable {
		return nil
	}

	return dynamicError(errCodeXTDE3362, "accumulator %q is not streamable", name)
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
	return arity < 0 || (arity >= function.MinArity() && arity <= function.MaxArity())
}

func (ec *execContext) builtinFunctionAvailable(uri, local string, arity int) bool {
	return xpath.BuiltinFunctionAvailable(ec.stylesheet.xpathVersion(), uri, local, arity)
}

// copy-of() returns a deep copy of the context node (zero-argument XSLT 3.0 streaming function).
