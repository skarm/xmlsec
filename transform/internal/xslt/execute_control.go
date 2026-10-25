// Derived from lestrrat-go/helium at 7362c0a70122a757780f4d0b545a9b370dead6ab.
// Copyright (c) 2015 lestrrat. MIT License; see licenses/MIT-helium.txt at the repository root.

package xslt

import (
	"context"
	"errors"
	"math"
	"strconv"
	"strings"

	"github.com/skarm/xmlsec/transform/internal/xdm"
	"github.com/skarm/xmlsec/transform/internal/xpath"
)

// executionFocus is the population focus restored after a loop or key evaluation.
// Group state and the current template rule have their own instruction scopes.
type executionFocus struct {
	currentNode xdm.Node
	contextNode xdm.Node
	contextItem xdm.Item
	position    int
	size        int
}

func (ec *execContext) execIf(ctx context.Context, inst *ifInst) error {
	b, err := ec.evalXPathEBV(ctx, inst.Test, ec.contextNode)
	if err != nil {
		return err
	}

	if !b {
		return nil
	}

	if err := ec.executeSequenceConstructor(ctx, inst.Body); err != nil {
		return err
	}

	return nil
}

func (ec *execContext) execChoose(ctx context.Context, inst *chooseInst) error {
	// Apply default-collation from xsl:choose
	savedCollation := ec.defaultCollation
	if inst.DefaultCollation != "" {
		ec.defaultCollation = inst.DefaultCollation
	}
	defer func() { ec.defaultCollation = savedCollation }()

	for _, when := range inst.When {
		// Apply per-when xpath-default-namespace and default-collation
		savedNS := ec.xpathDefaultNS
		savedHas := ec.hasXPathDefaultNS

		savedWhenCollation := ec.defaultCollation
		if when.HasXPathDefaultNS {
			ec.xpathDefaultNS = when.XPathDefaultNS
			ec.hasXPathDefaultNS = true
		}

		if when.DefaultCollation != "" {
			ec.defaultCollation = when.DefaultCollation
		}

		var (
			b   bool
			err error
		)
		// Override namespace bindings with per-clause bindings when present
		if when.Namespaces != nil {
			eval := ec.withCompat(ec.xpathEvaluator(ctx).Namespaces(when.Namespaces).StrictPrefixes(), when.Test)
			b, err = eval.EvaluateEBV(ec.xpathContext(ctx), when.Test, ec.contextNode)
		} else {
			b, err = ec.evalXPathEBV(ctx, when.Test, ec.contextNode)
		}

		if err != nil {
			ec.xpathDefaultNS = savedNS
			ec.hasXPathDefaultNS = savedHas
			ec.defaultCollation = savedWhenCollation

			return err
		}

		if b {
			if err := ec.executeSequenceConstructor(ctx, when.Body); err != nil {
				ec.xpathDefaultNS = savedNS
				ec.hasXPathDefaultNS = savedHas
				ec.defaultCollation = savedWhenCollation

				return err
			}

			ec.xpathDefaultNS = savedNS
			ec.hasXPathDefaultNS = savedHas
			ec.defaultCollation = savedWhenCollation

			return nil
		}

		ec.xpathDefaultNS = savedNS
		ec.hasXPathDefaultNS = savedHas
		ec.defaultCollation = savedWhenCollation
	}
	// otherwise
	savedNS := ec.xpathDefaultNS

	savedHas := ec.hasXPathDefaultNS
	if inst.HasOtherwiseXPNS {
		ec.xpathDefaultNS = inst.OtherwiseXPNS
		ec.hasXPathDefaultNS = true
	}

	if err := ec.executeSequenceConstructor(ctx, inst.Otherwise); err != nil {
		ec.xpathDefaultNS = savedNS
		ec.hasXPathDefaultNS = savedHas

		return err
	}

	ec.xpathDefaultNS = savedNS
	ec.hasXPathDefaultNS = savedHas

	return nil
}

func (ec *execContext) captureExecutionFocus() executionFocus {
	return executionFocus{
		currentNode: ec.currentNode,
		contextNode: ec.contextNode,
		contextItem: ec.contextItem,
		position:    ec.position,
		size:        ec.size,
	}
}

func (ec *execContext) restoreExecutionFocus(focus executionFocus) {
	ec.currentNode = focus.currentNode
	ec.contextNode = focus.contextNode
	ec.contextItem = focus.contextItem
	ec.position = focus.position
	ec.size = focus.size
}

func (ec *execContext) execForEach(ctx context.Context, inst *forEachInst) error {
	result, err := ec.evalXPath(ctx, inst.Select, ec.contextNode)
	if err != nil {
		return err
	}

	seq := result.Sequence()
	nodes, isNodes := xdm.NodesFrom(seq)

	if len(inst.Sort) > 0 {
		if isNodes {
			nodes, err = sortNodes(ctx, ec, nodes, inst.Sort)
		} else {
			seq, err = ec.sortForEachItems(ctx, seq, inst.Sort)
		}

		if err != nil {
			return err
		}
	}

	savedFocus := ec.captureExecutionFocus()
	savedTemplate := ec.currentTemplate
	// XSLT spec: inside xsl:for-each, the current template rule is absent.
	ec.setCurrentTemplate(nil)
	defer func() {
		ec.restoreExecutionFocus(savedFocus)
		ec.setCurrentTemplate(savedTemplate)
	}()

	ec.size = xdm.SequenceLen(seq)
	if isNodes {
		ec.size = len(nodes)
	}

	for i := range ec.size {
		if err := ctx.Err(); err != nil {
			return err
		}

		var item xdm.Item
		if isNodes {
			item = xdm.NodeItem{Node: nodes[i]}
		} else {
			item = seq.Get(i)
		}

		ec.setIterateContext(item, i+1)

		if err := ec.executeScopedSequenceConstructor(ctx, inst.Body); err != nil {
			return err
		}
	}

	return nil
}

func (ec *execContext) sortForEachItems(ctx context.Context, seq xdm.Sequence, keys []*sortKey) (xdm.Sequence, error) {
	// sortNodes validates these internally; sortItems needs validation even
	// when the selected population is empty (XTDE0030).
	for _, key := range keys {
		if err := validateSortKeyAttrs(ctx, ec, key); err != nil {
			return nil, err
		}
	}

	return sortItems(ctx, ec, seq, keys)
}

func (ec *execContext) executeScopedSequenceConstructor(ctx context.Context, body []instruction) error {
	ec.pushVarScope()
	defer ec.popVarScope()

	return ec.executeSequenceConstructor(ctx, body)
}

func (ec *execContext) selectGroupPopulation(ctx context.Context, inst *forEachGroupInst) (xdm.Sequence, error) {
	result, err := ec.evalXPath(ctx, inst.Select, ec.contextNode)
	if err != nil {
		return nil, err
	}

	seq := result.Sequence()
	if ec.stylesheet.processorLanguage() == 20 && (inst.GroupStartingWith != nil || inst.GroupEndingWith != nil) {
		for i := range xdm.SequenceLen(seq) {
			if _, ok := seq.Get(i).(xdm.NodeItem); !ok {
				return nil, dynamicError("XTTE1120", "XSLT 2.0 pattern grouping requires a population of nodes")
			}
		}
	}

	return seq, nil
}

func (ec *execContext) execForEachGroup(ctx context.Context, inst *forEachGroupInst) error {
	seq, err := ec.selectGroupPopulation(ctx, inst)
	if err != nil {
		return err
	}

	// Resolve collation key function: explicit collation attribute takes
	// precedence, then fall back to the default collation in scope.
	var collationKeyFn func(string) string

	if inst.Collation != nil {
		collationURI, collErr := inst.Collation.evaluate(ctx, ec.contextNode)
		if collErr != nil {
			return collErr
		}

		collationURI = resolveAgainstBaseURI(collationURI, ec.effectiveStaticBaseURI())

		collationKeyFn, err = xpath.ResolveCollationKeyFunc(collationURI)
		if err != nil {
			return dynamicErrorCause(errCodeXTDE1110, err, "unsupported grouping collation %q", collationURI)
		}
	} else if inst.DefaultCollation != "" {
		collationKeyFn, err = xpath.ResolveCollationKeyFunc(inst.DefaultCollation)
		if err != nil {
			return dynamicErrorCause(errCodeXTDE1110, err, "unsupported grouping collation %q", inst.DefaultCollation)
		}
	}

	// Build groups based on the grouping mode
	var groups []fegGroup

	switch {
	case inst.GroupBy != nil:
		groups, err = ec.groupBy(ctx, seq, inst.GroupBy, inst.Composite, collationKeyFn)
	case inst.GroupAdjacent != nil:
		groups, err = ec.groupAdjacent(ctx, seq, inst.GroupAdjacent, inst.Composite, collationKeyFn)
	case inst.GroupStartingWith != nil:
		groups = ec.groupStartingWith(ctx, seq, inst.GroupStartingWith)
	case inst.GroupEndingWith != nil:
		groups = ec.groupEndingWith(ctx, seq, inst.GroupEndingWith)
	default:
		// No grouping attribute — treat entire sequence as one group
		groups = []fegGroup{{items: xdm.Materialize(seq)}}
	}

	if err != nil {
		return err
	}

	if len(inst.Sort) > 0 {
		groups, err = sortGroups(ctx, ec, groups, inst.Sort, inst.GroupBy != nil || inst.GroupAdjacent != nil)
		if err != nil {
			return err
		}
	}

	savedCurrent := ec.currentNode
	savedContext := ec.contextNode
	savedItem := ec.contextItem
	savedPos := ec.position
	savedSize := ec.size
	savedGroup := ec.currentGroup
	savedGroupKey := ec.currentGroupKey
	savedInGroupCtx := ec.inGroupContext
	savedGroupHasKey := ec.groupHasKey
	ec.size = len(groups)
	ec.inGroupContext = true

	ec.groupHasKey = inst.GroupBy != nil || inst.GroupAdjacent != nil
	defer func() {
		ec.currentNode = savedCurrent
		ec.contextNode = savedContext
		ec.contextItem = savedItem
		ec.position = savedPos
		ec.size = savedSize
		ec.currentGroup = savedGroup
		ec.currentGroupKey = savedGroupKey
		ec.inGroupContext = savedInGroupCtx
		ec.groupHasKey = savedGroupHasKey
	}()

	for i, g := range groups {
		if err := ctx.Err(); err != nil {
			return err
		}

		ec.position = i + 1
		ec.currentGroup = g.items
		ec.currentGroupKey = g.key

		// Context item is the first item of the group
		if len(g.items) > 0 {
			if ni, ok := g.items[0].(xdm.NodeItem); ok {
				ec.currentNode = ni.Node
				ec.contextNode = ni.Node
				ec.contextItem = nil // clear atomic context when entering node context
			} else {
				ec.contextItem = g.items[0]
				ec.contextNode = nil
				ec.currentNode = nil
			}
		}

		ec.pushVarScope()

		if err := ec.executeSequenceConstructor(ctx, inst.Body); err != nil {
			ec.popVarScope()
			return err
		}

		ec.popVarScope()
	}

	return nil
}

func (ec *execContext) withSortGroupContext(groups []fegGroup, hasKey bool, fn func(i int, node xdm.Node) error) error {
	savedCurrent := ec.currentNode
	savedContext := ec.contextNode
	savedItem := ec.contextItem
	savedPos := ec.position
	savedSize := ec.size
	savedGroup := ec.currentGroup
	savedGroupKey := ec.currentGroupKey
	savedInGroupCtx := ec.inGroupContext

	savedGroupHasKey := ec.groupHasKey
	defer func() {
		ec.currentNode = savedCurrent
		ec.contextNode = savedContext
		ec.contextItem = savedItem
		ec.position = savedPos
		ec.size = savedSize
		ec.currentGroup = savedGroup
		ec.currentGroupKey = savedGroupKey
		ec.inGroupContext = savedInGroupCtx
		ec.groupHasKey = savedGroupHasKey
	}()

	ec.size = len(groups)
	ec.inGroupContext = true
	ec.groupHasKey = hasKey

	for i, g := range groups {
		ec.position = i + 1
		ec.currentGroup = g.items
		ec.currentGroupKey = g.key
		ec.currentNode = nil
		ec.contextNode = nil
		ec.contextItem = nil

		var node xdm.Node

		if len(g.items) > 0 {
			switch v := g.items[0].(type) {
			case xdm.NodeItem:
				node = v.Node
				ec.currentNode = v.Node
				ec.contextNode = v.Node
			default:
				ec.contextItem = g.items[0]
			}
		}

		if err := fn(i, node); err != nil {
			return err
		}
	}

	return nil
}

// groupBy compares atomized keys using deep-equal's atomic comparison rules.
// Collations affect string-like values only, not numeric, QName or temporal keys.
func (ec *execContext) groupBy(ctx context.Context, seq xdm.Sequence, groupByExpr *xpath.Expression, composite bool, collationKeyFn func(string) string) ([]fegGroup, error) {
	groups := groupByAccumulator{byKey: make(map[string][]*groupByEntry), collationKey: collationKeyFn, limit: xpath.NodeLimit(ctx, xdm.DefaultMaxNodeSetLength)}
	groups.equal = func(a, b xdm.Sequence) (bool, error) {
		return ec.groupingKeysEqual(ctx, a, b, collationKeyFn)
	}

	defer ec.restoreExecutionFocus(ec.captureExecutionFocus())

	ec.size = xdm.SequenceLen(seq)
	for i := range xdm.SequenceLen(seq) {
		item := seq.Get(i)
		ec.setIterateContext(item, i+1)

		result, err := ec.evalXPath(ctx, groupByExpr, ec.contextNode)
		if err != nil {
			return nil, err
		}

		atoms, err := xpath.FnAtomize(ctx, result.Sequence())
		if err != nil {
			return nil, err
		}

		keys := atomicGroupingSequence(atoms)
		if composite {
			err = groups.addComposite(ctx, item, keys)
		} else {
			err = groups.addKeys(ctx, item, keys)
		}

		if err != nil {
			return nil, err
		}
	}

	return groups.result(), nil
}

// groupAdjacent compares with the preceding population item's key, while the
// exposed current-grouping-key remains the initial item's key.
func (ec *execContext) groupAdjacent(ctx context.Context, seq xdm.Sequence, adjExpr *xpath.Expression, composite bool, collationKeyFn func(string) string) ([]fegGroup, error) {
	var (
		groups                  []fegGroup
		initialKey, previousKey xdm.Sequence
		currentItems            xdm.ItemSlice
	)

	retainedKeys := 0
	limit := xpath.NodeLimit(ctx, xdm.DefaultMaxNodeSetLength)

	defer ec.restoreExecutionFocus(ec.captureExecutionFocus())

	ec.size = xdm.SequenceLen(seq)
	for i := range xdm.SequenceLen(seq) {
		item := seq.Get(i)
		ec.setIterateContext(item, i+1)

		result, err := ec.evalXPath(ctx, adjExpr, ec.contextNode)
		if err != nil {
			return nil, err
		}

		atoms, err := xpath.FnAtomize(ctx, result.Sequence())
		if err != nil {
			return nil, err
		}

		if !composite && len(atoms) != 1 {
			return nil, dynamicError(errCodeXTTE1100, "group-adjacent key must atomize to exactly one value")
		}

		keys := atomicGroupingSequence(atoms)

		equal, err := ec.groupingKeysEqual(ctx, keys, previousKey, collationKeyFn)
		if err != nil {
			return nil, err
		}

		previousKey = keys

		if equal && len(currentItems) > 0 {
			currentItems = append(currentItems, item)
			continue
		}

		if len(atoms) > limit-retainedKeys {
			return nil, xpath.ErrBudget
		}

		retainedKeys += len(atoms)
		groups = appendAdjacentGroup(groups, initialKey, currentItems)
		initialKey = keys
		currentItems = xdm.ItemSlice{item}
	}

	return appendAdjacentGroup(groups, initialKey, currentItems), nil
}

func atomicGroupingSequence(atoms []xdm.AtomicValue) xdm.Sequence {
	keys := make(xdm.ItemSlice, len(atoms))
	for i, atom := range atoms {
		// XSLT grouping normalizes untypedAtomic keys to xs:string,
		// including the value exposed by current-grouping-key().
		if atom.TypeName == xdm.TypeUntypedAtomic {
			atom.TypeName = xdm.TypeString
		}

		keys[i] = atom
	}

	return keys
}

func (ec *execContext) groupingKeysEqual(ctx context.Context, a, b xdm.Sequence, collationKey func(string) string) (bool, error) {
	if err := xpath.Charge(ctx, 1); err != nil {
		return false, err
	}

	if xdm.SequenceLen(a) != xdm.SequenceLen(b) {
		return false, nil
	}

	for i := range xdm.SequenceLen(a) {
		if err := xpath.Charge(ctx, 1); err != nil {
			return false, err
		}

		first, firstOK := a.Get(i).(xdm.AtomicValue)

		second, secondOK := b.Get(i).(xdm.AtomicValue)
		if !firstOK || !secondOK || !ec.groupingAtomicEqual(first, second, collationKey) {
			return false, nil
		}
	}

	return true, nil
}

func (ec *execContext) groupingAtomicEqual(a, b xdm.AtomicValue, collationKey func(string) string) bool {
	a, b = xdm.PromoteSchemaType(a), xdm.PromoteSchemaType(b)
	first, firstString := groupingString(a)

	second, secondString := groupingString(b)
	if firstString && secondString {
		if collationKey != nil {
			return collationKey(first) == collationKey(second)
		}

		return first == second
	}

	if a.IsNumeric() && b.IsNumeric() && math.IsNaN(a.ToFloat64()) && math.IsNaN(b.ToFloat64()) {
		return true
	}

	equal, err := xpath.ValueCompareWithImplicitTimezone(xpath.TokenEq, a, b, ec.dynamicProperties.Timezone)

	return err == nil && equal // Incomparable atomic types belong to different groups.
}

func groupingString(value xdm.AtomicValue) (string, bool) {
	value = xdm.PromoteSchemaType(value)
	if xdm.IsStringDerived(value.TypeName) || value.TypeName == xdm.TypeUntypedAtomic || value.TypeName == xdm.TypeAnyURI {
		return value.StringVal(), true
	}

	return "", false
}

func appendAdjacentGroup(groups []fegGroup, keySeq xdm.Sequence, items xdm.ItemSlice) []fegGroup {
	if len(items) == 0 {
		return groups
	}

	return append(groups, fegGroup{key: keySeq, items: items})
}

// groupStartingWith implements group-starting-with: a new group starts
// whenever an item matches the pattern.
func (ec *execContext) groupStartingWith(ctx context.Context, seq xdm.Sequence, pat *pattern) []fegGroup {
	// Materialize the population so positional predicates in the pattern
	// (e.g. .[position()=3]) see the per-item focus of the population
	// sequence, and never the stale outer focus (ENG-005).
	pop := xdm.Materialize(seq)
	savedPos := ec.position
	savedSize := ec.size

	ec.size = len(pop)
	defer func() {
		ec.position = savedPos
		ec.size = savedSize
	}()

	var groups []fegGroup

	currentItems := make(xdm.ItemSlice, 0, len(pop))

	for i, item := range pop {
		ec.position = i + 1
		if pat.matchPatternItem(ctx, ec, item) && len(currentItems) > 0 {
			groups = append(groups, fegGroup{items: currentItems})
			currentItems = nil
		}

		currentItems = append(currentItems, item)
	}

	if len(currentItems) > 0 {
		groups = append(groups, fegGroup{items: currentItems})
	}

	return groups
}

// groupEndingWith implements group-ending-with: a group ends whenever
// an item matches the pattern.
func (ec *execContext) groupEndingWith(ctx context.Context, seq xdm.Sequence, pat *pattern) []fegGroup {
	// Materialize the population so positional predicates in the pattern
	// (e.g. .[position()=3]) see the per-item focus of the population
	// sequence, and never the stale outer focus (ENG-005).
	pop := xdm.Materialize(seq)
	savedPos := ec.position
	savedSize := ec.size

	ec.size = len(pop)
	defer func() {
		ec.position = savedPos
		ec.size = savedSize
	}()

	var groups []fegGroup

	currentItems := make(xdm.ItemSlice, 0, len(pop))

	for i, item := range pop {
		ec.position = i + 1

		currentItems = append(currentItems, item)
		if pat.matchPatternItem(ctx, ec, item) {
			groups = append(groups, fegGroup{items: currentItems})
			currentItems = nil
		}
	}

	if len(currentItems) > 0 {
		groups = append(groups, fegGroup{items: currentItems})
	}

	return groups
}

func (ec *execContext) execVariable(ctx context.Context, inst *variableInst) error {
	val, err := ec.evaluateVariableValue(ctx, inst)
	if err != nil {
		// Circular dependencies fail only if the variable is used (XSLT §9.5).
		if errors.Is(err, ErrCircularRef) {
			ec.setVarDeferred(inst.Name, err)
			return nil
		}

		return err
	}

	if inst.As != "" {
		val, err = checkSequenceType(ctx, val, parseSequenceType(inst.As), errCodeXTTE0570, "variable $"+inst.Name, ec)
		if err != nil {
			return err
		}
	}

	ec.setVar(inst.Name, val)

	return nil
}

func (ec *execContext) evaluateVariableValue(ctx context.Context, inst *variableInst) (xdm.Sequence, error) {
	if inst.Select != nil {
		result, err := ec.evalXPath(ctx, inst.Select, ec.contextNode)
		if err != nil {
			return nil, err
		}

		return result.Sequence(), nil
	}

	if len(inst.Body) > 0 {
		return ec.evaluateVariableBody(ctx, inst)
	}

	// An empty constructor yields an empty sequence only when the declared
	// type permits it; otherwise its default value is the empty string.
	if inst.As != "" && (strings.HasSuffix(inst.As, "?") || strings.HasSuffix(inst.As, "*")) {
		return nil, nil
	}

	return xdm.SingleString(""), nil
}

func (ec *execContext) evaluateVariableBody(ctx context.Context, inst *variableInst) (xdm.Sequence, error) {
	ec.temporaryOutputDepth++
	defer func() { ec.temporaryOutputDepth-- }()

	if inst.As == "" {
		// An untyped body constructs a document node (temporary tree).
		return ec.evaluateBodyAsDocument(ctx, inst.Body)
	}

	if !strings.HasPrefix(inst.As, "document-node") || strings.HasSuffix(inst.As, "*") || strings.HasSuffix(inst.As, "+") {
		// Repeated document types retain individual documents; other declared
		// types use a sequence constructor with separate node items.
		return ec.evaluateBodyAsSequence(ctx, inst.Body)
	}

	val, err := ec.evaluateBodyAsDocument(ctx, inst.Body)
	if err != nil {
		return nil, err
	}

	// A filtered-away optional document is absent, rather than an empty tree.
	if strings.HasSuffix(inst.As, "?") && isEmptyVariableDocument(val) {
		return nil, nil
	}

	return val, nil
}

func isEmptyVariableDocument(val xdm.Sequence) bool {
	if xdm.SequenceLen(val) != 1 {
		return false
	}

	item, ok := val.Get(0).(xdm.NodeItem)
	if !ok {
		return false
	}

	doc, ok := item.Node.(*xdm.Document)

	return ok && doc.FirstChild() == nil
}

func (ec *execContext) execParam(ctx context.Context, inst *paramInst) error {
	if _, ok := ec.localVars.lookup(inst.Name); ok {
		return nil
	}
	// Use default
	return ec.execVariable(ctx, &variableInst{
		Name:   inst.Name,
		Select: inst.Select,
		Body:   inst.Body,
		As:     inst.As,
	})
}

type fegGroup struct {
	key   xdm.Sequence
	items xdm.ItemSlice
}

type groupByEntry struct {
	keySeq   xdm.Sequence
	items    xdm.ItemSlice
	orderIdx int
}

// Typed buckets retain first-appearance order. Numeric/date/QName equality is
// refined by value comparison; a collation key is only a string lookup key.
type groupByAccumulator struct {
	order        []*groupByEntry
	byKey        map[string][]*groupByEntry
	collationKey func(string) string
	equal        func(xdm.Sequence, xdm.Sequence) (bool, error)
	limit        int
	members      int
	retainedKeys int
}

func (groups *groupByAccumulator) addComposite(ctx context.Context, item xdm.Item, keys xdm.Sequence) error {
	entry, err := groups.entryForKeys(ctx, keys)
	if err != nil {
		return err
	}

	return groups.addMember(ctx, entry, item)
}

func (groups *groupByAccumulator) addKeys(ctx context.Context, item xdm.Item, keys xdm.Sequence) error {
	added := make(map[int]struct{})

	for key := range xdm.SequenceItems(keys) {
		entry, err := groups.entryForKeys(ctx, xdm.ItemSlice{key})
		if err != nil {
			return err
		}

		if _, already := added[entry.orderIdx]; already {
			continue
		}

		if err := groups.addMember(ctx, entry, item); err != nil {
			return err
		}

		added[entry.orderIdx] = struct{}{}
	}

	return nil
}

func (groups *groupByAccumulator) addMember(ctx context.Context, entry *groupByEntry, item xdm.Item) error {
	if groups.members >= groups.limit {
		return xpath.ErrBudget
	}

	if err := xpath.Charge(ctx, 1); err != nil {
		return err
	}

	entry.items = append(entry.items, item)
	groups.members++

	return nil
}

func (groups *groupByAccumulator) entryForKeys(ctx context.Context, keys xdm.Sequence) (*groupByEntry, error) {
	bucket, err := groupingBucket(ctx, keys, groups.collationKey)
	if err != nil {
		return nil, err
	}

	for _, entry := range groups.byKey[bucket] {
		equal, err := groups.equal(keys, entry.keySeq)
		if err != nil {
			return nil, err
		}

		if equal {
			return entry, nil
		}
	}

	length := xdm.SequenceLen(keys)
	if length > groups.limit-groups.retainedKeys {
		return nil, xpath.ErrBudget
	}

	entry := &groupByEntry{keySeq: keys, orderIdx: len(groups.order)}
	groups.retainedKeys += length
	groups.byKey[bucket] = append(groups.byKey[bucket], entry)
	groups.order = append(groups.order, entry)

	return entry, nil
}

func groupingBucket(ctx context.Context, keys xdm.Sequence, collationKey func(string) string) (string, error) {
	var bucket strings.Builder

	for item := range xdm.SequenceItems(keys) {
		value, ok := item.(xdm.AtomicValue)
		if !ok {
			return "", dynamicError("XPTY0004", "grouping key must be atomic")
		}

		value = xdm.PromoteSchemaType(value)

		part := value.TypeName
		if text, stringLike := groupingString(value); stringLike {
			if err := xpath.Charge(ctx, max(len(text), 1)); err != nil {
				return "", err
			}

			if collationKey != nil {
				text = collationKey(text)
			}

			part = "S:" + text
		} else if value.IsNumeric() {
			part = "N"
		} else {
			switch value.TypeName {
			case xdm.TypeDateTimeStamp:
				part = xdm.TypeDateTime
			case xdm.TypeYearMonthDuration, xdm.TypeDayTimeDuration:
				part = xdm.TypeDuration
			}
		}

		bucket.WriteString(strconv.Itoa(len(part)))
		bucket.WriteByte(':')
		bucket.WriteString(part)
	}

	if err := xpath.ChargeString(ctx, bucket.Len()); err != nil {
		return "", err
	}

	return bucket.String(), nil
}

func (groups *groupByAccumulator) result() []fegGroup {
	result := make([]fegGroup, len(groups.order))
	for i, entry := range groups.order {
		result[i] = fegGroup{key: entry.keySeq, items: entry.items}
	}

	return result
}
