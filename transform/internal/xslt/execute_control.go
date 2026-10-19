// Derived from lestrrat-go/helium at 7362c0a70122a757780f4d0b545a9b370dead6ab.
// Copyright (c) 2015 lestrrat. MIT License; see licenses/MIT-helium.txt at the repository root.

package xslt

import (
	"context"
	"errors"
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

func (ec *execContext) execForEachGroup(ctx context.Context, inst *forEachGroupInst) error {
	result, err := ec.evalXPath(ctx, inst.Select, ec.contextNode)
	if err != nil {
		return err
	}

	seq := result.Sequence()

	// Resolve collation key function: explicit collation attribute takes
	// precedence, then fall back to the default collation in scope.
	var collationKeyFn func(string) string

	if inst.Collation != nil {
		collationURI, collErr := inst.Collation.evaluate(ctx, ec.contextNode)
		if collErr != nil {
			return collErr
		}

		collationKeyFn, err = xpath.ResolveCollationKeyFunc(collationURI)
		if err != nil {
			return err
		}
	} else if ec.defaultCollation != "" {
		collationKeyFn, err = xpath.ResolveCollationKeyFunc(ec.defaultCollation)
		if err != nil {
			return err
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

// groupBy implements group-by: items are grouped by the string value of the
// group-by expression evaluated with each item as context. When composite is
// false and the expression returns a sequence of multiple values, the item is
// added to a group for each value. When composite is true, the entire sequence
// is treated as a single composite key.
func (ec *execContext) groupBy(ctx context.Context, seq xdm.Sequence, groupByExpr *xpath.Expression, composite bool, collationKeyFn func(string) string) ([]fegGroup, error) {
	groups := groupByAccumulator{
		byKey:        make(map[string]*groupByEntry),
		collationKey: collationKeyFn,
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

		keys := result.Sequence()
		if xdm.SequenceLen(keys) == 0 {
			continue
		}

		if composite {
			groups.addComposite(item, keys)
		} else {
			groups.addKeys(item, keys)
		}
	}

	return groups.result(), nil
}

// groupAdjacent implements group-adjacent: consecutive items with equal
// grouping key values form a group. When composite is true, the key
// expression returns a sequence treated as a single composite key.
func (ec *execContext) groupAdjacent(ctx context.Context, seq xdm.Sequence, adjExpr *xpath.Expression, composite bool, collationKeyFn func(string) string) ([]fegGroup, error) {
	var (
		groups        []fegGroup
		currentKey    string
		currentKeySeq xdm.Sequence
		currentItems  xdm.ItemSlice
	)

	defer ec.restoreExecutionFocus(ec.captureExecutionFocus())

	ec.size = xdm.SequenceLen(seq)
	for i := range xdm.SequenceLen(seq) {
		item := seq.Get(i)
		ec.setIterateContext(item, i+1)

		result, err := ec.evalXPath(ctx, adjExpr, ec.contextNode)
		if err != nil {
			return nil, err
		}

		lookupKey, keySeq, err := adjacentGroupingKey(result.Sequence(), composite)
		if err != nil {
			return nil, err
		}

		if collationKeyFn != nil {
			lookupKey = collationKeyFn(stringifyResult(result))
		}

		if lookupKey == currentKey && len(currentItems) > 0 {
			currentItems = append(currentItems, item)
			continue
		}

		groups = appendAdjacentGroup(groups, currentKey, currentKeySeq, currentItems)
		currentKey = lookupKey
		currentKeySeq = keySeq
		currentItems = xdm.ItemSlice{item}
	}

	return appendAdjacentGroup(groups, currentKey, currentKeySeq, currentItems), nil
}

func adjacentGroupingKey(keys xdm.Sequence, composite bool) (string, xdm.Sequence, error) {
	if composite {
		return compositeKeyString(keys), atomizeSequence(keys), nil
	}

	if xdm.SequenceLen(keys) == 0 {
		return "", nil, dynamicError(errCodeXTTE1100,
			"group-adjacent key is an empty sequence")
	}

	if xdm.SequenceLen(keys) > 1 {
		return "", nil, dynamicError(errCodeXTTE1100,
			"group-adjacent key has %d items (expected 1)", xdm.SequenceLen(keys))
	}

	lookupKey, keySeq := groupLookupKey(keys.Get(0), nil)

	return lookupKey, keySeq, nil
}

func appendAdjacentGroup(groups []fegGroup, key string, keySeq xdm.Sequence, items xdm.ItemSlice) []fegGroup {
	if len(items) == 0 {
		return groups
	}

	if keySeq == nil {
		keySeq = xdm.SingleString(key)
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

func groupLookupKey(item xdm.Item, collationKeyFn func(string) string) (string, xdm.Sequence) {
	av, err := xpath.AtomizeItem(item)
	if err != nil {
		s := stringifyItem(item)
		if collationKeyFn != nil {
			return collationKeyFn(s), xdm.ItemSlice{xdm.AtomicValue{TypeName: xdm.TypeString, Value: s}}
		}

		return s, xdm.ItemSlice{xdm.AtomicValue{TypeName: xdm.TypeString, Value: s}}
	}

	s, err := xpath.AtomicToString(av)
	if err != nil {
		s = ""
	}

	if collationKeyFn != nil {
		return collationKeyFn(s), xdm.ItemSlice{av}
	}

	return canonicalKey(av), xdm.ItemSlice{av}
}

type groupByEntry struct {
	keyAtom  xdm.AtomicValue
	keySeq   xdm.Sequence
	items    xdm.ItemSlice
	orderIdx int
}

// groupByAccumulator retains first-appearance order and the original atomic
// keys. Numeric entries also need a value-comparison scan because equality
// across float/double/decimal is non-transitive (XSLT erratum E25).
type groupByAccumulator struct {
	order        []string
	byKey        map[string]*groupByEntry
	numeric      []*groupByEntry
	collationKey func(string) string
}

func (groups *groupByAccumulator) addComposite(item xdm.Item, keys xdm.Sequence) {
	lookupKey := compositeKeyString(keys)
	if groups.collationKey != nil {
		lookupKey = groups.collationKey(lookupKey)
	}

	if entry, ok := groups.byKey[lookupKey]; ok {
		entry.items = append(entry.items, item)
		return
	}

	groups.byKey[lookupKey] = &groupByEntry{
		keySeq: atomizeSequence(keys),
		items:  xdm.ItemSlice{item},
	}
	groups.order = append(groups.order, lookupKey)
}

func (groups *groupByAccumulator) addKeys(item xdm.Item, keys xdm.Sequence) {
	// Duplicate key values must not add the same population item twice.
	added := make(map[int]struct{})

	for key := range xdm.SequenceItems(keys) {
		entry := groups.entryForKey(key)
		if _, already := added[entry.orderIdx]; already {
			continue
		}

		entry.items = append(entry.items, item)
		added[entry.orderIdx] = struct{}{}
	}
}

func (groups *groupByAccumulator) entryForKey(key xdm.Item) *groupByEntry {
	av, err := xpath.AtomizeItem(key)
	if err == nil && av.IsNumeric() && groups.collationKey == nil {
		return groups.numericEntry(av)
	}

	lookupKey, keySeq := groupLookupKey(key, groups.collationKey)
	if entry, ok := groups.byKey[lookupKey]; ok {
		return entry
	}

	entry := &groupByEntry{keySeq: keySeq, orderIdx: len(groups.order)}
	groups.byKey[lookupKey] = entry
	groups.order = append(groups.order, lookupKey)

	return entry
}

func (groups *groupByAccumulator) numericEntry(key xdm.AtomicValue) *groupByEntry {
	for _, entry := range groups.numeric {
		if xpath.AtomicEquals(key, entry.keyAtom) {
			return entry
		}
	}

	index := len(groups.order)
	lookupKey := "N:" + strconv.Itoa(index)
	entry := &groupByEntry{keyAtom: key, keySeq: xdm.ItemSlice{key}, orderIdx: index}
	groups.byKey[lookupKey] = entry
	groups.numeric = append(groups.numeric, entry)
	groups.order = append(groups.order, lookupKey)

	return entry
}

func (groups *groupByAccumulator) result() []fegGroup {
	result := make([]fegGroup, len(groups.order))
	for i, key := range groups.order {
		entry := groups.byKey[key]
		result[i] = fegGroup{key: entry.keySeq, items: entry.items}
	}

	return result
}

// compositeKeyString creates a canonical string representation of a composite
// key for use as a map key. Items are separated by a NUL byte to avoid
// collisions.
func compositeKeyString(seq xdm.Sequence) string {
	parts := make([]string, xdm.SequenceLen(seq))
	for i := range xdm.SequenceLen(seq) {
		parts[i] = stringifyItem(seq.Get(i))
	}

	return strings.Join(parts, "\x00")
}
